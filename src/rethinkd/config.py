"""Configuration store: a single JSON file, written atomically, read by the UI."""

from __future__ import annotations

import json
import os
import secrets
import threading
import time
from copy import deepcopy
from pathlib import Path
from typing import Any

DEFAULT_CONFIG: dict[str, Any] = {
    "protected": True,
    "dns": {
        "enabled": True,
        # Addresses the DNS server binds. The first is the nat-REDIRECT target
        # (iptables sends hijacked queries to 127.0.0.1), the second is what
        # systemd-resolved is pointed at by the installer.
        "listen": ["127.0.0.1:5300", "127.0.0.42:53"],
        "hijack": True,
        "upstream": {"type": "system", "url": ""},
        "block_mode": "sinkhole",  # sinkhole (0.0.0.0) | nxdomain
        "log_size": 500,
    },
    "blocklists": {
        "categories": {},  # id -> bool, filled from blocklists.CATEGORIES
        "custom": [],  # [{"id","url","enabled"}]
    },
    "domains": {"block": [], "allow": []},  # per-domain overrides
    "firewall": {
        "enabled": True,
        "policy": "allow",  # allow: block only listed apps; block: allow only listed apps
        "apps": {},  # uid(str) -> "allow" | "block"
    },
    "proxy": {
        "enabled": False,
        "type": "http",
        "host": "",
        "port": 0,
        "username": "",
        "password": "",
        "bypass_lan": True,
        "bypass_domains": [],
    },
    "settings": {
        "theme": "dark",
        "start_protected": True,
        "log_level": "info",
        "listen": "127.0.0.1:8777",
    },
}


def _deep_merge(base: dict, extra: dict) -> dict:
    out = deepcopy(base)
    for key, value in extra.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


class Config:
    """Thread-safe JSON config. Every mutation goes through set()/update()."""

    def __init__(self, path: Path, token_path: Path | None = None) -> None:
        self.path = Path(path)
        self.token_path = Path(token_path) if token_path else self.path.parent / "token"
        self._lock = threading.RLock()
        self._data: dict[str, Any] = deepcopy(DEFAULT_CONFIG)
        self.load()

    # -- persistence -----------------------------------------------------
    def load(self) -> None:
        with self._lock:
            if self.path.exists():
                try:
                    raw = json.loads(self.path.read_text(encoding="utf-8"))
                    self._data = _deep_merge(DEFAULT_CONFIG, raw if isinstance(raw, dict) else {})
                except (OSError, ValueError):
                    self._data = deepcopy(DEFAULT_CONFIG)
            # seed category toggles so the UI sees every built-in category
            from .dns.blocklists import CATEGORIES

            cats = self._data["blocklists"].setdefault("categories", {})
            for cat in CATEGORIES:
                cats.setdefault(cat["id"], bool(cat.get("default")))

    def save(self) -> None:
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self._data, indent=2, sort_keys=True), encoding="utf-8")
            os.chmod(tmp, 0o640)
            tmp.replace(self.path)

    # -- access ----------------------------------------------------------
    @property
    def data(self) -> dict[str, Any]:
        with self._lock:
            return deepcopy(self._data)

    def get(self, path: str, default: Any = None) -> Any:
        node: Any = self._data
        for part in path.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return deepcopy(node)

    def set(self, path: str, value: Any, save: bool = True) -> None:
        parts = path.split(".")
        with self._lock:
            node = self._data
            for part in parts[:-1]:
                node = node.setdefault(part, {})
                if not isinstance(node, dict):
                    raise ValueError(f"cannot descend into {part}")
            node[parts[-1]] = value
            if save:
                self.save()

    def update(self, mapping: dict[str, Any], save: bool = True) -> None:
        with self._lock:
            self._data = _deep_merge(self._data, mapping)
            if save:
                self.save()

    # -- auth token ------------------------------------------------------
    def token(self) -> str:
        """The shared API token, created on first use and mode 0600."""
        with self._lock:
            try:
                existing = self.token_path.read_text(encoding="utf-8").strip()
                if existing:
                    return existing
            except OSError:
                pass
            self.token_path.parent.mkdir(parents=True, exist_ok=True)
            value = secrets.token_urlsafe(24)
            self.token_path.write_text(value + "\n", encoding="utf-8")
            os.chmod(self.token_path, 0o640)  # group-readable so rethinkctl works
            return value

    def rotate_token(self) -> str:
        with self._lock:
            value = secrets.token_urlsafe(24)
            self.token_path.parent.mkdir(parents=True, exist_ok=True)
            self.token_path.write_text(value + "\n", encoding="utf-8")
            os.chmod(self.token_path, 0o640)  # group-readable so rethinkctl works
            return value


def now() -> int:
    return int(time.time())
