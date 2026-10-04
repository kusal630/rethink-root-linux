"""Shared HTTP client for rethinkctl and the native GTK app.

Token/config discovery order: environment, the user's copy in
``~/.config/rethinkd``, then the system file in ``/etc/rethinkd``.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from pathlib import Path

DEFAULT_LISTEN = "127.0.0.1:8777"
SYSTEM_CONFIG = Path("/etc/rethinkd/config.json")


class ApiError(RuntimeError):
    """Any HTTP or transport failure talking to the daemon."""

    def __init__(self, message: str, status: int = 0) -> None:
        super().__init__(message)
        self.status = status


def config_path() -> Path:
    if os.environ.get("RETHINK_CONFIG"):
        return Path(os.environ["RETHINK_CONFIG"])
    if os.geteuid() == 0:
        return SYSTEM_CONFIG
    return Path.home() / ".config" / "rethinkd" / "config.json"


def read_json(path: Path, default=None):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def token_value() -> str:
    if os.environ.get("RETHINK_TOKEN"):
        return os.environ["RETHINK_TOKEN"].strip()
    candidates = []
    if os.environ.get("RETHINK_CONFIG"):
        candidates.append(Path(os.environ["RETHINK_CONFIG"]).parent / "token")
    candidates.append(Path.home() / ".config" / "rethinkd" / "token")
    candidates.append(Path("/etc/rethinkd/token"))
    for candidate in candidates:
        try:
            value = candidate.read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if value:
            return value
    return ""


def listen_address() -> str:
    """The daemon's listen address, best effort across user/system config."""
    for path in (config_path(), SYSTEM_CONFIG):
        cfg = read_json(path, {}) or {}
        listen = ((cfg.get("settings") or {}).get("listen") or "").strip()
        if listen:
            return listen
    return DEFAULT_LISTEN


def endpoints() -> tuple[str, str]:
    return f"http://{listen_address()}", token_value()


def ui_url() -> str:
    base, token = endpoints()
    return f"{base}/?token={token}"


def call(method: str, path: str, payload=None, timeout: float = 60.0):
    """One API round trip. Raises ApiError on any failure."""
    base, token = endpoints()
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(base + path, data=data, method=method)
    if token:
        req.add_header("X-Auth-Token", token)
    if data:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode() or "{}"
    except urllib.error.HTTPError as exc:
        text = exc.read().decode(errors="replace")[:300]
        raise ApiError(f"{exc.code} {text}", status=exc.code) from exc
    except OSError as exc:
        raise ApiError(f"cannot reach the daemon at {base} ({exc})") from exc
    try:
        return json.loads(body)
    except ValueError as exc:
        raise ApiError(f"bad response from the daemon: {body[:200]}") from exc


def reachable(timeout: float = 2.0) -> bool:
    try:
        call("GET", "/api/session", timeout=timeout)
        return True
    except ApiError:
        return False
