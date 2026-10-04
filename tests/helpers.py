"""Shared helpers for the rethinkd test-suite (stdlib unittest)."""

from __future__ import annotations

import os
import socket
import sys
import tempfile
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def temp_config() -> tuple[tempfile.TemporaryDirectory, Path]:
    tmp = tempfile.TemporaryDirectory(prefix="rethinkd-test-")
    return tmp, Path(tmp.name) / "config.json"


def make_daemon(dns_enabled: bool = False):
    """A dry-run daemon with DNS off unless asked, on a free API port."""
    from rethinkd.daemon import Daemon

    tmp, path = temp_config()
    daemon = Daemon(path, dry_run=True)
    daemon.cfg.set("dns.enabled", dns_enabled, save=False)
    if dns_enabled:
        port = free_port()
        daemon.cfg.set("dns.listen", [f"127.0.0.1:{port}"], save=False)
    listen_port = free_port()
    daemon.cfg.set("settings.listen", f"127.0.0.1:{listen_port}", save=False)
    return tmp, daemon, listen_port


def start_daemon(dns_enabled: bool = False):
    tmp, daemon, port = make_daemon(dns_enabled)
    daemon.start()
    import time
    import urllib.request

    base = f"http://127.0.0.1:{port}"
    for _ in range(50):
        try:
            with urllib.request.urlopen(base + "/api/session", timeout=0.5) as resp:
                if resp.status == 200:
                    break
        except OSError:
            time.sleep(0.05)
    return tmp, daemon, port, base


def api(base: str, token: str, method: str, path: str, payload=None):
    import json
    import urllib.error
    import urllib.request

    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(base + path, data=data, method=method)
    req.add_header("X-Auth-Token", token)
    if data:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode() or "{}"), resp.status
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")
        try:
            return json.loads(body), exc.code
        except ValueError:
            return {"raw": body}, exc.code


def env_online() -> bool:
    """Some tests touch the network; skip them when offline."""
    return bool(os.environ.get("RETHINK_ONLINE"))
