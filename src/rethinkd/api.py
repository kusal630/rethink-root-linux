"""HTTP API + static UI server (stdlib only, loopback only)."""

from __future__ import annotations

import hmac
import json
import mimetypes
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qs, urlparse

UI_DIR = Path(__file__).parent / "ui"
STATIC = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
    "/icon.svg": ("icon.svg", "image/svg+xml"),
}


class APIServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, host: str, port: int, core: Any) -> None:
        self.core = core
        super().__init__((host, port), Handler)

    def log_message(self, fmt: str, *args: Any) -> None:  # quiet by default
        if getattr(self.core, "verbose", False):
            super().log_message(fmt, *args)

    def handle_error(self, request, client_address) -> None:  # clients hang up all the time
        import sys

        exc = sys.exc_info()[1]
        if isinstance(exc, (BrokenPipeError, ConnectionResetError)):
            return
        super().handle_error(request, client_address)


class Handler(BaseHTTPRequestHandler):
    server: APIServer
    protocol_version = "HTTP/1.1"

    # -- plumbing -------------------------------------------------------
    def log_message(self, fmt: str, *args: Any) -> None:
        if getattr(self.server, "core", None) and getattr(self.server.core, "verbose", False):
            super().log_message(fmt, *args)

    @property
    def core(self) -> Any:
        return self.server.core

    def _send_json(self, payload: Any, status: int = 200) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        raw = self.rfile.read(min(length, 1 << 20))
        data = json.loads(raw.decode("utf-8", "replace") or "{}")
        return data if isinstance(data, dict) else {}

    def _authed(self) -> bool:
        token = self.headers.get("X-Auth-Token") or ""
        if not token:
            cookie = self.headers.get("Cookie") or ""
            for part in cookie.split(";"):
                key, _, value = part.strip().partition("=")
                if key == "rethink_token":
                    token = value
                    break
        expected = self.core.token()
        return bool(token) and hmac.compare_digest(token, expected)

    # -- verbs ----------------------------------------------------------
    def do_GET(self) -> None:
        self._dispatch("GET")

    def do_POST(self) -> None:
        self._dispatch("POST")

    def do_DELETE(self) -> None:
        self._dispatch("DELETE")

    def _dispatch(self, method: str) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        if path in STATIC and method == "GET":
            return self._serve_static(path)
        if not path.startswith("/api/"):
            return self._send_json({"error": "not found"}, 404)
        if path == "/api/session":
            return self._send_json({"authed": self._authed(), "version": self.core.version})
        if not self._authed():
            return self._send_json({"error": "unauthorized"}, 401)
        try:
            for pattern, methods, fn in ROUTES:
                if method not in methods:
                    continue
                match = re.fullmatch(pattern, path)
                if match:
                    payload = self._read_json() if method in ("POST", "DELETE") else {}
                    query = parse_qs(parsed.query)
                    result = fn(self.core, payload, query, *match.groups())
                    return self._send_json(result if result is not None else {"ok": True})
            return self._send_json({"error": "not found"}, 404)
        except (ValueError, KeyError) as exc:
            return self._send_json({"error": str(exc)}, 400)
        except FileNotFoundError as exc:
            return self._send_json({"error": str(exc)}, 404)
        except Exception as exc:  # noqa: BLE001 — surface anything as JSON
            return self._send_json({"error": str(exc)}, 500)

    def _serve_static(self, path: str) -> None:
        name, ctype = STATIC[path]
        file_path = UI_DIR / name
        if not file_path.exists():
            return self._send_json({"error": "ui missing"}, 404)
        body = file_path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(body)


# -- route table --------------------------------------------------------
Route = tuple[str, set[str], Callable[..., dict[str, Any]]]
ROUTES: list[Route] = []


def route(pattern: str, *methods: str) -> Callable[[Callable[..., dict[str, Any]]], Callable[..., dict[str, Any]]]:
    def wrapper(fn: Callable[..., dict[str, Any]]) -> Callable[..., dict[str, Any]]:
        ROUTES.append((pattern, set(methods or ("GET",)), fn))
        return fn

    return wrapper


# --- status ------------------------------------------------------------
@route(r"/api/status", "GET")
def get_status(core, _payload, _query):
    return core.status()


@route(r"/api/stats", "GET")
def get_stats(core, _payload, _query):
    return core.stats()


# --- protected ---------------------------------------------------------
@route(r"/api/protected", "POST")
def set_protected(core, payload, _query):
    if "on" not in payload:
        raise ValueError("expected {on: true|false}")
    core.set_protected(bool(payload["on"]))
    return {"ok": True, "protected": bool(payload["on"])}


# --- apps --------------------------------------------------------------
@route(r"/api/apps", "GET")
def get_apps(core, _payload, _query):
    return core.apps()


@route(r"/api/apps", "POST")
def post_app(core, payload, _query):
    uid = int(payload["uid"])
    action = payload["action"]
    if action not in ("allow", "block"):
        raise ValueError("action must be allow|block")
    core.set_app_rule(uid, action)
    return {"ok": True}


@route(r"/api/apps/(\d+)", "DELETE")
def delete_app(core, _payload, _query, uid):
    core.clear_app_rule(int(uid))
    return {"ok": True}


@route(r"/api/policy", "POST")
def set_policy(core, payload, _query):
    policy = payload.get("policy")
    if policy not in ("allow", "block"):
        raise ValueError("policy must be allow|block")
    core.set_policy(policy)
    return {"ok": True}


@route(r"/api/apps/refresh", "POST")
def refresh_apps(core, _payload, _query):
    core.refresh_apps()
    return {"ok": True}


# --- blocklists --------------------------------------------------------
@route(r"/api/blocklists", "GET")
def get_blocklists(core, _payload, _query):
    return core.blocklists.stats()


@route(r"/api/blocklists", "POST")
def toggle_blocklist(core, payload, _query):
    item_id = str(payload.get("id") or "")
    if "enabled" not in payload:
        raise ValueError("expected {id, enabled}")
    core.set_blocklist(item_id, bool(payload["enabled"]))
    return {"ok": True}


@route(r"/api/blocklists/custom", "POST")
def add_custom(core, payload, _query):
    url = str(payload.get("url") or "").strip()
    if not url.startswith(("http://", "https://")):
        raise ValueError("url must be http(s)")
    core.add_custom_list(url, bool(payload.get("enabled", True)))
    return {"ok": True}


@route(r"/api/blocklists/custom/([^/]+)", "DELETE")
def delete_custom(core, _payload, _query, cid):
    core.remove_custom_list(cid)
    return {"ok": True}


@route(r"/api/blocklists/refresh", "POST")
def refresh_blocklists(core, _payload, _query):
    return core.refresh_blocklists()


@route(r"/api/blocklists/test", "POST")
def test_domain(core, payload, _query):
    domain = str(payload.get("domain") or "")
    if not domain:
        raise ValueError("domain required")
    reason = core.matcher(domain)
    return {"blocked": reason is not None, "reason": reason}


# --- dns ---------------------------------------------------------------
@route(r"/api/dns", "GET")
def get_dns(core, _payload, _query):
    return core.dns_status()


@route(r"/api/dns/upstream", "POST")
def set_upstream(core, payload, _query):
    core.set_upstream(str(payload.get("type") or "system"), str(payload.get("url") or ""))
    return {"ok": True}


@route(r"/api/dns/domain", "POST")
def add_domain(core, payload, _query):
    domain = str(payload.get("domain") or "").strip()
    action = payload.get("action")
    if not domain or action not in ("block", "allow"):
        raise ValueError("expected {domain, action: block|allow}")
    core.add_domain_rule(domain, action)
    return {"ok": True}


@route(r"/api/dns/domain/([^/]+)", "DELETE")
def delete_domain(core, _payload, _query, domain):
    core.remove_domain_rule(domain)
    return {"ok": True}


@route(r"/api/dns/hijack", "POST")
def set_hijack(core, payload, _query):
    core.set_hijack(bool(payload.get("enabled")))
    return {"ok": True}


@route(r"/api/dns/clearlog", "POST")
def clear_log(core, _payload, _query):
    core.activity.clear_log()
    return {"ok": True}


# --- proxy -------------------------------------------------------------
@route(r"/api/proxy", "GET")
def get_proxy(core, _payload, _query):
    return core.proxy_status()


@route(r"/api/proxy", "POST")
def set_proxy(core, payload, _query):
    core.configure_proxy(payload)
    return {"ok": True}


@route(r"/api/proxy/toggle", "POST")
def toggle_proxy(core, payload, _query):
    core.toggle_proxy(bool(payload.get("enabled")))
    return {"ok": True}


# --- settings / activity ----------------------------------------------
@route(r"/api/settings", "GET")
def get_settings(core, _payload, _query):
    return core.settings()


@route(r"/api/settings", "POST")
def set_settings(core, payload, _query):
    core.set_settings(payload)
    return {"ok": True}


@route(r"/api/activity", "GET")
def get_activity(core, _payload, query):
    limit = int((query.get("limit") or ["200"])[0])
    return {"events": core.activity.events(limit)}


def serve(host: str, port: int, core: Any) -> APIServer:
    server = APIServer(host, port, core)
    threading.Thread(target=server.serve_forever, daemon=True, name="api").start()
    return server
