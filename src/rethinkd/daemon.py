"""Daemon wiring: config → DNS, firewall, proxy, activity, HTTP API."""

from __future__ import annotations

import platform
import signal
import sys
import threading
import time
from pathlib import Path
from typing import Any

from . import __version__
from .activity import Activity
from .api import serve as serve_api
from .config import Config
from .dns import wire
from .dns.blocklists import BlocklistManager, CATEGORIES, normalise
from .dns.server import DNSServer
from .dns.upstream import Upstream
from .firewall import Firewall, FirewallError, discover_apps
from .proxy import TransparentProxy

FALLBACK_DIR = Path("/etc/rethinkd")


class Daemon:
    def __init__(self, config_path: Path, dry_run: bool = False, verbose: bool = False) -> None:
        self.cfg = Config(config_path)
        self.dry_run = dry_run
        self.verbose = verbose
        self.version = __version__
        self.started = time.time()
        self._lock = threading.RLock()

        self.activity = Activity(int(self.cfg.get("dns.log_size", 500)))
        # state lives outside /etc: /var/lib/rethinkd when installed system-wide
        data_dir = Path("/var/lib/rethinkd") if str(config_path).startswith("/etc/") else config_path.parent
        cache_dir = data_dir / "cache"
        self.blocklists = BlocklistManager(cache_dir)
        self.upstream = Upstream()
        self.firewall = Firewall(self.cfg, dry_run=dry_run)
        self.proxy = TransparentProxy(self.cfg, self.activity)
        self.dns: DNSServer | None = None
        self._api = None
        self._stop = threading.Event()
        self._domain_rules = (set(), set())

        self._sync_from_config(first=True)

    # -- startup --------------------------------------------------------
    def start(self) -> None:
        self.cfg.token()  # create the API token now so rethinkctl works immediately
        self.blocklists.load_cache()
        self.blocklists.configure(
            self.cfg.get("blocklists.categories", {}),
            self.cfg.get("blocklists.custom", []),
            self.cfg.get("domains.block", []),
            self.cfg.get("domains.allow", []),
        )
        if self.cfg.get("dns.enabled", True):
            self._start_dns()
        try:
            self.firewall.apply()
        except FirewallError as exc:
            print(f"firewall: not applied ({exc})", file=sys.stderr)
        if self.cfg.get("proxy.enabled"):
            self._start_proxy()
        host, _, port = self.cfg.get("settings.listen", "127.0.0.1:8777").rpartition(":")
        self._api = serve_api(host or "127.0.0.1", int(port or 8777), self)
        print(f"rethinkd {self.version} → http://{host or '127.0.0.1'}:{port or 8777}/", file=sys.stderr)

    def stop(self) -> None:
        self._stop.set()
        if self.dns:
            self.dns.stop()
        self.proxy.stop()
        if self._api:
            self._api.shutdown()

    def wait(self) -> None:
        try:
            while not self._stop.wait(1.0):
                pass
        except KeyboardInterrupt:
            pass

    def install_signals(self) -> None:
        def handler(signum, _frame):
            self._stop.set()
            self.stop()

        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, handler)

    # -- helpers --------------------------------------------------------
    def _start_dns(self) -> None:
        if self.dns:
            self.dns.stop()
        endpoints: list[str] = []
        for endpoint in self.cfg.get("dns.listen", ["127.0.0.1:5300"]):
            if not self._can_bind(endpoint):
                print(f"dns: skipping {endpoint} (needs CAP_NET_BIND_SERVICE)", file=sys.stderr)
                continue
            endpoints.append(endpoint)
        if not endpoints:
            print("dns: no usable listen address — DNS filtering is off", file=sys.stderr)
            self.dns = None
            return
        self.dns = DNSServer(
            endpoints,
            self.upstream,
            self.matcher,
            self._on_dns_query,
            self.cfg.get("dns.block_mode", "sinkhole"),
        )
        try:
            self.dns.start()
        except OSError as exc:
            print(f"dns: cannot bind {endpoints}: {exc}", file=sys.stderr)
            self.dns = None

    @staticmethod
    def _can_bind(endpoint: str) -> bool:
        try:
            port = int(str(endpoint).rsplit(":", 1)[1])
        except (IndexError, ValueError):
            return True
        if port >= 1024:
            return True
        return Daemon._euid() == 0 or _has_capability(10)  # CAP_NET_BIND_SERVICE

    def _start_proxy(self) -> None:
        port = int(self.cfg.get("proxy.port", 0) or 0)
        if port:
            self.proxy.start(port)

    def _on_dns_query(self, name: str, qtype: int, client: str, blocked: bool, reason: str | None) -> None:
        self.activity.dns_query(name, wire.qtype_name(qtype), client, blocked, reason)

    def matcher(self, name: str) -> str | None:
        """Block decision for one domain (None → resolve it)."""
        if not self.cfg.get("protected", True):
            return None
        domain = normalise(name)
        if not domain:
            return None
        allow, block = self._domain_rules
        if _hit(domain, allow):
            return None
        if _hit(domain, block):
            return "domain:block"
        return self.blocklists.check(domain)

    def _sync_from_config(self, first: bool = False) -> None:
        kind = self.cfg.get("dns.upstream.type", "system")
        url = self.cfg.get("dns.upstream.url", "")
        try:
            self.upstream.configure(kind, url)
        except ValueError:
            self.upstream.configure("system", "")

    # -- auth -----------------------------------------------------------
    def token(self) -> str:
        return self.cfg.token()

    def rotate_token(self) -> str:
        return self.cfg.rotate_token()

    # -- protected ------------------------------------------------------
    def set_protected(self, on: bool) -> None:
        with self._lock:
            self.cfg.set("protected", bool(on))
            try:
                self.firewall.apply()
            except FirewallError as exc:
                print(f"firewall: {exc}", file=sys.stderr)

    # -- apps -----------------------------------------------------------
    def apps(self) -> dict[str, Any]:
        policy = self.cfg.get("firewall.policy", "allow")
        explicit = dict(self.cfg.get("firewall.apps", {}))
        apps = discover_apps(policy, explicit)
        counters = self.firewall.counters()
        for app in apps:
            stats = counters.get(app["uid"], {})
            app["packets"] = stats.get("packets", 0)
            app["dropped"] = stats.get("packets", 0) if app["action"] == "block" else 0
            app["bytes"] = stats.get("bytes", 0)
        return {"policy": policy, "apps": apps}

    def set_app_rule(self, uid: int, action: str) -> None:
        with self._lock:
            apps = dict(self.cfg.get("firewall.apps", {}))
            apps[str(uid)] = action
            self.cfg.set("firewall.apps", apps)
            self.firewall.apply()

    def clear_app_rule(self, uid: int) -> None:
        with self._lock:
            apps = dict(self.cfg.get("firewall.apps", {}))
            apps.pop(str(uid), None)
            self.cfg.set("firewall.apps", apps)
            self.firewall.apply()

    def set_policy(self, policy: str) -> None:
        with self._lock:
            self.cfg.set("firewall.policy", policy)
            self.firewall.apply()

    def refresh_apps(self) -> None:
        return None

    # -- blocklists -----------------------------------------------------
    def set_blocklist(self, item_id: str, enabled: bool) -> None:
        with self._lock:
            cats = dict(self.cfg.get("blocklists.categories", {}))
            custom = list(self.cfg.get("blocklists.custom", []))
            if any(c["id"] == item_id for c in CATEGORIES):
                cats[item_id] = enabled
            else:
                for entry in custom:
                    if entry["id"] == item_id:
                        entry["enabled"] = enabled
            self.cfg.set("blocklists.categories", cats)
            self.cfg.set("blocklists.custom", custom)
            self.blocklists.set_enabled(item_id, enabled)
            self._reconfigure_blocklists()

    def add_custom_list(self, url: str, enabled: bool) -> None:
        with self._lock:
            import secrets

            cid = secrets.token_hex(4)
            custom = list(self.cfg.get("blocklists.custom", []))
            custom.append({"id": cid, "url": url, "enabled": enabled})
            self.cfg.set("blocklists.custom", custom)
            self.blocklists.configure(
                self.cfg.get("blocklists.categories", {}),
                custom,
                self.cfg.get("domains.block", []),
                self.cfg.get("domains.allow", []),
            )
            self.blocklists.set_enabled(cid, enabled)
            self.blocklists.refresh_custom(cid, url)
            self._reconfigure_blocklists()

    def remove_custom_list(self, cid: str) -> None:
        with self._lock:
            custom = [c for c in self.cfg.get("blocklists.custom", []) if c["id"] != cid]
            self.cfg.set("blocklists.custom", custom)
            self.blocklists.remove_custom(cid)
            self._reconfigure_blocklists()

    def refresh_blocklists(self) -> dict[str, Any]:
        total_domains = 0
        total_categories = 0
        enabled = set(self.cfg.get("blocklists.categories", {})) | {
            c["id"] for c in self.cfg.get("blocklists.custom", []) if c.get("enabled", True)
        }
        for cat in CATEGORIES:
            if cat["id"] in enabled or self.cfg.get("blocklists.categories", {}).get(cat["id"]):
                result = self.blocklists.refresh_category(cat["id"])
                total_domains += result["count"]
                total_categories += 1
        for entry in self.cfg.get("blocklists.custom", []):
            result = self.blocklists.refresh_custom(entry["id"], entry["url"])
            total_domains += result["count"]
        self._reconfigure_blocklists()
        return {"ok": True, "categories": total_categories, "domains": total_domains}

    def _reconfigure_blocklists(self) -> None:
        self._domain_rules = (
            _norm_set(self.cfg.get("domains.allow", [])),
            _norm_set(self.cfg.get("domains.block", [])),
        )
        self.blocklists.configure(
            self.cfg.get("blocklists.categories", {}),
            self.cfg.get("blocklists.custom", []),
            self.cfg.get("domains.block", []),
            self.cfg.get("domains.allow", []),
        )

    # -- dns ------------------------------------------------------------
    def dns_status(self) -> dict[str, Any]:
        stats = self.activity.dns_stats()
        conf = self.cfg.get("dns", {})
        return {
            "upstream": self.cfg.get("dns.upstream", {"type": "system", "url": ""}),
            "hijack": bool(conf.get("hijack", True)),
            "listen": (self.dns.endpoints[0] if self.dns else (conf.get("listen") or [""])[0]),
            "queries": stats["queries"],
            "blocked": stats["blocked"],
            "log": self.activity.log(int(conf.get("log_size", 500))),
            "allow": self.cfg.get("domains.allow", []),
            "block": self.cfg.get("domains.block", []),
        }

    def set_upstream(self, kind: str, url: str) -> None:
        with self._lock:
            self.upstream.configure(kind, url)  # validates
            self.cfg.set("dns.upstream", {"type": kind, "url": url})
            self._sync_from_config()

    def add_domain_rule(self, domain: str, action: str) -> None:
        with self._lock:
            key = "domains.block" if action == "block" else "domains.allow"
            other = "domains.allow" if action == "block" else "domains.block"
            values = [d for d in self.cfg.get(other, []) if d != domain]
            self.cfg.set(other, values)
            current = list(self.cfg.get(key, []))
            if domain not in current:
                current.append(domain)
            self.cfg.set(key, current)
            self._reconfigure_blocklists()

    def remove_domain_rule(self, domain: str) -> None:
        with self._lock:
            for key in ("domains.block", "domains.allow"):
                self.cfg.set(key, [d for d in self.cfg.get(key, []) if d != domain])
            self._reconfigure_blocklists()

    def set_hijack(self, enabled: bool) -> None:
        with self._lock:
            self.cfg.set("dns.hijack", bool(enabled))
            try:
                self.firewall.apply()
            except FirewallError as exc:
                print(f"firewall: {exc}", file=sys.stderr)

    # -- proxy ----------------------------------------------------------
    def proxy_status(self) -> dict[str, Any]:
        proxy = self.cfg.get("proxy", {})
        stats = self.proxy.status()
        endpoint = None
        if proxy.get("enabled") and proxy.get("host") and proxy.get("port"):
            endpoint = f"{proxy['type']}://{proxy['host']}:{proxy['port']}"
        return {
            "enabled": bool(proxy.get("enabled")),
            "type": proxy.get("type", "http"),
            "host": proxy.get("host", ""),
            "port": int(proxy.get("port", 0) or 0),
            "username": proxy.get("username", ""),
            "password_set": bool(proxy.get("password")),
            "bypass_lan": bool(proxy.get("bypass_lan", True)),
            "bypass_domains": list(proxy.get("bypass_domains", []) or []),
            "active": stats.get("active", 0),
            "relayed": stats.get("relayed", 0),
            "last_error": stats.get("last_error") or self.firewall.last_error,
            "endpoint": endpoint,
        }

    def configure_proxy(self, payload: dict[str, Any]) -> None:
        with self._lock:
            proxy = dict(self.cfg.get("proxy", {}))
            for field in ("type", "host", "username"):
                if field in payload:
                    proxy[field] = str(payload[field])
            if "port" in payload:
                proxy["port"] = int(payload["port"] or 0)
            if "bypass_lan" in payload:
                proxy["bypass_lan"] = bool(payload["bypass_lan"])
            if "bypass_domains" in payload:
                domains = payload["bypass_domains"]
                proxy["bypass_domains"] = domains if isinstance(domains, list) else [d.strip() for d in str(domains).split(",")]
            if payload.get("password"):
                proxy["password"] = str(payload["password"])
            if "enabled" in payload:
                proxy["enabled"] = bool(payload["enabled"])
            if proxy["enabled"] and (not proxy.get("host") or not proxy.get("port")):
                raise ValueError("proxy needs host and port")
            if proxy.get("type", "http") not in ("http", "socks5"):
                raise ValueError("type must be http|socks5")
            self.cfg.set("proxy", proxy)
            self._apply_proxy()

    def toggle_proxy(self, enabled: bool) -> None:
        with self._lock:
            proxy = dict(self.cfg.get("proxy", {}))
            proxy["enabled"] = bool(enabled)
            if enabled and (not proxy.get("host") or not proxy.get("port")):
                raise ValueError("set host and port first")
            self.cfg.set("proxy", proxy)
            self._apply_proxy()

    def _apply_proxy(self) -> None:
        proxy = self.cfg.get("proxy", {})
        if proxy.get("enabled") and proxy.get("port"):
            self.proxy.start(int(proxy["port"]))
        else:
            self.proxy.stop()
        try:
            self.firewall.apply()
        except FirewallError as exc:
            print(f"firewall: {exc}", file=sys.stderr)

    # -- settings -------------------------------------------------------
    def settings(self) -> dict[str, Any]:
        settings = self.cfg.get("settings", {})
        token = self.cfg.token()
        return {
            **settings,
            "version": self.version,
            "uptime_s": int(time.time() - self.started),
            "token_hint": token[:8],
            "dry_run": self.dry_run,
        }

    def set_settings(self, payload: dict[str, Any]) -> None:
        with self._lock:
            settings = dict(self.cfg.get("settings", {}))
            for field in ("theme", "log_level"):
                if field in payload:
                    settings[field] = str(payload[field])
            for field in ("start_protected",):
                if field in payload:
                    settings[field] = bool(payload[field])
            if "listen" in payload and str(payload["listen"]) != settings.get("listen"):
                raise ValueError("listen address changes need a daemon restart")
            self.cfg.set("settings", settings)

    # -- status ---------------------------------------------------------
    def status(self) -> dict[str, Any]:
        stats = self.activity.dns_stats()
        counters = self.activity.counters()
        conf = self.cfg.get("dns", {})
        proxy = self.cfg.get("proxy", {})
        firewall = self.cfg.get("firewall", {})
        pstatus = self.proxy.status()
        fw_counters = self.firewall.counters()
        return {
            "authed": True,
            "version": self.version,
            "uptime_s": int(time.time() - self.started),
            "protected": bool(self.cfg.get("protected", True)),
            "running_as": f"{'root' if self._euid() == 0 else 'user'} (uid {self._euid()})",
            "dns": {
                "listening": self.dns.endpoints if self.dns else [],
                "hijack": bool(conf.get("hijack", True)) and bool(self.cfg.get("protected", True)),
                "upstream": self.cfg.get("dns.upstream.type", "system"),
                "upstream_url": self.upstream.endpoint,
                "queries": stats["queries"],
                "blocked": stats["blocked"],
                "block_rate": stats["block_rate"],
                "last_hour": stats["last_hour"],
            },
            "firewall": {
                "enabled": bool(self.firewall.applied) and bool(self.cfg.get("protected", True)),
                "policy": firewall.get("policy", "allow"),
                "apps_blocked": sum(1 for a in firewall.get("apps", {}).values() if a == "block"),
                "dropped_packets": counters["dropped_packets"] + sum(
                    v.get("packets", 0) for v in fw_counters.values()
                ),
                "error": self.firewall.last_error,
                "dry_run": self.dry_run,
            },
            "proxy": {
                "enabled": bool(proxy.get("enabled")),
                "type": proxy.get("type") if proxy.get("enabled") else None,
                "endpoint": (f"{proxy.get('host')}:{proxy.get('port')}" if proxy.get("enabled") else None),
                "active_conns": pstatus.get("active", 0),
                "relayed": pstatus.get("relayed", 0),
                "last_error": pstatus.get("last_error"),
            },
            "host": {
                "kernel": platform.release(),
                "os": self._os_name(),
                "python": platform.python_version(),
                "uid": self._euid(),
            },
        }

    def stats(self) -> dict[str, Any]:
        return self.activity.dns_stats()

    @staticmethod
    def _euid() -> int:
        import os

        return os.geteuid()

    @staticmethod
    def _os_name() -> str:
        try:
            import os

            data = {}
            for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
                if "=" in line:
                    key, _, value = line.partition("=")
                    data[key] = value.strip('"')
            return data.get("PRETTY_NAME", platform.platform())
        except OSError:
            return platform.platform()


def _has_capability(bit: int) -> bool:
    try:
        with open("/proc/self/status", "r", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("CapEff:"):
                    return bool(int(line.split()[1], 16) & (1 << bit))
    except (OSError, ValueError, IndexError):
        pass
    return False


def _norm_set(values) -> set[str]:
    out = set()
    for value in values or []:
        norm = normalise(str(value))
        if norm:
            out.add(norm)
    return out


def _hit(domain: str, table: set[str]) -> bool:
    if not table:
        return False
    if domain in table:
        return True
    parts = domain.split(".")
    return any(".".join(parts[i:]) in table for i in range(1, len(parts)))
