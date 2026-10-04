"""Blocklists: built-in categories, custom URL lists, per-domain overrides.

Formats understood for a downloaded list: hosts, plain domains, dnsmasq and
Adblock-style ``||domain^`` rules. Everything normalises into one set of
domains; a query is matched by walking from the full name up to the TLD, so a
rule for ``ads.example.com`` also covers ``a.b.ads.example.com``.
"""

from __future__ import annotations

import re
import threading
import urllib.request
from pathlib import Path
from typing import Any

CATEGORIES: list[dict[str, Any]] = [
    {
        "id": "ads",
        "name": "Ads",
        "default": True,
        "format": "hosts",
        "source": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    },
    {
        "id": "malware",
        "name": "Malware & phishing",
        "default": True,
        "format": "domains",
        "source": "https://raw.githubusercontent.com/Spam404/lists/master/main-blacklist.txt",
    },
    {
        "id": "tracking",
        "name": "Trackers & telemetry",
        "default": True,
        "format": "adblock",
        "source": "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/tracking_servers.txt",
    },
    {
        "id": "social",
        "name": "Social media",
        "default": False,
        "format": "hosts",
        "source": "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/social-only/hosts",
    },
    {
        "id": "gambling",
        "name": "Gambling",
        "default": False,
        "format": "hosts",
        "source": "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling-only/hosts",
    },
    {
        "id": "adult",
        "name": "Adult content",
        "default": False,
        "format": "hosts",
        "source": "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn-only/hosts",
    },
    {
        "id": "crypto",
        "name": "Crypto miners",
        "default": False,
        "format": "adblock",
        "source": "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/cryptominers.txt",
    },
]

# Small always-on seed so a fresh install blocks the obvious trackers even
# before the first list download (works offline).
BUILTIN: set[str] = {
    "doubleclick.net",
    "googleadservices.com",
    "googlesyndication.com",
    "google-analytics.com",
    "adservice.google.com",
    "pagead2.googlesyndication.com",
    "adnxs.com",
    "scorecardresearch.com",
    "quantserve.com",
    "criteo.com",
    "criteo.net",
    "moatads.com",
    "amazon-adsystem.com",
    "taboola.com",
    "outbrain.com",
    "connect.facebook.net",
    "bat.bing.com",
    "hotjar.com",
    "mixpanel.com",
    "amplitude.com",
    "segment.io",
    "branch.io",
    "appsflyer.com",
    "adjust.com",
    "app-measurement.com",
    "crashlytics.com",
    "sentry.io",
    "telemetry.microsoft.com",
    "data.microsoft.com",
    "arc.msn.com",
    "v10.events.data.microsoft.com",
    "telemetry.mozilla.org",
    "telemetry.reddit.com",
    "ads.yahoo.com",
    "advertising.com",
    "openx.net",
    "pubmatic.com",
    "rubiconproject.com",
    "casalemedia.com",
    "smartadserver.com",
    "yandex.ru",
    "mc.yandex.ru",
}

_ADBLOCK_RE = re.compile(r"^\|\|([a-z0-9.-]+)\^")
_SERVER_RE = re.compile(r"^(?:server|address)=/([^/]+)/")

# hosts files that are not real block entries
_HOST_ALIASES = {
    "localhost", "localhost.localdomain", "local", "broadcasthost",
    "ip6-localhost", "ip6-loopback", "ip6-localnet", "ip6-mcastprefix",
    "ip6-allnodes", "ip6-allrouters", "ip6-allhosts", "0.0.0.0",
}


def normalise(domain: str) -> str | None:
    """Canonical lowercase domain, or None when the line carries no domain."""
    d = domain.strip().lower()
    if not d or d.startswith(("#", "!", "[", "/")):
        return None
    if " " in d or "\t" in d:  # hosts line: "0.0.0.0 ads.example.com"
        parts = d.split()
        d = parts[1] if len(parts) > 1 and _looks_ip(parts[0]) else parts[0]
    d = d.strip(".")
    for prefix in ("||", "*.", "0.0.0.0 ", "127.0.0.1 ", "address=/", "server=/"):
        if d.startswith(prefix):
            d = d[len(prefix) :]
    d = d.rstrip("^").rstrip("/")
    d = d.split("$")[0].split("|")[0].strip(".")
    if not d or "/" in d or "=" in d or "*" in d or len(d) > 253:
        return None
    if not re.fullmatch(r"[a-z0-9.-]+", d) or ".." in d:
        return None
    return d


def parse_list(text: str, fmt: str = "domains") -> set[str]:
    out: set[str] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line[0] in "#![":
            continue
        if line.startswith("@@"):  # adblock exception — not honoured, skipped
            continue
        domain: str | None = None
        if fmt == "hosts":
            parts = line.split()
            if len(parts) >= 2 and _looks_ip(parts[0]):
                domain = parts[1]
            elif len(parts) == 1:
                domain = parts[0]
        elif fmt == "adblock":
            m = _ADBLOCK_RE.match(line)
            domain = m.group(1) if m else (line if "." in line and "|" not in line else None)
        elif fmt == "dnsmasq":
            m = _SERVER_RE.match(line)
            domain = m.group(1) if m else None
        else:  # plain domain list
            domain = line
        if domain:
            norm = normalise(domain)
            if norm and norm not in _HOST_ALIASES:
                out.add(norm)
    return out


def _looks_ip(token: str) -> bool:
    return token[0].isdigit() and (":" in token or token.count(".") == 3)


class BlocklistManager:
    """Holds every active domain set and answers "is this name blocked?"."""

    def __init__(self, cache_dir: Path) -> None:
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._categories: dict[str, set[str]] = {}
        self._custom: dict[str, set[str]] = {}  # id -> domains
        self._meta: dict[str, dict[str, Any]] = {}  # id -> {"count", "last_error", "url"}
        self._enabled_categories: set[str] = set()
        self._enabled_custom: set[str] = set()
        self._domain_block: set[str] = set()
        self._domain_allow: set[str] = set()
        self._builtin: set[str] = set(BUILTIN)

    # -- loading ---------------------------------------------------------
    def load_cache(self) -> None:
        """Read previously downloaded lists from disk (no network)."""
        with self._lock:
            for cat in CATEGORIES:
                path = self.cache_dir / f"{cat['id']}.txt"
                if path.exists():
                    try:
                        self._categories[cat["id"]] = parse_list(
                            path.read_text(encoding="utf-8", errors="replace"), cat["format"]
                        )
                    except OSError as exc:
                        self._meta[cat["id"]] = {"count": 0, "last_error": str(exc), "url": cat["source"]}
            for path in sorted(self.cache_dir.glob("custom-*.txt")):
                cid = path.stem[len("custom-") :]
                try:
                    self._custom[cid] = parse_list(
                        path.read_text(encoding="utf-8", errors="replace"), "domains"
                    )
                except OSError:
                    self._custom.setdefault(cid, set())

    def configure(
        self,
        categories: dict[str, bool],
        custom: list[dict[str, Any]],
        domain_block: list[str],
        domain_allow: list[str],
    ) -> None:
        with self._lock:
            self._enabled_categories = {k for k, v in categories.items() if v}
            self._enabled_custom = {c["id"] for c in custom if c.get("enabled", True)}
            for entry in custom:
                cid = entry["id"]
                self._meta.setdefault(cid, {})
                self._meta[cid]["url"] = entry.get("url", "")
            self._domain_block = {d for d in (normalise(x) or "" for x in domain_block) if d}
            self._domain_allow = {d for d in (normalise(x) or "" for x in domain_allow) if d}

    # -- refresh ---------------------------------------------------------
    def fetch(self, url: str, fmt: str = "domains", timeout: float = 25.0) -> str:
        req = urllib.request.Request(url, headers={"User-Agent": "rethinkd/0.1"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (user-supplied URL)
            raw = resp.read(32 * 1024 * 1024)
        return raw.decode("utf-8", "replace")

    def refresh_category(self, cat_id: str) -> dict[str, Any]:
        cat = next((c for c in CATEGORIES if c["id"] == cat_id), None)
        if cat is None:
            raise KeyError(cat_id)
        result = {"id": cat_id, "count": 0, "last_error": None}
        try:
            text = self.fetch(cat["source"], cat["format"])
            domains = parse_list(text, cat["format"])
            path = self.cache_dir / f"{cat_id}.txt"
            path.write_text(text, encoding="utf-8")
            with self._lock:
                self._categories[cat_id] = domains
                self._meta[cat_id] = {
                    "count": len(domains),
                    "last_error": None,
                    "url": cat["source"],
                }
            result["count"] = len(domains)
        except Exception as exc:  # network/parse errors must never kill the daemon
            result["last_error"] = str(exc)
            with self._lock:
                meta = self._meta.setdefault(cat_id, {"count": 0, "url": cat["source"]})
                meta["last_error"] = str(exc)
                result["count"] = meta.get("count", 0)
        return result

    def refresh_custom(self, cid: str, url: str) -> dict[str, Any]:
        result = {"id": cid, "count": 0, "last_error": None}
        try:
            text = self.fetch(url)
            domains = parse_list(text, "domains")
            (self.cache_dir / f"custom-{cid}.txt").write_text(text, encoding="utf-8")
            with self._lock:
                self._custom[cid] = domains
                self._meta[cid] = {"count": len(domains), "last_error": None, "url": url}
            result["count"] = len(domains)
        except Exception as exc:
            result["last_error"] = str(exc)
            with self._lock:
                meta = self._meta.setdefault(cid, {"count": 0, "url": url})
                meta["last_error"] = str(exc)
                result["count"] = meta.get("count", 0)
        return result

    def remove_custom(self, cid: str) -> None:
        with self._lock:
            self._custom.pop(cid, None)
            self._meta.pop(cid, None)
            self._enabled_custom.discard(cid)
        path = self.cache_dir / f"custom-{cid}.txt"
        if path.exists():
            path.unlink()

    def set_enabled(self, item_id: str, enabled: bool) -> None:
        with self._lock:
            if any(c["id"] == item_id for c in CATEGORIES):
                if enabled:
                    self._enabled_categories.add(item_id)
                else:
                    self._enabled_categories.discard(item_id)
            else:
                if enabled:
                    self._enabled_custom.add(item_id)
                else:
                    self._enabled_custom.discard(item_id)

    # -- matching --------------------------------------------------------
    def check(self, name: str) -> str | None:
        """Return the reason a name is blocked, or None to allow it."""
        d = normalise(name) if name else None
        if not d:
            return None
        with self._lock:
            if d in self._domain_allow or _walk_hit(d, self._domain_allow):
                return None
            if d in self._domain_block or _walk_hit(d, self._domain_block):
                return "domain:block"
            if _walk_hit(d, self._builtin):
                return "builtin"
            for cid in self._enabled_categories:
                if _walk_hit(d, self._categories.get(cid, ())):
                    return f"category:{cid}"
            for cid in self._enabled_custom:
                if _walk_hit(d, self._custom.get(cid, ())):
                    url = self._meta.get(cid, {}).get("url", cid)
                    return f"custom:{url}"
        return None

    def stats(self) -> dict[str, Any]:
        with self._lock:
            categories = []
            for cat in CATEGORIES:
                meta = self._meta.get(cat["id"], {})
                categories.append(
                    {
                        "id": cat["id"],
                        "name": cat["name"],
                        "source": cat["source"],
                        "enabled": cat["id"] in self._enabled_categories,
                        "domains": meta.get("count", len(self._categories.get(cat["id"], ()))),
                        "last_error": meta.get("last_error"),
                        "builtin": True,
                    }
                )
            custom = [
                {
                    "id": cid,
                    "url": self._meta.get(cid, {}).get("url", ""),
                    "enabled": cid in self._enabled_custom,
                    "domains": self._meta.get(cid, {}).get("count", len(self._custom.get(cid, ()))),
                    "last_error": self._meta.get(cid, {}).get("last_error"),
                }
                for cid in sorted(set(self._custom) | self._enabled_custom)
            ]
            enabled_total = len(self._builtin)
            for cid in self._enabled_categories:
                enabled_total += len(self._categories.get(cid, ()))
            for cid in self._enabled_custom:
                enabled_total += len(self._custom.get(cid, ()))
            return {"categories": categories, "custom": custom, "totals": {"domains": enabled_total,
                    "enabled": len(self._enabled_categories) + len(self._enabled_custom) + 1}}


def _walk_hit(name: str, table: Any) -> bool:
    """True when name or any parent domain is in table (a set)."""
    if not table:
        return False
    if name in table:
        return True
    parts = name.split(".")
    for i in range(1, len(parts)):
        if ".".join(parts[i:]) in table:
            return True
    return False
