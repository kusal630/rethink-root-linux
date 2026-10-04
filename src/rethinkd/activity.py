"""In-memory activity: query log, per-minute stats, top blockers, event feed."""

from __future__ import annotations

import threading
import time
from collections import Counter, deque
from typing import Any

BUCKETS = 60  # one minute each → an hour of history


class Activity:
    def __init__(self, log_size: int = 500) -> None:
        self._lock = threading.Lock()
        self._log: deque[dict[str, Any]] = deque(maxlen=log_size)
        self._events: deque[dict[str, Any]] = deque(maxlen=600)
        self._buckets: deque[dict[str, int]] = deque(maxlen=BUCKETS)
        self._by_type: Counter[str] = Counter()
        self._top_blocked: Counter[str] = Counter()
        self._queries = 0
        self._blocked = 0
        self._dropped_packets = 0
        self._relayed = 0

    # -- writers ---------------------------------------------------------
    def dns_query(self, name: str, qtype_name: str, client: str, blocked: bool, reason: str | None) -> None:
        now = int(time.time())
        with self._lock:
            self._queries += 1
            self._by_type[qtype_name] += 1
            if blocked:
                self._blocked += 1
                key = name if len(name) < 90 else name[:87] + "…"
                self._top_blocked[key] += 1
            self._bucket(now, blocked)
            self._log.appendleft(
                {"t": now, "name": name, "type": qtype_name, "blocked": blocked, "reason": reason, "client": client}
            )
            self._events.appendleft(
                {
                    "t": now,
                    "kind": "dns",
                    "name": name,
                    "action": "blocked" if blocked else "allowed",
                    "reason": reason,
                    "uid": None,
                    "app": None,
                }
            )

    def firewall_event(self, uid: int, app: str, packets: int) -> None:
        if packets <= 0:
            return
        now = int(time.time())
        with self._lock:
            self._dropped_packets += packets
            self._events.appendleft(
                {
                    "t": now,
                    "kind": "firewall",
                    "name": app or f"uid {uid}",
                    "action": "blocked",
                    "reason": f"{packets} packets dropped",
                    "uid": uid,
                    "app": app,
                }
            )

    def proxy_event(self, endpoint: str, action: str) -> None:
        now = int(time.time())
        with self._lock:
            if action == "relayed":
                self._relayed += 1
            self._events.appendleft(
                {
                    "t": now,
                    "kind": "proxy",
                    "name": endpoint,
                    "action": action,
                    "reason": None,
                    "uid": None,
                    "app": None,
                }
            )

    def _bucket(self, now: int, blocked: bool) -> None:
        minute = now - (now % 60)
        if self._buckets and self._buckets[-1]["t"] == minute:
            bucket = self._buckets[-1]
        else:
            bucket = {"t": minute, "total": 0, "blocked": 0}
            self._buckets.append(bucket)
        bucket["total"] += 1
        if blocked:
            bucket["blocked"] += 1

    def clear_log(self) -> None:
        with self._lock:
            self._log.clear()

    # -- readers ---------------------------------------------------------
    def log(self, limit: int = 200) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._log)[: max(0, limit)]

    def events(self, limit: int = 200) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._events)[: max(0, limit)]

    def dns_stats(self) -> dict[str, Any]:
        with self._lock:
            total, blocked = self._queries, self._blocked
            series = list(self._buckets)
            top = [{"domain": d, "count": c} for d, c in self._top_blocked.most_common(10)]
            by_type = dict(self._by_type.most_common(8))
            last_hour = {"total": sum(b["total"] for b in series), "blocked": sum(b["blocked"] for b in series)}
        rate = round(100.0 * blocked / total, 1) if total else 0.0
        return {
            "queries": total,
            "blocked": blocked,
            "block_rate": rate,
            "series": series,
            "top_blocked": top,
            "by_type": by_type,
            "last_hour": last_hour,
        }

    def counters(self) -> dict[str, int]:
        with self._lock:
            return {
                "dropped_packets": self._dropped_packets,
                "relayed": self._relayed,
            }
