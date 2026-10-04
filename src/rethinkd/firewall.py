"""Root firewall: per-app rules, DNS hijack and proxy redirect via iptables.

All rules live in three dedicated chains (``RETHINK_APPS``, ``RETHINK_DNS``,
``RETHINK_PROXY``) jumped to from ``OUTPUT``, so applying or removing our rules
never touches anyone else's and is idempotent. Rule *generation* is pure
(string lists) so it can be unit-tested without root.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import threading
from collections import Counter
from typing import Any

from .config import Config

CHAIN_APPS = "RETHINK_APPS"
CHAIN_DNS = "RETHINK_DNS"
CHAIN_PROXY = "RETHINK_PROXY"
JUMP_COMMENT = "rethink-root"

# RFC1918 + link-local + multicast — never redirected to a proxy
PRIVATE_V4 = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "127.0.0.0/8", "224.0.0.0/4"]
PRIVATE_V6 = ["fc00::/7", "fe80::/10", "::1/128", "ff00::/8"]

_COMMENT_RE = re.compile(r"--comment rethink-app:(\d+)")


class FirewallError(RuntimeError):
    pass


# -- pure rule generation (unit-tested) ---------------------------------
def app_rules(policy: str, apps: dict[str, str], exempt_uid: int) -> list[list[str]]:
    rules: list[list[str]] = [
        ["-m", "comment", "--comment", "rethink-exempt", "-m", "owner", "--uid-owner", str(exempt_uid), "-j", "RETURN"]
    ]
    if policy == "block":
        for uid, action in sorted(apps.items()):
            if action == "allow":
                rules.append(
                    ["-m", "comment", "--comment", f"rethink-app:{uid}", "-m", "owner", "--uid-owner", uid, "-j", "RETURN"]
                )
        rules.append(["-m", "comment", "--comment", "rethink-default", "-j", "DROP"])
    else:
        for uid, action in sorted(apps.items()):
            if action == "block":
                rules.append(
                    ["-m", "comment", "--comment", f"rethink-app:{uid}", "-m", "owner", "--uid-owner", uid, "-j", "DROP"]
                )
    return rules


def dns_rules(port: int, exempt_uid: int) -> list[list[str]]:
    return [
        ["-m", "owner", "--uid-owner", str(exempt_uid), "-j", "RETURN"],
        ["-d", "127.0.0.0/8", "-j", "RETURN"],
        ["-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", str(port)],
        ["-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-ports", str(port)],
    ]


def proxy_rules(port: int, exempt_uid: int, bypass_lan: bool) -> list[list[str]]:
    rules: list[list[str]] = [
        ["-m", "owner", "--uid-owner", str(exempt_uid), "-j", "RETURN"],
        ["-o", "lo", "-j", "RETURN"],
    ]
    if bypass_lan:
        for net in PRIVATE_V4:
            rules.append(["-d", net, "-j", "RETURN"])
    rules.append(["-p", "tcp", "-j", "REDIRECT", "--to-ports", str(port)])
    return rules


# -- process / socket discovery ----------------------------------------
def _read_proc() -> tuple[dict[int, dict[str, Any]], dict[int, int]]:
    procs: dict[int, dict[str, Any]] = {}
    sockets: Counter[int] = Counter()
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        pid = int(entry)
        uid: int | None = None
        comm = ""
        try:
            with open(f"/proc/{entry}/status", "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    if line.startswith("Name:"):
                        comm = line.split(None, 1)[1].strip()
                    elif line.startswith("Uid:"):
                        uid = int(line.split()[1])
                    if uid is not None and comm:
                        break
        except (OSError, IndexError, ValueError):
            continue
        if uid is None:
            continue
        info = procs.setdefault(uid, {"comm": Counter(), "pids": 0, "exe": ""})
        info["comm"][comm] += 1
        info["pids"] += 1
        if not info["exe"]:
            try:
                info["exe"] = os.readlink(f"/proc/{entry}/exe")
            except OSError:
                pass

    for table in ("tcp", "tcp6", "udp", "udp6"):
        try:
            with open(f"/proc/net/{table}", "r", encoding="utf-8", errors="replace") as fh:
                next(fh, None)
                for line in fh:
                    parts = line.split()
                    if len(parts) > 8 and parts[3] != "07":  # skip TIME_WAIT-ish for tcp
                        try:
                            sockets[int(parts[7])] += 1
                        except ValueError:
                            pass
        except OSError:
            continue
    return procs, dict(sockets)


def discover_apps(policy: str, explicit: dict[str, str]) -> list[dict[str, Any]]:
    procs, sockets = _read_proc()
    uids = set(procs) | set(sockets) | {int(u) for u in explicit}
    uids.discard(0)
    uids.discard(65534)
    apps: list[dict[str, Any]] = []
    for uid in uids:
        info = procs.get(uid)
        name = ""
        exe = ""
        pids = 0
        if info:
            name = (info["comm"].most_common(1) or [("", 0)])[0][0]
            exe = info["exe"]
            pids = info["pids"]
        if not name:
            name = _uid_guess(uid)
        action = explicit.get(str(uid), policy)
        apps.append(
            {
                "uid": uid,
                "name": name,
                "exe": exe,
                "processes": pids,
                "conns": sockets.get(uid, 0),
                "action": action,
                "explicit": str(uid) in explicit,
            }
        )
    apps.sort(key=lambda a: (-a["conns"], -a["processes"], a["uid"]))
    return apps


def _uid_guess(uid: int) -> str:
    try:
        with open("/etc/passwd", "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                parts = line.split(":")
                if len(parts) > 2 and parts[2] == str(uid):
                    return parts[0]
    except OSError:
        pass
    return f"uid {uid}"


# -- executor -----------------------------------------------------------
class Firewall:
    def __init__(self, cfg: Config, dry_run: bool = False) -> None:
        self.cfg = cfg
        self.dry_run = dry_run
        self._lock = threading.Lock()
        self._last_error: str | None = None
        self._applied = False
        self.iptables = shutil.which("iptables") or "iptables"
        self.ip6tables = shutil.which("ip6tables") or "ip6tables"

    # availability -----------------------------------------------------
    @staticmethod
    def available() -> bool:
        """Root or CAP_NET_ADMIN (systemd AmbientCapabilities) to touch iptables."""
        if os.geteuid() == 0:
            return True
        cap_net_admin = 1 << 12  # linux/capability.h
        try:
            with open("/proc/self/status", "r", encoding="utf-8") as fh:
                for line in fh:
                    if line.startswith("CapEff:"):
                        return bool(int(line.split()[1], 16) & cap_net_admin)
        except (OSError, ValueError, IndexError):
            pass
        return False

    @property
    def last_error(self) -> str | None:
        return self._last_error

    @property
    def applied(self) -> bool:
        return self._applied

    # execution --------------------------------------------------------
    def _run(self, argv: list[str]) -> subprocess.CompletedProcess:
        if self.dry_run:
            return subprocess.CompletedProcess(argv, 0, "", "")
        return subprocess.run(argv, capture_output=True, text=True, timeout=20)

    def _run_all(self, argvs: list[list[str]]) -> list[list[str]]:
        executed: list[list[str]] = []
        for argv in argvs:
            result = self._run(argv)
            executed.append(argv)
            if result.returncode != 0 and not _ignorable(argv, result.stderr):
                self._last_error = (result.stderr or result.stdout).strip()
                raise FirewallError(" ".join(argv) + ": " + self._last_error)
        self._last_error = None
        return executed

    # chain plumbing ---------------------------------------------------
    @staticmethod
    def _chain_argv(binary: str, table: str) -> list[list[str]]:
        return [
            [binary, "-w", "-t", table, "-N", CHAIN_APPS],
            [binary, "-w", "-t", table, "-N", CHAIN_DNS],
            [binary, "-w", "-t", table, "-N", CHAIN_PROXY],
            [binary, "-w", "-t", table, "-F", CHAIN_APPS],
            [binary, "-w", "-t", table, "-F", CHAIN_DNS],
            [binary, "-w", "-t", table, "-F", CHAIN_PROXY],
        ]

    @staticmethod
    def _jump_argv(binary: str, table: str, chain: str) -> tuple[list[str], list[str]]:
        """(check, add-or-remove) pair for the OUTPUT jump into one of our chains."""
        check = [binary, "-w", "-t", table, "-C", "OUTPUT", "-m", "comment", "--comment", JUMP_COMMENT, "-j", chain]
        change = [binary, "-w", "-t", table, "-A", "OUTPUT", "-m", "comment", "--comment", JUMP_COMMENT, "-j", chain]
        return check, change

    def _set_jump(self, binary: str, table: str, chain: str, on: bool) -> list[list[str]]:
        check, change = self._jump_argv(binary, table, chain)
        executed: list[list[str]] = []
        if on:
            if self._run(check).returncode == 0:
                return executed  # jump already installed
            return self._run_all([change])
        # remove every copy (there should only ever be one)
        remove = change.copy()
        remove[remove.index("-A")] = "-D"
        for _ in range(4):
            if self._run(check).returncode != 0:
                break
            executed += self._run_all([remove])
        return executed

    # public API -------------------------------------------------------
    def apply(self) -> list[list[str]]:
        """(Re)install every rule from the current config. Returns argvs run."""
        with self._lock:
            executed: list[list[str]] = []
            own_uid = os.geteuid()
            conf = self.cfg.data
            protected = bool(conf.get("protected", True))

            # always (re)build chains so a flush/reload is clean
            for binary in (self.iptables, self.ip6tables):
                executed += self._run_all(self._chain_argv(binary, "filter"))

            if not protected or not conf["firewall"].get("enabled", True):
                executed += self._remove_jumps()
                self._applied = False
                return executed

            # filter: per-app
            rules = app_rules(conf["firewall"].get("policy", "allow"), conf["firewall"].get("apps", {}), own_uid)
            for binary in (self.iptables, self.ip6tables):
                for rule in rules:
                    executed += self._run_all([[binary, "-w", "-t", "filter", "-A", CHAIN_APPS, *rule]])
                executed += self._set_jump(binary, "filter", CHAIN_APPS, True)

            # nat: DNS hijack + proxy redirect (IPv4 and IPv6)
            dns_port = _listen_port(conf["dns"].get("listen", []), 5300)
            if conf["dns"].get("hijack", True):
                for binary in (self.iptables, self.ip6tables):
                    for rule in dns_rules(dns_port, own_uid):
                        executed += self._run_all([[binary, "-w", "-t", "nat", "-A", CHAIN_DNS, *rule]])
                    executed += self._set_jump(binary, "nat", CHAIN_DNS, True)
            else:
                for binary in (self.iptables, self.ip6tables):
                    executed += self._set_jump(binary, "nat", CHAIN_DNS, False)

            proxy = conf.get("proxy", {})
            if proxy.get("enabled") and proxy.get("port"):
                for binary in (self.iptables, self.ip6tables):
                    for rule in proxy_rules(int(proxy["port"]), own_uid, bool(proxy.get("bypass_lan", True))):
                        executed += self._run_all([[binary, "-w", "-t", "nat", "-A", CHAIN_PROXY, *rule]])
                    executed += self._set_jump(binary, "nat", CHAIN_PROXY, True)
            else:
                for binary in (self.iptables, self.ip6tables):
                    executed += self._set_jump(binary, "nat", CHAIN_PROXY, False)

            self._applied = True
            return executed

    def _remove_jumps(self) -> list[list[str]]:
        executed: list[list[str]] = []
        for binary in (self.iptables, self.ip6tables):
            for table, chain in (("filter", CHAIN_APPS), ("nat", CHAIN_DNS), ("nat", CHAIN_PROXY)):
                executed += self._set_jump(binary, table, chain, False)
        return executed

    def clear(self) -> list[list[str]]:
        """Remove our jumps and flush our chains (protection off)."""
        with self._lock:
            executed = self._remove_jumps()
            for binary in (self.iptables, self.ip6tables):
                for table, chain in (("filter", CHAIN_APPS), ("nat", CHAIN_DNS), ("nat", CHAIN_PROXY)):
                    try:
                        executed += self._run_all([[binary, "-w", "-t", table, "-F", chain]])
                    except FirewallError:
                        pass
            self._applied = False
            return executed

    # counters ---------------------------------------------------------
    def counters(self) -> dict[int, dict[str, int]]:
        """Per-uid packet/byte counters from the installed chain."""
        out: dict[int, dict[str, int]] = {}
        if self.dry_run:
            return out
        for table, chain in (("filter", CHAIN_APPS),):
            result = self._run([self.iptables, "-w", "-t", table, "-L", chain, "-vnx"])
            for line in (result.stdout or "").splitlines():
                match = _COMMENT_RE.search(line)
                if not match:
                    continue
                parts = line.split()
                try:
                    pkts, bytes_ = int(parts[0]), int(parts[1])
                except (ValueError, IndexError):
                    continue
                out[int(match.group(1))] = {"packets": pkts, "bytes": bytes_}
        return out

    def status(self) -> dict[str, Any]:
        return {"enabled": self._applied, "error": self._last_error, "dry_run": self.dry_run}


def _ignorable(argv: list[str], stderr: str) -> bool:
    text = (stderr or "").lower()
    if "-n" in argv and "chain already exists" in text:
        return True
    if "-d" in argv and ("does a jump to chain" in text or "no such file" in text):
        return True
    if ("-C" in argv and "bad rule" in text) or ("-C" in argv and "no such file" in text):
        return True
    if ("-D" in argv and ("no such file" in text or "bad rule" in text or "not found" in text)):
        return True
    if "-F" in argv and "no chain" in text:
        return True
    if "-N" in argv and "chain already exists" in text:
        return True
    return False


def _listen_port(listen: list[str], default: int) -> int:
    for endpoint in listen:
        try:
            return int(str(endpoint).rsplit(":", 1)[1])
        except (IndexError, ValueError):
            continue
    return default
