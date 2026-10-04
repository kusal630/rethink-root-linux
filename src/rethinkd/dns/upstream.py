"""Upstream resolvers: system, plain UDP, DoT and DoH.

Everything returns the upstream's raw DNS response bytes; the query is relayed
untouched so the ID and EDNS options survive.
"""

from __future__ import annotations

import base64
import http.client
import re
import socket
import ssl
import struct
import threading
from pathlib import Path
from typing import Callable

_TYPES = ("system", "plain", "doh", "dot")
_LOCK = threading.Lock()


class UpstreamError(Exception):
    pass


def _is_loopback(host: str) -> bool:
    return host.startswith("127.") or host in ("::1", "0:0:0:0:0:0:0:1")


def system_nameservers(resolv_path: str = "/etc/resolv.conf") -> list[str]:
    servers: list[str] = []
    try:
        for line in Path(resolv_path).read_text(encoding="utf-8").splitlines():
            line = line.split("#", 1)[0].strip()
            if line.startswith("nameserver"):
                parts = line.split()
                if len(parts) > 1 and parts[1] not in servers:
                    servers.append(parts[1])
    except OSError:
        pass
    return servers


def _udp_exchange(server: str, port: int, query: bytes, timeout: float) -> bytes:
    family = socket.AF_INET6 if ":" in server and server.count(":") > 1 else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(query, (server, port))
        for _ in range(3):
            try:
                data, _ = sock.recvfrom(4096)
            except socket.timeout as exc:
                raise UpstreamError(f"timeout from {server}:{port}") from exc
            if len(data) >= 4 and data[:2] == query[:2]:
                return data
    raise UpstreamError(f"no matching reply from {server}:{port}")


def _tcp_exchange(server: str, port: int, query: bytes, timeout: float) -> bytes:
    family = socket.AF_INET6 if ":" in server and server.count(":") > 1 else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        sock.connect((server, port))
        sock.sendall(struct.pack("!H", len(query)) + query)
        header = _recv_exact(sock, 2)
        (length,) = struct.unpack("!H", header)
        return _recv_exact(sock, length)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise UpstreamError("connection closed")
        buf += chunk
    return buf


def _dot_exchange(host: str, port: int, query: bytes, timeout: float, server_name: str) -> bytes:
    context = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as raw:
        with context.wrap_socket(raw, server_hostname=server_name) as sock:
            sock.settimeout(timeout)
            sock.sendall(struct.pack("!H", len(query)) + query)
            (length,) = struct.unpack("!H", _recv_exact(sock, 2))
            return _recv_exact(sock, length)


def _doh_exchange(url: str, query: bytes, timeout: float) -> bytes:
    match = re.match(r"^https://([^/:]+)(?::(\d+))?(.*)$", url)
    if not match:
        raise UpstreamError(f"bad DoH url: {url}")
    host, port, path = match.group(1), int(match.group(2) or 443), match.group(3) or "/dns-query"
    conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ssl.create_default_context())
    try:
        conn.request(
            "POST",
            path,
            body=query,
            headers={
                "Content-Type": "application/dns-message",
                "Accept": "application/dns-message",
                "User-Agent": "rethinkd/0.1",
            },
        )
        resp = conn.getresponse()
        body = resp.read(64 * 1024)
        if resp.status != 200:
            raise UpstreamError(f"DoH {resp.status} from {host}")
        if len(body) < 12:
            raise UpstreamError("short DoH reply")
        return body
    finally:
        conn.close()


class Upstream:
    """Configured resolver. `configure()` swaps settings atomically."""

    def __init__(self) -> None:
        self._kind = "system"
        self._url = ""
        self._timeout = 5.0
        self._lock = _LOCK

    @property
    def kind(self) -> str:
        return self._kind

    @property
    def url(self) -> str:
        return self._url

    @property
    def endpoint(self) -> str:
        if self._kind == "system":
            servers = system_nameservers()
            return ", ".join(servers) if servers else "system default"
        if self._kind in ("doh", "dot"):
            return self._url
        return self._url or "system default"

    def configure(self, kind: str, url: str = "") -> None:
        if kind not in _TYPES:
            raise ValueError(f"unknown upstream type: {kind}")
        if kind in ("doh", "dot", "plain") and not url:
            raise ValueError(f"{kind} upstream needs a url")
        with self._lock:
            self._kind = kind
            self._url = url.strip()

    def resolve(self, query: bytes) -> bytes:
        with self._lock:
            kind, url = self._kind, self._url
        timeout = self._timeout
        if kind == "system":
            # loopback nameservers are excluded on purpose: when the DNS hijack is
            # active, a query that comes back through systemd-resolved would bounce
            # between us and the stub forever.
            servers = [s for s in system_nameservers() if not _is_loopback(s)]
            if not servers:
                servers = ["9.9.9.9", "149.112.112.112"]
            last: Exception | None = None
            for server in servers:
                try:
                    return _udp_exchange(server, 53, query, timeout)
                except Exception as exc:  # try the next resolver
                    last = exc
            raise UpstreamError(str(last or "no system resolver"))
        if kind == "plain":
            last = None
            for entry in url.replace(";", ",").split(","):
                entry = entry.strip()
                if not entry:
                    continue
                host, _, port = entry.partition(":")
                try:
                    return _udp_exchange(host, int(port or 53), query, timeout)
                except Exception as exc:
                    last = exc
            raise UpstreamError(str(last or "no plain resolver"))
        if kind == "doh":
            return _doh_exchange(url, query, timeout)
        # dot
        target = url
        if target.startswith("tls://"):
            target = target[6:]
        host, _, port = target.partition(":")
        return _dot_exchange(host, int(port or 853), query, timeout, server_name=host)


def doh_probe(url: str, timeout: float = 6.0) -> bool:
    """Cheap liveness check used by the settings screen."""
    query = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + b"\x07example\x03com\x00\x00\x01\x00\x01"
    try:
        return len(_doh_exchange(url, query, timeout)) >= 12
    except Exception:
        return False


def encode_base64url(query: bytes) -> str:
    return base64.urlsafe_b64encode(query).decode("ascii").rstrip("=")
