"""The DNS server: UDP + TCP listeners, block decision, upstream forwarding."""

from __future__ import annotations

import socket
import struct
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Callable

from . import wire

QueryHook = Callable[[str, int, str, bool, str | None], None]
Matcher = Callable[[str], str | None]


class DNSServer:
    def __init__(
        self,
        listen: list[str],
        upstream,
        matcher: Matcher,
        on_query: QueryHook,
        block_mode: str = "sinkhole",
    ) -> None:
        self._endpoints = [self._parse(ep) for ep in listen]
        self._upstream = upstream
        self._matcher = matcher
        self._on_query = on_query
        self._block_mode = block_mode
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._sockets: list[socket.socket] = []
        self._pool = ThreadPoolExecutor(max_workers=48, thread_name_prefix="dns")
        self._udp: dict[socket.socket, tuple[str, int]] = {}

    @staticmethod
    def _parse(endpoint: str) -> tuple[str, int]:
        host, _, port = endpoint.rpartition(":")
        return (host or "127.0.0.1"), int(port)

    # -- lifecycle -------------------------------------------------------
    def start(self) -> None:
        for host, port in self._endpoints:
            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            udp.bind((host, port))
            udp.settimeout(0.5)
            self._sockets.append(udp)
            self._udp[udp] = (host, port)

            tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            tcp.bind((host, port))
            tcp.listen(64)
            tcp.settimeout(0.5)
            self._sockets.append(tcp)

            threading.Thread(target=self._udp_loop, args=(udp,), daemon=True, name=f"dns-udp:{port}").start()
            threading.Thread(target=self._tcp_loop, args=(tcp,), daemon=True, name=f"dns-tcp:{port}").start()
        self._threads = []

    def stop(self) -> None:
        self._stop.set()
        for sock in self._sockets:
            try:
                sock.close()
            except OSError:
                pass
        self._sockets.clear()
        self._pool.shutdown(wait=False, cancel_futures=True)

    @property
    def endpoints(self) -> list[str]:
        return [f"{h}:{p}" for h, p in self._endpoints]

    # -- loops -----------------------------------------------------------
    def _udp_loop(self, sock: socket.socket) -> None:
        while not self._stop.is_set():
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                return
            if data:
                self._pool.submit(self._handle_udp, data, addr, sock)

    def _handle_udp(self, data: bytes, addr: tuple[str, int], sock: socket.socket) -> None:
        try:
            reply = self.handle(data, f"{addr[0]}:{addr[1]}")
        except Exception:
            return
        if reply:
            try:
                sock.sendto(reply, addr)  # OSError covers an already-closed socket
            except OSError:
                pass

    def _tcp_loop(self, listener: socket.socket) -> None:
        while not self._stop.is_set():
            try:
                conn, addr = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            self._pool.submit(self._handle_tcp, conn, addr)

    def _handle_tcp(self, conn: socket.socket, addr: tuple[str, int]) -> None:
        try:
            conn.settimeout(8)
            header = self._recv(conn, 2)
            if not header:
                return
            (length,) = struct.unpack("!H", header)
            if length > 65535:
                return
            query = self._recv(conn, length)
            if not query:
                return
            reply = self.handle(query, f"{addr[0]}:{addr[1]}")
            if reply:
                conn.sendall(struct.pack("!H", len(reply)) + reply)
        except (OSError, struct.error):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    @staticmethod
    def _recv(sock: socket.socket, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                break
            buf += chunk
        return buf

    # -- one query -------------------------------------------------------
    def handle(self, query: bytes, client: str) -> bytes | None:
        try:
            _ident, _flags, questions, _end = wire.parse_query(query)
        except wire.DNSError:
            return None
        name, qtype, _qclass = questions[0]
        reason = None
        try:
            reason = self._matcher(name)
        except Exception:
            reason = None

        if reason is not None:
            self._emit(name, qtype, client, True, reason)
            return wire.build_reply(query, self._block_mode)

        try:
            reply = self._upstream.resolve(query)
        except Exception:
            self._emit(name, qtype, client, False, None)
            return wire.build_reply(query, "servfail")
        self._emit(name, qtype, client, False, None)
        return reply

    def _emit(self, name: str, qtype: int, client: str, blocked: bool, reason: str | None) -> None:
        try:
            self._on_query(name, qtype, client, blocked, reason)
        except Exception:
            pass
