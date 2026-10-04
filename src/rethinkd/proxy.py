"""Transparent TCP proxy: nat-REDIRECT'd sockets → HTTP CONNECT / SOCKS5.

UDP (and therefore QUIC) is not proxied — it goes direct, which is also why the
LAN is bypassed: a redirected TCP connection to 192.168.1.10 would be pointless.
Connections are classified by destination IP (LAN) and, when TLS, by the SNI in
the ClientHello, so ``bypass_domains`` works for HTTPS.
"""

from __future__ import annotations

import base64
import socket
import struct
import time
import threading
from typing import Any, Callable

SO_ORIGINAL_DST = 80
SOL_IPV6 = 41
PROXY_BUFSIZE = 64 * 1024


class ProxyError(Exception):
    pass


def original_dst(conn: socket.socket) -> tuple[str, int]:
    """The (ip, port) the client was trying to reach, before REDIRECT."""
    try:
        raw = conn.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
        port = struct.unpack("!H", raw[2:4])[0]
        return socket.inet_ntoa(raw[4:8]), port
    except OSError:
        raw = conn.getsockopt(SOL_IPV6, SO_ORIGINAL_DST, 28)
        port = struct.unpack("!H", raw[2:4])[0]
        addr = socket.inet_ntop(socket.AF_INET6, raw[8:24])
        return addr, port


def _is_lan(ip: str) -> bool:
    if ip in ("::1", "localhost"):
        return True
    if ":" in ip:  # IPv6: link-local / unique-local
        return ip.startswith(("fe80", "fc", "fd", "ff"))
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    a, b = int(parts[0]), int(parts[1])
    return (
        a == 10
        or a == 127
        or a == 0
        or (a == 172 and 16 <= b <= 31)
        or (a == 192 and b == 168)
        or (a == 169 and b == 254)
        or a >= 224
    )


def peek_sni(head: bytes) -> str | None:
    """Extract the SNI hostname from a TLS ClientHello, or None."""
    try:
        if len(head) < 5 or head[0] != 0x16:  # handshake
            return None
        record_len = struct.unpack("!H", head[3:5])[0]
        body = head[5 : 5 + record_len]
        if not body or body[0] != 0x01:  # client_hello
            return None
        pos = 4  # handshake type + length already checked
        pos += 2  # client version
        pos += 32  # random
        session_id_len = body[pos]
        pos += 1 + session_id_len
        cipher_len = struct.unpack("!H", body[pos : pos + 2])[0]
        pos += 2 + cipher_len
        comp_len = body[pos]
        pos += 1 + comp_len
        if pos + 2 > len(body):
            return None
        ext_total = struct.unpack("!H", body[pos : pos + 2])[0]
        pos += 2
        end = pos + ext_total
        while pos + 4 <= end and pos + 4 <= len(body):
            ext_type, ext_len = struct.unpack("!HH", body[pos : pos + 4])
            pos += 4
            if ext_type == 0:  # server_name
                if pos + 2 > len(body):
                    return None
                list_len = struct.unpack("!H", body[pos : pos + 2])[0]
                p = pos + 2
                limit = min(p + list_len, len(body))
                while p + 3 <= limit:
                    name_type = body[p]
                    name_len = struct.unpack("!H", body[p + 1 : p + 3])[0]
                    p += 3
                    if name_type == 0:
                        return body[p : p + name_len].decode("idna", "ignore").lower()
                    p += name_len
                return None
            pos += ext_len
    except (struct.error, IndexError, ValueError, UnicodeError):
        return None
    return None


def _domain_matches(hostname: str, patterns: list[str]) -> bool:
    host = hostname.lower().lstrip(".")
    for pattern in patterns:
        p = pattern.strip().lower().lstrip("*.")
        if p and (host == p or host.endswith("." + p)):
            return True
    return False


class TransparentProxy:
    def __init__(
        self,
        cfg,  # Config
        activity,
        on_change: Callable[[], None] | None = None,
    ) -> None:
        self.cfg = cfg
        self.activity = activity
        self.on_change = on_change
        self._server: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self.active = 0
        self.relayed = 0
        self.bypassed = 0
        self.last_error: str | None = None
        self._port = 0

    # -- lifecycle -------------------------------------------------------
    @property
    def port(self) -> int:
        return self._port

    def start(self, port: int) -> None:
        self.stop()
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        deadline = time.time() + 2.0
        while True:  # the previous accept-loop may release the port a tick later
            try:
                listener.bind(("127.0.0.1", port))
                break
            except OSError:
                if time.time() > deadline:
                    listener.close()
                    raise
                time.sleep(0.05)
        listener.listen(256)
        listener.settimeout(0.5)
        self._server = listener
        self._port = port
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="proxy")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        server, self._server = self._server, None
        if server:
            try:
                server.shutdown(socket.SHUT_RDWR)  # wake a blocked accept()
            except OSError:
                pass
            try:
                server.close()
            except OSError:
                pass
        thread, self._thread = self._thread, None
        if thread and thread is not threading.current_thread():
            thread.join(timeout=2.0)

    def status(self) -> dict[str, Any]:
        with self._lock:
            return {"active": self.active, "relayed": self.relayed, "bypassed": self.bypassed,
                    "last_error": self.last_error, "port": self._port}

    # -- main loop -------------------------------------------------------
    def _loop(self) -> None:
        server = self._server
        if not server:
            return
        while not self._stop.is_set():
            try:
                conn, _ = server.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            thread = threading.Thread(target=self._serve, args=(conn,), daemon=True)
            thread.start()

    def _serve(self, client: socket.socket) -> None:
        upstream_sock: socket.socket | None = None
        try:
            client.settimeout(20)
            dst_ip, dst_port = original_dst(client)
            head = self._peek(client)
            sni = peek_sni(head) if head else None
            proxy = self.cfg.get("proxy", {})
            bypass_lan = bool(proxy.get("bypass_lan", True))
            bypass_domains = list(proxy.get("bypass_domains", []) or [])

            direct = (bypass_lan and _is_lan(dst_ip)) or (
                bool(bypass_domains) and sni and _domain_matches(sni, bypass_domains)
            ) or (not proxy.get("enabled"))
            if direct:
                self.bypassed += 1
                upstream_sock = self._dial_direct(dst_ip, dst_port)
            else:
                upstream_sock = self._dial_via_proxy(proxy, dst_ip, dst_port)
                self.relayed += 1
                self.activity.proxy_event(f"{dst_ip}:{dst_port}", "relayed")
            with self._lock:
                self.active += 1
            self._relay(client, upstream_sock)
        except Exception as exc:  # one bad connection must not kill the proxy
            self.last_error = str(exc)[:200]
        finally:
            with self._lock:
                self.active = max(0, self.active - 1)
            for sock in (client, upstream_sock):
                if sock:
                    try:
                        sock.close()
                    except OSError:
                        pass

    @staticmethod
    def _peek(client: socket.socket, n: int = 2048) -> bytes:
        """Read the first bytes without consuming what the relay will forward."""
        try:
            client.settimeout(5)
            head = client.recv(n, socket.MSG_PEEK)
            return head or b""
        except OSError:
            return b""

    # -- upstream dial ---------------------------------------------------
    def _dial_direct(self, ip: str, port: int) -> socket.socket:
        return socket.create_connection((ip, port), timeout=15)

    def _dial_via_proxy(self, proxy: dict[str, Any], ip: str, port: int) -> socket.socket:
        host = str(proxy.get("host") or "")
        pport = int(proxy.get("port") or 0)
        if not host or not pport:
            raise ProxyError("proxy is enabled but host/port is not set")
        sock = socket.create_connection((host, pport), timeout=15)
        sock.settimeout(20)
        kind = proxy.get("type", "http")
        if kind == "socks5":
            self._socks5_handshake(sock, ip, port, proxy)
        else:
            self._http_handshake(sock, ip, port, proxy)
        return sock

    @staticmethod
    def _http_handshake(sock: socket.socket, ip: str, port: int, proxy: dict[str, Any]) -> None:
        lines = [f"CONNECT {ip}:{port} HTTP/1.1", f"Host: {ip}:{port}"]
        user = proxy.get("username") or ""
        if user:
            token = base64.b64encode(f"{user}:{proxy.get('password') or ''}".encode()).decode()
            lines.append(f"Proxy-Authorization: Basic {token}")
        sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
        response = b""
        while b"\r\n\r\n" not in response and len(response) < 8192:
            chunk = sock.recv(1024)
            if not chunk:
                raise ProxyError("proxy closed during CONNECT")
            response += chunk
        status = response.split(b" ", 2)
        if len(status) < 2 or status[1] != b"200":
            raise ProxyError(f"proxy refused CONNECT ({status[1].decode(errors='replace') if len(status) > 1 else '?'})")

    @staticmethod
    def _socks5_handshake(sock: socket.socket, ip: str, port: int, proxy: dict[str, Any]) -> None:
        user = proxy.get("username") or ""
        methods = b"\x05\x02\x00\x02" if user else b"\x05\x01\x00"
        sock.sendall(methods)
        choice = sock.recv(2)
        if len(choice) != 2 or choice[0] != 5:
            raise ProxyError("bad SOCKS5 greeting")
        if choice[1] == 2:  # username/password
            cred = proxy.get("password") or ""
            sock.sendall(b"\x01" + bytes([len(user)]) + user.encode() + bytes([len(cred)]) + cred.encode())
            reply = sock.recv(2)
            if len(reply) != 2 or reply[1] != 0:
                raise ProxyError("SOCKS5 auth failed")
        elif choice[1] != 0:
            raise ProxyError("SOCKS5 method rejected")
        try:
            packed = socket.inet_aton(ip)
            addr = b"\x01" + packed
        except OSError:
            addr = b"\x04" + socket.inet_pton(socket.AF_INET6, ip)
        sock.sendall(b"\x05\x01\x00" + addr + struct.pack("!H", port))
        head = sock.recv(4)
        if len(head) < 4 or head[1] != 0:
            raise ProxyError(f"SOCKS5 connect failed ({head[1] if len(head) > 1 else 'short reply'})")
        skip = {1: 4 + 2, 3: 1 + sock.recv(1)[0] + 2, 4: 16 + 2}.get(head[3])
        if skip:
            remaining = skip - (len(head) - 4)
            while remaining > 0:
                chunk = sock.recv(min(remaining, 1024))
                if not chunk:
                    break
                remaining -= len(chunk)

    # -- relay -----------------------------------------------------------
    @staticmethod
    def _relay(client: socket.socket, upstream: socket.socket) -> None:
        client.setblocking(True)
        upstream.setblocking(True)
        errors: list[BaseException] = []

        def pump(src: socket.socket, dst: socket.socket) -> None:
            try:
                while True:
                    data = src.recv(PROXY_BUFSIZE)
                    if not data:
                        break
                    dst.sendall(data)
            except OSError as exc:
                errors.append(exc)
            finally:
                try:
                    dst.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

        threads = [
            threading.Thread(target=pump, args=(client, upstream), daemon=True),
            threading.Thread(target=pump, args=(upstream, client), daemon=True),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=300)
