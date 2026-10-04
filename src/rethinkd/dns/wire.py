"""Minimal DNS wire format support: parse questions, build sinkhole/NXDOMAIN replies.

Anything that has to be *forwarded* is relayed byte-for-byte — this module only
needs to read the question section (for logging, stats and block decisions) and
to synthesise a reply for a query we refuse to resolve.
"""

from __future__ import annotations

import ipaddress
import struct

# qtype <-> name, the ones a resolver actually sees in the wild
TYPES: dict[int, str] = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    35: "NAPTR",
    41: "OPT",
    43: "DS",
    46: "RRSIG",
    47: "NSEC",
    48: "DNSKEY",
    50: "NSEC3",
    52: "TLSA",
    64: "SVCB",
    65: "HTTPS",
    99: "SPF",
    252: "AXFR",
    255: "ANY",
    257: "CAA",
}
TYPE_IDS: dict[str, int] = {name: num for num, name in TYPES.items()}


class DNSError(Exception):
    pass


def read_name(data: bytes, offset: int, depth: int = 0) -> tuple[str, int]:
    """Decode a (possibly compressed) name. Returns (lowercase, next offset)."""
    if depth > 20:
        raise DNSError("compression pointer loop")
    labels: list[str] = []
    jumped = False
    end = offset
    while True:
        if offset >= len(data):
            raise DNSError("truncated name")
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise DNSError("truncated pointer")
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                end = offset + 2
            jumped = True
            offset = pointer
            depth += 1
            continue
        if length & 0xC0:
            raise DNSError("bad label length")
        offset += 1
        if offset + length > len(data):
            raise DNSError("truncated label")
        labels.append(data[offset : offset + length].decode("utf-8", "replace"))
        offset += length
        if not jumped:
            end = offset
    return ".".join(labels).lower(), (end if jumped else offset)


def parse_query(data: bytes) -> tuple[int, int, list[tuple[str, int, int]], int]:
    """Parse a query message.

    Returns (id, flags, questions, offset_past_questions) where each question is
    (name, qtype, qclass).
    """
    if len(data) < 12:
        raise DNSError("short header")
    ident, flags, qd, _an, _ns, _ar = struct.unpack("!HHHHHH", data[:12])
    if not qd:
        raise DNSError("no question")
    offset = 12
    questions: list[tuple[str, int, int]] = []
    for _ in range(qd):
        name, offset = read_name(data, offset)
        if offset + 4 > len(data):
            raise DNSError("truncated question")
        qtype, qclass = struct.unpack("!HH", data[offset : offset + 4])
        offset += 4
        questions.append((name, qtype, qclass))
    return ident, flags, questions, offset


def build_reply(query: bytes, mode: str = "sinkhole") -> bytes:
    """A reply for a query we are refusing to resolve.

    mode == "nxdomain"  -> RCODE 3, no answers
    mode == "sinkhole"  -> RCODE 0, A 0.0.0.0 / AAAA :: (other types: NODATA)
    mode == "servfail"  -> RCODE 2 (upstream unreachable)
    """
    ident, flags, questions, qend = parse_query(query)
    if not questions:
        raise DNSError("no question")
    name, qtype, qclass = questions[0]

    rcode = {"sinkhole": 0, "nxdomain": 3, "servfail": 2, "refused": 5}.get(mode, 3)
    answers = b""
    if mode == "nxdomain":
        rcode = 3
    elif mode == "sinkhole" and qtype in (TYPE_IDS["A"], TYPE_IDS["AAAA"]):
        addr = "\x00\x00\x00\x00" if qtype == TYPE_IDS["A"] else b"\x00" * 16
        if qtype == TYPE_IDS["A"]:
            addr = ipaddress.IPv4Address("0.0.0.0").packed
        else:
            addr = ipaddress.IPv6Address("::").packed
        # name as a pointer back to the question (always at offset 12)
        answers = struct.pack("!HHHIH", 0xC00C, qtype, qclass, 30, len(addr)) + addr

    # QR | keep opcode/RD/CD | RA | rcode
    reply_flags = (flags | 0x8000 | 0x0080) & ~0x000F
    reply_flags |= rcode
    header = struct.pack("!HHHHHH", ident, reply_flags, len(questions), 1 if answers else 0, 0, 0)
    return header + query[12:qend] + answers


def rcode_of(reply: bytes) -> int:
    if len(reply) < 4:
        return -1
    return reply[3] & 0x0F


def qtype_name(qtype: int) -> str:
    return TYPES.get(qtype, f"TYPE{qtype}")
