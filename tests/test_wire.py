"""DNS wire format: parsing, replies, sinkhole/nxdomain/servfail."""

from __future__ import annotations

import struct
import unittest

import helpers  # noqa: F401  (puts src/ on sys.path)

from rethinkd.dns import wire


def query_bytes(name: str = "ads.example.com", qtype: int = 1) -> bytes:
    header = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\x00"
    return header + qname + struct.pack("!HH", qtype, 1)


class WireTest(unittest.TestCase):
    def test_parse_query(self):
        ident, flags, questions, end = wire.parse_query(query_bytes())
        self.assertEqual(ident, 0x1234)
        self.assertEqual(flags & 0x8000, 0)  # it is a query
        self.assertEqual(questions, [("ads.example.com", 1, 1)])
        self.assertEqual(end, len(query_bytes()))

    def test_parse_rejects_truncated(self):
        with self.assertRaises(wire.DNSError):
            wire.parse_query(b"\x12\x34")

    def test_sinkhole_reply(self):
        reply = wire.build_reply(query_bytes(), "sinkhole")
        ident, flags, questions, end = wire.parse_query(reply)
        self.assertEqual(ident, 0x1234)
        self.assertEqual(flags & 0x8000, 0x8000)  # response bit
        self.assertEqual(flags & 0xF, 0)  # NOERROR
        self.assertEqual(questions[0][0], "ads.example.com")
        # ancount == 1 with an A record pointing at 0.0.0.0
        self.assertEqual(struct.unpack("!H", reply[6:8])[0], 1)
        self.assertIn(b"\x00\x00\x00\x00", reply[end:])

    def test_nxdomain_reply(self):
        reply = wire.build_reply(query_bytes(), "nxdomain")
        self.assertEqual(struct.unpack("!H", reply[2:4])[0] & 0xF, 3)
        self.assertEqual(struct.unpack("!H", reply[6:8])[0], 0)

    def test_servfail_and_refused(self):
        self.assertEqual(struct.unpack("!H", wire.build_reply(query_bytes(), "servfail")[2:4])[0] & 0xF, 2)
        self.assertEqual(struct.unpack("!H", wire.build_reply(query_bytes(), "refused")[2:4])[0] & 0xF, 5)

    def test_unknown_mode_falls_back_to_nxdomain(self):
        reply = wire.build_reply(query_bytes(), "nonsense")
        self.assertEqual(struct.unpack("!H", reply[2:4])[0] & 0xF, 3)

    def test_qtype_names(self):
        self.assertEqual(wire.qtype_name(1), "A")
        self.assertEqual(wire.qtype_name(28), "AAAA")
        self.assertEqual(wire.qtype_name(5), "CNAME")
        self.assertEqual(wire.qtype_name(12345), "TYPE12345")

    def test_ipv6_query_sinkhole_has_aaaa(self):
        reply = wire.build_reply(query_bytes(qtype=28), "sinkhole")
        end = wire.parse_query(reply)[3]
        self.assertEqual(struct.unpack("!H", reply[6:8])[0], 1)
        self.assertEqual(struct.unpack("!H", reply[end + 2:end + 4])[0], 28)


if __name__ == "__main__":
    unittest.main()
