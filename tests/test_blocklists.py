"""Blocklist parsing, matching, allow/block overrides."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import helpers

from rethinkd.dns.blocklists import BUILTIN, BlocklistManager, CATEGORIES, normalise, parse_list


class NormaliseTest(unittest.TestCase):
    def test_plain_domain(self):
        self.assertEqual(normalise("Example.COM"), "example.com")

    def test_host_line_shapes(self):
        self.assertEqual(normalise("0.0.0.0 ads.tracker.net"), "ads.tracker.net")
        self.assertEqual(normalise("||ads.example.org^"), "ads.example.org")
        self.assertEqual(normalise("address=/ads.example.org/"), "ads.example.org")

    def test_comments_and_junk(self):
        self.assertIsNone(normalise("# comment"))
        self.assertIsNone(normalise("! intel list"))
        self.assertIsNone(normalise("[Adblock]"))
        self.assertIsNone(normalise(""))
        self.assertIsNone(normalise("http://evil/path"))
        self.assertIsNone(normalise("a..b"))


class ParseListTest(unittest.TestCase):
    def test_hosts_format(self):
        text = "\n".join(
            [
                "0.0.0.0 one.test",
                "127.0.0.1 two.test",
                "localhost",
                "127.0.0.1 localhost.localdomain",
                "",
            ]
        )
        self.assertEqual(parse_list(text, "hosts"), {"one.test", "two.test"})

    def test_adblock_format(self):
        text = "\n".join(
            [
                "||tracker.example^",
                "@@||allowed.example^",
                "! comment",
                "||evil.example.org^$third-party",
            ]
        )
        self.assertEqual(parse_list(text, "adblock"), {"tracker.example", "evil.example.org"})

    def test_dnsmasq_format(self):
        text = "\n".join(["server=/ads.example.com/", "address=/telemetry.example.com/"])
        self.assertEqual(parse_list(text, "dnsmasq"), {"ads.example.com", "telemetry.example.com"})

    def test_plain_domain_format(self):
        self.assertEqual(parse_list("one.test\nTwo.test\n", "domains"), {"one.test", "two.test"})


class ManagerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="rethinkd-bl-")
        self.mgr = BlocklistManager(Path(self.tmp.name))
        self.mgr.configure({"ads": True}, [], [], [])

    def tearDown(self):
        self.tmp.cleanup()

    def test_builtin_seed_blocks_without_download(self):
        self.assertEqual(self.mgr.check("doubleclick.net"), "builtin")
        self.assertEqual(self.mgr.check("x.doubleclick.net"), "builtin")
        self.assertIsNone(self.mgr.check("example.com"))

    def test_builtin_seed_survives_category_toggle(self):
        self.mgr.configure({"ads": False, "tracking": True}, [], [], [])
        self.assertEqual(self.mgr.check("doubleclick.net"), "builtin")

    def test_category_hit_reports_category(self):
        self.mgr._categories["ads"] = {"ads.bad.example"}  # noqa: SLF001 — direct seed
        self.assertEqual(self.mgr.check("sub.ads.bad.example"), "category:ads")

    def test_allow_overrides_block(self):
        self.mgr.configure({"ads": True}, [], ["bad.example"], ["keep.bad.example"])
        self.assertEqual(self.mgr.check("bad.example"), "domain:block")
        self.assertIsNone(self.mgr.check("keep.bad.example"))

    def test_custom_list(self):
        self.mgr._custom["c1"] = {"cdn.custom.test"}  # noqa: SLF001
        self.mgr._meta["c1"] = {"count": 1, "url": "https://example.com/list.txt"}  # noqa: SLF001
        self.mgr.configure({"ads": False}, [{"id": "c1", "url": "https://example.com/list.txt", "enabled": True}], [], [])
        self.mgr.set_enabled("c1", True)
        self.assertEqual(self.mgr.check("cdn.custom.test"), "custom:https://example.com/list.txt")
        self.mgr.set_enabled("c1", False)
        self.assertIsNone(self.mgr.check("cdn.custom.test"))

    def test_stats_shape(self):
        stats = self.mgr.stats()
        self.assertEqual({c["id"] for c in stats["categories"]}, {c["id"] for c in CATEGORIES})
        self.assertIn("totals", stats)
        self.assertGreaterEqual(stats["totals"]["domains"], len(BUILTIN))
        ads = next(c for c in stats["categories"] if c["id"] == "ads")
        self.assertTrue(ads["enabled"])

    def test_remove_custom(self):
        self.mgr._custom["gone"] = {"x.test"}  # noqa: SLF001
        self.mgr._meta["gone"] = {"count": 1, "url": "u"}  # noqa: SLF001
        self.mgr.remove_custom("gone")
        self.assertIsNone(self.mgr.check("x.test"))  # not in any enabled set anyway
        self.assertNotIn("gone", self.mgr._custom)  # noqa: SLF001


if __name__ == "__main__":
    unittest.main()
