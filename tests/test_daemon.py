"""Config store, DNS query log and daemon status wiring."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import helpers

from rethinkd.activity import Activity
from rethinkd.config import DEFAULT_CONFIG, Config


class ConfigTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="rethinkd-cfg-")
        self.path = Path(self.tmp.name) / "config.json"
        self.cfg = Config(self.path)

    def tearDown(self):
        self.tmp.cleanup()

    def test_defaults_seeded(self):
        self.assertTrue(self.cfg.get("protected"))
        self.assertEqual(self.cfg.get("firewall.policy"), "allow")
        self.assertEqual(self.cfg.get("settings.listen"), "127.0.0.1:8777")
        self.assertTrue(self.cfg.get("dns.hijack"))

    def test_category_toggles_seeded(self):
        from rethinkd.dns.blocklists import CATEGORIES

        cats = self.cfg.get("blocklists.categories")
        for cat in CATEGORIES:
            self.assertIn(cat["id"], cats)
            self.assertEqual(cats[cat["id"]], bool(cat["default"]))

    def test_set_persists_atomically(self):
        self.cfg.set("firewall.policy", "block")
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        self.assertEqual(raw["firewall"]["policy"], "block")
        self.assertFalse(self.path.with_suffix(".tmp").exists())

    def test_get_path_notation(self):
        self.cfg.set("proxy.port", 8080)
        self.assertEqual(self.cfg.get("proxy.port"), 8080)
        self.assertIsNone(self.cfg.get("proxy.nope"))
        self.assertEqual(self.cfg.get("proxy.nope", 5), 5)

    def test_corrupt_file_falls_back_to_defaults(self):
        self.path.write_text("{not json", encoding="utf-8")
        cfg = Config(self.path)
        self.assertEqual(cfg.get("firewall.policy"), "allow")

    def test_token_created_and_rotated(self):
        token = self.cfg.token()
        self.assertGreater(len(token), 16)
        self.assertEqual(self.cfg.token(), token)  # stable
        mode = self.cfg.token_path.stat().st_mode & 0o777
        self.assertEqual(mode, 0o640)  # group-readable for rethinkctl
        rotated = self.cfg.rotate_token()
        self.assertNotEqual(rotated, token)
        self.assertEqual(self.cfg.token(), rotated)

    def test_default_config_is_json_safe(self):
        json.dumps(DEFAULT_CONFIG)


class ActivityTest(unittest.TestCase):
    def test_dns_log_and_counters(self):
        act = Activity(log_size=3)
        for i in range(5):
            act.dns_query(f"domain{i}.test", "A", "127.0.0.1:53", i % 2 == 0, "builtin" if i % 2 == 0 else None)
        self.assertEqual(len(act.log()), 3)  # deque capped
        stats = act.dns_stats()
        self.assertEqual(stats["queries"], 5)
        self.assertEqual(stats["blocked"], 3)
        self.assertAlmostEqual(stats["block_rate"], 60.0)
        self.assertTrue(stats["series"])
        self.assertEqual(stats["top_blocked"][0]["count"], 1)

    def test_events_and_clear(self):
        act = Activity()
        act.firewall_event(1000, "firefox", 12)
        act.proxy_event("127.0.0.1:9999", "relayed")
        act.dns_query("x.test", "A", "c", True, "builtin")
        events = act.events()
        self.assertEqual(len(events), 3)
        self.assertEqual(events[0]["kind"], "dns")
        counters = act.counters()
        self.assertEqual(counters["dropped_packets"], 12)
        self.assertEqual(counters["relayed"], 1)
        act.clear_log()
        self.assertEqual(act.log(), [])


class DaemonWiringTest(unittest.TestCase):
    def setUp(self):
        import pathlib

        self.tmp = tempfile.TemporaryDirectory(prefix="rethinkd-dm-")
        from rethinkd.daemon import Daemon

        self.daemon = Daemon(pathlib.Path(self.tmp.name) / "config.json", dry_run=True)

    def tearDown(self):
        self.tmp.cleanup()

    def test_status_shape(self):
        status = self.daemon.status()
        for section in ("version", "protected", "dns", "firewall", "proxy", "host", "running_as"):
            self.assertIn(section, status)
        self.assertTrue(status["firewall"]["dry_run"])
        self.assertIn("upstream", status["dns"])

    def test_matcher_respects_protection_switch(self):
        self.daemon.add_domain_rule("blocked.test", "block")
        self.assertEqual(self.daemon.matcher("blocked.test"), "domain:block")
        self.daemon.set_protected(False)
        self.assertIsNone(self.daemon.matcher("blocked.test"))
        self.daemon.set_protected(True)

    def test_app_rule_and_policy_flow(self):
        self.daemon.set_app_rule(1000, "block")
        self.assertEqual(self.daemon.cfg.get("firewall.apps", {}), {"1000": "block"})
        self.daemon.clear_app_rule(1000)
        self.assertEqual(self.daemon.cfg.get("firewall.apps", {}), {})
        self.daemon.set_policy("block")
        self.assertEqual(self.daemon.cfg.get("firewall.policy"), "block")
        self.daemon.set_policy("allow")

    def test_dns_query_hook_updates_activity(self):
        self.daemon._on_dns_query("ads.test", 1, "127.0.0.1:1234", True, "builtin")  # noqa: SLF001
        stats = self.daemon.activity.dns_stats()
        self.assertEqual(stats["queries"], 1)
        self.assertEqual(stats["blocked"], 1)
        self.assertEqual(stats["by_type"].get("A"), 1)

    def test_settings_listen_change_rejected(self):
        with self.assertRaises(ValueError):
            self.daemon.set_settings({"listen": "127.0.0.1:9"})

    def test_proxy_requires_host_and_port(self):
        with self.assertRaises(ValueError):
            self.daemon.toggle_proxy(True)
        self.daemon.configure_proxy({"type": "http", "host": "127.0.0.1", "port": 9999})
        self.assertEqual(self.daemon.cfg.get("proxy.port"), 9999)


if __name__ == "__main__":
    unittest.main()
