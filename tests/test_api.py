"""End-to-end HTTP API test against a live dry-run daemon."""

from __future__ import annotations

import unittest
import urllib.request

import helpers


class ApiTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp, cls.daemon, cls.port, cls.base = helpers.start_daemon(dns_enabled=False)
        cls.token = cls.daemon.token()

    @classmethod
    def tearDownClass(cls):
        cls.daemon.stop()
        cls.tmp.cleanup()

    # -- auth ------------------------------------------------------------
    def test_session_needs_no_token(self):
        req = urllib.request.Request(self.base + "/api/session")
        with urllib.request.urlopen(req, timeout=5) as resp:
            import json

            body = json.loads(resp.read().decode())
        self.assertFalse(body["authed"])
        self.assertIn("version", body)

    def test_status_rejects_bad_token(self):
        _, status = helpers.api(self.base, "wrong", "GET", "/api/status")
        self.assertEqual(status, 401)

    def test_status_accepts_good_token(self):
        body, status = helpers.api(self.base, self.token, "GET", "/api/status")
        self.assertEqual(status, 200)
        self.assertEqual(body["authed"], True)
        self.assertIn("dns", body)
        self.assertIn("firewall", body)
        self.assertIn("proxy", body)
        self.assertTrue(body["firewall"]["dry_run"])

    def test_static_ui_served(self):
        with urllib.request.urlopen(self.base + "/", timeout=5) as resp:
            html = resp.read().decode()
        self.assertIn("<html", html.lower())
        for asset in ("/app.js", "/style.css", "/icon.svg"):
            with urllib.request.urlopen(self.base + asset, timeout=5) as resp:
                self.assertEqual(resp.status, 200)

    def test_unknown_api_404(self):
        _, status = helpers.api(self.base, self.token, "GET", "/api/nope")
        self.assertEqual(status, 404)

    # -- protected -------------------------------------------------------
    def test_protected_toggle(self):
        body, _ = helpers.api(self.base, self.token, "POST", "/api/protected", {"on": False})
        self.assertFalse(body["protected"])
        status, _ = helpers.api(self.base, self.token, "GET", "/api/status")
        self.assertFalse(status["protected"])
        helpers.api(self.base, self.token, "POST", "/api/protected", {"on": True})
        self.assertTrue(helpers.api(self.base, self.token, "GET", "/api/status")[0]["protected"])

    def test_protected_requires_field(self):
        _, status = helpers.api(self.base, self.token, "POST", "/api/protected", {})
        self.assertEqual(status, 400)

    # -- apps ------------------------------------------------------------
    def test_apps_roundtrip(self):
        body, _ = helpers.api(self.base, self.token, "GET", "/api/apps")
        self.assertIn("policy", body)
        self.assertIsInstance(body["apps"], list)

        _, status = helpers.api(self.base, self.token, "POST", "/api/apps", {"uid": 1337, "action": "block"})
        self.assertEqual(status, 200)
        self.assertEqual(self.daemon.cfg.get("firewall.apps", {}), {"1337": "block"})

        _, status = helpers.api(self.base, self.token, "POST", "/api/apps", {"uid": 1337, "action": "bogus"})
        self.assertEqual(status, 400)

        _, status = helpers.api(self.base, self.token, "DELETE", "/api/apps/1337")
        self.assertEqual(status, 200)
        self.assertEqual(self.daemon.cfg.get("firewall.apps", {}), {})

    def test_policy_switch(self):
        helpers.api(self.base, self.token, "POST", "/api/policy", {"policy": "block"})
        self.assertEqual(self.daemon.cfg.get("firewall.policy"), "block")
        helpers.api(self.base, self.token, "POST", "/api/policy", {"policy": "allow"})
        self.assertEqual(self.daemon.cfg.get("firewall.policy"), "allow")
        _, status = helpers.api(self.base, self.token, "POST", "/api/policy", {"policy": "sideways"})
        self.assertEqual(status, 400)

    # -- blocklists ------------------------------------------------------
    def test_blocklists_shape_and_toggle(self):
        body, _ = helpers.api(self.base, self.token, "GET", "/api/blocklists")
        self.assertIn("categories", body)
        self.assertIn("custom", body)
        self.assertIn("totals", body)
        ads = next(c for c in body["categories"] if c["id"] == "ads")
        self.assertTrue(ads["enabled"])

        helpers.api(self.base, self.token, "POST", "/api/blocklists", {"id": "social", "enabled": True})
        body, _ = helpers.api(self.base, self.token, "GET", "/api/blocklists")
        self.assertTrue(next(c for c in body["categories"] if c["id"] == "social")["enabled"])
        self.assertTrue(self.daemon.cfg.get("blocklists.categories", {})["social"])
        helpers.api(self.base, self.token, "POST", "/api/blocklists", {"id": "social", "enabled": False})

    def test_domain_rules_and_matcher(self):
        _, status = helpers.api(self.base, self.token, "POST", "/api/dns/domain", {"domain": "bad.example", "action": "block"})
        self.assertEqual(status, 200)
        body, _ = helpers.api(self.base, self.token, "POST", "/api/blocklists/test", {"domain": "x.bad.example"})
        self.assertTrue(body["blocked"])
        self.assertEqual(body["reason"], "domain:block")

        _, status = helpers.api(self.base, self.token, "POST", "/api/dns/domain", {"domain": "good.bad.example", "action": "allow"})
        self.assertEqual(status, 200)
        body, _ = helpers.api(self.base, self.token, "POST", "/api/blocklists/test", {"domain": "good.bad.example"})
        self.assertFalse(body["blocked"])

        _, status = helpers.api(self.base, self.token, "DELETE", "/api/dns/domain/bad.example")
        self.assertEqual(status, 200)
        body, _ = helpers.api(self.base, self.token, "POST", "/api/blocklists/test", {"domain": "x.bad.example"})
        self.assertFalse(body["blocked"])

        _, status = helpers.api(self.base, self.token, "POST", "/api/dns/domain", {"domain": "bad.example", "action": "explode"})
        self.assertEqual(status, 400)

    def test_dns_status_and_upstream(self):
        body, _ = helpers.api(self.base, self.token, "GET", "/api/dns")
        self.assertIn("upstream", body)
        self.assertIn("log", body)
        self.assertIn("queries", body)

        _, status = helpers.api(self.base, self.token, "POST", "/api/dns/upstream", {"type": "doh", "url": "https://dns.example/dns-query"})
        self.assertEqual(status, 200)
        self.assertEqual(self.daemon.upstream.endpoint, "https://dns.example/dns-query")

        _, status = helpers.api(self.base, self.token, "POST", "/api/dns/upstream", {"type": "voodoo"})
        self.assertEqual(status, 400)
        helpers.api(self.base, self.token, "POST", "/api/dns/upstream", {"type": "system"})

    def test_hijack_and_clearlog(self):
        _, status = helpers.api(self.base, self.token, "POST", "/api/dns/hijack", {"enabled": False})
        self.assertEqual(status, 200)
        self.assertFalse(self.daemon.cfg.get("dns.hijack"))
        helpers.api(self.base, self.token, "POST", "/api/dns/hijack", {"enabled": True})

        _, status = helpers.api(self.base, self.token, "POST", "/api/dns/clearlog", {})
        self.assertEqual(status, 200)
        self.assertEqual(self.daemon.activity.log(), [])

    # -- proxy -----------------------------------------------------------
    def test_proxy_configure_and_toggle(self):
        body, _ = helpers.api(self.base, self.token, "GET", "/api/proxy")
        self.assertFalse(body["enabled"])

        _, status = helpers.api(
            self.base, self.token, "POST", "/api/proxy", {"type": "http", "host": "127.0.0.1", "port": 9999, "username": "u"}
        )
        self.assertEqual(status, 200)
        body, _ = helpers.api(self.base, self.token, "GET", "/api/proxy")
        self.assertEqual(body["port"], 9999)

        _, status = helpers.api(self.base, self.token, "POST", "/api/proxy", {"type": "voodoo", "host": "127.0.0.1", "port": 1})
        self.assertEqual(status, 400)

        _, status = helpers.api(self.base, self.token, "POST", "/api/proxy/toggle", {"enabled": True})
        self.assertEqual(status, 200)
        self.assertTrue(self.daemon.cfg.get("proxy.enabled"))
        helpers.api(self.base, self.token, "POST", "/api/proxy/toggle", {"enabled": False})

        _, status = helpers.api(self.base, self.token, "POST", "/api/proxy/toggle", {"enabled": True})
        self.assertEqual(status, 200)
        # turn it back off so the redirect rules do not stay installed
        helpers.api(self.base, self.token, "POST", "/api/proxy/toggle", {"enabled": False})
        self.assertFalse(self.daemon.cfg.get("proxy.enabled"))

    # -- settings / activity --------------------------------------------
    def test_settings_roundtrip(self):
        body, _ = helpers.api(self.base, self.token, "GET", "/api/settings")
        self.assertIn("theme", body)
        self.assertIn("token_hint", body)
        self.assertTrue(body["token_hint"])

        _, status = helpers.api(self.base, self.token, "POST", "/api/settings", {"theme": "light"})
        self.assertEqual(status, 200)
        self.assertEqual(self.daemon.cfg.get("settings.theme"), "light")

        _, status = helpers.api(self.base, self.token, "POST", "/api/settings", {"listen": "127.0.0.1:1"})
        self.assertEqual(status, 400)

        helpers.api(self.base, self.token, "POST", "/api/settings", {"theme": "dark"})

    def test_activity_feed(self):
        body, _ = helpers.api(self.base, self.token, "GET", "/api/activity")
        self.assertIn("events", body)
        self.assertIsInstance(body["events"], list)

    def test_stats_shape(self):
        body, _ = helpers.api(self.base, self.token, "GET", "/api/stats")
        for key in ("queries", "blocked", "block_rate", "series", "top_blocked", "by_type"):
            self.assertIn(key, body)

    def test_refresh_apps_is_ok(self):
        _, status = helpers.api(self.base, self.token, "POST", "/api/apps/refresh", {})
        self.assertEqual(status, 200)

    def test_config_persisted(self):
        self.assertTrue(self.daemon.cfg.path.exists())
        import json

        saved = json.loads(self.daemon.cfg.path.read_text(encoding="utf-8"))
        self.assertIn("firewall", saved)
        self.assertIn("dns", saved)


if __name__ == "__main__":
    unittest.main()
