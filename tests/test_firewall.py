"""Rule generation for the OUTPUT chains (no iptables needed)."""

from __future__ import annotations

import unittest

import helpers

from rethinkd.config import Config
from rethinkd.firewall import (
    CHAIN_APPS,
    CHAIN_DNS,
    CHAIN_PROXY,
    JUMP_COMMENT,
    Firewall,
    app_rules,
    dns_rules,
    proxy_rules,
)


class AppRulesTest(unittest.TestCase):
    def test_allow_policy_only_blocks_explicit(self):
        rules = app_rules("allow", {"1000": "block", "1001": "allow"}, exempt_uid=0)
        text = " ".join(" ".join(r) for r in rules)
        self.assertIn("-m owner --uid-owner 1000", text)
        self.assertIn("-j DROP", text)
        self.assertNotIn("uid-owner 1001", text)

    def test_block_policy_only_allows_explicit(self):
        rules = app_rules("block", {"1001": "allow"}, exempt_uid=0)
        text = " ".join(" ".join(r) for r in rules)
        self.assertIn("uid-owner 1001", text)
        self.assertIn("-j RETURN", text)
        self.assertTrue(text.strip().endswith("-j DROP") or "-j DROP" in text)

    def test_own_uid_is_exempted_not_dropped(self):
        rules = app_rules("block", {}, exempt_uid=1234)
        self.assertEqual(rules[0][-1], "RETURN")
        self.assertEqual(rules[0][rules[0].index("--uid-owner") + 1], "1234")
        drop = [r for r in rules if "-j" in r and r[r.index("-j") + 1] == "DROP"]
        self.assertEqual(len(drop), 1)  # the default drop, aimed at nobody in particular
        self.assertNotIn("1234", " ".join(drop[0]))

    def test_drop_rule_carries_the_uid_comment(self):
        rules = app_rules("allow", {"42": "block"}, exempt_uid=0)
        drop = [r for r in rules if "-j" in r and r[r.index("-j") + 1] == "DROP"]
        self.assertTrue(drop)
        self.assertIn("rethink-app:42", drop[0])
        self.assertEqual(drop[0][drop[0].index("--uid-owner") + 1], "42")


class DnsRulesTest(unittest.TestCase):
    def test_hijacks_tcp_and_udp_53_except_own_uid_and_loopback(self):
        rules = dns_rules(5300, exempt_uid=999)
        text = " ".join(" ".join(r) for r in rules)
        self.assertIn("--dport 53", text)
        self.assertIn("REDIRECT --to-ports 5300", text)
        self.assertIn("uid-owner 999", text)
        self.assertIn("127.0.0.0/8", text)
        self.assertIn("-j RETURN", text)
        # RETURN rules must come before the REDIRECT
        self.assertLess(text.index("-j RETURN"), text.index("REDIRECT"))

    def test_protocols_covered(self):
        text = " ".join(" ".join(r) for r in dns_rules(5300, exempt_uid=0))
        self.assertIn("tcp", text)
        self.assertIn("udp", text)


class ProxyRulesTest(unittest.TestCase):
    def test_redirects_outbound_tcp_to_proxy_port(self):
        rules = proxy_rules(5301, exempt_uid=0, bypass_lan=True)
        text = " ".join(" ".join(r) for r in rules)
        self.assertIn("-p tcp", text)
        self.assertIn("REDIRECT --to-ports 5301", text)
        self.assertIn("127.0.0.0/8", text)
        self.assertIn("-j RETURN", text)
        self.assertLess(text.index("-j RETURN"), text.index("REDIRECT"))

    def test_lan_bypass_optional(self):
        with_lan = " ".join(" ".join(r) for r in proxy_rules(5301, exempt_uid=0, bypass_lan=True))
        without = " ".join(" ".join(r) for r in proxy_rules(5301, exempt_uid=0, bypass_lan=False))
        self.assertNotEqual(with_lan, without)


class FirewallDryRunTest(unittest.TestCase):
    def setUp(self):
        import tempfile
        from pathlib import Path

        self.tmp = tempfile.TemporaryDirectory(prefix="rethinkd-fw-")
        self.cfg = Config(Path(self.tmp.name) / "config.json")
        self.fw = Firewall(self.cfg, dry_run=True)

    def tearDown(self):
        self.tmp.cleanup()

    def test_apply_is_idempotent_in_dry_run(self):
        first = self.fw.apply()
        second = self.fw.apply()
        self.assertTrue(self.fw.applied)
        self.assertIsNone(self.fw.last_error)
        self.assertTrue(first)
        self.assertTrue(second)

    def test_apply_installs_jumps_with_comment(self):
        argvs = self.fw.apply()
        flat = " ".join(" ".join(a) for a in argvs)
        self.assertIn(CHAIN_APPS, flat)
        self.assertIn(CHAIN_DNS, flat)
        self.assertIn(CHAIN_PROXY, flat)
        self.assertIn(JUMP_COMMENT, flat)

    def test_protected_off_removes_jumps(self):
        self.fw.apply()
        self.cfg.set("protected", False)
        argvs = self.fw.apply()
        flat = " ".join(" ".join(a) for a in argvs)
        self.assertIn("-D", flat)
        self.assertFalse(self.fw.applied)

    def test_counters_empty_in_dry_run(self):
        self.assertEqual(self.fw.counters(), {})

    def test_available_reflects_privileges(self):
        # this test process is neither root nor CAP_NET_ADMIN
        self.assertFalse(Firewall.available())


class ChainTableTest(unittest.TestCase):
    """Regression: RETHINK_DNS/RETHINK_PROXY live in nat, RETHINK_APPS in filter."""

    def test_chains_created_in_the_table_they_are_used_in(self):
        filter_argv = Firewall._chain_argv("iptables", "filter")
        nat_argv = Firewall._chain_argv("iptables", "nat")
        flat_filter = " ".join(" ".join(a) for a in filter_argv)
        flat_nat = " ".join(" ".join(a) for a in nat_argv)
        self.assertIn(CHAIN_APPS, flat_filter)
        self.assertNotIn(CHAIN_DNS, flat_filter)
        self.assertNotIn(CHAIN_PROXY, flat_filter)
        self.assertIn(CHAIN_DNS, flat_nat)
        self.assertIn(CHAIN_PROXY, flat_nat)
        self.assertNotIn(CHAIN_APPS, flat_nat)

    def test_apply_never_touches_a_nat_chain_that_is_missing_from_nat(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            cfg = Config(Path(tmp) / "config.json")
            fw = Firewall(cfg, dry_run=True)
            executed = fw.apply()
        nat_tables = set(Firewall.CHAINS["nat"])
        seen_nat_chains: set[str] = set()
        filter_seen: set[str] = set()
        for argv in executed:
            if "-t" in argv and argv[argv.index("-t") + 1] == "filter" and "-N" in argv:
                filter_seen.add(argv[argv.index("-N") + 1])
        self.assertEqual(filter_seen, set(Firewall.CHAINS["filter"]))
        for argv in executed:
            if "nat" not in argv:
                continue
            table = argv[argv.index("-t") + 1] if "-t" in argv else ""
            if table != "nat":
                continue
            for op in ("-N", "-F", "-A", "-C", "-D"):
                if op in argv:
                    chain = argv[argv.index(op) + 1]
                    if op == "-N":
                        seen_nat_chains.add(chain)
                    elif chain.startswith("RETHINK"):  # OUTPUT is a built-in
                        self.assertIn(
                            chain, nat_tables,
                            f"{op} {chain} in nat but that chain is never created there",
                        )
                    break
        self.assertEqual(seen_nat_chains, nat_tables)


if __name__ == "__main__":
    unittest.main()
