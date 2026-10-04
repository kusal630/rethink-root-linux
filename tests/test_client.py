"""Unit tests for rethinkd.client — token/config discovery and API calls."""

from __future__ import annotations

import json
import os
import unittest
from pathlib import Path
from unittest import mock

from helpers import start_daemon  # noqa: F401  (sets sys.path)

from rethinkd import client


class ConfigPathTest(unittest.TestCase):
    def test_env_override(self) -> None:
        with mock.patch.dict(os.environ, {"RETHINK_CONFIG": "/tmp/x/config.json"}):
            self.assertEqual(client.config_path(), Path("/tmp/x/config.json"))

    def test_defaults_to_user_config(self) -> None:
        env = {k: v for k, v in os.environ.items() if k != "RETHINK_CONFIG"}
        with mock.patch.dict(os.environ, env, clear=True), \
                mock.patch.object(client.os, "geteuid", return_value=1000), \
                mock.patch.object(Path, "home", return_value=Path("/home/u")):
            self.assertEqual(client.config_path(), Path("/home/u/.config/rethinkd/config.json"))

    def test_root_uses_system_config(self) -> None:
        env = {k: v for k, v in os.environ.items() if k != "RETHINK_CONFIG"}
        with mock.patch.dict(os.environ, env, clear=True), \
                mock.patch.object(client.os, "geteuid", return_value=0):
            self.assertEqual(client.config_path(), client.SYSTEM_CONFIG)


class TokenTest(unittest.TestCase):
    def test_env_wins(self) -> None:
        with mock.patch.dict(os.environ, {"RETHINK_TOKEN": " env-token "}):
            self.assertEqual(client.token_value(), "env-token")

    def test_read_next_to_config(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / "config.json"
            cfg.write_text("{}", encoding="utf-8")
            (Path(tmp) / "token").write_text("file-token\n", encoding="utf-8")
            with mock.patch.dict(os.environ, {"RETHINK_CONFIG": str(cfg), "RETHINK_TOKEN": ""}):
                self.assertEqual(client.token_value(), "file-token")

    def test_missing_files_yield_empty(self) -> None:
        env = {"RETHINK_TOKEN": "", "RETHINK_CONFIG": "/nonexistent/token-dir/config.json"}
        with mock.patch.dict(os.environ, env), \
                mock.patch.object(Path, "read_text", side_effect=OSError):
            self.assertEqual(client.token_value(), "")


class DiscoveryTest(unittest.TestCase):
    def test_listen_address_from_config(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / "config.json"
            cfg.write_text(json.dumps({"settings": {"listen": "127.0.0.1:9999"}}), encoding="utf-8")
            with mock.patch.dict(os.environ, {"RETHINK_CONFIG": str(cfg)}):
                self.assertEqual(client.listen_address(), "127.0.0.1:9999")
                self.assertEqual(client.endpoints()[0], "http://127.0.0.1:9999")

    def test_listen_address_falls_back_to_default(self) -> None:
        env = {k: v for k, v in os.environ.items() if k != "RETHINK_CONFIG"}
        with mock.patch.dict(os.environ, env, clear=True), \
                mock.patch.object(client, "SYSTEM_CONFIG", Path("/nonexistent/config.json")), \
                mock.patch.object(Path, "home", return_value=Path("/nonexistent-home")):
            self.assertEqual(client.listen_address(), client.DEFAULT_LISTEN)

    def test_ui_url_shape(self) -> None:
        with mock.patch.object(client, "endpoints", return_value=("http://127.0.0.1:8777", "tok")):
            self.assertEqual(client.ui_url(), "http://127.0.0.1:8777/?token=tok")


class CallTest(unittest.TestCase):
    def test_call_against_live_daemon(self) -> None:
        tmp, daemon, port, base = start_daemon()
        self.addCleanup(tmp.cleanup)
        self.addCleanup(daemon.stop)
        token = daemon.token()
        with mock.patch.object(client, "endpoints", return_value=(base, token)):
            status = client.call("GET", "/api/status")
        self.assertIn("protected", status)
        self.assertTrue(client.reachable())

    def test_http_error_becomes_api_error(self) -> None:
        tmp, daemon, port, base = start_daemon()
        self.addCleanup(tmp.cleanup)
        self.addCleanup(daemon.stop)
        with mock.patch.object(client, "endpoints", return_value=(base, "wrong-token")):
            with self.assertRaises(client.ApiError) as ctx:
                client.call("GET", "/api/status")
        self.assertEqual(ctx.exception.status, 401)

    def test_unreachable_daemon(self) -> None:
        with mock.patch.object(client, "endpoints", return_value=("http://127.0.0.1:1", "")):
            with self.assertRaises(client.ApiError) as ctx:
                client.call("GET", "/api/status", timeout=0.5)
            self.assertIn("cannot reach", str(ctx.exception))
            self.assertFalse(client.reachable(timeout=0.5))


if __name__ == "__main__":
    unittest.main()
