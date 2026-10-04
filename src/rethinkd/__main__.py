"""``python3 -m rethinkd`` — start the daemon."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .daemon import Daemon


def default_config_path() -> Path:
    import os

    if os.environ.get("RETHINK_CONFIG"):
        return Path(os.environ["RETHINK_CONFIG"])
    if os.geteuid() == 0:
        return Path("/etc/rethinkd/config.json")
    return Path.home() / ".config" / "rethinkd" / "config.json"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="rethinkd", description="Rethink Root — Linux edition daemon")
    parser.add_argument("--config", default=str(default_config_path()), help="config file path")
    parser.add_argument("--dry-run", action="store_true", help="never touch iptables (development)")
    parser.add_argument("--verbose", action="store_true", help="log every HTTP request")
    parser.add_argument("--version", action="version", version=f"rethinkd {__version__}")
    args = parser.parse_args(argv)

    daemon = Daemon(Path(args.config), dry_run=args.dry_run, verbose=args.verbose)
    daemon.install_signals()
    try:
        daemon.start()
    except OSError as exc:
        print(f"rethinkd: {exc}", file=sys.stderr)
        return 1
    daemon.wait()
    daemon.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
