# Rethink Root — Linux edition

**System-wide DNS firewall, per-app blocker and outbound proxy for your Linux desktop, driven by a native COSMIC/GTK app.**

Rethink Root runs *at the root level of the machine*: one daemon owns DNS for the whole
system, installs three dedicated `iptables` chains for per-app policy, and can transparently
push outbound TCP through your own HTTP/SOCKS5 proxy. Everything is controlled from the native
GTK4/libadwaita app, from a local web UI on `127.0.0.1:8777`, or from the `rethinkctl` command line.

* Daemon: `rethinkd` — a single, dependency-free Python 3 process (stdlib only).
* Desktop app: native GTK4 + libadwaita window (`rethink-app`, ships as its own launch entry) —
  dashboard, per-app rules, DNS, lists, proxy and settings, no browser required.
* Web UI: vanilla HTML/CSS/JS served by the daemon itself — no CDN, no build step, no phone-home;
  still available (and used automatically if the GTK bindings are missing).
* Packaged as a `.deb`, runs under systemd with only `CAP_NET_ADMIN`,
  `CAP_NET_BIND_SERVICE` and `CAP_NET_RAW`.
* Apache-2.0 licensed.

Looking for Android? That lives in
[`rethink-root-level-android`](https://github.com/kusal630/rethink-root-level-android).

---

## What it does

| Layer | How | What you get |
| --- | --- | --- |
| **DNS filtering** | UDP+TCP server on `127.0.0.1:5300` (+ `127.0.0.42:53` when privileged), all port-53 traffic nat-redirected into it | ad / tracker / malware / social / gambling / adult / crypto lists, per-domain block & allow, live query log |
| **Per-app firewall** | `RETHINK_APPS` chain jumped from `OUTPUT`, matched on `owner --uid-owner` | allow-list or block-list policy, per-app packet & byte counters, app discovery from `/proc` |
| **Transparent proxy** | `RETHINK_PROXY` chain REDIRECTs outbound TCP to a local listener, which dials out via your HTTP/SOCKS5 proxy | point the whole machine (or selected apps via bypass rules) at your own exit node |
| **Activity** | in-memory, rolling hour | queries/min series, top blocked domains, DNS/firewall/proxy event feed |

Everything is undoable: `rethinkctl off` (or the big switch in the UI) removes our jumps
again and leaves the rest of your firewall untouched, because our rules only ever live in
our own chains.

## Install

```bash
sudo dpkg -i dist/rethinkd_0.1.3_amd64.deb   # from a release asset
sudo apt-get install -f                       # if python3/iptables need pulling in
```

The postinst creates a locked-down `rethinkd` system user, enables `rethinkd.service`
and adds *you* (the `sudo`-ing user) to the `rethinkd` group so you can read the API token.

Then launch it — from your app grid (**Rethink Root** is the native window;
**Rethink Root (Web UI)** opens the browser) or from a terminal:

```bash
rethink-app                # native GTK4/libadwaita app
rethink-root-ui            # opens http://127.0.0.1:8777/?token=…
rethinkctl ui --open       # same, from the CLI
rethinkctl status
```

The native app needs `python3-gi`, `gir1.2-gtk-4.0` and `gir1.2-adw-1`
(pulled in by `apt`/COSMIC already; listed under `Recommends` in the package).

The postinst copies the API token to `~/.config/rethinkd/token` so both work
immediately; it also adds you to the `rethinkd` group, which takes effect at your
next login. If `sg rethinkd …` is not available (on Pop!_OS `sg` is `ast-grep`),
just use the copied token, `rethinkctl` as your user, or `sudo rethinkctl …`.

**From source** (no root needed to develop):

```bash
make test              # 87 unit/integration tests, stdlib unittest
make smoke             # boots the daemon unprivileged, hits the API, web UI and native app
make deb               # builds the .deb, source tarball and SHA256SUMS
```

## rethinkctl

```text
rethinkctl status                 # uptime, DNS stats, firewall & proxy state
rethinkctl ui [--open]            # print / open the web UI URL
rethinkctl on | off               # protection switch
rethinkctl block <domain>         # block one domain (allow/unblock to undo)
rethinkctl app list               # running apps + their rules
rethinkctl app block <uid>        # block one app     (allow / reset also)
rethinkctl set-policy allow|block # default policy when no app rule exists
rethinkctl list                   # blocklists + per-category domain counts
rethinkctl refresh                # re-download every enabled list
rethinkctl test <domain>          # why is this domain blocked/allowed?
rethinkctl dns | upstream doh https://dns.example/dns-query
rethinkctl proxy | proxy-set http|socks5 host port [user] | proxy-on | proxy-off
rethinkctl log -n 20              # recent DNS decisions
```

## The native desktop app

`rethink-app` starts a GTK4 + libadwaita window against the running daemon: dashboard with the
protection switch and live activity, per-app allow/block, upstream DNS and query log, blocklist
categories with refresh, proxy settings, and theme/about/log level. It polls the same API the
web UI uses, surfaces daemon errors in a banner with a retry, and exits cleanly when the daemon
is off — `rethink-root-ui` remains the browser-based fallback.

```bash
PYTHONPATH=src /usr/bin/python3 -m rethinkapp --selftest 8   # headless smoke run, prints status and exits
```

## How the pieces fit together

```text
                       ┌──────────────────────────────┐
      any app ─── :53 ─┤ nat: RETHINK_DNS  REDIRECT   ├──▶ rethinkd :5300 ──▶ upstream
                       │   (own uid → RETURN)         │        │
                       ├──────────────────────────────┤        ├─ blocked → 0.0.0.0 / NXDOMAIN
      any app ────────┤ filter: RETHINK_APPS          │        └─ allowed → logged + counted
                       │   per-uid RETURN / DROP      │
                       ├──────────────────────────────┤
      any app ── TCP ──┤ nat: RETHINK_PROXY REDIRECT  ├──▶ local listener ──▶ your proxy
                       │   (LAN + own uid → RETURN)   │
                       └──────────────────────────────┘
```

* The DNS server never loops on itself: our own uid is exempt and loopback
  destinations are returned before the redirect.
* Blocked names are answered from the daemon (`0.0.0.0` sinkhole, or `NXDOMAIN`),
  never forwarded — blocked trackers do not even see the query.
* List downloads are plain HTTPS GETs into `/var/lib/rethinkd/cache`; a failed download
  keeps the previous copy and shows the error in the UI instead of breaking the daemon.

## Security notes

* The API is loopback-only and requires the token in `X-Auth-Token` or the `rethink_token`
  cookie (`/api/session` is the only anonymous endpoint).
* The daemon runs as the unprivileged `rethinkd` user, keeping only network capabilities;
  `ProtectSystem=strict`, `NoNewPrivileges` and a tight `RestrictAddressFamilies` are set in
  the unit file.
* `/etc/rethinkd` (config + token) is `0750` and never world-readable — the config can hold
  your proxy password.
* If your distribution refuses capability-based `iptables`, switch the unit to
  `User=root`, `AmbientCapabilities=` and restart — the daemon will tell you either way
  through `status → firewall.error`.

## Uninstall

```bash
sudo systemctl disable --now rethinkd
sudo apt-get purge rethinkd     # keeps /etc/rethinkd; purge of the cache too
```

Manual (non-package) run during development:

```bash
python3 -m rethinkd --dry-run --config /tmp/dev.json   # never touches iptables
RETHINK_CONFIG=/tmp/dev.json rethinkctl status
PYTHONPATH=src /usr/bin/python3 -m rethinkapp          # native app (needs a display)
```

## Repository layout

```text
src/rethinkd/           daemon (api, config, activity, firewall, proxy)
src/rethinkd/dns/       wire format, blocklists, upstreams, UDP/TCP server
src/rethinkapp/         native GTK4/libadwaita desktop app
src/rethinkd/ui/        web UI (index.html, app.js, style.css, icon.svg)
bin/rethinkctl          command line client
systemd/rethinkd.service unit with capability hardening
packaging/build-deb.sh  .deb + tarball + SHA256SUMS
tests/                  stdlib unittest suite (87 tests)
docs/api.md             the HTTP API contract
```

## License

Apache-2.0 — see [LICENSE](LICENSE).
