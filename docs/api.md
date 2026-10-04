# rethinkd HTTP API contract (v0.1)

Base URL: `http://127.0.0.1:8777` (configurable). All API routes are JSON.

## Auth

* Static assets are public: `GET /`, `/app.js`, `/style.css`, `/icon.svg`.
* Every `/api/*` route requires the daemon token:
  * header `X-Auth-Token: <token>`, **or**
  * cookie `rethink_token=<token>`.
* The UI reads the token from `?token=` in the URL once, stores it in
  `localStorage.rethink_token`, and sends it as `X-Auth-Token` on every call.
* Failed auth → `401` with `{"error":"unauthorized"}`.

Errors everywhere else: `{"error": "<message>"}` with 4xx/5xx.

## Endpoints

### GET /api/session
`{"authed": true|false, "version": "0.1.0"}` — no auth required; lets the UI decide
whether to show the token screen.

### GET /api/status
```json
{
  "authed": true, "version": "0.1.0", "uptime_s": 1234,
  "protected": true,
  "running_as": "root (uid 0)",
  "dns": {
    "listening": ["127.0.0.42:53"], "hijack": true,
    "upstream": "doh", "upstream_url": "https://dns.quad9.net/dns-query",
    "queries": 12345, "blocked": 678, "block_rate": 5.4,
    "last_hour": {"total": 100, "blocked": 7}
  },
  "firewall": {"enabled": true, "policy": "allow", "apps_blocked": 3, "dropped_packets": 1234},
  "proxy": {"enabled": false, "type": null, "endpoint": null, "active_conns": 0, "relayed": 0},
  "host": {"kernel": "6.x", "os": "Pop!_OS 26.04", "python": "3.13.15", "uid": 1000}
}
```

### GET /api/stats
```json
{"series": [{"t": 1690000000, "total": 10, "blocked": 2}],
 "top_blocked": [{"domain": "x.ads.com", "count": 12}],
 "by_type": {"A": 40, "AAAA": 10, "HTTPS": 2}}
```
60 one-minute buckets.

### GET /api/apps
```json
{"policy": "allow",
 "apps": [{"uid": 1000, "name": "kusal", "exe": "/usr/bin/firefox",
           "processes": 12, "conns": 5, "action": "allow",
           "packets": 123, "dropped": 4}]}
```
`policy`: `allow` = everything allowed except apps explicitly `block`ed;
`block` = everything blocked except apps explicitly `allow`ed.
`action`: the explicit rule (`allow`/`block`), or the policy default when none.

* `POST /api/apps` `{"uid":1000,"action":"block"}` → updated `{"ok":true}`
* `DELETE /api/apps/<uid>` → remove the explicit rule → `{"ok":true}`
* `POST /api/policy` `{"policy":"block"}` → `{"ok":true}`
* `POST /api/apps/refresh` → `{"ok":true}` (rescan /proc for sockets/processes)

### GET /api/blocklists
```json
{"categories": [{"id":"ads","name":"Ads & tracking","enabled":true,
                 "source":"https://raw.githubusercontent.com/…/hosts",
                 "domains":12345,"last_error":null}],
 "custom": [{"id":"c1","url":"https://…","enabled":true,"domains":200,"last_error":null}],
 "totals": {"domains": 50000, "enabled": 4}}
```

* `POST /api/blocklists` `{"id":"ads","enabled":false}` → `{"ok":true}`
* `POST /api/blocklists/custom` `{"url":"https://…","enabled":true}` → `{"ok":true}`
* `DELETE /api/blocklists/custom/<id>` → `{"ok":true}`
* `POST /api/blocklists/refresh` → `{"ok":true,"categories":n,"domains":n}`
* `POST /api/blocklists/test` `{"domain":"ads.example.com"}` →
  `{"blocked":true,"reason":"category:ads"}` (reason may be
  `custom:<url>`, `domain:block`, `domain:allow`, or `null`)

### GET /api/dns
```json
{"upstream": {"type":"doh","url":"https://dns.quad9.net/dns-query"},
 "hijack": true, "listen": "127.0.0.42:53",
 "queries": 12345, "blocked": 678,
 "log": [{"t":1690000000,"name":"example.com","type":"A","blocked":false,
          "reason":null,"client":"127.0.0.1"}],
 "allow": [], "block": ["bad.example.com"]}
```

* `POST /api/dns/upstream` `{"type":"system"|"doh"|"dot"|"plain","url":"…"}` → `{"ok":true}`
  (`system`/`plain` ignore `url`; `doh`/`dot` need one)
* `POST /api/dns/domain` `{"domain":"example.com","action":"block"|"allow"}` → `{"ok":true}`
* `DELETE /api/dns/domain/<domain>` → `{"ok":true}`
* `POST /api/dns/hijack` `{"enabled":true}` → `{"ok":true}`
* `POST /api/dns/clearlog` → `{"ok":true}`

### GET /api/proxy
```json
{"enabled": false, "type": "http", "host": "127.0.0.1", "port": 8080,
 "username": "", "password_set": false, "bypass_lan": true,
 "bypass_domains": ["*.local"], "active": 0, "relayed": 0, "last_error": null}
```
* `POST /api/proxy` same shape (`password` write-only, omitted when empty) → `{"ok":true}`
* `POST /api/proxy/toggle` `{"enabled":true}` → `{"ok":true}`

### GET /api/settings
```json
{"theme":"dark","start_protected":true,"log_level":"info",
 "listen":"127.0.0.1:8777","token_hint":"a1b2c3d4"}
```
* `POST /api/settings` → `{"ok":true}`

### GET /api/activity?limit=200
```json
{"events":[{"t":1690000000,"kind":"dns","name":"ads.x.com","action":"blocked",
            "reason":"category:ads","uid":null,"app":null}]}
```
`kind`: `dns` | `firewall` | `proxy`. `app` is a best-effort process name.

## Conventions

* All timestamps are unix epoch **seconds** (int).
* Numbers are ints unless noted.
* Every POST answers `{"ok":true}` plus any echoed field, unless it returns a resource.
* No CDN assets, no external requests from the UI.
