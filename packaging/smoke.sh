#!/usr/bin/env bash
# Unprivileged smoke test: boots the daemon (dry-run), exercises the API and the UI.
set -euo pipefail
cd "$(dirname "$0")/.."

TMP="$(mktemp -d /tmp/rethinkd-smoke.XXXXXX)"
export PYTHONPATH="$PWD/src"
export RETHINK_CONFIG="$TMP/config.json"
PORT=18777

python3 - "$TMP/config.json" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text(json.dumps({"settings": {"listen": "127.0.0.1:18777"}}))
PY

python3 -m rethinkd --dry-run --config "$TMP/config.json" >"$TMP/log" 2>&1 &
PID=$!
trap 'kill "$PID" 2>/dev/null || true; sleep 0.3; rm -rf "$TMP"' EXIT
sleep 1.2

grep -q "http://127.0.0.1:$PORT" "$TMP/log" || { cat "$TMP/log"; exit 1; }
TOKEN="$(cat "$TMP/token")"
auth=(-H "X-Auth-Token: $TOKEN")

fail() { echo "FAIL: $1" >&2; exit 1; }

curl -sf "http://127.0.0.1:$PORT/api/session" | grep -q '"authed": false' || fail "session"
[ "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:$PORT/api/status)" = "401" ] || fail "auth"
curl -sf "${auth[@]}" "http://127.0.0.1:$PORT/api/status" | grep -q '"protected": true' || fail "status"
curl -sf -o /dev/null "http://127.0.0.1:$PORT/" || fail "ui index"
curl -sf -o /dev/null "http://127.0.0.1:$PORT/app.js" || fail "ui js"
curl -sf -X POST "${auth[@]}" -d '{"domain":"smoke.test","action":"block"}' \
  "http://127.0.0.1:$PORT/api/dns/domain" >/dev/null || fail "block domain"
curl -sf -X POST "${auth[@]}" -d '{"domain":"smoke.test"}' \
  "http://127.0.0.1:$PORT/api/blocklists/test" | grep -q '"blocked": true' || fail "matcher"
curl -sf -X POST "${auth[@]}" -d '{"on":false}' "http://127.0.0.1:$PORT/api/protected" >/dev/null || fail "off"
curl -sf -X POST "${auth[@]}" -d '{"on":true}' "http://127.0.0.1:$PORT/api/protected" >/dev/null || fail "on"
RETHINK_CONFIG="$TMP/config.json" python3 bin/rethinkctl status | grep -q "protection : ON" || fail "rethinkctl"

echo "smoke ok"
