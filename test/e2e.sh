#!/usr/bin/env bash
# Local end-to-end test: fake Okta + transmitter + web app.
# Logs in, sends a high user-risk SET, and checks that the app session is gone.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
J=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$J"' EXIT

FAKE=http://localhost:5055 TX=http://localhost:4000 APP=http://localhost:3000

PROVIDER_WELL_KNOWN=$TX/.well-known/ssf-configuration APP_LOGOUT_URL=$APP/global-token-revocation \
  node "$ROOT/test/fake-okta.js" > "$J/okta.log" 2>&1 &
(cd "$ROOT/transmitter" && OKTA_ORG_URL=$FAKE ADMIN_PASSWORD=pw node src/server.js > "$J/tx.log" 2>&1) &
(cd "$ROOT/webapp" && OKTA_ORG_URL=$FAKE OKTA_CLIENT_ID=demo-client OKTA_CLIENT_SECRET=s node src/server.js > "$J/app.log" 2>&1) &
for u in $FAKE/oauth2/v1/keys $TX/healthz $APP/healthz; do
  for i in $(seq 1 50); do curl -sf "$u" >/dev/null && break; sleep 0.2; done
done

C="$J/cookies"
echo "1. OIDC login"
curl -s -c "$C" -b "$C" -L -o /dev/null "$APP/login"
curl -s -b "$C" "$APP/api/me"; echo

echo "2. Metadata"
curl -s "$TX/.well-known/ssf-configuration"; echo
curl -s "$TX/.well-known/jwks.json" | head -c 160; echo ...

echo "3. Bad password is rejected"
curl -s -o /dev/null -w "%{http_code}\n" -X POST "$TX/api/events" -H 'Content-Type: application/json' -d '{}'

echo "4. Send user-risk-change (low -> high)"
curl -s -u admin:pw -X POST "$TX/api/events" -H 'Content-Type: application/json' \
  -d '{"type":"user-risk-change","email":"demo.user@example.com","previousLevel":"low","currentLevel":"high","reason":"test"}' \
  | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{const j=JSON.parse(s);console.log("delivery:",JSON.stringify(j.delivery));console.log(JSON.stringify(j.decoded,null,1))})'
sleep 0.5

echo "5. Session after SET"
ME=$(curl -s -b "$C" "$APP/api/me"); echo "$ME"
echo "fake okta saw:"; curl -s $FAKE/_received; echo

echo "6. Other event types are accepted (dry check against the receiver)"
for t in session-revoked device-risk-change ip-change device-compliance-change identifier-changed; do
  printf "%-26s " $t
  curl -s -u admin:pw -X POST "$TX/api/events" -H 'Content-Type: application/json' \
    -d "{\"type\":\"$t\",\"email\":\"demo.user@example.com\",\"newValue\":\"x@example.com\"}" \
    | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>console.log(JSON.parse(s).delivery?.status))'
done

echo "7. Logout endpoint rejects unauthenticated calls"
curl -s -o /dev/null -w "%{http_code}\n" -X POST "$APP/global-token-revocation" -H 'Content-Type: application/json' \
  -d '{"sub_id":{"format":"email","email":"demo.user@example.com"}}'
echo "--- app log"; cat "$J/app.log"

echo "$ME" | grep -q '"authenticated":false' && echo "PASS: SET -> Universal Logout ended the app session" || { echo FAIL; exit 1; }
