#!/bin/sh -eu
# oauth_smoke.sh — end-to-end exercise of the embedded OAuth 2.1 AS.
#
# Drives the exact dance a claude.ai / ChatGPT connector performs: discovery,
# dynamic client registration, the authorize form, a credentialed login, the
# PKCE code exchange, an authenticated tools/list, a refresh rotation, and —
# the part humans never test by hand — re-presenting the rotated-out refresh
# token and demanding the family die for it.
#
# Usage:
#   BASE=http://127.0.0.1:17718 PRINCIPAL=operator PASSWORD=... ./oauth_smoke.sh
#
# BASE defaults to the local loopback server; point it at
# https://gptimage.specterpoint.com to smoke the real deployment. Needs curl
# + python3 (for JSON poking; present on the VPS and in Git Bash).

BASE="${BASE:-http://127.0.0.1:17718}"
PRINCIPAL="${PRINCIPAL:-operator}"
: "${PASSWORD:?set PASSWORD in the environment (never argv — ps would show it)}"
REDIRECT="${REDIRECT:-https://claude.ai/api/mcp/auth_callback}"
PYTHON="${PYTHON:-python3}"   # Windows Git Bash ships `python`, not `python3`

say()  { printf '\033[1m[smoke]\033[0m %s\n' "$*"; }
die()  { printf '\033[31m[smoke] FAIL:\033[0m %s\n' "$*" >&2; exit 1; }
json() { "$PYTHON" -c "import json,sys; d=json.load(sys.stdin); print(d$1)"; }

# --- 1. discovery ------------------------------------------------------------
say "discovery documents"
PRM=$(curl -fsS "$BASE/.well-known/oauth-protected-resource/mcp") || die "protected-resource metadata"
echo "$PRM" | json "['authorization_servers'][0]" >/dev/null || die "PRM missing authorization_servers"

ASM=$(curl -fsS "$BASE/.well-known/oauth-authorization-server") || die "AS metadata"
AUTHZ=$(echo "$ASM" | json "['authorization_endpoint']")
TOKEN=$(echo "$ASM" | json "['token_endpoint']")
REG=$(echo "$ASM"   | json "['registration_endpoint']")
echo "$ASM" | json "['code_challenge_methods_supported']" | grep -q S256 || die "S256 not advertised"

curl -fsS "$BASE/.well-known/openid-configuration" >/dev/null || die "openid-configuration alias"
curl -fsS "$BASE/.well-known/jwks.json" | json "['keys'][0]['kid']" >/dev/null || die "jwks"

# When smoking a local instance the metadata carries the public issuer; keep
# hitting BASE by swapping the origin.
rebase() { printf '%s' "$1" | "$PYTHON" -c "
import sys,urllib.parse as u
url=sys.stdin.read(); base='$BASE'
p=u.urlsplit(url); b=u.urlsplit(base)
print(u.urlunsplit((b.scheme,b.netloc,p.path,p.query,p.fragment)))"; }
AUTHZ=$(rebase "$AUTHZ"); TOKEN=$(rebase "$TOKEN"); REG=$(rebase "$REG")

# --- 2. dynamic client registration -------------------------------------------
say "dynamic client registration"
REG_RESP=$(curl -fsS -X POST "$REG" -H 'Content-Type: application/json' -d "{
  \"client_name\": \"oauth_smoke\",
  \"redirect_uris\": [\"$REDIRECT\"],
  \"token_endpoint_auth_method\": \"none\",
  \"grant_types\": [\"authorization_code\", \"refresh_token\"]
}") || die "registration refused"
CLIENT_ID=$(echo "$REG_RESP" | json "['client_id']")
say "client_id=$CLIENT_ID"

# --- 3. PKCE material ----------------------------------------------------------
VERIFIER=$("$PYTHON" -c "import secrets; print(secrets.token_urlsafe(48)[:64])")
CHALLENGE=$(printf '%s' "$VERIFIER" | "$PYTHON" -c "
import sys,hashlib,base64
v=sys.stdin.read().encode()
print(base64.urlsafe_b64encode(hashlib.sha256(v).digest()).rstrip(b'=').decode())")
STATE=$("$PYTHON" -c "import secrets; print(secrets.token_urlsafe(16))")

# --- 4. authorize: form renders, then credentialed POST ------------------------
say "authorize form"
QS="response_type=code&client_id=$CLIENT_ID&redirect_uri=$("$PYTHON" -c "import urllib.parse;print(urllib.parse.quote('$REDIRECT',safe=''))")&code_challenge=$CHALLENGE&code_challenge_method=S256&state=$STATE"
curl -fsS "$AUTHZ?$QS" | grep -qi '<form' || die "authorize did not render a login form"

say "login as $PRINCIPAL"
LOCATION=$(curl -fsS -o /dev/null -w '%{redirect_url}' -X POST "$AUTHZ" \
  --data-urlencode "principal=$PRINCIPAL" \
  --data-urlencode "password=$PASSWORD" \
  --data-urlencode "response_type=code" \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "redirect_uri=$REDIRECT" \
  --data-urlencode "code_challenge=$CHALLENGE" \
  --data-urlencode "code_challenge_method=S256" \
  --data-urlencode "state=$STATE")
case "$LOCATION" in "$REDIRECT"*) ;; *) die "no redirect back to client (got: $LOCATION)";; esac
CODE=$(printf '%s' "$LOCATION" | "$PYTHON" -c "
import sys,urllib.parse as u
q=u.parse_qs(u.urlsplit(sys.stdin.read()).query)
assert q['state'][0]=='$STATE', 'state mismatch'
print(q['code'][0])")
say "authorization code obtained"

# --- 5. code exchange -----------------------------------------------------------
say "token exchange (PKCE)"
TOK=$(curl -fsS -X POST "$TOKEN" \
  --data-urlencode "grant_type=authorization_code" \
  --data-urlencode "code=$CODE" \
  --data-urlencode "redirect_uri=$REDIRECT" \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "code_verifier=$VERIFIER") || die "code exchange refused"
AT=$(echo "$TOK" | json "['access_token']")
RT1=$(echo "$TOK" | json "['refresh_token']")

# --- 6. authenticated MCP call ----------------------------------------------------
say "tools/list with the JWT"
TOOLS=$(curl -fsS -X POST "$BASE/mcp" \
  -H "Authorization: Bearer $AT" \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}') || die "authenticated /mcp failed"
echo "$TOOLS" | grep -q gptimage_search || die "tools/list missing gptimage_search"

# --- 7. refresh rotation + reuse detection -----------------------------------------
say "refresh rotation"
TOK2=$(curl -fsS -X POST "$TOKEN" \
  --data-urlencode "grant_type=refresh_token" \
  --data-urlencode "refresh_token=$RT1" \
  --data-urlencode "client_id=$CLIENT_ID") || die "refresh refused"
RT2=$(echo "$TOK2" | json "['refresh_token']")
[ "$RT1" != "$RT2" ] || die "refresh token did not rotate"

say "rotated-token reuse must revoke the family"
curl -fsS -o /dev/null -X POST "$TOKEN" \
  --data-urlencode "grant_type=refresh_token" \
  --data-urlencode "refresh_token=$RT1" \
  --data-urlencode "client_id=$CLIENT_ID" 2>/dev/null && die "rotated-token reuse was ACCEPTED"

curl -fsS -o /dev/null -X POST "$TOKEN" \
  --data-urlencode "grant_type=refresh_token" \
  --data-urlencode "refresh_token=$RT2" \
  --data-urlencode "client_id=$CLIENT_ID" 2>/dev/null && die "family survivor still works after reuse (family not revoked)"
say "reuse detected, family revoked (good)"

# --- 8. code replay (LAST: replay detection revokes this code's tokens) ------------
# Per RFC 9700 a replayed code must be refused AND revoke what it minted —
# which is why this probe runs after every other check.
curl -fsS -o /dev/null -X POST "$TOKEN" \
  --data-urlencode "grant_type=authorization_code" \
  --data-urlencode "code=$CODE" \
  --data-urlencode "redirect_uri=$REDIRECT" \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "code_verifier=$VERIFIER" 2>/dev/null && die "code replay was ACCEPTED"
say "code replay refused (good)"

say "ALL CHECKS PASSED"
