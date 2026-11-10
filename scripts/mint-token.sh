#!/usr/bin/env bash
# Mint an RS256 test token with the test keys. Needs only openssl.
#   ./scripts/mint-token.sh                          -> read scope, current key
#   SCOPE="write:documents" ./scripts/mint-token.sh
#   KID=retired ./scripts/mint-token.sh              -> should be rejected
#   AUD=billing-api ./scripts/mint-token.sh          -> should be rejected
set -euo pipefail
cd "$(dirname "$0")/.."

KID="${KID:-current}"
SCOPE="${SCOPE:-read:documents}"
ISS="${ISS:-https://auth.example.test}"
AUD="${AUD:-documents-api}"
TTL="${TTL:-300}"
ROLES="${ROLES:-}"            # e.g. ROLES='"admin"'
PERMISSIONS="${PERMISSIONS:-}" # e.g. PERMISSIONS='"documents:read:all"'

b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }

now=$(date +%s)
header=$(printf '{"alg":"RS256","typ":"JWT","kid":"%s"}' "$KID" | b64url)
payload=$(printf '{"sub":"reader-1","iss":"%s","aud":"%s","iat":%d,"exp":%d,"scope":"%s","roles":[%s],"permissions":[%s]}' \
  "$ISS" "$AUD" "$now" "$((now + TTL))" "$SCOPE" "$ROLES" "$PERMISSIONS" | b64url)
signature=$(printf '%s.%s' "$header" "$payload" | openssl dgst -sha256 -sign "src/test/resources/keys/$KID.pem" | b64url)

echo "$header.$payload.$signature"
