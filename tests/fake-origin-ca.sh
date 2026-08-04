#!/bin/bash
# fake-origin-ca.sh - stands in for `curl` against the Cloudflare Origin CA endpoint.
#
# Why this exists: the issuer generates its own private key and CSR, then verifies that the
# returned certificate matches that key. A canned certificate string can therefore never get past
# verification - which means every test downstream of it would pass without the install path ever
# running. This stub signs the CSR it is actually handed, so the certificate it returns genuinely
# matches the key the script just created.
#
# Driven by the environment:
#   FAKE_CA_DIR   working directory holding the throwaway CA and the recorded request
#   FAKE_CA_MODE  good | mismatched-key | missing-wildcard | expired | garbage
set -uo pipefail

DIR=${FAKE_CA_DIR:?FAKE_CA_DIR must be set}
MODE=${FAKE_CA_MODE:-good}

# Record what the caller sent, so tests can assert the credential never reached argv.
printf '%s\n' "$@" > "$DIR/argv.seen" 2>/dev/null || true
cat > "$DIR/stdin.seen" 2>/dev/null || true

if [ "$MODE" = garbage ]; then
  echo '{"success":true,"result":{"certificate":"this is not a certificate"}}'
  exit 0
fi

if [ ! -f "$DIR/ca.crt" ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
    -keyout "$DIR/ca.key" -out "$DIR/ca.crt" -subj '/CN=Test Origin CA' 2>/dev/null
fi

payload=""; prev=""
for a in "$@"; do
  [ "$prev" = "--data-binary" ] && payload="$a"
  prev="$a"
done

printf '%s' "$payload" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["csr"])' > "$DIR/req.csr" 2>/dev/null \
  || { echo '{"success":false,"errors":[{"message":"no csr in request"}]}'; exit 0; }

domain=$(printf '%s' "$payload" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["hostnames"][1])' 2>/dev/null)

if [ "$MODE" = missing-wildcard ]; then
  printf 'subjectAltName=DNS:%s\n' "$domain" > "$DIR/san.cnf"
else
  printf 'subjectAltName=DNS:%s,DNS:*.%s\n' "$domain" "$domain" > "$DIR/san.cnf"
fi

csr_in="$DIR/req.csr"
if [ "$MODE" = mismatched-key ]; then
  if [ ! -f "$DIR/other.csr" ]; then
    openssl req -new -newkey rsa:2048 -nodes -keyout "$DIR/other.key" \
      -out "$DIR/other.csr" -subj "/CN=$domain" 2>/dev/null
  fi
  csr_in="$DIR/other.csr"
fi

days=30
[ "$MODE" = expired ] && days=-1

openssl x509 -req -in "$csr_in" -CA "$DIR/ca.crt" -CAkey "$DIR/ca.key" -CAcreateserial \
  -days "$days" -extfile "$DIR/san.cnf" -out "$DIR/issued.crt" 2>/dev/null \
  || { echo '{"success":false,"errors":[{"message":"signing failed"}]}'; exit 0; }

python3 - "$DIR/issued.crt" <<'PY'
import json
import sys

with open(sys.argv[1], encoding='utf-8') as fh:
    print(json.dumps({"success": True, "result": {"certificate": fh.read()}}))
PY
