#!/bin/bash
# cf-origin-issue - issue Cloudflare Origin CA certificates in bulk.
#
# Origin CA certificates secure the hop between Cloudflare and your server. They are not
# publicly trusted, which is exactly the point: only Cloudflare needs to trust them, and
# they are what "Full (strict)" mode requires on the origin.
#
# Usage:
#   cf-origin-issue.sh --domains domains.txt [--out DIR] [--days N] [--dry-run]
#   cf-origin-issue.sh example.com another.example [--out DIR]
#
# Credentials (never passed on the command line, never written to disk by this script):
#   CF_ORIGIN_CA_KEY   your Cloudflare Origin CA key
#
# Exit: 0 all issued | 1 one or more failed | 2 usage/credential error
set -uo pipefail
umask 077

OUT_DIR="${CF_ORIGIN_OUT:-./origin-certs}"
VALIDITY_DAYS="${CF_ORIGIN_DAYS:-5475}"   # Cloudflare's own default: 15 years
DRY=0
DOMAINS=()
API="https://api.cloudflare.com/client/v4/certificates"

while [ $# -gt 0 ]; do
  case "$1" in
    --domains) shift; f="${1:?--domains needs a path}"
               [ -f "$f" ] || { echo "domain list not found: $f" >&2; exit 2; }
               while IFS= read -r line; do
                 line="${line%%#*}"; line=$(echo "$line" | tr -d '[:space:]')
                 [ -n "$line" ] && DOMAINS+=("$line")
               done < "$f" ;;
    --out)     shift; OUT_DIR="${1:?--out needs a path}" ;;
    --days)    shift; VALIDITY_DAYS="${1:?--days needs a number}" ;;
    --dry-run) DRY=1 ;;
    -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
    -*)        echo "unknown argument: $1" >&2; exit 2 ;;
    *)         DOMAINS+=("$1") ;;
  esac
  shift
done

[ "${#DOMAINS[@]}" -gt 0 ] || { echo 'no domains given (use --domains FILE or list them as arguments)' >&2; exit 2; }
command -v openssl >/dev/null 2>&1 || { echo 'openssl is required' >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo 'python3 is required (JSON handling)' >&2; exit 2; }

if [ "$DRY" = "0" ] && [ -z "${CF_ORIGIN_CA_KEY:-}" ]; then
  echo 'CF_ORIGIN_CA_KEY is not set.' >&2
  echo 'Get the Origin CA key from the Cloudflare dashboard and export it in your shell:' >&2
  echo '  read -rs CF_ORIGIN_CA_KEY && export CF_ORIGIN_CA_KEY' >&2
  exit 2
fi

mkdir -p "$OUT_DIR"
OK=0; BAD=0

for domain in "${DOMAINS[@]}"; do
  echo "== $domain"

  if [ "$DRY" = "1" ]; then
    echo "   dry-run: would request *.${domain} and ${domain}, validity ${VALIDITY_DAYS} days"
    echo "   dry-run: would write ${OUT_DIR}/${domain}.crt and ${OUT_DIR}/${domain}.key"
    OK=$((OK+1)); continue
  fi

  work=$(mktemp -d) || { echo '   cannot create temp dir'; BAD=$((BAD+1)); continue; }
  csr="$work/req.csr"; key="$work/req.key"

  echo '   [1/3] generating key and CSR'
  if ! openssl req -new -newkey rsa:2048 -nodes -out "$csr" -keyout "$key" \
        -subj "/CN=${domain}" 2>/dev/null; then
    echo '   FAILED to generate CSR'; rm -rf "$work"; BAD=$((BAD+1)); continue
  fi

  echo '   [2/3] requesting certificate from Cloudflare'
  # Build the request with a JSON encoder rather than string interpolation - a PEM body
  # inside a hand-built JSON string is one stray character away from a malformed request
  # that fails in a confusing way.
  payload=$(CSR_PATH="$csr" DOMAIN="$domain" DAYS="$VALIDITY_DAYS" python3 -c '
import json, os
with open(os.environ["CSR_PATH"], encoding="utf-8") as fh:
    csr = fh.read()
domain = os.environ["DOMAIN"]
print(json.dumps({
    "hostnames": [f"*.{domain}", domain],
    "requested_validity": int(os.environ["DAYS"]),
    "request_type": "origin-rsa",
    "csr": csr,
}))')

  response=$(curl -sS --max-time 45 -X POST "$API" \
    -H "X-Auth-User-Service-Key: ${CF_ORIGIN_CA_KEY}" \
    -H 'Content-Type: application/json' \
    --data-binary "$payload" 2>&1)

  echo '   [3/3] parsing response'
  cert=$(printf '%s' "$response" | python3 -c '
import json, sys
try:
    data = json.load(sys.stdin)
except Exception:
    sys.exit(1)
if not data.get("success"):
    msgs = "; ".join(str(e.get("message", e)) for e in data.get("errors") or []) or "unknown error"
    print("ERROR:" + msgs)
    sys.exit(0)
print(data.get("result", {}).get("certificate", ""))
' 2>/dev/null)

  case "$cert" in
    '')        echo '   FAILED: could not parse the Cloudflare response'; rm -rf "$work"; BAD=$((BAD+1)); continue ;;
    ERROR:*)   echo "   FAILED: ${cert#ERROR:}"; rm -rf "$work"; BAD=$((BAD+1)); continue ;;
  esac

  install -m 600 /dev/null "${OUT_DIR}/${domain}.crt"
  install -m 600 /dev/null "${OUT_DIR}/${domain}.key"
  printf '%s\n' "$cert" > "${OUT_DIR}/${domain}.crt"
  cat "$key" > "${OUT_DIR}/${domain}.key"
  rm -rf "$work"

  echo "   issued -> ${OUT_DIR}/${domain}.crt"
  OK=$((OK+1))
  sleep 2   # be polite to the API
done

echo
echo "issued=$OK failed=$BAD total=${#DOMAINS[@]}"
[ "$BAD" -eq 0 ]
