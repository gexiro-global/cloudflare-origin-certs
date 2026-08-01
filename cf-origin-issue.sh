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
# Credentials (never in the command line, never written to disk):
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
WORK=""

# The work directory holds a freshly generated private key. Remove it on any exit path,
# including Ctrl-C and SIGTERM - not only on the happy path.
cleanup(){ [ -n "$WORK" ] && rm -rf "$WORK"; WORK=""; }
# A signal handler that only cleans up and returns lets the loop carry on to the next domain,
# so Ctrl-C would not actually stop issuance. Clean up, then exit with the conventional status.
on_signal(){ sig="$1"; cleanup; echo "interrupted by SIG${sig}" >&2; trap - EXIT; exit $((128 + $2)); }
trap cleanup EXIT
trap 'on_signal INT 2'  INT
trap 'on_signal TERM 15' TERM
trap 'on_signal HUP 1'   HUP

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

# Domain names end up in filesystem paths below. Anything that is not a plain hostname is
# rejected here rather than sanitised, so a crafted entry like "../../etc/x" in a domain list
# cannot escape the output directory.
for d in "${DOMAINS[@]}"; do
  case "$d" in
    *[!a-zA-Z0-9.-]*|.*|-*|*.|*..*|'')
      echo "refusing implausible domain name: '$d'" >&2; exit 2 ;;
  esac
  printf '%s' "$d" | grep -qE '^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$' \
    || { echo "refusing implausible domain name: '$d'" >&2; exit 2; }
done

case "$VALIDITY_DAYS" in
  ''|*[!0-9]*) echo "--days must be a whole number of days, got '$VALIDITY_DAYS'" >&2; exit 2 ;;
esac

command -v openssl >/dev/null 2>&1 || { echo 'openssl is required' >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo 'python3 is required (JSON handling)' >&2; exit 2; }

if [ "$DRY" = "0" ]; then
  if [ -z "${CF_ORIGIN_CA_KEY:-}" ]; then
    echo 'CF_ORIGIN_CA_KEY is not set.' >&2
    echo 'Get the Origin CA key from the Cloudflare dashboard and export it in your shell:' >&2
    echo '  read -rs CF_ORIGIN_CA_KEY && export CF_ORIGIN_CA_KEY' >&2
    exit 2
  fi
  # The key is interpolated into curl config syntax below. A quote, backslash or newline in it
  # would let the value inject further curl directives, so refuse anything that is not a plain
  # credential token.
  case "$CF_ORIGIN_CA_KEY" in
    *[!a-zA-Z0-9_.-]*) echo 'CF_ORIGIN_CA_KEY contains unexpected characters; refusing to use it' >&2; exit 2 ;;
  esac
fi

mkdir -p "$OUT_DIR" || { echo "cannot create output directory: $OUT_DIR" >&2; exit 2; }
OK=0; BAD=0

for domain in "${DOMAINS[@]}"; do
  echo "== $domain"

  if [ "$DRY" = "1" ]; then
    echo "   dry-run: would request *.${domain} and ${domain}, validity ${VALIDITY_DAYS} days"
    echo "   dry-run: would write ${OUT_DIR}/${domain}.crt and ${OUT_DIR}/${domain}.key"
    OK=$((OK+1)); continue
  fi

  WORK=$(mktemp -d) || { echo '   FAILED: cannot create temp dir'; BAD=$((BAD+1)); continue; }
  csr="$WORK/req.csr"; key="$WORK/req.key"

  echo '   [1/3] generating key and CSR'
  if ! openssl req -new -newkey rsa:2048 -nodes -out "$csr" -keyout "$key" \
        -subj "/CN=${domain}" 2>/dev/null; then
    echo '   FAILED to generate CSR'; cleanup; BAD=$((BAD+1)); continue
  fi

  echo '   [2/3] requesting certificate from Cloudflare'
  # Build the request with a JSON encoder rather than string interpolation - a PEM body
  # inside a hand-built JSON string is one stray character away from a malformed request
  # that fails in a confusing way.
  if ! payload=$(CSR_PATH="$csr" DOMAIN="$domain" DAYS="$VALIDITY_DAYS" python3 -c '
import json, os, sys
try:
    with open(os.environ["CSR_PATH"], encoding="utf-8") as fh:
        csr = fh.read()
    domain = os.environ["DOMAIN"]
    print(json.dumps({
        "hostnames": [f"*.{domain}", domain],
        "requested_validity": int(os.environ["DAYS"]),
        "request_type": "origin-rsa",
        "csr": csr,
    }))
except Exception as exc:
    print(exc, file=sys.stderr)
    raise SystemExit(1)
'); then
    echo '   FAILED: could not build the request payload'; cleanup; BAD=$((BAD+1)); continue
  fi

  # The credential goes to curl on STDIN as a config stream: not in the command line, where
  # /proc would expose it to other local users, and not in a file, where an abrupt exit would
  # leave it on disk.
  response=$(printf 'header = "X-Auth-User-Service-Key: %s"\n' "$CF_ORIGIN_CA_KEY" \
    | curl -sS --max-time 45 -X POST "$API" -K - \
        -H 'Content-Type: application/json' \
        --data-binary "$payload" 2>&1)
  curl_rc=$?
  if [ "$curl_rc" -ne 0 ]; then
    echo "   FAILED: curl exited $curl_rc (${response:-no output})"
    cleanup; BAD=$((BAD+1)); continue
  fi

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
    '')        echo '   FAILED: could not parse the Cloudflare response'; cleanup; BAD=$((BAD+1)); continue ;;
    ERROR:*)   echo "   FAILED: ${cert#ERROR:}"; cleanup; BAD=$((BAD+1)); continue ;;
  esac

  # Write both files completely inside the work directory first, then move them into place.
  # Truncating the destinations up front means a failure partway through destroys a previously
  # valid certificate and leaves a mismatched pair behind.
  crt_out="${OUT_DIR}/${domain}.crt"; key_out="${OUT_DIR}/${domain}.key"
  crt_tmp="$WORK/out.crt"; key_tmp="$WORK/out.key"
  if ! (umask 077; printf '%s\n' "$cert" > "$crt_tmp") || ! (umask 077; cat "$key" > "$key_tmp"); then
    echo '   FAILED: could not stage the certificate or key'; cleanup; BAD=$((BAD+1)); continue
  fi
  chmod 600 "$crt_tmp" "$key_tmp" 2>/dev/null
  if ! mv -f "$crt_tmp" "$crt_out"; then
    echo '   FAILED: could not install the certificate'; cleanup; BAD=$((BAD+1)); continue
  fi
  if ! mv -f "$key_tmp" "$key_out"; then
    # The certificate landed but the key did not: remove the half-written pair rather than
    # leaving a certificate whose key is missing or stale.
    echo '   FAILED: could not install the key; removing the orphaned certificate'
    rm -f "$crt_out"
    cleanup; BAD=$((BAD+1)); continue
  fi
  cleanup

  echo "   issued -> $crt_out"
  OK=$((OK+1))
  sleep 2   # be polite to the API
done

echo
echo "issued=$OK failed=$BAD total=${#DOMAINS[@]}"
[ "$BAD" -eq 0 ]
