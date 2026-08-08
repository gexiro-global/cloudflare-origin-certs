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
# Set when a rollback failed: the work directory holds the only surviving copies of the
# previous pair, so it must outlive the run rather than being cleaned up under the operator.
KEEP_WORK=0
cleanup(){
  if [ "$KEEP_WORK" = 1 ] && [ -n "$WORK" ]; then
    echo "   recovery copies kept in $WORK - restore them by hand before re-running" >&2
    WORK=""
    KEEP_WORK=0
    return 0
  fi
  [ -n "$WORK" ] && rm -rf "$WORK"
  WORK=""
}
# A signal handler that only cleans up and returns lets the loop carry on to the next domain,
# so Ctrl-C would not actually stop issuance. Clean up, then exit with the conventional status.
on_signal(){ sig="$1"; cleanup; echo "interrupted by SIG${sig}" >&2; trap - EXIT; exit $((128 + $2)); }
# Publishing the cert/key pair (stage + two renames + match check) must not be splittable
# by a signal, or an interruption between the two renames would leave the new certificate
# with the old key. arm/disarm bracket that critical section: INT/TERM/HUP are ignored
# across it and re-armed immediately after. (SIGKILL/power loss between the two renames is
# the one residual; the next run re-issues and the post-install match check catches it.)
arm_signals(){ trap 'on_signal INT 2' INT; trap 'on_signal TERM 15' TERM; trap 'on_signal HUP 1' HUP; }
disarm_signals(){ trap '' INT TERM HUP; }
trap cleanup EXIT
arm_signals

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
# Private keys are written here, so refuse a symlinked or foreign-owned output dir: an
# attacker who controls it could redirect where keys land, or read them.
MY_UID=$(id -u)
if [ -L "$OUT_DIR" ] || [ ! -d "$OUT_DIR" ] || [ "$(stat -c %u "$OUT_DIR" 2>/dev/null)" != "$MY_UID" ]; then
  echo "unsafe output directory $OUT_DIR (must be a non-symlink directory you own)" >&2; exit 2
fi

# Two concurrent runs would interleave writes to the same certificate pair. Lock a
# validated directory under /run/lock, opened READ-ONLY (a directory cannot be truncated),
# NOT a lock file inside the output dir: a fixed lock file opened with `>` under an
# attacker-influenced output dir was a symlink-truncation primitive (CWE-59). Fail closed.
if [ "$DRY" = "0" ]; then
  command -v flock >/dev/null 2>&1 \
    || { echo "flock is required so two runs cannot write the same pair" >&2; exit 2; }
  if [ -n "${CF_ORIGIN_LOCK_DIR:-}" ]; then LOCK_DIR="$CF_ORIGIN_LOCK_DIR"
  elif [ "$MY_UID" = "0" ]; then LOCK_DIR=/run/lock/cf-origin-issue
  elif [ -n "${XDG_RUNTIME_DIR:-}" ] && [ -d "$XDG_RUNTIME_DIR" ]; then LOCK_DIR="$XDG_RUNTIME_DIR/cf-origin-issue"
  else LOCK_DIR="${TMPDIR:-/tmp}/cf-origin-issue-$MY_UID"; fi
  _lp=$(dirname "$LOCK_DIR")
  while :; do
    if [ -L "$_lp" ]; then echo "lock path ancestor is a symlink: $_lp" >&2; exit 2; fi
    if [ -e "$_lp" ]; then
      _lo=$(stat -c %u "$_lp" 2>/dev/null)
      if [ "$_lo" != "0" ] && [ "$_lo" != "$MY_UID" ]; then
        echo "lock path ancestor $_lp is owned by uid $_lo (not root or you)" >&2; exit 2
      fi
      _lm=$(stat -c %a "$_lp" 2>/dev/null); _lm=${_lm:-0}
      if [ "$(( (8#$_lm) & 18 ))" -ne 0 ] && [ "$(( (8#$_lm) & 512 ))" -eq 0 ]; then
        echo "lock path ancestor $_lp is group/world-writable and not sticky" >&2; exit 2
      fi
    fi
    _lpar=$(dirname "$_lp"); [ "$_lpar" = "$_lp" ] && break; _lp="$_lpar"
  done
  mkdir "$LOCK_DIR" 2>/dev/null || true
  if [ -L "$LOCK_DIR" ] || [ ! -d "$LOCK_DIR" ] || [ "$(stat -c %u "$LOCK_DIR" 2>/dev/null)" != "$MY_UID" ]; then
    echo "unsafe lock dir $LOCK_DIR (must be a non-symlink directory owned by uid $MY_UID)" >&2; exit 2
  fi
  { exec 7<"$LOCK_DIR"; } 2>/dev/null \
    || { echo "cannot open lock dir $LOCK_DIR" >&2; exit 2; }
  flock -n 7 || { echo "another issuance run holds the lock" >&2; exit 2; }
fi
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

  # Never install a certificate on the API's word alone. Verify it parses, belongs to the key we
  # generated, covers exactly the requested names, and is inside its validity window right now.
  printf '%s\n' "$cert" > "$WORK/verify.crt"

  if ! CERT_FILE="$WORK/verify.crt" KEY_FILE="$key" DOMAIN="$domain" python3 - <<'PY'
import datetime
import os
import subprocess
import sys

cert = os.environ['CERT_FILE']
key = os.environ['KEY_FILE']
domain = os.environ['DOMAIN'].lower()


def openssl(*args):
    return subprocess.run(['openssl', *args], capture_output=True, text=True)


if openssl('x509', '-noout', '-in', cert).returncode != 0:
    print('the response is not a parseable certificate', file=sys.stderr)
    raise SystemExit(1)

cert_mod = openssl('x509', '-noout', '-modulus', '-in', cert).stdout.strip()
key_mod = openssl('rsa', '-noout', '-modulus', '-in', key).stdout.strip()
if not cert_mod or cert_mod != key_mod:
    print('the certificate does not match the private key this run generated', file=sys.stderr)
    raise SystemExit(1)

# Compare whole SAN entries. A substring test would accept DNS:example.com.evil for example.com,
# because the requested name appears inside the longer one.
san_text = openssl('x509', '-noout', '-ext', 'subjectAltName', '-in', cert).stdout
names = set()
for chunk in san_text.replace('\n', ',').split(','):
    chunk = chunk.strip()
    if chunk.lower().startswith('dns:'):
        names.add(chunk[4:].strip().lower())

wanted = {domain, '*.' + domain}
missing = sorted(wanted - names)
if missing:
    print('certificate does not cover: ' + ', '.join(missing), file=sys.stderr)
    print('  it covers: ' + (', '.join(sorted(names)) or '(no DNS names)'), file=sys.stderr)
    raise SystemExit(1)


def field(name):
    out = openssl('x509', '-noout', name, '-in', cert).stdout.strip()
    value = out.split('=', 1)[1].replace('GMT', '').strip()
    # normalise the double space openssl uses for single-digit days
    return datetime.datetime.strptime(' '.join(value.split()), '%b %d %H:%M:%S %Y').replace(
        tzinfo=datetime.timezone.utc
    )


now = datetime.datetime.now(datetime.timezone.utc)
not_before = field('-startdate')
not_after = field('-enddate')

# -checkend only answers "does it expire soon". A certificate whose validity has not started yet
# would pass that and still be rejected by anything that checks the window.
if now < not_before:
    print('certificate is not valid yet (notBefore %s)' % not_before, file=sys.stderr)
    raise SystemExit(1)
if now >= not_after:
    print('certificate has already expired (notAfter %s)' % not_after, file=sys.stderr)
    raise SystemExit(1)
PY
  then
    echo '   FAILED: the returned certificate did not pass verification'
    cleanup; BAD=$((BAD+1)); continue
  fi

  echo '   verified: parses, matches the key, covers both names exactly, inside its validity window'

  # Installing a pair is transactional. The previous certificate and key are copied aside
  # first, because the old failure mode was: overwrite the certificate, fail to move the key,
  # delete the new certificate - and leave the host with a stale key and no certificate at
  # all. Any partial failure now restores BOTH previous files.
  crt_out="${OUT_DIR}/${domain}.crt"; key_out="${OUT_DIR}/${domain}.key"
  crt_tmp="$WORK/out.crt";   key_tmp="$WORK/out.key"
  crt_prev="$WORK/prev.crt"; key_prev="$WORK/prev.key"
  had_prev_crt=0; had_prev_key=0
  # Fail closed: if a previous file exists but cannot be copied aside, there is no rollback path,
  # so nothing may be overwritten. Continuing here was the difference between a transaction and a
  # best-effort attempt.
  if [ -f "$crt_out" ]; then
    if cp -p "$crt_out" "$crt_prev"; then
      had_prev_crt=1
    else
      echo "   FAILED: cannot back up the existing certificate; refusing to overwrite it"
      cleanup; BAD=$((BAD+1)); continue
    fi
  fi
  if [ -f "$key_out" ]; then
    if cp -p "$key_out" "$key_prev"; then
      had_prev_key=1
    else
      echo "   FAILED: cannot back up the existing key; refusing to overwrite it"
      cleanup; BAD=$((BAD+1)); continue
    fi
  fi

  # Rollback reports its own failures rather than swallowing them: an operator whose restore
  # silently failed is worse off than one who is told to look.
  restore_pair(){
    local rc=0
    if [ "$had_prev_crt" = 1 ]; then
      cp -p "$crt_prev" "$crt_out" || { echo "   ROLLBACK FAILED for $crt_out" >&2; rc=1; }
    else
      rm -f "$crt_out" || { echo "   ROLLBACK FAILED removing $crt_out" >&2; rc=1; }
    fi
    if [ "$had_prev_key" = 1 ]; then
      cp -p "$key_prev" "$key_out" || { echo "   ROLLBACK FAILED for $key_out" >&2; rc=1; }
    else
      rm -f "$key_out" || { echo "   ROLLBACK FAILED removing $key_out" >&2; rc=1; }
    fi
    [ "$rc" = 0 ] || echo "   the previous pair may be inconsistent - check $crt_out and $key_out" >&2
    return $rc
  }

  # --- critical section: publish the pair atomically w.r.t. INT/TERM/HUP --------------
  # With the signals disarmed, an interruption cannot land between the two renames and
  # leave a new cert with the old key. Any failure sets install_rc and rolls back; the
  # handlers are re-armed before the loop continues.
  disarm_signals
  install_rc=0
  if ! (umask 077; printf '%s\n' "$cert" > "$crt_tmp") \
     || ! (umask 077; cat "$key" > "$key_tmp"); then
    echo '   FAILED: could not stage the certificate or key'; install_rc=1
  fi
  if [ "$install_rc" = 0 ]; then
    chmod 600 "$crt_tmp" "$key_tmp" 2>/dev/null
    if ! mv -f "$crt_tmp" "$crt_out"; then
      echo '   FAILED: could not install the certificate; previous pair left untouched'
      restore_pair || KEEP_WORK=1; install_rc=1
    elif ! mv -f "$key_tmp" "$key_out"; then
      echo '   FAILED: could not install the key; restoring the previous pair'
      restore_pair || KEEP_WORK=1; install_rc=1
    else
      # Confirm what actually landed on disk matches, rather than trusting the moves.
      inst_crt=$(openssl x509 -noout -modulus -in "$crt_out" 2>/dev/null | openssl md5)
      inst_key=$(openssl rsa -noout -modulus -in "$key_out" 2>/dev/null | openssl md5)
      if [ -z "$inst_crt" ] || [ "$inst_crt" != "$inst_key" ]; then
        echo '   FAILED: the installed pair does not match; restoring the previous one'
        restore_pair || KEEP_WORK=1; install_rc=1
      fi
    fi
  fi
  arm_signals
  # --- end critical section -----------------------------------------------------------
  if [ "$install_rc" != 0 ]; then cleanup; BAD=$((BAD+1)); continue; fi
  cleanup

  echo "   issued -> $crt_out"
  OK=$((OK+1))
  sleep 2   # be polite to the API
done

echo
echo "issued=$OK failed=$BAD total=${#DOMAINS[@]}"
[ "$BAD" -eq 0 ]
