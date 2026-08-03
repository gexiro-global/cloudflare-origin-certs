#!/bin/bash
# Offline test suite. No Cloudflare API calls, no OpenLiteSpeed, no root.
# shellcheck disable=SC2015,SC2016,SC2181
# SC2015: the `[ cond ] && ok "..." || no "..."` shape is intentional here - `ok` cannot fail,
#         so this is a two-branch report, not a mis-written if-then-else.
# SC2016: single quotes are deliberate where a literal `$` belongs to awk, python or a stub.
# SC2181: these suites check `$?` immediately after the command under test, which is the
#         thing being asserted.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(dirname "$HERE")
PASS=0; FAIL=0
ok(){ echo "  ok   - $1"; PASS=$((PASS+1)); }
no(){ echo "  FAIL - $1"; FAIL=$((FAIL+1)); }

T=$(mktemp -d); trap 'rm -rf "$T"' EXIT

echo '== cf-origin-issue =='
OUT=$("$ROOT/cf-origin-issue.sh" --dry-run --domains "$ROOT/examples/domains.example.txt" --out "$T/certs" 2>&1)
printf '%s' "$OUT" | grep -q 'issued=2 failed=0' \
  && ok 'parses the domain list and honours --dry-run' || no 'parses the domain list and honours --dry-run'
[ -z "$(ls -A "$T/certs" 2>/dev/null)" ] \
  && ok 'dry run writes no certificates' || no 'dry run writes no certificates'

( unset CF_ORIGIN_CA_KEY; "$ROOT/cf-origin-issue.sh" example.com --out "$T/certs" >/dev/null 2>&1 )
[ $? -eq 2 ] && ok 'refuses to run without a credential' || no 'refuses to run without a credential'

"$ROOT/cf-origin-issue.sh" --dry-run --out "$T/certs" >/dev/null 2>&1
[ $? -eq 2 ] && ok 'refuses to run with no domains' || no 'refuses to run with no domains'

echo '== ols-ssl-wire =='
mkdir -p "$T/certs2" "$T/vhosts/site-a.example" "$T/vhosts/site-b.example"
touch "$T/certs2/site-a.example.crt" "$T/certs2/site-a.example.key"
touch "$T/certs2/orphan.example.crt"   # no key -> must be skipped
printf 'docRoot $VH_ROOT/public_html\n\ncontext / {\n  keyFile /should/not/be/touched\n}\n' > "$T/vhosts/site-a.example/vhost.conf"
printf 'docRoot $VH_ROOT/public_html\n' > "$T/vhosts/site-b.example/vhost.conf"
BEFORE=$(cat "$T/vhosts/site-a.example/vhost.conf")

OUT=$("$ROOT/ols-ssl-wire.sh" --certs "$T/certs2" --vhosts "$T/vhosts" 2>&1)
printf '%s' "$OUT" | grep -q 'WOULD append a vhssl block for site-a.example' \
  && ok 'dry run is the default and reports the intended change' || no 'dry run is the default and reports the intended change'
[ "$(cat "$T/vhosts/site-a.example/vhost.conf")" = "$BEFORE" ] \
  && ok 'dry run leaves vhost configs untouched' || no 'dry run leaves vhost configs untouched'
printf '%s' "$OUT" | grep -q 'SKIP orphan.example - no matching key' \
  && ok 'skips a certificate with no key' || no 'skips a certificate with no key'

"$ROOT/ols-ssl-wire.sh" --certs "$T/certs2" --vhosts "$T/vhosts" --apply >/dev/null 2>&1
grep -q 'vhssl {' "$T/vhosts/site-a.example/vhost.conf" \
  && ok '--apply appends a vhssl block' || no '--apply appends a vhssl block'
grep -q '/should/not/be/touched' "$T/vhosts/site-a.example/vhost.conf" \
  && ok 'leaves keyFile in other blocks alone' || no 'leaves keyFile in other blocks alone'
ls "$T/vhosts/site-a.example/"vhost.conf.bak.* >/dev/null 2>&1 \
  && ok 'backs up the config before editing' || no 'backs up the config before editing'

# second pass must update in place, not append a duplicate block
"$ROOT/ols-ssl-wire.sh" --certs "$T/certs2" --vhosts "$T/vhosts" --apply >/dev/null 2>&1
[ "$(grep -c 'vhssl {' "$T/vhosts/site-a.example/vhost.conf")" = "1" ] \
  && ok 'is idempotent - no duplicate vhssl block on re-run' || no 'is idempotent - no duplicate vhssl block on re-run'
grep -A3 'vhssl {' "$T/vhosts/site-a.example/vhost.conf" | grep -q "$T/certs2/site-a.example.key" \
  && ok 'updates keyFile inside the vhssl block' || no 'updates keyFile inside the vhssl block'
grep -q '/should/not/be/touched' "$T/vhosts/site-a.example/vhost.conf" \
  && ok 'update pass still leaves other blocks alone' || no 'update pass still leaves other blocks alone'

echo '== regressions =='
# A vhssl block that exists but lacks keyFile/certFile must have them inserted, not be
# silently reported as wired.
mkdir -p "$T/certs3" "$T/vhosts3/site.example"
touch "$T/certs3/site.example.crt" "$T/certs3/site.example.key"
printf 'docRoot /x\n\nvhssl {\n  certChain 0\n}\n' > "$T/vhosts3/site.example/vhost.conf"
"$ROOT/ols-ssl-wire.sh" --certs "$T/certs3" --vhosts "$T/vhosts3" --apply >/dev/null 2>&1
if grep -q 'keyFile' "$T/vhosts3/site.example/vhost.conf" && grep -q 'certFile' "$T/vhosts3/site.example/vhost.conf"; then
  ok 'inserts keyFile/certFile into a vhssl block that lacks them'
else
  no 'inserts keyFile/certFile into a vhssl block that lacks them'
fi

# A domain name is used to build a filesystem path, so anything that is not a plain
# hostname must be refused before it can traverse out of the output directory.
for bad in '../../etc/evil' 'has space' '-leading-dash' 'trailing.dot.'; do
  if "$ROOT/cf-origin-issue.sh" --dry-run --out "$T/certs3" "$bad" >/dev/null 2>&1; then
    no "refuses implausible domain '$bad'"
  else
    ok "refuses implausible domain '$bad'"
  fi
done
"$ROOT/cf-origin-issue.sh" --dry-run --out "$T/certs3" 'good.example.com' >/dev/null 2>&1 \
  && ok 'still accepts a normal hostname' || no 'still accepts a normal hostname'

# Assert the runtime property rather than a spelling in the source: run the script against a
# stub curl that records its own argv, and check the secret is not in it. A source grep would
# still pass if the credential were passed some other way.
CSTUB=$(mktemp -d)
SECRET='SENTINELsecretvalue123'
cat > "$CSTUB/curl" <<'STUBEOF'
#!/bin/bash
printf '%s\n' "$@" > "$ARGV_DUMP"
cat > "$STDIN_DUMP"
echo '{"success":true,"result":{"certificate":"-----BEGIN CERTIFICATE-----"}}'
STUBEOF
chmod +x "$CSTUB/curl"
mkdir -p "$CSTUB/out"
PATH="$CSTUB:$PATH" ARGV_DUMP="$CSTUB/argv" STDIN_DUMP="$CSTUB/stdin" \
  CF_ORIGIN_CA_KEY="$SECRET" "$ROOT/cf-origin-issue.sh" --out "$CSTUB/out" stub.example >/dev/null 2>&1

if [ -f "$CSTUB/argv" ]; then
  if grep -q "$SECRET" "$CSTUB/argv"; then
    no 'the credential never reaches curl argv'
  else
    ok 'the credential never reaches curl argv'
  fi
  if grep -q "$SECRET" "$CSTUB/stdin" 2>/dev/null; then
    ok 'the credential is delivered on stdin instead'
  else
    no 'the credential is delivered on stdin instead'
  fi
else
  no 'the credential never reaches curl argv (stub curl was not invoked)'
fi

if grep -rq "$SECRET" "$CSTUB/out" 2>/dev/null; then
  no 'no credential is left behind on disk'
else
  ok 'no credential is left behind on disk'
fi
rm -rf "$CSTUB"

# A signal handler that cleans up but returns lets the loop continue to the next domain, so
# Ctrl-C would not actually stop issuance. Deterministic check: a stub openssl terminates the
# script while the SECOND domain is being processed, and the second certificate must not exist.
SIG=$(mktemp -d)
mkdir -p "$SIG/out"
cat > "$SIG/openssl" <<'STUBEOF'
#!/bin/bash
COUNT_FILE="$STUB_DIR/count"
n=$(cat "$COUNT_FILE" 2>/dev/null || echo 0)
n=$((n + 1))
echo "$n" > "$COUNT_FILE"
if [ "$n" -ge 2 ]; then
  kill -TERM "$PPID" 2>/dev/null
  sleep 5
  exit 1
fi
# first domain: produce a usable key and CSR
out=""; keyout=""
while [ $# -gt 0 ]; do
  case "$1" in
    -out) shift; out="$1" ;;
    -keyout) shift; keyout="$1" ;;
  esac
  shift
done
[ -n "$out" ] && echo 'stub-csr' > "$out"
[ -n "$keyout" ] && echo 'stub-key' > "$keyout"
exit 0
STUBEOF
cat > "$SIG/curl" <<'STUBEOF'
#!/bin/bash
cat >/dev/null
echo '{"success":true,"result":{"certificate":"stub-cert"}}'
STUBEOF
chmod +x "$SIG/openssl" "$SIG/curl"

mkdir -p "$SIG/tmp"
set +e
PATH="$SIG:$PATH" STUB_DIR="$SIG" TMPDIR="$SIG/tmp" CF_ORIGIN_CA_KEY=stubkey \
  "$ROOT/cf-origin-issue.sh" --out "$SIG/out" first.example second.example >/dev/null 2>&1
SIGRC=$?
set -e

if [ -f "$SIG/out/second.example.crt" ]; then
  no 'a termination signal stops issuance instead of continuing to the next domain'
else
  ok 'a termination signal stops issuance instead of continuing to the next domain'
fi
[ "$SIGRC" -ne 0 ] && ok 'an interrupted run exits non-zero' || no 'an interrupted run exits non-zero'
# The work directory holds a private key; a signal must not leave it behind.
if [ -n "$(ls -A "$SIG/tmp" 2>/dev/null)" ]; then
  no 'no work directory is left behind after a signal'
else
  ok 'no work directory is left behind after a signal'
fi
rm -rf "$SIG"

# If the key cannot be installed, the certificate must not be left behind on its own: a
# certificate whose private key is missing or stale is worse than no certificate at all.
ORPH=$(mktemp -d)
mkdir -p "$ORPH/out"
cat > "$ORPH/curl" <<'STUBEOF'
#!/bin/bash
cat >/dev/null
echo '{"success":true,"result":{"certificate":"stub-cert"}}'
STUBEOF
chmod +x "$ORPH/curl"
# Make the key install genuinely fail: mv refuses when dst/<basename of src> is a non-empty
# directory. The staged key is named out.key, so block exactly that path.
mkdir -p "$ORPH/out/orphan.example.key/out.key/blocker"
set +e
PATH="$ORPH:$PATH" CF_ORIGIN_CA_KEY=stubkey \
  "$ROOT/cf-origin-issue.sh" --out "$ORPH/out" orphan.example >/dev/null 2>&1
set -e
if [ -f "$ORPH/out/orphan.example.crt" ]; then
  no 'a certificate is not left behind when its key cannot be installed'
else
  ok 'a certificate is not left behind when its key cannot be installed'
fi
rm -rf "$ORPH"

echo
echo "passed=$PASS failed=$FAIL"
[ "$FAIL" -eq 0 ]


