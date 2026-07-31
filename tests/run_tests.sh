#!/bin/bash
# Offline test suite. No Cloudflare API calls, no OpenLiteSpeed, no root.
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

# The credential must not be visible in the process arguments.
grep -q 'X-Auth-User-Service-Key: \${CF_ORIGIN_CA_KEY}' "$ROOT/cf-origin-issue.sh" \
  && no 'keeps the credential out of the command line' \
  || ok 'keeps the credential out of the command line'

echo
echo "passed=$PASS failed=$FAIL"
[ "$FAIL" -eq 0 ]
