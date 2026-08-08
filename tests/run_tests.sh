#!/bin/bash
# Offline test suite. No Cloudflare API calls, no OpenLiteSpeed, no root.
# shellcheck disable=SC2015,SC2016,SC2181,SC2094
# SC2015: the `[ cond ] && ok "..." || no "..."` shape is intentional here - `ok` cannot fail,
#         so this is a two-branch report, not a mis-written if-then-else.
# SC2016: single quotes are deliberate where a literal `$` belongs to awk, python or a stub.
# SC2181: these suites check `$?` immediately after the command under test, which is the
#         thing being asserted.
# SC2094: the lock-contention test deliberately holds the same file the script under test
#         then tries to lock - that collision is the property being verified.
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

# Private keys are written to --out, so a symlinked output directory (which could redirect
# where keys land) is refused.
mkdir -p "$T/realout"; ln -s "$T/realout" "$T/symout"
"$ROOT/cf-origin-issue.sh" --dry-run --out "$T/symout" example.com >/dev/null 2>&1
[ $? -eq 2 ] && ok 'refuses a symlinked output directory' || no 'refuses a symlinked output directory'

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
PATH="$SIG:$PATH" STUB_DIR="$SIG" TMPDIR="$SIG/tmp" CF_ORIGIN_CA_KEY=stubkey \
  "$ROOT/cf-origin-issue.sh" --out "$SIG/out" first.example second.example >/dev/null 2>&1
SIGRC=$?

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
PATH="$ORPH:$PATH" CF_ORIGIN_CA_KEY=stubkey \
  "$ROOT/cf-origin-issue.sh" --out "$ORPH/out" orphan.example >/dev/null 2>&1
if [ -f "$ORPH/out/orphan.example.crt" ]; then
  no 'a certificate is not left behind when its key cannot be installed'
else
  ok 'a certificate is not left behind when its key cannot be installed'
fi
rm -rf "$ORPH"

# --- issuance against a CA stub that actually signs the CSR ---------------------------------
# A canned certificate cannot match the key the script generates, so it is rejected before the
# install path runs - which would leave every assertion below it passing vacuously. This stub
# signs the real CSR, so the happy path is genuinely exercised.
ca_run(){ # <mode>
  CA=$(mktemp -d); mkdir -p "$CA/out" "$CA/tmp" "$CA/ca" "$CA/bin"
  cp "$HERE/fake-origin-ca.sh" "$CA/bin/curl"
  env PATH="$CA/bin:$PATH" TMPDIR="$CA/tmp" FAKE_CA_DIR="$CA/ca" FAKE_CA_MODE="$1" \
      CF_ORIGIN_CA_KEY=SENTINELsecret123 \
      "$ROOT/cf-origin-issue.sh" --out "$CA/out" a.example >/dev/null 2>&1
  CA_RC=$?
}

ca_run good
[ "$CA_RC" -eq 0 ] && ok 'issues a certificate that passes verification' \
                   || no "issues a certificate that passes verification (rc=$CA_RC)"

CRT_MOD=$(openssl x509 -noout -modulus -in "$CA/out/a.example.crt" 2>/dev/null | openssl md5)
KEY_MOD=$(openssl rsa  -noout -modulus -in "$CA/out/a.example.key" 2>/dev/null | openssl md5)
if [ -n "$CRT_MOD" ] && [ "$CRT_MOD" = "$KEY_MOD" ]; then
  ok 'the installed certificate and key are a matching pair'
else
  no 'the installed certificate and key are a matching pair'
fi

openssl x509 -noout -ext subjectAltName -in "$CA/out/a.example.crt" 2>/dev/null \
  | tr -d ' ' | grep -q 'DNS:a.example,DNS:\*.a.example' \
  && ok 'the installed certificate covers the apex and the wildcard' \
  || no 'the installed certificate covers the apex and the wildcard'

grep -q SENTINELsecret123 "$CA/ca/argv.seen" 2>/dev/null \
  && no 'the credential never reaches curl argv' \
  || ok 'the credential never reaches curl argv'
grep -q SENTINELsecret123 "$CA/ca/stdin.seen" 2>/dev/null \
  && ok 'the credential is delivered on stdin' \
  || no 'the credential is delivered on stdin'
rm -rf "$CA"

# --- what the API returns is not trusted on its word ----------------------------------------
for mode in garbage mismatched-key missing-wildcard expired san-superstring not-yet-valid; do
  ca_run "$mode"
  # find, not ls|grep: filenames here are ours, but the shellcheck rule is right in general
  left=$(find "$CA/out" -maxdepth 1 -type f ! -name '.*' 2>/dev/null | wc -l)
  if [ "$CA_RC" -ne 0 ] && [ "$left" -eq 0 ]; then
    ok "rejects a $mode certificate and installs nothing"
  else
    no "rejects a $mode certificate and installs nothing (rc=$CA_RC, files=$left)"
  fi
  rm -rf "$CA"
done

# --- a partial install must restore the previous pair, not destroy it ------------------------
ROLL=$(mktemp -d); mkdir -p "$ROLL/out" "$ROLL/tmp" "$ROLL/ca" "$ROLL/bin"
cp "$HERE/fake-origin-ca.sh" "$ROLL/bin/curl"
printf 'PREVIOUS-CERT\n' > "$ROLL/out/a.example.crt"
# The key destination is a non-empty directory, which mv refuses to overwrite - so the key install
# fails after the certificate has already been replaced.
mkdir -p "$ROLL/out/a.example.key/out.key/blocker"
env PATH="$ROLL/bin:$PATH" TMPDIR="$ROLL/tmp" FAKE_CA_DIR="$ROLL/ca" FAKE_CA_MODE=good \
    CF_ORIGIN_CA_KEY=SENTINELsecret123 \
    "$ROOT/cf-origin-issue.sh" --out "$ROLL/out" a.example >/dev/null 2>&1
grep -q 'PREVIOUS-CERT' "$ROLL/out/a.example.crt" 2>/dev/null \
  && ok 'a failed key install restores the previous certificate' \
  || no 'a failed key install restores the previous certificate'
rm -rf "$ROLL"

# Both halves must come back, not just the certificate. Make the backup itself impossible by
# turning the existing key into an unreadable-by-copy directory, and assert nothing is touched.
PAIR=$(mktemp -d); mkdir -p "$PAIR/out" "$PAIR/tmp" "$PAIR/ca" "$PAIR/bin"
cp "$HERE/fake-origin-ca.sh" "$PAIR/bin/curl"
printf 'PREVIOUS-CERT\n' > "$PAIR/out/a.example.crt"
mkdir -p "$PAIR/out/a.example.key"          # a directory where a key file is expected
env PATH="$PAIR/bin:$PATH" TMPDIR="$PAIR/tmp" FAKE_CA_DIR="$PAIR/ca" FAKE_CA_MODE=good \
    CF_ORIGIN_CA_KEY=SENTINELsecret123 \
    "$ROOT/cf-origin-issue.sh" --out "$PAIR/out" a.example >/dev/null 2>&1
PAIR_RC=$?
if [ "$PAIR_RC" -ne 0 ] && grep -q 'PREVIOUS-CERT' "$PAIR/out/a.example.crt" 2>/dev/null; then
  ok 'an un-installable key leaves the previous certificate intact'
else
  no "an un-installable key leaves the previous certificate intact (rc=$PAIR_RC)"
fi
rm -rf "$PAIR"

# --- the config must never be replaced without being validated first -----------------------
# A vhost edit that breaks parsing takes every site down the moment the server reloads, so the
# test runs before any restart and a failure must roll the file back.
OLS=$(mktemp -d); mkdir -p "$OLS/certs" "$OLS/vhosts/s.example" "$OLS/bin"
touch "$OLS/certs/s.example.crt" "$OLS/certs/s.example.key"
printf 'docRoot /x\n' > "$OLS/vhosts/s.example/vhost.conf"
cp "$OLS/vhosts/s.example/vhost.conf" "$OLS/orig.conf"

printf '%s\n' '#!/bin/bash' 'exit 0' > "$OLS/bin/openlitespeed"
chmod +x "$OLS/bin/openlitespeed"
OUT=$(OLS_BIN="$OLS/bin/openlitespeed" "$ROOT/ols-ssl-wire.sh" \
      --certs "$OLS/certs" --vhosts "$OLS/vhosts" --apply 2>&1)
printf '%s' "$OUT" | grep -q 'config test: OK' \
  && ok 'runs the OpenLiteSpeed config test before restarting' \
  || no 'runs the OpenLiteSpeed config test before restarting'
[ "$(grep -c 'vhssl' "$OLS/vhosts/s.example/vhost.conf")" -eq 1 ] \
  && ok 'a validated change is kept' || no 'a validated change is kept'

# now the same edit, with a config test that rejects it
cp "$OLS/orig.conf" "$OLS/vhosts/s.example/vhost.conf"
printf '%s\n' '#!/bin/bash' 'echo "parse error line 7" >&2' 'exit 1' > "$OLS/bin/openlitespeed"
printf '%s\n' '#!/bin/bash' "echo RESTARTED > $OLS/restarted" > "$OLS/bin/lswsctrl"
chmod +x "$OLS/bin/openlitespeed" "$OLS/bin/lswsctrl"
OLS_BIN="$OLS/bin/openlitespeed" LSWSCTRL="$OLS/bin/lswsctrl" "$ROOT/ols-ssl-wire.sh" \
  --certs "$OLS/certs" --vhosts "$OLS/vhosts" --apply --restart >/dev/null 2>&1
OLS_RC=$?
[ "$OLS_RC" -ne 0 ] && ok 'a failed config test fails the run' \
                    || no 'a failed config test fails the run'
diff -q "$OLS/orig.conf" "$OLS/vhosts/s.example/vhost.conf" >/dev/null \
  && ok 'a failed config test rolls the vhost back' \
  || no 'a failed config test rolls the vhost back'
[ -f "$OLS/restarted" ] && no 'a failed config test prevents the restart' \
                        || ok 'a failed config test prevents the restart'

# the live file must never be the thing being written to
grep -q 'mv -f "$staged" "$conf"' "$ROOT/ols-ssl-wire.sh" \
  && ok 'the new config is staged and swapped in atomically' \
  || no 'the new config is staged and swapped in atomically'
rm -rf "$OLS"

# Restarting a configuration nobody could validate is exactly the outcome the config test exists
# to prevent, so a missing test binary must block --restart rather than be noted and ignored.
NOV=$(mktemp -d); mkdir -p "$NOV/certs" "$NOV/vhosts/s.example" "$NOV/bin"
touch "$NOV/certs/s.example.crt" "$NOV/certs/s.example.key"
printf 'docRoot /x\n' > "$NOV/vhosts/s.example/vhost.conf"
cp "$NOV/vhosts/s.example/vhost.conf" "$NOV/orig.conf"
printf '%s\n' '#!/bin/bash' "echo R > $NOV/restarted" > "$NOV/bin/lswsctrl"
chmod +x "$NOV/bin/lswsctrl"

OLS_BIN="$NOV/bin/absent" LSWSCTRL="$NOV/bin/lswsctrl" "$ROOT/ols-ssl-wire.sh" \
  --certs "$NOV/certs" --vhosts "$NOV/vhosts" --apply --restart >/dev/null 2>&1
NOV_RC=$?
[ "$NOV_RC" -ne 0 ] && ok 'a missing config-test binary blocks --restart' \
                    || no 'a missing config-test binary blocks --restart'
diff -q "$NOV/orig.conf" "$NOV/vhosts/s.example/vhost.conf" >/dev/null \
  && ok 'and rolls the vhost back' || no 'and rolls the vhost back'
[ -f "$NOV/restarted" ] && no 'and does not restart' || ok 'and does not restart'

# Without --restart a skipped validation is not a success either: the changes are live but
# unproven, so the run reports failure unless the operator explicitly accepts them.
cp "$NOV/orig.conf" "$NOV/vhosts/s.example/vhost.conf"
OUT=$(OLS_BIN="$NOV/bin/absent" "$ROOT/ols-ssl-wire.sh" \
      --certs "$NOV/certs" --vhosts "$NOV/vhosts" --apply 2>&1)
RC=$?
if [ "$RC" -ne 0 ] && printf '%s' "$OUT" | grep -q 'could not be validated'; then
  ok 'a skipped validation reports failure even without --restart'
else
  no "a skipped validation reports failure even without --restart (rc=$RC)"
fi
# ...unless the operator explicitly accepts unvalidated changes.
cp "$NOV/orig.conf" "$NOV/vhosts/s.example/vhost.conf"
OLS_BIN="$NOV/bin/absent" OLS_ALLOW_UNVALIDATED=1 "$ROOT/ols-ssl-wire.sh" \
  --certs "$NOV/certs" --vhosts "$NOV/vhosts" --apply >/dev/null 2>&1
[ $? -eq 0 ] && ok 'OLS_ALLOW_UNVALIDATED=1 accepts unvalidated changes' \
             || no 'OLS_ALLOW_UNVALIDATED=1 accepts unvalidated changes'
rm -rf "$NOV"

# --- an incomplete batch must not be validated and reloaded --------------------------------
# A skipped vhost is one this run did not finish; reloading on a partially applied set carries
# the same hazard as reloading on a failed one.
INC=$(mktemp -d); mkdir -p "$INC/certs" "$INC/vhosts/ok.example" "$INC/bin"
touch "$INC/certs/ok.example.crt" "$INC/certs/ok.example.key"
touch "$INC/certs/orphan.example.crt"          # no key -> SKIPPED
printf 'docRoot /x\n' > "$INC/vhosts/ok.example/vhost.conf"
cp "$INC/vhosts/ok.example/vhost.conf" "$INC/orig.conf"
printf '%s\n' '#!/bin/bash' 'exit 0' > "$INC/bin/openlitespeed"
printf '%s\n' '#!/bin/bash' "echo R > $INC/restarted" > "$INC/bin/lswsctrl"
chmod +x "$INC/bin/openlitespeed" "$INC/bin/lswsctrl"
OUT=$(OLS_BIN="$INC/bin/openlitespeed" LSWSCTRL="$INC/bin/lswsctrl" OLS_WIRE_LOCK="$INC/lk" \
      "$ROOT/ols-ssl-wire.sh" --certs "$INC/certs" --vhosts "$INC/vhosts" --apply --restart 2>&1)
printf '%s' "$OUT" | grep -q 'batch incomplete' \
  && ok 'a skipped vhost blocks --restart' || no 'a skipped vhost blocks --restart'
diff -q "$INC/orig.conf" "$INC/vhosts/ok.example/vhost.conf" >/dev/null \
  && ok 'and the batch is rolled back' || no 'and the batch is rolled back'
[ -f "$INC/restarted" ] && no 'and nothing is restarted' || ok 'and nothing is restarted'
rm -rf "$INC"

# --- a signal mid-batch rolls back every applied vhost -------------------------------------
# Without a batch signal trap, an interrupted --apply leaves a partially wired (live) set.
BSIG=$(mktemp -d); mkdir -p "$BSIG/certs" "$BSIG/vhosts/a.example" "$BSIG/vhosts/b.example" "$BSIG/bin"
touch "$BSIG/certs/a.example.crt" "$BSIG/certs/a.example.key" "$BSIG/certs/b.example.crt" "$BSIG/certs/b.example.key"
printf 'docRoot /x\n' > "$BSIG/vhosts/a.example/vhost.conf"
printf 'docRoot /x\n' > "$BSIG/vhosts/b.example/vhost.conf"
cp "$BSIG/vhosts/a.example/vhost.conf" "$BSIG/a.orig"
cp "$BSIG/vhosts/b.example/vhost.conf" "$BSIG/b.orig"
# a stub chown (called per-domain, after staging, before the swap) that terminates the run
# during the SECOND domain - after the first has already been swapped in.
cat > "$BSIG/bin/chown" <<STUBEOF
#!/bin/bash
n=\$(cat "$BSIG/n" 2>/dev/null || echo 0); n=\$((n+1)); echo \$n > "$BSIG/n"
[ "\$n" -ge 2 ] && { kill -TERM \$PPID 2>/dev/null; sleep 5; }
exit 0
STUBEOF
chmod +x "$BSIG/bin/chown"
PATH="$BSIG/bin:$PATH" OLS_WIRE_LOCK_DIR="$BSIG/lk" "$ROOT/ols-ssl-wire.sh" \
  --certs "$BSIG/certs" --vhosts "$BSIG/vhosts" --apply >/dev/null 2>&1
if diff -q "$BSIG/a.orig" "$BSIG/vhosts/a.example/vhost.conf" >/dev/null 2>&1 \
   && diff -q "$BSIG/b.orig" "$BSIG/vhosts/b.example/vhost.conf" >/dev/null 2>&1; then
  ok 'a signal mid-batch rolls back every applied vhost'
else
  no 'a signal mid-batch rolls back every applied vhost'
fi
rm -rf "$BSIG"

# --- concurrent wiring runs are serialised -------------------------------------------------
LK=$(mktemp -d); mkdir -p "$LK/certs" "$LK/vhosts"
CLK=$(mktemp -d)
exec 200<"$CLK"; flock -n 200 || no 'test could not take its own lock'
OLS_WIRE_LOCK_DIR="$CLK" "$ROOT/ols-ssl-wire.sh" \
  --certs "$LK/certs" --vhosts "$LK/vhosts" --apply >/dev/null 2>&1
LK_RC=$?
exec 200<&-; rm -rf "$CLK"
[ "$LK_RC" = 2 ] \
  && ok 'a second wiring run refuses while the first holds the lock' \
  || no "a second wiring run refuses while the first holds the lock (rc=$LK_RC)"
rm -rf "$LK"

echo
echo "passed=$PASS failed=$FAIL"
[ "$FAIL" -eq 0 ]


