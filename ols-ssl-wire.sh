#!/bin/bash
# ols-ssl-wire - point OpenLiteSpeed vhosts at their Origin certificates.
#
# For every <domain>.crt + <domain>.key pair in the certificate directory, this finds the
# matching vhost and makes sure its vhssl block uses them.
#
# Two deliberate safety choices:
#   * DRY RUN IS THE DEFAULT. Nothing is written unless you pass --apply.
#   * It never restarts the web server unless you pass --restart. A config edit that breaks
#     a vhost is recoverable; a restart into a broken config takes every site down at once.
#
# Usage:
#   ols-ssl-wire.sh [--certs DIR] [--vhosts DIR] [--apply] [--restart]
#
# Exit: 0 ok | 1 something was skipped, the config test failed or was skipped, or the
#            restart failed | 2 usage error
# Env: OLS_WIRE_LOCK_DIR (lock dir), OLS_ALLOW_UNVALIDATED=1 (accept changes when the
#      config-test binary is absent and --restart was not requested)
set -uo pipefail

CERT_DIR="${OLS_CERT_DIR:-/usr/local/lsws/conf/cert/origin-certs}"
VHOST_DIR="${OLS_VHOST_DIR:-/usr/local/lsws/conf/vhosts}"
LSWSCTRL="${LSWSCTRL:-/usr/local/lsws/bin/lswsctrl}"
APPLY=0; RESTART=0

while [ $# -gt 0 ]; do
  case "$1" in
    --certs)   shift; CERT_DIR="${1:?--certs needs a path}" ;;
    --vhosts)  shift; VHOST_DIR="${1:?--vhosts needs a path}" ;;
    --apply)   APPLY=1 ;;
    --restart) RESTART=1 ;;
    -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
    *)         echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

[ -d "$CERT_DIR" ]  || { echo "certificate directory not found: $CERT_DIR" >&2; exit 2; }
[ -d "$VHOST_DIR" ] || { echo "vhost directory not found: $VHOST_DIR" >&2; exit 2; }
[ "$APPLY" = "1" ] || echo '(dry run - nothing will be written; pass --apply to make changes)'

# Two runs rewriting the same vhost tree would interleave their swaps and their backups.
# Fail closed, consistently with the rest of the toolkit.
if [ "$APPLY" = "1" ]; then
  command -v flock >/dev/null 2>&1 \
    || { echo "flock is required so two runs cannot rewrite the same vhosts" >&2; exit 2; }
  # Lock a validated /run/lock directory opened READ-ONLY (a directory cannot be
  # truncated), not a fixed /tmp lock file opened with `>` that a local user could
  # redirect at an arbitrary root-writable file via a pre-planted symlink (CWE-59).
  MY_UID=$(id -u)
  if [ -n "${OLS_WIRE_LOCK_DIR:-}" ]; then LOCK_DIR="$OLS_WIRE_LOCK_DIR"
  elif [ "$MY_UID" = "0" ]; then LOCK_DIR=/run/lock/ols-ssl-wire
  elif [ -n "${XDG_RUNTIME_DIR:-}" ] && [ -d "$XDG_RUNTIME_DIR" ]; then LOCK_DIR="$XDG_RUNTIME_DIR/ols-ssl-wire"
  else LOCK_DIR="${TMPDIR:-/tmp}/ols-ssl-wire-$MY_UID"; fi
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
  flock -n 7 || { echo "another wiring run holds the lock" >&2; exit 2; }
fi

WIRED=0; SKIPPED=0; FAILED=0
# "<backup>:<live file>" pairs, so a failed configuration test can restore every file this run
# touched - not just the last one.
BACKUPS=""

restore_all(){
  local pair b c rc=0
  for pair in $BACKUPS; do
    b=${pair%%:*}; c=${pair#*:}
    if [ -f "$b" ]; then
      cp -p "$b" "$c" || {
        echo "ROLLBACK FAILED for $c - the backup is still at $b" >&2
        rc=1
      }
    fi
  done
  [ "$rc" = 0 ] || echo 'one or more vhosts could not be rolled back - fix them before reloading' >&2
  return $rc
}

# An interruption mid-batch must not leave a partially applied vhost set live. Roll every
# file this run touched back to its backup, then exit. Only meaningful under --apply, where
# BACKUPS is populated; a dry run changes nothing.
on_wire_signal(){ echo "interrupted by SIG$1 - rolling back this batch" >&2; restore_all; trap - EXIT; exit $((128 + $2)); }
if [ "$APPLY" = "1" ]; then
  trap 'on_wire_signal INT 2'  INT
  trap 'on_wire_signal TERM 15' TERM
  trap 'on_wire_signal HUP 1'   HUP
fi

for cert in "$CERT_DIR"/*.crt; do
  [ -f "$cert" ] || continue
  domain=$(basename "$cert" .crt)
  key="$CERT_DIR/${domain}.key"
  conf="$VHOST_DIR/$domain/vhost.conf"

  if [ ! -f "$key" ];  then echo "SKIP $domain - no matching key";   SKIPPED=$((SKIPPED+1)); continue; fi
  if [ ! -f "$conf" ]; then echo "SKIP $domain - no vhost config";   SKIPPED=$((SKIPPED+1)); continue; fi

  if grep -qE '^[[:space:]]*vhssl[[:space:]]*\{' "$conf"; then
    action='update existing vhssl block'
  else
    action='append a vhssl block'
  fi

  if [ "$APPLY" = "0" ]; then
    echo "WOULD $action for $domain"
    WIRED=$((WIRED+1))
    continue
  fi

  # mktemp rather than a timestamp: two runs inside the same second would otherwise
  # collide and the second backup would overwrite the only pre-change copy.
  backup=$(mktemp "${conf}.bak.XXXXXX") || { echo "FAIL $domain - cannot create backup"; FAILED=$((FAILED+1)); continue; }
  # cp -p, not cat: a backup that loses the owner and mode is not a backup you can restore.
  cp -p "$conf" "$backup" || {
    echo "FAIL $domain - cannot copy the config aside"; FAILED=$((FAILED+1)); continue
  }
  BACKUPS="$BACKUPS $backup:$conf"

  # Everything is built here first; $conf itself is untouched until the rename below.
  staged=$(mktemp "${conf}.new.XXXXXX") || { echo "FAIL $domain - cannot create staging file"; FAILED=$((FAILED+1)); continue; }

  if grep -qE '^[[:space:]]*vhssl[[:space:]]*\{' "$conf"; then
    # Rewrite keyFile/certFile ONLY inside the vhssl block. A global substitution on
    # /keyFile.*/ also rewrites unrelated blocks in the same file, which is how a config
    # edit for one feature quietly breaks another. If the block exists but is missing
    # either directive, insert it before the block closes rather than silently doing
    # nothing and still reporting success.
    if ! KEY="$key" CERT="$cert" CONF="$conf" OUT="$staged" python3 - <<'PY'
import os
import re
import sys

path = os.environ['CONF']
with open(path, encoding='utf-8') as fh:
    lines = fh.readlines()

out, depth, inside = [], 0, False
seen_key = seen_cert = False
wrote_block = False

for line in lines:
    if not inside and re.match(r'^\s*vhssl\s*\{', line):
        inside = True
        depth = line.count('{') - line.count('}')
        seen_key = seen_cert = False
        out.append(line)
        continue
    if inside:
        if re.match(r'^\s*keyFile\b', line):
            out.append('  keyFile                 %s\n' % os.environ['KEY'])
            seen_key = True
            continue
        if re.match(r'^\s*certFile\b', line):
            out.append('  certFile                %s\n' % os.environ['CERT'])
            seen_cert = True
            continue
        depth += line.count('{') - line.count('}')
        if depth <= 0:
            # closing the block - add whatever the block was missing
            if not seen_key:
                out.append('  keyFile                 %s\n' % os.environ['KEY'])
            if not seen_cert:
                out.append('  certFile                %s\n' % os.environ['CERT'])
            inside = False
            wrote_block = True
    out.append(line)

if not wrote_block:
    # vhssl opened but never closed - refuse to guess at a malformed config
    sys.exit(1)

# Write the result beside the original. The live vhost.conf is only replaced later, by an
# atomic rename, so an interrupted run can never leave a half-written config in place.
with open(os.environ['OUT'], 'w', encoding='utf-8') as fh:
    fh.writelines(out)
PY
    then
      # $conf has not been touched - everything was built in $staged - so there is nothing to
      # restore. Writing the backup over the live file here would reintroduce exactly the
      # interrupted-write risk the staging design removes.
      echo "FAIL $domain - vhssl block looks malformed, leaving the original untouched"
      rm -f "$staged"
      FAILED=$((FAILED+1))
      continue
    fi
    if [ ! -s "$staged" ]; then
      echo "FAIL $domain - staged config is empty, leaving the original alone"
      rm -f "$staged"; FAILED=$((FAILED+1)); continue
    fi
    # mktemp creates 0600 root-owned files; the replacement must keep the vhost's own
    # ownership and mode or the server may stop being able to read its config.
    chmod --reference="$conf" "$staged" 2>/dev/null || true
    chown --reference="$conf" "$staged" 2>/dev/null || true
    if ! mv -f "$staged" "$conf"; then
      echo "FAIL $domain - could not install the new config; original untouched"
      rm -f "$staged"; FAILED=$((FAILED+1)); continue
    fi
    echo "WIRED $domain (updated vhssl)"
  else
    cat "$conf" > "$staged"
    cat >> "$staged" <<EOF

vhssl {
  keyFile                 $key
  certFile                $cert
  certChain               0
  sslProtocol             24
}
EOF
    chmod --reference="$conf" "$staged" 2>/dev/null || true
    chown --reference="$conf" "$staged" 2>/dev/null || true
    if [ ! -s "$staged" ] || ! mv -f "$staged" "$conf"; then
      echo "FAIL $domain - could not install the new config; original untouched"
      rm -f "$staged"; FAILED=$((FAILED+1)); continue
    fi
    echo "WIRED $domain (appended vhssl)"
  fi
  WIRED=$((WIRED+1))
done

echo
echo "wired=$WIRED skipped=$SKIPPED failed=$FAILED"

# Validate the configuration before anything is restarted. A vhost edit that breaks parsing takes
# every site on the box down the moment the server reloads, so the test runs first and a failure
# rolls every file this run touched back to its backup.
CONFIG_BAD=0; VALIDATE_SKIPPED=0
if [ "$APPLY" = "1" ] && [ "$WIRED" -gt 0 ]; then
  # A batch that partly failed must not be validated and restarted as if it were complete: the
  # server would come up on a half-applied set of changes. Roll the whole batch back instead.
  if [ "$FAILED" -gt 0 ] || { [ "$SKIPPED" -gt 0 ] && [ "$RESTART" = "1" ]; }; then
    # A skipped vhost is one this run did not finish. Reloading on a partially applied set is
    # the same hazard as reloading on a failed one, so --restart requires a complete batch.
    echo "batch incomplete (failed=$FAILED skipped=$SKIPPED) - rolling back, not restarting" >&2
    restore_all
    CONFIG_BAD=1
  else
    OLS_BIN="${OLS_BIN:-/usr/local/lsws/bin/openlitespeed}"
    if [ -x "$OLS_BIN" ]; then
      if "$OLS_BIN" -t >/dev/null 2>&1; then
        echo 'config test: OK'
      else
        echo 'CONFIG TEST FAILED - restoring every file this run changed, not restarting' >&2
        "$OLS_BIN" -t 2>&1 | tail -5 >&2
        restore_all
        CONFIG_BAD=1
      fi
    elif [ "$RESTART" = "1" ]; then
      # Restarting a configuration nobody could validate is the failure this whole section exists
      # to prevent, so a missing test binary is fatal here rather than a note.
      echo "CANNOT VALIDATE: $OLS_BIN not found or not executable, and --restart was requested" >&2
      echo 'rolling back every file this run changed; re-run without --restart to keep them' >&2
      restore_all
      CONFIG_BAD=1
    else
      # A skipped validation is not a success: the changes are live but unproven. Report
      # failure unless the operator explicitly accepts unvalidated changes.
      echo "config test skipped: $OLS_BIN not found or not executable" >&2
      if [ "${OLS_ALLOW_UNVALIDATED:-0}" = "1" ]; then
        echo 'the changes are in place but unvalidated (OLS_ALLOW_UNVALIDATED=1 accepted)' >&2
      else
        echo 'the changes are in place but could not be validated - reporting failure' >&2
        echo '(set OLS_ALLOW_UNVALIDATED=1 to accept unvalidated changes, or install the test binary)' >&2
        VALIDATE_SKIPPED=1
      fi
    fi
  fi
fi

RESTART_FAILED=0
if [ "$CONFIG_BAD" = "1" ]; then
  RESTART=0
fi
if [ "$APPLY" = "1" ] && [ "$RESTART" = "1" ] && [ "$WIRED" -gt 0 ]; then
  echo 'restarting OpenLiteSpeed'
  if ! "$LSWSCTRL" restart; then
    echo 'RESTART FAILED - check the config before retrying' >&2
    RESTART_FAILED=1
  fi
elif [ "$APPLY" = "1" ] && [ "$WIRED" -gt 0 ]; then
  echo "config updated. Reload when you are ready:  $LSWSCTRL restart"
fi

[ "$SKIPPED" -eq 0 ] && [ "$FAILED" -eq 0 ] && [ "$RESTART_FAILED" -eq 0 ] && [ "$CONFIG_BAD" -eq 0 ] && [ "$VALIDATE_SKIPPED" -eq 0 ]
