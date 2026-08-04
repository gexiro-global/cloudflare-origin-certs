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
# Exit: 0 ok | 1 something was skipped, the config test failed, or the restart failed | 2 usage error
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

WIRED=0; SKIPPED=0; FAILED=0
# "<backup>:<live file>" pairs, so a failed configuration test can restore every file this run
# touched - not just the last one.
BACKUPS=""

restore_all(){
  local pair b c
  for pair in $BACKUPS; do
    b=${pair%%:*}; c=${pair#*:}
    [ -f "$b" ] && cp -p "$b" "$c" 2>/dev/null
  done
}

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
  cat "$conf" > "$backup"
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
      echo "FAIL $domain - vhssl block looks malformed, restoring backup"
      cat "$backup" > "$conf"
      FAILED=$((FAILED+1))
      continue
    fi
    if [ ! -s "$staged" ]; then
      echo "FAIL $domain - staged config is empty, leaving the original alone"
      rm -f "$staged"; FAILED=$((FAILED+1)); continue
    fi
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
CONFIG_BAD=0
if [ "$APPLY" = "1" ] && [ "$WIRED" -gt 0 ]; then
  # A batch that partly failed must not be validated and restarted as if it were complete: the
  # server would come up on a half-applied set of changes. Roll the whole batch back instead.
  if [ "$FAILED" -gt 0 ]; then
    echo "$FAILED vhost(s) failed - rolling back every file this run changed, not restarting" >&2
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
      echo "config test skipped: $OLS_BIN not found or not executable" >&2
      echo 'the changes are in place but unvalidated - test before you reload' >&2
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

[ "$SKIPPED" -eq 0 ] && [ "$FAILED" -eq 0 ] && [ "$RESTART_FAILED" -eq 0 ] && [ "$CONFIG_BAD" -eq 0 ]
