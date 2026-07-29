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
# Exit: 0 ok | 1 something was skipped | 2 usage error
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

WIRED=0; SKIPPED=0

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

  cp -a "$conf" "${conf}.bak.$(date +%Y%m%d%H%M%S)"

  if grep -qE '^[[:space:]]*vhssl[[:space:]]*\{' "$conf"; then
    # Rewrite keyFile/certFile ONLY inside the vhssl block. A global substitution on
    # /keyFile.*/ also rewrites unrelated blocks in the same file, which is how a config
    # edit for one feature quietly breaks another.
    KEY="$key" CERT="$cert" CONF="$conf" python3 - <<'PY'
import os, re
path = os.environ['CONF']
with open(path, encoding='utf-8') as fh:
    lines = fh.readlines()
out, depth, inside = [], 0, False
for line in lines:
    if re.match(r'^\s*vhssl\s*\{', line):
        inside, depth = True, line.count('{') - line.count('}')
        out.append(line); continue
    if inside:
        if re.match(r'^\s*keyFile\b', line):
            out.append('  keyFile                 %s\n' % os.environ['KEY']); continue
        if re.match(r'^\s*certFile\b', line):
            out.append('  certFile                %s\n' % os.environ['CERT']); continue
        depth += line.count('{') - line.count('}')
        if depth <= 0:
            inside = False
    out.append(line)
with open(path, 'w', encoding='utf-8') as fh:
    fh.writelines(out)
PY
    echo "WIRED $domain (updated vhssl)"
  else
    cat >> "$conf" <<EOF

vhssl {
  keyFile                 $key
  certFile                $cert
  certChain               0
  sslProtocol             24
}
EOF
    echo "WIRED $domain (appended vhssl)"
  fi
  WIRED=$((WIRED+1))
done

echo
echo "wired=$WIRED skipped=$SKIPPED"

if [ "$APPLY" = "1" ] && [ "$RESTART" = "1" ] && [ "$WIRED" -gt 0 ]; then
  echo 'restarting OpenLiteSpeed'
  "$LSWSCTRL" restart || echo 'restart failed - check the config before retrying'
elif [ "$APPLY" = "1" ] && [ "$WIRED" -gt 0 ]; then
  echo "config updated. Reload when you are ready:  $LSWSCTRL restart"
fi

[ "$SKIPPED" -eq 0 ]
