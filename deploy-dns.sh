#!/bin/bash
# Deploy dnsscienced to DNS servers (ns1/ns2) via apps.afterdarksys.com jump host
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DAEMON="$SCRIPT_DIR/dnsscienced-linux-new"
COMPILE="$SCRIPT_DIR/dnsscienced-compile-linux-new"
ADMINCLI="$SCRIPT_DIR/dnsscienced-admin-linux"
JUMP="root@108.165.123.229"

# ns1 / ns2 are only reachable via the apps jump host
NS1="root@166.0.192.27"
NS2="root@108.165.120.57"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log()   { echo -e "${GREEN}[deploy]${NC} $1"; }
warn()  { echo -e "${YELLOW}[warn]${NC} $1"; }
error() { echo -e "${RED}[error]${NC} $1"; exit 1; }

# ── sanity checks ────────────────────────────────────────────────────────────

[ -f "$DAEMON"   ] || error "Daemon binary not found: $DAEMON  (run: GOOS=linux GOARCH=amd64 go build -o dnsscienced-linux-new ./cmd/dnsscienced/)"
[ -f "$COMPILE"  ] || error "Compiler binary not found: $COMPILE  (run: GOOS=linux GOARCH=amd64 go build -o dnsscienced-compile-linux-new ./cmd/dnsscienced-compile/)"
[ -f "$ADMINCLI" ] || error "Admin CLI not found: $ADMINCLI  (run: GOOS=linux GOARCH=amd64 go build -o dnsscienced-admin-linux ./cmd/dnsscienced-admin/)"

log "Daemon:    $DAEMON   ($(du -sh "$DAEMON"   | cut -f1))"
log "Compiler:  $COMPILE  ($(du -sh "$COMPILE"  | cut -f1))"
log "Admin CLI: $ADMINCLI ($(du -sh "$ADMINCLI" | cut -f1))"
echo ""

# ── helpers ──────────────────────────────────────────────────────────────────

# run a command on a nameserver via the jump host
ns_ssh() {
    local target="$1"; shift
    ssh -J "$JUMP" "$target" "$@"
}

# copy a local file to a nameserver via the jump host
ns_scp() {
    local src="$1"
    local target="$2"
    local dest="$3"
    # scp with ProxyJump
    scp -o "ProxyJump=$JUMP" "$src" "${target}:${dest}"
}

# ── deploy to one server ─────────────────────────────────────────────────────

deploy_to() {
    local label="$1"   # e.g. "ns1"
    local target="$2"  # e.g. root@166.0.192.27

    log "[$label] Creating /opt/dnsscienced/bin/ ..."
    ns_ssh "$target" "mkdir -p /opt/dnsscienced/bin"

    log "[$label] Uploading daemon ..."
    ns_scp "$DAEMON"  "$target" "/opt/dnsscienced/bin/dnsscienced.new"

    log "[$label] Uploading compiler ..."
    ns_scp "$COMPILE" "$target" "/opt/dnsscienced/bin/dnsscienced-compile.new"

    log "[$label] Uploading admin CLI ..."
    ns_scp "$ADMINCLI" "$target" "/opt/dnsscienced/bin/dnsscienced-admin"
    ns_ssh "$target" "chmod +x /opt/dnsscienced/bin/dnsscienced-admin"

    log "[$label] Swapping binaries and restarting ..."
    ns_ssh "$target" bash -s << 'REMOTE'
set -e
chmod +x /opt/dnsscienced/bin/dnsscienced.new
chmod +x /opt/dnsscienced/bin/dnsscienced-compile.new

# Atomic swap
mv /opt/dnsscienced/bin/dnsscienced.new   /opt/dnsscienced/bin/dnsscienced
mv /opt/dnsscienced/bin/dnsscienced-compile.new /opt/dnsscienced/bin/dnsscienced-compile

# Restart via systemd (or kill+start if no systemd unit)
if systemctl is-active --quiet dnsscienced 2>/dev/null; then
    systemctl restart dnsscienced
    sleep 2
    systemctl status dnsscienced --no-pager -l | head -20
elif pgrep -x dnsscienced > /dev/null; then
    pkill -x dnsscienced || true
    sleep 1
    nohup /opt/dnsscienced/bin/dnsscienced \
        -config /opt/dnsscienced/config/dnsscienced.yaml \
        >> /opt/dnsscienced/logs/dnsscienced.log 2>&1 &
    sleep 2
    pgrep -x dnsscienced && echo "dnsscienced running" || echo "WARNING: dnsscienced not running"
else
    echo "WARNING: dnsscienced is not currently running — not starting automatically"
    echo "  Start with: systemctl start dnsscienced"
fi
REMOTE

    log "[$label] Done."
}

# ── update production config with API key ────────────────────────────────────
#
# Only writes config if api_keys section is missing.
# The key below matches what itz.agency uses (dnsscienced admin key from memory).

ADMIN_KEY="6cqNMyu5YF5TmIy-_i_gsLs4xvVTK56RIgwCgJcKZiM"

patch_config() {
    local label="$1"
    local target="$2"
    local cfg="/opt/dnsscienced/config/dnsscienced.yaml"

    # Check if api_keys is already set
    if ns_ssh "$target" "grep -q 'api_keys' $cfg 2>/dev/null"; then
        log "[$label] api_keys already in config, skipping."
        return
    fi

    log "[$label] Patching config to add api_keys ..."
    ns_ssh "$target" bash -s <<REMOTE
set -e
# Append api_keys under the admin section
python3 - << 'PY'
import re, sys

cfg = open('/opt/dnsscienced/config/dnsscienced.yaml').read()

# If admin section exists but has no api_keys, add it
if 'admin:' in cfg and 'api_keys' not in cfg:
    cfg = cfg.replace(
        '  enabled: true',
        '  enabled: true\n  api_keys:\n    - "${ADMIN_KEY}"'
    )
    open('/opt/dnsscienced/config/dnsscienced.yaml', 'w').write(cfg)
    print('Patched.')
else:
    print('No change needed.')
PY
REMOTE
}

# ── main ─────────────────────────────────────────────────────────────────────

TARGET="${1:-both}"

case "$TARGET" in
    ns1)
        deploy_to "ns1" "$NS1"
        patch_config "ns1" "$NS1"
        ;;
    ns2)
        deploy_to "ns2" "$NS2"
        patch_config "ns2" "$NS2"
        ;;
    both|"")
        deploy_to "ns1" "$NS1"
        patch_config "ns1" "$NS1"
        echo ""
        deploy_to "ns2" "$NS2"
        patch_config "ns2" "$NS2"
        ;;
    *)
        error "Usage: $0 [ns1|ns2|both]"
        ;;
esac

echo ""
log "Deployment complete!"
log ""
log "Test gRPC on ns1: grpcurl -plaintext 166.0.192.27:9091 dnsscience.v1.ZoneService/ListZones"
log "Test gRPC on ns2: grpcurl -plaintext 108.165.120.57:9091 dnsscience.v1.ZoneService/ListZones"
