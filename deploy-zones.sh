#!/bin/bash
# Deploy zone files to gdns1 and gdns2
# Usage: ./deploy-zones.sh [zone-name]
#   No args: deploy all zones
#   With arg: deploy single zone (e.g. ./deploy-zones.sh secretserver.io)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ZONES_DIR="$SCRIPT_DIR/zones"
COMPILE_BIN="$SCRIPT_DIR/dnsscienced-compile"
DNS_SERVERS=("gdns1" "gdns2")
REMOTE_ZONES="/opt/dnsscienced/zones"
REMOTE_COMPILE="/opt/dnsscienced/bin/dnsscienced-compile"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
log()  { echo -e "${GREEN}[deploy]${NC} $1"; logger -t dnsscienced-deploy -p daemon.info "$1"; }
warn() { echo -e "${YELLOW}[warn]${NC} $1"; logger -t dnsscienced-deploy -p daemon.warning "$1"; }
error(){ echo -e "${RED}[error]${NC} $1"; logger -t dnsscienced-deploy -p daemon.error "$1"; exit 1; }

[ -f "$COMPILE_BIN" ] || error "Compile binary not found: $COMPILE_BIN"

# Determine which zones to deploy
if [ -n "$1" ]; then
    ZONE_FILES=("$ZONES_DIR/$1.dnszone")
    [ -f "${ZONE_FILES[0]}" ] || error "Zone file not found: ${ZONE_FILES[0]}"
else
    ZONE_FILES=("$ZONES_DIR"/*.dnszone)
fi

log "Deploying ${#ZONE_FILES[@]} zone(s) to: ${DNS_SERVERS[*]}"

deploy_to_server() {
    local server=$1
    log "[$server] Copying zone files..."
    scp -q "${ZONE_FILES[@]}" "$server:$REMOTE_ZONES/"

    log "[$server] Compiling and verifying zones on server..."
    local failed=()
    for zone_file in "${ZONE_FILES[@]}"; do
        base=$(basename "$zone_file")
        dzc="${REMOTE_ZONES}/${base%.dnszone}.dzc"
        # Compile with verify — on failure, remove any partial .dzc and track it
        if ssh "$server" "$REMOTE_COMPILE -input $REMOTE_ZONES/$base -output $dzc -verify 2>&1 | grep -E '(✓ Verification|Error|failed)'"; then
            ssh "$server" "logger -t dnsscienced-deploy -p daemon.info 'zone compile ok: $base'" 2>/dev/null
        else
            ssh "$server" "rm -f $dzc; logger -t dnsscienced-deploy -p daemon.warning 'zone compile FAILED: $base — falling back to .dnszone'" 2>/dev/null
            failed+=("$base")
            warn "[$server] FAILED: $base — .dzc removed, will load from text"
        fi
    done

    if [ ${#failed[@]} -gt 0 ]; then
        warn "[$server] ${#failed[@]} zone(s) failed verification: ${failed[*]}"
    fi

    log "[$server] Reloading dnsscienced..."
    ssh "$server" "systemctl restart dnsscienced"
    log "[$server] Done (${#failed[@]} fallback to .dnszone)"
}

# Deploy to both servers in parallel
for server in "${DNS_SERVERS[@]}"; do
    deploy_to_server "$server" &
done
wait

log "Verifying DNS resolution..."
sleep 2
for zone_file in "${ZONE_FILES[@]}"; do
    domain=$(basename "$zone_file" .dnszone)
    r1=$(dig @166.0.192.27 "$domain" A +short +time=3 2>/dev/null | head -1)
    r2=$(dig @108.165.120.57 "$domain" A +short +time=3 2>/dev/null | head -1)
    if [ "$r1" = "$r2" ] && [ -n "$r1" ]; then
        log "✓ $domain -> $r1"
    else
        warn "✗ $domain: gdns1=$r1 gdns2=$r2"
    fi
done

log "Deploy complete"
