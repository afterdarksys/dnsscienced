#!/bin/bash
# Deploy zone files to gdns1 and gdns2
# Usage: ./deploy-zones.sh <zone-name> | --all [--force]
#   <zone-name>  deploy a single zone (e.g. ./deploy-zones.sh secretserver.io)
#   --all        deploy every zone in zones/ — must be asked for explicitly
#   --check      run every guard, report, and exit without deploying
#   --force      skip the drift-guard (only when the repo is genuinely newer)
#
# A bare `./deploy-zones.sh` is refused on purpose: it used to push all 128
# zones and would revert any record edited directly on a host.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ZONES_DIR="$SCRIPT_DIR/zones"
case "$(uname -s)" in
    Darwin) COMPILE_BIN="$SCRIPT_DIR/dnsscienced-compile-darwin" ;;
    *)      COMPILE_BIN="$SCRIPT_DIR/dnsscienced-compile" ;;
esac
DNS_SERVERS=("ns1" "ns2")
REMOTE_ZONES="/opt/dnsscienced/zones"
REMOTE_COMPILE="/opt/dnsscienced/bin/dnsscienced-compile"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
log()  { echo -e "${GREEN}[deploy]${NC} $1"; logger -t dnsscienced-deploy -p daemon.info "$1"; }
warn() { echo -e "${YELLOW}[warn]${NC} $1"; logger -t dnsscienced-deploy -p daemon.warning "$1"; }
error(){ echo -e "${RED}[error]${NC} $1"; logger -t dnsscienced-deploy -p daemon.error "$1"; exit 1; }

[ -f "$COMPILE_BIN" ] || error "Compile binary not found: $COMPILE_BIN"

# Determine which zones to deploy
DEPLOY_ALL=0
FORCE=0
CHECK_ONLY=0
ZONE_ARG=""
for arg in "$@"; do
    case "$arg" in
        --all)   DEPLOY_ALL=1 ;;
        --force) FORCE=1 ;;
        --check) CHECK_ONLY=1 ;;
        -*)      error "Unknown flag: $arg (see usage at the top of this script)" ;;
        *)
            [ -n "$ZONE_ARG" ] && error "Deploy one zone at a time, or use --all"
            ZONE_ARG="$arg"
            ;;
    esac
done

if [ -n "$ZONE_ARG" ]; then
    ZONE_FILES=("$ZONES_DIR/$ZONE_ARG.dnszone")
    [ -f "${ZONE_FILES[0]}" ] || error "Zone file not found: ${ZONE_FILES[0]}"
elif [ "$DEPLOY_ALL" = "1" ]; then
    ZONE_FILES=("$ZONES_DIR"/*.dnszone)
    warn "all-zones mode: deploying every one of the ${#ZONE_FILES[@]} zones in $ZONES_DIR"
else
    error "Refusing a no-args deploy. That would push all $(ls "$ZONES_DIR"/*.dnszone 2>/dev/null | wc -l | tr -d ' ') zones and overwrite any record edited directly on a host. Name one zone (./deploy-zones.sh secretserver.io) or pass --all if you truly mean all of them."
fi

# --- zone-guard: refuse to deploy records pointing at decommissioned hosts ---
# Verified unreachable 2026-06-12 (retired Oracle Cloud boxes). Add IPs here as
# hosts are decommissioned; remove one only if that host is genuinely revived.
DEAD_IPS=("132.226.54.153" "129.80.158.147" "129.153.158.177")
guard_failed=0
for zone_file in "${ZONE_FILES[@]}"; do
    for dead in "${DEAD_IPS[@]}"; do
        if grep -qF "$dead" "$zone_file" 2>/dev/null; then
            warn "$(basename "$zone_file") references dead IP $dead:"
            grep -nF "$dead" "$zone_file" | sed 's/^/        /'
            guard_failed=1
        fi
    done
done
[ "$guard_failed" = "1" ] && error "zone-guard: refusing to deploy zone(s) pointing at decommissioned hosts. Repoint those records to a live host (or remove them) first."

# --- drift-guard: refuse to deploy a zone the servers have edited past ---
# 2026-08-05: the repo was two serials behind live and missing twelve records
# (login, support, signup, opc, oss, wiki, forums, clients, pmportal,
# inventory, licensing, webhooks). Deploying would have deleted all twelve,
# SSO included. Past sessions edited hosts directly; scp overwrites silently.
# This compares every zone about to ship against what each server actually
# holds, and stops if they disagree.
if [ "$FORCE" = "1" ]; then
    warn "drift-guard: SKIPPED (--force). You are asserting the repo is newer than live."
else
    log "drift-guard: comparing ${#ZONE_FILES[@]} zone(s) against ${DNS_SERVERS[*]}..."
    drift_tmp=$(mktemp -d)
    trap 'rm -rf "$drift_tmp"' EXIT
    # One scp per server rather than one per zone — 128 zones must not mean 256 round trips.
    for server in "${DNS_SERVERS[@]}"; do
        mkdir -p "$drift_tmp/$server"
        scp -q -o ConnectTimeout=8 "$server:$REMOTE_ZONES/*.dnszone" "$drift_tmp/$server/" 2>/dev/null || \
            warn "drift-guard: could not read zones from $server — cannot verify drift there"
    done
    drift_found=0
    for zone_file in "${ZONE_FILES[@]}"; do
        base=$(basename "$zone_file")
        for server in "${DNS_SERVERS[@]}"; do
            live="$drift_tmp/$server/$base"
            if [ ! -f "$live" ]; then
                log "  new on $server: $base (will be created)"
            elif ! diff -q "$zone_file" "$live" >/dev/null 2>&1; then
                warn "  DRIFT $base differs from live on $server (- repo, + server):"
                diff "$zone_file" "$live" | head -20 | sed 's/^/        /'
                drift_found=1
            fi
        done
    done
    if [ "$drift_found" = "1" ]; then
        error "drift-guard: live zone(s) differ from this repo. Lines marked '>' exist on the server and NOT here — deploying would delete them. Pull live down and reconcile first. Use --force only if you are certain the repo is the newer copy."
    fi
    log "drift-guard: clean, repo matches live"

    # orphan-guard: zones a server holds that the repo has no copy of. scp never
    # deletes, so these are not a deploy hazard — but this is exactly how seven
    # zones (adstelco.io, aftercloak.io, doms.net, meow.media, mockfactory.io,
    # secretserver.io, test123.agency) lived only on the hosts until 2026-08-05.
    # Warn, never block: an orphan is a bookkeeping problem, not a deploy risk.
    if [ "$DEPLOY_ALL" = "1" ]; then
        orphans=0
        for server in "${DNS_SERVERS[@]}"; do
            for live in "$drift_tmp/$server"/*.dnszone; do
                [ -f "$live" ] || continue
                base=$(basename "$live")
                if [ ! -f "$ZONES_DIR/$base" ]; then
                    warn "orphan-guard: $server serves $base with no copy in the repo"
                    orphans=$((orphans + 1))
                fi
            done
        done
        [ "$orphans" = "0" ] && log "orphan-guard: clean, every live zone has a repo copy"
    fi
fi

log "Running TXT doctor on ${#ZONE_FILES[@]} zone(s)..."
doctor_failed=()
for zone_file in "${ZONE_FILES[@]}"; do
    if ! "$COMPILE_BIN" -doctor -input "$zone_file" 2>&1; then
        doctor_failed+=("$(basename "$zone_file")")
    fi
done
if [ ${#doctor_failed[@]} -gt 0 ]; then
    error "TXT encoding issues found in: ${doctor_failed[*]} — rerun with -fix or fix manually"
fi

if [ "$CHECK_ONLY" = "1" ]; then
    log "check-only: all guards passed for ${#ZONE_FILES[@]} zone(s). Nothing deployed."
    exit 0
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
    r1=$(dig @ns1.idoms.net "$domain" A +short +time=3 2>/dev/null | head -1)
    r2=$(dig @ns2.idoms.net "$domain" A +short +time=3 2>/dev/null | head -1)
    if [ "$r1" = "$r2" ] && [ -n "$r1" ]; then
        log "✓ $domain -> $r1"
    else
        warn "✗ $domain: ns1=$r1 ns2=$r2"
    fi
done

log "Deploy complete"
