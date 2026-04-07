#!/bin/bash
# Deploy dnsscienced to DNS servers
# Build: GOOS=linux GOARCH=amd64 go build -o dnsscienced-linux ./cmd/dnsscienced/

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SCRIPT_DIR/dnsscienced-linux"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log() { echo -e "${GREEN}[deploy]${NC} $1"; }
warn() { echo -e "${YELLOW}[warn]${NC} $1"; }
error() { echo -e "${RED}[error]${NC} $1"; exit 1; }

# Check binary exists
[ -f "$BINARY" ] || error "Binary not found: $BINARY"

DNS_SERVERS=("gdns1" "gdns2")

deploy_to_server() {
    local server=$1
    log "Deploying to $server..."

    # Create directory structure
    ssh "$server" "mkdir -p /opt/dnsscienced/{bin,config,logs,zones}"

    # Upload binary
    log "Uploading binary..."
    scp "$BINARY" "$server:/opt/dnsscienced/bin/dnsscienced"
    ssh "$server" "chmod +x /opt/dnsscienced/bin/dnsscienced"

    # Create default config if doesn't exist
    ssh "$server" "test -f /opt/dnsscienced/config/dnsscienced.yaml" || cat > /tmp/dns-config.yaml << 'EOF'
server:
  listen: "0.0.0.0:53"
  tcp_listen: "0.0.0.0:53"
  workers: 4

cache:
  enabled: true
  max_size: 10000
  ttl: 300

logging:
  level: info
  file: /opt/dnsscienced/logs/dnsscienced.log

zones_dir: /opt/dnsscienced/zones
EOF

    if ! ssh "$server" "test -f /opt/dnsscienced/config/dnsscienced.yaml"; then
        scp /tmp/dns-config.yaml "$server:/opt/dnsscienced/config/dnsscienced.yaml"
        rm /tmp/dns-config.yaml
    fi

    # Create systemd service
    log "Creating systemd service..."
    ssh "$server" "cat > /etc/systemd/system/dnsscienced.service" << 'EOF'
[Unit]
Description=DNSScience DNS Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/dnsscienced
ExecStart=/opt/dnsscienced/bin/dnsscienced -config /opt/dnsscienced/config/dnsscienced.yaml
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    # Reload systemd and enable service
    ssh "$server" "systemctl daemon-reload"
    ssh "$server" "systemctl enable dnsscienced"

    log "✓ Deployed to $server"
    log "To start: ssh $server 'systemctl start dnsscienced'"
    log "To check: ssh $server 'systemctl status dnsscienced'"
}

# Main deployment
log "Starting DNS server deployment..."
log "Binary: $BINARY ($(ls -lh $BINARY | awk '{print $5}'))"
echo ""

for server in "${DNS_SERVERS[@]}"; do
    deploy_to_server "$server"
    echo ""
done

log "Deployment complete!"
log ""
log "Next steps:"
log "1. Review configs on each server"
log "2. Add zone files to /opt/dnsscienced/zones/"
log "3. Start services: systemctl start dnsscienced"
log "4. Test DNS: dig @<server-ip> example.com"
