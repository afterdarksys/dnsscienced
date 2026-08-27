# DNSScienced Quick Start Guide

Get up and running with DNSScienced in minutes.

## Prerequisites

- Go 1.25 or later
- Linux, macOS, or Windows
- Root/Administrator access (for binding to port 53)

## Installation

### Option 1: Build from Source

```bash
# Clone repository
git clone https://github.com/afterdarksys/dnsscienced.git
cd dnsscienced

# Build
make build

# Install (optional)
sudo make install
```

### Option 2: Go Install

```bash
go install github.com/dnsscience/dnsscienced/cmd/...@latest
```

### Option 3: Docker

```bash
# Pull images
docker pull dnsscience/dnsscienced:cached
docker pull dnsscience/dnsscienced:authd
```

## 1. Running the Recursive Resolver

The recursive resolver (`dnsscience_cached`) provides caching DNS resolution with DNSSEC validation.

### Minimal Configuration

Create `/etc/dnsscienced/cached.conf`:

```yaml
server {
    listen = ["127.0.0.1:53"]
}

cache {
    backend = "memory"
    size = "256MB"
}

dnssec {
    validation = yes
}
```

### Start the Resolver

```bash
sudo dnsscience-cached -c /etc/dnsscienced/cached.conf
```

### Test It

```bash
dig @127.0.0.1 example.com
dig @127.0.0.1 cloudflare.com AAAA
dig @127.0.0.1 google.com MX
```

## 2. Running the Authoritative Server

The authoritative server (`dnsscience_authd`) serves your DNS zones.

### Create a Zone File

Create `/var/lib/dnsscienced/zones/example.com.dnszone`:

```yaml
zone: example.com
serial: auto
ttl: 3600

primary-ns: ns1.example.com
admin-email: admin@example.com

nameservers:
  - ns1.example.com
  - ns2.example.com

mx:
  - priority: 10
    host: mail.example.com

records:
  "@":
    A: 192.0.2.1
    AAAA: 2001:db8::1
    TXT: "v=spf1 mx -all"

  ns1:
    A: 192.0.2.2

  ns2:
    A: 192.0.2.3

  www:
    CNAME: "@"

  mail:
    A: 192.0.2.10
```

### Minimal Configuration

Create `/etc/dnsscienced/authd.conf`:

```yaml
server {
    listen = ["0.0.0.0:53"]
}

zones {
    zone "example.com" {
        file = "/var/lib/dnsscienced/zones/example.com.dnszone"
        type = primary
    }
}
```

### Start the Server

```bash
sudo dnsscience-authd -c /etc/dnsscienced/authd.conf
```

### Test It

```bash
dig @127.0.0.1 example.com SOA
dig @127.0.0.1 example.com NS
dig @127.0.0.1 www.example.com A
```

## 3. Enable DNS over TLS (DoT)

Add TLS support to the recursive resolver:

```yaml
server {
    listen = ["0.0.0.0:53"]
    listen-tls = ["0.0.0.0:853"]

    tls-certificate = "/etc/dnsscienced/tls/server.crt"
    tls-key = "/etc/dnsscienced/tls/server.key"
}
```

Generate self-signed certificates for testing:

```bash
mkdir -p /etc/dnsscienced/tls
openssl req -x509 -newkey rsa:4096 -sha256 -days 365 -nodes \
  -keyout /etc/dnsscienced/tls/server.key \
  -out /etc/dnsscienced/tls/server.crt \
  -subj "/CN=dns.example.com"
```

Test with DoT:

```bash
dnsscience-dig +tls @127.0.0.1 example.com A
```

## 4. Enable Response Policy Zones (RPZ)

Block malicious domains with RPZ:

```yaml
rpz {
    # DNSScience.io threat feed (requires API key)
    zone "dnsscience-threat" {
        url = "https://rpz.dnsscience.io/threat.rpz"
        refresh = 3600
    }

    # Custom blocklist
    zone "custom-blocklist" {
        file = "/etc/dnsscienced/rpz/blocklist.rpz"
    }
}
```

Create a simple blocklist (`/etc/dnsscienced/rpz/blocklist.rpz`):

```
$TTL 300
@   SOA localhost. admin.localhost. 1 3600 600 86400 300
    NS  localhost.

; Block specific domains
malware.example.com     CNAME   .
phishing.example.net    CNAME   .
```

## 5. Enable DNSSEC Signing

Sign your authoritative zones:

### Generate Keys

```bash
# Generate KSK (Key Signing Key)
dnsscience-keygen -a ED25519 -f KSK example.com

# Generate ZSK (Zone Signing Key)
dnsscience-keygen -a ED25519 example.com
```

### Configure Auto-Signing

```yaml
zones {
    zone "example.com" {
        file = "/var/lib/dnsscienced/zones/example.com.dnszone"
        type = primary

        dnssec {
            auto-sign = yes
            algorithm = ED25519
            key-directory = "/var/lib/dnsscienced/keys"
        }
    }
}
```

### Verify DNSSEC

```bash
dnsscience-dig +dnssec @127.0.0.1 example.com A
```

## 6. Docker Compose Deployment

Create `docker-compose.yml`:

```yaml
version: '3.8'

services:
  dns-cached:
    image: dnsscience/dnsscienced:cached
    container_name: dns-cached
    ports:
      - "53:53/udp"
      - "53:53/tcp"
      - "853:853/tcp"
    volumes:
      - ./config/cached.conf:/etc/dnsscienced/cached.conf
      - ./tls:/etc/dnsscienced/tls
    restart: unless-stopped

  dns-authd:
    image: dnsscience/dnsscienced:authd
    container_name: dns-authd
    ports:
      - "5353:53/udp"
      - "5353:53/tcp"
    volumes:
      - ./config/authd.conf:/etc/dnsscienced/authd.conf
      - ./zones:/var/lib/dnsscienced/zones
    restart: unless-stopped
```

Start:

```bash
docker-compose up -d
```

## 7. Systemd Service

Create `/etc/systemd/system/dnsscience-cached.service`:

```ini
[Unit]
Description=DNSScienced Recursive Resolver
After=network.target

[Service]
Type=simple
User=dnsscienced
Group=dnsscienced
ExecStart=/usr/local/bin/dnsscience-cached -c /etc/dnsscienced/cached.conf
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/lib/dnsscienced /var/log/dnsscienced

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable dnsscience-cached
sudo systemctl start dnsscience-cached
sudo systemctl status dnsscience-cached
```

## 8. DNSScience.io Integration

Connect to the DNSScience.io cloud platform:

1. Get an API key from [dnsscience.io/dashboard/api-keys](https://dnsscience.io/dashboard/api-keys)

2. Add to your configuration:

```yaml
dnsscience-cloud {
    enabled = yes
    api-key = "your-api-key-here"
    threat-feeds = yes
    telemetry = yes
}
```

This enables:
- Real-time threat intelligence feeds
- Domain reputation lookups
- Anonymous query analytics
- Centralized monitoring

## CLI Quick Reference

```bash
# Control commands
dnsscience-ctl reload              # Reload configuration
dnsscience-ctl flush               # Flush cache
dnsscience-ctl stats               # Show statistics
dnsscience-ctl zone reload <zone>  # Reload specific zone

# DNS queries
dnsscience-dig example.com A       # Standard query
dnsscience-dig +dnssec example.com # With DNSSEC
dnsscience-dig +tls @1.1.1.1 ...   # DNS over TLS
dnsscience-dig +https @cloudflare-dns.com ...  # DNS over HTTPS

# Zone management
dnsscience-checkzone example.com zone.dnszone  # Validate zone
dnsscience-convert bind2dnszone in.zone -o out.dnszone  # Convert

# DNSSEC
dnsscience-keygen -a ED25519 example.com       # Generate ZSK
dnsscience-keygen -a ED25519 -f KSK example.com  # Generate KSK
dnsscience-signzone -o out.signed zone.dnszone  # Sign zone
```

## Troubleshooting

### Port 53 Already in Use

```bash
# Check what's using port 53
sudo lsof -i :53
sudo ss -tulnp | grep :53

# On Ubuntu, disable systemd-resolved
sudo systemctl disable systemd-resolved
sudo systemctl stop systemd-resolved
```

### Permission Denied

```bash
# Create user and directories
sudo useradd -r -s /sbin/nologin dnsscienced
sudo mkdir -p /var/lib/dnsscienced /var/log/dnsscienced
sudo chown dnsscienced:dnsscienced /var/lib/dnsscienced /var/log/dnsscienced

# Allow binding to privileged ports
sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/dnsscience-cached
sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/dnsscience-authd
```

### View Logs

```bash
# If using systemd
journalctl -u dnsscience-cached -f

# If logging to file
tail -f /var/log/dnsscienced/queries.log
```

### Check Configuration

```bash
# Validate config syntax
dnsscience-cached -c /etc/dnsscienced/cached.conf --check

# Validate zone file
dnsscience-checkzone example.com /path/to/zone.dnszone
```

## Next Steps

- [Full Configuration Reference](DEPLOYMENT_OPERATIONS.md)
- [DNSSEC Operations Guide](../DESIGN.md#8-dnssec-implementation)
- [Plugin Development](../DESIGN.md#10-pluginmodule-system)
- [Web3 DNS Setup](WEB3_DNS_MODULES.md)
- [API Documentation](API_SPECIFICATIONS.md)

---

For more information, visit [dnsscience.io/docs/server](https://dnsscience.io/docs/server)
