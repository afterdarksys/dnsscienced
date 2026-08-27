# DNSScienced Client Tools

## Official CLI Client: dnsgo (adsdnsgo)

The official command-line client for DNSScienced is `dnsgo`, provided by the `adsdnsgo` project.

### Repository

```
GitHub: github.com/afterdarksystems/adsdnsgo
Submodule: tools/adsdnsgo
```

### Submodule Integration

adsdnsgo is included as a Git submodule in the DNSScienced repository:

```
dnsscienced/
├── cmd/
│   ├── dnsscience-authd/
│   ├── dnsscience-cached/
│   └── dnssciencectl/
├── pkg/
├── internal/
├── plugins/
├── docs/
└── tools/
    └── adsdnsgo/          ← Submodule: Official CLI client
        ├── cmd/dnsgo/
        ├── pkg/
        └── ...
```

### Setup Submodule

```bash
# Clone with submodules
git clone --recursive https://github.com/afterdarksys/dnsscienced.git

# Or add submodule to existing clone
cd dnsscienced
git submodule add https://github.com/afterdarksystems/adsdnsgo.git tools/adsdnsgo
git submodule update --init --recursive

# Update submodule to latest
git submodule update --remote tools/adsdnsgo
```

### Build Together

```makefile
# Makefile targets
.PHONY: all server client tools

all: server client tools

server:
	go build -o bin/dnsscience-authd ./cmd/dnsscience-authd
	go build -o bin/dnsscience-cached ./cmd/dnsscience-cached
	go build -o bin/dnssciencectl ./cmd/dnssciencectl

client:
	cd tools/adsdnsgo && go build -o ../../bin/dnsgo ./cmd/dnsgo

tools: client
	go build -o bin/dnsscience-checkzone ./cmd/dnsscience-checkzone
	go build -o bin/dnsscience-keygen ./cmd/dnsscience-keygen
	go build -o bin/dnsscience-signzone ./cmd/dnsscience-signzone
	go build -o bin/dnsscience-convert ./cmd/dnsscience-convert

install: all
	install -m 755 bin/dnsscience-authd /usr/local/bin/
	install -m 755 bin/dnsscience-cached /usr/local/bin/
	install -m 755 bin/dnssciencectl /usr/local/bin/
	install -m 755 bin/dnsgo /usr/local/bin/
	install -m 755 bin/dnsscience-checkzone /usr/local/bin/
	install -m 755 bin/dnsscience-keygen /usr/local/bin/
	install -m 755 bin/dnsscience-signzone /usr/local/bin/
	install -m 755 bin/dnsscience-convert /usr/local/bin/
```

---

## Tool Suite Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       DNSSCIENCED TOOL SUITE                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  SERVER DAEMONS                                                             │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │  dnsscience-authd     Authoritative DNS server                       │  │
│  │  dnsscience-cached    Recursive DNS resolver                         │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
│  MANAGEMENT TOOLS                                                           │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │  dnssciencectl        Server control and management                  │  │
│  │  dnsgo                CLI client (query, debug, manage)              │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
│  ZONE TOOLS                                                                 │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │  dnsscience-checkzone Zone file validator                            │  │
│  │  dnsscience-convert   Zone format converter (BIND/djbdns → native)   │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
│  DNSSEC TOOLS                                                               │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │  dnsscience-keygen    DNSSEC key pair generator                      │  │
│  │  dnsscience-signzone  Zone signing utility                           │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## dnsgo Features for DNSScienced

### Server Management

```bash
# Connect to DNSScienced
dnsgo server connect dns.example.com --api-key key.json

# Status and health
dnsgo server status
dnsgo server health
dnsgo server stats --period 1h

# Zone operations
dnsgo server zones list
dnsgo server zones show example.com
dnsgo server zones reload example.com
dnsgo server zones notify example.com

# Cache operations
dnsgo server cache stats
dnsgo server cache flush example.com

# DNSSEC operations
dnsgo server dnssec status example.com
dnsgo server dnssec ds example.com
dnsgo server dnssec rollover example.com zsk
```

### DNS Query & Debug

```bash
# Query with verbosity levels
dnsgo query example.com A --level short|long|detail|verbose|debug

# Debug trace
dnsgo debug trace example.com
dnsgo debug compare example.com --resolvers 8.8.8.8,1.1.1.1
dnsgo debug propagation example.com
dnsgo debug delegation example.com

# Use dnsscience.io embedded DNS
dnsgo query domain.com --embedded-dns
```

### Zone Validation & Conversion

```bash
# Validate zone file for DNSScienced
dnsgo validate zone example.com.dnszone --platform dnsscienced

# Convert BIND zone to native format
dnsgo convert zone bind.zone native.dnszone --from bind --to dnsscienced
```

### Email Security

```bash
# SPF analysis
dnsgo spf get example.com --level verbose
dnsgo spf flatten example.com

# DKIM verification
dnsgo dkim get example.com --selector default
dnsgo dkim discover example.com

# DMARC policy
dnsgo dmarc get example.com
```

### dnsscience.io Integration

```bash
# Set API key
dnsgo science key set api-key.json

# Run scans
dnsgo science scan example.com
dnsgo science history example.com --limit 30
dnsgo science drift example.com --period 90d
```

---

## Configuration

### Client Config File

`~/.config/adsdnsgo/config.json`:

```json
{
  "defaults": {
    "output_level": "long",
    "color": true,
    "timeout": "10s"
  },
  "resolvers": {
    "default": ["8.8.8.8", "1.1.1.1"]
  },
  "dnsscienced": {
    "servers": {
      "production": {
        "host": "dns.example.com",
        "port": 8443,
        "api_key_file": "~/.config/adsdnsgo/prod-api-key.json"
      },
      "staging": {
        "host": "dns-staging.example.com",
        "port": 8443,
        "api_key_file": "~/.config/adsdnsgo/staging-api-key.json"
      }
    },
    "default_server": "production"
  },
  "dnsscience": {
    "api_key_file": "~/.config/adsdnsgo/dnsscience-key.json",
    "embedded_dns": {
      "enabled": true,
      "servers": [
        "cache01.dnsscience.io",
        "cache02.dnsscience.io"
      ]
    }
  }
}
```

---

## Comparison with Other Tools

| Feature | dnsgo | dig | drill | kdig |
|---------|-------|-----|-------|------|
| Basic queries | ✓ | ✓ | ✓ | ✓ |
| Verbosity levels | 5 | 1 | 1 | 1 |
| DNSSEC validation | ✓ | ✓ | ✓ | ✓ |
| DNSSEC chain trace | ✓ | ✗ | ✓ | ✗ |
| Wire-level debug | ✓ | ✓ | ✓ | ✓ |
| Email security (SPF/DKIM/DMARC) | ✓ | ✗ | ✗ | ✗ |
| Zone validation | ✓ | ✗ | ✗ | ✗ |
| Zone conversion | ✓ | ✗ | ✗ | ✗ |
| Server management | ✓ | ✗ | ✗ | ✗ |
| DDI appliance support | ✓ | ✗ | ✗ | ✗ |
| dnsscience.io integration | ✓ | ✗ | ✗ | ✗ |
| DNSScienced integration | ✓ | ✗ | ✗ | ✗ |
| JSON/YAML output | ✓ | ✗ | ✗ | ✓ |

---

## Links

- **adsdnsgo Repository**: [github.com/afterdarksystems/adsdnsgo](https://github.com/afterdarksystems/adsdnsgo)
- **Full Documentation**: [tools/adsdnsgo/DNSSCIENCED_CLIENT.md](../tools/adsdnsgo/DNSSCIENCED_CLIENT.md)
- **Design Document**: [tools/adsdnsgo/TICKET-001-ADSDNSGO-DESIGN.md](../tools/adsdnsgo/TICKET-001-ADSDNSGO-DESIGN.md)

---

*Part of the DNSScienced ecosystem*
