# Web3 DNS Integration Modules

## DNS Science: DNS Data, Management, Analytics, and Security Experts

**Bridging Traditional DNS and Decentralized Name Systems**

DNSScienced provides native, modular support for Web3 naming systems, enabling seamless resolution of blockchain-based domains alongside traditional DNS. Each Web3 naming system is implemented as a pluggable module.

---

## 1. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      WEB3 DNS RESOLUTION ARCHITECTURE                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  DNS Query: "vitalik.eth" A                                                │
│       │                                                                     │
│       ▼                                                                     │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    WEB3 DNS ROUTER                                   │   │
│  │                                                                      │   │
│  │   TLD Detection:                                                    │   │
│  │   ┌──────────────────────────────────────────────────────────────┐ │   │
│  │   │                                                               │ │   │
│  │   │  .eth      ──► ENS Module                                    │ │   │
│  │   │  .sol      ──► SNS Module                                    │ │   │
│  │   │  .crypto   ──► Unstoppable Domains Module                    │ │   │
│  │   │  .x        ──► Unstoppable Domains Module                    │ │   │
│  │   │  .wallet   ──► Unstoppable Domains Module                    │ │   │
│  │   │  .nft      ──► Unstoppable Domains Module                    │ │   │
│  │   │  .blockchain ──► Unstoppable Domains Module                  │ │   │
│  │   │  .888      ──► Unstoppable Domains Module                    │ │   │
│  │   │  .dao      ──► Unstoppable Domains Module                    │ │   │
│  │   │  .fn       ──► Freename Module                               │ │   │
│  │   │  .itz      ──► ITZ Module                                    │ │   │
│  │   │  *.tz.agency ──► ITZ Module (subdomain routing)             │ │   │
│  │   │  (other)   ──► Traditional DNS                               │ │   │
│  │   │                                                               │ │   │
│  │   └──────────────────────────────────────────────────────────────┘ │   │
│  │                                                                      │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                           │                                                 │
│         ┌─────────────────┼─────────────────┐                              │
│         ▼                 ▼                 ▼                              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                        │
│  │     ENS     │  │     SNS     │  │ Unstoppable │                        │
│  │   Module    │  │   Module    │  │   Module    │                        │
│  │             │  │             │  │             │                         │
│  │ Ethereum    │  │ Solana      │  │ Polygon     │                        │
│  │ L1 + L2     │  │ Mainnet     │  │ Mainnet     │                        │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘                        │
│         │                │                │                                │
│         └────────────────┼────────────────┘                                │
│                          ▼                                                 │
│                 ┌─────────────────┐                                        │
│                 │  Response Cache │                                        │
│                 │                 │                                        │
│                 │ • TTL-based     │                                        │
│                 │ • Invalidation  │                                        │
│                 │ • Multi-layer   │                                        │
│                 └─────────────────┘                                        │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. ENS (Ethereum Name Service) Module

### Overview

ENS is the dominant naming system on Ethereum, allowing `.eth` domains to resolve to addresses, content hashes, and arbitrary records.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         ENS MODULE ARCHITECTURE                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                       ENS RESOLUTION FLOW                            │   │
│  │                                                                      │   │
│  │  Query: "vitalik.eth"                                               │   │
│  │         │                                                           │   │
│  │         ▼                                                           │   │
│  │  ┌─────────────────┐                                               │   │
│  │  │  Namehash       │  keccak256("eth") + keccak256("vitalik")     │   │
│  │  │  Calculation    │  = 0xee6c4522aab0003e8d14cd40a6af439055fd2577│   │
│  │  └────────┬────────┘                                               │   │
│  │           │                                                         │   │
│  │           ▼                                                         │   │
│  │  ┌─────────────────┐                                               │   │
│  │  │  ENS Registry   │  Ethereum: 0x00000000000C2E074eC69A0dFb2997BA3│   │
│  │  │  Contract Call  │  Call: resolver(namehash)                     │   │
│  │  └────────┬────────┘                                               │   │
│  │           │                                                         │   │
│  │           ▼                                                         │   │
│  │  ┌─────────────────┐                                               │   │
│  │  │  Resolver       │  Call resolver contract                       │   │
│  │  │  Contract Call  │  Method: addr(namehash, coinType)            │   │
│  │  └────────┬────────┘                                               │   │
│  │           │                                                         │   │
│  │           ▼                                                         │   │
│  │  ┌─────────────────┐                                               │   │
│  │  │  Response       │  ETH Address, Content Hash, Text Records     │   │
│  │  │  Construction   │  DNS Record Types: A, AAAA, TXT, etc.        │   │
│  │  └─────────────────┘                                               │   │
│  │                                                                      │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                       SUPPORTED RECORDS                              │   │
│  │                                                                      │   │
│  │  ENS Record Type        DNS Mapping                                 │   │
│  │  ─────────────────────────────────────────────────────────────────  │   │
│  │  ETH Address (60)       TXT "a=0x..."                              │   │
│  │  BTC Address (0)        TXT "btc=bc1..."                           │   │
│  │  Content Hash           TXT "contenthash=ipfs://..."               │   │
│  │  Text Record "url"      TXT "url=https://..."                      │   │
│  │  Text Record "email"    TXT "email=..."                            │   │
│  │  Text Record "avatar"   TXT "avatar=..."                           │   │
│  │  A Record               A (via content hash gateway)               │   │
│  │  AAAA Record            AAAA (via content hash gateway)            │   │
│  │                                                                      │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                       L2 SUPPORT                                     │   │
│  │                                                                      │   │
│  │  ENS supports resolution via L2s using CCIP-Read (EIP-3668):       │   │
│  │                                                                      │   │
│  │  • Optimism                                                         │   │
│  │  • Arbitrum                                                         │   │
│  │  • Base                                                             │   │
│  │  • Linea                                                            │   │
│  │                                                                      │   │
│  │  Off-chain resolution:                                              │   │
│  │  1. Query L1 resolver                                              │   │
│  │  2. Resolver returns OffchainLookup error with gateway URL         │   │
│  │  3. Fetch data from gateway                                        │   │
│  │  4. Submit proof to L1 resolver for verification                   │   │
│  │                                                                      │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### ENS Module Configuration

```yaml
# /etc/dnsscienced/modules/ens.yaml

module: ens
enabled: true

# Ethereum RPC configuration
ethereum:
  # Primary RPC endpoints (fallback order)
  rpc-endpoints:
    - url: "https://eth-mainnet.g.alchemy.com/v2/${ALCHEMY_KEY}"
      priority: 1
    - url: "https://mainnet.infura.io/v3/${INFURA_KEY}"
      priority: 2
    - url: "https://ethereum.publicnode.com"
      priority: 3

  # L2 endpoints for CCIP-Read
  l2-endpoints:
    optimism:
      url: "https://opt-mainnet.g.alchemy.com/v2/${ALCHEMY_KEY}"
    arbitrum:
      url: "https://arb-mainnet.g.alchemy.com/v2/${ALCHEMY_KEY}"
    base:
      url: "https://base-mainnet.g.alchemy.com/v2/${ALCHEMY_KEY}"

  # Connection settings
  timeout: 5s
  retries: 3

# ENS contract addresses
contracts:
  registry: "0x00000000000C2E074eC69A0dFb2997BA3F7A6F5D"
  # Universal resolver for batch queries
  universal-resolver: "0xc0497E381f536Be9ce14B0dD3817cBcAe57d2F62"

# Resolution settings
resolution:
  # TLDs handled by this module
  tlds:
    - eth

  # Subdomains
  enable-subdomains: true

  # Wildcard resolution (*.name.eth)
  enable-wildcards: true

  # CCIP-Read for L2/offchain resolution
  ccip-read:
    enabled: true
    timeout: 10s
    max-redirects: 4

# Caching
cache:
  enabled: true
  ttl: 300                    # 5 minutes default
  negative-ttl: 60            # 1 minute for NXDOMAIN
  max-entries: 100000

# Record mapping
record-mapping:
  # Map ENS coin types to DNS records
  addresses:
    # ETH address (coin type 60)
    60:
      txt-prefix: "a"
      format: "a={address}"
    # BTC address (coin type 0)
    0:
      txt-prefix: "btc"
      format: "btc={address}"
    # Other cryptocurrencies...

  # Content hash to A/AAAA records
  content-hash:
    enabled: true
    # Gateway for IPFS/IPNS/Arweave content
    gateways:
      ipfs: "https://cloudflare-ipfs.com"
      ipns: "https://cloudflare-ipfs.com"
      arweave: "https://arweave.net"
    # Resolve to gateway IP for A records
    gateway-ip: "104.18.32.68"  # Cloudflare IPFS gateway
    gateway-ipv6: "2606:4700:3033::6812:2044"

  # Text records
  text-records:
    - url
    - email
    - avatar
    - description
    - notice
    - keywords
    - com.discord
    - com.github
    - com.twitter
    - org.telegram

# DNS response construction
dns-response:
  # Default TTL for ENS records
  ttl: 300

  # Include SOA for NXDOMAIN
  include-soa: true
  soa:
    mname: "ns1.ens.domains"
    rname: "admin.ens.domains"

  # Authority section
  ns-records:
    - "ns1.ens.domains"
    - "ns2.ens.domains"
```

### ENS Module Interface

```go
// ENS Module Go Interface

package ens

import (
    "github.com/ethereum/go-ethereum/ethclient"
    "github.com/wealdtech/go-ens/v3"
)

type ENSModule struct {
    client     *ethclient.Client
    registry   *ens.Registry
    cache      *ENSCache
    config     *ENSConfig
}

// Resolve handles DNS queries for .eth domains
func (m *ENSModule) Resolve(ctx context.Context, qname string, qtype uint16) (*dns.Msg, error) {
    // Parse ENS name
    name := strings.TrimSuffix(qname, ".")
    if !strings.HasSuffix(name, ".eth") {
        return nil, ErrNotENSDomain
    }

    // Check cache
    if cached := m.cache.Get(name, qtype); cached != nil {
        return cached, nil
    }

    // Calculate namehash
    namehash, err := ens.NameHash(name)
    if err != nil {
        return nil, err
    }

    // Get resolver
    resolver, err := m.registry.Resolver(namehash)
    if err != nil {
        return m.nxdomainResponse(qname), nil
    }

    // Resolve based on query type
    var response *dns.Msg
    switch qtype {
    case dns.TypeA, dns.TypeAAAA:
        response, err = m.resolveAddress(ctx, name, resolver, qtype)
    case dns.TypeTXT:
        response, err = m.resolveTextRecords(ctx, name, resolver)
    case dns.TypeANY:
        response, err = m.resolveAll(ctx, name, resolver)
    default:
        response = m.emptyResponse(qname, qtype)
    }

    if err != nil {
        return nil, err
    }

    // Cache response
    m.cache.Set(name, qtype, response)

    return response, nil
}

// CCIP-Read support for L2/offchain resolution
func (m *ENSModule) handleCCIPRead(ctx context.Context, err ens.OffchainLookupError) ([]byte, error) {
    // Fetch from gateway
    for _, url := range err.URLs {
        data, fetchErr := m.fetchFromGateway(ctx, url, err.CallData)
        if fetchErr == nil {
            // Verify proof on L1
            return m.verifyProof(ctx, err.CallbackFunction, data)
        }
    }
    return nil, ErrCCIPReadFailed
}
```

---

## 3. SNS (Solana Name Service) Module

### Overview

SNS provides `.sol` domain resolution on the Solana blockchain with significantly lower gas costs and faster finality.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         SNS MODULE ARCHITECTURE                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                       SNS RESOLUTION FLOW                            │   │
│  │                                                                      │   │
│  │  Query: "bonfida.sol"                                               │   │
│  │         │                                                           │   │
│  │         ▼                                                           │   │
│  │  ┌─────────────────┐                                               │   │
│  │  │  Domain Hash    │  SHA256("bonfida") → hashed_name              │   │
│  │  │  Calculation    │                                               │   │
│  │  └────────┬────────┘                                               │   │
│  │           │                                                         │   │
│  │           ▼                                                         │   │
│  │  ┌─────────────────┐                                               │   │
│  │  │  Registry PDA   │  Program: namesLPneVptA9Z5rqUDD9tMTWEJwofgaYwp│   │
│  │  │  Derivation     │  Seeds: [HASH_PREFIX, hashed_name]           │   │
│  │  └────────┬────────┘                                               │   │
│  │           │                                                         │   │
│  │           ▼                                                         │   │
│  │  ┌─────────────────┐                                               │   │
│  │  │  Account Fetch  │  RPC: getAccountInfo(registry_pda)           │   │
│  │  │                 │  Deserialize NameRegistry data               │   │
│  │  └────────┬────────┘                                               │   │
│  │           │                                                         │   │
│  │           ▼                                                         │   │
│  │  ┌─────────────────┐                                               │   │
│  │  │  Response       │  Owner address, Data records                 │   │
│  │  │  Construction   │                                               │   │
│  │  └─────────────────┘                                               │   │
│  │                                                                      │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                       SNS RECORD TYPES                               │   │
│  │                                                                      │   │
│  │  Record              Description           DNS Mapping              │   │
│  │  ────────────────────────────────────────────────────────────────── │   │
│  │  SOL                 Solana address        TXT "sol={address}"     │   │
│  │  ETH                 Ethereum address      TXT "eth={address}"     │   │
│  │  BTC                 Bitcoin address       TXT "btc={address}"     │   │
│  │  IPFS                Content hash          TXT "ipfs={cid}"        │   │
│  │  ARWV                Arweave hash          TXT "arweave={id}"      │   │
│  │  URL                 Website URL           TXT "url={url}"         │   │
│  │  Email               Email address         TXT "email={email}"     │   │
│  │  Discord             Discord handle        TXT "discord={handle}"  │   │
│  │  Twitter             Twitter handle        TXT "twitter={handle}"  │   │
│  │  A                   IPv4 (via IPFS gw)    A                       │   │
│  │  AAAA                IPv6 (via IPFS gw)    AAAA                    │   │
│  │                                                                      │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                       SUBDOMAIN SUPPORT                              │   │
│  │                                                                      │   │
│  │  SNS supports subdomains via parent domain delegation:              │   │
│  │                                                                      │   │
│  │  wallet.bonfida.sol                                                 │   │
│  │       │                                                             │   │
│  │       └─► Parent: bonfida.sol                                       │   │
│  │           └─► Subdomain account: derived from parent + "wallet"    │   │
│  │                                                                      │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### SNS Module Configuration

```yaml
# /etc/dnsscienced/modules/sns.yaml

module: sns
enabled: true

# Solana RPC configuration
solana:
  rpc-endpoints:
    - url: "https://api.mainnet-beta.solana.com"
      priority: 1
    - url: "https://solana-mainnet.g.alchemy.com/v2/${ALCHEMY_KEY}"
      priority: 2
    - url: "https://rpc.helius.xyz/?api-key=${HELIUS_KEY}"
      priority: 3

  # WebSocket for real-time updates (optional)
  websocket:
    enabled: false
    url: "wss://api.mainnet-beta.solana.com"

  # Connection settings
  timeout: 3s
  retries: 3
  commitment: confirmed  # processed | confirmed | finalized

# SNS program addresses
programs:
  name-service: "namesLPneVptA9Z5rqUDD9tMTWEJwofgaYwp"
  twitter-verification: "FvPH7PrVrLGKPfqaf3xJodFTjZriqrAXXLTVWEorTFBi"

# Resolution settings
resolution:
  tlds:
    - sol

  enable-subdomains: true

  # Record types to resolve
  records:
    - SOL      # Solana address
    - ETH      # Ethereum address
    - BTC      # Bitcoin address
    - IPFS     # IPFS content hash
    - URL      # Website URL
    - Email
    - Discord
    - Twitter
    - Telegram
    - Github

# Caching
cache:
  enabled: true
  ttl: 60                     # 1 minute (Solana has faster finality)
  negative-ttl: 30
  max-entries: 100000

# Content resolution
content:
  ipfs-gateway: "https://cloudflare-ipfs.com"
  arweave-gateway: "https://arweave.net"
```

---

## 4. Unstoppable Domains Module

### Overview

Unstoppable Domains provides multiple TLDs (`.crypto`, `.nft`, `.x`, `.wallet`, `.blockchain`, `.bitcoin`, `.dao`, `.888`) with resolution on Polygon and Ethereum.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    UNSTOPPABLE DOMAINS MODULE                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                       SUPPORTED TLDs                                 │   │
│  │                                                                      │   │
│  │   .crypto      Original UD TLD (Ethereum + Polygon)                │   │
│  │   .nft         NFT-focused domains                                 │   │
│  │   .x           Short, memorable domains                            │   │
│  │   .wallet      Wallet-focused domains                              │   │
│  │   .blockchain  Blockchain-themed domains                           │   │
│  │   .bitcoin     Bitcoin-themed domains                              │   │
│  │   .dao         DAO-focused domains                                 │   │
│  │   .888         Lucky number domains                                │   │
│  │   .zil         Zilliqa domains (legacy)                           │   │
│  │                                                                      │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                       RESOLUTION ARCHITECTURE                        │   │
│  │                                                                      │   │
│  │  Query: "brad.crypto"                                               │   │
│  │         │                                                           │   │
│  │         ▼                                                           │   │
│  │  ┌─────────────────┐                                               │   │
│  │  │  Namehash       │  EIP-137 compatible namehash                 │   │
│  │  │  (same as ENS)  │  keccak256("crypto") + keccak256("brad")     │   │
│  │  └────────┬────────┘                                               │   │
│  │           │                                                         │   │
│  │           ▼                                                         │   │
│  │  ┌─────────────────────────────────────────────────────────────┐   │   │
│  │  │              MULTI-CHAIN RESOLUTION                          │   │   │
│  │  │                                                              │   │   │
│  │  │   ┌──────────────┐         ┌──────────────┐                │   │   │
│  │  │   │   Polygon    │         │   Ethereum   │                │   │   │
│  │  │   │  (Primary)   │         │  (Fallback)  │                │   │   │
│  │  │   │              │         │              │                 │   │   │
│  │  │   │ ProxyReader: │         │ Registry:    │                │   │   │
│  │  │   │ 0xA3f32c8cd │         │ 0xD1E5b0FF │                │   │   │
│  │  │   │              │         │              │                 │   │   │
│  │  │   │ Low gas      │         │ Higher gas   │                │   │   │
│  │  │   │ Fast         │         │ More secure  │                │   │   │
│  │  │   └──────────────┘         └──────────────┘                │   │   │
│  │  │                                                              │   │   │
│  │  │   Resolution Priority: Polygon → Ethereum → Not Found      │   │   │
│  │  │                                                              │   │   │
│  │  └─────────────────────────────────────────────────────────────┘   │   │
│  │           │                                                         │   │
│  │           ▼                                                         │   │
│  │  ┌─────────────────┐                                               │   │
│  │  │  Record Keys    │  UD uses string-based record keys:           │   │
│  │  │                 │  "crypto.ETH.address"                        │   │
│  │  │                 │  "crypto.BTC.address"                        │   │
│  │  │                 │  "ipfs.html.value"                           │   │
│  │  │                 │  "dns.A", "dns.AAAA"                         │   │
│  │  └─────────────────┘                                               │   │
│  │                                                                      │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                       NATIVE DNS RECORDS                             │   │
│  │                                                                      │   │
│  │  Unstoppable Domains supports native DNS record types:              │   │
│  │                                                                      │   │
│  │  Record Key            DNS Type      Example                        │   │
│  │  ──────────────────────────────────────────────────────────────────  │   │
│  │  dns.A                 A             192.0.2.1                      │   │
│  │  dns.A.1               A             192.0.2.2                      │   │
│  │  dns.AAAA              AAAA          2001:db8::1                    │   │
│  │  dns.CNAME             CNAME         www.example.com                │   │
│  │  dns.TXT               TXT           v=spf1 ...                     │   │
│  │  dns.MX                MX            10 mail.example.com            │   │
│  │                                                                      │   │
│  │  Crypto address records:                                            │   │
│  │  crypto.ETH.address    TXT           eth=0x...                      │   │
│  │  crypto.BTC.address    TXT           btc=bc1...                     │   │
│  │  crypto.SOL.address    TXT           sol=...                        │   │
│  │                                                                      │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Unstoppable Domains Configuration

```yaml
# /etc/dnsscienced/modules/unstoppable.yaml

module: unstoppable-domains
enabled: true

# Blockchain configuration
chains:
  polygon:
    rpc-endpoints:
      - url: "https://polygon-mainnet.g.alchemy.com/v2/${ALCHEMY_KEY}"
        priority: 1
      - url: "https://polygon-rpc.com"
        priority: 2
    chain-id: 137
    contracts:
      proxy-reader: "0xA3f32c8cd786a3bF45AA02E0c25A1e7dB30Fc5A2"
      uns-registry: "0xa9a6A3626993D487d2Dbda3173cf58cA1a9D9e9f"
      cns-registry: "0xD1E5b0FF1287aA9f9A268759062E4Ab08b9Dacbe"
    priority: primary

  ethereum:
    rpc-endpoints:
      - url: "https://eth-mainnet.g.alchemy.com/v2/${ALCHEMY_KEY}"
        priority: 1
    chain-id: 1
    contracts:
      uns-registry: "0x049aba7510f45BA5b64ea9E658E342F904DB358D"
      cns-registry: "0xD1E5b0FF1287aA9f9A268759062E4Ab08b9Dacbe"
    priority: fallback

# Resolution settings
resolution:
  tlds:
    - crypto
    - nft
    - x
    - wallet
    - blockchain
    - bitcoin
    - dao
    - 888
    - zil

  # Resolution order
  chain-priority:
    - polygon    # Check Polygon first (faster, cheaper)
    - ethereum   # Fallback to Ethereum

  # Timeout per chain
  timeout: 5s

# Record mapping
records:
  # DNS record types (native support)
  dns:
    - A
    - AAAA
    - CNAME
    - TXT
    - MX

  # Cryptocurrency addresses
  crypto:
    - ETH
    - BTC
    - LTC
    - SOL
    - MATIC
    - USDT
    - USDC

  # Other records
  other:
    - ipfs.html.value     # IPFS website
    - browser.redirect    # HTTP redirect
    - social.twitter
    - social.discord

# Caching
cache:
  enabled: true
  ttl: 300
  negative-ttl: 60

# API fallback (Unstoppable Domains Resolution API)
api-fallback:
  enabled: true
  url: "https://resolve.unstoppabledomains.com"
  api-key: "${UD_API_KEY}"
  # Use API when blockchain is unavailable
  use-when: blockchain-unavailable
```

---

## 5. Freename Module

### Overview

Freename provides Web3 domain registration across multiple TLDs with NFT-based ownership.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         FREENAME MODULE                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                       FREENAME ARCHITECTURE                          │   │
│  │                                                                      │   │
│  │  Freename operates differently from other Web3 DNS:                 │   │
│  │                                                                      │   │
│  │  • Domains are NFTs on Polygon                                      │   │
│  │  • Custom TLDs can be registered                                    │   │
│  │  • Resolution via Freename API + blockchain verification           │   │
│  │  • Supports traditional DNS record types                           │   │
│  │                                                                      │   │
│  │  ┌─────────────────────────────────────────────────────────────┐   │   │
│  │  │                    RESOLUTION FLOW                           │   │   │
│  │  │                                                              │   │   │
│  │  │  Query: "example.fn"                                        │   │   │
│  │  │         │                                                    │   │   │
│  │  │         ▼                                                    │   │   │
│  │  │  ┌─────────────────┐                                       │   │   │
│  │  │  │  Freename API   │  REST API for resolution              │   │   │
│  │  │  │  Lookup         │  GET /api/v1/resolve/{domain}         │   │   │
│  │  │  └────────┬────────┘                                       │   │   │
│  │  │           │                                                  │   │   │
│  │  │           ▼                                                  │   │   │
│  │  │  ┌─────────────────┐                                       │   │   │
│  │  │  │  Blockchain     │  Verify NFT ownership on Polygon      │   │   │
│  │  │  │  Verification   │  (optional, for security)             │   │   │
│  │  │  └────────┬────────┘                                       │   │   │
│  │  │           │                                                  │   │   │
│  │  │           ▼                                                  │   │   │
│  │  │  ┌─────────────────┐                                       │   │   │
│  │  │  │  DNS Response   │  A, AAAA, TXT, MX, CNAME             │   │   │
│  │  │  │  Construction   │                                       │   │   │
│  │  │  └─────────────────┘                                       │   │   │
│  │  │                                                              │   │   │
│  │  └─────────────────────────────────────────────────────────────┘   │   │
│  │                                                                      │   │
│  │  Supported TLDs (dynamic, user-created):                           │   │
│  │  • .fn (Freename native)                                           │   │
│  │  • Custom TLDs registered via Freename                             │   │
│  │  • TLD list fetched from Freename API                              │   │
│  │                                                                      │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Freename Configuration

```yaml
# /etc/dnsscienced/modules/freename.yaml

module: freename
enabled: true

# Freename API configuration
api:
  base-url: "https://api.freename.io"
  api-key: "${FREENAME_API_KEY}"
  timeout: 5s

# Blockchain verification (optional but recommended)
blockchain:
  enabled: true
  polygon:
    rpc-url: "https://polygon-mainnet.g.alchemy.com/v2/${ALCHEMY_KEY}"
    contract: "0x..."  # Freename NFT contract

# TLD configuration
tlds:
  # Static TLDs
  static:
    - fn

  # Dynamic TLD discovery from API
  dynamic:
    enabled: true
    refresh-interval: 1h
    endpoint: "/api/v1/tlds"

# Resolution settings
resolution:
  # Verify on-chain ownership before resolving
  verify-ownership: true

  # Cache settings
  cache:
    enabled: true
    ttl: 300
    negative-ttl: 60
```

---

## 6. ITZ (Internet Token Zone) Module

### Overview

ITZ.agency provides DNS-based multi-chain cryptocurrency infrastructure, using DNS subdomains for network-specific operations.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         ITZ MODULE ARCHITECTURE                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                       ITZ.AGENCY INTEGRATION                         │   │
│  │                                                                      │   │
│  │  ITZ uses DNS infrastructure as blockchain routing:                 │   │
│  │                                                                      │   │
│  │  Network Subdomains:                                                │   │
│  │  ┌────────────────────────────────────────────────────────────┐    │   │
│  │  │                                                             │    │   │
│  │  │  e.tz.agency     → Ethereum                                │    │   │
│  │  │  b.tz.agency     → Bitcoin                                 │    │   │
│  │  │  s.tz.agency     → Solana                                  │    │   │
│  │  │  bnb.tz.agency   → BNB Chain                               │    │   │
│  │  │  arb.tz.agency   → Arbitrum                                │    │   │
│  │  │  cb.tz.agency    → Base (Coinbase)                         │    │   │
│  │  │  a.tz.agency     → Avalanche                               │    │   │
│  │  │  apt.tz.agency   → Aptos                                   │    │   │
│  │  │  r.tz.agency     → Ripple (XRP)                            │    │   │
│  │  │                                                             │    │   │
│  │  └────────────────────────────────────────────────────────────┘    │   │
│  │                                                                      │   │
│  │  Address Resolution:                                                │   │
│  │  ┌────────────────────────────────────────────────────────────┐    │   │
│  │  │                                                             │    │   │
│  │  │  {wallet}.e.tz.agency                                      │    │   │
│  │  │       │                                                     │    │   │
│  │  │       ▼                                                     │    │   │
│  │  │  Query ITZ API for wallet metadata                         │    │   │
│  │  │       │                                                     │    │   │
│  │  │       ▼                                                     │    │   │
│  │  │  Return:                                                   │    │   │
│  │  │  • TXT: Owner information                                  │    │   │
│  │  │  • TXT: Wallet label                                       │    │   │
│  │  │  • TXT: Network chain ID                                   │    │   │
│  │  │  • TXT: Verification status                                │    │   │
│  │  │                                                             │    │   │
│  │  └────────────────────────────────────────────────────────────┘    │   │
│  │                                                                      │   │
│  │  API Endpoint Resolution:                                           │   │
│  │  ┌────────────────────────────────────────────────────────────┐    │   │
│  │  │                                                             │    │   │
│  │  │  {network}.tz.agency                                       │    │   │
│  │  │       │                                                     │    │   │
│  │  │       ▼                                                     │    │   │
│  │  │  Return A/AAAA records pointing to:                        │    │   │
│  │  │  • ITZ API servers                                         │    │   │
│  │  │  • Load balanced endpoints                                 │    │   │
│  │  │  • Geo-routed servers                                      │    │   │
│  │  │                                                             │    │   │
│  │  │  HTTPS Records (SVCB/TYPE65):                              │    │   │
│  │  │  • alpn="h2,h3"                                            │    │   │
│  │  │  • API endpoint hints                                      │    │   │
│  │  │                                                             │    │   │
│  │  └────────────────────────────────────────────────────────────┘    │   │
│  │                                                                      │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                       SPECIAL FEATURES                               │   │
│  │                                                                      │   │
│  │  1. Wallet Discovery via DNS                                        │   │
│  │     Query: _wallets.e.tz.agency TXT                                │   │
│  │     Returns: List of verified wallets                              │   │
│  │                                                                      │   │
│  │  2. Network Metadata                                                │   │
│  │     Query: _meta.e.tz.agency TXT                                   │   │
│  │     Returns: Chain ID, RPC endpoints, block explorer               │   │
│  │                                                                      │   │
│  │  3. Service Discovery                                               │   │
│  │     Query: _api._tcp.e.tz.agency SRV                               │   │
│  │     Returns: API server locations and priorities                   │   │
│  │                                                                      │   │
│  │  4. DNSSEC Validation                                               │   │
│  │     All ITZ DNS responses can be DNSSEC signed                     │   │
│  │     Provides cryptographic proof of wallet ownership               │   │
│  │                                                                      │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### ITZ Module Configuration

```yaml
# /etc/dnsscienced/modules/itz.yaml

module: itz
enabled: true

# ITZ.agency API configuration
api:
  base-url: "https://api.itz.agency"
  api-key: "${ITZ_API_KEY}"
  timeout: 5s

# Domain patterns
domains:
  # Primary domain
  base: "tz.agency"

  # Network subdomains
  networks:
    e:
      name: "Ethereum"
      chain-id: 1

    b:
      name: "Bitcoin"
      chain-id: null

    s:
      name: "Solana"
      chain-id: null

    bnb:
      name: "BNB Chain"
      chain-id: 56

    arb:
      name: "Arbitrum"
      chain-id: 42161

    cb:
      name: "Base"
      chain-id: 8453

    a:
      name: "Avalanche"
      chain-id: 43114

    apt:
      name: "Aptos"
      chain-id: null

    r:
      name: "Ripple"
      chain-id: null

# Resolution modes
resolution:
  # Resolve wallet addresses
  wallet-resolution:
    enabled: true
    # Pattern: {wallet}.{network}.tz.agency
    pattern: "^([a-zA-Z0-9]+)\\.([a-z]+)\\.tz\\.agency$"

  # Resolve API endpoints
  api-resolution:
    enabled: true
    # Pattern: {network}.tz.agency
    pattern: "^([a-z]+)\\.tz\\.agency$"

  # Service discovery
  service-discovery:
    enabled: true
    # SRV records for API endpoints

# Load balancing
load-balancing:
  enabled: true
  strategy: geo          # geo | round-robin | weighted

  endpoints:
    us-east:
      ip: "192.0.2.1"
      ipv6: "2001:db8::1"
      weight: 100

    eu-west:
      ip: "198.51.100.1"
      ipv6: "2001:db8::2"
      weight: 100

    ap-southeast:
      ip: "203.0.113.1"
      ipv6: "2001:db8::3"
      weight: 100

# Caching
cache:
  enabled: true
  ttl: 60                # Short TTL for dynamic wallet data
  negative-ttl: 30

# DNSSEC
dnssec:
  # Sign ITZ responses (for wallet verification)
  sign-responses: true
```

### ITZ DNS Record Examples

```
; Network endpoint resolution
e.tz.agency.        60  IN  A       192.0.2.1
e.tz.agency.        60  IN  AAAA    2001:db8::1
e.tz.agency.        60  IN  HTTPS   1 . alpn="h2,h3" ipv4hint="192.0.2.1"

; Wallet resolution (0xabc123... on Ethereum)
0xabc123.e.tz.agency.   60  IN  TXT     "network=ethereum"
0xabc123.e.tz.agency.   60  IN  TXT     "chain-id=1"
0xabc123.e.tz.agency.   60  IN  TXT     "label=MyMainWallet"
0xabc123.e.tz.agency.   60  IN  TXT     "verified=true"
0xabc123.e.tz.agency.   60  IN  TXT     "owner=user@example.com"

; Network metadata
_meta.e.tz.agency.      300 IN  TXT     "chain-id=1"
_meta.e.tz.agency.      300 IN  TXT     "name=Ethereum Mainnet"
_meta.e.tz.agency.      300 IN  TXT     "symbol=ETH"
_meta.e.tz.agency.      300 IN  TXT     "explorer=https://etherscan.io"

; Service discovery
_api._tcp.e.tz.agency.  60  IN  SRV     10 100 443 api-us.itz.agency.
_api._tcp.e.tz.agency.  60  IN  SRV     20 100 443 api-eu.itz.agency.
```

---

## 7. Unified Web3 Module Interface

### Common Module Interface

```go
// Web3 DNS Module Interface
package web3dns

import (
    "context"
    "github.com/miekg/dns"
)

// Web3Module is the interface all Web3 DNS modules must implement
type Web3Module interface {
    // Metadata
    Name() string
    Version() string
    SupportedTLDs() []string

    // Lifecycle
    Init(config map[string]interface{}) error
    Start() error
    Stop() error
    HealthCheck() error

    // Resolution
    CanResolve(qname string) bool
    Resolve(ctx context.Context, qname string, qtype uint16) (*dns.Msg, error)

    // Caching hints
    GetTTL(qname string, qtype uint16) uint32
    ShouldCache(qname string, qtype uint16) bool
}

// Web3Record represents a resolved Web3 record
type Web3Record struct {
    Name       string
    RecordType string
    Value      string
    TTL        uint32
    Verified   bool
    Source     string   // "blockchain" | "api" | "cache"
    Chain      string   // "ethereum" | "solana" | "polygon" | etc
    TxHash     string   // Transaction hash for verification
}

// Web3ModuleRegistry manages all Web3 modules
type Web3ModuleRegistry struct {
    modules  map[string]Web3Module
    tldIndex map[string]Web3Module
}

func (r *Web3ModuleRegistry) RegisterModule(m Web3Module) error {
    r.modules[m.Name()] = m
    for _, tld := range m.SupportedTLDs() {
        r.tldIndex[tld] = m
    }
    return nil
}

func (r *Web3ModuleRegistry) ResolveForTLD(tld string) Web3Module {
    return r.tldIndex[tld]
}
```

### Web3 Router Configuration

```yaml
# /etc/dnsscienced/web3.yaml

web3-dns:
  enabled: true

  # Module loading
  modules:
    - ens
    - sns
    - unstoppable
    - freename
    - itz

  # TLD routing (auto-detected from modules, can override)
  routing:
    eth: ens
    sol: sns
    crypto: unstoppable
    nft: unstoppable
    x: unstoppable
    wallet: unstoppable
    blockchain: unstoppable
    fn: freename
    # ITZ uses subdomain matching, not TLD

  # Global settings
  global:
    # Timeout for Web3 resolution
    timeout: 10s

    # Retry settings
    retries: 2
    retry-delay: 500ms

    # Cache settings (can override per module)
    cache:
      enabled: true
      default-ttl: 300
      negative-ttl: 60

  # Fallback behavior
  fallback:
    # What to do if Web3 resolution fails
    on-error: servfail        # servfail | nxdomain | passthrough

    # Traditional DNS fallback for hybrid resolution
    traditional-dns:
      enabled: false
      servers:
        - 8.8.8.8
        - 1.1.1.1

  # Logging
  logging:
    # Log Web3 resolutions
    log-resolutions: true

    # Log blockchain calls
    log-blockchain-calls: true

    # Include transaction hashes
    include-tx-hash: true

  # Metrics
  metrics:
    enabled: true
    labels:
      - module
      - tld
      - chain
      - result
```

---

## 8. Security Considerations

### Blockchain Verification

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    WEB3 DNS SECURITY MODEL                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Trust Hierarchy:                                                           │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                                                                      │   │
│  │  BLOCKCHAIN (Highest Trust)                                         │   │
│  │  └─► Smart contract state                                           │   │
│  │      └─► Cryptographic proof                                        │   │
│  │          └─► Verifiable by anyone                                   │   │
│  │                                                                      │   │
│  │  API (Medium Trust)                                                 │   │
│  │  └─► Indexed blockchain data                                        │   │
│  │      └─► Faster but requires trust in API provider                 │   │
│  │          └─► Can be verified against blockchain                    │   │
│  │                                                                      │   │
│  │  CACHE (Lowest Trust)                                               │   │
│  │  └─► Previously verified data                                       │   │
│  │      └─► Subject to staleness                                       │   │
│  │          └─► Should have short TTL                                  │   │
│  │                                                                      │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  Verification Modes:                                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                                                                      │   │
│  │  MODE: STRICT                                                       │   │
│  │  • Always verify on blockchain                                      │   │
│  │  • Slower but cryptographically secure                             │   │
│  │  • Best for high-value transactions                                │   │
│  │                                                                      │   │
│  │  MODE: BALANCED (Default)                                           │   │
│  │  • Use API with periodic blockchain verification                   │   │
│  │  • Good balance of speed and security                              │   │
│  │  • Suitable for most use cases                                     │   │
│  │                                                                      │   │
│  │  MODE: FAST                                                         │   │
│  │  • API-only resolution                                              │   │
│  │  • Fastest but relies on API trust                                 │   │
│  │  • For read-heavy, low-risk applications                          │   │
│  │                                                                      │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  DNSSEC Integration:                                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                                                                      │   │
│  │  Web3 DNS responses can be DNSSEC signed:                          │   │
│  │                                                                      │   │
│  │  • DNSScienced signs responses with zone keys                      │   │
│  │  • Clients can verify chain of trust                               │   │
│  │  • Provides additional layer of authentication                     │   │
│  │  • Useful for clients that don't verify blockchain                 │   │
│  │                                                                      │   │
│  │  However, DNSSEC does NOT replace blockchain verification:         │   │
│  │  • DNSSEC verifies DNS server authenticity                         │   │
│  │  • Blockchain verifies on-chain state                              │   │
│  │  • Both are complementary security layers                          │   │
│  │                                                                      │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Security Configuration

```yaml
# /etc/dnsscienced/web3-security.yaml

web3-security:
  # Verification mode
  verification-mode: balanced   # strict | balanced | fast

  # Blockchain verification
  blockchain-verification:
    # Verify percentage of requests on-chain
    sample-rate: 0.1           # 10% of requests

    # Always verify for specific record types
    always-verify:
      - crypto-address
      - content-hash

    # Never verify (for performance)
    never-verify:
      - social-records
      - avatar

  # RPC security
  rpc:
    # Use multiple RPC providers
    multi-provider: true

    # Verify responses from multiple sources
    cross-verify:
      enabled: true
      min-agreement: 2         # At least 2 providers must agree

    # Rate limiting
    rate-limit:
      requests-per-second: 100

  # Cache security
  cache:
    # Maximum cache TTL (override module settings)
    max-ttl: 600

    # Invalidate cache on suspicious activity
    auto-invalidate: true

  # Response validation
  response-validation:
    # Validate address format
    validate-addresses: true

    # Validate content hashes
    validate-content-hashes: true

    # Maximum response size
    max-response-size: 4096
```

---

## 9. Performance Optimization

### Caching Strategy

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    WEB3 DNS CACHING ARCHITECTURE                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                       MULTI-LAYER CACHE                              │   │
│  │                                                                      │   │
│  │   L1: In-Memory (Hot Cache)                                        │   │
│  │   ┌─────────────────────────────────────────────────────────────┐  │   │
│  │   │  • Most frequently accessed domains                         │  │   │
│  │   │  • Sub-millisecond access                                   │  │   │
│  │   │  • Size: 10,000 - 100,000 entries                          │  │   │
│  │   │  • TTL: 60-300 seconds                                      │  │   │
│  │   └─────────────────────────────────────────────────────────────┘  │   │
│  │                              │                                      │   │
│  │                              ▼ Miss                                 │   │
│  │   L2: Redis (Warm Cache)                                           │   │
│  │   ┌─────────────────────────────────────────────────────────────┐  │   │
│  │   │  • Shared across instances                                  │  │   │
│  │   │  • Millisecond access                                       │  │   │
│  │   │  • Size: 1,000,000+ entries                                │  │   │
│  │   │  • TTL: 300-3600 seconds                                    │  │   │
│  │   └─────────────────────────────────────────────────────────────┘  │   │
│  │                              │                                      │   │
│  │                              ▼ Miss                                 │   │
│  │   L3: Blockchain/API (Cold Resolution)                             │   │
│  │   ┌─────────────────────────────────────────────────────────────┐  │   │
│  │   │  • Actual resolution                                        │  │   │
│  │   │  • 100ms - 5s access                                        │  │   │
│  │   │  • Rate limited                                             │  │   │
│  │   │  • Populate cache on response                              │  │   │
│  │   └─────────────────────────────────────────────────────────────┘  │   │
│  │                                                                      │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  Cache Invalidation:                                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                                                                      │   │
│  │  • Time-based (TTL expiration)                                     │   │
│  │  • Event-based (blockchain events)                                 │   │
│  │    - ENS: NewResolver, AddrChanged events                         │   │
│  │    - UD: ResetRecords, Set events                                 │   │
│  │  • Manual (API-triggered purge)                                    │   │
│  │                                                                      │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Batch Resolution

```yaml
# Batch resolution for efficiency
batch-resolution:
  enabled: true

  # ENS Universal Resolver supports batch queries
  ens:
    batch-size: 10

  # Multicall for other contracts
  multicall:
    enabled: true
    contract: "0xcA11bde05977b3631167028862bE2a173976CA11"
    max-calls: 50
```

---

## 10. Deployment Examples

### Docker Compose

```yaml
# docker-compose.yml for Web3 DNS

version: '3.8'

services:
  dnsscienced:
    image: afterdarksys/dnsscienced:latest
    ports:
      - "53:53/udp"
      - "53:53/tcp"
      - "853:853/tcp"    # DoT
    volumes:
      - ./config:/etc/dnsscienced
      - ./modules:/etc/dnsscienced/modules
    environment:
      - ALCHEMY_KEY=${ALCHEMY_KEY}
      - INFURA_KEY=${INFURA_KEY}
      - ITZ_API_KEY=${ITZ_API_KEY}
      - UD_API_KEY=${UD_API_KEY}
    depends_on:
      - redis

  redis:
    image: redis:7-alpine
    volumes:
      - redis-data:/data

volumes:
  redis-data:
```

### Usage Examples

```bash
# Resolve ENS domain
dig @localhost vitalik.eth TXT

# Resolve Unstoppable Domain
dig @localhost brad.crypto A

# Resolve Solana domain
dig @localhost bonfida.sol TXT

# Resolve ITZ wallet
dig @localhost 0xabc123.e.tz.agency TXT

# Query ITZ network metadata
dig @localhost _meta.e.tz.agency TXT
```

---

## Summary

DNSScienced provides comprehensive Web3 DNS support through modular, pluggable integrations:

| Module | TLDs | Blockchain | Features |
|--------|------|------------|----------|
| ENS | .eth | Ethereum (L1/L2) | Full record support, CCIP-Read, subdomains |
| SNS | .sol | Solana | Fast finality, low cost, subdomains |
| Unstoppable | .crypto, .nft, .x, etc | Polygon/Ethereum | Multi-chain, native DNS records |
| Freename | .fn, custom | Polygon | NFT domains, custom TLDs |
| ITZ | *.tz.agency | Multi-chain | DNS-based blockchain routing, wallet discovery |

**DNS Science: DNS Data, Management, Analytics, and Security Experts.**

---

*Document Version: 1.0*
*Web3 Integration Specification*
