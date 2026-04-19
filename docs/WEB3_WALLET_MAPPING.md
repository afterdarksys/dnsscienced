# Web3 Wallet Mapping Implementation

## draft-chins-dnsop-web3-wallet-mapping-03

DNSScienced implements the IETF draft specification for DNS to Web3 Wallet Mapping, enabling secure storage and retrieval of blockchain wallet addresses via DNS.

---

## Overview

**Problem**: Fragmentation in mapping Web3 wallets to domain names
**Solution**: Standardized DNS-based wallet address storage using WALLET RRType with TXT fallback

**Draft Status**: Individual submission, Standards Track (August 2025)
**Author**: SC. Chin (D3 Global Inc.)

---

## Features

### ✅ TXT Record Fallback
Uses `_waddr.domain` TXT records during transition period before WALLET RRType IANA assignment

### ✅ Multi-Blockchain Support
Supports multiple blockchain namespaces via standardized identifiers:
- **EIP-155**: Ethereum and EVM-compatible chains
- **BIP-122**: Bitcoin and Bitcoin-like chains
- **Solana**: Solana blockchain
- **Cosmos**: Cosmos ecosystem
- **Polkadot**: Polkadot ecosystem

### ✅ DNSSEC Security
Optional DNSSEC validation requirement ensures wallet address authenticity

### ✅ Namespace Filtering
Allow/deny lists for blockchain namespaces provide policy control

### ✅ Standards Compliance
- **SLIP-0044**: Registered coin type tokens
- **CAIP-2**: Blockchain ID specification

---

## Record Format

```
_waddr.domain IN TXT "namespace:reference:address"
```

**Components**:
- `namespace`: Blockchain namespace (3-8 chars, case-insensitive)
  Examples: `eip155`, `bip122`, `solana`

- `reference`: Coin type (SLIP-0044) or Chain ID (CAIP-2)
  Examples: `1` (ETH mainnet), `btc`, `sol`, `137` (Polygon)

- `address`: Wallet address (1-128 chars, case-sensitive)
  Examples: `0x742d35Cc...`, `bc1qxy2kg...`, `DRpbCBMx...`

---

## Examples

### Ethereum Mainnet
```dns
_waddr.example.com. IN TXT "eip155:1:0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb"
```

### Bitcoin Mainnet
```dns
_waddr.example.com. IN TXT "bip122:btc:bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"
```

### Solana
```dns
_waddr.example.com. IN TXT "solana:sol:DRpbCBMxVnDK7maPM5tGv6MvB3v1sRMC86PZ8okm21hy"
```

### Polygon (EIP-155 Chain ID 137)
```dns
_waddr.example.com. IN TXT "eip155:137:0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb"
```

### Multiple Wallets
```dns
_waddr.example.com. IN TXT "eip155:1:0xAAAAA..."
_waddr.example.com. IN TXT "bip122:btc:bc1qmulti..."
_waddr.example.com. IN TXT "solana:sol:BBBBBBB..."
```

---

## Configuration

```yaml
experimental:
  enabled: true

  web3_wallet:
    enabled: true                # Enable Web3 wallet resolution
    require_dnssec: true         # Require DNSSEC validation
    txt_fallback: true           # Use _waddr TXT records

    # Allowed namespaces (empty = all)
    allow_namespaces:
      - "eip155"   # Ethereum
      - "bip122"   # Bitcoin
      - "solana"   # Solana
      - "cosmos"   # Cosmos
      - "polkadot" # Polkadot

    # Cache settings
    enable_cache: true
    cache_ttl: 1h

    # Logging
    log_lookups: false
```

---

## Security Considerations

### DNSSEC Validation
Set `require_dnssec: true` (default) to ensure wallet addresses are authenticated via DNSSEC chain-of-trust.

**Without DNSSEC**: Results marked as "informational only"
**With DNSSEC**: Full cryptographic validation of wallet addresses

### Namespace Filtering
Use `allow_namespaces` to restrict supported blockchains:
```yaml
allow_namespaces:
  - "eip155"  # Only allow Ethereum
  - "bip122"  # Only allow Bitcoin
```

Use `deny_namespaces` to block specific blockchains:
```yaml
deny_namespaces:
  - "testchain"  # Block experimental chains
```

### Case Sensitivity
- Namespace: Case-insensitive (`eip155` = `EIP155`)
- Reference: Case-insensitive (`btc` = `BTC`)
- Address: **Case-sensitive** (preserves original wallet address case)

---

## API Usage

### Parsing Wallet Mappings
```go
import "github.com/dnsscience/dnsscienced/internal/web3wallet"

wallet, err := web3wallet.ParseWalletMapping("eip155:1:0x742d35...")
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Namespace: %s\n", wallet.Namespace)  // "eip155"
fmt.Printf("Reference: %s\n", wallet.Reference)  // "1"
fmt.Printf("Address: %s\n", wallet.Address)      // "0x742d35..."
```

### Creating TXT Records
```go
wallet := &web3wallet.WalletMapping{
    Namespace: "eip155",
    Reference: "1",
    Address:   "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb",
}

txtRecord := web3wallet.CreateWalletTXTRecord("example.com", wallet, 3600)
// Returns: _waddr.example.com. 3600 IN TXT "eip155:1:0x742d35..."
```

---

## Migration Path

**Current (Transition)**:
Use `_waddr.domain` TXT records with `txt_fallback: true`

**Future (Post-IANA Assignment)**:
Use WALLET RRType directly:
```dns
example.com. IN WALLET "eip155:1:0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb"
```

---

## References

- [draft-chins-dnsop-web3-wallet-mapping-03](https://datatracker.ietf.org/doc/html/draft-chins-dnsop-web3-wallet-mapping-03)
- [SLIP-0044](https://github.com/satoshilabs/slips/blob/master/slip-0044.md) - Registered coin types
- [CAIP-2](https://github.com/ChainAgnostic/CAIPs/blob/master/CAIPs/caip-2.md) - Blockchain ID specification
- [RFC 8914](https://www.rfc-editor.org/rfc/rfc8914.html) - Extended DNS Errors

---

## Example Zone Files

See `examples/web3-wallet.zone` for complete examples including:
- Ethereum mainnet/testnets/L2s
- Bitcoin mainnet
- Solana
- Multi-wallet configurations
- Subdomain wallet mappings
