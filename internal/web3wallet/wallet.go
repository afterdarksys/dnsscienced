package web3wallet

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// draft-chins-dnsop-web3-wallet-mapping-03
// DNS to Web3 Wallet Mapping implementation

var (
	ErrInvalidFormat    = errors.New("invalid wallet mapping format")
	ErrInvalidNamespace = errors.New("invalid namespace")
	ErrInvalidReference = errors.New("invalid reference")
	ErrInvalidAddress   = errors.New("invalid address")
)

// WalletMapping represents a parsed wallet address mapping
// Format: "namespace:reference:address"
// Example: "eip155:1:0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb"
type WalletMapping struct {
	Namespace string // e.g., "bip122", "eip155", "solana"
	Reference string // Coin type (SLIP-0044) or Chain ID (CAIP-2)
	Address   string // Wallet address (case-sensitive)
	Domain    string // Domain this mapping belongs to
}

// EBNF Grammar from draft-chins-dnsop-web3-wallet-mapping-03:
// namespace  = 3*8( ALPHA / DIGIT / "-" )  ; case-insensitive
// reference  = 1*16( ALPHA / DIGIT / "-" ) ; case-insensitive
// address    = 1*128( ALPHA / DIGIT / "-" / "." / "%" ) ; case-sensitive

var (
	namespaceRegex = regexp.MustCompile(`^[a-zA-Z0-9-]{3,8}$`)
	referenceRegex = regexp.MustCompile(`^[a-zA-Z0-9-]{1,16}$`)
	addressRegex   = regexp.MustCompile(`^[a-zA-Z0-9-.%]{1,128}$`)
)

// ParseWalletMapping parses a wallet mapping string
// Format: "namespace:reference:address"
func ParseWalletMapping(s string) (*WalletMapping, error) {
	parts := strings.SplitN(s, ":", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: expected 'namespace:reference:address', got %q", ErrInvalidFormat, s)
	}

	namespace := strings.ToLower(parts[0]) // Case-insensitive
	reference := strings.ToLower(parts[1]) // Case-insensitive
	address := parts[2]                     // Case-sensitive

	// Validate namespace (3-8 characters)
	if !namespaceRegex.MatchString(namespace) {
		return nil, fmt.Errorf("%w: %q (must be 3-8 alphanumerics/hyphens)", ErrInvalidNamespace, namespace)
	}

	// Validate reference (1-16 characters)
	if !referenceRegex.MatchString(reference) {
		return nil, fmt.Errorf("%w: %q (must be 1-16 alphanumerics/hyphens)", ErrInvalidReference, reference)
	}

	// Validate address (1-128 characters)
	if !addressRegex.MatchString(address) {
		return nil, fmt.Errorf("%w: %q (must be 1-128 allowed characters)", ErrInvalidAddress, address)
	}

	return &WalletMapping{
		Namespace: namespace,
		Reference: reference,
		Address:   address,
	}, nil
}

// String returns the canonical string representation
func (w *WalletMapping) String() string {
	return fmt.Sprintf("%s:%s:%s", w.Namespace, w.Reference, w.Address)
}

// CommonNamespaces defines well-known blockchain namespaces
var CommonNamespaces = map[string]string{
	"bip122": "Bitcoin (BIP-122)",
	"eip155": "Ethereum (EIP-155)",
	"solana": "Solana",
	"cosmos": "Cosmos",
	"polkadot": "Polkadot",
	"tezos":  "Tezos",
	"hedera": "Hedera Hashgraph",
	"cardano": "Cardano",
}

// CommonReferences defines well-known coin types (SLIP-0044)
var CommonReferences = map[string]string{
	"btc":  "Bitcoin",
	"eth":  "Ethereum",
	"sol":  "Solana",
	"atom": "Cosmos",
	"dot":  "Polkadot",
	"xtz":  "Tezos",
	"hbar": "Hedera",
	"ada":  "Cardano",
}

// IsKnownNamespace checks if namespace is in CommonNamespaces
func (w *WalletMapping) IsKnownNamespace() bool {
	_, ok := CommonNamespaces[w.Namespace]
	return ok
}

// IsKnownReference checks if reference is in CommonReferences
func (w *WalletMapping) IsKnownReference() bool {
	_, ok := CommonReferences[w.Reference]
	return ok
}

// Examples:
// eip155:1:0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb     (Ethereum mainnet)
// bip122:btc:bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh (Bitcoin mainnet)
// solana:sol:DRpbCBMxVnDK7maPM5tGv6MvB3v1sRMC86PZ8okm21hy  (Solana mainnet)
// eip155:137:0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb    (Polygon)
