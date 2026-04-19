package web3wallet

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// Resolver handles Web3 wallet address lookups
type Resolver struct {
	config Config
}

// Config holds Web3 wallet resolver configuration
type Config struct {
	Enabled         bool     `yaml:"enabled"`
	RequireDNSSEC   bool     `yaml:"require_dnssec"`    // Require DNSSEC validation
	TXTFallback     bool     `yaml:"txt_fallback"`      // Use _waddr TXT records as fallback
	AllowNamespaces []string `yaml:"allow_namespaces"`  // Allowed namespaces (empty = all)
	DenyNamespaces  []string `yaml:"deny_namespaces"`   // Denied namespaces
}

// DefaultConfig returns default configuration
func DefaultConfig() Config {
	return Config{
		Enabled:       false,
		RequireDNSSEC: true,  // Security: require DNSSEC by default
		TXTFallback:   true,  // Enable TXT fallback during transition
		AllowNamespaces: []string{
			"eip155",  // Ethereum
			"bip122",  // Bitcoin
			"solana",  // Solana
			"cosmos",  // Cosmos
			"polkadot", // Polkadot
		},
	}
}

// NewResolver creates a new Web3 wallet resolver
func NewResolver(cfg Config) *Resolver {
	return &Resolver{
		config: cfg,
	}
}

// LookupWallets queries for wallet mappings at a domain
// Returns wallet mappings found in WALLET or _waddr TXT records
func (r *Resolver) LookupWallets(zone interface{}, qname string) ([]*WalletMapping, error) {
	if !r.config.Enabled {
		return nil, nil
	}

	wallets := []*WalletMapping{}

	// TODO: Query WALLET RRType once assigned by IANA
	// For now, use TXT record fallback with _waddr prefix

	if r.config.TXTFallback {
		// Query _waddr.example.com TXT records
		waddrName := "_waddr." + qname

		// This is a placeholder - actual implementation would query the zone
		// For now, return empty to indicate feature is available but needs zone integration
		_ = waddrName
	}

	return wallets, nil
}

// ParseWalletFromTXT extracts wallet mapping from TXT record
func (r *Resolver) ParseWalletFromTXT(txt string, domain string) (*WalletMapping, error) {
	// Remove quotes if present
	txt = strings.Trim(txt, "\"")

	// Parse the wallet mapping
	wallet, err := ParseWalletMapping(txt)
	if err != nil {
		return nil, err
	}

	wallet.Domain = domain

	// Check namespace filtering
	if !r.isNamespaceAllowed(wallet.Namespace) {
		return nil, fmt.Errorf("namespace %q not allowed", wallet.Namespace)
	}

	return wallet, nil
}

// isNamespaceAllowed checks if a namespace is allowed
func (r *Resolver) isNamespaceAllowed(namespace string) bool {
	// Check deny list first
	for _, deny := range r.config.DenyNamespaces {
		if strings.EqualFold(deny, namespace) {
			return false
		}
	}

	// If allow list is empty, allow all (except denied)
	if len(r.config.AllowNamespaces) == 0 {
		return true
	}

	// Check allow list
	for _, allow := range r.config.AllowNamespaces {
		if strings.EqualFold(allow, namespace) {
			return true
		}
	}

	return false
}

// CreateWalletTXTRecord creates a TXT record for wallet mapping
// Uses _waddr.domain format as per draft-chins-dnsop-web3-wallet-mapping-03
func CreateWalletTXTRecord(domain string, wallet *WalletMapping, ttl uint32) *dns.TXT {
	fqdn := fmt.Sprintf("_waddr.%s", domain)
	if !strings.HasSuffix(fqdn, ".") {
		fqdn += "."
	}

	return &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   fqdn,
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		},
		Txt: []string{wallet.String()},
	}
}

// ValidateWalletRecord validates a wallet mapping against security requirements
func (r *Resolver) ValidateWalletRecord(wallet *WalletMapping, dnssecValid bool) error {
	if r.config.RequireDNSSEC && !dnssecValid {
		return fmt.Errorf("DNSSEC validation required but not valid")
	}

	if !r.isNamespaceAllowed(wallet.Namespace) {
		return fmt.Errorf("namespace %q not allowed", wallet.Namespace)
	}

	return nil
}
