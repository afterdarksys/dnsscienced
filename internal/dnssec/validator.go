package dnssec

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// ValidationResult represents the result of DNSSEC validation
type ValidationResult struct {
	// Validation status
	Secure        bool // Cryptographically validated
	Bogus         bool // Validation failed (bad signature, etc.)
	Insecure      bool // Not signed (no DNSSEC)
	Indeterminate bool // Unable to determine (network error, etc.)

	// Details
	Error        error  // Validation error if any
	ErrorMessage string // Human-readable error message
	ChainDepth   int    // Length of the DNSSEC chain validated

	// Trust chain
	TrustChain []TrustAnchor // Chain of trust from root to target
	DSRecords  []dns.DS      // DS records in the chain
	DNSKEYs    []dns.DNSKEY  // DNSKEY records validated

	// Signature information
	Signatures []dns.RRSIG // RRSIG records validated
	ValidFrom  time.Time   // Earliest signature inception
	ValidUntil time.Time   // Latest signature expiration
}

// TrustAnchor represents a DNSSEC trust anchor in the chain
type TrustAnchor struct {
	Name      string     // Zone name
	DNSKEY    dns.DNSKEY // Key
	DS        *dns.DS    // DS record from parent (nil for root)
	Validated bool       // Whether this anchor was validated
	Error     error      // Validation error if any
}

// Validator performs DNSSEC validation
type Validator struct {
	// Configuration
	config ValidatorConfig

	// Trust anchors (root keys)
	trustAnchors []dns.DNSKEY

	// Negative trust anchors (domains to skip validation)
	negativeTrustAnchors map[string]bool

	// Resolver for querying DNSKEY and DS records
	resolver DNSResolver

	// Cache for validated keys and signatures
	cache *ValidationCache
}

// ValidatorConfig holds DNSSEC validator configuration
type ValidatorConfig struct {
	TrustAnchorFile string `yaml:"trust_anchor_file"`
	// Chain validation settings
	MaxChainDepth int  // Maximum chain depth (default: 20)
	DSLookup      bool // Query parent zones for DS records
	AcceptBogus   bool // Accept bogus responses (don't fail)
	FailOnBogus   bool // Return error on bogus
	FailOnMissing bool // Fail when DNSSEC expected but missing

	// Caching
	CachePositive bool          // Cache validated responses
	CacheNegative bool          // Cache NSEC/NSEC3 proofs
	CacheBogus    bool          // Cache bogus responses
	CacheTTL      time.Duration // Cache TTL

	// NSEC/NSEC3 settings
	NSEC3MaxIterations uint16 // Maximum NSEC3 iterations to accept
	ValidateNSEC       bool   // Validate NSEC/NSEC3 proofs

	// Algorithm support
	DisabledAlgorithms map[uint8]bool // Algorithms to reject

	// Logging
	LogValidation bool // Log all validation attempts
	LogFailures   bool // Log failures only
}

// DNSResolver interface for querying DNS records
type DNSResolver interface {
	Query(ctx context.Context, name string, qtype uint16) (*dns.Msg, error)
}

var errInsecureDelegation = errors.New("insecure DNSSEC delegation")

// DefaultValidatorConfig returns secure default configuration
func DefaultValidatorConfig() ValidatorConfig {
	return ValidatorConfig{
		MaxChainDepth:      20,
		DSLookup:           true,
		AcceptBogus:        false,
		FailOnBogus:        true,
		FailOnMissing:      false,
		CachePositive:      true,
		CacheNegative:      true,
		CacheBogus:         true,
		CacheTTL:           time.Hour,
		NSEC3MaxIterations: 150, // RFC 5155 recommendation
		ValidateNSEC:       true,
		// RFC 8624 MUST-NOT-validate algorithms. RSASHA1 (5) and
		// RSASHA1-NSEC3-SHA1 (7) are intentionally left enabled — still
		// widely deployed. Do not add them here.
		DisabledAlgorithms: map[uint8]bool{
			dns.RSAMD5:       true, // 1
			dns.DSA:          true, // 3
			dns.DSANSEC3SHA1: true, // 6
		},
		LogValidation: false,
		LogFailures:   true,
	}
}

// NewValidator creates a new DNSSEC validator
func NewValidator(config ValidatorConfig, resolver DNSResolver) (*Validator, error) {
	if resolver == nil {
		return nil, fmt.Errorf("resolver cannot be nil")
	}

	if config.MaxChainDepth == 0 {
		config.MaxChainDepth = 20
	}

	v := &Validator{
		config:               config,
		trustAnchors:         make([]dns.DNSKEY, 0),
		negativeTrustAnchors: make(map[string]bool),
		resolver:             resolver,
		cache:                NewValidationCache(config.CacheTTL),
	}
	if config.TrustAnchorFile != "" {
		if err := v.LoadTrustAnchorsFromFile(config.TrustAnchorFile); err != nil {
			return nil, fmt.Errorf("load trust anchors: %w", err)
		}
	}

	return v, nil
}

// AddTrustAnchor adds a trust anchor (typically root KSK)
func (v *Validator) AddTrustAnchor(key dns.DNSKEY) {
	v.trustAnchors = append(v.trustAnchors, key)
}

// AddNegativeTrustAnchor adds a domain to skip validation
func (v *Validator) AddNegativeTrustAnchor(domain string) {
	v.negativeTrustAnchors[strings.ToLower(dns.Fqdn(domain))] = true
}

// LoadTrustAnchorsFromFile loads trust anchors from a file (RFC 5011 format)
func (v *Validator) LoadTrustAnchorsFromFile(filename string) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	var anchors []dns.DNSKEY
	scanner := bufio.NewScanner(f)
	for line := 1; scanner.Scan(); line++ {
		text := strings.TrimSpace(scanner.Text())
		if text == "" || strings.HasPrefix(text, ";") || strings.HasPrefix(text, "#") {
			continue
		}
		rr, err := dns.NewRR(text)
		if err != nil {
			return fmt.Errorf("line %d: %w", line, err)
		}
		key, ok := rr.(*dns.DNSKEY)
		if !ok {
			return fmt.Errorf("line %d: trust anchor must be DNSKEY, got %s", line, dns.TypeToString[rr.Header().Rrtype])
		}
		key.Hdr.Name = strings.ToLower(dns.Fqdn(key.Hdr.Name))
		anchors = append(anchors, *key)
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if len(anchors) == 0 {
		return fmt.Errorf("trust anchor file contains no DNSKEY records")
	}
	v.trustAnchors = append(v.trustAnchors, anchors...)
	return nil
}

// Validate performs DNSSEC validation on a DNS response
func (v *Validator) Validate(ctx context.Context, msg *dns.Msg, qname string, qtype uint16) (*ValidationResult, error) {
	qname = dns.Fqdn(strings.ToLower(qname))

	// Check negative trust anchors
	if v.isNegativeTrustAnchor(qname) {
		return &ValidationResult{
			Insecure:     true,
			ErrorMessage: "Domain in negative trust anchors (validation skipped)",
		}, nil
	}

	// NSEC3 iteration cap (RFC 9276). Reject responses whose NSEC3 records
	// use an iteration count above the configured maximum BEFORE performing
	// any hashing, to avoid a CPU-exhaustion DoS. This check is independent
	// of trust anchors.
	if v.config.NSEC3MaxIterations > 0 {
		if iters, over := nsec3IterationsOverCap(msg, v.config.NSEC3MaxIterations); over {
			return &ValidationResult{
				Bogus: true,
				ErrorMessage: fmt.Sprintf(
					"NSEC3 iterations %d exceed maximum %d (RFC 9276)",
					iters, v.config.NSEC3MaxIterations),
			}, nil
		}
	}

	// Fail closed: without a configured trust anchor we cannot anchor any
	// chain of trust to a known root. AD must never be asserted on data we
	// cannot cryptographically anchor, so return Indeterminate instead of
	// letting validateResponse mark the result Secure against attacker-
	// supplied wire keys.
	if len(v.trustAnchors) == 0 {
		return &ValidationResult{
			Indeterminate: true,
			ErrorMessage:  "no trust anchors configured; unable to validate (AD not asserted)",
		}, nil
	}

	// Check if response has DNSSEC records
	if !hasDNSSECRecords(msg) {
		if v.config.FailOnMissing {
			return &ValidationResult{
				Bogus:        true,
				ErrorMessage: "DNSSEC expected but not present",
			}, fmt.Errorf("DNSSEC expected but not present")
		}
		return &ValidationResult{
			Insecure:     true,
			ErrorMessage: "Response not signed",
		}, nil
	}

	// Validate the response
	result, err := v.validateResponse(ctx, msg, qname, qtype)
	if err != nil {
		if v.config.LogFailures {
			// Log validation failure
		}
		return result, err
	}

	if v.config.LogValidation {
		// Log successful validation
	}

	return result, nil
}

// validateResponse performs the actual DNSSEC validation
func (v *Validator) validateResponse(ctx context.Context, msg *dns.Msg, qname string, qtype uint16) (*ValidationResult, error) {
	result := &ValidationResult{
		TrustChain: make([]TrustAnchor, 0),
	}

	// Extract RRSIGs from response
	rrsigs := extractRRSIGs(msg, qname, qtype)
	if len(rrsigs) == 0 {
		result.Bogus = true
		result.ErrorMessage = "No RRSIG records found"
		return result, fmt.Errorf("no RRSIG records found for %s/%d", qname, qtype)
	}

	result.Signatures = rrsigs

	// Build and validate chain of trust
	if err := v.buildTrustChain(ctx, qname, result); err != nil {
		if errors.Is(err, errInsecureDelegation) {
			result.Insecure = true
			result.ErrorMessage = err.Error()
			return result, nil
		}
		result.Bogus = true
		result.Error = err
		result.ErrorMessage = fmt.Sprintf("Trust chain validation failed: %v", err)
		return result, err
	}

	// Verify signatures
	if err := v.verifySignatures(msg, qname, qtype, result); err != nil {
		result.Bogus = true
		result.Error = err
		result.ErrorMessage = fmt.Sprintf("Signature verification failed: %v", err)
		return result, err
	}

	// Validation successful
	result.Secure = true
	return result, nil
}

// buildTrustChain builds the DNSSEC chain of trust from root to target zone
func (v *Validator) buildTrustChain(ctx context.Context, qname string, result *ValidationResult) error {
	signerZone := dns.Fqdn(strings.ToLower(result.Signatures[0].SignerName))
	rootMsg, err := v.resolver.Query(ctx, ".", dns.TypeDNSKEY)
	if err != nil {
		return fmt.Errorf("root DNSKEY lookup: %w", err)
	}
	currentKeys := extractDNSKEYs(rootMsg, ".", v.config.DisabledAlgorithms)
	rootRRset := dnskeysToRRs(currentKeys)
	rootSigs := extractSignaturesFor(rootMsg, ".", dns.TypeDNSKEY)
	anchor := matchingTrustAnchor(v.trustAnchors, currentKeys)
	if anchor == nil {
		return fmt.Errorf("root DNSKEY RRset does not contain a configured trust anchor")
	}
	if err := verifyRRSetWithKeys(rootRRset, rootSigs, []dns.DNSKEY{*anchor}, v.config.DisabledAlgorithms); err != nil {
		return fmt.Errorf("authenticate root DNSKEY RRset: %w", err)
	}
	result.DNSKEYs = append(result.DNSKEYs, currentKeys...)
	result.TrustChain = append(result.TrustChain, TrustAnchor{Name: ".", DNSKEY: *anchor, Validated: true})
	result.ChainDepth = 1
	if signerZone == "." {
		return nil
	}

	labels := dns.SplitDomainName(signerZone)
	for i := len(labels) - 1; i >= 0; i-- {
		child := dns.Fqdn(strings.Join(labels[i:], "."))
		if result.ChainDepth >= v.config.MaxChainDepth {
			return fmt.Errorf("max chain depth exceeded")
		}
		dsMsg, err := v.resolver.Query(ctx, child, dns.TypeDS)
		if err != nil {
			return fmt.Errorf("DS lookup failed for %s: %w", child, err)
		}
		dsRecords := extractDSRecords(dsMsg, child)
		if len(dsRecords) == 0 {
			return fmt.Errorf("%w at %s", errInsecureDelegation, child)
		}
		if err := verifyRRSetWithKeys(dsToRRs(dsRecords), extractSignaturesFor(dsMsg, child, dns.TypeDS), currentKeys, v.config.DisabledAlgorithms); err != nil {
			return fmt.Errorf("authenticate DS RRset for %s: %w", child, err)
		}

		keyMsg, err := v.resolver.Query(ctx, child, dns.TypeDNSKEY)
		if err != nil {
			return fmt.Errorf("DNSKEY lookup failed for %s: %w", child, err)
		}
		childKeys := extractDNSKEYs(keyMsg, child, v.config.DisabledAlgorithms)
		matchedKeys := matchDSKeys(dsRecords, childKeys)
		if len(matchedKeys) == 0 {
			return fmt.Errorf("no DNSKEY at %s matches authenticated DS", child)
		}
		if err := verifyRRSetWithKeys(dnskeysToRRs(childKeys), extractSignaturesFor(keyMsg, child, dns.TypeDNSKEY), matchedKeys, v.config.DisabledAlgorithms); err != nil {
			return fmt.Errorf("authenticate DNSKEY RRset for %s: %w", child, err)
		}
		result.DSRecords = append(result.DSRecords, dsRecords...)
		result.DNSKEYs = append(result.DNSKEYs, childKeys...)
		result.TrustChain = append(result.TrustChain, TrustAnchor{Name: child, DNSKEY: matchedKeys[0], DS: &dsRecords[0], Validated: true})
		result.ChainDepth++
		currentKeys = childKeys
	}
	return nil
}

// verifySignatures verifies RRSIG signatures for the response
func (v *Validator) verifySignatures(msg *dns.Msg, qname string, qtype uint16, result *ValidationResult) error {
	// Extract RRset to verify
	rrset := extractRRset(msg, qname, qtype)
	if len(rrset) == 0 {
		return fmt.Errorf("no RRset found to verify")
	}

	// Verify each signature
	for _, rrsig := range result.Signatures {
		// Reject signatures made with disabled algorithms (RFC 8624
		// MUST-NOT-validate set, e.g. RSAMD5/DSA). Consulted here so a
		// bogus algorithm is rejected regardless of the DNSKEY path.
		if v.config.DisabledAlgorithms[rrsig.Algorithm] {
			return fmt.Errorf("RRSIG uses disabled algorithm %d (keytag=%d)", rrsig.Algorithm, rrsig.KeyTag)
		}

		// Check signature validity period.
		// dns.RRSIG.Inception and Expiration are uint32 Unix timestamps.
		inception := time.Unix(int64(rrsig.Inception), 0)
		expiration := time.Unix(int64(rrsig.Expiration), 0)
		now := time.Now()
		if now.Before(inception) || now.After(expiration) {
			return fmt.Errorf("signature outside validity period")
		}

		// Update result validity times
		if result.ValidFrom.IsZero() || inception.Before(result.ValidFrom) {
			result.ValidFrom = inception
		}
		if result.ValidUntil.IsZero() || expiration.After(result.ValidUntil) {
			result.ValidUntil = expiration
		}

		// Find matching DNSKEY
		dnskey := findDNSKEY(result.DNSKEYs, rrsig.SignerName, rrsig.KeyTag)
		if dnskey == nil {
			return fmt.Errorf("no DNSKEY found for RRSIG (keytag=%d)", rrsig.KeyTag)
		}

		// Verify signature (using miekg/dns)
		if err := rrsig.Verify(dnskey, rrset); err != nil {
			return fmt.Errorf("signature verification failed: %w", err)
		}
	}

	return nil
}

// queryDS queries for DS records at parent zone
func (v *Validator) queryDS(ctx context.Context, zone string, parent string) ([]dns.DS, error) {
	msg, err := v.resolver.Query(ctx, zone, dns.TypeDS)
	if err != nil {
		return nil, err
	}

	dsRecords := make([]dns.DS, 0)
	for _, rr := range msg.Answer {
		if ds, ok := rr.(*dns.DS); ok {
			dsRecords = append(dsRecords, *ds)
		}
	}

	return dsRecords, nil
}

// queryDNSKEY queries for DNSKEY records
func (v *Validator) queryDNSKEY(ctx context.Context, zone string) ([]dns.DNSKEY, error) {
	msg, err := v.resolver.Query(ctx, zone, dns.TypeDNSKEY)
	if err != nil {
		return nil, err
	}

	dnskeys := make([]dns.DNSKEY, 0)
	for _, rr := range msg.Answer {
		if key, ok := rr.(*dns.DNSKEY); ok {
			// Check if algorithm is disabled
			if v.config.DisabledAlgorithms[key.Algorithm] {
				continue
			}
			dnskeys = append(dnskeys, *key)
		}
	}

	return dnskeys, nil
}

// isNegativeTrustAnchor checks if a domain is in negative trust anchors
func (v *Validator) isNegativeTrustAnchor(qname string) bool {
	qname = dns.Fqdn(strings.ToLower(qname))

	// Check exact match and parent zones
	labels := dns.SplitDomainName(qname)
	for i := 0; i < len(labels); i++ {
		zone := dns.Fqdn(strings.Join(labels[i:], "."))
		if v.negativeTrustAnchors[zone] {
			return true
		}
	}

	return false
}

// Helper functions

func hasDNSSECRecords(msg *dns.Msg) bool {
	for _, rr := range msg.Answer {
		if rr.Header().Rrtype == dns.TypeRRSIG {
			return true
		}
	}
	for _, rr := range msg.Ns {
		if rr.Header().Rrtype == dns.TypeRRSIG || rr.Header().Rrtype == dns.TypeDS {
			return true
		}
	}
	return false
}

// nsec3IterationsOverCap reports whether any NSEC3 record in the message uses
// an iteration count greater than the supplied maximum. It scans both the
// answer and authority sections. Returns the offending iteration count and
// true when the cap is exceeded.
func nsec3IterationsOverCap(msg *dns.Msg, maxIterations uint16) (uint16, bool) {
	sections := [][]dns.RR{msg.Answer, msg.Ns}
	for _, section := range sections {
		for _, rr := range section {
			if nsec3, ok := rr.(*dns.NSEC3); ok {
				if nsec3.Iterations > maxIterations {
					return nsec3.Iterations, true
				}
			}
		}
	}
	return 0, false
}

func extractRRSIGs(msg *dns.Msg, qname string, qtype uint16) []dns.RRSIG {
	rrsigs := make([]dns.RRSIG, 0)

	for _, rr := range msg.Answer {
		if rrsig, ok := rr.(*dns.RRSIG); ok {
			if rrsig.TypeCovered == qtype && strings.EqualFold(rrsig.Header().Name, qname) {
				rrsigs = append(rrsigs, *rrsig)
			}
		}
	}

	return rrsigs
}

func extractRRset(msg *dns.Msg, qname string, qtype uint16) []dns.RR {
	rrset := make([]dns.RR, 0)

	for _, rr := range msg.Answer {
		if rr.Header().Rrtype == qtype && strings.EqualFold(rr.Header().Name, qname) {
			rrset = append(rrset, rr)
		}
	}

	return rrset
}

func findDNSKEY(dnskeys []dns.DNSKEY, signerName string, keyTag uint16) *dns.DNSKEY {
	for i := range dnskeys {
		key := &dnskeys[i]
		if strings.EqualFold(key.Header().Name, signerName) && key.KeyTag() == keyTag {
			return key
		}
	}
	return nil
}

func extractDNSKEYs(msg *dns.Msg, owner string, disabled map[uint8]bool) []dns.DNSKEY {
	owner = dns.Fqdn(strings.ToLower(owner))
	var keys []dns.DNSKEY
	for _, rr := range msg.Answer {
		key, ok := rr.(*dns.DNSKEY)
		if ok && strings.EqualFold(key.Hdr.Name, owner) && !disabled[key.Algorithm] {
			keys = append(keys, *key)
		}
	}
	return keys
}

func extractDSRecords(msg *dns.Msg, owner string) []dns.DS {
	owner = dns.Fqdn(strings.ToLower(owner))
	var records []dns.DS
	for _, section := range [][]dns.RR{msg.Answer, msg.Ns} {
		for _, rr := range section {
			ds, ok := rr.(*dns.DS)
			if ok && strings.EqualFold(ds.Hdr.Name, owner) {
				records = append(records, *ds)
			}
		}
	}
	return records
}

func extractSignaturesFor(msg *dns.Msg, owner string, covered uint16) []dns.RRSIG {
	owner = dns.Fqdn(strings.ToLower(owner))
	var signatures []dns.RRSIG
	for _, section := range [][]dns.RR{msg.Answer, msg.Ns} {
		for _, rr := range section {
			sig, ok := rr.(*dns.RRSIG)
			if ok && sig.TypeCovered == covered && strings.EqualFold(sig.Hdr.Name, owner) {
				signatures = append(signatures, *sig)
			}
		}
	}
	return signatures
}

func matchingTrustAnchor(anchors, keys []dns.DNSKEY) *dns.DNSKEY {
	for i := range anchors {
		for j := range keys {
			if strings.EqualFold(anchors[i].Hdr.Name, keys[j].Hdr.Name) &&
				anchors[i].KeyTag() == keys[j].KeyTag() && anchors[i].Algorithm == keys[j].Algorithm &&
				anchors[i].PublicKey == keys[j].PublicKey {
				return &keys[j]
			}
		}
	}
	return nil
}

func matchDSKeys(dsRecords []dns.DS, keys []dns.DNSKEY) []dns.DNSKEY {
	seen := make(map[uint16]bool)
	var matched []dns.DNSKEY
	for _, key := range keys {
		for _, ds := range dsRecords {
			if ds.KeyTag != key.KeyTag() || ds.Algorithm != key.Algorithm {
				continue
			}
			computed := key.ToDS(ds.DigestType)
			if computed != nil && strings.EqualFold(computed.Digest, ds.Digest) && !seen[key.KeyTag()] {
				matched = append(matched, key)
				seen[key.KeyTag()] = true
			}
		}
	}
	return matched
}

func verifyRRSetWithKeys(rrset []dns.RR, signatures []dns.RRSIG, keys []dns.DNSKEY, disabled map[uint8]bool) error {
	if len(rrset) == 0 || len(signatures) == 0 || len(keys) == 0 {
		return fmt.Errorf("missing RRset, signature, or key")
	}
	now := time.Now()
	var lastErr error
	for i := range signatures {
		sig := &signatures[i]
		if disabled[sig.Algorithm] || now.Before(time.Unix(int64(sig.Inception), 0)) || now.After(time.Unix(int64(sig.Expiration), 0)) {
			continue
		}
		for j := range keys {
			key := &keys[j]
			if key.KeyTag() != sig.KeyTag || key.Algorithm != sig.Algorithm || !strings.EqualFold(key.Hdr.Name, sig.SignerName) {
				continue
			}
			if err := sig.Verify(key, rrset); err == nil {
				return nil
			} else {
				lastErr = err
			}
		}
	}
	if lastErr != nil {
		return lastErr
	}
	return fmt.Errorf("no valid signature from an authenticated key")
}

func dnskeysToRRs(keys []dns.DNSKEY) []dns.RR {
	records := make([]dns.RR, len(keys))
	for i := range keys {
		records[i] = &keys[i]
	}
	return records
}

func dsToRRs(dsRecords []dns.DS) []dns.RR {
	records := make([]dns.RR, len(dsRecords))
	for i := range dsRecords {
		records[i] = &dsRecords[i]
	}
	return records
}
