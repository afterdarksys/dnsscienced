package dnssec

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// stubResolver returns empty responses for any query. Used so buildTrustChain
// completes without network access.
type stubResolver struct{}

func (stubResolver) Query(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	return &dns.Msg{}, nil
}

const testQname = "example.com."

func testARecord() *dns.A {
	return &dns.A{
		Hdr: dns.RR_Header{Name: testQname, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP("192.0.2.1"),
	}
}

func testRRSIG(algorithm uint8) *dns.RRSIG {
	now := time.Now()
	return &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: testQname, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 300},
		TypeCovered: dns.TypeA,
		Algorithm:   algorithm,
		Labels:      2,
		OrigTtl:     300,
		Expiration:  uint32(now.Add(24 * time.Hour).Unix()),
		Inception:   uint32(now.Add(-1 * time.Hour).Unix()),
		KeyTag:      12345,
		SignerName:  testQname,
		Signature:   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	}
}

// TestValidate_NoTrustAnchor_NeverSecure proves the fail-closed AD behavior:
// with no configured trust anchors the validator must never mark a response
// Secure (never assert AD=1), even when the response carries signatures that
// would "verify" against attacker-supplied wire keys.
func TestValidate_NoTrustAnchor_NeverSecure(t *testing.T) {
	v, err := NewValidator(DefaultValidatorConfig(), stubResolver{})
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}
	if len(v.trustAnchors) != 0 {
		t.Fatalf("expected zero default trust anchors, got %d", len(v.trustAnchors))
	}

	msg := &dns.Msg{}
	// Use an otherwise-enabled algorithm so nothing but the missing anchor
	// prevents a Secure result.
	msg.Answer = []dns.RR{testARecord(), testRRSIG(dns.RSASHA256)}

	result, err := v.Validate(context.Background(), msg, testQname, dns.TypeA)
	if err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}
	if result.Secure {
		t.Fatalf("result must NOT be Secure without a trust anchor (AD would be asserted)")
	}
	if !result.Indeterminate {
		t.Fatalf("expected Indeterminate result without trust anchors, got %+v", result)
	}
}

// TestValidate_NSEC3IterationsOverCap enforces the RFC 9276 iteration cap: an
// NSEC3 record above NSEC3MaxIterations must make the response bogus without
// performing the hashing.
func TestValidate_NSEC3IterationsOverCap(t *testing.T) {
	cfg := DefaultValidatorConfig()
	v, err := NewValidator(cfg, stubResolver{})
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}

	nsec3 := &dns.NSEC3{
		Hdr:        dns.RR_Header{Name: testQname, Rrtype: dns.TypeNSEC3, Class: dns.ClassINET, Ttl: 300},
		Hash:       dns.SHA1,
		Flags:      0,
		Iterations: cfg.NSEC3MaxIterations + 50, // above the cap
		SaltLength: 0,
		Salt:       "",
		HashLength: 20,
		NextDomain: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	}

	msg := &dns.Msg{}
	msg.Ns = []dns.RR{nsec3}

	result, err := v.Validate(context.Background(), msg, testQname, dns.TypeA)
	if err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}
	if result.Secure {
		t.Fatalf("NSEC3 over iteration cap must not be Secure")
	}
	if !result.Bogus {
		t.Fatalf("expected Bogus result for NSEC3 over cap, got %+v", result)
	}
}

// TestValidate_RSAMD5Rejected proves the RFC 8624 algorithm allowlist is
// consulted during signature validation: an RSAMD5-signed RRSIG is rejected.
func TestValidate_RSAMD5Rejected(t *testing.T) {
	v, err := NewValidator(DefaultValidatorConfig(), stubResolver{})
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}
	// Provide a trust anchor so the fail-closed guard does not short-circuit
	// before signature validation is reached.
	v.AddTrustAnchor(dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: ".", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.RSASHA256,
	})

	msg := &dns.Msg{}
	msg.Answer = []dns.RR{testARecord(), testRRSIG(dns.RSAMD5)}

	result, err := v.Validate(context.Background(), msg, testQname, dns.TypeA)
	if err == nil {
		t.Fatalf("expected error rejecting RSAMD5 RRSIG, got nil")
	}
	if result.Secure {
		t.Fatalf("RSAMD5-signed response must not be Secure")
	}
	if !result.Bogus {
		t.Fatalf("expected Bogus result for RSAMD5 RRSIG, got %+v", result)
	}
}

// TestDefaultConfig_DisabledAlgorithms verifies the RFC 8624 MUST-NOT set is
// disabled by default while RSASHA1 remains enabled.
func TestDefaultConfig_DisabledAlgorithms(t *testing.T) {
	cfg := DefaultValidatorConfig()
	for _, alg := range []uint8{dns.RSAMD5, dns.DSA, dns.DSANSEC3SHA1} {
		if !cfg.DisabledAlgorithms[alg] {
			t.Errorf("algorithm %d should be disabled by default", alg)
		}
	}
	for _, alg := range []uint8{dns.RSASHA1, dns.RSASHA1NSEC3SHA1} {
		if cfg.DisabledAlgorithms[alg] {
			t.Errorf("algorithm %d (RSASHA1 family) must NOT be disabled", alg)
		}
	}
}

// TestCacheKey_DecimalQtype guards the generateKey/CacheKey fix: qtype must be
// rendered as decimal digits, not a rune conversion.
func TestCacheKey_DecimalQtype(t *testing.T) {
	if got := CacheKey("example.com.", dns.TypeA); got != "example.com.:1" {
		t.Fatalf("CacheKey(A) = %q, want %q", got, "example.com.:1")
	}
	if got := CacheKey("example.com.", dns.TypeAAAA); got != "example.com.:28" {
		t.Fatalf("CacheKey(AAAA) = %q, want %q", got, "example.com.:28")
	}
}
