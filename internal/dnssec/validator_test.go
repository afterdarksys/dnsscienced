package dnssec

import (
	"context"
	"crypto"
	"net"
	"os"
	"path/filepath"
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

type mapResolver map[string]*dns.Msg

func (r mapResolver) Query(_ context.Context, name string, qtype uint16) (*dns.Msg, error) {
	msg := r[dns.Fqdn(name)+":"+dns.TypeToString[qtype]]
	if msg == nil {
		return new(dns.Msg), nil
	}
	return msg.Copy(), nil
}

func generatedDNSKEY(t *testing.T, owner string) (dns.DNSKEY, crypto.Signer) {
	t.Helper()
	key := dns.DNSKEY{Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300}, Flags: 257, Protocol: 3, Algorithm: dns.ECDSAP256SHA256}
	private, err := key.Generate(256)
	if err != nil {
		t.Fatalf("Generate(%s): %v", owner, err)
	}
	signer, ok := private.(crypto.Signer)
	if !ok {
		t.Fatalf("generated private key %T is not crypto.Signer", private)
	}
	return key, signer
}

func signedRRSet(t *testing.T, rrset []dns.RR, signer string, key dns.DNSKEY, private crypto.Signer) *dns.RRSIG {
	t.Helper()
	hdr := rrset[0].Header()
	now := time.Now()
	sig := &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: hdr.Name, Rrtype: dns.TypeRRSIG, Class: hdr.Class, Ttl: hdr.Ttl},
		TypeCovered: hdr.Rrtype, Algorithm: key.Algorithm, Labels: uint8(dns.CountLabel(hdr.Name)), OrigTtl: hdr.Ttl,
		Expiration: uint32(now.Add(time.Hour).Unix()), Inception: uint32(now.Add(-time.Minute).Unix()),
		KeyTag: key.KeyTag(), SignerName: signer,
	}
	if err := sig.Sign(private, rrset); err != nil {
		t.Fatalf("Sign(%s/%s): %v", hdr.Name, dns.TypeToString[hdr.Rrtype], err)
	}
	return sig
}

func TestValidateAuthenticatesDSDNSKEYChain(t *testing.T) {
	rootKey, rootPrivate := generatedDNSKEY(t, ".")
	comKey, comPrivate := generatedDNSKEY(t, "com.")
	exampleKey, examplePrivate := generatedDNSKEY(t, "example.com.")

	rootRRs := []dns.RR{&rootKey}
	rootMsg := &dns.Msg{Answer: append(rootRRs, signedRRSet(t, rootRRs, ".", rootKey, rootPrivate))}
	comDS := comKey.ToDS(dns.SHA256)
	comDSRRs := []dns.RR{comDS}
	comDSMsg := &dns.Msg{Answer: append(comDSRRs, signedRRSet(t, comDSRRs, ".", rootKey, rootPrivate))}
	comKeyRRs := []dns.RR{&comKey}
	comKeyMsg := &dns.Msg{Answer: append(comKeyRRs, signedRRSet(t, comKeyRRs, "com.", comKey, comPrivate))}
	exampleDS := exampleKey.ToDS(dns.SHA256)
	exampleDSRRs := []dns.RR{exampleDS}
	exampleDSMsg := &dns.Msg{Answer: append(exampleDSRRs, signedRRSet(t, exampleDSRRs, "com.", comKey, comPrivate))}
	exampleKeyRRs := []dns.RR{&exampleKey}
	exampleKeyMsg := &dns.Msg{Answer: append(exampleKeyRRs, signedRRSet(t, exampleKeyRRs, "example.com.", exampleKey, examplePrivate))}

	resolver := mapResolver{
		".:DNSKEY":            rootMsg,
		"com.:DS":             comDSMsg,
		"com.:DNSKEY":         comKeyMsg,
		"example.com.:DS":     exampleDSMsg,
		"example.com.:DNSKEY": exampleKeyMsg,
	}
	v, err := NewValidator(DefaultValidatorConfig(), resolver)
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}
	v.AddTrustAnchor(rootKey)
	leaf := testARecord()
	leafRRs := []dns.RR{leaf}
	msg := &dns.Msg{Answer: append(leafRRs, signedRRSet(t, leafRRs, "example.com.", exampleKey, examplePrivate))}
	result, err := v.Validate(context.Background(), msg, testQname, dns.TypeA)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !result.Secure || result.Bogus || result.ChainDepth != 3 {
		t.Fatalf("result=%+v, want authenticated three-zone chain", result)
	}
}

func authenticatedExampleValidator(t *testing.T) (*Validator, dns.DNSKEY, crypto.Signer) {
	t.Helper()
	rootKey, rootPrivate := generatedDNSKEY(t, ".")
	exampleKey, examplePrivate := generatedDNSKEY(t, "example.")
	rootRRs := []dns.RR{&rootKey}
	exampleDS := exampleKey.ToDS(dns.SHA256)
	exampleDSRRs := []dns.RR{exampleDS}
	exampleKeyRRs := []dns.RR{&exampleKey}
	resolver := mapResolver{
		".:DNSKEY":        {Answer: append(rootRRs, signedRRSet(t, rootRRs, ".", rootKey, rootPrivate))},
		"example.:DS":     {Answer: append(exampleDSRRs, signedRRSet(t, exampleDSRRs, ".", rootKey, rootPrivate))},
		"example.:DNSKEY": {Answer: append(exampleKeyRRs, signedRRSet(t, exampleKeyRRs, "example.", exampleKey, examplePrivate))},
	}
	v, err := NewValidator(DefaultValidatorConfig(), resolver)
	if err != nil {
		t.Fatal(err)
	}
	v.AddTrustAnchor(rootKey)
	return v, exampleKey, examplePrivate
}

func TestValidateAuthenticatesNXDOMAINNSECProof(t *testing.T) {
	v, key, private := authenticatedExampleValidator(t)
	soa := &dns.SOA{Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300}, Ns: "ns.example.", Mbox: "hostmaster.example.", Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minttl: 300}
	nsec := &dns.NSEC{Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300}, NextDomain: "example.", TypeBitMap: []uint16{dns.TypeSOA, dns.TypeNS, dns.TypeNSEC, dns.TypeRRSIG}}
	soaSet, nsecSet := []dns.RR{soa}, []dns.RR{nsec}
	msg := &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeNameError}}
	msg.Ns = []dns.RR{soa, signedRRSet(t, soaSet, "example.", key, private), nsec, signedRRSet(t, nsecSet, "example.", key, private)}

	result, err := v.Validate(context.Background(), msg, "missing.example.", dns.TypeA)
	if err != nil || !result.Secure || result.Bogus {
		t.Fatalf("Validate result=%+v err=%v, want Secure NXDOMAIN", result, err)
	}

	// A denial record modified after signing must fail cryptographic validation.
	tampered := msg.Copy()
	tampered.Ns[2].(*dns.NSEC).NextDomain = "z.example."
	result, err = v.Validate(context.Background(), tampered, "missing.example.", dns.TypeA)
	if err == nil || !result.Bogus || result.Secure {
		t.Fatalf("tampered result=%+v err=%v, want Bogus", result, err)
	}
}

func TestNSECAndNSEC3NODATAProofsRequireMissingType(t *testing.T) {
	nsec := &dns.NSEC{Hdr: dns.RR_Header{Name: "www.example.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET}, NextDomain: "z.example.", TypeBitMap: []uint16{dns.TypeA, dns.TypeRRSIG}}
	if err := validateNSECProof(dns.RcodeSuccess, []*dns.NSEC{nsec}, "www.example.", dns.TypeAAAA); err != nil {
		t.Fatalf("valid NSEC NODATA: %v", err)
	}
	if err := validateNSECProof(dns.RcodeSuccess, []*dns.NSEC{nsec}, "www.example.", dns.TypeA); err == nil {
		t.Fatal("NSEC bitmap containing queried type accepted as NODATA")
	}

	hash := dns.HashName("www.example.", dns.SHA1, 0, "")
	nsec3 := &dns.NSEC3{Hdr: dns.RR_Header{Name: hash + ".example.", Rrtype: dns.TypeNSEC3, Class: dns.ClassINET}, Hash: dns.SHA1, Iterations: 0, Salt: "", NextDomain: hash, TypeBitMap: []uint16{dns.TypeA, dns.TypeRRSIG}}
	if err := validateNSEC3Proof(dns.RcodeSuccess, []*dns.NSEC3{nsec3}, "www.example.", dns.TypeAAAA); err != nil {
		t.Fatalf("valid NSEC3 NODATA: %v", err)
	}
	if err := validateNSEC3Proof(dns.RcodeSuccess, []*dns.NSEC3{nsec3}, "www.example.", dns.TypeA); err == nil {
		t.Fatal("NSEC3 bitmap containing queried type accepted as NODATA")
	}
}

func TestNSEC3NXDOMAINRequiresClosestEncloserAndWildcardProof(t *testing.T) {
	hash := dns.HashName("example.", dns.SHA1, 0, "")
	nsec3 := &dns.NSEC3{Hdr: dns.RR_Header{Name: hash + ".example.", Rrtype: dns.TypeNSEC3, Class: dns.ClassINET}, Hash: dns.SHA1, NextDomain: hash, TypeBitMap: []uint16{dns.TypeSOA, dns.TypeNS}}
	if err := validateNSEC3Proof(dns.RcodeNameError, []*dns.NSEC3{nsec3}, "missing.example.", dns.TypeA); err != nil {
		t.Fatalf("valid NSEC3 NXDOMAIN: %v", err)
	}
	if err := validateNSEC3Proof(dns.RcodeNameError, []*dns.NSEC3{nsec3}, "missing.other.", dns.TypeA); err == nil {
		t.Fatal("out-of-zone NSEC3 proof accepted")
	}
}

func TestLoadTrustAnchorsFromFile(t *testing.T) {
	key := dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: ".", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
	}
	if _, err := key.Generate(256); err != nil {
		t.Fatalf("Generate DNSKEY: %v", err)
	}
	path := filepath.Join(t.TempDir(), "anchors.conf")
	if err := os.WriteFile(path, []byte("; root anchor\n"+key.String()+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	v, err := NewValidator(DefaultValidatorConfig(), stubResolver{})
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}
	if err := v.LoadTrustAnchorsFromFile(path); err != nil {
		t.Fatalf("LoadTrustAnchorsFromFile: %v", err)
	}
	if len(v.trustAnchors) != 1 || v.trustAnchors[0].KeyTag() != key.KeyTag() {
		t.Fatalf("anchors=%v, want generated key", v.trustAnchors)
	}
}

func TestMatchDSKeysRejectsUnrelatedDNSKEY(t *testing.T) {
	trusted := dns.DNSKEY{Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET}, Flags: 257, Protocol: 3, Algorithm: dns.ECDSAP256SHA256}
	if _, err := trusted.Generate(256); err != nil {
		t.Fatalf("Generate trusted key: %v", err)
	}
	attacker := dns.DNSKEY{Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET}, Flags: 257, Protocol: 3, Algorithm: dns.ECDSAP256SHA256}
	if _, err := attacker.Generate(256); err != nil {
		t.Fatalf("Generate attacker key: %v", err)
	}
	ds := trusted.ToDS(dns.SHA256)
	if got := matchDSKeys([]dns.DS{*ds}, []dns.DNSKEY{attacker}); len(got) != 0 {
		t.Fatalf("attacker key matched authenticated DS: %v", got)
	}
	if got := matchDSKeys([]dns.DS{*ds}, []dns.DNSKEY{trusted}); len(got) != 1 {
		t.Fatalf("trusted key did not match DS: %v", got)
	}
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
