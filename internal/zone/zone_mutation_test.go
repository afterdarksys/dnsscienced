package zone

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

// mutationTestZone creates a zone with known records for predictable assertions.
// Owners: example.com. (SOA, NS, MX), host.example.com. (A, AAAA), mail.example.com. (A)
func mutationTestZone() *Zone {
	z := New("example.com.")

	// SOA
	soa := &dns.SOA{
		Hdr:     dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
		Ns:      "ns1.example.com.",
		Mbox:    "admin.example.com.",
		Serial:  2024010101,
		Refresh: 3600, Retry: 900, Expire: 604800, Minttl: 86400,
	}
	_ = z.AddRecord(soa)

	// NS at apex
	ns := &dns.NS{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600},
		Ns:  "ns1.example.com.",
	}
	_ = z.AddRecord(ns)

	// MX at apex
	mx := &dns.MX{
		Hdr:        dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 3600},
		Preference: 10,
		Mx:         "mail.example.com.",
	}
	_ = z.AddRecord(mx)

	// A at host.example.com.
	a1 := &dns.A{
		Hdr: dns.RR_Header{Name: "host.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP("192.0.2.1"),
	}
	_ = z.AddRecord(a1)

	// Second A at host.example.com. (for rrset deletion test)
	a2 := &dns.A{
		Hdr: dns.RR_Header{Name: "host.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP("192.0.2.2"),
	}
	_ = z.AddRecord(a2)

	// AAAA at host.example.com. (should survive A rrset deletion)
	aaaa := &dns.AAAA{
		Hdr:  dns.RR_Header{Name: "host.example.com.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
		AAAA: net.ParseIP("2001:db8::1"),
	}
	_ = z.AddRecord(aaaa)

	// A at mail.example.com. (should survive host.example.com. DeleteName)
	mailA := &dns.A{
		Hdr: dns.RR_Header{Name: "mail.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP("192.0.2.10"),
	}
	_ = z.AddRecord(mailA)

	return z
}

// TestDeleteRecord_ExactMatch verifies DeleteRecord removes the matched RR and GetRecords returns empty after.
func TestDeleteRecord_ExactMatch(t *testing.T) {
	z := mutationTestZone()

	// Verify initial state: 2 A records at host.example.com.
	before := z.GetRecords("host.example.com.", dns.TypeA)
	if len(before) != 2 {
		t.Fatalf("expected 2 A records before delete, got %d", len(before))
	}

	// Delete first A record (192.0.2.1) — re-build to get a matching RR
	target := &dns.A{
		Hdr: dns.RR_Header{Name: "host.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP("192.0.2.1"),
	}
	if err := z.DeleteRecord(target); err != nil {
		t.Fatalf("DeleteRecord returned error: %v", err)
	}

	after := z.GetRecords("host.example.com.", dns.TypeA)
	if len(after) != 1 {
		t.Fatalf("expected 1 A record after delete, got %d", len(after))
	}
	if after[0].(*dns.A).A.String() != "192.0.2.2" {
		t.Errorf("expected remaining A record 192.0.2.2, got %s", after[0].(*dns.A).A)
	}
}

// TestDeleteRecord_RemovesLastRecord verifies that when the last RR in an rrset is deleted,
// the rrset entry is cleaned up from the map.
func TestDeleteRecord_RemovesLastRecord(t *testing.T) {
	z := mutationTestZone()

	// Delete both A records
	a1 := &dns.A{
		Hdr: dns.RR_Header{Name: "host.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP("192.0.2.1"),
	}
	a2 := &dns.A{
		Hdr: dns.RR_Header{Name: "host.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP("192.0.2.2"),
	}

	if err := z.DeleteRecord(a1); err != nil {
		t.Fatalf("DeleteRecord(a1) error: %v", err)
	}
	if err := z.DeleteRecord(a2); err != nil {
		t.Fatalf("DeleteRecord(a2) error: %v", err)
	}

	after := z.GetRecords("host.example.com.", dns.TypeA)
	if len(after) != 0 {
		t.Errorf("expected 0 A records after deleting all, got %d", len(after))
	}

	// AAAA should still be present at host.example.com.
	aaaa := z.GetRecords("host.example.com.", dns.TypeAAAA)
	if len(aaaa) != 1 {
		t.Errorf("expected AAAA record to survive A deletion, got %d", len(aaaa))
	}
}

// TestDeleteRecord_NoOp verifies that deleting a non-existent record returns nil.
func TestDeleteRecord_NoOp(t *testing.T) {
	z := mutationTestZone()

	nonexistent := &dns.A{
		Hdr: dns.RR_Header{Name: "nosuchhost.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP("10.0.0.1"),
	}
	if err := z.DeleteRecord(nonexistent); err != nil {
		t.Errorf("DeleteRecord no-op should return nil, got: %v", err)
	}

	// Also test deleting a record that doesn't match any existing RR at an existing owner
	wrongIP := &dns.A{
		Hdr: dns.RR_Header{Name: "host.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP("10.99.99.99"),
	}
	if err := z.DeleteRecord(wrongIP); err != nil {
		t.Errorf("DeleteRecord mis-match no-op should return nil, got: %v", err)
	}

	// Records should be unchanged
	after := z.GetRecords("host.example.com.", dns.TypeA)
	if len(after) != 2 {
		t.Errorf("expected 2 A records unchanged, got %d", len(after))
	}
}

// TestDeleteRecord_NilRR verifies that passing nil returns an error.
func TestDeleteRecord_NilRR(t *testing.T) {
	z := mutationTestZone()
	if err := z.DeleteRecord(nil); err == nil {
		t.Error("expected error for nil RR, got nil")
	}
}

// TestDeleteRecord_NormalizesOwner verifies case-insensitive owner matching.
func TestDeleteRecord_NormalizesOwner(t *testing.T) {
	z := mutationTestZone()

	// Delete using mixed-case owner — should still match
	target := &dns.A{
		Hdr: dns.RR_Header{Name: "HOST.EXAMPLE.COM.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP("192.0.2.1"),
	}
	if err := z.DeleteRecord(target); err != nil {
		t.Fatalf("DeleteRecord with uppercase owner error: %v", err)
	}

	after := z.GetRecords("host.example.com.", dns.TypeA)
	if len(after) != 1 {
		t.Errorf("expected 1 A record after case-normalized delete, got %d", len(after))
	}
}

// TestDeleteRRSet_RemovesAllOfType verifies DeleteRRSet removes all A records while leaving AAAA.
func TestDeleteRRSet_RemovesAllOfType(t *testing.T) {
	z := mutationTestZone()

	if err := z.DeleteRRSet("host.example.com.", dns.TypeA); err != nil {
		t.Fatalf("DeleteRRSet error: %v", err)
	}

	// All A records gone
	aRecords := z.GetRecords("host.example.com.", dns.TypeA)
	if len(aRecords) != 0 {
		t.Errorf("expected 0 A records after DeleteRRSet, got %d", len(aRecords))
	}

	// AAAA should still exist
	aaaaRecords := z.GetRecords("host.example.com.", dns.TypeAAAA)
	if len(aaaaRecords) != 1 {
		t.Errorf("expected 1 AAAA record to survive DeleteRRSet(TypeA), got %d", len(aaaaRecords))
	}
}

// TestDeleteRRSet_NoOp verifies DeleteRRSet on a non-existent rrset returns nil.
func TestDeleteRRSet_NoOp(t *testing.T) {
	z := mutationTestZone()

	// Non-existent owner
	if err := z.DeleteRRSet("nosuchhost.example.com.", dns.TypeA); err != nil {
		t.Errorf("DeleteRRSet non-existent owner should return nil, got: %v", err)
	}

	// Existing owner but non-existent type
	if err := z.DeleteRRSet("host.example.com.", dns.TypeMX); err != nil {
		t.Errorf("DeleteRRSet non-existent type should return nil, got: %v", err)
	}
}

// TestDeleteRRSet_NormalizesOwner verifies case-insensitive owner handling.
func TestDeleteRRSet_NormalizesOwner(t *testing.T) {
	z := mutationTestZone()

	if err := z.DeleteRRSet("HOST.EXAMPLE.COM.", dns.TypeA); err != nil {
		t.Fatalf("DeleteRRSet uppercase owner error: %v", err)
	}

	aRecords := z.GetRecords("host.example.com.", dns.TypeA)
	if len(aRecords) != 0 {
		t.Errorf("expected 0 A records after case-normalized DeleteRRSet, got %d", len(aRecords))
	}
}

// TestDeleteName_RemovesAllRRSets verifies DeleteName removes all rrsets at the given owner.
func TestDeleteName_RemovesAllRRSets(t *testing.T) {
	z := mutationTestZone()

	if err := z.DeleteName("host.example.com."); err != nil {
		t.Fatalf("DeleteName error: %v", err)
	}

	// Both A and AAAA should be gone
	aRecords := z.GetRecords("host.example.com.", dns.TypeA)
	if len(aRecords) != 0 {
		t.Errorf("expected 0 A records after DeleteName, got %d", len(aRecords))
	}
	aaaaRecords := z.GetRecords("host.example.com.", dns.TypeAAAA)
	if len(aaaaRecords) != 0 {
		t.Errorf("expected 0 AAAA records after DeleteName, got %d", len(aaaaRecords))
	}

	// HasName should return false
	if z.HasName("host.example.com.") {
		t.Error("HasName should return false after DeleteName")
	}

	// mail.example.com. should still exist
	mailRecords := z.GetRecords("mail.example.com.", dns.TypeA)
	if len(mailRecords) != 1 {
		t.Errorf("expected 1 A record at mail.example.com. to survive DeleteName, got %d", len(mailRecords))
	}
}

// TestDeleteName_NoOp verifies DeleteName on a non-existent owner returns nil.
func TestDeleteName_NoOp(t *testing.T) {
	z := mutationTestZone()

	if err := z.DeleteName("nosuchhost.example.com."); err != nil {
		t.Errorf("DeleteName non-existent owner should return nil, got: %v", err)
	}
}

// TestDeleteName_NormalizesOwner verifies case-insensitive owner handling.
func TestDeleteName_NormalizesOwner(t *testing.T) {
	z := mutationTestZone()

	if err := z.DeleteName("HOST.EXAMPLE.COM."); err != nil {
		t.Fatalf("DeleteName uppercase owner error: %v", err)
	}

	if z.HasName("host.example.com.") {
		t.Error("HasName should return false after case-normalized DeleteName")
	}
}
