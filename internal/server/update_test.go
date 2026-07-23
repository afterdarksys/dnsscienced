package server

import (
	"encoding/base64"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/dnsscience/dnsscienced/internal/tsig"
	"github.com/dnsscience/dnsscienced/internal/zone"
	"github.com/miekg/dns"
)

func TestNewRejectsInvalidUpdateReplayCacheSize(t *testing.T) {
	cfg := DefaultConfig()
	cfg.UpdateReplayCacheSize = -1
	if _, err := New(cfg); err == nil {
		t.Fatal("New accepted a negative update_replay_cache_size")
	}
}

// testServerWithUpdate creates a minimal Server configured for UPDATE testing.
// allowUpdate is the CIDR list for example.com.; pass nil for no-entry,
// []string{} for empty-entry (deny-all, D-15), or real CIDRs.
func testServerWithUpdate(allowUpdate []string) (*Server, error) {
	zones := map[string]*zone.Zone{
		"example.com.": testZone(),
	}
	var updateCIDRs map[string][]string
	if allowUpdate != nil {
		updateCIDRs = map[string][]string{
			"example.com.": allowUpdate,
		}
	}
	cfg := Config{
		Zones:              zones,
		UDPListeners:       1,
		ZoneUpdateCIDRs:    updateCIDRs,
		ZoneUpdateTSIGKeys: map[string][]string{"example.com.": {"test."}},
		TsigKeys: []tsig.KeyConfig{{
			Name:      "test.",
			Algorithm: "hmac-sha256",
			Secret:    base64.StdEncoding.EncodeToString([]byte("update-test-secret")),
		}},
	}
	return New(cfg)
}

// makeUpdateMsg builds a proper RFC 2136 UPDATE message.
//
//	zone:      FQDN of the zone (Question[0].Name)
//	owner:     owner name for the records in the Update section
//	addRRs:    records to add (class = zone class = INET)
//	deleteRRs: records to delete (class = ClassNONE for specific-RR delete;
//	           set class/type manually before passing for other delete forms)
func makeUpdateMsg(zoneFQDN string, prereqs []dns.RR, updateRRs []dns.RR) *dns.Msg {
	m := new(dns.Msg)
	m.Opcode = dns.OpcodeUpdate
	m.RecursionDesired = false
	// Zone section (Question[0]): zone FQDN, TypeSOA, ClassINET
	m.Question = []dns.Question{
		{Name: zoneFQDN, Qtype: dns.TypeSOA, Qclass: dns.ClassINET},
	}
	// Prerequisite section (Answer)
	m.Answer = prereqs
	// Update section (Ns)
	m.Ns = updateRRs
	// Add a fake TSIG so r.IsTsig() != nil (presence check passes).
	// The test writer returns tsigStatus=nil (valid) by default.
	m.Extra = []dns.RR{
		&dns.TSIG{
			Hdr:        dns.RR_Header{Name: "test.", Rrtype: dns.TypeTSIG, Class: dns.ClassANY, Ttl: 0},
			Algorithm:  dns.HmacSHA256,
			TimeSigned: uint64(time.Now().Unix()),
			Fudge:      300,
			MACSize:    0,
		},
	}
	return m
}

// makeAddRR creates an A-record RR ready for the Update section (add = zone class).
func makeAddRR(owner, ip string) dns.RR {
	return &dns.A{
		Hdr: dns.RR_Header{
			Name:   owner,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		A: net.ParseIP(ip),
	}
}

func TestHandleUpdate_PrereqValueRequiresExactRRSet(t *testing.T) {
	s, err := testServerWithUpdate([]string{"0.0.0.0/0"})
	if err != nil {
		t.Fatalf("testServerWithUpdate: %v", err)
	}
	defer s.Stop() //nolint:errcheck

	add := []dns.RR{
		makeAddRR("multi.example.com.", "198.51.100.1"),
		makeAddRR("multi.example.com.", "198.51.100.2"),
	}
	w := newAXFRTestWriter("192.0.2.1")
	s.handleUpdate(w, makeUpdateMsg("example.com.", nil, add), net.ParseIP("192.0.2.1"))

	prereq := makeAddRR("multi.example.com.", "198.51.100.1")
	prereq.Header().Ttl = 0
	w2 := newAXFRTestWriter("192.0.2.1")
	s.handleUpdate(w2, makeUpdateMsg("example.com.", []dns.RR{prereq}, nil), net.ParseIP("192.0.2.1"))
	if len(w2.msgs) == 0 || w2.msgs[0].Rcode != dns.RcodeNXRrset {
		t.Fatalf("response=%v, want NXRRSET for subset prerequisite", w2.msgs)
	}
}

func TestHandleUpdate_DuplicateAdditionIsIgnored(t *testing.T) {
	s, err := testServerWithUpdate([]string{"0.0.0.0/0"})
	if err != nil {
		t.Fatalf("testServerWithUpdate: %v", err)
	}
	defer s.Stop() //nolint:errcheck

	rr := makeAddRR("duplicate.example.com.", "198.51.100.3")
	w := newAXFRTestWriter("192.0.2.1")
	s.handleUpdate(w, makeUpdateMsg("example.com.", nil, []dns.RR{rr, dns.Copy(rr)}), net.ParseIP("192.0.2.1"))
	got := s.cfg.Zones["example.com."].ExactRecords("duplicate.example.com.", dns.TypeA)
	if len(got) != 1 {
		t.Fatalf("duplicate RR count=%d, want 1", len(got))
	}
}

func TestHandleUpdate_RejectsMalformedZoneSection(t *testing.T) {
	s, err := testServerWithUpdate([]string{"0.0.0.0/0"})
	if err != nil {
		t.Fatalf("testServerWithUpdate: %v", err)
	}
	defer s.Stop() //nolint:errcheck
	r := makeUpdateMsg("example.com.", nil, nil)
	r.Question[0].Qtype = dns.TypeA
	w := newAXFRTestWriter("192.0.2.1")
	s.handleUpdate(w, r, net.ParseIP("192.0.2.1"))
	if len(w.msgs) == 0 || w.msgs[0].Rcode != dns.RcodeFormatError {
		t.Fatalf("response=%v, want FORMERR", w.msgs)
	}
}

func TestHandleUpdate_ResponseCarriesTSIG(t *testing.T) {
	s, err := testServerWithUpdate([]string{"0.0.0.0/0"})
	if err != nil {
		t.Fatalf("testServerWithUpdate: %v", err)
	}
	defer s.Stop() //nolint:errcheck
	w := newAXFRTestWriter("192.0.2.1")
	s.handleUpdate(w, makeUpdateMsg("example.com.", nil, nil), net.ParseIP("192.0.2.1"))
	if len(w.msgs) == 0 || w.msgs[0].IsTsig() == nil {
		t.Fatalf("response=%v, want TSIG-authenticated response", w.msgs)
	}
}

// makeDeleteRR creates an RR for the Update section to delete a specific record (ClassNONE).
func makeDeleteRR(owner, ip string) dns.RR {
	return &dns.A{
		Hdr: dns.RR_Header{
			Name:   owner,
			Rrtype: dns.TypeA,
			Class:  dns.ClassNONE,
			Ttl:    0,
		},
		A: net.ParseIP(ip),
	}
}

// makeDeleteRRSet creates an RR to delete an entire rrset (ClassANY, specific type).
func makeDeleteRRSet(owner string, rrtype uint16) dns.RR {
	return &dns.ANY{
		Hdr: dns.RR_Header{
			Name:   owner,
			Rrtype: rrtype,
			Class:  dns.ClassANY,
			Ttl:    0,
		},
	}
}

// makeDeleteName creates an RR to delete all records at a name (ClassANY, TypeANY).
func makeDeleteName(owner string) dns.RR {
	return &dns.ANY{
		Hdr: dns.RR_Header{
			Name:   owner,
			Rrtype: dns.TypeANY,
			Class:  dns.ClassANY,
			Ttl:    0,
		},
	}
}

// makePrereqNameInUse creates a name-in-use prereq (ClassANY, TypeANY).
func makePrereqNameInUse(owner string) dns.RR {
	return &dns.ANY{
		Hdr: dns.RR_Header{
			Name:   owner,
			Rrtype: dns.TypeANY,
			Class:  dns.ClassANY,
			Ttl:    0,
		},
	}
}

// makePrereqNameNotInUse creates a name-not-in-use prereq (ClassNONE, TypeANY).
func makePrereqNameNotInUse(owner string) dns.RR {
	return &dns.ANY{
		Hdr: dns.RR_Header{
			Name:   owner,
			Rrtype: dns.TypeANY,
			Class:  dns.ClassNONE,
			Ttl:    0,
		},
	}
}

// makePrereqRRSetExists creates an rrset-exists prereq (ClassANY, specific type).
func makePrereqRRSetExists(owner string, rrtype uint16) dns.RR {
	return &dns.ANY{
		Hdr: dns.RR_Header{
			Name:   owner,
			Rrtype: rrtype,
			Class:  dns.ClassANY,
			Ttl:    0,
		},
	}
}

// makePrereqRRSetNotExists creates an rrset-not-exists prereq (ClassNONE, specific type).
func makePrereqRRSetNotExists(owner string, rrtype uint16) dns.RR {
	return &dns.ANY{
		Hdr: dns.RR_Header{
			Name:   owner,
			Rrtype: rrtype,
			Class:  dns.ClassNONE,
			Ttl:    0,
		},
	}
}

// --- Tests ---

// TestHandleUpdate_NoTSIG_NotAuth verifies that an unsigned UPDATE returns NOTAUTH (DYNUP-02).
func TestHandleUpdate_NoTSIG_NotAuth(t *testing.T) {
	s, err := testServerWithUpdate([]string{"0.0.0.0/0"})
	if err != nil {
		t.Fatalf("testServerWithUpdate: %v", err)
	}
	defer s.Stop() //nolint:errcheck

	w := newAXFRTestWriter("192.0.2.1")
	r := makeUpdateMsg("example.com.", nil, nil)
	r.Extra = nil // Remove TSIG so r.IsTsig() == nil

	s.handleUpdate(w, r, net.ParseIP("192.0.2.1"))

	if len(w.msgs) == 0 {
		t.Fatal("no response written")
	}
	if w.msgs[0].Rcode != dns.RcodeNotAuth {
		t.Errorf("Rcode = %d, want %d (NOTAUTH)", w.msgs[0].Rcode, dns.RcodeNotAuth)
	}
}

// TestHandleUpdate_BadTSIG_NotAuth verifies that a bad TSIG returns NOTAUTH (DYNUP-02).
func TestHandleUpdate_BadTSIG_NotAuth(t *testing.T) {
	s, err := testServerWithUpdate([]string{"0.0.0.0/0"})
	if err != nil {
		t.Fatalf("testServerWithUpdate: %v", err)
	}
	defer s.Stop() //nolint:errcheck

	w := newAXFRTestWriter("192.0.2.1")
	w.tsigStatus = fmt.Errorf("bad sig") // simulate failed TSIG verification
	r := makeUpdateMsg("example.com.", nil, nil)
	// r.Extra has TSIG so r.IsTsig() != nil — only the validity check fails.

	s.handleUpdate(w, r, net.ParseIP("192.0.2.1"))

	if len(w.msgs) == 0 {
		t.Fatal("no response written")
	}
	if w.msgs[0].Rcode != dns.RcodeNotAuth {
		t.Errorf("Rcode = %d, want %d (NOTAUTH)", w.msgs[0].Rcode, dns.RcodeNotAuth)
	}
}

// TestHandleUpdate_UnknownZone_Refused verifies that an UPDATE for an unknown zone returns REFUSED.
func TestHandleUpdate_UnknownZone_Refused(t *testing.T) {
	s, err := testServerWithUpdate([]string{"0.0.0.0/0"})
	if err != nil {
		t.Fatalf("testServerWithUpdate: %v", err)
	}
	defer s.Stop() //nolint:errcheck

	w := newAXFRTestWriter("192.0.2.1")
	r := makeUpdateMsg("notfound.com.", nil, nil)

	s.handleUpdate(w, r, net.ParseIP("192.0.2.1"))

	if len(w.msgs) == 0 {
		t.Fatal("no response written")
	}
	if w.msgs[0].Rcode != dns.RcodeRefused {
		t.Errorf("Rcode = %d, want %d (REFUSED)", w.msgs[0].Rcode, dns.RcodeRefused)
	}
}

// TestHandleUpdate_EmptyAllowUpdate_Refused verifies that empty allow_update returns REFUSED (DYNUP-03, D-15).
func TestHandleUpdate_EmptyAllowUpdate_Refused(t *testing.T) {
	s, err := testServerWithUpdate([]string{}) // empty = deny all
	if err != nil {
		t.Fatalf("testServerWithUpdate: %v", err)
	}
	defer s.Stop() //nolint:errcheck

	w := newAXFRTestWriter("192.0.2.1")
	r := makeUpdateMsg("example.com.", nil, nil)

	s.handleUpdate(w, r, net.ParseIP("192.0.2.1"))

	if len(w.msgs) == 0 {
		t.Fatal("no response written")
	}
	if w.msgs[0].Rcode != dns.RcodeRefused {
		t.Errorf("Rcode = %d, want %d (REFUSED for empty allow_update)", w.msgs[0].Rcode, dns.RcodeRefused)
	}
}

// TestHandleUpdate_IPNotAllowed_Refused verifies that a disallowed IP returns REFUSED (DYNUP-03).
func TestHandleUpdate_IPNotAllowed_Refused(t *testing.T) {
	s, err := testServerWithUpdate([]string{"192.168.1.0/24"})
	if err != nil {
		t.Fatalf("testServerWithUpdate: %v", err)
	}
	defer s.Stop() //nolint:errcheck

	w := newAXFRTestWriter("10.0.0.1") // not in 192.168.1.0/24
	r := makeUpdateMsg("example.com.", nil, nil)

	s.handleUpdate(w, r, net.ParseIP("10.0.0.1"))

	if len(w.msgs) == 0 {
		t.Fatal("no response written")
	}
	if w.msgs[0].Rcode != dns.RcodeRefused {
		t.Errorf("Rcode = %d, want %d (REFUSED)", w.msgs[0].Rcode, dns.RcodeRefused)
	}
}

func TestHandleUpdate_KeyNotAuthorizedForZone_Refused(t *testing.T) {
	s, err := testServerWithUpdate([]string{"0.0.0.0/0"})
	if err != nil {
		t.Fatalf("testServerWithUpdate: %v", err)
	}
	defer s.Stop() //nolint:errcheck
	if err := s.tsigKeyRing.Add(tsig.KeyConfig{
		Name:      "other.",
		Algorithm: "hmac-sha256",
		Secret:    base64.StdEncoding.EncodeToString([]byte("other-test-secret")),
	}); err != nil {
		t.Fatal(err)
	}

	r := makeUpdateMsg("example.com.", nil, []dns.RR{
		makeAddRR("forbidden.example.com.", "192.0.2.44"),
	})
	r.IsTsig().Hdr.Name = "other."
	w := newAXFRTestWriter("192.0.2.1")
	s.handleUpdate(w, r, net.ParseIP("192.0.2.1"))

	if len(w.msgs) == 0 || w.msgs[0].Rcode != dns.RcodeRefused {
		t.Fatalf("response=%v, want REFUSED for a valid but unauthorized key", w.msgs)
	}
	if got := s.GetZone("example.com.").ExactRecords("forbidden.example.com.", dns.TypeA); len(got) != 0 {
		t.Fatalf("unauthorized update mutated zone: %v", got)
	}
}

func TestHandleUpdate_MissingZoneKeyPolicy_Refused(t *testing.T) {
	cfg := Config{
		Zones: map[string]*zone.Zone{"example.com.": testZone()},
		ZoneUpdateCIDRs: map[string][]string{
			"example.com.": {"0.0.0.0/0"},
		},
		TsigKeys: []tsig.KeyConfig{{
			Name:      "test.",
			Algorithm: "hmac-sha256",
			Secret:    base64.StdEncoding.EncodeToString([]byte("update-test-secret")),
		}},
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Stop() //nolint:errcheck

	w := newAXFRTestWriter("192.0.2.1")
	s.handleUpdate(w, makeUpdateMsg("example.com.", nil, nil), net.ParseIP("192.0.2.1"))
	if len(w.msgs) == 0 || w.msgs[0].Rcode != dns.RcodeRefused {
		t.Fatalf("response=%v, want REFUSED when update_tsig_keys is absent", w.msgs)
	}
}

func TestNewRejectsUndefinedZoneUpdateKey(t *testing.T) {
	_, err := New(Config{
		ZoneUpdateTSIGKeys: map[string][]string{
			"example.com.": {"missing."},
		},
	})
	if err == nil {
		t.Fatal("New accepted an undefined update_tsig_keys reference")
	}
}

func TestHandleUpdate_OutOfZonePrerequisite_ReturnsNotZone(t *testing.T) {
	s, err := testServerWithUpdate([]string{"0.0.0.0/0"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Stop() //nolint:errcheck

	prereq := makeAddRR("outside.invalid.", "192.0.2.1")
	prereq.Header().Ttl = 0
	w := newAXFRTestWriter("192.0.2.1")
	s.handleUpdate(
		w,
		makeUpdateMsg("example.com.", []dns.RR{prereq}, nil),
		net.ParseIP("192.0.2.1"),
	)
	if len(w.msgs) == 0 || w.msgs[0].Rcode != dns.RcodeNotZone {
		t.Fatalf("response=%v, want NOTZONE for out-of-zone prerequisite", w.msgs)
	}
}

func TestHandleUpdate_OutOfZoneMutation_ReturnsNotZoneWithoutMutation(t *testing.T) {
	s, err := testServerWithUpdate([]string{"0.0.0.0/0"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Stop() //nolint:errcheck
	before := s.GetZone("example.com.").SOA.Serial

	w := newAXFRTestWriter("192.0.2.1")
	s.handleUpdate(
		w,
		makeUpdateMsg("example.com.", nil, []dns.RR{
			makeAddRR("outside.invalid.", "192.0.2.1"),
		}),
		net.ParseIP("192.0.2.1"),
	)
	if len(w.msgs) == 0 || w.msgs[0].Rcode != dns.RcodeNotZone {
		t.Fatalf("response=%v, want NOTZONE for out-of-zone update", w.msgs)
	}
	if after := s.GetZone("example.com.").SOA.Serial; after != before {
		t.Fatalf("serial changed from %d to %d after rejected update", before, after)
	}
}

// TestHandleUpdate_AddRecord verifies that an UPDATE adding an A record returns NOERROR
// and the record is visible in subsequent zone lookups (DYNUP-01).
func TestHandleUpdate_AddRecord(t *testing.T) {
	s, err := testServerWithUpdate([]string{"0.0.0.0/0"})
	if err != nil {
		t.Fatalf("testServerWithUpdate: %v", err)
	}
	defer s.Stop() //nolint:errcheck

	w := newAXFRTestWriter("192.0.2.1")
	newRR := makeAddRR("www.example.com.", "198.51.100.1")
	r := makeUpdateMsg("example.com.", nil, []dns.RR{newRR})

	s.handleUpdate(w, r, net.ParseIP("192.0.2.1"))

	if len(w.msgs) == 0 {
		t.Fatal("no response written")
	}
	if w.msgs[0].Rcode != dns.RcodeSuccess {
		t.Errorf("Rcode = %d, want %d (NOERROR)", w.msgs[0].Rcode, dns.RcodeSuccess)
	}
	// Verify the record is now visible in the live zone (DYNUP-04).
	records := s.cfg.Zones["example.com."].GetRecords("www.example.com.", dns.TypeA)
	if len(records) == 0 {
		t.Error("www.example.com. A record not found after UPDATE")
	}
}

// TestHandleUpdate_DeleteRecord verifies deleting a specific RR removes it (DYNUP-01).
func TestHandleUpdate_DeleteRecord(t *testing.T) {
	s, err := testServerWithUpdate([]string{"0.0.0.0/0"})
	if err != nil {
		t.Fatalf("testServerWithUpdate: %v", err)
	}
	defer s.Stop() //nolint:errcheck

	// First add a record.
	w := newAXFRTestWriter("192.0.2.1")
	addRR := makeAddRR("www.example.com.", "198.51.100.5")
	r := makeUpdateMsg("example.com.", nil, []dns.RR{addRR})
	s.handleUpdate(w, r, net.ParseIP("192.0.2.1"))
	if len(w.msgs) == 0 || w.msgs[0].Rcode != dns.RcodeSuccess {
		t.Fatal("add UPDATE failed")
	}

	// Now delete it.
	w2 := newAXFRTestWriter("192.0.2.1")
	delRR := makeDeleteRR("www.example.com.", "198.51.100.5")
	r2 := makeUpdateMsg("example.com.", nil, []dns.RR{delRR})
	s.handleUpdate(w2, r2, net.ParseIP("192.0.2.1"))

	if len(w2.msgs) == 0 {
		t.Fatal("no response for delete UPDATE")
	}
	if w2.msgs[0].Rcode != dns.RcodeSuccess {
		t.Errorf("Rcode = %d, want %d (NOERROR)", w2.msgs[0].Rcode, dns.RcodeSuccess)
	}
	// Verify removed.
	records := s.cfg.Zones["example.com."].GetRecords("www.example.com.", dns.TypeA)
	if len(records) != 0 {
		t.Errorf("www.example.com. A record still present after delete: %v", records)
	}
}

// TestHandleUpdate_DeleteRRSet verifies deleting an entire rrset removes all records of that type (DYNUP-01).
func TestHandleUpdate_DeleteRRSet(t *testing.T) {
	s, err := testServerWithUpdate([]string{"0.0.0.0/0"})
	if err != nil {
		t.Fatalf("testServerWithUpdate: %v", err)
	}
	defer s.Stop() //nolint:errcheck

	// Add two A records at the same name.
	w := newAXFRTestWriter("192.0.2.1")
	rrs := []dns.RR{
		makeAddRR("www.example.com.", "198.51.100.10"),
		makeAddRR("www.example.com.", "198.51.100.11"),
	}
	r := makeUpdateMsg("example.com.", nil, rrs)
	s.handleUpdate(w, r, net.ParseIP("192.0.2.1"))
	if len(w.msgs) == 0 || w.msgs[0].Rcode != dns.RcodeSuccess {
		t.Fatal("add UPDATE failed")
	}

	// Delete the entire rrset.
	w2 := newAXFRTestWriter("192.0.2.1")
	delRRSet := makeDeleteRRSet("www.example.com.", dns.TypeA)
	r2 := makeUpdateMsg("example.com.", nil, []dns.RR{delRRSet})
	s.handleUpdate(w2, r2, net.ParseIP("192.0.2.1"))

	if len(w2.msgs) == 0 {
		t.Fatal("no response for delete-rrset UPDATE")
	}
	if w2.msgs[0].Rcode != dns.RcodeSuccess {
		t.Errorf("Rcode = %d, want %d (NOERROR)", w2.msgs[0].Rcode, dns.RcodeSuccess)
	}
	records := s.cfg.Zones["example.com."].GetRecords("www.example.com.", dns.TypeA)
	if len(records) != 0 {
		t.Errorf("www.example.com. A records still present after rrset delete: %v", records)
	}
}

// TestHandleUpdate_DeleteName verifies deleting all records at a name (DYNUP-01).
func TestHandleUpdate_DeleteName(t *testing.T) {
	s, err := testServerWithUpdate([]string{"0.0.0.0/0"})
	if err != nil {
		t.Fatalf("testServerWithUpdate: %v", err)
	}
	defer s.Stop() //nolint:errcheck

	// Add records.
	w := newAXFRTestWriter("192.0.2.1")
	rrs := []dns.RR{makeAddRR("host.example.com.", "198.51.100.20")}
	r := makeUpdateMsg("example.com.", nil, rrs)
	s.handleUpdate(w, r, net.ParseIP("192.0.2.1"))
	if len(w.msgs) == 0 || w.msgs[0].Rcode != dns.RcodeSuccess {
		t.Fatal("add UPDATE failed")
	}

	// Delete all at name.
	w2 := newAXFRTestWriter("192.0.2.1")
	delName := makeDeleteName("host.example.com.")
	r2 := makeUpdateMsg("example.com.", nil, []dns.RR{delName})
	s.handleUpdate(w2, r2, net.ParseIP("192.0.2.1"))

	if len(w2.msgs) == 0 {
		t.Fatal("no response for delete-name UPDATE")
	}
	if w2.msgs[0].Rcode != dns.RcodeSuccess {
		t.Errorf("Rcode = %d, want %d (NOERROR)", w2.msgs[0].Rcode, dns.RcodeSuccess)
	}
	if s.cfg.Zones["example.com."].HasName("host.example.com.") {
		t.Error("host.example.com. still exists in zone after delete-name")
	}
}

// TestHandleUpdate_Prereq_NameInUse verifies that a name-in-use prereq passes when the name exists.
func TestHandleUpdate_Prereq_NameInUse(t *testing.T) {
	s, err := testServerWithUpdate([]string{"0.0.0.0/0"})
	if err != nil {
		t.Fatalf("testServerWithUpdate: %v", err)
	}
	defer s.Stop() //nolint:errcheck

	// "example.com." exists in testZone().
	prereq := makePrereqNameInUse("example.com.")
	w := newAXFRTestWriter("192.0.2.1")
	r := makeUpdateMsg("example.com.", []dns.RR{prereq}, nil)
	s.handleUpdate(w, r, net.ParseIP("192.0.2.1"))

	if len(w.msgs) == 0 {
		t.Fatal("no response")
	}
	if w.msgs[0].Rcode != dns.RcodeSuccess {
		t.Errorf("Rcode = %d, want %d (NOERROR — prereq should pass)", w.msgs[0].Rcode, dns.RcodeSuccess)
	}
}

// TestHandleUpdate_Prereq_NameInUse_Fail verifies that a name-in-use prereq fails when name absent → NXDOMAIN.
func TestHandleUpdate_Prereq_NameInUse_Fail(t *testing.T) {
	s, err := testServerWithUpdate([]string{"0.0.0.0/0"})
	if err != nil {
		t.Fatalf("testServerWithUpdate: %v", err)
	}
	defer s.Stop() //nolint:errcheck

	prereq := makePrereqNameInUse("absent.example.com.")
	w := newAXFRTestWriter("192.0.2.1")
	r := makeUpdateMsg("example.com.", []dns.RR{prereq}, nil)
	s.handleUpdate(w, r, net.ParseIP("192.0.2.1"))

	if len(w.msgs) == 0 {
		t.Fatal("no response")
	}
	if w.msgs[0].Rcode != dns.RcodeNameError {
		t.Errorf("Rcode = %d, want %d (NXDOMAIN — prereq name not in use)", w.msgs[0].Rcode, dns.RcodeNameError)
	}
}

// TestHandleUpdate_Prereq_RRSetExists verifies that an rrset-exists prereq passes when the rrset exists.
func TestHandleUpdate_Prereq_RRSetExists(t *testing.T) {
	s, err := testServerWithUpdate([]string{"0.0.0.0/0"})
	if err != nil {
		t.Fatalf("testServerWithUpdate: %v", err)
	}
	defer s.Stop() //nolint:errcheck

	// testZone() has NS at example.com.
	prereq := makePrereqRRSetExists("example.com.", dns.TypeNS)
	w := newAXFRTestWriter("192.0.2.1")
	r := makeUpdateMsg("example.com.", []dns.RR{prereq}, nil)
	s.handleUpdate(w, r, net.ParseIP("192.0.2.1"))

	if len(w.msgs) == 0 {
		t.Fatal("no response")
	}
	if w.msgs[0].Rcode != dns.RcodeSuccess {
		t.Errorf("Rcode = %d, want %d (NOERROR — rrset exists)", w.msgs[0].Rcode, dns.RcodeSuccess)
	}
}

// TestHandleUpdate_Prereq_RRSetNotExists_Fail verifies that rrset-not-exists fails when rrset exists → YXRrset (7).
func TestHandleUpdate_Prereq_RRSetNotExists_Fail(t *testing.T) {
	s, err := testServerWithUpdate([]string{"0.0.0.0/0"})
	if err != nil {
		t.Fatalf("testServerWithUpdate: %v", err)
	}
	defer s.Stop() //nolint:errcheck

	// testZone() has NS at example.com. — prereq "NS should NOT exist" must fail.
	prereq := makePrereqRRSetNotExists("example.com.", dns.TypeNS)
	w := newAXFRTestWriter("192.0.2.1")
	r := makeUpdateMsg("example.com.", []dns.RR{prereq}, nil)
	s.handleUpdate(w, r, net.ParseIP("192.0.2.1"))

	if len(w.msgs) == 0 {
		t.Fatal("no response")
	}
	if w.msgs[0].Rcode != dns.RcodeYXRrset {
		t.Errorf("Rcode = %d, want %d (YXRrset)", w.msgs[0].Rcode, dns.RcodeYXRrset)
	}
}

// TestHandleUpdate_PrereqFailure_NoUpdatesApplied verifies that a failing prereq leaves the zone untouched (D-03).
func TestHandleUpdate_PrereqFailure_NoUpdatesApplied(t *testing.T) {
	s, err := testServerWithUpdate([]string{"0.0.0.0/0"})
	if err != nil {
		t.Fatalf("testServerWithUpdate: %v", err)
	}
	defer s.Stop() //nolint:errcheck

	// Capture SOA serial before failed UPDATE.
	originalSerial := s.cfg.Zones["example.com."].SOA.Serial

	// Prereq will fail (absent name), paired with an add operation that should NOT be applied.
	prereq := makePrereqNameInUse("absent.example.com.") // fails
	addRR := makeAddRR("www.example.com.", "198.51.100.99")
	w := newAXFRTestWriter("192.0.2.1")
	r := makeUpdateMsg("example.com.", []dns.RR{prereq}, []dns.RR{addRR})
	s.handleUpdate(w, r, net.ParseIP("192.0.2.1"))

	if len(w.msgs) == 0 {
		t.Fatal("no response")
	}
	// Prereq failure must return an error rcode.
	if w.msgs[0].Rcode == dns.RcodeSuccess {
		t.Error("Rcode = NOERROR, want error rcode (prereq failed)")
	}
	// www.example.com. must NOT be in the zone (update was not applied).
	if s.cfg.Zones["example.com."].HasName("www.example.com.") {
		t.Error("www.example.com. was added despite prereq failure — atomicity violated (D-03)")
	}
	// Serial must not have changed.
	if s.cfg.Zones["example.com."].SOA.Serial != originalSerial {
		t.Error("serial changed despite prereq failure — atomicity violated")
	}
}

// TestHandleUpdate_SOAInUpdateIgnored verifies that SOA in the Update section is silently skipped
// and the serial is auto-incremented by the handler (D-09, D-10).
func TestHandleUpdate_SOAInUpdateIgnored(t *testing.T) {
	s, err := testServerWithUpdate([]string{"0.0.0.0/0"})
	if err != nil {
		t.Fatalf("testServerWithUpdate: %v", err)
	}
	defer s.Stop() //nolint:errcheck

	originalSerial := s.cfg.Zones["example.com."].SOA.Serial

	// Provide a SOA in the Update section with a deliberately different serial.
	soaRR := &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   "example.com.",
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		Serial: 9999999,
	}
	// Also add a legit A record so the UPDATE is non-empty beyond the SOA.
	addRR := makeAddRR("www.example.com.", "198.51.100.50")

	w := newAXFRTestWriter("192.0.2.1")
	r := makeUpdateMsg("example.com.", nil, []dns.RR{soaRR, addRR})
	s.handleUpdate(w, r, net.ParseIP("192.0.2.1"))

	if len(w.msgs) == 0 {
		t.Fatal("no response")
	}
	if w.msgs[0].Rcode != dns.RcodeSuccess {
		t.Errorf("Rcode = %d, want NOERROR", w.msgs[0].Rcode)
	}
	newSerial := s.cfg.Zones["example.com."].SOA.Serial
	// Serial must have auto-incremented, NOT be 9999999.
	if newSerial == 9999999 {
		t.Error("SOA serial set to caller value 9999999 — SOA in Update section was not ignored (D-10)")
	}
	if newSerial <= originalSerial {
		t.Errorf("serial did not increment: was %d, now %d", originalSerial, newSerial)
	}
}

// TestHandleUpdate_DeleteSOA_Refused verifies that deleting the SOA returns REFUSED (D-04).
func TestHandleUpdate_DeleteSOA_Refused(t *testing.T) {
	s, err := testServerWithUpdate([]string{"0.0.0.0/0"})
	if err != nil {
		t.Fatalf("testServerWithUpdate: %v", err)
	}
	defer s.Stop() //nolint:errcheck

	// Delete rrset: ClassANY, TypeSOA → REFUSED.
	delSOA := makeDeleteRRSet("example.com.", dns.TypeSOA)
	w := newAXFRTestWriter("192.0.2.1")
	r := makeUpdateMsg("example.com.", nil, []dns.RR{delSOA})
	s.handleUpdate(w, r, net.ParseIP("192.0.2.1"))

	if len(w.msgs) == 0 {
		t.Fatal("no response")
	}
	if w.msgs[0].Rcode != dns.RcodeRefused {
		t.Errorf("Rcode = %d, want %d (REFUSED for delete-SOA)", w.msgs[0].Rcode, dns.RcodeRefused)
	}
}

// TestHandleUpdate_DeleteAllNS_Refused verifies that deleting all NS at apex returns REFUSED (D-04).
func TestHandleUpdate_DeleteAllNS_Refused(t *testing.T) {
	s, err := testServerWithUpdate([]string{"0.0.0.0/0"})
	if err != nil {
		t.Fatalf("testServerWithUpdate: %v", err)
	}
	defer s.Stop() //nolint:errcheck

	// testZone() has exactly one NS at apex — deleting the rrset would remove all.
	delNS := makeDeleteRRSet("example.com.", dns.TypeNS)
	w := newAXFRTestWriter("192.0.2.1")
	r := makeUpdateMsg("example.com.", nil, []dns.RR{delNS})
	s.handleUpdate(w, r, net.ParseIP("192.0.2.1"))

	if len(w.msgs) == 0 {
		t.Fatal("no response")
	}
	if w.msgs[0].Rcode != dns.RcodeRefused {
		t.Errorf("Rcode = %d, want %d (REFUSED for delete-all-NS)", w.msgs[0].Rcode, dns.RcodeRefused)
	}
}

// TestHandleUpdate_ImmediateVisibility verifies that after a successful UPDATE,
// s.cfg.Zones[zone].GetRecords returns the new record (DYNUP-04).
func TestHandleUpdate_ImmediateVisibility(t *testing.T) {
	s, err := testServerWithUpdate([]string{"0.0.0.0/0"})
	if err != nil {
		t.Fatalf("testServerWithUpdate: %v", err)
	}
	defer s.Stop() //nolint:errcheck

	// Verify record absent before UPDATE.
	before := s.cfg.Zones["example.com."].GetRecords("new.example.com.", dns.TypeA)
	if len(before) != 0 {
		t.Fatalf("new.example.com. already present before UPDATE")
	}

	w := newAXFRTestWriter("192.0.2.1")
	addRR := makeAddRR("new.example.com.", "203.0.113.1")
	r := makeUpdateMsg("example.com.", nil, []dns.RR{addRR})
	s.handleUpdate(w, r, net.ParseIP("192.0.2.1"))

	if len(w.msgs) == 0 || w.msgs[0].Rcode != dns.RcodeSuccess {
		t.Fatalf("UPDATE failed: rcode=%d", w.msgs[len(w.msgs)-1].Rcode)
	}

	// Immediate visibility: record must be in the live zone now.
	after := s.cfg.Zones["example.com."].GetRecords("new.example.com.", dns.TypeA)
	if len(after) == 0 {
		t.Error("new.example.com. A not visible immediately after UPDATE (DYNUP-04 violated)")
	}
}

// TestHandleUpdate_SerialIncrement verifies that the SOA serial auto-increments after a successful UPDATE (D-09).
func TestHandleUpdate_SerialIncrement(t *testing.T) {
	s, err := testServerWithUpdate([]string{"0.0.0.0/0"})
	if err != nil {
		t.Fatalf("testServerWithUpdate: %v", err)
	}
	defer s.Stop() //nolint:errcheck

	before := s.cfg.Zones["example.com."].SOA.Serial

	w := newAXFRTestWriter("192.0.2.1")
	addRR := makeAddRR("serial.example.com.", "203.0.113.2")
	r := makeUpdateMsg("example.com.", nil, []dns.RR{addRR})
	s.handleUpdate(w, r, net.ParseIP("192.0.2.1"))

	if len(w.msgs) == 0 || w.msgs[0].Rcode != dns.RcodeSuccess {
		t.Fatalf("UPDATE failed: rcode=%d", w.msgs[len(w.msgs)-1].Rcode)
	}

	after := s.cfg.Zones["example.com."].SOA.Serial
	if after <= before {
		t.Errorf("serial did not increment: before=%d after=%d", before, after)
	}
}

// TestHandleUpdate_Prereq_NameNotInUse_Pass verifies the name-not-in-use prereq passes when absent.
func TestHandleUpdate_Prereq_NameNotInUse_Pass(t *testing.T) {
	s, err := testServerWithUpdate([]string{"0.0.0.0/0"})
	if err != nil {
		t.Fatalf("testServerWithUpdate: %v", err)
	}
	defer s.Stop() //nolint:errcheck

	// "absent.example.com." does not exist in testZone().
	prereq := makePrereqNameNotInUse("absent.example.com.")
	w := newAXFRTestWriter("192.0.2.1")
	r := makeUpdateMsg("example.com.", []dns.RR{prereq}, nil)
	s.handleUpdate(w, r, net.ParseIP("192.0.2.1"))

	if len(w.msgs) == 0 {
		t.Fatal("no response")
	}
	if w.msgs[0].Rcode != dns.RcodeSuccess {
		t.Errorf("Rcode = %d, want NOERROR (name-not-in-use prereq should pass)", w.msgs[0].Rcode)
	}
}

// TestHandleUpdate_Prereq_NameNotInUse_Fail verifies name-not-in-use fails when name exists → YXDomain (6).
func TestHandleUpdate_Prereq_NameNotInUse_Fail(t *testing.T) {
	s, err := testServerWithUpdate([]string{"0.0.0.0/0"})
	if err != nil {
		t.Fatalf("testServerWithUpdate: %v", err)
	}
	defer s.Stop() //nolint:errcheck

	// "example.com." exists in testZone().
	prereq := makePrereqNameNotInUse("example.com.")
	w := newAXFRTestWriter("192.0.2.1")
	r := makeUpdateMsg("example.com.", []dns.RR{prereq}, nil)
	s.handleUpdate(w, r, net.ParseIP("192.0.2.1"))

	if len(w.msgs) == 0 {
		t.Fatal("no response")
	}
	if w.msgs[0].Rcode != dns.RcodeYXDomain {
		t.Errorf("Rcode = %d, want %d (YXDomain)", w.msgs[0].Rcode, dns.RcodeYXDomain)
	}
}

// TestHandleUpdate_Prereq_RRSetExistsValue_Pass verifies value-match prereq passes when value present.
func TestHandleUpdate_Prereq_RRSetExistsValue_Pass(t *testing.T) {
	s, err := testServerWithUpdate([]string{"0.0.0.0/0"})
	if err != nil {
		t.Fatalf("testServerWithUpdate: %v", err)
	}
	defer s.Stop() //nolint:errcheck

	// First add a record.
	w := newAXFRTestWriter("192.0.2.1")
	addRR := makeAddRR("www.example.com.", "198.51.100.1")
	r := makeUpdateMsg("example.com.", nil, []dns.RR{addRR})
	s.handleUpdate(w, r, net.ParseIP("192.0.2.1"))
	if len(w.msgs) == 0 || w.msgs[0].Rcode != dns.RcodeSuccess {
		t.Fatal("add UPDATE failed")
	}

	// Now test prereq-value-match on the added record (Class = INET = zone class).
	prereqValue := &dns.A{
		Hdr: dns.RR_Header{
			Name:   "www.example.com.",
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET, // zone class = value-match prereq
			Ttl:    0,
		},
		A: net.ParseIP("198.51.100.1"),
	}
	w2 := newAXFRTestWriter("192.0.2.1")
	r2 := makeUpdateMsg("example.com.", []dns.RR{prereqValue}, nil)
	s.handleUpdate(w2, r2, net.ParseIP("192.0.2.1"))

	if len(w2.msgs) == 0 {
		t.Fatal("no response")
	}
	if w2.msgs[0].Rcode != dns.RcodeSuccess {
		t.Errorf("Rcode = %d, want NOERROR (value-match prereq should pass)", w2.msgs[0].Rcode)
	}
}
