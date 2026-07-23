package zone

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

func TestNew(t *testing.T) {
	z := New("example.com")

	if z.Name != "example.com." {
		t.Errorf("Name = %s, want example.com.", z.Name)
	}
	if z.Origin != "example.com." {
		t.Errorf("Origin = %s, want example.com.", z.Origin)
	}
	if z.Class != dns.ClassINET {
		t.Errorf("Class = %d, want %d", z.Class, dns.ClassINET)
	}
	if z.Records == nil {
		t.Error("Records map not initialized")
	}
}

func TestNew_AutoFQDN(t *testing.T) {
	// Should automatically add trailing dot
	z := New("example.com")
	if z.Name != "example.com." {
		t.Errorf("Name should be FQDN: got %s", z.Name)
	}

	// Should preserve existing trailing dot
	z2 := New("example.org.")
	if z2.Name != "example.org." {
		t.Errorf("Name should preserve FQDN: got %s", z2.Name)
	}
}

func TestAddRecord(t *testing.T) {
	z := New("example.com")

	rr := &dns.A{
		Hdr: dns.RR_Header{
			Name:   "www.example.com.",
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		A: net.ParseIP("192.0.2.1"),
	}

	err := z.AddRecord(rr)
	if err != nil {
		t.Fatalf("AddRecord() error = %v", err)
	}

	// Verify record was added
	records := z.GetRecords("www.example.com.", dns.TypeA)
	if len(records) != 1 {
		t.Fatalf("Expected 1 record, got %d", len(records))
	}

	a := records[0].(*dns.A)
	if !a.A.Equal(net.ParseIP("192.0.2.1")) {
		t.Errorf("A record IP = %v, want 192.0.2.1", a.A)
	}
}

func TestAddRecord_Nil(t *testing.T) {
	z := New("example.com")
	err := z.AddRecord(nil)
	if err == nil {
		t.Error("AddRecord(nil) should return error")
	}
}

func TestAddRecord_OutOfZone(t *testing.T) {
	z := New("example.com")

	rr := &dns.A{
		Hdr: dns.RR_Header{
			Name:   "www.example.org.", // Different zone!
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		A: net.ParseIP("192.0.2.1"),
	}

	err := z.AddRecord(rr)
	if err == nil {
		t.Error("AddRecord() should error for out-of-zone record")
	}
}

func TestAddRecord_SOA(t *testing.T) {
	z := New("example.com")

	soa := &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   "example.com.",
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		Ns:      "ns1.example.com.",
		Mbox:    "admin.example.com.",
		Serial:  2024010100,
		Refresh: 7200,
		Retry:   3600,
		Expire:  1209600,
		Minttl:  3600,
	}

	err := z.AddRecord(soa)
	if err != nil {
		t.Fatalf("AddRecord(SOA) error = %v", err)
	}

	if z.SOA == nil {
		t.Fatal("SOA not set")
	}
	if z.SOA.Serial != 2024010100 {
		t.Errorf("SOA serial = %d, want 2024010100", z.SOA.Serial)
	}
}

func TestGetRecords(t *testing.T) {
	z := New("example.com")

	// Add multiple A records
	for i := 1; i <= 3; i++ {
		rr := &dns.A{
			Hdr: dns.RR_Header{
				Name:   "www.example.com.",
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    3600,
			},
			A: net.ParseIP("192.0.2." + string(rune('0'+i))),
		}
		z.AddRecord(rr)
	}

	records := z.GetRecords("www.example.com.", dns.TypeA)
	if len(records) != 3 {
		t.Errorf("GetRecords() returned %d records, want 3", len(records))
	}
}

func TestGetRecords_Wildcard(t *testing.T) {
	z := New("example.com")

	// Add wildcard record
	rr := &dns.A{
		Hdr: dns.RR_Header{
			Name:   "*.example.com.",
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		A: net.ParseIP("192.0.2.100"),
	}
	z.AddRecord(rr)

	// Should match anything.example.com
	records := z.GetRecords("foo.example.com.", dns.TypeA)
	if len(records) == 0 {
		t.Error("Wildcard should match foo.example.com")
	}

	if len(records) > 0 {
		a := records[0].(*dns.A)
		// Owner name should be synthesized to actual query
		if a.Header().Name != "foo.example.com." {
			t.Errorf("Synthesized name = %s, want foo.example.com.", a.Header().Name)
		}
	}
}

func TestGetRecords_WildcardDoesNotOverrideExistingName(t *testing.T) {
	z := New("example.com.")
	_ = z.AddRecord(&dns.A{Hdr: dns.RR_Header{Name: "*.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP("192.0.2.1")})
	_ = z.AddRecord(&dns.TXT{Hdr: dns.RR_Header{Name: "host.example.com.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300}, Txt: []string{"exists"}})

	if got := z.GetRecords("host.example.com.", dns.TypeA); len(got) != 0 {
		t.Fatalf("wildcard synthesized at existing owner: %v", got)
	}
}

func TestGetRecords_UsesOnlyClosestEncloserWildcard(t *testing.T) {
	z := New("example.com.")
	_ = z.AddRecord(&dns.A{Hdr: dns.RR_Header{Name: "*.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP("192.0.2.1")})
	_ = z.AddRecord(&dns.TXT{Hdr: dns.RR_Header{Name: "leaf.block.example.com.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300}, Txt: []string{"creates empty non-terminal"}})

	if got := z.GetRecords("x.block.example.com.", dns.TypeA); len(got) != 0 {
		t.Fatalf("higher wildcard crossed closest encloser: %v", got)
	}
	if !z.HasName("block.example.com.") {
		t.Fatal("empty non-terminal should exist")
	}
}

func TestGetRecords_ANYReturnsAllExactRRSets(t *testing.T) {
	z := New("example.com.")
	_ = z.AddRecord(&dns.A{Hdr: dns.RR_Header{Name: "host.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP("192.0.2.1")})
	_ = z.AddRecord(&dns.TXT{Hdr: dns.RR_Header{Name: "host.example.com.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300}, Txt: []string{"value"}})

	if got := z.GetRecords("host.example.com.", dns.TypeANY); len(got) != 2 {
		t.Fatalf("ANY record count=%d, want 2", len(got))
	}
}

func TestGetRecords_AutoFQDN(t *testing.T) {
	z := New("example.com")

	rr := &dns.A{
		Hdr: dns.RR_Header{
			Name:   "www.example.com.",
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		A: net.ParseIP("192.0.2.1"),
	}
	z.AddRecord(rr)

	// Query without trailing dot - should still match
	records := z.GetRecords("www.example.com", dns.TypeA)
	if len(records) != 1 {
		t.Error("Should find record even without trailing dot in query")
	}
}

func TestGetNameservers(t *testing.T) {
	z := New("example.com")

	// Add NS records
	for i := 1; i <= 2; i++ {
		ns := &dns.NS{
			Hdr: dns.RR_Header{
				Name:   "example.com.",
				Rrtype: dns.TypeNS,
				Class:  dns.ClassINET,
				Ttl:    3600,
			},
			Ns: "ns" + string(rune('0'+i)) + ".example.com.",
		}
		z.AddRecord(ns)
	}

	nameservers := z.GetNameservers()
	if len(nameservers) != 2 {
		t.Errorf("GetNameservers() returned %d, want 2", len(nameservers))
	}
}

func TestValidate_NoSOA(t *testing.T) {
	z := New("example.com")

	err := z.Validate()
	if err == nil {
		t.Error("Validate() should error without SOA")
	}
}

func TestValidate_NoNS(t *testing.T) {
	z := New("example.com")

	// Add SOA but no NS
	soa := &dns.SOA{
		Hdr:     dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
		Ns:      "ns1.example.com.",
		Mbox:    "admin.example.com.",
		Serial:  1,
		Refresh: 7200,
		Retry:   3600,
		Expire:  1209600,
		Minttl:  3600,
	}
	z.AddRecord(soa)

	err := z.Validate()
	if err == nil {
		t.Error("Validate() should error without NS records")
	}
}

func TestValidate_MissingGlue(t *testing.T) {
	z := New("example.com")

	// Add SOA
	soa := &dns.SOA{
		Hdr:     dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
		Ns:      "ns1.example.com.",
		Mbox:    "admin.example.com.",
		Serial:  1,
		Refresh: 7200,
		Retry:   3600,
		Expire:  1209600,
		Minttl:  3600,
	}
	z.AddRecord(soa)

	// Add NS record pointing to in-zone name without glue
	ns := &dns.NS{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600},
		Ns:  "ns1.example.com.", // In-zone but no A/AAAA
	}
	z.AddRecord(ns)

	err := z.Validate()
	if err == nil {
		t.Error("Validate() should error for missing glue records")
	}
}

func TestValidate_WithGlue(t *testing.T) {
	z := New("example.com")

	// Add SOA
	soa := &dns.SOA{
		Hdr:     dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
		Ns:      "ns1.example.com.",
		Mbox:    "admin.example.com.",
		Serial:  1,
		Refresh: 7200,
		Retry:   3600,
		Expire:  1209600,
		Minttl:  3600,
	}
	z.AddRecord(soa)

	// Add NS record
	ns := &dns.NS{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600},
		Ns:  "ns1.example.com.",
	}
	z.AddRecord(ns)

	// Add glue
	a := &dns.A{
		Hdr: dns.RR_Header{Name: "ns1.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
		A:   net.ParseIP("192.0.2.1"),
	}
	z.AddRecord(a)

	err := z.Validate()
	if err != nil {
		t.Errorf("Validate() error = %v, should pass with glue", err)
	}
}

func TestValidate_CNAMEConflict(t *testing.T) {
	z := New("example.com")

	// Add valid SOA and NS
	soa := &dns.SOA{
		Hdr:     dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
		Ns:      "ns1.example.org.", // Out of zone
		Mbox:    "admin.example.com.",
		Serial:  1,
		Refresh: 7200,
		Retry:   3600,
		Expire:  1209600,
		Minttl:  3600,
	}
	z.AddRecord(soa)

	ns := &dns.NS{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600},
		Ns:  "ns1.example.org.",
	}
	z.AddRecord(ns)

	// Add CNAME
	cname := &dns.CNAME{
		Hdr:    dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 3600},
		Target: "web.example.com.",
	}
	z.AddRecord(cname)

	// Add A record at same name - invalid!
	a := &dns.A{
		Hdr: dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
		A:   net.ParseIP("192.0.2.1"),
	}
	z.AddRecord(a)

	err := z.Validate()
	if err == nil {
		t.Error("Validate() should error for CNAME coexisting with other records")
	}
}

func TestIncrementSerial(t *testing.T) {
	z := New("example.com")

	soa := &dns.SOA{
		Hdr:     dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
		Ns:      "ns1.example.com.",
		Mbox:    "admin.example.com.",
		Serial:  2024010100,
		Refresh: 7200,
		Retry:   3600,
		Expire:  1209600,
		Minttl:  3600,
	}
	z.AddRecord(soa)

	oldSerial := z.SOA.Serial
	err := z.IncrementSerial()
	if err != nil {
		t.Fatalf("IncrementSerial() error = %v", err)
	}

	if z.SOA.Serial <= oldSerial {
		t.Errorf("Serial not incremented: was %d, now %d", oldSerial, z.SOA.Serial)
	}
}

func TestClone(t *testing.T) {
	z := New("example.com")

	// Add some records
	soa := &dns.SOA{
		Hdr:     dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
		Ns:      "ns1.example.com.",
		Mbox:    "admin.example.com.",
		Serial:  1,
		Refresh: 7200,
		Retry:   3600,
		Expire:  1209600,
		Minttl:  3600,
	}
	z.AddRecord(soa)

	a := &dns.A{
		Hdr: dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
		A:   net.ParseIP("192.0.2.1"),
	}
	z.AddRecord(a)

	// Clone
	clone := z.Clone()

	// Verify clone has same data
	if clone.Name != z.Name {
		t.Errorf("Clone name = %s, want %s", clone.Name, z.Name)
	}
	if clone.SOA.Serial != z.SOA.Serial {
		t.Error("Clone SOA serial doesn't match")
	}

	// Modify clone - should not affect original
	clone.SOA.Serial = 999

	if z.SOA.Serial == 999 {
		t.Error("Modifying clone affected original")
	}
}

func TestGetStats(t *testing.T) {
	z := New("example.com")

	// Add various records
	soa := &dns.SOA{
		Hdr:     dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
		Ns:      "ns1.example.com.",
		Mbox:    "admin.example.com.",
		Serial:  1,
		Refresh: 7200,
		Retry:   3600,
		Expire:  1209600,
		Minttl:  3600,
	}
	z.AddRecord(soa)

	// 2 A records at www
	for i := 0; i < 2; i++ {
		a := &dns.A{
			Hdr: dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
			A:   net.ParseIP("192.0.2.1"),
		}
		z.AddRecord(a)
	}

	// 1 AAAA record at www
	aaaa := &dns.AAAA{
		Hdr:  dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 3600},
		AAAA: net.ParseIP("2001:db8::1"),
	}
	z.AddRecord(aaaa)

	stats := z.GetStats()

	// Should have 2 owners: example.com and www.example.com
	if stats.Owners != 2 {
		t.Errorf("Owners = %d, want 2", stats.Owners)
	}

	// Should have 3 record sets: SOA, A, AAAA
	if stats.RecordSets != 3 {
		t.Errorf("RecordSets = %d, want 3", stats.RecordSets)
	}

	// Should have 4 total records: 1 SOA + 2 A + 1 AAAA
	if stats.Records != 4 {
		t.Errorf("Records = %d, want 4", stats.Records)
	}
}

func TestJoinLabels(t *testing.T) {
	tests := []struct {
		labels []string
		want   string
	}{
		{[]string{}, "."},
		{[]string{"com"}, "com."},
		{[]string{"example", "com"}, "example.com."},
		{[]string{"www", "example", "com"}, "www.example.com."},
	}

	for _, tt := range tests {
		got := joinLabels(tt.labels)
		if got != tt.want {
			t.Errorf("joinLabels(%v) = %s, want %s", tt.labels, got, tt.want)
		}
	}
}

func TestFullyQualify(t *testing.T) {
	z := New("example.com")

	tests := []struct {
		name string
		want string
	}{
		{"", "example.com."},
		{"@", "example.com."},
		{"www", "www.example.com."},
		{"www.example.com.", "www.example.com."},
		{"sub.www", "sub.www.example.com."},
	}

	for _, tt := range tests {
		got := z.fullyQualify(tt.name)
		if got != tt.want {
			t.Errorf("fullyQualify(%q) = %s, want %s", tt.name, got, tt.want)
		}
	}
}
