package zone

import (
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestParseBIND(t *testing.T) {
	cfg := DefaultConfig()
	z, err := ParseBIND("testdata/example.org.bind", "example.org.", cfg)
	if err != nil {
		t.Fatalf("ParseBIND() error = %v", err)
	}

	if z == nil {
		t.Fatal("ParseBIND() returned nil zone")
	}

	if z.Name != "example.org." {
		t.Errorf("Zone name = %s, want example.org.", z.Name)
	}
}

func TestParseBIND_SOA(t *testing.T) {
	cfg := DefaultConfig()
	z, err := ParseBIND("testdata/example.org.bind", "example.org.", cfg)
	if err != nil {
		t.Fatalf("ParseBIND() error = %v", err)
	}

	if z.SOA == nil {
		t.Fatal("Zone has no SOA record")
	}

	if z.SOA.Ns != "ns1.example.org." {
		t.Errorf("SOA primary_ns = %s, want ns1.example.org.", z.SOA.Ns)
	}

	if z.SOA.Mbox != "hostmaster.example.org." {
		t.Errorf("SOA mbox = %s, want hostmaster.example.org.", z.SOA.Mbox)
	}

	if z.SOA.Serial != 2024010100 {
		t.Errorf("SOA serial = %d, want 2024010100", z.SOA.Serial)
	}

	if z.SOA.Refresh != 7200 {
		t.Errorf("SOA refresh = %d, want 7200", z.SOA.Refresh)
	}
}

func TestParseBIND_NSRecords(t *testing.T) {
	cfg := DefaultConfig()
	z, err := ParseBIND("testdata/example.org.bind", "example.org.", cfg)
	if err != nil {
		t.Fatalf("ParseBIND() error = %v", err)
	}

	ns := z.GetNameservers()
	if len(ns) != 2 {
		t.Fatalf("Expected 2 NS records, got %d", len(ns))
	}

	nsNames := make(map[string]bool)
	for _, n := range ns {
		nsNames[n.Ns] = true
	}

	if !nsNames["ns1.example.org."] {
		t.Error("Missing ns1.example.org")
	}
	if !nsNames["ns2.example.org."] {
		t.Error("Missing ns2.example.org")
	}
}

func TestParseBIND_ARecords(t *testing.T) {
	cfg := DefaultConfig()
	z, err := ParseBIND("testdata/example.org.bind", "example.org.", cfg)
	if err != nil {
		t.Fatalf("ParseBIND() error = %v", err)
	}

	// Check www has 2 A records
	aRecords := z.GetRecords("www.example.org.", dns.TypeA)
	if len(aRecords) != 2 {
		t.Errorf("www has %d A records, want 2", len(aRecords))
	}

	// Check apex has 1 A record
	apexA := z.GetRecords("example.org.", dns.TypeA)
	if len(apexA) != 1 {
		t.Errorf("apex has %d A records, want 1", len(apexA))
	}

	if len(apexA) > 0 {
		a := apexA[0].(*dns.A)
		if !a.A.Equal(net.ParseIP("198.51.100.1")) {
			t.Errorf("apex A = %v, want 198.51.100.1", a.A)
		}
	}
}

func TestParseBIND_MXRecords(t *testing.T) {
	cfg := DefaultConfig()
	z, err := ParseBIND("testdata/example.org.bind", "example.org.", cfg)
	if err != nil {
		t.Fatalf("ParseBIND() error = %v", err)
	}

	mx := z.GetRecords("example.org.", dns.TypeMX)
	if len(mx) != 2 {
		t.Fatalf("Expected 2 MX records, got %d", len(mx))
	}

	// Check priorities
	priorities := make(map[uint16]bool)
	for _, rr := range mx {
		m := rr.(*dns.MX)
		priorities[m.Preference] = true
	}

	if !priorities[10] || !priorities[20] {
		t.Error("Expected MX priorities 10 and 20")
	}
}

func TestParseBIND_TXTRecords(t *testing.T) {
	cfg := DefaultConfig()
	z, err := ParseBIND("testdata/example.org.bind", "example.org.", cfg)
	if err != nil {
		t.Fatalf("ParseBIND() error = %v", err)
	}

	// Check apex TXT
	txt := z.GetRecords("example.org.", dns.TypeTXT)
	if len(txt) != 1 {
		t.Fatalf("Expected 1 TXT record at apex, got %d", len(txt))
	}

	// Check DMARC TXT
	dmarc := z.GetRecords("_dmarc.example.org.", dns.TypeTXT)
	if len(dmarc) != 1 {
		t.Fatalf("Expected 1 DMARC TXT record, got %d", len(dmarc))
	}
}

func TestParseBIND_SRVRecords(t *testing.T) {
	cfg := DefaultConfig()
	z, err := ParseBIND("testdata/example.org.bind", "example.org.", cfg)
	if err != nil {
		t.Fatalf("ParseBIND() error = %v", err)
	}

	srv := z.GetRecords("_sip._tcp.example.org.", dns.TypeSRV)
	if len(srv) != 2 {
		t.Fatalf("Expected 2 SRV records, got %d", len(srv))
	}

	// Check first SRV
	s1 := srv[0].(*dns.SRV)
	if s1.Priority != 10 {
		t.Errorf("SRV priority = %d, want 10", s1.Priority)
	}
	if s1.Port != 5060 {
		t.Errorf("SRV port = %d, want 5060", s1.Port)
	}
}

func TestParseBIND_CNAME(t *testing.T) {
	cfg := DefaultConfig()
	z, err := ParseBIND("testdata/example.org.bind", "example.org.", cfg)
	if err != nil {
		t.Fatalf("ParseBIND() error = %v", err)
	}

	cname := z.GetRecords("ftp.example.org.", dns.TypeCNAME)
	if len(cname) != 1 {
		t.Fatalf("Expected 1 CNAME record, got %d", len(cname))
	}

	c := cname[0].(*dns.CNAME)
	if c.Target != "www.example.org." {
		t.Errorf("CNAME target = %s, want www.example.org.", c.Target)
	}
}

func TestParseBIND_Wildcard(t *testing.T) {
	cfg := DefaultConfig()
	z, err := ParseBIND("testdata/example.org.bind", "example.org.", cfg)
	if err != nil {
		t.Fatalf("ParseBIND() error = %v", err)
	}

	// Check wildcard exists
	wildcard := z.GetRecords("*.example.org.", dns.TypeA)
	if len(wildcard) != 1 {
		t.Fatalf("Expected 1 wildcard A record, got %d", len(wildcard))
	}

	// Check wildcard matches random names
	random := z.GetRecords("foo.example.org.", dns.TypeA)
	if len(random) == 0 {
		t.Error("Wildcard should match foo.example.org")
	}
}

func TestParseBIND_Validation(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Strict = true

	z, err := ParseBIND("testdata/example.org.bind", "example.org.", cfg)
	if err != nil {
		t.Fatalf("ParseBIND() error = %v (validation should pass)", err)
	}

	// Manually validate again
	err = z.Validate()
	if err != nil {
		t.Errorf("Validate() error = %v", err)
	}
}

func TestExportBIND(t *testing.T) {
	// Create a zone
	z := New("test.example")

	// Add SOA
	soa := &dns.SOA{
		Hdr:     dns.RR_Header{Name: "test.example.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
		Ns:      "ns1.test.example.",
		Mbox:    "admin.test.example.",
		Serial:  2024010100,
		Refresh: 7200,
		Retry:   3600,
		Expire:  1209600,
		Minttl:  3600,
	}
	z.AddRecord(soa)

	// Add NS
	ns := &dns.NS{
		Hdr: dns.RR_Header{Name: "test.example.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600},
		Ns:  "ns1.test.example.",
	}
	z.AddRecord(ns)

	// Add A record
	a := &dns.A{
		Hdr: dns.RR_Header{Name: "www.test.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
		A:   net.ParseIP("192.0.2.1"),
	}
	z.AddRecord(a)

	// Export
	bind, err := z.ExportBIND()
	if err != nil {
		t.Fatalf("ExportBIND() error = %v", err)
	}

	// Check output contains expected elements
	if !strings.Contains(bind, "$ORIGIN test.example.") {
		t.Error("Export should contain $ORIGIN")
	}
	if !strings.Contains(bind, "$TTL") {
		t.Error("Export should contain $TTL")
	}
	if !strings.Contains(bind, "SOA") {
		t.Error("Export should contain SOA")
	}
	if !strings.Contains(bind, "NS") {
		t.Error("Export should contain NS")
	}
	if !strings.Contains(bind, "192.0.2.1") {
		t.Error("Export should contain A record")
	}
}

func TestConvertBINDToDNSZone(t *testing.T) {
	cfg := DefaultConfig()
	yaml, err := ConvertBINDToDNSZone("testdata/example.org.bind", "example.org.", cfg)
	if err != nil {
		t.Fatalf("ConvertBINDToDNSZone() error = %v", err)
	}

	// Check YAML output
	if !strings.Contains(yaml, "zone:") {
		t.Error("YAML should contain zone section")
	}
	if !strings.Contains(yaml, "name: example.org") {
		t.Error("YAML should contain zone name")
	}
	if !strings.Contains(yaml, "soa:") {
		t.Error("YAML should contain SOA section")
	}
	if !strings.Contains(yaml, "records:") {
		t.Error("YAML should contain records section")
	}
	if !strings.Contains(yaml, "hostmaster@example.org") {
		t.Error("YAML should convert mbox to email format")
	}
}

func TestMakeRelative(t *testing.T) {
	tests := []struct {
		name   string
		origin string
		want   string
	}{
		{"example.org.", "example.org.", "@"},
		{"www.example.org.", "example.org.", "www"},
		{"sub.www.example.org.", "example.org.", "sub.www"},
		{"external.com.", "example.org.", "external.com"},
	}

	for _, tt := range tests {
		got := makeRelative(tt.name, tt.origin)
		if got != tt.want {
			t.Errorf("makeRelative(%q, %q) = %s, want %s", tt.name, tt.origin, got, tt.want)
		}
	}
}

func TestQuoteIfNeeded(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"www", "www"},
		{"@", `"@"`},
		{"*", `"*"`},
		{"_dmarc", "_dmarc"},
		{"test:colon", `"test:colon"`},
	}

	for _, tt := range tests {
		got := quoteIfNeeded(tt.input)
		if got != tt.want {
			t.Errorf("quoteIfNeeded(%q) = %s, want %s", tt.input, got, tt.want)
		}
	}
}

func TestParseBIND_SSHFP(t *testing.T) {
	cfg := DefaultConfig()
	z, err := ParseBIND("testdata/example.org.bind", "example.org.", cfg)
	if err != nil {
		t.Fatalf("ParseBIND() error = %v", err)
	}
	recs := z.GetRecords("host.example.org.", dns.TypeSSHFP)
	if len(recs) == 0 {
		t.Fatal("expected SSHFP records, got none")
	}
}

func TestParseBIND_NAPTR(t *testing.T) {
	cfg := DefaultConfig()
	z, err := ParseBIND("testdata/example.org.bind", "example.org.", cfg)
	if err != nil {
		t.Fatalf("ParseBIND() error = %v", err)
	}
	recs := z.GetRecords("_sip._tcp.example.org.", dns.TypeNAPTR)
	if len(recs) == 0 {
		t.Fatal("expected NAPTR records, got none")
	}
}

func TestParseBIND_SMIMEA(t *testing.T) {
	cfg := DefaultConfig()
	z, err := ParseBIND("testdata/example.org.bind", "example.org.", cfg)
	if err != nil {
		t.Fatalf("ParseBIND() error = %v", err)
	}
	recs := z.GetRecords("_smimecert._tcp.user.example.org.", dns.TypeSMIMEA)
	if len(recs) == 0 {
		t.Fatal("expected SMIMEA records, got none")
	}
}

func TestParseBIND_LOC(t *testing.T) {
	cfg := DefaultConfig()
	z, err := ParseBIND("testdata/example.org.bind", "example.org.", cfg)
	if err != nil {
		t.Fatalf("ParseBIND() error = %v", err)
	}
	recs := z.GetRecords("host.example.org.", dns.TypeLOC)
	if len(recs) == 0 {
		t.Fatal("expected LOC records, got none")
	}
}

func TestParseBIND_TLSA(t *testing.T) {
	cfg := DefaultConfig()
	z, err := ParseBIND("testdata/example.org.bind", "example.org.", cfg)
	if err != nil {
		t.Fatalf("ParseBIND() error = %v", err)
	}
	recs := z.GetRecords("_443._tcp.example.org.", dns.TypeTLSA)
	if len(recs) == 0 {
		t.Fatal("expected TLSA records, got none")
	}
}

func TestParseBIND_HTTPS(t *testing.T) {
	cfg := DefaultConfig()
	z, err := ParseBIND("testdata/example.org.bind", "example.org.", cfg)
	if err != nil {
		t.Fatalf("ParseBIND() error = %v", err)
	}
	recs := z.GetRecords("www.example.org.", dns.TypeHTTPS)
	if len(recs) == 0 {
		t.Fatal("expected HTTPS records, got none")
	}
}

func TestParseBIND_SVCB(t *testing.T) {
	cfg := DefaultConfig()
	z, err := ParseBIND("testdata/example.org.bind", "example.org.", cfg)
	if err != nil {
		t.Fatalf("ParseBIND() error = %v", err)
	}
	recs := z.GetRecords("_dns.resolver.example.org.", dns.TypeSVCB)
	if len(recs) == 0 {
		t.Fatal("expected SVCB records, got none")
	}
}

func BenchmarkParseBIND(b *testing.B) {
	cfg := DefaultConfig()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseBIND("testdata/example.org.bind", "example.org.", cfg)
	}
}

func BenchmarkExportBIND(b *testing.B) {
	cfg := DefaultConfig()
	z, _ := ParseBIND("testdata/example.org.bind", "example.org.", cfg)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = z.ExportBIND()
	}
}

func BenchmarkConvertBINDToDNSZone(b *testing.B) {
	cfg := DefaultConfig()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ConvertBINDToDNSZone("testdata/example.org.bind", "example.org.", cfg)
	}
}
