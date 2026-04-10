package zone

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestParseDNSZone(t *testing.T) {
	cfg := DefaultConfig()
	z, err := ParseDNSZone("testdata/example.com.dnszone", cfg)
	if err != nil {
		t.Fatalf("ParseDNSZone() error = %v", err)
	}

	if z == nil {
		t.Fatal("ParseDNSZone() returned nil zone")
	}

	if z.Name != "example.com." {
		t.Errorf("Zone name = %s, want example.com.", z.Name)
	}
}

func TestParseDNSZone_SOA(t *testing.T) {
	cfg := DefaultConfig()
	z, err := ParseDNSZone("testdata/example.com.dnszone", cfg)
	if err != nil {
		t.Fatalf("ParseDNSZone() error = %v", err)
	}

	if z.SOA == nil {
		t.Fatal("Zone has no SOA record")
	}

	if z.SOA.Ns != "ns1.example.com." {
		t.Errorf("SOA primary_ns = %s, want ns1.example.com.", z.SOA.Ns)
	}

	// Contact should be formatted: admin@example.com -> admin.example.com.
	if z.SOA.Mbox != "admin.example.com." {
		t.Errorf("SOA mbox = %s, want admin.example.com.", z.SOA.Mbox)
	}

	// Serial should be auto-generated (YYYYMMDD00 format)
	if z.SOA.Serial < 2024010100 {
		t.Errorf("SOA serial = %d, seems too old", z.SOA.Serial)
	}

	// Refresh = 2h = 7200s
	if z.SOA.Refresh != 7200 {
		t.Errorf("SOA refresh = %d, want 7200", z.SOA.Refresh)
	}

	// Retry = 1h = 3600s
	if z.SOA.Retry != 3600 {
		t.Errorf("SOA retry = %d, want 3600", z.SOA.Retry)
	}

	// Expire = 2w = 1209600s
	if z.SOA.Expire != 1209600 {
		t.Errorf("SOA expire = %d, want 1209600", z.SOA.Expire)
	}

	// Negative TTL = 1h = 3600s
	if z.SOA.Minttl != 3600 {
		t.Errorf("SOA negative_ttl = %d, want 3600", z.SOA.Minttl)
	}
}

func TestParseDNSZone_NSRecords(t *testing.T) {
	cfg := DefaultConfig()
	z, err := ParseDNSZone("testdata/example.com.dnszone", cfg)
	if err != nil {
		t.Fatalf("ParseDNSZone() error = %v", err)
	}

	ns := z.GetNameservers()
	if len(ns) != 2 {
		t.Fatalf("Expected 2 NS records, got %d", len(ns))
	}

	// Check nameservers
	nsNames := make(map[string]bool)
	for _, n := range ns {
		nsNames[n.Ns] = true
	}

	if !nsNames["ns1.example.com."] {
		t.Error("Missing ns1.example.com")
	}
	if !nsNames["ns2.example.com."] {
		t.Error("Missing ns2.example.com")
	}
}

func TestParseDNSZone_ARecords(t *testing.T) {
	cfg := DefaultConfig()
	z, err := ParseDNSZone("testdata/example.com.dnszone", cfg)
	if err != nil {
		t.Fatalf("ParseDNSZone() error = %v", err)
	}

	// Check www has 2 A records
	aRecords := z.GetRecords("www.example.com.", dns.TypeA)
	if len(aRecords) != 2 {
		t.Errorf("www has %d A records, want 2", len(aRecords))
	}

	// Check apex has 1 A record
	apexA := z.GetRecords("example.com.", dns.TypeA)
	if len(apexA) != 1 {
		t.Errorf("apex has %d A records, want 1", len(apexA))
	}

	if len(apexA) > 0 {
		a := apexA[0].(*dns.A)
		if !a.A.Equal(net.ParseIP("192.0.2.1")) {
			t.Errorf("apex A = %v, want 192.0.2.1", a.A)
		}
	}
}

func TestParseDNSZone_AAAARecords(t *testing.T) {
	cfg := DefaultConfig()
	z, err := ParseDNSZone("testdata/example.com.dnszone", cfg)
	if err != nil {
		t.Fatalf("ParseDNSZone() error = %v", err)
	}

	// Check apex has AAAA
	aaaa := z.GetRecords("example.com.", dns.TypeAAAA)
	if len(aaaa) != 1 {
		t.Errorf("apex has %d AAAA records, want 1", len(aaaa))
	}

	if len(aaaa) > 0 {
		record := aaaa[0].(*dns.AAAA)
		if !record.AAAA.Equal(net.ParseIP("2001:db8::1")) {
			t.Errorf("apex AAAA = %v, want 2001:db8::1", record.AAAA)
		}
	}
}

func TestParseDNSZone_MXRecords(t *testing.T) {
	cfg := DefaultConfig()
	z, err := ParseDNSZone("testdata/example.com.dnszone", cfg)
	if err != nil {
		t.Fatalf("ParseDNSZone() error = %v", err)
	}

	mx := z.GetRecords("example.com.", dns.TypeMX)
	if len(mx) != 2 {
		t.Fatalf("Expected 2 MX records, got %d", len(mx))
	}

	// Check priorities
	for _, rr := range mx {
		m := rr.(*dns.MX)
		if m.Preference != 10 && m.Preference != 20 {
			t.Errorf("MX priority = %d, want 10 or 20", m.Preference)
		}
	}
}

func TestParseDNSZone_TXTRecords(t *testing.T) {
	cfg := DefaultConfig()
	z, err := ParseDNSZone("testdata/example.com.dnszone", cfg)
	if err != nil {
		t.Fatalf("ParseDNSZone() error = %v", err)
	}

	// Check apex TXT (SPF)
	txt := z.GetRecords("example.com.", dns.TypeTXT)
	if len(txt) != 1 {
		t.Fatalf("Expected 1 TXT record at apex, got %d", len(txt))
	}

	t1 := txt[0].(*dns.TXT)
	if len(t1.Txt) == 0 || t1.Txt[0] != "v=spf1 mx -all" {
		t.Errorf("TXT = %v, want v=spf1 mx -all", t1.Txt)
	}

	// Check _dmarc TXT
	dmarc := z.GetRecords("_dmarc.example.com.", dns.TypeTXT)
	if len(dmarc) != 1 {
		t.Fatalf("Expected 1 DMARC TXT record, got %d", len(dmarc))
	}
}

func TestParseDNSZone_SRVRecords(t *testing.T) {
	cfg := DefaultConfig()
	z, err := ParseDNSZone("testdata/example.com.dnszone", cfg)
	if err != nil {
		t.Fatalf("ParseDNSZone() error = %v", err)
	}

	srv := z.GetRecords("_sip._tcp.example.com.", dns.TypeSRV)
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

func TestParseDNSZone_CNAME(t *testing.T) {
	cfg := DefaultConfig()
	z, err := ParseDNSZone("testdata/example.com.dnszone", cfg)
	if err != nil {
		t.Fatalf("ParseDNSZone() error = %v", err)
	}

	cname := z.GetRecords("ftp.example.com.", dns.TypeCNAME)
	if len(cname) != 1 {
		t.Fatalf("Expected 1 CNAME record, got %d", len(cname))
	}

	c := cname[0].(*dns.CNAME)
	if c.Target != "www.example.com." {
		t.Errorf("CNAME target = %s, want www.example.com.", c.Target)
	}
}

func TestParseDNSZone_Wildcard(t *testing.T) {
	cfg := DefaultConfig()
	z, err := ParseDNSZone("testdata/example.com.dnszone", cfg)
	if err != nil {
		t.Fatalf("ParseDNSZone() error = %v", err)
	}

	// Check wildcard exists
	wildcard := z.GetRecords("*.example.com.", dns.TypeA)
	if len(wildcard) != 1 {
		t.Fatalf("Expected 1 wildcard A record, got %d", len(wildcard))
	}

	// Check wildcard matches random names
	random := z.GetRecords("random-subdomain.example.com.", dns.TypeA)
	if len(random) == 0 {
		t.Error("Wildcard should match random-subdomain.example.com")
	}
}

func TestParseDNSZone_CustomTTL(t *testing.T) {
	cfg := DefaultConfig()
	z, err := ParseDNSZone("testdata/example.com.dnszone", cfg)
	if err != nil {
		t.Fatalf("ParseDNSZone() error = %v", err)
	}

	// mail2 has custom TTL of 7200
	mail2 := z.GetRecords("mail2.example.com.", dns.TypeA)
	if len(mail2) != 1 {
		t.Fatalf("Expected 1 A record for mail2, got %d", len(mail2))
	}

	if mail2[0].Header().Ttl != 7200 {
		t.Errorf("mail2 TTL = %d, want 7200", mail2[0].Header().Ttl)
	}
}

func TestParseDNSZone_Validation(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Strict = true

	z, err := ParseDNSZone("testdata/example.com.dnszone", cfg)
	if err != nil {
		t.Fatalf("ParseDNSZone() error = %v (validation should pass)", err)
	}

	// Manually validate again
	err = z.Validate()
	if err != nil {
		t.Errorf("Validate() error = %v", err)
	}
}

func TestParseDNSZone_LegacyFormat(t *testing.T) {
	cfg := DefaultConfig()
	z, err := ParseDNSZone("testdata/legacy.dnszone", cfg)
	if err != nil {
		t.Fatalf("ParseDNSZone() legacy format error = %v", err)
	}

	if z.Name != "legacy.example.com." {
		t.Errorf("Zone name = %s, want legacy.example.com.", z.Name)
	}

	if z.SOA == nil {
		t.Fatal("Zone has no SOA record")
	}

	if z.SOA.Ns != "ns1.example.com." {
		t.Errorf("SOA primary = %s, want ns1.example.com.", z.SOA.Ns)
	}

	// admin field uses dot notation — should pass through as-is
	if z.SOA.Mbox != "hostmaster.legacy.example.com." {
		t.Errorf("SOA mbox = %s, want hostmaster.legacy.example.com.", z.SOA.Mbox)
	}

	if z.SOA.Serial != 2024010100 {
		t.Errorf("SOA serial = %d, want 2024010100", z.SOA.Serial)
	}

	if z.SOA.Refresh != 3600 {
		t.Errorf("SOA refresh = %d, want 3600", z.SOA.Refresh)
	}

	if z.SOA.Retry != 600 {
		t.Errorf("SOA retry = %d, want 600", z.SOA.Retry)
	}

	if z.SOA.Expire != 604800 {
		t.Errorf("SOA expire = %d, want 604800", z.SOA.Expire)
	}

	if z.SOA.Minttl != 1800 {
		t.Errorf("SOA minimum = %d, want 1800", z.SOA.Minttl)
	}

	// Nameservers list should be injected as NS records at the apex
	ns := z.GetNameservers()
	if len(ns) != 2 {
		t.Fatalf("Expected 2 NS records, got %d", len(ns))
	}
	nsNames := map[string]bool{}
	for _, n := range ns {
		nsNames[n.Ns] = true
	}
	if !nsNames["ns1.example.com."] {
		t.Error("Missing ns1.example.com")
	}
	if !nsNames["ns2.example.com."] {
		t.Error("Missing ns2.example.com")
	}

	// Top-level ttl: 300 should be used as default TTL
	aRecords := z.GetRecords("legacy.example.com.", dns.TypeA)
	if len(aRecords) != 1 {
		t.Fatalf("Expected 1 apex A record, got %d", len(aRecords))
	}
	a := aRecords[0].(*dns.A)
	if !a.A.Equal(net.ParseIP("192.0.2.1")) {
		t.Errorf("apex A = %v, want 192.0.2.1", a.A)
	}
	if a.Hdr.Ttl != 300 {
		t.Errorf("apex A TTL = %d, want 300", a.Hdr.Ttl)
	}
}

func TestParseDNSZone_MissingFile(t *testing.T) {
	cfg := DefaultConfig()
	_, err := ParseDNSZone("testdata/nonexistent.dnszone", cfg)
	if err == nil {
		t.Error("ParseDNSZone() should error for missing file")
	}
}

func TestParseDuration(t *testing.T) {
	tests := []struct {
		input string
		want  time.Duration
	}{
		{"1h", 1 * time.Hour},
		{"30m", 30 * time.Minute},
		{"2h", 2 * time.Hour},
		{"1d", 24 * time.Hour},
		{"2w", 14 * 24 * time.Hour},
		{"90s", 90 * time.Second},
		// Uppercase variants
		{"1H", 1 * time.Hour},
		{"30M", 30 * time.Minute},
		{"1D", 24 * time.Hour},
		{"2W", 14 * 24 * time.Hour},
		{"90S", 90 * time.Second},
	}

	for _, tt := range tests {
		got, err := parseDuration(tt.input)
		if err != nil {
			t.Errorf("parseDuration(%q) error = %v", tt.input, err)
			continue
		}
		if got != tt.want {
			t.Errorf("parseDuration(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestParseTime(t *testing.T) {
	tests := []struct {
		input string
		want  uint32
	}{
		{"1h", 3600},
		{"2h", 7200},
		{"30m", 1800},
		{"1d", 86400},
		{"2w", 1209600},
		{"3600", 3600}, // Raw seconds
	}

	for _, tt := range tests {
		got, err := parseTime(tt.input)
		if err != nil {
			t.Errorf("parseTime(%q) error = %v", tt.input, err)
			continue
		}
		if got != tt.want {
			t.Errorf("parseTime(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestFormatEmailAddress(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"admin@example.com", "admin.example.com."},
		{"hostmaster@example.org", "hostmaster.example.org."},
		{"john.doe@example.com", "john.doe.example.com."},
	}

	for _, tt := range tests {
		got := formatEmailAddress(tt.input)
		if got != tt.want {
			t.Errorf("formatEmailAddress(%q) = %s, want %s", tt.input, got, tt.want)
		}
	}
}

func TestDNSSECAlgorithm(t *testing.T) {
	tests := []struct {
		name string
		want uint8
	}{
		{"RSASHA256", dns.RSASHA256},
		{"RSASHA512", dns.RSASHA512},
		{"ECDSAP256SHA256", dns.ECDSAP256SHA256},
		{"ECDSAP384SHA384", dns.ECDSAP384SHA384},
		{"ED25519", dns.ED25519},
		{"unknown", dns.ECDSAP256SHA256}, // Default
	}

	for _, tt := range tests {
		got := dnssecAlgorithm(tt.name)
		if got != tt.want {
			t.Errorf("dnssecAlgorithm(%q) = %d, want %d", tt.name, got, tt.want)
		}
	}
}

func BenchmarkParseDNSZone(b *testing.B) {
	cfg := DefaultConfig()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseDNSZone("testdata/example.com.dnszone", cfg)
	}
}
