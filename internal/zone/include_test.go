package zone

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/miekg/dns"
)

func TestParseInclude(t *testing.T) {
	incContent := `
records:
  '@':
    TXT:
      - "v=spf1 include:_spf.google.com ~all"
  _dmarc:
    TXT:
      - "v=DMARC1; p=quarantine"
`
	// Create a temporary directory so both the main zone file and the include
	// file reside in the same directory. The include is referenced by basename
	// (relative path) to satisfy the absolute-path guard.
	dir, err := os.MkdirTemp("", "zone-include-test-*")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	defer os.RemoveAll(dir)

	incPath := filepath.Join(dir, "include.dnszone.inc")
	if err := os.WriteFile(incPath, []byte(incContent), 0600); err != nil {
		t.Fatalf("write include file: %v", err)
	}

	mainContent := `
zone:
  name: test.example.com
  ttl: 300
soa:
  primary_ns: ns1.test.example.com
  contact: hostmaster@test.example.com
  serial: auto
  refresh: 3600
  retry: 600
  expire: 604800
  negative_ttl: 1800
includes:
  - include.dnszone.inc
records:
  '@':
    A: 1.2.3.4
`

	mainPath := filepath.Join(dir, "zone.dnszone")
	if err := os.WriteFile(mainPath, []byte(mainContent), 0600); err != nil {
		t.Fatalf("write main zone file: %v", err)
	}

	z, err := ParseDNSZone(mainPath, Config{DefaultTTL: 300})
	if err != nil {
		t.Fatal(err)
	}

	var txtCount int
	for _, typeMap := range z.Records {
		txtCount += len(typeMap[dns.TypeTXT])
	}
	if txtCount != 2 {
		t.Errorf("expected 2 TXT records from include, got %d", txtCount)
		for owner, typeMap := range z.Records {
			for rrtype, rrs := range typeMap {
				for _, rr := range rrs {
					t.Logf("  %s type=%d %s", owner, rrtype, rr)
				}
			}
		}
	}
}
