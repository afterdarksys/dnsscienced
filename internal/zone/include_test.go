package zone

import (
	"os"
	"strings"
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
	mainTemplate := `
zone:
  name: test.example.com
  ttl: 300
serial: auto
soa:
  primary_ns: ns1.test.example.com
  contact: hostmaster@test.example.com
  refresh: 3600
  retry: 600
  expire: 604800
  negative_ttl: 1800
includes:
  - INC_PATH
records:
  '@':
    A: 1.2.3.4
`
	incFile, _ := os.CreateTemp("", "*.dnszone.inc")
	incFile.WriteString(incContent)
	incFile.Close()
	defer os.Remove(incFile.Name())

	mainContent := strings.ReplaceAll(mainTemplate, "INC_PATH", incFile.Name())

	zoneFile, _ := os.CreateTemp("", "*.dnszone")
	zoneFile.WriteString(mainContent)
	zoneFile.Close()
	defer os.Remove(zoneFile.Name())

	z, err := ParseDNSZone(zoneFile.Name(), Config{DefaultTTL: 300})
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
