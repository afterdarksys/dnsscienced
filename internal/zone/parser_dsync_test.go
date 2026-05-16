package zone

import (
	"os"
	"testing"

	"github.com/dnsscience/dnsscienced/internal/dsync"
	"github.com/miekg/dns"
)

// TestDSYNCZoneFile_BIND verifies that a BIND-format zone file containing a
// TYPE66 (DSYNC) record loads correctly and the record is accessible via
// GetRecords. This satisfies DSYNC-09.
func TestDSYNCZoneFile_BIND(t *testing.T) {
	// Zone file with SOA, NS, A glue, and one TYPE66 at _dsync.example.com.
	// Hex: 003b0100350161016200
	//   003b = 59 (CDS), 01 = NOTIFY, 0035 = 53, 0161016200 = wire "a.b." (01='a',01='b',00=root)
	zoneContent := `$ORIGIN example.com.
$TTL 3600
@ IN SOA ns1.example.com. hostmaster.example.com. 2026010101 3600 900 604800 300
@ IN NS ns1.example.com.
ns1 IN A 192.0.2.1
_dsync IN TYPE66 \# 10 003b0100350161016200
`

	// Write zone file to a temp file
	tmpFile, err := os.CreateTemp(t.TempDir(), "dsync-*.bind")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	defer tmpFile.Close()

	if _, err := tmpFile.WriteString(zoneContent); err != nil {
		t.Fatalf("WriteString: %v", err)
	}
	tmpFile.Close()

	// Parse the zone file
	z, err := ParseBIND(tmpFile.Name(), "example.com.", DefaultConfig())
	if err != nil {
		t.Fatalf("ParseBIND() error = %v", err)
	}
	if z == nil {
		t.Fatal("ParseBIND() returned nil zone")
	}

	// Retrieve the TYPE66 records by owner + type
	records := z.GetRecords("_dsync.example.com.", dsync.TypeDSYNC)
	if len(records) != 1 {
		t.Fatalf("GetRecords(_dsync.example.com., TypeDSYNC) returned %d records, want 1", len(records))
	}

	// The record should be stored as *dns.RFC3597 (unknown type fallback)
	r3, ok := records[0].(*dns.RFC3597)
	if !ok {
		t.Fatalf("record is %T, want *dns.RFC3597", records[0])
	}
	if r3.Hdr.Rrtype != 66 {
		t.Errorf("Hdr.Rrtype = %d, want 66", r3.Hdr.Rrtype)
	}

	// Decode and validate the DSYNC RDATA
	rec, err := dsync.DecodeDSYNC(r3.Rdata)
	if err != nil {
		t.Fatalf("DecodeDSYNC() error = %v", err)
	}
	if rec.RRtype != dns.TypeCDS {
		t.Errorf("RRtype = %d, want %d (CDS)", rec.RRtype, dns.TypeCDS)
	}
	if rec.Scheme != dsync.DSYNCSchemeNOTIFY {
		t.Errorf("Scheme = %d, want %d (NOTIFY)", rec.Scheme, dsync.DSYNCSchemeNOTIFY)
	}
	if rec.Port != 53 {
		t.Errorf("Port = %d, want 53", rec.Port)
	}
}

// TestDSYNCZoneFile_MultipleRecords verifies that multiple TYPE66 records at the
// same owner name are all returned by GetRecords.
func TestDSYNCZoneFile_MultipleRecords(t *testing.T) {
	// Two TYPE66 records:
	//   003b... = CDS (59), NOTIFY, port 53, target a.b.
	//   003e... = CSYNC (62), NOTIFY, port 53, target a.b.
	zoneContent := `$ORIGIN example.com.
$TTL 3600
@ IN SOA ns1.example.com. hostmaster.example.com. 2026010101 3600 900 604800 300
@ IN NS ns1.example.com.
ns1 IN A 192.0.2.1
_dsync IN TYPE66 \# 10 003b0100350161016200
_dsync IN TYPE66 \# 10 003e0100350161016200
`

	tmpFile, err := os.CreateTemp(t.TempDir(), "dsync-multi-*.bind")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	defer tmpFile.Close()

	if _, err := tmpFile.WriteString(zoneContent); err != nil {
		t.Fatalf("WriteString: %v", err)
	}
	tmpFile.Close()

	z, err := ParseBIND(tmpFile.Name(), "example.com.", DefaultConfig())
	if err != nil {
		t.Fatalf("ParseBIND() error = %v", err)
	}

	records := z.GetRecords("_dsync.example.com.", dsync.TypeDSYNC)
	if len(records) != 2 {
		t.Fatalf("GetRecords(_dsync.example.com., TypeDSYNC) returned %d records, want 2", len(records))
	}
}
