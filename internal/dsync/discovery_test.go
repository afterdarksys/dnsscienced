package dsync

import (
	"context"
	"encoding/hex"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// newDSYNCRFC3597 creates a *dns.RFC3597 record for use in mock DNS responses.
func newDSYNCRFC3597(rrtype uint16, scheme uint8, port uint16, target string, owner string) (*dns.RFC3597, error) {
	rec := DSYNCRecord{RRtype: rrtype, Scheme: scheme, Port: port, Target: target}
	rdata, err := EncodeDSYNC(rec)
	if err != nil {
		return nil, err
	}
	return &dns.RFC3597{
		Hdr: dns.RR_Header{
			Name:     owner,
			Rrtype:   TypeDSYNC,
			Class:    dns.ClassINET,
			Ttl:      3600,
			Rdlength: uint16(len(rdata) / 2),
		},
		Rdata: rdata,
	}, nil
}

// startMockDNSServer starts a UDP DNS server that responds to every query
// using the provided handler function. Returns the address and a stop function.
func startMockDNSServer(t *testing.T, handler func(*dns.Msg) *dns.Msg) (string, func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			req := new(dns.Msg)
			if err := req.Unpack(buf[:n]); err != nil {
				continue
			}
			resp := handler(req)
			if resp == nil {
				continue
			}
			resp.SetReply(req)
			b, err := resp.Pack()
			if err != nil {
				continue
			}
			pc.WriteTo(b, addr) //nolint:errcheck
		}
	}()

	addr := pc.LocalAddr().String()
	stop := func() {
		pc.Close()
		<-done
	}
	return addr, stop
}

// TestDiscoverDSYNC_Found verifies that DiscoverDSYNC returns a non-empty slice
// when the mock resolver returns a DSYNC record for _dsync.<delegation>.
func TestDiscoverDSYNC_Found(t *testing.T) {
	rfc, err := newDSYNCRFC3597(dns.TypeCDS, DSYNCSchemeNOTIFY, 5359, "scanner.example.net.", "_dsync.child.example.com.")
	if err != nil {
		t.Fatalf("encode DSYNC: %v", err)
	}

	resolver, stop := startMockDNSServer(t, func(req *dns.Msg) *dns.Msg {
		resp := new(dns.Msg)
		resp.Answer = append(resp.Answer, rfc)
		return resp
	})
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := &dns.Client{Net: "udp", Timeout: 2 * time.Second}
	records, err := DiscoverDSYNC(ctx, "child.example.com.", client, resolver)
	if err != nil {
		t.Fatalf("DiscoverDSYNC returned error: %v", err)
	}
	if len(records) == 0 {
		t.Fatal("expected at least one DSYNC record, got none")
	}
	if records[0].RRtype != dns.TypeCDS {
		t.Errorf("expected RRtype CDS(%d), got %d", dns.TypeCDS, records[0].RRtype)
	}
	if records[0].Port != 5359 {
		t.Errorf("expected Port 5359, got %d", records[0].Port)
	}
}

// TestDiscoverDSYNC_NotFound verifies that DiscoverDSYNC returns an empty slice
// and nil error when the mock resolver returns NXDOMAIN for all candidates.
func TestDiscoverDSYNC_NotFound(t *testing.T) {
	resolver, stop := startMockDNSServer(t, func(req *dns.Msg) *dns.Msg {
		resp := new(dns.Msg)
		resp.Rcode = dns.RcodeNameError // NXDOMAIN
		return resp
	})
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := &dns.Client{Net: "udp", Timeout: 2 * time.Second}
	records, err := DiscoverDSYNC(ctx, "child.example.com.", client, resolver)
	if err != nil {
		t.Fatalf("DiscoverDSYNC returned unexpected error: %v", err)
	}
	if len(records) != 0 {
		t.Errorf("expected empty slice, got %d records", len(records))
	}
}

// TestDiscoverDSYNC_MultipleRecords verifies that DiscoverDSYNC returns all DSYNC
// records when the answer section contains multiple TYPE66 RRs.
func TestDiscoverDSYNC_MultipleRecords(t *testing.T) {
	rfc1, err := newDSYNCRFC3597(dns.TypeCDS, DSYNCSchemeNOTIFY, 53, "cds-scan.example.net.", "_dsync.child.example.com.")
	if err != nil {
		t.Fatalf("encode DSYNC 1: %v", err)
	}
	rfc2, err := newDSYNCRFC3597(dns.TypeCSYNC, DSYNCSchemeNOTIFY, 53, "csync-scan.example.net.", "_dsync.child.example.com.")
	if err != nil {
		t.Fatalf("encode DSYNC 2: %v", err)
	}

	resolver, stop := startMockDNSServer(t, func(req *dns.Msg) *dns.Msg {
		resp := new(dns.Msg)
		resp.Answer = append(resp.Answer, rfc1, rfc2)
		return resp
	})
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := &dns.Client{Net: "udp", Timeout: 2 * time.Second}
	records, err := DiscoverDSYNC(ctx, "child.example.com.", client, resolver)
	if err != nil {
		t.Fatalf("DiscoverDSYNC returned error: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 DSYNC records, got %d", len(records))
	}
	types := map[uint16]bool{records[0].RRtype: true, records[1].RRtype: true}
	if !types[dns.TypeCDS] || !types[dns.TypeCSYNC] {
		t.Errorf("expected CDS and CSYNC records, got %v", types)
	}
}

// TestDiscoverDSYNC_MaxLabels verifies that DiscoverDSYNC traverses parent labels
// when deeper candidates return no records. A 3-label delegation should try
// _dsync.a.b.c. and then _dsync.b.c.
func TestDiscoverDSYNC_MaxLabels(t *testing.T) {
	rfc, err := newDSYNCRFC3597(dns.TypeCDS, DSYNCSchemeNOTIFY, 53, "scan.example.net.", "_dsync.b.example.com.")
	if err != nil {
		t.Fatalf("encode DSYNC: %v", err)
	}

	// Server returns NXDOMAIN for _dsync.a.b.example.com. but
	// returns a DSYNC record for _dsync.b.example.com.
	resolver, stop := startMockDNSServer(t, func(req *dns.Msg) *dns.Msg {
		resp := new(dns.Msg)
		if len(req.Question) > 0 && req.Question[0].Name == "_dsync.b.example.com." {
			resp.Answer = append(resp.Answer, rfc)
		} else {
			resp.Rcode = dns.RcodeNameError
		}
		return resp
	})
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := &dns.Client{Net: "udp", Timeout: 2 * time.Second}
	records, err := DiscoverDSYNC(ctx, "a.b.example.com.", client, resolver)
	if err != nil {
		t.Fatalf("DiscoverDSYNC returned error: %v", err)
	}
	if len(records) == 0 {
		t.Fatal("expected at least one DSYNC record from parent label traversal, got none")
	}
}

// TestDiscoverDSYNC_MalformedRecord verifies that malformed DSYNC records in the
// answer section are silently skipped (not returned, not an error).
func TestDiscoverDSYNC_MalformedRecord(t *testing.T) {
	// Build an RFC3597 with an invalid (too-short) rdata.
	malformed := &dns.RFC3597{
		Hdr: dns.RR_Header{
			Name:   "_dsync.child.example.com.",
			Rrtype: TypeDSYNC,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		Rdata: hex.EncodeToString([]byte{0x00, 0x3B}), // Only 2 bytes — too short
	}

	resolver, stop := startMockDNSServer(t, func(req *dns.Msg) *dns.Msg {
		resp := new(dns.Msg)
		resp.Answer = append(resp.Answer, malformed)
		return resp
	})
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := &dns.Client{Net: "udp", Timeout: 2 * time.Second}
	records, err := DiscoverDSYNC(ctx, "child.example.com.", client, resolver)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Malformed record should be silently skipped; empty result expected.
	if len(records) != 0 {
		t.Errorf("expected 0 records (malformed skipped), got %d", len(records))
	}
}
