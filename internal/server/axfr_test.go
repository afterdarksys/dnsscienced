package server

import (
	"crypto/tls"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/dnsscience/dnsscienced/internal/zone"
	"github.com/miekg/dns"
)

// axfrTestResponseWriter is a dns.ResponseWriter for AXFR tests.
// It accumulates all WriteMsg calls into a msgs slice (deep-copy).
// Its RemoteAddr is *net.TCPAddr by default (AXFR is TCP).
type axfrTestResponseWriter struct {
	msgs       []dns.Msg
	tsigStatus error
	closed     bool
	remoteAddr net.Addr
	tlsState   *tls.ConnectionState
}

// newAXFRTestWriter creates a TCP-backed test writer for the given IP.
func newAXFRTestWriter(ip string) *axfrTestResponseWriter {
	return &axfrTestResponseWriter{
		remoteAddr: &net.TCPAddr{IP: net.ParseIP(ip), Port: 12345},
	}
}

// newAXFRTestWriterUDP creates a UDP-backed test writer (for UDP truncation test).
func newAXFRTestWriterUDP(ip string) *axfrTestResponseWriter {
	return &axfrTestResponseWriter{
		remoteAddr: &net.UDPAddr{IP: net.ParseIP(ip), Port: 12345},
	}
}

func (w *axfrTestResponseWriter) LocalAddr() net.Addr  { return &net.TCPAddr{} }
func (w *axfrTestResponseWriter) RemoteAddr() net.Addr { return w.remoteAddr }
func (w *axfrTestResponseWriter) WriteMsg(m *dns.Msg) error {
	// Deep-copy so that pool.PutMessage resets don't clobber captured values.
	w.msgs = append(w.msgs, *m.Copy())
	return nil
}
func (w *axfrTestResponseWriter) Write(b []byte) (int, error) { return len(b), nil }
func (w *axfrTestResponseWriter) Close() error                { w.closed = true; return nil }
func (w *axfrTestResponseWriter) TsigStatus() error           { return w.tsigStatus }
func (w *axfrTestResponseWriter) TsigTimersOnly(b bool)       {}
func (w *axfrTestResponseWriter) Hijack()                     {}
func (w *axfrTestResponseWriter) ConnectionState() *tls.ConnectionState {
	return w.tlsState
}

// testZone returns a minimal valid zone for AXFR testing.
func testZone() *zone.Zone {
	return &zone.Zone{
		Name:   "example.com",
		Origin: "example.com.",
		Class:  dns.ClassINET,
		SOA: &dns.SOA{
			Hdr:     dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
			Ns:      "ns1.example.com.",
			Mbox:    "admin.example.com.",
			Serial:  2024010101,
			Refresh: 3600, Retry: 900, Expire: 604800, Minttl: 86400,
		},
		Records: map[string]map[uint16][]dns.RR{
			"example.com.": {
				dns.TypeNS: {
					&dns.NS{
						Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600},
						Ns:  "ns1.example.com.",
					},
				},
			},
			"ns1.example.com.": {
				dns.TypeA: {
					&dns.A{
						Hdr: dns.RR_Header{Name: "ns1.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
						A:   net.ParseIP("192.0.2.1"),
					},
				},
			},
		},
	}
}

// makeAXFRRequest creates an AXFR query for the given zone name.
func makeAXFRRequest(qname string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(qname, dns.TypeAXFR)
	return m
}

// testServerWithAXFR creates a minimal Server configured for AXFR testing.
// allowTransfer is the CIDR list for example.com.; pass nil for no-entry,
// or []string{} for empty-entry (D-01 secure-by-default), or real CIDRs.
func testServerWithAXFR(allowTransfer []string) (*Server, error) {
	zones := map[string]*zone.Zone{
		"example.com.": testZone(),
	}
	var xferCIDRs map[string][]string
	if allowTransfer != nil {
		xferCIDRs = map[string][]string{
			"example.com.": allowTransfer,
		}
	}
	cfg := Config{
		Zones:             zones,
		ZoneTransferCIDRs: xferCIDRs,
		UDPListeners:      1,
	}
	return New(cfg)
}

// TestHandleAXFR_UDPTruncation verifies that an AXFR over UDP gets TC=1,
// not REFUSED (RFC 5936 D-08).
func TestHandleAXFR_UDPTruncation(t *testing.T) {
	s, err := testServerWithAXFR([]string{"0.0.0.0/0"})
	if err != nil {
		t.Fatalf("testServerWithAXFR: %v", err)
	}
	defer s.Stop() //nolint:errcheck

	w := newAXFRTestWriterUDP("192.0.2.100")
	r := makeAXFRRequest("example.com.")
	// Give it a TSIG so it passes TSIG checks (if transport check were bypassed).
	r.SetTsig("test.", dns.HmacSHA256, 300, time.Now().Unix())

	s.handleAXFR(w, r, net.ParseIP("192.0.2.100"))

	if len(w.msgs) == 0 {
		t.Fatal("no response written")
	}
	if !w.msgs[0].Truncated {
		t.Errorf("Truncated = false, want true for UDP AXFR")
	}
	if w.msgs[0].Rcode != dns.RcodeSuccess {
		t.Errorf("Rcode = %d, want %d (Success with TC=1 on UDP)", w.msgs[0].Rcode, dns.RcodeSuccess)
	}
}

// TestHandleAXFR_NoTSIG_NotAuth verifies that a TCP AXFR with no TSIG returns NOTAUTH (rcode 9).
func TestHandleAXFR_NoTSIG_NotAuth(t *testing.T) {
	s, err := testServerWithAXFR([]string{"0.0.0.0/0"})
	if err != nil {
		t.Fatalf("testServerWithAXFR: %v", err)
	}
	defer s.Stop() //nolint:errcheck

	w := newAXFRTestWriter("192.0.2.100")
	r := makeAXFRRequest("example.com.")
	// No TSIG added — r.IsTsig() == nil.

	s.handleAXFR(w, r, net.ParseIP("192.0.2.100"))

	if len(w.msgs) == 0 {
		t.Fatal("no response written")
	}
	if w.msgs[0].Rcode != dns.RcodeNotAuth {
		t.Errorf("Rcode = %d, want %d (NOTAUTH)", w.msgs[0].Rcode, dns.RcodeNotAuth)
	}
}

// TestHandleAXFR_BadTSIG_NotAuth verifies that a TCP AXFR with a bad TSIG returns NOTAUTH (rcode 9).
func TestHandleAXFR_BadTSIG_NotAuth(t *testing.T) {
	s, err := testServerWithAXFR([]string{"0.0.0.0/0"})
	if err != nil {
		t.Fatalf("testServerWithAXFR: %v", err)
	}
	defer s.Stop() //nolint:errcheck

	w := newAXFRTestWriter("192.0.2.100")
	w.tsigStatus = fmt.Errorf("bad sig") // simulate failed TSIG verification
	r := makeAXFRRequest("example.com.")
	// Add a TSIG RR so r.IsTsig() != nil (presence check passes).
	r.SetTsig("test.", dns.HmacSHA256, 300, time.Now().Unix())

	s.handleAXFR(w, r, net.ParseIP("192.0.2.100"))

	if len(w.msgs) == 0 {
		t.Fatal("no response written")
	}
	if w.msgs[0].Rcode != dns.RcodeNotAuth {
		t.Errorf("Rcode = %d, want %d (NOTAUTH)", w.msgs[0].Rcode, dns.RcodeNotAuth)
	}
}

// TestHandleAXFR_IPNotAllowed_Refused verifies that a valid TSIG but disallowed
// source IP results in REFUSED (D-03).
func TestHandleAXFR_IPNotAllowed_Refused(t *testing.T) {
	// allow_transfer only allows 192.168.1.0/24; client is 10.0.0.1
	s, err := testServerWithAXFR([]string{"192.168.1.0/24"})
	if err != nil {
		t.Fatalf("testServerWithAXFR: %v", err)
	}
	defer s.Stop() //nolint:errcheck

	w := newAXFRTestWriter("10.0.0.1")
	// tsigStatus nil = valid TSIG
	r := makeAXFRRequest("example.com.")
	r.SetTsig("test.", dns.HmacSHA256, 300, time.Now().Unix())

	s.handleAXFR(w, r, net.ParseIP("10.0.0.1"))

	if len(w.msgs) == 0 {
		t.Fatal("no response written")
	}
	if w.msgs[0].Rcode != dns.RcodeRefused {
		t.Errorf("Rcode = %d, want %d (REFUSED)", w.msgs[0].Rcode, dns.RcodeRefused)
	}
}

// TestHandleAXFR_NonExistentZone_Refused verifies that an AXFR for an unknown zone
// returns REFUSED.
func TestHandleAXFR_NonExistentZone_Refused(t *testing.T) {
	s, err := testServerWithAXFR([]string{"0.0.0.0/0"})
	if err != nil {
		t.Fatalf("testServerWithAXFR: %v", err)
	}
	defer s.Stop() //nolint:errcheck

	w := newAXFRTestWriter("192.0.2.100")
	r := makeAXFRRequest("notfound.com.") // not in cfg.Zones
	r.SetTsig("test.", dns.HmacSHA256, 300, time.Now().Unix())

	s.handleAXFR(w, r, net.ParseIP("192.0.2.100"))

	if len(w.msgs) == 0 {
		t.Fatal("no response written")
	}
	if w.msgs[0].Rcode != dns.RcodeRefused {
		t.Errorf("Rcode = %d, want %d (REFUSED)", w.msgs[0].Rcode, dns.RcodeRefused)
	}
}

// TestHandleAXFR_EmptyAllowTransfer_Refused verifies the D-01 secure-by-default rule:
// an empty allow_transfer list means REFUSED (deny all).
func TestHandleAXFR_EmptyAllowTransfer_Refused(t *testing.T) {
	// Empty slice: zone entry exists but no CIDRs → ACL should be nil → REFUSED.
	s, err := testServerWithAXFR([]string{})
	if err != nil {
		t.Fatalf("testServerWithAXFR: %v", err)
	}
	defer s.Stop() //nolint:errcheck

	w := newAXFRTestWriter("192.0.2.100")
	r := makeAXFRRequest("example.com.")
	r.SetTsig("test.", dns.HmacSHA256, 300, time.Now().Unix())

	s.handleAXFR(w, r, net.ParseIP("192.0.2.100"))

	if len(w.msgs) == 0 {
		t.Fatal("no response written")
	}
	if w.msgs[0].Rcode != dns.RcodeRefused {
		t.Errorf("Rcode = %d, want %d (REFUSED)", w.msgs[0].Rcode, dns.RcodeRefused)
	}
}

// TestHandleAXFR_Success_StreamsSOA verifies that when all guards pass, the
// transfer runs (Close() is called on the writer, signaling Transfer.Out completed).
// Full TCP framing is not tested here since dns.Transfer.Out requires real TCP.
// The unit test validates the guard chain passes and transfer is initiated.
func TestHandleAXFR_Success_StreamsSOA(t *testing.T) {
	s, err := testServerWithAXFR([]string{"0.0.0.0/0"})
	if err != nil {
		t.Fatalf("testServerWithAXFR: %v", err)
	}
	defer s.Stop() //nolint:errcheck

	w := newAXFRTestWriter("192.0.2.100")
	// tsigStatus nil = valid TSIG
	r := makeAXFRRequest("example.com.")
	r.SetTsig("test.", dns.HmacSHA256, 300, time.Now().Unix())

	s.handleAXFR(w, r, net.ParseIP("192.0.2.100"))

	// Transfer.Out will fail on mock writer (no TCP framing), but all guards pass.
	// Verify that Close() was called — this signals the transfer path was entered
	// (not an early REFUSED/NOTAUTH return).
	if !w.closed {
		t.Error("w.Close() was not called — transfer path was not entered (early guard rejection?)")
	}
}

func TestHandleAXFR_MixedCaseZoneName(t *testing.T) {
	s, err := testServerWithAXFR([]string{"0.0.0.0/0"})
	if err != nil {
		t.Fatalf("testServerWithAXFR: %v", err)
	}
	defer s.Stop() //nolint:errcheck
	w := newAXFRTestWriter("192.0.2.100")
	r := makeAXFRRequest("ExAmPlE.CoM.")
	r.SetTsig("test.", dns.HmacSHA256, 300, time.Now().Unix())
	s.handleAXFR(w, r, net.ParseIP("192.0.2.100"))
	if !w.closed {
		t.Fatal("mixed-case AXFR name was not normalized")
	}
}

func TestHandleIXFR_HonorsDisabledAXFRFallback(t *testing.T) {
	s, err := testServerWithAXFR([]string{"0.0.0.0/0"})
	if err != nil {
		t.Fatalf("testServerWithAXFR: %v", err)
	}
	defer s.Stop() //nolint:errcheck
	s.cfg.ZoneAllowAXFRFallback = map[string]bool{"example.com.": false}
	w := newAXFRTestWriter("192.0.2.100")
	r := new(dns.Msg)
	r.SetIxfr("example.com.", 0, "ns1.example.com.", "hostmaster.example.com.")
	r.SetTsig("test.", dns.HmacSHA256, 300, time.Now().Unix())
	s.handleAXFR(w, r, net.ParseIP("192.0.2.100"))
	if len(w.msgs) == 0 || w.msgs[0].Rcode != dns.RcodeNotImplemented {
		t.Fatalf("response=%v, want NOTIMP when AXFR fallback is disabled", w.msgs)
	}
}

func TestHandleIXFRStreamsJournalDelta(t *testing.T) {
	s, err := testServerWithAXFR([]string{"0.0.0.0/0"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Stop() //nolint:errcheck
	s.cfg.ZoneAllowAXFRFallback = map[string]bool{"example.com.": false}

	previous := s.GetZone("example.com.")
	next := previous.Clone()
	next.SOA.Serial++
	txt, _ := dns.NewRR("new.example.com. 300 IN TXT \"added\"")
	if err := next.AddRecord(txt); err != nil {
		t.Fatal(err)
	}
	if err := s.AddZone(next); err != nil {
		t.Fatal(err)
	}

	request := new(dns.Msg)
	request.SetIxfr("example.com.", previous.SOA.Serial, previous.SOA.Ns, previous.SOA.Mbox)
	request.SetTsig("test.", dns.HmacSHA256, 300, time.Now().Unix())
	writer := newAXFRTestWriter("192.0.2.100")
	s.handleAXFR(writer, request, net.ParseIP("192.0.2.100"))

	if len(writer.msgs) == 0 {
		t.Fatal("no IXFR response")
	}
	var records []dns.RR
	for _, msg := range writer.msgs {
		records = append(records, msg.Answer...)
	}
	if len(records) < 5 {
		t.Fatalf("IXFR records=%v", records)
	}
	first := records[0].(*dns.SOA)
	old := records[1].(*dns.SOA)
	last := records[len(records)-1].(*dns.SOA)
	if first.Serial != next.SOA.Serial || old.Serial != previous.SOA.Serial || last.Serial != next.SOA.Serial {
		t.Fatalf("IXFR SOA sequence first=%d old=%d last=%d", first.Serial, old.Serial, last.Serial)
	}
	foundTXT := false
	for _, rr := range records {
		if rr.Header().Rrtype == dns.TypeTXT {
			foundTXT = true
		}
	}
	if !foundTXT {
		t.Fatal("IXFR omitted added TXT record")
	}
}

func TestHandleIXFRSameSerialReturnsSingleSOA(t *testing.T) {
	s, err := testServerWithAXFR([]string{"0.0.0.0/0"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Stop() //nolint:errcheck
	current := s.GetZone("example.com.")
	request := new(dns.Msg)
	request.SetIxfr("example.com.", current.SOA.Serial, current.SOA.Ns, current.SOA.Mbox)
	request.SetTsig("test.", dns.HmacSHA256, 300, time.Now().Unix())
	writer := newAXFRTestWriter("192.0.2.100")
	s.handleAXFR(writer, request, net.ParseIP("192.0.2.100"))

	var records []dns.RR
	for _, msg := range writer.msgs {
		records = append(records, msg.Answer...)
	}
	if len(records) != 1 {
		t.Fatalf("records=%v, want one SOA", records)
	}
	if soa, ok := records[0].(*dns.SOA); !ok || soa.Serial != current.SOA.Serial {
		t.Fatalf("response=%v", records)
	}
}
