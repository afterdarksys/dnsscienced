package server

import (
	"net"
	"sync"

	"github.com/miekg/dns"
)

const axfrBatchSize = 100

// handleAXFR handles RFC 5936 zone transfer (AXFR) requests.
//
// Guard chain (each failure returns immediately with the specified rcode):
//  1. UDP truncation (D-08): return TC=1; no zone data on UDP
//  2. TSIG presence (D-04): absent TSIG → NOTAUTH (rcode 9)
//  3. TSIG validity (D-05): bad/replayed TSIG → NOTAUTH
//  4. Empty question guard → REFUSED
//  5. Zone lookup: unknown zone → REFUSED
//  6. ACL check (D-01, D-03): nil ACL (no allow_transfer) or IP not allowed → REFUSED
//  7. Stream: opening SOA + batched RRs + closing SOA via dns.Transfer.Out
func (s *Server) handleAXFR(w dns.ResponseWriter, r *dns.Msg, clientIP net.IP) {
	// 1. UDP truncation (D-08): signal retry over TCP; do NOT return zone data.
	if _, ok := w.RemoteAddr().(*net.UDPAddr); ok {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Truncated = true
		w.WriteMsg(m) //nolint:errcheck
		return
	}

	// 2. TSIG presence check (D-04): no TSIG record at all → NOTAUTH.
	// This MUST come before the validity check — an absent TSIG yields
	// TsigStatus() == nil, which would incorrectly allow unsigned requests.
	if r.IsTsig() == nil {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeNotAuth
		w.WriteMsg(m) //nolint:errcheck
		return
	}

	// 3. TSIG validity check (D-05): bad key, bad sig, replay attack.
	if w.TsigStatus() != nil {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeNotAuth
		w.WriteMsg(m) //nolint:errcheck
		return
	}

	// 4. Empty question guard.
	if len(r.Question) == 0 {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeRefused
		w.WriteMsg(m) //nolint:errcheck
		return
	}

	// 5. Zone lookup.
	qname := r.Question[0].Name
	z, ok := s.cfg.Zones[qname]
	if !ok {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeRefused
		w.WriteMsg(m) //nolint:errcheck
		return
	}

	// 6. ACL check (D-01, D-03):
	//    nil ACL = no allow_transfer configured = deny all (secure-by-default).
	//    non-nil ACL = source IP must be in the allowlist.
	acl := s.zoneTransferACLs[qname]
	if acl == nil || !acl.Check(clientIP) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeRefused
		w.WriteMsg(m) //nolint:errcheck
		return
	}

	// 7. Multi-message streaming (D-09) via dns.Transfer.Out.
	//    RFC 5936 §2.2: opening SOA, middle RRs, closing SOA.
	ch := make(chan *dns.Envelope)
	tr := new(dns.Transfer)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		tr.Out(w, r, ch) //nolint:errcheck
		wg.Done()
	}()

	// Opening SOA (RFC 5936 §2.2)
	ch <- &dns.Envelope{RR: []dns.RR{z.SOA}}

	// Middle: all zone RRs — exclude SOA because all production loaders
	// (ParseDNSZone, ParseBIND, LoadCompiledZone) call AddRecord for the SOA,
	// placing it in both z.SOA and z.Records.  Sending it again here would
	// produce a malformed transfer (RFC 5936 §2.2 forbids extra SOAs in the
	// middle section).
	allRRs := z.GetAllRecords()
	var rrs []dns.RR
	for _, rr := range allRRs {
		if rr.Header().Rrtype != dns.TypeSOA {
			rrs = append(rrs, rr)
		}
	}
	for i := 0; i < len(rrs); i += axfrBatchSize {
		end := i + axfrBatchSize
		if end > len(rrs) {
			end = len(rrs)
		}
		ch <- &dns.Envelope{RR: rrs[i:end]}
	}

	// Closing SOA (RFC 5936 §2.2)
	ch <- &dns.Envelope{RR: []dns.RR{z.SOA}}
	close(ch)
	wg.Wait()
	w.Close() //nolint:errcheck
}
