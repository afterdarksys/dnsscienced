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

	// 7. Nil SOA guard: LoadZone does not call Validate(), so a zone file with a
	//    missing or unparseable SOA may arrive here with z.SOA == nil.  Sending a
	//    nil concrete pointer as a dns.RR interface panics inside dns.Transfer.Out.
	if z.SOA == nil {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeServerFailure
		w.WriteMsg(m) //nolint:errcheck
		return
	}

	// 8. Multi-message streaming (D-09) via dns.Transfer.Out.
	//    RFC 5936 §2.2: opening SOA, middle RRs, closing SOA.
	//
	//    errCh is buffered so tr.Out can exit without blocking on the send,
	//    even if we are still inside the select below.  The send() helper
	//    aborts the loop and lets the caller drain wg if tr.Out exits early
	//    (e.g. TCP connection closed by peer), preventing a goroutine leak on
	//    an unbuffered ch.
	ch := make(chan *dns.Envelope)
	errCh := make(chan error, 1)
	tr := new(dns.Transfer)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		errCh <- tr.Out(w, r, ch)
		wg.Done()
	}()

	// send transmits one envelope; returns false if tr.Out exited early.
	send := func(env *dns.Envelope) bool {
		select {
		case ch <- env:
			return true
		case <-errCh:
			// tr.Out exited; abort send loop to avoid blocking forever.
			return false
		}
	}

	// Opening SOA (RFC 5936 §2.2)
	if !send(&dns.Envelope{RR: []dns.RR{z.SOA}}) {
		close(ch)
		wg.Wait()
		return
	}

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
	aborted := false
	for i := 0; i < len(rrs); i += axfrBatchSize {
		end := i + axfrBatchSize
		if end > len(rrs) {
			end = len(rrs)
		}
		if !send(&dns.Envelope{RR: rrs[i:end]}) {
			aborted = true
			break
		}
	}
	if aborted {
		close(ch)
		wg.Wait()
		return
	}

	// Closing SOA (RFC 5936 §2.2)
	send(&dns.Envelope{RR: []dns.RR{z.SOA}}) //nolint:errcheck — peer disconnect OK here
	close(ch)
	wg.Wait()
	w.Close() //nolint:errcheck
}
