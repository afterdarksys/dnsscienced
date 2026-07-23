package server

import (
	"net"
	"strings"
	"sync"

	"github.com/dnsscience/dnsscienced/internal/transport"
	"github.com/dnsscience/dnsscienced/internal/zone"
	"github.com/miekg/dns"
)

const axfrBatchSize = 100

// handleAXFR handles RFC 5936 zone transfer (AXFR) requests.
//
// Guard chain (each failure returns immediately with the specified rcode):
//  1. UDP truncation (D-08): return TC=1; no zone data on UDP
//  2. TSIG presence (D-04): absent TSIG → NOTAUTH (rcode 9)
//  3. TSIG validity (D-05): bad key/MAC/time/truncation → RFC 8945 error
//  4. Empty question guard → REFUSED
//  5. Zone lookup: unknown zone → REFUSED
//  6. ACL check (D-01, D-03): nil ACL (no allow_transfer) or IP not allowed → REFUSED
//  7. Stream: opening SOA + batched RRs + closing SOA via dns.Transfer.Out
func (s *Server) handleAXFR(w dns.ResponseWriter, r *dns.Msg, clientIP net.IP) {
	// 1. UDP truncation (D-08): signal retry over TCP; do NOT return zone data.
	if _, ok := transport.UDPAddress(w.RemoteAddr()); ok {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Truncated = true
		w.WriteMsg(m) //nolint:errcheck
		return
	}

	// A primary zone configured for an RFC 9103-only transfer group must not
	// expose AXFR or IXFR on the ordinary cleartext TCP listener.
	if len(r.Question) == 1 {
		qname := strings.ToLower(dns.Fqdn(r.Question[0].Name))
		if s.cfg.ZoneTransferTLSOnly[qname] && !isXoTWriter(w) {
			m := new(dns.Msg)
			m.SetReply(r)
			m.Rcode = dns.RcodeRefused
			w.WriteMsg(m) //nolint:errcheck
			return
		}
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

	// 3. TSIG validity check (D-05): bad key, MAC, time, or truncation.
	if verificationErr := w.TsigStatus(); verificationErr != nil {
		writeTSIGVerificationError(w, r, verificationErr)
		return
	}

	// 4. Empty question guard.
	if len(r.Question) != 1 ||
		(r.Question[0].Qtype != dns.TypeAXFR && r.Question[0].Qtype != dns.TypeIXFR) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeRefused
		w.WriteMsg(m) //nolint:errcheck
		return
	}

	// 5. Zone lookup.
	qname := strings.ToLower(dns.Fqdn(r.Question[0].Name))
	s.zonesMu.RLock()
	z, ok := s.cfg.Zones[qname]
	s.zonesMu.RUnlock()
	if !ok {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeRefused
		w.WriteMsg(m) //nolint:errcheck
		return
	}
	if r.Question[0].Qclass != z.Class {
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

	transferRRs := fullTransferRecords(z)
	if r.Question[0].Qtype == dns.TypeIXFR {
		requestedSerial, ok := ixfrRequestSerial(r, z.Class)
		if !ok {
			m := new(dns.Msg)
			m.SetReply(r)
			m.Rcode = dns.RcodeFormatError
			w.WriteMsg(m) //nolint:errcheck
			return
		}
		if !zone.SerialGreater(z.SOA.Serial, requestedSerial) {
			transferRRs = []dns.RR{dns.Copy(z.SOA)}
		} else if deltas, found := s.ixfrJournal.Changes(qname, requestedSerial, z.SOA.Serial); found {
			incremental := incrementalTransferRecords(z.SOA, deltas)
			allowFallback := true
			if configured, ok := s.cfg.ZoneAllowAXFRFallback[qname]; ok {
				allowFallback = configured
			}
			if !allowFallback || transferRecordSize(incremental) < transferRecordSize(transferRRs) {
				transferRRs = incremental
			}
		} else {
			allowFallback := true
			if configured, ok := s.cfg.ZoneAllowAXFRFallback[qname]; ok {
				allowFallback = configured
			}
			if !allowFallback {
				m := new(dns.Msg)
				m.SetReply(r)
				m.Rcode = dns.RcodeNotImplemented
				w.WriteMsg(m) //nolint:errcheck
				return
			}
		}
	}

	// 8. Multi-message streaming via dns.Transfer.Out.
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

	aborted := false
	for i := 0; i < len(transferRRs); i += axfrBatchSize {
		end := i + axfrBatchSize
		if end > len(transferRRs) {
			end = len(transferRRs)
		}
		if !send(&dns.Envelope{RR: transferRRs[i:end]}) {
			aborted = true
			break
		}
	}
	if aborted {
		close(ch)
		wg.Wait()
		return
	}

	close(ch)
	wg.Wait()
	w.Close() //nolint:errcheck
}

func ixfrRequestSerial(request *dns.Msg, zoneClass uint16) (uint32, bool) {
	if len(request.Ns) != 1 {
		return 0, false
	}
	soa, ok := request.Ns[0].(*dns.SOA)
	if !ok || soa.Hdr.Class != zoneClass ||
		!strings.EqualFold(dns.Fqdn(soa.Hdr.Name), dns.Fqdn(request.Question[0].Name)) {
		return 0, false
	}
	return soa.Serial, true
}

func fullTransferRecords(z *zone.Zone) []dns.RR {
	result := []dns.RR{dns.Copy(z.SOA)}
	for _, rr := range z.GetAllRecords() {
		if rr.Header().Rrtype != dns.TypeSOA {
			result = append(result, dns.Copy(rr))
		}
	}
	return append(result, dns.Copy(z.SOA))
}

func incrementalTransferRecords(current *dns.SOA, deltas []zone.Delta) []dns.RR {
	result := []dns.RR{dns.Copy(current)}
	for _, delta := range deltas {
		result = append(result, dns.Copy(delta.FromSOA))
		for _, rr := range delta.Deleted {
			result = append(result, dns.Copy(rr))
		}
		result = append(result, dns.Copy(delta.ToSOA))
		for _, rr := range delta.Added {
			result = append(result, dns.Copy(rr))
		}
	}
	return append(result, dns.Copy(current))
}

func transferRecordSize(records []dns.RR) int {
	total := 0
	for _, rr := range records {
		total += dns.Len(rr)
	}
	return total
}
