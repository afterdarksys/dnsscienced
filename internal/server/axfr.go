package server

import (
	"net"

	"github.com/miekg/dns"
)

// handleAXFR handles RFC 5936 zone transfer requests.
// Stub — full implementation in Task 2.
func (s *Server) handleAXFR(w dns.ResponseWriter, r *dns.Msg, clientIP net.IP) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Rcode = dns.RcodeNotImplemented
	w.WriteMsg(m) //nolint:errcheck
}
