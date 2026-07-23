package server

import (
	"context"
	"net"
)

// SOANotifyHandler receives ordinary RFC 1996 SOA NOTIFY after DNS framing and
// TSIG verification. Implementations still authorize the source and key for
// the specific secondary zone.
type SOANotifyHandler interface {
	HandleNotify(context.Context, string, net.IP, string) error
}

// SetSOANotifyHandler wires secondary-zone refresh into the DNS request path.
func (s *Server) SetSOANotifyHandler(handler SOANotifyHandler) {
	s.soaNotifyMu.Lock()
	s.soaNotifyHandler = handler
	s.soaNotifyMu.Unlock()
}
