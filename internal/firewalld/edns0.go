package firewalld

import (
	"github.com/miekg/dns"
	"github.com/rs/zerolog"
)

// edns0CustomerIDCode is the private-use EDNS0 option code carrying the
// customer identifier. RFC 6891 §6.1.3.1 reserves codes 65000–65534 for
// private use / local experimentation.
// Note: dns.EDNS0LOCALSTART = 0xFDE9 (65001); this code is 0xFDE8 (65000).
const edns0CustomerIDCode uint16 = 65000

// edns0MaxCustomerIDLen is the maximum accepted payload size in bytes.
// Chosen to accommodate UUID-prefixed variants (36 bytes for a bare UUID,
// headroom for short prefixes).
const edns0MaxCustomerIDLen = 64

// extractCustomerID returns the customer identifier from the EDNS0 option with
// code 65000, or "" if the option is absent or invalid.
// An oversized payload (> 64 bytes) is dropped with a single debug-level log.
func extractCustomerID(r *dns.Msg, logger zerolog.Logger) string {
	opt := r.IsEdns0()
	if opt == nil {
		return ""
	}
	for _, option := range opt.Option {
		local, ok := option.(*dns.EDNS0_LOCAL)
		if !ok || local.Code != edns0CustomerIDCode {
			continue
		}
		if len(local.Data) > edns0MaxCustomerIDLen {
			logger.Debug().
				Int("len", len(local.Data)).
				Msg("edns0 customer_id payload too large, ignoring")
			return ""
		}
		return string(local.Data)
	}
	return ""
}
