package dsync

import (
	"net"
	"strconv"
	"time"

	"github.com/miekg/dns"
	"github.com/rs/zerolog"
)

// Allower is the interface for source IP access control.
// Plan 05 replaces the AllowAll stub with a real SourceACL implementation.
type Allower interface {
	Check(ip net.IP) bool
}

// allowAll is the stub ACL that accepts all sources.
// Satisfies Allower interface. Plan 05 swaps this for real SourceACL.
type allowAll struct{}

func (allowAll) Check(_ net.IP) bool { return true }

// AllowAllACL returns a stub Allower that permits every source IP.
func AllowAllACL() Allower { return allowAll{} }

// Handler processes inbound NOTIFY(CDS/CSYNC) messages per RFC 9859.
type Handler struct {
	limiter *NotifyLimiter
	acl     Allower
	log     zerolog.Logger
	webhook *WebhookClient // nil = no webhook; set via SetWebhook after construction
}

// SetWebhook configures the webhook client for this handler.
// Called after NewHandler by server wiring code. Does not change constructor signature.
func (h *Handler) SetWebhook(wc *WebhookClient) {
	h.webhook = wc
}

// NewHandler creates an inbound NOTIFY handler.
// acl: source IP checker (use AllowAllACL() as default stub).
// limiter: per-source-IP rate limiter from Plan 01.
func NewHandler(limiter *NotifyLimiter, acl Allower, log zerolog.Logger) *Handler {
	return &Handler{
		limiter: limiter,
		acl:     acl,
		log:     log.With().Str("component", "dsync").Logger(),
	}
}

// HandleInbound processes an inbound DNS NOTIFY message.
// Order of checks (per D-06, D-14):
//  1. Empty question section -> RcodeFormatError
//  2. Source ACL check -> REFUSED if rejected
//  3. Rate limit check -> REFUSED if limited
//  4. Acknowledge NOERROR
//  5. Dispatch delegation check goroutine (stub: log only)
func (h *Handler) HandleInbound(w dns.ResponseWriter, r *dns.Msg, clientIP net.IP) {
	reply := new(dns.Msg)
	reply.SetReply(r)

	if len(r.Question) == 0 {
		reply.Rcode = dns.RcodeFormatError
		w.WriteMsg(reply) //nolint:errcheck
		return
	}

	// Step 1: Source ACL check (D-05/D-06)
	if !h.acl.Check(clientIP) {
		reply.Rcode = dns.RcodeRefused
		w.WriteMsg(reply) //nolint:errcheck
		return
	}

	// Step 2: Rate limit check (D-07/D-14)
	if !h.limiter.Allow(clientIP) {
		reply.Rcode = dns.RcodeRefused
		w.WriteMsg(reply) //nolint:errcheck
		return
	}

	// Step 3: Acknowledge NOERROR per RFC 1996 section 3.10
	reply.Rcode = dns.RcodeSuccess
	w.WriteMsg(reply) //nolint:errcheck

	// Step 4: Only process CDS and CSYNC NOTIFY types per RFC 9859
	qtype := r.Question[0].Qtype
	zone := r.Question[0].Name
	if qtype != dns.TypeCDS && qtype != dns.TypeCSYNC {
		return
	}

	// D-01: Fire webhook POST (fire-and-forget in goroutine, per D-04)
	if h.webhook != nil {
		go func() {
			payload := WebhookPayload{
				Zone:      zone,
				Qtype:     dns.TypeToString[qtype],
				SourceIP:  clientIP.String(),
				Timestamp: time.Now(),
			}
			if err := h.webhook.Fire(payload); err != nil {
				h.log.Error().Err(err).Str("zone", zone).Msg("webhook delivery failed")
			}
		}()
	}

	// Async delegation check (stub: log only in this phase)
	go h.scheduleDelegationCheck(zone, qtype)
}

// scheduleDelegationCheck is a STUB that only logs.
// No delegation maintenance engine is implemented in Phase 8.
func (h *Handler) scheduleDelegationCheck(zone string, qtype uint16) {
	qtypeName := dns.TypeToString[qtype]
	if qtypeName == "" {
		qtypeName = "TYPE" + strconv.Itoa(int(qtype))
	}
	h.log.Info().Str("zone", zone).Str("qtype", qtypeName).Msg("NOTIFY received - delegation check scheduled (stub)")
}
