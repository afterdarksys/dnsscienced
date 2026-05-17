package dsync

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/rs/zerolog"
)

// DSYNCNotifier sends outbound NOTIFY(CDS/CSYNC) to discovered parent endpoints.
// Events are enqueued on a buffered channel; a worker goroutine drains the channel
// and applies a propagation delay before discovery and sending (T-08-07: buffered
// channel of 64 drops events when full rather than blocking the caller).
type DSYNCNotifier struct {
	resolver         string
	propagationDelay time.Duration
	events           chan notifyEvent
	log              zerolog.Logger
	metrics          *DSYNCMetrics // nil = no metrics; set via SetMetrics after construction
}

type notifyEvent struct {
	zone  string
	qtype uint16
}

// NewDSYNCNotifier creates a notifier.
//
//   - resolver is the DNS resolver address (e.g. "127.0.0.1:53") used for
//     _dsync discovery queries.
//   - propagationDelay is the wait before sending outbound NOTIFY (RFC 9859
//     recommends waiting for zone propagation; 60s is a reasonable default).
//
// A background worker goroutine is started immediately.
func NewDSYNCNotifier(resolver string, propagationDelay time.Duration, log zerolog.Logger) *DSYNCNotifier {
	n := &DSYNCNotifier{
		resolver:         resolver,
		propagationDelay: propagationDelay,
		events:           make(chan notifyEvent, 64),
		log:              log.With().Str("component", "dsync-notifier").Logger(),
	}
	go n.worker()
	return n
}

// SetMetrics configures Prometheus metrics for the notifier.
// Called after NewDSYNCNotifier by server wiring code. Does not change constructor signature.
func (n *DSYNCNotifier) SetMetrics(m *DSYNCMetrics) {
	n.metrics = m
}

// Notify enqueues an outbound NOTIFY event for the given zone and qtype.
// Non-blocking: if the queue is full, the event is dropped with a warning log
// (T-08-07 mitigated).
func (n *DSYNCNotifier) Notify(zone string, qtype uint16) {
	select {
	case n.events <- notifyEvent{zone: zone, qtype: qtype}:
	default:
		n.log.Warn().Str("zone", zone).Msg("Notify queue full; dropping event")
	}
}

// worker drains the event queue, applies propagation delay, discovers _dsync
// endpoints, and sends outbound NOTIFYs.
func (n *DSYNCNotifier) worker() {
	client := &dns.Client{Net: "udp", Timeout: 5 * time.Second}
	for ev := range n.events {
		if n.propagationDelay > 0 {
			time.Sleep(n.propagationDelay)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		records, err := DiscoverDSYNC(ctx, ev.zone, client, n.resolver)
		cancel()

		if err != nil || len(records) == 0 {
			continue
		}

		for _, rec := range records {
			// Filter: only send to endpoints that match the event's qtype
			// and use the NOTIFY scheme.
			if rec.RRtype != ev.qtype || rec.Scheme != DSYNCSchemeNOTIFY {
				continue
			}
			ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
			if err := sendNotify(ctx2, ev.zone, ev.qtype, rec.Target, rec.Port); err != nil {
				n.log.Error().Err(err).
					Str("zone", ev.zone).
					Str("target", rec.Target).
					Msg("sendNotify failed")
				if n.metrics != nil {
					n.metrics.NotifyOutbound.WithLabelValues(ev.zone, "failed").Inc()
				}
			} else {
				if n.metrics != nil {
					n.metrics.NotifyOutbound.WithLabelValues(ev.zone, "sent").Inc()
				}
			}
			cancel2()
		}
	}
}

// sendNotify sends a single NOTIFY(qtype) to target:port using UDP.
// It uses dns.Msg.SetNotify (Opcode=4, AA=true) and then overrides
// Question[0].Qtype from TypeSOA to the requested CDS/CSYNC qtype per RFC 9859.
//
// target should be an FQDN (trailing dot is stripped before joining with port).
func sendNotify(ctx context.Context, zoneName string, qtype uint16, target string, port uint16) error {
	m := new(dns.Msg)
	m.SetNotify(zoneName)
	m.Question[0].Qtype = qtype // Override TypeSOA -> TypeCDS or TypeCSYNC (RFC 9859)

	c := &dns.Client{Net: "udp", Timeout: 5 * time.Second}
	addr := net.JoinHostPort(strings.TrimSuffix(target, "."), strconv.Itoa(int(port)))

	resp, _, err := c.ExchangeContext(ctx, m, addr)
	if err != nil {
		return fmt.Errorf("notify %s: %w", addr, err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("notify %s: rcode %s", addr, dns.RcodeToString[resp.Rcode])
	}
	return nil
}
