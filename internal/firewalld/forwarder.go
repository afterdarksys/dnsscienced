package firewalld

import (
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// Forwarder sends a DNS query to an arbitrary upstream server and returns
// the response.  Used to implement VerdictRedirect — the firewall policy
// decides which upstream should handle a query (e.g. a specialised resolver
// or a sinkhole that logs before answering).
type Forwarder struct {
	timeout time.Duration
	client  *dns.Client
}

// NewForwarder creates a Forwarder with the given per-query timeout.
// A zero timeout defaults to 3 seconds.
func NewForwarder(timeout time.Duration) *Forwarder {
	if timeout == 0 {
		timeout = 3 * time.Second
	}
	return &Forwarder{
		timeout: timeout,
		client: &dns.Client{
			Net:     "udp",
			Timeout: timeout,
		},
	}
}

// Forward sends r to server ("ip:port") and returns the response.
// It retries over TCP if the UDP response is truncated.
func (f *Forwarder) Forward(r *dns.Msg, server string) (*dns.Msg, error) {
	if _, _, err := net.SplitHostPort(server); err != nil {
		// Bare IP — add default port 53.
		server = net.JoinHostPort(server, "53")
	}

	resp, _, err := f.client.Exchange(r, server)
	if err != nil {
		return nil, fmt.Errorf("forward to %s: %w", server, err)
	}

	// Retry over TCP when the UDP response is truncated.
	if resp.Truncated {
		tcp := &dns.Client{Net: "tcp", Timeout: f.timeout}
		resp, _, err = tcp.Exchange(r, server)
		if err != nil {
			return nil, fmt.Errorf("forward (tcp retry) to %s: %w", server, err)
		}
	}

	return resp, nil
}

// UpstreamPool selects among configured upstream DNS addresses using
// atomic round-robin. Safe for concurrent use without locks.
type UpstreamPool struct {
	upstreams []string
	counter   atomic.Uint64
}

// newUpstreamPool creates a pool from the given upstream addresses.
// A nil or empty slice is valid — Next() will return an error (D-13).
func newUpstreamPool(upstreams []string) *UpstreamPool {
	return &UpstreamPool{upstreams: upstreams}
}

// Next returns the next upstream address via atomic round-robin.
// Returns ("", error) when the pool is empty; caller must return SERVFAIL (D-13).
func (p *UpstreamPool) Next() (string, error) {
	if len(p.upstreams) == 0 {
		return "", fmt.Errorf("upstream pool is empty — configure firewall.redirect.upstreams")
	}
	idx := (p.counter.Add(1) - 1) % uint64(len(p.upstreams))
	return p.upstreams[idx], nil
}
