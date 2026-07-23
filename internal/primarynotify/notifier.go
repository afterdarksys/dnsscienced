// Package primarynotify sends RFC 1996 SOA NOTIFY messages for primary zones.
package primarynotify

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

const (
	defaultWorkers  = 4
	defaultTimeout  = 2 * time.Second
	defaultBackoff  = 250 * time.Millisecond
	defaultAttempts = 3
)

var ErrClosed = errors.New("primary notify is closed")

type permanentError struct {
	err error
}

func (e permanentError) Error() string {
	return e.err.Error()
}

func (e permanentError) Unwrap() error {
	return e.err
}

// ZoneConfig defines outbound NOTIFY policy for one primary zone.
type ZoneConfig struct {
	Targets       []string
	TSIGKey       string
	TSIGAlgorithm string
	AllowUnsigned bool
	Timeout       time.Duration
	RetryBackoff  time.Duration
	Attempts      int
}

// Config defines the bounded worker topology and per-zone policies.
type Config struct {
	Workers int
	Zones   map[string]ZoneConfig
}

type notification struct {
	zone string
	soa  *dns.SOA
}

type sender interface {
	Send(context.Context, string, string, string, ZoneConfig, *dns.SOA) error
}

// Notifier coalesces changes by zone and routes each zone to one fixed worker.
type Notifier struct {
	cfg     Config
	sender  sender
	onError func(string, string, error)

	mu      sync.Mutex
	pending map[string]*dns.SOA
	queued  map[string]bool
	queues  []chan string
	started bool
	closed  bool
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup

	enqueued     atomic.Uint64
	coalesced    atomic.Uint64
	delivered    atomic.Uint64
	failed       atomic.Uint64
	retries      atomic.Uint64
	tcpFallbacks atomic.Uint64
}

// Stats is a lock-free snapshot of outbound NOTIFY activity.
type Stats struct {
	Enqueued     uint64
	Coalesced    uint64
	Delivered    uint64
	Failed       uint64
	Retries      uint64
	TCPFallbacks uint64
}

// New validates configuration and creates a stopped notifier. Call Start after
// initial zones are loaded so startup changes are coalesced before delivery.
func New(cfg Config, provider dns.TsigProvider, onError func(string, string, error)) (*Notifier, error) {
	if cfg.Workers == 0 {
		cfg.Workers = defaultWorkers
	}
	if cfg.Workers < 1 || cfg.Workers > 1024 {
		return nil, fmt.Errorf("primary notify workers must be between 1 and 1024")
	}

	normalized := make(map[string]ZoneConfig, len(cfg.Zones))
	for zoneName, zoneCfg := range cfg.Zones {
		rawZoneName := strings.TrimSpace(zoneName)
		if rawZoneName == "" {
			return nil, fmt.Errorf("primary notify zone name is required")
		}
		zoneName = strings.ToLower(dns.Fqdn(rawZoneName))
		if _, exists := normalized[zoneName]; exists {
			return nil, fmt.Errorf("duplicate primary notify zone %s", zoneName)
		}
		if len(zoneCfg.Targets) == 0 {
			continue
		}
		zoneCfg.Targets = append([]string(nil), zoneCfg.Targets...)
		zoneCfg.TSIGKey = strings.ToLower(dns.Fqdn(strings.TrimSpace(zoneCfg.TSIGKey)))
		if zoneCfg.TSIGKey == "." {
			zoneCfg.TSIGKey = ""
		}
		if zoneCfg.TSIGKey == "" && !zoneCfg.AllowUnsigned {
			return nil, fmt.Errorf(
				"primary notify zone %s requires a TSIG key; allow unsigned only for an explicit legacy trust boundary",
				zoneName,
			)
		}
		if zoneCfg.TSIGKey != "" {
			if provider == nil {
				return nil, fmt.Errorf("primary notify zone %s requires a TSIG provider", zoneName)
			}
			zoneCfg.TSIGAlgorithm = strings.ToLower(dns.Fqdn(strings.TrimSpace(zoneCfg.TSIGAlgorithm)))
			if zoneCfg.TSIGAlgorithm == "." {
				return nil, fmt.Errorf("primary notify zone %s TSIG algorithm is required", zoneName)
			}
			switch dns.CanonicalName(zoneCfg.TSIGAlgorithm) {
			case dns.HmacSHA256, dns.HmacSHA384, dns.HmacSHA512:
			default:
				return nil, fmt.Errorf(
					"primary notify zone %s has unsupported TSIG algorithm %q",
					zoneName,
					zoneCfg.TSIGAlgorithm,
				)
			}
		}
		if zoneCfg.Timeout < 0 {
			return nil, fmt.Errorf("primary notify zone %s timeout must not be negative", zoneName)
		}
		if zoneCfg.Timeout == 0 {
			zoneCfg.Timeout = defaultTimeout
		}
		if zoneCfg.RetryBackoff < 0 {
			return nil, fmt.Errorf("primary notify zone %s retry backoff must not be negative", zoneName)
		}
		if zoneCfg.RetryBackoff == 0 {
			zoneCfg.RetryBackoff = defaultBackoff
		}
		if zoneCfg.Attempts < 0 {
			return nil, fmt.Errorf("primary notify zone %s attempts must not be negative", zoneName)
		}
		if zoneCfg.Attempts == 0 {
			zoneCfg.Attempts = defaultAttempts
		}
		if zoneCfg.Attempts > 10 {
			return nil, fmt.Errorf("primary notify zone %s attempts must not exceed 10", zoneName)
		}
		for i, target := range zoneCfg.Targets {
			normalizedTarget, err := withDNSPort(target)
			if err != nil {
				return nil, fmt.Errorf("primary notify zone %s target %q: %w", zoneName, target, err)
			}
			zoneCfg.Targets[i] = normalizedTarget
		}
		normalized[zoneName] = zoneCfg
	}
	cfg.Zones = normalized

	routeCounts := make([]int, cfg.Workers)
	for zoneName := range normalized {
		routeCounts[routeFor(zoneName, cfg.Workers)]++
	}
	queues := make([]chan string, cfg.Workers)
	for i := range queues {
		queues[i] = make(chan string, routeCounts[i]+1)
	}
	return &Notifier{
		cfg:     cfg,
		sender:  dnsSender{provider: provider},
		onError: onError,
		pending: make(map[string]*dns.SOA),
		queued:  make(map[string]bool),
		queues:  queues,
	}, nil
}

func withDNSPort(target string) (string, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", fmt.Errorf("empty target")
	}
	if _, _, err := net.SplitHostPort(target); err == nil {
		return target, nil
	}
	if ip := net.ParseIP(strings.Trim(target, "[]")); ip != nil {
		return net.JoinHostPort(ip.String(), "53"), nil
	}
	if strings.Contains(target, ":") {
		return "", fmt.Errorf("invalid address")
	}
	if strings.ContainsAny(target, " \t\r\n/") {
		return "", fmt.Errorf("invalid hostname")
	}
	return net.JoinHostPort(target, "53"), nil
}

// Start launches the fixed workers. It is safe to enqueue before Start.
func (n *Notifier) Start(parent context.Context) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return ErrClosed
	}
	if n.started {
		return fmt.Errorf("primary notify already started")
	}
	n.ctx, n.cancel = context.WithCancel(parent)
	n.started = true
	for i := range n.queues {
		n.wg.Add(1)
		go n.runWorker(i)
	}
	return nil
}

// Notify records the newest SOA for a configured zone. Repeated changes while a
// delivery is queued or running collapse into one subsequent notification.
func (n *Notifier) Notify(zoneName string, soa *dns.SOA) error {
	if strings.TrimSpace(zoneName) == "" {
		return fmt.Errorf("primary notify zone name is required")
	}
	zoneName = strings.ToLower(dns.Fqdn(zoneName))
	if _, configured := n.cfg.Zones[zoneName]; !configured {
		return nil
	}
	var snapshot *dns.SOA
	if soa != nil {
		snapshot = dns.Copy(soa).(*dns.SOA)
	}

	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return ErrClosed
	}
	n.pending[zoneName] = snapshot
	if n.queued[zoneName] {
		n.coalesced.Add(1)
		return nil
	}
	n.queued[zoneName] = true
	n.enqueued.Add(1)
	n.queues[n.route(zoneName)] <- zoneName
	return nil
}

func (n *Notifier) route(zoneName string) int {
	return routeFor(zoneName, len(n.queues))
}

func routeFor(zoneName string, workers int) int {
	hash := fnv.New32a()
	_, _ = hash.Write([]byte(zoneName))
	return int(hash.Sum32() % uint32(workers))
}

func (n *Notifier) runWorker(worker int) {
	defer n.wg.Done()
	for {
		select {
		case <-n.ctx.Done():
			return
		case zoneName := <-n.queues[worker]:
			n.deliver(zoneName)
		}
	}
}

func (n *Notifier) deliver(zoneName string) {
	defer n.finishDelivery(zoneName)
	n.mu.Lock()
	soa := n.pending[zoneName]
	delete(n.pending, zoneName)
	n.mu.Unlock()

	zoneCfg := n.cfg.Zones[zoneName]
	for _, target := range zoneCfg.Targets {
		var err error
		for attempt := 0; attempt < zoneCfg.Attempts; attempt++ {
			attemptCtx, cancel := context.WithTimeout(n.ctx, zoneCfg.Timeout)
			err = n.sender.Send(attemptCtx, "udp", target, zoneName, zoneCfg, soa)
			cancel()
			if err == nil {
				break
			}
			var permanent permanentError
			if errors.As(err, &permanent) {
				break
			}
			if attempt+1 < zoneCfg.Attempts && !waitContext(n.ctx, retryDelay(zoneCfg.RetryBackoff, attempt)) {
				return
			}
			if attempt+1 < zoneCfg.Attempts {
				n.retries.Add(1)
			}
		}
		var permanent permanentError
		if err != nil && !errors.As(err, &permanent) {
			n.tcpFallbacks.Add(1)
			attemptCtx, cancel := context.WithTimeout(n.ctx, zoneCfg.Timeout)
			err = n.sender.Send(attemptCtx, "tcp", target, zoneName, zoneCfg, soa)
			cancel()
		}
		if err != nil && n.onError != nil {
			n.onError(zoneName, target, err)
		}
		if err != nil {
			n.failed.Add(1)
		} else {
			n.delivered.Add(1)
		}
	}
}

// Stats returns current counters without stopping workers.
func (n *Notifier) Stats() Stats {
	return Stats{
		Enqueued:     n.enqueued.Load(),
		Coalesced:    n.coalesced.Load(),
		Delivered:    n.delivered.Load(),
		Failed:       n.failed.Load(),
		Retries:      n.retries.Load(),
		TCPFallbacks: n.tcpFallbacks.Load(),
	}
}

func (n *Notifier) finishDelivery(zoneName string) {
	n.mu.Lock()
	if _, changedAgain := n.pending[zoneName]; changedAgain &&
		!n.closed &&
		n.ctx != nil &&
		n.ctx.Err() == nil {
		n.queues[n.route(zoneName)] <- zoneName
	} else {
		n.queued[zoneName] = false
		delete(n.pending, zoneName)
	}
	n.mu.Unlock()
}

func retryDelay(base time.Duration, attempt int) time.Duration {
	if attempt > 6 {
		attempt = 6
	}
	return base * time.Duration(1<<attempt)
}

func waitContext(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// Close stops workers and discards pending notifications.
func (n *Notifier) Close() {
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		return
	}
	n.closed = true
	clear(n.pending)
	cancel := n.cancel
	n.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	n.wg.Wait()
}

type dnsSender struct {
	provider dns.TsigProvider
}

func (s dnsSender) Send(
	ctx context.Context,
	network string,
	target string,
	zoneName string,
	cfg ZoneConfig,
	soa *dns.SOA,
) error {
	request := new(dns.Msg)
	request.SetNotify(zoneName)
	if soa != nil {
		request.Answer = []dns.RR{dns.Copy(soa)}
	}
	if cfg.TSIGKey != "" {
		request.SetTsig(cfg.TSIGKey, cfg.TSIGAlgorithm, 300, time.Now().Unix())
	}

	client := &dns.Client{
		Net:          network,
		Timeout:      cfg.Timeout,
		TsigProvider: s.provider,
	}
	response, _, err := client.ExchangeContext(ctx, request, target)
	if err != nil {
		if errors.Is(err, dns.ErrSig) ||
			errors.Is(err, dns.ErrKeyAlg) ||
			errors.Is(err, dns.ErrSecret) {
			return permanentError{err: err}
		}
		return err
	}
	if response == nil || !response.Response || response.Opcode != dns.OpcodeNotify {
		return permanentError{err: fmt.Errorf("invalid NOTIFY response")}
	}
	if response.Rcode != dns.RcodeSuccess {
		return permanentError{err: fmt.Errorf("NOTIFY response rcode %s", dns.RcodeToString[response.Rcode])}
	}
	if cfg.TSIGKey != "" {
		responseTSIG := response.IsTsig()
		if responseTSIG == nil {
			return permanentError{err: fmt.Errorf("signed NOTIFY received unsigned response")}
		}
		if !strings.EqualFold(responseTSIG.Hdr.Name, cfg.TSIGKey) ||
			dns.CanonicalName(responseTSIG.Algorithm) != dns.CanonicalName(cfg.TSIGAlgorithm) {
			return permanentError{err: fmt.Errorf("NOTIFY response TSIG identity does not match request")}
		}
	}
	return nil
}
