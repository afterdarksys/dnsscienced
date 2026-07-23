package transport

import (
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	tcpConnectionsAcceptedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "dnsscienced_tcp_connections_accepted_total",
		Help: "Total TCP DNS connections admitted by the connection limiter.",
	})
	tcpConnectionsRejectedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "dnsscienced_tcp_connections_rejected_total",
		Help: "Total established TCP DNS connections rejected by bounded reason.",
	}, []string{"reason"})
	tcpConnectionsActive = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "dnsscienced_tcp_connections_active",
		Help: "Current TCP DNS connections admitted by the connection limiter.",
	})
)

// TCPProtectionConfig controls established TCP connection admission. SYNs that
// have not completed the handshake remain a kernel or upstream edge concern.
type TCPProtectionConfig struct {
	Enabled                 bool `yaml:"enabled"`
	MaxConnections          int  `yaml:"max_connections"`
	MaxConnectionsPerClient int  `yaml:"max_connections_per_client"`
	AcceptRatePerSecond     int  `yaml:"accept_rate_per_second"`
	AcceptBurst             int  `yaml:"accept_burst"`
	MaxQueriesPerConnection int  `yaml:"max_queries_per_connection"`
}

// DefaultTCPProtectionConfig returns secure defaults sized for a busy
// authoritative service while retaining explicit memory and descriptor bounds.
func DefaultTCPProtectionConfig() TCPProtectionConfig {
	return TCPProtectionConfig{
		Enabled:                 true,
		MaxConnections:          20000,
		MaxConnectionsPerClient: 128,
		AcceptRatePerSecond:     10000,
		AcceptBurst:             20000,
		MaxQueriesPerConnection: 100,
	}
}

// Validate checks TCP protection bounds.
func (cfg TCPProtectionConfig) Validate() error {
	if !cfg.Enabled {
		return nil
	}
	values := []struct {
		name  string
		value int
		max   int
	}{
		{"max_connections", cfg.MaxConnections, 10_000_000},
		{"max_connections_per_client", cfg.MaxConnectionsPerClient, 1_000_000},
		{"accept_rate_per_second", cfg.AcceptRatePerSecond, 10_000_000},
		{"accept_burst", cfg.AcceptBurst, 10_000_000},
		{"max_queries_per_connection", cfg.MaxQueriesPerConnection, 1_000_000},
	}
	for _, field := range values {
		if field.value < 1 || field.value > field.max {
			return fmt.Errorf("tcp_protection.%s must be between 1 and %d", field.name, field.max)
		}
	}
	if cfg.MaxConnectionsPerClient > cfg.MaxConnections {
		return fmt.Errorf("tcp_protection.max_connections_per_client must not exceed max_connections")
	}
	return nil
}

// TCPConnectionStats is an atomic snapshot of listener admission.
type TCPConnectionStats struct {
	Active   int64
	Accepted uint64
	Rejected uint64
}

// LimitedListener bounds established TCP connections before the DNS server
// allocates a goroutine for them.
type LimitedListener struct {
	net.Listener
	cfg TCPProtectionConfig

	mu         sync.Mutex
	active     int
	perClient  map[netip.Addr]int
	tokens     float64
	lastRefill time.Time
	now        func() time.Time
	sleep      func(time.Duration)

	accepted atomic.Uint64
	rejected atomic.Uint64
}

// NewLimitedListener wraps listener with fixed global, per-client, and accept
// rate limits. A disabled configuration returns listener unchanged.
func NewLimitedListener(listener net.Listener, cfg TCPProtectionConfig) (net.Listener, error) {
	if listener == nil {
		return nil, fmt.Errorf("tcp protection listener must not be nil")
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if !cfg.Enabled {
		return listener, nil
	}
	now := time.Now
	return &LimitedListener{
		Listener:   listener,
		cfg:        cfg,
		perClient:  make(map[netip.Addr]int),
		tokens:     float64(cfg.AcceptBurst),
		lastRefill: now(),
		now:        now,
		sleep:      time.Sleep,
	}, nil
}

// Accept admits only connections within all configured bounds. Rejected
// established connections are closed immediately and never reach dns.Server.
func (l *LimitedListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		client, haveClient := remoteIP(conn.RemoteAddr())
		reason := l.admit(client, haveClient)
		if reason == "" {
			tcpConnectionsAcceptedTotal.Inc()
			tcpConnectionsActive.Inc()
			l.accepted.Add(1)
			return &limitedConn{
				Conn: conn,
				release: func() {
					l.release(client, haveClient)
				},
			}, nil
		}
		l.rejected.Add(1)
		tcpConnectionsRejectedTotal.WithLabelValues(reason).Inc()
		_ = conn.Close()
		l.sleep(l.rejectionDelay())
	}
}

// Stats returns an atomic activity snapshot.
func (l *LimitedListener) Stats() TCPConnectionStats {
	if l == nil {
		return TCPConnectionStats{}
	}
	l.mu.Lock()
	active := l.active
	l.mu.Unlock()
	return TCPConnectionStats{
		Active:   int64(active),
		Accepted: l.accepted.Load(),
		Rejected: l.rejected.Load(),
	}
}

func (l *LimitedListener) admit(client netip.Addr, haveClient bool) string {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	elapsed := now.Sub(l.lastRefill).Seconds()
	if elapsed > 0 {
		l.tokens = min(float64(l.cfg.AcceptBurst), l.tokens+elapsed*float64(l.cfg.AcceptRatePerSecond))
		l.lastRefill = now
	}
	if l.tokens < 1 {
		return "accept_rate"
	}
	// Every completed handshake consumes admission budget, including a
	// connection rejected by a capacity limit. This bounds accept/close churn.
	l.tokens--
	if l.active >= l.cfg.MaxConnections {
		return "global_capacity"
	}
	if haveClient && l.perClient[client] >= l.cfg.MaxConnectionsPerClient {
		return "client_capacity"
	}
	l.active++
	if haveClient {
		l.perClient[client]++
	}
	return ""
}

func (l *LimitedListener) rejectionDelay() time.Duration {
	delay := time.Second / time.Duration(l.cfg.AcceptRatePerSecond)
	if delay < 50*time.Microsecond {
		return 50 * time.Microsecond
	}
	if delay > 10*time.Millisecond {
		return 10 * time.Millisecond
	}
	return delay
}

func (l *LimitedListener) release(client netip.Addr, haveClient bool) {
	l.mu.Lock()
	if l.active > 0 {
		l.active--
	}
	if haveClient {
		if remaining := l.perClient[client] - 1; remaining > 0 {
			l.perClient[client] = remaining
		} else {
			delete(l.perClient, client)
		}
	}
	l.mu.Unlock()
	tcpConnectionsActive.Dec()
}

type limitedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

func remoteIP(addr net.Addr) (netip.Addr, bool) {
	switch value := addr.(type) {
	case *net.TCPAddr:
		ip, ok := netip.AddrFromSlice(value.IP)
		return ip.Unmap(), ok
	case *net.UDPAddr:
		ip, ok := netip.AddrFromSlice(value.IP)
		return ip.Unmap(), ok
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return netip.Addr{}, false
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return ip.Unmap(), true
}
