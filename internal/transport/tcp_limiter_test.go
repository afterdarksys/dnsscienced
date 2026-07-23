package transport

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type queuedListener struct {
	mu     sync.Mutex
	conns  []net.Conn
	closed bool
}

func (l *queuedListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.conns) == 0 {
		return nil, errors.New("test listener drained")
	}
	conn := l.conns[0]
	l.conns = l.conns[1:]
	return conn, nil
}

func (l *queuedListener) Close() error {
	l.mu.Lock()
	l.closed = true
	l.mu.Unlock()
	return nil
}

func (l *queuedListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4zero, Port: 53}
}

type testTCPConn struct {
	net.Conn
	remote net.Addr
	closed atomic.Bool
}

func (c *testTCPConn) RemoteAddr() net.Addr { return c.remote }

func (c *testTCPConn) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

func newTestTCPConn(ip string) *testTCPConn {
	left, right := net.Pipe()
	_ = right.Close()
	return &testTCPConn{
		Conn:   left,
		remote: &net.TCPAddr{IP: net.ParseIP(ip), Port: 12345},
	}
}

func testTCPProtectionConfig() TCPProtectionConfig {
	cfg := DefaultTCPProtectionConfig()
	cfg.MaxConnections = 2
	cfg.MaxConnectionsPerClient = 1
	cfg.AcceptRatePerSecond = 10
	cfg.AcceptBurst = 10
	return cfg
}

func TestLimitedListenerRejectsPerClientAndAdmitsNextConnection(t *testing.T) {
	first := newTestTCPConn("192.0.2.1")
	rejected := newTestTCPConn("192.0.2.1")
	secondClient := newTestTCPConn("192.0.2.2")
	base := &queuedListener{conns: []net.Conn{first, rejected, secondClient}}
	wrapped, err := NewLimitedListener(base, testTCPProtectionConfig())
	if err != nil {
		t.Fatal(err)
	}
	limiter := wrapped.(*LimitedListener)
	limiter.sleep = func(time.Duration) {}
	conn1, err := limiter.Accept()
	if err != nil {
		t.Fatal(err)
	}
	conn2, err := limiter.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if !rejected.closed.Load() {
		t.Fatal("excess per-client connection was not closed")
	}
	stats := limiter.Stats()
	if stats.Active != 2 || stats.Accepted != 2 || stats.Rejected != 1 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
	var closeWG sync.WaitGroup
	for i := 0; i < 8; i++ {
		closeWG.Add(1)
		go func() {
			defer closeWG.Done()
			_ = conn1.Close()
		}()
	}
	closeWG.Wait()
	_ = conn2.Close()
	if active := limiter.Stats().Active; active != 0 {
		t.Fatalf("active after close = %d, want 0", active)
	}
}

func TestLimitedListenerRejectsAcceptRateAndRefills(t *testing.T) {
	cfg := testTCPProtectionConfig()
	cfg.MaxConnections = 10
	cfg.MaxConnectionsPerClient = 10
	cfg.AcceptRatePerSecond = 1
	cfg.AcceptBurst = 1
	first := newTestTCPConn("192.0.2.1")
	rejected := newTestTCPConn("192.0.2.2")
	afterRefill := newTestTCPConn("192.0.2.3")
	base := &queuedListener{conns: []net.Conn{first, rejected, afterRefill}}
	wrapped, err := NewLimitedListener(base, cfg)
	if err != nil {
		t.Fatal(err)
	}
	limiter := wrapped.(*LimitedListener)
	limiter.sleep = func(time.Duration) {}
	now := time.Unix(100, 0)
	limiter.lastRefill = now
	call := 0
	limiter.now = func() time.Time {
		call++
		if call >= 3 {
			return now.Add(time.Second)
		}
		return now
	}
	conn1, err := limiter.Accept()
	if err != nil {
		t.Fatal(err)
	}
	conn2, err := limiter.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if !rejected.closed.Load() {
		t.Fatal("connection beyond accept rate was not closed")
	}
	_ = conn1.Close()
	_ = conn2.Close()
}

func TestTCPProtectionConfigValidation(t *testing.T) {
	cfg := DefaultTCPProtectionConfig()
	cfg.MaxConnectionsPerClient = cfg.MaxConnections + 1
	if err := cfg.Validate(); err == nil {
		t.Fatal("per-client maximum above global maximum was accepted")
	}
	cfg = DefaultTCPProtectionConfig()
	cfg.AcceptBurst = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("zero accept burst was accepted")
	}
}

func TestLimitedListenerCapacityRejectionConsumesAcceptBudget(t *testing.T) {
	cfg := testTCPProtectionConfig()
	cfg.MaxConnections = 1
	cfg.MaxConnectionsPerClient = 1
	cfg.AcceptRatePerSecond = 1
	cfg.AcceptBurst = 2
	wrapped, err := NewLimitedListener(&queuedListener{}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	limiter := wrapped.(*LimitedListener)
	now := time.Unix(100, 0)
	limiter.lastRefill = now
	limiter.now = func() time.Time { return now }
	first := net.ParseIP("192.0.2.1")
	second := net.ParseIP("192.0.2.2")
	firstAddr, _ := remoteIP(&net.TCPAddr{IP: first})
	secondAddr, _ := remoteIP(&net.TCPAddr{IP: second})
	if reason := limiter.admit(firstAddr, true); reason != "" {
		t.Fatalf("first admission rejected: %s", reason)
	}
	if reason := limiter.admit(secondAddr, true); reason != "global_capacity" {
		t.Fatalf("capacity rejection reason = %q", reason)
	}
	if reason := limiter.admit(secondAddr, true); reason != "accept_rate" {
		t.Fatalf("post-capacity rejection reason = %q, want accept_rate", reason)
	}
	limiter.release(firstAddr, true)
}
