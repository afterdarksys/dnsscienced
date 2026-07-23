package server

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestTCPProtectionServesThroughLimitedListener(t *testing.T) {
	cfg := DefaultConfig()
	cfg.UDPAddr = "127.0.0.1:0"
	cfg.TCPAddr = "127.0.0.1:0"
	cfg.UDPListeners = 1
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := srv.Stop(); err != nil {
			t.Errorf("stop server: %v", err)
		}
	}()

	request := new(dns.Msg)
	request.SetQuestion("example.", dns.TypeA)
	client := &dns.Client{Net: "tcp", Timeout: 2 * time.Second}
	response, _, err := client.Exchange(request, srv.tcpServer.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if response == nil {
		t.Fatal("TCP query returned no response")
	}
	stats := srv.GetStats().TCPConnections
	if stats.Accepted != 1 {
		t.Fatalf("accepted TCP connections = %d, want 1", stats.Accepted)
	}
}
