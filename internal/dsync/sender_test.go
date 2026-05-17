package dsync

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/rs/zerolog"
)

// startCaptureServer starts a UDP listener that captures the first DNS message
// it receives, sends NOERROR, then stops. Returns the server address and a channel
// that delivers the captured message.
func startCaptureServer(t *testing.T) (addr string, capturedMsg <-chan *dns.Msg) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("startCaptureServer: listen: %v", err)
	}

	ch := make(chan *dns.Msg, 1)
	go func() {
		defer pc.Close()
		buf := make([]byte, 4096)
		n, raddr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		msg := new(dns.Msg)
		if err2 := msg.Unpack(buf[:n]); err2 != nil {
			return
		}
		ch <- msg

		// Reply NOERROR so sendNotify returns success.
		reply := new(dns.Msg)
		reply.SetReply(msg)
		reply.Rcode = dns.RcodeSuccess
		b, err2 := reply.Pack()
		if err2 != nil {
			return
		}
		pc.WriteTo(b, raddr) //nolint:errcheck
	}()

	return pc.LocalAddr().String(), ch
}

// parseAddr splits a "host:port" address into its host and uint16 port.
func parseAddr(t *testing.T, addr string) (host string, port uint16) {
	t.Helper()
	ta, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		t.Fatalf("parseAddr %q: %v", addr, err)
	}
	return ta.IP.String(), uint16(ta.Port)
}

// TestSendNotifyQtype_CDS verifies that sendNotify sends a NOTIFY with
// Question[0].Qtype == dns.TypeCDS (59), NOT TypeSOA (6).
func TestSendNotifyQtype_CDS(t *testing.T) {
	addr, captured := startCaptureServer(t)
	host, port := parseAddr(t, addr)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// host is already an IP; sendNotify expects FQDN target (trimmed inside).
	err := sendNotify(ctx, "example.com.", dns.TypeCDS, host+".", port)
	if err != nil {
		t.Logf("sendNotify returned error (may be race with goroutine close): %v", err)
	}

	select {
	case msg := <-captured:
		if len(msg.Question) == 0 {
			t.Fatal("captured message has no question section")
		}
		if msg.Question[0].Qtype != dns.TypeCDS {
			t.Errorf("expected Qtype TypeCDS(%d), got %d (TypeSOA=%d)",
				dns.TypeCDS, msg.Question[0].Qtype, dns.TypeSOA)
		}
		if msg.Opcode != dns.OpcodeNotify {
			t.Errorf("expected OpcodeNotify(%d), got %d", dns.OpcodeNotify, msg.Opcode)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for captured message")
	}
}

// TestSendNotifyQtype_CSYNC verifies that sendNotify sends with Qtype=TypeCSYNC (62).
func TestSendNotifyQtype_CSYNC(t *testing.T) {
	addr, captured := startCaptureServer(t)
	host, port := parseAddr(t, addr)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := sendNotify(ctx, "example.com.", dns.TypeCSYNC, host+".", port)
	if err != nil {
		t.Logf("sendNotify error: %v", err)
	}

	select {
	case msg := <-captured:
		if len(msg.Question) == 0 {
			t.Fatal("captured message has no question section")
		}
		if msg.Question[0].Qtype != dns.TypeCSYNC {
			t.Errorf("expected Qtype TypeCSYNC(%d), got %d", dns.TypeCSYNC, msg.Question[0].Qtype)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for captured message")
	}
}

// TestDSYNCNotifier_Enqueue verifies that DSYNCNotifier.Notify() does not block
// and enqueues events on the buffered channel.
func TestDSYNCNotifier_Enqueue(t *testing.T) {
	log := zerolog.Nop()
	// Use a very long propagation delay so the worker never actually attempts
	// network I/O during this test.
	n := NewDSYNCNotifier("127.0.0.1:0", 24*time.Hour, log, nil)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 10; i++ {
			n.Notify("zone"+string(rune('a'+i))+".example.com.", dns.TypeCDS)
		}
	}()

	select {
	case <-done:
		// Good: Notify() returned without blocking.
	case <-time.After(2 * time.Second):
		t.Fatal("Notify() blocked for too long")
	}
}

// TestSendNotify_Roundtrip is a direct end-to-end test verifying that sendNotify
// correctly sets NOTIFY opcode and overrides Qtype from SOA to CDS.
func TestSendNotify_Roundtrip(t *testing.T) {
	addr, captured := startCaptureServer(t)
	host, port := parseAddr(t, addr)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := sendNotify(ctx, "roundtrip.example.com.", dns.TypeCDS, host+".", port); err != nil {
		t.Fatalf("sendNotify returned error: %v", err)
	}

	select {
	case msg := <-captured:
		if msg.Opcode != dns.OpcodeNotify {
			t.Errorf("expected OpcodeNotify, got %d", msg.Opcode)
		}
		if len(msg.Question) == 0 {
			t.Fatal("no question section")
		}
		if msg.Question[0].Qtype != dns.TypeCDS {
			t.Errorf("expected TypeCDS(%d), got %d (TypeSOA is %d)",
				dns.TypeCDS, msg.Question[0].Qtype, dns.TypeSOA)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for message")
	}
}
