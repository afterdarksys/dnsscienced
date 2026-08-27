package server

import (
	"context"
	"encoding/base64"
	"net"
	"testing"
	"time"

	"github.com/afterdarksys/dnsscienced/internal/primarynotify"
	"github.com/afterdarksys/dnsscienced/internal/tsig"
	"github.com/miekg/dns"
)

func TestAddZoneTriggersConfiguredPrimaryNotify(t *testing.T) {
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	received := make(chan *dns.Msg, 1)
	receiver := &dns.Server{
		PacketConn: packetConn,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
			received <- request.Copy()
			response := new(dns.Msg)
			response.SetReply(request)
			_ = w.WriteMsg(response)
		}),
	}
	done := make(chan error, 1)
	go func() {
		done <- receiver.ActivateAndServe()
	}()
	defer func() {
		_ = receiver.Shutdown()
		<-done
	}()

	cfg := DefaultConfig()
	cfg.UDPListeners = 1
	cfg.PrimaryNotifyWorkers = 1
	cfg.PrimaryNotifyZones = map[string]primarynotify.ZoneConfig{
		"example.com.": {
			Targets:       []string{packetConn.LocalAddr().String()},
			AllowUnsigned: true,
			Attempts:      1,
			Timeout:       time.Second,
		},
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Stop() //nolint:errcheck
	if err := s.primaryNotifier.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := s.AddZone(testZone()); err != nil {
		t.Fatal(err)
	}

	select {
	case request := <-received:
		if request.Opcode != dns.OpcodeNotify ||
			len(request.Question) != 1 ||
			request.Question[0].Name != "example.com." ||
			len(request.Answer) != 1 {
			t.Fatalf("NOTIFY request = %v", request)
		}
	case <-time.After(time.Second):
		t.Fatal("AddZone did not trigger NOTIFY")
	}
}

func TestNewRejectsPrimaryNotifyAlgorithmMismatch(t *testing.T) {
	cfg := DefaultConfig()
	cfg.UDPListeners = 1
	cfg.TsigKeys = []tsig.KeyConfig{{
		Name:      "notify.example.",
		Algorithm: "hmac-sha512",
		Secret:    base64.StdEncoding.EncodeToString([]byte("notify-secret")),
	}}
	cfg.PrimaryNotifyZones = map[string]primarynotify.ZoneConfig{
		"example.com.": {
			Targets:       []string{"192.0.2.2"},
			TSIGKey:       "notify.example.",
			TSIGAlgorithm: dns.HmacSHA256,
		},
	}
	if _, err := New(cfg); err == nil {
		t.Fatal("New accepted a NOTIFY algorithm that does not match the configured TSIG key")
	}
}
