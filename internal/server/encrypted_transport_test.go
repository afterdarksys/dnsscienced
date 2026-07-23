package server

import (
	"context"
	"net"
	"testing"

	"github.com/miekg/dns"
)

func TestEncryptedTransportUsesClientAddressForRecursionACL(t *testing.T) {
	cfg := DefaultConfig()
	cfg.UDPListeners = 1
	cfg.EnableRecursive = true
	cfg.RecursionAllowedCIDRs = []string{"192.0.2.0/24"}
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	req.RecursionDesired = true
	resp, err := srv.HandleDNS(context.Background(), req, &net.TCPAddr{IP: net.ParseIP("198.51.100.8"), Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Rcode != dns.RcodeRefused || resp.RecursionAvailable {
		t.Fatalf("response rcode=%s RA=%v, want REFUSED RA=false", dns.RcodeToString[resp.Rcode], resp.RecursionAvailable)
	}
}

func TestEncryptedTransportFailsClosedForUnverifiedTSIG(t *testing.T) {
	cfg := DefaultConfig()
	cfg.UDPListeners = 1
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()

	req := new(dns.Msg)
	req.SetUpdate("example.com.")
	req.SetTsig("update-key.", dns.HmacSHA256, 300, 0)
	resp, err := srv.HandleDNS(context.Background(), req, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 853})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Rcode != dns.RcodeNotAuth {
		t.Fatalf("rcode = %s, want NOTAUTH", dns.RcodeToString[resp.Rcode])
	}
}
