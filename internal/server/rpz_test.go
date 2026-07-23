package server

import (
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/dnsscience/dnsscienced/internal/ede"
	"github.com/dnsscience/dnsscienced/internal/resolver"
	"github.com/dnsscience/dnsscienced/internal/zone"
	"github.com/miekg/dns"
)

func TestServerEnforcesAndReloadsRPZ(t *testing.T) {
	firstPolicy := writeServerRPZFile(t, "blocked.example IN CNAME .")
	srv, err := New(Config{
		RPZ: RPZConfig{
			Enabled: true,
			Zones: []RPZZoneConfig{{
				Name: "primary",
				File: firstPolicy,
			}},
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer srv.Stop() //nolint:errcheck

	resp := queryServer(t, srv, "blocked.example.")
	if resp.Rcode != dns.RcodeNameError {
		t.Fatalf("rcode = %s, want NXDOMAIN", dns.RcodeToString[resp.Rcode])
	}
	edes := ede.GetEDEFromMessage(resp)
	if len(edes) != 1 || edes[0].InfoCode != ede.InfoCodeFiltered {
		t.Fatalf("EDEs = %+v, want one Filtered EDE", edes)
	}
	if edes[0].ExtraText != ede.EDEFiltered.ExtraText {
		t.Fatalf("EDE text = %q, want privacy-safe generic text %q", edes[0].ExtraText, ede.EDEFiltered.ExtraText)
	}

	badConfig := RPZConfig{
		Enabled: true,
		Zones: []RPZZoneConfig{{
			Name: "broken",
			File: filepath.Join(t.TempDir(), "missing.bind"),
		}},
	}
	if err := srv.ReloadRPZ(badConfig); err == nil {
		t.Fatal("expected malformed reload to fail")
	}
	if got := queryServer(t, srv, "blocked.example."); got.Rcode != dns.RcodeNameError {
		t.Fatalf("failed reload replaced last valid policy: rcode=%s", dns.RcodeToString[got.Rcode])
	}

	secondPolicy := writeServerRPZFile(t, "replacement.example IN CNAME .")
	if err := srv.ReloadRPZ(RPZConfig{
		Enabled: true,
		Zones: []RPZZoneConfig{{
			Name: "replacement",
			File: secondPolicy,
		}},
	}); err != nil {
		t.Fatalf("ReloadRPZ: %v", err)
	}
	if got := queryServer(t, srv, "replacement.example."); got.Rcode != dns.RcodeNameError {
		t.Fatalf("replacement policy rcode=%s, want NXDOMAIN", dns.RcodeToString[got.Rcode])
	}
	if stats := srv.GetRPZStats(); len(stats) != 1 || stats[0].Name != "replacement" {
		t.Fatalf("RPZ stats = %+v", stats)
	}
}

func TestRPZPriorityAndPassthru(t *testing.T) {
	allowPolicy := writeServerRPZFile(t, "shared.example IN CNAME rpz-passthru.")
	blockPolicy := writeServerRPZFile(t, "shared.example IN CNAME .")
	srv, err := New(Config{
		RPZ: RPZConfig{
			Enabled: true,
			Zones: []RPZZoneConfig{
				{Name: "block", File: blockPolicy, Priority: 20},
				{Name: "allow", File: allowPolicy, Priority: 10},
			},
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer srv.Stop() //nolint:errcheck

	if stats := srv.GetRPZStats(); len(stats) != 2 || stats[0].Name != "allow" {
		t.Fatalf("precedence = %+v, want allow first", stats)
	}
	if got := queryServer(t, srv, "shared.example."); got.Rcode == dns.RcodeNameError {
		t.Fatal("passthru in the highest-priority zone must override lower-priority block")
	}
}

func TestServerEnforcesClientIPBeforeResolution(t *testing.T) {
	policy := writeServerRPZFile(t, "24.0.2.0.192.rpz-client-ip IN CNAME .")
	srv, err := New(Config{
		RPZ: RPZConfig{
			Enabled: true,
			Zones: []RPZZoneConfig{{
				Name: "quarantine",
				File: policy,
			}},
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer srv.Stop() //nolint:errcheck

	response := queryServer(t, srv, "otherwise-unhandled.example.")
	if response.Rcode != dns.RcodeNameError {
		t.Fatalf("rcode = %s, want client-IP NXDOMAIN", dns.RcodeToString[response.Rcode])
	}
}

func TestServerEnforcesResponseIPOnAuthoritativeAnswer(t *testing.T) {
	policy := writeServerRPZFile(t, "24.0.2.0.192.rpz-ip IN CNAME .")
	srv, err := New(Config{
		EnableAuthoritative: true,
		Zones:               map[string]*zone.Zone{"example.com.": testZone()},
		RPZ: RPZConfig{
			Enabled: true,
			Zones: []RPZZoneConfig{{
				Name: "response-ip",
				File: policy,
			}},
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer srv.Stop() //nolint:errcheck

	response := queryServer(t, srv, "ns1.example.com.")
	if response.Rcode != dns.RcodeNameError || len(response.Answer) != 0 {
		t.Fatalf("response = %+v, want response-IP NXDOMAIN", response)
	}
	edes := ede.GetEDEFromMessage(response)
	if len(edes) != 1 || edes[0].InfoCode != ede.InfoCodeFiltered {
		t.Fatalf("EDEs = %+v, want one Filtered EDE", edes)
	}
}

func TestServerEnforcesResponseIPOnRecursiveAnswer(t *testing.T) {
	upstreamConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	upstream := &dns.Server{
		PacketConn: upstreamConn,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
			response := new(dns.Msg)
			response.SetReply(request)
			response.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{
					Name:   request.Question[0].Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				A: net.ParseIP("203.0.113.9"),
			}}
			_ = w.WriteMsg(response)
		}),
	}
	go func() {
		_ = upstream.ActivateAndServe()
	}()
	defer upstream.Shutdown() //nolint:errcheck

	policy := writeServerRPZFile(t, "24.0.113.0.203.rpz-ip IN CNAME .")
	cfg := DefaultConfig()
	cfg.EnableRecursive = true
	cfg.RecursionAllowedCIDRs = []string{"192.0.2.0/24"}
	cfg.RecursiveConfig.ForwardMode = resolver.ForwardModeOnly
	cfg.RecursiveConfig.Forwarders = []string{upstreamConn.LocalAddr().String()}
	cfg.RecursiveConfig.EnableDNSSEC = false
	cfg.RPZ = RPZConfig{
		Enabled: true,
		Zones: []RPZZoneConfig{{
			Name: "response-ip",
			File: policy,
		}},
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer srv.Stop() //nolint:errcheck

	response := queryServer(t, srv, "forwarded.example.")
	if response.Rcode != dns.RcodeNameError || len(response.Answer) != 0 {
		t.Fatalf("response = %+v, want response-IP NXDOMAIN", response)
	}
}

func TestServerEnforcesRegexRPZ(t *testing.T) {
	srv, err := New(Config{
		RPZ: RPZConfig{
			Enabled: true,
			Zones: []RPZZoneConfig{{
				Name:   "regex",
				Reason: "generated domain",
				RegexRules: []RPZRegexRuleConfig{{
					Pattern: `(^|\.)blocked-[0-9]+\.example\.$`,
					Action:  "nxdomain",
				}},
			}},
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer srv.Stop() //nolint:errcheck

	if got := queryServer(t, srv, "blocked-42.example."); got.Rcode != dns.RcodeNameError {
		t.Fatalf("regex policy rcode=%s, want NXDOMAIN", dns.RcodeToString[got.Rcode])
	}
	if stats := srv.GetRPZStats(); len(stats) != 1 || stats[0].RegexRules != 1 {
		t.Fatalf("RPZ stats = %+v, want one regex rule", stats)
	}
}

func TestRPZReloadConcurrentQueries(t *testing.T) {
	blockPolicy := writeServerRPZFile(t, "blocked.example IN CNAME .")
	allowPolicy := writeServerRPZFile(t, "other.example IN CNAME .")
	srv, err := New(Config{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer srv.Stop() //nolint:errcheck

	configs := []RPZConfig{
		{Enabled: true, Zones: []RPZZoneConfig{{Name: "block", File: blockPolicy}}},
		{Enabled: true, Zones: []RPZZoneConfig{{Name: "allow", File: allowPolicy}}},
		{},
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		req := new(dns.Msg)
		req.SetQuestion("blocked.example.", dns.TypeA)
		for range 200 {
			resp := new(dns.Msg)
			resp.SetReply(req)
			srv.applyRPZ(req, resp)
		}
	}()
	go func() {
		defer wg.Done()
		for i := range 60 {
			if err := srv.ReloadRPZ(configs[i%len(configs)]); err != nil {
				t.Errorf("ReloadRPZ: %v", err)
				return
			}
		}
	}()
	wg.Wait()
}

func queryServer(t *testing.T, srv *Server, name string) *dns.Msg {
	t.Helper()
	req := new(dns.Msg)
	req.SetQuestion(name, dns.TypeA)
	req.SetEdns0(1232, false)
	writer := newTestResponseWriter("192.0.2.10")
	srv.handleDNS(writer, req)
	if writer.msg == nil {
		t.Fatal("query produced no response")
	}
	return writer.msg
}

func writeServerRPZFile(t *testing.T, rule string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rpz.example.bind")
	contents := `$ORIGIN rpz.example.
$TTL 60
@ IN SOA localhost. hostmaster.localhost. 1 60 60 60 60
@ IN NS localhost.
` + rule + "\n"
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	return path
}
