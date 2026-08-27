package protective

import (
	"net"
	"testing"

	"github.com/afterdarksys/dnsscienced/internal/experimental"
	"github.com/miekg/dns"
)

func TestEngine_CheckQuery(t *testing.T) {
	config := experimental.ProtectiveDNSConfig{
		Enabled:  true,
		Strategy: "nxdomain",
		Categories: []string{"malware", "phishing"},
	}

	engine, err := NewEngine(config)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}

	// Add test entries to blocklist
	engine.blocklist.Add("malware.example.com", "malware", "test")
	engine.blocklist.Add("phishing.example.com", "phishing", "test")

	tests := []struct {
		name     string
		domain   string
		wantBlocked bool
		wantCategory string
	}{
		{
			name:     "malware domain blocked",
			domain:   "malware.example.com",
			wantBlocked: true,
			wantCategory: "malware",
		},
		{
			name:     "phishing domain blocked",
			domain:   "phishing.example.com",
			wantBlocked: true,
			wantCategory: "phishing",
		},
		{
			name:     "clean domain allowed",
			domain:   "clean.example.com",
			wantBlocked: false,
		},
		{
			name:     "subdomain of blocked domain blocked",
			domain:   "sub.malware.example.com",
			wantBlocked: true,
			wantCategory: "malware",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := engine.CheckQuery(tt.domain, net.ParseIP("192.0.2.1"))
			if err != nil {
				t.Fatalf("CheckQuery failed: %v", err)
			}

			if result.Blocked != tt.wantBlocked {
				t.Errorf("CheckQuery(%s) blocked = %v, want %v", tt.domain, result.Blocked, tt.wantBlocked)
			}

			if tt.wantBlocked && result.Category != tt.wantCategory {
				t.Errorf("CheckQuery(%s) category = %s, want %s", tt.domain, result.Category, tt.wantCategory)
			}
		})
	}
}

func TestEngine_RewriteStrategies(t *testing.T) {
	tests := []struct {
		name     string
		strategy string
		qtype    uint16
		validate func(*testing.T, *dns.Msg)
	}{
		{
			name:     "nxdomain strategy",
			strategy: "nxdomain",
			qtype:    dns.TypeA,
			validate: func(t *testing.T, msg *dns.Msg) {
				if msg.Rcode != dns.RcodeNameError {
					t.Errorf("Expected NXDOMAIN, got %s", dns.RcodeToString[msg.Rcode])
				}
				if len(msg.Answer) != 0 {
					t.Errorf("Expected empty answer section, got %d records", len(msg.Answer))
				}
			},
		},
		{
			name:     "servfail strategy",
			strategy: "servfail",
			qtype:    dns.TypeA,
			validate: func(t *testing.T, msg *dns.Msg) {
				if msg.Rcode != dns.RcodeServerFailure {
					t.Errorf("Expected SERVFAIL, got %s", dns.RcodeToString[msg.Rcode])
				}
			},
		},
		{
			name:     "localhost strategy IPv4",
			strategy: "localhost",
			qtype:    dns.TypeA,
			validate: func(t *testing.T, msg *dns.Msg) {
				if len(msg.Answer) == 0 {
					t.Fatal("Expected answer section")
				}
				a, ok := msg.Answer[0].(*dns.A)
				if !ok {
					t.Fatal("Expected A record")
				}
				if !a.A.Equal(net.IPv4(127, 0, 0, 1)) {
					t.Errorf("Expected 127.0.0.1, got %s", a.A)
				}
			},
		},
		{
			name:     "localhost strategy IPv6",
			strategy: "localhost",
			qtype:    dns.TypeAAAA,
			validate: func(t *testing.T, msg *dns.Msg) {
				if len(msg.Answer) == 0 {
					t.Fatal("Expected answer section")
				}
				aaaa, ok := msg.Answer[0].(*dns.AAAA)
				if !ok {
					t.Fatal("Expected AAAA record")
				}
				if !aaaa.AAAA.Equal(net.IPv6loopback) {
					t.Errorf("Expected ::1, got %s", aaaa.AAAA)
				}
			},
		},
		{
			name:     "redirect strategy IPv4",
			strategy: "redirect",
			qtype:    dns.TypeA,
			validate: func(t *testing.T, msg *dns.Msg) {
				if len(msg.Answer) == 0 {
					t.Fatal("Expected answer section")
				}
				a, ok := msg.Answer[0].(*dns.A)
				if !ok {
					t.Fatal("Expected A record")
				}
				expected := net.ParseIP("0.0.0.0")
				if !a.A.Equal(expected) {
					t.Errorf("Expected %s, got %s", expected, a.A)
				}
			},
		},
		{
			name:     "empty strategy",
			strategy: "empty",
			qtype:    dns.TypeA,
			validate: func(t *testing.T, msg *dns.Msg) {
				if msg.Rcode != dns.RcodeSuccess {
					t.Errorf("Expected NOERROR, got %s", dns.RcodeToString[msg.Rcode])
				}
				if len(msg.Answer) != 0 {
					t.Errorf("Expected empty answer section, got %d records", len(msg.Answer))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := experimental.ProtectiveDNSConfig{
				Enabled:      true,
				Strategy:     tt.strategy,
				RedirectIPv4: "0.0.0.0",
				RedirectIPv6: "::",
				CNAMETarget:  "blocked.example.com",
				CustomTTL:    60,
			}

			engine, err := NewEngine(config)
			if err != nil {
				t.Fatalf("NewEngine failed: %v", err)
			}

			// Create query
			query := new(dns.Msg)
			query.SetQuestion("blocked.example.com.", tt.qtype)

			// Create block result
			result := &BlockResult{
				Blocked:  true,
				Domain:   "blocked.example.com",
				Category: "malware",
				Source:   "test",
			}

			// Rewrite response
			response := engine.RewriteResponse(query, result)

			// Validate
			tt.validate(t, response)
		})
	}
}

func TestEngine_ExemptDomains(t *testing.T) {
	config := experimental.ProtectiveDNSConfig{
		Enabled:       true,
		Strategy:      "nxdomain",
		ExemptDomains: []string{"trusted.com"},
	}

	engine, err := NewEngine(config)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}

	// Add domain to blocklist
	engine.blocklist.Add("trusted.com", "malware", "test")

	// Check if domain is still allowed (due to exemption)
	result, err := engine.CheckQuery("trusted.com", net.ParseIP("192.0.2.1"))
	if err != nil {
		t.Fatalf("CheckQuery failed: %v", err)
	}

	if result.Blocked {
		t.Error("Expected domain to be allowed due to exemption")
	}
}

func TestEngine_ExemptClients(t *testing.T) {
	config := experimental.ProtectiveDNSConfig{
		Enabled:       true,
		Strategy:      "nxdomain",
		ExemptClients: []string{"192.0.2.0/24"},
	}

	engine, err := NewEngine(config)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}

	// Add domain to blocklist
	engine.blocklist.Add("malware.example.com", "malware", "test")

	// Check from exempt client
	result, err := engine.CheckQuery("malware.example.com", net.ParseIP("192.0.2.10"))
	if err != nil {
		t.Fatalf("CheckQuery failed: %v", err)
	}

	if result.Blocked {
		t.Error("Expected domain to be allowed due to client exemption")
	}

	// Check from non-exempt client
	result, err = engine.CheckQuery("malware.example.com", net.ParseIP("198.51.100.1"))
	if err != nil {
		t.Fatalf("CheckQuery failed: %v", err)
	}

	if !result.Blocked {
		t.Error("Expected domain to be blocked for non-exempt client")
	}
}

func TestEngine_Statistics(t *testing.T) {
	config := experimental.ProtectiveDNSConfig{
		Enabled:  true,
		Strategy: "nxdomain",
	}

	engine, err := NewEngine(config)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}

	// Add test entries
	engine.blocklist.Add("malware.example.com", "malware", "test")
	engine.blocklist.Add("phishing.example.com", "phishing", "test")

	// Run some queries
	engine.CheckQuery("malware.example.com", net.ParseIP("192.0.2.1"))
	engine.CheckQuery("phishing.example.com", net.ParseIP("192.0.2.1"))
	engine.CheckQuery("clean.example.com", net.ParseIP("192.0.2.1"))

	// Check statistics
	stats := engine.GetStats()

	if stats.QueriesTotal != 3 {
		t.Errorf("Expected 3 total queries, got %d", stats.QueriesTotal)
	}

	if stats.QueriesBlocked != 2 {
		t.Errorf("Expected 2 blocked queries, got %d", stats.QueriesBlocked)
	}

	if stats.QueriesAllowed != 1 {
		t.Errorf("Expected 1 allowed query, got %d", stats.QueriesAllowed)
	}

	if stats.BlockedByCategory["malware"] != 1 {
		t.Errorf("Expected 1 malware block, got %d", stats.BlockedByCategory["malware"])
	}

	if stats.BlockedByCategory["phishing"] != 1 {
		t.Errorf("Expected 1 phishing block, got %d", stats.BlockedByCategory["phishing"])
	}
}
