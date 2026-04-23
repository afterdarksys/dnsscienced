package firewalld

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// makeQuery builds a simple DNS query message.
func makeQuery(name string, qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	return m
}

var localhost = net.ParseIP("127.0.0.1")

// makeQueryWithCustomerID builds a DNS query message with a custom EDNS0 option
// carrying the given customerID value at code 65000.
func makeQueryWithCustomerID(name string, qtype uint16, customerID string) *dns.Msg {
	m := makeQuery(name, qtype)
	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	opt.Option = append(opt.Option, &dns.EDNS0_LOCAL{
		Code: edns0CustomerIDCode,
		Data: []byte(customerID),
	})
	m.Extra = append(m.Extra, opt)
	return m
}

// ---- JunkDetector tests ----

func TestJunkDetector_DGA(t *testing.T) {
	jd := newJunkDetector(JunkConfig{BlockDGA: true, RandomSubdomainThreshold: 4.0})

	tests := []struct {
		name    string
		domain  string
		wantDGA bool
	}{
		{"legit short", "google.com", false},
		{"legit branded", "example.com", false},
		// High-entropy SLD consistent with DGA.
		// Need 19+ unique chars in the SLD for Shannon entropy > 4.2 (log2(19)=4.25).
		{"dga-like", "qzxmvpkblrtnfjsghdye.com", true},
		{"dga-like-long", "abcdefghijklmnopqrst.net", true},
		// Short domains are never DGA
		{"short", "abc.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			qctx := &QueryContext{
				Msg:      makeQuery(tt.domain, dns.TypeA),
				ClientIP: localhost,
				Name:     dns.Fqdn(tt.domain),
				Qtype:    dns.TypeA,
			}
			d := jd.Detect(qctx)
			if tt.wantDGA {
				assert.Equal(t, VerdictNXDomain, d.Verdict, "expected NXDomain for DGA domain %q", tt.domain)
				assert.Equal(t, "junk:dga", d.RuleName)
			} else {
				assert.Equal(t, VerdictAllow, d.Verdict, "expected Allow for %q", tt.domain)
			}
		})
	}
}

func TestJunkDetector_DataExfil(t *testing.T) {
	jd := newJunkDetector(JunkConfig{BlockDataExfil: true, RandomSubdomainThreshold: 4.0})

	// Craft a name longer than 60 chars with high entropy (base64-like).
	longExfil := "aGVsbG8td29ybGQtdGhpcy1pcy1hLWxvbmctZW5jb2RlZC1zdHJpbmctZm9y.example.com"
	qctx := &QueryContext{
		Msg:      makeQuery(longExfil, dns.TypeA),
		ClientIP: localhost,
		Name:     dns.Fqdn(longExfil),
		Qtype:    dns.TypeA,
	}
	d := jd.Detect(qctx)
	assert.Equal(t, VerdictNXDomain, d.Verdict)
	assert.Equal(t, "junk:data_exfil", d.RuleName)

	// Short name should pass.
	qctx2 := &QueryContext{Name: dns.Fqdn("short.example.com"), ClientIP: localhost}
	d2 := jd.Detect(qctx2)
	assert.Equal(t, VerdictAllow, d2.Verdict)
}

func TestJunkDetector_RandomSubdomain(t *testing.T) {
	jd := newJunkDetector(JunkConfig{
		BlockRandomSubdomain:     true,
		RandomSubdomainThreshold: 4.0,
	})

	// Bot-style query: leftmost label needs 17+ unique chars for entropy > 4.0.
	junkName := "abcde12345fghijklmn.foo.com"
	qctx := &QueryContext{Name: dns.Fqdn(junkName), ClientIP: localhost}
	d := jd.Detect(qctx)
	assert.Equal(t, VerdictNXDomain, d.Verdict)
	assert.Equal(t, "junk:random_subdomain", d.RuleName)

	// Normal subdomain should pass.
	qctx2 := &QueryContext{Name: dns.Fqdn("www.foo.com"), ClientIP: localhost}
	d2 := jd.Detect(qctx2)
	assert.Equal(t, VerdictAllow, d2.Verdict)
}

// ---- ThreatIntel tests ----

func TestThreatIntel_Score(t *testing.T) {
	ti := newThreatIntel(ThreatIntelConfig{
		BlockThreshold: 80,
		StaticIPScores: map[string]int{
			"10.0.0.0/8": 70,
		},
		ZoneScores: map[string]int{
			"bad.example": 30,
		},
		CustomerMeta: map[string]CustomerMeta{
			"cust-001": {AccountType: "enterprise", TrustBonus: 20},
		},
	})

	// IP in bad range.
	qctx := &QueryContext{
		Name:     "www.example.com.",
		ClientIP: net.ParseIP("10.1.2.3"),
	}
	score := ti.Score(qctx)
	assert.Equal(t, 70, score)

	// Zone score adds.
	qctx2 := &QueryContext{
		Name:     "www.bad.example.",
		ClientIP: net.ParseIP("10.1.2.3"),
	}
	score2 := ti.Score(qctx2)
	assert.Equal(t, 100, score2, "should be clamped to 100 (70+30)")

	// Customer trust bonus reduces.
	qctx3 := &QueryContext{
		Name:       "www.bad.example.",
		ClientIP:   net.ParseIP("10.1.2.3"),
		CustomerID: "cust-001",
	}
	score3 := ti.Score(qctx3)
	assert.Equal(t, 80, score3, "100 - 20 trust bonus")
}

func TestThreatIntel_DynamicScores(t *testing.T) {
	ti := newThreatIntel(ThreatIntelConfig{BlockThreshold: 80})

	ti.AddIPScore("1.2.3.4", 90)
	qctx := &QueryContext{Name: "example.com.", ClientIP: net.ParseIP("1.2.3.4")}
	assert.Equal(t, 90, ti.Score(qctx))

	ti.AddDomainScore("evil.org", 50)
	qctx2 := &QueryContext{Name: "www.evil.org.", ClientIP: net.ParseIP("8.8.8.8")}
	assert.Equal(t, 50, ti.Score(qctx2))

	ti.RemoveDomainScore("evil.org")
	assert.Equal(t, 0, ti.Score(qctx2))
}

// ---- PolicyEngine tests ----

func TestPolicyEngine_StaticRules(t *testing.T) {
	rules := []RuleConfig{
		{
			Name:   "block-bad-tld",
			Match:  MatchConfig{DomainSuffix: ".bad."},
			Action: "nxdomain",
		},
		{
			Name:   "allow-safe",
			Match:  MatchConfig{DomainExact: "safe.bad."},
			Action: "allow",
		},
		{
			Name:          "rewrite-test",
			Match:         MatchConfig{DomainSuffix: ".rewrite."},
			Action:        "rewrite",
			RewriteTarget: "sink.example.com.",
		},
	}

	pe, err := newPolicyEngine(rules)
	require.NoError(t, err)

	// First matching rule: allow for safe.bad (exact match listed second but
	// evaluated in order, so block-bad-tld fires first).
	qctx := &QueryContext{Name: "anything.bad.", ClientIP: localhost}
	d := pe.Evaluate(qctx)
	assert.Equal(t, VerdictNXDomain, d.Verdict)

	// Rewrite rule.
	qctx2 := &QueryContext{Name: "foo.rewrite.", ClientIP: localhost}
	d2 := pe.Evaluate(qctx2)
	assert.Equal(t, VerdictRewrite, d2.Verdict)
	assert.Equal(t, "sink.example.com.", d2.Target)

	// No match: allow.
	qctx3 := &QueryContext{Name: "google.com.", ClientIP: localhost}
	d3 := pe.Evaluate(qctx3)
	assert.Equal(t, VerdictAllow, d3.Verdict)
}

func TestPolicyEngine_InvalidRule(t *testing.T) {
	_, err := newPolicyEngine([]RuleConfig{
		{Name: "bad", Match: MatchConfig{}, Action: "rewrite"},
	})
	assert.Error(t, err, "rewrite without target should fail")
}

// ---- Starlark engine tests ----

func TestStarlarkEngine_NXDomain(t *testing.T) {
	se, err := newStarlarkEngine(0)
	require.NoError(t, err)

	src := `
def on_query(q, score):
    if q["name"].endswith(".blocked."):
        firewall.nxdomain(reason="geo block test")
`
	require.NoError(t, se.Load("test-geo", src))

	qctx := &QueryContext{Name: "www.blocked.", ClientIP: localhost}
	d := se.Run(qctx, 0)
	assert.Equal(t, VerdictNXDomain, d.Verdict)
	assert.Equal(t, "geo block test", d.Reason)

	qctx2 := &QueryContext{Name: "www.allowed.", ClientIP: localhost}
	d2 := se.Run(qctx2, 0)
	assert.Equal(t, VerdictAllow, d2.Verdict)
}

func TestStarlarkEngine_Rewrite(t *testing.T) {
	se, err := newStarlarkEngine(0)
	require.NoError(t, err)

	src := `
def on_query(q, score):
    if score > 50:
        firewall.rewrite(target="sinkhole.example.", reason="high score")
`
	require.NoError(t, se.Load("test-score", src))

	qctx := &QueryContext{Name: "example.com.", ClientIP: localhost}
	d := se.Run(qctx, 75)
	assert.Equal(t, VerdictRewrite, d.Verdict)
	assert.Equal(t, "sinkhole.example.", d.Target)
}

func TestStarlarkEngine_Drop(t *testing.T) {
	se, err := newStarlarkEngine(0)
	require.NoError(t, err)

	src := `
def on_query(q, score):
    if q["client_ip"].startswith("192.168."):
        firewall.drop(reason="internal")
`
	require.NoError(t, se.Load("test-drop", src))

	qctx := &QueryContext{Name: "example.com.", ClientIP: net.ParseIP("192.168.1.1")}
	d := se.Run(qctx, 0)
	assert.Equal(t, VerdictDrop, d.Verdict)
}

func TestStarlarkEngine_NoOnQuery(t *testing.T) {
	se, err := newStarlarkEngine(0)
	require.NoError(t, err)

	// Script with no on_query function should allow.
	src := `x = 1 + 1`
	require.NoError(t, se.Load("test-noop", src))

	qctx := &QueryContext{Name: "example.com.", ClientIP: localhost}
	d := se.Run(qctx, 0)
	assert.Equal(t, VerdictAllow, d.Verdict)
}

// ---- Firewall integration tests ----

func TestFirewall_Disabled(t *testing.T) {
	fw, err := New(Config{Enabled: false})
	require.NoError(t, err)
	assert.Nil(t, fw, "disabled firewall should return nil")
}

func TestFirewall_BlockDGA(t *testing.T) {
	fw, err := New(Config{
		Enabled: true,
		Junk:    JunkConfig{BlockDGA: true},
		ThreatIntel: ThreatIntelConfig{
			BlockThreshold: 100,
		},
	})
	require.NoError(t, err)

	// 20 unique chars in SLD → entropy ≈ 4.32 > threshold of 4.2.
	r := makeQuery("qzxmvpkblrtnfjsghdye.com", dns.TypeA)
	d := fw.Check(r, localhost)
	assert.Equal(t, VerdictNXDomain, d.Verdict)
}

func TestFirewall_AllowLegit(t *testing.T) {
	fw, err := New(Config{
		Enabled: true,
		Junk:    JunkConfig{BlockDGA: true},
		ThreatIntel: ThreatIntelConfig{
			BlockThreshold: 80,
		},
	})
	require.NoError(t, err)

	r := makeQuery("google.com", dns.TypeA)
	d := fw.Check(r, localhost)
	assert.Equal(t, VerdictAllow, d.Verdict)
}

func TestFirewall_ThreatScoreBlock(t *testing.T) {
	fw, err := New(Config{
		Enabled: true,
		ThreatIntel: ThreatIntelConfig{
			BlockThreshold: 70,
			StaticIPScores: map[string]int{
				"10.0.0.0/8": 75,
			},
		},
	})
	require.NoError(t, err)

	r := makeQuery("example.com", dns.TypeA)
	d := fw.Check(r, net.ParseIP("10.5.5.5"))
	assert.Equal(t, VerdictNXDomain, d.Verdict)
	assert.Equal(t, "threat_intel", d.RuleName)
}

func TestFirewall_Apply_NXDomain(t *testing.T) {
	fw, err := New(Config{Enabled: true, ThreatIntel: ThreatIntelConfig{BlockThreshold: 100}})
	require.NoError(t, err)

	r := makeQuery("example.com", dns.TypeA)
	d := &Decision{Verdict: VerdictNXDomain, Reason: "test"}
	resp := fw.Apply(r, d)
	require.NotNil(t, resp)
	assert.Equal(t, dns.RcodeNameError, resp.Rcode)
}

func TestFirewall_Apply_Rewrite(t *testing.T) {
	fw, err := New(Config{Enabled: true, ThreatIntel: ThreatIntelConfig{BlockThreshold: 100}})
	require.NoError(t, err)

	r := makeQuery("example.com", dns.TypeA)
	d := &Decision{Verdict: VerdictRewrite, Target: "sink.example.com.", Reason: "test"}
	resp := fw.Apply(r, d)
	require.NotNil(t, resp)
	require.Len(t, resp.Answer, 1)
	cname, ok := resp.Answer[0].(*dns.CNAME)
	require.True(t, ok)
	assert.Equal(t, "sink.example.com.", cname.Target)
}

func TestFirewall_StarlarkIntegration(t *testing.T) {
	fw, err := New(Config{
		Enabled:       true,
		ScriptTimeout: 0,
		ThreatIntel:   ThreatIntelConfig{BlockThreshold: 100},
	})
	require.NoError(t, err)

	src := `
def on_query(q, score):
    if "starlark-blocked" in q["name"]:
        firewall.nxdomain(reason="starlark integration test")
`
	// Load inline script directly via the starlark engine (no file I/O).
	require.NoError(t, fw.starlark.Load("inline:test", src))

	r := makeQuery("starlark-blocked.example.com", dns.TypeA)
	d := fw.Check(r, localhost)
	assert.Equal(t, VerdictNXDomain, d.Verdict)
	assert.Contains(t, d.Reason, "starlark integration test")
}

func TestFirewall_Stats(t *testing.T) {
	fw, err := New(Config{
		Enabled: true,
		Junk:    JunkConfig{BlockDGA: true},
		ThreatIntel: ThreatIntelConfig{BlockThreshold: 100},
	})
	require.NoError(t, err)

	// DGA query → blocked (20 unique chars in SLD → entropy > 4.2).
	fw.Check(makeQuery("qzxmvpkblrtnfjsghdye.com", dns.TypeA), localhost)
	// Legit query → allowed.
	fw.Check(makeQuery("google.com", dns.TypeA), localhost)

	stats := fw.Stats()
	assert.Equal(t, uint64(2), stats.TotalQueries)
	assert.Equal(t, uint64(1), stats.TotalBlocked)
	assert.Equal(t, uint64(1), stats.TotalNXDomain)
}

// ---- EDNS0 CustomerID tests ----

func TestExtractCustomerID(t *testing.T) {
	logger := zerolog.Nop()
	tests := []struct {
		name       string
		msg        *dns.Msg
		wantResult string
	}{
		{
			name:       "present",
			msg:        makeQueryWithCustomerID("example.com.", dns.TypeA, "cust-abc"),
			wantResult: "cust-abc",
		},
		{
			name:       "no_opt",
			msg:        makeQuery("example.com.", dns.TypeA),
			wantResult: "",
		},
		{
			name: "wrong_code",
			msg: func() *dns.Msg {
				m := makeQuery("example.com.", dns.TypeA)
				opt := new(dns.OPT)
				opt.Hdr.Name = "."
				opt.Hdr.Rrtype = dns.TypeOPT
				opt.Option = append(opt.Option, &dns.EDNS0_LOCAL{
					Code: 65001, // dns.EDNS0LOCALSTART — not our code
					Data: []byte("other"),
				})
				m.Extra = append(m.Extra, opt)
				return m
			}(),
			wantResult: "",
		},
		{
			name:       "oversized",
			msg:        makeQueryWithCustomerID("example.com.", dns.TypeA, string(make([]byte, 65))),
			wantResult: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractCustomerID(tt.msg, logger)
			assert.Equal(t, tt.wantResult, got)
		})
	}
}

func TestFirewall_CustomerIDExtracted(t *testing.T) {
	// Confirm that Firewall.Check() populates qctx.CustomerID before evaluation.
	// We verify via the ThreatIntel customer trust bonus: configure a customer
	// with a trust bonus so the score is reduced when CustomerID is extracted.
	fw, err := New(Config{
		Enabled: true,
		ThreatIntel: ThreatIntelConfig{
			BlockThreshold: 100,
			StaticIPScores: map[string]int{
				"10.0.0.0/8": 50,
			},
			CustomerMeta: map[string]CustomerMeta{
				"cust-test": {AccountType: "enterprise", TrustBonus: 50},
			},
		},
	})
	require.NoError(t, err)

	// Query WITH customer ID — trust bonus reduces score below threshold → Allow.
	withID := makeQueryWithCustomerID("example.com.", dns.TypeA, "cust-test")
	result := fw.Check(withID, net.ParseIP("10.1.2.3"))
	require.NotNil(t, result)
	// Score would be 50 (IP) - 50 (trust bonus) = 0 → below threshold → Allow.
	assert.Equal(t, VerdictAllow, result.Verdict, "CustomerID trust bonus should reduce score to 0")
}

func TestFirewall_CustomerIDTrustBonus(t *testing.T) {
	// Verify that Firewall.Check() with a valid CustomerID results in the
	// trust bonus path in threat_intel.Score() being exercised.
	// CustomerID must be populated BEFORE intel.Score() is called (D-04).
	fw, err := New(Config{
		Enabled: true,
		ThreatIntel: ThreatIntelConfig{
			BlockThreshold: 80,
			StaticIPScores: map[string]int{
				"10.0.0.0/8": 90,
			},
			CustomerMeta: map[string]CustomerMeta{
				"cust-bonus": {AccountType: "enterprise", TrustBonus: 20},
			},
		},
	})
	require.NoError(t, err)

	// A query without CustomerID — score = 90 → blocked (>= threshold 80).
	noID := makeQuery("example.com.", dns.TypeA)
	result1 := fw.Check(noID, net.ParseIP("10.1.2.3"))
	require.NotNil(t, result1)
	assert.Equal(t, VerdictNXDomain, result1.Verdict, "without CustomerID, high score should block")

	// A query with CustomerID — score = 90 - 20 = 70 → allowed (< threshold 80).
	withID := makeQueryWithCustomerID("example.com.", dns.TypeA, "cust-bonus")
	result2 := fw.Check(withID, net.ParseIP("10.1.2.3"))
	require.NotNil(t, result2)
	assert.Equal(t, VerdictAllow, result2.Verdict, "with CustomerID trust bonus, score should drop below threshold")
}

func TestFirewall_NoCustomerID_Allowed(t *testing.T) {
	// Queries without EDNS0 option must proceed normally; CustomerID stays "".
	fw, err := New(Config{
		Enabled:     true,
		ThreatIntel: ThreatIntelConfig{BlockThreshold: 100},
	})
	require.NoError(t, err)

	m := makeQuery("example.com.", dns.TypeA)
	result := fw.Check(m, net.ParseIP("127.0.0.1"))
	require.NotNil(t, result)
	assert.Equal(t, VerdictAllow, result.Verdict)
}

// --- TDD RED: redirect builtin uses pool (REDIR-03) ---
// This test fails until starlark.go is updated to call pool.Next() instead of
// requiring server= kwarg.

func TestRedirect_PoolBehavior_RED(t *testing.T) {
	fw, err := New(Config{
		Enabled:       true,
		DefaultAction: "allow",
		ScriptTimeout: 2 * time.Millisecond,
		ThreatIntel:   ThreatIntelConfig{BlockThreshold: 100},
		Redirect:      RedirectConfig{Upstreams: []string{"1.1.1.1:53", "2.2.2.2:53"}},
	})
	require.NoError(t, err)
	require.NotNil(t, fw)

	// Script calls redirect() with NO server= arg — pool should be used.
	script := `
def on_query(q, score):
    firewall.redirect(reason="pool test")
`
	require.NoError(t, fw.LoadSource("red-test", script))

	q := makeQuery("example.com", dns.TypeA)
	d := fw.Check(q, net.ParseIP("127.0.0.1"))
	assert.Equal(t, VerdictRedirect, d.Verdict)
	assert.Contains(t, []string{"1.1.1.1:53", "2.2.2.2:53"}, d.Server,
		"redirect must select from configured pool upstreams")
}

// --- UpstreamPool unit tests (REDIR-01, REDIR-02) ---
// Note: TestUpstreamPool_RoundRobin and TestUpstreamPool_SingleUpstream already exist in
// forwarder_test.go (Plan 01 artifact). Only the assert-style variant for empty pool is added here.

func TestUpstreamPool_Empty(t *testing.T) {
	p := newUpstreamPool(nil)
	_, err := p.Next()
	assert.Error(t, err, "empty pool must return an error")
}

// --- Starlark redirect integration tests (REDIR-03) ---

func TestStarlarkRedirect_UsesPool(t *testing.T) {
	fw, err := New(Config{
		Enabled:       true,
		DefaultAction: "allow",
		ScriptTimeout: 2 * time.Millisecond,
		ThreatIntel:   ThreatIntelConfig{BlockThreshold: 100},
		Redirect:      RedirectConfig{Upstreams: []string{"1.1.1.1:53", "2.2.2.2:53"}},
	})
	require.NoError(t, err)
	require.NotNil(t, fw)

	script := `
def on_query(q, score):
    firewall.redirect(reason="pool test")
`
	require.NoError(t, fw.LoadSource("test-redirect-pool", script))

	q := makeQuery("example.com", dns.TypeA)
	d := fw.Check(q, net.ParseIP("127.0.0.1"))
	assert.Equal(t, VerdictRedirect, d.Verdict)
	assert.Contains(t, []string{"1.1.1.1:53", "2.2.2.2:53"}, d.Server,
		"redirect must select from configured pool upstreams")
	assert.Equal(t, "pool test", d.Reason)
}

func TestStarlarkRedirect_ServerArgRejected(t *testing.T) {
	fw, err := New(Config{
		Enabled:       true,
		DefaultAction: "allow",
		ScriptTimeout: 2 * time.Millisecond,
		ThreatIntel:   ThreatIntelConfig{BlockThreshold: 100},
		Redirect:      RedirectConfig{Upstreams: []string{"1.1.1.1:53"}},
	})
	require.NoError(t, err)
	require.NotNil(t, fw)

	// Script that passes the now-removed server= kwarg.
	script := `
def on_query(q, score):
    firewall.redirect(server="9.9.9.9:53", reason="old api")
`
	require.NoError(t, fw.LoadSource("test-redirect-server-arg", script))

	q := makeQuery("example.com", dns.TypeA)
	// The builtin returns an error at evaluation time; starlark.Run() logs and
	// continues, so the final verdict falls through to the default action (allow).
	d := fw.Check(q, net.ParseIP("127.0.0.1"))
	// The script errored out; final verdict should NOT be VerdictRedirect with "9.9.9.9:53".
	if d.Verdict == VerdictRedirect {
		assert.NotEqual(t, "9.9.9.9:53", d.Server,
			"server= arg must not be used even if script passes it")
	}
}

// --- Static rule redirect integration tests (REDIR-04) ---

func TestStaticRedirectRule_UsesPool(t *testing.T) {
	fw, err := New(Config{
		Enabled:       true,
		DefaultAction: "allow",
		ScriptTimeout: 2 * time.Millisecond,
		Rules: []RuleConfig{
			{
				Name:   "pool-redirect",
				Match:  MatchConfig{DomainSuffix: ".redirect.test."},
				Action: "redirect",
				// No RedirectServer — uses global pool.
			},
		},
		Redirect: RedirectConfig{Upstreams: []string{"1.1.1.1:53", "2.2.2.2:53"}},
	})
	require.NoError(t, err)
	require.NotNil(t, fw)

	q := makeQuery("foo.redirect.test.", dns.TypeA)
	d := fw.Check(q, net.ParseIP("127.0.0.1"))
	assert.Equal(t, VerdictRedirect, d.Verdict)
	assert.Contains(t, []string{"1.1.1.1:53", "2.2.2.2:53"}, d.Server,
		"static redirect rule without redirect_server must use pool")
}

func TestStaticRedirectRule_PerRuleOverride(t *testing.T) {
	fw, err := New(Config{
		Enabled:       true,
		DefaultAction: "allow",
		ScriptTimeout: 2 * time.Millisecond,
		Rules: []RuleConfig{
			{
				Name:           "override-redirect",
				Match:          MatchConfig{DomainSuffix: ".override.test."},
				Action:         "redirect",
				RedirectServer: "9.9.9.9:53", // per-rule override
			},
		},
		Redirect: RedirectConfig{Upstreams: []string{"1.1.1.1:53", "2.2.2.2:53"}},
	})
	require.NoError(t, err)
	require.NotNil(t, fw)

	q := makeQuery("foo.override.test.", dns.TypeA)
	d := fw.Check(q, net.ParseIP("127.0.0.1"))
	assert.Equal(t, VerdictRedirect, d.Verdict)
	assert.Equal(t, "9.9.9.9:53", d.Server,
		"per-rule redirect_server must bypass pool")
}

func TestNew_EmptyPoolWithPoolRedirectRule(t *testing.T) {
	_, err := New(Config{
		Enabled:       true,
		DefaultAction: "allow",
		ScriptTimeout: 2 * time.Millisecond,
		Rules: []RuleConfig{
			{
				Name:   "no-server-no-pool",
				Match:  MatchConfig{DomainSuffix: ".test."},
				Action: "redirect",
				// No RedirectServer and no pool upstreams — must fail at New().
			},
		},
		Redirect: RedirectConfig{Upstreams: []string{}},
	})
	assert.Error(t, err, "New() must fail when redirect rule has no server and pool is empty")
}
