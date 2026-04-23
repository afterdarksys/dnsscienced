package firewalld

import (
	"net"
	"testing"

	"github.com/miekg/dns"
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
