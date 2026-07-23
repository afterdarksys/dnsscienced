package engine

import (
	"net"
	"net/netip"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestRPZ_ExactMatch(t *testing.T) {
	rpz := NewRPZ("blocklist")
	rpz.AddRule("malware.example.com", RPZActionNXDomain, "malware")

	// Exact match should trigger
	rule, action := rpz.Check("malware.example.com.")
	assert.NotNil(t, rule)
	assert.Equal(t, RPZActionNXDomain, action)
	assert.Equal(t, "malware", rule.Reason)

	// Non-matching should not trigger
	rule, action = rpz.Check("safe.example.com.")
	assert.Nil(t, rule)
	assert.Equal(t, RPZActionNone, action)
}

func TestRPZ_WildcardMatch(t *testing.T) {
	rpz := NewRPZ("blocklist")
	rpz.AddWildcard("badsite.com", RPZActionNXDomain, "phishing")

	// Subdomain should match wildcard
	rule, action := rpz.Check("www.badsite.com.")
	assert.NotNil(t, rule)
	assert.Equal(t, RPZActionNXDomain, action)

	// Deep subdomain should also match
	rule, action = rpz.Check("a.b.c.badsite.com.")
	assert.NotNil(t, rule)
	assert.Equal(t, RPZActionNXDomain, action)

	// Apex should also match
	rule, action = rpz.Check("badsite.com.")
	assert.NotNil(t, rule)
	assert.Equal(t, RPZActionNXDomain, action)
}

func TestRPZ_Passthru(t *testing.T) {
	rpz := NewRPZ("blocklist")

	// Block the whole domain
	rpz.AddWildcard("example.com", RPZActionNXDomain, "blocked")

	// But allow a specific subdomain
	rpz.AddPassthru("safe.example.com", "whitelist")

	// Whitelisted subdomain should pass through
	rule, action := rpz.Check("safe.example.com.")
	assert.NotNil(t, rule)
	assert.Equal(t, RPZActionPassthru, action)

	// Other subdomains should be blocked
	rule, action = rpz.Check("other.example.com.")
	assert.NotNil(t, rule)
	assert.Equal(t, RPZActionNXDomain, action)
}

func TestRPZ_Rewrite(t *testing.T) {
	rpz := NewRPZ("redirect")
	rpz.AddRewriteRule("ads.example.com", "sinkhole.local", "ad blocking")

	rule, action := rpz.Check("ads.example.com.")
	assert.NotNil(t, rule)
	assert.Equal(t, RPZActionRewrite, action)
	assert.Equal(t, "sinkhole.local.", rule.RewriteTarget)
}

func TestRPZ_ApplyToResponse(t *testing.T) {
	rpz := NewRPZ("blocklist")
	rpz.AddRule("blocked.example.com", RPZActionNXDomain, "test")

	// Create a response for a blocked domain
	msg := new(dns.Msg)
	msg.SetQuestion("blocked.example.com.", dns.TypeA)
	msg.Answer = append(msg.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: "blocked.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   []byte{1, 2, 3, 4},
	})

	// Apply RPZ
	modified := rpz.ApplyToResponse(msg)
	assert.True(t, modified)
	assert.Equal(t, dns.RcodeNameError, msg.Rcode)
	assert.Empty(t, msg.Answer)
}

func TestRPZ_Disabled(t *testing.T) {
	rpz := NewRPZ("blocklist")
	rpz.AddRule("blocked.example.com", RPZActionNXDomain, "test")

	// Disable RPZ
	rpz.Disable()

	// Should not match when disabled
	rule, action := rpz.Check("blocked.example.com.")
	assert.Nil(t, rule)
	assert.Equal(t, RPZActionNone, action)

	// Enable again
	rpz.Enable()

	// Should match when enabled
	rule, action = rpz.Check("blocked.example.com.")
	assert.NotNil(t, rule)
	assert.Equal(t, RPZActionNXDomain, action)
}

func TestRPZ_ClearRemovesRegexRules(t *testing.T) {
	rpz := NewRPZ("blocklist")
	if err := rpz.AddRegexRule(`^blocked\.example\.$`, RPZActionNXDomain, "", "test", "test"); err != nil {
		t.Fatalf("AddRegexRule: %v", err)
	}

	rpz.Clear()

	if rule, action := rpz.Check("blocked.example."); rule != nil || action != RPZActionNone {
		t.Fatalf("cleared regex matched: rule=%+v action=%v", rule, action)
	}
	if stats := rpz.Stats(); stats.RegexRules != 0 {
		t.Fatalf("regex rules after Clear = %d, want 0", stats.RegexRules)
	}
}

func TestRPZAggregate(t *testing.T) {
	agg := NewRPZAggregate()

	// First zone - malware block
	malware := NewRPZ("malware")
	malware.AddRule("evil.com", RPZActionNXDomain, "malware")
	agg.AddZone(malware)

	// Second zone - ad blocking
	ads := NewRPZ("ads")
	ads.AddWildcard("ads.example.com", RPZActionNoData, "ads")
	agg.AddZone(ads)

	// Check malware match
	rule, action := agg.Check("evil.com.")
	assert.NotNil(t, rule)
	assert.Equal(t, RPZActionNXDomain, action)

	// Check ads match
	rule, action = agg.Check("tracker.ads.example.com.")
	assert.NotNil(t, rule)
	assert.Equal(t, RPZActionNoData, action)

	// Check no match
	rule, action = agg.Check("google.com.")
	assert.Nil(t, rule)
	assert.Equal(t, RPZActionNone, action)
}

func TestRPZAggregateResponseIPPrecedence(t *testing.T) {
	agg := NewRPZAggregate()
	first := NewRPZ("first")
	if err := first.AddResponseIPRule(
		netip.MustParsePrefix("192.0.2.0/24"),
		RPZActionNXDomain,
		"",
		"malware host",
		"test",
	); err != nil {
		t.Fatal(err)
	}
	agg.AddZone(first)
	second := NewRPZ("second")
	second.AddRule("answer.example.", RPZActionNoData, "later qname")
	agg.AddZone(second)

	if rule, action, decisive := agg.CheckQueryShortcut("answer.example."); decisive ||
		rule != nil || action != RPZActionNone {
		t.Fatalf("query shortcut = (%+v, %v, %v), want deferred", rule, action, decisive)
	}
	request := new(dns.Msg)
	request.SetQuestion("answer.example.", dns.TypeA)
	response := new(dns.Msg)
	response.SetReply(request)
	response.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: "answer.example.", Rrtype: dns.TypeA, Class: dns.ClassINET},
		A:   net.ParseIP("192.0.2.53"),
	}}
	rule, action := agg.CheckResponse("answer.example.", response)
	if rule == nil || rule.Zone != "first" || action != RPZActionNXDomain {
		t.Fatalf("response match = (%+v, %v), want first-zone RPZ-IP", rule, action)
	}
}

func TestRPZQNAMEOutranksResponseIPWithinZone(t *testing.T) {
	policy := NewRPZ("policy")
	policy.AddRule("answer.example.", RPZActionPassthru, "allow")
	if err := policy.AddResponseIPRule(
		netip.MustParsePrefix("192.0.2.0/24"),
		RPZActionNXDomain,
		"",
		"block",
		"test",
	); err != nil {
		t.Fatal(err)
	}
	request := new(dns.Msg)
	request.SetQuestion("answer.example.", dns.TypeA)
	response := new(dns.Msg)
	response.SetReply(request)
	response.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: "answer.example.", Rrtype: dns.TypeA, Class: dns.ClassINET},
		A:   net.ParseIP("192.0.2.53"),
	}}
	rule, action := policy.CheckResponse("answer.example.", response)
	if rule == nil || action != RPZActionPassthru {
		t.Fatalf("response match = (%+v, %v), want QNAME passthru", rule, action)
	}
}

func TestRPZClientIPOutranksOtherTriggersWithinZone(t *testing.T) {
	policy := NewRPZ("policy")
	if err := policy.AddClientIPRule(
		netip.MustParsePrefix("192.0.2.0/24"),
		RPZActionPassthru,
		"",
		"allow client",
		"test",
	); err != nil {
		t.Fatal(err)
	}
	policy.AddRule("answer.example.", RPZActionNXDomain, "block name")
	if err := policy.AddResponseIPRule(
		netip.MustParsePrefix("203.0.113.0/24"),
		RPZActionNoData,
		"",
		"block address",
		"test",
	); err != nil {
		t.Fatal(err)
	}
	aggregate := NewRPZAggregate()
	aggregate.AddZone(policy)
	rule, action, decisive := aggregate.CheckRequestShortcut(
		"answer.example.",
		netip.MustParseAddr("192.0.2.10"),
	)
	if !decisive || rule == nil || action != RPZActionPassthru {
		t.Fatalf("request result = (%+v, %v, %v), want client-IP passthru", rule, action, decisive)
	}
}

func TestRPZEarlierResponseIPDefersLaterClientIP(t *testing.T) {
	aggregate := NewRPZAggregate()
	first := NewRPZ("first")
	if err := first.AddResponseIPRule(
		netip.MustParsePrefix("203.0.113.0/24"),
		RPZActionNXDomain,
		"",
		"first response",
		"test",
	); err != nil {
		t.Fatal(err)
	}
	aggregate.AddZone(first)
	second := NewRPZ("second")
	if err := second.AddClientIPRule(
		netip.MustParsePrefix("192.0.2.0/24"),
		RPZActionPassthru,
		"",
		"later client",
		"test",
	); err != nil {
		t.Fatal(err)
	}
	aggregate.AddZone(second)

	client := netip.MustParseAddr("192.0.2.10")
	if rule, action, decisive := aggregate.CheckRequestShortcut("answer.example.", client); decisive ||
		rule != nil || action != RPZActionNone {
		t.Fatalf("shortcut = (%+v, %v, %v), want deferred", rule, action, decisive)
	}
	request := new(dns.Msg)
	request.SetQuestion("answer.example.", dns.TypeA)
	response := new(dns.Msg)
	response.SetReply(request)
	response.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: "answer.example.", Rrtype: dns.TypeA, Class: dns.ClassINET},
		A:   net.ParseIP("203.0.113.9"),
	}}
	rule, action := aggregate.CheckRequestResponse("answer.example.", client, response)
	if rule == nil || rule.Zone != "first" || action != RPZActionNXDomain {
		t.Fatalf("response = (%+v, %v), want first-zone response-IP", rule, action)
	}
}

func TestRPZRejectsInvalidResponseIPPrefix(t *testing.T) {
	policy := NewRPZ("policy")
	if err := policy.AddResponseIPRule(
		netip.Prefix{},
		RPZActionNXDomain,
		"",
		"invalid",
		"test",
	); err == nil {
		t.Fatal("accepted invalid response-IP prefix")
	}
}
