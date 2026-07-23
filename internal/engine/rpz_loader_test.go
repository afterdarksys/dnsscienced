package engine

import (
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/miekg/dns"
)

func TestLoadRPZFile(t *testing.T) {
	policyFile := writeRPZFile(t, `
$ORIGIN rpz.example.
$TTL 60
@ IN SOA localhost. hostmaster.localhost. 1 60 60 60 60
@ IN NS localhost.
malware.example.com IN CNAME .
empty.example.com IN CNAME *.
safe.example.com IN CNAME rpz-passthru.
drop.example.com IN CNAME rpz-drop.
rewrite.example.com IN CNAME sinkhole.example.
*.tracking.example.com IN CNAME .
`)

	policy, err := LoadRPZFile("security", policyFile, "threat-feed")
	if err != nil {
		t.Fatalf("LoadRPZFile: %v", err)
	}

	tests := []struct {
		name    string
		action  RPZAction
		rewrite string
	}{
		{name: "malware.example.com.", action: RPZActionNXDomain},
		{name: "empty.example.com.", action: RPZActionNoData},
		{name: "safe.example.com.", action: RPZActionPassthru},
		{name: "drop.example.com.", action: RPZActionDrop},
		{name: "rewrite.example.com.", action: RPZActionRewrite, rewrite: "sinkhole.example."},
		{name: "sub.tracking.example.com.", action: RPZActionNXDomain},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rule, action := policy.Check(test.name)
			if rule == nil || action != test.action {
				t.Fatalf("Check() = (%v, %v), want action %v", rule, action, test.action)
			}
			if rule.RewriteTarget != test.rewrite {
				t.Fatalf("rewrite target = %q, want %q", rule.RewriteTarget, test.rewrite)
			}
			if rule.Zone != "security" || rule.Source != policyFile || rule.Reason != "threat-feed" {
				t.Fatalf("missing attribution: %+v", rule)
			}
		})
	}
}

func TestLoadRPZFileRejectsEmptyPolicy(t *testing.T) {
	policyFile := writeRPZFile(t, `
$ORIGIN rpz.example.
$TTL 60
@ IN SOA localhost. hostmaster.localhost. 1 60 60 60 60
@ IN NS localhost.
`)

	if _, err := LoadRPZFile("empty", policyFile, ""); err == nil {
		t.Fatal("expected empty policy to be rejected")
	}
}

func TestLoadRPZFileWildcardDoesNotMatchApex(t *testing.T) {
	policyFile := writeRPZFile(t, `
$ORIGIN rpz.example.
$TTL 60
@ IN SOA localhost. hostmaster.localhost. 1 60 60 60 60
@ IN NS localhost.
*.tracking.example.com IN CNAME .
`)

	policy, err := LoadRPZFile("security", policyFile, "")
	if err != nil {
		t.Fatalf("LoadRPZFile: %v", err)
	}
	if rule, action := policy.Check("tracking.example.com."); rule != nil || action != RPZActionNone {
		t.Fatalf("wildcard matched apex: rule=%+v action=%v", rule, action)
	}
	if rule, action := policy.Check("host.tracking.example.com."); rule == nil || action != RPZActionNXDomain {
		t.Fatalf("wildcard did not match descendant: rule=%+v action=%v", rule, action)
	}
}

func TestLoadRPZFileLoadsResponseIPTriggers(t *testing.T) {
	policyFile := writeRPZFile(t, `
$ORIGIN rpz.example.
$TTL 60
@ IN SOA localhost. hostmaster.localhost. 1 60 60 60 60
@ IN NS localhost.
24.0.2.0.192.rpz-ip IN CNAME .
32.2.2.0.192.rpz-ip IN CNAME rpz-passthru.
48.zz.101.db8.2001.rpz-ip IN CNAME *.
`)

	policy, err := LoadRPZFile("security", policyFile, "")
	if err != nil {
		t.Fatalf("LoadRPZFile: %v", err)
	}
	tests := []struct {
		address string
		action  RPZAction
	}{
		{address: "192.0.2.1", action: RPZActionNXDomain},
		{address: "192.0.2.2", action: RPZActionPassthru},
		{address: "2001:db8:101::53", action: RPZActionNoData},
		{address: "198.51.100.1", action: RPZActionNone},
	}
	for _, test := range tests {
		t.Run(test.address, func(t *testing.T) {
			request := new(dns.Msg)
			request.SetQuestion("answer.example.", dns.TypeA)
			response := new(dns.Msg)
			response.SetReply(request)
			if ip := net.ParseIP(test.address); ip.To4() != nil {
				response.Answer = append(response.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: "answer.example.", Rrtype: dns.TypeA, Class: dns.ClassINET},
					A:   ip,
				})
			} else {
				response.Answer = append(response.Answer, &dns.AAAA{
					Hdr:  dns.RR_Header{Name: "answer.example.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET},
					AAAA: ip,
				})
			}
			_, action := policy.CheckResponse("answer.example.", response)
			if action != test.action {
				t.Fatalf("action = %v, want %v", action, test.action)
			}
		})
	}
	if stats := policy.Stats(); stats.ResponseIPRules != 3 {
		t.Fatalf("stats = %+v, want three response-IP rules", stats)
	}
}

func TestLoadRPZFileRejectsInvalidResponseIPTriggers(t *testing.T) {
	for _, trigger := range []string{
		"rpz-ip",
		"8.2.0.0.10.rpz-ip",
		"0.0.0.0.0.rpz-ip",
		"24.00.2.0.192.rpz-ip",
		"48.zz.zz.db8.2001.rpz-ip",
		"48.1.101.db8.2001.rpz-ip",
	} {
		t.Run(trigger, func(t *testing.T) {
			policyFile := writeRPZFile(t, `
$ORIGIN rpz.example.
@ IN SOA localhost. hostmaster.localhost. 1 60 60 60 60
@ IN NS localhost.
`+trigger+` IN CNAME .
`)
			if _, err := LoadRPZFile("security", policyFile, ""); err == nil {
				t.Fatalf("accepted invalid response-IP trigger %q", trigger)
			}
		})
	}
}

func TestLoadRPZFileLoadsClientIPTriggers(t *testing.T) {
	policyFile := writeRPZFile(t, `
$ORIGIN rpz.example.
@ IN SOA localhost. hostmaster.localhost. 1 60 60 60 60
@ IN NS localhost.
24.0.2.0.192.rpz-client-ip IN CNAME .
32.10.2.0.192.rpz-client-ip IN CNAME rpz-passthru.
`)
	policy, err := LoadRPZFile("clients", policyFile, "quarantine")
	if err != nil {
		t.Fatalf("LoadRPZFile: %v", err)
	}
	aggregate := NewRPZAggregate()
	aggregate.AddZone(policy)
	tests := []struct {
		client   string
		action   RPZAction
		decisive bool
	}{
		{client: "192.0.2.9", action: RPZActionNXDomain, decisive: true},
		{client: "192.0.2.10", action: RPZActionPassthru, decisive: true},
		{client: "198.51.100.1", action: RPZActionNone, decisive: true},
	}
	for _, test := range tests {
		t.Run(test.client, func(t *testing.T) {
			addr, _ := netip.ParseAddr(test.client)
			_, action, decisive := aggregate.CheckRequestShortcut("answer.example.", addr)
			if action != test.action || decisive != test.decisive {
				t.Fatalf("result = (%v, %v), want (%v, %v)", action, decisive, test.action, test.decisive)
			}
		})
	}
	if stats := policy.Stats(); stats.ClientIPRules != 2 {
		t.Fatalf("stats = %+v, want two client-IP rules", stats)
	}
}

func TestLoadRPZFileLoadsNameserverTriggers(t *testing.T) {
	policyFile := writeRPZFile(t, `
$ORIGIN rpz.example.
@ IN SOA localhost. hostmaster.localhost. 1 60 60 60 60
@ IN NS localhost.
24.0.2.0.192.rpz-nsip IN CNAME .
ns.evil.example.rpz-nsdname IN CNAME *.
*.bad-ns.example.rpz-nsdname IN CNAME rpz-passthru.
`)
	policy, err := LoadRPZFile("security", policyFile, "")
	if err != nil {
		t.Fatalf("LoadRPZFile: %v", err)
	}
	response := new(dns.Msg)
	response.SetQuestion("answer.example.", dns.TypeA)

	tests := []struct {
		name       string
		nameserver RPZNameserverData
		action     RPZAction
	}{
		{
			name:       "NSIP",
			nameserver: RPZNameserverData{Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.53")}},
			action:     RPZActionNXDomain,
		},
		{
			name:       "NSDNAME exact",
			nameserver: RPZNameserverData{Names: []string{"ns.evil.example."}},
			action:     RPZActionNoData,
		},
		{
			name:       "NSDNAME wildcard",
			nameserver: RPZNameserverData{Names: []string{"host.bad-ns.example."}},
			action:     RPZActionPassthru,
		},
		{
			name:       "NSDNAME wildcard excludes apex",
			nameserver: RPZNameserverData{Names: []string{"bad-ns.example."}},
			action:     RPZActionNone,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, action := policy.CheckResponseWithNameservers(
				"answer.example.",
				response,
				&test.nameserver,
			)
			if action != test.action {
				t.Fatalf("action = %v, want %v", action, test.action)
			}
		})
	}
	stats := policy.Stats()
	if stats.NSDNameRules != 2 || stats.NSIPRules != 1 {
		t.Fatalf("stats = %+v, want two NSDNAME and one NSIP rule", stats)
	}
}

func TestLoadRPZFileRejectsInvalidNameserverTriggers(t *testing.T) {
	for _, trigger := range []string{
		"rpz-nsdname",
		"rpz-nsip",
		"0.0.0.0.0.rpz-nsip",
		"24.00.2.0.192.rpz-nsip",
	} {
		t.Run(trigger, func(t *testing.T) {
			policyFile := writeRPZFile(t, `
$ORIGIN rpz.example.
@ IN SOA localhost. hostmaster.localhost. 1 60 60 60 60
@ IN NS localhost.
`+trigger+` IN CNAME .
`)
			if _, err := LoadRPZFile("security", policyFile, ""); err == nil {
				t.Fatalf("accepted invalid nameserver trigger %q", trigger)
			}
		})
	}
}

func writeRPZFile(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rpz.example.bind")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	return path
}
