package engine

import (
	"os"
	"path/filepath"
	"testing"
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

func TestLoadRPZFileRejectsUnsupportedTrigger(t *testing.T) {
	policyFile := writeRPZFile(t, `
$ORIGIN rpz.example.
$TTL 60
@ IN SOA localhost. hostmaster.localhost. 1 60 60 60 60
@ IN NS localhost.
24.0.2.0.192.rpz-ip IN CNAME .
`)

	if _, err := LoadRPZFile("security", policyFile, ""); err == nil {
		t.Fatal("expected unsupported response-IP trigger to fail closed")
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
