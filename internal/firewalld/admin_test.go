package firewalld

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func newTestFirewall(t *testing.T) *Firewall {
	t.Helper()
	fw, err := New(Config{Enabled: true, ThreatIntel: ThreatIntelConfig{BlockThreshold: 100}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return fw
}

func doReq(t *testing.T, h http.Handler, method, path, auth string) int {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

// TestAdminHandler_FailsClosedWithoutToken: an empty configured token denies all.
func TestAdminHandler_FailsClosedWithoutToken(t *testing.T) {
	h := AdminHandler(newTestFirewall(t), AdminConfig{}) // no token
	if code := doReq(t, h, http.MethodGet, "/stats", "Bearer anything"); code != http.StatusForbidden {
		t.Errorf("no-token handler: got %d, want 403", code)
	}
}

// TestAdminHandler_RejectsBadToken: wrong/missing bearer token is 401.
func TestAdminHandler_RejectsBadToken(t *testing.T) {
	h := AdminHandler(newTestFirewall(t), AdminConfig{AuthToken: "s3cret"})
	if code := doReq(t, h, http.MethodGet, "/stats", ""); code != http.StatusUnauthorized {
		t.Errorf("missing auth: got %d, want 401", code)
	}
	if code := doReq(t, h, http.MethodGet, "/stats", "Bearer wrong"); code != http.StatusUnauthorized {
		t.Errorf("wrong token: got %d, want 401", code)
	}
}

// TestAdminHandler_AllowsGoodToken: correct token reaches the route.
func TestAdminHandler_AllowsGoodToken(t *testing.T) {
	h := AdminHandler(newTestFirewall(t), AdminConfig{AuthToken: "s3cret"})
	if code := doReq(t, h, http.MethodGet, "/stats", "Bearer s3cret"); code != http.StatusOK {
		t.Errorf("good token: got %d, want 200", code)
	}
}

// TestResolveInRoot_ContainsTraversal: traversal/absolute paths are neutralized
// to stay within root (chroot-style join), so no file outside root is reachable.
func TestResolveInRoot_ContainsTraversal(t *testing.T) {
	root := "/opt/dnsscienced/policies"
	prefix := root + string(filepath.Separator)
	for _, in := range []string{"../../etc/passwd", "/etc/passwd", "a/../../b"} {
		got, err := resolveInRoot(root, in)
		if err != nil {
			t.Errorf("resolveInRoot(%q) errored: %v", in, err)
			continue
		}
		if got != root && !strings.HasPrefix(got, prefix) {
			t.Errorf("resolveInRoot(%q) = %q escaped root %q", in, got, root)
		}
		if got == "/etc/passwd" {
			t.Errorf("resolveInRoot(%q) reached real /etc/passwd", in)
		}
	}
	if got, err := resolveInRoot(root, "block.star"); err != nil || got != prefix+"block.star" {
		t.Errorf("resolveInRoot(%q) = %q, %v; want %q", "block.star", got, err, prefix+"block.star")
	}
}
