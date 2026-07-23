package firewalld

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
)

var errPathEscape = errors.New("path escapes policy root")

// AdminConfig configures the firewall HTTP management API. Both fields are
// security-critical: an empty AuthToken makes the handler fail closed (it
// refuses every request), and PolicyRoot constrains where /scripts/load may
// read from so an attacker cannot load an arbitrary local file as policy.
type AdminConfig struct {
	// AuthToken is the bearer token required on every request. Empty = deny all.
	AuthToken string
	// PolicyRoot is the only directory /scripts/load may read scripts from.
	// Empty = script loading disabled.
	PolicyRoot string
}

// AdminHandler returns an http.Handler that exposes firewall management over a
// JSON/HTTP API. Every request requires "Authorization: Bearer <cfg.AuthToken>".
// This API performs privileged operations (loading policy scripts, mutating
// threat intelligence) and MUST NOT be exposed without a token; an empty token
// makes it deny all. Mount under a prefix, e.g.:
//
//	mux.Handle("/firewall/", http.StripPrefix("/firewall", firewalld.AdminHandler(fw, cfg)))
//
// Endpoints:
//
//	GET  /stats                        — counters snapshot
//	POST /scripts/load                 — load/reload a Starlark script from PolicyRoot
//	                                     body: {"id":"name","path":"relative.star"}
//	DELETE /scripts/{id}               — remove a loaded script
//	POST /intel/domain                 — inject a domain threat score
//	                                     body: {"domain":"evil.com","score":80}
//	DELETE /intel/domain               — remove an injected domain score
//	                                     body: {"domain":"evil.com"}
//	POST /intel/ip                     — inject an IP threat score
//	                                     body: {"ip":"1.2.3.4","score":90}
func AdminHandler(fw *Firewall, cfg AdminConfig) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		writeJSON(w, fw.Stats())
	})

	mux.HandleFunc("/scripts/load", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			ID   string `json:"id"`
			Path string `json:"path"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
			return
		}
		if req.Path == "" {
			http.Error(w, "path required", http.StatusBadRequest)
			return
		}
		if cfg.PolicyRoot == "" {
			http.Error(w, "script loading disabled (no policy_root configured)", http.StatusForbidden)
			return
		}
		// Constrain the requested path to PolicyRoot. Reject anything that
		// escapes it (absolute paths, "..", symlink-style traversal) so an
		// attacker cannot load arbitrary local files as policy.
		safePath, err := resolveInRoot(cfg.PolicyRoot, req.Path)
		if err != nil {
			http.Error(w, "invalid path: "+err.Error(), http.StatusBadRequest)
			return
		}
		id := req.ID
		if id == "" {
			id = req.Path
		}
		if err := fw.starlark.LoadFile(safePath); err != nil {
			http.Error(w, "load failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]string{"status": "ok", "id": id})
	})

	mux.HandleFunc("/scripts/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/scripts/")
		if id == "" {
			http.Error(w, "script id required", http.StatusBadRequest)
			return
		}
		fw.starlark.Remove(id)
		writeJSON(w, map[string]string{"status": "ok", "id": id})
	})

	mux.HandleFunc("/intel/domain", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Domain string `json:"domain"`
			Score  int    `json:"score"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
			return
		}
		if req.Domain == "" {
			http.Error(w, "domain required", http.StatusBadRequest)
			return
		}
		switch r.Method {
		case http.MethodPost:
			fw.intel.AddDomainScore(req.Domain, req.Score)
			writeJSON(w, map[string]string{"status": "ok", "domain": req.Domain})
		case http.MethodDelete:
			fw.intel.RemoveDomainScore(req.Domain)
			writeJSON(w, map[string]string{"status": "ok", "domain": req.Domain})
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/intel/ip", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			IP    string `json:"ip"`
			Score int    `json:"score"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
			return
		}
		if req.IP == "" {
			http.Error(w, "ip required", http.StatusBadRequest)
			return
		}
		fw.intel.AddIPScore(req.IP, req.Score)
		writeJSON(w, map[string]string{"status": "ok", "ip": req.IP})
	})

	// Wrap every route in a fail-closed bearer-token guard.
	return authGuard(cfg.AuthToken, mux)
}

// authGuard enforces "Authorization: Bearer <token>" on every request using a
// constant-time comparison. An empty configured token denies all requests
// (fail closed) so the API is never accidentally exposed without auth.
func authGuard(token string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if token == "" {
			http.Error(w, "firewall admin API disabled (no auth token configured)", http.StatusForbidden)
			return
		}
		const prefix = "Bearer "
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, prefix) ||
			subtle.ConstantTimeCompare([]byte(auth[len(prefix):]), []byte(token)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// resolveInRoot joins rel onto root and verifies the result stays within root,
// rejecting absolute paths and "../" traversal. Returns the cleaned absolute path.
func resolveInRoot(root, rel string) (string, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	joined := filepath.Join(absRoot, filepath.Clean("/"+rel))
	// filepath.Join cleans the path; ensure it is still under absRoot.
	if joined != absRoot && !strings.HasPrefix(joined, absRoot+string(filepath.Separator)) {
		return "", errPathEscape
	}
	return joined, nil
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
