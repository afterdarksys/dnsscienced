package firewalld

import (
	"encoding/json"
	"net/http"
	"strings"
)

// AdminHandler returns an http.Handler that exposes firewall management over
// a simple JSON/HTTP API.  Mount it under a prefix, e.g.:
//
//	mux.Handle("/firewall/", http.StripPrefix("/firewall", firewalld.AdminHandler(fw)))
//
// Endpoints:
//
//	GET  /stats                        — counters snapshot
//	POST /scripts/load                 — load/reload a Starlark script from disk
//	                                     body: {"id":"name","path":"/etc/..."}
//	DELETE /scripts/{id}               — remove a loaded script
//	POST /intel/domain                 — inject a domain threat score
//	                                     body: {"domain":"evil.com","score":80}
//	DELETE /intel/domain               — remove an injected domain score
//	                                     body: {"domain":"evil.com"}
//	POST /intel/ip                     — inject an IP threat score
//	                                     body: {"ip":"1.2.3.4","score":90}
func AdminHandler(fw *Firewall) http.Handler {
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
		id := req.ID
		if id == "" {
			id = req.Path
		}
		if err := fw.starlark.LoadFile(req.Path); err != nil {
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

	return mux
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
