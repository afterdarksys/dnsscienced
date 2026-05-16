package dsync

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestWebhookClient_FireJSON: POST with JSON content-type and expected body fields.
func TestWebhookClient_FireJSON(t *testing.T) {
	var gotContentType string
	var gotBody []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotContentType = r.Header.Get("Content-Type")
		body, _ := io.ReadAll(r.Body)
		gotBody = body
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	wc := NewWebhookClient(srv.URL, "json", 5*time.Second)
	payload := WebhookPayload{
		Zone:      "example.com.",
		Qtype:     "CDS",
		SourceIP:  "1.2.3.4",
		Timestamp: time.Now(),
	}
	if err := wc.Fire(payload); err != nil {
		t.Fatalf("Fire() error: %v", err)
	}

	if gotContentType != "application/json" {
		t.Errorf("expected Content-Type application/json, got %q", gotContentType)
	}

	var decoded WebhookPayload
	if err := json.Unmarshal(gotBody, &decoded); err != nil {
		t.Fatalf("body is not valid JSON: %v", err)
	}
	if decoded.Zone != payload.Zone {
		t.Errorf("zone mismatch: got %q, want %q", decoded.Zone, payload.Zone)
	}
	if decoded.Qtype != payload.Qtype {
		t.Errorf("qtype mismatch: got %q, want %q", decoded.Qtype, payload.Qtype)
	}
	if decoded.SourceIP != payload.SourceIP {
		t.Errorf("source_ip mismatch: got %q, want %q", decoded.SourceIP, payload.SourceIP)
	}
}

// TestWebhookClient_FireBase64: format="base64" sends base64-encoded JSON body.
func TestWebhookClient_FireBase64(t *testing.T) {
	var gotBody []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotBody = body
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	wc := NewWebhookClient(srv.URL, "base64", 5*time.Second)
	payload := WebhookPayload{
		Zone:      "test.com.",
		Qtype:     "CSYNC",
		SourceIP:  "10.0.0.1",
		Timestamp: time.Now(),
	}
	if err := wc.Fire(payload); err != nil {
		t.Fatalf("Fire() error: %v", err)
	}

	// Decode the base64 body to verify it contains JSON
	jsonBytes, err := base64.StdEncoding.DecodeString(string(gotBody))
	if err != nil {
		t.Fatalf("body is not valid base64: %v", err)
	}
	var decoded WebhookPayload
	if err := json.Unmarshal(jsonBytes, &decoded); err != nil {
		t.Fatalf("decoded body is not valid JSON: %v", err)
	}
	if decoded.Zone != payload.Zone {
		t.Errorf("zone mismatch: got %q, want %q", decoded.Zone, payload.Zone)
	}
}

// TestWebhookClient_Timeout: slow server triggers timeout error within 2s.
func TestWebhookClient_Timeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	wc := NewWebhookClient(srv.URL, "json", 1*time.Second)
	payload := WebhookPayload{
		Zone:      "timeout.com.",
		Qtype:     "CDS",
		SourceIP:  "1.2.3.4",
		Timestamp: time.Now(),
	}

	start := time.Now()
	err := wc.Fire(payload)
	elapsed := time.Since(start)

	if err == nil {
		t.Error("expected timeout error, got nil")
	}
	if elapsed > 2*time.Second {
		t.Errorf("expected Fire() to return within 2s, took %v", elapsed)
	}
}

// TestWebhookClient_NilURL: empty URL returns nil immediately (no-op per D-02).
func TestWebhookClient_NilURL(t *testing.T) {
	wc := NewWebhookClient("", "json", 5*time.Second)
	payload := WebhookPayload{
		Zone:      "noop.com.",
		Qtype:     "CDS",
		SourceIP:  "1.2.3.4",
		Timestamp: time.Now(),
	}
	if err := wc.Fire(payload); err != nil {
		t.Errorf("expected nil from Fire() with empty URL, got: %v", err)
	}
}
