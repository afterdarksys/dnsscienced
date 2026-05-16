package dsync

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// WebhookPayload is the JSON body sent on NOTIFY events (per D-03).
type WebhookPayload struct {
	Zone      string    `json:"zone"`
	Qtype     string    `json:"qtype"`
	SourceIP  string    `json:"source_ip"`
	Timestamp time.Time `json:"timestamp"`
}

// WebhookClient fires POST requests on inbound NOTIFY events.
// Fire-and-forget: configurable timeout, no retry, failure logged (per D-04).
type WebhookClient struct {
	url    string
	format string // "json" or "base64"
	client *http.Client
}

// NewWebhookClient creates a webhook client. Empty url means no-op (per D-02).
func NewWebhookClient(url, format string, timeout time.Duration) *WebhookClient {
	if format == "" {
		format = "json"
	}
	return &WebhookClient{
		url:    url,
		format: format,
		client: &http.Client{Timeout: timeout},
	}
}

// Fire sends the webhook POST. Returns nil immediately if url is empty (per D-02).
// Caller is expected to invoke in a goroutine for fire-and-forget semantics.
func (wc *WebhookClient) Fire(payload WebhookPayload) error {
	if wc.url == "" {
		return nil
	}

	var body []byte
	var contentType string

	switch wc.format {
	case "base64":
		jsonBytes, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("webhook marshal: %w", err)
		}
		encoded := base64.StdEncoding.EncodeToString(jsonBytes)
		body = []byte(encoded)
		contentType = "application/octet-stream"
	default: // "json"
		var err error
		body, err = json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("webhook marshal: %w", err)
		}
		contentType = "application/json"
	}

	resp, err := wc.client.Post(wc.url, contentType, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("webhook POST %s: %w", wc.url, err)
	}
	resp.Body.Close()
	return nil
}
