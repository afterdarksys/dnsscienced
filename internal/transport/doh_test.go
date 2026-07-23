package transport

import (
	"bytes"
	"context"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestDoHRejectsOversizedPOSTInsteadOfParsingTruncatedMessage(t *testing.T) {
	l := &DoHListener{}
	req := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(make([]byte, 65536)))
	req.Header.Set("Content-Type", "application/dns-message")
	if _, err := l.parsePOST(req); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("parsePOST error = %v, want oversized-message error", err)
	}
}

func TestDoHRequiresExactDNSMediaType(t *testing.T) {
	l := &DoHListener{}
	req := httptest.NewRequest(http.MethodPost, "/dns-query", strings.NewReader("bad"))
	req.Header.Set("Content-Type", "application/dns-message-evil")
	if _, err := l.parsePOST(req); err == nil {
		t.Fatal("parsePOST accepted a media type with only a matching prefix")
	}
}

func TestDoHPreservesRemoteAddress(t *testing.T) {
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	wirebase, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}

	var gotRemote net.Addr
	l := &DoHListener{handler: HandlerFunc(func(_ context.Context, req *dns.Msg, remote net.Addr) (*dns.Msg, error) {
		gotRemote = remote
		resp := new(dns.Msg)
		resp.SetReply(req)
		return resp, nil
	})}
	req := httptest.NewRequest(http.MethodGet, "/dns-query?dns="+base64.RawURLEncoding.EncodeToString(wirebase), nil)
	req.RemoteAddr = "192.0.2.44:53000"
	recorder := httptest.NewRecorder()
	l.handleDoH(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	addr, ok := gotRemote.(*net.TCPAddr)
	if !ok || !addr.IP.Equal(net.ParseIP("192.0.2.44")) {
		t.Fatalf("remote address = %#v, want 192.0.2.44", gotRemote)
	}
}

func TestDoHNegativeCacheControlUsesSOAMinimum(t *testing.T) {
	l := &DoHListener{}
	resp := &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeNameError}}
	resp.Ns = []dns.RR{&dns.SOA{
		Hdr:    dns.RR_Header{Name: "example.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 600},
		Minttl: 90,
	}}
	if got := l.getCacheControl(resp); got != "max-age=90" {
		t.Fatalf("Cache-Control = %q, want max-age=90", got)
	}
}
