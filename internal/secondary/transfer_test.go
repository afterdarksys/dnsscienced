package secondary

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestAXFRFetcherTransfersAndValidatesZone(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	zoneName := "secondary.test."
	source := validZone(zoneName, 7)
	records := []dns.RR{source.SOA}
	for _, rr := range source.GetAllRecords() {
		if rr.Header().Rrtype != dns.TypeSOA {
			records = append(records, rr)
		}
	}
	records = append(records, source.SOA)
	server := &dns.Server{
		Listener: listener,
		Net:      "tcp",
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
			envelopes := make(chan *dns.Envelope, 1)
			envelopes <- &dns.Envelope{RR: records}
			close(envelopes)
			_ = new(dns.Transfer).Out(w, request, envelopes)
		}),
	}
	done := make(chan error, 1)
	go func() { done <- server.ActivateAndServe() }()
	defer func() {
		_ = server.Shutdown()
		<-done
	}()

	fetcher := AXFRFetcher{Timeout: time.Second}
	transferred, err := fetcher.Fetch(context.Background(), Config{
		Name:    zoneName,
		Masters: []string{listener.Addr().String()},
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if transferred.SOA == nil || transferred.SOA.Serial != 7 {
		t.Fatalf("transferred SOA = %v", transferred.SOA)
	}
	if err := transferred.Validate(); err != nil {
		t.Fatalf("transferred zone invalid: %v", err)
	}
}
