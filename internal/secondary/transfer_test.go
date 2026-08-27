package secondary

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/afterdarksys/dnsscienced/internal/zone"
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
	}, nil)
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

func TestTransferFetcherConsumesIXFR(t *testing.T) {
	current := validZone("secondary.test.", 1)
	next := current.Clone()
	next.SOA.Serial = 2
	added, _ := dns.NewRR("added.secondary.test. 300 IN A 192.0.2.88")
	if err := next.AddRecord(added); err != nil {
		t.Fatal(err)
	}
	records := ixfrRecords(next.SOA, zone.Diff(current, next))

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var sawIXFR atomic.Bool
	server := &dns.Server{
		Listener: listener,
		Net:      "tcp",
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
			sawIXFR.Store(request.Question[0].Qtype == dns.TypeIXFR)
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

	fetcher := TransferFetcher{Timeout: time.Second}
	transferred, err := fetcher.Fetch(context.Background(), Config{
		Name:              current.Origin,
		Masters:           []string{listener.Addr().String()},
		AllowAXFRFallback: false,
	}, current)
	if err != nil {
		t.Fatal(err)
	}
	if !sawIXFR.Load() || transferred.SOA.Serial != 2 ||
		len(transferred.GetRecords("added.secondary.test.", dns.TypeA)) != 1 {
		t.Fatalf("sawIXFR=%v transferred=%v", sawIXFR.Load(), transferred.SOA)
	}
}
