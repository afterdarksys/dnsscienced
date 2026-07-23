package secondary

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/dnsscience/dnsscienced/internal/zone"
	"github.com/miekg/dns"
)

type memoryStore struct {
	mu    sync.RWMutex
	zones map[string]*zone.Zone
}

func newMemoryStore() *memoryStore {
	return &memoryStore{zones: make(map[string]*zone.Zone)}
}

func (s *memoryStore) AddZone(z *zone.Zone) error {
	if err := z.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	s.zones[z.Origin] = z
	s.mu.Unlock()
	return nil
}

func (s *memoryStore) GetZone(name string) *zone.Zone {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.zones[name]
}

type fakeFetcher struct {
	mu       sync.Mutex
	serial   uint32
	calls    int
	currents []uint32
}

func (f *fakeFetcher) Fetch(_ context.Context, cfg Config, current *zone.Zone) (*zone.Zone, error) {
	f.mu.Lock()
	f.calls++
	var serial uint32
	if current != nil && current.SOA != nil {
		serial = current.SOA.Serial
	}
	f.currents = append(f.currents, serial)
	fetchedSerial := f.serial
	f.mu.Unlock()
	return validZone(cfg.Name, fetchedSerial), nil
}

func (f *fakeFetcher) setSerial(serial uint32) {
	f.mu.Lock()
	f.serial = serial
	f.mu.Unlock()
}

func (f *fakeFetcher) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func validZone(name string, serial uint32) *zone.Zone {
	name = dns.Fqdn(name)
	z := zone.New(name)
	soa, _ := dns.NewRR(name + " 300 IN SOA ns1." + name + " hostmaster." + name + " " +
		serialString(serial) + " 60 30 3600 60")
	ns, _ := dns.NewRR(name + " 300 IN NS ns1." + name)
	glue, _ := dns.NewRR("ns1." + name + " 300 IN A 192.0.2.53")
	_ = z.AddRecord(soa)
	_ = z.AddRecord(ns)
	_ = z.AddRecord(glue)
	return z
}

func serialString(serial uint32) string {
	if serial == 0 {
		return "1"
	}
	var digits [10]byte
	i := len(digits)
	for serial > 0 {
		i--
		digits[i] = byte('0' + serial%10)
		serial /= 10
	}
	return string(digits[i:])
}

func TestManagerInitialAndNotifyRefresh(t *testing.T) {
	store := newMemoryStore()
	fetcher := &fakeFetcher{serial: 1}
	manager, err := NewManager(store, fetcher, []Config{{
		Name:    "secondary.test.",
		Masters: []string{"192.0.2.1"},
		TransferKey: &TransferKey{
			Name:      "xfer.example.",
			Algorithm: dns.HmacSHA256,
			Secret:    "c2VjcmV0",
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	if got := store.GetZone("secondary.test.").SOA.Serial; got != 1 {
		t.Fatalf("initial serial = %d, want 1", got)
	}

	fetcher.setSerial(2)
	if err := manager.HandleNotify(context.Background(), "secondary.test", net.ParseIP("192.0.2.1"), "xfer.example."); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if got := store.GetZone("secondary.test.").SOA.Serial; got == 2 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("NOTIFY did not trigger refresh")
}

func TestManagerRejectsUnauthorizedNotify(t *testing.T) {
	manager, err := NewManager(newMemoryStore(), &fakeFetcher{serial: 1}, []Config{{
		Name:    "secondary.test.",
		Masters: []string{"192.0.2.1"},
		TransferKey: &TransferKey{
			Name:      "xfer.example.",
			Algorithm: dns.HmacSHA256,
			Secret:    "c2VjcmV0",
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.HandleNotify(context.Background(), "secondary.test.", net.ParseIP("198.51.100.1"), "xfer.example."); err != ErrUnauthorizedSource {
		t.Fatalf("source error = %v", err)
	}
	if err := manager.HandleNotify(context.Background(), "secondary.test.", net.ParseIP("192.0.2.1"), "wrong.example."); err != ErrUnauthorizedTSIG {
		t.Fatalf("TSIG error = %v", err)
	}
	if err := manager.HandleNotify(context.Background(), "missing.test.", net.ParseIP("192.0.2.1"), "xfer.example."); err != ErrUnknownZone {
		t.Fatalf("unknown-zone error = %v", err)
	}
}

func TestManagerRequiresAuthenticatedSecondaryByDefault(t *testing.T) {
	_, err := NewManager(newMemoryStore(), &fakeFetcher{serial: 1}, []Config{{
		Name:    "secondary.test.",
		Masters: []string{"192.0.2.1"},
	}})
	if err == nil {
		t.Fatal("NewManager accepted an unsigned secondary without explicit opt-in")
	}
}

func TestManagerAllowsExplicitLegacyUnsignedSecondary(t *testing.T) {
	manager, err := NewManager(newMemoryStore(), &fakeFetcher{serial: 1}, []Config{{
		Name:                  "secondary.test.",
		Masters:               []string{"192.0.2.1"},
		AllowUnsignedTransfer: true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.HandleNotify(
		context.Background(),
		"secondary.test.",
		net.ParseIP("192.0.2.1"),
		"",
	); err != nil {
		t.Fatalf("explicit legacy unsigned NOTIFY rejected: %v", err)
	}
}

func TestSerialGreaterWraparound(t *testing.T) {
	if !zone.SerialGreater(0, ^uint32(0)) {
		t.Fatal("serial wraparound should be newer")
	}
	if zone.SerialGreater(10, 10) || zone.SerialGreater(9, 10) {
		t.Fatal("equal or previous serial reported as newer")
	}
}

func TestRefreshDelayUsesSOAAndBounds(t *testing.T) {
	z := validZone("secondary.test.", 1)
	z.SOA.Refresh = 5
	z.SOA.Retry = 2
	cfg := Config{
		MinRefreshTime: 10 * time.Second,
		MaxRefreshTime: time.Minute,
		MinRetryTime:   3 * time.Second,
		MaxRetryTime:   30 * time.Second,
	}
	if got := refreshDelay(cfg, z, false); got != 10*time.Second {
		t.Fatalf("refresh delay = %v", got)
	}
	if got := refreshDelay(cfg, z, true); got != 3*time.Second {
		t.Fatalf("retry delay = %v", got)
	}
}
