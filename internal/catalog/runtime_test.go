package catalog

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"

	"github.com/dnsscience/dnsscienced/internal/secondary"
	"github.com/dnsscience/dnsscienced/internal/zone"
	"github.com/miekg/dns"
)

type runtimeStore struct {
	mu    sync.RWMutex
	zones map[string]*zone.Zone
}

func newRuntimeStore() *runtimeStore {
	return &runtimeStore{zones: make(map[string]*zone.Zone)}
}

func (s *runtimeStore) AddZone(z *zone.Zone) error {
	if err := z.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	s.zones[normalizeName(z.Origin)] = z
	s.mu.Unlock()
	return nil
}

func (s *runtimeStore) GetZone(name string) *zone.Zone {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.zones[normalizeName(name)]
}

func (s *runtimeStore) RemoveZone(name string) {
	s.mu.Lock()
	delete(s.zones, normalizeName(name))
	s.mu.Unlock()
}

func (s *runtimeStore) GetZoneNames() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]string, 0, len(s.zones))
	for name := range s.zones {
		result = append(result, name)
	}
	return result
}

type runtimeController struct {
	runtime *Runtime
	mu      sync.Mutex
	upserts []secondary.Config
	resets  []bool
	removed []string
	err     error
}

func (c *runtimeController) Upsert(_ context.Context, cfg secondary.Config, reset bool) error {
	c.mu.Lock()
	c.upserts = append(c.upserts, cfg)
	c.resets = append(c.resets, reset)
	err := c.err
	serial := uint32(len(c.upserts))
	c.mu.Unlock()
	if err != nil {
		return err
	}
	return c.runtime.AddZone(runtimeMemberZone(cfg.Name, serial))
}

func (c *runtimeController) Remove(name string) bool {
	c.mu.Lock()
	c.removed = append(c.removed, normalizeName(name))
	c.mu.Unlock()
	return true
}

func runtimeMemberZone(name string, serial uint32) *zone.Zone {
	name = normalizeName(name)
	z := zone.New(name)
	for _, text := range []string{
		name + " 300 IN SOA ns1." + name + " hostmaster." + name + " " + serialStringForRuntime(serial) + " 3600 600 86400 300",
		name + " 300 IN NS ns1." + name,
		"ns1." + name + " 300 IN A 192.0.2.53",
	} {
		rr, _ := dns.NewRR(text)
		_ = z.AddRecord(rr)
	}
	return z
}

func serialStringForRuntime(serial uint32) string {
	if serial == 0 {
		return "1"
	}
	const digits = "0123456789"
	var buffer [10]byte
	i := len(buffer)
	for serial > 0 {
		i--
		buffer[i] = digits[serial%10]
		serial /= 10
	}
	return string(buffer[i:])
}

func runtimeSource(name string) SourceConfig {
	return SourceConfig{
		Name: name,
		Defaults: secondary.Config{
			Masters:               []string{"192.0.2.1"},
			AllowUnsignedTransfer: true,
		},
		Groups: map[string]secondary.Config{
			"blue": {
				Masters:               []string{"192.0.2.2"},
				AllowUnsignedTransfer: true,
			},
		},
	}
}

func newTestRuntime(t *testing.T, store *runtimeStore, statePath string) (*Runtime, *runtimeController) {
	t.Helper()
	runtime, err := NewRuntime(store, []SourceConfig{runtimeSource("catalog.example.")}, statePath, nil)
	if err != nil {
		t.Fatal(err)
	}
	controller := &runtimeController{runtime: runtime}
	if err := runtime.AttachController(controller); err != nil {
		t.Fatal(err)
	}
	return runtime, controller
}

func TestRuntimeProvisionsGroupedMemberAndKeepsCatalogPrivate(t *testing.T) {
	store := newRuntimeStore()
	runtime, controller := newTestRuntime(t, store, filepath.Join(t.TempDir(), "catalog-state.json"))
	catalog := catalogZone(
		t,
		"catalog.example.",
		`a1.zones.catalog.example. 0 IN PTR alpha.example.`,
		`group.a1.zones.catalog.example. 0 IN TXT "blue"`,
	)
	if err := runtime.AddZone(catalog); err != nil {
		t.Fatal(err)
	}
	if store.GetZone("catalog.example.") != nil {
		t.Fatal("catalog zone was exposed through the authoritative store")
	}
	if store.GetZone("alpha.example.") == nil {
		t.Fatal("catalog member was not provisioned")
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if len(controller.upserts) != 1 || controller.upserts[0].Masters[0] != "192.0.2.2" {
		t.Fatalf("upserts=%+v, want blue group master", controller.upserts)
	}
}

func TestRuntimeBrokenCatalogRetainsLastValidMember(t *testing.T) {
	store := newRuntimeStore()
	runtime, controller := newTestRuntime(t, store, filepath.Join(t.TempDir(), "catalog-state.json"))
	valid := catalogZone(t, "catalog.example.", `a1.zones.catalog.example. 0 IN PTR alpha.example.`)
	if err := runtime.AddZone(valid); err != nil {
		t.Fatal(err)
	}
	broken := catalogZone(
		t,
		"catalog.example.",
		`a1.zones.catalog.example. 0 IN PTR alpha.example.`,
		`a1.zones.catalog.example. 0 IN PTR duplicate.example.`,
	)
	if err := runtime.AddZone(broken); err == nil {
		t.Fatal("broken catalog was accepted")
	}
	if store.GetZone("alpha.example.") == nil {
		t.Fatal("last-valid member was withdrawn after broken catalog")
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if len(controller.removed) != 0 {
		t.Fatalf("removed=%v after broken catalog", controller.removed)
	}
}

func TestRuntimeRejectsStaleOrEqualCatalogSerial(t *testing.T) {
	store := newRuntimeStore()
	runtime, controller := newTestRuntime(t, store, filepath.Join(t.TempDir(), "catalog-state.json"))
	valid := catalogZone(t, "catalog.example.", `a1.zones.catalog.example. 0 IN PTR alpha.example.`)
	valid.SOA.Serial = 42
	if err := runtime.AddZone(valid); err != nil {
		t.Fatal(err)
	}

	for _, serial := range []uint32{42, 41} {
		stale := catalogZone(t, "catalog.example.")
		stale.SOA.Serial = serial
		if err := runtime.AddZone(stale); err == nil {
			t.Fatalf("catalog serial %d was accepted after serial 42", serial)
		}
		if store.GetZone("alpha.example.") == nil {
			t.Fatalf("catalog serial %d withdrew the last-valid member", serial)
		}
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if len(controller.removed) != 0 {
		t.Fatalf("stale catalog removed members: %v", controller.removed)
	}
}

func TestRuntimeAcceptsCatalogSerialWraparound(t *testing.T) {
	store := newRuntimeStore()
	runtime, _ := newTestRuntime(t, store, filepath.Join(t.TempDir(), "catalog-state.json"))
	beforeWrap := catalogZone(t, "catalog.example.", `a1.zones.catalog.example. 0 IN PTR alpha.example.`)
	beforeWrap.SOA.Serial = ^uint32(0)
	if err := runtime.AddZone(beforeWrap); err != nil {
		t.Fatal(err)
	}
	afterWrap := catalogZone(t, "catalog.example.", `a1.zones.catalog.example. 0 IN PTR alpha.example.`)
	afterWrap.SOA.Serial = 0
	if err := runtime.AddZone(afterWrap); err != nil {
		t.Fatalf("RFC 1982 serial wraparound rejected: %v", err)
	}
}

func TestRuntimeRemovalWithdrawsOnlyOwnedMember(t *testing.T) {
	store := newRuntimeStore()
	runtime, controller := newTestRuntime(t, store, filepath.Join(t.TempDir(), "catalog-state.json"))
	if err := runtime.AddZone(catalogZone(t, "catalog.example.", `a1.zones.catalog.example. 0 IN PTR alpha.example.`)); err != nil {
		t.Fatal(err)
	}
	removed := catalogZone(t, "catalog.example.")
	removed.SOA.Serial = 43
	if err := runtime.AddZone(removed); err != nil {
		t.Fatal(err)
	}
	if store.GetZone("alpha.example.") != nil {
		t.Fatal("removed member remains authoritative")
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if len(controller.removed) != 1 || controller.removed[0] != "alpha.example." {
		t.Fatalf("removed=%v", controller.removed)
	}
}

func TestRuntimePersistsAndRestoresCatalogAndMemberState(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "catalog-state.json")
	firstStore := newRuntimeStore()
	first, _ := newTestRuntime(t, firstStore, statePath)
	if err := first.AddZone(catalogZone(t, "catalog.example.", `a1.zones.catalog.example. 0 IN PTR alpha.example.`)); err != nil {
		t.Fatal(err)
	}

	secondStore := newRuntimeStore()
	second, controller := newTestRuntime(t, secondStore, statePath)
	if secondStore.GetZone("alpha.example.") == nil {
		t.Fatal("persisted member was not restored")
	}
	if second.GetZone("catalog.example.") == nil {
		t.Fatal("last-valid catalog was not restored privately")
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if len(controller.upserts) != 1 || controller.upserts[0].Name != "alpha.example." {
		t.Fatalf("retained member was not seeded: %+v", controller.upserts)
	}
}

func TestRuntimeRejectsOperatorZoneClash(t *testing.T) {
	store := newRuntimeStore()
	if err := store.AddZone(runtimeMemberZone("alpha.example.", 10)); err != nil {
		t.Fatal(err)
	}
	runtime, controller := newTestRuntime(t, store, filepath.Join(t.TempDir(), "catalog-state.json"))
	if err := runtime.AddZone(catalogZone(t, "catalog.example.", `a1.zones.catalog.example. 0 IN PTR alpha.example.`)); err != nil {
		t.Fatal(err)
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if len(controller.upserts) != 0 {
		t.Fatalf("operator zone was replaced: %+v", controller.upserts)
	}
	if got := store.GetZone("alpha.example.").SOA.Serial; got != 10 {
		t.Fatalf("operator zone serial = %d, want 10", got)
	}
}

func TestRuntimeRejectsReservedUnloadedSecondaryClash(t *testing.T) {
	store := newRuntimeStore()
	runtime, err := NewRuntime(
		store,
		[]SourceConfig{runtimeSource("catalog.example.")},
		filepath.Join(t.TempDir(), "catalog-state.json"),
		[]string{"secondary.example."},
	)
	if err != nil {
		t.Fatal(err)
	}
	controller := &runtimeController{runtime: runtime}
	if err := runtime.AttachController(controller); err != nil {
		t.Fatal(err)
	}
	if err := runtime.AddZone(catalogZone(
		t,
		"catalog.example.",
		`a1.zones.catalog.example. 0 IN PTR secondary.example.`,
	)); err != nil {
		t.Fatal(err)
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if len(controller.upserts) != 0 {
		t.Fatalf("reserved secondary was catalog-provisioned: %+v", controller.upserts)
	}
}

func TestRuntimeFailedProvisionDoesNotClaimMember(t *testing.T) {
	store := newRuntimeStore()
	runtime, controller := newTestRuntime(t, store, filepath.Join(t.TempDir(), "catalog-state.json"))
	controller.err = errors.New("transfer unavailable")
	err := runtime.AddZone(catalogZone(t, "catalog.example.", `a1.zones.catalog.example. 0 IN PTR alpha.example.`))
	if err == nil {
		t.Fatal("failed member transfer was accepted")
	}
	runtime.mu.RLock()
	_, owned := runtime.ownership["alpha.example."]
	runtime.mu.RUnlock()
	if owned {
		t.Fatal("failed member transfer created ownership")
	}
}

func TestRuntimeOwnershipTransferAppliesDestinationPolicy(t *testing.T) {
	store := newRuntimeStore()
	destination := runtimeSource("next-catalog.example.")
	destination.Defaults.Masters = []string{"198.51.100.7"}
	runtime, err := NewRuntime(
		store,
		[]SourceConfig{runtimeSource("catalog.example."), destination},
		filepath.Join(t.TempDir(), "catalog-state.json"),
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	controller := &runtimeController{runtime: runtime}
	if err := runtime.AttachController(controller); err != nil {
		t.Fatal(err)
	}
	if err := runtime.AddZone(catalogZone(
		t,
		"catalog.example.",
		`a1.zones.catalog.example. 0 IN PTR alpha.example.`,
	)); err != nil {
		t.Fatal(err)
	}
	if err := runtime.AddZone(catalogZone(
		t,
		"next-catalog.example.",
		`a1.zones.next-catalog.example. 0 IN PTR alpha.example.`,
	)); err != nil {
		t.Fatal(err)
	}
	ownershipTransfer := catalogZone(
		t,
		"catalog.example.",
		`a1.zones.catalog.example. 0 IN PTR alpha.example.`,
		`coo.a1.zones.catalog.example. 0 IN PTR next-catalog.example.`,
	)
	ownershipTransfer.SOA.Serial = 43
	if err := runtime.AddZone(ownershipTransfer); err != nil {
		t.Fatal(err)
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if len(controller.upserts) != 2 ||
		controller.upserts[1].Masters[0] != "198.51.100.7" ||
		controller.resets[1] {
		t.Fatalf("ownership transfer upserts=%+v resets=%v", controller.upserts, controller.resets)
	}
}
