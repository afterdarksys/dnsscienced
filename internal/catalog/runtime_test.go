package catalog

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/dnsscience/dnsscienced/internal/secondary"
	"github.com/dnsscience/dnsscienced/internal/zone"
	"github.com/miekg/dns"
)

type runtimeStore struct {
	mu         sync.RWMutex
	zones      map[string]*zone.Zone
	batchCalls int
	batchErr   error
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

func (s *runtimeStore) ApplyZoneBatch(upserts []*zone.Zone, removals []string) error {
	for _, z := range upserts {
		if z == nil {
			return errors.New("nil zone")
		}
		if err := z.Validate(); err != nil {
			return err
		}
	}
	s.mu.Lock()
	if s.batchErr != nil {
		err := s.batchErr
		s.mu.Unlock()
		return err
	}
	next := make(map[string]*zone.Zone, len(s.zones)+len(upserts))
	for name, z := range s.zones {
		next[name] = z
	}
	for _, name := range removals {
		delete(next, normalizeName(name))
	}
	for _, z := range upserts {
		next[normalizeName(z.Origin)] = z
	}
	s.zones = next
	s.batchCalls++
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

type catalogIntegrationFetcher struct {
	catalog *zone.Zone
}

func (f catalogIntegrationFetcher) Fetch(
	_ context.Context,
	cfg secondary.Config,
	_ *zone.Zone,
) (*zone.Zone, error) {
	if normalizeName(cfg.Name) == normalizeName(f.catalog.Origin) {
		return f.catalog.Clone(), nil
	}
	return runtimeMemberZone(cfg.Name, 1), nil
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

func (c *runtimeController) ApplyBatch(
	_ context.Context,
	changes []secondary.BatchChange,
	publish secondary.BatchPublisher,
) error {
	c.mu.Lock()
	err := c.err
	baseSerial := len(c.upserts)
	c.mu.Unlock()
	if err != nil {
		return err
	}
	upserts := make([]*zone.Zone, 0, len(changes))
	removals := make([]string, 0, len(changes))
	for _, change := range changes {
		if change.Remove {
			removals = append(removals, normalizeName(change.Name))
			continue
		}
		upserts = append(upserts, runtimeMemberZone(change.Config.Name, uint32(baseSerial+len(upserts)+1)))
	}
	if err := publish(upserts, removals); err != nil {
		return err
	}
	c.mu.Lock()
	for _, change := range changes {
		if change.Remove {
			c.removed = append(c.removed, normalizeName(change.Name))
			continue
		}
		c.upserts = append(c.upserts, change.Config)
		c.resets = append(c.resets, change.ResetState)
	}
	c.mu.Unlock()
	return nil
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

func TestRuntimeAndSecondaryManagerAtomicallyProvisionInitialCatalog(t *testing.T) {
	store := newRuntimeStore()
	runtime, err := NewRuntime(
		store,
		[]SourceConfig{runtimeSource("catalog.example.")},
		filepath.Join(t.TempDir(), "catalog-state.json"),
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	catalog := catalogZone(
		t,
		"catalog.example.",
		`a1.zones.catalog.example. 0 IN PTR alpha.example.`,
		`a2.zones.catalog.example. 0 IN PTR beta.example.`,
	)
	manager, err := secondary.NewManager(
		runtime,
		catalogIntegrationFetcher{catalog: catalog},
		[]secondary.Config{{
			Name:                  "catalog.example.",
			Masters:               []string{"192.0.2.1"},
			AllowUnsignedTransfer: true,
			RetainOnError:         true,
		}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.AttachController(manager); err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer manager.Close()

	if store.GetZone("catalog.example.") != nil {
		t.Fatal("catalog zone was exposed through the authoritative store")
	}
	if store.GetZone("alpha.example.") == nil || store.GetZone("beta.example.") == nil {
		t.Fatal("initial catalog fleet was not published")
	}
	store.mu.RLock()
	batchCalls := store.batchCalls
	store.mu.RUnlock()
	if batchCalls != 1 {
		t.Fatalf("authoritative batch publications = %d, want 1", batchCalls)
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

func TestRuntimeEnforcesMemberSuffixPolicyAtomically(t *testing.T) {
	store := newRuntimeStore()
	source := runtimeSource("catalog.example.")
	source.MemberAllowSuffixes = []string{"customer.example."}
	source.MemberDenySuffixes = []string{"suspended.customer.example."}
	runtime, err := NewRuntime(
		store,
		[]SourceConfig{source},
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
	valid := catalogZone(
		t,
		"catalog.example.",
		`a1.zones.catalog.example. 0 IN PTR alpha.customer.example.`,
	)
	if err := runtime.AddZone(valid); err != nil {
		t.Fatal(err)
	}

	for _, member := range []string{"evil.suspended.customer.example.", "outside.example."} {
		rejected := catalogZone(
			t,
			"catalog.example.",
			`a2.zones.catalog.example. 0 IN PTR `+member,
		)
		rejected.SOA.Serial = valid.SOA.Serial + 1
		if err := runtime.AddZone(rejected); err == nil {
			t.Fatalf("out-of-scope member %s was accepted", member)
		}
		if store.GetZone("alpha.customer.example.") == nil {
			t.Fatalf("rejected member %s disturbed last-valid state", member)
		}
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if len(controller.upserts) != 1 || len(controller.removed) != 0 {
		t.Fatalf("scope rejection caused side effects: upserts=%v removed=%v", controller.upserts, controller.removed)
	}
}

func TestRuntimeRejectsInvalidMemberSuffix(t *testing.T) {
	source := runtimeSource("catalog.example.")
	source.MemberAllowSuffixes = []string{""}
	if _, err := NewRuntime(
		newRuntimeStore(),
		[]SourceConfig{source},
		filepath.Join(t.TempDir(), "catalog-state.json"),
		nil,
	); err == nil {
		t.Fatal("empty member allow suffix was accepted")
	}
}

func TestRuntimeRejectsPersistedMemberOutsideNarrowedScope(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "catalog-state.json")
	first, _ := newTestRuntime(t, newRuntimeStore(), statePath)
	if err := first.AddZone(catalogZone(
		t,
		"catalog.example.",
		`a1.zones.catalog.example. 0 IN PTR alpha.customer.example.`,
	)); err != nil {
		t.Fatal(err)
	}

	narrowed := runtimeSource("catalog.example.")
	narrowed.MemberAllowSuffixes = []string{"other.example."}
	if _, err := NewRuntime(newRuntimeStore(), []SourceConfig{narrowed}, statePath, nil); err == nil {
		t.Fatal("persisted member outside narrowed scope was restored")
	}
}

func TestRuntimeEnforcesMemberAndReconcileLimits(t *testing.T) {
	records := []string{
		`a1.zones.catalog.example. 0 IN PTR one.example.`,
		`a2.zones.catalog.example. 0 IN PTR two.example.`,
	}
	for name, configure := range map[string]func(*SourceConfig){
		"members": func(source *SourceConfig) { source.MaxMembers = 1 },
		"actions": func(source *SourceConfig) { source.MaxReconcileActions = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			source := runtimeSource("catalog.example.")
			configure(&source)
			runtime, err := NewRuntime(
				newRuntimeStore(),
				[]SourceConfig{source},
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
			if err := runtime.AddZone(catalogZone(t, "catalog.example.", records...)); err == nil {
				t.Fatalf("%s limit was not enforced", name)
			}
			controller.mu.Lock()
			defer controller.mu.Unlock()
			if len(controller.upserts) != 0 {
				t.Fatalf("%s limit allowed partial provisioning: %v", name, controller.upserts)
			}
		})
	}
}

func TestRuntimeRejectsInvalidResourceLimits(t *testing.T) {
	for name, configure := range map[string]func(*SourceConfig){
		"members":      func(source *SourceConfig) { source.MaxMembers = -1 },
		"actions":      func(source *SourceConfig) { source.MaxReconcileActions = -1 },
		"action_rate":  func(source *SourceConfig) { source.ReconcileActionsPerMinute = -1 },
		"action_burst": func(source *SourceConfig) { source.ReconcileActionBurst = -1 },
	} {
		t.Run(name, func(t *testing.T) {
			source := runtimeSource("catalog.example.")
			configure(&source)
			if _, err := NewRuntime(
				newRuntimeStore(),
				[]SourceConfig{source},
				filepath.Join(t.TempDir(), "catalog-state.json"),
				nil,
			); err == nil {
				t.Fatalf("invalid %s limit was accepted", name)
			}
		})
	}
}

func TestRuntimeBoundsCatalogSourceCount(t *testing.T) {
	sources := make([]SourceConfig, maxCatalogSources+1)
	for i := range sources {
		sources[i] = runtimeSource("catalog-" + serialStringForRuntime(uint32(i+1)) + ".example.")
	}
	if _, err := NewRuntime(
		newRuntimeStore(),
		sources,
		filepath.Join(t.TempDir(), "catalog-state.json"),
		nil,
	); err == nil {
		t.Fatal("catalog source limit was not enforced")
	}
}

func TestRuntimeReconcileRateBudgetRefillsOverTime(t *testing.T) {
	store := newRuntimeStore()
	source := runtimeSource("catalog.example.")
	source.MaxReconcileActions = 10
	source.ReconcileActionsPerMinute = 2
	source.ReconcileActionBurst = 2
	runtime, err := NewRuntime(
		store,
		[]SourceConfig{source},
		filepath.Join(t.TempDir(), "catalog-state.json"),
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(100, 0)
	runtime.now = func() time.Time { return now }
	runtime.budgets["catalog.example."].lastRefill = now
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
	replacement := catalogZone(
		t,
		"catalog.example.",
		`b1.zones.catalog.example. 0 IN PTR beta.example.`,
	)
	replacement.SOA.Serial = 43
	if err := runtime.AddZone(replacement); err == nil {
		t.Fatal("two-action replacement exceeded the remaining burst")
	}
	if store.GetZone("alpha.example.") == nil || store.GetZone("beta.example.") != nil {
		t.Fatal("rate-limited reconciliation changed the fleet")
	}
	now = now.Add(30 * time.Second)
	if err := runtime.AddZone(replacement); err != nil {
		t.Fatalf("refilled action budget rejected reconciliation: %v", err)
	}
	if store.GetZone("alpha.example.") != nil || store.GetZone("beta.example.") == nil {
		t.Fatal("refilled reconciliation did not atomically replace the fleet")
	}
}

func TestRuntimeReconcileRateBudgetRefundsFailure(t *testing.T) {
	store := newRuntimeStore()
	source := runtimeSource("catalog.example.")
	source.ReconcileActionsPerMinute = 1
	source.ReconcileActionBurst = 1
	runtime, err := NewRuntime(
		store,
		[]SourceConfig{source},
		filepath.Join(t.TempDir(), "catalog-state.json"),
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	controller := &runtimeController{runtime: runtime, err: errors.New("transfer failed")}
	if err := runtime.AttachController(controller); err != nil {
		t.Fatal(err)
	}
	catalog := catalogZone(
		t,
		"catalog.example.",
		`a1.zones.catalog.example. 0 IN PTR alpha.example.`,
	)
	if err := runtime.AddZone(catalog); err == nil {
		t.Fatal("failed transfer was accepted")
	}
	controller.mu.Lock()
	controller.err = nil
	controller.mu.Unlock()
	if err := runtime.AddZone(catalog); err != nil {
		t.Fatalf("failed reconciliation did not refund its token: %v", err)
	}
}

func TestRuntimeRejectsConfiguredCatalogAsMember(t *testing.T) {
	runtime, controller := newTestRuntime(
		t,
		newRuntimeStore(),
		filepath.Join(t.TempDir(), "catalog-state.json"),
	)
	if err := runtime.AddZone(catalogZone(
		t,
		"catalog.example.",
		`self.zones.catalog.example. 0 IN PTR catalog.example.`,
	)); err == nil {
		t.Fatal("configured catalog was accepted as its own member")
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if len(controller.upserts) != 0 {
		t.Fatalf("self-member caused provisioning: %v", controller.upserts)
	}
}

func TestRuntimeRejectsSelfReferentialCOO(t *testing.T) {
	runtime, _ := newTestRuntime(
		t,
		newRuntimeStore(),
		filepath.Join(t.TempDir(), "catalog-state.json"),
	)
	if err := runtime.AddZone(catalogZone(
		t,
		"catalog.example.",
		`a1.zones.catalog.example. 0 IN PTR alpha.example.`,
		`coo.a1.zones.catalog.example. 0 IN PTR catalog.example.`,
	)); err == nil {
		t.Fatal("self-referential COO was accepted")
	}
}

func TestRuntimeRejectsCrossCatalogOwnershipCycle(t *testing.T) {
	store := newRuntimeStore()
	runtime, err := NewRuntime(
		store,
		[]SourceConfig{
			runtimeSource("first.catalog."),
			runtimeSource("second.catalog."),
		},
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
		"first.catalog.",
		`a1.zones.first.catalog. 0 IN PTR alpha.example.`,
		`coo.a1.zones.first.catalog. 0 IN PTR second.catalog.`,
	)); err != nil {
		t.Fatal(err)
	}
	if err := runtime.AddZone(catalogZone(
		t,
		"second.catalog.",
		`b1.zones.second.catalog. 0 IN PTR alpha.example.`,
		`coo.b1.zones.second.catalog. 0 IN PTR first.catalog.`,
	)); err == nil {
		t.Fatal("cross-catalog COO cycle was accepted")
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if len(controller.upserts) != 1 {
		t.Fatalf("cycle rejection caused side effects: %v", controller.upserts)
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

func TestRuntimeFailedMultiActionRetainsPreviousCatalogAndFleet(t *testing.T) {
	store := newRuntimeStore()
	runtime, controller := newTestRuntime(t, store, filepath.Join(t.TempDir(), "catalog-state.json"))
	if err := runtime.AddZone(catalogZone(
		t,
		"catalog.example.",
		`a1.zones.catalog.example. 0 IN PTR alpha.example.`,
	)); err != nil {
		t.Fatal(err)
	}
	controller.err = errors.New("second fleet unavailable")
	replacement := catalogZone(
		t,
		"catalog.example.",
		`b1.zones.catalog.example. 0 IN PTR beta.example.`,
	)
	replacement.SOA.Serial = 43
	if err := runtime.AddZone(replacement); err == nil {
		t.Fatal("failed multi-action reconciliation was accepted")
	}
	if store.GetZone("alpha.example.") == nil {
		t.Fatal("previous member disappeared after failed reconciliation")
	}
	if store.GetZone("beta.example.") != nil {
		t.Fatal("new member leaked after failed reconciliation")
	}
	runtime.mu.RLock()
	serial := runtime.catalogs["catalog.example."].Serial
	_, ownsAlpha := runtime.ownership["alpha.example."]
	_, ownsBeta := runtime.ownership["beta.example."]
	runtime.mu.RUnlock()
	if serial != 42 || !ownsAlpha || ownsBeta {
		t.Fatalf("state after failure: serial=%d ownsAlpha=%v ownsBeta=%v", serial, ownsAlpha, ownsBeta)
	}
}

func TestRuntimeAuthoritativeBatchFailureRollsBackPersistedState(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "catalog-state.json")
	store := newRuntimeStore()
	runtime, _ := newTestRuntime(t, store, statePath)
	if err := runtime.AddZone(catalogZone(
		t,
		"catalog.example.",
		`a1.zones.catalog.example. 0 IN PTR alpha.example.`,
	)); err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	store.batchErr = errors.New("atomic publication unavailable")
	store.mu.Unlock()
	replacement := catalogZone(
		t,
		"catalog.example.",
		`b1.zones.catalog.example. 0 IN PTR beta.example.`,
	)
	replacement.SOA.Serial = 43
	if err := runtime.AddZone(replacement); err == nil {
		t.Fatal("failed authoritative batch was accepted")
	}
	if store.GetZone("alpha.example.") == nil || store.GetZone("beta.example.") != nil {
		t.Fatal("authoritative fleet changed after batch failure")
	}

	store.mu.Lock()
	store.batchErr = nil
	store.mu.Unlock()
	restoredStore := newRuntimeStore()
	restored, _ := newTestRuntime(t, restoredStore, statePath)
	restored.mu.RLock()
	serial := restored.catalogs["catalog.example."].Serial
	restored.mu.RUnlock()
	if serial != 42 || restoredStore.GetZone("alpha.example.") == nil {
		t.Fatalf("persisted rollback did not retain serial 42 and alpha member (serial=%d)", serial)
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
