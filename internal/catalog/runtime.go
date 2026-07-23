package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/dnsscience/dnsscienced/internal/secondary"
	"github.com/dnsscience/dnsscienced/internal/zone"
	"github.com/miekg/dns"
)

const stateVersion = 1

const (
	maxCatalogSources           = 128
	defaultMaxCatalogMembers    = 100_000
	absoluteMaxCatalogMembers   = 10_000_000
	defaultMaxReconcileActions  = 200_000
	absoluteMaxReconcileActions = 10_000_000
)

// AuthoritativeStore is the publication surface used for catalog-managed
// member zones. Catalog zones themselves are deliberately kept private.
type AuthoritativeStore interface {
	AddZone(*zone.Zone) error
	GetZone(string) *zone.Zone
	RemoveZone(string)
	GetZoneNames() []string
}

// SecondaryController is the dynamic portion of secondary.Manager used by the
// reconciler. The interface keeps catalog logic independently testable.
type SecondaryController interface {
	Upsert(context.Context, secondary.Config, bool) error
	Remove(string) bool
}

// SourceConfig maps an authenticated catalog to transfer settings inherited by
// its members. A matching RFC 9432 group overrides Defaults.
type SourceConfig struct {
	Name                string
	Defaults            secondary.Config
	Groups              map[string]secondary.Config
	MemberAllowSuffixes []string
	MemberDenySuffixes  []string
	MaxMembers          int
	MaxReconcileActions int
}

// Runtime retains last-valid catalog state, plans RFC 9432 changes, and
// provisions member zones through the authenticated secondary manager.
type Runtime struct {
	store      AuthoritativeStore
	statePath  string
	order      []string
	sources    map[string]SourceConfig
	reserved   []string
	controller SecondaryController

	reconcileMu sync.Mutex
	mu          sync.RWMutex
	catalogs    map[string]*Catalog
	catalogZone map[string]*zone.Zone
	ownership   map[string]Ownership
	memberZone  map[string]*zone.Zone
}

type diskState struct {
	Version   int                      `json:"version"`
	Catalogs  map[string]persistedZone `json:"catalogs"`
	Ownership map[string]Ownership     `json:"ownership"`
	Members   map[string]persistedZone `json:"members"`
}

type persistedZone struct {
	Origin  string   `json:"origin"`
	Records []string `json:"records"`
}

// NewRuntime loads and validates persisted state before restoring any member
// data. statePath is required so ownership cannot be forgotten across restart.
func NewRuntime(
	store AuthoritativeStore,
	sources []SourceConfig,
	statePath string,
	reservedZones []string,
) (*Runtime, error) {
	if store == nil {
		return nil, fmt.Errorf("catalog: authoritative store is required")
	}
	if strings.TrimSpace(statePath) == "" {
		return nil, fmt.Errorf("catalog: state path is required")
	}
	if len(sources) > maxCatalogSources {
		return nil, fmt.Errorf("catalog: at most %d sources are allowed", maxCatalogSources)
	}
	r := &Runtime{
		store:       store,
		statePath:   statePath,
		sources:     make(map[string]SourceConfig, len(sources)),
		catalogs:    make(map[string]*Catalog),
		catalogZone: make(map[string]*zone.Zone),
		ownership:   make(map[string]Ownership),
		memberZone:  make(map[string]*zone.Zone),
	}
	for _, source := range sources {
		source.Name = normalizeName(source.Name)
		if source.Name == "." {
			return nil, fmt.Errorf("catalog: source name is required")
		}
		if _, exists := r.sources[source.Name]; exists {
			return nil, fmt.Errorf("catalog: duplicate source %s", source.Name)
		}
		source.Defaults.RetainOnError = true
		for group, cfg := range source.Groups {
			cfg.RetainOnError = true
			source.Groups[group] = cfg
		}
		var err error
		source.MemberAllowSuffixes, err = normalizeSuffixes(source.MemberAllowSuffixes)
		if err != nil {
			return nil, fmt.Errorf("catalog %s member allow suffixes: %w", source.Name, err)
		}
		source.MemberDenySuffixes, err = normalizeSuffixes(source.MemberDenySuffixes)
		if err != nil {
			return nil, fmt.Errorf("catalog %s member deny suffixes: %w", source.Name, err)
		}
		if source.MaxMembers == 0 {
			source.MaxMembers = defaultMaxCatalogMembers
		}
		if source.MaxMembers < 1 || source.MaxMembers > absoluteMaxCatalogMembers {
			return nil, fmt.Errorf("catalog %s max_members must be between 1 and %d", source.Name, absoluteMaxCatalogMembers)
		}
		if source.MaxReconcileActions == 0 {
			source.MaxReconcileActions = defaultMaxReconcileActions
		}
		if source.MaxReconcileActions < 1 || source.MaxReconcileActions > absoluteMaxReconcileActions {
			return nil, fmt.Errorf(
				"catalog %s max_reconcile_actions must be between 1 and %d",
				source.Name,
				absoluteMaxReconcileActions,
			)
		}
		r.sources[source.Name] = source
		r.order = append(r.order, source.Name)
	}
	r.reserved = normalizeNames(append(append([]string(nil), store.GetZoneNames()...), reservedZones...))
	r.reserved = normalizeNames(append(r.reserved, r.order...))
	if err := r.load(); err != nil {
		return nil, err
	}
	for catalogName, accepted := range r.catalogs {
		if err := r.validateMemberScope(catalogName, accepted); err != nil {
			return nil, fmt.Errorf("catalog: persisted snapshot violates current limits: %w", err)
		}
	}
	if err := r.validateCatalogGraph(r.catalogs); err != nil {
		return nil, fmt.Errorf("catalog: persisted snapshots contain an ownership cycle: %w", err)
	}
	for zoneName, owner := range r.ownership {
		source, ok := r.sources[owner.Catalog]
		if !ok {
			delete(r.ownership, zoneName)
			delete(r.memberZone, zoneName)
			continue
		}
		if err := validateMemberName(owner.Catalog, zoneName, source); err != nil {
			return nil, fmt.Errorf("catalog: persisted ownership violates current policy: %w", err)
		}
		if containsName(r.reserved, zoneName) {
			return nil, fmt.Errorf("catalog: persisted member %s conflicts with an operator-configured zone", zoneName)
		}
		member := r.memberZone[zoneName]
		if member == nil {
			return nil, fmt.Errorf("catalog: persisted ownership for %s has no member zone data", zoneName)
		}
		if err := r.store.AddZone(member); err != nil {
			return nil, fmt.Errorf("catalog: restore member %s: %w", zoneName, err)
		}
	}
	return r, nil
}

// AttachController seeds retained members before the manager starts. It must be
// called exactly once.
func (r *Runtime) AttachController(controller SecondaryController) error {
	if controller == nil {
		return fmt.Errorf("catalog: secondary controller is required")
	}
	r.reconcileMu.Lock()
	defer r.reconcileMu.Unlock()
	if r.controller != nil {
		return fmt.Errorf("catalog: secondary controller already attached")
	}
	r.controller = controller

	for _, zoneName := range sortedOwnershipZones(r.ownership) {
		owner := r.ownership[zoneName]
		cat := r.catalogs[owner.Catalog]
		member, ok := memberIn(cat, zoneName)
		if !ok {
			return fmt.Errorf("catalog: retained owner %s no longer contains member %s", owner.Catalog, zoneName)
		}
		cfg, err := r.memberConfig(owner.Catalog, member)
		if err != nil {
			return err
		}
		if err := controller.Upsert(context.Background(), cfg, false); err != nil {
			return fmt.Errorf("catalog: seed member %s: %w", zoneName, err)
		}
	}
	return r.persist()
}

// CatalogSecondaryConfigs returns private, authenticated secondaries for the
// configured catalog zones.
func (r *Runtime) CatalogSecondaryConfigs(configs map[string]secondary.Config) ([]secondary.Config, error) {
	result := make([]secondary.Config, 0, len(r.order))
	for _, name := range r.order {
		cfg, ok := configs[name]
		if !ok {
			return nil, fmt.Errorf("catalog: transfer configuration missing for %s", name)
		}
		cfg.Name = name
		cfg.RetainOnError = true
		result = append(result, cfg)
	}
	return result, nil
}

// AddZone implements secondary.ZoneStore. Catalog publications reconcile
// privately; member publications are atomically forwarded and persisted.
func (r *Runtime) AddZone(z *zone.Zone) error {
	if z == nil {
		return fmt.Errorf("catalog: cannot publish nil zone")
	}
	name := normalizeName(z.Origin)
	if _, isCatalog := r.sources[name]; !isCatalog {
		previous := r.store.GetZone(name)
		if err := r.store.AddZone(z); err != nil {
			return err
		}
		r.mu.Lock()
		previousPersisted := r.memberZone[name]
		if _, managed := r.ownership[name]; managed {
			r.memberZone[name] = z.Clone()
		}
		err := r.persistLocked()
		if err != nil {
			if previousPersisted == nil {
				delete(r.memberZone, name)
			} else {
				r.memberZone[name] = previousPersisted
			}
		}
		r.mu.Unlock()
		if err != nil {
			if previous == nil {
				r.store.RemoveZone(name)
			} else {
				_ = r.store.AddZone(previous)
			}
		}
		return err
	}

	parsed, err := Parse(z)
	if err != nil {
		return fmt.Errorf("catalog %s rejected; retaining last valid state: %w", name, err)
	}
	return r.reconcile(name, parsed, z)
}

// GetZone implements secondary.ZoneStore without exposing catalog zones to the
// authoritative server.
func (r *Runtime) GetZone(name string) *zone.Zone {
	name = normalizeName(name)
	r.mu.RLock()
	catalogZone := r.catalogZone[name]
	r.mu.RUnlock()
	if catalogZone != nil {
		return catalogZone
	}
	return r.store.GetZone(name)
}

func (r *Runtime) reconcile(name string, accepted *Catalog, raw *zone.Zone) error {
	r.reconcileMu.Lock()
	defer r.reconcileMu.Unlock()
	if r.controller == nil {
		return fmt.Errorf("catalog: secondary controller is not attached")
	}
	if err := r.validateMemberScope(name, accepted); err != nil {
		return err
	}

	r.mu.RLock()
	current := r.catalogs[name]
	previous := cloneCatalogMap(r.catalogs)
	next := cloneCatalogMap(r.catalogs)
	ownership := cloneOwnership(r.ownership)
	r.mu.RUnlock()
	if current != nil && !zone.SerialGreater(accepted.Serial, current.Serial) {
		return fmt.Errorf(
			"catalog %s serial %d does not advance last-valid serial %d",
			name,
			accepted.Serial,
			current.Serial,
		)
	}
	next[name] = accepted
	if err := r.validateCatalogGraph(next); err != nil {
		return err
	}

	actions, err := Plan(previous, next, ownership, r.order, r.reserved)
	if err != nil {
		return fmt.Errorf("catalog %s plan: %w", name, err)
	}
	if len(actions) > r.sources[name].MaxReconcileActions {
		return fmt.Errorf(
			"catalog %s reconciliation has %d actions; max_reconcile_actions is %d",
			name,
			len(actions),
			r.sources[name].MaxReconcileActions,
		)
	}
	// Persist the accepted snapshot before side effects. If reconciliation is
	// interrupted, the next refresh deterministically resumes missing actions
	// from persisted ownership rather than forgetting the desired state.
	r.mu.Lock()
	r.catalogs[name] = accepted
	r.catalogZone[name] = raw.Clone()
	err = r.persistLocked()
	r.mu.Unlock()
	if err != nil {
		return err
	}
	for _, action := range actions {
		if action.Kind == ActionConflict {
			continue
		}
		member, memberExists := memberIn(next[action.Catalog], action.Zone)
		switch action.Kind {
		case ActionAdd, ActionReconfigure, ActionRecreate:
			if !memberExists {
				return fmt.Errorf("catalog: action %s has no member %s", action.Kind, action.Zone)
			}
			cfg, err := r.memberConfig(action.Catalog, member)
			if err != nil {
				return err
			}
			if err := r.controller.Upsert(context.Background(), cfg, action.ResetState); err != nil {
				return fmt.Errorf("catalog: %s member %s: %w", action.Kind, action.Zone, err)
			}
			r.mu.Lock()
			r.ownership[action.Zone] = Ownership{Catalog: action.Catalog, Label: action.Label}
			if published := r.store.GetZone(action.Zone); published != nil {
				r.memberZone[action.Zone] = published.Clone()
			}
			err = r.persistLocked()
			r.mu.Unlock()
			if err != nil {
				return err
			}
		case ActionTransferOwnership:
			if !memberExists {
				return fmt.Errorf("catalog: ownership transfer has no destination member %s", action.Zone)
			}
			cfg, err := r.memberConfig(action.Catalog, member)
			if err != nil {
				return err
			}
			if err := r.controller.Upsert(context.Background(), cfg, action.ResetState); err != nil {
				return fmt.Errorf("catalog: transfer member %s: %w", action.Zone, err)
			}
			r.mu.Lock()
			r.ownership[action.Zone] = Ownership{Catalog: action.Catalog, Label: action.Label}
			if published := r.store.GetZone(action.Zone); published != nil {
				r.memberZone[action.Zone] = published.Clone()
			}
			err = r.persistLocked()
			r.mu.Unlock()
			if err != nil {
				return err
			}
		case ActionRemove:
			r.controller.Remove(action.Zone)
			r.store.RemoveZone(action.Zone)
			r.mu.Lock()
			delete(r.ownership, action.Zone)
			delete(r.memberZone, action.Zone)
			err = r.persistLocked()
			r.mu.Unlock()
			if err != nil {
				return err
			}
		default:
			return fmt.Errorf("catalog: unsupported reconciliation action %q", action.Kind)
		}
	}

	return nil
}

func (r *Runtime) validateMemberScope(catalogName string, accepted *Catalog) error {
	source, ok := r.sources[normalizeName(catalogName)]
	if !ok {
		return fmt.Errorf("catalog: no source configuration for %s", catalogName)
	}
	if len(accepted.Members) > source.MaxMembers {
		return fmt.Errorf(
			"catalog %s has %d members; max_members is %d",
			catalogName,
			len(accepted.Members),
			source.MaxMembers,
		)
	}
	for memberName := range accepted.Members {
		if _, isCatalog := r.sources[memberName]; isCatalog {
			return fmt.Errorf("catalog %s cannot provision configured catalog %s as a member", catalogName, memberName)
		}
		if err := validateMemberName(catalogName, memberName, source); err != nil {
			return err
		}
	}
	return nil
}

func (r *Runtime) validateCatalogGraph(catalogs map[string]*Catalog) error {
	memberZones := make(map[string]struct{})
	for _, accepted := range catalogs {
		for memberName := range accepted.Members {
			memberZones[memberName] = struct{}{}
		}
	}
	for _, memberName := range sortedSet(memberZones) {
		edges := make(map[string]string)
		for catalogName, accepted := range catalogs {
			member, exists := accepted.Members[memberName]
			if !exists || member.ChangeOfOwnership == "" {
				continue
			}
			target := normalizeName(member.ChangeOfOwnership)
			if target == catalogName {
				return fmt.Errorf("catalog %s member %s has self-referential coo", catalogName, memberName)
			}
			if _, configured := r.sources[target]; configured {
				edges[catalogName] = target
			}
		}
		for _, start := range sortedMapKeys(edges) {
			seen := make(map[string]bool)
			current := start
			for current != "" {
				if seen[current] {
					return fmt.Errorf("member %s has cyclic catalog ownership through %s", memberName, current)
				}
				seen[current] = true
				current = edges[current]
			}
		}
	}
	return nil
}

func validateMemberName(catalogName, memberName string, source SourceConfig) error {
	for _, suffix := range source.MemberDenySuffixes {
		if dns.IsSubDomain(suffix, memberName) {
			return fmt.Errorf("catalog %s member %s is denied by suffix %s", catalogName, memberName, suffix)
		}
	}
	if len(source.MemberAllowSuffixes) == 0 {
		return nil
	}
	for _, suffix := range source.MemberAllowSuffixes {
		if dns.IsSubDomain(suffix, memberName) {
			return nil
		}
	}
	return fmt.Errorf("catalog %s member %s is outside allowed suffixes", catalogName, memberName)
}

func (r *Runtime) memberConfig(catalogName string, member Member) (secondary.Config, error) {
	source, ok := r.sources[normalizeName(catalogName)]
	if !ok {
		return secondary.Config{}, fmt.Errorf("catalog: no source configuration for %s", catalogName)
	}
	cfg := source.Defaults
	for _, group := range member.Groups {
		groupName := strings.Join(group.Strings, "")
		if groupCfg, found := source.Groups[groupName]; found {
			cfg = groupCfg
			break
		}
	}
	cfg.Name = member.Zone
	cfg.RetainOnError = true
	if len(cfg.Masters) == 0 {
		return secondary.Config{}, fmt.Errorf("catalog %s member %s has no configured masters", catalogName, member.Zone)
	}
	return cfg, nil
}

func (r *Runtime) load() error {
	data, err := os.ReadFile(r.statePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("catalog: read state: %w", err)
	}
	var state diskState
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("catalog: decode state: %w", err)
	}
	if state.Version != stateVersion {
		return fmt.Errorf("catalog: unsupported state version %d", state.Version)
	}
	for name, persisted := range state.Catalogs {
		z, err := restoreZone(persisted)
		if err != nil {
			return fmt.Errorf("catalog: restore catalog %s: %w", name, err)
		}
		parsed, err := Parse(z)
		if err != nil {
			return fmt.Errorf("catalog: persisted catalog %s is invalid: %w", name, err)
		}
		name = normalizeName(name)
		if parsed.Name != name {
			return fmt.Errorf("catalog: persisted key %s contains %s", name, parsed.Name)
		}
		if _, configured := r.sources[name]; configured {
			r.catalogs[name] = parsed
			r.catalogZone[name] = z
		}
	}
	for name, owner := range state.Ownership {
		name = normalizeName(name)
		owner.Catalog = normalizeName(owner.Catalog)
		r.ownership[name] = owner
	}
	for name, persisted := range state.Members {
		z, err := restoreZone(persisted)
		if err != nil {
			return fmt.Errorf("catalog: restore member %s: %w", name, err)
		}
		name = normalizeName(name)
		if z.Origin != name {
			return fmt.Errorf("catalog: persisted member key %s contains %s", name, z.Origin)
		}
		r.memberZone[name] = z
	}
	return nil
}

func (r *Runtime) persist() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.persistLocked()
}

func (r *Runtime) persistLocked() error {
	state := diskState{
		Version:   stateVersion,
		Catalogs:  make(map[string]persistedZone, len(r.catalogZone)),
		Ownership: cloneOwnership(r.ownership),
		Members:   make(map[string]persistedZone, len(r.memberZone)),
	}
	for name, z := range r.catalogZone {
		state.Catalogs[name] = persistZone(z)
	}
	for name, z := range r.memberZone {
		if _, owned := r.ownership[name]; owned {
			state.Members[name] = persistZone(z)
		}
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("catalog: encode state: %w", err)
	}
	data = append(data, '\n')
	dir := filepath.Dir(r.statePath)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("catalog: create state directory: %w", err)
	}
	temp, err := os.CreateTemp(dir, ".catalog-state-*")
	if err != nil {
		return fmt.Errorf("catalog: create temporary state: %w", err)
	}
	tempName := temp.Name()
	removeTemp := true
	defer func() {
		if removeTemp {
			_ = os.Remove(tempName)
		}
	}()
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return fmt.Errorf("catalog: protect temporary state: %w", err)
	}
	if _, err := temp.Write(data); err != nil {
		_ = temp.Close()
		return fmt.Errorf("catalog: write state: %w", err)
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return fmt.Errorf("catalog: sync state: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("catalog: close state: %w", err)
	}
	if err := os.Rename(tempName, r.statePath); err != nil {
		return fmt.Errorf("catalog: replace state: %w", err)
	}
	removeTemp = false
	if directory, err := os.Open(dir); err == nil {
		_ = directory.Sync()
		_ = directory.Close()
	}
	return nil
}

func persistZone(z *zone.Zone) persistedZone {
	records := z.GetAllRecords()
	result := persistedZone{Origin: z.Origin, Records: make([]string, 0, len(records))}
	for _, rr := range records {
		result.Records = append(result.Records, rr.String())
	}
	sort.Strings(result.Records)
	return result
}

func restoreZone(persisted persistedZone) (*zone.Zone, error) {
	result := zone.New(normalizeName(persisted.Origin))
	for _, text := range persisted.Records {
		rr, err := dns.NewRR(text)
		if err != nil {
			return nil, err
		}
		if err := result.AddRecord(rr); err != nil {
			return nil, err
		}
	}
	if err := result.Validate(); err != nil {
		return nil, err
	}
	return result, nil
}

func cloneCatalogMap(source map[string]*Catalog) map[string]*Catalog {
	result := make(map[string]*Catalog, len(source))
	for name, catalog := range source {
		result[name] = catalog
	}
	return result
}

func cloneOwnership(source map[string]Ownership) map[string]Ownership {
	result := make(map[string]Ownership, len(source))
	for name, owner := range source {
		result[name] = owner
	}
	return result
}

func normalizeNames(names []string) []string {
	result := make([]string, 0, len(names))
	seen := make(map[string]bool, len(names))
	for _, name := range names {
		name = normalizeName(name)
		if !seen[name] {
			result = append(result, name)
			seen[name] = true
		}
	}
	sort.Strings(result)
	return result
}

func normalizeSuffixes(suffixes []string) ([]string, error) {
	result := make([]string, 0, len(suffixes))
	for _, suffix := range suffixes {
		if strings.TrimSpace(suffix) == "" {
			return nil, fmt.Errorf("DNS suffix cannot be empty")
		}
		suffix = normalizeName(suffix)
		if _, ok := dns.IsDomainName(suffix); !ok {
			return nil, fmt.Errorf("invalid DNS suffix %q", suffix)
		}
		result = append(result, suffix)
	}
	return normalizeNames(result), nil
}

func sortedSet(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func sortedMapKeys(values map[string]string) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func containsName(names []string, target string) bool {
	index := sort.SearchStrings(names, normalizeName(target))
	return index < len(names) && names[index] == normalizeName(target)
}
