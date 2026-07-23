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
	"time"

	"github.com/dnsscience/dnsscienced/internal/secondary"
	"github.com/dnsscience/dnsscienced/internal/zone"
	"github.com/miekg/dns"
)

const stateVersion = 1

var (
	ErrCatalogNotFound = errors.New("catalog snapshot not found")
	ErrCatalogChanged  = errors.New("catalog snapshot changed during pagination")
)

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
	ApplyZoneBatch([]*zone.Zone, []string) error
	GetZone(string) *zone.Zone
	RemoveZone(string)
	GetZoneNames() []string
}

// SecondaryController is the dynamic portion of secondary.Manager used by the
// reconciler. The interface keeps catalog logic independently testable.
type SecondaryController interface {
	Upsert(context.Context, secondary.Config, bool) error
	Remove(string) bool
	ApplyBatch(context.Context, []secondary.BatchChange, secondary.BatchPublisher) error
}

// SourceConfig maps an authenticated catalog to transfer settings inherited by
// its members. A matching RFC 9432 group overrides Defaults.
type SourceConfig struct {
	Name                      string
	Defaults                  secondary.Config
	Groups                    map[string]secondary.Config
	MemberAllowSuffixes       []string
	MemberDenySuffixes        []string
	MaxMembers                int
	MaxReconcileActions       int
	ReconcileActionsPerMinute int
	ReconcileActionBurst      int
	DryRun                    bool
	ApprovalRequiredAbove     int
	ApprovedSerial            *uint32
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
	acceptedAt  map[string]time.Time
	budgets     map[string]*reconcileBudget
	status      map[string]Status
	now         func() time.Time
	auditSink   AuditSink
	generation  uint64
}

// Status is an immutable operator view of one configured catalog.
type Status struct {
	Name                string
	Serial              uint32
	Members             int
	LastAttempt         time.Time
	LastSuccess         time.Time
	LastError           string
	PendingSerial       uint32
	PendingReason       string
	PendingActionCounts map[string]int
}

// MemberStatus is the audit-safe operator view of one catalog member. Transfer
// secrets are deliberately excluded.
type MemberStatus struct {
	Zone              string
	Label             string
	Groups            []string
	ChangeOfOwnership string
	OwnerCatalog      string
	EffectiveGroup    string
	Masters           []string
	TransferKeyName   string
	TransferAlgorithm string
}

type reconcileBudget struct {
	tokens     float64
	lastRefill time.Time
}

type diskState struct {
	Version   int                      `json:"version"`
	Catalogs  map[string]persistedZone `json:"catalogs"`
	Ownership map[string]Ownership     `json:"ownership"`
	Members   map[string]persistedZone `json:"members"`
}

type persistedZone struct {
	Origin     string    `json:"origin"`
	Records    []string  `json:"records"`
	AcceptedAt time.Time `json:"accepted_at,omitempty"`
}

// NewRuntime loads and validates persisted state before restoring any member
// data. statePath is required so ownership cannot be forgotten across restart.
func NewRuntime(
	store AuthoritativeStore,
	sources []SourceConfig,
	statePath string,
	reservedZones []string,
	auditSinks ...AuditSink,
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
	if len(auditSinks) > 1 {
		return nil, fmt.Errorf("catalog: at most one audit sink is allowed")
	}
	r := &Runtime{
		store:       store,
		statePath:   statePath,
		sources:     make(map[string]SourceConfig, len(sources)),
		catalogs:    make(map[string]*Catalog),
		catalogZone: make(map[string]*zone.Zone),
		ownership:   make(map[string]Ownership),
		memberZone:  make(map[string]*zone.Zone),
		acceptedAt:  make(map[string]time.Time),
		budgets:     make(map[string]*reconcileBudget, len(sources)),
		status:      make(map[string]Status, len(sources)),
		now:         time.Now,
	}
	if len(auditSinks) == 1 {
		r.auditSink = auditSinks[0]
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
		if source.ReconcileActionsPerMinute == 0 {
			source.ReconcileActionsPerMinute = source.MaxReconcileActions
		}
		if source.ReconcileActionsPerMinute < 1 ||
			source.ReconcileActionsPerMinute > absoluteMaxReconcileActions {
			return nil, fmt.Errorf(
				"catalog %s reconcile_actions_per_minute must be between 1 and %d",
				source.Name,
				absoluteMaxReconcileActions,
			)
		}
		if source.ReconcileActionBurst == 0 {
			source.ReconcileActionBurst = source.MaxReconcileActions
		}
		if source.ReconcileActionBurst < 1 || source.ReconcileActionBurst > absoluteMaxReconcileActions {
			return nil, fmt.Errorf(
				"catalog %s reconcile_action_burst must be between 1 and %d",
				source.Name,
				absoluteMaxReconcileActions,
			)
		}
		if source.ApprovalRequiredAbove < 0 ||
			source.ApprovalRequiredAbove > absoluteMaxReconcileActions {
			return nil, fmt.Errorf(
				"catalog %s approval_required_above must be between 0 and %d",
				source.Name,
				absoluteMaxReconcileActions,
			)
		}
		r.sources[source.Name] = source
		r.budgets[source.Name] = &reconcileBudget{
			tokens:     float64(source.ReconcileActionBurst),
			lastRefill: r.now(),
		}
		r.status[source.Name] = Status{Name: source.Name}
		catalogSerial.WithLabelValues(source.Name).Set(0)
		catalogMembers.WithLabelValues(source.Name).Set(0)
		catalogLastSuccessTimestamp.WithLabelValues(source.Name).Set(0)
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
		currentStatus := r.status[catalogName]
		currentStatus.Serial = accepted.Serial
		currentStatus.Members = len(accepted.Members)
		currentStatus.LastSuccess = r.acceptedAt[catalogName]
		r.status[catalogName] = currentStatus
		catalogSerial.WithLabelValues(catalogName).Set(float64(accepted.Serial))
		catalogMembers.WithLabelValues(catalogName).Set(float64(len(accepted.Members)))
		if !currentStatus.LastSuccess.IsZero() {
			catalogLastSuccessTimestamp.WithLabelValues(catalogName).Set(
				float64(currentStatus.LastSuccess.Unix()),
			)
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

	started := r.recordAttempt(name)
	r.emitAudit(AuditEvent{
		Time:    started,
		Kind:    AuditReceipt,
		Catalog: name,
		Outcome: "received",
		Stage:   "receipt",
	})
	parsed, err := Parse(z)
	if err != nil {
		r.recordFailure(name, started, err)
		r.emitAudit(AuditEvent{
			Time:    r.now(),
			Kind:    AuditRejected,
			Catalog: name,
			Outcome: "rejected",
			Stage:   "validation",
			Error:   err.Error(),
		})
		return fmt.Errorf("catalog %s rejected; retaining last valid state: %w", name, err)
	}
	actions, err := r.reconcile(name, parsed, z)
	if err != nil {
		r.recordFailure(name, started, err)
		r.emitAudit(AuditEvent{
			Time:    r.now(),
			Kind:    AuditRejected,
			Catalog: name,
			Serial:  parsed.Serial,
			Members: len(parsed.Members),
			Outcome: "rejected",
			Stage:   "reconciliation",
			Error:   err.Error(),
		})
		return err
	}
	r.recordSuccess(name, started, parsed, actions)
	r.emitAudit(AuditEvent{
		Time:         r.now(),
		Kind:         AuditReconciliation,
		Catalog:      name,
		Serial:       parsed.Serial,
		Members:      len(parsed.Members),
		Outcome:      "committed",
		Stage:        "reconciliation",
		ActionCounts: auditActionCounts(actions),
	})
	return nil
}

// Statuses returns a stable snapshot ordered by configured catalog precedence.
func (r *Runtime) Statuses() []Status {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]Status, 0, len(r.order))
	for _, name := range r.order {
		status := r.status[name]
		status.PendingActionCounts = cloneIntMap(status.PendingActionCounts)
		result = append(result, status)
	}
	return result
}

// CatalogMembers returns a bounded, lexicographically ordered page. cursor is
// the last zone name from the previous page; empty starts at the beginning.
func (r *Runtime) CatalogMembers(
	catalogName string,
	cursor string,
	limit int,
	expectedSerial *uint32,
) ([]MemberStatus, string, int, uint32, error) {
	catalogName = normalizeName(catalogName)
	var err error
	cursor, err = normalizeMemberCursor(cursor)
	if err != nil {
		return nil, "", 0, 0, err
	}
	if limit < 1 || limit > 1000 {
		return nil, "", 0, 0, fmt.Errorf("catalog: page size must be between 1 and 1000")
	}

	for attempt := 0; attempt < 3; attempt++ {
		r.mu.RLock()
		accepted := r.catalogs[catalogName]
		if accepted == nil {
			r.mu.RUnlock()
			return nil, "", 0, 0, fmt.Errorf("%w: %s", ErrCatalogNotFound, catalogName)
		}
		if expectedSerial != nil && accepted.Serial != *expectedSerial {
			r.mu.RUnlock()
			return nil, "", 0, 0, fmt.Errorf(
				"%w: token serial %d, current serial %d",
				ErrCatalogChanged,
				*expectedSerial,
				accepted.Serial,
			)
		}
		total := len(accepted.Members)
		generation := r.generation
		r.mu.RUnlock()

		// Accepted Catalog values are immutable after publication. Scan outside
		// the runtime lock so a very large catalog cannot stall reconciliation.
		names := boundedMemberPage(accepted.Members, cursor, limit)
		owners := make(map[string]string, len(names))
		r.mu.RLock()
		if r.generation != generation {
			r.mu.RUnlock()
			continue
		}
		for _, name := range names {
			if owner, ok := r.ownership[name]; ok {
				owners[name] = owner.Catalog
			}
		}
		r.mu.RUnlock()

		result := make([]MemberStatus, 0, len(names))
		for _, name := range names {
			member := accepted.Members[name]
			cfg, group, err := r.memberConfigWithGroup(catalogName, member)
			if err != nil {
				return nil, "", 0, 0, err
			}
			status := MemberStatus{
				Zone:              member.Zone,
				Label:             member.Label,
				Groups:            memberGroupNames(member),
				ChangeOfOwnership: member.ChangeOfOwnership,
				EffectiveGroup:    group,
				Masters:           append([]string(nil), cfg.Masters...),
			}
			status.OwnerCatalog = owners[name]
			if cfg.TransferKey != nil {
				status.TransferKeyName = cfg.TransferKey.Name
				status.TransferAlgorithm = cfg.TransferKey.Algorithm
			}
			result = append(result, status)
		}
		hasMore := false
		if len(names) > 0 {
			last := names[len(names)-1]
			for name := range accepted.Members {
				if name > last {
					hasMore = true
					break
				}
			}
		}
		nextCursor := ""
		if hasMore {
			nextCursor = names[len(names)-1]
		}
		return result, nextCursor, total, accepted.Serial, nil
	}
	return nil, "", 0, 0, ErrCatalogChanged
}

// ObserveTransfer implements secondary.TransferObserver. Only configured
// catalog-zone transfers are attributed here; member transfers are reflected in
// their enclosing reconciliation outcome.
func (r *Runtime) ObserveTransfer(name string, err error) {
	name = normalizeName(name)
	if _, configured := r.sources[name]; !configured {
		return
	}
	outcome := "success"
	if err != nil {
		outcome = "failure"
		now := r.now()
		r.mu.Lock()
		status := r.status[name]
		status.LastAttempt = now
		status.LastError = "catalog transfer: " + err.Error()
		r.status[name] = status
		r.mu.Unlock()
	}
	catalogTransfersTotal.WithLabelValues(name, outcome).Inc()
	event := AuditEvent{
		Time:    r.now(),
		Kind:    AuditTransfer,
		Catalog: name,
		Outcome: outcome,
		Stage:   "transfer",
	}
	if err != nil {
		event.Error = err.Error()
	}
	r.emitAudit(event)
}

func (r *Runtime) emitAudit(event AuditEvent) {
	if r.auditSink != nil {
		r.auditSink.EmitCatalogAudit(event)
	}
}

func auditActionCounts(actions []Action) map[string]int {
	counts := make(map[string]int)
	for _, action := range actions {
		counts[string(action.Kind)]++
		if action.ResetState {
			counts["state_reset"]++
		}
	}
	return counts
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

func (r *Runtime) reconcile(name string, accepted *Catalog, raw *zone.Zone) ([]Action, error) {
	r.reconcileMu.Lock()
	defer r.reconcileMu.Unlock()
	if r.controller == nil {
		return nil, fmt.Errorf("catalog: secondary controller is not attached")
	}
	if err := r.validateMemberScope(name, accepted); err != nil {
		return nil, err
	}

	r.mu.RLock()
	current := r.catalogs[name]
	previous := cloneCatalogMap(r.catalogs)
	next := cloneCatalogMap(r.catalogs)
	ownership := cloneOwnership(r.ownership)
	r.mu.RUnlock()
	if current != nil && !zone.SerialGreater(accepted.Serial, current.Serial) {
		return nil, fmt.Errorf(
			"catalog %s serial %d does not advance last-valid serial %d",
			name,
			accepted.Serial,
			current.Serial,
		)
	}
	next[name] = accepted
	if err := r.validateCatalogGraph(next); err != nil {
		return nil, err
	}

	actions, err := Plan(previous, next, ownership, r.order, r.reserved)
	if err != nil {
		return nil, fmt.Errorf("catalog %s plan: %w", name, err)
	}
	if len(actions) > r.sources[name].MaxReconcileActions {
		return nil, fmt.Errorf(
			"catalog %s reconciliation has %d actions; max_reconcile_actions is %d",
			name,
			len(actions),
			r.sources[name].MaxReconcileActions,
		)
	}
	destructiveActions := countDestructiveActions(actions)
	source := r.sources[name]
	if source.DryRun {
		r.recordPending(name, accepted.Serial, "dry_run", actions)
		return nil, fmt.Errorf(
			"catalog %s dry-run plan: serial %d has %d actions (%d destructive); retaining last valid state",
			name,
			accepted.Serial,
			len(actions),
			destructiveActions,
		)
	}
	if source.ApprovalRequiredAbove > 0 &&
		destructiveActions > source.ApprovalRequiredAbove &&
		(source.ApprovedSerial == nil || *source.ApprovedSerial != accepted.Serial) {
		r.recordPending(name, accepted.Serial, "approval_required", actions)
		return nil, fmt.Errorf(
			"catalog %s serial %d requires explicit approval: %d destructive actions exceeds approval_required_above %d",
			name,
			accepted.Serial,
			destructiveActions,
			source.ApprovalRequiredAbove,
		)
	}
	actionCount := 0
	for _, action := range actions {
		if action.Kind != ActionConflict {
			actionCount++
		}
	}
	if !r.takeReconcileBudget(name, actionCount) {
		source := r.sources[name]
		return nil, fmt.Errorf(
			"catalog %s reconciliation needs %d action tokens; budget is %d/minute with burst %d",
			name,
			actionCount,
			source.ReconcileActionsPerMinute,
			source.ReconcileActionBurst,
		)
	}
	committed := false
	defer func() {
		if !committed {
			r.refundReconcileBudget(name, actionCount)
		}
	}()

	changes := make([]secondary.BatchChange, 0, len(actions))
	finalOwnership := cloneOwnership(ownership)
	for _, action := range actions {
		if action.Kind == ActionConflict {
			continue
		}
		member, memberExists := memberIn(next[action.Catalog], action.Zone)
		switch action.Kind {
		case ActionAdd, ActionReconfigure, ActionRecreate:
			if !memberExists {
				return nil, fmt.Errorf("catalog: action %s has no member %s", action.Kind, action.Zone)
			}
			cfg, err := r.memberConfig(action.Catalog, member)
			if err != nil {
				return nil, err
			}
			changes = append(changes, secondary.BatchChange{
				Config:     cfg,
				ResetState: action.ResetState,
			})
			finalOwnership[action.Zone] = Ownership{Catalog: action.Catalog, Label: action.Label}
		case ActionTransferOwnership:
			if !memberExists {
				return nil, fmt.Errorf("catalog: ownership transfer has no destination member %s", action.Zone)
			}
			cfg, err := r.memberConfig(action.Catalog, member)
			if err != nil {
				return nil, err
			}
			changes = append(changes, secondary.BatchChange{
				Config:     cfg,
				ResetState: action.ResetState,
			})
			finalOwnership[action.Zone] = Ownership{Catalog: action.Catalog, Label: action.Label}
		case ActionRemove:
			changes = append(changes, secondary.BatchChange{Name: action.Zone, Remove: true})
			delete(finalOwnership, action.Zone)
		default:
			return nil, fmt.Errorf("catalog: unsupported reconciliation action %q", action.Kind)
		}
	}

	err = r.controller.ApplyBatch(
		context.Background(),
		changes,
		func(upserts []*zone.Zone, removals []string) error {
			return r.commitReconciliation(name, raw, next, finalOwnership, upserts, removals)
		},
	)
	if err != nil {
		return nil, fmt.Errorf("catalog %s reconciliation: %w", name, err)
	}
	committed = true
	return actions, nil
}

func countDestructiveActions(actions []Action) int {
	count := 0
	for _, action := range actions {
		switch action.Kind {
		case ActionRemove, ActionRecreate:
			count++
		case ActionTransferOwnership:
			if action.ResetState {
				count++
			}
		}
	}
	return count
}

func (r *Runtime) recordAttempt(name string) time.Time {
	now := r.now()
	r.mu.Lock()
	status := r.status[name]
	status.LastAttempt = now
	r.status[name] = status
	r.mu.Unlock()
	return now
}

func (r *Runtime) recordFailure(name string, started time.Time, err error) {
	r.mu.Lock()
	status := r.status[name]
	status.LastError = err.Error()
	r.status[name] = status
	r.mu.Unlock()
	catalogReconcilesTotal.WithLabelValues(name, "failure").Inc()
	catalogReconcileDuration.WithLabelValues(name, "failure").Observe(r.now().Sub(started).Seconds())
}

func (r *Runtime) recordSuccess(name string, started time.Time, accepted *Catalog, actions []Action) {
	completed := r.now()
	r.mu.Lock()
	status := r.status[name]
	status.Serial = accepted.Serial
	status.Members = len(accepted.Members)
	status.LastSuccess = completed
	status.LastError = ""
	status.PendingSerial = 0
	status.PendingReason = ""
	status.PendingActionCounts = nil
	r.status[name] = status
	r.mu.Unlock()

	catalogReconcilesTotal.WithLabelValues(name, "success").Inc()
	catalogReconcileDuration.WithLabelValues(name, "success").Observe(completed.Sub(started).Seconds())
	catalogSerial.WithLabelValues(name).Set(float64(accepted.Serial))
	catalogMembers.WithLabelValues(name).Set(float64(len(accepted.Members)))
	catalogLastSuccessTimestamp.WithLabelValues(name).Set(float64(completed.Unix()))
	for _, action := range actions {
		catalogReconcileActionsTotal.WithLabelValues(name, string(action.Kind)).Inc()
	}
}

func (r *Runtime) recordPending(name string, serial uint32, reason string, actions []Action) {
	r.mu.Lock()
	status := r.status[name]
	status.PendingSerial = serial
	status.PendingReason = reason
	status.PendingActionCounts = auditActionCounts(actions)
	r.status[name] = status
	r.mu.Unlock()
}

func (r *Runtime) takeReconcileBudget(name string, actions int) bool {
	if actions == 0 {
		return true
	}
	source := r.sources[name]
	budget := r.budgets[name]
	now := r.now()
	elapsedMinutes := now.Sub(budget.lastRefill).Minutes()
	if elapsedMinutes > 0 {
		budget.tokens = min(
			float64(source.ReconcileActionBurst),
			budget.tokens+elapsedMinutes*float64(source.ReconcileActionsPerMinute),
		)
		budget.lastRefill = now
	}
	if budget.tokens < float64(actions) {
		return false
	}
	budget.tokens -= float64(actions)
	return true
}

func (r *Runtime) refundReconcileBudget(name string, actions int) {
	if actions == 0 {
		return
	}
	source := r.sources[name]
	budget := r.budgets[name]
	budget.tokens = min(float64(source.ReconcileActionBurst), budget.tokens+float64(actions))
}

func (r *Runtime) commitReconciliation(
	name string,
	raw *zone.Zone,
	next map[string]*Catalog,
	finalOwnership map[string]Ownership,
	upserts []*zone.Zone,
	removals []string,
) error {
	r.mu.Lock()
	previousCatalogs := r.catalogs
	previousCatalogZones := r.catalogZone
	previousOwnership := r.ownership
	previousMembers := r.memberZone
	previousAcceptedAt := r.acceptedAt
	previousGeneration := r.generation

	nextCatalogZones := cloneZoneMap(previousCatalogZones)
	nextCatalogZones[name] = raw.Clone()
	nextAcceptedAt := cloneTimes(previousAcceptedAt)
	nextAcceptedAt[name] = r.now().UTC()
	nextMembers := cloneZoneMap(previousMembers)
	for _, member := range upserts {
		if member == nil {
			r.mu.Unlock()
			return fmt.Errorf("catalog: batch contains nil member zone")
		}
		nextMembers[normalizeName(member.Origin)] = member.Clone()
	}
	for _, removed := range removals {
		delete(nextMembers, normalizeName(removed))
	}
	for memberName := range finalOwnership {
		if nextMembers[memberName] == nil {
			r.mu.Unlock()
			return fmt.Errorf("catalog: committed owner %s has no member zone data", memberName)
		}
	}

	r.catalogs = next
	r.catalogZone = nextCatalogZones
	r.ownership = cloneOwnership(finalOwnership)
	r.memberZone = nextMembers
	r.acceptedAt = nextAcceptedAt
	r.generation++
	if err := r.persistLocked(); err != nil {
		r.catalogs = previousCatalogs
		r.catalogZone = previousCatalogZones
		r.ownership = previousOwnership
		r.memberZone = previousMembers
		r.acceptedAt = previousAcceptedAt
		r.generation = previousGeneration
		r.mu.Unlock()
		return err
	}
	r.mu.Unlock()

	if err := r.store.ApplyZoneBatch(upserts, removals); err != nil {
		r.mu.Lock()
		r.catalogs = previousCatalogs
		r.catalogZone = previousCatalogZones
		r.ownership = previousOwnership
		r.memberZone = previousMembers
		r.acceptedAt = previousAcceptedAt
		r.generation = previousGeneration
		rollbackErr := r.persistLocked()
		r.mu.Unlock()
		if rollbackErr != nil {
			return errors.Join(err, fmt.Errorf("catalog: roll back persisted state: %w", rollbackErr))
		}
		return err
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
	cfg, _, err := r.memberConfigWithGroup(catalogName, member)
	return cfg, err
}

func (r *Runtime) memberConfigWithGroup(
	catalogName string,
	member Member,
) (secondary.Config, string, error) {
	source, ok := r.sources[normalizeName(catalogName)]
	if !ok {
		return secondary.Config{}, "", fmt.Errorf("catalog: no source configuration for %s", catalogName)
	}
	cfg := source.Defaults
	effectiveGroup := ""
	for _, group := range member.Groups {
		groupName := strings.Join(group.Strings, "")
		if groupCfg, found := source.Groups[groupName]; found {
			cfg = groupCfg
			effectiveGroup = groupName
			break
		}
	}
	cfg.Name = member.Zone
	cfg.RetainOnError = true
	if len(cfg.Masters) == 0 {
		return secondary.Config{}, "", fmt.Errorf(
			"catalog %s member %s has no configured masters",
			catalogName,
			member.Zone,
		)
	}
	return cfg, effectiveGroup, nil
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
			r.acceptedAt[name] = persisted.AcceptedAt
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
		persisted := persistZone(z)
		persisted.AcceptedAt = r.acceptedAt[name]
		state.Catalogs[name] = persisted
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

func cloneTimes(input map[string]time.Time) map[string]time.Time {
	result := make(map[string]time.Time, len(input))
	for name, value := range input {
		result[name] = value
	}
	return result
}

func cloneIntMap(input map[string]int) map[string]int {
	if input == nil {
		return nil
	}
	result := make(map[string]int, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}

func normalizeMemberCursor(cursor string) (string, error) {
	cursor = strings.TrimSpace(strings.ToLower(cursor))
	if cursor == "" {
		return "", nil
	}
	cursor = dns.Fqdn(cursor)
	if _, ok := dns.IsDomainName(cursor); !ok {
		return "", fmt.Errorf("catalog: invalid member page cursor")
	}
	return cursor, nil
}

func boundedMemberPage(members map[string]Member, cursor string, limit int) []string {
	result := make([]string, 0, min(limit, len(members)))
	for name := range members {
		if name <= cursor {
			continue
		}
		index := sort.SearchStrings(result, name)
		if index < len(result) && result[index] == name {
			continue
		}
		if len(result) < limit {
			result = append(result, "")
			copy(result[index+1:], result[index:])
			result[index] = name
			continue
		}
		if index >= limit {
			continue
		}
		copy(result[index+1:], result[index:limit-1])
		result[index] = name
	}
	return result
}

func memberGroupNames(member Member) []string {
	result := make([]string, 0, len(member.Groups))
	for _, group := range member.Groups {
		result = append(result, strings.Join(group.Strings, ""))
	}
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

func cloneZoneMap(source map[string]*zone.Zone) map[string]*zone.Zone {
	result := make(map[string]*zone.Zone, len(source))
	for name, z := range source {
		result[name] = z
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
