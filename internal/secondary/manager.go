package secondary

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/dnsscience/dnsscienced/internal/zone"
	"github.com/miekg/dns"
)

var (
	ErrUnknownZone        = errors.New("unknown secondary zone")
	ErrUnauthorizedSource = errors.New("notify source is not a configured master")
	ErrUnauthorizedTSIG   = errors.New("notify TSIG does not match transfer key")
)

// TransferKey authenticates inbound NOTIFY and outbound zone transfers.
type TransferKey struct {
	Name      string
	Algorithm string
	Secret    string
}

// Config defines one secondary zone.
type Config struct {
	Name                  string
	Masters               []string
	TransferSource        string
	TransferKey           *TransferKey
	AllowUnsignedTransfer bool
	// RetainOnError permits startup with an already-published zone when its
	// masters are temporarily unavailable. It is intended for persisted
	// catalog-managed state; ordinary secondaries remain fail-fast by default.
	RetainOnError     bool
	RefreshInterval   time.Duration
	MinRefreshTime    time.Duration
	MaxRefreshTime    time.Duration
	MinRetryTime      time.Duration
	MaxRetryTime      time.Duration
	AllowAXFRFallback bool
	// MaxTransferRecords and MaxTransferBytes bound AXFR/IXFR material before
	// it is copied into memory. Zero selects the secure operational defaults.
	MaxTransferRecords int
	MaxTransferBytes   int64
}

// ZoneStore atomically publishes a fully validated zone.
type ZoneStore interface {
	AddZone(*zone.Zone) error
	GetZone(string) *zone.Zone
}

// Fetcher obtains a complete, validated replacement zone.
type Fetcher interface {
	Fetch(context.Context, Config, *zone.Zone) (*zone.Zone, error)
}

type managedZone struct {
	cfg              Config
	allowedMasterIPs []net.IP
	trigger          chan struct{}
	ctx              context.Context
	cancel           context.CancelFunc
	opMu             sync.Mutex
}

// Manager schedules initial, timer-driven, and NOTIFY-driven secondary refresh.
// Each zone has one goroutine, which serializes transfers for that zone.
type Manager struct {
	store   ZoneStore
	fetcher Fetcher

	mutationMu sync.Mutex
	mu         sync.RWMutex
	zones      map[string]*managedZone
	order      []string
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	started    bool
}

func NewManager(store ZoneStore, fetcher Fetcher, configs []Config) (*Manager, error) {
	if store == nil {
		return nil, fmt.Errorf("secondary: zone store is required")
	}
	if fetcher == nil {
		fetcher = TransferFetcher{Timeout: 10 * time.Second}
	}

	m := &Manager{
		store:   store,
		fetcher: fetcher,
		zones:   make(map[string]*managedZone, len(configs)),
	}
	for _, cfg := range configs {
		managed, err := prepareManagedZone(cfg)
		if err != nil {
			return nil, err
		}
		cfg = managed.cfg
		if _, exists := m.zones[cfg.Name]; exists {
			return nil, fmt.Errorf("secondary: duplicate zone %s", cfg.Name)
		}
		m.zones[cfg.Name] = managed
		m.order = append(m.order, cfg.Name)
	}
	return m, nil
}

// Start performs an initial transfer for every configured zone before starting
// background refresh loops. A daemon never advertises an empty secondary zone.
func (m *Manager) Start(parent context.Context) error {
	m.mu.Lock()
	if m.started {
		m.mu.Unlock()
		return fmt.Errorf("secondary: manager already started")
	}
	m.ctx, m.cancel = context.WithCancel(parent)
	m.started = true
	zones := make([]*managedZone, 0, len(m.order))
	for _, name := range m.order {
		if managed := m.zones[name]; managed != nil {
			zones = append(zones, managed)
		}
	}
	m.mu.Unlock()

	for _, managed := range zones {
		managed.ctx, managed.cancel = context.WithCancel(m.ctx)
		if err := m.refresh(managed.ctx, managed); err != nil &&
			(!managed.cfg.RetainOnError || m.store.GetZone(managed.cfg.Name) == nil) {
			m.cancel()
			return err
		}
	}
	for _, managed := range zones {
		m.wg.Add(1)
		go m.runZone(managed)
	}
	return nil
}

func (m *Manager) Close() {
	m.mu.RLock()
	cancel := m.cancel
	m.mu.RUnlock()
	if cancel != nil {
		cancel()
	}
	m.wg.Wait()
}

// Upsert validates and pre-fetches a replacement before changing the active
// worker. resetState forces a full logical restart by withholding the current
// zone from the fetcher (RFC 9432 member-label changes require this).
func (m *Manager) Upsert(ctx context.Context, cfg Config, resetState bool) error {
	m.mutationMu.Lock()
	defer m.mutationMu.Unlock()

	candidate, err := prepareManagedZone(cfg)
	if err != nil {
		return err
	}

	m.mu.RLock()
	currentManaged := m.zones[candidate.cfg.Name]
	started := m.started
	managerCtx := m.ctx
	m.mu.RUnlock()

	if !started {
		m.mu.Lock()
		if !m.started {
			if _, exists := m.zones[candidate.cfg.Name]; !exists {
				m.order = append(m.order, candidate.cfg.Name)
			}
			m.zones[candidate.cfg.Name] = candidate
			m.mu.Unlock()
			return nil
		}
		currentManaged = m.zones[candidate.cfg.Name]
		managerCtx = m.ctx
		m.mu.Unlock()
	}

	if currentManaged != nil {
		currentManaged.opMu.Lock()
		defer currentManaged.opMu.Unlock()
	}
	current := m.store.GetZone(candidate.cfg.Name)
	if resetState {
		current = nil
	}
	replacement, err := m.fetcher.Fetch(ctx, candidate.cfg, current)
	if err != nil {
		if !(candidate.cfg.RetainOnError && current != nil) {
			return fmt.Errorf("secondary %s: transfer failed: %w", candidate.cfg.Name, err)
		}
	} else if err := m.publish(candidate.cfg, replacement, resetState); err != nil {
		return err
	}

	candidate.ctx, candidate.cancel = context.WithCancel(managerCtx)
	m.mu.Lock()
	previous := m.zones[candidate.cfg.Name]
	if previous == nil {
		m.order = append(m.order, candidate.cfg.Name)
	}
	m.zones[candidate.cfg.Name] = candidate
	m.wg.Add(1)
	m.mu.Unlock()
	if previous != nil && previous.cancel != nil {
		previous.cancel()
	}
	m.runZoneAsync(candidate)
	return nil
}

// Remove stops refreshes for a zone. The published zone is intentionally left
// untouched so callers can order worker removal and authoritative withdrawal
// transactionally.
func (m *Manager) Remove(name string) bool {
	m.mutationMu.Lock()
	defer m.mutationMu.Unlock()

	name = strings.ToLower(dns.Fqdn(strings.TrimSpace(name)))
	m.mu.Lock()
	managed, ok := m.zones[name]
	if ok {
		delete(m.zones, name)
		for i, orderedName := range m.order {
			if orderedName == name {
				m.order = append(m.order[:i], m.order[i+1:]...)
				break
			}
		}
	}
	m.mu.Unlock()
	if ok && managed.cancel != nil {
		managed.cancel()
	}
	if ok {
		// Wait for any in-flight transfer to finish before the caller withdraws
		// the published zone, preventing a late refresh from resurrecting it.
		managed.opMu.Lock()
		managed.opMu.Unlock()
	}
	return ok
}

// HandleNotify validates the source and key, then coalesces a refresh trigger.
func (m *Manager) HandleNotify(ctx context.Context, zoneName string, sourceIP net.IP, tsigName string) error {
	name := strings.ToLower(dns.Fqdn(zoneName))
	m.mu.RLock()
	managed, ok := m.zones[name]
	m.mu.RUnlock()
	if !ok {
		return ErrUnknownZone
	}
	if !masterAllows(managed.allowedMasterIPs, sourceIP) {
		return ErrUnauthorizedSource
	}
	if managed.cfg.TransferKey != nil {
		keyName := strings.ToLower(dns.Fqdn(tsigName))
		if tsigName == "" || keyName != managed.cfg.TransferKey.Name {
			return ErrUnauthorizedTSIG
		}
	} else if !managed.cfg.AllowUnsignedTransfer {
		// NewManager rejects this state, but retain the fail-closed guard in the
		// request path so a future alternate constructor cannot weaken NOTIFY.
		return ErrUnauthorizedTSIG
	}

	select {
	case managed.trigger <- struct{}{}:
	default:
		// A refresh is already pending; RFC 1996 permits NOTIFY coalescing.
	}
	return nil
}

func (m *Manager) runZone(managed *managedZone) {
	defer m.wg.Done()
	delay := refreshDelay(managed.cfg, m.store.GetZone(managed.cfg.Name), false)
	timer := time.NewTimer(delay)
	defer timer.Stop()

	for {
		select {
		case <-managed.ctx.Done():
			return
		case <-managed.trigger:
		case <-timer.C:
		}

		err := m.refresh(managed.ctx, managed)
		delay = refreshDelay(managed.cfg, m.store.GetZone(managed.cfg.Name), err != nil)
		timer.Reset(delay)
	}
}

func (m *Manager) runZoneAsync(managed *managedZone) {
	go m.runZone(managed)
}

func (m *Manager) refresh(ctx context.Context, managed *managedZone) error {
	managed.opMu.Lock()
	defer managed.opMu.Unlock()
	current := m.store.GetZone(managed.cfg.Name)
	replacement, err := m.fetcher.Fetch(ctx, managed.cfg, current)
	if err != nil {
		return fmt.Errorf("secondary %s: transfer failed: %w", managed.cfg.Name, err)
	}
	return m.publish(managed.cfg, replacement, false)
}

func (m *Manager) publish(cfg Config, replacement *zone.Zone, force bool) error {
	if replacement == nil || replacement.SOA == nil {
		return fmt.Errorf("secondary %s: transfer returned no SOA", cfg.Name)
	}
	if replacement.Origin != cfg.Name {
		return fmt.Errorf("secondary %s: transfer returned origin %s", cfg.Name, replacement.Origin)
	}
	current := m.store.GetZone(cfg.Name)
	if !force && current != nil && current.SOA != nil &&
		!zone.SerialGreater(replacement.SOA.Serial, current.SOA.Serial) {
		return nil
	}
	if err := m.store.AddZone(replacement); err != nil {
		return fmt.Errorf("secondary %s: publish: %w", cfg.Name, err)
	}
	return nil
}

func prepareManagedZone(cfg Config) (*managedZone, error) {
	cfg.Name = strings.ToLower(dns.Fqdn(strings.TrimSpace(cfg.Name)))
	if cfg.Name == "." {
		return nil, fmt.Errorf("secondary: zone name is required")
	}
	if len(cfg.Masters) == 0 {
		return nil, fmt.Errorf("secondary %s: at least one master is required", cfg.Name)
	}
	cfg.Masters = append([]string(nil), cfg.Masters...)
	var allowedMasterIPs []net.IP
	for i, master := range cfg.Masters {
		cfg.Masters[i] = withDNSPort(master)
		host, _, err := net.SplitHostPort(cfg.Masters[i])
		if err != nil {
			return nil, fmt.Errorf("secondary %s: invalid master %q: %w", cfg.Name, master, err)
		}
		if ip := net.ParseIP(host); ip != nil {
			allowedMasterIPs = append(allowedMasterIPs, ip)
		} else {
			ips, err := net.LookupIP(host)
			if err != nil {
				return nil, fmt.Errorf("secondary %s: resolve master %q: %w", cfg.Name, host, err)
			}
			allowedMasterIPs = append(allowedMasterIPs, ips...)
		}
	}
	if cfg.TransferKey != nil {
		key := *cfg.TransferKey
		key.Name = strings.ToLower(dns.Fqdn(key.Name))
		key.Algorithm = strings.ToLower(dns.Fqdn(key.Algorithm))
		if key.Name == "." || key.Secret == "" {
			return nil, fmt.Errorf("secondary %s: transfer key name and secret are required", cfg.Name)
		}
		cfg.TransferKey = &key
	} else if !cfg.AllowUnsignedTransfer {
		return nil, fmt.Errorf(
			"secondary %s: transfer key is required; set allow_unsigned_transfer only for an explicitly accepted legacy trust boundary",
			cfg.Name,
		)
	}
	if _, err := newTransferAccumulator(cfg); err != nil {
		return nil, fmt.Errorf("secondary %s: %w", cfg.Name, err)
	}
	return &managedZone{
		cfg:              cfg,
		allowedMasterIPs: allowedMasterIPs,
		trigger:          make(chan struct{}, 1),
	}, nil
}

func refreshDelay(cfg Config, current *zone.Zone, retry bool) time.Duration {
	var delay time.Duration
	if cfg.RefreshInterval > 0 {
		delay = cfg.RefreshInterval
	} else if current != nil && current.SOA != nil {
		seconds := current.SOA.Refresh
		if retry {
			seconds = current.SOA.Retry
		}
		delay = time.Duration(seconds) * time.Second
	}
	if delay <= 0 {
		if retry {
			delay = time.Minute
		} else {
			delay = time.Hour
		}
	}
	minimum, maximum := cfg.MinRefreshTime, cfg.MaxRefreshTime
	if retry {
		minimum, maximum = cfg.MinRetryTime, cfg.MaxRetryTime
	}
	if minimum > 0 && delay < minimum {
		delay = minimum
	}
	if maximum > 0 && delay > maximum {
		delay = maximum
	}
	return delay
}

func masterAllows(masters []net.IP, source net.IP) bool {
	if source == nil {
		return false
	}
	for _, master := range masters {
		if master.Equal(source) {
			return true
		}
	}
	return false
}

func withDNSPort(address string) string {
	address = strings.TrimSpace(address)
	if _, _, err := net.SplitHostPort(address); err == nil {
		return address
	}
	return net.JoinHostPort(strings.Trim(address, "[]"), "53")
}
