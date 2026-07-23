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
	Name              string
	Masters           []string
	TransferSource    string
	TransferKey       *TransferKey
	RefreshInterval   time.Duration
	MinRefreshTime    time.Duration
	MaxRefreshTime    time.Duration
	MinRetryTime      time.Duration
	MaxRetryTime      time.Duration
	AllowAXFRFallback bool
}

// ZoneStore atomically publishes a fully validated zone.
type ZoneStore interface {
	AddZone(*zone.Zone) error
	GetZone(string) *zone.Zone
}

// Fetcher obtains a complete, validated replacement zone.
type Fetcher interface {
	Fetch(context.Context, Config, uint32) (*zone.Zone, error)
}

type managedZone struct {
	cfg              Config
	allowedMasterIPs []net.IP
	trigger          chan struct{}
}

// Manager schedules initial, timer-driven, and NOTIFY-driven secondary refresh.
// Each zone has one goroutine, which serializes transfers for that zone.
type Manager struct {
	store   ZoneStore
	fetcher Fetcher

	mu      sync.RWMutex
	zones   map[string]*managedZone
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	started bool
}

func NewManager(store ZoneStore, fetcher Fetcher, configs []Config) (*Manager, error) {
	if store == nil {
		return nil, fmt.Errorf("secondary: zone store is required")
	}
	if fetcher == nil {
		fetcher = AXFRFetcher{Timeout: 10 * time.Second}
	}

	m := &Manager{
		store:   store,
		fetcher: fetcher,
		zones:   make(map[string]*managedZone, len(configs)),
	}
	for _, cfg := range configs {
		cfg.Name = strings.ToLower(dns.Fqdn(strings.TrimSpace(cfg.Name)))
		if cfg.Name == "." {
			return nil, fmt.Errorf("secondary: zone name is required")
		}
		if len(cfg.Masters) == 0 {
			return nil, fmt.Errorf("secondary %s: at least one master is required", cfg.Name)
		}
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
			cfg.TransferKey.Name = strings.ToLower(dns.Fqdn(cfg.TransferKey.Name))
			cfg.TransferKey.Algorithm = strings.ToLower(dns.Fqdn(cfg.TransferKey.Algorithm))
			if cfg.TransferKey.Name == "." || cfg.TransferKey.Secret == "" {
				return nil, fmt.Errorf("secondary %s: transfer key name and secret are required", cfg.Name)
			}
		}
		if _, exists := m.zones[cfg.Name]; exists {
			return nil, fmt.Errorf("secondary: duplicate zone %s", cfg.Name)
		}
		m.zones[cfg.Name] = &managedZone{
			cfg:              cfg,
			allowedMasterIPs: allowedMasterIPs,
			trigger:          make(chan struct{}, 1),
		}
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
	zones := make([]*managedZone, 0, len(m.zones))
	for _, managed := range m.zones {
		zones = append(zones, managed)
	}
	m.mu.Unlock()

	for _, managed := range zones {
		if err := m.refresh(m.ctx, managed); err != nil {
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
		case <-m.ctx.Done():
			return
		case <-managed.trigger:
		case <-timer.C:
		}

		err := m.refresh(m.ctx, managed)
		delay = refreshDelay(managed.cfg, m.store.GetZone(managed.cfg.Name), err != nil)
		timer.Reset(delay)
	}
}

func (m *Manager) refresh(ctx context.Context, managed *managedZone) error {
	var serial uint32
	if current := m.store.GetZone(managed.cfg.Name); current != nil && current.SOA != nil {
		serial = current.SOA.Serial
	}
	replacement, err := m.fetcher.Fetch(ctx, managed.cfg, serial)
	if err != nil {
		return fmt.Errorf("secondary %s: transfer failed: %w", managed.cfg.Name, err)
	}
	if replacement == nil || replacement.SOA == nil {
		return fmt.Errorf("secondary %s: transfer returned no SOA", managed.cfg.Name)
	}
	if replacement.Origin != managed.cfg.Name {
		return fmt.Errorf("secondary %s: transfer returned origin %s", managed.cfg.Name, replacement.Origin)
	}
	if serial != 0 && !serialGreater(replacement.SOA.Serial, serial) {
		return nil
	}
	if err := m.store.AddZone(replacement); err != nil {
		return fmt.Errorf("secondary %s: publish: %w", managed.cfg.Name, err)
	}
	return nil
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

func serialGreater(next, current uint32) bool {
	return next != current && uint32(next-current) < 1<<31
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
