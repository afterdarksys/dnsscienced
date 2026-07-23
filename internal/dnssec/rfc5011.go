package dnssec

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	rfc5011AddHoldDown    = 30 * 24 * time.Hour
	rfc5011RemoveHoldDown = 30 * 24 * time.Hour
	rfc5011MinRefresh     = time.Hour
	rfc5011MaxRefresh     = 15 * 24 * time.Hour
	rfc5011MaxRetry       = 24 * time.Hour
	dnskeyRevokeFlag      = uint16(1 << 7)
	dnskeySEPFlag         = uint16(1)
	dnskeyZoneFlag        = uint16(1 << 8)
)

type rfc5011State string

const (
	rfc5011Valid      rfc5011State = "valid"
	rfc5011AddPending rfc5011State = "add-pending"
	rfc5011Missing    rfc5011State = "missing"
	rfc5011Revoked    rfc5011State = "revoked"
	rfc5011Removed    rfc5011State = "removed"
)

type rfc5011KeyState struct {
	ID          string        `json:"id"`
	Key         string        `json:"key"`
	State       rfc5011State  `json:"state"`
	FirstSeen   time.Time     `json:"first_seen,omitempty"`
	StateSince  time.Time     `json:"state_since"`
	HoldDown    time.Duration `json:"hold_down,omitempty"`
	ValidatedBy []string      `json:"validated_by,omitempty"`
}

type rfc5011DiskState struct {
	Version int                `json:"version"`
	Keys    []*rfc5011KeyState `json:"keys"`
}

type rfc5011Manager struct {
	mu               sync.Mutex
	startOnce        sync.Once
	validator        *Validator
	path             string
	keys             map[string]*rfc5011KeyState
	now              func() time.Time
	lastRefreshDelay time.Duration
}

func newRFC5011Manager(validator *Validator, path string) (*rfc5011Manager, error) {
	manager := &rfc5011Manager{
		validator:        validator,
		path:             path,
		keys:             make(map[string]*rfc5011KeyState),
		now:              time.Now,
		lastRefreshDelay: rfc5011MinRefresh,
	}
	if err := manager.loadOrBootstrap(validator.anchorSnapshot()); err != nil {
		return nil, err
	}
	manager.publishAnchors()
	return manager, nil
}

func (m *rfc5011Manager) loadOrBootstrap(bootstrap []dns.DNSKEY) error {
	data, err := os.ReadFile(m.path)
	if err == nil {
		info, statErr := os.Stat(m.path)
		if statErr != nil {
			return statErr
		}
		if info.Mode().Perm()&0o077 != 0 {
			return fmt.Errorf("state file permissions %o are too broad; require 0600 or stricter", info.Mode().Perm())
		}
		var state rfc5011DiskState
		if err := json.Unmarshal(data, &state); err != nil {
			return fmt.Errorf("decode %s: %w", m.path, err)
		}
		if state.Version != 1 {
			return fmt.Errorf("unsupported state version %d", state.Version)
		}
		for _, item := range state.Keys {
			if item == nil || item.ID == "" {
				return fmt.Errorf("state contains an invalid key entry")
			}
			if _, duplicate := m.keys[item.ID]; duplicate {
				return fmt.Errorf("state contains duplicate key %s", item.ID)
			}
			key, err := parseDNSKEY(item.Key)
			if err != nil {
				return fmt.Errorf("state key %s: %w", item.ID, err)
			}
			if rfc5011KeyID(&key) != item.ID {
				return fmt.Errorf("state key %s does not match its DNSKEY identity", item.ID)
			}
			if !validRootSEP(key) {
				return fmt.Errorf("state key %s is not a root SEP DNSKEY", item.ID)
			}
			switch item.State {
			case rfc5011Valid, rfc5011AddPending, rfc5011Missing, rfc5011Revoked, rfc5011Removed:
			default:
				return fmt.Errorf("state key %s has unknown state %q", item.ID, item.State)
			}
			if item.StateSince.IsZero() {
				return fmt.Errorf("state key %s has no state transition timestamp", item.ID)
			}
			if item.State == rfc5011AddPending &&
				(item.FirstSeen.IsZero() || item.HoldDown < rfc5011AddHoldDown || len(item.ValidatedBy) == 0) {
				return fmt.Errorf("pending state key %s has invalid hold-down metadata", item.ID)
			}
			m.keys[item.ID] = item
		}
		return nil
	}
	if !os.IsNotExist(err) {
		return err
	}
	if len(bootstrap) == 0 {
		return fmt.Errorf("cannot bootstrap without a configured trust anchor")
	}
	now := m.now()
	for i := range bootstrap {
		key := bootstrap[i]
		if !validRootSEP(key) {
			return fmt.Errorf("bootstrap key %d is not a root SEP DNSKEY", key.KeyTag())
		}
		id := rfc5011KeyID(&key)
		m.keys[id] = &rfc5011KeyState{
			ID: id, Key: key.String(), State: rfc5011Valid, StateSince: now,
		}
	}
	return m.persist()
}

func (m *rfc5011Manager) start(ctx context.Context, resolver DNSResolver, configuredInterval time.Duration) {
	m.startOnce.Do(func() {
		go func() {
			delay := time.Duration(0)
			timer := time.NewTimer(delay)
			defer timer.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-timer.C:
				}
				next, err := m.refresh(ctx, resolver)
				if err != nil {
					next = rfc5011RetryDelay(next)
				}
				if configuredInterval > 0 && configuredInterval < next {
					next = configuredInterval
				}
				if next < rfc5011MinRefresh {
					next = rfc5011MinRefresh
				}
				timer.Reset(next)
			}
		}()
	})
}

func (m *rfc5011Manager) refresh(ctx context.Context, resolver DNSResolver) (time.Duration, error) {
	message, err := resolver.Query(ctx, ".", dns.TypeDNSKEY)
	if err != nil {
		return m.previousRefreshDelay(), err
	}
	keys, signatures := rootDNSKEYMaterial(message)
	if len(keys) == 0 || len(signatures) == 0 {
		return m.previousRefreshDelay(), fmt.Errorf("root DNSKEY response lacks keys or signatures")
	}
	delay := rfc5011RefreshDelay(keys, signatures, m.now())
	if err := m.process(keys, signatures); err != nil {
		return delay, err
	}
	m.mu.Lock()
	m.lastRefreshDelay = delay
	m.mu.Unlock()
	return delay, nil
}

func (m *rfc5011Manager) previousRefreshDelay() time.Duration {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastRefreshDelay
}

func (m *rfc5011Manager) process(keys []dns.DNSKEY, signatures []dns.RRSIG) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	rrset := dnskeysToRRs(keys)
	trusted := m.usableAnchors()
	validators := make(map[string]struct{})
	for i := range trusted {
		for j := range signatures {
			if signatures[j].KeyTag == trusted[i].KeyTag() &&
				signatures[j].Algorithm == trusted[i].Algorithm &&
				signatures[j].ValidityPeriod(m.now()) &&
				signatures[j].Verify(&trusted[i], rrset) == nil {
				validators[rfc5011KeyID(&trusted[i])] = struct{}{}
			}
		}
	}
	now := m.now()
	present := make(map[string]dns.DNSKEY, len(keys))
	revoked := false
	for i := range keys {
		key := keys[i]
		id := rfc5011KeyID(&key)
		present[id] = key
		if existing := m.keys[id]; existing != nil &&
			(existing.State == rfc5011Valid || existing.State == rfc5011Missing) &&
			key.Flags&dnskeyRevokeFlag != 0 &&
			selfSignedDNSKEY(key, rrset, signatures, now) {
			existing.Key = key.String()
			existing.State = rfc5011Revoked
			existing.StateSince = now
			revoked = true
		}
	}
	// Revocation is immediate. Remove the key from the live validator before
	// any state-file I/O or unrelated add-pending transition can fail.
	if revoked {
		m.publishAnchors()
	}
	if len(validators) == 0 {
		if !revoked {
			return fmt.Errorf("DNSKEY RRset was not authenticated by a current trust anchor")
		}
		if err := m.persist(); err != nil {
			return err
		}
		return nil
	}

	for id, item := range m.keys {
		key, exists := present[id]
		switch item.State {
		case rfc5011AddPending:
			if !exists || key.Flags&dnskeyRevokeFlag != 0 ||
				!anyValidatorRemaining(item.ValidatedBy, m.keys) {
				delete(m.keys, id)
			} else if !now.Before(item.FirstSeen.Add(item.HoldDown)) {
				item.Key = key.String()
				item.State = rfc5011Valid
				item.StateSince = now
				item.ValidatedBy = nil
			}
		case rfc5011Valid:
			if !exists {
				item.State = rfc5011Missing
				item.StateSince = now
			}
		case rfc5011Missing:
			if exists {
				item.Key = key.String()
				item.State = rfc5011Valid
				item.StateSince = now
			}
		case rfc5011Revoked:
			if !exists && !now.Before(item.StateSince.Add(rfc5011RemoveHoldDown)) {
				item.State = rfc5011Removed
				item.StateSince = now
			}
		}
	}

	for id, key := range present {
		if _, known := m.keys[id]; known ||
			!validRootSEP(key) ||
			m.validator.config.DisabledAlgorithms[key.Algorithm] ||
			key.Flags&dnskeyRevokeFlag != 0 {
			continue
		}
		validatedBy := make([]string, 0, len(validators))
		for validatorID := range validators {
			validatedBy = append(validatedBy, validatorID)
		}
		sort.Strings(validatedBy)
		holdDown := rfc5011AddHoldDown
		if ttl := time.Duration(key.Hdr.Ttl) * time.Second; ttl > holdDown {
			holdDown = ttl
		}
		m.keys[id] = &rfc5011KeyState{
			ID: id, Key: key.String(), State: rfc5011AddPending,
			FirstSeen: now, StateSince: now, HoldDown: holdDown, ValidatedBy: validatedBy,
		}
	}
	if err := m.persist(); err != nil {
		return err
	}
	m.publishAnchors()
	return nil
}

func (m *rfc5011Manager) usableAnchors() []dns.DNSKEY {
	anchors := make([]dns.DNSKEY, 0, len(m.keys))
	for _, item := range m.keys {
		if item.State != rfc5011Valid && item.State != rfc5011Missing {
			continue
		}
		key, err := parseDNSKEY(item.Key)
		if err == nil {
			key.Flags &^= dnskeyRevokeFlag
			anchors = append(anchors, key)
		}
	}
	return anchors
}

func (m *rfc5011Manager) publishAnchors() {
	m.validator.replaceTrustAnchors(m.usableAnchors())
}

func (m *rfc5011Manager) persist() error {
	state := rfc5011DiskState{Version: 1, Keys: make([]*rfc5011KeyState, 0, len(m.keys))}
	for _, item := range m.keys {
		copyItem := *item
		copyItem.ValidatedBy = append([]string(nil), item.ValidatedBy...)
		state.Keys = append(state.Keys, &copyItem)
	}
	sort.Slice(state.Keys, func(i, j int) bool { return state.Keys[i].ID < state.Keys[j].ID })
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	dir := filepath.Dir(m.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	temp, err := os.CreateTemp(dir, "."+filepath.Base(m.path)+".tmp-*")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if err := temp.Chmod(0o600); err != nil {
		temp.Close()
		return err
	}
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempName, m.path); err != nil {
		return err
	}
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func rootDNSKEYMaterial(message *dns.Msg) ([]dns.DNSKEY, []dns.RRSIG) {
	var keys []dns.DNSKEY
	var signatures []dns.RRSIG
	for _, rr := range message.Answer {
		switch value := rr.(type) {
		case *dns.DNSKEY:
			if strings.EqualFold(value.Hdr.Name, ".") {
				keys = append(keys, *value)
			}
		case *dns.RRSIG:
			if strings.EqualFold(value.Hdr.Name, ".") && value.TypeCovered == dns.TypeDNSKEY {
				signatures = append(signatures, *value)
			}
		}
	}
	return keys, signatures
}

func validRootSEP(key dns.DNSKEY) bool {
	return strings.EqualFold(dns.Fqdn(key.Hdr.Name), ".") &&
		key.Protocol == 3 &&
		key.Flags&(dnskeySEPFlag|dnskeyZoneFlag) == dnskeySEPFlag|dnskeyZoneFlag
}

func selfSignedDNSKEY(key dns.DNSKEY, rrset []dns.RR, signatures []dns.RRSIG, now time.Time) bool {
	for i := range signatures {
		if signatures[i].KeyTag == key.KeyTag() &&
			signatures[i].Algorithm == key.Algorithm &&
			signatures[i].ValidityPeriod(now) &&
			signatures[i].Verify(&key, rrset) == nil {
			return true
		}
	}
	return false
}

func anyValidatorRemaining(ids []string, states map[string]*rfc5011KeyState) bool {
	for _, id := range ids {
		if item := states[id]; item != nil &&
			(item.State == rfc5011Valid || item.State == rfc5011Missing) {
			return true
		}
	}
	return false
}

func rfc5011KeyID(key *dns.DNSKEY) string {
	flags := key.Flags &^ dnskeyRevokeFlag
	material := fmt.Sprintf("%s|%d|%d|%d|%s",
		strings.ToLower(dns.Fqdn(key.Hdr.Name)), flags, key.Protocol, key.Algorithm, key.PublicKey)
	sum := sha256.Sum256([]byte(material))
	return hex.EncodeToString(sum[:])
}

func parseDNSKEY(text string) (dns.DNSKEY, error) {
	rr, err := dns.NewRR(text)
	if err != nil {
		return dns.DNSKEY{}, err
	}
	key, ok := rr.(*dns.DNSKEY)
	if !ok {
		return dns.DNSKEY{}, fmt.Errorf("record is not DNSKEY")
	}
	return *key, nil
}

func rfc5011RefreshDelay(keys []dns.DNSKEY, signatures []dns.RRSIG, now time.Time) time.Duration {
	delay := rfc5011MaxRefresh
	if len(keys) > 0 {
		ttlDelay := time.Duration(keys[0].Hdr.Ttl) * time.Second / 2
		if ttlDelay < delay {
			delay = ttlDelay
		}
	}
	for i := range signatures {
		expiryDelay := time.Unix(int64(signatures[i].Expiration), 0).Sub(now) / 2
		if expiryDelay < delay {
			delay = expiryDelay
		}
	}
	if delay < rfc5011MinRefresh {
		return rfc5011MinRefresh
	}
	return delay
}

func rfc5011RetryDelay(refreshDelay time.Duration) time.Duration {
	delay := refreshDelay / 5
	if delay > rfc5011MaxRetry {
		delay = rfc5011MaxRetry
	}
	if delay < rfc5011MinRefresh {
		delay = rfc5011MinRefresh
	}
	return delay
}
