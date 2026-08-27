package engine

import (
	"context"
	"fmt"
	"sync"

	"github.com/afterdarksys/dnsscienced/api/grpc/ports"
)

// ZoneManager implements ports.ZoneManager using in-memory storage.
type ZoneManager struct {
	mu    sync.RWMutex
	zones map[string]*ports.ZoneInfo
	recs  map[string][]ports.ResourceRecord
}

// NewZoneManager creates a new empty ZoneManager.
func NewZoneManager() *ZoneManager {
	return &ZoneManager{
		zones: make(map[string]*ports.ZoneInfo),
		recs:  make(map[string][]ports.ResourceRecord),
	}
}

// AddZone is a helper to populate the manager with test data.
func (zm *ZoneManager) AddZone(z ports.ZoneInfo, records []ports.ResourceRecord) {
	zm.mu.Lock()
	defer zm.mu.Unlock()
	zm.zones[z.Name] = &z
	zm.recs[z.Name] = records
}

func (zm *ZoneManager) ListZones(ctx context.Context, zoneType string, pattern string) ([]ports.ZoneInfo, error) {
	zm.mu.RLock()
	defer zm.mu.RUnlock()
	var out []ports.ZoneInfo
	for _, z := range zm.zones {
		// Filter logic could go here
		out = append(out, *z)
	}
	return out, nil
}

func (zm *ZoneManager) GetZone(ctx context.Context, name string, includeRecords bool, recordType string) (*ports.ZoneInfo, []ports.ResourceRecord, error) {
	zm.mu.RLock()
	defer zm.mu.RUnlock()

	z, ok := zm.zones[name]
	if !ok {
		return nil, nil, fmt.Errorf("zone not found: %s", name)
	}

	var records []ports.ResourceRecord
	if includeRecords {
		if rs, ok := zm.recs[name]; ok {
			records = rs
			// Filter by recordType if needed
		}
	}
	return z, records, nil
}

func (zm *ZoneManager) ReloadZone(ctx context.Context, name string, verifyOnly bool) (*ports.ReloadOutcome, error) {
	return &ports.ReloadOutcome{
		Zone:    name,
		Success: true,
		Message: "Reloaded (mock-engine)",
	}, nil
}

func (zm *ZoneManager) Notify(ctx context.Context, name string, servers []string) (*ports.NotifyOutcome, error) {
	return &ports.NotifyOutcome{Zone: name, Serial: 0}, nil
}

func (zm *ZoneManager) Transfer(ctx context.Context, name string, typ string, server string) (*ports.TransferOutcome, error) {
	return &ports.TransferOutcome{Zone: name, Success: false, Error: "not implemented"}, nil
}

func (zm *ZoneManager) UpdateRecords(ctx context.Context, name string, updates []ports.RecordUpdate, incrementSerial bool) (*ports.UpdateOutcome, error) {
	return &ports.UpdateOutcome{Zone: name, Failed: 1}, fmt.Errorf("read-only engine")
}

func (zm *ZoneManager) GetRecords(ctx context.Context, name string, host string, rtype string) ([]ports.ResourceRecord, error) {
	zm.mu.RLock()
	defer zm.mu.RUnlock()

	if _, ok := zm.zones[name]; !ok {
		return nil, fmt.Errorf("zone not found")
	}

	rs := zm.recs[name]
	var out []ports.ResourceRecord
	for _, r := range rs {
		if (host == "" || r.Name == host) && (rtype == "" || r.Type == rtype) {
			out = append(out, r)
		}
	}
	return out, nil
}
