package reload

import (
	"fmt"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/dnsscience/dnsscienced/internal/zone"
	"github.com/rs/zerolog/log"
)

// Manager handles graceful configuration reloads
type Manager struct {
	mu sync.RWMutex

	// Atomic zone storage (copy-on-write)
	zones atomic.Value // map[string]*zone.Zone

	// Zone file paths
	zoneFiles map[string]string // zone name -> file path

	// Reload status
	lastReload atomic.Value // time.Time
	reloading  atomic.Bool

	// Signal channel
	signalChan chan os.Signal
}

// NewManager creates a new reload manager
func NewManager() *Manager {
	m := &Manager{
		zoneFiles:  make(map[string]string),
		signalChan: make(chan os.Signal, 1),
	}

	// Initialize with empty zone map
	m.zones.Store(make(map[string]*zone.Zone))
	m.lastReload.Store(time.Now())

	return m
}

// RegisterZone registers a zone file for reloading
func (m *Manager) RegisterZone(name, filePath string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.zoneFiles[name] = filePath
}

// GetZone retrieves a zone (read-only, lock-free)
func (m *Manager) GetZone(name string) (*zone.Zone, bool) {
	zones := m.zones.Load().(map[string]*zone.Zone)
	z, ok := zones[name]
	return z, ok
}

// GetAllZones returns all loaded zones
func (m *Manager) GetAllZones() map[string]*zone.Zone {
	return m.zones.Load().(map[string]*zone.Zone)
}

// SetZone sets a zone atomically
func (m *Manager) SetZone(name string, z *zone.Zone) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Copy-on-write: create new map with updated zone
	oldZones := m.zones.Load().(map[string]*zone.Zone)
	newZones := make(map[string]*zone.Zone, len(oldZones)+1)

	// Copy existing zones
	for k, v := range oldZones {
		newZones[k] = v
	}

	// Add/update new zone
	newZones[name] = z

	// Atomic swap
	m.zones.Store(newZones)
}

// RemoveZone removes a zone atomically
func (m *Manager) RemoveZone(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	oldZones := m.zones.Load().(map[string]*zone.Zone)
	newZones := make(map[string]*zone.Zone, len(oldZones))

	// Copy all except the removed zone
	for k, v := range oldZones {
		if k != name {
			newZones[k] = v
		}
	}

	m.zones.Store(newZones)

	// Also remove from registered files
	delete(m.zoneFiles, name)
}

// Reload reloads all zones from disk
func (m *Manager) Reload() error {
	if !m.reloading.CompareAndSwap(false, true) {
		return fmt.Errorf("reload already in progress")
	}
	defer m.reloading.Store(false)

	log.Info().Msg("Starting graceful zone reload")
	startTime := time.Now()

	m.mu.RLock()
	files := make(map[string]string, len(m.zoneFiles))
	for name, path := range m.zoneFiles {
		files[name] = path
	}
	m.mu.RUnlock()

	// Load all zones into temporary map
	newZones := make(map[string]*zone.Zone, len(files))
	failedZones := make([]string, 0)

	for name, path := range files {
		log.Info().
			Str("zone", name).
			Str("file", path).
			Msg("Reloading zone")

		// Try to load zone
		z, err := zone.ParseZoneFile(path, zone.DefaultConfig())
		if err != nil {
			log.Error().
				Err(err).
				Str("zone", name).
				Str("file", path).
				Msg("Failed to reload zone")
			failedZones = append(failedZones, name)

			// Keep old zone if reload fails
			if oldZone, ok := m.GetZone(name); ok {
				newZones[name] = oldZone
			}
			continue
		}

		// Validate zone
		if err := z.Validate(); err != nil {
			log.Error().
				Err(err).
				Str("zone", name).
				Msg("Zone validation failed")
			failedZones = append(failedZones, name)

			// Keep old zone if validation fails
			if oldZone, ok := m.GetZone(name); ok {
				newZones[name] = oldZone
			}
			continue
		}

		newZones[name] = z
		log.Info().
			Str("zone", name).
			Int("records", z.GetStats().Records).
			Msg("Zone reloaded successfully")
	}

	// Atomic swap to new zones
	m.zones.Store(newZones)
	m.lastReload.Store(time.Now())

	duration := time.Since(startTime)
	if len(failedZones) > 0 {
		log.Warn().
			Strs("failed_zones", failedZones).
			Dur("duration", duration).
			Msg("Zone reload completed with errors")
		return fmt.Errorf("failed to reload %d zone(s): %v", len(failedZones), failedZones)
	}

	log.Info().
		Int("zones", len(newZones)).
		Dur("duration", duration).
		Msg("Zone reload completed successfully")

	return nil
}

// StartSignalHandler starts listening for SIGHUP signals
func (m *Manager) StartSignalHandler() {
	signal.Notify(m.signalChan, syscall.SIGHUP)

	go func() {
		for range m.signalChan {
			log.Info().Msg("Received SIGHUP, reloading zones")

			if err := m.Reload(); err != nil {
				log.Error().
					Err(err).
					Msg("Zone reload failed")
			}
		}
	}()

	log.Info().Msg("Signal handler started (SIGHUP for reload)")
}

// Stop stops the signal handler
func (m *Manager) Stop() {
	signal.Stop(m.signalChan)
	close(m.signalChan)
}

// GetLastReload returns the time of the last successful reload
func (m *Manager) GetLastReload() time.Time {
	return m.lastReload.Load().(time.Time)
}

// IsReloading returns true if a reload is in progress
func (m *Manager) IsReloading() bool {
	return m.reloading.Load()
}

// ZoneCount returns the number of loaded zones
func (m *Manager) ZoneCount() int {
	zones := m.zones.Load().(map[string]*zone.Zone)
	return len(zones)
}
