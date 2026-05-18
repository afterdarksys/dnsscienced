package roothints

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	// Official IANA root hints URL
	RootHintsURL = "https://www.internic.net/domain/named.root"

	// Backup URLs in case primary fails
	BackupURL1 = "https://www.iana.org/domains/root/files/named.root"
	BackupURL2 = "ftp://rs.internic.net/domain/named.root"

	// Update interval
	DefaultUpdateInterval = 7 * 24 * time.Hour // Weekly
)

// Config holds root hints updater configuration
type Config struct {
	Enabled        bool          `yaml:"enabled"`
	UpdateInterval time.Duration `yaml:"update_interval"`
	HintsPath      string        `yaml:"hints_path"`
	AutoUpdate     bool          `yaml:"auto_update"`      // Automatically update on schedule
	ValidateUpdate bool          `yaml:"validate_update"`  // Validate before applying
	BackupOld      bool          `yaml:"backup_old"`       // Keep backup of old hints
}

// DefaultConfig returns default root hints updater configuration
func DefaultConfig() Config {
	return Config{
		Enabled:        true,
		UpdateInterval: DefaultUpdateInterval,
		HintsPath:      "/etc/dnsscienced/root.hints",
		AutoUpdate:     true,
		ValidateUpdate: true,
		BackupOld:      true,
	}
}

// Updater manages automatic root hints updates
type Updater struct {
	mu     sync.RWMutex
	config Config

	lastUpdate time.Time
	lastHash   string

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Callbacks
	onUpdate func(oldHash, newHash string)
}

// NewUpdater creates a new root hints updater
func NewUpdater(cfg Config) *Updater {
	ctx, cancel := context.WithCancel(context.Background())

	u := &Updater{
		config: cfg,
		ctx:    ctx,
		cancel: cancel,
	}

	// Load current hints hash
	if _, err := os.Stat(cfg.HintsPath); err == nil {
		hash, _ := u.calculateFileHash(cfg.HintsPath)
		u.lastHash = hash
	}

	return u
}

// Start starts the automatic update loop
func (u *Updater) Start() error {
	if !u.config.Enabled {
		return nil
	}

	// Perform initial update if hints file doesn't exist
	if _, err := os.Stat(u.config.HintsPath); os.IsNotExist(err) {
		if err := u.Update(); err != nil {
			fmt.Printf("[ROOTHINTS] Initial update failed: %v\n", err)
		}
	}

	if u.config.AutoUpdate {
		u.wg.Add(1)
		go u.updateLoop()
	}

	return nil
}

// Stop stops the updater
func (u *Updater) Stop() {
	u.cancel()
	u.wg.Wait()
}

// updateLoop runs periodic updates
func (u *Updater) updateLoop() {
	defer u.wg.Done()

	ticker := time.NewTicker(u.config.UpdateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := u.Update(); err != nil {
				fmt.Printf("[ROOTHINTS] Periodic update failed: %v\n", err)
			}
		case <-u.ctx.Done():
			return
		}
	}
}

// Update fetches and installs the latest root hints
func (u *Updater) Update() error {
	u.mu.Lock()
	defer u.mu.Unlock()

	fmt.Printf("[ROOTHINTS] Checking for root hints updates...\n")

	// Download latest hints
	content, err := u.downloadHints()
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}

	// Calculate hash
	newHash := fmt.Sprintf("%x", sha256.Sum256(content))

	// Check if update is needed
	if newHash == u.lastHash {
		fmt.Printf("[ROOTHINTS] Root hints are up to date (hash: %s)\n", newHash[:8])
		return nil
	}

	// Validate hints if enabled
	if u.config.ValidateUpdate {
		if err := u.validateHints(content); err != nil {
			return fmt.Errorf("validation failed: %w", err)
		}
	}

	// Backup old hints if enabled
	if u.config.BackupOld {
		if err := u.backupCurrentHints(); err != nil {
			fmt.Printf("[ROOTHINTS] Warning: backup failed: %v\n", err)
		}
	}

	// Write new hints
	if err := u.writeHints(content); err != nil {
		return fmt.Errorf("write failed: %w", err)
	}

	oldHash := u.lastHash
	u.lastHash = newHash
	u.lastUpdate = time.Now()

	fmt.Printf("[ROOTHINTS] Root hints updated successfully\n")
	fmt.Printf("[ROOTHINTS] Old hash: %s\n", truncateHash(oldHash, 8))
	fmt.Printf("[ROOTHINTS] New hash: %s\n", truncateHash(newHash, 8))

	// Trigger callback
	if u.onUpdate != nil {
		u.onUpdate(oldHash, newHash)
	}

	return nil
}

// downloadHints downloads root hints from official sources
func (u *Updater) downloadHints() ([]byte, error) {
	urls := []string{RootHintsURL, BackupURL1}

	var lastErr error

	for _, url := range urls {
		ctx, cancel := context.WithTimeout(u.ctx, 30*time.Second)
		defer cancel()

		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			lastErr = err
			continue
		}

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
			continue
		}

		content, err := io.ReadAll(resp.Body)
		if err != nil {
			lastErr = err
			continue
		}

		// Success!
		return content, nil
	}

	return nil, fmt.Errorf("all download attempts failed, last error: %w", lastErr)
}

// validateHints performs basic validation on root hints content
func (u *Updater) validateHints(content []byte) error {
	// Basic validation: must contain root server names
	requiredStrings := []string{
		"A.ROOT-SERVERS.NET",
		"B.ROOT-SERVERS.NET",
		"M.ROOT-SERVERS.NET",
	}

	contentStr := string(content)
	for _, required := range requiredStrings {
		if len(contentStr) == 0 || !contains(contentStr, required) {
			return fmt.Errorf("validation failed: missing expected content (%s)", required)
		}
	}

	// Size check: root hints should be reasonable size (2KB - 100KB)
	if len(content) < 2048 {
		return fmt.Errorf("validation failed: content too small (%d bytes)", len(content))
	}
	if len(content) > 102400 {
		return fmt.Errorf("validation failed: content too large (%d bytes)", len(content))
	}

	return nil
}

// backupCurrentHints creates a backup of the current hints file
func (u *Updater) backupCurrentHints() error {
	if _, err := os.Stat(u.config.HintsPath); os.IsNotExist(err) {
		return nil // No existing file to backup
	}

	backupPath := u.config.HintsPath + "." + time.Now().Format("20060102-150405") + ".bak"

	content, err := os.ReadFile(u.config.HintsPath)
	if err != nil {
		return err
	}

	return os.WriteFile(backupPath, content, 0644)
}

// writeHints writes new hints to disk atomically
func (u *Updater) writeHints(content []byte) error {
	// Ensure directory exists
	dir := filepath.Dir(u.config.HintsPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// Write to temporary file
	tmpPath := u.config.HintsPath + ".tmp"
	if err := os.WriteFile(tmpPath, content, 0644); err != nil {
		return err
	}

	// Atomic rename
	return os.Rename(tmpPath, u.config.HintsPath)
}

// calculateFileHash calculates SHA256 hash of a file
func (u *Updater) calculateFileHash(path string) (string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}

	hash := sha256.Sum256(content)
	return fmt.Sprintf("%x", hash), nil
}

// OnUpdate registers a callback for when hints are updated
func (u *Updater) OnUpdate(fn func(oldHash, newHash string)) {
	u.onUpdate = fn
}

// GetLastUpdate returns the time of the last successful update
func (u *Updater) GetLastUpdate() time.Time {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return u.lastUpdate
}

// GetCurrentHash returns the hash of the current hints file
func (u *Updater) GetCurrentHash() string {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return u.lastHash
}

// ForceUpdate forces an immediate update check
func (u *Updater) ForceUpdate() error {
	return u.Update()
}

func contains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && len(s) >= len(substr) &&
		(s == substr || (len(s) > len(substr) && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// truncateHash returns the first n characters of a hash string, or the full
// string if it is shorter than n. This prevents slice-bounds panics when the
// hash is empty (e.g. on the very first update when no prior hints file exists).
func truncateHash(h string, n int) string {
	if len(h) <= n {
		return h
	}
	return h[:n]
}
