package rrl

import (
	"net"
	"sync"
	"testing"
)

func TestGetConfig_ReturnsCopy(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ResponsesPerSecond = 42
	l := NewLimiter(cfg)
	defer l.Close()

	got := l.GetConfig()
	if got.ResponsesPerSecond != 42 {
		t.Errorf("GetConfig().ResponsesPerSecond = %d, want 42", got.ResponsesPerSecond)
	}
	// Mutating returned copy must not affect limiter
	got.ResponsesPerSecond = 99
	if l.GetConfig().ResponsesPerSecond != 42 {
		t.Error("mutating returned Config copy should not change Limiter cfg")
	}
}

func TestUpdateConfig_NewLimitsApplied(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = false // start disabled
	l := NewLimiter(cfg)
	defer l.Close()

	newCfg := DefaultConfig()
	newCfg.ResponsesPerSecond = 1
	newCfg.Enabled = true
	l.UpdateConfig(newCfg)

	got := l.GetConfig()
	if !got.Enabled {
		t.Error("expected Enabled=true after UpdateConfig")
	}
	if got.ResponsesPerSecond != 1 {
		t.Errorf("ResponsesPerSecond = %d, want 1", got.ResponsesPerSecond)
	}
}

func TestCheck_UsesCfgMuSnapshot(t *testing.T) {
	// Race-detector test: concurrent Check + UpdateConfig must not race.
	cfg := DefaultConfig()
	cfg.ResponsesPerSecond = 100
	l := NewLimiter(cfg)
	defer l.Close()

	clientIP := net.ParseIP("192.0.2.10")
	var wg sync.WaitGroup

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			l.Check(clientIP, "example.com", 1, CategoryResponse)
		}()
	}

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			c := DefaultConfig()
			c.ResponsesPerSecond = n + 1
			l.UpdateConfig(c)
		}(i)
	}

	wg.Wait()
}

func TestCfgMu_FieldExists(t *testing.T) {
	// Structural: cfgMu must be a sync.RWMutex accessible on Limiter
	l := NewLimiter(DefaultConfig())
	defer l.Close()
	// Lock/unlock to confirm field exists and is functional
	l.cfgMu.Lock()
	l.cfgMu.Unlock()
}
