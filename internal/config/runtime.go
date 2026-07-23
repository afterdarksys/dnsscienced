package config

import (
	"runtime"
	"runtime/debug"
)

const bytesPerMiB = int64(1024 * 1024)

// ApplyRuntime applies explicit runtime overrides. Omitted settings preserve
// Go's environment- and container-derived defaults.
func ApplyRuntime(cfg RuntimeConfig) {
	if cfg.MaxProcs > 0 {
		runtime.GOMAXPROCS(cfg.MaxProcs)
	}
	if cfg.GCPercent != nil {
		debug.SetGCPercent(*cfg.GCPercent)
	}
	if cfg.MemoryLimitMB > 0 {
		debug.SetMemoryLimit(cfg.MemoryLimitMB * bytesPerMiB)
	}
}
