package config

import (
	"math"
	"os"
	"runtime"
	"runtime/debug"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadRejectsInvalidRuntimeConfig(t *testing.T) {
	tests := []struct {
		name string
		yaml string
	}{
		{name: "negative max procs", yaml: "runtime:\n  max_procs: -1\n"},
		{name: "excessive max procs", yaml: "runtime:\n  max_procs: 65537\n"},
		{name: "invalid gc percent", yaml: "runtime:\n  gc_percent: -2\n"},
		{name: "excessive gc percent", yaml: "runtime:\n  gc_percent: 10001\n"},
		{name: "negative memory limit", yaml: "runtime:\n  memory_limit_mb: -1\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := t.TempDir() + "/config.yaml"
			require.NoError(t, os.WriteFile(path, []byte(tt.yaml), 0o600))
			_, err := Load(path)
			require.Error(t, err)
		})
	}
}

func TestRuntimeConfigZeroValuesAreValid(t *testing.T) {
	require.NoError(t, (RuntimeConfig{}).Validate())
}

func TestApplyRuntimeAppliesExplicitOverrides(t *testing.T) {
	oldProcs := runtime.GOMAXPROCS(0)
	oldGC := debug.SetGCPercent(100)
	oldLimit := debug.SetMemoryLimit(math.MaxInt64)
	defer runtime.GOMAXPROCS(oldProcs)
	defer debug.SetGCPercent(oldGC)
	defer debug.SetMemoryLimit(oldLimit)

	gcPercent := 37
	ApplyRuntime(RuntimeConfig{
		MaxProcs:      1,
		GCPercent:     &gcPercent,
		MemoryLimitMB: 64,
	})

	require.Equal(t, 1, runtime.GOMAXPROCS(0))
	require.Equal(t, 37, debug.SetGCPercent(100))
	require.Equal(t, int64(64*1024*1024), debug.SetMemoryLimit(math.MaxInt64))
}
