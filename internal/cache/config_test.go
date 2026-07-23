package cache

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConfigValidate(t *testing.T) {
	require.NoError(t, (Config{}).Validate())
	require.NoError(t, (Config{
		ShardCount:        64,
		MaxEntries:        1000,
		MaxMemoryMB:       128,
		PrefetchMinTTLPct: 0.2,
	}).Validate())

	for _, cfg := range []Config{
		{ShardCount: -1},
		{ShardCount: 65537},
		{MaxEntries: -1},
		{MaxMemoryMB: -1},
		{PrefetchMinTTLPct: -0.1},
		{PrefetchMinTTLPct: 1.1},
		{ShardCount: 256, MaxEntries: 128},
		{ShardCount: 300, MaxEntries: 300},
	} {
		require.Error(t, cfg.Validate())
	}
}
