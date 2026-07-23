package server

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewRejectsInvalidUDPListenerCount(t *testing.T) {
	for _, listeners := range []int{-1, 65537} {
		cfg := DefaultConfig()
		cfg.UDPListeners = listeners
		_, err := New(cfg)
		require.Error(t, err)
	}
}

func TestNewDefaultsZeroUDPListenerCount(t *testing.T) {
	cfg := DefaultConfig()
	cfg.UDPListeners = 0
	srv, err := New(cfg)
	require.NoError(t, err)
	require.Len(t, srv.udpServers, runtime.NumCPU())
	srv.cancel()
}
