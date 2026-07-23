package server

import (
	"runtime"
	"testing"
	"time"

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

func TestNewWiresTCPProtectionBounds(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TCPProtection.MaxQueriesPerConnection = 17
	cfg.IdleTimeout = 3 * time.Second
	srv, err := New(cfg)
	require.NoError(t, err)
	require.Equal(t, 17, srv.tcpServer.MaxTCPQueries)
	require.Equal(t, 3*time.Second, srv.tcpServer.IdleTimeout())
	srv.cancel()
}

func TestNewRejectsInvalidTCPProtection(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TCPProtection.MaxConnections = 0
	_, err := New(cfg)
	require.Error(t, err)
}

func TestNewDefaultsZeroUDPListenerCount(t *testing.T) {
	cfg := DefaultConfig()
	cfg.UDPListeners = 0
	srv, err := New(cfg)
	require.NoError(t, err)
	require.Len(t, srv.udpServers, runtime.NumCPU())
	srv.cancel()
}
