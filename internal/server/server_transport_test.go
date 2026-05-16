package server

import (
	"testing"
)

// TestStats_HasUDPTCPFields verifies the Stats struct has UDPQueries and TCPQueries fields.
func TestStats_HasUDPTCPFields(t *testing.T) {
	s := Stats{}
	s.UDPQueries = 10
	s.TCPQueries = 5
	if s.UDPQueries != 10 {
		t.Errorf("UDPQueries = %d, want 10", s.UDPQueries)
	}
	if s.TCPQueries != 5 {
		t.Errorf("TCPQueries = %d, want 5", s.TCPQueries)
	}
}

// TestServer_AtomicFields verifies udpQueries and tcpQueries exist on Server struct.
func TestServer_AtomicFields(t *testing.T) {
	s := &Server{}
	s.udpQueries.Add(3)
	s.tcpQueries.Add(7)
	if s.udpQueries.Load() != 3 {
		t.Errorf("udpQueries = %d, want 3", s.udpQueries.Load())
	}
	if s.tcpQueries.Load() != 7 {
		t.Errorf("tcpQueries = %d, want 7", s.tcpQueries.Load())
	}
}

// TestGetStats_ReturnsUDPTCPCounts verifies GetStats populates UDPQueries and TCPQueries.
func TestGetStats_ReturnsUDPTCPCounts(t *testing.T) {
	s := &Server{}
	s.udpQueries.Store(12)
	s.tcpQueries.Store(34)

	stats := s.GetStats()
	if stats.UDPQueries != 12 {
		t.Errorf("GetStats().UDPQueries = %d, want 12", stats.UDPQueries)
	}
	if stats.TCPQueries != 34 {
		t.Errorf("GetStats().TCPQueries = %d, want 34", stats.TCPQueries)
	}
}
