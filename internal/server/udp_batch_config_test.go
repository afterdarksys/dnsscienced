package server

import "testing"

func TestNewRejectsOversizedUDPBatch(t *testing.T) {
	cfg := DefaultConfig()
	cfg.UDPBatchSize = 257
	if _, err := New(cfg); err == nil {
		t.Fatal("New accepted udp_batch_size above the recvmmsg descriptor bound")
	}
}
