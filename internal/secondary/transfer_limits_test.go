package secondary

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestTransferAccumulatorEnforcesRecordAndByteLimits(t *testing.T) {
	rr, err := dns.NewRR("bounded.example. 300 IN TXT \"" + strings.Repeat("x", 128) + "\"")
	if err != nil {
		t.Fatal(err)
	}

	records, err := newTransferAccumulator(Config{MaxTransferRecords: 1, MaxTransferBytes: 4096})
	if err != nil {
		t.Fatal(err)
	}
	if err := records.add(rr); err != nil {
		t.Fatal(err)
	}
	if err := records.add(rr); err == nil {
		t.Fatal("record limit was not enforced")
	}

	bytes, err := newTransferAccumulator(Config{
		MaxTransferRecords: 10,
		MaxTransferBytes:   int64(dns.Len(rr) - 1),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := bytes.add(rr); err == nil {
		t.Fatal("byte limit was not enforced")
	}
}

func TestTransferAccumulatorRejectsInvalidLimitsAndNilRecords(t *testing.T) {
	for _, cfg := range []Config{
		{MaxTransferRecords: -1},
		{MaxTransferRecords: absoluteMaxTransferRecords + 1},
		{MaxTransferBytes: -1},
		{MaxTransferBytes: absoluteMaxTransferBytes + 1},
	} {
		if _, err := newTransferAccumulator(cfg); err == nil {
			t.Fatalf("invalid transfer limits accepted: %+v", cfg)
		}
	}
	accumulator, err := newTransferAccumulator(Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := accumulator.add(nil); err == nil {
		t.Fatal("nil transfer record was accepted")
	}
}
