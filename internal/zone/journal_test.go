package zone

import (
	"testing"

	"github.com/miekg/dns"
)

func journalTestZone(t *testing.T, serial uint32, address string) *Zone {
	t.Helper()
	z := New("example.test.")
	for _, text := range []string{
		"example.test. 300 IN SOA ns1.example.test. hostmaster.example.test. " + serialText(serial) + " 60 30 3600 60",
		"example.test. 300 IN NS ns1.example.test.",
		"ns1.example.test. 300 IN A " + address,
	} {
		rr, err := dns.NewRR(text)
		if err != nil {
			t.Fatal(err)
		}
		if err := z.AddRecord(rr); err != nil {
			t.Fatal(err)
		}
	}
	return z
}

func serialText(serial uint32) string {
	if serial == 0 {
		return "0"
	}
	var buf [10]byte
	i := len(buf)
	for serial > 0 {
		i--
		buf[i] = byte('0' + serial%10)
		serial /= 10
	}
	return string(buf[i:])
}

func TestJournalReturnsContiguousDeltaChain(t *testing.T) {
	one := journalTestZone(t, 1, "192.0.2.1")
	two := journalTestZone(t, 2, "192.0.2.2")
	three := journalTestZone(t, 3, "192.0.2.3")
	journal := NewJournal(10)
	journal.Record(one, two)
	journal.Record(two, three)

	deltas, ok := journal.Changes("EXAMPLE.TEST", 1, 3)
	if !ok || len(deltas) != 2 {
		t.Fatalf("deltas=%v ok=%v, want two changes", deltas, ok)
	}
	if len(deltas[0].Deleted) != 1 || len(deltas[0].Added) != 1 {
		t.Fatalf("first delta deleted=%d added=%d", len(deltas[0].Deleted), len(deltas[0].Added))
	}
	if _, ok := journal.Changes("example.test.", 0, 3); ok {
		t.Fatal("journal returned a non-contiguous history")
	}
}

func TestJournalPurgesOldestDelta(t *testing.T) {
	one := journalTestZone(t, 1, "192.0.2.1")
	two := journalTestZone(t, 2, "192.0.2.2")
	three := journalTestZone(t, 3, "192.0.2.3")
	journal := NewJournal(1)
	journal.Record(one, two)
	journal.Record(two, three)

	if _, ok := journal.Changes("example.test.", 1, 3); ok {
		t.Fatal("purged serial remained available")
	}
	if deltas, ok := journal.Changes("example.test.", 2, 3); !ok || len(deltas) != 1 {
		t.Fatalf("latest delta=%v ok=%v", deltas, ok)
	}
}

func TestSerialGreaterWraparound(t *testing.T) {
	if !SerialGreater(0, ^uint32(0)) {
		t.Fatal("wraparound serial should be newer")
	}
	if SerialGreater(1, 1) || SerialGreater(0, 1) {
		t.Fatal("equal or previous serial reported newer")
	}
}
