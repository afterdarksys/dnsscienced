package secondary

import (
	"testing"

	"github.com/dnsscience/dnsscienced/internal/zone"
	"github.com/miekg/dns"
)

func TestApplyTransferAppliesIXFRDeltaChain(t *testing.T) {
	one := validZone("secondary.test.", 1)
	two := one.Clone()
	two.SOA.Serial = 2
	txt, _ := dns.NewRR("new.secondary.test. 300 IN TXT \"two\"")
	if err := two.AddRecord(txt); err != nil {
		t.Fatal(err)
	}
	three := two.Clone()
	three.SOA.Serial = 3
	if err := three.DeleteRecord(txt); err != nil {
		t.Fatal(err)
	}
	a, _ := dns.NewRR("final.secondary.test. 300 IN A 192.0.2.99")
	if err := three.AddRecord(a); err != nil {
		t.Fatal(err)
	}

	deltaOne := zone.Diff(one, two)
	deltaTwo := zone.Diff(two, three)
	records := ixfrRecords(three.SOA, deltaOne, deltaTwo)
	got, incremental, err := applyTransfer(one, one.Origin, records)
	if err != nil {
		t.Fatal(err)
	}
	if !incremental || got.SOA.Serial != 3 {
		t.Fatalf("incremental=%v serial=%d", incremental, got.SOA.Serial)
	}
	if len(got.GetRecords("new.secondary.test.", dns.TypeTXT)) != 0 {
		t.Fatal("deleted TXT survived IXFR")
	}
	if len(got.GetRecords("final.secondary.test.", dns.TypeA)) != 1 {
		t.Fatal("added A record missing after IXFR")
	}
	if one.SOA.Serial != 1 {
		t.Fatal("IXFR mutated the live input zone")
	}
}

func TestApplyTransferRecognizesAXFRFallback(t *testing.T) {
	current := validZone("secondary.test.", 1)
	next := validZone("secondary.test.", 2)
	records := []dns.RR{dns.Copy(next.SOA)}
	for _, rr := range next.GetAllRecords() {
		if rr.Header().Rrtype != dns.TypeSOA {
			records = append(records, dns.Copy(rr))
		}
	}
	records = append(records, dns.Copy(next.SOA))

	got, incremental, err := applyTransfer(current, current.Origin, records)
	if err != nil {
		t.Fatal(err)
	}
	if incremental || got.SOA.Serial != 2 {
		t.Fatalf("incremental=%v serial=%d", incremental, got.SOA.Serial)
	}
}

func TestApplyTransferRejectsBrokenIXFRWithoutMutation(t *testing.T) {
	current := validZone("secondary.test.", 1)
	target := validZone("secondary.test.", 3)
	badOld := dns.Copy(current.SOA).(*dns.SOA)
	badOld.Serial = 2
	records := []dns.RR{target.SOA, badOld, target.SOA, target.SOA}

	if _, _, err := applyTransfer(current, current.Origin, records); err == nil {
		t.Fatal("broken delta chain was accepted")
	}
	if current.SOA.Serial != 1 {
		t.Fatal("failed IXFR mutated current zone")
	}
}

func ixfrRecords(current *dns.SOA, deltas ...zone.Delta) []dns.RR {
	records := []dns.RR{dns.Copy(current)}
	for _, delta := range deltas {
		records = append(records, dns.Copy(delta.FromSOA))
		for _, rr := range delta.Deleted {
			records = append(records, dns.Copy(rr))
		}
		records = append(records, dns.Copy(delta.ToSOA))
		for _, rr := range delta.Added {
			records = append(records, dns.Copy(rr))
		}
	}
	return append(records, dns.Copy(current))
}
