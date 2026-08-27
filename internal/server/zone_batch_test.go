package server

import (
	"testing"

	"github.com/afterdarksys/dnsscienced/internal/zone"
	"github.com/miekg/dns"
)

func TestApplyZoneBatchSwapsCompleteFleetAndRejectsInvalidBatch(t *testing.T) {
	cfg := DefaultConfig()
	cfg.EnableAuthoritative = true
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	alpha := batchTestZone(t, "alpha.example.", 1)
	if err := srv.AddZone(alpha); err != nil {
		t.Fatal(err)
	}

	invalid := zone.New("invalid.example.")
	if err := srv.ApplyZoneBatch([]*zone.Zone{invalid}, []string{"alpha.example."}); err == nil {
		t.Fatal("invalid batch was accepted")
	}
	if srv.GetZone("alpha.example.") == nil || srv.GetZone("invalid.example.") != nil {
		t.Fatal("invalid batch partially mutated authoritative zones")
	}

	beta := batchTestZone(t, "beta.example.", 1)
	gamma := batchTestZone(t, "gamma.example.", 1)
	if err := srv.ApplyZoneBatch(
		[]*zone.Zone{beta, gamma},
		[]string{"alpha.example."},
	); err != nil {
		t.Fatal(err)
	}
	srv.zonesMu.RLock()
	_, hasAlpha := srv.cfg.Zones["alpha.example."]
	_, hasBeta := srv.cfg.Zones["beta.example."]
	_, hasGamma := srv.cfg.Zones["gamma.example."]
	srv.zonesMu.RUnlock()
	if hasAlpha || !hasBeta || !hasGamma {
		t.Fatalf("unexpected fleet after batch: alpha=%v beta=%v gamma=%v", hasAlpha, hasBeta, hasGamma)
	}
}

func batchTestZone(t *testing.T, name string, serial uint32) *zone.Zone {
	t.Helper()
	z := zone.New(name)
	records := []string{
		name + " 300 IN SOA ns1." + name + " hostmaster." + name + " " + serialString(serial) + " 3600 600 86400 300",
		name + " 300 IN NS ns1." + name,
		"ns1." + name + " 300 IN A 192.0.2.53",
	}
	for _, text := range records {
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

func serialString(serial uint32) string {
	if serial == 0 {
		return "1"
	}
	const digits = "0123456789"
	var buffer [10]byte
	i := len(buffer)
	for serial > 0 {
		i--
		buffer[i] = digits[serial%10]
		serial /= 10
	}
	return string(buffer[i:])
}
