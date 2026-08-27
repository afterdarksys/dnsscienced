package catalog

import (
	"encoding/hex"
	"reflect"
	"testing"

	"github.com/afterdarksys/dnsscienced/internal/zone"
	"github.com/miekg/dns"
)

func FuzzParseCatalogRecord(f *testing.F) {
	f.Add(`a1.zones.catalog.example. 0 IN PTR alpha.example.`)
	f.Add(`group.a1.zones.catalog.example. 0 IN TXT "blue"`)
	f.Add(`coo.a1.zones.catalog.example. 0 IN PTR next.example.`)
	f.Add(`vendor.policy.ext.a1.zones.catalog.example. 0 IN TXT "strict"`)
	f.Add(`a1.zones.catalog.example. 0 CH PTR alpha.example.`)

	f.Fuzz(func(t *testing.T, record string) {
		z, ok := fuzzCatalogBase()
		if !ok {
			t.Fatal("fixed catalog seed is invalid")
		}
		if len(record) > 4096 {
			return
		}
		rr, err := dns.NewRR(record)
		if err == nil {
			// Out-of-zone data is intentionally rejected by the ordinary zone
			// model before the catalog parser sees it.
			if err := z.AddRecord(rr); err != nil {
				return
			}
		}
		_, _ = Parse(z)
	})
}

func FuzzCatalogPlanDeterministic(f *testing.F) {
	f.Add([]byte{1, 2, 3, 4, 5, 6})
	f.Add([]byte{0xff, 0, 0xff, 1, 2, 3, 4, 5})

	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 1024 {
			return
		}
		previous, next, ownership, order, reserved := fuzzPlanInput(input)
		first, firstErr := Plan(previous, next, ownership, order, reserved)
		second, secondErr := Plan(previous, next, ownership, order, reserved)
		if (firstErr == nil) != (secondErr == nil) {
			t.Fatalf("nondeterministic errors: first=%v second=%v", firstErr, secondErr)
		}
		if firstErr == nil && !reflect.DeepEqual(first, second) {
			t.Fatalf("nondeterministic plan:\nfirst=%+v\nsecond=%+v", first, second)
		}
	})
}

func fuzzCatalogBase() (*zone.Zone, bool) {
	z := zone.New("catalog.example.")
	for _, record := range []string{
		"catalog.example. 300 IN SOA ns1.catalog.example. hostmaster.catalog.example. 42 3600 600 86400 300",
		"catalog.example. 300 IN NS ns1.catalog.example.",
		"ns1.catalog.example. 300 IN A 192.0.2.53",
		`version.catalog.example. 0 IN TXT "2"`,
	} {
		rr, err := dns.NewRR(record)
		if err != nil || z.AddRecord(rr) != nil {
			return nil, false
		}
	}
	return z, true
}

func fuzzPlanInput(input []byte) (
	map[string]*Catalog,
	map[string]*Catalog,
	map[string]Ownership,
	[]string,
	[]string,
) {
	catalogNames := []string{"first.catalog.", "second.catalog."}
	previous := map[string]*Catalog{}
	next := map[string]*Catalog{}
	ownership := map[string]Ownership{}
	var reserved []string

	for i, value := range input {
		// Reuse a small zone-name set so fuzzing exercises catalog clashes,
		// ownership changes, removals, and reconfiguration rather than only adds.
		zoneName := hex.EncodeToString([]byte{byte(i % 8), value & 7}) + ".example."
		catalogName := catalogNames[int(value)&1]
		label := hex.EncodeToString([]byte{value, byte(i)})
		member := Member{Zone: zoneName, Label: label}
		if value&4 != 0 {
			member.Groups = []TXTValue{{Strings: []string{"group", label}}}
		}
		if value&8 != 0 {
			member.ChangeOfOwnership = catalogNames[(int(value)+1)&1]
		}
		target := next
		if value&2 != 0 {
			target = previous
		}
		if target[catalogName] == nil {
			target[catalogName] = &Catalog{Name: catalogName, Members: map[string]Member{}}
		}
		target[catalogName].Members[zoneName] = member
		if value&16 != 0 {
			ownership[zoneName] = Ownership{Catalog: catalogName, Label: label}
		}
		if value&32 != 0 {
			reserved = append(reserved, zoneName)
		}
	}
	return previous, next, ownership, catalogNames, reserved
}
