package catalog

import (
	"strings"
	"testing"

	"github.com/dnsscience/dnsscienced/internal/zone"
	"github.com/miekg/dns"
)

func catalogZone(t *testing.T, origin string, records ...string) *zone.Zone {
	t.Helper()
	origin = dns.Fqdn(origin)
	z := zone.New(origin)
	base := []string{
		origin + " 300 IN SOA ns1." + origin + " hostmaster." + origin + " 42 3600 600 86400 300",
		origin + " 300 IN NS ns1." + origin,
		"ns1." + origin + " 300 IN A 192.0.2.53",
		"version." + origin + ` 0 IN TXT "2"`,
	}
	for _, text := range append(base, records...) {
		rr, err := dns.NewRR(text)
		if err != nil {
			t.Fatalf("dns.NewRR(%q): %v", text, err)
		}
		if err := z.AddRecord(rr); err != nil {
			t.Fatalf("AddRecord(%q): %v", text, err)
		}
	}
	return z
}

func TestParseVersion2Catalog(t *testing.T) {
	z := catalogZone(
		t,
		"catalog.example.",
		`a1.zones.catalog.example. 0 IN PTR alpha.example.`,
		`group.a1.zones.catalog.example. 0 IN TXT "blue"`,
		`group.a1.zones.catalog.example. 0 IN TXT "prod" "east"`,
		`coo.a1.zones.catalog.example. 0 IN PTR next-catalog.example.`,
		`x-owner.ext.a1.zones.catalog.example. 0 IN TXT "tenant-7"`,
		`vendor.policy.ext.a1.zones.catalog.example. 0 IN TXT "strict"`,
		`defaults.ext.catalog.example. 0 IN TXT "secure"`,
		`vendor.defaults.ext.catalog.example. 0 IN TXT "v2"`,
		`ignored.a1.zones.catalog.example. 0 IN TXT "unknown-property"`,
	)

	got, err := Parse(z)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "catalog.example." || got.Serial != 42 || len(got.Members) != 1 {
		t.Fatalf("catalog=%+v", got)
	}
	member := got.Members["alpha.example."]
	if member.Label != "a1" ||
		member.ChangeOfOwnership != "next-catalog.example." ||
		len(member.Groups) != 2 ||
		len(member.Extensions["x-owner"]) != 1 ||
		len(member.Extensions["vendor.policy"]) != 1 ||
		len(got.GlobalExtensions["defaults"]) != 1 ||
		len(got.GlobalExtensions["vendor.defaults"]) != 1 {
		t.Fatalf("member=%+v global=%v", member, got.GlobalExtensions)
	}
	if strings.Join(member.Groups[1].Strings, "/") != "prod/east" {
		t.Fatalf("groups=%+v", member.Groups)
	}
}

func TestParseRejectsMissingOrUnsupportedVersion(t *testing.T) {
	missing := zone.New("catalog.example.")
	for _, text := range []string{
		"catalog.example. 300 IN SOA ns.catalog.example. hostmaster.catalog.example. 1 3600 600 86400 300",
		"catalog.example. 300 IN NS ns.catalog.example.",
	} {
		rr, _ := dns.NewRR(text)
		_ = missing.AddRecord(rr)
	}
	if _, err := Parse(missing); err == nil {
		t.Fatal("Parse accepted catalog without version")
	}

	unsupported := catalogZone(t, "catalog.example.")
	version := unsupported.ExactRecords("version.catalog.example.", dns.TypeTXT)[0].(*dns.TXT)
	version.Txt = []string{"1"}
	if _, err := Parse(unsupported); err == nil {
		t.Fatal("Parse accepted unsupported catalog version")
	}

	extraUnsupportedRR := catalogZone(
		t,
		"catalog.example.",
		`version.catalog.example. 0 IN A 192.0.2.99`,
	)
	if _, err := Parse(extraUnsupportedRR); err != nil {
		t.Fatalf("Parse did not ignore unsupported RR type at version owner: %v", err)
	}
}

func TestParseRejectsAmbiguousMembers(t *testing.T) {
	multiplePTR := catalogZone(
		t,
		"catalog.example.",
		`a1.zones.catalog.example. 0 IN PTR alpha.example.`,
		`a1.zones.catalog.example. 0 IN PTR beta.example.`,
	)
	if _, err := Parse(multiplePTR); err == nil {
		t.Fatal("Parse accepted multiple member PTR records for one label")
	}

	duplicateZone := catalogZone(
		t,
		"catalog.example.",
		`a1.zones.catalog.example. 0 IN PTR alpha.example.`,
		`a2.zones.catalog.example. 0 IN PTR ALPHA.EXAMPLE.`,
	)
	if _, err := Parse(duplicateZone); err == nil {
		t.Fatal("Parse accepted one member zone under multiple labels")
	}
}

func TestParseIgnoresOrphanAndUnknownProperties(t *testing.T) {
	z := catalogZone(
		t,
		"catalog.example.",
		`group.orphan.zones.catalog.example. 0 IN TXT "ignored"`,
		`unknown.orphan.zones.catalog.example. 0 IN TXT "ignored"`,
	)
	got, err := Parse(z)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Members) != 0 {
		t.Fatalf("members=%v, want none", got.Members)
	}
}

func TestParseRejectsNonINRecord(t *testing.T) {
	z := catalogZone(t, "catalog.example.")
	rr, err := dns.NewRR(`a1.zones.catalog.example. 0 CH PTR alpha.example.`)
	if err != nil {
		t.Fatal(err)
	}
	// Insert directly because Zone.AddRecord accepts only in-zone ownership but
	// intentionally does not impose a class policy.
	z.Records["a1.zones.catalog.example."] = map[uint16][]dns.RR{
		dns.TypePTR: {rr},
	}
	if _, err := Parse(z); err == nil {
		t.Fatal("Parse accepted a non-IN catalog record")
	}
}
