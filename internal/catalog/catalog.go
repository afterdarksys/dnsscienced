// Package catalog parses and reconciles DNS catalog zones as defined by RFC 9432.
package catalog

import (
	"fmt"
	"sort"
	"strings"

	"github.com/dnsscience/dnsscienced/internal/zone"
	"github.com/miekg/dns"
)

const Version2 = "2"

// TXTValue preserves every character-string in one TXT RDATA. The boundary is
// significant because RFC 9432 defines the complete TXT RDATA as a group value.
type TXTValue struct {
	Strings []string
}

// Member is one catalog member and its standard and custom properties.
type Member struct {
	Zone              string
	Label             string
	Groups            []TXTValue
	ChangeOfOwnership string
	Extensions        map[string][]dns.RR
}

// Catalog is one validated RFC 9432 version 2 snapshot.
type Catalog struct {
	Name             string
	Serial           uint32
	Members          map[string]Member
	GlobalExtensions map[string][]dns.RR
}

// Parse validates and extracts an RFC 9432 version 2 catalog zone.
func Parse(z *zone.Zone) (*Catalog, error) {
	if z == nil {
		return nil, fmt.Errorf("catalog zone is nil")
	}
	if err := z.Validate(); err != nil {
		return nil, fmt.Errorf("catalog zone validation: %w", err)
	}
	if z.SOA == nil {
		return nil, fmt.Errorf("catalog zone has no SOA")
	}

	origin := normalizeName(z.Origin)
	result := &Catalog{
		Name:             origin,
		Serial:           z.SOA.Serial,
		Members:          make(map[string]Member),
		GlobalExtensions: make(map[string][]dns.RR),
	}
	records := z.GetAllRecords()
	for _, rr := range records {
		if rr == nil {
			return nil, fmt.Errorf("catalog zone contains a nil record")
		}
		if rr.Header().Class != dns.ClassINET {
			return nil, fmt.Errorf("catalog record %s is not IN class", rr.Header().Name)
		}
	}

	if err := parseVersion(records, origin); err != nil {
		return nil, err
	}

	type memberBuilder struct {
		ptr        []*dns.PTR
		groups     []TXTValue
		coo        []*dns.PTR
		extensions map[string][]dns.RR
	}
	builders := make(map[string]*memberBuilder)
	memberBuilderFor := func(label string) *memberBuilder {
		builder := builders[label]
		if builder == nil {
			builder = &memberBuilder{extensions: make(map[string][]dns.RR)}
			builders[label] = builder
		}
		return builder
	}

	for _, rr := range records {
		labels, ok := relativeLabels(rr.Header().Name, origin)
		if !ok {
			return nil, fmt.Errorf("catalog record %s is outside %s", rr.Header().Name, origin)
		}
		switch {
		case len(labels) == 2 && labels[1] == "zones":
			if ptr, ok := rr.(*dns.PTR); ok {
				memberBuilderFor(labels[0]).ptr = append(memberBuilderFor(labels[0]).ptr, ptr)
			}
		case len(labels) == 3 && labels[0] == "group" && labels[2] == "zones":
			if txt, ok := rr.(*dns.TXT); ok {
				builder := memberBuilderFor(labels[1])
				builder.groups = append(builder.groups, TXTValue{Strings: append([]string(nil), txt.Txt...)})
			}
		case len(labels) == 3 && labels[0] == "coo" && labels[2] == "zones":
			if ptr, ok := rr.(*dns.PTR); ok {
				builder := memberBuilderFor(labels[1])
				builder.coo = append(builder.coo, ptr)
			}
		case len(labels) >= 2 && labels[len(labels)-1] == "ext":
			prefix := strings.Join(labels[:len(labels)-1], ".")
			result.GlobalExtensions[prefix] = append(
				result.GlobalExtensions[prefix],
				dns.Copy(rr),
			)
		case len(labels) >= 4 &&
			labels[len(labels)-3] == "ext" &&
			labels[len(labels)-1] == "zones":
			builder := memberBuilderFor(labels[len(labels)-2])
			prefix := strings.Join(labels[:len(labels)-3], ".")
			builder.extensions[prefix] = append(builder.extensions[prefix], dns.Copy(rr))
		}
	}

	seenZones := make(map[string]string)
	for label, builder := range builders {
		if len(builder.ptr) == 0 {
			// RFC 9432 permits consumers to ignore unknown or orphan properties.
			continue
		}
		if len(builder.ptr) != 1 {
			return nil, fmt.Errorf("catalog member label %s has %d PTR records; want exactly one", label, len(builder.ptr))
		}
		memberZone := normalizeName(builder.ptr[0].Ptr)
		if memberZone == "." {
			return nil, fmt.Errorf("catalog member label %s has an empty member zone", label)
		}
		if previousLabel, duplicate := seenZones[memberZone]; duplicate {
			return nil, fmt.Errorf(
				"catalog member zone %s appears under labels %s and %s",
				memberZone,
				previousLabel,
				label,
			)
		}
		if len(builder.coo) > 1 {
			return nil, fmt.Errorf("catalog member label %s has %d coo PTR records; want at most one", label, len(builder.coo))
		}
		member := Member{
			Zone:       memberZone,
			Label:      label,
			Groups:     append([]TXTValue(nil), builder.groups...),
			Extensions: cloneExtensions(builder.extensions),
		}
		if len(builder.coo) == 1 {
			member.ChangeOfOwnership = normalizeName(builder.coo[0].Ptr)
			if member.ChangeOfOwnership == "." {
				return nil, fmt.Errorf("catalog member label %s has an empty coo target", label)
			}
		}
		sortTXTValues(member.Groups)
		seenZones[memberZone] = label
		result.Members[memberZone] = member
	}
	sortExtensionRecords(result.GlobalExtensions)
	for zoneName, member := range result.Members {
		sortExtensionRecords(member.Extensions)
		result.Members[zoneName] = member
	}
	return result, nil
}

func parseVersion(records []dns.RR, origin string) error {
	versionOwner := "version." + origin
	var versions []*dns.TXT
	for _, rr := range records {
		if strings.EqualFold(rr.Header().Name, versionOwner) {
			if txt, ok := rr.(*dns.TXT); ok {
				versions = append(versions, txt)
			}
		}
	}
	if len(versions) != 1 {
		return fmt.Errorf("catalog %s must contain exactly one version TXT RR", origin)
	}
	if len(versions[0].Txt) != 1 || versions[0].Txt[0] != Version2 {
		return fmt.Errorf("catalog %s has unsupported version TXT data %v", origin, versions[0].Txt)
	}
	return nil
}

func relativeLabels(owner, origin string) ([]string, bool) {
	owner = normalizeName(owner)
	origin = normalizeName(origin)
	if !dns.IsSubDomain(origin, owner) {
		return nil, false
	}
	if owner == origin {
		return nil, true
	}
	relative := strings.TrimSuffix(owner, origin)
	relative = strings.TrimSuffix(relative, ".")
	labels := dns.SplitDomainName(relative)
	for i := range labels {
		labels[i] = strings.ToLower(labels[i])
	}
	return labels, true
}

func normalizeName(name string) string {
	return strings.ToLower(dns.Fqdn(strings.TrimSpace(name)))
}

func cloneExtensions(source map[string][]dns.RR) map[string][]dns.RR {
	cloned := make(map[string][]dns.RR, len(source))
	for prefix, records := range source {
		for _, rr := range records {
			cloned[prefix] = append(cloned[prefix], dns.Copy(rr))
		}
	}
	return cloned
}

func sortTXTValues(values []TXTValue) {
	sort.Slice(values, func(i, j int) bool {
		return txtValueKey(values[i]) < txtValueKey(values[j])
	})
}

func txtValueKey(value TXTValue) string {
	var builder strings.Builder
	for _, part := range value.Strings {
		fmt.Fprintf(&builder, "%d:%s;", len(part), part)
	}
	return builder.String()
}

func sortExtensionRecords(extensions map[string][]dns.RR) {
	for prefix := range extensions {
		sort.Slice(extensions[prefix], func(i, j int) bool {
			return extensions[prefix][i].String() < extensions[prefix][j].String()
		})
	}
}
