package zone

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"
)

// MarshalZoneFile marshals a DNSZoneFile struct to YAML bytes.
// This is useful when building a DNSZoneFile directly (e.g., CreateZone) without
// going through a full *Zone round-trip.
func MarshalZoneFile(zf *DNSZoneFile) ([]byte, error) {
	data, err := yaml.Marshal(zf)
	if err != nil {
		return nil, fmt.Errorf("marshal zone YAML: %w", err)
	}
	return data, nil
}

// rrRdata extracts the rdata portion from a miekg/dns RR string representation.
// miekg uses tab-separated fields: "name\tTTL\tclass\ttype\trdata"
func rrRdata(rr dns.RR) string {
	parts := strings.SplitN(rr.String(), "\t", 5)
	if len(parts) == 5 {
		return parts[4]
	}
	return ""
}

// SerializeDNSZone serializes a *Zone back to valid .dnszone YAML format.
// The result can be written to a .dnszone file and fed to dnsscienced-compile.
func SerializeDNSZone(z *Zone) ([]byte, error) {
	if z == nil {
		return nil, fmt.Errorf("nil zone")
	}
	if z.SOA == nil {
		return nil, fmt.Errorf("zone %s has no SOA record", z.Origin)
	}

	// Determine zone name without trailing dot for the YAML name field.
	zoneName := strings.TrimSuffix(z.Origin, ".")

	// Default TTL from SOA header TTL.
	defaultTTL := z.SOA.Header().Ttl

	zf := DNSZoneFile{
		Zone: ZoneSection{
			Name:  zoneName,
			Class: "IN",
			TTL:   fmt.Sprintf("%d", defaultTTL),
		},
		SOA: SOASection{
			PrimaryNS:   z.SOA.Ns,
			Contact:     soaContactToEmail(z.SOA.Mbox),
			Serial:      "auto",
			Refresh:     fmt.Sprintf("%d", z.SOA.Refresh),
			Retry:       fmt.Sprintf("%d", z.SOA.Retry),
			Expire:      fmt.Sprintf("%d", z.SOA.Expire),
			NegativeTTL: fmt.Sprintf("%d", z.SOA.Minttl),
		},
		Records: make(map[string]RecordSection),
	}

	// Build records map, grouped by relative owner name.
	// Use a staging map so we can accumulate multiple types under one owner.
	type ownerData struct {
		aRecords    []string
		aaaaRecords []string
		cname       string
		ptr         string
		nsRecords   []string
		txtRecords  []string
		mxRecords   []MXRecord
		srvRecords  []SRVRecord
		// rawTypes collects rdata strings for all other record types by type code.
		rawTypes map[uint16][]string
	}
	owners := make(map[string]*ownerData)

	for owner, typeMap := range z.Records {
		relOwner := absoluteToRelative(owner, z.Origin)

		for rrtype, rrs := range typeMap {
			// Skip SOA — it lives in the soa: section.
			if rrtype == dns.TypeSOA {
				continue
			}

			if owners[relOwner] == nil {
				owners[relOwner] = &ownerData{}
			}
			od := owners[relOwner]

			for _, rr := range rrs {
				switch v := rr.(type) {
				case *dns.A:
					od.aRecords = append(od.aRecords, v.A.String())

				case *dns.AAAA:
					od.aaaaRecords = append(od.aaaaRecords, v.AAAA.String())

				case *dns.CNAME:
					od.cname = v.Target

				case *dns.PTR:
					od.ptr = v.Ptr

				case *dns.NS:
					od.nsRecords = append(od.nsRecords, v.Ns)

				case *dns.TXT:
					// Re-join TXT chunks (they were split at 255 bytes on parse).
					od.txtRecords = append(od.txtRecords, strings.Join(v.Txt, ""))

				case *dns.MX:
					od.mxRecords = append(od.mxRecords, MXRecord{
						Priority: int(v.Preference),
						Target:   v.Mx,
					})

				case *dns.SRV:
					od.srvRecords = append(od.srvRecords, SRVRecord{
						Priority: int(v.Priority),
						Weight:   int(v.Weight),
						Port:     int(v.Port),
						Target:   v.Target,
					})
				default:
					// Collect all other types as raw rdata strings.
					if od.rawTypes == nil {
						od.rawTypes = make(map[uint16][]string)
					}
					rt := rr.Header().Rrtype
					od.rawTypes[rt] = append(od.rawTypes[rt], rrRdata(rr))
				}
			}
		}
	}

	// Convert ownerData → RecordSection entries.
	for relOwner, od := range owners {
		sec := RecordSection{}

		switch len(od.aRecords) {
		case 0:
			// no A records
		case 1:
			sec.A = od.aRecords[0]
		default:
			iface := make([]interface{}, len(od.aRecords))
			for i, v := range od.aRecords {
				iface[i] = v
			}
			sec.A = iface
		}

		switch len(od.aaaaRecords) {
		case 0:
		case 1:
			sec.AAAA = od.aaaaRecords[0]
		default:
			iface := make([]interface{}, len(od.aaaaRecords))
			for i, v := range od.aaaaRecords {
				iface[i] = v
			}
			sec.AAAA = iface
		}

		if od.cname != "" {
			sec.CNAME = od.cname
		}

		if od.ptr != "" {
			sec.PTR = od.ptr
		}

		switch len(od.nsRecords) {
		case 0:
		case 1:
			sec.NS = od.nsRecords[0]
		default:
			iface := make([]interface{}, len(od.nsRecords))
			for i, v := range od.nsRecords {
				iface[i] = v
			}
			sec.NS = iface
		}

		switch len(od.txtRecords) {
		case 0:
		case 1:
			sec.TXT = od.txtRecords[0]
		default:
			iface := make([]interface{}, len(od.txtRecords))
			for i, v := range od.txtRecords {
				iface[i] = v
			}
			sec.TXT = iface
		}

		if len(od.mxRecords) > 0 {
			iface := make([]interface{}, len(od.mxRecords))
			for i, mx := range od.mxRecords {
				iface[i] = map[string]interface{}{
					"priority": mx.Priority,
					"target":   mx.Target,
				}
			}
			sec.MX = iface
		}

		if len(od.srvRecords) > 0 {
			iface := make([]interface{}, len(od.srvRecords))
			for i, srv := range od.srvRecords {
				iface[i] = map[string]interface{}{
					"priority": srv.Priority,
					"weight":   srv.Weight,
					"port":     srv.Port,
					"target":   srv.Target,
				}
			}
			sec.SRV = iface
		}

		// Assign remaining record types to named fields or Generic TYPE### fallback.
		for rt, rdatas := range od.rawTypes {
			var fieldData interface{}
			if len(rdatas) == 1 {
				fieldData = rdatas[0]
			} else {
				iface := make([]interface{}, len(rdatas))
				for i, v := range rdatas {
					iface[i] = v
				}
				fieldData = iface
			}
			switch rt {
			case dns.TypeCAA:
				sec.CAA = fieldData
			case dns.TypeTLSA:
				sec.TLSA = fieldData
			case dns.TypeSSHFP:
				sec.SSHFP = fieldData
			case dns.TypeNAPTR:
				sec.NAPTR = fieldData
			case dns.TypeSMIMEA:
				sec.SMIMEA = fieldData
			case dns.TypeLOC:
				sec.LOC = fieldData
			case dns.TypeHTTPS:
				sec.HTTPS = fieldData
			case dns.TypeSVCB:
				sec.SVCB = fieldData
			case dns.TypeHINFO:
				sec.HINFO = fieldData
			case dns.TypeCERT:
				sec.CERT = fieldData
			case dns.TypeIPSECKEY:
				sec.IPSECKEY = fieldData
			case dns.TypeOPENPGPKEY:
				sec.OPENPGPKEY = fieldData
			case dns.TypeURI:
				sec.URI = fieldData
			case dns.TypeEUI48:
				sec.EUI48 = fieldData
			case dns.TypeEUI64:
				sec.EUI64 = fieldData
			case dns.TypeCDS:
				sec.CDS = fieldData
			case dns.TypeCDNSKEY:
				sec.CDNSKEY = fieldData
			case dns.TypeZONEMD:
				sec.ZONEMD = fieldData
			case dns.TypeCSYNC:
				sec.CSYNC = fieldData
			case dns.TypeRP:
				sec.RP = fieldData
			case dns.TypeAFSDB:
				sec.AFSDB = fieldData
			case dns.TypeKX:
				sec.KX = fieldData
			case dns.TypeDHCID:
				sec.DHCID = fieldData
			default:
				// Truly unknown type: emit as TYPE### for parseGenericTypes to consume.
				typeKey := fmt.Sprintf("TYPE%d", rt)
				if sec.Generic == nil {
					sec.Generic = make(map[string]interface{})
				}
				sec.Generic[typeKey] = fieldData
			}
		}

		zf.Records[relOwner] = sec
	}

	data, err := yaml.Marshal(&zf)
	if err != nil {
		return nil, fmt.Errorf("marshal zone YAML: %w", err)
	}
	return data, nil
}

// absoluteToRelative converts a fully-qualified owner name to the relative form
// used in .dnszone files:
//   - zone apex (e.g., "example.com.") → "@"
//   - subdomain (e.g., "www.example.com.") → "www"
//   - already relative names → returned as-is
func absoluteToRelative(owner, origin string) string {
	// DNS names are lowercased when stored; normalise origin too.
	origin = strings.ToLower(origin)
	owner = strings.ToLower(owner)

	if owner == origin {
		return "@"
	}

	// Strip the ".<origin>" suffix.
	suffix := "." + origin
	if strings.HasSuffix(owner, suffix) {
		return strings.TrimSuffix(owner, suffix)
	}

	// Fallback: return owner as-is (should not normally happen for in-zone names).
	return owner
}

// soaContactToEmail converts a DNS-format MBOX (e.g., "hostmaster.example.com.")
// back to an email address string suitable for the .dnszone contact field.
// The convention used by formatEmailAddress() in parser_dnszone.go replaces "@" with ".";
// we reverse that by replacing the first "." with "@".
func soaContactToEmail(mbox string) string {
	// Strip trailing dot.
	mbox = strings.TrimSuffix(mbox, ".")

	// Replace the first dot with "@" to recreate a valid email string.
	idx := strings.Index(mbox, ".")
	if idx < 0 {
		return mbox
	}
	return mbox[:idx] + "@" + mbox[idx+1:]
}
