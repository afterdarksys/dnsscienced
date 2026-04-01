package zone

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"
)

// DNSZoneFile represents the structure of a .dnszone YAML file
type DNSZoneFile struct {
	Zone      ZoneSection               `yaml:"zone"`
	SOA       SOASection                `yaml:"soa"`
	Records   map[string]RecordSection  `yaml:"records"`
	Templates map[string]TemplateSection `yaml:"templates,omitempty"`
	Apply     []ApplySection            `yaml:"apply,omitempty"`
	DNSSEC    *DNSSECSection            `yaml:"dnssec,omitempty"`
}

// ZoneSection holds zone metadata
type ZoneSection struct {
	Name    string `yaml:"name"`
	TTL     string `yaml:"ttl,omitempty"`
	Class   string `yaml:"class,omitempty"`
	Comment string `yaml:"comment,omitempty"`
}

// SOASection holds SOA record details
type SOASection struct {
	PrimaryNS   string `yaml:"primary_ns"`
	Contact     string `yaml:"contact"`
	Serial      string `yaml:"serial"`      // Can be "auto" or number
	Refresh     string `yaml:"refresh"`
	Retry       string `yaml:"retry"`
	Expire      string `yaml:"expire"`
	NegativeTTL string `yaml:"negative_ttl"`
}

// RecordSection holds records for an owner name
type RecordSection struct {
	A       interface{} `yaml:"A,omitempty"`
	AAAA    interface{} `yaml:"AAAA,omitempty"`
	CNAME   string      `yaml:"CNAME,omitempty"`
	MX      interface{} `yaml:"MX,omitempty"`
	NS      interface{} `yaml:"NS,omitempty"`
	TXT     interface{} `yaml:"TXT,omitempty"`
	SRV     interface{} `yaml:"SRV,omitempty"`
	PTR     string      `yaml:"PTR,omitempty"`
	TLSA    interface{} `yaml:"TLSA,omitempty"`
	HTTPS   interface{} `yaml:"HTTPS,omitempty"`
	SVCB    interface{} `yaml:"SVCB,omitempty"`
	CAA     interface{} `yaml:"CAA,omitempty"`

	TTL     int    `yaml:"ttl,omitempty"`
	Comment string `yaml:"comment,omitempty"`
	Reverse bool   `yaml:"reverse,omitempty"`
}

// MXRecord represents an MX record
type MXRecord struct {
	Priority int    `yaml:"priority"`
	Target   string `yaml:"target"`
}

// SRVRecord represents an SRV record
type SRVRecord struct {
	Priority int    `yaml:"priority"`
	Weight   int    `yaml:"weight"`
	Port     int    `yaml:"port"`
	Target   string `yaml:"target"`
}

// TLSARecord represents a TLSA record
type TLSARecord struct {
	Usage     int    `yaml:"usage"`
	Selector  int    `yaml:"selector"`
	Matching  int    `yaml:"matching"`
	Data      string `yaml:"data"`
}

// HTTPSRecord represents an HTTPS/SVCB record
type HTTPSRecord struct {
	Priority int                    `yaml:"priority"`
	Target   string                 `yaml:"target"`
	Params   map[string]interface{} `yaml:"params,omitempty"`
}

// CAARecord represents a CAA record
type CAARecord struct {
	Flags int    `yaml:"flags"`
	Tag   string `yaml:"tag"`
	Value string `yaml:"value"`
}

// TemplateSection defines a record template
type TemplateSection map[string]interface{}

// ApplySection applies a template to multiple names
type ApplySection struct {
	Template string                   `yaml:"template"`
	To       []map[string]interface{} `yaml:"to"`
}

// DNSSECSection holds DNSSEC configuration
type DNSSECSection struct {
	Enabled      bool          `yaml:"enabled"`
	Algorithm    string        `yaml:"algorithm,omitempty"`
	KSKLifetime  string        `yaml:"ksk-lifetime,omitempty"`
	ZSKLifetime  string        `yaml:"zsk-lifetime,omitempty"`
	NSEC3        *NSEC3Section `yaml:"nsec3,omitempty"`
}

// NSEC3Section holds NSEC3 parameters
type NSEC3Section struct {
	Enabled    bool   `yaml:"enabled"`
	Iterations int    `yaml:"iterations"`
	SaltLength int    `yaml:"salt-length"`
}

// ParseDNSZone parses a .dnszone YAML file
func ParseDNSZone(filename string, cfg Config) (*Zone, error) {
	// Read file
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	// Parse YAML
	var zf DNSZoneFile
	if err := yaml.Unmarshal(data, &zf); err != nil {
		return nil, fmt.Errorf("parse YAML: %w", err)
	}

	// Create zone
	zone := New(zf.Zone.Name)

	// Parse default TTL
	defaultTTL := cfg.DefaultTTL
	if zf.Zone.TTL != "" {
		if ttl, err := parseDuration(zf.Zone.TTL); err == nil {
			defaultTTL = uint32(ttl.Seconds())
		}
	}

	// Parse SOA
	soa, err := parseSOA(&zf, zone.Origin, defaultTTL)
	if err != nil {
		return nil, fmt.Errorf("parse SOA: %w", err)
	}
	zone.AddRecord(soa)

	// Parse records
	for owner, section := range zf.Records {
		recordTTL := defaultTTL
		if section.TTL > 0 {
			recordTTL = uint32(section.TTL)
		}

		fqdn := zone.fullyQualify(owner)

		// Parse each record type
		if err := parseARecords(zone, fqdn, section.A, recordTTL); err != nil {
			return nil, fmt.Errorf("parse A records for %s: %w", owner, err)
		}
		if err := parseAAAARecords(zone, fqdn, section.AAAA, recordTTL); err != nil {
			return nil, fmt.Errorf("parse AAAA records for %s: %w", owner, err)
		}
		if section.CNAME != "" {
			if err := parseCNAME(zone, fqdn, section.CNAME, recordTTL); err != nil {
				return nil, fmt.Errorf("parse CNAME for %s: %w", owner, err)
			}
		}
		if err := parseMXRecords(zone, fqdn, section.MX, recordTTL); err != nil {
			return nil, fmt.Errorf("parse MX records for %s: %w", owner, err)
		}
		if err := parseNSRecords(zone, fqdn, section.NS, recordTTL); err != nil {
			return nil, fmt.Errorf("parse NS records for %s: %w", owner, err)
		}
		if err := parseTXTRecords(zone, fqdn, section.TXT, recordTTL); err != nil {
			return nil, fmt.Errorf("parse TXT records for %s: %w", owner, err)
		}
		if err := parseSRVRecords(zone, fqdn, section.SRV, recordTTL); err != nil {
			return nil, fmt.Errorf("parse SRV records for %s: %w", owner, err)
		}
		if section.PTR != "" {
			if err := parsePTR(zone, fqdn, section.PTR, recordTTL); err != nil {
				return nil, fmt.Errorf("parse PTR for %s: %w", owner, err)
			}
		}
		if err := parseCAARecords(zone, fqdn, section.CAA, recordTTL); err != nil {
			return nil, fmt.Errorf("parse CAA records for %s: %w", owner, err)
		}
		if err := parseTLSARecords(zone, fqdn, section.TLSA, recordTTL); err != nil {
			return nil, fmt.Errorf("parse TLSA records for %s: %w", owner, err)
		}
		if err := parseSVCBHTTPRecords(zone, fqdn, section.HTTPS, recordTTL, "HTTPS"); err != nil {
			return nil, fmt.Errorf("parse HTTPS records for %s: %w", owner, err)
		}
		if err := parseSVCBHTTPRecords(zone, fqdn, section.SVCB, recordTTL, "SVCB"); err != nil {
			return nil, fmt.Errorf("parse SVCB records for %s: %w", owner, err)
		}
	}

	// Apply templates
	if err := applyTemplates(zone, &zf, defaultTTL); err != nil {
		return nil, fmt.Errorf("apply templates: %w", err)
	}

	// Parse DNSSEC config
	if zf.DNSSEC != nil && zf.DNSSEC.Enabled {
		zone.DNSSEC = &DNSSECConfig{
			Enabled: true,
		}
		if zf.DNSSEC.Algorithm != "" {
			zone.DNSSEC.Algorithm = dnssecAlgorithm(zf.DNSSEC.Algorithm)
		}
	}

	// Validate zone
	if cfg.Strict {
		if err := zone.Validate(); err != nil {
			return nil, fmt.Errorf("validation failed: %w", err)
		}
	}

	return zone, nil
}

// parseSOA creates an SOA record from the YAML structure
func parseSOA(zf *DNSZoneFile, origin string, defaultTTL uint32) (*dns.SOA, error) {
	soa := &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   origin,
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    defaultTTL,
		},
		Ns:   dns.Fqdn(zf.SOA.PrimaryNS),
		Mbox: formatEmailAddress(zf.SOA.Contact),
	}

	// Parse serial
	if zf.SOA.Serial == "auto" {
		// Generate serial: YYYYMMDD00
		today := time.Now().Format("20060102")
		fmt.Sscanf(today+"00", "%d", &soa.Serial)
	} else {
		var serial uint64
		fmt.Sscanf(zf.SOA.Serial, "%d", &serial)
		soa.Serial = uint32(serial)
	}

	// Parse timing values
	var err error
	if soa.Refresh, err = parseTime(zf.SOA.Refresh); err != nil {
		return nil, fmt.Errorf("invalid refresh: %w", err)
	}
	if soa.Retry, err = parseTime(zf.SOA.Retry); err != nil {
		return nil, fmt.Errorf("invalid retry: %w", err)
	}
	if soa.Expire, err = parseTime(zf.SOA.Expire); err != nil {
		return nil, fmt.Errorf("invalid expire: %w", err)
	}
	if soa.Minttl, err = parseTime(zf.SOA.NegativeTTL); err != nil {
		return nil, fmt.Errorf("invalid negative_ttl: %w", err)
	}

	return soa, nil
}

// parseARecords parses A records (IPv4)
func parseARecords(zone *Zone, owner string, data interface{}, ttl uint32) error {
	if data == nil {
		return nil
	}

	ips := []string{}
	switch v := data.(type) {
	case string:
		ips = append(ips, v)
	case []interface{}:
		for _, ip := range v {
			if ipStr, ok := ip.(string); ok {
				ips = append(ips, ipStr)
			}
		}
	default:
		return fmt.Errorf("invalid A record format")
	}

	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil || ip.To4() == nil {
			return fmt.Errorf("invalid IPv4 address: %s", ipStr)
		}

		rr := &dns.A{
			Hdr: dns.RR_Header{
				Name:   owner,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    ttl,
			},
			A: ip.To4(),
		}
		zone.AddRecord(rr)
	}

	return nil
}

// parseAAAARecords parses AAAA records (IPv6)
func parseAAAARecords(zone *Zone, owner string, data interface{}, ttl uint32) error {
	if data == nil {
		return nil
	}

	ips := []string{}
	switch v := data.(type) {
	case string:
		ips = append(ips, v)
	case []interface{}:
		for _, ip := range v {
			if ipStr, ok := ip.(string); ok {
				ips = append(ips, ipStr)
			}
		}
	default:
		return fmt.Errorf("invalid AAAA record format")
	}

	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil || ip.To16() == nil {
			return fmt.Errorf("invalid IPv6 address: %s", ipStr)
		}

		rr := &dns.AAAA{
			Hdr: dns.RR_Header{
				Name:   owner,
				Rrtype: dns.TypeAAAA,
				Class:  dns.ClassINET,
				Ttl:    ttl,
			},
			AAAA: ip.To16(),
		}
		zone.AddRecord(rr)
	}

	return nil
}

// parseCNAME parses a CNAME record
func parseCNAME(zone *Zone, owner, target string, ttl uint32) error {
	rr := &dns.CNAME{
		Hdr: dns.RR_Header{
			Name:   owner,
			Rrtype: dns.TypeCNAME,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		},
		Target: dns.Fqdn(target),
	}
	return zone.AddRecord(rr)
}

// parseMXRecords parses MX records
func parseMXRecords(zone *Zone, owner string, data interface{}, ttl uint32) error {
	if data == nil {
		return nil
	}

	mxList := []MXRecord{}
	switch v := data.(type) {
	case []interface{}:
		for _, item := range v {
			if mxMap, ok := item.(map[string]interface{}); ok {
				mx := MXRecord{}
				if priority, ok := mxMap["priority"].(int); ok {
					mx.Priority = priority
				}
				if target, ok := mxMap["target"].(string); ok {
					mx.Target = target
				}
				mxList = append(mxList, mx)
			}
		}
	default:
		return fmt.Errorf("invalid MX record format")
	}

	for _, mx := range mxList {
		rr := &dns.MX{
			Hdr: dns.RR_Header{
				Name:   owner,
				Rrtype: dns.TypeMX,
				Class:  dns.ClassINET,
				Ttl:    ttl,
			},
			Preference: uint16(mx.Priority),
			Mx:         dns.Fqdn(mx.Target),
		}
		zone.AddRecord(rr)
	}

	return nil
}

// parseNSRecords parses NS records
func parseNSRecords(zone *Zone, owner string, data interface{}, ttl uint32) error {
	if data == nil {
		return nil
	}

	nameservers := []string{}
	switch v := data.(type) {
	case string:
		nameservers = append(nameservers, v)
	case []interface{}:
		for _, ns := range v {
			if nsStr, ok := ns.(string); ok {
				nameservers = append(nameservers, nsStr)
			}
		}
	default:
		return fmt.Errorf("invalid NS record format")
	}

	for _, ns := range nameservers {
		rr := &dns.NS{
			Hdr: dns.RR_Header{
				Name:   owner,
				Rrtype: dns.TypeNS,
				Class:  dns.ClassINET,
				Ttl:    ttl,
			},
			Ns: dns.Fqdn(ns),
		}
		zone.AddRecord(rr)
	}

	return nil
}

// parseTXTRecords parses TXT records
func parseTXTRecords(zone *Zone, owner string, data interface{}, ttl uint32) error {
	if data == nil {
		return nil
	}

	txtRecords := []string{}
	switch v := data.(type) {
	case string:
		txtRecords = append(txtRecords, v)
	case []interface{}:
		for _, txt := range v {
			if txtStr, ok := txt.(string); ok {
				txtRecords = append(txtRecords, txtStr)
			}
		}
	default:
		return fmt.Errorf("invalid TXT record format")
	}

	for _, txt := range txtRecords {
		rr := &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   owner,
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    ttl,
			},
			Txt: []string{txt},
		}
		zone.AddRecord(rr)
	}

	return nil
}

// parseSRVRecords parses SRV records
func parseSRVRecords(zone *Zone, owner string, data interface{}, ttl uint32) error {
	if data == nil {
		return nil
	}

	srvList := []SRVRecord{}
	switch v := data.(type) {
	case []interface{}:
		for _, item := range v {
			if srvMap, ok := item.(map[string]interface{}); ok {
				srv := SRVRecord{}
				if priority, ok := srvMap["priority"].(int); ok {
					srv.Priority = priority
				}
				if weight, ok := srvMap["weight"].(int); ok {
					srv.Weight = weight
				}
				if port, ok := srvMap["port"].(int); ok {
					srv.Port = port
				}
				if target, ok := srvMap["target"].(string); ok {
					srv.Target = target
				}
				srvList = append(srvList, srv)
			}
		}
	default:
		return fmt.Errorf("invalid SRV record format")
	}

	for _, srv := range srvList {
		rr := &dns.SRV{
			Hdr: dns.RR_Header{
				Name:   owner,
				Rrtype: dns.TypeSRV,
				Class:  dns.ClassINET,
				Ttl:    ttl,
			},
			Priority: uint16(srv.Priority),
			Weight:   uint16(srv.Weight),
			Port:     uint16(srv.Port),
			Target:   dns.Fqdn(srv.Target),
		}
		zone.AddRecord(rr)
	}

	return nil
}

// parsePTR parses a PTR record
func parsePTR(zone *Zone, owner, target string, ttl uint32) error {
	rr := &dns.PTR{
		Hdr: dns.RR_Header{
			Name:   owner,
			Rrtype: dns.TypePTR,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		},
		Ptr: dns.Fqdn(target),
	}
	return zone.AddRecord(rr)
}

// parseCAARecords parses CAA records
func parseCAARecords(zone *Zone, owner string, data interface{}, ttl uint32) error {
	if data == nil {
		return nil
	}

	caaList := []CAARecord{}
	switch v := data.(type) {
	case []interface{}:
		for _, item := range v {
			if caaMap, ok := item.(map[string]interface{}); ok {
				caa := CAARecord{}
				// Handle both int and float64 (YAML parser uses float64 for ints sometimes)
				if flags, ok := caaMap["flags"].(int); ok {
					caa.Flags = flags
				} else if flagsF, ok := caaMap["flags"].(float64); ok {
                    caa.Flags = int(flagsF)
                }
				if tag, ok := caaMap["tag"].(string); ok {
					caa.Tag = tag
				}
				if value, ok := caaMap["value"].(string); ok {
					caa.Value = value
				}
				caaList = append(caaList, caa)
			}
		}
	default:
		return fmt.Errorf("invalid CAA record format")
	}

	for _, caa := range caaList {
		s := fmt.Sprintf("%s %d IN CAA %d %s \"%s\"", owner, ttl, caa.Flags, caa.Tag, caa.Value)
		rr, err := dns.NewRR(s)
		if err != nil {
			return fmt.Errorf("failed to parse CAA string: %w", err)
		}
		if rr != nil {
		    zone.AddRecord(rr)
        }
	}
	return nil
}

// parseTLSARecords parses TLSA records
func parseTLSARecords(zone *Zone, owner string, data interface{}, ttl uint32) error {
	if data == nil {
		return nil
	}

	tlsaList := []TLSARecord{}
	switch v := data.(type) {
	case []interface{}:
		for _, item := range v {
			if tlsaMap, ok := item.(map[string]interface{}); ok {
				tlsa := TLSARecord{}
				if usage, ok := tlsaMap["usage"].(int); ok {
					tlsa.Usage = usage
				} else if usageF, ok := tlsaMap["usage"].(float64); ok {
                    tlsa.Usage = int(usageF)
                }
				if selector, ok := tlsaMap["selector"].(int); ok {
					tlsa.Selector = selector
				} else if selectorF, ok := tlsaMap["selector"].(float64); ok {
                    tlsa.Selector = int(selectorF)
                }
				if matching, ok := tlsaMap["matching"].(int); ok {
					tlsa.Matching = matching
				} else if matchingF, ok := tlsaMap["matching"].(float64); ok {
                    tlsa.Matching = int(matchingF)
                }
				if d, ok := tlsaMap["data"].(string); ok {
					tlsa.Data = d
				}
				tlsaList = append(tlsaList, tlsa)
			}
		}
	default:
		return fmt.Errorf("invalid TLSA record format")
	}

	for _, tlsa := range tlsaList {
		s := fmt.Sprintf("%s %d IN TLSA %d %d %d %s", owner, ttl, tlsa.Usage, tlsa.Selector, tlsa.Matching, tlsa.Data)
		rr, err := dns.NewRR(s)
		if err != nil {
			return fmt.Errorf("failed to parse TLSA string: %w", err)
		}
		if rr != nil {
		    zone.AddRecord(rr)
        }
	}
	return nil
}

// parseSVCBHTTPRecords parses SVCB or HTTPS records
func parseSVCBHTTPRecords(zone *Zone, owner string, data interface{}, ttl uint32, recType string) error {
	if data == nil {
		return nil
	}

	recList := []HTTPSRecord{}
	switch v := data.(type) {
	case []interface{}:
		for _, item := range v {
			if recMap, ok := item.(map[string]interface{}); ok {
				rec := HTTPSRecord{}
				if priority, ok := recMap["priority"].(int); ok {
					rec.Priority = priority
				} else if priorityF, ok := recMap["priority"].(float64); ok {
                    rec.Priority = int(priorityF)
                }
				if target, ok := recMap["target"].(string); ok {
					rec.Target = target
				}
				if params, ok := recMap["params"].(map[string]interface{}); ok {
					rec.Params = params
				}
				recList = append(recList, rec)
			}
		}
	default:
		return fmt.Errorf("invalid %s record format", recType)
	}

	for _, rec := range recList {
		var paramsStr strings.Builder
		for k, v := range rec.Params {
			paramsStr.WriteString(" ")
			paramsStr.WriteString(k)
			paramsStr.WriteString("=")
			switch val := v.(type) {
			case []interface{}:
				paramsStr.WriteString("\"")
				for i, elem := range val {
					if i > 0 {
						paramsStr.WriteString(",")
					}
					paramsStr.WriteString(fmt.Sprintf("%v", elem))
				}
				paramsStr.WriteString("\"")
			case string:
				paramsStr.WriteString(fmt.Sprintf("\"%s\"", val))
			default:
				paramsStr.WriteString(fmt.Sprintf("\"%v\"", val))
			}
		}

		s := fmt.Sprintf("%s %d IN %s %d %s%s", owner, ttl, recType, rec.Priority, dns.Fqdn(rec.Target), paramsStr.String())
		rr, err := dns.NewRR(s)
		if err != nil {
			return fmt.Errorf("failed to parse %s string: %w: %s", recType, err, s)
		}
		if rr != nil {
		    zone.AddRecord(rr)
        }
	}
	return nil
}

// applyTemplates applies templates to generate records
func applyTemplates(zone *Zone, zf *DNSZoneFile, defaultTTL uint32) error {
	// Template application not yet implemented
	// Would need variable substitution and template expansion
	return nil
}

// Helper functions

// parseDuration parses a duration string like "1h", "30m", "1d"
func parseDuration(s string) (time.Duration, error) {
	// Support custom suffixes
	s = strings.TrimSpace(s)
	if strings.HasSuffix(s, "d") {
		days, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil {
			return 0, err
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	if strings.HasSuffix(s, "w") {
		weeks, err := strconv.Atoi(strings.TrimSuffix(s, "w"))
		if err != nil {
			return 0, err
		}
		return time.Duration(weeks) * 7 * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}

// parseTime parses a time value (supports "1h", "30m", or raw seconds)
func parseTime(s string) (uint32, error) {
	if d, err := parseDuration(s); err == nil {
		return uint32(d.Seconds()), nil
	}
	// Try as raw number
	var seconds uint64
	if _, err := fmt.Sscanf(s, "%d", &seconds); err == nil {
		return uint32(seconds), nil
	}
	return 0, fmt.Errorf("invalid time format: %s", s)
}

// formatEmailAddress converts email to DNS format (replace @ with .)
func formatEmailAddress(email string) string {
	email = strings.ReplaceAll(email, "@", ".")
	return dns.Fqdn(email)
}

// dnssecAlgorithm converts algorithm name to number
func dnssecAlgorithm(name string) uint8 {
	switch strings.ToUpper(name) {
	case "RSASHA256":
		return dns.RSASHA256
	case "RSASHA512":
		return dns.RSASHA512
	case "ECDSAP256SHA256":
		return dns.ECDSAP256SHA256
	case "ECDSAP384SHA384":
		return dns.ECDSAP384SHA384
	case "ED25519":
		return dns.ED25519
	default:
		return dns.ECDSAP256SHA256 // Default
	}
}
