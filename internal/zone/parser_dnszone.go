package zone

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
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
	Includes  []string                  `yaml:"includes,omitempty"`
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

// OldSOASection holds SOA fields from the legacy zone format.
type OldSOASection struct {
	Primary string `yaml:"primary"`
	Admin   string `yaml:"admin"`
	Serial  int    `yaml:"serial"`
	Refresh int    `yaml:"refresh"`
	Retry   int    `yaml:"retry"`
	Expire  int    `yaml:"expire"`
	Minimum int    `yaml:"minimum"`
}

// OldDNSZoneFile represents the legacy .dnszone format where zone: is a plain
// string and SOA uses different field names (primary/admin/minimum).
type OldDNSZoneFile struct {
	Zone        string                    `yaml:"zone"`
	Serial      int                       `yaml:"serial,omitempty"`
	TTL         int                       `yaml:"ttl,omitempty"`
	SOA         OldSOASection             `yaml:"soa"`
	Nameservers []string                  `yaml:"nameservers,omitempty"`
	Includes    []string                  `yaml:"includes,omitempty"`
	Records     map[string]RecordSection  `yaml:"records"`
	Templates   map[string]TemplateSection `yaml:"templates,omitempty"`
	Apply       []ApplySection            `yaml:"apply,omitempty"`
	DNSSEC      *DNSSECSection            `yaml:"dnssec,omitempty"`
}

// convertOldFormat converts a legacy OldDNSZoneFile to the current DNSZoneFile.
func convertOldFormat(ozf OldDNSZoneFile) DNSZoneFile {
	serial := ozf.SOA.Serial
	if serial == 0 {
		serial = ozf.Serial
	}

	zf := DNSZoneFile{
		Zone: ZoneSection{
			Name: ozf.Zone,
		},
		SOA: SOASection{
			PrimaryNS:   ozf.SOA.Primary,
			Contact:     ozf.SOA.Admin,
			Serial:      strconv.Itoa(serial),
			Refresh:     strconv.Itoa(ozf.SOA.Refresh),
			Retry:       strconv.Itoa(ozf.SOA.Retry),
			Expire:      strconv.Itoa(ozf.SOA.Expire),
			NegativeTTL: strconv.Itoa(ozf.SOA.Minimum),
		},
		Includes:  ozf.Includes,
		Records:   ozf.Records,
		Templates: ozf.Templates,
		Apply:     ozf.Apply,
		DNSSEC:    ozf.DNSSEC,
	}

	if ozf.TTL > 0 {
		zf.Zone.TTL = strconv.Itoa(ozf.TTL) + "s"
	}

	// Inject nameservers list as NS records at the zone apex.
	if len(ozf.Nameservers) > 0 {
		if zf.Records == nil {
			zf.Records = make(map[string]RecordSection)
		}
		apex := zf.Records["@"]
		nsList := make([]interface{}, len(ozf.Nameservers))
		for i, ns := range ozf.Nameservers {
			nsList[i] = ns
		}
		apex.NS = nsList
		zf.Records["@"] = apex
	}

	return zf
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
	SSHFP  interface{} `yaml:"SSHFP,omitempty"`
	NAPTR  interface{} `yaml:"NAPTR,omitempty"`
	SMIMEA interface{} `yaml:"SMIMEA,omitempty"`
	LOC    interface{} `yaml:"LOC,omitempty"`

	// Generic type support (TYPE### syntax)
	// Key is type code (e.g., "TYPE257" for CAA)
	// Value is the rdata string
	Generic map[string]interface{} `yaml:",inline"`

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

// SSHFPRecord represents an SSHFP record (RFC 4255)
type SSHFPRecord struct {
	Algorithm       int    `yaml:"algorithm"`        // 1=RSA, 2=DSA, 3=ECDSA, 4=Ed25519
	FingerprintType int    `yaml:"fingerprint_type"` // 1=SHA-1, 2=SHA-256
	Fingerprint     string `yaml:"fingerprint"`
}

// NAPTRRecord represents a NAPTR record (RFC 3403)
type NAPTRRecord struct {
	Order       int    `yaml:"order"`
	Preference  int    `yaml:"preference"`
	Flags       string `yaml:"flags"`
	Service     string `yaml:"service"`
	Regexp      string `yaml:"regexp,omitempty"`
	Replacement string `yaml:"replacement"`
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

	// Parse YAML — try current format first, fall back to legacy format.
	var zf DNSZoneFile
	if err := yaml.Unmarshal(data, &zf); err != nil {
		var ozf OldDNSZoneFile
		if err2 := yaml.Unmarshal(data, &ozf); err2 != nil {
			return nil, fmt.Errorf("parse YAML: %w", err)
		}
		zf = convertOldFormat(ozf)
	}

	// Create zone
	zone := New(zf.Zone.Name)

	// Parse default TTL — use parseTime so raw seconds (e.g. 300) and duration
	// strings (e.g. "5m") are both accepted.
	defaultTTL := cfg.DefaultTTL
	if zf.Zone.TTL != "" {
		if ttl, err := parseTime(zf.Zone.TTL); err == nil {
			defaultTTL = ttl
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
		if err := parseSSHFPRecords(zone, fqdn, section.SSHFP, recordTTL); err != nil {
			return nil, fmt.Errorf("parse SSHFP records for %s: %w", owner, err)
		}
		if err := parseNAPTRRecords(zone, fqdn, section.NAPTR, recordTTL); err != nil {
			return nil, fmt.Errorf("parse NAPTR records for %s: %w", owner, err)
		}
		if err := parseSMIMEARecords(zone, fqdn, section.SMIMEA, recordTTL); err != nil {
			return nil, fmt.Errorf("parse SMIMEA records for %s: %w", owner, err)
		}
		if err := parseLOCRecords(zone, fqdn, section.LOC, recordTTL); err != nil {
			return nil, fmt.Errorf("parse LOC records for %s: %w", owner, err)
		}

		// Parse generic TYPE### records (defensive DNS feature)
		if err := parseGenericTypes(zone, fqdn, section.Generic, recordTTL); err != nil {
			return nil, fmt.Errorf("parse generic types for %s: %w", owner, err)
		}
	}

	// Process includes
	if len(zf.Includes) > 0 {
		baseDir := filepath.Clean(filepath.Dir(filename))
		for _, inc := range zf.Includes {
			// Reject absolute paths: they bypass the join/clean pipeline and
			// could reference files anywhere on the filesystem.
			if filepath.IsAbs(inc) {
				return nil, fmt.Errorf("include %q: absolute paths are not allowed", inc)
			}
			incPath := filepath.Join(baseDir, inc)
			// Prevent directory traversal: the resolved include path must stay
			// within baseDir. filepath.Join already cleans ".." sequences, so
			// comparing the clean prefix is sufficient.
			cleanInc := filepath.Clean(incPath)
			if cleanInc != baseDir && !strings.HasPrefix(cleanInc, baseDir+string(filepath.Separator)) {
				return nil, fmt.Errorf("include %q: path escapes zone directory", inc)
			}
			if err := parseIncludeFile(zone, cleanInc, defaultTTL); err != nil {
				return nil, fmt.Errorf("include %q: %w", inc, err)
			}
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
		if n, err := fmt.Sscanf(zf.SOA.Serial, "%d", &serial); n != 1 || err != nil {
			return nil, fmt.Errorf("invalid SOA serial %q: expected integer", zf.SOA.Serial)
		}
		soa.Serial = uint32(serial)
	}

	// Parse timing values
	var err error
	if soa.Refresh, err = parseTime(zf.SOA.Refresh); err != nil {
		return nil, fmt.Errorf("invalid refresh: %w", err)
	}
	if soa.Refresh == 0 {
		return nil, fmt.Errorf("SOA refresh must be non-zero")
	}
	if soa.Retry, err = parseTime(zf.SOA.Retry); err != nil {
		return nil, fmt.Errorf("invalid retry: %w", err)
	}
	if soa.Retry == 0 {
		return nil, fmt.Errorf("SOA retry must be non-zero")
	}
	if soa.Expire, err = parseTime(zf.SOA.Expire); err != nil {
		return nil, fmt.Errorf("invalid expire: %w", err)
	}
	if soa.Expire == 0 {
		return nil, fmt.Errorf("SOA expire must be non-zero")
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
		// To4() returns non-nil for IPv4 addresses; reject them here so that
		// AAAA records only ever contain pure IPv6 addresses.
		if ip == nil || ip.To4() != nil {
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
				} else if priorityF, ok := mxMap["priority"].(float64); ok {
					mx.Priority = int(priorityF)
				}
				if target, ok := mxMap["target"].(string); ok {
					mx.Target = target
				} else if value, ok := mxMap["value"].(string); ok {
					mx.Target = value
				} else if host, ok := mxMap["host"].(string); ok {
					mx.Target = host
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
		// RFC 1035 limits each TXT string to 255 bytes
		// Some broken DNS providers (OCI!) violate this
		// Split oversized strings into chunks
		chunks := chunkTXTString(txt, 255)

		rr := &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   owner,
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    ttl,
			},
			Txt: chunks,
		}
		zone.AddRecord(rr)
	}

	return nil
}

// chunkTXTString splits a TXT string into RFC-compliant chunks
// RFC 1035 limits each string in a TXT record to 255 bytes
func chunkTXTString(s string, maxChunkSize int) []string {
	if len(s) <= maxChunkSize {
		return []string{s}
	}

	var chunks []string
	for len(s) > 0 {
		chunkSize := maxChunkSize
		if len(s) < chunkSize {
			chunkSize = len(s)
		}
		chunks = append(chunks, s[:chunkSize])
		s = s[chunkSize:]
	}
	return chunks
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
				} else if priorityF, ok := srvMap["priority"].(float64); ok {
					srv.Priority = int(priorityF)
				}
				if weight, ok := srvMap["weight"].(int); ok {
					srv.Weight = weight
				} else if weightF, ok := srvMap["weight"].(float64); ok {
					srv.Weight = int(weightF)
				}
				if port, ok := srvMap["port"].(int); ok {
					srv.Port = port
				} else if portF, ok := srvMap["port"].(float64); ok {
					srv.Port = int(portF)
				}
				if target, ok := srvMap["target"].(string); ok {
					srv.Target = target
				} else if value, ok := srvMap["value"].(string); ok {
					srv.Target = value
				} else if host, ok := srvMap["host"].(string); ok {
					srv.Target = host
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

// parseSSHFPRecords parses SSHFP records (RFC 4255)
func parseSSHFPRecords(zone *Zone, owner string, data interface{}, ttl uint32) error {
	if data == nil {
		return nil
	}

	sshfpList := []SSHFPRecord{}
	switch v := data.(type) {
	case []interface{}:
		for i, item := range v {
			sshfpMap, ok := item.(map[string]interface{})
			if !ok {
				return fmt.Errorf("SSHFP record item %d: expected map, got %T", i, item)
			}
			rec := SSHFPRecord{}
			if algorithm, ok := sshfpMap["algorithm"].(int); ok {
				rec.Algorithm = algorithm
			} else if algorithmF, ok := sshfpMap["algorithm"].(float64); ok {
				rec.Algorithm = int(algorithmF)
			}
			if fpType, ok := sshfpMap["fingerprint_type"].(int); ok {
				rec.FingerprintType = fpType
			} else if fpTypeF, ok := sshfpMap["fingerprint_type"].(float64); ok {
				rec.FingerprintType = int(fpTypeF)
			}
			if fp, ok := sshfpMap["fingerprint"].(string); ok {
				rec.Fingerprint = fp
			}
			sshfpList = append(sshfpList, rec)
		}
	default:
		return fmt.Errorf("invalid SSHFP record format")
	}

	for _, rec := range sshfpList {
		s := fmt.Sprintf("%s %d IN SSHFP %d %d %s", owner, ttl, rec.Algorithm, rec.FingerprintType, rec.Fingerprint)
		rr, err := dns.NewRR(s)
		if err != nil {
			return fmt.Errorf("failed to parse SSHFP string: %w", err)
		}
		if rr != nil {
			zone.AddRecord(rr)
		}
	}
	return nil
}

// parseNAPTRRecords parses NAPTR records (RFC 3403)
func parseNAPTRRecords(zone *Zone, owner string, data interface{}, ttl uint32) error {
	if data == nil {
		return nil
	}

	naptrList := []NAPTRRecord{}
	switch v := data.(type) {
	case []interface{}:
		for i, item := range v {
			naptrMap, ok := item.(map[string]interface{})
			if !ok {
				return fmt.Errorf("NAPTR record item %d: expected map, got %T", i, item)
			}
			rec := NAPTRRecord{}
			if order, ok := naptrMap["order"].(int); ok {
				rec.Order = order
			} else if orderF, ok := naptrMap["order"].(float64); ok {
				rec.Order = int(orderF)
			}
			if pref, ok := naptrMap["preference"].(int); ok {
				rec.Preference = pref
			} else if prefF, ok := naptrMap["preference"].(float64); ok {
				rec.Preference = int(prefF)
			}
			if flags, ok := naptrMap["flags"].(string); ok {
				rec.Flags = flags
			}
			if service, ok := naptrMap["service"].(string); ok {
				rec.Service = service
			}
			if regexp, ok := naptrMap["regexp"].(string); ok {
				rec.Regexp = regexp
			}
			if replacement, ok := naptrMap["replacement"].(string); ok {
				rec.Replacement = replacement
			}
			naptrList = append(naptrList, rec)
		}
	default:
		return fmt.Errorf("invalid NAPTR record format")
	}

	for _, rec := range naptrList {
		// Build the struct directly to avoid format-string injection from
		// user-controlled fields (flags, service, regexp) containing newlines.
		rr := &dns.NAPTR{
			Hdr: dns.RR_Header{
				Name:   owner,
				Rrtype: dns.TypeNAPTR,
				Class:  dns.ClassINET,
				Ttl:    ttl,
			},
			Order:       uint16(rec.Order),
			Preference:  uint16(rec.Preference),
			Flags:       rec.Flags,
			Service:     rec.Service,
			Regexp:      rec.Regexp,
			Replacement: dns.Fqdn(rec.Replacement),
		}
		zone.AddRecord(rr)
	}
	return nil
}

// parseSMIMEARecords parses SMIMEA records (RFC 8162)
// SMIMEA has the same wire format as TLSA; reuses TLSARecord for deserialization.
func parseSMIMEARecords(zone *Zone, owner string, data interface{}, ttl uint32) error {
	if data == nil {
		return nil
	}

	smimeaList := []TLSARecord{}
	switch v := data.(type) {
	case []interface{}:
		for i, item := range v {
			smimeaMap, ok := item.(map[string]interface{})
			if !ok {
				return fmt.Errorf("SMIMEA record item %d: expected map, got %T", i, item)
			}
			rec := TLSARecord{}
			if usage, ok := smimeaMap["usage"].(int); ok {
				rec.Usage = usage
			} else if usageF, ok := smimeaMap["usage"].(float64); ok {
				rec.Usage = int(usageF)
			}
			if selector, ok := smimeaMap["selector"].(int); ok {
				rec.Selector = selector
			} else if selectorF, ok := smimeaMap["selector"].(float64); ok {
				rec.Selector = int(selectorF)
			}
			if matching, ok := smimeaMap["matching"].(int); ok {
				rec.Matching = matching
			} else if matchingF, ok := smimeaMap["matching"].(float64); ok {
				rec.Matching = int(matchingF)
			}
			if d, ok := smimeaMap["data"].(string); ok {
				rec.Data = d
			}
			smimeaList = append(smimeaList, rec)
		}
	default:
		return fmt.Errorf("invalid SMIMEA record format")
	}

	for _, rec := range smimeaList {
		s := fmt.Sprintf("%s %d IN SMIMEA %d %d %d %s", owner, ttl, rec.Usage, rec.Selector, rec.Matching, rec.Data)
		rr, err := dns.NewRR(s)
		if err != nil {
			return fmt.Errorf("failed to parse SMIMEA string: %w", err)
		}
		if rr != nil {
			zone.AddRecord(rr)
		}
	}
	return nil
}

// parseLOCRecords parses LOC records (RFC 1876)
// LOC records are expressed as plain strings (e.g. "42 21 43.952 N 71 06 18.910 W 24m").
// Only list format is accepted; a single string value is an error.
func parseLOCRecords(zone *Zone, owner string, data interface{}, ttl uint32) error {
	if data == nil {
		return nil
	}

	locStrings := []string{}
	switch v := data.(type) {
	case []interface{}:
		for i, item := range v {
			locStr, ok := item.(string)
			if !ok {
				return fmt.Errorf("LOC record item %d: expected string, got %T", i, item)
			}
			locStrings = append(locStrings, locStr)
		}
	default:
		return fmt.Errorf("invalid LOC record format: LOC records must be a list of strings")
	}

	for _, locStr := range locStrings {
		s := fmt.Sprintf("%s %d IN LOC %s", owner, ttl, locStr)
		rr, err := dns.NewRR(s)
		if err != nil {
			return fmt.Errorf("failed to parse LOC string: %w", err)
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

// parseGenericTypes parses generic TYPE### syntax records
// Example: TYPE257: 0 issue "letsencrypt.org" for CAA before native support
// This provides forward compatibility with new DNS record types and supports
// legacy BIND zone files using generic syntax
func parseGenericTypes(zone *Zone, owner string, data map[string]interface{}, ttl uint32) error {
	if data == nil || len(data) == 0 {
		return nil
	}

	for key, value := range data {
		// Check if key matches TYPE### pattern
		keyUpper := strings.ToUpper(key)
		if !strings.HasPrefix(keyUpper, "TYPE") {
			continue
		}

		// Extract type code
		typeStr := strings.TrimPrefix(keyUpper, "TYPE")
		typeCode, err := strconv.Atoi(typeStr)
		if err != nil {
			continue // Not a valid TYPE### key, skip
		}

		// Validate type code range (1-65535)
		if typeCode < 1 || typeCode > 65535 {
			return fmt.Errorf("invalid TYPE code %d: must be 1-65535", typeCode)
		}

		// Handle both single value and list
		values := []string{}
		switch v := value.(type) {
		case string:
			values = append(values, v)
		case []interface{}:
			for _, item := range v {
				if str, ok := item.(string); ok {
					values = append(values, str)
				}
			}
		default:
			return fmt.Errorf("invalid TYPE%d record format: expected string or list", typeCode)
		}

		// Parse each record using dns.NewRR
		for _, rdata := range values {
			// Build RR string: owner TTL CLASS TYPE### rdata
			rrStr := fmt.Sprintf("%s %d IN TYPE%d %s", owner, ttl, typeCode, rdata)
			rr, err := dns.NewRR(rrStr)
			if err != nil {
				return fmt.Errorf("failed to parse TYPE%d: %w: %s", typeCode, err, rrStr)
			}
			if rr != nil {
				zone.AddRecord(rr)
			}
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

// parseDuration parses a duration string like "1h", "30m", "1d".
// Case-insensitive: "1H", "1M", "1D", "1W" are all accepted.
func parseDuration(s string) (time.Duration, error) {
	s = strings.ToLower(strings.TrimSpace(s))
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

// parseIncludeFile loads a partial .dnszone include file and merges its records into the zone.
// Include files only need a records: section; zone/soa/serial fields are ignored.
func parseIncludeFile(zone *Zone, filename string, defaultTTL uint32) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("read: %w", err)
	}

	var inc struct {
		Records map[string]RecordSection `yaml:"records"`
	}
	if err := yaml.Unmarshal(data, &inc); err != nil {
		return fmt.Errorf("parse YAML: %w", err)
	}

	for owner, section := range inc.Records {
		recordTTL := defaultTTL
		if section.TTL > 0 {
			recordTTL = uint32(section.TTL)
		}
		fqdn := zone.fullyQualify(owner)

		if err := parseARecords(zone, fqdn, section.A, recordTTL); err != nil {
			return fmt.Errorf("A records for %s: %w", owner, err)
		}
		if err := parseAAAARecords(zone, fqdn, section.AAAA, recordTTL); err != nil {
			return fmt.Errorf("AAAA records for %s: %w", owner, err)
		}
		if section.CNAME != "" {
			if err := parseCNAME(zone, fqdn, section.CNAME, recordTTL); err != nil {
				return fmt.Errorf("CNAME for %s: %w", owner, err)
			}
		}
		if err := parseMXRecords(zone, fqdn, section.MX, recordTTL); err != nil {
			return fmt.Errorf("MX records for %s: %w", owner, err)
		}
		if err := parseNSRecords(zone, fqdn, section.NS, recordTTL); err != nil {
			return fmt.Errorf("NS records for %s: %w", owner, err)
		}
		if err := parseTXTRecords(zone, fqdn, section.TXT, recordTTL); err != nil {
			return fmt.Errorf("TXT records for %s: %w", owner, err)
		}
		if err := parseSRVRecords(zone, fqdn, section.SRV, recordTTL); err != nil {
			return fmt.Errorf("SRV records for %s: %w", owner, err)
		}
		if section.PTR != "" {
			if err := parsePTR(zone, fqdn, section.PTR, recordTTL); err != nil {
				return fmt.Errorf("PTR for %s: %w", owner, err)
			}
		}
		if err := parseCAARecords(zone, fqdn, section.CAA, recordTTL); err != nil {
			return fmt.Errorf("CAA records for %s: %w", owner, err)
		}
		if err := parseTLSARecords(zone, fqdn, section.TLSA, recordTTL); err != nil {
			return fmt.Errorf("TLSA records for %s: %w", owner, err)
		}
		if err := parseSVCBHTTPRecords(zone, fqdn, section.HTTPS, recordTTL, "HTTPS"); err != nil {
			return fmt.Errorf("HTTPS records for %s: %w", owner, err)
		}
		if err := parseSVCBHTTPRecords(zone, fqdn, section.SVCB, recordTTL, "SVCB"); err != nil {
			return fmt.Errorf("SVCB records for %s: %w", owner, err)
		}
		if err := parseSSHFPRecords(zone, fqdn, section.SSHFP, recordTTL); err != nil {
			return fmt.Errorf("SSHFP records for %s: %w", owner, err)
		}
		if err := parseNAPTRRecords(zone, fqdn, section.NAPTR, recordTTL); err != nil {
			return fmt.Errorf("NAPTR records for %s: %w", owner, err)
		}
		if err := parseSMIMEARecords(zone, fqdn, section.SMIMEA, recordTTL); err != nil {
			return fmt.Errorf("SMIMEA records for %s: %w", owner, err)
		}
		if err := parseLOCRecords(zone, fqdn, section.LOC, recordTTL); err != nil {
			return fmt.Errorf("LOC records for %s: %w", owner, err)
		}
		if err := parseGenericTypes(zone, fqdn, section.Generic, recordTTL); err != nil {
			return fmt.Errorf("generic types for %s: %w", owner, err)
		}
	}
	return nil
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
