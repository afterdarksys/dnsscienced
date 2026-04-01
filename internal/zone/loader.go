package zone

import (
	"fmt"
	"os"
	"time"

	"github.com/miekg/dns"
	"google.golang.org/protobuf/proto"
)

// LoadCompiledZone loads a compiled zone from a .dzc file
func LoadCompiledZone(path string) (*Zone, error) {
	// Read file
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	// Unmarshal protobuf
	compiled := &CompiledZone{}
	if err := proto.Unmarshal(data, compiled); err != nil {
		return nil, fmt.Errorf("unmarshal protobuf: %w", err)
	}

	// Verify format version
	if compiled.Metadata != nil && compiled.Metadata.FormatVersion != CompiledZoneFormatVersion {
		return nil, fmt.Errorf("unsupported format version: %d (expected %d)",
			compiled.Metadata.FormatVersion, CompiledZoneFormatVersion)
	}

	// Create zone
	zone := &Zone{
		Name:    compiled.Name,
		Origin:  compiled.Origin,
		Class:   uint16(compiled.Class),
		Records: make(map[string]map[uint16][]dns.RR),
	}

	// Load SOA
	if compiled.Soa == nil {
		return nil, fmt.Errorf("compiled zone missing SOA record")
	}
	zone.SOA = loadSOA(compiled.Soa, zone.Origin)

	// Add SOA to records
	if err := zone.AddRecord(zone.SOA); err != nil {
		return nil, fmt.Errorf("add SOA record: %w", err)
	}

	// Load all records
	for owner, recordSet := range compiled.Records {
		if recordSet == nil || recordSet.Records == nil {
			continue
		}

		for _, recordList := range recordSet.Records {
			if recordList == nil || recordList.Records == nil {
				continue
			}

			for _, record := range recordList.Records {
				rr, err := loadRecord(record)
				if err != nil {
					return nil, fmt.Errorf("load record %s: %w", owner, err)
				}

				if err := zone.AddRecord(rr); err != nil {
					return nil, fmt.Errorf("add record %s: %w", owner, err)
				}
			}
		}
	}

	// Load DNSSEC config
	if compiled.Dnssec != nil {
		zone.DNSSEC = loadDNSSEC(compiled.Dnssec)
	}

	return zone, nil
}

// loadSOA converts protobuf SOA to dns.SOA
func loadSOA(soa *SOARecord, origin string) *dns.SOA {
	return &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   origin,
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    soa.Ttl,
		},
		Ns:     soa.PrimaryNs,
		Mbox:   soa.AdminEmail,
		Serial: soa.Serial,
		Refresh: soa.Refresh,
		Retry:  soa.Retry,
		Expire: soa.Expire,
		Minttl: soa.MinimumTtl,
	}
}

// loadRecord converts protobuf Record to dns.RR
func loadRecord(record *Record) (dns.RR, error) {
	if record == nil || len(record.Rdata) == 0 {
		return nil, fmt.Errorf("empty record")
	}

	// Unpack from wire format
	rr, _, err := dns.UnpackRR(record.Rdata, 0)
	if err != nil {
		return nil, fmt.Errorf("unpack RR: %w", err)
	}

	return rr, nil
}

// loadDNSSEC converts protobuf DNSSEC config to zone DNSSEC config
func loadDNSSEC(compiled *CompiledDNSSECConfig) *DNSSECConfig {
	cfg := &DNSSECConfig{
		Enabled:     compiled.Enabled,
		Algorithm:   uint8(compiled.Algorithm),
		KSKLifetime: time.Duration(compiled.KskLifetimeSeconds) * time.Second,
		ZSKLifetime: time.Duration(compiled.ZskLifetimeSeconds) * time.Second,
	}

	if compiled.Nsec3 != nil && compiled.Nsec3.Enabled {
		cfg.NSEC3Enabled = true
		cfg.NSEC3Iterations = uint16(compiled.Nsec3.Iterations)
		cfg.NSEC3SaltLength = uint8(compiled.Nsec3.SaltLength)
	}

	return cfg
}

// IsCompiledZone checks if a file is a compiled zone
func IsCompiledZone(path string) bool {
	// Quick check: read first few bytes and try to parse as protobuf
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}

	compiled := &CompiledZone{}
	err = proto.Unmarshal(data, compiled)
	return err == nil && compiled.Metadata != nil && compiled.Metadata.FormatVersion == CompiledZoneFormatVersion
}

// GetCompiledZoneInfo returns metadata about a compiled zone without fully loading it
func GetCompiledZoneInfo(path string) (*CompilationMeta, *ZoneStats, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read file: %w", err)
	}

	compiled := &CompiledZone{}
	if err := proto.Unmarshal(data, compiled); err != nil {
		return nil, nil, fmt.Errorf("unmarshal protobuf: %w", err)
	}

	return compiled.Metadata, compiled.Stats, nil
}
