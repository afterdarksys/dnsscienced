package zone

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/miekg/dns"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	// CompiledZoneFormatVersion is the current format version
	CompiledZoneFormatVersion = 1

	// CompiledZoneExtension is the file extension for compiled zones
	CompiledZoneExtension = ".dzc"
)

// CompileOptions contains options for zone compilation
type CompileOptions struct {
	// SourceFile is the original zone file path
	SourceFile string

	// OutputFile is the compiled zone output path (optional, defaults to source + .dzc)
	OutputFile string

	// SourceFormat is the format of the source file ("dnszone", "bind", etc.)
	SourceFormat string

	// Compress enables protobuf compression
	Compress bool

	// IncludeTextRepr includes human-readable text representation of records
	IncludeTextRepr bool
}

// CompileZone compiles a zone from text format to binary format
func CompileZone(z *Zone, opts CompileOptions) (*CompiledZone, error) {
	if z == nil {
		return nil, fmt.Errorf("nil zone")
	}

	// Validate zone first
	if err := z.Validate(); err != nil {
		return nil, fmt.Errorf("zone validation failed: %w", err)
	}

	// Create compiled zone
	compiled := &CompiledZone{
		Name:   z.Name,
		Origin: z.Origin,
		Class:  uint32(z.Class),
	}

	// Compile SOA record
	if z.SOA == nil {
		return nil, fmt.Errorf("zone missing SOA record")
	}
	compiled.Soa = compileSOA(z.SOA)

	// Compile all records
	compiled.Records = make(map[string]*RecordSet)
	ownerIndex := make([]string, 0, len(z.Records))

	for owner, typeMap := range z.Records {
		ownerIndex = append(ownerIndex, owner)

		recordSet := &RecordSet{
			Records: make(map[string]*RecordList),
		}

		for rrtype, records := range typeMap {
			// SOA is stored separately in compiled.Soa; skip it here to avoid
			// the loader having to deduplicate it on every load.
			if rrtype == dns.TypeSOA {
				continue
			}

			recordList := &RecordList{
				Records: make([]*Record, 0, len(records)),
			}

			for _, rr := range records {
				record, err := compileRecord(rr, opts.IncludeTextRepr)
				if err != nil {
					return nil, fmt.Errorf("compile record %s: %w", rr.Header().Name, err)
				}
				recordList.Records = append(recordList.Records, record)
			}

			// Use string key for protobuf map
			typeKey := fmt.Sprintf("%d", rrtype)
			recordSet.Records[typeKey] = recordList
		}

		compiled.Records[owner] = recordSet
	}

	// Sort owner index for binary search
	compiled.OwnerIndex = ownerIndex

	// Compile DNSSEC config
	if z.DNSSEC != nil {
		compiled.Dnssec = compileDNSSEC(z.DNSSEC)
	}

	// Compute statistics
	compiled.Stats = computeStats(z, compiled)

	// Add compilation metadata
	compiled.Metadata = &CompilationMeta{
		FormatVersion:    CompiledZoneFormatVersion,
		SourceFile:       opts.SourceFile,
		SourceFormat:     opts.SourceFormat,
		CompiledAt:       timestamppb.Now(),
		CompilerVersion:  getCompilerVersion(),
	}

	// Compute source file hash if available
	if opts.SourceFile != "" {
		hash, mtime, err := computeFileHash(opts.SourceFile)
		if err == nil {
			compiled.Metadata.SourceSha256 = hash
			compiled.Metadata.SourceModifiedAt = timestamppb.New(mtime)
		}
	}

	return compiled, nil
}

// compileSOA converts a dns.SOA to our protobuf format
func compileSOA(soa *dns.SOA) *SOARecord {
	return &SOARecord{
		PrimaryNs:   soa.Ns,
		AdminEmail:  soa.Mbox,
		Serial:      soa.Serial,
		Refresh:     soa.Refresh,
		Retry:       soa.Retry,
		Expire:      soa.Expire,
		MinimumTtl:  soa.Minttl,
		Ttl:         soa.Header().Ttl,
	}
}

// compileRecord converts a dns.RR to our protobuf Record format
func compileRecord(rr dns.RR, includeText bool) (*Record, error) {
	hdr := rr.Header()

	// Pack record to wire format
	wireData := make([]byte, dns.MaxMsgSize)
	off, err := dns.PackRR(rr, wireData, 0, nil, false)
	if err != nil {
		return nil, fmt.Errorf("pack RR: %w", err)
	}

	record := &Record{
		Name:  hdr.Name,
		Type:  uint32(hdr.Rrtype),
		Class: uint32(hdr.Class),
		Ttl:   hdr.Ttl,
		Rdata: wireData[:off],
	}

	if includeText {
		record.Text = rr.String()
	}

	return record, nil
}

// compileDNSSEC converts DNSSEC config to protobuf format
func compileDNSSEC(dnssec *DNSSECConfig) *CompiledDNSSECConfig {
	cfg := &CompiledDNSSECConfig{
		Enabled:            dnssec.Enabled,
		Algorithm:          uint32(dnssec.Algorithm),
		KskLifetimeSeconds: uint64(dnssec.KSKLifetime.Seconds()),
		ZskLifetimeSeconds: uint64(dnssec.ZSKLifetime.Seconds()),
	}

	if dnssec.NSEC3Enabled {
		cfg.Nsec3 = &NSEC3Params{
			Enabled:    true,
			Iterations: uint32(dnssec.NSEC3Iterations),
			SaltLength: uint32(dnssec.NSEC3SaltLength),
		}
	}

	return cfg
}

// computeStats calculates zone statistics
func computeStats(z *Zone, compiled *CompiledZone) *ZoneStats {
	stats := &ZoneStats{
		UniqueOwners: uint32(len(z.Records)),
		TypeCounts:   make(map[string]uint32),
	}

	recordSets := uint32(0)
	totalRecords := uint32(0)

	for _, typeMap := range z.Records {
		for rrtype, records := range typeMap {
			recordSets++
			count := len(records)
			totalRecords += uint32(count)

			// Track by type
			typeName := dns.TypeToString[rrtype]
			stats.TypeCounts[typeName] = stats.TypeCounts[typeName] + uint32(count)
		}
	}

	stats.RecordSets = recordSets
	stats.TotalRecords = totalRecords

	return stats
}

// WriteCompiledZone writes a compiled zone to disk
func WriteCompiledZone(compiled *CompiledZone, outputPath string) error {
	// Marshal to protobuf
	data, err := proto.Marshal(compiled)
	if err != nil {
		return fmt.Errorf("marshal protobuf: %w", err)
	}

	// Update size in stats
	if compiled.Stats != nil {
		compiled.Stats.SizeBytes = uint64(len(data))
	}

	// Write to file
	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return fmt.Errorf("write file: %w", err)
	}

	return nil
}

// CompileAndWrite is a convenience function that compiles and writes a zone
func CompileAndWrite(z *Zone, opts CompileOptions) (string, error) {
	// Determine output file
	outputFile := opts.OutputFile
	if outputFile == "" && opts.SourceFile != "" {
		// Replace extension with .dzc
		base := strings.TrimSuffix(opts.SourceFile, filepath.Ext(opts.SourceFile))
		outputFile = base + CompiledZoneExtension
	}
	if outputFile == "" {
		outputFile = z.Name + CompiledZoneExtension
	}

	// Compile zone
	compiled, err := CompileZone(z, opts)
	if err != nil {
		return "", fmt.Errorf("compile zone: %w", err)
	}

	// Write to disk
	if err := WriteCompiledZone(compiled, outputFile); err != nil {
		return "", fmt.Errorf("write compiled zone: %w", err)
	}

	return outputFile, nil
}

// Helper functions

// computeFileHash computes SHA-256 hash and modification time of a file
func computeFileHash(path string) ([]byte, time.Time, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, time.Time{}, err
	}

	stat, err := os.Stat(path)
	if err != nil {
		return nil, time.Time{}, err
	}

	hash := sha256.Sum256(data)
	return hash[:], stat.ModTime(), nil
}

// getCompilerVersion returns the dnsscienced version
func getCompilerVersion() string {
	// TODO: Get from build-time variable
	return "dev"
}
