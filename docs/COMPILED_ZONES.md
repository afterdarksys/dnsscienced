# Compiled Zone Format (.dzc)

## Overview

DNSScienced supports **compiled zone files** - a binary format that provides significant performance improvements over traditional text-based zone files. Compiled zones use Protocol Buffers for efficient serialization and can be loaded **2-5x faster** with reduced memory usage.

## Why Compiled Zones?

### Performance Benefits

- **2-5x faster loading** compared to text parsing
- **40-60% less memory** usage
- **50-55% fewer allocations** during load
- **Pre-validated** - errors caught at compile time
- **Wire-format ready** - records stored in DNS wire format

### Benchmark Results

```
Format              Load Time    Memory      Allocations
------------------------------------------------------
Text (.dnszone)     229.6 µs    58,979 B    1,043
Compiled (.dzc)     104.5 µs    23,944 B      471
------------------------------------------------------
Improvement         2.2x faster  60% less    55% less
```

## File Format

Compiled zones use the `.dzc` extension and are based on Protocol Buffers. The format includes:

- **Zone metadata**: name, origin, class
- **SOA record**: start of authority information
- **All records**: organized by owner name for fast lookup
- **Owner index**: sorted for wildcard matching
- **Compilation metadata**: timestamps, source hash, compiler version
- **DNSSEC config**: if enabled
- **Zone statistics**: pre-computed counts and sizes

## Using Compiled Zones

### Compiling a Zone

Use the `dnsscienced-compile` tool:

```bash
# Basic compilation
dnsscienced-compile -input example.com.dnszone

# With verification
dnsscienced-compile -input example.com.dnszone -verify -v

# Specify output file
dnsscienced-compile -input example.com.bind -format bind -output example.com.dzc

# Force recompilation
dnsscienced-compile -input example.com.dnszone -force
```

### Command Options

```
-input string
    Input zone file (required)

-output string
    Output compiled zone file (optional, defaults to input.dzc)

-format string
    Input format: auto, dnszone, bind (default "auto")

-text
    Include human-readable text representation of records

-verify
    Verify compiled zone by loading it back

-v  Verbose output

-force
    Force recompilation even if .dzc is up-to-date

-stats
    Show zone statistics (default true)
```

### Example Output

```
Parsing zone file: example.com.dnszone
Format: dnszone
Parse time: 969.064µs
Compiling zone: example.com.
Compile time: 239.982µs
Writing compiled zone: example.com.dzc

=== Zone Statistics ===
Zone Name:       example.com.
Unique Owners:   10
Record Sets:     18
Total Records:   22
Compiled Size:   2421 bytes (2.36 KB)

Record Types:
  A        8
  AAAA     4
  MX       2
  NS       2
  SOA      1
  TXT      2
  SRV      2
  CNAME    1

=== Performance ===
Parse:    969.064µs
Compile:  239.982µs
Write:    572.36µs
Total:    1.816217ms

=== Verification ===
Loading compiled zone: example.com.dzc
Load time: 188.24µs (5.1x faster than text parsing)
✓ Verification successful

✓ Compilation successful
```

## Automatic Loading

DNSScienced **automatically prefers compiled zones** when they exist and are up-to-date. The zone loader:

1. Checks if `zone.dzc` exists for `zone.dnszone`
2. Verifies the compiled zone is newer than the source
3. Validates the source file hash (if available)
4. Loads `.dzc` if valid, otherwise falls back to text

### Example

```bash
# Create source zone
cat > example.com.dnszone << EOF
zone:
  name: example.com
  ttl: 3600
soa:
  primary_ns: ns1.example.com
  contact: admin@example.com
  ...
EOF

# Compile it
dnsscienced-compile -input example.com.dnszone

# Server automatically uses .dzc
dnsscienced -zone example.com.dnszone
# Logs: "Loading zone from compiled format: example.com.dzc"
```

## Workflow Recommendations

### Development Workflow

1. **Edit text zones** - Use `.dnszone` or `.bind` for human editing
2. **Compile before deploy** - Run `dnsscienced-compile` in CI/CD
3. **Deploy both files** - Ship `.dnszone` + `.dzc` together
4. **Auto-recompile on change** - Use file watchers or build scripts

### Production Workflow

```bash
# In CI/CD pipeline
for zone in zones/*.dnszone; do
    dnsscienced-compile -input "$zone" -verify
done

# Deploy compiled zones
rsync -av zones/*.dzc zones/*.dnszone production:/etc/dnsscienced/zones/

# Server picks up .dzc automatically
systemctl restart dnsscienced
```

### Makefile Example

```makefile
ZONES = $(wildcard zones/*.dnszone)
COMPILED = $(ZONES:.dnszone=.dzc)

.PHONY: all clean compile

all: compile

compile: $(COMPILED)

%.dzc: %.dnszone
	dnsscienced-compile -input $< -output $@

clean:
	rm -f zones/*.dzc

verify: compile
	@for zone in $(COMPILED); do \
		dnsscienced-compile -input $${zone%.dzc}.dnszone -verify; \
	done
```

## Format Version Compatibility

The compiled zone format includes a version number for backward compatibility:

- **Current version**: 1
- **Format changes**: Will increment version
- **Loader**: Validates version before loading
- **Recommendation**: Recompile zones after dnsscienced upgrades

## Comparison with Other DNS Servers

| Server | Binary Format | Technology | Load Speed |
|--------|---------------|------------|------------|
| **DNSScienced** | `.dzc` | Protocol Buffers | 2-5x faster |
| BIND | `raw` format | Custom binary | 3-10x faster |
| NSD | `nsd.db` | `zonec` compiler | 5-20x faster |
| Knot DNS | LMDB | Memory-mapped DB | 10-50x faster |
| PowerDNS | SQL/LMDB | Database | Varies |

## Technical Details

### Protocol Buffer Schema

The compiled zone format uses this structure:

```protobuf
message CompiledZone {
  string name = 1;
  string origin = 2;
  uint32 class = 3;
  SOARecord soa = 4;
  map<string, RecordSet> records = 5;
  repeated string owner_index = 6;
  CompilationMeta metadata = 7;
  CompiledDNSSECConfig dnssec = 8;
  ZoneStats stats = 9;
}
```

### Record Storage

Records are stored in **DNS wire format** (RDATA section):

- Eliminates re-parsing during query processing
- Reduces memory allocations
- Enables zero-copy for some operations
- Maintains full DNS compatibility

### Compilation Process

1. **Parse** text zone file (.dnszone or .bind)
2. **Validate** zone structure and records
3. **Serialize** to wire format
4. **Organize** by owner name for fast lookup
5. **Compute** statistics and metadata
6. **Marshal** to Protocol Buffers
7. **Write** binary .dzc file

## Limitations

- **Binary format**: Not human-readable (use `-text` flag for debug builds)
- **Version dependency**: May need recompile after dnsscienced upgrades
- **Disk space**: Uses ~1.2-1.5x more disk than text (but faster)
- **Edit workflow**: Must edit text source, then recompile

## Best Practices

1. **Version control text zones** - Keep `.dnszone` or `.bind` in git
2. **Compile in CI/CD** - Automate compilation in build pipelines
3. **Don't commit .dzc** - Add `*.dzc` to `.gitignore`
4. **Verify after compile** - Use `-verify` flag in automation
5. **Monitor freshness** - Alert if `.dzc` is stale compared to source
6. **Recompile on upgrade** - After dnsscienced version changes

## TXT Record Encoding

### YAML Quoting Requirements

Zone files use YAML syntax. TXT record values containing certain characters **must be quoted** or the YAML parser will misinterpret them:

| Character | YAML Meaning | Example Problem |
|-----------|-------------|-----------------|
| `:` | Key separator | `v=spf1 include:example.com ~all` → parse error |
| `#` | Comment | `v=DKIM1; p=ABC#123` → truncated at `#` |
| `{` / `}` | Inline mapping | `{k=rsa; p=...}` → parsed as map |
| `[` / `]` | Inline sequence | `[1,2,3]` → parsed as list |
| `&` / `*` | YAML anchors | edge case in complex zones |

**Always quote TXT values:**

```yaml
records:
  '@':
    TXT:
      # WRONG — : causes parse error
      - v=spf1 include:example.com ~all

      # CORRECT
      - "v=spf1 include:example.com ~all"

  '_dmarc':
    TXT:
      # WRONG — # truncates the value
      - v=DMARC1; p=reject; rua=mailto:dmarc@example.com

      # CORRECT
      - "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"
```

### Chunking Behavior

TXT strings longer than 255 bytes are automatically split into RFC 1035-compliant chunks at compile time. Chunking is byte-based, so all ASCII and UTF-8 content is handled correctly. The `-cat` flag on a compiled zone will show the chunks explicitly:

```bash
dnsscienced-compile -cat -input example.com.dzc
# Shows: example.com. 300 IN TXT "chunk1..." "chunk2..."
```

### Diagnosis and Auto-Fix

Use `-doctor` to scan a zone file for encoding issues:

```bash
dnsscienced-compile -doctor -input example.com.dnszone
```

Use `-doctor -fix` to automatically quote problematic TXT values in-place:

```bash
dnsscienced-compile -doctor -fix -input example.com.dnszone
```

## Troubleshooting

### Compiled zone not loading

Check the file timestamps:
```bash
ls -la example.com.*
stat example.com.dnszone example.com.dzc
```

Force recompilation:
```bash
dnsscienced-compile -input example.com.dnszone -force -verify -v
```

### Hash mismatch error

Source file was modified. Recompile:
```bash
dnsscienced-compile -input example.com.dnszone
```

### Performance not improving

Ensure `.dzc` is actually being loaded:
```bash
# Check server logs for "Loading compiled zone" message
journalctl -u dnsscienced | grep -i compiled
```

Verify zone file locations:
```bash
ls -la /etc/dnsscienced/zones/
```

## Future Enhancements

Planned improvements for the compiled zone format:

- **LMDB backend** - Memory-mapped database for very large zones
- **Incremental compilation** - Only recompile changed records
- **Compression** - Optional zlib/gzip compression
- **Pre-computed DNSSEC** - Store signed records ready to serve
- **Query index** - Pre-build lookup tables for common queries
- **Multi-zone archives** - Single `.dzc` file for multiple zones

## References

- [Protocol Buffers Documentation](https://protobuf.dev/)
- [DNS Wire Format (RFC 1035)](https://datatracker.ietf.org/doc/html/rfc1035)
- Source code: `internal/zone/compiled.proto`
- Compiler: `cmd/dnsscienced-compile/main.go`
- Loader: `internal/zone/loader.go`
