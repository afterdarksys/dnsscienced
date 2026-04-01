package zone

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ParseZoneFile is a smart parser that automatically detects the zone format
// and prefers compiled zones (.dzc) over text formats for performance
func ParseZoneFile(filename string, cfg Config) (*Zone, error) {
	// Check if a compiled version exists and is up-to-date
	compiledPath := strings.TrimSuffix(filename, filepath.Ext(filename)) + CompiledZoneExtension

	// Try to use compiled zone if it exists
	if compiledPath != filename {
		if compiled, err := tryLoadCompiled(filename, compiledPath, cfg); err == nil && compiled != nil {
			return compiled, nil
		}
	}

	// Fall back to text parsing
	return ParseZoneFileText(filename, cfg)
}

// ParseZoneFileText parses a zone file from text format (auto-detects .dnszone vs .bind)
func ParseZoneFileText(filename string, cfg Config) (*Zone, error) {
	// Detect format based on extension
	ext := strings.ToLower(filepath.Ext(filename))

	switch ext {
	case ".dnszone":
		return ParseDNSZone(filename, cfg)
	case ".bind", ".zone", "":
		// BIND format (need to detect origin from filename or content)
		origin := detectOriginFromFilename(filename)
		return ParseBIND(filename, origin, cfg)
	case CompiledZoneExtension:
		// Already compiled
		return LoadCompiledZone(filename)
	default:
		// Try to detect format by reading file
		return autoDetectAndParse(filename, cfg)
	}
}

// tryLoadCompiled attempts to load a compiled zone if it's up-to-date
func tryLoadCompiled(sourcePath, compiledPath string, cfg Config) (*Zone, error) {
	// Check if compiled file exists
	compiledInfo, err := os.Stat(compiledPath)
	if err != nil {
		// Compiled file doesn't exist
		return nil, err
	}

	// Check if source file exists
	sourceInfo, err := os.Stat(sourcePath)
	if err != nil {
		// Source doesn't exist, but compiled does - use compiled
		return LoadCompiledZone(compiledPath)
	}

	// Check if compiled is newer than source
	if compiledInfo.ModTime().Before(sourceInfo.ModTime()) {
		// Source is newer, need to recompile
		return nil, fmt.Errorf("compiled zone is outdated")
	}

	// Get compiled zone metadata to verify
	meta, _, err := GetCompiledZoneInfo(compiledPath)
	if err != nil {
		return nil, err
	}

	// Verify source file hash if available
	if meta.SourceSha256 != nil && len(meta.SourceSha256) > 0 {
		hash, _, err := computeFileHash(sourcePath)
		if err != nil {
			return nil, err
		}

		// Compare hashes
		if !bytesEqual(hash, meta.SourceSha256) {
			return nil, fmt.Errorf("source file has changed")
		}
	}

	// All checks passed, load compiled zone
	return LoadCompiledZone(compiledPath)
}

// autoDetectAndParse tries to detect the zone file format
func autoDetectAndParse(filename string, cfg Config) (*Zone, error) {
	// Read first few lines
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	content := string(data)

	// Check for YAML indicators
	if strings.Contains(content, "zone:") && strings.Contains(content, "soa:") {
		return ParseDNSZone(filename, cfg)
	}

	// Default to BIND format
	origin := detectOriginFromFilename(filename)
	return ParseBIND(filename, origin, cfg)
}

// detectOriginFromFilename tries to extract the zone origin from the filename
func detectOriginFromFilename(filename string) string {
	// Get base filename without path
	base := filepath.Base(filename)

	// Remove extension
	name := strings.TrimSuffix(base, filepath.Ext(base))

	// If it looks like a domain name, use it
	if strings.Contains(name, ".") {
		return name + "."
	}

	// Default to root zone
	return "."
}

// bytesEqual compares two byte slices
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
