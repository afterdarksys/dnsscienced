package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/afterdarksys/dnsscienced/internal/zone"
)

var (
	input       = flag.String("input", "", "Input zone file (required)")
	output      = flag.String("output", "", "Output compiled zone file (optional, defaults to input.dzc)")
	format      = flag.String("format", "auto", "Input format: auto, dnszone, bind")
	includeText = flag.Bool("text", false, "Include human-readable text representation of records")
	verify      = flag.Bool("verify", false, "Verify compiled zone by loading it back")
	verbose     = flag.Bool("v", false, "Verbose output")
	force       = flag.Bool("force", false, "Force recompilation even if .dzc is up-to-date")
	stats       = flag.Bool("stats", true, "Show zone statistics")
	cat         = flag.Bool("cat", false, "Print contents of a compiled .dzc file (use with -input pointing to .dzc)")
	doctor      = flag.Bool("doctor", false, "Scan zone file for TXT record YAML encoding issues")
	fix         = flag.Bool("fix", false, "Auto-fix TXT encoding issues found by -doctor (rewrites file in-place)")
)

// txtInlineRe matches lines with an inline TXT value: "    TXT: somevalue"
// Group 1 = everything before the value, Group 2 = the value itself
var txtInlineRe = regexp.MustCompile(`^(\s+TXT:\s+)(.+)$`)

// txtBlockStartRe matches a bare "    TXT:" with no inline value (list follows)
var txtBlockStartRe = regexp.MustCompile(`^\s+TXT:\s*$`)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\nCompiles DNS zone files into optimized binary format (.dzc)\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s -input example.com.dnszone\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -input example.com.bind -format bind -output example.com.dzc\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -input example.com.dnszone -verify -v\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -cat -input example.com.dzc\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -doctor -input example.com.dnszone\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -doctor -fix -input example.com.dnszone\n", os.Args[0])
	}

	flag.Parse()

	if *input == "" {
		fmt.Fprintf(os.Stderr, "Error: -input is required\n\n")
		flag.Usage()
		os.Exit(1)
	}

	// cat mode: dump contents of a compiled .dzc file
	if *cat {
		z, err := zone.LoadCompiledZone(*input)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading compiled zone: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("; Compiled zone: %s\n", *input)
		fmt.Printf("; Zone: %s\n\n", z.Name)
		for _, rr := range z.GetAllRecords() {
			// Print each RR in RFC 1035 presentation format
			// TXT records show chunks explicitly so encoding issues are visible
			fmt.Println(rr.String())
		}
		return
	}

	// doctor mode: lint (and optionally fix) TXT encoding issues
	if *doctor {
		if *fix {
			fmt.Printf("Scanning and fixing TXT encoding issues in: %s\n", *input)
		} else {
			fmt.Printf("Scanning TXT encoding issues in: %s\n", *input)
		}
		count, err := doctorZoneFile(*input, *fix)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		if count == 0 {
			fmt.Println("✓ No TXT encoding issues found")
		} else if *fix {
			fmt.Printf("✓ Fixed %d TXT encoding issue(s)\n", count)
		} else {
			fmt.Printf("✗ Found %d TXT encoding issue(s) — rerun with -fix to auto-quote\n", count)
			os.Exit(1)
		}
		return
	}

	// Check if input file exists
	if _, err := os.Stat(*input); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Error: input file not found: %s\n", *input)
		os.Exit(1)
	}

	// Determine output file
	outputFile := *output
	if outputFile == "" {
		base := strings.TrimSuffix(*input, filepath.Ext(*input))
		outputFile = base + zone.CompiledZoneExtension
	}

	// Check if output already exists and is up-to-date (including any include files)
	if !*force {
		includes := extractIncludes(*input)
		if upToDate, err := isOutputUpToDate(*input, outputFile, includes); err == nil && upToDate {
			fmt.Printf("✓ Compiled zone is up-to-date: %s\n", outputFile)
			if *stats {
				showStats(outputFile)
			}
			return
		}
	}

	// Parse input zone
	fmt.Printf("Parsing zone file: %s\n", *input)
	startParse := time.Now()

	cfg := zone.DefaultConfig()
	cfg.Strict = true

	var z *zone.Zone
	var err error

	sourceFormat := detectFormat(*input, *format)
	fmt.Printf("Format: %s\n", sourceFormat)

	z, err = zone.ParseZoneFileText(*input, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing zone: %v\n", err)
		os.Exit(1)
	}

	parseDuration := time.Since(startParse)
	if *verbose {
		fmt.Printf("Parse time: %v\n", parseDuration)
	}

	// Compile zone
	fmt.Printf("Compiling zone: %s\n", z.Name)
	startCompile := time.Now()

	opts := zone.CompileOptions{
		SourceFile:      *input,
		OutputFile:      outputFile,
		SourceFormat:    sourceFormat,
		IncludeTextRepr: *includeText,
	}

	compiled, err := zone.CompileZone(z, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error compiling zone: %v\n", err)
		os.Exit(1)
	}

	compileDuration := time.Since(startCompile)
	if *verbose {
		fmt.Printf("Compile time: %v\n", compileDuration)
	}

	// Write compiled zone
	fmt.Printf("Writing compiled zone: %s\n", outputFile)
	startWrite := time.Now()

	if err := zone.WriteCompiledZone(compiled, outputFile); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing compiled zone: %v\n", err)
		os.Exit(1)
	}

	writeDuration := time.Since(startWrite)
	if *verbose {
		fmt.Printf("Write time: %v\n", writeDuration)
	}

	totalDuration := time.Since(startParse)

	// Show statistics
	if *stats && compiled.Stats != nil {
		fmt.Println("\n=== Zone Statistics ===")
		fmt.Printf("Zone Name:       %s\n", compiled.Name)
		fmt.Printf("Unique Owners:   %d\n", compiled.Stats.UniqueOwners)
		fmt.Printf("Record Sets:     %d\n", compiled.Stats.RecordSets)
		fmt.Printf("Total Records:   %d\n", compiled.Stats.TotalRecords)
		fmt.Printf("Compiled Size:   %d bytes (%.2f KB)\n", compiled.Stats.SizeBytes, float64(compiled.Stats.SizeBytes)/1024)

		if len(compiled.Stats.TypeCounts) > 0 {
			fmt.Println("\nRecord Types:")
			for rtype, count := range compiled.Stats.TypeCounts {
				fmt.Printf("  %-8s %d\n", rtype, count)
			}
		}
	}

	fmt.Println("\n=== Performance ===")
	fmt.Printf("Parse:    %v\n", parseDuration)
	fmt.Printf("Compile:  %v\n", compileDuration)
	fmt.Printf("Write:    %v\n", writeDuration)
	fmt.Printf("Total:    %v\n", totalDuration)

	// Verify if requested
	if *verify {
		fmt.Println("\n=== Verification ===")
		fmt.Printf("Loading compiled zone: %s\n", outputFile)
		startVerify := time.Now()

		verifiedZone, err := zone.LoadCompiledZone(outputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading compiled zone: %v\n", err)
			os.Exit(1)
		}

		verifyDuration := time.Since(startVerify)
		fmt.Printf("Load time: %v (%.1fx faster than text parsing)\n",
			verifyDuration,
			float64(parseDuration)/float64(verifyDuration))

		// Validate loaded zone
		if err := verifiedZone.Validate(); err != nil {
			fmt.Fprintf(os.Stderr, "Error validating loaded zone: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("✓ Verification successful")

		// Compare record counts
		originalStats := z.GetStats()
		verifiedStats := verifiedZone.GetStats()

		if originalStats.Records != verifiedStats.Records {
			fmt.Fprintf(os.Stderr, "Warning: record count mismatch (original: %d, verified: %d)\n",
				originalStats.Records, verifiedStats.Records)
		}
	}

	fmt.Println("\n✓ Compilation successful")
}

// detectFormat determines the zone file format
func detectFormat(filename, formatFlag string) string {
	if formatFlag != "auto" {
		return formatFlag
	}

	ext := strings.ToLower(filepath.Ext(filename))
	switch ext {
	case ".dnszone":
		return "dnszone"
	case ".bind", ".zone":
		return "bind"
	default:
		return "dnszone" // default
	}
}

// isOutputUpToDate checks if compiled zone is newer than source and all include files.
func isOutputUpToDate(source, compiled string, includes []string) (bool, error) {
	compiledInfo, err := os.Stat(compiled)
	if err != nil {
		return false, err
	}
	compiledMod := compiledInfo.ModTime()

	for _, path := range append([]string{source}, includes...) {
		info, err := os.Stat(path)
		if err != nil {
			return false, err
		}
		if info.ModTime().After(compiledMod) {
			return false, nil
		}
	}
	return true, nil
}

// extractIncludes reads the includes: list from a .dnszone file without full parsing.
// Paths are resolved relative to the zone file's directory.
func extractIncludes(zoneFile string) []string {
	data, err := os.ReadFile(zoneFile)
	if err != nil {
		return nil
	}
	baseDir := filepath.Dir(zoneFile)

	var inIncludes bool
	var paths []string
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "includes:" {
			inIncludes = true
			continue
		}
		if inIncludes {
			if strings.HasPrefix(trimmed, "- ") {
				p := strings.TrimPrefix(trimmed, "- ")
				p = strings.Trim(p, `"'`)
				if !filepath.IsAbs(p) {
					p = filepath.Join(baseDir, p)
				}
				paths = append(paths, p)
			} else if trimmed != "" && !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
				break
			}
		}
	}
	return paths
}

// doctorZoneFile scans a .dnszone file for unquoted TXT values that contain
// YAML-unsafe characters. With autoFix=true it rewrites the file in-place,
// wrapping problematic values in double quotes.
//
// Dangerous patterns in unquoted YAML plain scalars:
//   - " #"  — space+hash becomes a YAML comment, silently truncating the value
//   - ": "  — colon+space looks like a new mapping key
//   - leading "{" or "[" — parsed as YAML flow mapping / sequence
//   - leading "*" or "&" — parsed as YAML alias / anchor
func doctorZoneFile(filename string, autoFix bool) (int, error) {
	f, err := os.Open(filename)
	if err != nil {
		return 0, fmt.Errorf("opening %s: %w", filename, err)
	}
	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	f.Close()
	if err := scanner.Err(); err != nil {
		return 0, fmt.Errorf("reading %s: %w", filename, err)
	}

	issueCount := 0
	modified := false

	inTXTList := false   // true after a bare "TXT:" line (list items follow)
	listIndent := 0      // column indent of the "TXT:" key line

	for i, line := range lines {
		stripped := strings.TrimLeft(line, " \t")
		indent := len(line) - len(stripped)

		// ── leave TXT-list context once we hit a non-continuation line ──
		if inTXTList {
			isListItem := strings.HasPrefix(stripped, "- ")
			isContinuation := indent > listIndent && stripped != ""
			if !isListItem && !isContinuation {
				inTXTList = false
			}
		}

		// ── case 1: TXT: <value on same line> ──
		if m := txtInlineRe.FindStringSubmatch(line); m != nil {
			prefix, value := m[1], m[2]
			if txtValueNeedsQuoting(value) {
				issueCount++
				fmt.Printf("%s:%d: unquoted TXT value: %s\n", filename, i+1, value)
				if autoFix {
					lines[i] = prefix + quoteForYAML(value)
					modified = true
				}
			}
			inTXTList = false
			continue
		}

		// ── case 2: bare "TXT:" — list of values follows ──
		if txtBlockStartRe.MatchString(line) {
			inTXTList = true
			listIndent = indent
			continue
		}

		// ── case 3: list item inside a TXT block ──
		if inTXTList && strings.HasPrefix(stripped, "- ") {
			value := stripped[2:]
			if txtValueNeedsQuoting(value) {
				issueCount++
				fmt.Printf("%s:%d: unquoted TXT list item: %s\n", filename, i+1, value)
				if autoFix {
					lines[i] = line[:indent] + "- " + quoteForYAML(value)
					modified = true
				}
			}
		}
	}

	if autoFix && modified {
		content := strings.Join(lines, "\n")
		if err := os.WriteFile(filename, []byte(content), 0644); err != nil {
			return issueCount, fmt.Errorf("writing %s: %w", filename, err)
		}
	}

	return issueCount, nil
}

// txtValueNeedsQuoting returns true when an unquoted plain YAML scalar
// contains characters that will be misinterpreted by a standard YAML parser.
func txtValueNeedsQuoting(value string) bool {
	if value == "" {
		return false
	}
	// Skip values that are already quoted with " or '
	if (strings.HasPrefix(value, `"`) && strings.HasSuffix(value, `"`)) ||
		(strings.HasPrefix(value, `'`) && strings.HasSuffix(value, `'`)) {
		return false
	}
	// " #" → rest of line treated as YAML comment
	if strings.Contains(value, " #") {
		return true
	}
	// ": " → parsed as start of a new mapping key
	if strings.Contains(value, ": ") {
		return true
	}
	// Leading flow indicators
	if strings.HasPrefix(value, "{") || strings.HasPrefix(value, "[") {
		return true
	}
	// Leading anchor / alias sigils
	if strings.HasPrefix(value, "*") || strings.HasPrefix(value, "&") {
		return true
	}
	return false
}

// quoteForYAML wraps a value in double quotes, escaping any embedded
// double quotes so the result is valid YAML.
func quoteForYAML(value string) string {
	escaped := strings.ReplaceAll(value, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	return `"` + escaped + `"`
}

// showStats displays statistics for an existing compiled zone
func showStats(filename string) {
	meta, stats, err := zone.GetCompiledZoneInfo(filename)
	if err != nil {
		return
	}

	fmt.Println("\n=== Compiled Zone Info ===")
	if meta != nil {
		fmt.Printf("Source File:     %s\n", meta.SourceFile)
		fmt.Printf("Source Format:   %s\n", meta.SourceFormat)
		if meta.CompiledAt != nil {
			fmt.Printf("Compiled At:     %s\n", meta.CompiledAt.AsTime().Format(time.RFC3339))
		}
		fmt.Printf("Format Version:  %d\n", meta.FormatVersion)
	}

	if stats != nil {
		fmt.Printf("\nUnique Owners:   %d\n", stats.UniqueOwners)
		fmt.Printf("Record Sets:     %d\n", stats.RecordSets)
		fmt.Printf("Total Records:   %d\n", stats.TotalRecords)
		fmt.Printf("Size:            %d bytes\n", stats.SizeBytes)
	}
}
