package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dnsscience/dnsscienced/internal/zone"
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
)

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
	}

	flag.Parse()

	if *input == "" {
		fmt.Fprintf(os.Stderr, "Error: -input is required\n\n")
		flag.Usage()
		os.Exit(1)
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

	// Check if output already exists and is up-to-date
	if !*force {
		if upToDate, err := isOutputUpToDate(*input, outputFile); err == nil && upToDate {
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

// isOutputUpToDate checks if compiled zone is newer than source
func isOutputUpToDate(source, compiled string) (bool, error) {
	compiledInfo, err := os.Stat(compiled)
	if err != nil {
		return false, err
	}

	sourceInfo, err := os.Stat(source)
	if err != nil {
		return false, err
	}

	return compiledInfo.ModTime().After(sourceInfo.ModTime()), nil
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
