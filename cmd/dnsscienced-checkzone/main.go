package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/dnsscience/dnsscienced/internal/zone"
	"gopkg.in/yaml.v3"
)

type checkOptions struct {
	input        string
	format       string
	quiet        bool
	verbose      bool
	compileCheck bool
}

type checkResult struct {
	zoneName string
	stats    zone.Stats
	compiled *zone.CompiledZone
}

var (
	knownRecordKeys = map[string]bool{
		"A": true, "AAAA": true, "CNAME": true, "MX": true, "NS": true,
		"TXT": true, "SRV": true, "PTR": true, "TLSA": true, "HTTPS": true,
		"SVCB": true, "CAA": true, "SSHFP": true, "NAPTR": true, "SMIMEA": true,
		"LOC": true, "HINFO": true, "CERT": true, "IPSECKEY": true,
		"OPENPGPKEY": true, "URI": true, "EUI48": true, "EUI64": true,
		"CDS": true, "CDNSKEY": true, "ZONEMD": true, "CSYNC": true,
		"RP": true, "AFSDB": true, "KX": true, "DHCID": true, "APL": true,
		"ttl": true, "comment": true, "reverse": true,
	}
	genericTypeKeyRE = regexp.MustCompile(`(?i)^TYPE([1-9][0-9]{0,4})$`)
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	opts, err := parseFlags(args, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}

	result, err := checkZone(opts)
	if err != nil {
		fmt.Fprintf(stderr, "zone %s: not ok\n", opts.input)
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	if !opts.quiet {
		fmt.Fprintf(stdout, "zone %s: ok\n", opts.input)
		fmt.Fprintf(stdout, "zone name: %s\n", result.zoneName)
		if opts.verbose {
			fmt.Fprintf(stdout, "owners: %d\n", result.stats.Owners)
			fmt.Fprintf(stdout, "record sets: %d\n", result.stats.RecordSets)
			fmt.Fprintf(stdout, "records: %d\n", result.stats.Records)
			if result.compiled != nil && result.compiled.Stats != nil {
				fmt.Fprintln(stdout, "compiled record types:")
				for _, line := range formatTypeCounts(result.compiled.Stats.TypeCounts) {
					fmt.Fprintf(stdout, "  %s\n", line)
				}
			}
		}
	}

	return 0
}

func parseFlags(args []string, stderr io.Writer) (checkOptions, error) {
	var opts checkOptions
	fs := flag.NewFlagSet("dnsscienced-checkzone", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&opts.input, "input", "", "Input zone file")
	fs.StringVar(&opts.format, "format", "auto", "Input format: auto, dnszone, bind, compiled")
	fs.BoolVar(&opts.quiet, "q", false, "Quiet mode; print only errors")
	fs.BoolVar(&opts.verbose, "v", false, "Verbose output")
	fs.BoolVar(&opts.compileCheck, "compile-check", true, "Verify the zone can be compiled to .dzc in memory")

	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: %s [options] <zonefile>\n\n", fs.Name())
		fmt.Fprintln(stderr, "Checks dnsscienced YAML zones, BIND zones, or compiled .dzc files.")
		fmt.Fprintln(stderr, "\nOptions:")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return opts, err
	}

	if opts.input == "" {
		switch fs.NArg() {
		case 0:
			fs.Usage()
			return opts, fmt.Errorf("zone file is required")
		case 1:
			opts.input = fs.Arg(0)
		default:
			return opts, fmt.Errorf("expected one zone file, got %d", fs.NArg())
		}
	} else if fs.NArg() > 0 {
		return opts, fmt.Errorf("use either -input or positional zone file, not both")
	}

	switch opts.format {
	case "auto", "dnszone", "bind", "compiled":
	default:
		return opts, fmt.Errorf("unsupported -format %q", opts.format)
	}

	return opts, nil
}

func checkZone(opts checkOptions) (*checkResult, error) {
	if opts.input == "" {
		return nil, fmt.Errorf("zone file is required")
	}
	if _, err := os.Stat(opts.input); err != nil {
		return nil, err
	}

	format := detectFormat(opts.input, opts.format)
	if format == "dnszone" {
		if err := lintDNSZoneFile(opts.input); err != nil {
			return nil, err
		}
	}

	cfg := zone.DefaultConfig()
	cfg.Strict = true

	z, err := parseInputZone(opts.input, format, cfg)
	if err != nil {
		return nil, err
	}
	if err := z.Validate(); err != nil {
		return nil, err
	}

	result := &checkResult{
		zoneName: z.Name,
		stats:    z.GetStats(),
	}
	if opts.compileCheck && format != "compiled" {
		compiled, err := zone.CompileZone(z, zone.CompileOptions{
			SourceFile:      opts.input,
			SourceFormat:    format,
			IncludeTextRepr: true,
		})
		if err != nil {
			return nil, err
		}
		result.compiled = compiled
	}

	return result, nil
}

func parseInputZone(input, format string, cfg zone.Config) (z *zone.Zone, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("parser panic: %v", r)
		}
	}()

	switch format {
	case "compiled":
		return zone.LoadCompiledZone(input)
	case "dnszone", "bind":
		return zone.ParseZoneFileText(input, cfg)
	default:
		return zone.ParseZoneFileText(input, cfg)
	}
}

func detectFormat(filename, formatFlag string) string {
	if formatFlag != "auto" {
		return formatFlag
	}

	switch strings.ToLower(filepath.Ext(filename)) {
	case ".dnszone":
		return "dnszone"
	case ".bind", ".zone":
		return "bind"
	case zone.CompiledZoneExtension:
		return "compiled"
	default:
		return "dnszone"
	}
}

func lintDNSZoneFile(filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("read file: %w", err)
	}

	var root yaml.Node
	dec := yaml.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&root); err != nil {
		return fmt.Errorf("parse YAML: %w", err)
	}
	if len(root.Content) == 0 {
		return fmt.Errorf("empty YAML document")
	}

	doc := root.Content[0]
	if doc.Kind != yaml.MappingNode {
		return yamlNodeError(doc, "top-level YAML document must be a mapping")
	}

	if err := lintZoneHeader(doc); err != nil {
		return err
	}

	top := mappingNode(doc, "records")
	if top == nil {
		return yamlNodeError(doc, "missing records section")
	}
	if err := lintRecordMap(top); err != nil {
		return err
	}

	return nil
}

func lintZoneHeader(doc *yaml.Node) error {
	zoneNode := mappingNode(doc, "zone")
	if zoneNode == nil {
		return yamlNodeError(doc, "missing zone section")
	}

	switch zoneNode.Kind {
	case yaml.ScalarNode:
		if strings.TrimSpace(zoneNode.Value) == "" {
			return yamlNodeError(zoneNode, "zone name must not be empty")
		}
	case yaml.MappingNode:
		nameNode := mappingNode(zoneNode, "name")
		if nameNode == nil || strings.TrimSpace(nameNode.Value) == "" {
			return yamlNodeError(zoneNode, "missing zone.name")
		}
	default:
		return yamlNodeError(zoneNode, "zone section must be a mapping or legacy scalar name")
	}

	return nil
}

func lintRecordMap(records *yaml.Node) error {
	if records.Kind != yaml.MappingNode {
		return yamlNodeError(records, "records section must be a mapping")
	}

	for i := 0; i < len(records.Content); i += 2 {
		owner := records.Content[i]
		section := records.Content[i+1]
		if section.Kind != yaml.MappingNode {
			return yamlNodeError(section, "record section for %q must be a mapping", owner.Value)
		}
		if err := lintRecordSection(owner.Value, section); err != nil {
			return err
		}
	}
	return nil
}

func lintRecordSection(owner string, section *yaml.Node) error {
	for i := 0; i < len(section.Content); i += 2 {
		key := section.Content[i]
		if knownRecordKeys[key.Value] {
			continue
		}
		if isGenericTypeKey(key.Value) {
			continue
		}
		return yamlNodeError(key, "unknown record key %q at owner %q", key.Value, owner)
	}
	return nil
}

func isGenericTypeKey(key string) bool {
	matches := genericTypeKeyRE.FindStringSubmatch(key)
	if matches == nil {
		return false
	}
	var n int
	if _, err := fmt.Sscanf(matches[1], "%d", &n); err != nil {
		return false
	}
	return n >= 1 && n <= 65535
}

func mappingNode(parent *yaml.Node, key string) *yaml.Node {
	for i := 0; i < len(parent.Content); i += 2 {
		if parent.Content[i].Value == key {
			return parent.Content[i+1]
		}
	}
	return nil
}

func yamlNodeError(node *yaml.Node, format string, args ...interface{}) error {
	msg := fmt.Sprintf(format, args...)
	if node != nil && node.Line > 0 {
		return fmt.Errorf("line %d: %s", node.Line, msg)
	}
	return fmt.Errorf("%s", msg)
}

func formatTypeCounts(counts map[string]uint32) []string {
	lines := make([]string, 0, len(counts))
	for typ, count := range counts {
		lines = append(lines, fmt.Sprintf("%-8s %d", typ, count))
	}
	sort.Strings(lines)
	return lines
}
