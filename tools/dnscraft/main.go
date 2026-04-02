package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "query":
		runQuery(os.Args[2:])
	case "update":
		runUpdate(os.Args[2:])
	case "batch":
		runBatch(os.Args[2:])
	case "axfr":
		runAXFR(os.Args[2:])
	case "compare":
		runCompare(os.Args[2:])
	default:
		fmt.Printf("Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("dnscraft - The DNS Swiss Army Knife")
	fmt.Println("\nUsage:")
	fmt.Println("  dnscraft <command> [arguments]")
	fmt.Println("\nCommands:")
	fmt.Println("  query    Send a surgically crafted DNS query")
	fmt.Println("  update   Send a dynamic DNS update (CREATE A, etc.)")
	fmt.Println("  batch    Execute bulk DNS lookups from a file (CSV/JSON/TXT)")
	fmt.Println("  axfr     Perform a zone transfer")
	fmt.Println("  compare  Compare results between two servers (AXFR or batch)")
	fmt.Println("\nRun 'dnscraft <command> -h' to see flags for a specific command.")
}

// runQuery sends a custom DNS query
func runQuery(args []string) {
	fs := flag.NewFlagSet("query", flag.ExitOnError)
	server := fs.String("server", "8.8.8.8:53", "DNS server address")
	qtype := fs.String("type", "A", "Query type (A, AAAA, MX, TXT, etc.)")
	qclass := fs.String("class", "IN", "Query class (IN, CH, HS)")
	proto := fs.String("proto", "udp", "Protocol (udp, tcp)")
	dnssec := fs.Bool("dnssec", false, "Set DNSSEC OK bit")
	recursion := fs.Bool("rd", true, "Recursion desired")
	edns0 := fs.Bool("edns0", true, "Use EDNS0")
	bufsize := fs.Int("bufsize", 4096, "EDNS0 buffer size")
	timeout := fs.Duration("timeout", 5*time.Second, "Query timeout")
	fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Usage: dnscraft query [flags] <name>\n")
		fs.PrintDefaults()
		os.Exit(1)
	}

	name := dns.Fqdn(fs.Arg(0))

	// Parse query type
	var qt uint16
	if t, ok := dns.StringToType[strings.ToUpper(*qtype)]; ok {
		qt = t
	} else {
		fmt.Fprintf(os.Stderr, "Invalid query type: %s\n", *qtype)
		os.Exit(1)
	}

	// Parse query class
	var qc uint16
	if c, ok := dns.StringToClass[strings.ToUpper(*qclass)]; ok {
		qc = c
	} else {
		fmt.Fprintf(os.Stderr, "Invalid query class: %s\n", *qclass)
		os.Exit(1)
	}

	// Build query
	m := new(dns.Msg)
	m.SetQuestion(name, qt)
	m.RecursionDesired = *recursion
	m.Question[0].Qclass = qc

	if *edns0 {
		m.SetEdns0(uint16(*bufsize), *dnssec)
	}

	// Send query
	c := new(dns.Client)
	c.Net = *proto
	c.Timeout = *timeout

	r, rtt, err := c.Exchange(m, *server)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Display response
	fmt.Printf(";; Query time: %v\n", rtt)
	fmt.Printf(";; SERVER: %s\n", *server)
	fmt.Printf(";; MSG SIZE rcvd: %d\n\n", r.Len())
	fmt.Println(r.String())
}

// runUpdate sends a DNS UPDATE message
func runUpdate(args []string) {
	fs := flag.NewFlagSet("update", flag.ExitOnError)
	server := fs.String("server", "127.0.0.1:53", "DNS server address")
	zone := fs.String("zone", "", "Zone name (required)")
	add := fs.String("add", "", "Add record: name,type,ttl,data")
	del := fs.String("del", "", "Delete record: name,type")
	proto := fs.String("proto", "udp", "Protocol (udp, tcp)")
	timeout := fs.Duration("timeout", 5*time.Second, "Query timeout")
	fs.Parse(args)

	if *zone == "" {
		fmt.Fprintf(os.Stderr, "Zone name is required\n")
		fs.PrintDefaults()
		os.Exit(1)
	}

	if *add == "" && *del == "" {
		fmt.Fprintf(os.Stderr, "Must specify -add or -del\n")
		fs.PrintDefaults()
		os.Exit(1)
	}

	m := new(dns.Msg)
	m.SetUpdate(dns.Fqdn(*zone))

	// Add records
	if *add != "" {
		parts := strings.Split(*add, ",")
		if len(parts) != 4 {
			fmt.Fprintf(os.Stderr, "Invalid add format. Expected: name,type,ttl,data\n")
			os.Exit(1)
		}

		name := dns.Fqdn(parts[0])
		ttl, _ := strconv.ParseUint(parts[2], 10, 32)

		var rr dns.RR
		var err error
		switch strings.ToUpper(parts[1]) {
		case "A":
			rr, err = dns.NewRR(fmt.Sprintf("%s %d IN A %s", name, ttl, parts[3]))
		case "AAAA":
			rr, err = dns.NewRR(fmt.Sprintf("%s %d IN AAAA %s", name, ttl, parts[3]))
		case "TXT":
			rr, err = dns.NewRR(fmt.Sprintf("%s %d IN TXT %s", name, ttl, parts[3]))
		case "CNAME":
			rr, err = dns.NewRR(fmt.Sprintf("%s %d IN CNAME %s", name, ttl, parts[3]))
		default:
			fmt.Fprintf(os.Stderr, "Unsupported record type: %s\n", parts[1])
			os.Exit(1)
		}

		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating RR: %v\n", err)
			os.Exit(1)
		}

		m.Insert([]dns.RR{rr})
	}

	// Delete records
	if *del != "" {
		parts := strings.Split(*del, ",")
		if len(parts) != 2 {
			fmt.Fprintf(os.Stderr, "Invalid del format. Expected: name,type\n")
			os.Exit(1)
		}

		name := dns.Fqdn(parts[0])
		rtype := strings.ToUpper(parts[1])

		var rr dns.RR
		switch rtype {
		case "A":
			rr = &dns.A{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassANY, Ttl: 0}}
		case "AAAA":
			rr = &dns.AAAA{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeAAAA, Class: dns.ClassANY, Ttl: 0}}
		case "TXT":
			rr = &dns.TXT{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassANY, Ttl: 0}}
		case "CNAME":
			rr = &dns.CNAME{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeCNAME, Class: dns.ClassANY, Ttl: 0}}
		default:
			fmt.Fprintf(os.Stderr, "Unsupported record type: %s\n", rtype)
			os.Exit(1)
		}

		m.Remove([]dns.RR{rr})
	}

	// Send update
	c := new(dns.Client)
	c.Net = *proto
	c.Timeout = *timeout

	r, rtt, err := c.Exchange(m, *server)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf(";; Update time: %v\n", rtt)
	fmt.Printf(";; Response: %s\n", dns.RcodeToString[r.Rcode])
	if r.Rcode != dns.RcodeSuccess {
		fmt.Println(r.String())
		os.Exit(1)
	}
	fmt.Println("Update successful")
}

// runBatch performs bulk DNS lookups
func runBatch(args []string) {
	fs := flag.NewFlagSet("batch", flag.ExitOnError)
	server := fs.String("server", "8.8.8.8:53", "DNS server address")
	file := fs.String("file", "", "Input file (CSV, JSON, or TXT)")
	format := fs.String("format", "txt", "Input format (txt, csv, json)")
	qtype := fs.String("type", "A", "Query type")
	output := fs.String("output", "", "Output file (stdout if not specified)")
	concurrent := fs.Int("concurrent", 10, "Concurrent queries")
	timeout := fs.Duration("timeout", 5*time.Second, "Query timeout")
	fs.Parse(args)

	if *file == "" {
		fmt.Fprintf(os.Stderr, "Input file is required\n")
		fs.PrintDefaults()
		os.Exit(1)
	}

	// Read input file
	var names []string
	switch *format {
	case "txt":
		names = readTxtFile(*file)
	case "csv":
		names = readCsvFile(*file)
	case "json":
		names = readJsonFile(*file)
	default:
		fmt.Fprintf(os.Stderr, "Invalid format: %s\n", *format)
		os.Exit(1)
	}

	// Parse query type
	var qt uint16
	if t, ok := dns.StringToType[strings.ToUpper(*qtype)]; ok {
		qt = t
	} else {
		fmt.Fprintf(os.Stderr, "Invalid query type: %s\n", *qtype)
		os.Exit(1)
	}

	// Setup output
	var outFile *os.File
	if *output != "" {
		f, err := os.Create(*output)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating output file: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		outFile = f
	} else {
		outFile = os.Stdout
	}

	// Query channel
	type result struct {
		name string
		rr   []dns.RR
		err  error
		rtt  time.Duration
	}

	jobs := make(chan string, len(names))
	results := make(chan result, len(names))

	// Workers
	for w := 0; w < *concurrent; w++ {
		go func() {
			c := new(dns.Client)
			c.Timeout = *timeout

			for name := range jobs {
				m := new(dns.Msg)
				m.SetQuestion(dns.Fqdn(name), qt)

				r, rtt, err := c.Exchange(m, *server)
				if err != nil {
					results <- result{name: name, err: err}
					continue
				}

				results <- result{name: name, rr: r.Answer, rtt: rtt}
			}
		}()
	}

	// Send jobs
	for _, name := range names {
		jobs <- name
	}
	close(jobs)

	// Collect results
	for i := 0; i < len(names); i++ {
		res := <-results
		if res.err != nil {
			fmt.Fprintf(outFile, "%s,ERROR,%v\n", res.name, res.err)
		} else if len(res.rr) == 0 {
			fmt.Fprintf(outFile, "%s,NXDOMAIN\n", res.name)
		} else {
			for _, rr := range res.rr {
				fmt.Fprintf(outFile, "%s,%s,%v\n", res.name, rr.String(), res.rtt)
			}
		}
	}

	fmt.Fprintf(os.Stderr, "Completed %d queries\n", len(names))
}

// runAXFR performs a zone transfer
func runAXFR(args []string) {
	fs := flag.NewFlagSet("axfr", flag.ExitOnError)
	server := fs.String("server", "127.0.0.1:53", "DNS server address")
	output := fs.String("output", "", "Output file (stdout if not specified)")
	fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Usage: dnscraft axfr [flags] <zone>\n")
		fs.PrintDefaults()
		os.Exit(1)
	}

	zone := dns.Fqdn(fs.Arg(0))

	// Setup output
	var outFile *os.File
	if *output != "" {
		f, err := os.Create(*output)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating output file: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		outFile = f
	} else {
		outFile = os.Stdout
	}

	// Perform AXFR
	t := new(dns.Transfer)

	m := new(dns.Msg)
	m.SetAxfr(zone)

	c, err := t.In(m, *server)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initiating transfer: %v\n", err)
		os.Exit(1)
	}

	count := 0
	for env := range c {
		if env.Error != nil {
			fmt.Fprintf(os.Stderr, "Transfer error: %v\n", env.Error)
			os.Exit(1)
		}

		for _, rr := range env.RR {
			fmt.Fprintln(outFile, rr.String())
			count++
		}
	}

	fmt.Fprintf(os.Stderr, "Transferred %d records\n", count)
}

// runCompare compares DNS responses between two servers
func runCompare(args []string) {
	fs := flag.NewFlagSet("compare", flag.ExitOnError)
	server1 := fs.String("server1", "8.8.8.8:53", "First DNS server")
	server2 := fs.String("server2", "1.1.1.1:53", "Second DNS server")
	zone := fs.String("zone", "", "Zone for AXFR comparison")
	file := fs.String("file", "", "File with names for batch comparison")
	qtype := fs.String("type", "A", "Query type for batch mode")
	timeout := fs.Duration("timeout", 5*time.Second, "Query timeout")
	fs.Parse(args)

	if *zone == "" && *file == "" {
		fmt.Fprintf(os.Stderr, "Must specify -zone (AXFR mode) or -file (batch mode)\n")
		fs.PrintDefaults()
		os.Exit(1)
	}

	if *zone != "" {
		compareAXFR(*server1, *server2, *zone, *timeout)
	} else {
		compareBatch(*server1, *server2, *file, *qtype, *timeout)
	}
}

func compareAXFR(server1, server2, zone string, timeout time.Duration) {
	zone = dns.Fqdn(zone)

	// Transfer from server1
	fmt.Fprintf(os.Stderr, "Transferring from %s...\n", server1)
	rr1 := doAXFR(server1, zone, timeout)

	// Transfer from server2
	fmt.Fprintf(os.Stderr, "Transferring from %s...\n", server2)
	rr2 := doAXFR(server2, zone, timeout)

	// Compare
	fmt.Printf("Server1: %d records\n", len(rr1))
	fmt.Printf("Server2: %d records\n", len(rr2))

	// Build maps for comparison
	map1 := make(map[string]bool)
	map2 := make(map[string]bool)

	for _, rr := range rr1 {
		map1[rr.String()] = true
	}
	for _, rr := range rr2 {
		map2[rr.String()] = true
	}

	// Find differences
	var onlyIn1, onlyIn2 int
	for rr := range map1 {
		if !map2[rr] {
			fmt.Printf("Only in %s: %s\n", server1, rr)
			onlyIn1++
		}
	}
	for rr := range map2 {
		if !map1[rr] {
			fmt.Printf("Only in %s: %s\n", server2, rr)
			onlyIn2++
		}
	}

	if onlyIn1 == 0 && onlyIn2 == 0 {
		fmt.Println("✓ Zones are identical")
	} else {
		fmt.Printf("✗ Found %d differences (%d unique to server1, %d unique to server2)\n", onlyIn1+onlyIn2, onlyIn1, onlyIn2)
	}
}

func compareBatch(server1, server2, file, qtype string, timeout time.Duration) {
	names := readTxtFile(file)

	var qt uint16
	if t, ok := dns.StringToType[strings.ToUpper(qtype)]; ok {
		qt = t
	} else {
		fmt.Fprintf(os.Stderr, "Invalid query type: %s\n", qtype)
		os.Exit(1)
	}

	c := new(dns.Client)
	c.Timeout = timeout

	different := 0
	for _, name := range names {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(name), qt)

		r1, _, err1 := c.Exchange(m, server1)
		r2, _, err2 := c.Exchange(m, server2)

		if (err1 != nil) != (err2 != nil) {
			fmt.Printf("DIFF %s: server1 error=%v, server2 error=%v\n", name, err1, err2)
			different++
			continue
		}

		if err1 != nil {
			continue // Both errored
		}

		// Compare answers
		if len(r1.Answer) != len(r2.Answer) {
			fmt.Printf("DIFF %s: different answer counts (%d vs %d)\n", name, len(r1.Answer), len(r2.Answer))
			different++
			continue
		}

		// Simple comparison of answer strings
		map1 := make(map[string]bool)
		map2 := make(map[string]bool)
		for _, rr := range r1.Answer {
			map1[rr.String()] = true
		}
		for _, rr := range r2.Answer {
			map2[rr.String()] = true
		}

		diff := false
		for rr := range map1 {
			if !map2[rr] {
				diff = true
				break
			}
		}
		if diff {
			fmt.Printf("DIFF %s: different answers\n", name)
			different++
		}
	}

	fmt.Printf("Compared %d names, found %d differences\n", len(names), different)
}

func doAXFR(server, zone string, timeout time.Duration) []dns.RR {
	t := new(dns.Transfer)

	m := new(dns.Msg)
	m.SetAxfr(zone)

	c, err := t.In(m, server)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initiating transfer: %v\n", err)
		os.Exit(1)
	}

	var rrs []dns.RR
	for env := range c {
		if env.Error != nil {
			fmt.Fprintf(os.Stderr, "Transfer error: %v\n", env.Error)
			os.Exit(1)
		}
		rrs = append(rrs, env.RR...)
	}

	return rrs
}

// File readers

func readTxtFile(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening file: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}

	return lines
}

func readCsvFile(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening file: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	r := csv.NewReader(f)
	records, err := r.ReadAll()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading CSV: %v\n", err)
		os.Exit(1)
	}

	var names []string
	for _, record := range records {
		if len(record) > 0 {
			names = append(names, record[0])
		}
	}

	return names
}

func readJsonFile(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening file: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	var names []string
	decoder := json.NewDecoder(f)
	err = decoder.Decode(&names)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing JSON: %v\n", err)
		os.Exit(1)
	}

	return names
}
