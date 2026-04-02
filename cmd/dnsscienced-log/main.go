package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/dnsscience/dnsscienced/internal/logging"
)

var (
	domain     = flag.String("domain", "all", "Filter by domain (or 'all' for all domains)")
	filter     = flag.String("filter", "", "Filter by query type or pattern")
	client     = flag.String("client", "", "Filter by client IP")
	backend    = flag.String("backend", "", "Filter by backend/upstream server")
	logFile    = flag.String("log", "/var/log/dnsscienced/queries.log", "Query log file path")
	format     = flag.String("format", "table", "Output format: table, json, csv")
	follow     = flag.Bool("follow", false, "Follow log file (like tail -f)")
	since      = flag.String("since", "", "Show entries since time (RFC3339 or duration like '1h')")
	until      = flag.String("until", "", "Show entries until time (RFC3339)")
	blocked    = flag.Bool("blocked", false, "Show only blocked queries")
	cacheHit   = flag.Bool("cache-hit", false, "Show only cache hits")
	cacheMiss  = flag.Bool("cache-miss", false, "Show only cache misses")
	threatOnly = flag.Bool("threat-only", false, "Show only queries with threat scores > 0")
)

func main() {
	flag.Parse()

	// Parse time filters
	var sinceTime, untilTime time.Time
	var err error

	if *since != "" {
		// Try parsing as duration first
		if duration, err := time.ParseDuration(*since); err == nil {
			sinceTime = time.Now().Add(-duration)
		} else {
			// Try parsing as RFC3339 timestamp
			sinceTime, err = time.Parse(time.RFC3339, *since)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Invalid --since format: %v\n", err)
				os.Exit(1)
			}
		}
	}

	if *until != "" {
		untilTime, err = time.Parse(time.RFC3339, *until)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid --until format: %v\n", err)
			os.Exit(1)
		}
	}

	// Open log file
	f, err := os.Open(*logFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open log file: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)

	// Print header for table format
	if *format == "table" {
		printTableHeader()
	} else if *format == "csv" {
		printCSVHeader()
	}

	lineCount := 0
	matchCount := 0

	for scanner.Scan() {
		lineCount++
		line := scanner.Text()

		// Parse JSON log entry
		var entry logging.QueryLogEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			// Skip invalid lines
			continue
		}

		// Apply filters
		if !matchesFilters(&entry, sinceTime, untilTime) {
			continue
		}

		// Print matching entry
		matchCount++
		switch *format {
		case "table":
			printTableRow(&entry)
		case "json":
			fmt.Println(line)
		case "csv":
			printCSVRow(&entry)
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "Error reading log file: %v\n", err)
		os.Exit(1)
	}

	// Print summary
	if *format == "table" {
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "Processed %d lines, found %d matches\n", lineCount, matchCount)
	}
}

func matchesFilters(entry *logging.QueryLogEntry, sinceTime, untilTime time.Time) bool {
	// Time filters
	if !sinceTime.IsZero() && entry.Timestamp.Before(sinceTime) {
		return false
	}
	if !untilTime.IsZero() && entry.Timestamp.After(untilTime) {
		return false
	}

	// Domain filter
	if *domain != "all" && !strings.Contains(strings.ToLower(entry.QName), strings.ToLower(*domain)) {
		return false
	}

	// Query type filter
	if *filter != "" && !strings.Contains(strings.ToLower(entry.QType), strings.ToLower(*filter)) {
		return false
	}

	// Client IP filter
	if *client != "" && !strings.Contains(entry.ClientIP, *client) {
		return false
	}

	// Backend/upstream filter
	if *backend != "" && !strings.Contains(entry.Upstream, *backend) {
		return false
	}

	// Blocked filter
	if *blocked && !entry.Blocked {
		return false
	}

	// Cache hit filter
	if *cacheHit && !entry.CacheHit {
		return false
	}

	// Cache miss filter
	if *cacheMiss && entry.CacheHit {
		return false
	}

	// Threat filter
	if *threatOnly && entry.ThreatScore == 0 {
		return false
	}

	return true
}

func printTableHeader() {
	fmt.Printf("%-20s %-15s %-6s %-40s %-8s %-10s %8s %5s %8s\n",
		"TIMESTAMP", "CLIENT", "PROTO", "QNAME", "QTYPE", "RCODE", "LATENCY", "CACHE", "THREAT")
	fmt.Println(strings.Repeat("-", 130))
}

func printTableRow(entry *logging.QueryLogEntry) {
	timestamp := entry.Timestamp.Format("2006-01-02 15:04:05")
	cacheStatus := " "
	if entry.CacheHit {
		cacheStatus = "HIT"
	} else {
		cacheStatus = "MISS"
	}

	threatStatus := " "
	if entry.ThreatScore > 0 {
		threatStatus = fmt.Sprintf("%d", entry.ThreatScore)
	}
	if entry.Blocked {
		threatStatus = "BLOCKED"
	}

	fmt.Printf("%-20s %-15s %-6s %-40s %-8s %-10s %6dms %5s %8s\n",
		timestamp,
		entry.ClientIP,
		entry.Protocol,
		truncate(entry.QName, 40),
		entry.QType,
		entry.RCode,
		entry.Latency,
		cacheStatus,
		threatStatus,
	)
}

func printCSVHeader() {
	fmt.Println("timestamp,client_ip,client_port,protocol,qname,qtype,qclass,rcode,answer_count,latency_ms,cache_hit,blocked,block_reason,upstream,dnssec,threat_score")
}

func printCSVRow(entry *logging.QueryLogEntry) {
	fmt.Printf("%s,%s,%d,%s,%s,%s,%s,%s,%d,%d,%t,%t,%s,%s,%t,%d\n",
		entry.Timestamp.Format(time.RFC3339),
		entry.ClientIP,
		entry.ClientPort,
		entry.Protocol,
		entry.QName,
		entry.QType,
		entry.QClass,
		entry.RCode,
		entry.AnswerCount,
		entry.Latency,
		entry.CacheHit,
		entry.Blocked,
		entry.BlockReason,
		entry.Upstream,
		entry.DNSSEC,
		entry.ThreatScore,
	)
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
