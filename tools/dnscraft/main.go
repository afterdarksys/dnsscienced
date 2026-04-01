package main

import (
	"fmt"
	"os"
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
