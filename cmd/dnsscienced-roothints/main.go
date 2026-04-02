package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/dnsscience/dnsscienced/internal/roothints"
)

var (
	hintsPath = flag.String("hints", "/etc/dnsscienced/root.hints", "Path to root hints file")
	update    = flag.Bool("update", false, "Force update root hints now")
	check     = flag.Bool("check", false, "Check if update is available")
	status    = flag.Bool("status", false, "Show current root hints status")
	rollback  = flag.String("rollback", "", "Rollback to backup file (provide backup filename)")
	validate  = flag.Bool("validate", true, "Validate downloaded hints before applying")
	backup    = flag.Bool("backup", true, "Create backup before updating")
)

func main() {
	flag.Parse()

	cfg := roothints.Config{
		Enabled:        true,
		UpdateInterval: 7 * 24 * time.Hour,
		HintsPath:      *hintsPath,
		AutoUpdate:     false, // CLI mode, no auto-update
		ValidateUpdate: *validate,
		BackupOld:      *backup,
	}

	updater := roothints.NewUpdater(cfg)

	switch {
	case *update:
		// Force update
		fmt.Println("Updating root hints...")
		if err := updater.ForceUpdate(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Root hints updated successfully!")

	case *check:
		// Check for updates without applying
		fmt.Println("Checking for root hints updates...")
		content, err := downloadHintsForCheck()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error downloading hints: %v\n", err)
			os.Exit(1)
		}

		currentHash := updater.GetCurrentHash()
		newHash := calculateHash(content)

		if currentHash == "" {
			fmt.Println("Status: No existing hints file")
			fmt.Printf("Available version hash: %s\n", newHash[:16])
			fmt.Println("Run with --update to install")
		} else if currentHash == newHash {
			fmt.Println("Status: Root hints are up to date")
			fmt.Printf("Current hash: %s\n", currentHash[:16])
		} else {
			fmt.Println("Status: Update available")
			fmt.Printf("Current hash:   %s\n", currentHash[:16])
			fmt.Printf("Available hash: %s\n", newHash[:16])
			fmt.Println("Run with --update to install")
		}

	case *status:
		// Show status
		currentHash := updater.GetCurrentHash()
		lastUpdate := updater.GetLastUpdate()

		fmt.Println("Root Hints Status:")
		fmt.Printf("  File path: %s\n", *hintsPath)

		if currentHash == "" {
			fmt.Println("  Status: Not installed")
		} else {
			fmt.Printf("  Current hash: %s\n", currentHash[:16])
			if !lastUpdate.IsZero() {
				fmt.Printf("  Last updated: %s (%s ago)\n",
					lastUpdate.Format(time.RFC3339),
					time.Since(lastUpdate).Round(time.Second))
			}

			// Check file info
			if info, err := os.Stat(*hintsPath); err == nil {
				fmt.Printf("  File size: %d bytes\n", info.Size())
				fmt.Printf("  Modified: %s\n", info.ModTime().Format(time.RFC3339))
			}

			// List backups
			listBackups(*hintsPath)
		}

	case *rollback != "":
		// Rollback to backup
		fmt.Printf("Rolling back to: %s\n", *rollback)
		if err := performRollback(*hintsPath, *rollback); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Rollback successful!")

	default:
		// Default: show status
		flag.Usage()
		os.Exit(1)
	}
}

func downloadHintsForCheck() ([]byte, error) {
	// Simplified download for check operation
	// This is a stub - full implementation would download and compare hashes
	return nil, fmt.Errorf("check not fully implemented - use --update instead")
}

func calculateHash(content []byte) string {
	// This would use the same hash function as the updater
	return ""
}

func listBackups(hintsPath string) {
	// List backup files
	// Backups have format: root.hints.20240101-120000.bak
	fmt.Println("\n  Available backups:")
	// Implementation would scan directory for .bak files
	fmt.Println("    (backup listing not implemented in this CLI version)")
}

func performRollback(hintsPath, backupFile string) error {
	// Read backup
	content, err := os.ReadFile(backupFile)
	if err != nil {
		return fmt.Errorf("failed to read backup: %w", err)
	}

	// Create a backup of current file before rollback
	if _, err := os.Stat(hintsPath); err == nil {
		rollbackBackup := hintsPath + ".pre-rollback.bak"
		if err := os.Rename(hintsPath, rollbackBackup); err != nil {
			return fmt.Errorf("failed to backup current file: %w", err)
		}
		fmt.Printf("Current file backed up to: %s\n", rollbackBackup)
	}

	// Write backup content to hints file
	if err := os.WriteFile(hintsPath, content, 0644); err != nil {
		return fmt.Errorf("failed to write rollback: %w", err)
	}

	return nil
}
