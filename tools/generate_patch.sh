#!/bin/bash
set -e

# Generates a Linux Kernel patch for the DNS Firewall module.
# Run from the project root.

OUTPUT_PATCH="dns_netfilter.patch"
TEMP_DIR=$(mktemp -d)

# Setup directory structure
mkdir -p "$TEMP_DIR/a/net/ipv4/netfilter"
mkdir -p "$TEMP_DIR/b/net/ipv4/netfilter"

# Copy files
# We treat 'a' as empty for new files to generate standard diff
cp driver/dns_firewall.c "$TEMP_DIR/b/net/ipv4/netfilter/"
cp driver/dnsasm_kernel.h "$TEMP_DIR/b/net/ipv4/netfilter/"

# Generate Patch
echo "Generating $OUTPUT_PATCH..."
# Use diff -Naur to handle new files
diff -Naur "$TEMP_DIR/a" "$TEMP_DIR/b" > "$OUTPUT_PATCH" || true

# Check if patch has content
if [ -s "$OUTPUT_PATCH" ]; then
    echo "Success: $OUTPUT_PATCH created."
else
    echo "Error: Failed to create patch."
    exit 1
fi

rm -rf "$TEMP_DIR"
