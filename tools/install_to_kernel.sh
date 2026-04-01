#!/bin/bash
set -e

# Installs the DNS Firewall module into a Linux Kernel source tree.
# Usage: ./install_to_kernel.sh /path/to/linux-source

KERNEL_DIR="$1"
PATCH_FILE="dns_netfilter.patch"

if [ -z "$KERNEL_DIR" ]; then
    echo "Usage: $0 <path-to-kernel-source>"
    exit 1
fi

if [ ! -d "$KERNEL_DIR" ]; then
    echo "Error: Directory $KERNEL_DIR does not exist."
    exit 1
fi

if [ ! -f "$PATCH_FILE" ]; then
    echo "Error: $PATCH_FILE not found. Run tools/generate_patch.sh first."
    exit 1
fi

echo "Installing to $KERNEL_DIR..."

# 1. Apply Patch (Adds C/H files)
# -p1 strips 'a/' and 'b/' prefixes
patch -d "$KERNEL_DIR" -p1 < "$PATCH_FILE"
echo "files applied."

# 2. Update Kconfig
KCONFIG="$KERNEL_DIR/net/ipv4/netfilter/Kconfig"
if grep -q "NF_DNS_FIREWALL" "$KCONFIG"; then
    echo "Kconfig already updated."
else
    echo "Updating Kconfig..."
    # Append to end of file (simple approach) or insert before 'endmenu'
    # For robust scripting, we append mostly.
    
    cat <<EOF >> "$KCONFIG"

config NF_DNS_FIREWALL
	tristate "DNS Packet Firewall (RPZ)"
	depends on NETFILTER
	help
	  High-performance DNS Firewall module with RPZ support.
	  Parses DNS packets and filters by QNAME using a hashtable.

EOF
fi

# 3. Update Makefile
MAKEFILE="$KERNEL_DIR/net/ipv4/netfilter/Makefile"
if grep -q "dns_firewall.o" "$MAKEFILE"; then
    echo "Makefile already updated."
else
    echo "Updating Makefile..."
    echo "obj-\$(CONFIG_NF_DNS_FIREWALL) += dns_firewall.o" >> "$MAKEFILE"
fi

echo "Done. You can now run 'make menuconfig' in $KERNEL_DIR and enable 'DNS Packet Firewall'."
