# DNS Netfilter Kernel Module (Reforged with RPZ)

> **Experimental; do not load in production.** This module is not the planned
> XDP/AF_XDP fast path. It has a separate, incomplete policy plane and currently
> lacks the protocol, privilege, lifecycle, and parity guarantees required by
> DNSScienced. See [the XDP design](../docs/XDP_FAST_PATH.md).

This directory contains a Linux Kernel Module that integrates with Netfilter to inspect, mark, and **filter (RPZ)** DNS packets directly in the kernel.

## Features

- **Low Latency Check**: Parses QNAME in O(n) and checks Hash Table (O(1)).
- **Action Support**:
    - `DROP`: Silently drops packet.
    - `MARK`: Sets `skb->mark` for userspace tools.
- **Dynamic Policy**: Manage rules via `/proc/dns_firewall_rules`.

## Build & Load

### Option 1: Out-of-Tree (Easiest)
Requires kernel headers installed.

```bash
make
sudo insmod dns_firewall.ko
```

### Option 2: In-Tree (Kernel Patch)
To compile this module directly into your kernel (e.g. for a custom router firmware):
1.  Run `tools/generate_patch.sh` in the project root to create `dns_netfilter.patch`.
2.  Run `tools/install_to_kernel.sh <path-to-kernel-src>` to apply it.
3.  Run `make menuconfig` in your kernel source and enable **"DNS Packet Firewall (RPZ)"** (under Networking -> Netfilter).

## Userspace Integration

**Does `dnsscienced` see the markings?**
Not directly. Standard UDP sockets isolate applications from lower-level Netfilter marks.
- **Current Flow**: The driver acts as a "Bouncer". It Drops bad traffic *before* `dnsscienced` sees it, saving CPU.
- **Future**: To read marks in userspace, we would need to switch to using `NFQUEUE` (passing the full packet verdict to userspace), or use eBPF.
- **Benefit**: Even without reading marks, `dnsscienced` benefits from reduced load (bad packets are dropped at the driver level).

## Security Boundaries

- Rule reads and writes are root-only (`0600`), and mutation additionally
  requires `CAP_NET_ADMIN`.
- Debug match logging is disabled by default and rate-limited when enabled.
- The hook inspects only unfragmented inbound IPv4 UDP queries addressed to port
  53 with exactly one standard QUERY question.
- Unsupported, malformed, fragmented, IPv6, TCP, and uncertain traffic is passed
  to the normal stack.
- Rule names are normalized to lowercase and validated for DNS label lengths.

These controls reduce the module's immediate risk; they do not give it feature
or policy parity with the Go server.
