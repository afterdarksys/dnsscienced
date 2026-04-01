#!/usr/bin/env python3
"""
Convert OCI JSON zone exports to DNSScienced YAML zone format (.dnszone).

Usage:
  oci2dnsscienced.py --zone <oci-json-file> [--dry-run] [--save] [--out-dir DIR]
  oci2dnsscienced.py --batch <dir> [--dry-run] [--save] [--out-dir DIR]
"""
import argparse
import json
import os
import sys
import glob
from typing import Dict, Any, List, Optional
from collections import defaultdict

try:
    import yaml
except Exception:
    print("ERROR: This tool requires PyYAML. Install with: pip install pyyaml", file=sys.stderr)
    sys.exit(2)


def parse_soa_rdata(rdata: str) -> Dict[str, Any]:
    """Parse SOA rdata string into components."""
    parts = rdata.split()
    if len(parts) < 7:
        raise ValueError(f"Invalid SOA rdata: {rdata}")

    return {
        'primary': parts[0].rstrip('.'),
        'admin': parts[1].rstrip('.'),
        'serial': int(parts[2]),
        'refresh': int(parts[3]),
        'retry': int(parts[4]),
        'expire': int(parts[5]),
        'minimum': int(parts[6])
    }


def normalize_domain(domain: str, zone: str) -> str:
    """Convert full domain to relative name or @ for apex."""
    domain = domain.rstrip('.')
    zone = zone.rstrip('.')

    if domain == zone:
        return '@'

    if domain.endswith('.' + zone):
        return domain[:-len(zone)-1]

    return domain


def oci_to_dnszone(path: str) -> Dict[str, Any]:
    """Convert OCI JSON zone export to dnszone format."""
    with open(path, 'r') as f:
        data = json.load(f)

    items = data.get('data', {}).get('items', [])
    if not items:
        raise ValueError(f"No records found in {path}")

    # Determine zone name from SOA or apex records
    zone_name = None
    for item in items:
        if item.get('rtype') == 'SOA':
            zone_name = item.get('domain', '')
            break

    # Fallback: find shortest non-wildcard domain (likely the apex)
    if not zone_name:
        domains = [item.get('domain', '') for item in items if item.get('domain')]
        domains = [d for d in domains if d and not d.startswith('*') and not d.startswith('_')]
        if domains:
            zone_name = min(domains, key=len)

    if not zone_name:
        zone_name = items[0].get('domain', 'unknown.zone')

    zone_name = zone_name.rstrip('.')

    doc: Dict[str, Any] = {
        'zone': {
            'name': zone_name,
            'class': 'IN'
        },
        'serial': 'auto',
    }

    nameservers: List[str] = []
    mx_list: List[Dict[str, Any]] = []
    records: Dict[str, Dict[str, List]] = defaultdict(lambda: defaultdict(list))
    default_ttl: Optional[int] = None
    soa_data: Optional[Dict[str, Any]] = None

    for item in items:
        domain = item.get('domain', '')
        rtype = item.get('rtype', '')
        rdata = item.get('rdata', '')
        ttl = item.get('ttl', 300)
        is_protected = item.get('is-protected', False)

        if not domain or not rtype or not rdata:
            continue

        # Set default TTL from first non-SOA record
        if default_ttl is None and rtype != 'SOA':
            default_ttl = ttl

        # Handle SOA
        if rtype == 'SOA':
            try:
                soa_data = parse_soa_rdata(rdata)
                # Convert to expected field names
                doc['soa'] = {
                    'primary_ns': soa_data['primary'],
                    'contact': soa_data['admin'],
                    'serial': soa_data['serial'],
                    'refresh': soa_data['refresh'],
                    'retry': soa_data['retry'],
                    'expire': soa_data['expire'],
                    'negative_ttl': soa_data['minimum']
                }
                doc['serial'] = soa_data['serial']
            except Exception as e:
                print(f"WARN: Failed to parse SOA: {e}", file=sys.stderr)
            continue

        # Handle NS at apex
        if rtype == 'NS':
            ns_value = rdata.rstrip('.')
            # Skip OCI nameservers
            if 'oraclecloud.net' in ns_value:
                continue
            nameservers.append(ns_value)
            continue

        # Handle MX at apex
        if rtype == 'MX' and normalize_domain(domain, zone_name) == '@':
            parts = rdata.split(None, 1)
            if len(parts) == 2:
                mx_list.append({
                    'priority': int(parts[0]),
                    'host': parts[1].rstrip('.')
                })
            continue

        # Normalize domain name
        owner = normalize_domain(domain, zone_name)

        # Add record
        if rtype == 'A':
            records[owner]['A'].append(rdata)
        elif rtype == 'AAAA':
            records[owner]['AAAA'].append(rdata)
        elif rtype == 'CNAME':
            records[owner]['CNAME'].append(rdata.rstrip('.'))
        elif rtype == 'TXT':
            # Remove surrounding quotes if present
            txt_value = rdata.strip('"')
            records[owner]['TXT'].append(txt_value)
        elif rtype == 'MX':
            parts = rdata.split(None, 1)
            if len(parts) == 2:
                records[owner]['MX'].append(f"{parts[0]} {parts[1].rstrip('.')}")
        elif rtype == 'SRV':
            records[owner]['SRV'].append(rdata.rstrip('.'))
        elif rtype == 'CAA':
            records[owner]['CAA'].append(rdata)
        elif rtype == 'PTR':
            records[owner]['PTR'].append(rdata.rstrip('.'))
        else:
            # Generic record type
            records[owner][rtype].append(rdata)

    # Set default TTL in zone section
    if default_ttl:
        doc['zone']['ttl'] = default_ttl

    # Add nameservers as NS records in @ (apex)
    if not nameservers:
        # Default to our DNS servers
        nameservers = ['ns1.gdns.dartnode.io', 'ns2.gdns.dartnode.io']

    if nameservers:
        apex_ns = sorted(list(set(nameservers)))
        if '@' not in records:
            records['@'] = defaultdict(list)
        records['@']['NS'] = apex_ns

    # Add MX records
    if mx_list:
        doc['mx'] = sorted(mx_list, key=lambda x: (x['priority'], x['host']))

    # Convert records dict, simplifying single-value lists
    if records:
        final_records = {}
        for owner, rtypes in records.items():
            final_records[owner] = {}
            for rtype, values in rtypes.items():
                if len(values) == 1:
                    final_records[owner][rtype] = values[0]
                else:
                    final_records[owner][rtype] = values
        doc['records'] = final_records

    return doc


def write_dnszone(doc: Dict[str, Any], out_path: str) -> None:
    """Write zone data to YAML file."""
    with open(out_path, 'w') as f:
        yaml.dump(doc, f, sort_keys=False, default_flow_style=False, allow_unicode=True)


def convert_one(path: str, out_dir: Optional[str], save: bool, dry_run: bool) -> int:
    """Convert a single OCI JSON file."""
    try:
        doc = oci_to_dnszone(path)
    except Exception as e:
        print(f"ERROR converting {path}: {e}", file=sys.stderr)
        return 1

    if dry_run and not save:
        print(yaml.dump(doc, sort_keys=False, default_flow_style=False, allow_unicode=True))
        return 0

    # Determine output path
    base = os.path.basename(path)
    # Remove .oci.json extension
    if base.endswith('.oci.json'):
        name_no_ext = base[:-9]
    else:
        name_no_ext = os.path.splitext(base)[0]

    out_name = f"{name_no_ext}.dnszone"
    out_path = os.path.join(out_dir or os.path.dirname(path), out_name)

    if save:
        write_dnszone(doc, out_path)
        print(f"Saved: {out_path}")
    else:
        print(yaml.dump(doc, sort_keys=False, default_flow_style=False, allow_unicode=True))

    return 0


def main(argv: Optional[List[str]] = None) -> int:
    """Main entry point."""
    ap = argparse.ArgumentParser(description="Convert OCI JSON zones to DNSScienced YAML format")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument('--zone', help='Path to a single OCI JSON zone file')
    g.add_argument('--batch', help='Directory containing OCI JSON zone files')
    ap.add_argument('--dry-run', action='store_true', help='Do not write files; print result to stdout')
    ap.add_argument('--save', action='store_true', help='Write .dnszone files to disk')
    ap.add_argument('--out-dir', help='Output directory (default: alongside input)')

    args = ap.parse_args(argv)

    if args.zone:
        if not os.path.isfile(args.zone):
            print(f"ERROR: file not found: {args.zone}", file=sys.stderr)
            return 2
        return convert_one(args.zone, args.out_dir, args.save, args.dry_run)

    # Batch mode
    if not os.path.isdir(args.batch):
        print(f"ERROR: directory not found: {args.batch}", file=sys.stderr)
        return 2

    files = sorted(glob.glob(os.path.join(args.batch, '*.oci.json')))
    if not files:
        print("No OCI JSON zone files found", file=sys.stderr)
        return 1

    rc = 0
    for f in files:
        try:
            rc |= convert_one(f, args.out_dir, args.save, args.dry_run)
        except Exception as e:
            print(f"ERROR converting {f}: {e}", file=sys.stderr)
            rc = 1

    return rc


if __name__ == '__main__':
    sys.exit(main())
