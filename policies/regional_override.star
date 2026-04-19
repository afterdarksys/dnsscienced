# Regional DNS Overrides
# Override specific domains with region-specific responses
# Similar to Unbound's local-data feature

# Regional IP mappings
REGIONAL_OVERRIDES = {
    "ms.com": {
        "10.0.0.0/8": "10.1.1.100",      # Internal network A
        "172.16.0.0/12": "172.16.1.100", # Internal network B
        "default": "20.190.160.1",       # Default/external
    },
    "office.com": {
        "10.0.0.0/8": "10.2.1.100",
        "default": "20.190.160.2",
    },
}

def get_regional_ip(domain, client_ip):
    """
    Get region-specific IP for a domain based on client location.
    """
    if domain not in REGIONAL_OVERRIDES:
        return None

    mapping = REGIONAL_OVERRIDES[domain]

    # Check each CIDR range
    for cidr, target_ip in mapping.items():
        if cidr == "default":
            continue

        # Simple CIDR match (in production, use proper IP matching)
        if matches_cidr(client_ip, cidr):
            return target_ip

    # Return default if no match
    return mapping.get("default")

def matches_cidr(ip, cidr):
    """
    Simple CIDR matching (simplified for demo).
    In production, use proper IP/CIDR library.
    """
    prefix = cidr.split("/")[0]
    # Simple prefix matching
    return ip.startswith(prefix.split(".")[0])

def main():
    """
    Override DNS responses based on client location.
    """
    domain = query["domain"]
    qtype = query["type"]
    client = query["client_ip"]

    # Only process A records
    if qtype != "A":
        return

    # Check for regional override
    override_ip = get_regional_ip(domain, client)

    if override_ip:
        log.info(f"Regional override for {domain}: {client} -> {override_ip}")

        # Set authoritative bit (we're providing local data)
        dns.modify_response(authoritative=True)

        # Add override record (if dns.add_answer is implemented)
        # dns.add_answer(domain, "A", override_ip, ttl=300)

        log.info(f"Overrode {domain} with {override_ip} for client {client}")

# Execute main function
main()
