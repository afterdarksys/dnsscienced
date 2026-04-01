# dga_detector.star
# ThreatScript example: Detect Domain Generation Algorithm (DGA) patterns

def main():
    """Detect and block DGA-generated domains"""

    domain = query["domain"]
    client_ip = query["client_ip"]

    # Check domain characteristics
    domain_parts = domain.split(".")
    if len(domain_parts) < 2:
        return {"action": "allow"}

    subdomain = domain_parts[0]

    # DGA detection heuristics
    is_dga = False
    dga_score = 0

    # 1. Check length (DGA domains often 10-20 chars)
    if len(subdomain) >= 10 and len(subdomain) <= 20:
        dga_score += 20

    # 2. Check entropy (DGA domains are random-looking)
    vowels = sum(1 for c in subdomain.lower() if c in "aeiou")
    consonants = len(subdomain) - vowels
    if vowels < 2 or consonants / len(subdomain) > 0.8:
        dga_score += 30

    # 3. Check for numeric characters (common in DGA)
    if any(c.isdigit() for c in subdomain):
        dga_score += 10

    # 4. Check reputation
    reputation = dns.check_reputation(domain)
    if reputation < 30:  # Low reputation
        dga_score += 20

    # Decision threshold
    if dga_score >= 50:
        is_dga = True

    if is_dga:
        log.alert(f"DGA domain detected: {domain} (score={dga_score}) from {client_ip}")

        # Blackhole the domain
        dns.blackhole(domain)

        # Alert SOC
        notify.slack(f"🤖 DGA domain blocked: {domain} (score={dga_score})")

        # If client is repeatedly querying DGA domains, block them
        # (This would require stateful tracking in production)
        log.warn(f"Client {client_ip} querying potential C2 domain")

        return {"action": "block", "reason": f"DGA detected (score={dga_score})"}

    return {"action": "allow"}

main()
