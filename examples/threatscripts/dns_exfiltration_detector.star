# dns_exfiltration_detector.star
# ThreatScript example: Detect DNS tunneling / data exfiltration

def main():
    """Detect DNS tunneling and data exfiltration attempts"""

    domain = query["domain"]
    query_type = query["type"]
    client_ip = query["client_ip"]

    # Exfiltration indicators
    suspicious = False
    reason = ""

    domain_parts = domain.split(".")
    if len(domain_parts) < 2:
        return {"action": "allow"}

    subdomain = domain_parts[0]

    # 1. Check subdomain length (tunneling uses long subdomains)
    if len(subdomain) > 50:
        suspicious = True
        reason = "Unusually long subdomain (possible tunneling)"

    # 2. Check for base64-like patterns
    if is_base64_like(subdomain):
        suspicious = True
        reason = "Base64-encoded subdomain (possible data exfiltration)"

    # 3. Check query frequency (would need stateful tracking)
    # For now, just log
    log.debug(f"DNS query: {domain} from {client_ip}")

    # 4. Check query type (TXT queries often used for tunneling)
    if query_type == "TXT" and len(subdomain) > 30:
        suspicious = True
        reason = "Suspicious TXT query with long subdomain"

    if suspicious:
        log.alert(f"DNS exfiltration detected: {domain} - {reason}")

        # Block the domain
        dns.blackhole(domain)

        # Rate-limit the client
        firewall.block(client_ip, protocol="udp", port=53)

        # Alert security team with full details
        notify.webhook("https://soc.company.com/alert", {
            "alert_type": "dns_exfiltration",
            "domain": domain,
            "client_ip": client_ip,
            "query_type": query_type,
            "reason": reason,
            "timestamp": runtime.now()
        })

        notify.slack(f"🚨 DNS exfiltration blocked: {domain[:50]}... from {client_ip}")

        return {"action": "block", "reason": reason}

    return {"action": "allow"}

def is_base64_like(s):
    """Check if string looks like base64 encoding"""
    # Simple heuristic: mostly alphanumeric with + or / or =
    if len(s) < 10:
        return False

    special_chars = sum(1 for c in s if c in "+/=")
    alphanum = sum(1 for c in s if c.isalnum())

    return (alphanum + special_chars) / len(s) > 0.95 and special_chars > 0

main()
