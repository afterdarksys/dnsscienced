# Force Authoritative Bit for Broken Proxies
# This policy forces the AA bit on all recursive responses
# Required for broken proxies like Bluecoat

def main():
    """
    Force AA bit on all responses for enterprise proxy compatibility.

    This is a workaround for broken proxies (Bluecoat, etc.) that
    incorrectly require the Authoritative Answer bit to be set on
    all responses, even for recursive queries.
    """
    # Get query information
    domain = query["domain"]
    qtype = query["type"]
    client = query["client_ip"]

    # Log for debugging
    log.info(f"Processing query for {domain} ({qtype}) from {client}")

    # Force authoritative bit on the response
    dns.modify_response(authoritative=True)

    log.info(f"Forced AA bit for {domain}")

# Execute main function
main()
