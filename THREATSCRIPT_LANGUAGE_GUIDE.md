# ThreatScript Language Guide v1.0

**Official Language Specification for Security Automation**

ThreatScript is a domain-specific language (DSL) built on Starlark (Python-like syntax) designed for enterprise security automation, threat response, and compliance enforcement.

---

## Table of Contents

1. [Overview](#overview)
2. [Core Concepts](#core-concepts)
3. [Language Syntax](#language-syntax)
4. [Module Reference](#module-reference)
5. [Security Model](#security-model)
6. [Integration Points](#integration-points)
7. [Best Practices](#best-practices)
8. [Advanced Patterns](#advanced-patterns)

---

## Overview

### What is ThreatScript?

ThreatScript enables security teams to write automation scripts that:
- **Detect** threats using real-time intelligence
- **Respond** automatically to security incidents
- **Enforce** compliance policies across infrastructure
- **Orchestrate** multi-system responses (DNS, firewall, cloud, telephony)

### Why Starlark?

- **Sandboxed** - Cannot access arbitrary files or network
- **Deterministic** - Same inputs = same outputs (reproducible)
- **Python-like** - Easy to learn, familiar syntax
- **Fast** - JIT-compiled execution
- **Safe** - No eval(), no reflection, bounded execution

### Architecture

```
┌─────────────────────────────────────────────────┐
│           ThreatScript Runtime Engine           │
├─────────────────────────────────────────────────┤
│  Starlark Interpreter + Security Sandbox        │
├─────────────────────────────────────────────────┤
│  Module Ecosystem (20+ modules)                 │
│  ├─ Core: firewall, dns, proxy, network        │
│  ├─ Advanced: dlp, cloud, ai, threat           │
│  └─ Telephony: asterisk, telnyx, twilio, tts   │
├─────────────────────────────────────────────────┤
│  Integration Layer                              │
│  ├─ dnsscienced (DNS-level automation)         │
│  ├─ ads-httpproxy (HTTP-level automation)      │
│  └─ security-appliance (Standalone runtime)    │
└─────────────────────────────────────────────────┘
```

---

## Core Concepts

### 1. Scripts

A ThreatScript is a `.star` file containing Starlark code:

```python
# detect_exfiltration.star
def main():
    # Scan network traffic
    packets = pcap.capture(interface="eth0", count=100)

    for packet in packets:
        data = pcap.decode(packet)

        # Check for data exfiltration patterns
        if dlp.contains_secrets(str(data)):
            source_ip = data["src_ip"]

            # Block immediately
            firewall.block(source_ip, protocol="tcp")

            # Alert SOC
            notify.slack(f"🚨 Data exfiltration blocked: {source_ip}")

            # Generate incident report
            log.alert(f"Blocked exfiltration attempt from {source_ip}")

main()
```

### 2. Modules

Modules provide domain-specific functionality:

```python
firewall.block(ip)           # Network control
dns.blackhole(domain)        # DNS sinkholing
dlp.scan_text(content)       # Data loss prevention
cloud.evaluate_policy(...)   # Cloud access control
ai.analyze_threat(iocs)      # AI-powered analysis
```

### 3. Event-Driven Execution

Scripts can be triggered by:
- **HTTP Requests** - Via proxy/gateway
- **DNS Queries** - Via DNS server
- **Scheduled** - Cron-style periodic execution
- **Manual** - Admin invocation via API
- **Webhooks** - External system events

### 4. Security Sandbox

All scripts run in a sandboxed environment:
- ✅ **Allowed**: Module calls, math, string operations
- ❌ **Denied**: File I/O, network sockets, OS commands
- ⏱️ **Limited**: Max execution time (5s default)
- 💾 **Limited**: Max memory (256MB default)

---

## Language Syntax

### Basic Types

```python
# Strings
message = "Hello, ThreatScript"
template = f"Alert: {threat_level}"

# Numbers
score = 85
threshold = 100.0

# Booleans
is_malicious = True
allow_traffic = False

# Lists
ips = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
categories = ["malware", "phishing", "c2"]

# Dictionaries
threat = {
    "ip": "192.168.1.100",
    "score": 95,
    "category": "malware",
}

# None
result = None
```

### Functions

```python
def check_threat(ip, threshold=80):
    """Check if IP exceeds threat threshold"""
    threat_data = threat.check_ip(ip)
    return threat_data["score"] > threshold

def main():
    if check_threat("192.168.1.100"):
        firewall.block("192.168.1.100")
```

### Control Flow

```python
# If/elif/else
if threat_level == "critical":
    firewall.block(source_ip)
elif threat_level == "high":
    log.alert(f"High threat: {source_ip}")
else:
    log.info(f"Normal traffic from {source_ip}")

# For loops
for ip in blocked_ips:
    firewall.unblock(ip)

# List comprehension
high_threats = [ip for ip in scan_results if ip["score"] > 80]
```

### Error Handling

```python
# Graceful degradation
def safe_block(ip):
    result = firewall.block(ip)
    if not result:
        log.error(f"Failed to block {ip}")
        notify.slack(f"Manual intervention needed: {ip}")
        return False
    return True
```

---

## Module Reference

### Core Security Modules

#### firewall.*

Network firewall control.

```python
# Block IP (all protocols)
firewall.block(ip)

# Block specific port/protocol
firewall.block(ip, port=443, protocol="tcp")

# Unblock IP
firewall.unblock(ip)

# List active rules
rules = firewall.list_rules()

# Add custom rule
firewall.add_rule({
    "action": "drop",
    "src": "192.168.1.0/24",
    "dst_port": 22,
    "protocol": "tcp"
})
```

#### dns.*

DNS blackholing and redirection.

```python
# Blackhole domain (return NXDOMAIN)
dns.blackhole(domain)

# Redirect to sinkhole
dns.redirect(domain, sinkhole_ip="127.0.0.1")

# Remove blackhole
dns.unblackhole(domain)

# Query threat intelligence
intel = dns.query_threat_intel(domain)
if intel["malicious"]:
    dns.blackhole(domain)
```

#### proxy.*

HTTP/HTTPS proxy control.

```python
# Block URL
proxy.block_url(url)

# Allow URL
proxy.allow_url(url)

# Get request context
req = proxy.get_request()
log.info(f"User: {req['user']}, URL: {req['url']}")

# Modify response
proxy.inject_header("X-Security-Scan", "passed")
```

#### network.*

Network operations and analysis.

```python
# Get device info
device = network.get_device_by_ip(ip)
log.info(f"Device: {device['hostname']}, MAC: {device['mac']}")

# Port scan
ports = network.port_scan(ip, ports=[22, 80, 443])

# Traceroute
path = network.traceroute(destination)

# Get network topology
topology = network.get_topology()
```

### Data Loss Prevention

#### dlp.*

Content scanning and policy enforcement.

```python
# Scan text for sensitive data
result = dlp.scan_text(email_body, sensitivity="high")
if result["has_pii"]:
    log.alert("PII detected")

# Specific detectors
has_cc = dlp.contains_credit_cards(text)
has_ssn = dlp.contains_ssn(text)
has_phi = dlp.contains_phi(medical_record)
has_secrets = dlp.contains_secrets(config_file)

# Pattern matching
emails = dlp.find_emails(text)
phones = dlp.find_phone_numbers(text)
api_keys = dlp.find_pattern(r'AKIA[0-9A-Z]{16}', logs)

# Data transformation
redacted = dlp.redact(text, patterns=["ssn", "credit_card"])
masked = dlp.mask(credit_card_number, pattern_type="credit_card")
hashed = dlp.hash_pii(email)

# Policy enforcement
policy_result = dlp.enforce_policy(scan_result, policy="block")
if policy_result["action"] == "block":
    dlp.quarantine_file(file_path)

# Compliance checks
hipaa = dlp.check_hipaa_compliance(scan_result)
pci = dlp.check_pci_compliance(scan_result)
gdpr = dlp.check_gdpr_compliance(scan_result)
```

### Cloud & Access Control

#### cloud.*

Multi-cloud access control and compliance.

```python
# Check user permissions
can_access = cloud.check_permission(
    user_id="john@company.com",
    action="read_object",
    provider=cloud.AWS
)

# Evaluate policy
policy = cloud.evaluate_policy({
    "user_id": "john@company.com",
    "cloud_provider": "aws",
    "service": "s3",
    "action": "GetObject",
    "resource": "arn:aws:s3:::production/*"
})

if policy["allow"]:
    log.info("Access granted")
else:
    log.alert(f"Access denied: {policy['reason']}")

# Get user profile
profile = cloud.get_user_profile(user_id)
compliance_frameworks = profile["compliance"]

# Compliance logs
sox_logs = cloud.get_compliance_logs(cloud.SOX, days=90)
hipaa_logs = cloud.get_compliance_logs(cloud.HIPAA, days=30)

# Audit trail verification
verification = cloud.verify_audit_chain()
if not verification["valid"]:
    notify.slack("🚨 Audit log tampering detected!")

# Log action
cloud.log_action({
    "user_id": user_id,
    "action": "CreateBucket",
    "resource": "arn:aws:s3:::new-bucket",
    "timestamp": runtime.now()
})

# Supported providers
cloud.AWS      # Amazon Web Services
cloud.GCP      # Google Cloud Platform
cloud.AZURE    # Microsoft Azure
cloud.OCI      # Oracle Cloud Infrastructure

# Compliance frameworks
cloud.HIPAA    # Healthcare
cloud.SOX      # Financial
cloud.PCI_DSS  # Payment Card
cloud.GDPR     # Privacy
cloud.FEDRAMP  # Government
```

### Threat Intelligence

#### threat.*

Threat intelligence integration.

```python
# Check IP reputation
threat_data = threat.check_ip(ip)
log.info(f"Threat score: {threat_data['score']}")
log.info(f"Categories: {threat_data['categories']}")

# Check domain
domain_intel = threat.check_domain(domain)
if domain_intel["malicious"]:
    dns.blackhole(domain)

# Check file hash
file_threat = threat.check_hash(sha256_hash)

# Get feed data
malware_ips = threat.get_feed("malware_ips")
c2_domains = threat.get_feed("c2_domains")

# Submit IOC
threat.submit_ioc({
    "type": "ip",
    "value": "192.168.1.100",
    "confidence": "high",
    "category": "malware"
})
```

### AI & Machine Learning

#### ai.*

AI-powered security analysis (OpenRouter BYOK).

```python
# Analyze threat
analysis = ai.analyze_threat(
    iocs=["192.168.1.100", "malicious.com"],
    threat_type="ransomware",
    context="Attack on production server"
)
log.info(f"AI Assessment: {analysis['threat_assessment']}")

# Analyze packet
packet_analysis = ai.analyze_packet(
    packet_data=str(packet),
    protocol="https",
    context="Possible data exfiltration"
)

# Chat interface
response = ai.chat([
    {"role": "system", "content": "You are a security analyst"},
    {"role": "user", "content": "Analyze this log: ..."}
])

# Generate security rule
rule = ai.generate_rule(
    description="Block cryptocurrency mining traffic",
    rule_type="firewall",
    platform="iptables"
)

# Run AI skill
result = ai.run_skill(
    skill_name="incident_responder",
    input_data="Suspicious activity from 10.0.0.50"
)
```

### Telephony & Alerts

#### asterisk.*

On-premises PBX/VoIP control.

```python
# Emergency call
asterisk.emergency_call(
    from_number="5000",
    to_number="+15550101",
    message="Critical security alert"
)

# Conference call (SOC team)
asterisk.create_conference(
    numbers=["+15550101", "+15550102"],
    pin="1234"
)

# Voicemail
asterisk.send_voicemail(
    mailbox="5000",
    message_file="/tmp/alert.wav"
)
```

#### tts.*

AI voice generation (ElevenLabs).

```python
# Generate alert audio
audio_file = tts.speak(
    text="Critical security alert. Data exfiltration detected.",
    voice_id="rachel",  # Professional female
    output_path="/tmp/alert.mp3"
)

# Available voices
tts.RACHEL     # Professional female
tts.ADAM       # Professional male
tts.CLYDE      # Authoritative male
```

#### telnyx.*

Cloud telephony (carrier #1).

```python
# Send SMS
telnyx.send_sms(
    from_number="+18005550100",
    to_number="+15550101",
    text="Security alert: Firewall breach detected"
)

# Make call
telnyx.make_call(
    from_number="+18005550100",
    to_number="+15550101",
    message="This is a security alert",
    voice="male"
)

# Emergency broadcast
result = telnyx.emergency_broadcast(
    numbers=["+15550101", "+15550102", "+15550103"],
    message="Critical incident",
    from_number="+18005550100"
)
log.info(f"Delivered: {result['success']}/{result['total']}")
```

#### twilio.*

Cloud telephony (carrier #2 - failover).

```python
# Same API as telnyx
twilio.send_sms(...)
twilio.make_call(...)
twilio.emergency_broadcast(...)
```

### Packet Capture & Analysis

#### pcap.*

Packet capture and deep inspection.

```python
# Capture packets
packets = pcap.capture(
    interface="eth0",
    count=1000,
    filter="port 443"
)

# Decode packet
for packet in packets:
    data = pcap.decode(packet)
    log.info(f"Packet: {data['src_ip']} -> {data['dst_ip']}")

    # Extract payload
    if "payload" in data:
        if dlp.contains_secrets(data["payload"]):
            firewall.block(data["src_ip"])

# Save PCAP
pcap.save(packets, "/tmp/suspicious.pcap")

# Load PCAP
loaded = pcap.load("/tmp/capture.pcap")
```

### Email Processing

#### email.*

Email parsing and inspection.

```python
# Parse email
parsed = email.parse(raw_email_data)
log.info(f"From: {parsed['from']}")
log.info(f"Subject: {parsed['subject']}")

# Scan attachments
for attachment in parsed["attachments"]:
    scan = dlp.scan_file(attachment["path"])
    if scan["blocked"]:
        email.quarantine(message_id)

# Headers
headers = email.get_headers(raw_email)
spf = headers["Received-SPF"]
dkim = headers["DKIM-Signature"]
```

### Notifications

#### notify.*

Multi-channel alerting.

```python
# Slack
notify.slack("🚨 Security alert: Firewall breach")

# Email
notify.email(
    to="soc@company.com",
    subject="Critical Alert",
    body="Details: ..."
)

# Webhook
notify.webhook("https://soc.company.com/alert", {
    "severity": "critical",
    "source": "threatscript",
    "alert": "Data exfiltration detected"
})

# PagerDuty
notify.pagerduty(
    service_key="xxx",
    description="Security incident",
    severity="critical"
)
```

### Logging

#### log.*

Structured logging with levels.

```python
log.debug("Detailed diagnostic info")
log.info("Normal operations")
log.warn("Potential issue")
log.error("Error occurred")
log.alert("Security alert - requires attention")
log.critical("System critical - immediate action required")

# Structured logging
log.info("User login", {
    "user": "john@company.com",
    "ip": "10.0.0.50",
    "timestamp": runtime.now()
})
```

### Mobile Device Management

#### mdm.*

Device control and enforcement.

```python
# Lock device
mdm.lock_device(device_id)

# Wipe device (remote)
mdm.wipe_device(device_id)

# Get device status
status = mdm.get_device_status(device_id)
if not status["compliant"]:
    mdm.lock_device(device_id)

# Enforce policy
mdm.enforce_policy(device_id, policy_id="corporate_security")
```

### Runtime

#### runtime.*

Runtime utilities and context.

```python
# Current time
now = runtime.now()
timestamp = runtime.timestamp()

# Script info
script_id = runtime.get_script_id()
execution_id = runtime.get_execution_id()

# Variables (context-specific)
user = runtime.get_variable("user")
request_url = runtime.get_variable("request_url")

# Environment
env_var = runtime.get_env("API_KEY")

# Sleep (limited to prevent abuse)
runtime.sleep(seconds=1)  # Max 5s
```

---

## Security Model

### Sandboxing

ThreatScript runs in a hardened sandbox:

1. **No File I/O**: Cannot read/write arbitrary files
2. **No Network I/O**: Cannot make arbitrary HTTP requests
3. **No OS Commands**: Cannot execute shell commands
4. **Bounded Resources**: Max execution time, memory limits
5. **Module Whitelisting**: Only approved modules available

### Execution Limits

```python
# Default limits
MAX_EXECUTION_TIME = 5 seconds
MAX_MEMORY = 256 MB
MAX_ITERATIONS = 1,000,000
MAX_RECURSION_DEPTH = 100
```

### Rate Limiting

Scripts are rate-limited per:
- User
- Script ID
- IP address

### Audit Logging

All script executions are logged:
- Script ID
- User/trigger
- Input parameters
- Execution time
- Success/failure
- Actions taken (firewall blocks, alerts, etc.)

---

## Integration Points

### dnsscienced Integration

DNS-level threat automation:

```python
# Example: dns_threat_blocker.star
def on_dns_query(query):
    domain = query["domain"]

    # Check threat intelligence
    intel = threat.check_domain(domain)

    if intel["score"] > 80:
        # Block at DNS level
        dns.blackhole(domain)

        # Alert
        log.alert(f"Blocked malicious domain: {domain}")
        notify.slack(f"🚨 DNS threat blocked: {domain}")

        return {"action": "block"}

    return {"action": "allow"}
```

### ads-httpproxy Integration

HTTP-level threat automation:

```python
# Example: http_dlp_scanner.star
def on_http_request(request):
    url = request["url"]
    body = request["body"]

    # DLP scan
    scan = dlp.scan_text(body)

    if scan["has_secrets"]:
        # Block request
        proxy.block_url(url)

        # Alert
        log.alert(f"Blocked request with secrets: {url}")

        return {"action": "block", "reason": "Secrets detected"}

    return {"action": "allow"}
```

### security-appliance Integration

Standalone runtime for scheduled/manual execution:

```python
# Example: daily_threat_sweep.star (scheduled: 0 2 * * *)
def main():
    log.info("Starting daily threat sweep")

    # Get active firewall rules
    rules = firewall.list_rules()

    # Re-check threat scores
    for rule in rules:
        if "blocked_ip" in rule:
            ip = rule["blocked_ip"]
            current_threat = threat.check_ip(ip)

            # Unblock if threat score dropped
            if current_threat["score"] < 20:
                firewall.unblock(ip)
                log.info(f"Unblocked {ip} (threat score now {current_threat['score']})")

    log.info("Daily threat sweep completed")
```

---

## Best Practices

### 1. Always Log Actions

```python
# Good
if threat_data["score"] > 80:
    firewall.block(ip)
    log.alert(f"Blocked {ip} (score: {threat_data['score']})")

# Bad
if threat_data["score"] > 80:
    firewall.block(ip)  # Silent action
```

### 2. Graceful Degradation

```python
# Good
intel = threat.check_ip(ip)
if intel:  # Check if API returned data
    if intel["score"] > 80:
        firewall.block(ip)
else:
    log.warn(f"Threat intel unavailable for {ip}")

# Bad
intel = threat.check_ip(ip)
if intel["score"] > 80:  # Will crash if API fails
    firewall.block(ip)
```

### 3. Use Descriptive Names

```python
# Good
def block_malicious_ip(ip, threat_score, reason):
    log.alert(f"Blocking {ip}: {reason} (score={threat_score})")
    firewall.block(ip)

# Bad
def do_thing(x, y, z):
    log.alert(f"{x} {z}")
    firewall.block(x)
```

### 4. Modular Functions

```python
# Good
def is_high_threat(score):
    return score > 80

def should_block(ip):
    threat_data = threat.check_ip(ip)
    return is_high_threat(threat_data["score"])

# Bad
def main():
    if threat.check_ip("10.0.0.1")["score"] > 80:  # Inline logic
        firewall.block("10.0.0.1")
```

### 5. Fail-Safe Defaults

```python
# Good - Fail open (allow traffic on error)
def main():
    try:
        intel = threat.check_ip(ip)
        if intel and intel["score"] > 90:  # Only block on high confidence
            firewall.block(ip)
    except:
        log.warn(f"Threat check failed for {ip}, allowing")

# Bad - Fail closed (could cause outage)
def main():
    if not threat.check_ip(ip):  # Block on API error
        firewall.block(ip)
```

---

## Advanced Patterns

### Multi-Stage Response

```python
def respond_to_threat(ip, threat_level):
    if threat_level == "low":
        log.info(f"Low threat from {ip}")

    elif threat_level == "medium":
        log.warn(f"Medium threat from {ip}")
        network.rate_limit(ip, max_requests=100)

    elif threat_level == "high":
        log.alert(f"High threat from {ip}")
        firewall.block(ip, duration="1h")
        notify.slack(f"⚠️ High threat blocked: {ip}")

    elif threat_level == "critical":
        log.critical(f"Critical threat from {ip}")
        firewall.block(ip)  # Permanent block
        dns.blackhole(network.reverse_dns(ip))
        notify.pagerduty("Critical threat detected")
        telnyx.emergency_broadcast(
            numbers=oncall_numbers,
            message=f"Critical threat from {ip}"
        )
```

### Correlation Analysis

```python
def detect_coordinated_attack():
    # Get recent firewall events
    events = firewall.get_events(minutes=5)

    # Group by source network
    networks = {}
    for event in events:
        ip = event["source_ip"]
        network = ".".join(ip.split(".")[:3]) + ".0/24"

        if network not in networks:
            networks[network] = []
        networks[network].append(ip)

    # Alert on coordinated attacks (5+ IPs from same /24)
    for network, ips in networks.items():
        if len(ips) >= 5:
            log.alert(f"Coordinated attack detected from {network}")

            # Block entire subnet
            for ip in ips:
                firewall.block(ip)

            # Escalate
            notify.pagerduty(f"Coordinated attack: {len(ips)} hosts from {network}")
```

### Compliance-Aware Automation

```python
def enforce_data_classification(file_path, classification):
    # Scan file
    scan = dlp.scan_file(file_path)

    # Determine required compliance
    required_frameworks = []
    if classification == "pii":
        required_frameworks = [cloud.SOX, cloud.GDPR]
    elif classification == "phi":
        required_frameworks = [cloud.HIPAA]
    elif classification == "financial":
        required_frameworks = [cloud.SOX, cloud.PCI_DSS]

    # Check compliance
    violations = []
    for framework in required_frameworks:
        if framework == cloud.HIPAA:
            result = dlp.check_hipaa_compliance(scan)
        elif framework == cloud.PCI_DSS:
            result = dlp.check_pci_compliance(scan)
        elif framework == cloud.GDPR:
            result = dlp.check_gdpr_compliance(scan)

        if not result["compliant"]:
            violations.append(result)

    # Take action
    if violations:
        dlp.quarantine_file(file_path)
        for violation in violations:
            log.alert(f"Compliance violation: {violation['framework']} - {violation['violation']}")
        notify.email("compliance@company.com", "Compliance Violation Detected", str(violations))

    return len(violations) == 0
```

---

## Debugging & Testing

### Local Testing

```bash
# Test script locally
threatscript run script.star

# With input variables
threatscript run script.star --var user=john --var ip=10.0.0.1

# Dry-run mode (no actual actions)
threatscript run script.star --dry-run
```

### Logging for Debug

```python
def main():
    log.debug("Script started")

    ip = "10.0.0.1"
    log.debug(f"Checking threat for {ip}")

    threat_data = threat.check_ip(ip)
    log.debug(f"Threat data: {threat_data}")

    if threat_data["score"] > 80:
        log.debug(f"Score {threat_data['score']} exceeds threshold 80")
        firewall.block(ip)
        log.info(f"Blocked {ip}")
```

---

## Version History

- **v1.0** (2026-04-01): Initial release
  - Core modules: firewall, dns, proxy, network
  - DLP module with compliance
  - Cloud access control
  - AI integration
  - Telephony modules (Asterisk, Telnyx, Twilio)
  - Integration with dnsscienced, ads-httpproxy, security-appliance

---

## License

ThreatScript is proprietary software developed by After Dark Systems, LLC.

---

## Support

For questions, bug reports, or feature requests:
- Email: support@afterdarksys.com
- Documentation: https://docs.afterdarksys.com/threatscript
- GitHub: https://github.com/afterdarksys/threatscript

---

*RyCat approved 🐱*
