# Lab 07 — Phishing Mail Identification with Wazuh Custom Rules

## Summary

This lab builds a **custom phishing detection pipeline** in Wazuh. A dedicated log file acts as a simulated email log source. Custom Wazuh rules scan each log entry for phishing indicators — spoofed sender domains, shortened URLs, executable attachments, urgency language, and Base64-encoded content. When a simulated phishing email is injected into the log file, the rules fire and the alert appears on the Wazuh dashboard with MITRE ATT&CK annotations. This demonstrates how SOC teams build custom detection logic for threat vectors not covered by default rules.

---

## Architecture & Data Flow

```
Phishing email received (simulated via log injection)
        |
        | Written to /var/log/phishing-mails.log on Ubuntu Agent
        v
Wazuh Agent — localfile monitor (syslog format)
        |
        | Log line forwarded to Manager
        v
Wazuh Manager — custom rules 100500–100505 evaluated
        |
        | Match: spoofed domain / malicious URL / executable attachment
        v
Alert generated with MITRE T1566 annotation
        v
Wazuh Dashboard → Security Events
```

---

## Mermaid Diagram

```mermaid
graph TD
    A[Phishing email log entry injected] --> B[/var/log/phishing-mails.log]
    B --> C[Wazuh Agent localfile monitor]
    C --> D[Wazuh Manager]
    D --> E{Custom rules 100500-100505}
    E --> F{paypa1.com in line?}
    E --> G{bit.ly URL detected?}
    E --> H{.exe attachment detected?}
    E --> I{Urgency language?}
    F -- Yes --> J[Rule 100500: Level 10]
    G -- Yes --> K[Rule 100501: Level 12]
    H -- Yes --> L[Rule 100502: Level 14]
    I -- Yes --> M[Rule 100503: Level 8]
    J & K & L & M --> N[Alerts in Wazuh Dashboard]
```

---

## Prerequisites

| Component | Version / Notes |
|-----------|----------------|
| Wazuh Manager | 4.x |
| Ubuntu Agent | 20.04 / 22.04 |
| Custom rules | Written in this lab (no external tools required) |
| Email server | Not required — log file is simulated |

---

## Theory Background

### What is Phishing?

**Phishing** is a social engineering attack where an adversary impersonates a trusted entity (a bank, an IT helpdesk, a package courier) to trick victims into revealing credentials, clicking malicious links, or opening malware-laden attachments.

MITRE ATT&CK classifies phishing under **T1566** (Phishing) with sub-techniques:
- T1566.001 — Spearphishing Attachment
- T1566.002 — Spearphishing Link
- T1566.003 — Spearphishing via Service

### Common Phishing Indicators

| Indicator | Example | Why Suspicious |
|-----------|---------|----------------|
| Domain spoofing | `paypa1.com` (1 instead of l) | Lookalike domain impersonating PayPal |
| Shortened URL | `bit.ly/abc123` | Hides actual destination |
| Executable attachment | `invoice.exe` | Direct malware delivery |
| Urgency language | "account suspended", "verify now" | Pressure tactics bypass critical thinking |
| Base64 content | `SGVsbG8gV29ybGQ=` | Obfuscation of malicious payload |

### Why Log-Based Detection?

In a production environment, phishing detection typically happens at the **email gateway** (Proofpoint, Mimecast, Microsoft Defender for O365) which parses every inbound email and outputs structured logs. These logs — containing sender, recipient, subject, URLs, attachment names, and verdicts — are forwarded to a SIEM.

This lab simulates that pipeline: the log file plays the role of the email gateway log. The custom rules play the role of the SIEM detection content. The approach is identical regardless of whether the source is a real gateway or a lab simulation.

### Custom Rule Design

Wazuh rules are evaluated against the decoded log content. The `<match>` tag does a case-sensitive string search. For phishing, we match on specific known-bad strings (domains, file extensions) and behavioral patterns (urgency phrases).

Rule severity levels used in this lab:
- Level 8 — Suspicious but low confidence (urgency language alone)
- Level 10 — Moderate confidence (spoofed domain)
- Level 12 — High confidence (shortened URL, common delivery vector)
- Level 14 — Near-certain threat (executable attachment)

---

## Step-by-Step Instructions

### Part 1 — Create the Phishing Log File

On the Ubuntu Agent:

```bash
sudo touch /var/log/phishing-mails.log
sudo chmod 644 /var/log/phishing-mails.log
```

---

### Part 2 — Add Log Source to Wazuh Agent

```bash
sudo nano /var/ossec/etc/ossec.conf
```

Add before `</ossec_config>`:

```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/phishing-mails.log</location>
</localfile>
```

**Restart the Agent:**

```bash
sudo systemctl restart wazuh-agent
```

---

### Part 3 — Create Custom Phishing Detection Rules

Navigate to: **Wazuh GUI → Management → Rules → Manage Rules Files → local_rules.xml**

Or directly on the Manager:

```bash
sudo nano /var/ossec/etc/rules/local_rules.xml
```

Add:

```xml
<group name="phishing_detection,email_security">

  <!-- Rule 1: Spoofed/lookalike sender domain -->
  <rule id="100500" level="10">
    <match>paypa1.com</match>
    <description>Possible phishing sender domain detected (lookalike)</description>
    <mitre>
      <id>T1566</id>
    </mitre>
  </rule>

  <!-- Rule 2: Shortened URL (common phishing delivery) -->
  <rule id="100501" level="12">
    <match>bit.ly</match>
    <description>Suspicious shortened phishing URL detected</description>
    <mitre>
      <id>T1566</id>
    </mitre>
  </rule>

  <!-- Rule 3: Executable attachment (direct malware) -->
  <rule id="100502" level="14">
    <match>invoice.exe</match>
    <description>Suspicious executable attachment detected in email log</description>
    <mitre>
      <id>T1204</id>
    </mitre>
  </rule>

  <!-- Rule 4: Urgency language (social engineering pressure) -->
  <rule id="100503" level="8">
    <match>account suspended</match>
    <description>Phishing urgency language detected</description>
    <mitre>
      <id>T1566</id>
    </mitre>
  </rule>

  <!-- OPTIONAL Rule 5: Base64 encoded content (obfuscation) -->
  <rule id="100504" level="10">
    <regex>[A-Za-z0-9+/]{100,}={0,2}</regex>
    <description>Possible Base64 encoded phishing content detected</description>
    <mitre>
      <id>T1566</id>
    </mitre>
  </rule>

  <!-- OPTIONAL Rule 6: Multiple phishing attempts (volume detection) -->
  <rule id="100505" level="15" frequency="5" timeframe="60">
    <if_matched_sid>100500</if_matched_sid>
    <description>Multiple phishing attempts from same source detected</description>
    <mitre>
      <id>T1566</id>
    </mitre>
  </rule>

</group>
```

**Rule Notes:**

| Rule ID | Technique | Level | Notes |
|---------|-----------|-------|-------|
| 100500 | Domain spoofing | 10 | Extend with more lookalike domains: `g00gle.com`, `arnazon.com` |
| 100501 | Shortened URL | 12 | Also consider: `t.co`, `tinyurl.com`, `ow.ly` |
| 100502 | Malicious attachment | 14 | Extend to `.vbs`, `.js`, `.bat`, `.ps1` |
| 100503 | Social engineering | 8 | Also: "verify immediately", "your password has expired" |
| 100504 | Obfuscation | 10 | Base64 of 100+ chars is rarely legitimate in email headers |
| 100505 | Campaign detection | 15 | 5+ domain-spoofing hits in 60 seconds = active campaign |

**Restart the Manager:**

```bash
sudo systemctl restart wazuh-manager
```

---

### Part 4 — Trigger Phishing Alerts

Inject a simulated phishing email log entry on the Ubuntu Agent:

```bash
echo "From: support@paypa1.com Subject: Your account has been suspended - verify account now http://bit.ly/login Attachment: invoice.exe" | sudo tee -a /var/log/phishing-mails.log
```

This single line contains **four indicators** and should trigger rules 100500, 100501, 100502, and 100503 simultaneously.

**Test individual indicators:**

```bash
# Only shortened URL
echo "Click here: http://bit.ly/abc123 to reset your password" | sudo tee -a /var/log/phishing-mails.log

# Only executable attachment
echo "Please review the attached invoice.exe from Accounting" | sudo tee -a /var/log/phishing-mails.log

# Base64 encoded content (obfuscated payload)
echo "Body: SGVsbG8sIHBsZWFzZSBjbGljayBoZXJlIHRvIHZlcmlmeSB5b3VyIGFjY291bnQgaW1tZWRpYXRlbHk=" | sudo tee -a /var/log/phishing-mails.log
```

---

### Part 5 — View Alerts

Navigate to: **Wazuh Dashboard → Agents → [ubuntu-agent] → Security Events**

Filter by rule group `phishing_detection` or search for rule IDs 100500–100505.

---

## Expected Alerts & How to Read Them

### Alert: Spoofed Domain (Rule 100500)

```json
{
  "rule": {
    "id": "100500",
    "level": 10,
    "description": "Possible phishing sender domain detected (lookalike)",
    "groups": ["phishing_detection", "email_security"],
    "mitre": {
      "technique": ["Phishing"],
      "id": ["T1566"]
    }
  },
  "full_log": "From: support@paypa1.com Subject: Your account has been suspended",
  "agent": {
    "name": "ubuntu-agent",
    "ip": "192.168.43.142"
  },
  "timestamp": "2025-06-01T12:30:00.000Z"
}
```

### Alert: Executable Attachment (Rule 100502)

```json
{
  "rule": {
    "id": "100502",
    "level": 14,
    "description": "Suspicious executable attachment detected in email log",
    "mitre": {
      "technique": ["User Execution"],
      "id": ["T1204"]
    }
  },
  "full_log": "...Attachment: invoice.exe"
}
```

**Key fields:**
- `rule.level` — level 14 is near-critical; most SIEM workflows page on-call at level 12+
- `rule.mitre.id` — links to MITRE ATT&CK framework for playbook lookup
- `full_log` — the raw log line that matched; shows exact context

---

## Troubleshooting

| Problem | Likely Cause | Fix |
|---------|-------------|-----|
| No alerts after log injection | Agent not monitoring the file | Verify `<localfile>` block and restart agent |
| Rules not triggering | Rule syntax error in XML | Check for unclosed tags; restart manager and check `/var/ossec/logs/ossec.log` |
| Only some rules firing | Manager rule loading issue | Run `sudo /var/ossec/bin/wazuh-logtest` and pipe a test log line to verify |
| `wazuh-manager` fails to restart | XML syntax error in rules | Validate XML: `xmllint --noout /var/ossec/etc/rules/local_rules.xml` |
| Rule ID conflict | ID already used by another rule | Choose IDs in 100000–109999 range; search existing rules first |

**Test a rule manually without waiting for log injection:**

```bash
echo "support@paypa1.com account suspended invoice.exe bit.ly" | sudo /var/ossec/bin/wazuh-logtest
```

This pipes a test line through Wazuh's decoder/rule engine interactively.

---

## SOC Analysis Methodology

When phishing alerts fire in a real SOC, the analyst follows a structured workflow:

```
1. IDENTIFY
   - Who is the recipient?
   - What is the sender domain? (WHOIS, registration age)
   - Is this isolated or part of a campaign?

2. ANALYZE
   - Expand shortened URL (use a sandbox — never click directly)
   - Submit attachment hash to VirusTotal (Lab 06)
   - Check email headers for SPF/DKIM/DMARC failures
   - Decode Base64 content if present

3. CONTAIN
   - Block sender domain at email gateway
   - Block malicious URL at web proxy
   - Quarantine the email from all recipient mailboxes

4. NOTIFY
   - Alert the recipient not to open the email
   - Notify the security team if credential theft may have occurred
   - Report the phishing domain to registrar / Google Safe Browsing

5. DOCUMENT
   - Create an incident ticket
   - Log IOCs: sender domain, URL, file hash, subject line
   - Feed IOCs back into detection rules (as new <match> entries)
```

---

## Optional Enhancements

### Block the Sender IP via Active Response

Combine this lab with Lab 05's active response to automatically block the source IP when phishing rule 100500 fires.

### VirusTotal Lookup of Attachment Hash

When an executable attachment is detected, combine with Lab 06 — extract the filename, compute hash, query VirusTotal automatically.

### Email Header Analysis

In a real deployment, extend the log format to include full email headers. Add rules that detect:
- `SPF: fail` — sender not authorized for domain
- `DMARC: fail` — domain policy violation
- `X-Mailer: Kali` — known attacker tooling headers

---

## Real-World Relevance

According to the Verizon Data Breach Investigations Report, **phishing is consistently the #1 initial access vector** in breaches year after year. SOC teams invest significant effort in building and tuning phishing detection rules that can adapt to new campaign patterns.

The custom rule approach in this lab — matching on specific indicators and tagging with MITRE IDs — is identical to how commercial SIEM content is written. The difference in production is the data source (a real email security gateway instead of a simulated log file) and the breadth of indicators (hundreds of rules instead of five).

---

## What I Learned

- Custom Wazuh rules are the mechanism for extending detection beyond the built-in ruleset — this skill is directly applicable to any Wazuh deployment.
- The `<match>` tag does simple string matching; `<regex>` supports patterns like Base64 detection — knowing when to use each is important.
- MITRE ATT&CK IDs in rules aren't just labels — they link to structured playbooks that tell analysts exactly how to respond.
- `wazuh-logtest` is an invaluable debugging tool — it lets you test rules interactively without deploying to production.
- Rule frequency + timeframe detection (rule 100505) is how you build **campaign detection** on top of individual IOC matches — a crucial upgrade from single-event alerting.
