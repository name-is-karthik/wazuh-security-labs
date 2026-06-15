# Lab 04 — Detecting Malicious Commands with auditd + Wazuh

## Summary

This lab uses **Linux Audit Daemon (auditd)** to log the execution of specific high-risk binaries (`wget`, `curl`, `nmap`, `netcat`, `bash`, `python3`) on an Ubuntu agent. Wazuh ingests these audit logs and a custom detection rule fires a high-severity alert whenever one of these commands is executed. This mimics how a SOC detects post-exploitation activity — the phase after an attacker has gained a foothold and begins living off the land.

---

## Architecture & Data Flow

```
Attacker / User runs: wget, curl, nc, nmap, bash, python3
        |
        | Linux kernel audit subsystem intercepts syscall
        v
auditd — writes EXECVE record to /var/log/audit/audit.log
        |
        | Wazuh Agent reads audit.log via localfile monitor
        v
Wazuh Manager — decodes audit format, matches custom rule 100300
        v
Alert: "Potential malicious command execution detected via auditd"
        v
Wazuh Dashboard — Security Events (level 12)
```

---

## Mermaid Diagram

```mermaid
graph TD
    A[User executes: wget / curl / nc / nmap] --> B[Linux Kernel Audit Subsystem]
    B --> C[auditd records EXECVE syscall event]
    C --> D[/var/log/audit/audit.log]
    D --> E[Wazuh Agent localfile monitor]
    E --> F[Wazuh Manager]
    F --> G{Matches custom rule 100300?}
    G -- Yes --> H[Alert: Level 12 - Malicious command execution]
    G -- No --> I[Event stored, no high-priority alert]
    H --> J[Wazuh Dashboard]
```

---

## Prerequisites

| Component | Version / Notes |
|-----------|----------------|
| Ubuntu Agent | 20.04 / 22.04 |
| auditd | `auditd` + `audispd-plugins` packages |
| Wazuh Agent | Connected to Wazuh Manager |
| Wazuh Manager | 4.x |
| Test binaries | `wget`, `curl`, `nmap`, `netcat` should be installed |

---

## Theory Background

### What is auditd?

The **Linux Audit Daemon** is a kernel-level subsystem built into the Linux kernel that can record security-relevant system calls and file access events. Unlike application-level logs, auditd sits below the application — it catches events even if the application itself produces no logs.

Key concepts:
- **Audit rules** tell the kernel which events to track (e.g., every execution of `/usr/bin/wget`)
- **Audit keys (`-k`)** are labels attached to rules — they appear in log entries for easy filtering
- **EXECVE records** are generated every time the `execve()` system call is made — which is how every Linux process launches

### What is "Living off the Land" (LotL)?

Modern attackers often avoid dropping custom malware. Instead, they use **legitimate system tools** that are already present — `wget`/`curl` to download second-stage payloads, `nc`/`netcat` for reverse shells, `python3` for in-memory execution, `nmap` for internal reconnaissance.

This technique is called **Living off the Land (LotL)** because the attacker uses the "land" (the victim's own tools) rather than bringing their own weapons.

By monitoring these binaries with auditd, blue teams can detect LotL activity regardless of obfuscation — the kernel audit subsystem can't be fooled by renaming binaries or changing arguments.

### auditd Rule Syntax

```
-w <path>    Watch this file
-p x         Trigger on execute permission
-k <key>     Attach this label to matching log events
```

Example:
```
-w /usr/bin/wget -p x -k wget_execution
```
This rule tells the kernel: "Whenever `/usr/bin/wget` is executed, write an audit record tagged `wget_execution`."

---

## Step-by-Step Instructions

### Part 1 — Install auditd

```bash
sudo apt update
sudo apt install auditd audispd-plugins -y
```

**Enable and start:**

```bash
sudo systemctl enable auditd
sudo systemctl start auditd
sudo systemctl status auditd
```

**Verify it's writing logs:**

```bash
sudo tail -f /var/log/audit/audit.log
```

You should see `type=DAEMON_START` and ongoing system event records.

---

### Part 2 — Integrate auditd with Wazuh Agent

```bash
sudo nano /var/ossec/etc/ossec.conf
```

Add before `</ossec_config>`:

```xml
<localfile>
  <location>/var/log/audit/audit.log</location>
  <log_format>audit</log_format>
</localfile>
```

> The `<log_format>audit</log_format>` tag is critical — it tells Wazuh to use its built-in auditd decoder instead of the generic syslog decoder.

```bash
sudo systemctl restart wazuh-agent
```

---

### Part 3 — Add Audit Rules for Dangerous Commands

```bash
sudo nano /etc/audit/rules.d/audit.rules
```

Add these rules:

```
## Monitor execution of high-risk binaries
-w /usr/bin/wget     -p x -k wget_execution
-w /usr/bin/curl     -p x -k curl_execution
-w /usr/bin/nc       -p x -k nc_execution
-w /usr/bin/nmap     -p x -k nmap_execution
-w /usr/bin/bash     -p x -k bash_execution
-w /usr/bin/python3  -p x -k python_execution
```

> **Note:** `bash` and `python3` are intentionally broad — these rules will fire on every shell and Python invocation, which can be noisy. In production, you'd scope these more tightly (e.g., only when launched by specific non-root users, or only from world-writable directories).

**Load the rules without a reboot:**

```bash
sudo augenrules --load
```

**Verify the rules are active:**

```bash
sudo auditctl -l
```

Expected output shows each `-w` rule listed.

---

### Part 4 — Create Custom Wazuh Detection Rule

Navigate to Wazuh GUI → **Management → Rules → Manage Rules Files** → open `local_rules.xml`.

Add the following rule (or edit directly on the Manager):

```bash
sudo nano /var/ossec/etc/rules/local_rules.xml
```

```xml
<group name="auditd,command_execution">

  <rule id="100300" level="12">
    <match>wget_execution|curl_execution|nc_execution|nmap_execution</match>
    <description>Potential malicious command execution detected via auditd</description>
    <mitre>
      <id>T1059</id>
    </mitre>
  </rule>

</group>
```

| Field | Explanation |
|-------|-------------|
| `id="100300"` | Custom rules use IDs 100000–109999 to avoid conflict with built-ins |
| `level="12"` | High severity (scale 0–15); level 12 triggers most SIEM alerts |
| `<match>` | Looks for the audit key in the log line |
| `T1059` | MITRE ATT&CK technique: Command and Scripting Interpreter |

**Restart the Manager:**

```bash
sudo systemctl restart wazuh-manager
```

---

### Part 5 — Attack Simulation

Run these commands on the Ubuntu Agent to trigger alerts:

```bash
# Download a file (wget)
wget http://example.com/test.sh

# Fetch a URL (curl)
curl http://example.com

# Open a listening port (netcat — typical reverse shell setup)
nc -lvnp 4444

# Port scan localhost (nmap)
nmap localhost
```

---

## Expected Alerts & How to Read Them

### Raw auditd Log Entry

```
type=SYSCALL msg=audit(1717200000.123:456): arch=c000003e syscall=59 success=yes exit=0 a0=55a1b2c3 a1=55a1b2c4 a2=55a1b2c5 a3=0 items=2 ppid=1234 pid=5678 auid=0 uid=0 gid=0 euid=0 ses=1 tty=pts0 comm="wget" exe="/usr/bin/wget" key="wget_execution"
type=EXECVE msg=audit(1717200000.123:456): argc=2 a0="wget" a1="http://example.com/test.sh"
```

**Key fields:**
- `comm="wget"` — the command name
- `exe="/usr/bin/wget"` — full path of the executed binary
- `key="wget_execution"` — the audit rule label that matched
- `uid=0` — executed as root (escalation concern)
- `ppid=1234` / `pid=5678` — parent and child process IDs (useful for process tree reconstruction)
- `EXECVE a0, a1...` — the full command line arguments

### Wazuh Alert

```json
{
  "rule": {
    "id": "100300",
    "level": 12,
    "description": "Potential malicious command execution detected via auditd",
    "mitre": {
      "technique": ["Command and Scripting Interpreter"],
      "id": ["T1059"]
    }
  },
  "data": {
    "audit": {
      "command": "wget",
      "exe": "/usr/bin/wget",
      "key": "wget_execution",
      "auid": "0",
      "uid": "0",
      "pid": "5678",
      "ppid": "1234",
      "tty": "pts0"
    }
  },
  "agent": {
    "name": "ubuntu-agent",
    "ip": "192.168.43.142"
  }
}
```

**Verify alerts via command line:**

```bash
sudo ausearch -k wget_execution
sudo tail -f /var/log/audit/audit.log
```

---

## Troubleshooting

| Problem | Likely Cause | Fix |
|---------|-------------|-----|
| No audit logs generated | auditd not running | `sudo systemctl start auditd` |
| Rules not persisting after reboot | Rules in wrong file | Use `/etc/audit/rules.d/audit.rules`, not `/etc/audit/audit.rules` |
| `augenrules: command not found` | `auditd` package incomplete | Install `auditd` not just `audit-libs` |
| Wazuh not parsing audit logs | Wrong log format | Confirm `<log_format>audit</log_format>` (not `syslog`) |
| Custom rule not matching | Key mismatch | `auditctl -l` — confirm key matches exactly what's in the `<match>` tag |
| Rule ID conflict | ID already used | Run ID range 100000–109999; search existing rules first |
| `nc` path different | Netcat installed differently | Run `which nc` — may be at `/bin/nc.openbsd` or `/usr/bin/nc` |

---

## Real-World Relevance

In enterprise environments, auditd-based command monitoring is a layer of **endpoint detection** that complements EDR tools. The specific binaries monitored in this lab match several well-known threat actor TTPs:

| Binary | Real-World Use by Attackers |
|--------|----------------------------|
| `wget` / `curl` | Stage 2 payload download, C2 check-in |
| `nc` / `netcat` | Reverse shells, data exfiltration |
| `nmap` | Internal reconnaissance after initial access |
| `python3` | In-memory payloads, running downloaded scripts |
| `bash` | Script execution after download, privilege escalation |

MITRE ATT&CK T1059 (Command and Scripting Interpreter) is consistently in the **top 5 most-used techniques** in real breach reports. Having detection for these execution vectors is a baseline expectation in any mature SOC.

---

## What I Learned

- auditd operates at the kernel syscall level — it cannot be bypassed by applications the way file-based logging can.
- Audit keys (`-k`) are the linking mechanism between kernel events and Wazuh rules — the key name must match exactly.
- The `EXECVE` record captures the full argument list — this means you can see not just that `wget` ran, but the exact URL it was told to fetch.
- Wazuh's `<log_format>audit</log_format>` setting activates a specialized decoder that extracts structured fields from the verbose auditd format.
- `bash_execution` and `python3_execution` rules are intentionally broad — in production, combining them with user/path context prevents alert fatigue.
