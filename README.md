# Wazuh Blue Team Security Labs

A collection of hands-on cybersecurity labs built around the **Wazuh SIEM/XDR platform**, documenting real detection, monitoring, and automated response scenarios in a self-hosted homelab environment.

---

## About

Hi, I'm **Mukkamala Karthik** — a final-year MCA student at Sathyabama University, Chennai, with a background in Python, Node.js, React, and FastAPI development.

These labs represent my journey into **blue team security and SOC operations**. I built this homelab to go beyond textbook knowledge and practice the detection engineering, log analysis, and automated response skills that real security teams use every day. My goal is to grow into a role where I can contribute to defensive security — whether that's as a SOC analyst, a security engineer, or a DevSecOps practitioner.

**Lab environment:**
- **Wazuh Manager** — central SIEM/XDR platform
- **Ubuntu 22.04** — monitored agent (simulated production server)
- **Kali Linux** — attacker machine for simulating threats

---

## Labs

| # | Folder | Lab Title | Description | Key Tools |
|---|--------|-----------|-------------|-----------|
| 01 | [`01-wazuh-file-integrity`](./01-wazuh-file-integrity/) | File Integrity Monitoring | Real-time detection of file creation, modification, and deletion in `/root` using Wazuh FIM (syscheck) | Wazuh FIM, inotify |
| 02 | [`02-suricata-nids-wazuh`](./02-suricata-nids-wazuh/) | Network Intrusion Detection | Suricata NIDS integrated with Wazuh to detect Nmap port scans and network-level attack signatures | Suricata, Wazuh, Nmap, AF_PACKET |
| 03 | [`03-vulnerability-detection`](./03-vulnerability-detection/) | Vulnerability Detection | Wazuh's built-in Vulnerability Detector cross-references installed package versions against NVD/OVAL CVE feeds | Wazuh Vuln Detector, NVD, Ubuntu OVAL |
| 04 | [`04-malicious-command-detection`](./04-malicious-command-detection/) | Malicious Command Detection | auditd kernel-level monitoring of high-risk binary execution (wget, curl, nc, nmap) with custom Wazuh rules | auditd, Wazuh, MITRE T1059 |
| 05 | [`05-ssh-brute-force-response`](./05-ssh-brute-force-response/) | SSH Brute Force + Active Response | Hydra brute force detected by Wazuh; attacker IP automatically blocked via iptables firewall-drop | Hydra, Wazuh Active Response, iptables |
| 06 | [`06-virustotal-fim-integration`](./06-virustotal-fim-integration/) | VirusTotal + FIM Integration | Files dropped in `/root` are automatically checked against VirusTotal's 70+ AV engines via API integration | Wazuh FIM, VirusTotal API, EICAR |
| 07 | [`07-phishing-mail-detection`](./07-phishing-mail-detection/) | Phishing Mail Detection | Custom Wazuh rules detect phishing indicators in email logs: spoofed domains, shortened URLs, executable attachments | Wazuh custom rules, MITRE T1566 |

---

## Lab Environment Setup

### Prerequisites

- Virtualization platform: VMware Workstation, VirtualBox, or Proxmox
- Wazuh OVA or manual install: [https://documentation.wazuh.com/current/quickstart.html](https://documentation.wazuh.com/current/quickstart.html)
- Ubuntu 22.04 Server ISO
- Kali Linux ISO

### Network Layout

```
┌─────────────────────────────────────────────┐
│              Host-Only / NAT Network         │
│              192.168.43.0/24                 │
│                                              │
│  ┌───────────────┐    ┌───────────────────┐  │
│  │  Wazuh        │    │  Ubuntu Agent     │  │
│  │  Manager      │◄───│  192.168.43.142   │  │
│  │  .1 or .200   │    │  (monitored)      │  │
│  └───────────────┘    └───────────────────┘  │
│                                              │
│  ┌───────────────┐                           │
│  │  Kali Linux   │                           │
│  │  192.168.43.x │ ← Attacker VM             │
│  └───────────────┘                           │
└─────────────────────────────────────────────┘
```

### Wazuh Agent Installation (Ubuntu)

```bash
# Download and install Wazuh agent (replace VERSION with current)
wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.x.x_amd64.deb
sudo WAZUH_MANAGER='MANAGER_IP' dpkg -i wazuh-agent_4.x.x_amd64.deb
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
```

---

## Detection Coverage Map

| MITRE ATT&CK Technique | Covered By |
|------------------------|-----------|
| T1059 — Command & Scripting Interpreter | Lab 04 |
| T1070 — Indicator Removal | Lab 01 (FIM detects log deletion) |
| T1110 — Brute Force | Lab 05 |
| T1204 — User Execution | Lab 07 |
| T1566 — Phishing | Lab 07 |
| T1595 — Active Scanning | Lab 02 |
| CVE-based vulnerabilities | Lab 03 |
| Malware file drops | Lab 06 |

---

## Tools Reference

| Tool | Purpose | Labs Used |
|------|---------|-----------|
| Wazuh | SIEM/XDR — central alerting platform | All labs |
| Suricata | Network IDS — packet-level detection | Lab 02 |
| auditd | Kernel-level command execution audit | Lab 04 |
| Hydra | Password brute force simulator | Lab 05 |
| VirusTotal API | Cloud-based malware hash lookup | Lab 06 |
| Nmap | Network scanner (attacker simulation) | Lab 02, 04 |
| iptables | Host firewall (active response backend) | Lab 05 |
| EICAR | Standard AV test file | Lab 06 |

---

## Key Skills Demonstrated

- Wazuh deployment, configuration, and custom rule authoring
- SIEM log source integration (auditd, Suricata, email logs, FIM)
- Writing detection rules with MITRE ATT&CK annotations
- Automated incident response (active response / firewall-drop)
- Third-party API integration (VirusTotal)
- Network intrusion detection and packet capture analysis
- Vulnerability management with CVE/CVSS scoring
- Phishing indicator detection and SOC triage methodology

---

## References & Learning Resources

- [Wazuh Documentation](https://documentation.wazuh.com/)
- [Suricata User Guide](https://docs.suricata.io/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [VirusTotal API Docs](https://developers.virustotal.com/reference/)
- [Linux Audit System Documentation](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/chap-system_auditing)
- [Emerging Threats Suricata Rules](https://rules.emergingthreats.net/)
- [National Vulnerability Database (NVD)](https://nvd.nist.gov/)

---

## License

This project is for educational purposes. All labs are conducted in an isolated homelab environment. No external systems were targeted.
