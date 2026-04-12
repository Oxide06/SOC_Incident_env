# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

"""Data models for the SOC Incident Response Environment."""

from typing import Any, Dict, List, Literal, Optional

from openenv.core.env_server.types import Action, Observation
from pydantic import Field

SOCDecision = Literal[
    "ignore",             # False positive — take no action
    "monitor",            # Keep watching but don't act yet
    "investigate",        # Pull SIEM logs, review endpoint telemetry
    "query_logs",         # Deep SIEM query — firewall, proxy, DNS logs
    "check_threat_intel", # Query VirusTotal, Shodan, MISP, Mandiant
    "run_sandbox",        # Detonate suspicious file in sandbox
    "block_ip",           # Block offending IP at perimeter firewall
    "block_account",      # Disable the user account
    "isolate_device",     # Quarantine the endpoint from network
    "escalate",           # Hand off to Tier-2 / Incident Commander
    "request_mfa",        # Force re-authentication with MFA
    "patch_system",       # Apply patch / remove malicious package
    "collect_forensics",  # Preserve evidence for forensic analysis
]


class SOCAction(Action):
    """Action taken by the SOC analyst agent."""
    decision: SOCDecision = Field(
        ...,
        description="The analyst's response decision"
    )
    reasoning: Optional[str] = Field(
        default=None,
        description="Optional free-text reasoning (used for LLM agents)"
    )


class SOCObservation(Observation):
    """What the SOC analyst sees at each step."""
    alert_type: str = Field(default="", description="Type of security alert")
    severity: str = Field(default="low", description="Alert severity: low/medium/high/critical")
    signals: List[str] = Field(default_factory=list, description="Observable threat indicators")
    context: Dict[str, Any] = Field(default_factory=dict, description="Contextual info gathered so far")
    available_actions: List[str] = Field(default_factory=list, description="Valid actions at this step")
    phase: str = Field(default="detection", description="Incident lifecycle phase")
    feedback: str = Field(default="", description="Feedback on the last action")
    score: float = Field(default=0.0, description="Cumulative reward so far")
    step: int = Field(default=0, description="Current step")
    max_steps: int = Field(default=10, description="Max steps before done")