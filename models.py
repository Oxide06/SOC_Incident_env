# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

"""
Data models for the SOC Incident Response Environment.
 
The agent acts as a SOC analyst who:
  1. Receives a security alert (observation)
  2. Chooses an investigation/response action
  3. Gets rewarded for correct, proportionate decisions
 
Difficulty levels:
  - easy:   single-signal alerts, clear indicators
  - medium: multi-signal alerts, some ambiguity
  - hard:   noisy, conflicting signals, requires chained reasoning
"""
 
from typing import Any, Dict, List, Literal, Optional
 
from openenv.core.env_server.types import Action, Observation
from pydantic import Field
 
# ──────────────────────────────────────────────
# ACTION
# ──────────────────────────────────────────────
 
# Every valid decision a SOC analyst can take
SOCDecision = Literal[
    "ignore",           # False positive – take no action
    "monitor",          # Keep watching but don't act yet
    "investigate",      # Pull logs / run queries for more context
    "block_ip",         # Block the offending IP at firewall
    "block_account",    # Disable the user account
    "isolate_device",   # Quarantine the endpoint
    "escalate",         # Hand off to Tier-2 / Incident Commander
    "request_mfa",      # Force re-authentication with MFA
    "patch_system",     # Apply patch / remediate vulnerability
    "collect_forensics",# Preserve evidence for forensic analysis
]
 
 
class SOCAction(Action):
    """
    Action taken by the SOC analyst agent.
 
    The agent picks ONE decision from the list above.
    Optionally it can attach a reasoning string (good for LLM agents).
    """
    decision: SOCDecision = Field(
        ...,
        description="The analyst's response decision"
    )
    reasoning: Optional[str] = Field(
        default=None,
        description="Optional free-text reasoning (used for LLM agents)"
    )
 
 
# ──────────────────────────────────────────────
# OBSERVATION
# ──────────────────────────────────────────────
 
class SOCObservation(Observation):
    """
    What the SOC analyst sees at each step.
 
    alert_type        : Category of the security alert
    severity          : 'low' | 'medium' | 'high' | 'critical'
    signals           : List of observable indicators (what triggered the alert)
    context           : Extra background info unlocked by prior investigation steps
    available_actions : Which decisions are legal in the current state
    phase             : Where we are in the incident lifecycle
    feedback          : Textual feedback on the last action taken
    score             : Cumulative score so far
    step              : Current step number
    max_steps         : Maximum steps before episode ends
    done              : Whether the episode has ended
    reward            : Reward received for the last action
    """
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
 