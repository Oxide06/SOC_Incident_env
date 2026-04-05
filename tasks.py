# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

"""
SOC Environment — Task Definitions with Agent Graders.

Each task is a concrete, named objective with:
  - A fixed scenario (deterministic — same seed every run)
  - A grader function that scores agent performance 0.0–1.0
  - Clear success/failure criteria

Tasks:
  task_easy   — Login anomaly triage (false positive detection)
  task_medium — Insider threat response (multi-step containment)
  task_hard   — APT lateral movement response (chained reasoning)
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class TaskResult:
    task_name: str
    score: float          # 0.0–1.0
    steps_taken: int
    actions_taken: List[str]
    success: bool
    reason: str


# ─────────────────────────────────────────────────────────────────────────────
# TASK DEFINITIONS
# Each task pins a specific scenario ID (deterministic) and defines its grader.
# ─────────────────────────────────────────────────────────────────────────────

TASKS = {
    "task_easy": {
        "name": "task_easy",
        "display_name": "Login Anomaly Triage",
        "difficulty": "easy",
        "scenario_id": "easy_false_positive_vpn",   # pinned — always this scenario
        "description": (
            "A low-severity login alert has fired for an employee logging in "
            "from an unusual location. The agent must correctly identify this "
            "as a false positive (VPN usage) and choose to ignore it — without "
            "over-reacting and disrupting a legitimate user."
        ),
        "max_steps": 5,
        "success_criteria": "Agent correctly ignores the false-positive alert.",
    },
    "task_medium": {
        "name": "task_medium",
        "display_name": "Insider Threat Containment",
        "difficulty": "medium",
        "scenario_id": "medium_insider_threat",     # pinned
        "description": (
            "A departing employee is actively exfiltrating confidential files "
            "on their final working days. The agent must investigate, contain "
            "the account, preserve evidence, and escalate — in a logical order."
        ),
        "max_steps": 8,
        "success_criteria": "Agent escalates after investigating and blocking the account.",
    },
    "task_hard": {
        "name": "task_hard",
        "display_name": "APT Lateral Movement Response",
        "difficulty": "hard",
        "scenario_id": "hard_apt_lateral_movement",  # pinned
        "description": (
            "An Advanced Persistent Threat (APT) is actively moving laterally "
            "through the network using Cobalt Strike. The agent must identify "
            "the attack chain, isolate compromised hosts, block C2 communication, "
            "collect forensic evidence, and escalate to Tier-2 — all within "
            "12 steps on a noisy, high-stakes incident."
        ),
        "max_steps": 12,
        "success_criteria": "Agent isolates device, blocks IP, collects forensics, and escalates.",
    },
}


# ─────────────────────────────────────────────────────────────────────────────
# GRADERS  — deterministic, 0.0–1.0
# ─────────────────────────────────────────────────────────────────────────────

def grade_task_easy(actions: List[str], final_score: float, done: bool) -> TaskResult:
    """
    Grader for task_easy (false-positive VPN login).

    Scoring:
      1.0 — investigated then ignored (perfect)
      0.8 — ignored without investigating (correct but skipped diligence)
      0.4 — investigated but did NOT ignore (missed false positive)
      0.0 — took a destructive terminal action (block_account, isolate_device, escalate)
      linear deduction for extra steps
    """
    investigated = "investigate" in actions
    ignored = "ignore" in actions
    overreacted = any(a in actions for a in ["block_account", "isolate_device", "escalate", "block_ip"])

    if overreacted:
        score = 0.0
        success = False
        reason = "Over-reacted to a false positive — disrupted a legitimate user."
    elif ignored and investigated:
        # Perfect path — penalise slightly for extra steps
        extra = max(0, len(actions) - 2)
        score = max(0.7, 1.0 - extra * 0.05)
        success = True
        reason = f"Correctly identified false positive after investigation. Steps: {len(actions)}"
    elif ignored:
        score = 0.8
        success = True
        reason = "Correctly ignored false positive (skipped investigation step)."
    elif investigated:
        score = 0.4
        success = False
        reason = "Investigated but failed to conclude this was a false positive."
    else:
        score = 0.1 * len(actions) if actions else 0.0
        success = False
        reason = "Did not reach a conclusion."

    return TaskResult(
        task_name="task_easy",
        score=round(min(1.0, max(0.0, score)), 2),
        steps_taken=len(actions),
        actions_taken=actions,
        success=success,
        reason=reason,
    )


def grade_task_medium(actions: List[str], final_score: float, done: bool) -> TaskResult:
    """
    Grader for task_medium (insider threat).

    Ideal sequence: investigate → block_account → collect_forensics → escalate

    Scoring rubric:
      investigate present       : +0.20
      block_account present     : +0.25
      collect_forensics present : +0.20
      escalate as terminal      : +0.25
      correct ordering bonus    : +0.10
      step efficiency deduction : −0.05 per wasted step (beyond 6)
    """
    score = 0.0
    investigated = "investigate" in actions
    blocked = "block_account" in actions
    forensics = "collect_forensics" in actions
    escalated = "escalate" in actions

    if investigated:    score += 0.20
    if blocked:         score += 0.25
    if forensics:       score += 0.20
    if escalated:       score += 0.25

    # Ordering bonus: investigate before block before escalate
    try:
        idx_inv = actions.index("investigate")
        idx_blk = actions.index("block_account")
        idx_esc = actions.index("escalate")
        if idx_inv < idx_blk < idx_esc:
            score += 0.10
    except ValueError:
        pass

    # Efficiency deduction
    extra = max(0, len(actions) - 6)
    score -= extra * 0.05

    score = round(min(1.0, max(0.0, score)), 2)
    success = score >= 0.7

    reason_parts = []
    if not investigated: reason_parts.append("missing investigation")
    if not blocked:      reason_parts.append("account not blocked")
    if not forensics:    reason_parts.append("no forensics collected")
    if not escalated:    reason_parts.append("not escalated")

    reason = (
        f"Score {score:.2f}. " +
        (f"Missing: {', '.join(reason_parts)}." if reason_parts else "All key actions taken.")
    )

    return TaskResult(
        task_name="task_medium",
        score=score,
        steps_taken=len(actions),
        actions_taken=actions,
        success=success,
        reason=reason,
    )


def grade_task_hard(actions: List[str], final_score: float, done: bool) -> TaskResult:
    """
    Grader for task_hard (APT lateral movement).

    Ideal: investigate → isolate_device → block_ip → collect_forensics → escalate

    Scoring:
      investigate       : +0.15
      isolate_device    : +0.20
      block_ip          : +0.20
      collect_forensics : +0.20
      escalate          : +0.15
      order bonus (all 5 in correct relative order) : +0.10
      step efficiency (> 8 steps) : −0.04 per extra step
      penalty for ignoring a critical threat : −0.5 (floor 0)
    """
    score = 0.0
    investigated  = "investigate"       in actions
    isolated      = "isolate_device"    in actions
    blocked_ip    = "block_ip"          in actions
    forensics     = "collect_forensics" in actions
    escalated     = "escalate"          in actions
    ignored       = "ignore"            in actions

    if ignored:
        return TaskResult(
            task_name="task_hard",
            score=0.0,
            steps_taken=len(actions),
            actions_taken=actions,
            success=False,
            reason="Critical APT incident ignored — catastrophic failure.",
        )

    if investigated:  score += 0.15
    if isolated:      score += 0.20
    if blocked_ip:    score += 0.20
    if forensics:     score += 0.20
    if escalated:     score += 0.15

    # Order bonus
    key_actions = ["investigate", "isolate_device", "block_ip", "collect_forensics", "escalate"]
    present_in_order = [a for a in actions if a in key_actions]
    expected_order = [a for a in key_actions if a in actions]
    if present_in_order == expected_order and len(expected_order) == 5:
        score += 0.10

    extra = max(0, len(actions) - 8)
    score -= extra * 0.04

    score = round(min(1.0, max(0.0, score)), 2)
    success = score >= 0.65

    missing = [a for a in key_actions if a not in actions]
    reason = (
        f"Score {score:.2f}. " +
        (f"Missing key actions: {', '.join(missing)}." if missing else "All critical actions taken.")
    )

    return TaskResult(
        task_name="task_hard",
        score=score,
        steps_taken=len(actions),
        actions_taken=actions,
        success=success,
        reason=reason,
    )


# Grader registry
GRADERS = {
    "task_easy":   grade_task_easy,
    "task_medium": grade_task_medium,
    "task_hard":   grade_task_hard,
}


def run_grader(task_name: str, actions: List[str], final_score: float, done: bool) -> TaskResult:
    """Run the grader for a named task and return a TaskResult."""
    if task_name not in GRADERS:
        raise ValueError(f"Unknown task: {task_name}. Available: {list(GRADERS.keys())}")
    return GRADERS[task_name](actions, final_score, done)
