from dataclasses import dataclass
from typing import List


@dataclass
class TaskResult:
    task_name: str
    score: float
    steps_taken: int
    actions_taken: List[str]
    success: bool
    reason: str


TASKS = {
    "task_easy": {
        "name": "task_easy",
        "display_name": "Login Anomaly Triage",
        "difficulty": "easy",
        "scenario_id": "easy_false_positive_vpn",
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
        "scenario_id": "medium_insider_threat",
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
        "scenario_id": "hard_apt_lateral_movement",
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


def _clamp(score: float) -> float:
    """Clamp score to strictly open interval (0.01, 0.99)."""
    return round(min(0.99, max(0.01, score)), 2)


def grade_task_easy(actions: List[str], final_score: float, done: bool) -> TaskResult:
    investigated = "investigate" in actions
    ignored = "ignore" in actions
    overreacted = any(a in actions for a in ["block_account", "isolate_device", "escalate", "block_ip"])

    if overreacted:
        score = 0.02
        success = False
        reason = "Over-reacted to a false positive — disrupted a legitimate user."
    elif ignored and investigated:
        extra = max(0, len(actions) - 2)
        score = max(0.70, 0.98 - extra * 0.05)
        success = True
        reason = f"Correctly identified false positive after investigation. Steps: {len(actions)}"
    elif ignored:
        score = 0.78
        success = True
        reason = "Correctly ignored false positive (skipped investigation step)."
    elif investigated:
        score = 0.40
        success = False
        reason = "Investigated but failed to conclude this was a false positive."
    else:
        score = max(0.01, 0.10 * len(actions)) if actions else 0.01
        success = False
        reason = "Did not reach a conclusion."

    return TaskResult(
        task_name="task_easy",
        score=_clamp(score),
        steps_taken=len(actions),
        actions_taken=actions,
        success=success,
        reason=reason,
    )


def grade_task_medium(actions: List[str], final_score: float, done: bool) -> TaskResult:
    score = 0.0
    investigated = "investigate" in actions
    blocked = "block_account" in actions
    forensics = "collect_forensics" in actions
    escalated = "escalate" in actions

    if investigated:  score += 0.20
    if blocked:       score += 0.25
    if forensics:     score += 0.20
    if escalated:     score += 0.25

    try:
        idx_inv = actions.index("investigate")
        idx_blk = actions.index("block_account")
        idx_esc = actions.index("escalate")
        if idx_inv < idx_blk < idx_esc:
            score += 0.05
    except ValueError:
        pass

    extra = max(0, len(actions) - 6)
    score -= extra * 0.05

    score = _clamp(score)
    success = score >= 0.70

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
    ignored = "ignore" in actions
    if ignored:
        return TaskResult(
            task_name="task_hard",
            score=0.01,
            steps_taken=len(actions),
            actions_taken=actions,
            success=False,
            reason="Critical APT incident ignored — catastrophic failure.",
        )

    score = 0.0
    investigated  = "investigate"       in actions
    isolated      = "isolate_device"    in actions
    blocked_ip    = "block_ip"          in actions
    forensics     = "collect_forensics" in actions
    escalated     = "escalate"          in actions

    if investigated:  score += 0.15
    if isolated:      score += 0.20
    if blocked_ip:    score += 0.20
    if forensics:     score += 0.20
    if escalated:     score += 0.15

    key_actions = ["investigate", "isolate_device", "block_ip", "collect_forensics", "escalate"]
    present_in_order = [a for a in actions if a in key_actions]
    expected_order = [a for a in key_actions if a in actions]
    if present_in_order == expected_order and len(expected_order) == 5:
        score += 0.05

    extra = max(0, len(actions) - 8)
    score -= extra * 0.04

    score = _clamp(score)
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


GRADERS = {
    "task_easy":   grade_task_easy,
    "task_medium": grade_task_medium,
    "task_hard":   grade_task_hard,
}


def run_grader(task_name: str, actions: List[str], final_score: float, done: bool) -> TaskResult:
    if task_name not in GRADERS:
        raise ValueError(f"Unknown task: {task_name}. Available: {list(GRADERS.keys())}")
    return GRADERS[task_name](actions, final_score, done)