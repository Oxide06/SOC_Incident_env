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
            "A low-severity login alert fired for an employee logging in from an "
            "unusual location. Correctly identify this as a false positive (approved "
            "VPN travel) without over-reacting and disrupting a legitimate user."
        ),
        "max_steps": 5,
        "success_criteria": "Agent correctly ignores the false-positive alert after investigation.",
    },
    "task_medium": {
        "name": "task_medium",
        "display_name": "Insider Threat Containment",
        "difficulty": "medium",
        "scenario_id": "medium_insider_threat",
        "description": (
            "A departing employee is exfiltrating 6.8 GB of sensitive IP including "
            "source code and client data to a competitor. Investigate, contain the "
            "account, preserve forensic evidence, and escalate to legal/IR team."
        ),
        "max_steps": 8,
        "success_criteria": "Agent investigates, blocks account, collects forensics, and escalates.",
    },
    "task_hard": {
        "name": "task_hard",
        "display_name": "APT Lateral Movement Response",
        "difficulty": "hard",
        "scenario_id": "hard_apt_lateral_movement",
        "description": (
            "APT29-attributed active intrusion with Cobalt Strike C2. Pass-the-Hash "
            "lateral movement detected across 3 workstations toward Domain Controller. "
            "Domain Admin hash captured. Isolate, block C2, collect forensics, escalate."
        ),
        "max_steps": 12,
        "success_criteria": "Isolate device, block C2 IP, collect forensics, escalate to IR team.",
    },
}


def _clamp(score: float) -> float:
    return round(min(0.99, max(0.01, score)), 2)


def grade_task_easy(actions: List[str], final_score: float, done: bool) -> TaskResult:
    investigated = "investigate" in actions
    ignored      = "ignore" in actions
    overreacted  = any(a in actions for a in ["block_account", "isolate_device", "block_ip"])

    if overreacted:
        score, success, reason = 0.02, False, "Over-reacted to false positive."
    elif ignored and investigated:
        extra = max(0, len(actions) - 2)
        score = max(0.70, 0.97 - extra * 0.06)
        success, reason = True, f"Correctly identified false positive. Steps: {len(actions)}"
    elif ignored:
        score, success, reason = 0.75, True, "Correctly ignored false positive."
    elif investigated:
        score, success, reason = 0.35, False, "Investigated but no conclusion."
    else:
        score = max(0.01, 0.08 * len(actions)) if actions else 0.01
        success, reason = False, "No conclusion reached."

    return TaskResult(task_name="task_easy", score=_clamp(score),
                      steps_taken=len(actions), actions_taken=actions,
                      success=success, reason=reason)


def grade_task_medium(actions: List[str], final_score: float, done: bool) -> TaskResult:
    score = 0.0
    if "investigate"       in actions: score += 0.20
    if "block_account"     in actions: score += 0.25
    if "collect_forensics" in actions: score += 0.20
    if "escalate"          in actions: score += 0.25

    try:
        if (actions.index("investigate") < actions.index("block_account")
                < actions.index("escalate")):
            score += 0.05
    except ValueError:
        pass

    score -= max(0, len(actions) - 5) * 0.04
    score = _clamp(score)

    missing = [a for a in ["investigate","block_account","collect_forensics","escalate"]
               if a not in actions]
    reason = f"Score {score:.2f}. " + (f"Missing: {', '.join(missing)}." if missing else "All key actions taken.")

    return TaskResult(task_name="task_medium", score=score,
                      steps_taken=len(actions), actions_taken=actions,
                      success=score >= 0.65, reason=reason)


def grade_task_hard(actions: List[str], final_score: float, done: bool) -> TaskResult:
    if "ignore" in actions:
        return TaskResult(task_name="task_hard", score=0.01,
                          steps_taken=len(actions), actions_taken=actions,
                          success=False, reason="Critical APT incident ignored.")

    key_map = {"investigate": 0.15, "isolate_device": 0.20,
               "block_ip": 0.20, "collect_forensics": 0.20, "escalate": 0.15}
    score = sum(w for a, w in key_map.items() if a in actions)

    taken = [a for a in actions if a in key_map]
    expected = [a for a in key_map if a in actions]
    if taken == expected and len(expected) == 5:
        score += 0.05

    score -= max(0, len(actions) - 7) * 0.04
    score = _clamp(score)

    missing = [a for a in key_map if a not in actions]
    reason = f"Score {score:.2f}. " + (f"Missing: {', '.join(missing)}." if missing else "All critical actions taken.")

    return TaskResult(task_name="task_hard", score=score,
                      steps_taken=len(actions), actions_taken=actions,
                      success=score >= 0.65, reason=reason)


GRADERS = {
    "task_easy":   grade_task_easy,
    "task_medium": grade_task_medium,
    "task_hard":   grade_task_hard,
}


def run_grader(task_name: str, actions: List[str], final_score: float, done: bool) -> TaskResult:
    if task_name not in GRADERS:
        raise ValueError(f"Unknown task: {task_name}. Available: {list(GRADERS.keys())}")
    return GRADERS[task_name](actions, final_score, done)