from typing import List, Literal, Optional
from uuid import uuid4
import random

from openenv.core.env_server.interfaces import Environment
from openenv.core.env_server.types import State

try:
    from models import SOCAction, SOCObservation
    from scenarios import EASY_SCENARIOS, HARD_SCENARIOS, MEDIUM_SCENARIOS, SCENARIOS
except ImportError:
    from ..models import SOCAction, SOCObservation
    from ..scenarios import EASY_SCENARIOS, HARD_SCENARIOS, MEDIUM_SCENARIOS, SCENARIOS

SCENARIO_BY_ID = {s["id"]: s for s in SCENARIOS}
Difficulty = Literal["easy", "medium", "hard", "random"]
TERMINAL_ACTIONS = {"ignore", "escalate", "patch_system"}
MAX_STEPS = {"easy": 5, "medium": 8, "hard": 12}

# Actions that reveal additional investigation context
INVESTIGATION_ACTIONS = {"investigate", "query_logs", "check_threat_intel", "run_sandbox"}


class SOCEnvironment(Environment):
    SUPPORTS_CONCURRENT_SESSIONS: bool = True

    def __init__(self, difficulty: Difficulty = "random", pinned_scenario_id: Optional[str] = None):
        self.difficulty = difficulty
        self._pinned_scenario_id = pinned_scenario_id
        self._state = State(episode_id=str(uuid4()), step_count=0)
        self._scenario = None
        self._actions_taken: List[str] = []
        self._investigation_done = False
        self._deep_investigation_done = False
        self._cumulative_score = 0.0
        self._done = False
        self.reset()

    def reset(self) -> SOCObservation:
        self._state = State(episode_id=str(uuid4()), step_count=0)
        self._actions_taken = []
        self._investigation_done = False
        self._deep_investigation_done = False
        self._cumulative_score = 0.0
        self._done = False
        self._scenario = self._pick_scenario()
        max_steps = MAX_STEPS.get(self._scenario["difficulty"], 8)

        return SOCObservation(
            alert_type=self._scenario["alert_type"],
            severity=self._scenario["severity"],
            signals=self._scenario["initial_signals"],
            context={},
            available_actions=self._get_available_actions(),
            phase="detection",
            feedback=(
                f"New Alert: {self._scenario['alert_type'].replace('_', ' ').title()}\n"
                f"Severity: {self._scenario['severity'].upper()}\n"
                f"Description: {self._scenario['description']}\n"
                f"Tip: Use investigate, query_logs, or check_threat_intel to gather context."
            ),
            score=0.0,
            step=0,
            max_steps=max_steps,
            done=False,
            reward=0.0,
        )

    def step(self, action: SOCAction) -> SOCObservation:
        if self._scenario is None:
            self.reset()

        if self._done:
            return self._terminal_obs("Episode already ended. Call reset().")

        self._state.step_count += 1
        decision = action.decision
        max_steps = MAX_STEPS.get(self._scenario["difficulty"], 8)

        reward, feedback, phase = self._evaluate(decision)
        self._cumulative_score += reward
        self._actions_taken.append(decision)

        done = False
        if decision in TERMINAL_ACTIONS:
            done = True
            self._done = True
        elif self._state.step_count >= max_steps:
            done = True
            self._done = True
            reward -= 0.2
            self._cumulative_score -= 0.2
            feedback += f" Max steps ({max_steps}) reached — incident unresolved."

        # Build context based on investigation depth
        context = self._build_context(decision)

        return SOCObservation(
            alert_type=self._scenario["alert_type"],
            severity=self._scenario["severity"],
            signals=self._scenario["initial_signals"],
            context=context,
            available_actions=self._get_available_actions() if not done else [],
            phase=phase,
            feedback=feedback,
            score=round(self._cumulative_score, 2),
            step=self._state.step_count,
            max_steps=max_steps,
            done=done,
            reward=round(reward, 2),
        )

    def _build_context(self, decision: str) -> dict:
        """
        Reveal context progressively based on investigation depth.
        - First investigate/query_logs: reveals basic investigation_context
        - check_threat_intel: reveals threat_intel_context if available
        - run_sandbox: reveals sandbox_context if available
        - Second investigate: reveals deep_investigation_context if available
        """
        context = {}
        scenario = self._scenario

        if decision == "investigate" and not self._investigation_done:
            self._investigation_done = True
            context = scenario.get("investigation_context", {})
            # Add a note if deeper investigation is possible
            if scenario.get("deep_investigation_context"):
                context["_hint"] = "More context available — try check_threat_intel or run_sandbox."

        elif decision == "query_logs" and not self._investigation_done:
            self._investigation_done = True
            context = scenario.get("investigation_context", {})
            context["_source"] = "SIEM log query results"

        elif decision == "check_threat_intel":
            ti = scenario.get("threat_intel_context", {})
            if ti:
                context = ti
                context["_source"] = "Threat intelligence platform"
            elif self._investigation_done:
                context = {"_note": "No additional threat intel beyond what was already found."}
            else:
                context = {"_note": "Run investigate first to correlate threat intel."}

        elif decision == "run_sandbox":
            sb = scenario.get("sandbox_context", {})
            if sb:
                self._deep_investigation_done = True
                context = sb
                context["_source"] = "Dynamic sandbox analysis"
            else:
                context = {"_note": "No samples available for sandbox analysis."}

        elif decision == "investigate" and self._investigation_done:
            # Second investigate reveals deeper context
            deep = scenario.get("deep_investigation_context", {})
            if deep and not self._deep_investigation_done:
                self._deep_investigation_done = True
                context = deep
                context["_source"] = "Deep-dive investigation"
            else:
                context = {"_note": "No additional context found. Consider other actions."}

        return context

    @property
    def state(self) -> State:
        return self._state

    def _pick_scenario(self):
        if self._pinned_scenario_id:
            scenario = SCENARIO_BY_ID.get(self._pinned_scenario_id)
            if scenario:
                return scenario
        if self.difficulty == "easy":
            pool = EASY_SCENARIOS
        elif self.difficulty == "medium":
            pool = MEDIUM_SCENARIOS
        elif self.difficulty == "hard":
            pool = HARD_SCENARIOS
        else:
            pool = SCENARIOS
        return random.choice(pool)

    def _get_available_actions(self):
        return [
            "ignore", "monitor", "investigate", "query_logs",
            "check_threat_intel", "run_sandbox", "block_ip",
            "block_account", "isolate_device", "escalate",
            "request_mfa", "patch_system", "collect_forensics",
        ]

    def _evaluate(self, decision: str):
        scenario = self._scenario
        is_fp = scenario["false_positive"]
        correct_seq = scenario["correct_sequence"]
        optimal = scenario["optimal_terminal"]

        if decision in self._actions_taken:
            return -0.1, f"Already chose '{decision}'. Try a different approach.", "investigation"

        # Investigation actions — always somewhat useful
        if decision in INVESTIGATION_ACTIONS:
            if decision == "investigate":
                if not self._investigation_done:
                    return 0.15, "Investigation initiated. Basic context now available.", "investigation"
                elif not self._deep_investigation_done and scenario.get("deep_investigation_context"):
                    return 0.10, "Deeper investigation complete. Additional context revealed.", "investigation"
                else:
                    return 0.05, "No new findings from further investigation.", "investigation"
            elif decision == "query_logs":
                if not self._investigation_done:
                    return 0.15, "SIEM log query complete. Context now available.", "investigation"
                else:
                    return 0.05, "Logs already queried. Try correlating with threat intel.", "investigation"
            elif decision == "check_threat_intel":
                if scenario.get("threat_intel_context"):
                    return 0.12, "Threat intel matched. IOCs and attribution context revealed.", "investigation"
                else:
                    return 0.05, "No threat intel match found for these indicators.", "investigation"
            elif decision == "run_sandbox":
                if scenario.get("sandbox_context"):
                    return 0.12, "Sandbox detonation complete. Malware behavior confirmed.", "investigation"
                else:
                    return 0.05, "Nothing to sandbox — no file samples available.", "investigation"

        # False positive handling
        if is_fp:
            if decision == "ignore":
                return 0.8, "Correct! This was a false positive — alert closed.", "closed"
            elif decision in TERMINAL_ACTIONS:
                return -0.3, "Over-reaction! This was a false positive — legitimate activity disrupted.", "closed"
            else:
                return 0.0, f"'{decision}' noted but has no effect on a false positive.", "monitoring"

        # Real threat handling
        if decision == "ignore":
            return -0.5, "Dangerous! This is a real threat — ignoring it is a critical mistake.", "detection"

        if decision == optimal and decision in TERMINAL_ACTIONS:
            return 1.0, f"Perfect! '{decision}' is exactly the right call. Incident contained.", "resolved"

        if decision in correct_seq:
            idx = correct_seq.index(decision)
            # Reward higher if earlier in sequence (correct ordering)
            seq_bonus = 0.05 if idx == 0 else 0.0
            return 0.3 + seq_bonus, f"Good step! Part of correct response sequence ({idx+1}/{len(correct_seq)}).", "containment"

        if decision == "escalate" and scenario["severity"] in ("low", "medium"):
            return -0.2, "Premature escalation on low/medium severity — handle at Tier-1 first.", "investigation"

        if decision in TERMINAL_ACTIONS:
            return -0.3, f"Wrong terminal action. Optimal response was: '{optimal}'.", "closed"

        if decision == "monitor":
            if scenario["severity"] in ("critical", "high"):
                return -0.1, "Passive monitoring on a high/critical severity alert wastes time.", "monitoring"
            return 0.05, "Monitoring in progress — gather more context before acting.", "monitoring"

        return 0.0, f"'{decision}' noted. No significant effect on this incident.", "investigation"

    def _terminal_obs(self, msg: str) -> SOCObservation:
        return SOCObservation(
            alert_type=self._scenario["alert_type"] if self._scenario else "",
            severity="", signals=[], context={}, available_actions=[],
            phase="closed", feedback=msg,
            score=round(self._cumulative_score, 2),
            step=self._state.step_count,
            max_steps=MAX_STEPS.get(self._scenario["difficulty"], 8) if self._scenario else 8,
            done=True, reward=0.0,
        )