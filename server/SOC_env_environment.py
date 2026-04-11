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


class SOCEnvironment(Environment):
    SUPPORTS_CONCURRENT_SESSIONS: bool = True

    def __init__(self, difficulty: Difficulty = "random", pinned_scenario_id: Optional[str] = None):
        self.difficulty = difficulty
        self._pinned_scenario_id = pinned_scenario_id
        self._state = State(episode_id=str(uuid4()), step_count=0)
        self._scenario = None
        self._actions_taken: List[str] = []
        self._investigation_done = False
        self._cumulative_score = 0.0
        self._done = False
        self.reset()

    def reset(self) -> SOCObservation:
        self._state = State(episode_id=str(uuid4()), step_count=0)
        self._actions_taken = []
        self._investigation_done = False
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
                f"Description: {self._scenario['description']}"
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
            feedback += f" Max steps ({max_steps}) reached."

        context = {}
        if decision == "investigate" and not self._investigation_done:
            context = self._scenario["investigation_context"]
            self._investigation_done = True

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
            "ignore", "monitor", "investigate", "block_ip",
            "block_account", "isolate_device", "escalate",
            "request_mfa", "patch_system", "collect_forensics",
        ]

    def _evaluate(self, decision: str):
        scenario = self._scenario
        is_fp = scenario["false_positive"]
        correct_seq = scenario["correct_sequence"]
        optimal = scenario["optimal_terminal"]

        if decision in self._actions_taken:
            return -0.1, f"Already chose '{decision}'. Try something new.", "investigation"

        if is_fp:
            if decision == "ignore":
                return 0.8, "Correct! This was a false positive.", "closed"
            elif decision == "investigate":
                return 0.1, "Good - investigate before acting.", "investigation"
            elif decision in TERMINAL_ACTIONS:
                return -0.3, "Over-reaction! This was a false positive.", "closed"
            else:
                return 0.0, f"'{decision}' noted.", "monitoring"

        if decision == "ignore":
            return -0.5, "Dangerous! This is a real threat.", "detection"
        if decision == "investigate":
            r = 0.1 if self._investigation_done else 0.15
            return r, "Investigation initiated. Context now available.", "investigation"
        if decision == optimal and decision in TERMINAL_ACTIONS:
            return 1.0, f"Perfect! '{decision}' is exactly right. Incident contained.", "resolved"
        if decision in correct_seq:
            idx = correct_seq.index(decision)
            return 0.3, f"Good step! Part of correct sequence ({idx+1}/{len(correct_seq)}).", "containment"
        if decision == "escalate" and scenario["severity"] in ("low", "medium"):
            return -0.2, "Premature escalation on low/medium severity.", "investigation"
        if decision in TERMINAL_ACTIONS:
            return -0.3, f"Wrong terminal. Optimal was: '{optimal}'.", "closed"

        return 0.0, f"'{decision}' noted. No direct effect.", "investigation"

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

