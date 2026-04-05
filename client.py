# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

"""SOC Incident Response Environment Client."""

from typing import Dict

from openenv.core import EnvClient
from openenv.core.client_types import StepResult
from openenv.core.env_server.types import State

from .models import SOCAction, SOCObservation


class SOCEnv(EnvClient[SOCAction, SOCObservation, State]):
    """
    Client for the SOC Incident Response Environment.

    Maintains a persistent WebSocket connection to the environment server.

    Example (local server):
        >>> with SOCEnv(base_url="http://localhost:8000") as env:
        ...     obs = env.reset()
        ...     print(obs.alert_type)
        ...     result = env.step(SOCAction(decision="investigate"))
        ...     print(result.observation.feedback)

    Example (Docker):
        >>> env = SOCEnv.from_docker_image("soc-env:latest")
        >>> try:
        ...     obs = env.reset()
        ...     result = env.step(SOCAction(decision="block_account"))
        ... finally:
        ...     env.close()
    """

    def _step_payload(self, action: SOCAction) -> Dict:
        payload = {"decision": action.decision}
        if action.reasoning:
            payload["reasoning"] = action.reasoning
        return payload

    def _parse_result(self, payload: Dict) -> StepResult[SOCObservation]:
        obs_data = payload.get("observation", {})
        observation = SOCObservation(
            alert_type=obs_data.get("alert_type", ""),
            severity=obs_data.get("severity", "low"),
            signals=obs_data.get("signals", []),
            context=obs_data.get("context", {}),
            available_actions=obs_data.get("available_actions", []),
            phase=obs_data.get("phase", "detection"),
            feedback=obs_data.get("feedback", ""),
            score=obs_data.get("score", 0.0),
            step=obs_data.get("step", 0),
            max_steps=obs_data.get("max_steps", 8),
            done=payload.get("done", False),
            reward=payload.get("reward", 0.0),
        )
        return StepResult(
            observation=observation,
            reward=payload.get("reward", 0.0),
            done=payload.get("done", False),
        )

    def _parse_state(self, payload: Dict) -> State:
        return State(
            episode_id=payload.get("episode_id"),
            step_count=payload.get("step_count", 0),
        )