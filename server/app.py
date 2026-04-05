from typing import Optional
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel

try:
    from models import SOCAction, SOCObservation
    from tasks import TASKS as TASK_REGISTRY
    from server.SOC_env_environment import SOCEnvironment
except ImportError:
    from ..models import SOCAction, SOCObservation
    from ..tasks import TASKS as TASK_REGISTRY
    from .SOC_env_environment import SOCEnvironment

app = FastAPI(title="SOC Incident Response Environment")

_env = SOCEnvironment()


class ResetRequest(BaseModel):
    task: Optional[str] = None
    difficulty: Optional[str] = "random"


class StepRequest(BaseModel):
    decision: str
    reasoning: Optional[str] = None


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/reset")
async def reset(req: ResetRequest = ResetRequest()):
    global _env
    pinned_id = None
    difficulty = req.difficulty or "random"
    if req.task and req.task in TASK_REGISTRY:
        task_def = TASK_REGISTRY[req.task]
        pinned_id = task_def["scenario_id"]
        difficulty = task_def["difficulty"]
    _env = SOCEnvironment(difficulty=difficulty, pinned_scenario_id=pinned_id)
    obs = _env.reset()
    return JSONResponse({"observation": obs.model_dump(), "reward": 0.0, "done": False})


@app.post("/step")
async def step(req: StepRequest):
    action = SOCAction(decision=req.decision, reasoning=req.reasoning)
    obs = _env.step(action)
    return JSONResponse({"observation": obs.model_dump(), "reward": obs.reward, "done": obs.done})


@app.get("/state")
async def state():
    s = _env.state
    return JSONResponse({"episode_id": s.episode_id, "step_count": s.step_count})


@app.get("/tasks")
async def list_tasks():
    return JSONResponse({
        "tasks": [
            {"name": t["name"], "display_name": t["display_name"],
             "difficulty": t["difficulty"], "description": t["description"],
             "max_steps": t["max_steps"], "success_criteria": t["success_criteria"]}
            for t in TASK_REGISTRY.values()
        ]
    })


@app.get("/schema")
async def schema():
    return JSONResponse({
        "action": SOCAction.model_json_schema(),
        "observation": SOCObservation.model_json_schema(),
    })


def main(host: str = "0.0.0.0", port: int = 8000):
    import uvicorn
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    main(port=args.port)
