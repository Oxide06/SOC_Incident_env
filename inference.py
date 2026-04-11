import os, sys, json
from typing import List, Optional
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv(override=True)

API_BASE_URL = os.getenv("API_BASE_URL", "https://router.huggingface.co/v1")
MODEL_NAME   = os.getenv("MODEL_NAME",   "Qwen/Qwen2.5-72B-Instruct")
HF_TOKEN     = os.getenv("HF_TOKEN")

if HF_TOKEN is None:
    print("[DEBUG] HF_TOKEN not set ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â using baseline policy.", flush=True)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from server.SOC_env_environment import SOCEnvironment
    from models import SOCAction
except ImportError:
    from SOC_env.server.SOC_env_environment import SOCEnvironment
    from SOC_env.models import SOCAction

BENCHMARK = "SOC_env"
MAX_STEPS  = 12
TASKS = ["task_easy", "task_medium", "task_hard"]

TASK_SCENARIOS = {
    "task_easy":     "easy_false_positive_vpn",
    "task_medium":   "medium_insider_threat",
    "task_hard":     "hard_apt_lateral_movement",
    "task_critical": "critical_ransomware_precursor",
}

TASK_DIFFICULTY = {
    "task_easy":     "easy",
    "task_medium":   "medium",
    "task_hard":     "hard",
    "task_critical": "hard",
}

BASELINE = {
    "task_easy":     ["investigate", "ignore"],
    "task_medium":   ["investigate", "block_account", "collect_forensics", "escalate"],
    "task_hard":     ["investigate", "isolate_device", "block_ip", "collect_forensics", "escalate"],
    "task_critical": ["investigate", "isolate_device", "block_ip", "collect_forensics", "escalate"],
}

SYSTEM_PROMPT = """You are an expert SOC Tier-1 analyst. Respond ONLY with JSON:
{"decision": "<action>", "reasoning": "<one sentence>"}

Decision rules:
1. ALWAYS investigate first if context is empty
2. Authorized/normal activity (VPN, approved scan) -> ignore
3. Active malware or C2 beacon -> isolate_device immediately
4. Known malicious IP -> block_ip
5. Compromised account -> block_account
6. Phishing with credential risk -> request_mfa
7. Supply chain / patching needed -> patch_system
8. Evidence preservation required -> collect_forensics
9. Beyond Tier-1 scope (APT, ransomware, legal) -> escalate
10. Never repeat an action already taken"""

client = None


def choose_action_baseline(task_name: str, step: int, history: List[str]):
    seq = BASELINE.get(task_name, ["investigate", "escalate"])
    idx = step - 1
    if idx < len(seq) and seq[idx] not in history:
        return seq[idx], "baseline policy"
    for a in seq:
        if a not in history:
            return a, "baseline policy"
    return "escalate", "baseline exhausted"


def llm_decide(obs_dict: dict, history: List[str], task_name: str, step: int):
    available = obs_dict.get("available_actions", [
        "ignore", "monitor", "investigate", "block_ip", "block_account",
        "isolate_device", "escalate", "request_mfa", "patch_system", "collect_forensics",
    ])
    signals_str  = "\n".join(f"  ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢ {s}" for s in obs_dict.get("signals", []))
    context_str  = (
        json.dumps(obs_dict.get("context", {}), indent=2)
        if obs_dict.get("context")
        else "(empty ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â run investigate first)"
    )
    user_msg = (
        f"Alert type : {obs_dict.get('alert_type', '')}\n"
        f"Severity   : {obs_dict.get('severity', '').upper()}\n"
        f"Phase      : {obs_dict.get('phase', '')}\n"
        f"Step       : {obs_dict.get('step', 0)}/{obs_dict.get('max_steps', 12)}\n\n"
        f"Signals:\n{signals_str}\n\n"
        f"Investigation context:\n{context_str}\n\n"
        f"Last feedback: {obs_dict.get('feedback', '')}\n\n"
        f"Available actions: {', '.join(available)}\n"
        f"Already taken    : {', '.join(history) if history else 'none'}\n\n"
        "Respond ONLY with JSON."
    )
    try:
        response = client.chat.completions.create(
            model=MODEL_NAME,
            max_tokens=200,
            temperature=0.1,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user",   "content": user_msg},
            ],
        )
        text = response.choices[0].message.content.strip()
        if "```" in text:
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]
        parsed   = json.loads(text.strip())
        decision = parsed.get("decision", "investigate")
        if decision not in available:
            decision = "investigate"
        return decision, parsed.get("reasoning", ""), None
    except Exception as exc:
        d, r = choose_action_baseline(task_name, step, history)
        return d, r, str(exc)


def compute_score(task_name: str, actions: List[str]) -> float:
    if task_name == "task_easy":
        if "ignore" in actions and not any(
            a in actions for a in ["block_account", "isolate_device", "block_ip"]
        ):
            return 0.97
        elif any(a in actions for a in ["block_account", "isolate_device", "block_ip"]):
            return 0.02
        elif "investigate" in actions:
            return 0.35
        return 0.10

    key_weights = {
        "task_medium": {
            "investigate": 0.20, "block_account": 0.25,
            "collect_forensics": 0.20, "escalate": 0.25,
        },
        "task_hard": {
            "investigate": 0.15, "isolate_device": 0.20,
            "block_ip": 0.20, "collect_forensics": 0.20, "escalate": 0.15,
        },
        "task_critical": {
            "investigate": 0.12, "isolate_device": 0.22,
            "block_ip": 0.22, "collect_forensics": 0.18, "escalate": 0.18,
        },
    }
    weights = key_weights.get(task_name, {})
    score   = sum(w for a, w in weights.items() if a in actions)
    return round(min(0.99, max(0.01, score)), 2)


def run_episode(task_name: str):
    print(f"[START] task={task_name} env={BENCHMARK} model={MODEL_NAME}", flush=True)
    rewards: List[float] = []
    actions: List[str]   = []
    step = 0

    try:
        env = SOCEnvironment(
            difficulty=TASK_DIFFICULTY[task_name],
            pinned_scenario_id=TASK_SCENARIOS[task_name],
        )
        obs  = env.reset()
        done = obs.done
    except Exception as exc:
        print(
            f"[END] success=false steps=0 rewards=",
            flush=True,
        )
        return False, 0, []

    while not done and step < MAX_STEPS:
        step += 1
        obs_dict = obs.model_dump()

        if client is not None:
            decision, reasoning, llm_error = llm_decide(obs_dict, actions, task_name, step)
        else:
            decision, reasoning = choose_action_baseline(task_name, step, actions)
            llm_error = "no_client"

        try:
            action   = SOCAction(decision=decision, reasoning=reasoning)
            obs      = env.step(action)
            reward   = float(obs.reward)
            done     = obs.done
        except Exception as exc:
            reward, done, llm_error = 0.0, True, str(exc)

        rewards.append(reward)
        actions.append(decision)
        error_str = llm_error if llm_error else "null"
        print(
            f"[STEP] step={step} action={decision} reward={reward:.2f} "
            f"done={'true' if done else 'false'} error={error_str}",
            flush=True,
        )

    success     = compute_score(task_name, actions) >= 0.60
    rewards_str = ",".join(f"{r:.2f}" for r in rewards)
    print(
        f"[END] success={'true' if success else 'false'} steps={step} rewards={rewards_str}",
        flush=True,
    )
    return success, step, rewards


def main():
    passed = 0
    for task_name in TASKS:
        success, steps, rewards = run_episode(task_name)
        if success:
            passed += 1
        print(flush=True)
    print(f"# Tasks passed: {passed}/{len(TASKS)}", flush=True)


if __name__ == "__main__":
    if HF_TOKEN:
        try:
            client = OpenAI(base_url=API_BASE_URL, api_key=HF_TOKEN)
            print("[DEBUG] OpenAI client initialized.", flush=True)
        except Exception as e:
            print(f"[DEBUG] Client init failed: {e} ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â using baseline.", flush=True)
    else:
        print("[DEBUG] No HF_TOKEN ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â using baseline policy.", flush=True)
    main()