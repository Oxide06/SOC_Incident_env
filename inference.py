import os, json
from typing import List, Optional
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv(override=True)

API_KEY      = os.getenv("HF_TOKEN") or os.getenv("OPENAI_API_KEY") or os.getenv("API_KEY")
API_BASE_URL = os.getenv("API_BASE_URL", "https://router.huggingface.co/v1")
MODEL_NAME   = os.getenv("MODEL_NAME", "Qwen/Qwen2.5-7B-Instruct")

try:
    from server.SOC_env_environment import SOCEnvironment
    from models import SOCAction
except ImportError:
    from SOC_env.server.SOC_env_environment import SOCEnvironment
    from SOC_env.models import SOCAction

BENCHMARK = "SOC_env"
MAX_STEPS = 12
TASKS = ["task_easy", "task_medium", "task_hard"]
SUCCESS_SCORE_THRESHOLD = 0.60

client = None

TASK_SCENARIOS = {
    "task_easy":   "easy_false_positive_vpn",
    "task_medium": "medium_insider_threat",
    "task_hard":   "hard_apt_lateral_movement",
}

TASK_DIFFICULTY = {
    "task_easy":   "easy",
    "task_medium": "medium",
    "task_hard":   "hard",
}

BASELINE = {
    "task_easy":   ["investigate", "ignore"],
    "task_medium": ["investigate", "block_account", "collect_forensics", "escalate"],
    "task_hard":   ["investigate", "isolate_device", "block_ip", "collect_forensics", "escalate"],
}

SYSTEM_PROMPT = '''You are an expert SOC Tier-1 analyst. Respond ONLY with JSON:
{"decision": "<action>", "reasoning": "<one sentence>"}
Rules:
1. Always investigate first when context is empty
2. Authorized/normal activity -> ignore
3. Account compromise -> block_account or request_mfa
4. Active malware/C2 -> isolate_device
5. Malicious IP -> block_ip
6. Beyond Tier-1 -> escalate
7. Never repeat an action already taken'''

AVAILABLE_ACTIONS = [
    "ignore", "monitor", "investigate", "block_ip", "block_account",
    "isolate_device", "escalate", "request_mfa", "patch_system", "collect_forensics"
]

def choose_action_baseline(task_name, step, history):
    """Random fallback — does NOT leak correct answers to the LLM."""
    import random
    # Always investigate first if no context gathered yet
    if step == 1 or "investigate" not in history:
        return "investigate", "random fallback - gather context first"
    # Pick random action not yet taken
    remaining = [a for a in AVAILABLE_ACTIONS if a not in history]
    if remaining:
        return random.choice(remaining), "random fallback"
    return "escalate", "random fallback - exhausted"

def llm_decide(obs_dict, history, task_name, step):
    available = obs_dict.get("available_actions", [
        "ignore","monitor","investigate","block_ip","block_account",
        "isolate_device","escalate","request_mfa","patch_system","collect_forensics"
    ])
    user_msg = (
        f"Alert: {obs_dict.get('alert_type','')}\nSeverity: {obs_dict.get('severity','')}\n"
        f"Step: {obs_dict.get('step',0)}/{obs_dict.get('max_steps',8)}\n\nSignals:\n" +
        "\n".join(f"  - {s}" for s in obs_dict.get("signals",[])) +
        f"\n\nContext:\n{json.dumps(obs_dict.get('context',{}),indent=2) if obs_dict.get('context') else '(empty - use investigate)'}\n\n"
        f"Last feedback: {obs_dict.get('feedback','')}\nAvailable: {', '.join(available)}\n"
        f"Already taken: {', '.join(history) if history else 'none'}\nRespond ONLY with JSON."
    )
    try:
        response = client.chat.completions.create(
            model=MODEL_NAME, max_tokens=300, temperature=0.2,
            messages=[{"role":"system","content":SYSTEM_PROMPT},{"role":"user","content":user_msg}],
        )
        text = response.choices[0].message.content.strip()
        if "```" in text:
            text = text.split("```")[1]
            if text.startswith("json"): text = text[4:]
        parsed = json.loads(text.strip())
        decision = parsed.get("decision", "investigate")
        if decision not in available:
            decision = "investigate"
        return decision, parsed.get("reasoning", ""), None
    except Exception as exc:
        d, r = choose_action_baseline(task_name, step, history)
        return d, r, str(exc)

def compute_score(task_name, actions):
    if task_name == "task_easy":
        if "ignore" in actions and not any(a in actions for a in ["block_account","isolate_device"]):
            return 0.98
        elif any(a in actions for a in ["block_account","isolate_device","escalate"]):
            return 0.02
        elif "investigate" in actions:
            return 0.40
        return 0.10
    elif task_name == "task_medium":
        s = 0.0
        if "investigate" in actions:       s += 0.20
        if "block_account" in actions:     s += 0.25
        if "collect_forensics" in actions: s += 0.20
        if "escalate" in actions:          s += 0.25
        return round(min(0.99, max(0.01, s)), 2)
    elif task_name == "task_hard":
        key = ["investigate","isolate_device","block_ip","collect_forensics","escalate"]
        weights = [0.15, 0.20, 0.20, 0.20, 0.15]
        s = sum(w for a, w in zip(key, weights) if a in actions)
        return round(min(0.99, max(0.01, s)), 2)
    return 0.50

def run_episode(task_name):
    print(f"[START] task={task_name} env={BENCHMARK} model={MODEL_NAME}", flush=True)
    rewards, actions, step = [], [], 0

    try:
        env = SOCEnvironment(
            difficulty=TASK_DIFFICULTY[task_name],
            pinned_scenario_id=TASK_SCENARIOS[task_name]
        )
        obs = env.reset()
    except Exception as exc:
        print(f"[END] success=false steps=0 score=0.01 rewards=", flush=True)
        return False, 0, [], 0.01

    done = obs.done

    while not done and step < MAX_STEPS:
        step += 1
        obs_dict = obs.model_dump()

        if client is not None:
            decision, reasoning, llm_error = llm_decide(obs_dict, actions, task_name, step)
        else:
            decision, reasoning = choose_action_baseline(task_name, step, actions)
            llm_error = "no client"

        try:
            action = SOCAction(decision=decision, reasoning=reasoning)
            obs = env.step(action)
            reward = float(obs.reward)
            done = obs.done
        except Exception as exc:
            reward, done, llm_error = 0.0, True, str(exc)

        rewards.append(reward)
        actions.append(decision)
        error_str = llm_error if llm_error else "null"
        print(f"[STEP] step={step} action={decision} reward={reward:.2f} done={'true' if done else 'false'} error={error_str}", flush=True)

    score = compute_score(task_name, actions)
    success = score >= SUCCESS_SCORE_THRESHOLD
    print(f"[END] success={'true' if success else 'false'} steps={step} score={score:.2f} rewards={','.join(f'{r:.2f}' for r in rewards)}", flush=True)
    return success, step, rewards, score

def main():
    results = []
    for task_name in TASKS:
        success, steps, rewards, score = run_episode(task_name)
        results.append({"task":task_name,"success":success,"steps":steps,"score":score,"total_reward":round(sum(rewards),2)})
        print(flush=True)
    print("# SUMMARY", flush=True)
    for r in results:
        print(f"# {r['task']:20s} {'SUCCESS' if r['success'] else 'FAIL':8s} steps={r['steps']:2d} score={r['score']:.2f} total_reward={r['total_reward']:.2f}", flush=True)
    print(f"# Tasks passed: {sum(1 for r in results if r['success'])}/{len(results)}", flush=True)

if __name__ == "__main__":
    if API_KEY:
        try:
            client = OpenAI(base_url=API_BASE_URL, api_key=API_KEY)
            print("[DEBUG] OpenAI client initialized.", flush=True)
        except Exception as e:
            print(f"[DEBUG] Failed to initialize OpenAI client: {e}", flush=True)
            client = None
    else:
        print("[DEBUG] No API key found. Using baseline policy.", flush=True)
        client = None
    main()