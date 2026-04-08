---
title: SOC Incident Response Environment
emoji: 🔐
colorFrom: red
colorTo: blue
sdk: docker
pinned: false
app_port: 8000
tags:
  - openenv
  - reinforcement-learning
  - cybersecurity
---

# 🔐 SOC Incident Response Environment

> **Meta-PyTorch × Scaler OpenEnv Hackathon Submission**

An RL environment where an AI agent acts as a **Security Operations Center (SOC) Tier-1 analyst** — investigating security alerts and deciding how to respond, step by step.

---

## What It Does

Each episode = one real-world security incident. The agent:
1. Receives an **alert** with observable signals (login anomaly, malware, data exfiltration, etc.)
2. Chooses **investigation or response actions** sequentially
3. Gets **partial rewards** for correct, proportionate decisions
4. Episode ends when a terminal action is taken or max steps reached

---

## Action Space

| Action | When to use |
|---|---|
| `investigate` | Always valid — unlocks deeper context |
| `ignore` | Confirmed false positive |
| `monitor` | Watching, not acting yet |
| `block_ip` | Malicious source IP identified |
| `block_account` | Compromised account |
| `isolate_device` | Active malware or breach on endpoint |
| `escalate` | Incident beyond Tier-1 scope |
| `request_mfa` | Account takeover suspected |
| `patch_system` | Vulnerable software needs remediation |
| `collect_forensics` | Preserve evidence |

---

## Observation Space

| Field | Type | Description |
|---|---|---|
| `alert_type` | str | Category of security alert |
| `severity` | str | low / medium / high / critical |
| `signals` | list | Observable threat indicators |
| `context` | dict | Extra info unlocked by `investigate` |
| `available_actions` | list | Valid decisions at this step |
| `phase` | str | Incident lifecycle phase |
| `feedback` | str | Result of last action |
| `score` | float | Cumulative reward so far |
| `step` / `max_steps` | int | Progress through episode |

---

## Reward Design

| Situation | Reward |
|---|---|
| Correct terminal action | **+1.0** |
| Good intermediate step | **+0.3** |
| Investigate (first time) | **+0.15** |
| Correctly ignore false positive | **+0.8** |
| Over-react to false positive | **−0.3** |
| Ignore a real threat | **−0.5** |
| Premature escalation | **−0.2** |
| Repeat same action | **−0.1** |

---

## Tasks

| Task | Scenario | Difficulty | Max Steps |
|---|---|---|---|
| `task_easy` | VPN login flagged as anomaly — false positive detection | Easy | 5 |
| `task_medium` | Departing employee exfiltrating confidential files | Medium | 8 |
| `task_hard` | Active APT lateral movement with Cobalt Strike C2 | Hard | 12 |

Each task is **pinned to a deterministic scenario** — same scenario every run for reproducible evaluation.

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/reset` | Start new episode (pass `{"task": "task_easy"}` to pin) |
| `POST` | `/step` | Submit decision `{"decision": "investigate"}` |
| `GET` | `/state` | Current episode state |
| `GET` | `/tasks` | List all 3 evaluation tasks |
| `GET` | `/health` | Health check |
| `GET` | `/web` | Interactive web UI |
| `GET` | `/docs` | API documentation |

---

## Quick Start

```bash
# Clone and build
git clone https://github.com/Oxide06/SOC_Incident_env.git
cd SOC_Incident_env
docker build -t soc-env:latest .
docker run -p 8000:8000 soc-env:latest
```

```python
# Use with Python
import requests

# Start a pinned task
obs = requests.post("http://localhost:8000/reset",
                    json={"task": "task_easy"}).json()["observation"]
print(obs["alert_type"])   # anomalous_login_location
print(obs["signals"])      # list of threat indicators

# Take an action
result = requests.post("http://localhost:8000/step",
                       json={"decision": "investigate"}).json()
print(result["reward"])    # 0.15
print(result["observation"]["context"])  # unlocked context
```

---

## Run the Baseline Agent

```bash
# Set your API key
export OPENAI_API_KEY="your-groq-or-hf-key"
export API_BASE_URL="https://api.groq.com/openai/v1"
export MODEL_NAME="llama-3.3-70b-versatile"
export ENV_BASE_URL="http://localhost:8000"

python inference.py
```

**Baseline results (llama-3.3-70b-versatile):**

```
task_easy    SUCCESS  steps=2  reward=0.90   investigate → ignore
task_medium  SUCCESS  steps=5  reward=1.75   investigate → block_account → escalate
task_hard    SUCCESS  steps=5  reward=1.35   investigate → isolate_device → escalate
Tasks passed: 3/3
```

---

## Project Structure

```
SOC_env/
├── inference.py              # Baseline LLM agent
├── models.py                 # SOCAction, SOCObservation (Pydantic)
├── scenarios.py              # 9 realistic incident scenarios
├── tasks.py                  # 3 named tasks + deterministic graders
├── client.py                 # WebSocket/HTTP client
├── Dockerfile                # Container definition
├── openenv.yaml              # OpenEnv manifest
└── server/
    ├── app.py                # FastAPI server + web UI
    └── SOC_env_environment.py  # Core RL logic
```

---

## Interactive Demo

Visit `/web` after starting the server for a live interactive UI where you can play analyst yourself.