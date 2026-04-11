---
title: Security Operations Center Incident Response Environment
emoji: Ã°Å¸â€Â
colorFrom: red
colorTo: blue
sdk: docker
app_port: 8000
pinned: true
tags:
  - openenv
  - reinforcement-learning
  - cybersecurity
  - soc
  - incident-response
---

# Ã°Å¸â€Â Security Operations Center (SOC) Incident Response Environment

An OpenEnv reinforcement learning environment where an AI agent acts as a **Tier-1 Security Operations Center (SOC) analyst**, triaging and responding to real-world cybersecurity incidents.

## Ã°Å¸Å½Â¯ Motivation

SOC analysts make high-stakes decisions under time pressure with incomplete information Ã¢â‚¬â€ exactly the kind of sequential decision-making problem that RL agents excel at. Today's SOCs are overwhelmed: the average analyst handles 1,000+ alerts per day, with alert fatigue causing 45% of alerts to go uninvestigated (IBM Cost of a Data Breach Report 2024).

This environment trains agents to:
- Distinguish real threats from false positives
- Follow correct incident response playbooks (NIST SP 800-61)
- Apply proportionate responses (not over- or under-reacting)
- Reason through multi-step containment chains under uncertainty

Scenarios are grounded in real threat intelligence: **MITRE ATT&CK techniques**, actual CVE references, and TTPs from named threat actors (APT29, BlackCat/ALPHV, Scattered Spider).

---

## Ã°Å¸â€”â€šÃ¯Â¸Â Environment Overview

| Property | Value |
|---|---|
| **Framework** | OpenEnv (FastAPI + WebSocket) |
| **Tasks** | 4 (easy Ã¢â€ â€™ medium Ã¢â€ â€™ hard Ã¢â€ â€™ critical) |
| **Actions** | 10 discrete analyst decisions |
| **Episode length** | 5Ã¢â‚¬â€œ12 steps depending on task |
| **Reward** | Shaped Ã¢â‚¬â€ partial credit for correct intermediate steps |

---

## Ã°Å¸Å½Â® Action Space

The agent chooses one action per step from 10 discrete options:

| Action | Description |
|---|---|
| `investigate` | Pull logs, run SIEM queries, gather context |
| `ignore` | Close alert Ã¢â‚¬â€ confirmed false positive |
| `monitor` | Watch passively without intervening |
| `block_ip` | Block offending IP at perimeter firewall |
| `block_account` | Disable compromised user account |
| `isolate_device` | Quarantine endpoint from network |
| `escalate` | Hand off to Tier-2 / Incident Commander |
| `request_mfa` | Force re-authentication with MFA |
| `patch_system` | Apply patch or remove malicious package |
| `collect_forensics` | Preserve evidence for forensic analysis |

---

## Ã°Å¸â€˜ÂÃ¯Â¸Â Observation Space

Each step the agent receives a structured observation:

| Field | Type | Description |
|---|---|---|
| `alert_type` | string | Category of security alert (e.g. `lateral_movement_detected`) |
| `severity` | string | `low` / `medium` / `high` / `critical` |
| `signals` | list[str] | Observable threat indicators (what triggered the alert) |
| `context` | dict | Investigation context unlocked by the `investigate` action |
| `available_actions` | list[str] | Which actions are valid at this step |
| `phase` | string | Incident lifecycle phase: `detection` Ã¢â€ â€™ `investigation` Ã¢â€ â€™ `containment` Ã¢â€ â€™ `resolved` |
| `feedback` | string | Analyst feedback on the last action taken |
| `score` | float | Cumulative reward so far |
| `step` | int | Current step number |
| `max_steps` | int | Maximum steps before episode ends |
| `done` | bool | Whether the episode has ended |
| `reward` | float | Reward for the last action |

---

## Ã°Å¸â€œâ€¹ Tasks

### Task 1 Ã¢â‚¬â€ Login Anomaly Triage `[easy]`
**Scenario:** A low-severity login alert fired for an employee logging in from an unusual country.

**Challenge:** Distinguish a legitimate VPN user on approved travel from a real account compromise. The agent must investigate before acting and correctly identify this as a false positive Ã¢â‚¬â€ without blocking a legitimate employee.

**Key skills:** False positive detection, proportionate response, avoiding alert over-reaction.

**Success criteria:** Agent investigates and correctly ignores the alert.

**Max steps:** 5 | **Target score:** Ã¢â€°Â¥ 0.75

---

### Task 2 Ã¢â‚¬â€ Insider Threat Containment `[medium]`
**Scenario:** A departing employee exfiltrates 6.8 GB of sensitive IP Ã¢â‚¬â€ source code, client data, and salary records Ã¢â‚¬â€ to a competitor on their final working days.

**Challenge:** Multi-step containment chain in the correct order: investigate Ã¢â€ â€™ block account Ã¢â€ â€™ collect forensics Ã¢â€ â€™ escalate. Legal hold requirements mean forensics must be preserved before any destructive actions.

**Key skills:** Ordered decision chains, evidence preservation, legal escalation judgment.

**Success criteria:** Investigate, block account, collect forensics, escalate Ã¢â‚¬â€ in logical order.

**Max steps:** 8 | **Target score:** Ã¢â€°Â¥ 0.65

---

### Task 3 Ã¢â‚¬â€ APT Lateral Movement Response `[hard]`
**Scenario:** An APT29 (Cozy Bear) attributed intrusion is actively moving laterally through the network using Cobalt Strike. Pass-the-Hash attacks detected across 3 workstations toward the Domain Controller. Domain Admin hash captured but not yet used.

**Challenge:** Noisy, multi-signal environment with fileless malware (no AV detections). Agent must reason through the full kill chain: isolate compromised hosts, block C2 IP, collect forensics, escalate Ã¢â‚¬â€ all within 12 steps before Domain Controller is reached.

**Key skills:** Kill chain reasoning, C2 identification, chained containment, APT-level threat judgment.

**Success criteria:** Isolate device, block C2 IP, collect forensics, escalate.

**Max steps:** 12 | **Target score:** Ã¢â€°Â¥ 0.65

---

### Task 4 Ã¢â‚¬â€ Ransomware Precursor Response `[critical]`
**Scenario:** BlackCat/ALPHV ransomware pre-encryption stage. Shadow copies deleted on 6 servers, Windows Defender disabled on 34 endpoints, 4 domain admin accounts compromised, 12 GB already exfiltrated. Estimated 2Ã¢â‚¬â€œ4 hours before encryption begins.

**Challenge:** This is a P0 incident requiring the fastest possible correct response. Passive actions like `monitor` are penalized Ã¢â‚¬â€ every minute counts. Speed bonus awarded for completing all key actions in 5 steps or fewer.

**Key skills:** P0 incident recognition, speed under pressure, ransomware-specific playbook.

**Success criteria:** Isolate, block exfil IP, collect forensics, escalate immediately.

**Max steps:** 12 | **Target score:** Ã¢â€°Â¥ 0.70

---

## Ã°Å¸Ââ€  Baseline Performance Scores

Scores achieved by the baseline LLM agent (Qwen2.5-72B-Instruct via HuggingFace Router):

| Task | Difficulty | Steps | Score | Result |
|---|---|---|---|---|
| Login Anomaly Triage | Easy | 2 | 0.97 | Ã¢Å“â€¦ SUCCESS |
| Insider Threat Containment | Medium | 4 | 0.90 | Ã¢Å“â€¦ SUCCESS |
| APT Lateral Movement | Hard | 5 | 0.90 | Ã¢Å“â€¦ SUCCESS |
| Ransomware Precursor | Critical | 5 | 0.92 | Ã¢Å“â€¦ SUCCESS |

**Tasks passed: 4/4**

---

## Ã°Å¸â€Â§ Setup & Usage

### Option 1 Ã¢â‚¬â€ Use the Live HuggingFace Space (Recommended)

```python
from openai import OpenAI
import requests

BASE_URL = "https://apoorvabadoni-soc-env.hf.space"

# Reset environment
obs = requests.post(f"{BASE_URL}/reset", json={"task": "task_hard"}).json()
print(obs["observation"]["alert_type"])

# Take a step
result = requests.post(f"{BASE_URL}/step", json={"decision": "investigate"}).json()
print(result["observation"]["feedback"])
```

### Option 2 Ã¢â‚¬â€ Run Locally with Docker

```bash
# Clone the repo
git clone https://github.com/Oxide06/SOC_Incident_env.git
cd SOC_Incident_env

# Build and run
docker build -t soc-env:latest .
docker run -p 8000:8000 soc-env:latest

# Test
curl -X POST http://localhost:8000/reset \
  -H "Content-Type: application/json" \
  -d '{"task": "task_hard"}'
```

### Option 3 Ã¢â‚¬â€ Run Inference Script

```bash
# Install dependencies
pip install openenv-core openai python-dotenv requests

# Set credentials
export HF_TOKEN=your_hf_token
export API_BASE_URL=https://router.huggingface.co/v1
export MODEL_NAME=Qwen/Qwen2.5-72B-Instruct
export ENV_BASE_URL=http://localhost:8000

# Run
python inference.py
```

### Option 4 Ã¢â‚¬â€ Python Client (Direct Import)

```python
from server.SOC_env_environment import SOCEnvironment
from models import SOCAction

env = SOCEnvironment(difficulty="hard", pinned_scenario_id="hard_apt_lateral_movement")
obs = env.reset()

while not obs.done:
    print(f"Alert: {obs.alert_type} | Phase: {obs.phase}")
    action = SOCAction(decision="investigate", reasoning="Gathering context first")
    obs = env.step(action)
    print(f"Feedback: {obs.feedback} | Reward: {obs.reward}")
```

---

## Ã°Å¸Å’Â API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/health` | GET | Health check Ã¢â‚¬â€ returns `{"status": "healthy"}` |
| `/reset` | POST | Start new episode. Body: `{"task": "task_easy"}` |
| `/step` | POST | Take action. Body: `{"decision": "investigate"}` |
| `/state` | GET | Current episode state |
| `/tasks` | GET | List all available tasks |
| `/schema` | GET | Action and observation JSON schemas |
| `/metadata` | GET | Environment name and description |
| `/mcp` | POST | MCP JSON-RPC endpoint |

---

## Ã°Å¸Â§Â  Reward Structure

| Action | Reward | Condition |
|---|---|---|
| Correct terminal action | +1.0 | Optimal final decision for scenario |
| Good intermediate step | +0.3 | Part of correct sequence |
| Investigate (first time) | +0.15 | Context not yet gathered |
| Investigate (repeat) | +0.10 | Already investigated |
| Ignore (false positive) | +0.8 | Correctly identified benign alert |
| Ignore (real threat) | -0.5 | Dangerous Ã¢â‚¬â€ threat missed |
| Wrong terminal action | -0.3 | Suboptimal final decision |
| Premature escalation | -0.2 | Escalating low/medium without investigation |
| Repeat action | -0.1 | Already took this action |

---

## Ã°Å¸â€œÂ Project Structure

```
SOC_Incident_env/
Ã¢â€Å“Ã¢â€â‚¬Ã¢â€â‚¬ inference.py          # Baseline LLM agent script
Ã¢â€Å“Ã¢â€â‚¬Ã¢â€â‚¬ models.py             # SOCAction and SOCObservation Pydantic models
Ã¢â€Å“Ã¢â€â‚¬Ã¢â€â‚¬ scenarios.py          # 9 threat scenarios with MITRE ATT&CK mapping
Ã¢â€Å“Ã¢â€â‚¬Ã¢â€â‚¬ tasks.py              # 4 task definitions with deterministic graders
Ã¢â€Å“Ã¢â€â‚¬Ã¢â€â‚¬ client.py             # OpenEnv HTTP client
Ã¢â€Å“Ã¢â€â‚¬Ã¢â€â‚¬ openenv.yaml          # OpenEnv spec manifest
Ã¢â€Å“Ã¢â€â‚¬Ã¢â€â‚¬ pyproject.toml        # Package configuration
Ã¢â€Å“Ã¢â€â‚¬Ã¢â€â‚¬ Dockerfile            # Container definition
Ã¢â€â€Ã¢â€â‚¬Ã¢â€â‚¬ server/
    Ã¢â€Å“Ã¢â€â‚¬Ã¢â€â‚¬ app.py            # FastAPI server with all endpoints
    Ã¢â€â€Ã¢â€â‚¬Ã¢â€â‚¬ SOC_env_environment.py  # Core environment logic
```

---

## Ã°Å¸â€â€” References

- [MITRE ATT&CK Framework](https://attack.mitre.org)
- [NIST SP 800-61 Incident Response Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf)
- [OpenEnv Framework](https://github.com/meta-pytorch/OpenEnv)
- [IBM Cost of a Data Breach Report 2024](https://www.ibm.com/reports/data-breach)

---

*Built for the Meta-PyTorch OpenEnv Hackathon 2025*