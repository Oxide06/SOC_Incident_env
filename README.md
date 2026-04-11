---
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

# Security Operations Center (SOC) Incident Response Environment

An OpenEnv reinforcement learning environment where an AI agent acts as a
**Tier-1 Security Operations Center (SOC) analyst**, triaging and responding
to real-world cybersecurity incidents.

## Motivation

SOC analysts make high-stakes decisions under time pressure with incomplete
information. Today's SOCs are overwhelmed: the average analyst handles 1,000+
alerts per day, with alert fatigue causing 45% of alerts to go uninvestigated
(IBM Cost of a Data Breach Report 2024).

This environment trains agents to:
- Distinguish real threats from false positives
- Follow correct incident response playbooks (NIST SP 800-61)
- Apply proportionate responses (not over- or under-reacting)
- Reason through multi-step containment chains under uncertainty

Scenarios are grounded in real threat intelligence: **MITRE ATT&CK techniques**,
actual CVE references, and TTPs from named threat actors (APT29, BlackCat/ALPHV,
Scattered Spider).

---

## Environment Overview

| Property | Value |
|---|---|
| **Framework** | OpenEnv (FastAPI + WebSocket) |
| **Tasks** | 4 (easy, medium, hard, critical) |
| **Actions** | 10 discrete analyst decisions |
| **Episode length** | 5-12 steps depending on task |
| **Reward** | Shaped - partial credit for correct intermediate steps |

---

## Action Space

The agent chooses one action per step from 10 discrete options:

| Action | Description |
|---|---|
| `investigate` | Pull logs, run SIEM queries, gather context |
| `ignore` | Close alert - confirmed false positive |
| `monitor` | Watch passively without intervening |
| `block_ip` | Block offending IP at perimeter firewall |
| `block_account` | Disable compromised user account |
| `isolate_device` | Quarantine endpoint from network |
| `escalate` | Hand off to Tier-2 / Incident Commander |
| `request_mfa` | Force re-authentication with MFA |
| `patch_system` | Apply patch or remove malicious package |
| `collect_forensics` | Preserve evidence for forensic analysis |

---

## Observation Space

Each step the agent receives a structured observation:

| Field | Type | Description |
|---|---|---|
| `alert_type` | string | Category of security alert |
| `severity` | string | low / medium / high / critical |
| `signals` | list[str] | Observable threat indicators |
| `context` | dict | Investigation context unlocked by investigate action |
| `available_actions` | list[str] | Valid actions at this step |
| `phase` | string | detection, investigation, containment, resolved |
| `feedback` | string | Analyst feedback on last action |
| `score` | float | Cumulative reward so far |
| `step` | int | Current step number |
| `max_steps` | int | Maximum steps before episode ends |
| `done` | bool | Whether the episode has ended |
| `reward` | float | Reward for last action |

---

## Tasks

### Task 1 - Login Anomaly Triage [easy]

**Scenario:** A low-severity login alert fired for an employee logging in from
an unusual country.

**Challenge:** Distinguish a legitimate VPN user on approved travel from a real
account compromise. The agent must investigate before acting and correctly
identify this as a false positive without blocking a legitimate employee.

**Key skills:** False positive detection, proportionate response.

**Success criteria:** Agent investigates and correctly ignores the alert.

**Max steps:** 5 | **Target score:** >= 0.75

---

### Task 2 - Insider Threat Containment [medium]

**Scenario:** A departing employee exfiltrates 6.8 GB of sensitive IP including
source code, client data, and salary records to a competitor on their final
working days.

**Challenge:** Multi-step containment chain in correct order: investigate,
block account, collect forensics, escalate. Legal hold requirements mean
forensics must be preserved before any destructive actions.

**Key skills:** Ordered decision chains, evidence preservation, legal escalation.

**Success criteria:** Investigate, block account, collect forensics, escalate.

**Max steps:** 8 | **Target score:** >= 0.65

---

### Task 3 - APT Lateral Movement Response [hard]

**Scenario:** An APT29 (Cozy Bear) attributed intrusion actively moving
laterally through the network using Cobalt Strike. Pass-the-Hash attacks
detected across 3 workstations toward the Domain Controller. Domain Admin
hash captured but not yet used.

**Challenge:** Noisy, multi-signal environment with fileless malware (no AV
detections). Agent must reason through the full kill chain within 12 steps
before the Domain Controller is reached.

**Key skills:** Kill chain reasoning, C2 identification, chained containment.

**Success criteria:** Isolate device, block C2 IP, collect forensics, escalate.

**Max steps:** 12 | **Target score:** >= 0.65

---

### Task 4 - Ransomware Precursor Response [critical]

**Scenario:** BlackCat/ALPHV ransomware pre-encryption stage. Shadow copies
deleted on 6 servers, Windows Defender disabled on 34 endpoints, 4 domain
admin accounts compromised, 12 GB already exfiltrated. Estimated 2-4 hours
before encryption begins.

**Challenge:** P0 incident requiring the fastest possible correct response.
Passive actions like monitor are penalized. Speed bonus for completing all
key actions in 5 steps or fewer.

**Key skills:** P0 incident recognition, speed under pressure,
ransomware-specific playbook.

**Success criteria:** Isolate, block exfil IP, collect forensics, escalate.

**Max steps:** 12 | **Target score:** >= 0.70

---

## Baseline Performance Scores

Scores achieved by the baseline LLM agent (Qwen2.5-72B-Instruct):

| Task | Difficulty | Steps | Score | Result |
|---|---|---|---|---|
| Login Anomaly Triage | Easy | 2 | 0.97 | SUCCESS |
| Insider Threat Containment | Medium | 4 | 0.90 | SUCCESS |
| APT Lateral Movement | Hard | 5 | 0.90 | SUCCESS |
| Ransomware Precursor | Critical | 5 | 0.92 | SUCCESS |

**Tasks passed: 4/4**

---

## Setup and Usage

### Option 1 - Use the Live HuggingFace Space

```python
import requests

BASE_URL = "https://apoorvabadoni-soc-env.hf.space"

obs = requests.post(f"{BASE_URL}/reset", json={"task": "task_hard"}).json()
print(obs["observation"]["alert_type"])

result = requests.post(f"{BASE_URL}/step", json={"decision": "investigate"}).json()
print(result["observation"]["feedback"])
```

### Option 2 - Run Locally with Docker

```bash
git clone https://github.com/Oxide06/SOC_Incident_env.git
cd SOC_Incident_env
docker build -t soc-env:latest .
docker run -p 8000:8000 soc-env:latest
```

### Option 3 - Run Inference Script

```bash
pip install openenv-core openai python-dotenv requests

export HF_TOKEN=your_hf_token
export API_BASE_URL=https://router.huggingface.co/v1
export MODEL_NAME=Qwen/Qwen2.5-72B-Instruct

python inference.py
```

### Option 4 - Python Client (Direct Import)

```python
from server.SOC_env_environment import SOCEnvironment
from models import SOCAction

env = SOCEnvironment(difficulty="hard", pinned_scenario_id="hard_apt_lateral_movement")
obs = env.reset()

while not obs.done:
    action = SOCAction(decision="investigate", reasoning="Gathering context first")
    obs = env.step(action)
    print(f"Feedback: {obs.feedback} | Reward: {obs.reward}")
```

---

## API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/health` | GET | Health check |
| `/reset` | POST | Start new episode. Body: {"task": "task_easy"} |
| `/step` | POST | Take action. Body: {"decision": "investigate"} |
| `/state` | GET | Current episode state |
| `/tasks` | GET | List all available tasks |
| `/schema` | GET | Action and observation JSON schemas |
| `/metadata` | GET | Environment name and description |
| `/mcp` | POST | MCP JSON-RPC endpoint |

---

## Reward Structure

| Action | Reward | Condition |
|---|---|---|
| Correct terminal action | +1.0 | Optimal final decision for scenario |
| Good intermediate step | +0.3 | Part of correct sequence |
| Investigate (first time) | +0.15 | Context not yet gathered |
| Ignore (false positive) | +0.8 | Correctly identified benign alert |
| Ignore (real threat) | -0.5 | Dangerous - threat missed |
| Wrong terminal action | -0.3 | Suboptimal final decision |
| Premature escalation | -0.2 | Escalating without investigation |
| Repeat action | -0.1 | Already took this action |

---

## Project Structure

```
SOC_Incident_env/
|-- inference.py          # Baseline LLM agent script
|-- models.py             # SOCAction and SOCObservation Pydantic models
|-- scenarios.py          # 9 threat scenarios with MITRE ATT&CK mapping
|-- tasks.py              # 4 task definitions with deterministic graders
|-- client.py             # OpenEnv HTTP client
|-- openenv.yaml          # OpenEnv spec manifest
|-- pyproject.toml        # Package configuration
|-- Dockerfile            # Container definition
|-- server/
    |-- app.py            # FastAPI server with all endpoints
    |-- SOC_env_environment.py  # Core environment logic
```

---

## References

- [MITRE ATT&CK Framework](https://attack.mitre.org)
- [NIST SP 800-61 Incident Response Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf)
- [OpenEnv Framework](https://github.com/meta-pytorch/OpenEnv)
- [IBM Cost of a Data Breach Report 2024](https://www.ibm.com/reports/data-breach)

---

Built for the Meta-PyTorch OpenEnv Hackathon 2025
