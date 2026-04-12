---
title: SOC Incident Response Environment
emoji: 🔐
colorFrom: red
colorTo: blue
sdk: docker
pinned: true
app_port: 8000
tags:
  - openenv
  - reinforcement-learning
  - cybersecurity
  - soc
  - incident-response
---

# 🔐 SOC Incident Response Environment

> **Meta-PyTorch × Scaler OpenEnv Hackathon Submission**

An RL environment where an AI agent acts as a **Tier-1 Security Operations Center (SOC) analyst** — investigating real cybersecurity incidents and deciding how to respond, step by step, under incomplete information and time pressure.

---

## Motivation & Real-World Utility

SOC analysts are overwhelmed. The average analyst handles **1,000+ alerts per day**, with alert fatigue causing **45% of alerts to go uninvestigated** (IBM Cost of a Data Breach Report 2024). A single missed alert can lead to a breach costing millions.

This environment trains AI agents on the exact skills SOC analysts use:

- **False positive triage** — most alerts are noise; ignoring them correctly is as important as catching real threats
- **Multi-step reasoning** — real incidents require 4–6 ordered decisions, not a single answer
- **Proportionate response** — over-reacting (blocking a legitimate user) is penalized as much as under-reacting
- **Investigation-first discipline** — agents learn to gather context before acting, mirroring NIST SP 800-61 playbooks

Scenarios are grounded in **real threat intelligence**: named threat actors (APT29, Lazarus Group, Scattered Spider), actual CVE references (CVE-2023-36884, CVE-2022-30190), and MITRE ATT&CK techniques from real breaches.

---

## Environment Design

### Episode Structure

```
reset() → agent receives alert + signals (context hidden)
step(investigate) → context unlocked, reward +0.15
step(block_account) → containment step, reward +0.30
step(escalate) → terminal action, reward +0.99, done=True
```

Each episode is one security incident. Context is hidden until the agent investigates — mirroring real SOC work where analysts pull logs before acting.

### Reward Design

Rewards are shaped across the full trajectory — not sparse end-of-episode signals:

| Situation                              | Reward   | Notes |
|----------------------------------------|----------|-------|
| Correct terminal action                | **+1.0** | Perfect match to optimal_terminal |
| Good intermediate step (correct seq)   | **+0.30 – +0.38** | +0.05 bonus for early correct steps |
| First investigation                    | **+0.15** | `investigate` or `query_logs` |
| Additional investigation               | **+0.10 – +0.12** | `check_threat_intel`, `run_sandbox`, deep investigate |
| Correctly ignore false positive        | **+0.80 – +0.85** | Best outcome on FP scenarios |
| Over-reaction on false positive        | **−0.30 – −0.35** | Blocking/isolating legitimate activity |
| Ignore real threat                     | **−0.50 – −0.55** | Critical mistake |
| Premature escalation (low/medium)      | **−0.20** | Tier-1 should handle first |
| Repeat same action                     | **−0.10 – −0.12** | Penalized |
| Max steps reached without resolution   | **−0.20** | Penalty |

**Why this matters:** false positives are rewarded for `ignore` (+0.80) but penalized for `block_account` (−0.30). The agent must learn *when* each action is appropriate, not just *what* actions exist.

---

## Action Space

13 discrete actions covering the full SOC analyst toolkit:

| Action | Category | When to use |
|---|---|---|
| `investigate` | Intelligence | Pull SIEM logs, endpoint telemetry — always first |
| `query_logs` | Intelligence | Deep firewall/proxy/DNS log query |
| `check_threat_intel` | Intelligence | Query VirusTotal, Shodan, MISP, Mandiant |
| `run_sandbox` | Intelligence | Detonate suspicious file in isolated sandbox |
| `monitor` | Passive | Watch without acting — low severity only |
| `ignore` | Resolution | Close as confirmed false positive |
| `block_ip` | Containment | Block malicious IP at perimeter firewall |
| `block_account` | Containment | Disable compromised user account |
| `isolate_device` | Containment | Network quarantine for infected endpoint |
| `request_mfa` | Containment | Force MFA re-enrollment after credential theft |
| `patch_system` | Remediation | Remove malicious package or apply patch |
| `collect_forensics` | Evidence | Preserve disk/memory/logs for investigation |
| `escalate` | Escalation | Hand off to Tier-2 / Incident Commander |

Progressive investigation: `investigate` → `query_logs` → `check_threat_intel` → `run_sandbox` reveal progressively deeper context.

---

## Observation Space

| Field | Type | Description |
|---|---|---|
| `alert_type` | str | Category of security alert |
| `severity` | str | `low` / `medium` / `high` / `critical` |
| `signals` | list[str] | Observable indicators (may include `[NOISE]` signals) |
| `context` | dict | Context unlocked by investigation actions |
| `available_actions` | list[str] | Valid actions at this step |
| `phase` | str | `detection` → `investigation` → `containment` → `resolved` |
| `feedback` | str | Result of the last action |
| `score` | float | Cumulative reward (strictly between 0 and 1) |
| `step` / `max_steps` | int | Episode progress |
| `done` | bool | Episode ended |
| `reward` | float | Reward for the last action |

**Noise signals:** some scenarios include `[NOISE]` signals — benign events that look suspicious. Agents that over-investigate noise waste steps and lose score.

---

## Tasks

### task_easy — Login Anomaly Triage
**Difficulty:** Easy | **Max steps:** 5 | **Target score:** ≥ 0.75

A junior marketing analyst's login triggers a geo-anomaly alert from Zurich. Investigation reveals: corporate ZPA VPN, approved conference travel, strong MFA, fully managed device. Classic false positive.

**Challenge:** Resist acting without context. Investigate first, then correctly close the alert without disrupting a legitimate employee.

**Correct sequence:** `investigate → ignore`

**Grader:** investigate+ignore = 0.97 | ignore only = 0.78 | block/escalate on FP = 0.02

---

### task_medium — Insider Threat Containment
**Difficulty:** Medium | **Max steps:** 8 | **Target score:** ≥ 0.65

Senior R&D engineer exfiltrates 8.3 GB including source code, live AWS/Stripe keys, and 47,000 customer PII records to personal Dropbox — night after submitting resignation.

**Challenge:** Multi-step ordered chain. Legal hold means forensics must be collected before blocking. GDPR/SOC2 exposure requires escalation to legal.

**Correct sequence:** `investigate → block_account → collect_forensics → escalate`

**Grader:** +0.20 investigate, +0.25 block, +0.20 forensics, +0.25 escalate, +0.05 order bonus

---

### task_hard — APT Lateral Movement Response
**Difficulty:** Hard | **Max steps:** 12 | **Target score:** ≥ 0.65

Active APT29 (Cozy Bear) intrusion — Cobalt Strike C2 live, Pass-the-Hash lateral movement WS-01 → WS-04 → FS-01 → DC-01. Domain Admin hash being cracked. CVE-2023-36884 initial access 56h ago. Zero AV detections — fully fileless LOLBin attack.

**Challenge:** Noisy signals, fileless malware, nation-state OPSEC, multiple compromised accounts. DC-01 not yet reached — window is closing.

**Correct sequence:** `investigate → isolate_device → block_ip → collect_forensics → escalate`

**Grader:** each key action weighted, perfect order bonus +0.05, `ignore` = instant 0.01

---

## Scenario Library

9 scenarios across 3 tiers — 3 of 9 are false positives (agents that always block score poorly):

| Scenario | Threat Actor | Technique | FP? |
|---|---|---|---|
| Impossible travel / BEC | West African BEC | T1078.004 | No |
| VPN geo-alert | — | — | **Yes** |
| Emotet dropper | — | CVE-2022-30190 | No |
| RDP brute force | Scattered Spider | T1110.001 | No |
| Insider data exfil | — | T1048.003 | No |
| AiTM phishing | Storm-1167 | T1557 | No |
| APT lateral movement | APT29 | CVE-2023-36884 | No |
| PyPI supply chain | Lazarus Group | T1195.001 | No |
| Authorized pentest | — | — | **Yes** |

---

## Baseline Performance

Scores achieved by the baseline LLM agent (Qwen2.5-72B-Instruct):

| Task | Difficulty | Steps | Score | Result |
|---|---|---|---|---|
| Login Anomaly Triage | Easy | 2 | 0.98 | SUCCESS |
| Insider Threat Containment | Medium | 5 | 0.90 | SUCCESS |
| APT Lateral Movement | Hard | 5 | 0.70 | SUCCESS |

**Tasks passed: 3/3** — without task-specific prompting, just NIST SP 800-61 playbook in system prompt.

---

## Setup & Usage

### Docker

```bash
git clone https://github.com/Oxide06/SOC_Incident_env.git
cd SOC_Incident_env
docker build -t soc-env:latest .
docker run -p 8000:8000 soc-env:latest
```

Open `http://localhost:8000/web` for the interactive UI.

### Run baseline inference

```bash
pip install openenv-core openai python-dotenv requests

export HF_TOKEN=your_hf_token
export API_BASE_URL=https://router.huggingface.co/v1
export MODEL_NAME=Qwen/Qwen2.5-72B-Instruct

python inference.py
```

### Python API

```python
import requests

# Start a pinned task
obs = requests.post("http://localhost:8000/reset",
                    json={"task": "task_hard"}).json()["observation"]

# Step through the incident
result = requests.post("http://localhost:8000/step",
                       json={"decision": "investigate"}).json()
print(result["reward"])   # 0.15
print(result["observation"]["context"])  # APT29 attribution, C2 details...
```

### Direct Python import

```python
from server.SOC_env_environment import SOCEnvironment
from models import SOCAction

env = SOCEnvironment(difficulty="hard",
                     pinned_scenario_id="hard_apt_lateral_movement")
obs = env.reset()

while not obs.done:
    action = SOCAction(decision="investigate",
                       reasoning="Gathering context first")
    obs = env.step(action)
    print(f"Step {obs.step} | Reward: {obs.reward:.2f}")
```

---

## API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Health check |
| `POST` | `/reset` | Start episode — body: `{"task": "task_easy"}` |
| `POST` | `/step` | Submit action — body: `{"decision": "investigate"}` |
| `GET` | `/state` | Current episode state |
| `GET` | `/tasks` | List all evaluation tasks |
| `GET` | `/schema` | Action + observation schemas |
| `GET` | `/web` | Interactive web UI |
| `GET` | `/docs` | Auto-generated API docs |

---

## Project Structure

```
SOC_Incident_env/
├── inference.py              # Baseline LLM agent (OpenAI client)
├── models.py                 # SOCAction + SOCObservation (Pydantic)
├── scenarios.py              # 9 real-world threat scenarios (MITRE ATT&CK)
├── tasks.py                  # 3 named tasks + deterministic graders
├── client.py                 # OpenEnv WebSocket/HTTP client
├── Dockerfile                # Container (root — docker build .)
├── openenv.yaml              # OpenEnv spec manifest
├── pyproject.toml            # Package config
└── server/
    ├── app.py                # FastAPI server + web UI
    └── SOC_env_environment.py  # Core RL logic
```

---

## References

- [MITRE ATT&CK Framework](https://attack.mitre.org)
- [NIST SP 800-61 Incident Response Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf)
- [OpenEnv Framework](https://github.com/meta-pytorch/OpenEnv)
- [IBM Cost of a Data Breach 2024](https://www.ibm.com/reports/data-breach)
- [CVE-2023-36884 — Microsoft Office HTML RCE](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36884)
- [APT29 Midnight Blizzard — Microsoft Threat Intelligence](https://www.microsoft.com/en-us/security/blog/tag/midnight-blizzard/)
