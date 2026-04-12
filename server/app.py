from typing import Optional
from fastapi import FastAPI
from fastapi.responses import JSONResponse, HTMLResponse
from pydantic import BaseModel

try:
    from SOC_env.server.SOC_env_environment import SOCEnvironment
    from SOC_env.models import SOCAction, SOCObservation
    from SOC_env.tasks import TASKS as TASK_REGISTRY
except ModuleNotFoundError:
    from server.SOC_env_environment import SOCEnvironment
    from models import SOCAction, SOCObservation
    from tasks import TASKS as TASK_REGISTRY

app = FastAPI(title="SOC Incident Response Environment", version="0.1.0")
_env = SOCEnvironment()

class ResetRequest(BaseModel):
    task: Optional[str] = None
    difficulty: Optional[str] = "random"

class StepRequest(BaseModel):
    decision: str
    reasoning: Optional[str] = None

@app.get("/health")
async def health():
    return {"status": "healthy"}

@app.get("/metadata")
async def metadata():
    return {
        "name": "SOC_env",
        "description": "SOC Incident Response Environment — AI agent acts as a Tier-1 SOC analyst triaging security alerts across easy, medium, and hard scenarios.",
        "version": "0.1.0",
        "author": "ApoorvaBadoni",
    }

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
    return JSONResponse({"tasks": [
        {"name": t["name"], "display_name": t["display_name"],
         "difficulty": t["difficulty"], "description": t["description"],
         "max_steps": t["max_steps"], "success_criteria": t["success_criteria"]}
        for t in TASK_REGISTRY.values()
    ]})

@app.get("/schema")
async def schema():
    from openenv.core.env_server.types import State
    return JSONResponse({
        "action": SOCAction.model_json_schema(),
        "observation": SOCObservation.model_json_schema(),
        "state": State.model_json_schema(),
    })

@app.post("/mcp")
async def mcp():
    return JSONResponse({
        "jsonrpc": "2.0",
        "id": None,
        "result": {
            "name": "SOC_env",
            "description": "SOC Incident Response Environment",
            "tools": []
        }
    })

@app.get("/web", response_class=HTMLResponse)
@app.get("/", response_class=HTMLResponse)
async def web_ui():
    return HTMLResponse(content=WEB_UI)

def main(host: str = "0.0.0.0", port: int = 8000):
    import uvicorn
    uvicorn.run(app, host=host, port=port, reload=False)

if __name__ == "__main__":
    main()

WEB_UI = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>SOC Incident Response Environment</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:'Segoe UI',system-ui,sans-serif;background:#0f1117;color:#e2e8f0;min-height:100vh}
  header{background:linear-gradient(135deg,#1a1f2e,#16213e);border-bottom:1px solid #2d3748;padding:1.5rem 2rem;display:flex;align-items:center;gap:1rem}
  header h1{font-size:1.5rem;font-weight:700;color:#fff}
  header span{background:#e53e3e;color:#fff;font-size:0.7rem;font-weight:700;padding:2px 8px;border-radius:99px;letter-spacing:1px}
  .badge{display:inline-block;padding:2px 10px;border-radius:99px;font-size:0.72rem;font-weight:600}
  .badge-red{background:#742a2a;color:#fc8181}
  .badge-yellow{background:#744210;color:#f6e05e}
  .badge-green{background:#1c4532;color:#68d391}
  .badge-blue{background:#1a365d;color:#90cdf4}
  .badge-purple{background:#44337a;color:#d6bcfa}
  .container{max-width:1200px;margin:0 auto;padding:2rem}
  .grid{display:grid;grid-template-columns:1fr 1fr;gap:1.5rem}
  @media(max-width:900px){.grid{grid-template-columns:1fr}}
  .card{background:#1a1f2e;border:1px solid #2d3748;border-radius:12px;padding:1.5rem}
  .card h2{font-size:0.85rem;font-weight:600;color:#718096;text-transform:uppercase;letter-spacing:1px;margin-bottom:1rem}
  .action-section{margin-bottom:0.75rem}
  .action-section-label{font-size:0.7rem;color:#4a5568;text-transform:uppercase;letter-spacing:1px;margin-bottom:0.4rem;font-weight:600}
  .action-grid{display:grid;grid-template-columns:1fr 1fr;gap:0.4rem}
  .action-grid-3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:0.4rem}
  .action-btn{padding:0.45rem 0.5rem;font-size:0.75rem;font-weight:600;border:1px solid #2d3748;background:#0f1117;color:#718096;border-radius:6px;transition:all .15s;cursor:pointer;text-align:center}
  .action-btn:hover:not(:disabled){background:#2d3748;color:#e2e8f0;border-color:#4a5568}
  .action-btn.active{border-color:#3182ce;color:#90cdf4}
  .action-btn.intel{border-color:#2d3748;color:#b794f4}
  .action-btn.intel:hover:not(:disabled){background:#2d3748;color:#d6bcfa;border-color:#553c9a}
  .action-btn.danger{color:#fc8181}
  .action-btn.danger:hover:not(:disabled){background:#742a2a;border-color:#fc8181}
  .action-btn.safe{color:#68d391}
  .action-btn.safe:hover:not(:disabled){background:#1c4532;border-color:#68d391}
  .action-btn:disabled{opacity:0.3;cursor:not-allowed}
  .alert-box{background:#1e2a3a;border:1px solid #2d5282;border-radius:8px;padding:1rem;margin-bottom:1rem}
  .alert-type{font-size:1rem;font-weight:700;color:#90cdf4;margin-bottom:0.5rem;text-transform:uppercase;letter-spacing:0.5px}
  .signals{list-style:none;margin-top:0.5rem}
  .signals li{padding:0.3rem 0;border-bottom:1px solid #1a2a3a;font-size:0.82rem;color:#cbd5e0;display:flex;align-items:flex-start;gap:0.5rem}
  .signals li:last-child{border:none}
  .signal-dot{width:6px;height:6px;border-radius:50%;flex-shrink:0;margin-top:5px}
  .signal-real{background:#e53e3e}
  .signal-noise{background:#4a5568}
  .context-box{background:#0d1f0d;border:1px solid #276749;border-radius:8px;padding:1rem;margin-top:0.75rem;font-size:0.78rem;color:#9ae6b4;max-height:200px;overflow-y:auto}
  .context-box pre{white-space:pre-wrap;word-break:break-word;font-family:'Courier New',monospace}
  .context-source{font-size:0.7rem;color:#48bb78;margin-bottom:0.5rem;font-weight:600;text-transform:uppercase;letter-spacing:1px}
  .log{background:#0a0d13;border:1px solid #2d3748;border-radius:8px;padding:0.75rem;height:240px;overflow-y:auto;font-family:'Courier New',monospace;font-size:0.75rem}
  .log-entry{padding:0.2rem 0;border-bottom:1px solid #0f1117;line-height:1.4}
  .log-step{color:#68d391}.log-reward-pos{color:#68d391}.log-reward-neg{color:#fc8181}
  .log-info{color:#90cdf4}.log-warn{color:#f6e05e}.log-intel{color:#b794f4}
  .score-bar{background:#1a1f2e;border-radius:99px;height:6px;margin-top:0.5rem;overflow:hidden;border:1px solid #2d3748}
  .score-fill{height:100%;background:linear-gradient(90deg,#3182ce,#68d391);border-radius:99px;transition:width .4s}
  .stat{text-align:center;padding:0.75rem 0.5rem}
  .stat-value{font-size:1.8rem;font-weight:700;color:#90cdf4;line-height:1}
  .stat-label{font-size:0.65rem;color:#4a5568;text-transform:uppercase;letter-spacing:1px;margin-top:0.3rem}
  .stats-row{display:grid;grid-template-columns:repeat(3,1fr);gap:0.5rem;margin-bottom:0.75rem}
  .phase-pill{display:inline-block;padding:3px 10px;border-radius:99px;font-size:0.7rem;font-weight:600;background:#2d3748;color:#a0aec0;margin-top:0.5rem}
  .phase-detection{background:#2d1f1f;color:#fc8181}
  .phase-investigation{background:#1f2d1f;color:#68d391}
  .phase-containment{background:#1f1f2d;color:#90cdf4}
  .phase-resolved{background:#1c4532;color:#68d391}
  .feedback-box{background:#111827;border-left:3px solid #3182ce;padding:0.75rem 1rem;border-radius:0 8px 8px 0;font-size:0.82rem;color:#cbd5e0;margin-top:0.75rem;white-space:pre-wrap;max-height:120px;overflow-y:auto}
  #episode-done{display:none;border-radius:8px;padding:1rem;text-align:center;margin-top:1rem}
  #episode-done h3{font-size:1.1rem}
  .tasks-list{display:flex;flex-direction:column;gap:0.5rem}
  .task-card{background:#0f1117;border:1px solid #2d3748;border-radius:8px;padding:0.75rem 1rem;cursor:pointer;transition:all .15s}
  .task-card:hover{border-color:#3182ce;background:#111827}
  .task-card.selected{border-color:#3182ce;background:#111827}
  .task-card h3{font-size:0.85rem;font-weight:600;color:#e2e8f0}
  .task-card p{font-size:0.75rem;color:#4a5568;margin-top:0.25rem;line-height:1.4}
  .divider{border:none;border-top:1px solid #2d3748;margin:0.75rem 0}
  .hint{font-size:0.72rem;color:#4a5568;font-style:italic;margin-top:0.5rem}
</style>
</head>
<body>
<header>
  <div style="font-size:1.6rem">🔐</div>
  <div>
    <h1>SOC Incident Response Environment</h1>
    <div style="font-size:0.75rem;color:#4a5568;margin-top:2px">OpenEnv · RL Training Environment · Tier-1 SOC Analyst Simulation</div>
  </div>
  <span style="margin-left:auto">LIVE</span>
</header>

<div class="container">
  <div class="grid">
    <!-- LEFT PANEL -->
    <div>
      <div class="card" style="margin-bottom:1.25rem">
        <h2>Select Task</h2>
        <div class="tasks-list" id="tasks-list">
          <div style="color:#4a5568;font-size:0.82rem">Loading tasks...</div>
        </div>
      </div>

      <div class="card" style="margin-bottom:1.25rem">
        <h2>Active Alert</h2>
        <div id="alert-panel">
          <div style="color:#4a5568;text-align:center;padding:2rem;font-size:0.85rem">
            Select a task to begin incident response
          </div>
        </div>
      </div>

      <div class="card">
        <h2>Response Actions</h2>

        <div class="action-section">
          <div class="action-section-label">🔍 Investigation</div>
          <div class="action-grid-3">
            <button class="action-btn intel" disabled data-action="investigate" title="Pull SIEM logs and endpoint telemetry">investigate</button>
            <button class="action-btn intel" disabled data-action="query_logs" title="Deep firewall/proxy/DNS log query">query_logs</button>
            <button class="action-btn intel" disabled data-action="check_threat_intel" title="Query VirusTotal, Shodan, MISP">threat_intel</button>
          </div>
          <div class="action-grid" style="margin-top:0.4rem">
            <button class="action-btn intel" disabled data-action="run_sandbox" title="Detonate sample in sandbox">run_sandbox</button>
            <button class="action-btn" disabled data-action="monitor" title="Passive monitoring">monitor</button>
          </div>
        </div>

        <hr class="divider">

        <div class="action-section">
          <div class="action-section-label">🛡️ Containment</div>
          <div class="action-grid">
            <button class="action-btn danger" disabled data-action="block_ip" title="Block at perimeter firewall">block_ip</button>
            <button class="action-btn danger" disabled data-action="block_account" title="Disable user account">block_account</button>
            <button class="action-btn danger" disabled data-action="isolate_device" title="Network quarantine">isolate_device</button>
            <button class="action-btn" disabled data-action="request_mfa" title="Force MFA re-enrollment">request_mfa</button>
          </div>
        </div>

        <hr class="divider">

        <div class="action-section">
          <div class="action-section-label">📋 Resolution</div>
          <div class="action-grid-3">
            <button class="action-btn" disabled data-action="collect_forensics" title="Preserve disk/memory/logs">forensics</button>
            <button class="action-btn" disabled data-action="patch_system" title="Remove package or apply patch">patch</button>
            <button class="action-btn danger" disabled data-action="escalate" title="Hand off to Tier-2/IR team">escalate</button>
          </div>
          <div style="margin-top:0.4rem">
            <button class="action-btn safe" disabled data-action="ignore" title="Close as false positive" style="width:100%">ignore (false positive)</button>
          </div>
        </div>

        <div id="episode-done">
          <h3 id="done-msg">Episode Complete</h3>
          <p style="color:#718096;font-size:0.8rem;margin-top:0.4rem">Select a task above to start a new episode</p>
        </div>
        <div class="hint" id="action-hint"></div>
      </div>
    </div>

    <!-- RIGHT PANEL -->
    <div>
      <div class="card" style="margin-bottom:1.25rem">
        <h2>Episode Stats</h2>
        <div class="stats-row">
          <div class="stat">
            <div class="stat-value" id="stat-step">0</div>
            <div class="stat-label">Step</div>
          </div>
          <div class="stat">
            <div class="stat-value" id="stat-score" style="color:#68d391">0.00</div>
            <div class="stat-label">Score</div>
          </div>
          <div class="stat">
            <div class="stat-value" id="stat-max">—</div>
            <div class="stat-label">Max Steps</div>
          </div>
        </div>
        <div class="score-bar"><div class="score-fill" id="score-fill" style="width:0%"></div></div>
      </div>

      <div class="card" style="margin-bottom:1.25rem">
        <h2>Analyst Feedback</h2>
        <div class="feedback-box" id="feedback-box">Waiting for episode to start...</div>
        <div id="phase-pill" class="phase-pill phase-detection">detection</div>
      </div>

      <div class="card" style="margin-bottom:1.25rem">
        <h2>Investigation Context</h2>
        <div id="context-panel">
          <div style="color:#4a5568;font-size:0.8rem;font-style:italic">
            Use investigate, query_logs, check_threat_intel, or run_sandbox to reveal context.
          </div>
        </div>
      </div>

      <div class="card">
        <h2>Episode Log</h2>
        <div class="log" id="log"></div>
      </div>
    </div>
  </div>
</div>

<script>
const BASE = '';
let episodeDone = false;
let currentTask = null;

const ACTION_MAP = {
  'investigate': 'investigate',
  'query_logs': 'query_logs',
  'threat_intel': 'check_threat_intel',
  'run_sandbox': 'run_sandbox',
  'monitor': 'monitor',
  'block_ip': 'block_ip',
  'block_account': 'block_account',
  'isolate_device': 'isolate_device',
  'request_mfa': 'request_mfa',
  'forensics': 'collect_forensics',
  'patch': 'patch_system',
  'escalate': 'escalate',
  'ignore (false positive)': 'ignore',
};

async function loadTasks() {
  const r = await fetch(BASE + '/tasks');
  const data = await r.json();
  const container = document.getElementById('tasks-list');
  container.innerHTML = '';
  const colors = {easy:'badge-green', medium:'badge-yellow', hard:'badge-red'};
  data.tasks.forEach(t => {
    const div = document.createElement('div');
    div.className = 'task-card';
    div.id = 'task-' + t.name;
    div.innerHTML = `
      <div style="display:flex;align-items:center;gap:0.5rem;margin-bottom:0.25rem">
        <h3>${t.display_name}</h3>
        <span class="badge ${colors[t.difficulty] || 'badge-blue'}">${t.difficulty}</span>
      </div>
      <p>${t.description.substring(0,110)}...</p>`;
    div.onclick = () => startTask(t.name);
    container.appendChild(div);
  });
}

async function startTask(taskName) {
  currentTask = taskName;
  episodeDone = false;
  document.getElementById('episode-done').style.display = 'none';
  document.getElementById('context-panel').innerHTML = '<div style="color:#4a5568;font-size:0.8rem;font-style:italic">Use investigate, query_logs, check_threat_intel, or run_sandbox to reveal context.</div>';
  document.getElementById('log').innerHTML = '';
  document.getElementById('stat-step').textContent = '0';
  document.getElementById('stat-score').textContent = '0.00';
  document.getElementById('score-fill').style.width = '0%';
  document.getElementById('action-hint').textContent = '';

  document.querySelectorAll('.task-card').forEach(c => c.classList.remove('selected'));
  const tc = document.getElementById('task-' + taskName);
  if (tc) tc.classList.add('selected');

  const r = await fetch(BASE + '/reset', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({task: taskName})
  });
  const data = await r.json();
  const obs = data.observation;
  renderAlert(obs);
  enableActions(obs.available_actions);
  addLog('Episode started: ' + taskName, 'log-info');
  addLog('Alert: ' + obs.alert_type + ' | Severity: ' + obs.severity.toUpperCase(), 'log-info');
}

async function takeAction(decision) {
  if (episodeDone) return;
  const r = await fetch(BASE + '/step', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({decision: decision})
  });
  const data = await r.json();
  const obs = data.observation;
  const reward = data.reward;

  document.getElementById('stat-step').textContent = obs.step;
  document.getElementById('stat-score').textContent = obs.score.toFixed(2);
  const pct = Math.min(100, Math.max(0, obs.score * 50));
  document.getElementById('score-fill').style.width = pct + '%';
  document.getElementById('stat-max').textContent = obs.max_steps;
  document.getElementById('feedback-box').textContent = obs.feedback;

  const pill = document.getElementById('phase-pill');
  pill.textContent = obs.phase;
  pill.className = 'phase-pill phase-' + obs.phase;

  if (obs.context && Object.keys(obs.context).length > 0) {
    renderContext(obs.context, decision);
  }

  const rewardSign = reward >= 0 ? '+' : '';
  const rewardClass = reward >= 0 ? 'log-reward-pos' : 'log-reward-neg';
  const isIntel = ['investigate','query_logs','check_threat_intel','run_sandbox'].includes(decision);
  addLog(
    'Step ' + obs.step + ': <b>' + decision + '</b>' +
    ' | reward <span class="' + rewardClass + '">' + rewardSign + reward.toFixed(2) + '</span>' +
    ' | score: ' + obs.score.toFixed(2),
    isIntel ? 'log-intel' : 'log-step'
  );

  if (data.done) {
    episodeDone = true;
    disableActions();
    const success = obs.score > 0.5;
    const doneEl = document.getElementById('episode-done');
    doneEl.style.display = 'block';
    doneEl.style.background = success ? '#1c4532' : '#2d1f1f';
    doneEl.style.border = '1px solid ' + (success ? '#276749' : '#742a2a');
    document.getElementById('done-msg').textContent = success ? 'Incident Contained' : 'Incident Unresolved';
    document.getElementById('done-msg').style.color = success ? '#68d391' : '#fc8181';
    addLog('Episode complete | Final score: ' + obs.score.toFixed(2), success ? 'log-reward-pos' : 'log-reward-neg');
  } else {
    enableActions(obs.available_actions);
  }
}

function renderContext(context, action) {
  const source = context._source || action;
  const filtered = Object.fromEntries(Object.entries(context).filter(([k]) => !k.startsWith('_')));
  const hint = context._hint || context._note || '';
  const sourceColors = {
    'investigate': '#90cdf4',
    'query_logs': '#90cdf4',
    'check_threat_intel': '#b794f4',
    'run_sandbox': '#f6ad55',
    'Deep-dive investigation': '#68d391',
  };
  const color = sourceColors[source] || '#9ae6b4';

  const panel = document.getElementById('context-panel');
  const existing = panel.innerHTML;
  const newBlock = `
    <div class="context-box" style="margin-bottom:0.5rem">
      <div class="context-source" style="color:${color}">${source.replace(/_/g,' ').toUpperCase()}</div>
      <pre>${JSON.stringify(filtered, null, 2)}</pre>
      ${hint ? '<div style="color:#718096;font-size:0.72rem;margin-top:0.5rem;font-style:italic">' + hint + '</div>' : ''}
    </div>`;

  if (panel.querySelector('.context-box')) {
    panel.innerHTML = newBlock + panel.innerHTML;
  } else {
    panel.innerHTML = newBlock;
  }
}

function renderAlert(obs) {
  const severityColors = {low:'badge-green', medium:'badge-yellow', high:'badge-red', critical:'badge-red'};
  const signals = obs.signals.map(s => {
    const isNoise = s.includes('[NOISE]');
    const clean = s.replace('[NOISE] ', '');
    return `<li>
      <span class="signal-dot ${isNoise ? 'signal-noise' : 'signal-real'}"></span>
      <span style="${isNoise ? 'color:#4a5568;font-style:italic' : ''}">${clean}${isNoise ? ' <span style="color:#4a5568;font-size:0.7rem">[possibly benign]</span>' : ''}</span>
    </li>`;
  }).join('');
  document.getElementById('alert-panel').innerHTML = `
    <div class="alert-box">
      <div class="alert-type">${obs.alert_type.replace(/_/g,' ')}</div>
      <span class="badge ${severityColors[obs.severity] || 'badge-blue'}">${obs.severity.toUpperCase()}</span>
      <ul class="signals" style="margin-top:0.75rem">${signals}</ul>
    </div>`;
  document.getElementById('feedback-box').textContent = obs.feedback;
  document.getElementById('stat-max').textContent = obs.max_steps;
}

function enableActions(available) {
  document.querySelectorAll('.action-btn').forEach(btn => {
    const action = ACTION_MAP[btn.textContent.trim()] || btn.dataset.action;
    btn.disabled = false;
    if (available && action && !available.includes(action)) {
      btn.style.opacity = '0.4';
    } else {
      btn.style.opacity = '1';
    }
    btn.onclick = () => {
      const a = ACTION_MAP[btn.textContent.trim()] || btn.dataset.action;
      if (a) takeAction(a);
    };
  });
}

function disableActions() {
  document.querySelectorAll('.action-btn').forEach(btn => {
    btn.disabled = true;
  });
}

function addLog(msg, cls) {
  const log = document.getElementById('log');
  const div = document.createElement('div');
  div.className = 'log-entry ' + cls;
  div.innerHTML = '<span style="color:#2d3748">[' + new Date().toLocaleTimeString() + ']</span> ' + msg;
  log.appendChild(div);
  log.scrollTop = log.scrollHeight;
}

loadTasks();
</script>
</body>
</html>"""