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
  .container{max-width:1100px;margin:0 auto;padding:2rem}
  .grid{display:grid;grid-template-columns:1fr 1fr;gap:1.5rem}
  @media(max-width:768px){.grid{grid-template-columns:1fr}}
  .card{background:#1a1f2e;border:1px solid #2d3748;border-radius:12px;padding:1.5rem}
  .card h2{font-size:1rem;font-weight:600;color:#a0aec0;text-transform:uppercase;letter-spacing:1px;margin-bottom:1rem}
  select,button{font-family:inherit;font-size:0.9rem;border-radius:8px;border:1px solid #2d3748;cursor:pointer}
  select{background:#0f1117;color:#e2e8f0;padding:0.6rem 1rem;width:100%;margin-bottom:0.75rem}
  .btn{display:inline-block;padding:0.65rem 1.5rem;font-weight:600;border:none;border-radius:8px;cursor:pointer;transition:all .2s;width:100%;margin-bottom:0.5rem}
  .btn-red{background:#e53e3e;color:#fff}.btn-red:hover{background:#c53030}
  .btn-blue{background:#3182ce;color:#fff}.btn-blue:hover{background:#2b6cb0}
  .btn-gray{background:#2d3748;color:#e2e8f0}.btn-gray:hover{background:#4a5568}
  .action-grid{display:grid;grid-template-columns:1fr 1fr;gap:0.5rem;margin-top:0.5rem}
  .action-btn{padding:0.5rem;font-size:0.8rem;font-weight:600;border:1px solid #2d3748;background:#0f1117;color:#a0aec0;border-radius:8px;transition:all .2s}
  .action-btn:hover{background:#2d3748;color:#fff}
  .action-btn.active{background:#3182ce;color:#fff;border-color:#3182ce}
  .action-btn:disabled{opacity:0.4;cursor:not-allowed}
  .alert-box{background:#1e2a3a;border:1px solid #2d5282;border-radius:8px;padding:1rem;margin-bottom:1rem}
  .alert-type{font-size:1.1rem;font-weight:700;color:#90cdf4;margin-bottom:0.4rem}
  .signals{list-style:none;margin-top:0.5rem}
  .signals li{padding:0.3rem 0;border-bottom:1px solid #2d3748;font-size:0.85rem;color:#cbd5e0}
  .signals li:last-child{border:none}
  .signal-dot{display:inline-block;width:6px;height:6px;background:#e53e3e;border-radius:50%;margin-right:8px}
  .context-box{background:#1a2e1a;border:1px solid #276749;border-radius:8px;padding:1rem;margin-top:0.75rem;font-size:0.82rem;color:#9ae6b4}
  .context-box pre{white-space:pre-wrap;word-break:break-word}
  .log{background:#0f1117;border:1px solid #2d3748;border-radius:8px;padding:1rem;height:280px;overflow-y:auto;font-family:'Courier New',monospace;font-size:0.8rem}
  .log-entry{padding:0.25rem 0;border-bottom:1px solid #1a1f2e}
  .log-step{color:#68d391}.log-reward-pos{color:#68d391}.log-reward-neg{color:#fc8181}
  .log-info{color:#90cdf4}.log-warn{color:#f6e05e}.log-error{color:#fc8181}
  .score-bar{background:#2d3748;border-radius:99px;height:8px;margin-top:0.5rem;overflow:hidden}
  .score-fill{height:100%;background:linear-gradient(90deg,#3182ce,#68d391);border-radius:99px;transition:width .5s}
  .stat{text-align:center;padding:1rem}
  .stat-value{font-size:2rem;font-weight:700;color:#90cdf4}
  .stat-label{font-size:0.75rem;color:#718096;text-transform:uppercase;letter-spacing:1px}
  .stats-row{display:grid;grid-template-columns:repeat(3,1fr);gap:0.5rem;margin-bottom:1rem}
  .phase-pill{display:inline-block;padding:3px 12px;border-radius:99px;font-size:0.75rem;font-weight:600;background:#2d3748;color:#a0aec0;margin-top:0.5rem}
  .feedback-box{background:#1e2535;border-left:3px solid #3182ce;padding:0.75rem 1rem;border-radius:0 8px 8px 0;font-size:0.85rem;color:#cbd5e0;margin-top:0.75rem;white-space:pre-wrap}
  #episode-done{display:none;background:#1c4532;border:1px solid #276749;border-radius:8px;padding:1rem;text-align:center;margin-top:1rem}
  #episode-done h3{color:#68d391;font-size:1.2rem}
  .tasks-list{display:flex;flex-direction:column;gap:0.5rem}
  .task-card{background:#0f1117;border:1px solid #2d3748;border-radius:8px;padding:0.75rem 1rem;cursor:pointer;transition:all .2s}
  .task-card:hover{border-color:#3182ce;background:#1a2035}
  .task-card h3{font-size:0.9rem;font-weight:600;color:#e2e8f0}
  .task-card p{font-size:0.78rem;color:#718096;margin-top:0.25rem}
</style>
</head>
<body>
<header>
  <div style="font-size:1.8rem">🔐</div>
  <div>
    <h1>SOC Incident Response Environment</h1>
    <div style="font-size:0.8rem;color:#718096;margin-top:2px">OpenEnv · Meta-PyTorch Hackathon · Interactive Demo</div>
  </div>
  <span style="margin-left:auto">LIVE</span>
</header>

<div class="container">
  <div class="grid">
    <!-- LEFT PANEL -->
    <div>
      <!-- Task selector -->
      <div class="card" style="margin-bottom:1.5rem">
        <h2>Select Task</h2>
        <div class="tasks-list" id="tasks-list">
          <div style="color:#718096;font-size:0.85rem">Loading tasks...</div>
        </div>
      </div>

      <!-- Alert panel -->
      <div class="card" style="margin-bottom:1.5rem">
        <h2>Current Alert</h2>
        <div id="alert-panel">
          <div style="color:#718096;text-align:center;padding:2rem">
            Select a task and click Reset to start
          </div>
        </div>
      </div>

      <!-- Actions -->
      <div class="card">
        <h2>Actions</h2>
        <div class="action-grid" id="action-grid">
          <button class="action-btn" disabled>investigate</button>
          <button class="action-btn" disabled>ignore</button>
          <button class="action-btn" disabled>monitor</button>
          <button class="action-btn" disabled>block_ip</button>
          <button class="action-btn" disabled>block_account</button>
          <button class="action-btn" disabled>isolate_device</button>
          <button class="action-btn" disabled>escalate</button>
          <button class="action-btn" disabled>request_mfa</button>
          <button class="action-btn" disabled>patch_system</button>
          <button class="action-btn" disabled>collect_forensics</button>
        </div>
        <div id="episode-done">
          <h3 id="done-msg">Episode Complete</h3>
          <p style="color:#a0aec0;font-size:0.85rem;margin-top:0.5rem">Select a task above to start a new episode</p>
        </div>
      </div>
    </div>

    <!-- RIGHT PANEL -->
    <div>
      <!-- Stats -->
      <div class="card" style="margin-bottom:1.5rem">
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
            <div class="stat-value" id="stat-max">-</div>
            <div class="stat-label">Max Steps</div>
          </div>
        </div>
        <div class="score-bar"><div class="score-fill" id="score-fill" style="width:0%"></div></div>
      </div>

      <!-- Feedback -->
      <div class="card" style="margin-bottom:1.5rem">
        <h2>Feedback</h2>
        <div class="feedback-box" id="feedback-box">Waiting for episode to start...</div>
        <div id="phase-pill" class="phase-pill">detection</div>
      </div>

      <!-- Context (unlocked by investigate) -->
      <div class="card" style="margin-bottom:1.5rem" id="context-card" style="display:none">
        <h2>🔍 Investigation Context</h2>
        <div class="context-box" id="context-box"><em>Not yet investigated</em></div>
      </div>

      <!-- Episode log -->
      <div class="card">
        <h2>Episode Log</h2>
        <div class="log" id="log"></div>
      </div>
    </div>
  </div>
</div>

<script>
const BASE = '';
let currentTask = null;
let episodeDone = false;

async function loadTasks() {
  const r = await fetch(BASE + '/tasks');
  const data = await r.json();
  const container = document.getElementById('tasks-list');
  container.innerHTML = '';
  const colors = {easy:'badge-green', medium:'badge-yellow', hard:'badge-red'};
  data.tasks.forEach(t => {
    const div = document.createElement('div');
    div.className = 'task-card';
    div.innerHTML = `
      <div style="display:flex;align-items:center;gap:0.5rem">
        <h3>${t.display_name}</h3>
        <span class="badge ${colors[t.difficulty]}">${t.difficulty}</span>
      </div>
      <p>${t.description.substring(0,100)}...</p>`;
    div.onclick = () => startTask(t.name);
    container.appendChild(div);
  });
}

async function startTask(taskName) {
  currentTask = taskName;
  episodeDone = false;
  document.getElementById('episode-done').style.display = 'none';
  document.getElementById('context-box').innerHTML = '<em>Not yet investigated</em>';
  document.getElementById('log').innerHTML = '';
  document.getElementById('stat-step').textContent = '0';
  document.getElementById('stat-score').textContent = '0.00';
  document.getElementById('score-fill').style.width = '0%';

  const r = await fetch(BASE + '/reset', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({task: taskName})
  });
  const data = await r.json();
  const obs = data.observation;
  renderAlert(obs);
  enableActions(obs.available_actions);
  addLog(`🚨 Episode started: ${taskName}`, 'log-info');
  addLog(`Alert: ${obs.alert_type} | Severity: ${obs.severity.toUpperCase()}`, 'log-info');
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
  const pct = Math.min(100, Math.max(0, (obs.score / obs.max_steps) * 100));
  document.getElementById('score-fill').style.width = pct + '%';
  document.getElementById('stat-max').textContent = obs.max_steps;

  document.getElementById('feedback-box').textContent = obs.feedback;
  document.getElementById('phase-pill').textContent = obs.phase;

  if (obs.context && Object.keys(obs.context).length > 0) {
    document.getElementById('context-box').innerHTML = '<pre>' + JSON.stringify(obs.context, null, 2) + '</pre>';
  }

  const rewardClass = reward >= 0 ? 'log-reward-pos' : 'log-reward-neg';
  const rewardSign = reward >= 0 ? '+' : '';
  addLog(`Step ${obs.step}: ${decision} → reward <span class="${rewardClass}">${rewardSign}${reward.toFixed(2)}</span> | score: ${obs.score.toFixed(2)}`, 'log-step');

  if (data.done) {
    episodeDone = true;
    disableActions();
    const success = obs.score > 0.5;
    document.getElementById('episode-done').style.display = 'block';
    document.getElementById('done-msg').textContent = success ? '✅ Episode Complete — Good work!' : '❌ Episode Failed — Try again';
    document.getElementById('done-msg').style.color = success ? '#68d391' : '#fc8181';
    addLog(`🏁 Episode done | Final score: ${obs.score.toFixed(2)}`, success ? 'log-reward-pos' : 'log-error');
  } else {
    enableActions(obs.available_actions);
  }
}

function renderAlert(obs) {
  const severityColors = {low:'badge-green', medium:'badge-yellow', high:'badge-red', critical:'badge-red'};
  const signals = obs.signals.map(s => `<li><span class="signal-dot"></span>${s}</li>`).join('');
  document.getElementById('alert-panel').innerHTML = `
    <div class="alert-box">
      <div class="alert-type">${obs.alert_type.replace(/_/g,' ').toUpperCase()}</div>
      <span class="badge ${severityColors[obs.severity] || 'badge-blue'}">${obs.severity.toUpperCase()}</span>
      <ul class="signals">${signals}</ul>
    </div>`;
  document.getElementById('feedback-box').textContent = obs.feedback;
  document.getElementById('stat-max').textContent = obs.max_steps;
}

function enableActions(available) {
  document.querySelectorAll('.action-btn').forEach(btn => {
    btn.disabled = false;
    btn.classList.toggle('active', available && available.includes(btn.textContent));
    btn.onclick = () => takeAction(btn.textContent);
  });
}

function disableActions() {
  document.querySelectorAll('.action-btn').forEach(btn => {
    btn.disabled = true;
    btn.classList.remove('active');
  });
}

function addLog(msg, cls) {
  const log = document.getElementById('log');
  const div = document.createElement('div');
  div.className = `log-entry ${cls}`;
  div.innerHTML = `<span style="color:#4a5568">[${new Date().toLocaleTimeString()}]</span> ${msg}`;
  log.appendChild(div);
  log.scrollTop = log.scrollHeight;
}

loadTasks();
</script>
</body>
</html>"""