// Dashboard refresh logic. It only fetches /api/status and displays it.
// All text is inserted with textContent, so a process name can never be
// interpreted as HTML.

const REFRESH_MS = Number(document.body.dataset.refreshSeconds || 2) * 1000;
const LEVELS = ["low", "medium", "high", "critical"];
const byId = (id) => document.getElementById(id);

function cell(text, className) {
  const td = document.createElement("td");
  td.textContent = text === null || text === undefined ? "-" : String(text);
  if (className) td.className = className;
  return td;
}

function emptyRow(message) {
  const tr = document.createElement("tr");
  const td = cell(message, "empty");
  td.colSpan = 6;
  tr.appendChild(td);
  return tr;
}

function renderAlerts(alerts) {
  const body = byId("alerts-body");
  body.replaceChildren();
  if (!alerts.length) {
    body.appendChild(emptyRow("No alerts in this session."));
    return;
  }
  for (const a of alerts) {
    const tr = document.createElement("tr");
    tr.appendChild(cell(a.time, "nowrap"));
    tr.appendChild(cell(a.pid, "mono"));
    tr.appendChild(cell(a.process));
    tr.appendChild(cell(a.reason, "wrap"));
    const severity = cell("");
    const badge = document.createElement("span");
    badge.className = "badge sev-" + String(a.severity).toLowerCase();
    badge.textContent = a.severity;
    severity.appendChild(badge);
    if (a.simulated) {
      const tag = document.createElement("span");
      tag.className = "tag small";
      tag.textContent = "simulated input";
      severity.appendChild(tag);
    }
    tr.appendChild(severity);
    tr.appendChild(cell(a.action, "wrap"));
    body.appendChild(tr);
  }
}

let lastProcesses = [];

function renderProcesses() {
  const body = byId("process-body");
  const query = byId("filter").value.trim().toLowerCase();
  const rows = lastProcesses.filter((p) =>
    !query || `${p.pid} ${p.name} ${p.owner}`.toLowerCase().includes(query));
  body.replaceChildren();
  if (!lastProcesses.length) {
    body.appendChild(emptyRow("Auditor is not running."));
  } else if (!rows.length) {
    body.appendChild(emptyRow("No process matches the filter."));
  }
  for (const p of rows) {
    const tr = document.createElement("tr");
    tr.appendChild(cell(p.pid, "mono"));
    tr.appendChild(cell(p.name));
    tr.appendChild(cell(p.owner));
    tr.appendChild(cell(p.ppid, "mono"));
    tr.appendChild(cell(Number(p.cpu_percent).toFixed(1), "num"));
    tr.appendChild(cell(Number(p.memory_mb).toFixed(1), "num"));
    body.appendChild(tr);
  }
  byId("process-hint").textContent = lastProcesses.length
    ? `${rows.length} of ${lastProcesses.length} shown, sorted by CPU` : "";
}

function render(data) {
  const running = data.status === "RUNNING";
  const status = byId("status");
  status.textContent = data.status;
  status.className = "status " + (running ? "running" : "stopped");
  byId("test-mode").classList.toggle("hidden", !data.test_mode);
  byId("status-detail").textContent = running
    ? `session ${data.session_id} · last poll ${data.heartbeat_age_seconds}s ago`
    : (data.session_id ? `last session ${data.session_id}` : "start it with: python3 -m src.main");

  byId("c-processes").textContent = data.processes_monitored;
  byId("c-total").textContent = data.total_alerts;
  const largest = Math.max(1, ...LEVELS.map((l) => data.counts[l.toUpperCase()]));
  for (const level of LEVELS) {
    const count = data.counts[level.toUpperCase()];
    byId("c-" + level).textContent = count;
    byId("n-" + level).textContent = count;
    byId("b-" + level).style.width = (count / largest) * 100 + "%";
  }

  byId("i-interval").textContent = data.system.polling_interval;
  byId("i-logging").textContent = data.system.logging;
  byId("i-protected").textContent = data.system.protected;
  byId("i-watchlist").textContent = data.system.watchlist;
  byId("i-cycle").textContent = data.cycle;
  byId("i-suppressed").textContent = data.suppressed_duplicates;

  renderAlerts(data.alerts);
  lastProcesses = data.processes;
  renderProcesses();
  byId("updated").textContent = new Date().toLocaleTimeString();
}

function showError(message) {
  const box = byId("error");
  box.textContent = message;
  box.classList.toggle("hidden", !message);
}

async function refresh() {
  try {
    const response = await fetch("/api/status", { cache: "no-store" });
    const data = await response.json();
    if (data.error) throw new Error(data.error);
    showError("");
    render(data);
  } catch (error) {
    showError("Dashboard could not load data: " + error.message);
  }
}

byId("filter").addEventListener("input", renderProcesses);
refresh();
setInterval(refresh, REFRESH_MS);
