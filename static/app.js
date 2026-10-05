// Shared dashboard code: small DOM helpers, the header status indicator and
// the refresh loop. Every page only FETCHES JSON from the Flask API and
// displays it. All text is inserted with textContent, so a process name can
// never be interpreted as HTML.

const REFRESH_MS = Number(document.body.dataset.refreshSeconds || 2) * 1000;
const LEVELS = ["low", "medium", "high", "critical"];
const byId = (id) => document.getElementById(id);

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

function cell(text, className) {
  return el("td", className, text === null || text === undefined || text === "" ? "-" : text);
}

function emptyRow(message, columns) {
  const tr = el("tr");
  const td = el("td", "empty", message);
  td.colSpan = columns;
  tr.appendChild(td);
  return tr;
}

function severityBadge(severity) {
  return el("span", "badge sev-" + String(severity).toLowerCase(), severity);
}

// One entry of the Security Activity Timeline (an <a> so it can be a link or a button).
function timelineEntry(item) {
  const entry = el("a", "timeline-entry sev-" + String(item.severity).toLowerCase());
  entry.appendChild(el("span", "timeline-time mono", String(item.time).slice(11)));
  entry.appendChild(severityBadge(item.severity));
  const text = el("span", "timeline-text");
  text.appendChild(el("span", "timeline-title", item.title));
  text.appendChild(el("span", "timeline-process mono", `${item.process} | PID ${item.pid}`));
  entry.appendChild(text);
  if (item.simulated) entry.appendChild(el("span", "tag small", "simulated input"));
  return entry;
}

// "SUSPICIOUS (HIGH, 2 alerts)", "PROTECTED" or "NORMAL" for the process tables.
function securityStateCell(p) {
  const td = el("td");
  const state = el("span", "state state-" + p.security_state.toLowerCase(), p.security_state);
  td.appendChild(state);
  if (p.security_state === "SUSPICIOUS") {
    td.appendChild(severityBadge(p.highest_severity));
    const link = el("a", "state-link", `${p.alert_count} alert${p.alert_count === 1 ? "" : "s"}`);
    link.href = "/alerts";
    td.appendChild(link);
    if (p.protected) td.appendChild(el("span", "hint", "protected"));
  }
  return td;
}

// One row of a process table; withStatus adds the OS process status column.
function processRow(p, withStatus) {
  const tr = el("tr", p.security_state === "SUSPICIOUS" ? "row-suspicious" : "");
  tr.appendChild(cell(p.pid, "mono"));
  const name = cell(p.name);
  if (p.is_test_process) name.appendChild(el("span", "tag small", "test process"));
  tr.appendChild(name);
  tr.appendChild(cell(p.user));
  tr.appendChild(cell(p.ppid, "mono"));
  tr.appendChild(cell(Number(p.cpu_percent).toFixed(1), "num"));
  // macOS does not let an ordinary user read the memory of other users' processes.
  const memory = Number(p.memory_mb) > 0
    ? `${Number(p.memory_mb).toFixed(1)} MB (${Number(p.memory_percent || 0).toFixed(1)}%)` : "n/a";
  tr.appendChild(cell(memory, "num nowrap"));
  if (withStatus) tr.appendChild(cell(p.status, "mono"));
  tr.appendChild(securityStateCell(p));
  return tr;
}

// Horizontal bar chart drawn with plain <div>s. items: [{label, count, key?}]
// Bars are scaled to the largest count in the group; "key" picks a severity colour.
function renderBars(containerId, items) {
  const box = byId(containerId);
  const largest = Math.max(1, ...items.map((item) => item.count));
  box.replaceChildren();
  for (const item of items) {
    const row = el("div", "bar-row");
    row.appendChild(el("span", "bar-name", item.label));
    const track = el("div", "bar-track");
    const bar = el("div", "bar" + (item.key ? " sev-" + item.key : ""));
    bar.style.width = (item.count / largest) * 100 + "%";
    track.appendChild(bar);
    row.appendChild(track);
    row.appendChild(el("span", "bar-count", item.count));
    box.appendChild(row);
  }
}

function showError(message) {
  const box = byId("error");
  box.textContent = message;
  box.classList.toggle("hidden", !message);
}

async function fetchJSON(url, options) {
  const response = await fetch(url, Object.assign({ cache: "no-store" }, options || {}));
  const data = await response.json();
  if (data.error) throw new Error(data.error);
  return data;
}

// Header: "● AUDITOR ACTIVE" / "AUDITOR STOPPED", shown on every page.
function renderHeader(status) {
  const running = status.status === "RUNNING";
  byId("status").className = "status " + (running ? "running" : "stopped");
  byId("status-text").textContent = running ? "AUDITOR ACTIVE" : "AUDITOR STOPPED";
  byId("test-mode").classList.toggle("hidden", !status.test_mode);
  byId("status-detail").textContent = running
    ? `session ${status.session_id} · last poll ${status.heartbeat_age_seconds}s ago`
    : (status.session_id ? `last session ${status.session_id}` : "start it with: python3 -m src.main");
  byId("updated").textContent = new Date().toLocaleTimeString();
}

// Each page calls startRefresh(url, render). The API response always carries
// the header status under "header" (or is the status object itself).
function startRefresh(url, render) {
  async function tick() {
    try {
      const data = await fetchJSON(url);
      showError("");
      renderHeader(data.header || data);
      render(data);
    } catch (error) {
      showError("Dashboard could not load data: " + error.message);
    }
  }
  tick();
  setInterval(tick, REFRESH_MS);
}
