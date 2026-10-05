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
