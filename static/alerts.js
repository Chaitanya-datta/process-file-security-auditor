// Alerts page: Security Activity Timeline (left) and Alert Details (right).
// Everything shown comes from the alert as it was logged by the auditor.

let alerts = [];
let selectedId = decodeURIComponent(window.location.hash.slice(1)) || null;
let severityFilter = "";

function renderTimeline() {
  const box = byId("timeline");
  const shown = alerts.filter((a) => !severityFilter || a.severity === severityFilter);
  box.replaceChildren();
  if (!shown.length) {
    box.appendChild(el("p", "empty", alerts.length ? "No alerts with this severity." : "No alerts in this session."));
  }
  for (const alert of shown) {
    const entry = timelineEntry(alert);
    entry.href = "#" + encodeURIComponent(alert.id);
    if (alert.id === selectedId) entry.classList.add("selected");
    entry.addEventListener("click", (event) => {
      event.preventDefault();
      selectedId = alert.id;
      history.replaceState(null, "", "#" + encodeURIComponent(alert.id));
      renderTimeline();
      renderDetails();
    });
    box.appendChild(entry);
  }
  byId("timeline-hint").textContent = alerts.length ? `${shown.length} of ${alerts.length} shown, newest first` : "";
}

function setList(id, items, className) {
  const list = byId(id);
  list.replaceChildren();
  for (const item of items) list.appendChild(el("li", className, item));
}

function responseText(alert) {
  switch (alert.response_type) {
    case "SUGGESTED_ACTION": return "Suggestion shown - no change was made to the process";
    case "AUTO_RESPONSE": return `Automatic response: ${alert.action_taken} - ${alert.result}`;
    case "BLOCKED_PROTECTED": return "No action - blocked by the protected-process policy";
    case "WITHHELD": return "No action - " + alert.result;
    default: return alert.result || "-";
  }
}

function protectedText(alert) {
  if (alert.protected === true) return "YES - " + alert.protected_reason;
  if (alert.protected === false) return "NO - " + alert.protected_reason;
  return "Not checked (the protected list is only consulted for Critical alerts)";
}

function renderDetails() {
  const alert = alerts.find((a) => a.id === selectedId);
  byId("details-empty").classList.toggle("hidden", Boolean(alert));
  byId("details-body").classList.toggle("hidden", !alert);
  if (!alert) return;

  byId("d-badge").replaceChildren(severityBadge(alert.severity));
  byId("d-title").textContent = alert.title;
  byId("d-sub").textContent = `${alert.process} | PID ${alert.pid} | ${alert.time}`;

  const rules = byId("d-rules");
  rules.replaceChildren();
  for (const rule of alert.rules) {
    const item = el("li", rule.triggered ? "yes" : "no");
    item.appendChild(el("span", "mark", rule.triggered ? "✓" : "✗"));
    item.appendChild(el("span", null, rule.label));
    if (rule.carried_over) item.appendChild(el("span", "hint", "seen in an earlier poll"));
    rules.appendChild(item);
  }
  const severity = byId("d-severity");
  severity.replaceChildren(severityBadge(alert.severity), el("span", "after-badge", alert.severity_explanation));
  setList("d-reasons", alert.reasons);

  byId("d-process").textContent = alert.process + (alert.is_test_process ? "  (controlled test process)" : "");
  byId("d-pid").textContent = alert.pid;
  byId("d-parent").textContent = `${alert.parent} (PPID ${alert.ppid})`;
  byId("d-user").textContent = alert.user || "unknown";
  byId("d-exe").textContent = alert.executable || "not available";
  byId("d-files").textContent = alert.files.length ? alert.files.join("\n") : "none";
  byId("d-usage").textContent = alert.cpu_percent === null || alert.cpu_percent === undefined
    ? "not recorded"
    : `CPU ${Number(alert.cpu_percent).toFixed(1)}%  ·  memory ${Number(alert.memory_percent).toFixed(1)}% at the time of the alert`;
  byId("d-time").textContent = alert.time;

  byId("d-recommended").textContent = alert.recommended_action
    || "None - Critical alerts are handled by the Auto-Response Module";
  byId("d-response").textContent = responseText(alert);
  byId("d-protected").textContent = protectedText(alert);
  byId("d-id").textContent = "Alert ID " + alert.id
    + (alert.simulated ? "  ·  owner change was SIMULATED by controlled test injection" : "");
}

function render(data) {
  alerts = data.alerts;
  if (!alerts.some((a) => a.id === selectedId)) selectedId = alerts.length ? alerts[0].id : null;
  renderTimeline();
  renderDetails();
}

for (const chip of document.querySelectorAll("#severity-chips .chip")) {
  chip.addEventListener("click", () => {
    severityFilter = chip.dataset.severity;
    document.querySelectorAll("#severity-chips .chip").forEach((c) => c.classList.toggle("active", c === chip));
    renderTimeline();
  });
}
startRefresh("/api/alerts", render);
