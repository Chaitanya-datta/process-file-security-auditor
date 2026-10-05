// Security Overview page.

function renderTimeline(items) {
  const box = byId("timeline");
  box.replaceChildren();
  if (!items.length) {
    box.appendChild(el("p", "empty", "No alerts in this session."));
    return;
  }
  for (const item of items) {
    const link = timelineEntry(item);
    link.href = "/alerts#" + encodeURIComponent(item.id);
    box.appendChild(link);
  }
}

function renderProcesses(processes) {
  const body = byId("process-body");
  body.replaceChildren();
  if (!processes.length) body.appendChild(emptyRow("Auditor is not running.", 7));
  for (const p of processes) body.appendChild(processRow(p, false));
}

function render(data) {
  byId("c-processes").textContent = data.processes_monitored;
  byId("c-processes-note").textContent = data.status === "RUNNING"
    ? `${data.suspicious_processes} with alerts · poll ${data.cycle}` : "auditor not running";
  byId("c-total").textContent = data.total_alerts;
  byId("c-high").textContent = data.counts.HIGH;
  byId("c-critical").textContent = data.counts.CRITICAL;

  const largest = Math.max(1, ...LEVELS.map((l) => data.counts[l.toUpperCase()]));
  for (const level of LEVELS) {
    const count = data.counts[level.toUpperCase()];
    byId("n-" + level).textContent = count;
    byId("b-" + level).style.width = (count / largest) * 100 + "%";
  }
  byId("suppressed-note").textContent =
    `${data.suppressed_duplicates} repeated alert(s) suppressed by the cooldown`;

  byId("i-auditor").textContent = data.system.auditor;
  byId("i-logging").textContent = data.system.logging;
  byId("i-response").textContent = data.system.auto_response;
  byId("i-interval").textContent = data.system.polling_interval;
  byId("i-protected").textContent = data.system.protected_processes;
  byId("i-watched").textContent = data.system.watched_paths;

  renderTimeline(data.timeline);
  renderProcesses(data.top_processes);
}

startRefresh("/api/status", render);
