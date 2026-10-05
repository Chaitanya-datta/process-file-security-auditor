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

let lastProcesses = [];

function renderProcesses() {
  const body = byId("process-body");
  const query = byId("filter").value.trim().toLowerCase();
  const rows = lastProcesses.filter((p) =>
    !query || `${p.pid} ${p.name} ${p.owner}`.toLowerCase().includes(query));
  body.replaceChildren();
  if (!lastProcesses.length) {
    body.appendChild(emptyRow("Auditor is not running.", 6));
  } else if (!rows.length) {
    body.appendChild(emptyRow("No process matches the filter.", 6));
  }
  for (const p of rows) {
    const tr = el("tr");
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
  byId("c-processes").textContent = data.processes_monitored;
  byId("c-processes-note").textContent = data.status === "RUNNING"
    ? `poll ${data.cycle} · every ${data.system.polling_interval}` : "auditor not running";
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
  lastProcesses = data.processes;
  renderProcesses();
}

byId("filter").addEventListener("input", renderProcesses);
startRefresh("/api/status", render);
