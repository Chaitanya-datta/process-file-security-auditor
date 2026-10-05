// Processes page: live process table with search and security-state filters.

let processes = [];
let stateFilter = "ALL";

function matchesFilter(p) {
  if (stateFilter === "ALL") return true;
  if (stateFilter === "PROTECTED") return p.protected;
  return p.security_state === stateFilter;
}

function renderTable() {
  const query = byId("search").value.trim().toLowerCase();
  const rows = processes.filter((p) =>
    matchesFilter(p) && (!query || String(p.pid).includes(query) || String(p.name).toLowerCase().includes(query)));

  const body = byId("process-body");
  body.replaceChildren();
  if (!processes.length) {
    body.appendChild(emptyRow("Auditor is not running.", 8));
  } else if (!rows.length) {
    body.appendChild(emptyRow("No process matches the search and filter.", 8));
  }
  for (const p of rows) body.appendChild(processRow(p, true));

  byId("process-hint").textContent = processes.length ? `${rows.length} of ${processes.length} shown` : "";
  byId("n-all").textContent = processes.length;
  byId("n-normal").textContent = processes.filter((p) => p.security_state === "NORMAL").length;
  byId("n-suspicious").textContent = processes.filter((p) => p.security_state === "SUSPICIOUS").length;
  byId("n-protected").textContent = processes.filter((p) => p.protected).length;
}

function render(data) {
  processes = data.processes;
  renderTable();
}

byId("search").addEventListener("input", renderTable);
for (const chip of document.querySelectorAll("#state-chips .chip")) {
  chip.addEventListener("click", () => {
    stateFilter = chip.dataset.state;
    document.querySelectorAll("#state-chips .chip").forEach((c) => c.classList.toggle("active", c === chip));
    renderTable();
  });
}
// ?state=SUSPICIOUS / ?q=name in the address pre-selects a filter or search.
const params = new URLSearchParams(window.location.search);
if (params.get("q")) byId("search").value = params.get("q");
const preset = document.querySelector(`#state-chips .chip[data-state="${(params.get("state") || "").toUpperCase()}"]`);
if (preset) preset.click();
startRefresh("/api/processes", render);
