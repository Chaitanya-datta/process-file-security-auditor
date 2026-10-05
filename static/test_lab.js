// Test Lab page: shows the built-in scenarios and their latest results, and
// lets the user start one. The request carries only the scenario letter.

let lab = null;
let selectedLetter = null;

async function runScenario(letter) {
  try {
    await fetchJSON(`/api/test-lab/run/${letter}`, {
      method: "POST",
      headers: { "X-Requested-With": "psa-dashboard" },
    });
    showError("");
  } catch (error) {
    showError("Could not start scenario " + letter + ": " + error.message);
  }
}

function resultCell(scenario) {
  const td = el("td", "wrap");
  if (scenario.status === "running") {
    td.appendChild(el("span", "lab-state running", "RUNNING…"));
    return td;
  }
  if (scenario.error) {
    td.appendChild(el("span", "lab-state fail", "ERROR"));
    td.appendChild(el("span", "after-badge", scenario.error));
    return td;
  }
  const result = scenario.result;
  if (!result) {
    td.appendChild(el("span", "lab-state", "NOT RUN YET"));
    return td;
  }
  td.appendChild(el("span", "lab-state " + (result.passed ? "pass" : "fail"), result.passed ? "PASS" : "FAIL"));
  td.appendChild(el("span", "after-badge", result.observed));
  td.appendChild(el("div", "hint", `${result.when} · ${result.source}`));
  return td;
}

function renderDetails() {
  const scenario = lab && lab.scenarios.find((s) => s.letter === selectedLetter);
  const result = scenario && scenario.result;
  byId("lab-details").classList.toggle("hidden", !result);
  if (!result) return;
  byId("lab-details-title").textContent = `Scenario ${scenario.letter} - ${scenario.description}`;
  const list = byId("lab-checks");
  list.replaceChildren();
  for (const [name, ok] of Object.entries(result.checks)) {
    const item = el("li", ok ? "yes" : "no");
    item.appendChild(el("span", "mark", ok ? "✓" : "✗"));
    item.appendChild(el("span", null, name));
    list.appendChild(item);
  }
  byId("lab-notes").textContent = [
    result.simulated_input ? "Input: owner change simulated by controlled test injection." : "",
    result.notes,
  ].filter(Boolean).join(" ");
}

function render(data) {
  lab = data.lab;
  const banner = byId("lab-banner");
  banner.textContent = lab.can_run
    ? (lab.running ? `Scenario ${lab.running} is running…` : "Auditor is running in test mode: scenarios can be started.")
    : lab.cannot_run_reason;
  banner.className = "lab-banner " + (lab.can_run ? "ok" : "warn");

  const body = byId("lab-body");
  body.replaceChildren();
  for (const scenario of lab.scenarios) {
    const tr = el("tr", scenario.letter === selectedLetter ? "row-selected" : "");
    tr.appendChild(cell(scenario.letter, "lab-letter mono"));
    tr.appendChild(cell(scenario.description));
    tr.appendChild(cell(scenario.expected));
    tr.appendChild(resultCell(scenario));
    const time = scenario.result && scenario.result.detection_time_s;
    tr.appendChild(cell(time === null || time === undefined ? "-" : Number(time).toFixed(2) + " s", "mono nowrap"));

    const actions = el("td", "nowrap");
    const run = el("button", "button", "Run");
    run.type = "button";
    run.disabled = !lab.can_run || Boolean(lab.running);
    run.addEventListener("click", (event) => { event.stopPropagation(); runScenario(scenario.letter); });
    actions.appendChild(run);
    tr.appendChild(actions);

    tr.addEventListener("click", () => { selectedLetter = scenario.letter; render(data); });
    body.appendChild(tr);
  }

  byId("lab-full-run").textContent = lab.last_full_run
    ? `Last full terminal run: ${lab.last_full_run.run_at} - ${lab.last_full_run.passed} / ${lab.last_full_run.total} passed.`
    : "No full terminal run recorded yet.";
  renderDetails();
}

startRefresh("/api/test-lab", render);
