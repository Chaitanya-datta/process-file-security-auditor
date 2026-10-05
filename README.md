# Process & File-Access Security Auditor

A small watchdog that monitors the processes running on a computer, detects
suspicious behaviour with six rule-based checks, rates how serious it is, and
responds appropriately.

| | |
|---|---|
| **OS area** | Operating Systems Security / Process Management |
| **Course** | Operating Systems Lab (BCSE303P) |
| **Team** | Unta Chaitanya Datta (24BCE0327), M. Sana Fathima (24BCI0021) |
| **Faculty** | Suchithra J |
| **Platform** | macOS, Python 3, psutil (Flask for the dashboard) |

It is a rule-based, polling, user-space tool for an OS lab. It is **not**
malware detection, not an EDR product, not kernel-level monitoring and it
uses no machine learning.

---

## Quick start

```bash
cd ~/Desktop/process-file-security-auditor
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt

python3 -m tests.test_runner        # runs scenarios A-J and prints the results table
```

| What | Command |
|---|---|
| Auditor | `python3 -m src.main` |
| Auditor for the demo and tests | `python3 -m src.main --test-mode` |
| Dashboard | `python3 -m src.dashboard`, then open <http://127.0.0.1:5050> |
| All scenarios (A-J) | `python3 -m tests.test_runner` |
| One scenario | `python3 -m tests.scenario_b` (a ... j) |
| Unit and dashboard checks | `python3 -m unittest tests.test_units tests.test_dashboard` |

## Demo (5-10 minutes)

Open two terminals in the project folder and run `source .venv/bin/activate` in each.

| Step | Where | Do | Point out |
|---|---|---|---|
| 1 | Terminal 1 | `python3 -m src.main --test-mode` | Live status line: processes monitored, polling every 2 s |
| 2 | Terminal 2 | `python3 -m src.dashboard` | - |
| 3 | Browser | open <http://127.0.0.1:5050> | AUDITOR ACTIVE, real process count, 0 alerts |
| 4 | Browser | **Architecture** page | The pipeline, one box per module |
| 5 | Browser | **Detection Rules** page | Six checks, live thresholds, the severity table |
| 6 | Browser | **Test Lab** → Run **A** | Normal activity: no alert anywhere |
| 7 | Browser | Test Lab → Run **B**, then **D** | HIGH (sensitive file) and MEDIUM (unusual parent); suggestions only |
| 8 | Browser | **Alerts** page, click an alert | "Why this alert was generated": ticked rules, severity, reason |
| 9 | Browser | Test Lab → Run **E**, then **F** | E: CRITICAL, not protected, process suspended. F: CRITICAL, protected, no action |
| 10 | Browser | Test Lab → Run **G**, **H**, **J** | New detections, and two findings combining into HIGH |
| 11 | Browser | **Statistics** and **Processes** pages | Counts by severity / detection; search and the Protected filter |
| 12 | Terminal 1 | show `logs/audit.log`, then `Ctrl+C` | The same alerts in the log; clean shutdown; dashboard shows STOPPED |

Scenario I (sustained CPU) takes about 15 seconds because the rule needs five
consecutive polls. Every scenario can also be run from a terminal, for example
`python3 -m tests.scenario_e --hold 15` keeps the suspended test process for
15 seconds so `ps -o pid,stat,command -p <PID>` shows state `T` (stopped).

---

## 1. Problem statement

Attackers try to gain extra permissions or quietly open sensitive files such
as private keys and password files. Tools like Activity Monitor, `ps` and
`top` show what is running, but they only display information: they do not
remember a process's original owner, check which files it has open, judge
whether its parent is unusual, rate a finding, or respond to it.

This project provides that missing workflow:

> process monitoring → suspicious-activity detection → alert generation →
> event correlation → severity classification → suggested response →
> controlled automatic response → logging

## 2. Objectives

1. Monitor every running process: PID, owner, permission level, parent, executable, open files, CPU, memory.
2. Detect suspicious behaviour with six explainable rules (section 5).
3. Combine findings about the same process into one alert and avoid repeated alerts.
4. Give every alert one severity: Low, Medium, High or Critical.
5. Suggest a next step for Low, Medium and High alerts; the user decides.
6. Automatically suspend or terminate the process for Critical alerts only.
7. Never act on a process in the protected process list.
8. Log every alert with time, PID, reason, severity and action taken.
9. Show everything on a local dashboard.
10. Validate the system with controlled test scenarios.

## 3. Operating-system concepts used

| Concept | Where it appears in this project |
|---|---|
| **Process** | The unit the auditor watches. Every program runs as one or more processes. |
| **Process table** | The OS's list of all processes. `psutil.process_iter()` reads it each cycle. |
| **PID** | Unique number of a running process; the key for baselines and alerts. PIDs are reused after a process exits, so the creation time is stored with it. |
| **PPID / parent-child** | Every process is created by a parent (`fork`/`exec`). The PPID links child to parent; the unusual-parent and process-burst checks use it. |
| **Process ownership** | Each process runs as a user (real UID) with a permission level (effective UID; 0 = root). A change while running suggests privilege escalation. |
| **Executable path** | The file a process was started from; the suspicious-location check compares it with a list of folders. |
| **Polling** | The auditor asks the OS for the current state every few seconds instead of being notified by the kernel. |
| **File access** | The OS tracks each process's open file descriptors. `psutil.open_files()` lists them; paths are compared with the watchlist. |
| **Resource accounting** | The OS records CPU time and resident memory per process; the resource check reads them. |
| **Process control** | The OS lets one process send signals to another it has permission over. |
| **Suspension** | `SIGSTOP` freezes a process (state `stopped`); `SIGCONT` resumes it. Reversible. Default Critical response. |
| **Termination** | `SIGTERM` asks a process to exit. Optional Critical response. |
| **OS security** | Access control decides what the auditor may read: macOS denies an unprivileged process the open-file list of other users' processes. |

## 4. Architecture

```
Running Processes (OS process table)
        ↓
Process Watcher                 one snapshot every N seconds
        ↓
Detection Layer
 ├── Owner Change
 ├── Sensitive File
 ├── Unusual Parent
 ├── Suspicious Execution Location
 ├── Process Creation Burst
 └── Resource Usage Anomaly
        ↓
Alert Maker                     one alert per process; repeats removed (cooldown)
        ↓
Event Correlation               adds the same process's findings from earlier polls
        ↓
Severity Scorer                 LOW / MEDIUM / HIGH / CRITICAL
        ↓
 LOW / MEDIUM / HIGH  → Suggested Action Advisor (no change is made)
 CRITICAL             → Protected Process Check → Auto-Response (suspend / terminate)
        ↓
Logging                         audit.log, alerts.jsonl, terminal
        ↓
Dashboard                       reads the log and status files
```

More detail and a Mermaid diagram: [docs/architecture.md](docs/architecture.md).
The dashboard's Architecture page shows the same pipeline.

## 5. The six detection checks

| # | Check | Rule in one sentence | On its own | Configured in |
|---|---|---|---|---|
| 1 | **Owner Change** | The process's owner or effective UID differs from the baseline recorded when it was first seen. | HIGH | automatic baseline |
| 2 | **Sensitive File Access** | The process has a file open that is on the watchlist. | HIGH (LOW if tagged `low`) | `config/sensitive_files.txt` |
| 3 | **Unusual Parent** | The (parent, child) name pair matches a rule, e.g. a browser starting a shell. | MEDIUM | `config/parent_rules.json` |
| 4 | **Suspicious Execution Location** | The process's executable file is inside a listed folder such as `/tmp` or `~/Downloads`. | MEDIUM | `config/suspicious_locations.txt` |
| 5 | **Process Creation Burst** | One parent created 10 or more children within 10 seconds. | MEDIUM | `config/settings.json` |
| 6 | **Resource Usage Anomaly** | CPU above 90 % or memory above 80 % for 5 polls in a row. | MEDIUM | `config/settings.json` |

Every check follows the same shape: *collect data → apply rule → return
finding*. All six read the same snapshot from the Process Watcher; none of
them starts a subprocess or scans the filesystem.

## 6. Modules

| Module | File | What it does |
|---|---|---|
| Process Watcher | [src/process_watcher.py](src/process_watcher.py) | Polls all processes through psutil; skips processes that exit, are zombies or deny access |
| Owner Change Detection | [src/owner_detector.py](src/owner_detector.py) | Baseline per PID + creation time; flags a later change |
| Sensitive File Detection | [src/sensitive_file_detector.py](src/sensitive_file_detector.py) | Compares open files with the watchlist |
| Unusual Parent Detection | [src/parent_detector.py](src/parent_detector.py) | Checks parent-child name pairs against rules |
| Suspicious Execution Location | [src/exec_location_detector.py](src/exec_location_detector.py) | Compares executable paths with listed folders |
| Process Creation Burst | [src/burst_detector.py](src/burst_detector.py) | Counts recently created children per parent |
| Resource Usage Anomaly | [src/resource_detector.py](src/resource_detector.py) | Counts consecutive polls above a threshold |
| Alert Maker | [src/alert_maker.py](src/alert_maker.py) | One alert per process per cycle |
| Alert De-duplication | [src/alert_deduplicator.py](src/alert_deduplicator.py) | Cooldown per process + rule + object |
| Event Correlation | [src/event_correlation.py](src/event_correlation.py) | Remembers each process's recent findings and adds them to new alerts |
| Severity Scorer | [src/severity_scorer.py](src/severity_scorer.py) | Fixed table → exactly one level |
| Suggested Action Advisor | [src/action_advisor.py](src/action_advisor.py) | Recommends a next step; never changes a process |
| Protected Process List | [src/protected_processes.py](src/protected_processes.py) | Decides whether a process may be acted on |
| Auto-Response Module | [src/auto_response.py](src/auto_response.py) | Critical only: suspend / terminate, then verify with the OS |
| Logging / Screen Display | [src/audit_logger.py](src/audit_logger.py) | `audit.log`, `alerts.jsonl`, terminal, status file |
| Dashboard | [src/dashboard.py](src/dashboard.py), [src/test_lab.py](src/test_lab.py) | Local web pages |
| Test Script | [tests/](tests/) | Scenarios A-J, harness, unit checks |

[src/main.py](src/main.py) connects them in `Auditor.run_cycle`.

## 7. Severity rules

| Triggered rule(s) on one process | Severity | Response |
|---|---|---|
| Sensitive file tagged `low` | **LOW** | Suggestion |
| Unusual parent alone | **MEDIUM** | Suggestion |
| Suspicious execution location alone | **MEDIUM** | Suggestion |
| Process creation burst alone | **MEDIUM** | Suggestion |
| Resource usage anomaly alone | **MEDIUM** | Suggestion |
| Sensitive file alone | **HIGH** | Suggestion |
| Owner change alone | **HIGH** | Suggestion |
| Two or more different MEDIUM rules together | **HIGH** | Suggestion |
| **Owner change + sensitive-file access** | **CRITICAL** | Protected check, then suspend / terminate |

In one sentence: *each rule has a base level, the alert takes the highest
one, two medium findings together make HIGH, and owner change with
sensitive-file access makes CRITICAL.* The table is fixed, so the same
findings always give the same severity.

CRITICAL is the only level that can lead to automatic action, and only the
owner-change + sensitive-file combination can reach it. The three added
detections can never cause a process to be suspended or terminated.

## 8. Event correlation and de-duplication

**Correlation.** Findings for the same process (same PID *and* creation time)
are combined into one alert:

- findings from the same poll are grouped by the Alert Maker;
- the Event Correlator remembers each process's findings for
  `correlation_window_seconds` (60 s) and adds them to a later alert for that
  process, marked "seen N s earlier".

Example: a program running from `/tmp` (MEDIUM) later creates a burst of
children; the new alert lists both rules and is rated HIGH.

**De-duplication.** The auditor polls every 2 seconds, so a condition lasting
a minute would otherwise be reported 30 times. A finding is identified by
*process + rule + object* (the file path, the executable path, the old/new
owner...). An alert is raised only if at least one of its findings has not
been seen during the last `alert_cooldown_seconds` (120 s). The cooldown
restarts every time the finding is seen again, so a condition that persists is
reported once, and again only after it has been absent for a full cooldown.
New behaviour (another rule, another file) is never suppressed.

## 9. Response and protection

- **Low / Medium / High**: the Suggested Action Advisor attaches a
  recommended next step. Nothing is changed.
- **Critical**: the Auto-Response Module asks the Protected Process List
  first. A process is protected if its **name** is listed (`launchd`,
  `WindowServer`, `loginwindow`, `Finder`, ...), its **PID** is listed (0 and 1
  always are), its name is in the **testing policy** list (Scenario F fixture),
  or it is **the auditor itself or one of its parents**. If protected: no
  action, logged with `Protected: YES` and the reason.
- The check is repeated on the live process immediately before
  `suspend()` / `terminate()`, together with a PID-reuse check.
- **Scope policy**: with the default `auto_response_scope: "test_only"`, only
  processes started by this project's test framework can be acted on. A
  Critical alert on any other process is logged as "automatic response
  withheld".
- The default action is **suspend**, which is reversible.

## 10. Dashboard

`python3 -m src.dashboard`, then <http://127.0.0.1:5050>. Pages refresh every
2 seconds.

| Page | Shows |
|---|---|
| **Overview** | Auditor status, cards (processes monitored, total / high / critical alerts), system status (auditor, logging, auto-response, polling interval, protected processes, watched paths), severity bars, latest alerts, busiest processes |
| **Alerts** | Security Activity Timeline with severity filters; Alert Details: why the alert was generated (ticked rules, severity, reasons), process, PPID, user, executable, relevant file, CPU / memory, recommended action, response status, protected-process decision |
| **Processes** | Live table with search (name or PID) and filters All / Normal / Suspicious / Protected |
| **Statistics** | Alerts by severity and by detection rule |
| **Test Lab** | Scenarios A-J with expected and latest results; a Run button for each |
| **Detection Rules** | The six checks in plain English with the configured values; the severity table |
| **Architecture** | The pipeline diagram |

Every number comes from the auditor's own files (`logs/auditor_state.json`,
`logs/alerts.jsonl`) or from `config/`; nothing is hard-coded. If the auditor
is not running, the header says AUDITOR STOPPED.

The dashboard has no buttons that control processes. The only action it
offers is starting one of the fixed test scenarios in the Test Lab: the
request carries a scenario letter that is looked up in a fixed table, no shell
is used, requests must come from the dashboard page on the same computer, and
the auditor must be running in `--test-mode`.

## 11. Configuration

All configuration is in `config/`; see [docs/configuration.md](docs/configuration.md)
for every setting. A missing or malformed file never crashes the auditor: it
prints a warning and uses safe defaults.

| File | Purpose |
|---|---|
| `settings.json` | Polling interval, cooldown, correlation window, burst and resource thresholds, response action and scope, dashboard port |
| `sensitive_files.txt` | Sensitive-file watchlist |
| `parent_rules.json` | Unusual parent-child rules |
| `suspicious_locations.txt` | Suspicious execution folders |
| `protected_processes.json` | Protected process list |

## 12. Logging

| File | Content |
|---|---|
| `logs/audit.log` | Human-readable audit trail, plus start / stop events |
| `logs/alerts.jsonl` | The same alerts, one JSON object per line |
| `logs/auditor_state.json` | Current status and process table (for the dashboard) |

```
[ALERT]
  Alert ID: 20261005-211332-52914-0010
  Time: 2026-10-05 21:14:34
  PID: 52981
  Process: psa_unusual_location_app (owner: chaitanyadatta)
  Parent: python3.10 (PID 52911)
  Executable: .../tests/sandbox/unusual_location/psa_unusual_location_app
  Rule(s): SUSPICIOUS_EXEC_LOCATION + PROCESS_BURST
  Reason: Suspicious execution location: ... (inside configured location 'tests/sandbox/unusual_location')
  Reason: Process creation burst: ... created 12 child processes within 10 seconds (threshold 10); children: sleep
  Severity: HIGH - 2 medium-level findings on the same process: SUSPICIOUS_EXEC_LOCATION + PROCESS_BURST
  Suggested Action: Investigate now: check what the process has read or changed. ...
  Action: Suggested action shown (no change made to the process)

[CRITICAL]
  ...
  Rule(s): OWNER_CHANGE + SENSITIVE_FILE
  Severity: CRITICAL - Owner change combined with sensitive-file access in the same process
  Protected: NO (not on the protected process list)
  Action: Process suspended
  Result: Success (verified: process state is 'stopped')
```

## 13. Testing and results

`python3 -m tests.test_runner` runs ten scenarios against a real running
auditor. A-F are the six original scenarios, G-I cover the three added
detections, and J covers correlation and de-duplication.

Latest run on the development Mac (macOS 27.0, Python 3.10.11, psutil 7.2.2, polling interval 2 s), 2026-10-05 21:39:45: **10 / 10 passed**.

| Scenario | Expected Result | Observed Result | Pass/Fail | Severity | Response | Detection Time | Logging Correct | Protected Safety |
|---|---|---|---|---|---|---|---|---|
| A | No Alert | No Alert | PASS | - | None | n/a (watched 8.0s) | Yes | Yes |
| B | Alert + HIGH + Suggestion | Alert + HIGH + Suggestion | PASS | HIGH | Suggestion | 1.95s | Yes | Yes |
| C | Alert + HIGH + Suggestion | Alert + HIGH + Suggestion | PASS | HIGH | Suggestion | 1.99s | Yes | Yes |
| D | Alert + MEDIUM + Suggestion | Alert + MEDIUM + Suggestion | PASS | MEDIUM | Suggestion | 1.93s | Yes | Yes |
| E | CRITICAL + Auto-response (suspend) | CRITICAL + Suspended (auto) | PASS | CRITICAL | Suspended (auto) | 2.02s | Yes | Yes |
| F | CRITICAL + No action (protected) + reason logged | CRITICAL + None (protected) | PASS | CRITICAL | None (protected) | 2.00s | Yes | Yes |
| G | Alert + MEDIUM + Suggestion | Alert + MEDIUM + Suggestion | PASS | MEDIUM | Suggestion | 1.92s | Yes | Yes |
| H | Alert + MEDIUM + Suggestion | Alert + MEDIUM + Suggestion | PASS | MEDIUM | Suggestion | 1.96s | Yes | Yes |
| I | Alert + MEDIUM + Suggestion | Alert + MEDIUM + Suggestion | PASS | MEDIUM | Suggestion | 9.95s | Yes | Yes |
| J | MEDIUM, then HIGH (combined) + Suggestion; no repeats | MEDIUM, then HIGH (combined) + Suggestion; 2 alerts in total | PASS | HIGH | Suggestion | 1.99s | Yes | Yes |

These values are measured and change slightly on every run; the current ones
are always in `results/test_results.md`. Detection times are close to one
polling interval (2 s) because the tests trigger the activity right after a
poll, which is the worst case. Scenario I takes about 10 s by design: the
rule needs five consecutive polls above the threshold.

**Simulated input.** In scenarios C, E and F the *owner change* is simulated
through a clearly separated test hook, because an unprivileged macOS process
cannot change its owner and the project does not perform real privilege
escalation. Detection, scoring, response and logging are the production code,
and those alerts are labelled as simulated. Scenarios A, B, D, G, H, I and J
use no simulation. Full explanation: [docs/testing.md](docs/testing.md).

Unit and dashboard checks (57 tests, no auditor needed):
`python3 -m unittest tests.test_units tests.test_dashboard`.

## 14. Project structure

```
process-file-security-auditor/
├── README.md, requirements.txt, .gitignore
├── src/
│   ├── main.py                     # pipeline + command-line entry point
│   ├── config.py, models.py        # configuration loading; records passed between modules
│   ├── process_watcher.py
│   ├── owner_detector.py, sensitive_file_detector.py, parent_detector.py
│   ├── exec_location_detector.py, burst_detector.py, resource_detector.py
│   ├── alert_maker.py, alert_deduplicator.py, event_correlation.py
│   ├── severity_scorer.py, action_advisor.py
│   ├── protected_processes.py, auto_response.py
│   ├── audit_logger.py
│   ├── dashboard.py, test_lab.py
│   └── test_hooks.py               # controlled test injection (test mode only)
├── config/                         # settings.json + four rule / list files
├── templates/                      # base, overview, alerts, processes, statistics, test_lab, rules, architecture
├── static/                         # style.css + one small script per page
├── tests/
│   ├── test_runner.py              # runs A-J, writes results
│   ├── scenario_a.py ... scenario_j.py
│   ├── harness.py, fixture_process.py
│   └── test_units.py, test_dashboard.py
├── logs/                           # audit.log, alerts.jsonl, auditor_state.json
├── results/                        # test_results.md / .csv / .json
└── docs/                           # architecture, testing, configuration, macOS setup
```

`tests/sandbox/` (dummy files and named test executables) is created
automatically by the test harness.

## 15. macOS notes and troubleshooting

Setup details and troubleshooting: [docs/macos_setup.md](docs/macos_setup.md).
No `sudo` and no change to macOS security settings is needed.

| Symptom | Fix |
|---|---|
| `No module named 'psutil'` | `source .venv/bin/activate` and reinstall requirements |
| `No module named src` | Run commands from the project folder |
| "An auditor is already running" | Stop the other one with `Ctrl+C` |
| Dashboard port in use | `python3 -m src.dashboard --port 5051` (macOS uses 5000 for AirPlay, so the default is 5050) |
| Header shows AUDITOR STOPPED | Start the auditor in another terminal |
| Test Lab buttons disabled | Start the auditor with `--test-mode` |

## 16. Safety

- The auditor never opens, reads or modifies a watched file; it compares paths.
- Low, Medium and High alerts never change a process.
- Automatic action needs: Critical severity + not protected + within the
  scope policy + same PID and creation time as the alert.
- Default response is suspend (reversible); default scope is test processes only.
- No `sudo`, `killall`, `pkill`, `kill -9`, `chmod`/`chown` of system files or `rm -rf` is used.
- The dashboard cannot run arbitrary commands.
- The tests touch only dummy files and their own test processes, and clean up.

## 17. Limitations

- **Polling is not kernel-level monitoring.** Activity shorter than one
  polling interval (a file opened and closed between two polls, a child that
  starts and exits between two polls) can be missed, and detection takes up to
  one interval.
- **macOS permissions limit what can be read.** Without root, the open files,
  command line, CPU and memory of other users' processes are not readable, so
  the sensitive-file and resource checks effectively cover the current user's
  processes. Name, owner, parent and executable path are readable for
  (almost) every process.
- **Suspicious locations are a heuristic.** Legitimately running an installer
  from `~/Downloads` or a build output from `/tmp` raises a MEDIUM alert.
- **Process-burst detection is threshold-based.** Builds and scripts that
  start many processes can reach it; very short-lived children are not counted.
- **Resource thresholds are fixed rules.** Legitimate heavy work (a compile, a
  video call) can raise a MEDIUM alert; CPU % is per core.
- **Owner change is direction-blind.** A daemon that drops privileges
  (root → service account) after it was first seen is reported like an
  escalation. It is reported once while it lasts.
- **Name-based rules.** Parent rules and the protected list match process
  names, which a malicious program could imitate.
- **Heuristics, not proof.** An alert means "unusual", not "attack".
- **Simulated owner change in tests**, as described above.
- **Baseline starts at first sight.** A process that changed owner before the
  auditor started is recorded with its current owner.

### Compared with OSSEC and Falco

Falco receives events from the kernel (eBPF / kernel module), so it sees every
system call as it happens; OSSEC combines log analysis, file-integrity checks
and active response across many hosts. This project uses the same idea -
observe, apply rules, rate, respond, log - but in user space with polling,
which is far simpler and portable at the cost of the polling gap above.

## 18. Possible future work

- Event-based monitoring (Endpoint Security on macOS, eBPF on Linux) to close the polling gap.
- Distinguishing privilege drops from escalations in the owner-change rule.
- A user-approved "resume" command for suspended processes.
- Learning normal parent-child pairs instead of fixed rules.
