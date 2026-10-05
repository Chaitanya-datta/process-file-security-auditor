# Process & File-Access Security Auditor

A small watchdog that monitors the processes running on a computer, detects
suspicious behaviour, rates how serious it is, and responds appropriately.

| | |
|---|---|
| **OS area** | Operating Systems Security / Process Management |
| **Course** | Operating Systems Lab (BCSE303P) |
| **Team** | Unta Chaitanya Datta (24BCE0327), M. Sana Fathima (24BCI0021) |
| **Faculty** | Suchithra J |
| **Platform** | macOS, Python 3, psutil (Flask for the dashboard) |

---

## Quick start

```bash
cd ~/Desktop/process-file-security-auditor
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt

python3 -m tests.test_runner        # runs all six scenarios, prints the results table
```

## Demo (5-10 minutes)

Open three terminals in the project folder and run `source .venv/bin/activate` in each.

| Step | Where | Command | What to point out |
|---|---|---|---|
| 1 | Terminal 1 | `python3 -m src.main --test-mode` | Live status line: processes monitored, polling every 2 s |
| 2 | Terminal 2 | `python3 -m src.dashboard` | - |
| 3 | Browser | open <http://127.0.0.1:5050> | RUNNING, real process table, 0 alerts |
| 4 | Terminal 3 | `python3 -m tests.scenario_a` | Normal file: **no alert** anywhere |
| 5 | Terminal 3 | `python3 -m tests.scenario_b` | Sensitive file: **HIGH** + suggested action; process untouched |
| 6 | Terminal 3 | `python3 -m tests.scenario_d` | Fake browser starts a shell: **MEDIUM** + suggestion |
| 7 | Terminal 3 | `python3 -m tests.scenario_e --hold 15` | **CRITICAL**: protected check = NO, process **suspended** (verified) |
| 8 | Terminal 3 | `python3 -m tests.scenario_f` | **CRITICAL** on a protected process: **no action**, reason logged |
| 9 | Terminal 3 | `python3 -m tests.test_runner` | Full A-F results table, saved to `results/` |
| 10 | Terminal 1 | `Ctrl+C` | Clean shutdown; dashboard switches to STOPPED |

After each scenario the alert appears in Terminal 1, in `logs/audit.log`, and
on the dashboard (cards, severity bars and the Recent Alerts table update
within about 2 seconds). Scenario C (`python3 -m tests.scenario_c`) shows the
owner-change rule on its own.

During step 7, `--hold 15` keeps the suspended test process for 15 seconds, so
you can show its state in another terminal with `ps -o pid,stat,command -p <PID>`
(`T` = stopped).

---

## 1. Problem statement

Attackers try to gain extra permissions or quietly open sensitive files such
as private keys and password files. Tools like Activity Monitor, `ps` and
`top` show what is running, but they only display information: they do not
remember a process's original owner, check which files it has open, judge
whether its parent is unusual, rate a finding, or respond to it.

This project provides that missing workflow:

> process monitoring -> suspicious-activity detection -> alert generation ->
> severity classification -> suggested response -> controlled automatic
> response -> logging

## 2. Objectives

1. Monitor every running process: PID, owner, permission level, parent, open files.
2. Detect a change of owner or permission level while a process is running.
3. Detect access to files on a configurable sensitive-file watchlist.
4. Detect unusual parent-child process relationships.
5. Give every alert one severity: Low, Medium, High or Critical.
6. Suggest a next step for Low, Medium and High alerts; the user decides.
7. Automatically suspend or terminate the process for Critical alerts.
8. Never act on a process in the protected process list.
9. Log every alert with time, PID, reason, severity and action taken.
10. Validate the system with six controlled test scenarios.

## 3. Operating-system concepts used

| Concept | Where it appears in this project |
|---|---|
| **Process** | The unit the auditor watches. Every program runs as one or more processes. |
| **Process table** | The OS's list of all processes. `psutil.process_iter()` reads it each cycle. |
| **PID** | Unique number of a running process; the key for baselines and alerts. PIDs are reused after a process exits, so the creation time is stored with it. |
| **PPID / parent-child** | Every process is created by a parent (`fork`/`exec`). The PPID links child to parent; the unusual-parent check uses it. |
| **Process ownership** | Each process runs as a user (real UID) with a permission level (effective UID; 0 = root). A change while running suggests privilege escalation. |
| **Polling** | The auditor asks the OS for the current state every few seconds instead of being notified by the kernel. |
| **File access** | The OS tracks each process's open file descriptors. `psutil.open_files()` lists them; paths are compared with the watchlist. |
| **Process control** | The OS lets one process send signals to another it has permission over. |
| **Suspension** | `SIGSTOP` freezes a process (state `stopped`); `SIGCONT` resumes it. Reversible. Used by default for Critical alerts. |
| **Termination** | `SIGTERM` asks a process to exit. Optional Critical response. |
| **OS security** | Access control decides what the auditor may read: macOS denies an unprivileged process the open-file list of other users' processes. |

## 4. Architecture and data flow

```
Operating System (process table)
        |
  1. Process Watcher  -- every N seconds -->  process snapshot
        |
        +--> 2. Owner Change Detection ------+
        +--> 3. Sensitive File Detection ----+--> 5. Alert Maker --> 6. Severity Scorer
        +--> 4. Unusual Parent Detection ----+                              |
                                                                            |
              LOW / MEDIUM / HIGH <-----------------------------------------+------> CRITICAL
                      |                                                                 |
          7. Suggested Action Advisor                                    9. Protected Process Check
             (no change is made)                                          |                    |
                      |                                               protected          not protected
                      |                                           (no action, why)    8. Auto-Response
                      |                                                   |          (suspend / terminate)
                      +-------------> 10. Logging + Screen Display <------+--------------------+
                                                |
                                    12. Dashboard + statistics (read-only)

  11. Test Script (tests/) creates controlled activity for the pipeline to detect.
```

A Mermaid version and the step-by-step data flow are in
[docs/architecture.md](docs/architecture.md).

## 5. The eleven modules

| # | Module | File | What it does |
|---|---|---|---|
| 1 | Process Watcher | [src/process_watcher.py](src/process_watcher.py) | Polls all processes through psutil; skips processes that exit, are zombies or deny access |
| 2 | Owner Change Detection | [src/owner_detector.py](src/owner_detector.py) | Stores each PID's original owner and effective UID; flags any later change; handles PID reuse |
| 3 | Sensitive File Detection | [src/sensitive_file_detector.py](src/sensitive_file_detector.py) | Compares open files with the editable watchlist |
| 4 | Unusual Parent Process Detection | [src/parent_detector.py](src/parent_detector.py) | Checks (parent, child) name pairs against configurable rules |
| 5 | Alert Maker | [src/alert_maker.py](src/alert_maker.py) | One alert per process per cycle, listing every triggered rule; suppresses duplicates |
| 6 | Severity Scorer | [src/severity_scorer.py](src/severity_scorer.py) | Assigns exactly one of LOW / MEDIUM / HIGH / CRITICAL |
| 7 | Suggested Action Advisor | [src/action_advisor.py](src/action_advisor.py) | Looks up a recommended next step; never changes a process |
| 8 | Auto-Response Module | [src/auto_response.py](src/auto_response.py) | Critical only: suspend / terminate, then verify the result with the OS |
| 9 | Protected Process List | [src/protected_processes.py](src/protected_processes.py) | Decides whether a process may be acted on |
| 10 | Logging / Screen Display | [src/audit_logger.py](src/audit_logger.py) | Writes `audit.log`, `alerts.jsonl` and the terminal output |
| 11 | Test Script | [tests/](tests/) | Six scenarios, harness, results table |
| + | Dashboard and statistics | [src/dashboard.py](src/dashboard.py) | Read-only local web page |

[src/main.py](src/main.py) connects modules 1-10 (`Auditor.run_cycle`).

## 6. Technologies

- **Python 3** - standard library plus two packages.
- **psutil** - reads the process table (`process_iter`, `username`, `uids`,
  `ppid`, `open_files`, `cpu_percent`, `memory_info`) and controls processes
  (`suspend`, `terminate`).
- **Flask** - serves the one-page local dashboard.

No database, no front-end framework, no kernel module, no eBPF.

## 7. Project structure

```
process-file-security-auditor/
├── README.md
├── requirements.txt
├── .gitignore
├── src/
│   ├── main.py                     # pipeline + command-line entry point
│   ├── config.py                   # loads config/, safe defaults
│   ├── models.py                   # ProcessRecord, Finding, Alert
│   ├── process_watcher.py          # module 1
│   ├── owner_detector.py           # module 2
│   ├── sensitive_file_detector.py  # module 3
│   ├── parent_detector.py          # module 4
│   ├── alert_maker.py              # module 5
│   ├── severity_scorer.py          # module 6
│   ├── action_advisor.py           # module 7
│   ├── auto_response.py            # module 8
│   ├── protected_processes.py      # module 9
│   ├── audit_logger.py             # module 10
│   ├── dashboard.py                # dashboard (Flask)
│   └── test_hooks.py               # controlled test injection (test mode only)
├── config/
│   ├── settings.json               # polling interval, cooldown, response, port
│   ├── sensitive_files.txt         # watchlist
│   ├── parent_rules.json           # unusual parent-child rules
│   └── protected_processes.json    # protected process list
├── templates/dashboard.html
├── static/style.css, dashboard.js
├── tests/
│   ├── test_runner.py              # runs A-F, writes results
│   ├── scenario_a.py ... scenario_f.py
│   ├── harness.py                  # shared test harness
│   ├── fixture_process.py          # the controlled test process
│   └── test_units.py               # module-level checks
├── logs/                           # audit.log, alerts.jsonl, auditor_state.json
├── results/                        # test_results.md / .csv / .json
└── docs/
    ├── architecture.md
    ├── testing.md
    └── macos_setup.md
```

`tests/sandbox/` (dummy files and named test executables) is created
automatically by the test harness.

## 8. Installation (macOS)

```bash
python3 --version
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt
```

More detail: [docs/macos_setup.md](docs/macos_setup.md).

## 9. Configuration

All configuration is in `config/`. A missing or malformed file never crashes
the auditor: it prints a warning and uses safe defaults.

**`settings.json`**

| Key | Default | Meaning |
|---|---|---|
| `polling_interval_seconds` | `2` | Time between polls (also `--interval`) |
| `alert_cooldown_seconds` | `120` | How long an identical alert stays quiet |
| `auto_response_action` | `"suspend"` | `"suspend"` or `"terminate"` for Critical alerts |
| `auto_response_scope` | `"test_only"` | `"test_only"`: only controlled test processes may be acted on. `"all_unprotected"`: any non-protected process |
| `log_dir` | `"logs"` | Where logs are written |
| `dashboard_host` / `dashboard_port` | `127.0.0.1` / `5050` | Dashboard address |

**`sensitive_files.txt`** - one path per line; `~` and project-relative paths
work; a trailing `/` watches a whole directory; ` | low` marks a
low-sensitivity entry. Edits are picked up while the auditor is running.

**`parent_rules.json`** - each rule has `parents` and `children` name
patterns (case-insensitive, `*` wildcard). Several browsers and several shells
are listed; add your own.

**`protected_processes.json`** - `protected_names`, `protected_pids`, and
`test_policy_protected_names` (the Scenario F fixture).

## 10. Running

```bash
python3 -m src.main                 # normal monitoring
python3 -m src.main --test-mode     # for the demo and the test scenarios
python3 -m src.main --interval 3    # different polling interval
python3 -m src.main --cycles 5      # stop after 5 polls
```

`Ctrl+C` stops it cleanly: logs are flushed and closed, the status file is
marked stopped, and any test process the auditor suspended is ended.

```bash
python3 -m src.dashboard            # http://127.0.0.1:5050
python3 -m tests.test_runner        # all six scenarios
```

## 11. Severity rules

| Triggered rule(s) | Severity | Response |
|---|---|---|
| Watched file tagged `low` | **LOW** | Suggestion: review when convenient |
| Unusual parent process alone | **MEDIUM** | Suggestion: inspect process and parent |
| Sensitive file alone | **HIGH** | Suggestion: investigate what was accessed |
| Owner / permission change alone | **HIGH** | Suggestion: investigate now |
| Several rules, not the Critical pair | highest individual level | Suggestion |
| **Owner change + sensitive-file access** | **CRITICAL** | Protected check, then suspend / terminate |

How to say it in one sentence: *each rule has a base level, the alert takes
the highest one, and owner change together with sensitive-file access is
escalated to Critical.* Low, Medium and High alerts never change a process.

## 12. Protected-process mechanism

Before any automatic action, the Auto-Response Module asks the Protected
Process List. A process is protected if:

- its **name** is listed (`launchd`, `WindowServer`, `loginwindow`, `Finder`, ...),
- its **PID** is listed (0 and 1 are always protected),
- its name is in the **testing policy** list (Scenario F fixture), or
- it is **the auditor itself or one of its parents** (your shell and terminal).

Names are the main mechanism because PIDs change on every boot. The check is
done when the Critical alert arrives and again on the live process immediately
before `suspend()` / `terminate()`. If protected: no action, and the alert is
logged with `Protected: YES` and the reason.

A second safety layer is the **scope policy**: with the default
`auto_response_scope: "test_only"`, only processes started by this project's
test framework can be suspended. A Critical alert on any other process is
logged as "automatic response withheld" for the user to investigate.

## 13. Logging

| File | Content |
|---|---|
| `logs/audit.log` | Human-readable audit trail, plus start / stop events |
| `logs/alerts.jsonl` | The same alerts, one JSON object per line |
| `logs/auditor_state.json` | Current status and process table (for the dashboard) |

Every alert records: timestamp, PID, process name and owner, parent, rule(s),
reason(s), severity, suggested action or automatic action, result, and the
protected-process decision for Critical alerts.

## 14. Expected output

```
[ALERT]
  Alert ID: 20261005-121418-36757-0001
  Time: 2026-10-05 12:14:26
  PID: 36769
  Process: python3.10 (owner: chaitanyadatta)
  Parent: python3.10 (PID 36766)
  Rule(s): SENSITIVE_FILE
  Reason: Sensitive file open: .../tests/sandbox/sensitive/fake_ssh_private_key.txt (watchlist entry '...', high sensitivity)
  Severity: HIGH - Access to a sensitive file on its own
  Suggested Action: Investigate now: check what the process has read or changed. Check why this process has the watched file open and whether it should have access.
  Action: Suggested action shown (no change made to the process)

[CRITICAL]
  ...
  Rule(s): OWNER_CHANGE + SENSITIVE_FILE
  Severity: CRITICAL - Owner change combined with sensitive-file access in the same process
  Protected: NO (not on the protected process list)
  Action: Process suspended
  Result: Success (verified: process state is 'stopped')

[CRITICAL]
  ...
  Process: psa_protected_fixture (owner: root)
  Protected: YES ('psa_protected_fixture' is on the protected process list (testing policy))
  Action: NONE
  Result: Automatic response blocked by protected-process policy: ...
```

## 15. Dashboard

One page at <http://127.0.0.1:5050>, refreshed every 2 seconds:

- auditor status (RUNNING / STOPPED) and TEST MODE tag,
- cards: processes monitored, total / low / medium / high / critical alerts,
- system information: polling interval, logging status, protected-process safety,
- alert statistics: one bar per severity,
- recent alerts: time, PID, process, reason, severity, action,
- process table: PID, name, owner, parent PID, CPU, memory (with a filter box).

Every number comes from the auditor's own files; nothing is hard-coded. If
the auditor is not running the page says STOPPED and shows no processes. The
dashboard has no buttons that control processes.

## 16. Testing and results

Six scenarios, one command: `python3 -m tests.test_runner`.

Latest run on the development Mac (macOS 27.0, Python 3.10.11, psutil 7.2.2,
polling interval 2 s), 2026-10-05:

| Scenario | Expected Result | Observed Result | Pass/Fail | Severity | Response | Detection Time | Logging Correct | Protected Safety |
|---|---|---|---|---|---|---|---|---|
| A | No Alert | No Alert | PASS | - | None | n/a (watched 8.1s) | Yes | Yes |
| B | Alert + HIGH + Suggestion | Alert + HIGH + Suggestion | PASS | HIGH | Suggestion | 1.97s | Yes | Yes |
| C | Alert + HIGH + Suggestion | Alert + HIGH + Suggestion | PASS | HIGH | Suggestion | 1.99s | Yes | Yes |
| D | Alert + MEDIUM + Suggestion | Alert + MEDIUM + Suggestion | PASS | MEDIUM | Suggestion | 1.90s | Yes | Yes |
| E | CRITICAL + Auto-response (suspend) | CRITICAL + Suspended (auto) | PASS | CRITICAL | Suspended (auto) | 2.00s | Yes | Yes |
| F | CRITICAL + No action (protected) + reason logged | CRITICAL + None (protected) | PASS | CRITICAL | None (protected) | 1.99s | Yes | Yes |

These values are measured, and they change slightly on every run; the current
ones are always in `results/test_results.md`. The detection times are near
2 s because the tests trigger the activity right after a poll, which is the
worst case for a 2 s polling interval.

**Simulated input.** In scenarios C, E and F the *owner change* is simulated
through a clearly separated test hook, because an unprivileged macOS process
cannot change its owner and the project does not perform real privilege
escalation. Detection, scoring, response and logging are the production code,
and the alerts are labelled as simulated. Full explanation:
[docs/testing.md](docs/testing.md).

Module-level checks (15 tests, no auditor needed):
`python3 -m unittest tests.test_units -v`.

## 17. Troubleshooting

| Symptom | Fix |
|---|---|
| `No module named 'psutil'` | `source .venv/bin/activate` and reinstall requirements |
| `No module named src` | Run commands from the project folder |
| "An auditor is already running" | Stop the other one with `Ctrl+C` |
| Dashboard port in use | `python3 -m src.dashboard --port 5051` |
| Dashboard shows STOPPED | Start the auditor in another terminal |
| Test runner refuses to start | Restart the auditor with `--test-mode` |

## 18. macOS limitations

- **Open files of other users' processes are not readable** without root
  (about a third of processes on the development Mac). They are skipped, so
  sensitive-file detection effectively covers the current user's processes.
  Owner-change and unusual-parent detection cover all processes.
- **Port 5000** belongs to AirPlay Receiver, so the dashboard uses 5050.
- **A real owner change cannot be produced** by an unprivileged test, hence
  the simulated input in scenarios C, E and F.
- **Named test processes** rely on copying the Python interpreter; framework
  Python builds may not support this (see [docs/testing.md](docs/testing.md)).

## 19. Safety considerations

- The auditor never opens, reads or modifies a watched file; it compares paths.
- Low, Medium and High alerts never change a process.
- Automatic action needs: Critical severity + not protected + within the
  scope policy + same PID and creation time as the alert.
- Default response is suspend (reversible); default scope is test processes only.
- No `sudo`, `killall`, `pkill`, `kill -9`, `chmod`, `chown` or `rm -rf` is used.
- The tests touch only dummy files and their own test processes, and clean up.

## 20. Known limitations

- **Polling gap.** Activity shorter than one polling interval (a file opened
  and closed between two polls, a very short-lived process) can be missed, and
  detection takes up to one interval. A shorter interval detects faster but
  uses more CPU.
- **Path-based file detection.** Only files that are open at the moment of a
  poll are seen; reads through other means are not.
- **Name-based rules.** Parent rules and the protected list match process
  names, which a malicious program could imitate.
- **Heuristics, not proof.** An alert means "unusual", not "attack"; legitimate
  software can trigger a rule (for example a service that drops privileges).
- **Baseline starts at first sight.** A process that changed owner before the
  auditor started is recorded with its current owner.

### Compared with OSSEC and Falco

Falco receives events from the kernel (eBPF / kernel module), so it sees every
system call as it happens; OSSEC combines log analysis, file-integrity checks
and active response across many hosts. This project uses the same idea -
observe, apply rules, rate, respond, log - but in user space with polling,
which is far simpler and portable at the cost of the polling gap above.

## 21. Future improvements

- Optional matplotlib timeline of alerts from `alerts.jsonl`.
- Per-entry severity levels beyond `low` / `high` in the watchlist.
- A user-approved "resume" command for suspended processes.
- Event-based monitoring (Endpoint Security on macOS, eBPF on Linux) to close
  the polling gap.
- Learning normal parent-child pairs automatically instead of fixed rules.
