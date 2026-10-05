# Testing

## How to run

```bash
python3 -m tests.test_runner          # all six scenarios + results table
python3 -m tests.scenario_b           # one scenario (a, b, c, d, e or f)
python3 -m tests.scenario_e --hold 15 # keep the test process 15 s after the check
python3 -m unittest tests.test_units -v   # module-level checks, no auditor needed
```

The scenarios need an auditor running in **test mode**:

- if one is already running (`python3 -m src.main --test-mode`), it is used,
  so the alerts also appear in its terminal and on the dashboard;
- if none is running, the runner starts a temporary one and stops it at the end
  (its output goes to `results/auditor_output_during_tests.log`);
- if one is running *without* `--test-mode`, the runner stops with a message.

Results are written to `results/test_results.md`, `.csv` and `.json`.

## How a scenario is judged

Nothing is hard-coded. For each scenario the harness (`tests/harness.py`):

1. starts a controlled test process (`tests/fixture_process.py`),
2. makes it perform the activity and notes the time,
3. waits for the alert to appear in the auditor's real `logs/alerts.jsonl`,
4. checks the alert's rule(s), severity and response against what is expected,
5. asks the OS directly (psutil) whether the test process is running or
   stopped - it does not trust the auditor's own claim,
6. checks that the alert is complete in `alerts.jsonl` and present in `audit.log`,
7. checks that no alert shows an action against a protected process.

PASS means every one of those checks passed. The individual checks are listed
per scenario in `results/test_results.md`.

**Detection time** = alert timestamp minus the moment of the activity. The
harness triggers the activity just after a poll, so the measured values are
close to the worst case of one polling interval (about 2 s by default).

## The six scenarios

| | What the test does | Expected |
|---|---|---|
| A | A test process opens an ordinary file and is watched for 3 polling cycles | No alert, nothing logged |
| B | A test process opens the dummy "private key" file on the watchlist | Alert, HIGH, suggestion, process untouched |
| C | The owner of a running test process changes (**simulated input**) | Alert, HIGH, suggestion, process untouched |
| D | A process named `psa_fake_browser` starts a real `/bin/sh` child | Alert on the shell, MEDIUM, suggestion |
| E | Owner change (**simulated input**) + real sensitive-file access | CRITICAL, not protected, process really suspended |
| F | The same combination on a process named `psa_protected_fixture` | CRITICAL, protected, no action, reason logged |

## Production logic vs controlled test injection

This distinction matters, so it is stated exactly.

### What is real in every scenario

- The Process Watcher reads real processes from the real process table.
- All detection, alert, severity, advisor, protected-list, auto-response and
  logging code is the production code - the tests have no separate copy.
- File access is real: the test process really opens the file, and the auditor
  really finds it through `psutil.open_files()`.
- The parent-child relationship in D is real: the shell's PPID really is the
  fake browser's PID.
- The suspension in E is real, and it is verified by reading the process state
  back from the OS (`stopped`).
- All timings are measured.

### What is simulated, and why

**Only one thing: the owner change in scenarios C, E and F.**

On macOS a normal user's process cannot change its owner - `setuid()` requires
root. Reproducing a genuine owner change would mean performing a real
privilege escalation on a personal laptop, which this project deliberately
does not do.

Instead:

1. The test process starts normally. The auditor records its **true** owner as
   the baseline (production code, `src/owner_detector.py`).
2. The harness writes a request to `tests/sandbox/test_injection.json`:
   "report PID *n* (created at time *t*) as owned by `root`, effective UID 0".
3. On the next poll, `src/test_hooks.py` replaces the owner in that one process
   record and marks it `owner_simulated`.
4. Owner Change Detection compares the record with its baseline exactly as it
   would for any process, and raises the finding.

Safeguards on the hook:

- it is only active when the auditor is started with `--test-mode`
  (the terminal and the dashboard show a TEST MODE banner);
- it only applies to a process that carries the test marker
  `--psa-test-process` in its command line **and** matches the PID and
  creation time in the request - a real process can never be affected;
- every alert it leads to is labelled: the reason ends with
  `[SIMULATED by controlled test injection]`, the log entry has a `Note:` line,
  `alerts.jsonl` has `"simulated": true`, and the dashboard shows a
  "simulated input" tag.

So for C, E and F: **the input to the owner detector is simulated; the
detection, scoring, response and logging that follow are real.**

Owner-change detection is additionally checked without any hook in
`tests/test_units.py` (baseline, change, PID reuse, clean-up), and the
detector runs against every real process on the machine all the time.

### Test fixtures that are not simulation

- **`psa_fake_browser` (D)** - a real process with that name. It is listed
  next to the real browsers in `config/parent_rules.json`. Using it avoids
  having to make Safari or Chrome start a shell.
- **`psa_protected_fixture` (F)** - a real process with that name, listed
  under `test_policy_protected_names` in `config/protected_processes.json`.
  It exercises the same protected-list check that guards `launchd` or
  `WindowServer`, without putting a real system process at risk.
- **Sandbox files** - `tests/sandbox/sensitive/*.txt` are dummy text files
  created by the harness. No real key or password file is ever opened.

### Named test processes

macOS takes a process's name from its executable file. To get a process
called `psa_fake_browser`, the harness copies the Python interpreter to
`tests/sandbox/bin/psa_fake_browser` and runs the fixture with that copy
(`PYTHONHOME` tells the copy where the standard library is).

This works with ordinary Python builds (pyenv, Homebrew, system). Some
"framework" builds re-execute themselves under the name `Python`; if that
happens, scenarios D and F report a clear set-up error instead of a wrong
result. Use a pyenv or Homebrew Python for the tests in that case.

## Safety of the tests

- Test processes only read files inside `tests/sandbox/`, and exit on their own
  (lifetime limit, or when the harness closes their input).
- The harness stops every process it started, including the suspended one.
- If the auditor is stopped while a test process is suspended, the auditor
  ends that test process during shutdown.
- No `sudo`, `killall`, `pkill`, `chmod`, `chown` or system-file change is used
  anywhere.
