# macOS Setup

Everything runs as your normal user. No `sudo` and no change to macOS
security settings is needed.

## 1. One-time setup

Open Terminal (or the VS Code terminal) and go to the project folder:

```bash
cd ~/Desktop/process-file-security-auditor

python3 --version                      # 3.9 or newer

python3 -m venv .venv
source .venv/bin/activate

python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt
```

## 2. Every new terminal window

```bash
cd ~/Desktop/process-file-security-auditor
source .venv/bin/activate
```

## 3. Commands

| What | Command |
|---|---|
| Start the auditor | `python3 -m src.main` |
| Start the auditor for the demo / tests | `python3 -m src.main --test-mode` |
| Start the dashboard | `python3 -m src.dashboard` then open <http://127.0.0.1:5050> |
| Run all six tests | `python3 -m tests.test_runner` |
| Run one scenario | `python3 -m tests.scenario_b` |
| Module-level checks | `python3 -m unittest tests.test_units -v` |
| Stop the auditor or dashboard | `Ctrl+C` in its terminal |

Always run the commands from the project folder (they use `python3 -m ...`).

## 4. macOS behaviour you will see

**Port 5000 is taken by AirPlay Receiver.** macOS uses port 5000 for the
AirPlay Receiver in Control Center, so the dashboard uses **5050**. To use a
different port: `python3 -m src.dashboard --port 5051`, or change
`dashboard_port` in `config/settings.json`.

**Open files of other users' processes cannot be read.** Without root, macOS
only lets you list the open files (and command line, memory) of processes you
own. For system processes psutil raises `AccessDenied`; the auditor notes it
and carries on. In practice this means sensitive-file detection covers your
own user's processes, which is where the test scenarios run. Name, owner,
UIDs and parent PID are readable for every process, so owner-change and
unusual-parent detection cover all processes.

**No permission prompt is expected.** The auditor does not read the content
of any watched file - it only compares paths - so it needs no Full Disk
Access. If macOS ever shows a prompt for Terminal or VS Code, it is safe to
decline; the auditor keeps working with what it is allowed to read.

**Running with `sudo` is not required and not recommended** for the demo. It
would let the auditor read more processes' open files, but the project is
designed and tested to run unprivileged.

## 5. Troubleshooting

| Symptom | Fix |
|---|---|
| `ModuleNotFoundError: No module named 'psutil'` | Activate the venv: `source .venv/bin/activate`, then reinstall requirements |
| `No module named src` | You are not in the project folder; `cd` into it |
| "An auditor is already running" | Another terminal is running it; stop that one with `Ctrl+C` |
| Dashboard shows STOPPED | Start the auditor in another terminal |
| "Could not start the dashboard on port ..." | Use `--port 5051` |
| Test runner: "running WITHOUT --test-mode" | Restart the auditor with `--test-mode` |
| Scenario D / F: "should be named ... but the OS reports 'Python'" | Framework Python build; use a pyenv / Homebrew Python (see `docs/testing.md`) |
