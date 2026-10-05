"""Shared test harness for scenarios A-F.

The harness plays the role of the "Test Script" module in the design. It:

  * prepares a sandbox of harmless dummy files (tests/sandbox/),
  * makes sure an auditor is running in --test-mode (it uses the one you
    already started, or starts its own and stops it afterwards),
  * starts controlled test processes (tests/fixture_process.py),
  * watches the auditor's real log files for the resulting alerts,
  * independently checks the real state of the test process with psutil,
  * builds the results table from what was OBSERVED - nothing is hard-coded.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import queue
import shutil
import signal
import subprocess
import sys
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, List, Optional

import psutil

from src import config
from src.audit_logger import read_alerts, read_state
from src.main import is_auditor_running

FIXTURE_SCRIPT = Path(__file__).resolve().parent / "fixture_process.py"
SENSITIVE_DIR = config.SANDBOX_DIR / "sensitive"
NORMAL_DIR = config.SANDBOX_DIR / "normal"
BIN_DIR = config.SANDBOX_DIR / "bin"
# Listed in config/suspicious_locations.txt for scenario G.
UNUSUAL_LOCATION_DIR = config.SANDBOX_DIR / "unusual_location"

SENSITIVE_TEST_FILE = SENSITIVE_DIR / "fake_ssh_private_key.txt"
NORMAL_TEST_FILE = NORMAL_DIR / "normal_notes.txt"

# Process names used by the named fixtures. They must match
# config/parent_rules.json and config/protected_processes.json.
FAKE_BROWSER_NAME = "psa_fake_browser"
PROTECTED_FIXTURE_NAME = "psa_protected_fixture"

REQUIRED_LOG_FIELDS = ["alert_id", "timestamp", "time", "pid", "process_name",
                       "rules", "reasons", "severity", "action_taken", "result"]


class HarnessError(RuntimeError):
    """The test environment could not be set up (not a detection failure)."""


@dataclass
class ScenarioResult:
    scenario: str
    description: str
    expected: str
    observed: str = "Not run"
    passed: bool = False
    severity: str = "-"
    response: str = "-"
    detection_time_s: Optional[float] = None
    response_time_s: Optional[float] = None
    observation_window_s: Optional[float] = None
    logging_correct: bool = False
    protected_safety: bool = False
    simulated_input: bool = False
    checks: Dict[str, bool] = field(default_factory=dict)
    notes: str = ""


class Fixture:
    """A running controlled test process."""

    def __init__(self, popen: subprocess.Popen) -> None:
        self.popen = popen
        self._events = _start_reader(popen)
        ready = _wait_event(self._events, "ready")
        self.pid: int = popen.pid
        self.child_pid: Optional[int] = ready.get("child_pid")
        self.spawn_time: Optional[float] = ready.get("spawn_time")
        self.ready_time: float = float(ready.get("time", time.time()))
        self.create_time: float = psutil.Process(self.pid).create_time()

    def open_file(self, path: Path) -> float:
        """Ask the process to open *path*; returns the time it did so."""
        self.popen.stdin.write(f"open {path}\n")
        self.popen.stdin.flush()
        return float(_wait_event(self._events, "opened")["time"])

    def spawn_burst(self, count: int) -> float:
        """Ask the process to start *count* sleeping children; returns when it finished."""
        self.popen.stdin.write(f"burst {count}\n")
        self.popen.stdin.flush()
        return float(_wait_event(self._events, "burst")["time"])

    def burn_cpu(self, seconds: float) -> float:
        """Ask the process to keep one CPU core busy; returns when it started."""
        self.popen.stdin.write(f"cpu {seconds}\n")
        self.popen.stdin.flush()
        return float(_wait_event(self._events, "burning")["time"])

    def state(self) -> str:
        """Real OS state of the process: 'running', 'stopped', 'gone', ..."""
        return process_state(self.pid)

    def stop(self) -> None:
        if self.popen.poll() is None:
            self.popen.terminate()
            try:
                # A suspended process cannot react to SIGTERM until resumed.
                psutil.Process(self.pid).resume()
            except psutil.Error:
                pass
            try:
                self.popen.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.popen.kill()
                self.popen.wait(timeout=3)
        for stream in (self.popen.stdin, self.popen.stdout):
            try:
                stream.close()
            except OSError:
                pass


def process_state(pid: int) -> str:
    try:
        status = psutil.Process(pid).status()
    except psutil.NoSuchProcess:
        return "gone"
    except psutil.Error:
        return "unknown"
    return "gone" if status == psutil.STATUS_ZOMBIE else status


def _start_reader(popen: subprocess.Popen) -> "queue.Queue[dict]":
    """Collect the JSON event lines of a test process on a background thread."""
    events: "queue.Queue[dict]" = queue.Queue()

    def pump() -> None:
        try:
            for line in popen.stdout:
                try:
                    events.put(json.loads(line))
                except json.JSONDecodeError:
                    continue
        except (OSError, ValueError):
            pass

    threading.Thread(target=pump, daemon=True).start()
    return events


def _wait_event(events: "queue.Queue[dict]", expected: str, timeout: float = 10.0) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            event = events.get(timeout=0.2)
        except queue.Empty:
            continue
        if event.get("event") == expected:
            return event
    raise HarnessError(f"test process did not report '{expected}'")


class Harness:
    def __init__(self) -> None:
        self.settings = config.load_settings()
        self.fixtures: List[Fixture] = []
        self._auditor: Optional[subprocess.Popen] = None
        self._auditor_output = None
        self.started_own_auditor = False
        self.session_id = ""
        self.interval = self.settings.polling_interval_seconds

    # ------------------------------------------------------------- lifecycle
    def __enter__(self) -> "Harness":
        self._prepare_sandbox()
        self._ensure_auditor()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.cleanup_fixtures()
        self._clear_injection()
        self._stop_auditor()

    def _prepare_sandbox(self) -> None:
        for directory in (SENSITIVE_DIR, NORMAL_DIR, BIN_DIR, UNUSUAL_LOCATION_DIR):
            directory.mkdir(parents=True, exist_ok=True)
        dummy = {
            SENSITIVE_TEST_FILE: "DUMMY TEST FILE - this is NOT a real private key.\n",
            SENSITIVE_DIR / "fake_passwords.txt": "DUMMY TEST FILE - no real passwords here.\n",
            SENSITIVE_DIR / "fake_notes.txt": "DUMMY TEST FILE - low-sensitivity example.\n",
            NORMAL_TEST_FILE: "An ordinary file that is not on the watchlist.\n",
        }
        for path, text in dummy.items():
            if not path.exists():
                path.write_text(text, encoding="utf-8")
        self._clear_injection()

    def _ensure_auditor(self) -> None:
        state = read_state(self.settings.state_file)
        if is_auditor_running(state):
            if not state.get("test_mode"):
                raise HarnessError(
                    "An auditor is running WITHOUT --test-mode. Stop it (Ctrl+C) and start it with:\n"
                    "    python3 -m src.main --test-mode\n"
                    "or stop it and let the test runner start its own auditor."
                )
            print(f"Using the auditor that is already running (PID {state['auditor_pid']}).")
        else:
            config.RESULTS_DIR.mkdir(parents=True, exist_ok=True)
            self._auditor_output = open(config.RESULTS_DIR / "auditor_output_during_tests.log", "w")
            self._auditor = subprocess.Popen(
                [sys.executable, "-m", "src.main", "--test-mode"],
                cwd=str(config.PROJECT_ROOT),
                stdout=self._auditor_output, stderr=subprocess.STDOUT,
            )
            self.started_own_auditor = True
            print(f"Started a temporary auditor in --test-mode (PID {self._auditor.pid}).")

        deadline = time.time() + 20
        while time.time() < deadline:
            state = read_state(self.settings.state_file)
            if is_auditor_running(state) and state.get("cycle", 0) >= 1 and (
                self._auditor is None or state.get("auditor_pid") == self._auditor.pid
            ):
                self.session_id = state["session_id"]
                self.interval = float(state["polling_interval_seconds"])
                return
            if self._auditor is not None and self._auditor.poll() is not None:
                raise HarnessError("The auditor exited during start-up; see "
                                   "results/auditor_output_during_tests.log")
            time.sleep(0.1)
        raise HarnessError("The auditor did not complete a polling cycle within 20 seconds")

    def _stop_auditor(self) -> None:
        if self._auditor is not None and self._auditor.poll() is None:
            self._auditor.send_signal(signal.SIGINT)      # same as Ctrl+C
            try:
                self._auditor.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self._auditor.terminate()
                self._auditor.wait(timeout=5)
        if self._auditor_output is not None:
            self._auditor_output.close()

    @property
    def timeout(self) -> float:
        return max(20.0, 8 * self.interval)

    # ----------------------------------------------------- auditor observers
    def state(self) -> dict:
        return read_state(self.settings.state_file) or {}

    def wait_cycles(self, count: int) -> None:
        """Block until the auditor has finished *count* more polling cycles."""
        start = self.state().get("cycle", 0)
        deadline = time.time() + self.timeout + count * self.interval
        while time.time() < deadline:
            if self.state().get("cycle", 0) >= start + count:
                return
            time.sleep(0.02)
        raise HarnessError("The auditor stopped completing polling cycles")

    def wait_until_baselined(self, pid: int) -> None:
        """Block until the auditor has seen *pid* in a polling cycle."""
        deadline = time.time() + self.timeout
        while time.time() < deadline:
            if any(p["pid"] == pid for p in self.state().get("processes", [])):
                return
            time.sleep(0.05)
        raise HarnessError(f"The auditor never listed test process {pid}")

    def alerts_for(self, pid: int, since: float) -> List[dict]:
        return [a for a in read_alerts(self.settings.alerts_file, self.session_id)
                if a.get("pid") == pid and a.get("timestamp", 0) >= since]

    def wait_for_alert(self, pid: int, since: float,
                       predicate: Callable[[dict], bool] = lambda alert: True,
                       timeout: Optional[float] = None) -> Optional[dict]:
        deadline = time.time() + (timeout or self.timeout)
        while time.time() < deadline:
            for alert in self.alerts_for(pid, since):
                if predicate(alert):
                    return alert
            time.sleep(0.05)
        return None

    # --------------------------------------------------------------- fixtures
    def start_fixture(self, process_name: Optional[str] = None, open_path: Optional[Path] = None,
                      spawn_shell: bool = False, directory: Optional[Path] = None) -> Fixture:
        """Start a controlled test process.

        *process_name* gives the process a specific name in the OS process
        table. macOS takes that name from the executable file, so the harness
        runs the fixture with a private COPY of the Python interpreter that
        has that file name (kept in tests/sandbox/bin/, or in *directory*).
        """
        environment = dict(os.environ)
        interpreter = sys.executable
        if process_name:
            interpreter = str(self._named_interpreter(process_name, directory or BIN_DIR))
            environment["PYTHONHOME"] = sys.base_prefix   # lets the copy find the standard library
            environment.pop("__PYVENV_LAUNCHER__", None)

        command = [interpreter, str(FIXTURE_SCRIPT), config.TEST_PROCESS_MARKER]
        if open_path:
            command += ["--open", str(open_path)]
        if spawn_shell:
            command.append("--spawn-shell")

        popen = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 text=True, env=environment, cwd=str(config.PROJECT_ROOT))
        try:
            fixture = Fixture(popen)
        except Exception:
            popen.kill()
            raise
        self.fixtures.append(fixture)

        if process_name:
            actual = psutil.Process(fixture.pid).name()
            if actual != process_name:
                raise HarnessError(
                    f"The test process should be named '{process_name}' but the OS reports '{actual}'. "
                    "This Python build re-executes itself under another name (framework build); "
                    "see docs/testing.md, section 'Named test processes'."
                )
        return fixture

    @staticmethod
    def _named_interpreter(process_name: str, directory: Path) -> Path:
        source = Path(os.path.realpath(sys.executable))
        target = directory / process_name
        if not target.exists() or target.stat().st_size != source.stat().st_size:
            shutil.copyfile(source, target)
            target.chmod(0o755)
        return target

    def cleanup_fixtures(self) -> None:
        for fixture in self.fixtures:
            fixture.stop()
        self.fixtures.clear()

    # ------------------------------------------- controlled test injection
    def inject_owner_change(self, fixture: Fixture, owner: str = "root", effective_uid: int = 0) -> float:
        """SIMULATE an owner change for one test process (see src/test_hooks.py).

        Writes the request to tests/sandbox/test_injection.json. The auditor
        reads it only in --test-mode and only for marked test processes.
        """
        data = self._read_injection()
        data["owner_overrides"][str(fixture.pid)] = {
            "owner": owner, "effective_uid": effective_uid, "create_time": fixture.create_time,
        }
        self._write_injection(data)
        return time.time()

    @staticmethod
    def _read_injection() -> dict:
        try:
            data = json.loads(config.TEST_INJECTION_FILE.read_text(encoding="utf-8"))
            if isinstance(data.get("owner_overrides"), dict):
                return data
        except (OSError, json.JSONDecodeError, AttributeError):
            pass
        return {"owner_overrides": {}}

    @staticmethod
    def _write_injection(data: dict) -> None:
        config.SANDBOX_DIR.mkdir(parents=True, exist_ok=True)
        temporary = config.TEST_INJECTION_FILE.with_suffix(".tmp")
        temporary.write_text(json.dumps(data), encoding="utf-8")
        os.replace(temporary, config.TEST_INJECTION_FILE)

    def _clear_injection(self) -> None:
        self._write_injection({"owner_overrides": {}})

    # ------------------------------------------------------------ evaluation
    def logging_correct(self, alert: dict) -> bool:
        """The alert must be complete in alerts.jsonl AND present in audit.log."""
        for name in REQUIRED_LOG_FIELDS:
            if alert.get(name) in (None, "", []):
                return False
        if alert["severity"] not in config.SEVERITY_ORDER:
            return False
        if alert["severity"] == config.CRITICAL:
            if not isinstance(alert.get("protected"), bool) or not alert.get("protected_reason"):
                return False
        elif not alert.get("suggested_action"):
            return False
        return self._text_log_contains(f"Alert ID: {alert['alert_id']}", f"PID: {alert['pid']}",
                                       f"Severity: {alert['severity']}")

    def _text_log_contains(self, *fragments: str) -> bool:
        try:
            text = self.settings.audit_log_file.read_text(encoding="utf-8")
        except OSError:
            return False
        marker = text.find(fragments[0])
        if marker < 0:
            return False
        block = text[marker:text.find("\n\n", marker)]
        return all(fragment in block or fragment == fragments[0] for fragment in fragments)

    def pid_absent_from_logs(self, pid: int, since: float) -> bool:
        if self.alerts_for(pid, since):
            return False
        try:
            text = self.settings.audit_log_file.read_text(encoding="utf-8")
        except OSError:
            return True
        return f"  PID: {pid}\n" not in text

    def protected_safety(self, since: float) -> bool:
        """No alert since *since* shows an action against a protected process."""
        for alert in read_alerts(self.settings.alerts_file, self.session_id):
            if alert.get("timestamp", 0) >= since and alert.get("protected") is True \
                    and alert.get("action_code") != "NONE":
                return False
        return True


def describe_response(alert: dict) -> str:
    kind = alert.get("response_type")
    if kind == "SUGGESTED_ACTION":
        return "Suggestion"
    if kind == "AUTO_RESPONSE":
        action = "Suspended" if alert.get("action_code") == "SUSPEND" else "Terminated"
        return f"{action} (auto)"
    if kind == "BLOCKED_PROTECTED":
        return "None (protected)"
    if kind == "WITHHELD":
        return "None (withheld)"
    return "None (failed)"


# --------------------------------------------------------------------------
# Running scenarios and reporting
# --------------------------------------------------------------------------
def _yes(value: bool) -> str:
    return "Yes" if value else "No"


def _time_text(result: ScenarioResult) -> str:
    if result.detection_time_s is not None:
        return f"{result.detection_time_s:.2f}s"
    if result.observation_window_s is not None:
        return f"n/a (watched {result.observation_window_s:.1f}s)"
    return "-"


def table_rows(results: List[ScenarioResult]) -> List[List[str]]:
    header = ["Scenario", "Expected Result", "Observed Result", "Pass/Fail", "Severity",
              "Response", "Detection Time", "Logging Correct", "Protected Safety"]
    rows = [header]
    for r in results:
        rows.append([r.scenario, r.expected, r.observed, "PASS" if r.passed else "FAIL", r.severity,
                     r.response, _time_text(r), _yes(r.logging_correct), _yes(r.protected_safety)])
    return rows


def print_table(results: List[ScenarioResult]) -> None:
    rows = table_rows(results)
    widths = [max(len(row[i]) for row in rows) for i in range(len(rows[0]))]
    for index, row in enumerate(rows):
        print(" | ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)))
        if index == 0:
            print("-+-".join("-" * width for width in widths))


def save_results(results: List[ScenarioResult], harness: Harness) -> None:
    config.RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    rows = table_rows(results)
    run_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    summary = {
        "run_at": run_at,
        "polling_interval_seconds": harness.interval,
        "auditor_session": harness.session_id,
        "auditor_started_by_test_runner": harness.started_own_auditor,
        "passed": sum(r.passed for r in results),
        "total": len(results),
        "results": [asdict(r) for r in results],
    }
    (config.RESULTS_DIR / "test_results.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    with open(config.RESULTS_DIR / "test_results.csv", "w", newline="", encoding="utf-8") as handle:
        csv.writer(handle).writerows(rows)

    lines = [
        "# Test Results - Process & File-Access Security Auditor", "",
        f"- Run at: {run_at}",
        f"- Polling interval: {harness.interval:g} s",
        f"- Auditor session: {harness.session_id}",
        f"- Passed: {summary['passed']} / {summary['total']}", "",
        "| " + " | ".join(rows[0]) + " |",
        "|" + "|".join("---" for _ in rows[0]) + "|",
    ]
    lines += ["| " + " | ".join(row) + " |" for row in rows[1:]]
    lines += ["", "## Details", ""]
    for r in results:
        lines.append(f"### Scenario {r.scenario} - {r.description}")
        if r.response_time_s is not None:
            lines.append(f"- Response time (activity -> action verified): {r.response_time_s:.2f} s")
        if r.simulated_input:
            lines.append("- Input: owner change SIMULATED by controlled test injection (see docs/testing.md)")
        for name, ok in r.checks.items():
            lines.append(f"- [{'x' if ok else ' '}] {name}")
        if r.notes:
            lines.append(f"- Notes: {r.notes}")
        lines.append("")
    lines.append("All values above were measured during this run; nothing is hard-coded.")
    (config.RESULTS_DIR / "test_results.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def run_scenarios(scenarios: List[Callable[[Harness], ScenarioResult]], save: bool = False,
                  argv: Optional[List[str]] = None) -> int:
    """Run the given scenario functions and print the results table."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--hold", type=float, default=0.0,
                        help="keep each scenario's test process alive this many seconds after "
                             "the check (useful to look at the dashboard during a demo)")
    args = parser.parse_args(argv)

    results: List[ScenarioResult] = []
    try:
        with Harness() as harness:
            for scenario in scenarios:
                label = scenario.__module__.split(".")[-1].replace("_", " ").title()
                print(f"\n>>> Running {label} ...", flush=True)
                try:
                    result = scenario(harness)
                except HarnessError as exc:
                    result = ScenarioResult(scenario=label[-1], description=label, expected="-",
                                            observed="Test setup error", notes=str(exc))
                if args.hold > 0:
                    time.sleep(args.hold)
                harness.cleanup_fixtures()
                harness._clear_injection()
                results.append(result)
                print(f"    {'PASS' if result.passed else 'FAIL'}: {result.observed}"
                      + (f"  [{result.notes}]" if result.notes else ""))
            print("\n================ RESULTS ================\n")
            print_table(results)
            if save:
                save_results(results, harness)
                print(f"\nSaved to {config.RESULTS_DIR}/test_results.md, .csv and .json")
    except HarnessError as exc:
        print(f"\nTEST SETUP ERROR: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nInterrupted - test processes were cleaned up.")
        return 130

    passed = sum(r.passed for r in results)
    print(f"\n{passed} / {len(results)} scenario(s) passed.")
    return 0 if passed == len(results) else 1


def finish(result: ScenarioResult) -> ScenarioResult:
    """A scenario passes only if every individual check passed."""
    result.passed = bool(result.checks) and all(result.checks.values())
    failed = [name for name, ok in result.checks.items() if not ok]
    if failed:
        result.notes = (result.notes + " " if result.notes else "") + "Failed check(s): " + "; ".join(failed)
    return result
