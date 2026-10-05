"""Test Lab support for the dashboard.

Lets the dashboard start ONE of the project's own built-in test scenarios and
show its result. This is deliberately narrow:

  * Only the fixed scenarios listed in SCENARIOS can be started. The letter in
    the request is looked up in that table; nothing from the request is ever
    put on a command line.
  * The scenario is started as `python -m tests.scenario_x` with an argument
    list (no shell), exactly as it would be from the terminal.
  * One scenario at a time, with a time limit.
  * It only runs while an auditor is running in --test-mode, so the alerts it
    produces appear in that auditor's log and on the dashboard.

The scenarios themselves only use the controlled test processes and dummy
files described in docs/testing.md.
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional

from . import config

LAB_RESULTS_DIR = config.RESULTS_DIR / "test_lab"
FULL_RUN_RESULTS_FILE = config.RESULTS_DIR / "test_results.json"
TIME_LIMIT_SECONDS = 180

# letter -> (what the scenario does, expected result)
SCENARIOS: Dict[str, tuple] = {
    "A": ("Normal process opens a normal file", "No alert"),
    "B": ("Process opens a sensitive file", "Alert + HIGH + suggestion"),
    "C": ("Process owner changes while running (simulated input)", "Alert + HIGH + suggestion"),
    "D": ("Process started by an unusual parent", "Alert + MEDIUM + suggestion"),
    "E": ("Owner change + sensitive file", "CRITICAL + controlled auto-response"),
    "F": ("Critical event on a protected process", "CRITICAL + no automatic action + reason logged"),
    "G": ("Program runs from a suspicious location", "Alert + MEDIUM + suggestion"),
    "H": ("Parent creates a burst of child processes", "Alert + MEDIUM + suggestion"),
    "I": ("Sustained high CPU use", "Alert + MEDIUM + suggestion"),
    "J": ("Two findings on one process (correlation + de-duplication)", "MEDIUM, then HIGH; no repeats"),
}

_lock = threading.Lock()
_running: Optional[str] = None       # letter of the scenario running now, if any
_errors: Dict[str, str] = {}         # letter -> message, when a run could not produce a result


def running_scenario() -> Optional[str]:
    return _running


def start(letter: str) -> None:
    """Start scenario *letter* in the background. Raises ValueError / RuntimeError."""
    global _running
    if letter not in SCENARIOS:
        raise ValueError("Unknown scenario")
    with _lock:
        if _running is not None:
            raise RuntimeError(f"Scenario {_running} is still running")
        _running = letter
    threading.Thread(target=_run, args=(letter,), daemon=True).start()


def _run(letter: str) -> None:
    global _running
    result_file = LAB_RESULTS_DIR / f"{letter}.json"
    try:
        LAB_RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        result_file.unlink(missing_ok=True)
        _errors.pop(letter, None)
        process = subprocess.Popen(
            [sys.executable, "-m", f"tests.scenario_{letter.lower()}", "--json", str(result_file)],
            cwd=str(config.PROJECT_ROOT),
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            process.wait(timeout=TIME_LIMIT_SECONDS)
        except subprocess.TimeoutExpired:
            process.terminate()
            process.wait(timeout=10)
            _errors[letter] = f"Stopped after the {TIME_LIMIT_SECONDS} s time limit"
        if not result_file.exists() and letter not in _errors:
            _errors[letter] = "The scenario ended without a result (is the auditor running in --test-mode?)"
    except (OSError, subprocess.SubprocessError) as exc:
        _errors[letter] = f"Could not run the scenario: {exc}"
    finally:
        with _lock:
            _running = None


def _read_json(path: Path) -> Optional[object]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _summary(result: dict, when: str, source: str) -> dict:
    return {
        "passed": bool(result.get("passed")),
        "observed": result.get("observed", ""),
        "severity": result.get("severity", "-"),
        "response": result.get("response", "-"),
        "detection_time_s": result.get("detection_time_s"),
        "simulated_input": bool(result.get("simulated_input")),
        "checks": result.get("checks", {}),
        "notes": result.get("notes", ""),
        "when": when,
        "source": source,
    }


def overview() -> dict:
    """Status and latest result of every scenario, from the result files."""
    full_run = _read_json(FULL_RUN_RESULTS_FILE)
    full_results = {}
    if isinstance(full_run, dict):
        full_results = {r.get("scenario"): r for r in full_run.get("results", []) if isinstance(r, dict)}

    scenarios: List[dict] = []
    for letter, (description, expected) in SCENARIOS.items():
        entry = {"letter": letter, "description": description, "expected": expected,
                 "status": "running" if _running == letter else "idle",
                 "error": _errors.get(letter, ""), "result": None}
        lab_file = LAB_RESULTS_DIR / f"{letter}.json"
        lab = _read_json(lab_file)
        if isinstance(lab, list) and lab and isinstance(lab[0], dict):
            when = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(lab_file.stat().st_mtime))
            entry["result"] = _summary(lab[0], when, "Test Lab")
        elif letter in full_results:
            entry["result"] = _summary(full_results[letter], str(full_run.get("run_at", "")), "terminal test run")
        scenarios.append(entry)

    return {
        "running": _running,
        "scenarios": scenarios,
        "last_full_run": {"run_at": full_run.get("run_at"), "passed": full_run.get("passed"),
                          "total": full_run.get("total")} if isinstance(full_run, dict) else None,
    }
