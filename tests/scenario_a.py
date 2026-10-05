"""Scenario A - a normal process opens a normal file. Expected: NO alert."""

import sys
import time

from tests.harness import (Harness, NORMAL_TEST_FILE, ScenarioResult, finish, run_scenarios)

CYCLES_TO_WATCH = 3


def run(h: Harness) -> ScenarioResult:
    result = ScenarioResult("A", "Normal process opens a normal file", expected="No Alert")
    started = time.time()
    fixture = h.start_fixture(open_path=NORMAL_TEST_FILE)

    # Let the auditor look at the process for several full polling cycles.
    h.wait_until_baselined(fixture.pid)
    h.wait_cycles(CYCLES_TO_WATCH)
    result.observation_window_s = time.time() - started

    alerts = h.alerts_for(fixture.pid, started)
    result.observed = "No Alert" if not alerts else f"{len(alerts)} alert(s) raised"
    result.response = "None"
    result.logging_correct = h.pid_absent_from_logs(fixture.pid, started)
    result.protected_safety = h.protected_safety(started)
    result.checks = {
        "no alert was raised for the normal process": not alerts,
        "nothing was written to the logs for this process": result.logging_correct,
        "the process was left running": fixture.state() not in ("stopped", "gone"),
        "no protected process was acted on": result.protected_safety,
    }
    return finish(result)


if __name__ == "__main__":
    sys.exit(run_scenarios([run]))
