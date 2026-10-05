"""Scenario H - one parent creates a burst of child processes.

Expected: alert on the PARENT + severity MEDIUM + suggested action; nothing is touched.

Everything here is real: the test process really starts the children (each
one is just `/bin/sleep`), and the auditor counts them from the PPID and
creation time of the processes it sees.
"""

import sys
import time

from src import config
from tests.harness import Harness, ScenarioResult, describe_response, finish, run_scenarios

EXTRA_CHILDREN = 2      # start a few more than the threshold


def run(h: Harness) -> ScenarioResult:
    result = ScenarioResult("H", "Parent creates a burst of child processes",
                            expected="Alert + MEDIUM + Suggestion")
    threshold = h.settings.process_burst_threshold
    started = time.time()
    fixture = h.start_fixture()
    h.wait_until_baselined(fixture.pid)

    burst_done_at = fixture.spawn_burst(threshold + EXTRA_CHILDREN)     # the suspicious activity
    alert = h.wait_for_alert(fixture.pid, started)
    result.protected_safety = h.protected_safety(started)
    if alert is None:
        result.observed = "No Alert"
        result.checks = {"an alert was raised": False}
        return finish(result)

    details = alert["findings"][0]["details"]
    result.observed = "Alert + " + alert["severity"] + " + " + describe_response(alert)
    result.severity = alert["severity"]
    result.response = describe_response(alert)
    result.detection_time_s = alert["timestamp"] - burst_done_at
    result.logging_correct = h.logging_correct(alert)
    result.checks = {
        "the process-burst rule (and only that rule) was triggered":
            alert["rules"] == [config.RULE_PROCESS_BURST],
        "the alert is raised on the parent process": details.get("parent_pid") == fixture.pid,
        "the alert records the real child count, threshold and window":
            details.get("child_count") == threshold + EXTRA_CHILDREN
            and details.get("threshold") == threshold
            and details.get("window_seconds") == h.settings.process_burst_window_seconds,
        "severity is MEDIUM": alert["severity"] == config.MEDIUM,
        "a suggested action was given":
            alert["response_type"] == "SUGGESTED_ACTION" and bool(alert["suggested_action"]),
        "no automatic action: the parent is still running": fixture.state() not in ("stopped", "gone"),
        "the burst is reported once, not on every poll": _reported_once(h, fixture.pid, started),
        "the log entry is complete": result.logging_correct,
        "no protected process was acted on": result.protected_safety,
    }
    return finish(result)


def _reported_once(h: Harness, pid: int, since: float) -> bool:
    h.wait_cycles(2)
    return len(h.alerts_for(pid, since)) == 1


if __name__ == "__main__":
    sys.exit(run_scenarios([run]))
