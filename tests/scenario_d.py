"""Scenario D - a process is started by an unusual parent.

Expected: alert + severity MEDIUM + suggested action, and the process is NOT touched.

A test process named 'psa_fake_browser' (listed with the browsers in
config/parent_rules.json) starts a real /bin/sh child that only sleeps. The
parent-child relationship is real: the auditor reads it from the PPID.
"""

import sys
import time

from src import config
from tests.harness import (FAKE_BROWSER_NAME, Harness, ScenarioResult, describe_response,
                           finish, process_state, run_scenarios)


def run(h: Harness) -> ScenarioResult:
    result = ScenarioResult("D", "Process started by an unusual parent",
                            expected="Alert + MEDIUM + Suggestion")
    started = time.time()
    parent = h.start_fixture(process_name=FAKE_BROWSER_NAME, spawn_shell=True)
    child_pid = parent.child_pid                             # the shell is the flagged process

    alert = h.wait_for_alert(child_pid, started)
    result.protected_safety = h.protected_safety(started)
    if alert is None:
        result.observed = "No Alert"
        result.checks = {"an alert was raised": False}
        return finish(result)

    details = alert["findings"][0]["details"]
    result.observed = "Alert + " + alert["severity"] + " + " + describe_response(alert)
    result.severity = alert["severity"]
    result.response = describe_response(alert)
    result.detection_time_s = alert["timestamp"] - parent.spawn_time
    result.logging_correct = h.logging_correct(alert)
    result.checks = {
        "the unusual-parent rule (and only that rule) was triggered":
            alert["rules"] == [config.RULE_UNUSUAL_PARENT],
        "the alert names the real parent (PID and name)":
            details.get("parent_pid") == parent.pid and details.get("parent_name") == FAKE_BROWSER_NAME,
        "severity is MEDIUM": alert["severity"] == config.MEDIUM,
        "a suggested action was given":
            alert["response_type"] == "SUGGESTED_ACTION" and bool(alert["suggested_action"]),
        "no automatic action: parent and child are still running":
            parent.state() not in ("stopped", "gone") and process_state(child_pid) not in ("stopped", "gone"),
        "the log entry is complete": result.logging_correct,
        "no protected process was acted on": result.protected_safety,
    }
    return finish(result)


if __name__ == "__main__":
    sys.exit(run_scenarios([run]))
