"""Scenario C - the owner of a process changes while it is running.

Expected: alert + severity HIGH + suggested action, and the process is NOT touched.

CONTROLLED TEST INJECTION: an ordinary macOS user cannot really change a
process's owner (that needs root), so the owner change is SIMULATED through
src/test_hooks.py. The Owner Change Detection logic that catches it is the
real production code: it recorded the true owner as the baseline first.
"""

import sys
import time

from src import config
from tests.harness import Harness, ScenarioResult, describe_response, finish, run_scenarios


def run(h: Harness) -> ScenarioResult:
    result = ScenarioResult("C", "Process owner changes while running (simulated input)",
                            expected="Alert + HIGH + Suggestion", simulated_input=True)
    started = time.time()
    fixture = h.start_fixture()
    h.wait_until_baselined(fixture.pid)      # the real owner is now the stored baseline
    h.wait_cycles(1)

    injected_at = h.inject_owner_change(fixture)            # the suspicious activity
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
    result.detection_time_s = alert["timestamp"] - injected_at
    result.logging_correct = h.logging_correct(alert)
    result.checks = {
        "the owner-change rule (and only that rule) was triggered":
            alert["rules"] == [config.RULE_OWNER_CHANGE],
        "the alert records the previous and the new owner":
            details.get("previous_owner") not in (None, "root") and details.get("current_owner") == "root",
        "the alert is labelled as simulated": alert["simulated"] is True,
        "severity is HIGH": alert["severity"] == config.HIGH,
        "a suggested action was given":
            alert["response_type"] == "SUGGESTED_ACTION" and bool(alert["suggested_action"]),
        "no automatic action: the process is still running": fixture.state() not in ("stopped", "gone"),
        "the log entry is complete": result.logging_correct,
        "no protected process was acted on": result.protected_safety,
    }
    return finish(result)


if __name__ == "__main__":
    sys.exit(run_scenarios([run]))
