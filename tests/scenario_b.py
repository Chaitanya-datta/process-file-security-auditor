"""Scenario B - a test process opens a watched (sensitive) test file.

Expected: alert + severity HIGH + suggested action, and the process is NOT touched.
Everything here is real: the process really opens the dummy file and the
auditor finds it through psutil.open_files().
"""

import sys
import time

from src import config
from tests.harness import (Harness, SENSITIVE_TEST_FILE, ScenarioResult, describe_response,
                           finish, run_scenarios)


def run(h: Harness) -> ScenarioResult:
    result = ScenarioResult("B", "Process opens a sensitive file",
                            expected="Alert + HIGH + Suggestion")
    started = time.time()
    fixture = h.start_fixture()
    h.wait_until_baselined(fixture.pid)

    opened_at = fixture.open_file(SENSITIVE_TEST_FILE)      # the suspicious activity
    alert = h.wait_for_alert(fixture.pid, started)
    result.protected_safety = h.protected_safety(started)
    if alert is None:
        result.observed = "No Alert"
        result.checks = {"an alert was raised": False}
        return finish(result)

    result.observed = "Alert + " + alert["severity"] + " + " + describe_response(alert)
    result.severity = alert["severity"]
    result.response = describe_response(alert)
    result.detection_time_s = alert["timestamp"] - opened_at
    result.logging_correct = h.logging_correct(alert)
    result.checks = {
        "the sensitive-file rule (and only that rule) was triggered":
            alert["rules"] == [config.RULE_SENSITIVE_FILE],
        "the alert names the watched file":
            str(SENSITIVE_TEST_FILE.resolve()) in alert["sensitive_paths"],
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
