"""Scenario G - a program runs from a suspicious location.

Expected: alert + severity MEDIUM + suggested action, and the process is NOT touched.

Everything here is real: the test process's executable file really is inside
tests/sandbox/unusual_location/ (listed in config/suspicious_locations.txt)
and the auditor reads that path from the OS through psutil.
"""

import sys
import time

from src import config
from tests.harness import (Harness, ScenarioResult, UNUSUAL_LOCATION_DIR, describe_response,
                           finish, run_scenarios)

PROCESS_NAME = "psa_unusual_location_app"


def run(h: Harness) -> ScenarioResult:
    result = ScenarioResult("G", "Program runs from a suspicious location",
                            expected="Alert + MEDIUM + Suggestion")
    started = time.time()
    fixture = h.start_fixture(process_name=PROCESS_NAME, directory=UNUSUAL_LOCATION_DIR)

    alert = h.wait_for_alert(fixture.pid, started)
    result.protected_safety = h.protected_safety(started)
    if alert is None:
        result.observed = "No Alert"
        result.checks = {"an alert was raised": False}
        return finish(result)

    details = alert["findings"][0]["details"]
    expected_path = str((UNUSUAL_LOCATION_DIR / PROCESS_NAME).resolve())
    result.observed = "Alert + " + alert["severity"] + " + " + describe_response(alert)
    result.severity = alert["severity"]
    result.response = describe_response(alert)
    result.detection_time_s = alert["timestamp"] - fixture.ready_time
    result.logging_correct = h.logging_correct(alert)
    result.checks = {
        "the suspicious-location rule (and only that rule) was triggered":
            alert["rules"] == [config.RULE_SUSPICIOUS_LOCATION],
        "the alert records the real executable path": details.get("executable") == expected_path,
        "the alert names the configured location that matched":
            details.get("matched_location") == "tests/sandbox/unusual_location",
        "severity is MEDIUM": alert["severity"] == config.MEDIUM,
        "a suggested action was given":
            alert["response_type"] == "SUGGESTED_ACTION" and bool(alert["suggested_action"]),
        "no automatic action: the process is still running": fixture.state() not in ("stopped", "gone"),
        "the log entry is complete": result.logging_correct,
        "no protected process was acted on": result.protected_safety,
    }
    return finish(result)


if __name__ == "__main__":
    sys.exit(run_scenarios([run]))
