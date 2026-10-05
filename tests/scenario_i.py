"""Scenario I - a process keeps the CPU busy for a sustained period.

Expected: alert + severity MEDIUM + suggested action; the process is NOT touched,
and the alert appears only after the required number of consecutive polls.

Everything here is real: the test process really keeps one CPU core busy
(for a limited time, then it stops by itself) and the auditor reads its CPU
percentage from the OS through psutil.

The memory threshold uses the same code path; it is checked in
tests/test_units.py because filling 80% of the machine's RAM in a test would
not be safe.
"""

import sys
import time

from src import config
from tests.harness import Harness, ScenarioResult, describe_response, finish, run_scenarios

EXTRA_POLLS = 6         # how much longer than strictly needed the CPU stays busy


def run(h: Harness) -> ScenarioResult:
    result = ScenarioResult("I", "Sustained high CPU use",
                            expected="Alert + MEDIUM + Suggestion")
    required = h.settings.resource_sustained_cycles
    burn_seconds = (required + EXTRA_POLLS) * h.interval
    started = time.time()
    fixture = h.start_fixture()
    h.wait_until_baselined(fixture.pid)

    burning_since = fixture.burn_cpu(burn_seconds)                      # the unusual activity
    alert = h.wait_for_alert(fixture.pid, started, timeout=burn_seconds + h.timeout)
    result.protected_safety = h.protected_safety(started)
    if alert is None:
        result.observed = "No Alert"
        result.checks = {"an alert was raised": False}
        return finish(result)

    details = alert["findings"][0]["details"]
    result.observed = "Alert + " + alert["severity"] + " + " + describe_response(alert)
    result.severity = alert["severity"]
    result.response = describe_response(alert)
    result.detection_time_s = alert["timestamp"] - burning_since
    result.logging_correct = h.logging_correct(alert)
    result.notes = f"needs {required} consecutive polls above the threshold by design"
    result.checks = {
        "the resource-anomaly rule (and only that rule) was triggered":
            alert["rules"] == [config.RULE_RESOURCE_ANOMALY],
        "the alert records the measured CPU % and the threshold":
            details.get("cpu_percent", 0) > details.get("cpu_threshold_percent", 1e9)
            and details.get("cpu_threshold_percent") == h.settings.resource_cpu_threshold_percent
            and "cpu" in details.get("exceeded", []),
        "it was not raised from a single reading (waited for the required polls)":
            details.get("consecutive_cycles") == required
            and result.detection_time_s >= (required - 1) * h.interval * 0.9,
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
