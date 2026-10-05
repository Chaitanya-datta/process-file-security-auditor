"""Scenario J - event correlation and alert de-duplication, end to end.

A test process runs from a suspicious location (first alert, MEDIUM) and then
creates a burst of child processes. Expected:

  * the second alert lists BOTH rules for the same process and is rated HIGH
    (two medium-level findings on one process),
  * HIGH is still advisory: a suggestion only, the process is NOT touched,
  * while both conditions continue, no further alerts are raised (no flood).

Everything here is real: no simulated input is used.
"""

import sys
import time

from src import config
from tests.harness import (Harness, ScenarioResult, UNUSUAL_LOCATION_DIR, describe_response,
                           finish, run_scenarios)
from tests.scenario_g import PROCESS_NAME

EXTRA_CHILDREN = 2
QUIET_POLLS = 3         # polls to watch afterwards for repeated alerts


def run(h: Harness) -> ScenarioResult:
    result = ScenarioResult("J", "Correlation of two findings + de-duplication",
                            expected="MEDIUM, then HIGH (combined) + Suggestion; no repeats")
    started = time.time()
    fixture = h.start_fixture(process_name=PROCESS_NAME, directory=UNUSUAL_LOCATION_DIR)

    first = h.wait_for_alert(fixture.pid, started)
    if first is None:
        result.observed = "No Alert"
        result.checks = {"a first alert was raised for the suspicious location": False}
        return finish(result)

    burst_done_at = fixture.spawn_burst(h.settings.process_burst_threshold + EXTRA_CHILDREN)
    combined = h.wait_for_alert(fixture.pid, started, lambda a: config.RULE_PROCESS_BURST in a["rules"])
    result.protected_safety = h.protected_safety(started)
    if combined is None:
        result.observed = "First alert only; no combined alert"
        result.checks = {"a combined alert was raised after the burst": False}
        return finish(result)

    h.wait_cycles(QUIET_POLLS)
    all_alerts = h.alerts_for(fixture.pid, started)

    result.observed = (f"{first['severity']}, then {combined['severity']} (combined) + "
                       f"{describe_response(combined)}; {len(all_alerts)} alerts in total")
    result.severity = combined["severity"]
    result.response = describe_response(combined)
    result.detection_time_s = combined["timestamp"] - burst_done_at
    result.logging_correct = h.logging_correct(first) and h.logging_correct(combined)
    result.checks = {
        "first alert: suspicious location alone, MEDIUM":
            first["rules"] == [config.RULE_SUSPICIOUS_LOCATION] and first["severity"] == config.MEDIUM,
        "second alert lists both rules for the same process":
            set(combined["rules"]) == {config.RULE_SUSPICIOUS_LOCATION, config.RULE_PROCESS_BURST},
        "the combination is rated HIGH and names the combination":
            combined["severity"] == config.HIGH and bool(combined["correlation"]),
        "HIGH stays advisory: suggestion only":
            combined["response_type"] == "SUGGESTED_ACTION" and combined["action_code"] == "NONE",
        "no automatic action: the process is still running": fixture.state() not in ("stopped", "gone"),
        f"no repeated alerts during {QUIET_POLLS} further polls (exactly 2 in total)": len(all_alerts) == 2,
        "the log entries are complete": result.logging_correct,
        "no protected process was acted on": result.protected_safety,
    }
    return finish(result)


if __name__ == "__main__":
    sys.exit(run_scenarios([run]))
