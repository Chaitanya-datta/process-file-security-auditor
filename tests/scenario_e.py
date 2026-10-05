"""Scenario E - Critical combination: owner change + sensitive-file access.

Expected: CRITICAL alert, protected check says "not protected", and the
controlled automatic response really suspends the test process.

The file access is real. The owner change is SIMULATED (see scenario C).
The suspension is real: the harness confirms it by asking the OS for the
process state instead of trusting the auditor's log.
"""

import sys
import time

from src import config
from tests.harness import (Harness, SENSITIVE_TEST_FILE, ScenarioResult, describe_response,
                           finish, run_scenarios)


def run(h: Harness) -> ScenarioResult:
    result = ScenarioResult("E", "Critical combination: owner change + sensitive file",
                            expected="CRITICAL + Auto-response (suspend)", simulated_input=True)
    started = time.time()
    fixture = h.start_fixture()
    h.wait_until_baselined(fixture.pid)
    h.wait_cycles(1)                         # start both triggers right after a poll

    triggered_at = h.inject_owner_change(fixture)
    fixture.open_file(SENSITIVE_TEST_FILE)

    alert = h.wait_for_alert(fixture.pid, started, lambda a: a["severity"] == config.CRITICAL)
    earlier = [a for a in h.alerts_for(fixture.pid, started) if a["severity"] != config.CRITICAL]
    result.protected_safety = h.protected_safety(started)
    if alert is None:
        result.observed = "No Critical alert"
        result.checks = {"a Critical alert was raised": False}
        return finish(result)

    state_after = fixture.state()            # independent check with psutil
    result.observed = alert["severity"] + " + " + describe_response(alert)
    result.severity = alert["severity"]
    result.response = describe_response(alert)
    result.detection_time_s = alert["timestamp"] - triggered_at
    if alert.get("responded_at"):
        result.response_time_s = alert["responded_at"] - triggered_at
    result.logging_correct = h.logging_correct(alert)
    if earlier:
        result.notes = "a lower alert was logged one poll earlier (the two triggers straddled a poll)"
    result.checks = {
        "both rules were combined into one alert":
            set(alert["rules"]) == {config.RULE_OWNER_CHANGE, config.RULE_SENSITIVE_FILE},
        "severity is CRITICAL": alert["severity"] == config.CRITICAL,
        "the protected check ran and answered 'not protected'": alert["protected"] is False,
        "the auditor reports a successful suspend":
            alert["response_type"] == "AUTO_RESPONSE" and alert["action_code"] == "SUSPEND"
            and alert["success"] is True,
        "the OS confirms the process is stopped": state_after == "stopped",
        "the log entry is complete": result.logging_correct,
        "no protected process was acted on": result.protected_safety,
    }
    return finish(result)


if __name__ == "__main__":
    sys.exit(run_scenarios([run]))
