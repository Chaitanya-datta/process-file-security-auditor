"""Scenario F - the Critical combination on a PROTECTED process.

Expected: CRITICAL alert, protected = YES, NO automatic action, reason logged.

The test process is named 'psa_protected_fixture', which is on the protected
list under "test_policy_protected_names" in config/protected_processes.json.
No real macOS system process is involved. The decision is made by the same
Protected Process List code that guards real system processes.
"""

import sys
import time

from src import config
from tests.harness import (Harness, PROTECTED_FIXTURE_NAME, SENSITIVE_TEST_FILE, ScenarioResult,
                           describe_response, finish, run_scenarios)


def run(h: Harness) -> ScenarioResult:
    result = ScenarioResult("F", "Critical combination on a protected process",
                            expected="CRITICAL + No action (protected) + reason logged",
                            simulated_input=True)
    started = time.time()
    fixture = h.start_fixture(process_name=PROTECTED_FIXTURE_NAME)
    h.wait_until_baselined(fixture.pid)
    h.wait_cycles(1)

    triggered_at = h.inject_owner_change(fixture)
    fixture.open_file(SENSITIVE_TEST_FILE)

    alert = h.wait_for_alert(fixture.pid, started, lambda a: a["severity"] == config.CRITICAL)
    earlier = [a for a in h.alerts_for(fixture.pid, started) if a["severity"] != config.CRITICAL]
    if alert is None:
        result.observed = "No Critical alert"
        result.protected_safety = h.protected_safety(started)
        result.checks = {"a Critical alert was raised": False}
        return finish(result)

    h.wait_cycles(2)                         # give the auditor time to (wrongly) act
    state_after = fixture.state()            # independent check with psutil
    still_untouched = state_after not in ("stopped", "gone")
    result.protected_safety = h.protected_safety(started) and still_untouched

    result.observed = alert["severity"] + " + " + describe_response(alert)
    result.severity = alert["severity"]
    result.response = describe_response(alert)
    result.detection_time_s = alert["timestamp"] - triggered_at
    result.logging_correct = h.logging_correct(alert)
    if earlier:
        result.notes = "a lower alert was logged one poll earlier (the two triggers straddled a poll)"
    result.checks = {
        "both rules were combined into one alert":
            set(alert["rules"]) == {config.RULE_OWNER_CHANGE, config.RULE_SENSITIVE_FILE},
        "severity is CRITICAL": alert["severity"] == config.CRITICAL,
        "the protected check answered 'protected'": alert["protected"] is True,
        "no automatic action was taken":
            alert["response_type"] == "BLOCKED_PROTECTED" and alert["action_code"] == "NONE",
        "the reason for taking no action was logged":
            "protected" in alert["result"].lower() and bool(alert["protected_reason"]),
        "the OS confirms the process is still running": still_untouched,
        "the log entry is complete": result.logging_correct,
    }
    return finish(result)


if __name__ == "__main__":
    sys.exit(run_scenarios([run]))
