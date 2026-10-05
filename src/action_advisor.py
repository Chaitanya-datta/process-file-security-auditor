"""Module 7 - Suggested Action Advisor.

For LOW, MEDIUM and HIGH alerts it looks up a recommended next step in a small
table and attaches it to the alert. It NEVER changes a process: the decision
is left to the user.
"""

from __future__ import annotations

from . import config
from .models import Alert

# General guidance for each non-critical level.
LEVEL_GUIDANCE = {
    config.LOW: "Review the process when convenient.",
    config.MEDIUM: "Inspect the process and its parent more closely.",
    config.HIGH: "Investigate now: check what the process has read or changed.",
}

# Specific next step for each detection rule.
RULE_SUGGESTIONS = {
    config.RULE_OWNER_CHANGE:
        "Confirm why the owner / permission level changed and whether the user expected it.",
    config.RULE_SENSITIVE_FILE:
        "Check why this process has the watched file open and whether it should have access.",
    config.RULE_UNUSUAL_PARENT:
        "Check the parent process and the command line of the child it started.",
    config.RULE_SUSPICIOUS_LOCATION:
        "Check what this program is and why it runs from that folder; move trusted "
        "software to a normal install location.",
    config.RULE_PROCESS_BURST:
        "Check what the parent is running and whether starting this many child "
        "processes is expected (a build or script) or runaway behaviour.",
    config.RULE_RESOURCE_ANOMALY:
        "Check in Activity Monitor whether this heavy CPU / memory use is expected "
        "work or a stuck / runaway process.",
}


class SuggestedActionAdvisor:
    def advise(self, alert: Alert) -> None:
        """Attach a suggestion to a LOW / MEDIUM / HIGH alert. No process is touched."""
        if alert.severity == config.CRITICAL:
            raise ValueError("Critical alerts are handled by the Auto-Response Module")

        steps = [LEVEL_GUIDANCE[alert.severity]]
        steps += [RULE_SUGGESTIONS[rule] for rule in alert.rules if rule in RULE_SUGGESTIONS]

        alert.suggested_action = " ".join(steps)
        alert.response_type = "SUGGESTED_ACTION"
        alert.action_code = "NONE"
        alert.action_taken = "Suggested action shown (no change made to the process)"
        alert.result = "Decision left to the user"
