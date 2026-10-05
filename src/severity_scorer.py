"""Module 6 - Severity Scorer.

Gives every alert exactly one level: LOW, MEDIUM, HIGH or CRITICAL.

The scoring is deliberately small enough to explain in one breath:

  1. Each triggered rule has a base level
         unusual parent                      -> MEDIUM
         suspicious execution location       -> MEDIUM
         sensitive file (tagged "low")       -> LOW
         sensitive file (default, "high")    -> HIGH
         owner / permission change           -> HIGH
  2. The alert takes the HIGHEST base level among its rules.
  3. One combination is escalated:
         owner change + sensitive-file access in the same process -> CRITICAL
"""

from __future__ import annotations

from typing import List

from . import config
from .models import Alert

_RANK = {level: index for index, level in enumerate(config.SEVERITY_ORDER)}


def _base_level(finding: dict) -> str:
    rule = finding["rule"]
    if rule in (config.RULE_UNUSUAL_PARENT, config.RULE_SUSPICIOUS_LOCATION):
        return config.MEDIUM
    if rule == config.RULE_OWNER_CHANGE:
        return config.HIGH
    if rule == config.RULE_SENSITIVE_FILE:
        sensitivity = finding.get("details", {}).get("sensitivity", "high")
        return config.LOW if sensitivity == "low" else config.HIGH
    return config.LOW


class SeverityScorer:
    def score(self, alert: Alert) -> None:
        """Set alert.severity and a one-line explanation of why."""
        if config.RULE_OWNER_CHANGE in alert.rules and config.RULE_SENSITIVE_FILE in alert.rules:
            alert.severity = config.CRITICAL
            alert.severity_explanation = (
                "Owner change combined with sensitive-file access in the same process"
            )
            return

        levels: List[str] = [_base_level(f) for f in alert.findings]
        alert.severity = max(levels, key=lambda level: _RANK[level]) if levels else config.LOW

        if len(alert.rules) == 1:
            explanation = {
                config.RULE_UNUSUAL_PARENT: "Unusual parent process on its own",
                config.RULE_SUSPICIOUS_LOCATION: "Program running from a suspicious location on its own",
                config.RULE_OWNER_CHANGE: "Owner / permission change on its own",
                config.RULE_SENSITIVE_FILE: (
                    "Access to a low-sensitivity watched file"
                    if alert.severity == config.LOW
                    else "Access to a sensitive file on its own"
                ),
            }.get(alert.rules[0], "Single rule triggered")
        else:
            explanation = "Highest level among the triggered rules: " + " + ".join(alert.rules)
        alert.severity_explanation = explanation
