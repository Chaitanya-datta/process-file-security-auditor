"""Module 6 - Severity Scorer.

Gives every alert exactly one level: LOW, MEDIUM, HIGH or CRITICAL.

The scoring is a fixed table, small enough to explain in one breath:

  1. Each triggered rule has a base level
         sensitive file (tagged "low")       -> LOW
         unusual parent                      -> MEDIUM
         suspicious execution location       -> MEDIUM
         process creation burst              -> MEDIUM
         resource usage anomaly              -> MEDIUM
         sensitive file (default, "high")    -> HIGH
         owner / permission change           -> HIGH
  2. The alert takes the HIGHEST base level among its rules.
  3. Two combinations on the same process raise the level:
         two or more different MEDIUM rules                   -> HIGH
         owner change + sensitive-file access                 -> CRITICAL

CRITICAL is the only level that can lead to automatic action, and only the
owner-change + sensitive-file combination can reach it.
"""

from __future__ import annotations

from typing import List

from . import config
from .models import Alert

_RANK = {level: index for index, level in enumerate(config.SEVERITY_ORDER)}

MEDIUM_RULES = (
    config.RULE_UNUSUAL_PARENT,
    config.RULE_SUSPICIOUS_LOCATION,
    config.RULE_PROCESS_BURST,
    config.RULE_RESOURCE_ANOMALY,
)

_SINGLE_RULE_EXPLANATION = {
    config.RULE_UNUSUAL_PARENT: "Unusual parent process on its own",
    config.RULE_SUSPICIOUS_LOCATION: "Program running from a suspicious location on its own",
    config.RULE_PROCESS_BURST: "Burst of child-process creation on its own",
    config.RULE_RESOURCE_ANOMALY: "Sustained high CPU / memory use on its own",
    config.RULE_OWNER_CHANGE: "Owner / permission change on its own",
}


def _base_level(finding: dict) -> str:
    rule = finding["rule"]
    if rule in MEDIUM_RULES:
        return config.MEDIUM
    if rule == config.RULE_OWNER_CHANGE:
        return config.HIGH
    if rule == config.RULE_SENSITIVE_FILE:
        sensitivity = finding.get("details", {}).get("sensitivity", "high")
        return config.LOW if sensitivity == "low" else config.HIGH
    return config.LOW


class SeverityScorer:
    def score(self, alert: Alert) -> None:
        """Set alert.severity, the explanation, and the combination that applied (if any)."""
        # Combination 1: the one Critical case.
        if config.RULE_OWNER_CHANGE in alert.rules and config.RULE_SENSITIVE_FILE in alert.rules:
            alert.severity = config.CRITICAL
            alert.correlation = "OWNER_CHANGE + SENSITIVE_FILE"
            alert.severity_explanation = (
                "Owner change combined with sensitive-file access in the same process"
            )
            return

        levels: List[str] = [_base_level(f) for f in alert.findings]
        highest = max(levels, key=lambda level: _RANK[level]) if levels else config.LOW

        # Combination 2: two or more different MEDIUM rules on the same process.
        medium_rules = [rule for rule in alert.rules if rule in MEDIUM_RULES]
        if len(medium_rules) >= 2 and _RANK[highest] <= _RANK[config.HIGH]:
            alert.severity = config.HIGH
            alert.correlation = " + ".join(medium_rules)
            alert.severity_explanation = (
                f"{len(medium_rules)} medium-level findings on the same process: "
                + " + ".join(medium_rules)
            )
            return

        alert.severity = highest
        if len(alert.rules) == 1:
            if alert.rules[0] == config.RULE_SENSITIVE_FILE:
                alert.severity_explanation = (
                    "Access to a low-sensitivity watched file" if highest == config.LOW
                    else "Access to a sensitive file on its own"
                )
            else:
                alert.severity_explanation = _SINGLE_RULE_EXPLANATION.get(alert.rules[0], "Single rule triggered")
        else:
            alert.severity_explanation = "Highest level among the triggered rules: " + " + ".join(alert.rules)
