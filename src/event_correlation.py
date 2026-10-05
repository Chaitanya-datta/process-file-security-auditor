"""Event Correlation.

Sits between the Alert Maker and the Severity Scorer.

The Alert Maker already combines the findings a process triggers in the SAME
poll. Some findings, however, are raised in one poll only (a process burst, a
resource anomaly) and related behaviour may show up a few polls later. The
Event Correlator therefore remembers, per process, which rules it triggered
during the last WINDOW seconds, and adds those earlier findings to a new
alert for the same process.

Example (window 60 s):

    12:00:05  process 4242 runs from a suspicious location      -> alert, MEDIUM
    12:00:21  process 4242 creates a burst of child processes   -> alert lists
              BOTH rules; the Severity Scorer rates the combination HIGH

The correlator only gathers evidence. Which combinations raise the severity
is decided by the fixed table in src/severity_scorer.py.
"""

from __future__ import annotations

import copy
from dataclasses import asdict
from typing import Dict, List, Tuple

from . import config
from .models import Alert, Finding, Snapshot

ProcessKey = Tuple[int, float]     # (PID, creation time)


class EventCorrelator:
    def __init__(self, window_seconds: float) -> None:
        self._window = window_seconds
        # process -> rule -> (finding as dict, time it was last seen)
        self._recent: Dict[ProcessKey, Dict[str, Tuple[dict, float]]] = {}

    def observe(self, findings: List[Finding], snapshot: Snapshot) -> None:
        """Remember this poll's findings and forget old ones. Called every poll."""
        now = snapshot.taken_at
        for finding in findings:
            record = snapshot.records.get(finding.pid)
            if record is None:
                continue
            key: ProcessKey = (finding.pid, round(record.create_time, 2))
            self._recent.setdefault(key, {})[finding.rule] = (asdict(finding), now)

        for key in list(self._recent):
            record = snapshot.records.get(key[0])
            if record is None or round(record.create_time, 2) != key[1]:
                del self._recent[key]               # process exited or PID was reused
                continue
            rules = self._recent[key]
            for rule in [r for r, (_, seen) in rules.items() if now - seen > self._window]:
                del rules[rule]
            if not rules:
                del self._recent[key]

    def correlate(self, alert: Alert) -> None:
        """Add this process's earlier findings (other rules, still in the window)."""
        remembered = self._recent.get((alert.pid, round(alert.create_time, 2)), {})
        for rule, (finding, seen) in remembered.items():
            if rule in alert.rules:
                continue
            seconds_ago = max(0, round(alert.timestamp - seen))
            earlier = copy.deepcopy(finding)
            earlier["carried_over"] = True
            earlier["seen_seconds_ago"] = seconds_ago
            alert.findings.append(earlier)
            alert.rules.append(rule)
            alert.correlated_rules.append(rule)
            alert.reasons.append(f"{finding['reason']} [seen {seconds_ago}s earlier]")
            if rule == config.RULE_SENSITIVE_FILE:
                alert.sensitive_paths.append(str(finding["details"]["path"]))
            alert.simulated = alert.simulated or bool(finding.get("simulated"))
