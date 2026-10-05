"""Alert De-duplication / Cooldown.

The auditor polls every few seconds, so a condition that lasts a minute would
otherwise be reported thirty times. This module decides whether an alert is
NEW or a repeat.

A finding is identified by:

    same process (PID + creation time) + same rule + same object

where "object" is what the finding is about (the file path, the executable
path, the old/new owner, ...).

Rules:
  * An alert is raised only if at least one of its findings is new, i.e. has
    not been seen during the last COOLDOWN seconds.
  * Every time a finding is seen again its cooldown restarts. So a condition
    that persists is reported once, and is reported again only after it has
    been absent for a full cooldown period.
  * New behaviour is never suppressed: a different rule, or the same rule on
    a different object, is a different finding.
"""

from __future__ import annotations

from typing import Dict, List, Tuple

from .models import Finding, Snapshot

FindingKey = Tuple[int, float, str, str]    # (PID, creation time, rule, object)


class AlertDeduplicator:
    def __init__(self, cooldown_seconds: float) -> None:
        self._cooldown = cooldown_seconds
        self._last_seen: Dict[FindingKey, float] = {}
        self.suppressed_duplicates = 0

    def is_new(self, pid: int, create_time: float, findings: List[Finding], now: float) -> bool:
        """True if these findings should produce an alert; records them either way."""
        new_behaviour = False
        for finding in findings:
            key: FindingKey = (pid, round(create_time, 2), finding.rule, finding.resource)
            last = self._last_seen.get(key)
            if last is None or now - last >= self._cooldown:
                new_behaviour = True
            self._last_seen[key] = now          # seen again: the cooldown restarts
        if not new_behaviour:
            self.suppressed_duplicates += 1
        return new_behaviour

    def forget_dead_processes(self, snapshot: Snapshot) -> None:
        """Drop entries of processes that exited (their PID may be reused)."""
        for key in list(self._last_seen):
            record = snapshot.records.get(key[0])
            if record is None or round(record.create_time, 2) != key[1]:
                del self._last_seen[key]
