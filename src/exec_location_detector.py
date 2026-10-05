"""Suspicious Execution Location Detection.

Compares the executable path of every process with the directories listed in
config/suspicious_locations.txt and raises a finding when a program is
running from one of them (for example /tmp or ~/Downloads).

The rule is a plain path comparison on information the Process Watcher has
already collected. It is a heuristic about WHERE a program runs from, not a
judgement about what the program is, and it never leads to automatic action.
"""

from __future__ import annotations

from typing import List, Optional

from . import config
from .models import Finding, Snapshot


class SuspiciousLocationDetector:
    def __init__(self) -> None:
        self._locations: List[config.SuspiciousLocation] = config.load_suspicious_locations()

    @property
    def location_count(self) -> int:
        return len(self._locations)

    def _match(self, executable: str) -> Optional[config.SuspiciousLocation]:
        for location in self._locations:
            if location.contains(executable):
                return location
        return None

    def check(self, snapshot: Snapshot) -> List[Finding]:
        findings: List[Finding] = []
        if not self._locations:
            return findings

        for record in snapshot.records.values():
            # An empty path means the OS would not tell us (access denied or
            # the process has no executable file); there is nothing to compare.
            if not record.exe:
                continue
            location = self._match(record.exe)
            if location is None:
                continue
            findings.append(
                Finding(
                    rule=config.RULE_SUSPICIOUS_LOCATION,
                    pid=record.pid,
                    process_name=record.name,
                    timestamp=snapshot.taken_at,
                    reason=f"Suspicious execution location: '{record.name}' is running from "
                           f"{record.exe} (inside configured location '{location.original}')",
                    resource=record.exe,
                    details={
                        "executable": record.exe,
                        "matched_location": location.original,
                        "detection_type": "Suspicious Execution Location",
                    },
                )
            )
        return findings
