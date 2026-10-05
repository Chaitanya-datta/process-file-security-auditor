"""Module 2 - Owner Change Detection.

Remembers the original owner (username) and permission level (effective UID)
of every process the first time it is seen, and raises a finding if either of
them is different on a later poll. A process that starts as an ordinary user
and later runs as root is the classic sign of privilege escalation.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional

from . import config
from .models import Finding, ProcessRecord, Snapshot

# Two reads of the same process give the same creation time; anything further
# apart than this means the PID was reused by a new process.
CREATE_TIME_TOLERANCE = 0.01


@dataclass
class Baseline:
    owner: Optional[str]
    real_uid: Optional[int]
    effective_uid: Optional[int]
    create_time: float
    name: str
    first_seen: float


class OwnerChangeDetector:
    def __init__(self) -> None:
        self._baseline: Dict[int, Baseline] = {}

    @property
    def baseline_size(self) -> int:
        return len(self._baseline)

    def check(self, snapshot: Snapshot) -> List[Finding]:
        findings: List[Finding] = []
        for pid, record in snapshot.records.items():
            stored = self._baseline.get(pid)

            # First sight of this PID, or the PID was reused by a different
            # process (different creation time): record a fresh baseline.
            if stored is None or abs(stored.create_time - record.create_time) > CREATE_TIME_TOLERANCE:
                self._baseline[pid] = Baseline(
                    owner=record.owner,
                    real_uid=record.real_uid,
                    effective_uid=record.effective_uid,
                    create_time=record.create_time,
                    name=record.name,
                    first_seen=snapshot.taken_at,
                )
                continue

            finding = self._compare(stored, record, snapshot.taken_at)
            if finding:
                findings.append(finding)

        # Forget processes that no longer exist, so a reused PID is never
        # compared with another process's baseline.
        for pid in [p for p in self._baseline if p not in snapshot.records]:
            del self._baseline[pid]
        return findings

    @staticmethod
    def _compare(stored: Baseline, record: ProcessRecord, now: float) -> Optional[Finding]:
        # If the owner could not be read (access denied) there is nothing to compare.
        if record.owner is None or stored.owner is None:
            return None

        owner_changed = record.owner != stored.owner
        level_changed = (
            record.effective_uid is not None
            and stored.effective_uid is not None
            and record.effective_uid != stored.effective_uid
        )
        if not (owner_changed or level_changed):
            return None

        previous = f"{stored.owner} (effective UID {stored.effective_uid})"
        current = f"{record.owner} (effective UID {record.effective_uid})"
        reason = f"Owner / permission level changed while running: {previous} -> {current}"
        if record.owner_simulated:
            reason += " [SIMULATED by controlled test injection]"

        return Finding(
            rule=config.RULE_OWNER_CHANGE,
            pid=record.pid,
            process_name=record.name,
            timestamp=now,
            reason=reason,
            resource=f"{stored.owner}/{stored.effective_uid}->{record.owner}/{record.effective_uid}",
            details={
                "previous_owner": stored.owner,
                "current_owner": record.owner,
                "previous_effective_uid": stored.effective_uid,
                "current_effective_uid": record.effective_uid,
                "baseline_recorded_at": stored.first_seen,
            },
            simulated=record.owner_simulated,
        )
