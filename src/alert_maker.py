"""Module 5 - Alert Maker.

Groups the findings of one polling cycle by process, so a process that
triggered several rules produces ONE combined alert. Combining matters because
Critical severity depends on a combination of findings.

It also removes duplicates: the same process showing the same behaviour is
reported once and then stays quiet for a configurable cooldown, instead of
flooding the log every polling cycle.
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import asdict
from datetime import datetime
from typing import Dict, List, Tuple

from . import config
from .models import Alert, Finding, Snapshot

DedupKey = Tuple[int, float, Tuple[str, ...]]


class AlertMaker:
    def __init__(self, session_id: str, cooldown_seconds: float) -> None:
        self._session_id = session_id
        self._cooldown = cooldown_seconds
        self._last_raised: Dict[DedupKey, float] = {}
        self._counter = 0
        self.suppressed_duplicates = 0

    def build(self, findings: List[Finding], snapshot: Snapshot) -> List[Alert]:
        """Return the new (non-duplicate) alerts for this cycle."""
        by_pid: Dict[int, List[Finding]] = defaultdict(list)
        for finding in findings:
            by_pid[finding.pid].append(finding)

        alerts: List[Alert] = []
        now = time.time()
        for pid, process_findings in by_pid.items():
            record = snapshot.records.get(pid)
            if record is None:
                continue

            # Same process (PID + creation time) + same rules + same resources
            # = the same behaviour as before. New behaviour gives a new key.
            signature = tuple(sorted(f"{f.rule}:{f.resource}" for f in process_findings))
            key: DedupKey = (pid, round(record.create_time, 2), signature)
            last = self._last_raised.get(key)
            if last is not None and now - last < self._cooldown:
                self.suppressed_duplicates += 1
                continue
            self._last_raised[key] = now

            self._counter += 1
            rules: List[str] = []
            for finding in process_findings:
                if finding.rule not in rules:
                    rules.append(finding.rule)

            alerts.append(
                Alert(
                    alert_id=f"{self._session_id}-{self._counter:04d}",
                    session_id=self._session_id,
                    timestamp=now,
                    time=datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M:%S"),
                    pid=pid,
                    process_name=record.name,
                    create_time=record.create_time,
                    owner=record.owner,
                    ppid=record.ppid,
                    parent_name=record.parent_name,
                    rules=rules,
                    reasons=[f.reason for f in process_findings],
                    sensitive_paths=[
                        str(f.details["path"])
                        for f in process_findings
                        if f.rule == config.RULE_SENSITIVE_FILE
                    ],
                    findings=[asdict(f) for f in process_findings],
                    is_test_process=record.is_test_process,
                    simulated=any(f.simulated for f in process_findings),
                )
            )

        self._forget_dead_processes(snapshot)
        return alerts

    def _forget_dead_processes(self, snapshot: Snapshot) -> None:
        for key in [k for k in self._last_raised if k[0] not in snapshot.records]:
            del self._last_raised[key]
