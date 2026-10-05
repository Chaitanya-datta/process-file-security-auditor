"""Module 5 - Alert Maker.

Groups the findings of one polling cycle by process, so a process that
triggered several rules produces ONE combined alert. Combining matters because
severity can depend on a combination of findings.

Repeats are filtered out with the Alert De-duplicator
(src/alert_deduplicator.py): the same process showing the same behaviour is
reported once instead of on every polling cycle.
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import asdict
from datetime import datetime
from typing import Dict, List

from . import config
from .alert_deduplicator import AlertDeduplicator
from .models import Alert, Finding, Snapshot


class AlertMaker:
    def __init__(self, session_id: str, cooldown_seconds: float) -> None:
        self._session_id = session_id
        self._deduplicator = AlertDeduplicator(cooldown_seconds)
        self._counter = 0

    @property
    def suppressed_duplicates(self) -> int:
        return self._deduplicator.suppressed_duplicates

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
            if not self._deduplicator.is_new(pid, record.create_time, process_findings, now):
                continue

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

        self._deduplicator.forget_dead_processes(snapshot)
        return alerts
