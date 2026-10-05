"""Module 4 - Unusual Parent Process Detection.

Uses the PID / PPID relationship of every process to form a (parent, child)
pair and checks the pair against the rules in config/parent_rules.json.
Example: a web browser that starts a command shell.
"""

from __future__ import annotations

from typing import List

from . import config
from .models import Finding, Snapshot


class UnusualParentDetector:
    def __init__(self) -> None:
        self._rules: List[config.ParentRule] = config.load_parent_rules()

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    def check(self, snapshot: Snapshot) -> List[Finding]:
        findings: List[Finding] = []
        if not self._rules:
            return findings

        for child in snapshot.records.values():
            parent = snapshot.records.get(child.ppid) if child.ppid is not None else None
            if parent is None or parent.pid == child.pid:
                continue  # parent already exited or is not visible
            for rule in self._rules:
                if rule.matches(parent.name, child.name):
                    findings.append(
                        Finding(
                            rule=config.RULE_UNUSUAL_PARENT,
                            pid=child.pid,
                            process_name=child.name,
                            timestamp=snapshot.taken_at,
                            reason=f"Unusual parent: '{child.name}' (PID {child.pid}) was started by "
                                   f"'{parent.name}' (PID {parent.pid}) - {rule.description}",
                            resource=f"{parent.pid}:{parent.name}",
                            details={
                                "child_pid": child.pid,
                                "child_name": child.name,
                                "parent_pid": parent.pid,
                                "parent_name": parent.name,
                                "rule": rule.name,
                            },
                        )
                    )
                    break  # one unusual-parent finding per process
        return findings
