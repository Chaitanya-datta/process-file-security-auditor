"""Process Creation Burst Detection.

Flags a parent process that creates an unusually large number of child
processes within a short time window (for example 10 children in 10 seconds).

How it works, using only what the Process Watcher already collected:

  1. Every poll, each process created within the last WINDOW seconds is
     remembered under its parent (PPID). The memory is a small dictionary:
         parent -> {child PID: child creation time}
     Remembering matters because a child may already have exited by the next
     poll, but it was still created.
  2. Children whose creation time is older than the window are forgotten.
  3. If a parent has THRESHOLD or more remembered children, one finding is
     raised for the parent. It is raised once per burst: the parent must fall
     back below the threshold before it can be reported again.

It is a counting rule with a threshold - no statistics and no learning.
Children that start and exit entirely between two polls are never seen.
"""

from __future__ import annotations

from typing import Dict, List, Set, Tuple

from . import config
from .models import Finding, ProcessRecord, Snapshot

ParentKey = Tuple[int, float]      # (parent PID, parent creation time)
MAX_CHILD_NAMES_IN_REASON = 5


class ProcessBurstDetector:
    def __init__(self, threshold: int, window_seconds: float, ignored_parents: List[str]) -> None:
        self._threshold = threshold
        self._window = window_seconds
        self._ignored = {name.lower() for name in ignored_parents}
        self._recent_children: Dict[ParentKey, Dict[int, float]] = {}
        self._child_names: Dict[ParentKey, Dict[int, str]] = {}
        self._reported: Set[ParentKey] = set()

    def check(self, snapshot: Snapshot) -> List[Finding]:
        now = snapshot.taken_at
        self._remember_new_children(snapshot, now)
        self._forget_old_children(snapshot, now)

        findings: List[Finding] = []
        for key, children in self._recent_children.items():
            if len(children) < self._threshold:
                self._reported.discard(key)       # burst is over; may be reported again later
                continue
            if key in self._reported:
                continue                          # this burst was already reported
            parent = snapshot.records.get(key[0])
            if parent is None:
                continue
            self._reported.add(key)
            findings.append(self._finding(parent, key, now))
        return findings

    def _remember_new_children(self, snapshot: Snapshot, now: float) -> None:
        for child in snapshot.records.values():
            if child.ppid is None or child.create_time <= 0:
                continue
            if now - child.create_time > self._window:
                continue                          # not a recently created process
            parent = snapshot.records.get(child.ppid)
            if parent is None or parent.pid == child.pid:
                continue                          # parent already exited
            if parent.name.lower() in self._ignored:
                continue                          # e.g. launchd starts everything
            key: ParentKey = (parent.pid, round(parent.create_time, 2))
            self._recent_children.setdefault(key, {})[child.pid] = child.create_time
            self._child_names.setdefault(key, {})[child.pid] = child.name

    def _forget_old_children(self, snapshot: Snapshot, now: float) -> None:
        for key in list(self._recent_children):
            parent = snapshot.records.get(key[0])
            parent_gone = parent is None or round(parent.create_time, 2) != key[1]
            children = self._recent_children[key]
            for pid in [p for p, created in children.items() if now - created > self._window]:
                del children[pid]
                self._child_names[key].pop(pid, None)
            if parent_gone or not children:
                del self._recent_children[key]
                self._child_names.pop(key, None)
                self._reported.discard(key)

    def _finding(self, parent: ProcessRecord, key: ParentKey, now: float) -> Finding:
        count = len(self._recent_children[key])
        names = sorted(set(self._child_names[key].values()))
        shown = ", ".join(names[:MAX_CHILD_NAMES_IN_REASON]) + (", ..." if len(names) > MAX_CHILD_NAMES_IN_REASON else "")
        return Finding(
            rule=config.RULE_PROCESS_BURST,
            pid=parent.pid,
            process_name=parent.name,
            timestamp=now,
            reason=f"Process creation burst: '{parent.name}' (PID {parent.pid}) created {count} child "
                   f"processes within {self._window:g} seconds (threshold {self._threshold}); "
                   f"children: {shown}",
            resource="burst",
            details={
                "parent_pid": parent.pid,
                "parent_name": parent.name,
                "child_count": count,
                "window_seconds": self._window,
                "threshold": self._threshold,
                "child_names": names,
                "detection_type": "Process Creation Burst",
            },
        )
