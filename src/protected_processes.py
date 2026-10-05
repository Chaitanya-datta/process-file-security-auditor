"""Module 9 - Protected Process List.

Decides whether the Auto-Response Module is allowed to act on a process.
A process is protected if:

  * its name is on the protected list (system-critical macOS processes),
  * its PID is on the protected list (PID 0 and PID 1 always are),
  * its name is protected by the testing policy (the Scenario F fixture), or
  * it is the auditor itself or one of the auditor's parent processes.

Names are the main mechanism because PIDs change on every boot.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Set

import psutil

from . import config


@dataclass
class ProtectionDecision:
    protected: bool
    reason: str


class ProtectedProcessList:
    def __init__(self) -> None:
        loaded = config.load_protected_processes()
        self._names: Set[str] = set(loaded.names)
        self._test_policy_names: Set[str] = set(loaded.test_policy_names)
        self._pids: Set[int] = set(loaded.pids)
        self._own_pids: Set[int] = self._auditor_and_ancestors()

    @staticmethod
    def _auditor_and_ancestors() -> Set[int]:
        """The auditor must never stop itself or the shell / terminal running it."""
        pids = {os.getpid()}
        try:
            pids.update(parent.pid for parent in psutil.Process().parents())
        except psutil.Error:
            pass
        return pids

    @property
    def size(self) -> int:
        return len(self._names) + len(self._test_policy_names) + len(self._pids)

    def check(self, pid: int, name: str) -> ProtectionDecision:
        lowered = (name or "").lower()
        if pid in self._pids:
            return ProtectionDecision(True, f"PID {pid} is on the protected process list")
        if pid in self._own_pids:
            return ProtectionDecision(True, "the process is the auditor itself or one of its parents")
        if lowered in self._names:
            return ProtectionDecision(True, f"'{name}' is on the protected process list (system-critical)")
        if lowered in self._test_policy_names:
            return ProtectionDecision(True, f"'{name}' is on the protected process list (testing policy)")
        return ProtectionDecision(False, "not on the protected process list")
