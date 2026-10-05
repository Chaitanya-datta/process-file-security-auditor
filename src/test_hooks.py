"""CONTROLLED TEST INJECTION - not part of the production detection logic.

Why this exists
---------------
On macOS an ordinary (non-root) process cannot change its own owner: setuid()
needs root privileges. Scenarios C and E need "a process whose owner changes
while it is running", and performing a real privilege escalation on a personal
laptop would be unsafe.

So, ONLY when the auditor is started with ``--test-mode``, the Process Watcher
asks this module whether the test framework has requested a *simulated* owner
for a process. If so, the reported owner in that one ProcessRecord is replaced
and the record is flagged ``owner_simulated=True``. The flag travels through
the finding, the alert and the log, so a simulated owner change is always
labelled as such.

What stays real
---------------
Owner Change Detection (src/owner_detector.py) is unchanged: it stores the
baseline owner on first sight and compares it on every later poll. The hook
only changes the *input* it sees, for a process that:

  * carries the test marker in its command line (started by tests/harness.py),
  * matches the PID *and* creation time written by the test framework.

A real process can never be affected.
"""

from __future__ import annotations

import json
from typing import Dict

from . import config
from .models import ProcessRecord


class TestHooks:
    """Reads tests/sandbox/test_injection.json and applies owner overrides."""

    __test__ = False  # not a pytest test class

    def __init__(self) -> None:
        self._overrides: Dict[str, dict] = {}

    def refresh(self) -> None:
        """Re-read the injection file. Called once per polling cycle."""
        try:
            data = json.loads(config.TEST_INJECTION_FILE.read_text(encoding="utf-8"))
            overrides = data.get("owner_overrides", {})
            self._overrides = overrides if isinstance(overrides, dict) else {}
        except (FileNotFoundError, OSError, json.JSONDecodeError, AttributeError):
            self._overrides = {}

    def apply(self, record: ProcessRecord) -> None:
        """Replace the owner of *record* if a matching test override exists."""
        if not record.is_test_process:
            return
        override = self._overrides.get(str(record.pid))
        if not isinstance(override, dict):
            return
        try:
            if abs(float(override["create_time"]) - record.create_time) > 0.01:
                return  # the PID now belongs to a different process
            record.owner = str(override["owner"])
            record.effective_uid = int(override["effective_uid"])
            record.owner_simulated = True
        except (KeyError, TypeError, ValueError):
            return
