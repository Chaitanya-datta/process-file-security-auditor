"""Module 8 - Auto-Response Module.

Handles CRITICAL alerts only. The order of checks is fixed:

    Critical alert
      -> Protected Process Check      protected?  -> no action, reason logged
      -> Scope policy                 outside scope? -> no action, reason logged
      -> Identity check               PID reused?  -> no action
      -> Protected check again, on the live process, immediately before acting
      -> psutil suspend() or terminate()
      -> verify the result by reading the process state back from the OS

Scope policy ("auto_response_scope" in config/settings.json):
  test_only        (default) only controlled test processes started by this
                   project's test framework may be suspended / terminated.
  all_unprotected  any process that is not protected may be acted on.

The default keeps the tool safe on a personal laptop: a heuristic alone never
stops a real application.
"""

from __future__ import annotations

import time
from typing import Dict

import psutil

from . import config
from .models import Alert
from .protected_processes import ProtectedProcessList

TERMINATE_WAIT_SECONDS = 3.0
SUSPEND_VERIFY_SECONDS = 1.0
CREATE_TIME_TOLERANCE = 0.01


class AutoResponseModule:
    def __init__(self, protected: ProtectedProcessList, action: str, scope: str) -> None:
        self._protected = protected
        self._action = action
        self._scope = scope
        # PID -> (creation time, is_test_process) of processes this module suspended.
        self.suspended: Dict[int, tuple] = {}

    def respond(self, alert: Alert) -> None:
        """Apply the permitted response to a Critical alert and record the outcome."""
        if alert.severity != config.CRITICAL:
            raise ValueError("Auto-response is reserved for Critical alerts")

        # 1. Protected Process Check.
        decision = self._protected.check(alert.pid, alert.process_name)
        alert.protected = decision.protected
        alert.protected_reason = decision.reason
        if decision.protected:
            self._no_action(
                alert, "BLOCKED_PROTECTED",
                f"Automatic response blocked by protected-process policy: {decision.reason}",
            )
            return

        # 2. Scope policy.
        if self._scope == "test_only" and not alert.is_test_process:
            self._no_action(
                alert, "WITHHELD",
                "Automatic response withheld: auto_response_scope is 'test_only' and this is "
                "not a controlled test process. Manual investigation required.",
            )
            return

        # 3-5. Act on the live process.
        try:
            self._act(alert)
        except psutil.NoSuchProcess:
            self._no_action(alert, "FAILED", "Process exited before the response could be applied")
        except psutil.AccessDenied:
            self._no_action(alert, "FAILED", "The operating system denied permission to control this process")
        except psutil.Error as exc:
            self._no_action(alert, "FAILED", f"Response failed: {exc}")
        alert.responded_at = time.time()

    def _act(self, alert: Alert) -> None:
        proc = psutil.Process(alert.pid)

        # 3. Identity check: make sure the PID still belongs to the same process.
        if abs(proc.create_time() - alert.create_time) > CREATE_TIME_TOLERANCE:
            self._no_action(alert, "FAILED", "PID was reused by a different process; no action taken")
            return

        # 4. Protected check on the live process, immediately before the action.
        live = self._protected.check(proc.pid, proc.name())
        if live.protected:
            alert.protected, alert.protected_reason = True, live.reason
            self._no_action(
                alert, "BLOCKED_PROTECTED",
                f"Automatic response blocked by protected-process policy: {live.reason}",
            )
            return

        alert.response_type = "AUTO_RESPONSE"
        # 5. Controlled response.
        if self._action == "terminate":
            proc.terminate()                      # SIGTERM: a polite request to exit
            alert.action_code = "TERMINATE"
            alert.action_taken = "Process terminated"
            try:
                proc.wait(timeout=TERMINATE_WAIT_SECONDS)
                alert.success, alert.result = True, "Success (verified: process no longer exists)"
            except psutil.TimeoutExpired:
                alert.success, alert.result = False, "Terminate signal sent but the process is still running"
            return

        proc.suspend()                            # SIGSTOP: reversible with resume()
        alert.action_code = "SUSPEND"
        alert.action_taken = "Process suspended"
        if self._wait_until_stopped(proc):
            alert.success, alert.result = True, "Success (verified: process state is 'stopped')"
            self.suspended[proc.pid] = (alert.create_time, alert.is_test_process)
        else:
            alert.success, alert.result = False, "Suspend signal sent but the process did not stop"

    @staticmethod
    def _wait_until_stopped(proc: psutil.Process) -> bool:
        deadline = time.time() + SUSPEND_VERIFY_SECONDS
        while time.time() < deadline:
            if proc.status() == psutil.STATUS_STOPPED:
                return True
            time.sleep(0.02)
        return proc.status() == psutil.STATUS_STOPPED

    @staticmethod
    def _no_action(alert: Alert, response_type: str, explanation: str) -> None:
        alert.response_type = response_type
        alert.action_code = "NONE"
        alert.action_taken = "NONE"
        alert.result = explanation
        alert.success = None
        alert.responded_at = time.time()

    def cleanup_on_shutdown(self) -> Dict[str, list]:
        """Called when the auditor stops.

        Controlled test processes that this module suspended are terminated so
        nothing is left behind. Real processes (only possible with the
        'all_unprotected' scope) are left suspended for the user to decide and
        are reported so they can be resumed with `kill -CONT <pid>`.
        """
        report: Dict[str, list] = {"terminated_test_processes": [], "left_suspended": []}
        for pid, (create_time, is_test) in list(self.suspended.items()):
            try:
                proc = psutil.Process(pid)
                if abs(proc.create_time() - create_time) > CREATE_TIME_TOLERANCE:
                    continue
                if proc.status() != psutil.STATUS_STOPPED:
                    continue
                if is_test:
                    proc.terminate()
                    proc.resume()   # a stopped process handles SIGTERM once resumed
                    report["terminated_test_processes"].append(pid)
                else:
                    report["left_suspended"].append(pid)
            except psutil.Error:
                continue
        self.suspended.clear()
        return report
