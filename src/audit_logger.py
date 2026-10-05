"""Module 10 - Logging and Screen Display.

Every alert is written to three places at the same moment:

  logs/audit.log      human-readable audit trail (also holds start/stop events)
  logs/alerts.jsonl   the same alert as one JSON object per line (structured)
  the terminal        a readable, colour-coded block

The auditor also writes logs/auditor_state.json once per polling cycle: a small
status file (heartbeat, process table, settings). The dashboard and the test
runner only ever READ these files, which keeps them separate from detection.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, TextIO

from . import config
from .models import Alert

_COLOURS = {
    config.LOW: "\033[36m",        # cyan
    config.MEDIUM: "\033[33m",     # yellow
    config.HIGH: "\033[35m",       # magenta
    config.CRITICAL: "\033[1;31m", # bold red
}
_RESET = "\033[0m"


def format_alert(alert: Alert) -> str:
    """Build the readable text block used for both the log file and the screen."""
    critical = alert.severity == config.CRITICAL
    lines = [
        "[CRITICAL]" if critical else "[ALERT]",
        f"  Alert ID: {alert.alert_id}",
        f"  Time: {alert.time}",
        f"  PID: {alert.pid}",
        f"  Process: {alert.process_name} (owner: {alert.owner or 'unknown'})",
        f"  Parent: {alert.parent_name} (PID {alert.ppid})",
        f"  Rule(s): {' + '.join(alert.rules)}",
    ]
    lines += [f"  Reason: {reason}" for reason in alert.reasons]
    lines.append(f"  Severity: {alert.severity} - {alert.severity_explanation}")
    if alert.correlated_rules:
        lines.append(f"  Correlated: {' + '.join(alert.correlated_rules)} carried over from earlier polls")
    if critical:
        lines.append(f"  Protected: {'YES' if alert.protected else 'NO'} ({alert.protected_reason})")
        lines.append(f"  Action: {alert.action_taken}")
        lines.append(f"  Result: {alert.result}")
    else:
        lines.append(f"  Suggested Action: {alert.suggested_action}")
        lines.append(f"  Action: {alert.action_taken}")
    if alert.simulated:
        lines.append("  Note: owner change was SIMULATED by controlled test injection (--test-mode)")
    return "\n".join(lines)


class AuditLogger:
    def __init__(self, settings: config.Settings, quiet: bool = False) -> None:
        self._settings = settings
        self._quiet = quiet
        self._use_colour = sys.stdout.isatty()
        self._status_line_active = False
        settings.log_dir.mkdir(parents=True, exist_ok=True)
        self._text: Optional[TextIO] = open(settings.audit_log_file, "a", encoding="utf-8")
        self._json: Optional[TextIO] = open(settings.alerts_file, "a", encoding="utf-8")
        self.alerts_logged = 0

    # ---------------------------------------------------------------- alerts
    def log_alert(self, alert: Alert) -> None:
        block = format_alert(alert)
        self._write(self._text, block + "\n\n")
        self._write(self._json, json.dumps(alert.to_dict()) + "\n")
        self.alerts_logged += 1
        if not self._quiet:
            self._clear_status_line()
            colour = _COLOURS.get(alert.severity, "") if self._use_colour else ""
            reset = _RESET if colour else ""
            print(f"\n{colour}{block}{reset}\n", flush=True)

    # ---------------------------------------------------------------- events
    def log_event(self, message: str) -> None:
        """Record a non-alert event such as start-up or shutdown."""
        stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._write(self._text, f"[EVENT] {stamp} {message}\n\n")
        if not self._quiet:
            self._clear_status_line()
            print(f"[{stamp}] {message}", flush=True)

    def show_status(self, message: str) -> None:
        """One live status line per cycle (rewritten in place on a terminal)."""
        if self._quiet or not sys.stdout.isatty():
            return
        print(f"\r\033[K{message}", end="", flush=True)
        self._status_line_active = True

    def _clear_status_line(self) -> None:
        if self._status_line_active:
            print("\r\033[K", end="")
            self._status_line_active = False

    # ----------------------------------------------------------------- state
    def write_state(self, state: Dict[str, object]) -> None:
        """Atomically replace the status file read by the dashboard."""
        path = self._settings.state_file
        temporary = path.with_suffix(".json.tmp")
        try:
            temporary.write_text(json.dumps(state), encoding="utf-8")
            os.replace(temporary, path)
        except OSError as exc:
            print(f"[logger] WARNING: could not write state file: {exc}", file=sys.stderr)

    # ------------------------------------------------------------------ misc
    @staticmethod
    def _write(handle: Optional[TextIO], text: str) -> None:
        if handle is None:
            return
        try:
            handle.write(text)
            handle.flush()
        except OSError as exc:
            print(f"[logger] WARNING: could not write to log: {exc}", file=sys.stderr)

    def close(self) -> None:
        self._clear_status_line()
        for handle in (self._text, self._json):
            if handle is not None:
                try:
                    handle.flush()
                    handle.close()
                except OSError:
                    pass
        self._text = self._json = None


# --------------------------------------------------------------------------
# Read-only helpers used by the dashboard and the test runner
# --------------------------------------------------------------------------
def read_state(state_file: Path) -> Optional[dict]:
    try:
        data = json.loads(state_file.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return None


def read_alerts(alerts_file: Path, session_id: Optional[str] = None) -> List[dict]:
    """Return logged alerts (oldest first), optionally for one auditor session."""
    alerts: List[dict] = []
    try:
        with open(alerts_file, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    alert = json.loads(line)
                except json.JSONDecodeError:
                    continue  # a line that is still being written
                if session_id is None or alert.get("session_id") == session_id:
                    alerts.append(alert)
    except (FileNotFoundError, OSError):
        pass
    return alerts
