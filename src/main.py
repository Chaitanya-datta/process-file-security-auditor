"""Process & File-Access Security Auditor - main program.

Connects the modules into the pipeline from the project design:

    Process Watcher -> detection modules -> Alert Maker -> Event Correlation
        -> Severity Scorer
        -> LOW / MEDIUM / HIGH : Suggested Action Advisor
        -> CRITICAL            : Protected Process Check -> Auto-Response Module
        -> Logging + Screen Display

Run from the project root:

    python3 -m src.main                 normal monitoring
    python3 -m src.main --test-mode     also accept controlled test injection
    python3 -m src.main --interval 3    change the polling interval
"""

from __future__ import annotations

import argparse
import os
import signal
import sys
import threading
import time
from datetime import datetime
from typing import List, Optional

import psutil

from . import config
from .action_advisor import SuggestedActionAdvisor
from .alert_maker import AlertMaker
from .audit_logger import AuditLogger, read_state
from .auto_response import AutoResponseModule
from .burst_detector import ProcessBurstDetector
from .event_correlation import EventCorrelator
from .exec_location_detector import SuspiciousLocationDetector
from .models import Alert, Snapshot
from .owner_detector import OwnerChangeDetector
from .parent_detector import UnusualParentDetector
from .process_watcher import ProcessWatcher
from .protected_processes import ProtectedProcessList
from .resource_detector import ResourceAnomalyDetector
from .sensitive_file_detector import SensitiveFileDetector
from .severity_scorer import SeverityScorer

# A state file older than this many polling intervals is treated as stale.
STALE_HEARTBEAT_INTERVALS = 4
MIN_STALE_SECONDS = 10.0


def is_auditor_running(state: Optional[dict]) -> bool:
    """True if *state* describes an auditor process that is alive right now."""
    if not state or state.get("status") != "running":
        return False
    interval = float(state.get("polling_interval_seconds", 2.0))
    limit = max(MIN_STALE_SECONDS, STALE_HEARTBEAT_INTERVALS * interval)
    if time.time() - float(state.get("last_heartbeat", 0)) > limit:
        return False
    try:
        return psutil.pid_exists(int(state.get("auditor_pid", -1)))
    except (TypeError, ValueError):
        return False


class Auditor:
    def __init__(self, settings: config.Settings, test_mode: bool = False, quiet: bool = False) -> None:
        self.settings = settings
        self.test_mode = test_mode
        self.started_at = time.time()
        self.session_id = f"{datetime.now().strftime('%Y%m%d-%H%M%S')}-{os.getpid()}"
        self.cycle = 0
        self.severity_counts = {level: 0 for level in config.SEVERITY_ORDER}

        self.logger = AuditLogger(settings, quiet=quiet)
        self.watcher = ProcessWatcher(test_mode=test_mode)
        self.owner_detector = OwnerChangeDetector()
        self.file_detector = SensitiveFileDetector()
        self.parent_detector = UnusualParentDetector()
        self.location_detector = SuspiciousLocationDetector()
        self.burst_detector = ProcessBurstDetector(
            settings.process_burst_threshold,
            settings.process_burst_window_seconds,
            settings.process_burst_ignored_parents,
        )
        self.resource_detector = ResourceAnomalyDetector(
            settings.resource_cpu_threshold_percent,
            settings.resource_memory_threshold_percent,
            settings.resource_sustained_cycles,
        )
        self.alert_maker = AlertMaker(self.session_id, settings.alert_cooldown_seconds)
        self.correlator = EventCorrelator(settings.correlation_window_seconds)
        self.scorer = SeverityScorer()
        self.advisor = SuggestedActionAdvisor()
        self.protected = ProtectedProcessList()
        self.auto_response = AutoResponseModule(
            self.protected, settings.auto_response_action, settings.auto_response_scope
        )
        self._stop = threading.Event()

    # ------------------------------------------------------------ one cycle
    def run_cycle(self) -> List[Alert]:
        """One pass of the pipeline. Returns the alerts raised in this cycle."""
        cycle_started = time.time()
        snapshot = self.watcher.snapshot()

        findings = (
            self.owner_detector.check(snapshot)
            + self.file_detector.check(snapshot)
            + self.parent_detector.check(snapshot)
            + self.location_detector.check(snapshot)
            + self.burst_detector.check(snapshot)
            + self.resource_detector.check(snapshot)
        )
        alerts = self.alert_maker.build(findings, snapshot)

        for alert in alerts:
            self.correlator.correlate(alert)
            self.scorer.score(alert)
            if alert.severity == config.CRITICAL:
                self.auto_response.respond(alert)
            else:
                self.advisor.advise(alert)
            self.severity_counts[alert.severity] += 1
            self.logger.log_alert(alert)

        # Remember this poll's findings so later polls can be correlated with them.
        self.correlator.observe(findings, snapshot)

        self.cycle += 1
        self._write_state(snapshot, "running", time.time() - cycle_started)
        self.logger.show_status(
            f"[{datetime.now().strftime('%H:%M:%S')}] cycle {self.cycle}: "
            f"{len(snapshot.records)} processes monitored, "
            f"{sum(self.severity_counts.values())} alert(s) this session  (Ctrl+C to stop)"
        )
        return alerts

    def _write_state(self, snapshot: Optional[Snapshot], status: str, cycle_seconds: float = 0.0) -> None:
        processes = []
        if snapshot is not None:
            processes = [
                {
                    "pid": r.pid, "name": r.name, "owner": r.owner or "-",
                    "ppid": r.ppid, "parent_name": r.parent_name,
                    "cpu_percent": r.cpu_percent, "memory_mb": r.memory_mb,
                    "memory_percent": r.memory_percent,
                    "status": r.status, "is_test_process": r.is_test_process,
                }
                for r in snapshot.records.values()
            ]
        self.logger.write_state({
            "status": status,
            "auditor_pid": os.getpid(),
            "session_id": self.session_id,
            "test_mode": self.test_mode,
            "started_at": self.started_at,
            "last_heartbeat": time.time(),
            "cycle": self.cycle,
            "cycle_duration_seconds": round(cycle_seconds, 4),
            "polling_interval_seconds": self.settings.polling_interval_seconds,
            "alert_cooldown_seconds": self.settings.alert_cooldown_seconds,
            "correlation_window_seconds": self.settings.correlation_window_seconds,
            "auto_response_action": self.settings.auto_response_action,
            "auto_response_scope": self.settings.auto_response_scope,
            "audit_log_file": str(self.settings.audit_log_file),
            "alerts_file": str(self.settings.alerts_file),
            "protected_entries": self.protected.size,
            "watchlist_entries": self.file_detector.watchlist_size,
            "parent_rules": self.parent_detector.rule_count,
            "suspicious_locations": self.location_detector.location_count,
            "process_burst_threshold": self.settings.process_burst_threshold,
            "process_burst_window_seconds": self.settings.process_burst_window_seconds,
            "resource_cpu_threshold_percent": self.settings.resource_cpu_threshold_percent,
            "resource_memory_threshold_percent": self.settings.resource_memory_threshold_percent,
            "resource_sustained_cycles": self.settings.resource_sustained_cycles,
            "processes_monitored": len(processes),
            "open_files_unreadable": snapshot.open_files_denied if snapshot else 0,
            "baseline_size": self.owner_detector.baseline_size,
            "severity_counts": self.severity_counts,
            "suppressed_duplicates": self.alert_maker.suppressed_duplicates,
            "processes": processes,
        })

    # -------------------------------------------------------------- running
    def request_stop(self, *_args: object) -> None:
        self._stop.set()

    def run(self, max_cycles: Optional[int] = None) -> None:
        self.logger.log_event(
            f"Auditor started (PID {os.getpid()}, session {self.session_id}, "
            f"polling every {self.settings.polling_interval_seconds:g}s, "
            f"auto-response: {self.settings.auto_response_action} / scope {self.settings.auto_response_scope}, "
            f"{self.protected.size} protected entries, {self.file_detector.watchlist_size} watched paths, "
            f"{self.parent_detector.rule_count} parent rules, "
            f"{self.location_detector.location_count} suspicious locations)"
        )
        if self.test_mode:
            self.logger.log_event(
                "TEST MODE: controlled test injection is enabled "
                "(simulated owner changes are accepted for test processes only)"
            )
        try:
            while not self._stop.is_set():
                cycle_started = time.time()
                try:
                    self.run_cycle()
                except Exception as exc:  # one bad cycle must not end monitoring
                    self.logger.log_event(f"Cycle error (monitoring continues): {type(exc).__name__}: {exc}")
                if max_cycles is not None and self.cycle >= max_cycles:
                    break
                remaining = self.settings.polling_interval_seconds - (time.time() - cycle_started)
                self._stop.wait(max(0.0, remaining))
        finally:
            self.shutdown()

    def shutdown(self) -> None:
        report = self.auto_response.cleanup_on_shutdown()
        if report["terminated_test_processes"]:
            self.logger.log_event(
                f"Cleanup: ended suspended test process(es) {report['terminated_test_processes']}"
            )
        if report["left_suspended"]:
            self.logger.log_event(
                f"NOTE: process(es) {report['left_suspended']} were suspended by the auditor and are "
                f"still suspended. Resume with: kill -CONT <pid>"
            )
        self._write_state(None, "stopped")
        self.logger.log_event(
            f"Auditor stopped after {self.cycle} cycle(s); "
            f"{sum(self.severity_counts.values())} alert(s) logged this session"
        )
        self.logger.close()


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Process & File-Access Security Auditor")
    parser.add_argument("--interval", type=float, help="polling interval in seconds (overrides settings.json)")
    parser.add_argument("--test-mode", action="store_true",
                        help="accept controlled test injection (needed for test scenarios C and E)")
    parser.add_argument("--cycles", type=int, help="stop after this many polling cycles")
    parser.add_argument("--quiet", action="store_true", help="do not print alerts to the screen")
    args = parser.parse_args(argv)

    settings = config.load_settings()
    if args.interval is not None:
        if args.interval < 0.5:
            parser.error("--interval must be at least 0.5 seconds")
        settings.polling_interval_seconds = args.interval

    if is_auditor_running(read_state(settings.state_file)):
        print("An auditor is already running (see logs/auditor_state.json). "
              "Stop it with Ctrl+C before starting another one.", file=sys.stderr)
        return 1

    auditor = Auditor(settings, test_mode=args.test_mode, quiet=args.quiet)
    signal.signal(signal.SIGINT, auditor.request_stop)    # Ctrl+C
    signal.signal(signal.SIGTERM, auditor.request_stop)
    auditor.run(max_cycles=args.cycles)
    return 0


if __name__ == "__main__":
    sys.exit(main())
