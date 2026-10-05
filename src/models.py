"""Data records passed between the modules of the auditor.

    Process Watcher  -> ProcessRecord / Snapshot
    Detection        -> Finding
    Alert Maker      -> Alert
    Severity Scorer, Advisor, Auto-Response fill in the rest of the Alert.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional


@dataclass
class ProcessRecord:
    """What the Process Watcher read about one process in one polling cycle."""

    pid: int
    name: str
    owner: Optional[str]            # username of the real UID (None if unreadable)
    real_uid: Optional[int]
    effective_uid: Optional[int]    # the "permission level" (0 = root)
    ppid: Optional[int]
    parent_name: str = "unknown"
    cmdline: str = ""
    open_files: List[str] = field(default_factory=list)
    open_files_readable: bool = True    # False if macOS denied access
    cpu_percent: float = 0.0
    memory_mb: float = 0.0
    create_time: float = 0.0
    status: str = ""
    is_test_process: bool = False       # started by the project's test framework
    owner_simulated: bool = False       # owner injected by the test hook (test mode only)


@dataclass
class Snapshot:
    """All process records collected in one polling cycle."""

    taken_at: float
    records: Dict[int, ProcessRecord]
    skipped: int = 0                # processes that vanished / were zombies mid-read
    open_files_denied: int = 0      # processes whose open-file list was not readable


@dataclass
class Finding:
    """One triggered detection rule for one process."""

    rule: str                       # OWNER_CHANGE / SENSITIVE_FILE / UNUSUAL_PARENT
    pid: int
    process_name: str
    timestamp: float
    reason: str                     # human-readable sentence
    resource: str                   # what the finding is about (used for de-duplication)
    details: Dict[str, object] = field(default_factory=dict)
    simulated: bool = False         # True only for controlled test injection


@dataclass
class Alert:
    """One logical alert: every finding for one process in one cycle."""

    alert_id: str
    session_id: str
    timestamp: float                # epoch seconds when the alert was raised
    time: str                       # the same moment, human readable
    pid: int
    process_name: str
    create_time: float
    owner: Optional[str]
    ppid: Optional[int]
    parent_name: str
    rules: List[str]
    reasons: List[str]
    sensitive_paths: List[str]
    findings: List[Dict[str, object]]
    is_test_process: bool = False
    simulated: bool = False
    # --- filled in by the Severity Scorer ---
    severity: str = ""
    severity_explanation: str = ""
    # --- filled in by the Suggested Action Advisor or the Auto-Response Module ---
    response_type: str = ""         # SUGGESTED_ACTION / AUTO_RESPONSE / BLOCKED_PROTECTED / WITHHELD / FAILED
    suggested_action: str = ""
    protected: Optional[bool] = None    # only decided for Critical alerts
    protected_reason: str = ""
    action_code: str = "NONE"       # NONE / SUSPEND / TERMINATE
    action_taken: str = ""          # human-readable action
    result: str = ""
    success: Optional[bool] = None
    responded_at: Optional[float] = None

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)
