"""Module 3 - Sensitive File Detection.

Compares the open files of every process with the editable watchlist in
config/sensitive_files.txt and raises a finding for every match.

The detector never opens a watched file itself; it only compares paths that
psutil reports. The watchlist is re-read automatically when the file changes,
so it can be edited while the auditor is running.
"""

from __future__ import annotations

from typing import List

from . import config
from .models import Finding, Snapshot


class SensitiveFileDetector:
    def __init__(self) -> None:
        self._entries: List[config.WatchEntry] = []
        self._loaded_mtime: float = -1.0
        self._reload_if_changed()

    @property
    def watchlist_size(self) -> int:
        return len(self._entries)

    def _reload_if_changed(self) -> None:
        try:
            mtime = config.SENSITIVE_FILES_FILE.stat().st_mtime
        except OSError:
            mtime = 0.0
        if mtime != self._loaded_mtime:
            self._entries = config.load_sensitive_files()
            self._loaded_mtime = mtime

    def check(self, snapshot: Snapshot) -> List[Finding]:
        self._reload_if_changed()
        findings: List[Finding] = []
        if not self._entries:
            return findings

        for record in snapshot.records.values():
            # Processes whose open-file list macOS would not let us read have
            # an empty list here, so they are simply skipped.
            for path in record.open_files:
                for entry in self._entries:
                    if entry.matches(path):
                        findings.append(
                            Finding(
                                rule=config.RULE_SENSITIVE_FILE,
                                pid=record.pid,
                                process_name=record.name,
                                timestamp=snapshot.taken_at,
                                reason=f"Sensitive file open: {path} "
                                       f"(watchlist entry '{entry.original}', {entry.sensitivity} sensitivity)",
                                resource=path,
                                details={
                                    "path": path,
                                    "watchlist_entry": entry.original,
                                    "sensitivity": entry.sensitivity,
                                },
                            )
                        )
                        break  # one finding per open file is enough
        return findings
