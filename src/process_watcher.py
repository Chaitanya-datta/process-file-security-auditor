"""Module 1 - Process Watcher.

Polls the operating system's process table through psutil and returns a
Snapshot: one ProcessRecord per running process, holding the PID, name, owner,
permission level (effective UID), parent PID, command line, open files, CPU
and memory use.

The watcher only READS information. It never changes a process.
"""

from __future__ import annotations

import time
from typing import Callable, Optional, TypeVar

import psutil

from . import config
from .models import ProcessRecord, Snapshot
from .test_hooks import TestHooks

T = TypeVar("T")

MAX_CMDLINE_CHARS = 300
BYTES_PER_MB = 1024 * 1024


def _read(getter: Callable[[], T], default: T) -> T:
    """Read one attribute; return *default* if the OS denies access.

    macOS does not let an ordinary user read the command line, memory or open
    files of processes owned by other users (psutil.AccessDenied). That is
    normal and must not stop the auditor.

    NoSuchProcess / ZombieProcess are deliberately NOT caught here: they mean
    the whole process is gone, and the caller skips it.
    """
    try:
        return getter()
    except (psutil.AccessDenied, PermissionError):
        return default


class ProcessWatcher:
    def __init__(self, test_mode: bool = False) -> None:
        # The hook object only exists in --test-mode (see src/test_hooks.py).
        self._test_hooks: Optional[TestHooks] = TestHooks() if test_mode else None

    def snapshot(self) -> Snapshot:
        """Read the current state of every running process."""
        if self._test_hooks:
            self._test_hooks.refresh()

        snapshot = Snapshot(taken_at=time.time(), records={})

        # process_iter() keeps one Process object per PID between calls, which
        # is what lets cpu_percent(interval=None) compare with the last poll.
        for proc in psutil.process_iter():
            try:
                record = self._read_process(proc, snapshot)
            except (psutil.NoSuchProcess, psutil.ZombieProcess):
                # The process exited (or is a zombie) between two reads.
                snapshot.skipped += 1
                continue
            except (psutil.Error, OSError):
                # Any other per-process failure: skip this process only.
                snapshot.skipped += 1
                continue
            if self._test_hooks:
                self._test_hooks.apply(record)
            snapshot.records[record.pid] = record

        # Second pass: turn each parent PID into a parent name.
        for record in snapshot.records.values():
            parent = snapshot.records.get(record.ppid) if record.ppid is not None else None
            if parent is not None and parent.pid != record.pid:
                record.parent_name = parent.name
        return snapshot

    @staticmethod
    def _read_process(proc: psutil.Process, snapshot: Snapshot) -> ProcessRecord:
        # oneshot() makes psutil fetch several attributes with one system call.
        with proc.oneshot():
            pid = proc.pid
            name = _read(proc.name, "") or f"pid-{pid}"
            status = _read(proc.status, "")
            if status == psutil.STATUS_ZOMBIE:
                raise psutil.ZombieProcess(pid)

            uids = _read(proc.uids, None)
            owner = _read(proc.username, None)
            ppid = _read(proc.ppid, None)
            create_time = _read(proc.create_time, 0.0)
            cmdline_parts = _read(proc.cmdline, []) or []
            cpu_percent = _read(lambda: proc.cpu_percent(interval=None), 0.0)
            memory = _read(proc.memory_info, None)

            open_files_readable = True
            try:
                open_files = [f.path for f in proc.open_files()]
            except (psutil.AccessDenied, PermissionError):
                open_files, open_files_readable = [], False
                snapshot.open_files_denied += 1

        return ProcessRecord(
            pid=pid,
            name=name,
            owner=owner,
            real_uid=uids.real if uids else None,
            effective_uid=uids.effective if uids else None,
            ppid=ppid,
            cmdline=" ".join(cmdline_parts)[:MAX_CMDLINE_CHARS],
            open_files=open_files,
            open_files_readable=open_files_readable,
            cpu_percent=round(cpu_percent or 0.0, 1),
            memory_mb=round(memory.rss / BYTES_PER_MB, 1) if memory else 0.0,
            create_time=create_time or 0.0,
            status=status,
            is_test_process=config.TEST_PROCESS_MARKER in cmdline_parts,
        )
