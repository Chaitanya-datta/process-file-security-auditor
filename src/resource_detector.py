"""Resource Usage Anomaly Detection.

Flags a process whose CPU or memory use stays above a configured threshold
for several polling cycles in a row.

  * CPU %    - as reported by psutil: 100 means one full CPU core, so a
               multi-threaded process can exceed 100.
  * Memory % - the process's resident memory as a share of physical RAM.

One high reading is normal (a program starting, a page loading), so a single
reading never raises an alert. The rule is a persistence rule:

    above a threshold for N consecutive polls  ->  one finding

A counter per process is increased on every poll that is above a threshold
and reset to zero by any poll that is not. The finding is raised when the
counter reaches N, once per episode: usage must drop below the thresholds
before the same process can be reported again.

This is a resource-monitoring rule. It never leads to automatic action.
"""

from __future__ import annotations

from typing import Dict, List, Set, Tuple

from . import config
from .models import Finding, ProcessRecord, Snapshot

ProcessKey = Tuple[int, float]     # (PID, creation time) - safe against PID reuse


class ResourceAnomalyDetector:
    def __init__(self, cpu_threshold: float, memory_threshold: float, sustained_cycles: int) -> None:
        self._cpu_threshold = cpu_threshold
        self._memory_threshold = memory_threshold
        self._sustained_cycles = sustained_cycles
        self._cycles_above: Dict[ProcessKey, int] = {}
        self._reported: Set[ProcessKey] = set()

    def check(self, snapshot: Snapshot) -> List[Finding]:
        findings: List[Finding] = []
        seen: Set[ProcessKey] = set()

        for record in snapshot.records.values():
            key: ProcessKey = (record.pid, round(record.create_time, 2))
            exceeded = self._exceeded(record)
            if not exceeded:
                # Back to normal: forget the streak so the next one starts at zero.
                self._cycles_above.pop(key, None)
                self._reported.discard(key)
                continue

            seen.add(key)
            self._cycles_above[key] = self._cycles_above.get(key, 0) + 1
            if self._cycles_above[key] >= self._sustained_cycles and key not in self._reported:
                self._reported.add(key)
                findings.append(self._finding(record, exceeded, self._cycles_above[key], snapshot.taken_at))

        # Forget processes that exited while above a threshold.
        for key in [k for k in self._cycles_above if k not in seen]:
            del self._cycles_above[key]
            self._reported.discard(key)
        return findings

    def _exceeded(self, record: ProcessRecord) -> List[str]:
        exceeded: List[str] = []
        if record.cpu_percent > self._cpu_threshold:
            exceeded.append("cpu")
        if record.memory_percent > self._memory_threshold:
            exceeded.append("memory")
        return exceeded

    def _finding(self, record: ProcessRecord, exceeded: List[str], cycles: int, now: float) -> Finding:
        parts = []
        if "cpu" in exceeded:
            parts.append(f"CPU {record.cpu_percent:.1f}% (threshold {self._cpu_threshold:g}%)")
        if "memory" in exceeded:
            parts.append(f"memory {record.memory_percent:.1f}% (threshold {self._memory_threshold:g}%)")
        return Finding(
            rule=config.RULE_RESOURCE_ANOMALY,
            pid=record.pid,
            process_name=record.name,
            timestamp=now,
            reason=f"Resource usage anomaly: '{record.name}' (PID {record.pid}) stayed above threshold "
                   f"for {cycles} consecutive polls - " + " and ".join(parts),
            resource="+".join(exceeded),
            details={
                "cpu_percent": record.cpu_percent,
                "memory_percent": record.memory_percent,
                "cpu_threshold_percent": self._cpu_threshold,
                "memory_threshold_percent": self._memory_threshold,
                "exceeded": exceeded,
                "consecutive_cycles": cycles,
                "required_cycles": self._sustained_cycles,
                "detection_type": "Resource Usage Anomaly",
            },
        )
