"""Configuration loading for the Process & File-Access Security Auditor.

All paths are resolved relative to the project root, so the tool behaves the
same whether it is started from the VS Code terminal or the macOS Terminal.

Every loader falls back to safe defaults when a file is missing or malformed,
so a broken configuration file can never crash the auditor.
"""

from __future__ import annotations

import fnmatch
import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

# --------------------------------------------------------------------------
# Paths
# --------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = PROJECT_ROOT / "config"
RESULTS_DIR = PROJECT_ROOT / "results"
SANDBOX_DIR = PROJECT_ROOT / "tests" / "sandbox"

SETTINGS_FILE = CONFIG_DIR / "settings.json"
SENSITIVE_FILES_FILE = CONFIG_DIR / "sensitive_files.txt"
PARENT_RULES_FILE = CONFIG_DIR / "parent_rules.json"
PROTECTED_PROCESSES_FILE = CONFIG_DIR / "protected_processes.json"
SUSPICIOUS_LOCATIONS_FILE = CONFIG_DIR / "suspicious_locations.txt"

# --------------------------------------------------------------------------
# Controlled testing constants (see src/test_hooks.py and docs/testing.md)
# --------------------------------------------------------------------------
# Every process started by the project's test framework carries this marker
# in its command line. It is how the auditor recognises "controlled test
# processes".
TEST_PROCESS_MARKER = "--psa-test-process"
# File through which the test framework injects a SIMULATED owner change.
# It is only read when the auditor is started with --test-mode.
TEST_INJECTION_FILE = SANDBOX_DIR / "test_injection.json"

# --------------------------------------------------------------------------
# Rule names and severity levels
# --------------------------------------------------------------------------
RULE_OWNER_CHANGE = "OWNER_CHANGE"
RULE_SENSITIVE_FILE = "SENSITIVE_FILE"
RULE_UNUSUAL_PARENT = "UNUSUAL_PARENT"
RULE_SUSPICIOUS_LOCATION = "SUSPICIOUS_EXEC_LOCATION"

LOW, MEDIUM, HIGH, CRITICAL = "LOW", "MEDIUM", "HIGH", "CRITICAL"
SEVERITY_ORDER = [LOW, MEDIUM, HIGH, CRITICAL]

# Used only if protected_processes.json is missing or malformed, so that the
# safety list can never silently become empty.
FALLBACK_PROTECTED_NAMES = [
    "kernel_task", "launchd", "WindowServer", "loginwindow", "logd",
    "securityd", "opendirectoryd", "configd", "Finder", "Dock",
    "SystemUIServer", "Terminal", "systemd", "init",
]
FALLBACK_PROTECTED_PIDS = [0, 1]


def _warn(message: str) -> None:
    print(f"[config] WARNING: {message}", file=sys.stderr)


def _read_json(path: Path) -> Optional[dict]:
    """Read a JSON object from *path*; return None if missing or malformed."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        _warn(f"{path.name} not found - using safe defaults.")
        return None
    except (OSError, json.JSONDecodeError) as exc:
        _warn(f"{path.name} could not be read ({exc}) - using safe defaults.")
        return None
    if not isinstance(data, dict):
        _warn(f"{path.name} must contain a JSON object - using safe defaults.")
        return None
    return data


# --------------------------------------------------------------------------
# General settings
# --------------------------------------------------------------------------
@dataclass
class Settings:
    polling_interval_seconds: float = 2.0
    alert_cooldown_seconds: float = 120.0
    auto_response_action: str = "suspend"      # "suspend" or "terminate"
    auto_response_scope: str = "test_only"     # "test_only" or "all_unprotected"
    log_dir: Path = PROJECT_ROOT / "logs"
    dashboard_host: str = "127.0.0.1"
    dashboard_port: int = 5050

    @property
    def audit_log_file(self) -> Path:
        return self.log_dir / "audit.log"

    @property
    def alerts_file(self) -> Path:
        return self.log_dir / "alerts.jsonl"

    @property
    def state_file(self) -> Path:
        return self.log_dir / "auditor_state.json"


def load_settings() -> Settings:
    settings = Settings()
    data = _read_json(SETTINGS_FILE) or {}

    def number(key: str, default: float, minimum: float) -> float:
        value = data.get(key, default)
        if isinstance(value, (int, float)) and not isinstance(value, bool) and value >= minimum:
            return float(value)
        _warn(f"settings.json: '{key}' is invalid - using {default}.")
        return default

    settings.polling_interval_seconds = number("polling_interval_seconds", 2.0, 0.5)
    settings.alert_cooldown_seconds = number("alert_cooldown_seconds", 120.0, 0.0)

    action = data.get("auto_response_action", "suspend")
    if action in ("suspend", "terminate"):
        settings.auto_response_action = action
    else:
        _warn("settings.json: 'auto_response_action' must be suspend/terminate - using suspend.")

    scope = data.get("auto_response_scope", "test_only")
    if scope in ("test_only", "all_unprotected"):
        settings.auto_response_scope = scope
    else:
        _warn("settings.json: 'auto_response_scope' is invalid - using test_only.")

    log_dir = data.get("log_dir", "logs")
    if isinstance(log_dir, str) and log_dir.strip():
        path = Path(log_dir).expanduser()
        settings.log_dir = path if path.is_absolute() else PROJECT_ROOT / path

    host = data.get("dashboard_host", "127.0.0.1")
    if isinstance(host, str) and host:
        settings.dashboard_host = host
    port = data.get("dashboard_port", 5050)
    if isinstance(port, int) and 1024 <= port <= 65535:
        settings.dashboard_port = port
    else:
        _warn("settings.json: 'dashboard_port' is invalid - using 5050.")
    return settings


# --------------------------------------------------------------------------
# Sensitive-file watchlist
# --------------------------------------------------------------------------
@dataclass
class WatchEntry:
    """One line of config/sensitive_files.txt."""

    original: str          # the text as written in the watchlist
    resolved: str          # absolute path with symlinks resolved
    is_directory: bool     # True if the entry ended with '/'
    sensitivity: str       # "high" or "low"

    def matches(self, open_path: str) -> bool:
        if self.is_directory:
            return open_path.startswith(self.resolved.rstrip("/") + "/")
        return open_path == self.resolved


def resolve_path(text: str) -> str:
    """Expand ~, anchor relative paths at the project root, resolve symlinks.

    Symlinks matter on macOS: /etc is really /private/etc, and psutil reports
    the real path of an open file.
    """
    path = Path(text).expanduser()
    if not path.is_absolute():
        path = PROJECT_ROOT / path
    return os.path.realpath(str(path))


def load_sensitive_files() -> List[WatchEntry]:
    entries: List[WatchEntry] = []
    try:
        lines = SENSITIVE_FILES_FILE.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        _warn("sensitive_files.txt not found - the watchlist is empty.")
        return entries
    except OSError as exc:
        _warn(f"sensitive_files.txt could not be read ({exc}) - the watchlist is empty.")
        return entries

    for line_number, raw in enumerate(lines, start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        path_text, _, tag = line.partition("|")
        path_text, tag = path_text.strip(), tag.strip().lower()
        if not path_text:
            continue
        if tag not in ("", "high", "low"):
            _warn(f"sensitive_files.txt line {line_number}: unknown tag '{tag}' - treated as high.")
            tag = "high"
        entries.append(
            WatchEntry(
                original=path_text,
                resolved=resolve_path(path_text),
                is_directory=path_text.endswith("/"),
                sensitivity=tag or "high",
            )
        )
    return entries


# --------------------------------------------------------------------------
# Suspicious execution locations
# --------------------------------------------------------------------------
@dataclass
class SuspiciousLocation:
    """One directory from config/suspicious_locations.txt."""

    original: str          # the text as written in the file
    resolved: str          # absolute directory path with symlinks resolved

    def contains(self, executable: str) -> bool:
        # The trailing '/' stops /tmp from also matching /tmpfiles/app.
        return executable.startswith(self.resolved.rstrip("/") + "/")


def load_suspicious_locations() -> List[SuspiciousLocation]:
    locations: List[SuspiciousLocation] = []
    try:
        lines = SUSPICIOUS_LOCATIONS_FILE.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        _warn("suspicious_locations.txt not found - no execution locations are checked.")
        return locations
    except OSError as exc:
        _warn(f"suspicious_locations.txt could not be read ({exc}) - no execution locations are checked.")
        return locations

    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        resolved = resolve_path(line)
        if resolved == "/":
            _warn("suspicious_locations.txt: '/' would match every process - entry ignored.")
            continue
        locations.append(SuspiciousLocation(original=line, resolved=resolved))
    return locations


# --------------------------------------------------------------------------
# Unusual parent-child rules
# --------------------------------------------------------------------------
@dataclass
class ParentRule:
    name: str
    description: str
    parents: List[str]
    children: List[str]

    @staticmethod
    def _match(process_name: str, patterns: List[str]) -> bool:
        lowered = process_name.lower()
        return any(fnmatch.fnmatchcase(lowered, pattern) for pattern in patterns)

    def matches(self, parent_name: str, child_name: str) -> bool:
        return self._match(parent_name, self.parents) and self._match(child_name, self.children)


def load_parent_rules() -> List[ParentRule]:
    data = _read_json(PARENT_RULES_FILE)
    rules: List[ParentRule] = []
    if data is None:
        return rules
    for index, item in enumerate(data.get("rules", []), start=1):
        try:
            parents = [str(p).lower() for p in item["parents"]]
            children = [str(c).lower() for c in item["children"]]
            if not parents or not children:
                raise ValueError("empty parents/children")
            rules.append(
                ParentRule(
                    name=str(item.get("name", f"rule-{index}")),
                    description=str(item.get("description", "Unusual parent-child relationship")),
                    parents=parents,
                    children=children,
                )
            )
        except (KeyError, TypeError, ValueError) as exc:
            _warn(f"parent_rules.json: rule {index} skipped ({exc}).")
    return rules


# --------------------------------------------------------------------------
# Protected process list
# --------------------------------------------------------------------------
@dataclass
class ProtectedConfig:
    names: List[str] = field(default_factory=list)              # lower-case
    pids: List[int] = field(default_factory=list)
    test_policy_names: List[str] = field(default_factory=list)  # lower-case


def load_protected_processes() -> ProtectedConfig:
    data = _read_json(PROTECTED_PROCESSES_FILE)
    if data is None:
        return ProtectedConfig(
            names=[n.lower() for n in FALLBACK_PROTECTED_NAMES],
            pids=list(FALLBACK_PROTECTED_PIDS),
        )

    def names(key: str) -> List[str]:
        value = data.get(key, [])
        if not isinstance(value, list):
            _warn(f"protected_processes.json: '{key}' must be a list.")
            return []
        return [str(v).lower() for v in value if str(v).strip()]

    config = ProtectedConfig(
        names=names("protected_names"),
        test_policy_names=names("test_policy_protected_names"),
    )
    raw_pids = data.get("protected_pids", [])
    if isinstance(raw_pids, list):
        config.pids = [p for p in raw_pids if isinstance(p, int) and not isinstance(p, bool)]
    if not config.names:
        _warn("protected_processes.json has no protected names - adding built-in defaults.")
        config.names = [n.lower() for n in FALLBACK_PROTECTED_NAMES]
    # PID 0 (kernel) and PID 1 (launchd / init) are always protected.
    for pid in FALLBACK_PROTECTED_PIDS:
        if pid not in config.pids:
            config.pids.append(pid)
    return config
