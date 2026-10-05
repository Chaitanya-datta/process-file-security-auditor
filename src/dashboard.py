"""Module 12 - Simple Local Dashboard (presentation layer only).

    python3 -m src.dashboard            then open http://127.0.0.1:5050

The dashboard contains NO detection or response logic and has NO buttons that
control processes. It reads the files the auditor writes:

    logs/auditor_state.json   heartbeat, settings and the current process table
    logs/alerts.jsonl         every alert that was logged

and shows them. If the auditor is not running, the header says STOPPED.

The one action it offers is in the Test Lab: starting one of the project's
own fixed test scenarios (see src/test_lab.py). No other command can be run.
"""

from __future__ import annotations

import argparse
import sys
import time
from typing import List, Optional

from flask import Flask, jsonify, render_template, request

from . import config, test_lab
from .audit_logger import read_alerts, read_state
from .main import is_auditor_running

RECENT_ALERT_LIMIT = 50       # rows in the overview table
TIMELINE_LIMIT = 200          # alerts sent to the timeline page
OVERVIEW_TIMELINE_LIMIT = 6
OVERVIEW_PROCESS_LIMIT = 8
REFRESH_SECONDS = 2

app = Flask(
    __name__,
    template_folder=str(config.PROJECT_ROOT / "templates"),
    static_folder=str(config.PROJECT_ROOT / "static"),
)

# Navigation shown on every page: (label, Flask endpoint name).
NAV = [
    ("Overview", "index"),
    ("Alerts", "alerts_page"),
    ("Processes", "processes_page"),
    ("Statistics", "statistics_page"),
    ("Test Lab", "test_lab_page"),
    ("Detection Rules", "rules_page"),
    ("Architecture", "architecture_page"),
]


@app.context_processor
def _template_globals() -> dict:
    return {"nav": NAV, "refresh_seconds": REFRESH_SECONDS}


# alerts.jsonl is re-parsed only when the file has changed.
_alert_cache: dict = {"stamp": None, "alerts": []}


def _all_alerts(settings: config.Settings) -> List[dict]:
    try:
        stat = settings.alerts_file.stat()
        stamp = (stat.st_mtime_ns, stat.st_size)
    except OSError:
        stamp = None
    if stamp != _alert_cache["stamp"]:
        _alert_cache["alerts"] = read_alerts(settings.alerts_file)
        _alert_cache["stamp"] = stamp
    return _alert_cache["alerts"]


def _session_alerts(settings: config.Settings, session_id: Optional[str]) -> List[dict]:
    if not session_id:
        return []
    return [a for a in _all_alerts(settings) if a.get("session_id") == session_id]


def _alert_title(alert: dict) -> str:
    return " + ".join(config.RULE_LABELS.get(rule, rule) for rule in alert.get("rules", []))


def _timeline_item(alert: dict) -> dict:
    return {
        "id": alert.get("alert_id"),
        "time": alert.get("time"),
        "severity": alert.get("severity"),
        "title": _alert_title(alert),
        "process": alert.get("process_name"),
        "pid": alert.get("pid"),
        "simulated": bool(alert.get("simulated")),
    }


def _alert_details(alert: dict) -> dict:
    """Everything the Alert Details panel shows, taken from the logged alert."""
    carried = set(alert.get("correlated_rules", []))
    triggered = alert.get("rules", [])
    item = _timeline_item(alert)
    item.update({
        "ppid": alert.get("ppid"),
        "parent": alert.get("parent_name"),
        "user": alert.get("owner"),
        "executable": alert.get("executable", ""),
        "cpu_percent": alert.get("cpu_percent"),
        "memory_percent": alert.get("memory_percent"),
        "rules": [
            {"label": label, "triggered": rule in triggered, "carried_over": rule in carried}
            for rule, label in config.RULE_LABELS.items()
        ],
        "severity_explanation": alert.get("severity_explanation", ""),
        "correlation": alert.get("correlation", ""),
        "reasons": alert.get("reasons", []),
        "files": alert.get("sensitive_paths", []),
        "recommended_action": alert.get("suggested_action", ""),
        "response_type": alert.get("response_type", ""),
        "action_taken": alert.get("action_taken", ""),
        "result": alert.get("result", ""),
        "protected": alert.get("protected"),
        "protected_reason": alert.get("protected_reason", ""),
        "is_test_process": bool(alert.get("is_test_process")),
    })
    return item


_RANK = {level: index for index, level in enumerate(config.SEVERITY_ORDER)}


def _process_rows(state: dict, alerts: List[dict]) -> List[dict]:
    """The live process table with a security state for every process.

    SUSPICIOUS  the process has at least one alert in this session
    PROTECTED   the process is on the protected process list
    NORMAL      neither
    A process is matched to its alerts by PID and creation time, so a new
    process that reuses an old PID does not inherit the old alerts.
    """
    by_process: dict = {}
    for alert in alerts:
        key = (alert.get("pid"), round(float(alert.get("create_time", 0)), 2))
        entry = by_process.setdefault(key, {"count": 0, "highest": config.LOW})
        entry["count"] += 1
        if _RANK.get(alert.get("severity"), 0) > _RANK[entry["highest"]]:
            entry["highest"] = alert["severity"]

    rows = []
    for process in state.get("processes", []):
        key = (process.get("pid"), round(float(process.get("create_time", 0)), 2))
        flagged = by_process.get(key)
        protected = bool(process.get("protected"))
        rows.append({
            "pid": process.get("pid"),
            "name": process.get("name"),
            "user": process.get("owner"),
            "ppid": process.get("ppid"),
            "cpu_percent": process.get("cpu_percent", 0),
            "memory_mb": process.get("memory_mb", 0),
            "memory_percent": process.get("memory_percent", 0),
            "status": process.get("status") or "-",
            "protected": protected,
            "is_test_process": bool(process.get("is_test_process")),
            "alert_count": flagged["count"] if flagged else 0,
            "highest_severity": flagged["highest"] if flagged else None,
            "security_state": "SUSPICIOUS" if flagged else ("PROTECTED" if protected else "NORMAL"),
        })
    rows.sort(key=lambda r: (-r["cpu_percent"], -r["memory_mb"]))
    return rows


def _describe_action(alert: dict) -> str:
    kind = alert.get("response_type")
    if kind == "SUGGESTED_ACTION":
        return "Suggested: " + str(alert.get("suggested_action", ""))
    if kind == "AUTO_RESPONSE":
        return f"{alert.get('action_taken')} - {alert.get('result')}"
    return f"No action - {alert.get('result')}"


def build_status() -> dict:
    """Collect everything the page shows, from the auditor's own files."""
    settings = config.load_settings()
    state = read_state(settings.state_file)
    running = is_auditor_running(state)
    state = state or {}

    # Alerts of the most recent auditor session (the running one, if any).
    session_id: Optional[str] = state.get("session_id")
    alerts: List[dict] = _session_alerts(settings, session_id)
    counts = {level: 0 for level in config.SEVERITY_ORDER}
    for alert in alerts:
        if alert.get("severity") in counts:
            counts[alert["severity"]] += 1

    recent = [
        {
            "time": a.get("time"),
            "pid": a.get("pid"),
            "process": a.get("process_name"),
            "reason": " | ".join(a.get("reasons", [])),
            "rules": " + ".join(a.get("rules", [])),
            "severity": a.get("severity"),
            "action": _describe_action(a),
            "protected": a.get("protected"),
            "simulated": bool(a.get("simulated")),
        }
        for a in reversed(alerts[-RECENT_ALERT_LIMIT:])
    ]

    processes = _process_rows(state, alerts) if running else []

    scope = state.get("auto_response_scope", settings.auto_response_scope)
    action = state.get("auto_response_action", settings.auto_response_action)
    scope_text = ("controlled test processes only" if scope == "test_only"
                  else "any process that is not protected")
    interval = state.get("polling_interval_seconds", settings.polling_interval_seconds)
    return {
        "status": "RUNNING" if running else "STOPPED",
        "test_mode": bool(state.get("test_mode")) if running else False,
        "session_id": session_id,
        "started_at": state.get("started_at") if running else None,
        "heartbeat_age_seconds": round(time.time() - state["last_heartbeat"], 1)
        if state.get("last_heartbeat") else None,
        "cycle": state.get("cycle", 0),
        "processes_monitored": len(processes),
        "counts": counts,
        "total_alerts": len(alerts),
        "suppressed_duplicates": state.get("suppressed_duplicates", 0),
        "system": {
            "auditor": ("ACTIVE" + (" (test mode)" if state.get("test_mode") else "")
                        + f" - PID {state.get('auditor_pid')}, {state.get('cycle', 0)} polls completed")
                       if running else "STOPPED",
            "logging": ("ACTIVE" if running else "IDLE")
                       + f" - {settings.audit_log_file.name} and {settings.alerts_file.name} in {settings.log_dir}",
            "auto_response": f"Critical alerts only - {action} - {scope_text}",
            "polling_interval": f"{interval:g} s",
            "protected_processes": f"{state['protected_entries']} entries on the protected list"
                                   if "protected_entries" in state else "auditor has not been started yet",
            "watched_paths": f"{state['watchlist_entries']} sensitive paths"
                             + (f", {state['suspicious_locations']} suspicious locations"
                                if "suspicious_locations" in state else "")
                             if "watchlist_entries" in state else "auditor has not been started yet",
        },
        "timeline": [_timeline_item(a) for a in reversed(alerts[-OVERVIEW_TIMELINE_LIMIT:])],
        "suspicious_processes": sum(1 for p in processes if p["security_state"] == "SUSPICIOUS"),
        "top_processes": processes[:OVERVIEW_PROCESS_LIMIT],
        "processes": processes,
        "alerts": recent,
    }


@app.route("/")
def index():
    return render_template("overview.html")


@app.route("/alerts")
def alerts_page():
    return render_template("alerts.html")


def _header_only(status: dict) -> dict:
    """The parts of the status every page needs for its header."""
    return {key: value for key, value in status.items()
            if key not in ("processes", "top_processes", "alerts", "timeline")}


def _statistics(alerts: List[dict]) -> dict:
    """Counts for the Statistics page, computed from the logged alerts."""
    by_severity = {level: 0 for level in config.SEVERITY_ORDER}
    by_detection = {rule: 0 for rule in config.RULE_LABELS}
    combined = 0
    for alert in alerts:
        if alert.get("severity") in by_severity:
            by_severity[alert["severity"]] += 1
        rules = alert.get("rules", [])
        for rule in rules:
            if rule in by_detection:
                by_detection[rule] += 1        # an alert with two rules counts under both
        if len(rules) > 1:
            combined += 1
    return {
        "total_alerts": len(alerts),
        "combined_alerts": combined,
        "by_severity": [{"label": level.title(), "key": level.lower(), "count": by_severity[level]}
                        for level in config.SEVERITY_ORDER],
        "by_detection": [{"label": label, "count": by_detection[rule]}
                         for rule, label in config.RULE_LABELS.items()],
    }


# --------------------------------------------------------------------------
# Test Lab
# --------------------------------------------------------------------------
LAB_REQUEST_HEADER = "X-Requested-With"
LAB_REQUEST_VALUE = "psa-dashboard"
LOCAL_HOSTS = ("127.0.0.1", "localhost", "::1")


@app.route("/test-lab")
def test_lab_page():
    return render_template("test_lab.html")


def _lab_status() -> dict:
    status = build_status()
    lab = test_lab.overview()
    ready = status["status"] == "RUNNING" and status["test_mode"]
    lab["can_run"] = ready
    lab["cannot_run_reason"] = "" if ready else (
        "Start the auditor with:  python3 -m src.main --test-mode"
        if status["status"] != "RUNNING" else
        "The auditor is running without --test-mode. Restart it with:  python3 -m src.main --test-mode")
    return {"header": _header_only(status), "lab": lab}


@app.route("/api/test-lab")
def api_test_lab():
    try:
        return jsonify(_lab_status())
    except Exception as exc:
        return jsonify({"error": f"{type(exc).__name__}: {exc}"}), 500


@app.route("/api/test-lab/run/<letter>", methods=["POST"])
def api_test_lab_run(letter: str):
    """Start one built-in scenario. Only requests made by this dashboard's own page are accepted."""
    host = (request.host or "").rsplit(":", 1)[0].strip("[]")
    if request.remote_addr not in LOCAL_HOSTS or host not in LOCAL_HOSTS:
        return jsonify({"error": "The Test Lab only accepts requests from this computer"}), 403
    if request.headers.get(LAB_REQUEST_HEADER) != LAB_REQUEST_VALUE:
        return jsonify({"error": "Request did not come from the dashboard page"}), 403
    letter = letter.upper()
    if letter not in test_lab.SCENARIOS:
        return jsonify({"error": "Unknown scenario"}), 404
    lab = _lab_status()["lab"]
    if not lab["can_run"]:
        return jsonify({"error": lab["cannot_run_reason"]}), 409
    try:
        test_lab.start(letter)
    except RuntimeError as exc:
        return jsonify({"error": str(exc)}), 409
    return jsonify({"started": letter}), 202


# --------------------------------------------------------------------------
# Detection Rules and Architecture (static explanations with live configuration)
# --------------------------------------------------------------------------
def _rules_context() -> dict:
    settings = config.load_settings()
    watchlist = config.load_sensitive_files()
    parent_rules = config.load_parent_rules()
    locations = config.load_suspicious_locations()
    protected = config.load_protected_processes()
    rules = [
        {
            "name": config.RULE_LABELS[config.RULE_SENSITIVE_FILE], "level": "HIGH",
            "level_note": "LOW for entries tagged 'low'",
            "checks": "Checks each process's open files against the sensitive-file watchlist.",
            "how": "The Process Watcher lists the files every process has open. Any path that matches "
                   "a watchlist entry raises a finding. The auditor compares paths only; it never opens the files.",
            "config_file": "config/sensitive_files.txt",
            "config_values": [f"{len(watchlist)} watched paths"] + [f"{e.original}  ({e.sensitivity})" for e in watchlist],
        },
        {
            "name": config.RULE_LABELS[config.RULE_OWNER_CHANGE], "level": "HIGH", "level_note": "",
            "checks": "Compares the current owner of each process with the recorded baseline.",
            "how": "The first time a PID is seen its owner (user and effective UID) is stored. On every "
                   "later poll the current owner is compared with that baseline. The PID's creation time is "
                   "stored too, so a reused PID gets a fresh baseline.",
            "config_file": "no configuration - the baseline is learned automatically",
            "config_values": [],
        },
        {
            "name": config.RULE_LABELS[config.RULE_UNUSUAL_PARENT], "level": "MEDIUM", "level_note": "",
            "checks": "Checks whether a process has an unexpected parent relationship.",
            "how": "Each process's PPID gives its parent. The (parent name, child name) pair is compared "
                   "with the configured rules, for example a web browser starting a command shell.",
            "config_file": "config/parent_rules.json",
            "config_values": [f"{len(parent_rules)} rules"] + [
                f"{r.name}: {len(r.parents)} parent patterns -> {len(r.children)} child patterns"
                for r in parent_rules],
        },
        {
            "name": config.RULE_LABELS[config.RULE_SUSPICIOUS_LOCATION], "level": "MEDIUM", "level_note": "",
            "checks": "Checks executable paths against configured suspicious locations.",
            "how": "The path of each process's executable file is compared with the listed folders "
                   "(temporary and download folders). A program running from inside one raises a finding. "
                   "It is a location heuristic, not malware detection.",
            "config_file": "config/suspicious_locations.txt",
            "config_values": [f"{len(locations)} locations"] + [l.original for l in locations],
        },
        {
            "name": config.RULE_LABELS[config.RULE_PROCESS_BURST], "level": "MEDIUM", "level_note": "",
            "checks": "Checks for unusually rapid child-process creation by one parent.",
            "how": "Using PPID and creation time, recently created children are counted per parent. "
                   "Reaching the threshold inside the time window raises one finding on the parent.",
            "config_file": "config/settings.json",
            "config_values": [f"threshold: {settings.process_burst_threshold} children",
                       f"time window: {settings.process_burst_window_seconds:g} s",
                       "ignored parents: " + ", ".join(settings.process_burst_ignored_parents)],
        },
        {
            "name": config.RULE_LABELS[config.RULE_RESOURCE_ANOMALY], "level": "MEDIUM", "level_note": "",
            "checks": "Checks CPU and memory use against configured thresholds.",
            "how": "A process must stay above a threshold for several polls in a row before a finding "
                   "is raised, so one short spike is ignored. CPU % is per core (100 = one full core).",
            "config_file": "config/settings.json",
            "config_values": [f"CPU threshold: {settings.resource_cpu_threshold_percent:g} %",
                       f"memory threshold: {settings.resource_memory_threshold_percent:g} % of RAM",
                       f"must persist for: {settings.resource_sustained_cycles} consecutive polls"],
        },
    ]
    return {
        "rules": rules,
        "settings": settings,
        "protected_count": len(protected.names) + len(protected.test_policy_names) + len(protected.pids),
        "scope_text": ("controlled test processes only" if settings.auto_response_scope == "test_only"
                       else "any process that is not protected"),
    }


@app.route("/rules")
def rules_page():
    return render_template("rules.html", **_rules_context())


@app.route("/architecture")
def architecture_page():
    return render_template("architecture.html")


@app.route("/statistics")
def statistics_page():
    return render_template("statistics.html")


@app.route("/api/statistics")
def api_statistics():
    try:
        header = _header_only(build_status())
        session = _session_alerts(config.load_settings(), header["session_id"])
        return jsonify({"header": header, "statistics": _statistics(session)})
    except Exception as exc:
        return jsonify({"error": f"{type(exc).__name__}: {exc}"}), 500


@app.route("/processes")
def processes_page():
    return render_template("processes.html")


@app.route("/api/processes")
def api_processes():
    try:
        status = build_status()
        return jsonify({"header": _header_only(status), "processes": status["processes"]})
    except Exception as exc:
        return jsonify({"error": f"{type(exc).__name__}: {exc}"}), 500


@app.route("/api/alerts")
def api_alerts():
    try:
        header = _header_only(build_status())
        session = _session_alerts(config.load_settings(), header["session_id"])
        return jsonify({
            "header": header,
            "total": len(session),
            "alerts": [_alert_details(a) for a in reversed(session[-TIMELINE_LIMIT:])],
        })
    except Exception as exc:
        return jsonify({"error": f"{type(exc).__name__}: {exc}"}), 500


@app.route("/api/status")
def api_status():
    try:
        status = build_status()
        status.pop("processes")          # the full table is served by /api/processes
        return jsonify(status)
    except Exception as exc:  # the page shows the error instead of going blank
        return jsonify({"error": f"{type(exc).__name__}: {exc}"}), 500


def main(argv: Optional[List[str]] = None) -> int:
    settings = config.load_settings()
    parser = argparse.ArgumentParser(description="Local dashboard for the Security Auditor")
    parser.add_argument("--port", type=int, default=settings.dashboard_port)
    parser.add_argument("--host", default=settings.dashboard_host)
    args = parser.parse_args(argv)

    print(f"Dashboard: http://{args.host}:{args.port}   (Ctrl+C to stop)")
    try:
        app.run(host=args.host, port=args.port, debug=False, use_reloader=False)
    except OSError as exc:
        # On macOS, port 5000 is normally taken by the AirPlay Receiver.
        print(f"Could not start the dashboard on port {args.port}: {exc}\n"
              f"Try another port:  python3 -m src.dashboard --port {args.port + 1}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
