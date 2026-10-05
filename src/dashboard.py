"""Module 12 - Simple Local Dashboard (presentation layer only).

    python3 -m src.dashboard            then open http://127.0.0.1:5050

The dashboard contains NO detection or response logic and has NO buttons that
control processes. It only reads the files the auditor writes:

    logs/auditor_state.json   heartbeat, settings and the current process table
    logs/alerts.jsonl         every alert that was logged

and shows them. If the auditor is not running, the page says STOPPED.
"""

from __future__ import annotations

import argparse
import sys
import time
from typing import List, Optional

from flask import Flask, jsonify, render_template

from . import config
from .audit_logger import read_alerts, read_state
from .main import is_auditor_running

RECENT_ALERT_LIMIT = 50       # rows in the overview table
TIMELINE_LIMIT = 200          # alerts sent to the timeline page
OVERVIEW_TIMELINE_LIMIT = 6
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

    processes = state.get("processes", []) if running else []
    processes = sorted(processes, key=lambda p: (-p.get("cpu_percent", 0), -p.get("memory_mb", 0)))

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
        "processes": processes,
        "alerts": recent,
    }


@app.route("/")
def index():
    return render_template("overview.html")


@app.route("/alerts")
def alerts_page():
    return render_template("alerts.html")


@app.route("/api/alerts")
def api_alerts():
    try:
        header = build_status()
        session = _session_alerts(config.load_settings(), header["session_id"])
        for key in ("processes", "alerts", "timeline"):
            header.pop(key, None)
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
        return jsonify(build_status())
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
