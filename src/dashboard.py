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

RECENT_ALERT_LIMIT = 50
REFRESH_SECONDS = 2

app = Flask(
    __name__,
    template_folder=str(config.PROJECT_ROOT / "templates"),
    static_folder=str(config.PROJECT_ROOT / "static"),
)


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
    alerts: List[dict] = read_alerts(settings.alerts_file, session_id) if session_id else []
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
    scope_text = ("controlled test processes only" if scope == "test_only"
                  else "any process that is not protected")
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
            "polling_interval": f"{state.get('polling_interval_seconds', settings.polling_interval_seconds):g} s",
            "logging": ("ACTIVE" if running else "IDLE") + f" - {settings.audit_log_file.name}, "
                       f"{settings.alerts_file.name} in {settings.log_dir}",
            "protected": f"ENABLED - {state.get('protected_entries', 0)} protected entries; "
                         f"auto-response ({state.get('auto_response_action', settings.auto_response_action)}) "
                         f"limited to {scope_text}" if state else "Auditor has not been started yet",
            "watchlist": f"{state.get('watchlist_entries', 0)} watched paths, "
                         f"{state.get('parent_rules', 0)} parent rules" if state else "-",
            "open_files_unreadable": state.get("open_files_unreadable", 0) if running else 0,
        },
        "processes": processes,
        "alerts": recent,
    }


@app.route("/")
def index():
    return render_template("dashboard.html", refresh_seconds=REFRESH_SECONDS)


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
