"""Dashboard checks that need no running auditor.

    python3 -m unittest tests.test_dashboard -v

They use Flask's built-in test client (no network port is opened) to confirm
that every page and API endpoint answers, that the API has the fields the
pages rely on, and that the Test Lab refuses anything except a request from
the dashboard page for one of the fixed scenarios.
"""

import unittest

from src import config, test_lab
from src.dashboard import LAB_REQUEST_HEADER, LAB_REQUEST_VALUE, _alert_details, _statistics, app

PAGES = ["/", "/alerts", "/processes", "/statistics", "/test-lab", "/rules", "/architecture"]
LAB_HEADERS = {LAB_REQUEST_HEADER: LAB_REQUEST_VALUE}


def sample_alert(rules, severity, **extra):
    alert = {"alert_id": "s-0001", "time": "2026-01-01 10:00:00", "severity": severity, "rules": rules,
             "process_name": "tool", "pid": 42, "ppid": 1, "parent_name": "launchd", "owner": "alice",
             "reasons": ["because"], "sensitive_paths": [], "response_type": "SUGGESTED_ACTION"}
    alert.update(extra)
    return alert


class PagesTest(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_every_page_loads(self):
        for page in PAGES:
            response = self.client.get(page)
            self.assertEqual(response.status_code, 200, page)
            self.assertIn(b"PROCESS &amp; FILE SECURITY AUDITOR", response.data)

    def test_status_api_has_the_overview_fields(self):
        data = self.client.get("/api/status").get_json()
        self.assertIn(data["status"], ("RUNNING", "STOPPED"))
        self.assertEqual(set(data["counts"]), set(config.SEVERITY_ORDER))
        self.assertEqual(data["total_alerts"], sum(data["counts"].values()))
        for key in ("auditor", "logging", "auto_response", "polling_interval",
                    "protected_processes", "watched_paths"):
            self.assertIn(key, data["system"])
        self.assertNotIn("processes", data)

    def test_other_apis_answer_with_a_header(self):
        for url, key in (("/api/alerts", "alerts"), ("/api/processes", "processes"),
                         ("/api/statistics", "statistics"), ("/api/test-lab", "lab")):
            data = self.client.get(url).get_json()
            self.assertIn("header", data, url)
            self.assertIn(key, data, url)

    def test_rules_page_shows_the_configured_values(self):
        settings = config.load_settings()
        html = self.client.get("/rules").get_data(as_text=True)
        for label in config.RULE_LABELS.values():
            self.assertIn(label, html)
        self.assertIn(f"threshold: {settings.process_burst_threshold} children", html)
        self.assertIn(f"must persist for: {settings.resource_sustained_cycles} consecutive polls", html)


class AlertPresentationTest(unittest.TestCase):
    def test_details_list_all_six_rules_with_ticks(self):
        details = _alert_details(sample_alert(
            [config.RULE_SENSITIVE_FILE, config.RULE_OWNER_CHANGE], "CRITICAL",
            correlated_rules=[config.RULE_SENSITIVE_FILE], protected=False))
        self.assertEqual(len(details["rules"]), 6)
        ticked = {r["label"] for r in details["rules"] if r["triggered"]}
        self.assertEqual(ticked, {"Sensitive File Access", "Owner Change"})
        self.assertEqual([r["label"] for r in details["rules"] if r["carried_over"]], ["Sensitive File Access"])
        self.assertEqual(details["title"], "Sensitive File Access + Owner Change")

    def test_statistics_count_by_severity_and_detection(self):
        stats = _statistics([
            sample_alert([config.RULE_UNUSUAL_PARENT], "MEDIUM"),
            sample_alert([config.RULE_SUSPICIOUS_LOCATION, config.RULE_PROCESS_BURST], "HIGH"),
            sample_alert([config.RULE_SUSPICIOUS_LOCATION], "MEDIUM"),
        ])
        self.assertEqual((stats["total_alerts"], stats["combined_alerts"]), (3, 1))
        self.assertEqual({s["label"]: s["count"] for s in stats["by_severity"]},
                         {"Low": 0, "Medium": 2, "High": 1, "Critical": 0})
        by_detection = {d["label"]: d["count"] for d in stats["by_detection"]}
        self.assertEqual(by_detection["Suspicious Execution Location"], 2)
        self.assertEqual(by_detection["Process Creation Burst"], 1)
        self.assertEqual(by_detection["Resource Usage Anomaly"], 0)


class TestLabGuardTest(unittest.TestCase):
    """None of these requests may start a scenario."""

    def setUp(self):
        self.client = app.test_client()

    def test_request_without_the_dashboard_header_is_refused(self):
        self.assertEqual(self.client.post("/api/test-lab/run/B").status_code, 403)

    def test_request_with_a_foreign_host_is_refused(self):
        response = self.client.post("/api/test-lab/run/B", headers={**LAB_HEADERS, "Host": "evil.example"})
        self.assertEqual(response.status_code, 403)

    def test_unknown_scenarios_and_other_text_are_refused(self):
        for letter in ("Z", "AA", "b;id", "..%2Fmain", "scenario_b"):
            response = self.client.post(f"/api/test-lab/run/{letter}", headers=LAB_HEADERS)
            self.assertEqual(response.status_code, 404, letter)
        with self.assertRaises(ValueError):
            test_lab.start("rm")

    def test_scenarios_cannot_be_started_with_get(self):
        self.assertEqual(self.client.get("/api/test-lab/run/B").status_code, 405)

    def test_lab_lists_exactly_the_built_in_scenarios(self):
        lab = self.client.get("/api/test-lab").get_json()["lab"]
        self.assertEqual([s["letter"] for s in lab["scenarios"]], list("ABCDEFGHIJ"))
        self.assertIsNone(test_lab.running_scenario())


if __name__ == "__main__":
    unittest.main()
