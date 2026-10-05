"""Module-level checks that need no running auditor.

    python3 -m unittest tests.test_units -v

These exercise the real module code with small hand-built inputs: baseline and
PID-reuse handling, watchlist matching, parent rules, alert combination and
de-duplication, the severity table, the advisor and the protected list.
"""

import os
import time
import unittest

from src import config
from src.action_advisor import SuggestedActionAdvisor
from src.alert_maker import AlertMaker
from src.auto_response import AutoResponseModule
from src.exec_location_detector import SuspiciousLocationDetector
from src.models import ProcessRecord, Snapshot
from src.owner_detector import OwnerChangeDetector
from src.parent_detector import UnusualParentDetector
from src.process_watcher import ProcessWatcher
from src.protected_processes import ProtectedProcessList
from src.sensitive_file_detector import SensitiveFileDetector
from src.severity_scorer import SeverityScorer

WATCHED = config.resolve_path("tests/sandbox/sensitive/fake_ssh_private_key.txt")
WATCHED_LOW = config.resolve_path("tests/sandbox/sensitive/fake_notes.txt")


def record(pid, name="proc", owner="alice", euid=501, ppid=1, files=(), created=100.0, test=False,
           exe="/usr/bin/proc"):
    return ProcessRecord(pid=pid, name=name, owner=owner, real_uid=501, effective_uid=euid,
                         ppid=ppid, open_files=list(files), create_time=created, is_test_process=test,
                         exe=exe)


def snapshot(*records):
    return Snapshot(taken_at=time.time(), records={r.pid: r for r in records})


class ProcessWatcherTest(unittest.TestCase):
    def test_reads_real_processes_including_itself(self):
        snap = ProcessWatcher().snapshot()
        self.assertGreater(len(snap.records), 10)
        me = snap.records[os.getpid()]
        self.assertEqual(me.ppid, os.getppid())
        self.assertEqual(me.real_uid, os.getuid())
        self.assertTrue(me.owner)


class OwnerChangeTest(unittest.TestCase):
    def test_first_sight_is_baseline_then_change_is_flagged(self):
        detector = OwnerChangeDetector()
        self.assertEqual(detector.check(snapshot(record(50))), [])
        self.assertEqual(detector.check(snapshot(record(50))), [])
        findings = detector.check(snapshot(record(50, owner="root", euid=0)))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].details["previous_owner"], "alice")
        self.assertEqual(findings[0].details["current_owner"], "root")

    def test_permission_level_change_alone_is_flagged(self):
        detector = OwnerChangeDetector()
        detector.check(snapshot(record(50)))
        self.assertEqual(len(detector.check(snapshot(record(50, euid=0)))), 1)

    def test_reused_pid_is_not_compared_with_old_baseline(self):
        detector = OwnerChangeDetector()
        detector.check(snapshot(record(50, created=100.0)))
        # Same PID, different creation time and owner: a NEW process, not a change.
        self.assertEqual(detector.check(snapshot(record(50, owner="root", euid=0, created=200.0))), [])

    def test_baseline_is_removed_when_process_exits(self):
        detector = OwnerChangeDetector()
        detector.check(snapshot(record(50), record(51)))
        detector.check(snapshot(record(51)))
        self.assertEqual(detector.baseline_size, 1)


class SensitiveFileTest(unittest.TestCase):
    def test_watched_file_is_flagged_and_normal_file_is_not(self):
        detector = SensitiveFileDetector()
        findings = detector.check(snapshot(record(60, files=[WATCHED]),
                                           record(61, files=["/tmp/ordinary.txt"])))
        self.assertEqual([f.pid for f in findings], [60])
        self.assertEqual(findings[0].details["path"], WATCHED)


class UnusualParentTest(unittest.TestCase):
    def test_browser_starting_shell_is_flagged(self):
        detector = UnusualParentDetector()
        findings = detector.check(snapshot(record(70, name="Google Chrome Helper"),
                                           record(71, name="zsh", ppid=70),
                                           record(72, name="Terminal"),
                                           record(73, name="zsh", ppid=72)))
        self.assertEqual([f.pid for f in findings], [71])
        self.assertEqual(findings[0].details["parent_pid"], 70)


class SuspiciousLocationTest(unittest.TestCase):
    TMP = config.resolve_path("/tmp")           # /private/tmp on macOS

    def test_program_in_listed_location_is_flagged(self):
        findings = SuspiciousLocationDetector().check(snapshot(
            record(80, name="tool", exe=self.TMP + "/build/tool"),
            record(81, name="ls", exe="/bin/ls"),
            record(82, name="app", exe="/Applications/App.app/Contents/MacOS/app")))
        self.assertEqual([f.pid for f in findings], [80])
        self.assertEqual(findings[0].rule, config.RULE_SUSPICIOUS_LOCATION)
        self.assertEqual(findings[0].details["executable"], self.TMP + "/build/tool")
        self.assertEqual(findings[0].details["matched_location"], "/tmp")

    def test_unreadable_executable_path_is_skipped(self):
        self.assertEqual(SuspiciousLocationDetector().check(snapshot(record(83, exe=""))), [])

    def test_similar_folder_name_does_not_match(self):
        # /tmp must not match a different folder whose name merely starts with "tmp".
        self.assertEqual(SuspiciousLocationDetector().check(
            snapshot(record(84, exe=self.TMP + "files/app"))), [])

    def test_watcher_reads_its_own_executable_path(self):
        me = ProcessWatcher().snapshot().records[os.getpid()]
        self.assertTrue(os.path.isabs(me.exe))


class PipelineLogicTest(unittest.TestCase):
    def make_alert(self, *records, baseline=None):
        owner, files, parent = OwnerChangeDetector(), SensitiveFileDetector(), UnusualParentDetector()
        location = SuspiciousLocationDetector()
        if baseline:
            owner.check(snapshot(*baseline))
        snap = snapshot(*records)
        findings = owner.check(snap) + files.check(snap) + parent.check(snap) + location.check(snap)
        alerts = AlertMaker("unit", cooldown_seconds=60).build(findings, snap)
        for alert in alerts:
            SeverityScorer().score(alert)
        return alerts

    def test_unusual_parent_alone_is_medium(self):
        alerts = self.make_alert(record(1, name="firefox"), record(2, name="bash", ppid=1))
        self.assertEqual([a.severity for a in alerts], [config.MEDIUM])

    def test_suspicious_location_alone_is_medium_with_suggestion_only(self):
        alert = self.make_alert(record(9, exe=config.resolve_path("/tmp") + "/x/tool"))[0]
        self.assertEqual(alert.rules, [config.RULE_SUSPICIOUS_LOCATION])
        self.assertEqual(alert.severity, config.MEDIUM)
        SuggestedActionAdvisor().advise(alert)
        self.assertEqual((alert.response_type, alert.action_code), ("SUGGESTED_ACTION", "NONE"))
        self.assertIn("folder", alert.suggested_action)

    def test_suspicious_location_does_not_weaken_existing_levels(self):
        tmp_exe = config.resolve_path("/tmp") + "/x/tool"
        self.assertEqual(self.make_alert(record(10, files=[WATCHED], exe=tmp_exe))[0].severity, config.HIGH)
        critical = self.make_alert(record(11, owner="root", euid=0, files=[WATCHED], exe=tmp_exe),
                                   baseline=[record(11, exe=tmp_exe)])
        self.assertEqual([a.severity for a in critical], [config.CRITICAL])

    def test_sensitive_file_alone_is_high_and_low_tag_is_low(self):
        self.assertEqual(self.make_alert(record(3, files=[WATCHED]))[0].severity, config.HIGH)
        self.assertEqual(self.make_alert(record(3, files=[WATCHED_LOW]))[0].severity, config.LOW)

    def test_owner_change_alone_is_high(self):
        alerts = self.make_alert(record(4, owner="root", euid=0), baseline=[record(4)])
        self.assertEqual(alerts[0].severity, config.HIGH)

    def test_owner_change_plus_sensitive_file_is_one_critical_alert(self):
        alerts = self.make_alert(record(5, owner="root", euid=0, files=[WATCHED]), baseline=[record(5)])
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, config.CRITICAL)
        self.assertEqual(set(alerts[0].rules), {config.RULE_OWNER_CHANGE, config.RULE_SENSITIVE_FILE})

    def test_duplicates_are_suppressed_but_new_behaviour_is_not(self):
        maker, files = AlertMaker("unit", cooldown_seconds=60), SensitiveFileDetector()
        first = snapshot(record(6, files=[WATCHED]))
        self.assertEqual(len(maker.build(files.check(first), first)), 1)
        self.assertEqual(len(maker.build(files.check(first), first)), 0)
        self.assertEqual(maker.suppressed_duplicates, 1)
        second = snapshot(record(6, files=[WATCHED, WATCHED_LOW]))
        self.assertEqual(len(maker.build(files.check(second), second)), 1)

    def test_advisor_suggests_and_refuses_critical(self):
        advisor = SuggestedActionAdvisor()
        alert = self.make_alert(record(7, files=[WATCHED]))[0]
        advisor.advise(alert)
        self.assertEqual(alert.response_type, "SUGGESTED_ACTION")
        self.assertEqual(alert.action_code, "NONE")
        self.assertTrue(alert.suggested_action)
        critical = self.make_alert(record(8, owner="root", euid=0, files=[WATCHED]), baseline=[record(8)])[0]
        with self.assertRaises(ValueError):
            advisor.advise(critical)


class ProtectionTest(unittest.TestCase):
    def setUp(self):
        self.protected = ProtectedProcessList()

    def test_protected_names_and_pids(self):
        self.assertTrue(self.protected.check(1, "launchd").protected)
        self.assertTrue(self.protected.check(4242, "WindowServer").protected)
        self.assertTrue(self.protected.check(4242, "windowserver").protected)
        self.assertTrue(self.protected.check(4242, "psa_protected_fixture").protected)
        self.assertTrue(self.protected.check(os.getpid(), "python").protected)
        self.assertFalse(self.protected.check(4242, "some_app").protected)

    def test_auto_response_never_acts_on_protected_or_out_of_scope(self):
        responder = AutoResponseModule(self.protected, action="suspend", scope="test_only")
        maker = PipelineLogicTest()
        critical = lambda r: maker.make_alert(r, baseline=[record(r.pid, name=r.name, test=r.is_test_process)])[0]

        blocked = critical(record(1, name="launchd", owner="x", files=[WATCHED], test=True))
        responder.respond(blocked)
        self.assertEqual((blocked.protected, blocked.action_code, blocked.response_type),
                         (True, "NONE", "BLOCKED_PROTECTED"))

        # Not protected, but not a controlled test process: withheld by the scope policy.
        withheld = critical(record(999999, name="some_app", owner="x", files=[WATCHED]))
        responder.respond(withheld)
        self.assertEqual((withheld.protected, withheld.action_code, withheld.response_type),
                         (False, "NONE", "WITHHELD"))
        self.assertEqual(responder.suspended, {})


if __name__ == "__main__":
    unittest.main()
