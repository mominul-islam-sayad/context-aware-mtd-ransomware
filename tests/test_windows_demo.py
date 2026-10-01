from __future__ import annotations

import subprocess
from pathlib import Path
import sys
import tempfile
import time
import unittest

from windows_demo.demo_config import DemoPaths
from windows_demo.live_mtd import LiveMTD, MutationGuard, SandboxManager
from windows_demo.monitor import SandboxMonitor, ThreatTracker
from windows_demo.app import DemoController


class WindowsDemoTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="mtd_test_")
        root = Path(self.temp.name).resolve() / "sandbox"
        self.paths = DemoPaths(root, root / "protected", root / "decoys")
        self.manager = SandboxManager(self.paths)
        self.manager.reset()

    def tearDown(self):
        self.temp.cleanup()

    def test_sandbox_path_protection(self):
        outside = Path(self.temp.name).resolve() / "outside.txt"
        with self.assertRaises(ValueError):
            self.paths.safe(outside)
        with self.assertRaises(ValueError):
            self.paths.safe(self.paths.sandbox)

    def test_test_file_and_decoy_generation(self):
        self.assertEqual(self.manager.stats(), {"protected": 10, "decoys": 4})
        self.assertTrue(all("DECOY" in path.name for path in self.manager.decoy_files()))
        self.assertGreater(len({len(path.relative_to(self.paths.sandbox).parts) for path in self.manager.decoy_files()}), 1)

    def test_threat_scoring_and_escalation(self):
        tracker = ThreatTracker(self.paths, lambda path: False, clock_hour=lambda: 10)
        files = self.manager.protected_files()
        levels = []
        for path in files[:5]:
            levels.append(tracker.record("modified", path)["level"])
        self.assertIn("MEDIUM", levels)
        self.assertIn(tracker.record("moved", files[5])["level"], {"HIGH", "CRITICAL"})

    def test_decoy_is_critical(self):
        mtd = LiveMTD(self.manager)
        tracker = ThreatTracker(self.paths, mtd.is_decoy)
        result = tracker.record("modified", self.manager.decoy_files()[0])
        self.assertEqual(result["level"], "CRITICAL")
        self.assertTrue(tracker.critical)

    def test_context_raises_score_off_hours_and_on_sensitive_files(self):
        files = {path.name: path for path in self.manager.protected_files()}
        day = ThreatTracker(self.paths, lambda path: False, clock_hour=lambda: 10)
        night = ThreatTracker(self.paths, lambda path: False, clock_hour=lambda: 2)
        day_result = day.record("modified", files["notes.txt"])
        night_result = night.record("modified", files["notes.txt"])
        self.assertEqual(day_result["context"], "business hours")
        self.assertEqual(night_result["context"], "off-hours")
        self.assertGreater(night_result["score"], day_result["score"])
        sensitive = ThreatTracker(self.paths, lambda path: False, clock_hour=lambda: 10)
        sensitive_result = sensitive.record("modified", files["budget.csv"])
        self.assertTrue(sensitive_result["sensitive"])
        self.assertGreater(sensitive_result["score"], day_result["score"])

    def test_mtd_mutation_stays_inside_sandbox(self):
        mtd = LiveMTD(self.manager, MutationGuard())
        before = set(self.manager.protected_files()) | set(self.manager.decoy_files())
        self.assertTrue(mtd.mutate())
        after = set(self.manager.protected_files()) | set(self.manager.decoy_files())
        self.assertEqual(len(after), len(before))
        self.assertTrue(all(self.paths.safe(path).is_relative_to(self.paths.sandbox) for path in after))

    def test_reset_recreates_clean_state(self):
        extra = self.paths.safe(self.paths.protected / "generated.txt")
        extra.write_text("temporary", encoding="utf-8")
        outside = Path(self.temp.name).resolve() / "outside.txt"
        outside.write_text("must remain", encoding="utf-8")
        self.manager.reset()
        self.assertEqual(self.manager.stats(), {"protected": 10, "decoys": 4})
        self.assertFalse(extra.exists())
        self.assertTrue(outside.exists())

    def test_rapid_modification_monitor(self):
        tracker = ThreatTracker(self.paths, lambda path: False, clock_hour=lambda: 10)
        levels = []
        monitor = SandboxMonitor(
            self.paths,
            lambda event, path, dest: levels.append(tracker.record(event, path, dest)["level"]),
            prefer_watchdog=False,
        )
        monitor.start()
        try:
            for path in self.manager.protected_files()[:5]:
                path.write_text(path.read_text(encoding="utf-8") + "x", encoding="utf-8")
            deadline = time.time() + 3
            while time.time() < deadline and not levels:
                time.sleep(0.05)
        finally:
            monitor.stop()
        self.assertTrue(levels)
        self.assertIn("MEDIUM", levels + [tracker.snapshot()["level"]])

    def test_attacker_subprocess_startup_and_kill_switch(self):
        events = []
        controller = DemoController(self.paths, event_sink=events.append)
        try:
            controller.initialize()
            controller.start_protection()
            self.assertTrue(controller.start_attacker())
            deadline = time.time() + 10
            while time.time() < deadline and "ATTACK BLOCKED" not in events:
                time.sleep(0.1)
            self.assertIn("KILL-SWITCH ACTIVATED", events)
            self.assertIn("ATTACK SIMULATOR TERMINATED", events)
            self.assertIn("ATTACK BLOCKED", events)
            self.assertEqual(controller.status()["attack"], "STOPPED")
        finally:
            controller.close()

    def test_attack_does_not_start_protection(self):
        events = []
        controller = DemoController(self.paths, event_sink=events.append)
        try:
            controller.initialize()
            self.assertTrue(controller.start_attacker())
            self.assertEqual(controller.status()["protection"], "STOPPED")
            self.assertIn("WARNING: protection is STOPPED - attack will run undefended", events)
            deadline = time.time() + 15
            while time.time() < deadline and "ATTACK COMPLETED - NOT BLOCKED" not in events:
                time.sleep(0.1)
            self.assertIn("ATTACK COMPLETED - NOT BLOCKED", events)
            self.assertTrue(any(e.startswith("Files damaged: 5/10") for e in events))
            self.assertNotIn("KILL-SWITCH ACTIVATED", events)
            self.assertTrue(any(p.name.endswith(".locked_demo") for p in self.manager.protected_files()))
        finally:
            controller.close()


if __name__ == "__main__":
    unittest.main()

