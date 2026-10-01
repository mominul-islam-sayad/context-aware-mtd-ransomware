import random
import shutil
import tempfile
import unittest

from attacker import Attacker
from mtd import CONFIGS, ProcessSuspended, VirtualFS, build_workspace
from run import backup_workload

CONFIG = {cfg.name: cfg for cfg in CONFIGS}


class ContextSimulationTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="mtd_ctx_test_")
        self.files = build_workspace(self.root, seed=1)

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def vfs(self, name, hour=10):
        return VirtualFS(self.root, self.files, CONFIG[name], seed=1, hour=hour)

    def test_context_weight_combines_who_what_when(self):
        vfs = self.vfs("FULL context-aware", hour=2)        # off-hours, user idle
        self.assertAlmostEqual(vfs._context("attacker"), 1.5 * 1.25)
        self.assertAlmostEqual(vfs._context("backup"), 0.2 * 1.5 * 1.25)
        self.assertAlmostEqual(vfs._context("attacker", "d0/budget_3.docx"), 1.5 * 1.5 * 1.25)
        self.assertEqual(self.vfs("FULL adaptive", hour=2)._context("attacker"), 1.0)

    def test_off_hours_speed_up_mutation(self):
        day = self.vfs("FULL context-aware", hour=10)._interval()
        night = self.vfs("FULL context-aware", hour=2)._interval()
        self.assertLess(night, day)

    def test_trusted_backup_scan_is_killed_without_context(self):
        vfs = self.vfs("FULL adaptive", hour=2)
        with self.assertRaises(ProcessSuspended):
            backup_workload(vfs, self.files, random.Random(1))

    def test_trusted_backup_scan_is_allowed_with_context(self):
        vfs = self.vfs("FULL context-aware", hour=2)
        backup_workload(vfs, self.files, random.Random(1))
        self.assertNotIn("backup", vfs.suspended)
        self.assertTrue(any("trusted read of decoy" in msg for _, msg in vfs.events))

    def test_unknown_attacker_is_still_stopped(self):
        vfs = self.vfs("FULL context-aware", hour=2)
        result = Attacker(vfs, "dfs", seed=1).run()
        self.assertTrue(result["stopped"])

    def test_attacker_spoofing_trusted_tool_is_stopped_on_decoy_write(self):
        vfs = self.vfs("FULL context-aware", hour=2)
        result = Attacker(vfs, "dfs", seed=1, pid="backup").run()
        self.assertTrue(result["stopped"])
        self.assertIn("backup", vfs.detect_tick)


if __name__ == "__main__":
    unittest.main()
