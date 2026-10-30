"""A refused source binding cannot advertise completed migration observations."""
import json
from pathlib import Path
import tempfile
import unittest

from tools.qualify_hia_c_loop_migration import LoopMigrationTrial


class LoopMigrationQualificationTests(unittest.TestCase):
    def test_wrong_source_commit_retains_failure_without_positive_claim(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "refused"
            report = LoopMigrationTrial(output, clang="absent-loop-qualification-clang",
                                        source_sha="0" * 40).run()
            self.assertFalse(report["ok"])
            self.assertEqual(report["status"], "failed")
            self.assertIn("--source-sha", report["error"]["message"])
            self.assertFalse(report["claims"]["finite_capability_and_resource_observations"])
            self.assertNotIn("validation", report)
            self.assertEqual(json.loads((output / "qualification.json").read_text()), report)
            self.assertTrue((output / "invocations.jsonl").is_file())
            self.assertTrue((output / "processes.jsonl").is_file())


if __name__ == "__main__":
    unittest.main()
