"""Reject stale or symlinked release evidence even after a zero-exit gate."""
import importlib.util
from pathlib import Path
import tempfile
import time
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "tools" / "release_check.py"
SPEC = importlib.util.spec_from_file_location("release_check_freshness", SOURCE)
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class FreshEvidenceTests(unittest.TestCase):
    def test_newly_written_evidence_is_accepted(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "report.json"
            p.write_text('{"status":"passed"}')
            before = module.evidence_state(p)
            time.sleep(.002)
            p.write_text('{"status":"passed","iteration":2}')
            self.assertEqual(module.require_fresh_evidence(p, before),
                             b'{"status":"passed","iteration":2}')

    def test_previous_pass_report_cannot_qualify_noop_producer(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "report.json"
            p.write_text('{"status":"passed"}')
            before = module.evidence_state(p)
            # A gate exits zero but did not write its expected evidence file.
            with self.assertRaisesRegex(ValueError, "E_STALE_GATE_EVIDENCE"):
                module.require_fresh_evidence(p, before)

    def test_missing_report_cannot_qualify_producer(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "missing.json"
            with self.assertRaisesRegex(ValueError, "E_STALE_GATE_EVIDENCE"):
                module.require_fresh_evidence(p, module.evidence_state(p))

    def test_symlink_report_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            target = root / "old.json"
            target.write_text('{"status":"passed"}')
            p = root / "report.json"
            p.symlink_to(target)
            with self.assertRaisesRegex(ValueError, "E_UNSAFE_GATE_EVIDENCE"):
                module.require_fresh_evidence(p, None)


if __name__ == "__main__":
    unittest.main()
