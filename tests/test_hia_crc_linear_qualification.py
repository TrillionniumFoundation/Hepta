"""Failure accounting controls; these stubs never qualify native behavior."""
from __future__ import annotations

from contextlib import ExitStack
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from hepta.hia_crc_kernel import kernel
from hepta.hia_program import verify_program
from tools import qualify_hia_crc_linear as study


class _Bank:
    def __init__(self, release_error=None, release_complete=True):
        self.release_error = release_error
        self.release_complete = release_complete

    def prepare_trace(self, plan):
        return SimpleNamespace(sha256="b" * 64, expected=[])

    def run(self, trace, *, report):
        report.update(status="completed", prefix={"complete": True,
            "completed_requests": [{"calls": 9} for _ in range(18)]})

    def close(self):
        if self.release_error:
            raise self.release_error
        return {"complete": self.release_complete}


class CRCLinearQualificationTests(unittest.TestCase):
    def _run(self, *, bank=None, source_after_error=None, forced_expired=False):
        bank = bank or _Bank()

        def capture(path, clang, cc, report):
            report["source_bridge"] = {"kernel_sha256": verify_program(kernel()).sha256}

        def build(*args, **kwargs):
            kwargs["report"].update(candidates={name: {"native_differential": {"cases_executed": 64}}
                                                for name in study.LABELS})
            return bank

        class NoEarlyDeadline:
            # Fault injection isolates the mandatory final deadline check.
            def __init__(self, *args):
                pass

            def stage(self, label, ledger, operation):
                return study.measured(label, ledger, operation)

        with tempfile.TemporaryDirectory() as temporary, ExitStack() as patches:
            patches.enter_context(patch.object(study, "source_state", side_effect=[{"head": "a" * 40},
                source_after_error if source_after_error else {"head": "a" * 40}]))
            patches.enter_context(patch.object(study, "tool_state", return_value={"fixed": "tool"}))
            patches.enter_context(patch.object(study, "_capture_and_compare", side_effect=capture))
            patches.enter_context(patch.object(study, "build_bank", side_effect=build))
            patches.enter_context(patch.object(study, "disassembly", return_value={"stub": True}))
            if forced_expired:
                patches.enter_context(patch.object(study, "EpisodeBudget", NoEarlyDeadline))
                patches.enter_context(patch.object(study, "BUDGET_NS", 1))
            out = Path(temporary) / "result"
            result = study.qualify(output=out, expected_head="a" * 40, clang="unused", cc="unused", objdump="unused")
            stored = json.loads((out / "RESULT.json").read_bytes())
            self.assertEqual(stored, result)
            self.assertTrue((out / "NATIVE.json").is_file())
            self.assertEqual(result["actual_counts"]["finite_kernel_calls"], 162)
            self.assertEqual(result["actual_counts"]["native_preparation_differential_cases"], 384)
            self.assertTrue(all(type(row["wall_ns"]) is int and row["wall_ns"] >= 0 for row in result["ledger"]))
            self.assertFalse(result["claims"]["performance_qualified"])
            self.assertFalse(result["claims"]["economic_study_executed"])
            return result

    def test_close_exception_preserves_acquired_counts_and_costs(self):
        result = self._run(bank=_Bank(release_error=RuntimeError("injected close uncertainty")))
        self.assertFalse(result["qualified"])
        self.assertEqual(result["status"], "failed")
        self.assertEqual([r["stage"] for r in result["errors"]], ["bank.close"])

    def test_false_release_cannot_grant_qualification(self):
        result = self._run(bank=_Bank(release_complete=False))
        self.assertFalse(result["qualified"])
        self.assertFalse(result["release"]["complete"])

    def test_final_source_file_failure_retains_observations_and_report(self):
        result = self._run(source_after_error=FileNotFoundError("injected removed source"))
        self.assertFalse(result["qualified"])
        self.assertEqual([r["stage"] for r in result["errors"]], ["source.after"])

    def test_cleanup_and_first_result_write_cannot_escape_deadline(self):
        result = self._run(forced_expired=True)
        self.assertFalse(result["qualified"])
        self.assertEqual({r["stage"] for r in result["errors"]}, {"deadline", "result.deadline"})
        self.assertGreater(result["wall_through_first_result_write_ns"], 1)


if __name__ == "__main__":
    unittest.main()
