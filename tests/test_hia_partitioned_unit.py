"""Real child processes and adversarial replay for the complete-ID collector."""
from contextlib import redirect_stdout
import copy
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

from tools.qualify_hia_unit import (CHILD_SCHEMA, MODULE_DEADLINE_SECONDS, canonical, digest,
                                    qualify, validate_module, validate_report)


class PartitionedUnitTests(unittest.TestCase):
    def test_replay_rejects_partial_duplicate_skipped_and_forged_execution(self):
        ids = ["test_control.Case.test_a", "test_control.Case.test_b"]
        row = {"module": "test_control", "returncode": 0,
               "stderr_text": "Ran 2 tests in 0.001s\n\nOK\n",
               "child": {"schema": CHILD_SCHEMA, "module": "test_control", "ok": True,
                         "status": "completed", "deadline_seconds": MODULE_DEADLINE_SECONDS,
                         "deadline_expired": False, "tests_run": 2, "failures": 0, "errors": 0,
                         "skipped": 0, "expected_failures": 0, "unexpected_successes": 0,
                         "discovered_ids": ids, "started_ids": ids, "finished_ids": ids}}
        self.assertTrue(validate_module(row, ids))
        mutations = [
            lambda value: value.update(returncode=1),
            lambda value: value.update(capture_error="E_CAPTURE_TIMEOUT"),
            lambda value: value.update(stderr_text="Ran 1 test in 0.001s\n\nOK\n"),
            lambda value: value["child"].update(started_ids=ids[:1]),
            lambda value: value["child"].update(finished_ids=[ids[0], ids[0]]),
            lambda value: value["child"].update(discovered_ids=ids + ["test_control.Case.test_c"]),
            lambda value: value["child"].update(skipped=1),
            lambda value: value["child"].update(expected_failures=1),
            lambda value: value["child"].update(deadline_expired=True),
            lambda value: value["child"].update(status="interrupted"),
            lambda value: value["child"].update(tests_run=True),
        ]
        for change in mutations:
            value = copy.deepcopy(row)
            change(value)
            self.assertFalse(validate_module(value, ids), repr(value))

    def run_fixture(self, modules):
        temporary = tempfile.TemporaryDirectory(prefix="hia-unit-protocol-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        tests = root / "tests"
        tests.mkdir()
        for name, body in modules.items():
            (tests / (name + ".py")).write_text(body)
            self.addCleanup(sys.modules.pop, name, None)
        with redirect_stdout(io.StringIO()):
            report = qualify(root / "output", root=root, workers=2)
        return report, root / "output"

    def test_actual_two_module_execution_and_bound_logs_replay(self):
        report, directory = self.run_fixture({
            "test_protocol_actual_alpha": "import unittest\nclass C(unittest.TestCase):\n def test_a(self): self.assertEqual(2+2,4)\n",
            "test_protocol_actual_beta": "import unittest\nclass C(unittest.TestCase):\n def test_b(self): self.assertFalse(False)\n def test_c(self): self.assertTrue(True)\n",
        })
        self.assertTrue(report["ok"], report)
        self.assertEqual(report["reported_tests_run"], 3)
        expected_ids = list(report["discovered_ids"])
        self.assertEqual(validate_report(report, directory, expected_ids=expected_ids), 3)
        self.assertFalse(report["single_process_full_suite"])
        self.assertEqual(len(list(directory.glob("progress-*.json"))), 2)
        for field, value in (("reported_tests_run", 3000), ("passed_module_count", 30),
                             ("failed_modules", ["hidden"]), ("single_process_full_suite", True),
                             ("workers", True)):
            contradictory = copy.deepcopy(report)
            contradictory[field] = value
            with self.assertRaises(ValueError):
                validate_report(contradictory, directory, expected_ids=expected_ids)
        for field, value in (("passed", False), ("expected_ids", [])):
            contradictory = copy.deepcopy(report)
            contradictory["modules"][0][field] = value
            with self.assertRaises(ValueError):
                validate_report(contradictory, directory, expected_ids=expected_ids)
        # A same-success-looking child with fewer tests cannot be substituted.
        forged = copy.deepcopy(report)
        forged["discovered_ids"].pop()
        forged["id_inventory_sha256"] = digest(canonical(sorted(forged["discovered_ids"])))
        with self.assertRaises(ValueError):
            validate_report(forged, directory, expected_ids=expected_ids)
        # Dropping a whole module, all its IDs and every count/hash together
        # must still fail against the independently frozen discovery set.
        omitted = copy.deepcopy(report)
        removed = omitted["modules"].pop()
        omitted["discovered_ids"] = [value for value in omitted["discovered_ids"]
                                     if not value.startswith(removed["module"] + ".")]
        omitted["id_inventory_sha256"] = digest(canonical(omitted["discovered_ids"]))
        omitted["expected_module_count"] -= 1
        omitted["completed_module_count"] -= 1
        omitted["passed_module_count"] -= 1
        omitted["reported_tests_run"] -= removed["child"]["tests_run"]
        with self.assertRaisesRegex(ValueError, "independent discovery"):
            validate_report(omitted, directory, expected_ids=expected_ids)
        module = report["modules"][0]
        (directory / module["stderr"]["path"]).write_text("Ran 3 tests in 0.001s\n\nOK\n")
        with self.assertRaisesRegex(ValueError, "bytes changed"):
            validate_report(report, directory, expected_ids=expected_ids)

    def test_duplicate_and_nonfinite_child_receipts_are_refused_even_if_rehashed(self):
        report, directory = self.run_fixture({
            "test_protocol_actual_json": "import unittest\nclass C(unittest.TestCase):\n def test_a(self): self.assertTrue(True)\n"})
        self.assertTrue(report["ok"])
        original = report["modules"][0]
        path = directory / original["child_receipt"]["path"]
        for suffix in (', "ok":true}', ', "untrusted":NaN}'):
            raw = json.dumps(original["child"])[:-1].encode() + suffix.encode()
            path.write_bytes(raw)
            forged = copy.deepcopy(report)
            forged["modules"][0]["child_receipt"].update(sha256=digest(raw), bytes=len(raw))
            with self.assertRaisesRegex(ValueError, "Duplicate|Nonfinite"):
                validate_report(forged, directory, expected_ids=report["discovered_ids"])

    def test_skip_failure_and_setup_class_error_stay_in_completed_matrix(self):
        report, directory = self.run_fixture({
            "test_protocol_actual_skip": "import unittest\nclass C(unittest.TestCase):\n @unittest.skip('negative control')\n def test_a(self): pass\n",
            "test_protocol_actual_failure": "import unittest\nclass C(unittest.TestCase):\n def test_a(self): self.fail('retained negative control')\n",
            "test_protocol_actual_setup": "import unittest\nclass C(unittest.TestCase):\n @classmethod\n def setUpClass(cls): raise RuntimeError('setup negative')\n def test_a(self): pass\n",
        })
        self.assertFalse(report["ok"])
        self.assertEqual(report["status"], "completed")
        self.assertEqual(report["completed_module_count"], 3)
        self.assertEqual(len(report["failed_modules"]), 3)
        self.assertTrue(all(not row["passed"] for row in report["modules"]))
        self.assertEqual(json.loads((directory / "qualification.json").read_text()), report)
        with self.assertRaises(ValueError):
            validate_report(report, directory, expected_ids=report["discovered_ids"])

    def test_previous_output_is_preserved_and_success_flags_are_insufficient(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "existing"
            path.mkdir()
            marker = path / "evidence"
            marker.write_text("previous evidence")
            with self.assertRaises(FileExistsError):
                qualify(path)
            self.assertEqual(marker.read_text(), "previous evidence")
            with self.assertRaises(ValueError):
                validate_report({"schema": "hepta.hia.partitioned-unit-qualification.v1", "ok": True,
                                 "status": "completed", "modules": []}, path,
                                expected_ids=["test_control.Case.test_a"])


if __name__ == "__main__":
    unittest.main()
