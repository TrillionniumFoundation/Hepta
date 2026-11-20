"""Two additional entries for all36 controls; no old gate is replaced."""
from __future__ import annotations
import os
from pathlib import Path
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/cold_native_transport_controls_v4.json"


class ColdNativeTransportControlsSourceTests(unittest.TestCase):
    def test_all_original36_definitions_and_complete_executable_input_inventory(self):
        from tools.hia_cold_native_transport_evidence import Captures, data_pin
        from tools.read_hia_cold_native_transport_controls import CORE_PINS, FIXTURE_PIN, NEW_INPUTS
        captured = Captures()
        fixture = captured.json(FIXTURE, FIXTURE_PIN)
        before = captured.json(ROOT / "tests/fixtures/cold_native_transport_controls_v3.json")
        gates = captured.json(ROOT / "tests/fixtures/cold_native_transport_original_gates_v3.json")
        self.assertEqual(fixture["original_CT36"], before["original_CT36"])
        self.assertEqual(fixture["ordered_ids"], ["CT-%02d" % index for index in range(1, 37)])
        self.assertEqual(len(fixture["public_cases"]), 75)
        self.assertEqual(len(fixture["policy_cases"]), 32)
        all_rows = fixture["public_cases"] + fixture["policy_cases"]
        self.assertEqual(set(row["id"] for row in all_rows), set(fixture["ordered_ids"]))
        self.assertEqual(len({row["subcase"] for row in all_rows}), 107)
        self.assertIsNone(fixture["expected_runtime_results"])
        self.assertTrue(all(row["expected_runtime_result"] is None for row in fixture["original_CT36"]))
        self.assertEqual(gates["original_method_count"], 44)
        self.assertEqual(len(before["handoff_controls"]), 8)
        self.assertEqual((gates["independent_reference_count"], gates["cold_phase_count"]), (17, 38))
        self.assertEqual((fixture["budgets"]["cold_inner_seconds"],
                          fixture["budgets"]["cold_cleanup_seconds"],
                          fixture["budgets"]["cold_outer_seconds"]), (180, 3, 240))
        for name, expected in CORE_PINS.items():
            self.assertEqual(data_pin(captured.raw(ROOT / name, expected)), expected)
        self.assertEqual(len(NEW_INPUTS), 7)
        for name in NEW_INPUTS:
            self.assertGreater(len(captured.raw(ROOT / name)), 0)
        for name, expected in gates["original_tests"].items():
            self.assertEqual(data_pin(captured.raw(ROOT / name, expected)), expected)
        for row in gates["original_observers"]:
            current = captured.raw(ROOT / row["path"])
            tail = row["selection_tail"].encode()
            self.assertTrue(current.endswith(tail))
            self.assertEqual(data_pin(current[:-len(tail)]), row["before"])
        captured.unchanged()


class ColdNativeTransportControlsNativeTests(unittest.TestCase):
    def test_all36_original_first_public_and_actual_policy_controls(self):
        from tools.hia_cold_native_transport_evidence import (
            Captures, clean_environment, run_owned, successful_exit, terminal_owned)
        manifest = os.environ.get("HEPTA_HIA_COLD_NATIVE_TRANSPORT_MANIFEST")
        root = os.environ.get("HEPTA_HIA_COLD_NATIVE_TRANSPORT_CT36_EVIDENCE")
        if not manifest or not root or os.environ.get("HEPTA_HIA_COLD_NATIVE_TRANSPORT_ALLOW_DEVELOPMENT") != "1":
            raise ValueError("one actual current build, explicit development and retained CT36 output are required")
        output = Path(root).resolve()
        output.mkdir(mode=0o700)
        environment = clean_environment()
        runtime = str(Path(sys.executable).resolve(strict=True))
        deadline = time.monotonic() + 1800
        command = [runtime, "-I", "-S", "-B",
                   str(ROOT / "tools/qualify_hia_cold_native_transport_controls.py"),
                   "--manifest", str(Path(manifest).resolve(strict=True)),
                   "--output", str(output / "controls")]
        result = run_owned(command, cwd=ROOT, directory=output / "owned", timeout_seconds=1800,
                           environment=environment, deadline=deadline)
        self.assertTrue(successful_exit(result), result)
        capture = Captures()
        terminal_owned(capture, output / "owned", seconds=1800, expected_argv=command, cwd=ROOT)
        read_command = [runtime, "-I", "-S", "-B",
                        str(ROOT / "tools/read_hia_cold_native_transport_controls.py"),
                        "--evidence", str(output / "controls"), "--output", str(output / "independent"),
                        "--owner", str(output / "owned")]
        if time.monotonic() >= deadline:
            raise AssertionError("complete original CT36 owner cap reached before independent readback")
        result = run_owned(read_command, cwd=ROOT, directory=output / "reader-owned",
                           timeout_seconds=60, environment=environment, deadline=deadline)
        self.assertTrue(successful_exit(result), result)
        terminal_owned(capture, output / "reader-owned", seconds=60, expected_argv=read_command, cwd=ROOT)
        report = capture.json(output / "independent/READBACK.json")
        self.assertEqual(report["status"], "CT36_CONTROL_ASSERTIONS_PASS")
        self.assertEqual(report["ordered_ids"], ["CT-%02d" % index for index in range(1, 37)])
        self.assertEqual((report["public_subcase_count"], report["policy_subcase_count"]), (75, 32))
        self.assertIs(report["raw_public_equivalence_proved"], False)
        self.assertIs(report["qualification_complete"], False)
        self.assertIs(report["whole_native"], False)
        item = report["complete_raw_differences"]
        capture.raw(item["path"], item["pin"])
        self.assertLess(time.monotonic(), deadline)
        capture.unchanged()


if __name__ == "__main__":
    unittest.main()
