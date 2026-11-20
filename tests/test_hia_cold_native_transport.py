"""Independent original-source/profile gates and actual atomic-handoff controls.

No old test is replaced. New controls do not stand for the original 44 methods,
the full 17 references/38 phases, or arbitrary Python provider equivalence.
"""
from __future__ import annotations
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
GATES = ROOT / "tests/fixtures/cold_native_transport_original_gates_v3.json"
CONTROLS = ROOT / "tests/fixtures/cold_native_transport_controls_v3.json"


class ColdNativeTransportSourceTests(unittest.TestCase):
    def test_exact_original_observers_and_complete_original_44_ids(self):
        from tools.hia_cold_native_transport_evidence import regular_bytes, parse
        from tools.run_hia_unittest_gate import load_declared_suite
        plan = parse(regular_bytes(GATES))
        self.assertEqual(plan["original_method_count"], 44)
        for name, expected in plan["original_tests"].items():
            raw = regular_bytes(ROOT / name)
            self.assertEqual({"bytes": len(raw), "sha256": sha256(raw).hexdigest()}, expected)
        for row in plan["original_observers"]:
            raw = regular_bytes(ROOT / row["path"])
            tail = row["selection_tail"].encode()
            self.assertTrue(raw.endswith(tail))
            before = raw[:-len(tail)]
            self.assertEqual({"bytes": len(before), "sha256": sha256(before).hexdigest()}, row["before"])
            original = row["execute_source"].encode()
            self.assertEqual(before.count(original), 1)
            self.assertEqual({"bytes": len(original), "sha256": sha256(original).hexdigest()}, row["execute"])
        suite, actual = load_declared_suite(plan["original_modules"])
        self.assertEqual(list(actual), plan["original_method_ids"])
        self.assertEqual(suite.countTestCases(), 44)
        self.assertEqual(plan["cold_phase_count"], 38)
        self.assertEqual(plan["independent_reference_count"], 17)
        self.assertEqual(plan["original_caps"]["cold_seconds"], 180)
        self.assertEqual(plan["original_caps"]["cleanup_seconds"], 3)

    def test_actual_generated_policy_retains_complete_original_profile_limits(self):
        from tools.generate_hia_cold_native_transport import document
        from hepta.hia_agent_assembly import assemble_program, render_assembly
        raw = (ROOT / "examples/hia_bootstrap/cold_native_transport.hepta").read_bytes()
        self.assertEqual(render_assembly(document()).encode(), raw)
        value = assemble_program(raw).as_dict()
        functions = value["functions"]
        self.assertLessEqual(len(functions), 128)
        self.assertLessEqual(sum(len(fn["blocks"]) for fn in functions), 1536)
        self.assertLessEqual(sum(len(block["ops"]) for fn in functions for block in fn["blocks"]), 8192)
        self.assertLessEqual(max(len(fn["blocks"]) for fn in functions), 256)
        self.assertLessEqual(max(len(block["params"]) for fn in functions for block in fn["blocks"]), 16)
        self.assertEqual(value["schema"], "hepta.hia.program.v8")


class ColdNativeTransportHandoffTests(unittest.TestCase):
    def test_all_eight_actual_atomic_handoff_controls(self):
        from tools.hia_cold_native_transport_bridge import SELECTOR, DEVELOPMENT, _Captured
        from tools.hia_cold_native_transport_evidence import (Captures, data_pin, parse,
            regular_bytes, run_owned, successful_exit, terminal_owned)
        path = os.environ.get(SELECTOR)
        if not path or os.environ.get(DEVELOPMENT) != "1":
            raise ValueError("explicit current R3 build and development scope are required")
        captured = _Captured(path)
        item = captured.value["handoff_controls"]
        executable = Path(item["path"]).resolve(strict=True)
        raw = regular_bytes(executable)
        self.assertEqual(data_pin(raw), item["pin"])
        cases = parse(regular_bytes(CONTROLS))["handoff_controls"]
        evidence = os.environ.get("HEPTA_HIA_COLD_NATIVE_TRANSPORT_HANDOFF_EVIDENCE")
        if not evidence:
            raise ValueError("a new retained control evidence directory is required")
        output = Path(evidence).resolve()
        output.mkdir(mode=0o700)
        report_path = output / "controls.json"
        command = [str(executable), sys.executable, str(report_path)]
        result = run_owned(command, cwd=ROOT, directory=output / "owned",
                           timeout_seconds=60, environment=dict(os.environ))
        self.assertTrue(successful_exit(result), result)
        read = Captures()
        command_data, actual_result = terminal_owned(
            read, output / "owned", seconds=60, expected_argv=command, cwd=ROOT)
        report = read.json(report_path)
        self.assertEqual(report["schema"], "hepta.cold-native-transport.handoff-controls.r3")
        self.assertEqual(report["planned"], 8)
        self.assertEqual([row["id"] for row in report["controls"]], [row["id"] for row in cases])
        self.assertEqual(len(report["controls"]), 8)
        for row, expected in zip(report["controls"], cases):
            self.assertIs(row["passed"], True, row)
            self.assertIs(type(row["handoff_return"]), int)
            self.assertEqual(row["handoff_return"], expected["expected_return"])
            self.assertIs(row["actual_pending"], expected["expected_pending"])
            self.assertEqual(row["failure_line"], 0)
        for index in (0, 1, 4, 5):
            self.assertIs(report["controls"][index]["real_number_reuse_checked"], True)
        self.assertEqual(report["status"], "CONTROLS_PASS")
        self.assertIs(report["whole_native"], False)
        self.assertEqual(regular_bytes(executable), raw)
        captured.unchanged()
        read.unchanged()
        # This is an additional exact raw control proof, not a replacement for
        # any original product/worker/phase qualification.
        (output / "readback.json").write_text(json.dumps({
            "scope": report["scope"], "controls": [row["id"] for row in cases],
            "consumed": read.pins(), "source_stable": True,
            "whole_native": False, "qualification_complete": False,
        }, sort_keys=True, indent=2) + "\n")


if __name__ == "__main__":
    unittest.main()
