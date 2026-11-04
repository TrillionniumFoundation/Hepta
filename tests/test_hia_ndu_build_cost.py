"""Real process/log accounting controls; child commands are compiler fixtures.

These tests do not claim a Rust compilation. A real source-preserving rebuild
separately supplies native build observations for the actual adapter.
"""
from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest

from tools.build_hia_ndu_bridge import _build_cost, _children_cpu_ns, _run_build_command
from tools.measure_hia_raw_model_cost import amortization, build_cost_observation


class NativeBuildCostTests(unittest.TestCase):
    def observed(self, root, code=0):
        root.mkdir()
        started, parent, children = time.monotonic_ns(), time.process_time_ns(), _children_cpu_ns()
        argv = [sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'out\\x00\\xff\\n'); "
                "sys.stderr.buffer.write(b'err\\x00\\xfe\\n'); raise SystemExit(" + str(code) + ")"]
        command = _run_build_command(argv, env=dict(os.environ), output=root)
        cost = _build_cost(started, parent, children, command, False, completed=code == 0)
        manifest = {"build_command": argv, "build_command_evidence": command, "build_cost": cost}
        receipt = root / "build-receipt.json"
        receipt.write_text(json.dumps(manifest))
        return manifest, receipt

    def test_actual_success_and_failure_keep_original_binary_streams(self):
        with tempfile.TemporaryDirectory() as directory:
            for code in (0, 17):
                with self.subTest(code=code):
                    manifest, receipt = self.observed(Path(directory) / str(code), code)
                    command = manifest["build_command_evidence"]
                    self.assertEqual(command["returncode"], code)
                    self.assertGreater(command["wall_ns"], 0)
                    self.assertGreaterEqual(manifest["build_cost"]["wall_ns"], command["wall_ns"])
                    for name, raw in (("stdout", b"out\x00\xff\n"), ("stderr", b"err\x00\xfe\n")):
                        row = command[name]
                        self.assertEqual((receipt.parent / row["path"]).read_bytes(), raw)
                        self.assertEqual(row["sha256"], sha256(raw).hexdigest())
                        self.assertEqual(row["bytes"], len(raw))
                    self.assertEqual(json.loads((receipt.parent / "command-evidence/cargo.json").read_text()), command)
                    if code:
                        with self.assertRaises(ValueError):
                            build_cost_observation(manifest, receipt)
                    else:
                        self.assertEqual(build_cost_observation(manifest, receipt)["wall_ns"],
                                         manifest["build_cost"]["wall_ns"])

    def test_launch_failure_keeps_evidence_and_cannot_be_success(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            started, parent, children = time.monotonic_ns(), time.process_time_ns(), _children_cpu_ns()
            argv = [str(root / "missing-cargo")]
            command = _run_build_command(argv, env=dict(os.environ), output=root)
            self.assertIsNone(command["returncode"])
            self.assertIn("FileNotFoundError", command["launch_error"])
            self.assertTrue((root / "command-evidence/cargo.json").is_file())
            manifest = {"build_command": argv, "build_command_evidence": command,
                        "build_cost": _build_cost(started, parent, children, command, False, completed=False)}
            with self.assertRaises(ValueError):
                build_cost_observation(manifest)

    def test_changed_stream_refuses_recorded_build_cost(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest, receipt = self.observed(Path(directory) / "build")
            build_cost_observation(manifest, receipt)
            (receipt.parent / "command-evidence/cargo.stdout").write_bytes(b"altered")
            with self.assertRaisesRegex(ValueError, "compiler stream changed"):
                build_cost_observation(manifest, receipt)

    def test_malformed_cost_never_becomes_observed_or_zero(self):
        with tempfile.TemporaryDirectory() as directory:
            original, receipt = self.observed(Path(directory) / "build")
            mutations = []
            for value in (True, False, 0, -1, 1.0, "12"):
                manifest = deepcopy(original)
                manifest["build_cost"]["wall_ns"] = value
                mutations.append(manifest)
            for field, value in (("completed", False), ("cargo_wall_ns", original["build_cost"]["wall_ns"] + 1),
                                 ("parent_cpu_ns", True), ("child_cpu_ns", -1), ("scope", None),
                                 ("fully_cold_machine_claim", True)):
                manifest = deepcopy(original)
                manifest["build_cost"][field] = value
                mutations.append(manifest)
            manifest = deepcopy(original)
            manifest["build_command_evidence"]["returncode"] = False
            mutations.append(manifest)
            manifest = deepcopy(original)
            manifest["build_command_evidence"]["stderr"]["bytes"] = True
            mutations.append(manifest)
            manifest = deepcopy(original)
            manifest.pop("build_command")
            manifest["build_command_evidence"].pop("argv")
            mutations.append(manifest)
            for index, manifest in enumerate(mutations):
                with self.subTest(index=index), self.assertRaises(ValueError):
                    build_cost_observation(manifest, receipt)

    def test_unknown_build_stays_unknown_and_observed_build_is_charged_once(self):
        totals = {mode: {"mean_ns": 7, "sum_ns": 14} for mode in ("exact_dp", "ndu")}
        for manifest in ({}, {"build_cost": None}):
            observed = build_cost_observation(manifest)
            self.assertIsNone(observed["wall_ns"])
            report = amortization(observed["wall_ns"], totals)
            self.assertIsNone(report["per_call_ns"]["1"]["exact_dp"])
            self.assertIsNone(report["standalone_arm_build_plus_calls_ns"]["ndu"])
        report = amortization(23, totals)
        self.assertEqual(report["per_call_ns"]["1"], {"exact_dp": 30, "ndu": 30})
        self.assertAlmostEqual(report["per_call_ns"]["10"]["ndu"], 9.3)
        self.assertEqual(report["standalone_arm_build_plus_calls_ns"], {"exact_dp": 37, "ndu": 37})
        self.assertFalse(report["full_lifecycle_cost_complete"])
        self.assertFalse(report["machine_cold_claim"])


if __name__ == "__main__":
    unittest.main()
