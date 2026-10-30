"""The separate u32 batch gate cannot borrow checksum-session authority."""
from __future__ import annotations

import copy
from base64 import b64decode
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from hepta import hia_guarded_batch as gb
from hepta.hia_program import verify_program
from hepta.hia_program_runtime import HIAProgramTrap, execute_program


def observations():
    protocol = gb.load_protocol()
    rows = []
    for module in protocol["modules"]:
        for phase in ("training", "validation"):
            for seed in protocol[phase + "_seeds"]:
                for action in protocol["actions"]:
                    rows.append({"module": module["id"], "phase": phase, "seed": seed,
                        "candidate": action, "calls": protocol["iterations_per_batch"],
                        "elapsed_ns": 1_000_000 if action == "baseline" else 500_000,
                        "outer_wall_ns": 1_100_000 if action == "baseline" else 600_000})
    code = {action: {"sha256": str(i) * 64} for i, action in enumerate(protocol["actions"])}
    return protocol, rows, code


class GuardedBatchTests(unittest.TestCase):
    def test_protocol_hash_is_frozen_before_any_observation(self):
        protocol = gb.load_protocol()
        self.assertEqual(protocol["expected_calls_per_module"], 100_000_000)
        self.assertEqual(protocol["max_selected_specializations"], 1)
        self.assertTrue(set(protocol["training_seeds"]).isdisjoint(protocol["validation_seeds"]))
        with patch.object(Path, "read_bytes", return_value=b"{}"):
            with self.assertRaisesRegex(gb.GuardedBatchRejected, "protocol bytes changed"):
                gb.load_protocol()

    def test_core_and_independent_formula_cover_guard_misses_and_first_traps(self):
        for label, program in gb.candidates().items():
            gb.checked_profile(program)
            for x in (0, 1, 7, 8, 9, (1 << 31), gb.MASK32):
                for denominator in (0, 1, 2, 8, 10, 251, gb.MASK32):
                    with self.subTest(candidate=label, x=x, d=denominator):
                        try:
                            row = execute_program(program, "calculate", [x, denominator], max_steps=100)
                            observed = {"status": row["status"], "values": row["values"]}
                        except HIAProgramTrap as error:
                            observed = {"status": "trapped", "code": error.code}
                        self.assertEqual(observed, gb.formula(x, denominator))

    def test_old_checksum_abi_and_widened_return_are_rejected(self):
        for parameter_types in (("u64", "u64"), ("usize", "u32")):
            program = gb.workload()
            # A separate valid scalar program cannot pass on same arity alone.
            fn = program["functions"][0]
            fn["params"] = [{"name": "x", "type": parameter_types[0]},
                            {"name": "denominator", "type": parameter_types[1]}]
            fn["blocks"][0]["params"] = copy.deepcopy(fn["params"])
            fn["blocks"][0]["ops"] = []
            fn["blocks"][0]["term"]["values"] = ["x"]
            fn["returns"] = [parameter_types[0]]
            verify_program(program)
            with self.assertRaisesRegex(gb.GuardedBatchRejected, "only calculate"):
                gb.checked_profile(program)

    def test_unknown_or_refuted_proof_never_reaches_emitter_or_compiler(self):
        for status in ("unknown", "disproved"):
            report = {}
            with patch.object(gb, "validate_translation", return_value={"status": status}):
                with patch.object(gb, "emit_program_llvm") as emit:
                    with self.assertRaisesRegex(gb.GuardedBatchRejected, "first-trap proof did not pass"):
                        gb.build_candidate(gb.workload(), "unused.so", clang="unused", report=report)
                    emit.assert_not_called()
            self.assertGreater(report["preparation_wall_ns"], 0)
            self.assertEqual(report["translation"]["status"], status)

    def test_exact_bounded_arguments_refuse_bool_negative_and_overrun(self):
        for values in ((True, 0, 1, 8), (0, 0, 1, 8), (gb.MAX_ITERATIONS + 1, 0, 1, 8),
                       (1, 100001, 1, 8), (1, 0, -1, 8), (1, 0, 1 << 32, 8), (1, 0, 1, 9)):
            with self.subTest(values=values), self.assertRaises(gb.GuardedBatchRejected):
                gb.validate_batch(*values)

    def test_immutable_abi_checksum_record_rejects_duplicates_and_forged_checksum(self):
        pin = {"path": "/not-executed", "sha256": "a" * 64}
        row = {"calls": 1, "checksum": 5, "close_ns": 1, "cpu_ns": 1,
               "elapsed_ns": 1, "hot": 8, "load_ns": 1, "seed": 1}
        for raw in (gb.wire({**row, "checksum": 6}) + b"\n",
                    gb.wire(row)[:-1] + b',"checksum":5}\n',
                    gb.wire({**row, "cpu_ns": True}) + b"\n"):
            report = {}
            with patch.object(gb, "run_bounded", return_value=SimpleNamespace(
                    returncode=0, stdout=raw.decode(), stderr="")):
                with self.assertRaises(gb.GuardedBatchRejected):
                    gb.sample(pin, pin, calls=1, warmup=0, seed=1, hot=8, expected=5, report=report)
            self.assertEqual(report["stdout"].encode(), raw)
            self.assertGreater(report["outer_wall_ns"], 0)

    def test_failed_capture_keeps_exact_prefixes_totals_and_actual_cost(self):
        from hepta.clang_capture import CaptureFailure, CaptureRejected
        error = CaptureRejected("E_CAPTURE_OUTPUT_SIZE", "over limit")
        error.capture = CaptureFailure(("sealed-driver", "sealed-image"), -9, b"one\r\n\xff", b"error\x00", 50_000, 10_000)
        error.capture_error = "cleanup diagnostic"
        pin, report = {"path": "not-executed", "sha256": "a" * 64}, {}
        with patch.object(gb, "run_bounded", side_effect=error):
            with self.assertRaises(CaptureRejected):
                gb.sample(pin, pin, calls=1, warmup=0, seed=1, hot=8, expected=5, report=report)
        retained = report["capture_failure"]
        self.assertEqual(b64decode(retained["stdout_prefix_base64"]), b"one\r\n\xff")
        self.assertEqual(b64decode(retained["stderr_prefix_base64"]), b"error\x00")
        self.assertEqual(retained["stdout_total_bytes"], 50_000)
        self.assertEqual(retained["stderr_total_bytes"], 10_000)
        self.assertEqual(retained["capture_error"], "cleanup diagnostic")
        self.assertEqual(report["error"]["code"], "E_CAPTURE_OUTPUT_SIZE")
        self.assertGreater(report["outer_wall_ns"], 0)

    def test_normalized_newline_cannot_forge_canonical_native_bytes(self):
        from hepta.clang_capture import CaptureResult
        pin, report = {"path": "not-executed", "sha256": "a" * 64}, {}
        value = {"calls": 1, "checksum": 5, "close_ns": 1, "cpu_ns": 1,
                 "elapsed_ns": 1, "hot": 8, "load_ns": 1, "seed": 1}
        raw = gb.wire(value) + b"\r\n"
        result = CaptureResult(0, (gb.wire(value) + b"\n").decode(), "", raw, b"")
        with patch.object(gb, "run_bounded", return_value=result):
            with self.assertRaisesRegex(gb.GuardedBatchRejected, "malformed"):
                gb.sample(pin, pin, calls=1, warmup=0, seed=1, hot=8, expected=5, report=report)
        self.assertEqual(b64decode(report["raw_stdout_base64"]), raw)

    def test_identical_machine_code_and_total_cost_each_prevent_positive_gate(self):
        protocol, samples, code = observations()
        result = gb.assess_opportunities(protocol, samples, code, 10)
        self.assertTrue(result["opportunity_gate_passed"])
        self.assertFalse(result["NDU_gain_established"])
        for candidate in protocol["actions"][1:]:
            code[candidate] = code["baseline"]
        self.assertFalse(gb.assess_opportunities(protocol, samples, code, 10)["opportunity_gate_passed"])
        _, _, code = observations()
        result = gb.assess_opportunities(protocol, samples, code, 300_000_000)
        self.assertFalse(result["opportunity_gate_passed"])
        self.assertEqual(result["status"], "no-economic-opportunity")

    def test_validation_regression_missing_or_duplicate_sample_cannot_be_trimmed(self):
        protocol, samples, code = observations()
        damaged = copy.deepcopy(samples)
        next(s for s in damaged if s["module"] == "hot8" and s["phase"] == "validation"
             and s["candidate"] == "guard_denominator_8")["outer_wall_ns"] = 2_000_000
        self.assertFalse(gb.assess_opportunities(protocol, damaged, code, 10)["opportunity_gate_passed"])
        for bad in (samples[:-1], samples + [samples[0]], samples[:-1] + [samples[0]]):
            with self.assertRaises(gb.GuardedBatchRejected):
                gb.assess_opportunities(protocol, bad, code, 10)

    def test_faster_inner_kernel_with_slower_future_batch_cannot_pass(self):
        protocol, samples, code = observations()
        for row in samples:
            row["elapsed_ns"] = 4_000_000 if row["candidate"] == "baseline" else 1_000_000
            row["outer_wall_ns"] = 5_000_000 if row["candidate"] == "baseline" else 6_000_000
        # The actual 600ms qualification cost also covers all 476ms of child
        # observations; future 500-batch deployment must pay its slower driver.
        self.assertLessEqual(sum(s["outer_wall_ns"] for s in samples), 600_000_000)
        result = gb.assess_opportunities(protocol, samples, code, 600_000_000)
        self.assertEqual(result["future_batches_per_module"], 500)
        self.assertFalse(result["opportunity_gate_passed"])
        for module in result["module_opportunities"]:
            for phase in module["phases"].values():
                self.assertEqual(phase["kernel_saved_batch_ns_diagnostic"], 3_000_000)
                self.assertEqual(phase["prospective_savings_ns"], -500_000_000)
                self.assertEqual(phase["net_savings_ns"], -1_100_000_000)

    def test_demand_cannot_be_replaced_after_observation(self):
        protocol, samples, code = observations()
        protocol["expected_calls_per_module"] *= 10
        with self.assertRaisesRegex(gb.GuardedBatchRejected, "frozen protocol"):
            gb.assess_opportunities(protocol, samples, code, 10)

    def test_uncertain_descriptor_close_is_not_retried_or_certified(self):
        data, rows = b"bytes", []
        release = SimpleNamespace(attempt=lambda: {"native_release_succeeded": False,
                                                  "native_retry_permitted": False})
        with patch.object(gb, "_pin_native_artifact", return_value=(data, (), 100)):
            with patch.object(gb, "_NativeRelease", return_value=release):
                with self.assertRaisesRegex(gb.GuardedBatchRejected, "descriptor close is uncertain"):
                    with gb.pinned("not-opened", gb.sha256(data).hexdigest(), releases=rows):
                        pass
        self.assertEqual(len(rows), 1)
        self.assertFalse(rows[0]["native_release_succeeded"])

    def test_qualification_requires_exact_clean_source_before_native_work(self):
        from tools import qualify_hia_guarded_opportunity as tool
        with tempfile.TemporaryDirectory() as temporary:
            for label, source in (("wrong_head", {"head": "b" * 40, "status": ""}),
                                  ("dirty", {"head": "a" * 40, "status": " M source.py\n"})):
                with self.subTest(source=label), patch.object(tool, "_source_state", return_value=source):
                    with patch.object(tool, "_run") as native:
                        result = tool.qualify(clang="not-executed", workdir=Path(temporary) / label,
                                              expected_source="a" * 40)
                        native.assert_not_called()
                        self.assertFalse(result["qualified"])
                        self.assertEqual(result["status"], "failed")
                        self.assertIn("clean source", result["error"]["message"])

    def test_output_inside_source_and_short_expected_commit_refuse(self):
        from tools import qualify_hia_guarded_opportunity as tool
        with patch.object(tool, "_run") as native:
            with self.assertRaisesRegex(gb.GuardedBatchRejected, "outside the source tree"):
                tool.qualify(clang="not-executed", workdir=tool.ROOT / "forbidden-guarded-output",
                             expected_source="a" * 40)
            with self.assertRaisesRegex(gb.GuardedBatchRejected, "full lowercase commit SHA"):
                tool.qualify(clang="not-executed", workdir="unused", expected_source="a" * 7)
            native.assert_not_called()

    def test_final_source_or_budget_failure_revokes_all_opportunity_eligibility(self):
        from tools import qualify_hia_guarded_opportunity as tool
        for failure in ("source", "budget"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                clock, reads = [0], [0]
                state = {"head": "a" * 40, "tree": "b" * 40, "status": "", "files": {"core.py": "c" * 64}}
                def source_state():
                    reads[0] += 1
                    if reads[0] == 2:
                        if failure == "source":
                            raise ValueError("raw HEAD blob changed")
                        clock[0] = 60_000_000_001
                    return copy.deepcopy(state)
                def run(clang, directory, report, started):
                    _, report["samples"], report["exported_code"] = observations()
                    # Even after 60s of charged work this fabricated corpus
                    # has +35s/module arithmetic value. Neither final source
                    # drift nor deadline failure may leave an eligible flag.
                    for row in report["samples"]:
                        row["elapsed_ns"] = 10_000_000 if row["candidate"] == "baseline" else 1000
                        row["outer_wall_ns"] = 200_000_000 if row["candidate"] == "baseline" else 10_000_000
                with patch.object(tool, "_source_state", side_effect=source_state), \
                     patch.object(tool, "_sources", return_value={"module": "fixed"}), \
                     patch.object(tool, "_run", side_effect=run), \
                     patch.object(tool.time, "monotonic_ns", side_effect=lambda: clock[0]):
                    result = tool.qualify(clang="not-executed", workdir=Path(temporary) / "out",
                                          expected_source="a" * 40)
                self.assertEqual(result["status"], "failed")
                self.assertFalse(result["qualified"])
                self.assertFalse(result["economics"]["opportunity_gate_passed"])
                self.assertFalse(result["economics"]["ndu_comparison_authorized_by_this_evidence"])
                self.assertEqual(result["economics"]["status"], "invalid_qualification_evidence")
                self.assertEqual(result["economics"]["qualification_denial"]["reason"], "complete_qualification_failed")
                self.assertTrue(all(phase["net_savings_ns"] > 0
                    for row in result["economics"]["module_opportunities"] for phase in row["phases"].values()))

    @unittest.skipUnless(importlib.util.find_spec("z3"), "actual Z3 required")
    def test_real_removed_guard_has_counterexample_and_cannot_compile(self):
        candidate = gb.candidates()["guard_denominator_8"]
        condition = candidate["functions"][0]["blocks"][0]["ops"][-1]
        condition["op"], condition["args"], condition["attrs"] = "const", [], {"value": True}
        verify_program(candidate)
        report = {}
        with patch.object(gb, "compile_program_llvm") as compiler:
            with self.assertRaisesRegex(gb.GuardedBatchRejected, "first-trap proof did not pass"):
                gb.build_candidate(candidate, "unused.so", clang="unused", report=report)
            compiler.assert_not_called()
        self.assertEqual(report["translation"]["status"], "disproved")
        self.assertIsNotNone(report["translation"]["counterexample"])


CLANG = os.environ.get("CLANG") or shutil.which("clang-20") or shutil.which("clang")
NATIVE = bool(CLANG and platform.system() == "Linux" and platform.machine().lower() in {"x86_64", "amd64"}
              and importlib.util.find_spec("z3"))


@unittest.skipUnless(NATIVE, "actual Linux x86-64 Clang20+, Z3 and seals required")
class GuardedBatchNativeTests(unittest.TestCase):
    def test_real_proofs_distinct_code_abi_traps_and_sealed_child_driver(self):
        # This is a correctness test with one-call batch observations. It is not
        # a run of the preregistered performance experiment or an opportunity win.
        with tempfile.TemporaryDirectory(prefix="hia-guarded-u32-") as temporary:
            root = Path(temporary)
            hashes, code = {}, {}
            for label, program in gb.candidates().items():
                report = {}
                hashes[label] = gb.build_candidate(program, root / (label + ".so"), clang=CLANG, report=report)
                self.assertEqual(report["translation"]["status"], "proved")
                self.assertEqual(report["translation"]["solver"]["timeout_ms"], gb.SOLVER_TIMEOUT_MS)
                self.assertEqual(report["lowering"]["status"], "verified")
                self.assertEqual(report["native_differential"]["cases_executed"], 14)
                self.assertEqual(report["native_differential"]["defined_traps_observed"], 2)
                code[label] = gb.export_code_identity((root / (label + ".so")).read_bytes())
            self.assertNotEqual(code["baseline"]["sha256"], code["guard_denominator_8"]["sha256"])
            self.assertNotEqual(code["baseline"]["sha256"], code["guard_denominator_10"]["sha256"])
            driver = gb.build_driver(root, clang=CLANG)
            releases = []
            with gb.pinned(driver["path"], driver["sha256"], releases=releases) as driver_pin:
                for label in hashes:
                    with gb.pinned(root / (label + ".so"), hashes[label], releases=releases) as library_pin:
                        # A mutable original pathname is not the execution source.
                        (root / (label + ".so")).write_bytes(b"replaced after sealing")
                        for hot in (8, 10):
                            result = gb.sample(driver_pin, library_pin, calls=1, warmup=0, seed=26701,
                                               hot=hot, expected=gb.expected_checksum(1, 26701, hot))
                            self.assertEqual(result["returncode"], 0)
                            self.assertEqual(result["checksum"], gb.formula(
                                (26701 * 1664525 + 1013904223) & gb.MASK32, hot)["values"][0])
            self.assertEqual(len(releases), 4)
            self.assertTrue(all(r["native_release_succeeded"] for r in releases))


if __name__ == "__main__":
    unittest.main()
