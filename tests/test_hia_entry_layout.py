"""Entry outlining must preserve complete CFGs, traps, initialization and provenance."""
from copy import deepcopy
from dataclasses import replace
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_entry_layout import LAYOUT, entry_plan
from hepta.hia_program import verify_program
from hepta.hia_program_source import lower_source
from hepta.hia_program_llvm import (
    HIAProgramLLVMRejected, TARGET_AARCH64, build_program_native,
    compile_program_llvm, emit_program_llvm,
)
from hepta.hia_reduction import propose_reduction_pipeline, reduction_program

ROOT = Path(__file__).resolve().parents[1]


def trap_example(template):
    data = deepcopy(template)
    function = data["functions"][0]
    function["params"] = [{"name": "n", "type": "usize"}, {"name": "seed", "type": "u32"}]
    function["entry"] = "guard"
    function["blocks"] = [
        {"id": "guard", "params": deepcopy(function["params"]),
         "ops": [
             {"op": "const", "args": [], "out": [{"name": "bound", "type": "usize"}], "attrs": {"value": 7}},
             {"op": "compare.le", "args": ["n", "bound"], "out": [{"name": "choose", "type": "bool"}], "attrs": {}},
         ],
         "term": {"op": "branch", "cond": "choose",
                  "then": {"target": "fast", "args": ["n", "seed"]},
                  "else": {"target": "slow", "args": ["n", "seed"]}}},
        {"id": "fast", "params": [{"name": "fast_n", "type": "usize"}, {"name": "fast_seed", "type": "u32"}],
         "ops": [
             {"op": "const", "args": [], "out": [{"name": "one", "type": "u64"}], "attrs": {"value": 1}},
             {"op": "int.cast", "args": ["fast_n"], "out": [{"name": "denominator", "type": "u64"}], "attrs": {"mode": "wrap"}},
             {"op": "int.div.checked", "args": ["one", "denominator"], "out": [{"name": "quotient", "type": "u64"}], "attrs": {}},
         ], "term": {"op": "ret", "values": ["quotient"]}},
        {"id": "slow", "params": [{"name": "slow_n", "type": "usize"}, {"name": "slow_seed", "type": "u32"}],
         "ops": [{"op": "int.cast", "args": ["slow_seed"], "out": [{"name": "fallback", "type": "u64"}], "attrs": {"mode": "wrap"}}],
         "term": {"op": "ret", "values": ["fallback"]}},
    ]
    return verify_program(data)


class EntryLayoutTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = lower_source((ROOT / "benchmarks/hia_reduction_release/linear.hepta").read_text())
        cls.reduced = reduction_program(
            cls.original, propose_reduction_pipeline(cls.original, include_induction=True))
        cls.function = cls.reduced.as_dict()["functions"][0]
        cls.example = trap_example(cls.original.as_dict())

    def test_complete_disjoint_components_preserve_every_original_operation(self):
        plan = entry_plan(self.function)
        self.assertIsNotNone(plan)
        actual = {b["id"]: b for child in plan["components"] for b in child["blocks"]}
        expected = {b["id"]: b for b in self.function["blocks"] if b["id"] != self.function["entry"]}
        self.assertEqual(actual, expected)
        self.assertEqual(sum(len(c["blocks"]) for c in plan["components"]), len(expected))
        self.assertEqual(sum(plan["component_operation_counts"]) + 2, plan["operation_count"])
        self.assertEqual(plan["maximum"], (2**64 - 1) // 255)

    def test_empty_dispatch_identity_is_valid_for_all_unsigned_machine_words(self):
        import z3
        n, bound = z3.BitVecs("entry_length entry_bound", 64)
        solver = z3.Solver()
        solver.set(timeout=2000)
        emitted_length = z3.If(n == 0, z3.BitVecVal(0, 64), n)
        emitted_fast = z3.Or(n == 0, z3.ULE(n, bound))
        solver.add(z3.Or(emitted_length != n, emitted_fast != z3.ULE(n, bound)))
        self.assertEqual(solver.check(), z3.unsat)

    def test_original_initialization_decision_is_inherited(self):
        from hepta import hia_program_llvm as native
        entry = self.function["entry"]
        # A separated branch might appear more permissive; the original
        # whole-function decision must remain authoritative for both helpers.
        with patch.object(native, "_can_elide_zero_initialization",
                          side_effect=lambda function: function["entry"] != entry):
            text = emit_program_llvm(self.reduced, layout=LAYOUT).text
        self.assertIn("i1 true)", text)
        self.assertNotIn("i1 false)", text)

    def test_unsupported_guard_and_transport_shapes_do_not_qualify(self):
        mutants = []
        f = deepcopy(self.function); f["blocks"][0]["ops"][1]["op"] = "compare.lt"; mutants.append(f)
        f = deepcopy(self.function); f["blocks"][0]["ops"][1]["args"].reverse(); mutants.append(f)
        f = deepcopy(self.function); f["blocks"][0]["term"]["then"]["args"].reverse(); mutants.append(f)
        f = deepcopy(self.function); f["blocks"][0]["term"]["else"]["target"] = f["blocks"][0]["term"]["then"]["target"]; mutants.append(f)
        f = deepcopy(self.function); f["blocks"][0]["ops"][0]["attrs"]["value"] = True; mutants.append(f)
        f = deepcopy(self.function); f["blocks"][0]["ops"].append(deepcopy(f["blocks"][0]["ops"][0])); mutants.append(f)
        for index, f in enumerate(mutants):
            with self.subTest(mutation=index):
                self.assertIsNone(entry_plan(f))

    def test_backedge_into_component_entry_is_refused(self):
        f = self.example.as_dict()["functions"][0]
        root = f["blocks"][1]
        root["term"] = {"op": "jump", "target": root["id"], "args": [p["name"] for p in root["params"]]}
        self.assertIsNone(entry_plan(f))

    def test_unreachable_extra_block_is_not_silently_omitted(self):
        f = deepcopy(self.function)
        extra = deepcopy(f["blocks"][-1]); extra["id"] = "extra_unaccounted_block"
        f["blocks"].append(extra)
        self.assertIsNone(entry_plan(f))

    def test_unknown_layout_unsupported_program_and_target_are_refused(self):
        for layout in ("unsafe", True, {}, None):
            with self.subTest(layout=layout), self.assertRaises(HIAProgramLLVMRejected):
                emit_program_llvm(self.reduced, layout=layout)
        with self.assertRaisesRegex(HIAProgramLLVMRejected, "no complete disjoint"):
            emit_program_llvm(self.original, layout=LAYOUT)
        with self.assertRaisesRegex(HIAProgramLLVMRejected, "x86_64"):
            emit_program_llvm(self.reduced, layout=LAYOUT, target=TARGET_AARCH64)

    def test_ir_is_regenerated_with_the_same_layout_before_compilation(self):
        ir = emit_program_llvm(self.reduced, layout=LAYOUT)
        self.assertEqual(ir.layout, LAYOUT)
        self.assertEqual(ir.core_sha256, self.reduced.sha256)
        tampered = ir.text.replace("icmp ule i64", "icmp ult i64", 1)
        mutants = [
            replace(ir, layout="canonical"),
            replace(ir, text=tampered, sha256=sha256(tampered.encode()).hexdigest()),
        ]
        with tempfile.TemporaryDirectory() as directory:
            for index, mutant in enumerate(mutants):
                with self.subTest(mutation=index), self.assertRaisesRegex(HIAProgramLLVMRejected, "differs from independently reverified"):
                    compile_program_llvm(mutant, program=self.reduced,
                                         output=Path(directory) / (str(index) + ".o"), kind="object")

    def test_zero_path_contains_the_real_trapping_body(self):
        ir = emit_program_llvm(self.example, layout=LAYOUT)
        self.assertIn("udiv i64", ir.text)
        self.assertIn("call void @abort()", ir.text)
        self.assertIn("i64 0, i32 %entry_1) alwaysinline", ir.text)
        self.assertNotIn("ret i64 0", ir.text)

    @unittest.skipUnless(os.environ.get("HIA_TEST_CLANG20"), "set HIA_TEST_CLANG20 for actual native semantic checks")
    def test_actual_native_both_branches_and_zero_division_trap(self):
        cc = os.environ["HIA_TEST_CLANG20"]
        with tempfile.TemporaryDirectory() as directory:
            for layout in ("canonical", LAYOUT):
                output = Path(directory) / (layout + ".so")
                receipt = build_program_native(self.example, output, clang=cc, layout=layout)
                self.assertEqual(receipt["entry_layout"], layout)
                probe = (
                    "import ctypes,json,resource,sys;"
                    "resource.setrlimit(resource.RLIMIT_CORE,(0,0));"
                    "f=ctypes.CDLL(sys.argv[1]).calculate;"
                    "f.argtypes=[ctypes.c_size_t,ctypes.c_uint32];f.restype=ctypes.c_uint64;"
                    "print(json.dumps([f(int(n),4294967295) for n in sys.argv[2:]]))"
                )
                good = subprocess.run([sys.executable, "-c", probe, str(output), "1", "2", "7", "8", str(2**64-1)],
                                      capture_output=True, text=True, timeout=10)
                self.assertEqual(good.returncode, 0, good.stderr)
                self.assertEqual(json.loads(good.stdout), [1, 0, 0, 2**32-1, 2**32-1])
                trapped = subprocess.run([sys.executable, "-c", probe, str(output), "0"],
                                         capture_output=True, text=True, timeout=10)
                self.assertEqual(trapped.returncode, -6, trapped.stderr)


if __name__ == "__main__":
    unittest.main()
