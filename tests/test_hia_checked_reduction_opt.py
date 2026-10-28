"""Actual checked arithmetic, resource and native controls for a closed form."""
from __future__ import annotations

import copy
import os
from pathlib import Path
import shutil
import tempfile
import unittest

from hepta.hia_checked_reduction_opt import rewrite_checked_unsigned_reduction
from hepta.hia_program import HIAProgramRejected, verify_program
from hepta.hia_program_runtime import execute_program, HIAProgramTrap, HIAProgramBudgetExceeded
from hepta.hia_schema import COMPOSITE_SCHEMA, PRIMITIVE_SCHEMAS, SCHEMA_V7
from tests.test_hia_program import b, branch, c, f, i, jump, m, ret


def reduction_program(typ="usize"):
    return m(f("reduce", [("count", typ), ("value", typ)], [typ], ["trap"], [
        b("start", [("count", typ), ("value", typ)], [c("zero", typ, 0)],
          jump("loop", "count", "value", "zero", "zero")),
        b("loop", [("ln", typ), ("lv", typ), ("index", typ), ("sum", typ)], [
            i("compare.lt", ["index", "ln"], [("more", "bool")]),
        ], branch("more", ("body", "ln", "lv", "index", "sum"), ("done", "sum"))),
        b("body", [("bn", typ), ("bv", typ), ("bi", typ), ("bs", typ)], [
            c("one", typ, 1), i("int.add.checked", ["bs", "bv"], [("next_sum", typ)]),
            i("int.add.checked", ["bi", "one"], [("next_index", typ)]),
        ], jump("loop", "bn", "bv", "next_index", "next_sum")),
        b("done", [("answer", typ)], [], ret("answer")),
    ]))


def reduction_probe_program():
    """Existing NDU instrument ABI, without pretending this is an external app."""
    data = reduction_program()
    params = [(name, "usize") for name in ("count", "value", "offset", "mask")]
    data["functions"].append(f("reduction_probe", params, ["u8"], ["trap"], [
        b("entry", params, [
            i("int.cast", ["mask"], [("byte_mask", "u8")], mode="checked"),
            i("call", ["count", "value"], [("total", "usize")], function="reduce"),
            i("int.add.checked", ["total", "offset"], [("shifted", "usize")]),
            i("int.cast", ["shifted"], [("byte", "u8")], mode="wrap"),
            i("bit.xor", ["byte", "byte_mask"], [("result", "u8")]),
        ], ret("result")),
    ]))
    data["module"] = "ndu_checked_unsigned_reduction"
    return data


def owned_reduction_program():
    data = reduction_program("u8")
    params = [("size", "usize"), ("count", "u8"), ("value", "u8")]
    data["functions"].append(f("owned_reduce", params, ["u8"], ["alloc", "read", "write", "trap"], [
        b("entry", params, [
            i("buffer.new", ["size"], [("owner", "buffer")]),
            i("borrow.mut", ["owner"], [("view", "mutbuf")]),
            i("call", ["count", "value"], [("total", "u8")], function="reduce"),
            c("zero", "usize", 0), i("buffer.store", ["view", "zero", "total"]),
            i("buffer.load", ["view", "zero"], [("answer", "u8")]),
            i("loan.end", ["view"]), i("owner.drop", ["owner"]),
        ], ret("answer")),
    ]))
    return data


def observation(program, args, *, entry="reduce", **options):
    try:
        report = execute_program(program, entry, args, **options)
    except (HIAProgramTrap, HIAProgramBudgetExceeded) as error:
        report = error.report
    return ({key: report.get(key) for key in ("status", "values", "resources")},
            report.get("error", {}).get("code"))


class CheckedReductionTests(unittest.TestCase):
    def assert_unchanged(self, source):
        before = verify_program(source)
        result = rewrite_checked_unsigned_reduction(before)
        self.assertEqual(result.replacements, 0)
        self.assertEqual(result.program.canonical_bytes, before.canonical_bytes)

    def test_reproduced_and_reverified_without_schema_change(self):
        before = verify_program(reduction_program())
        result = rewrite_checked_unsigned_reduction(before)
        self.assertEqual(result.replacements, 1)
        self.assertNotEqual(result.before_sha256, result.after_sha256)
        self.assertEqual(result.program.as_dict()["schema"], before.as_dict()["schema"])
        self.assertEqual(verify_program(result.program.canonical_bytes).sha256, result.after_sha256)
        self.assertEqual(rewrite_checked_unsigned_reduction(result.program).replacements, 0)
        self.assertTrue(result.claims["checked_overflow_semantics_preserved"])
        self.assertFalse(result.claims["formal_backend_refinement_proved"])

    def test_every_u8_count_with_boundary_products_and_all_unsigned_widths(self):
        # Each u8 count checks zero, one, max, and the three adjacent values
        # around its exact multiplication-overflow boundary. Wider widths check
        # the same boundaries and full-width counts that overflow immediately.
        for typ, width in (("u8", 8), ("u16", 16), ("u32", 32), ("u64", 64), ("usize", 64)):
            maximum = (1 << width) - 1
            before = verify_program(reduction_program(typ))
            after = rewrite_checked_unsigned_reduction(before).program
            counts = range(256) if typ == "u8" else (0, 1, 2, 3, 7, 31, 255)
            rows = set()
            for count in counts:
                boundary = maximum // count if count else maximum
                values = {0, 1, maximum, max(0, boundary - 1), boundary, min(maximum, boundary + 1)}
                rows.update((count, value) for value in values)
            if typ != "u8":
                rows.add((maximum, maximum))
                rows.add((maximum - 1, maximum))
            for count, value in sorted(rows):
                with self.subTest(type=typ, count=count, value=value):
                    old = observation(before, [count, value])
                    new = observation(after, [count, value])
                    self.assertEqual(old, new)
                    if count * value > maximum:
                        self.assertEqual(old[1], "overflow")
                    else:
                        self.assertEqual(old[0]["values"], [count * value])

    def test_zero_cases_and_outer_trap_order_are_retained(self):
        before = verify_program(reduction_probe_program())
        after = rewrite_checked_unsigned_reduction(before).program
        maximum = (1 << 64) - 1
        cases = [[0, maximum, 0, 0], [1, maximum, 0, 0], [2, maximum, 0, 0],
                 [2, maximum, 0, 256], [1, maximum, 1, 0], [7, 37, 0, 173]]
        for args in cases:
            with self.subTest(args=args):
                self.assertEqual(observation(before, args, entry="reduction_probe"),
                                 observation(after, args, entry="reduction_probe"))

    def test_external_owners_loans_failures_and_traps_keep_complete_resource_ledgers(self):
        before = verify_program(owned_reduction_program())
        after = rewrite_checked_unsigned_reduction(before).program
        for size in (0, 1, 32, (1 << 64) - 1):
            for count, value in ((0, 255), (1, 255), (2, 128), (7, 31)):
                for failure in (None, 1):
                    with self.subTest(size=size, count=count, value=value, failure=failure):
                        self.assertEqual(observation(before, [size, count, value], entry="owned_reduce",
                                                     allocation_fail_at=failure),
                                         observation(after, [size, count, value], entry="owned_reduce",
                                                     allocation_fail_at=failure))

    def test_active_formal_loan_carried_through_the_matched_loop_is_retained(self):
        data = owned_reduction_program()
        reduction, outer = data["functions"]
        reduction["params"].append({"name": "formal", "type": "mutbuf"})
        start, header, body, done = reduction["blocks"]
        start["params"].append({"name": "formal", "type": "mutbuf"})
        start["term"]["args"].append("formal")
        header["params"].append({"name": "loop_loan", "type": "mutbuf"})
        header["term"]["then"]["args"].append("loop_loan")
        header["term"]["else"]["args"].append("loop_loan")
        body["params"].append({"name": "body_loan", "type": "mutbuf"})
        body["term"]["args"].append("body_loan")
        done["params"].append({"name": "done_loan", "type": "mutbuf"})
        outer["blocks"][0]["ops"][2]["args"].append("view")
        before = verify_program(data)
        result = rewrite_checked_unsigned_reduction(before)
        self.assertEqual(result.replacements, 1)
        for size, count, value in ((0, 0, 255), (1, 0, 255), (1, 7, 31), (1, 2, 128)):
            self.assertEqual(observation(before, [size, count, value], entry="owned_reduce"),
                             observation(result.program, [size, count, value], entry="owned_reduce"))

    def test_exit_index_and_accumulator_are_replaced_with_correct_values(self):
        data = reduction_program("u8")
        fn = data["functions"][0]
        fn["returns"] = ["u8", "u8", "u8"]
        fn["blocks"][1]["term"]["else"]["args"] = ["sum", "index", "ln"]
        fn["blocks"][3]["params"] = [{"name": name, "type": "u8"} for name in ("answer", "last", "length")]
        fn["blocks"][3]["term"] = ret("answer", "last", "length")
        result = rewrite_checked_unsigned_reduction(data)
        self.assertEqual(result.replacements, 1)
        for args in ([0, 255], [1, 255], [7, 31], [255, 1], [255, 2]):
            self.assertEqual(observation(data, args), observation(result.program, args))

    def test_valid_near_misses_refuse(self):
        for mode in ("nonzero", "stride", "wrap_sum", "wrap_index", "inclusive", "signed",
                     "index_value", "accumulator_value", "changing_value", "changing_count", "extra_trap"):
            data = reduction_program("i32" if mode == "signed" else "u8")
            start, header, body, _ = data["functions"][0]["blocks"]
            if mode == "nonzero":
                start["ops"][0]["attrs"]["value"] = 1
            elif mode == "stride":
                body["ops"][0]["attrs"]["value"] = 2
            elif mode == "wrap_sum":
                body["ops"][1]["op"] = "int.add.wrap"
            elif mode == "wrap_index":
                body["ops"][2]["op"] = "int.add.wrap"
            elif mode == "inclusive":
                header["ops"][0]["op"] = "compare.le"
            elif mode == "index_value":
                body["ops"][1]["args"][1] = "bi"
            elif mode == "accumulator_value":
                body["ops"][1]["args"][1] = "bs"
            elif mode == "changing_value":
                body["term"]["args"][1] = "next_index"
            elif mode == "changing_count":
                body["term"]["args"][0] = "next_index"
            elif mode == "extra_trap":
                body["ops"].append(i("int.add.checked", ["bv", "bv"], [("extra", "u8")]))
            with self.subTest(mode=mode):
                self.assert_unchanged(data)

    def test_condition_escape_and_additional_predecessor_refuse(self):
        data = reduction_program()
        fn = data["functions"][0]
        fn["returns"].append("bool")
        fn["blocks"][1]["term"]["else"]["args"].append("more")
        fn["blocks"][3]["params"].append({"name": "final_condition", "type": "bool"})
        fn["blocks"][3]["term"] = ret("answer", "final_condition")
        self.assert_unchanged(data)
        data = reduction_program()
        fn = data["functions"][0]
        start = fn["blocks"][0]
        start["ops"].append(c("choice", "bool", True))
        start["term"] = branch("choice", ("loop", "count", "value", "zero", "zero"),
                               ("other", "count", "value"))
        fn["blocks"].append(b("other", [("on", "usize"), ("ov", "usize")], [c("oz", "usize", 0)],
                              jump("loop", "on", "ov", "oz", "oz")))
        self.assert_unchanged(data)

    def test_count_may_also_be_invariant_addend(self):
        data = reduction_program("u8")
        data["functions"][0]["blocks"][2]["ops"][1]["args"][1] = "bn"
        result = rewrite_checked_unsigned_reduction(data)
        self.assertEqual(result.replacements, 1)
        for count in (0, 1, 7, 15, 16, 255):
            self.assertEqual(observation(data, [count, 3]), observation(result.program, [count, 3]))

    def test_every_primitive_version_preserved_and_composite_identity_refused(self):
        for schema in sorted(PRIMITIVE_SCHEMAS):
            data = reduction_program()
            data["schema"] = schema
            if schema == SCHEMA_V7:
                data["functions"][0]["effects"].append("alloc")
                data["functions"][0]["blocks"][0]["ops"][:0] = [
                    i("chain.empty", out=[("empty", "chain")]), i("owner.drop", ["empty"])]
            result = rewrite_checked_unsigned_reduction(data)
            self.assertEqual(result.replacements, 1)
            self.assertEqual(result.program.as_dict()["schema"], schema)
            self.assertEqual(observation(data, [7, 11]), observation(result.program, [7, 11]))
        data = reduction_program()
        data.update(schema=COMPOSITE_SCHEMA, types=[])
        self.assertIsNotNone(verify_program(data).structured_bytes)
        with self.assertRaisesRegex(HIAProgramRejected, "primitive Core identity"):
            rewrite_checked_unsigned_reduction(data)

    def test_fresh_result_name_and_input_isolation(self):
        data = reduction_program()
        data["functions"][0]["blocks"][0]["ops"].append(c("hia_reduction_result_0", "usize", 9))
        original = copy.deepcopy(data)
        result = rewrite_checked_unsigned_reduction(data)
        self.assertEqual(data, original)
        self.assertEqual(result.replacements, 1)
        self.assertEqual(result.program.as_dict()["functions"][0]["blocks"][1]["ops"][0]["out"][0]["name"],
                         "hia_reduction_result_1")

    def test_instruction_budget_equivalence_is_explicitly_not_claimed(self):
        before = verify_program(reduction_program())
        result = rewrite_checked_unsigned_reduction(before)
        self.assertFalse(result.claims["instruction_step_budget_equivalence"])
        self.assertEqual(observation(before, [100, 0], max_steps=30)[0]["status"], "budget_exceeded")
        self.assertEqual(observation(result.program, [100, 0], max_steps=30)[0]["status"], "returned")

    @unittest.skipUnless(shutil.which(os.environ.get("LEAN", "lean")), "actual Lean compiler unavailable")
    def test_independent_lean_model_and_wrong_value_and_missing_overflow_controls(self):
        from hepta.clang_capture import run_bounded
        lean = os.environ.get("LEAN", "lean")
        source = Path(__file__).resolve().parents[1] / "formal/HiaCheckedReduction.lean"
        text = source.read_text()
        actual = run_bounded([lean, str(source)], timeout=30)
        self.assertEqual(actual.returncode, 0, actual.stdout + actual.stderr)
        self.assertNotIn("sorryAx", actual.stdout + actual.stderr)
        self.assertIn("HiaCheckedReduction.repeated_eq_closed", actual.stdout)
        self.assertIn("HiaCheckedReduction.overflow_agrees", actual.stdout)
        with tempfile.TemporaryDirectory(prefix="hia-reduction-proof-negative-") as temporary:
            for name, old, new in (
                ("wrong_zero", "| 0 => some 0", "| 0 => some 1"),
                ("unchecked_product", "if count * value ≤ maximum then", "if 0 ≤ maximum then"),
            ):
                self.assertEqual(text.count(old), 1)
                path = Path(temporary) / (name + ".lean")
                path.write_text(text.replace(old, new))
                negative = run_bounded([lean, str(path)], timeout=30)
                self.assertNotEqual(negative.returncode, 0, name + " must not satisfy the unchanged theorem")
                self.assertIn("error:", negative.stdout + negative.stderr)

    @unittest.skipUnless(Path("/usr/bin/clang-20").is_file(), "Clang native integration unavailable")
    def test_actual_native_artifacts_and_returns_and_traps(self):
        from hepta.hia_program_llvm import compile_program_llvm, emit_program_llvm
        from hepta.hia_native_differential import _pin_native_artifact, _observe_native
        source = verify_program(reduction_program("u32"))
        target = rewrite_checked_unsigned_reduction(source).program
        with tempfile.TemporaryDirectory(prefix="hia-reduction-native-") as temporary:
            root = Path(temporary)
            reports = [compile_program_llvm(emit_program_llvm(program), program=program,
                                           output=root / name, clang="/usr/bin/clang-20")
                       for program, name in ((source, "before.so"), (target, "after.so"))]
            # Actual file comparison, never evidence of performance on its own.
            self.assertNotEqual((root / "before.so").read_bytes(), (root / "after.so").read_bytes())
            self.assertTrue(all(report["ok"] for report in reports))
            self.assertEqual(reports[0]["flags"], reports[1]["flags"])
            self.assertEqual(reports[0]["toolchain"], reports[1]["toolchain"])
            maximum = (1 << 32) - 1
            rows = [(0, maximum), (1, maximum), (2, maximum), (maximum, maximum),
                    (255, maximum // 255), (255, maximum // 255 + 1), (1024, 37), (4096, 0)]
            for path in (root / "before.so", root / "after.so"):
                _, _, descriptor = _pin_native_artifact(path)
                try:
                    for count, value in rows:
                        expected = (("trap", None) if count * value > maximum else ("value", count * value))
                        self.assertEqual(_observe_native(path, "reduce", "u32", [count, value],
                                                         timeout=3.0, pinned_fd=descriptor), expected)
                finally:
                    os.close(descriptor)


if __name__ == "__main__":
    unittest.main()
