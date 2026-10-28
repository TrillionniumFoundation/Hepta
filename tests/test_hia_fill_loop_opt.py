"""A structurally checked loop rewrite, including valid near-miss programs."""
import copy
import json
from pathlib import Path
import unittest

from hepta.hia_fill_loop_opt import rewrite_full_view_fill_loop
from hepta.hia_program import HIAProgramRejected, verify_program
from hepta.hia_program_runtime import execute_program, HIAProgramBudgetExceeded, HIAProgramTrap
from hepta.hia_schema import SCHEMA, SCHEMA_V2, SCHEMA_V3, SCHEMA_V4, SCHEMA_V5, SCHEMA_V6, SCHEMA_V7
from tests.test_hia_program import b, branch, c, f, i, jump, m, ret


def fill_loop_program():
    fill = f("fill_view", [("view", "mutbuf"), ("byte", "u8")], [], ["read", "write", "trap"], [
        b("start", [("view", "mutbuf"), ("byte", "u8")], [c("zero", "usize", 0)],
          jump("loop", "view", "zero", "byte")),
        b("loop", [("lv", "mutbuf"), ("index", "usize"), ("value", "u8")], [
            i("buffer.len", ["lv"], [("length", "usize")]),
            i("compare.lt", ["index", "length"], [("more", "bool")]),
        ], branch("more", ("body", "lv", "index", "value"), ("done", "lv"))),
        b("body", [("bv", "mutbuf"), ("bi", "usize"), ("byte_value", "u8")], [
            i("buffer.store", ["bv", "bi", "byte_value"]), c("one", "usize", 1),
            i("int.add.checked", ["bi", "one"], [("next", "usize")]),
        ], jump("loop", "bv", "next", "byte_value")),
        b("done", [("dv", "mutbuf")], [], ret()),
    ])
    params = [(name, "usize") for name in ("size", "value", "probe", "mask")]
    outer = f("fill_probe", params, ["u8"], ["alloc", "read", "write", "trap"], [
        b("entry", params, [
            i("int.cast", ["value"], [("byte", "u8")], mode="checked"),
            i("int.cast", ["mask"], [("mask_byte", "u8")], mode="checked"),
            i("buffer.new", ["size"], [("owner", "buffer")]),
            i("borrow.mut", ["owner"], [("view", "mutbuf")]),
            i("call", ["view", "byte"], function="fill_view"),
            i("buffer.load", ["view", "probe"], [("observed", "u8")]),
            i("bit.xor", ["observed", "mask_byte"], [("answer", "u8")]),
            i("loan.end", ["view"]), i("owner.drop", ["owner"]),
        ], ret("answer")),
    ])
    result = m(fill, outer)
    result["module"] = "ndu_full_view_fill"
    return result


def observation(program, args, **options):
    try:
        report = execute_program(program, "fill_probe", args, **options)
    except (HIAProgramTrap, HIAProgramBudgetExceeded) as error:
        report = error.report
    return {key: report.get(key) for key in ("status", "values", "resources")}, report.get("error", {}).get("code")


class FillLoopRewriteTests(unittest.TestCase):
    def test_full_view_fill_is_reproduced_and_reverified(self):
        baseline = verify_program(fill_loop_program())
        result = rewrite_full_view_fill_loop(baseline)
        self.assertEqual(result.replacements, 1)
        self.assertEqual(result.program.as_dict()["schema"], SCHEMA_V2)
        self.assertNotEqual(result.after_sha256, result.before_sha256)
        self.assertEqual(verify_program(result.program.canonical_bytes).sha256, result.after_sha256)
        self.assertFalse(result.claims["formal_backend_refinement_proved"])
        self.assertEqual(rewrite_full_view_fill_loop(result.program).replacements, 0)
        self.assertEqual(len(result.program.as_dict()["functions"][0]["blocks"]), 3)

    def test_values_full_ledgers_and_actual_failure_paths_agree(self):
        before = verify_program(fill_loop_program())
        after = rewrite_full_view_fill_loop(before).program
        rows = [[n, value, probe, mask] for n in (1, 2, 7, 32)
                for value in (0, 7, 255) for probe in (0, n - 1) for mask in (0, 173)]
        rows += [[0, 7, 0, 0], [5, 7, 5, 0], [5, 256, 0, 0], [5, 7, 0, 256]]
        for args in rows:
            for failure in (None, 1):
                with self.subTest(args=args, failure=failure):
                    self.assertEqual(observation(before, args, allocation_fail_at=failure),
                                     observation(after, args, allocation_fail_at=failure))

    def test_registered_rule_does_not_claim_step_budget_equivalence(self):
        source = fill_loop_program()
        target = rewrite_full_view_fill_loop(source)
        self.assertFalse(target.claims["instruction_step_budget_equivalence"])
        self.assertEqual(observation(source, [32, 7, 0, 0], max_steps=80)[0]["status"], "budget_exceeded")
        self.assertEqual(observation(target.program, [32, 7, 0, 0], max_steps=80)[0]["status"], "returned")

    def assert_unchanged(self, data):
        original = verify_program(data)
        result = rewrite_full_view_fill_loop(original)
        self.assertEqual(result.replacements, 0)
        self.assertEqual(result.program.canonical_bytes, original.canonical_bytes)

    def test_nonzero_start_different_stride_and_wrapping_increment_do_not_match(self):
        for mode in ("start", "stride", "wrap", "unchanged_index"):
            data = fill_loop_program()
            start, _, body, _ = data["functions"][0]["blocks"]
            if mode == "start":
                start["ops"][0]["attrs"]["value"] = 1
            elif mode == "stride":
                body["ops"][1]["attrs"]["value"] = 2
            elif mode == "wrap":
                body["ops"][2]["op"] = "int.add.wrap"
            else:
                body["term"]["args"][1] = "bi"
            with self.subTest(mode=mode):
                self.assert_unchanged(data)

    def test_inverted_or_non_extent_bound_does_not_match(self):
        for mode in ("reverse", "inclusive", "index_bound"):
            data = fill_loop_program()
            compare = data["functions"][0]["blocks"][1]["ops"][1]
            if mode == "reverse":
                compare["args"].reverse()
            elif mode == "inclusive":
                compare["op"] = "compare.le"
            else:
                compare["args"][1] = "index"
            with self.subTest(mode=mode):
                self.assert_unchanged(data)

    def test_extra_observable_read_or_trapping_operation_refuses_rewrite(self):
        for operation in (i("buffer.load", ["bv", "bi"], [("readback", "u8")]),
                          i("int.add.checked", ["byte_value", "byte_value"], [("double", "u8")])):
            data = fill_loop_program()
            data["functions"][0]["blocks"][2]["ops"].insert(1, operation)
            self.assert_unchanged(data)

    def test_escaping_final_index_is_not_silently_dropped(self):
        data = fill_loop_program()
        fill, outer = data["functions"]
        fill["returns"] = ["usize"]
        fill["blocks"][1]["term"]["else"]["args"].append("index")
        fill["blocks"][3]["params"].append({"name": "final_index", "type": "usize"})
        fill["blocks"][3]["term"] = ret("final_index")
        outer["blocks"][0]["ops"][4]["out"] = [{"name": "unused_size", "type": "usize"}]
        self.assert_unchanged(data)

    def test_escaping_view_length_is_preserved(self):
        data = fill_loop_program()
        fill, outer = data["functions"]
        fill["returns"] = ["usize"]
        fill["blocks"][1]["term"]["else"]["args"].append("length")
        fill["blocks"][3]["params"].append({"name": "final_length", "type": "usize"})
        fill["blocks"][3]["term"] = ret("final_length")
        outer["blocks"][0]["ops"][4]["out"] = [{"name": "observed_length", "type": "usize"}]
        # Observe the escaped extent, rather than merely checking a dead value.
        outer["blocks"][0]["ops"].insert(5, i("int.cast", ["observed_length"],
            [("length_byte", "u8")], mode="checked"))
        outer["blocks"][0]["ops"][7]["args"][1] = "length_byte"
        before = verify_program(data)
        result = rewrite_full_view_fill_loop(before)
        self.assertEqual(result.replacements, 1)
        for size in (0, 1, 7, 32, 256):
            with self.subTest(size=size):
                self.assertEqual(observation(before, [size, 173, 0, 0]),
                                 observation(result.program, [size, 173, 0, 0]))

    def test_multiple_initial_predecessors_do_not_match(self):
        data = fill_loop_program()
        fill = data["functions"][0]
        start = fill["blocks"][0]
        start["ops"].append(c("choice", "bool", True))
        start["term"] = branch("choice", ("loop", "view", "zero", "byte"), ("other", "view", "byte"))
        fill["blocks"].append(b("other", [("ov", "mutbuf"), ("ob", "u8")],
                                [c("oz", "usize", 0)], jump("loop", "ov", "oz", "ob")))
        self.assert_unchanged(data)

    def test_input_version_is_preserved_after_v2(self):
        for schema in (SCHEMA_V2, SCHEMA_V3, SCHEMA_V4, SCHEMA_V5, SCHEMA_V6):
            data = fill_loop_program()
            data["schema"] = schema
            with self.subTest(schema=schema):
                result = rewrite_full_view_fill_loop(data)
                self.assertEqual(result.replacements, 1)
                self.assertEqual(result.program.as_dict()["schema"], schema)

    def test_newer_wire_and_unverified_effects_refuse_before_rewrite(self):
        data = fill_loop_program()
        data["schema"] = SCHEMA_V7
        with self.assertRaisesRegex(HIAProgramRejected, "primitive v1-v6"):
            rewrite_full_view_fill_loop(data)
        data = fill_loop_program()
        data["functions"][0]["effects"].remove("write")
        with self.assertRaises(HIAProgramRejected):
            rewrite_full_view_fill_loop(data)

    @unittest.skipUnless(Path("/usr/bin/clang-20").is_file(), "Clang native integration unavailable")
    def test_actual_native_results_match_both_cores(self):
        from tools.hia_ndu_measure import measure_pair
        source = verify_program(fill_loop_program())
        candidate = rewrite_full_view_fill_loop(source).program
        cases = [[1, 7, 0, 0], [7, 173, 6, 93], [32, 255, 17, 17]]
        report = measure_pair(source, candidate, "fill_probe", cases,
                              clang="/usr/bin/clang-20", samples=15, iterations=2)
        self.assertTrue(report["ok"], report.get("diagnostics"))
        self.assertEqual(report["counts"]["untimed_correctness_calls"], 6)
        # The tiny loop here checks the instrument/result path only. Its timing
        # observations establish no performance improvement or qualification.
        self.assertEqual(report["native"]["baseline"]["core_sha256"], source.sha256)
        self.assertEqual(report["native"]["candidate"]["core_sha256"], candidate.sha256)


if __name__ == "__main__":
    unittest.main()
