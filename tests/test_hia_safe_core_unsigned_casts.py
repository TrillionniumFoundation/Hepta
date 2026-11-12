"""Independent arithmetic checks for the explicit Safe Core v2 extension."""
import ctypes
import json
from pathlib import Path
import tempfile
import unittest
from hepta.hia_program import verify_program
from hepta.hia_program_native import emit_program_machine, compile_program_machine
from hepta.hia_safe_core import (ARTIFACT_PROFILE_V2, PROFILE, PROFILE_V2, SafeCoreRejected,
    WIDTHS_V2, _profile, _Theory, build_safe_core, validate_safe_core_artifact)
from tools.build_hia_safe_core import build
from tools.check_hia_safe_core import check
from tools.qualify_hia_safe_core_unsigned_casts import UNSIGNED_TYPES, cast_document
from tests.test_hia_program import arithmetic, b, branch, f, i, jump, ret


class UnsignedCastProfileTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="hia-safe-casts-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def test_default_scope_and_strict_version(self):
        for source, target, mode in (("u16", "u64", "wrap"), ("u64", "u8", "checked")):
            with self.subTest(source=source, target=target), self.assertRaises(SafeCoreRejected):
                _profile(verify_program(cast_document(source, target, mode=mode)))
        core = verify_program(cast_document("u64", "u8", mode="wrap"))
        for version in (True, False, "2", 2.0, 0, 3, None):
            with self.subTest(version=version), self.assertRaises(SafeCoreRejected):
                _profile(core, profile_version=version)
        self.assertEqual(build_safe_core(core, self.root / "v1.so")["validation"]["profile"], PROFILE)

    def test_reference_matches_integer_math_at_every_cast_boundary(self):
        import z3
        for source in UNSIGNED_TYPES:
            for target in UNSIGNED_TYPES:
                fn, blocks = _profile(verify_program(cast_document(source, target)), profile_version=2)
                theory = _Theory(z3, 15000, widths=WIDTHS_V2)
                theory.arguments(fn)
                coverage, aborted, value, _ = theory.merge(theory.reference(fn, blocks, None))
                sm, tm = (1 << WIDTHS_V2[source]) - 1, (1 << WIDTHS_V2[target]) - 1
                for word in {0, 1, sm, tm, tm + 1, (1 << 64) - 1}:
                    raw = word & ((1 << 64) - 1)
                    evaluate = lambda term: z3.simplify(z3.substitute(term, (theory.words[0], theory.bv(raw))))
                    expected = raw & sm
                    with self.subTest(source=source, target=target, raw=raw):
                        self.assertTrue(z3.is_true(evaluate(coverage)))
                        self.assertEqual(z3.is_true(evaluate(aborted)), expected > tm)
                        if expected <= tm:
                            self.assertEqual(evaluate(value).as_long(), expected)

    def test_u16_arithmetic_and_dirty_abi(self):
        for op in ("int.add.wrap", "int.sub.wrap", "int.add.checked", "int.sub.checked"):
            report = build_safe_core(arithmetic(op, "u16"), self.root / (op + ".so"), profile_version=2)
            self.assertEqual(report["validation"]["profile"], PROFILE_V2)
            self.assertEqual([o["result"] for o in report["validation"]["obligations"]], ["sat"] + ["unsat"] * 4)
        report = build_safe_core(cast_document("u16", "u64"), self.root / "wide.so", profile_version=2)
        library = ctypes.CDLL(report["output"])
        fn = library.convert
        fn.argtypes, fn.restype = [ctypes.c_uint64], ctypes.c_uint64
        for word in (0, 1, 65535, 65536, (1 << 32) + 37, (1 << 64) - 1):
            self.assertEqual(fn(word), word & 65535)

    def test_u16_bits_comparisons_select_and_typed_cfg(self):
        params = [("a", "u16"), ("z", "u16"), ("choose", "bool")]
        operations = [
            i("bit.and", ["a", "z"], [("both", "u16")]),
            i("bit.or", ["a", "z"], [("either", "u16")]),
            i("bit.xor", ["both", "either"], [("different", "u16")]),
            i("bit.not", ["different"], [("inverse", "u16")]),
            i("select", ["choose", "different", "inverse"], [("answer", "u16")]),
        ]
        selected = {"schema": "hepta.hia.program.v8", "module": "u16_selected", "functions": [
            f("selected", params, ["u16"], [], [b("entry", params, operations, ret("answer"))])]}
        report = build_safe_core(selected, self.root / "selected.so", profile_version=2)
        self.assertEqual(report["validation"]["profile"], PROFILE_V2)
        self.assertEqual([o["result"] for o in report["validation"]["obligations"]], ["sat"] + ["unsat"] * 4)
        for relation in ("eq", "ne", "lt", "le", "gt", "ge"):
            pair = [("a", "u16"), ("z", "u16")]
            compared = {"schema": "hepta.hia.program.v8", "module": "u16_compare", "functions": [
                f("compare", pair, ["bool"], [], [b("entry", pair, [
                    i("compare." + relation, ["a", "z"], [("answer", "bool")])], ret("answer"))])]}
            with self.subTest(relation=relation):
                proof = build_safe_core(compared, self.root / (relation + ".so"), profile_version=2)["validation"]
                self.assertEqual(proof["profile"], PROFILE_V2)
                self.assertEqual([o["result"] for o in proof["obligations"]], ["sat"] + ["unsat"] * 4)
        cfg = {"schema": "hepta.hia.program.v8", "module": "u16_cfg", "functions": [
            f("choose_sum_or_difference", params, ["u16"], [], [
                b("entry", params, [], branch("choose", ("left", "a", "z"), ("right", "a", "z"))),
                b("left", [("la", "u16"), ("lz", "u16")], [
                    i("int.add.wrap", ["la", "lz"], [("sum", "u16")])], jump("join", "sum")),
                b("right", [("ra", "u16"), ("rz", "u16")], [
                    i("int.sub.wrap", ["ra", "rz"], [("difference", "u16")])], jump("join", "difference")),
                b("join", [("answer", "u16")], [], ret("answer")),
            ])]}
        proof = build_safe_core(cfg, self.root / "cfg.so", profile_version=2)["validation"]
        self.assertEqual(proof["profile"], PROFILE_V2)
        self.assertEqual([o["result"] for o in proof["obligations"]], ["sat"] + ["unsat"] * 4)
        self.assertEqual(proof["model_counts"]["core_terminal_paths"], 2)

    def test_wrapping_and_checked_casts_are_distinct(self):
        wrapping = verify_program(cast_document("u64", "u16", mode="wrap"))
        image = emit_program_machine(wrapping)
        path = self.root / "wrapping.so"
        compile_program_machine(image, program=wrapping, output=path, linker="ld")
        # No overflowing call or modified machine image is executed.
        with self.assertRaises(SafeCoreRejected) as caught:
            validate_safe_core_artifact(cast_document("u64", "u16"), image.object_bytes,
                                        path.read_bytes(), profile_version=2)
        witness = caught.exception.counterexample
        self.assertEqual(witness["obligation"], "core_to_final_image_return_abort_and_caller_bytes")
        self.assertGreater(witness["abi_words"][0], 65535)

    def test_retained_tools_bind_the_explicit_version(self):
        source = self.root / "source.json"
        source.write_text(json.dumps(cast_document("u64", "u16")))
        result = build(source, self.root / "build", profile_version=2)
        self.assertTrue(result["ok"], result)
        directory = self.root / "build"
        self.assertFalse(check(source, directory / "candidate.o", directory / "program.so", self.root / "v1-check")["ok"])
        report = check(source, directory / "candidate.o", directory / "program.so", self.root / "v2-check", profile_version=2)
        self.assertTrue(report["ok"], report)
        proof = report["validation"]
        self.assertEqual(proof["profile"], ARTIFACT_PROFILE_V2)
        self.assertTrue({"subject", "property", "profile", "assumptions", "checker", "unproved_obligations"} <= proof.keys())
        self.assertFalse(report["native_execution_observed"])
        self.assertFalse(proof["checker"]["producer_reemission_used"])


if __name__ == "__main__":
    unittest.main()
