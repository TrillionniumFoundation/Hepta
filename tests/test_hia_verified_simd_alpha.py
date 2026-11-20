"""Identifier-only SIMD admission preserves the complete original recurrence."""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_program import verify_program
from hepta.hia_safe_core_elf import _ELF
from hepta.hia_verified_simd import emit_verified_simd, simd_kernel_program
from hepta.hia_verified_simd_check import (
    CORE_RECOGNITION_PROFILE, VerifiedSIMDRejected, _recognize_simd_core,
    recognize_simd_core, validate_verified_simd_artifact,
)


KINDS = ("sum_u8", "all_zero_u8", "copy_u8")
AVAILABLE = (platform.system() == "Linux" and platform.machine().lower() in {"x86_64", "amd64"}
             and shutil.which("ld") is not None and importlib.util.find_spec("z3") is not None)


def definitions(document):
    return [value["name"] for block in document["functions"][0]["blocks"]
            for value in [*block["params"], *[out for op in block["ops"] for out in op["out"]]]]


def renamed(document, *, crossed=False, order=(4, 2, 0, 3, 1), namespace_collision=False):
    """Independent fixture substitution; never calls the production normalizer."""
    source = document.as_dict() if hasattr(document, "as_dict") else deepcopy(document)
    names = definitions(source)
    identifiers = [block["id"] for block in source["functions"][0]["blocks"]]
    values = {name: names[(index + 1) % len(names)] if crossed else "value_" + str(index)
              for index, name in enumerate(names)}
    blocks = {name: identifiers[(index + 1) % len(identifiers)] if crossed else "block_" + str(index)
              for index, name in enumerate(identifiers)}
    if namespace_collision:
        blocks = {name: "value_" + str(index) for index, name in enumerate(identifiers)}
    function = source["functions"][0]
    for parameter in function["params"]:
        parameter["name"] = values[parameter["name"]]
    function["entry"] = blocks[function["entry"]]
    for block in function["blocks"]:
        block["id"] = blocks[block["id"]]
        for parameter in block["params"]:
            parameter["name"] = values[parameter["name"]]
        for operation in block["ops"]:
            operation["args"] = [values[name] for name in operation["args"]]
            for output in operation["out"]:
                output["name"] = values[output["name"]]
        term = block["term"]
        if term["op"] == "branch":
            term["cond"] = values[term["cond"]]
            edges = [term["then"], term["else"]]
        else:
            edges = [term] if term["op"] == "jump" else []
        for edge in edges:
            edge["target"] = blocks[edge["target"]]
            edge["args"] = [values[name] for name in edge["args"]]
        if term["op"] == "ret":
            term["values"] = [values[name] for name in term["values"]]
    function["blocks"] = [function["blocks"][index] for index in order]
    return source


class SIMDAlphaRecognitionTests(unittest.TestCase):
    def test_all_three_kernels_allow_complete_renaming_and_crossed_existing_names(self):
        for kind in KINDS:
            core = simd_kernel_program(kind)
            for options in ({}, {"crossed": True}, {"namespace_collision": True}):
                with self.subTest(kind=kind, options=options):
                    altered = verify_program(renamed(core, **options))
                    actual, export, evidence = _recognize_simd_core(altered)
                    self.assertEqual((actual, export), (kind, "calculate"))
                    self.assertEqual(evidence["profile"], CORE_RECOGNITION_PROFILE)
                    self.assertEqual(evidence["original_core_sha256"], altered.sha256)
                    self.assertEqual(evidence["normal_form_core_sha256"], core.sha256)
                    self.assertNotEqual(altered.sha256, core.sha256)
                    self.assertTrue(evidence["bijections_checked"])
                    self.assertTrue(evidence["inverse_roundtrip_checked"])
                    self.assertEqual(evidence["renamed_blocks"], 5)
                    self.assertEqual(evidence["renamed_ssa_definitions"], len(definitions(core.as_dict())))
                    self.assertTrue(evidence["block_declaration_order_changed"])
                    mapping = evidence["renaming"]
                    self.assertEqual(set(mapping["ssa"]), set(definitions(altered.as_dict())))
                    self.assertEqual(set(mapping["ssa"].values()), set(definitions(core.as_dict())))
                    self.assertEqual(evidence["renaming_sha256"], sha256(json.dumps(
                        mapping, sort_keys=True, separators=(",", ":")).encode()).hexdigest())

    def test_single_entry_rename_and_every_block_at_first_declaration_position(self):
        for kind in KINDS:
            original = simd_kernel_program(kind).as_dict()
            first = deepcopy(original)
            first["functions"][0]["entry"] = "start"
            first["functions"][0]["blocks"][0]["id"] = "start"
            self.assertEqual(recognize_simd_core(first), (kind, "calculate"))
            for shift in range(5):
                changed = deepcopy(first)
                blocks = changed["functions"][0]["blocks"]
                changed["functions"][0]["blocks"] = blocks[shift:] + blocks[:shift]
                with self.subTest(kind=kind, first=shift):
                    self.assertEqual(recognize_simd_core(changed), (kind, "calculate"))

    def test_original_core_and_export_identity_are_preserved(self):
        core = simd_kernel_program("sum_u8", name="user_export")
        source = renamed(core)
        before = deepcopy(source)
        kind, export, evidence = _recognize_simd_core(source)
        self.assertEqual((kind, export), ("sum_u8", "user_export"))
        self.assertEqual(source, before)
        self.assertEqual(evidence["normal_form_core_sha256"], core.sha256)
        self.assertEqual(evidence["original_core_sha256"], verify_program(source).sha256)

    def test_identity_renaming_keeps_the_original_normal_form(self):
        for kind in KINDS:
            core = simd_kernel_program(kind)
            _, _, evidence = _recognize_simd_core(core)
            self.assertEqual(evidence["normal_form_core_sha256"], core.sha256)
            self.assertEqual(evidence["renamed_ssa_definitions"], 0)
            self.assertEqual(evidence["renamed_blocks"], 0)
            self.assertFalse(evidence["block_declaration_order_changed"])

    def test_inverse_roundtrip_is_an_executed_gate(self):
        import hepta.hia_verified_simd_check as checker
        original = checker._alpha_rewrite
        calls = []
        def wrong_inverse(*args):
            result = original(*args)
            calls.append(result)
            if len(calls) == 2:
                result["module"] = "lost_original_identity"
            return result
        with patch.object(checker, "_alpha_rewrite", side_effect=wrong_inverse), \
                self.assertRaisesRegex(VerifiedSIMDRejected, "inverse round trip"):
            recognize_simd_core(renamed(simd_kernel_program("sum_u8")))
        self.assertEqual(len(calls), 2)

    def reject_typed_change(self, kind, mutate):
        source = simd_kernel_program(kind).as_dict()
        mutate(source["functions"][0])
        # These are semantically wrong *typed* programs. Type/SSA rejection
        # alone must not be mistaken for the recurrence check rejecting them.
        changed = verify_program(renamed(verify_program(source), crossed=True))
        with self.assertRaises(VerifiedSIMDRejected):
            recognize_simd_core(changed)

    def test_same_type_edge_argument_substitutions_are_rejected(self):
        for kind in KINDS:
            count_index = 2 if kind == "copy_u8" else 1
            for location in ("entry", "body", "then", "else"):
                def change(function, location=location):
                    blocks = {block["id"]: block for block in function["blocks"]}
                    edge = (blocks["entry"]["term"]["then"] if location == "entry" else
                            blocks["body"]["term"] if location == "body" else
                            blocks["loop"]["term"][location])
                    edge["args"][count_index], edge["args"][count_index + 1] = (
                        edge["args"][count_index + 1], edge["args"][count_index])
                with self.subTest(kind=kind, edge=location):
                    self.reject_typed_change(kind, change)

    def test_guards_offsets_initial_values_and_stride_are_not_alpha_renaming(self):
        for kind in KINDS:
            changes = {
                "strict_extent": lambda f: f["blocks"][0]["ops"][1].__setitem__("op", "compare.lt"),
                "inclusive_loop": lambda f: f["blocks"][1]["ops"][0].__setitem__("op", "compare.le"),
                "wrong_load_index": lambda f: f["blocks"][2]["ops"][0]["args"].__setitem__(1, "b_count"),
                "stride_two": lambda f: f["blocks"][2]["ops"][-2]["attrs"].__setitem__("value", 2),
                "initial_index_one": lambda f: next(op for op in f["blocks"][0]["ops"]
                    if op["out"][0]["name"] == "zero")["attrs"].__setitem__("value", 1),
                "wrong_trap": lambda f: f["blocks"][4]["term"].__setitem__("code", "overflow"),
            }
            for name, change in changes.items():
                with self.subTest(kind=kind, change=name):
                    self.reject_typed_change(kind, change)

    def test_copy_requires_both_extents_and_the_original_result(self):
        self.reject_typed_change("copy_u8", lambda f:
            f["blocks"][0]["ops"][4]["args"].__setitem__(1, "source_fits"))
        self.reject_typed_change("copy_u8", lambda f:
            f["blocks"][3]["ops"][0]["args"].__setitem__(0, "d_index"))

    def test_reduction_operation_and_boolean_result_are_not_rewritten(self):
        self.reject_typed_change("sum_u8", lambda f:
            f["blocks"][2]["ops"][2].__setitem__("op", "int.sub.wrap"))
        self.reject_typed_change("all_zero_u8", lambda f:
            f["blocks"][3]["ops"][3].__setitem__("args", ["all_zero", "done_zero", "done_one"]))
        self.reject_typed_change("sum_u8", lambda f:
            f["blocks"][2]["ops"][1]["attrs"].__setitem__("mode", "checked"))

    def test_wrong_control_flow_extra_operations_and_metadata_stay_outside_scope(self):
        def flip_entry(function):
            term = function["blocks"][0]["term"]
            term["then"], term["else"] = term["else"], term["then"]
        def extra_operation(function):
            function["blocks"][2]["ops"].append({"op": "const", "args": [],
                "out": [{"name": "unused", "type": "u64"}], "attrs": {"value": 0}})
        for change in (flip_entry, extra_operation,
                       lambda f: f.__setitem__("return_loans", [None]),
                       lambda f: f["effects"].append("write")):
            self.reject_typed_change("sum_u8", change)

    def test_nonbijective_or_undefined_source_names_fail_before_admission(self):
        for mutation in (
            lambda f: f["blocks"][1]["params"][0].__setitem__("name", "source"),
            lambda f: f["blocks"][2].__setitem__("id", "loop"),
            lambda f: f["blocks"][2]["ops"][0]["args"].__setitem__(0, "missing_value"),
        ):
            source = simd_kernel_program("sum_u8").as_dict()
            mutation(source["functions"][0])
            with self.assertRaises(ValueError):
                recognize_simd_core(source)


@unittest.skipUnless(AVAILABLE, "Linux x86-64, GNU ld and pinned z3 are required")
class SIMDAlphaFinalByteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="hia-simd-alpha-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        cls.cases = {}
        for isa, unroll in (("sse2", 1), ("sse2", 4), ("avx2", 4), ("avx512", 4)):
            for kind in KINDS:
                core = simd_kernel_program(kind)
                changed = verify_program(renamed(core))
                options = {"copy_tail": "byte"} if kind == "copy_u8" and isa != "sse2" else {}
                image = emit_verified_simd(core, isa=isa, unroll=unroll, **options)
                alpha_image = emit_verified_simd(changed, isa=isa, unroll=unroll, **options)
                if image.object_bytes != alpha_image.object_bytes or image.text_bytes != alpha_image.text_bytes:
                    raise AssertionError("identifier-only change altered machine emission")
                obj = cls.root / (kind + isa + str(unroll) + ".o")
                final = obj.with_suffix(".so")
                obj.write_bytes(image.object_bytes)
                subprocess.run(["ld", "-m", "elf_x86_64", "-shared", "-z", "defs", "-z", "noexecstack",
                    "-z", "relro", "-z", "now", "--hash-style=both", "--build-id=none",
                    str(obj), "-lc", "-o", str(final)], check=True, capture_output=True, text=True, timeout=30)
                data = final.read_bytes()
                baseline = validate_verified_simd_artifact(core, image.object_bytes, data)
                alpha = validate_verified_simd_artifact(changed, image.object_bytes, data)
                cls.cases[isa, unroll, kind] = core, changed, image, data, baseline, alpha

    def test_all_machine_profiles_retain_identical_original_isa_obligations(self):
        for (isa, unroll, kind), (core, changed, image, data, baseline, alpha) in self.cases.items():
            with self.subTest(isa=isa, unroll=unroll, kind=kind):
                self.assertEqual(alpha["profile"], baseline["profile"])
                self.assertEqual(alpha["obligations"], baseline["obligations"])
                self.assertEqual(alpha["model_counts"], baseline["model_counts"])
                self.assertEqual(alpha["required_cpu_features"], baseline["required_cpu_features"])
                self.assertEqual(alpha["subject"]["core_sha256"], changed.sha256)
                self.assertEqual(alpha["subject"]["input_sha256"], changed.input_sha256)
                self.assertNotEqual(alpha["subject"]["core_sha256"], core.sha256)
                self.assertEqual(alpha["core_recognition"]["normal_form_core_sha256"], core.sha256)
                self.assertEqual(alpha["subject"]["object_sha256"], sha256(image.object_bytes).hexdigest())
                self.assertEqual(alpha["subject"]["final_image_sha256"], sha256(data).hexdigest())

    def test_supplied_bytes_and_alpha_maps_never_call_any_producer(self):
        _, changed, image, data, _, _ = self.cases["avx512", 4, "sum_u8"]
        with patch("hepta.hia_verified_simd.simd_kernel_program", side_effect=AssertionError("template producer used")), \
             patch("hepta.hia_verified_simd.emit_verified_simd", side_effect=AssertionError("producer used")), \
             patch("hepta.hia_verified_simd_wide.emit_wide_simd", side_effect=AssertionError("wide producer used")):
            proof = validate_verified_simd_artifact(changed, image.object_bytes, data)
        self.assertTrue(proof["ok"])
        self.assertFalse(proof["checker"]["producer_reemission_used"])

    def test_machine_arithmetic_mutant_still_has_a_counterexample_after_renaming(self):
        _, changed, image, data, _, _ = self.cases["sse2", 1, "sum_u8"]
        at = image.text_bytes.index(bytes.fromhex("660fd4c1"))
        obj, final = bytearray(image.object_bytes), bytearray(data)
        for blob, elf_kind in ((obj, 1), (final, 3)):
            offset = _ELF(bytes(blob), elf_kind).section(".text")["offset"] + at
            blob[offset:offset + 4] = bytes.fromhex("660ffbc1")
        with self.assertRaises(VerifiedSIMDRejected) as caught:
            validate_verified_simd_artifact(changed, bytes(obj), bytes(final))
        self.assertEqual(caught.exception.counterexample["obligation"], "vector_sum_induction")

    def test_ordinary_shared_cli_admits_all_three_user_named_recurrences(self):
        from tests.test_hia_verified_cli import _invoke
        for kind in KINDS:
            core = verify_program(renamed(simd_kernel_program(kind), crossed=True))
            source, output = self.root / (kind + ".core.hepta"), self.root / (kind + ".cli.so")
            source.write_bytes(core.canonical_bytes)
            code, stdout, stderr = _invoke(["build", source, "-o", output, "--kind", "shared",
                                           "--target-isa", "sse2"])
            with self.subTest(kind=kind):
                self.assertEqual(code, 0, (stdout, stderr))
                report = json.loads(stdout)
                self.assertTrue(output.is_file())
                self.assertEqual(report["selected_strategy"], "simd")
                self.assertEqual(report["validation"]["subject"]["core_sha256"], core.sha256)
                self.assertEqual(report["validation"]["core_recognition"]["original_core_sha256"], core.sha256)


if __name__ == "__main__":
    unittest.main()
