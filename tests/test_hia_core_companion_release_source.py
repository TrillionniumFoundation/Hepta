"""Source and protocol controls for the native Core companion release addition."""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
from pathlib import Path
import struct
import unittest

from hepta.hia_agent_assembly import render_assembly
from tools import generate_hia_core_companion_manifest as owner
from tools import generate_hia_core_companion_stage as checker
from tools import generate_hia_core_companion_recipe as release
from tools import generate_hia_core_companion_worker_manifest as worker
from tools.generate_hia_source_helper_manifest import original, function, constant
from tools.hia_core_companion_release import manifest_request, check_request, COMPANIONS, inputs

ROOT = Path(__file__).resolve().parents[1]


class CoreCompanionReleaseSourceTests(unittest.TestCase):
    def test_checked_native_outputs_are_exact_author_outputs(self):
        self.assertEqual((ROOT / owner.OUTPUT).read_bytes(), owner.generated())
        self.assertEqual((ROOT / checker.OUTPUT).read_bytes(), checker.generated())
        self.assertEqual((ROOT / release.SOURCE_PATH).read_bytes(), release.recipe().binary())
        source, table, model = worker.render()
        self.assertEqual((ROOT / worker.SOURCE_PATH).read_bytes(), source)
        self.assertEqual((ROOT / worker.TABLE_PATH).read_bytes(), table)
        self.assertEqual(model["table_sha256"], sha256(table).hexdigest())

    def test_original_owner_child_compilation_and_sha_functions_are_retained(self):
        prior = original("helper")
        actual = {item["name"]: item for item in owner.document()["functions"]}
        for old in prior["functions"]:
            expected = deepcopy(old)
            if expected["name"] in ("admit", "render"):
                expected["name"] += "_original_reference"
            if expected["name"] == "helper_manifest":
                constant(expected, "v17", 512, 1024)
            self.assertEqual(actual[expected["name"]], expected)

    def test_original_global_stage_is_not_extended(self):
        self.assertEqual((ROOT / "examples/hia_bootstrap/source_release_stage_plan.hepta").read_bytes(),
                         render_assembly(original("stage")).encode("ascii"))

    def test_checker_keeps_independent_original_sha_and_object_parser(self):
        prior = original("stage")
        actual = {item["name"]: item for item in checker.document()["functions"]}
        self.assertEqual(actual["f46"], function(prior, "f46"))
        parser = deepcopy(function(prior, "f49"))
        constant(parser, "v4", 2048, 16384)
        constant(parser, "v34", 5, 8)
        constant(parser, "v89", 31, 255)
        self.assertEqual(actual["f49"], parser)
        self.assertNotIn("render", actual)
        self.assertNotIn("digest", actual)

    def test_checker_retains_original_cli_entry_with_only_closed_other_modes(self):
        entry = deepcopy(function(original("stage"), "f0"))
        count = 0
        for block in entry["blocks"]:
            for op in block["ops"]:
                if op["op"] == "call" and op["attrs"].get("function") in ("f1", "f16"):
                    op["attrs"]["function"] = "reject_other"
                    count += 1
        self.assertEqual(count, 2)
        self.assertEqual(function(checker.document(), "f0"), entry)

    def test_checker_stays_within_original_compiler_capacity(self):
        document = checker.document()
        functions = {f["name"]: f for f in document["functions"]}
        self.assertLess(sum(len(f["blocks"]) for f in functions.values()), 1536)
        for fn in functions.values():
            for block in fn["blocks"]:
                for op in block["ops"]:
                    if op["op"] == "call":
                        self.assertIn(op["attrs"]["function"], functions)

    def test_closed_request_words_and_all_seven_physical_inputs(self):
        pieces = tuple(bytes([index]) * (index + 1) for index in range(7))
        raw = manifest_request(11, pieces)
        self.assertEqual(struct.unpack("<8s8Q", raw[:72]),
                         (b"HIACCM01", 11, *map(len, pieces)))
        self.assertEqual(raw[72:], b"".join(pieces))
        checked = check_request(13, pieces)
        self.assertEqual(struct.unpack("<8s4Q", checked[:40]), (b"HIASTC01", 14, 13, 7, 0))
        at = 40
        for piece in pieces:
            length, = struct.unpack("<Q", checked[at:at + 8])
            at += 8
            self.assertEqual(checked[at:at + length], piece)
            at += length
        self.assertEqual(at, len(checked))

    def test_host_transport_rejects_type_aliases_and_partial_inputs(self):
        parts = (b"x",) * 7
        for role in (True, 11.0, "11", 9, 10, 14):
            with self.subTest(role=role), self.assertRaises(ValueError):
                manifest_request(role, parts)
            with self.subTest(check_role=role), self.assertRaises(ValueError):
                check_request(role, parts)
        for changed in (parts[:-1], (*parts, b"x"), (b"", *parts[1:]),
                        (bytearray(b"x"), *parts[1:])):
            with self.subTest(parts=repr(changed)[:80]), self.assertRaises(ValueError):
                manifest_request(11, changed)
        with self.assertRaises(ValueError):
            check_request(11, (b"x" * 16385, *parts[1:]))

    def test_release_dag_captures_abi_bridge_selection_and_uses_independent_checker(self):
        recipe = release.recipe()
        paths = set()
        for operation, _, _, raw in recipe.nodes:
            if operation != 1:
                continue
            count, = struct.unpack_from("<Q", raw)
            at = 8
            for _ in range(count):
                alias_len, path_len = struct.unpack_from("<2Q", raw, at)
                at += 16
                at += alias_len
                paths.add(raw[at:at + path_len].decode())
                at += path_len
            self.assertEqual(at, len(raw))
        for _, family in COMPANIONS:
            self.assertTrue(set(inputs(family)) <= paths)
        self.assertIn("examples/hia_bootstrap/" + release.OWNER, paths)
        self.assertIn("examples/hia_bootstrap/" + release.CHECKER, paths)
        self.assertFalse({operation for operation, _, _, _ in recipe.nodes} & {5, 10})
        checks = [raw for operation, _, _, raw in recipe.nodes
                  if operation == 12 and raw.startswith(b"HIASTC01")]
        self.assertEqual([struct.unpack("<8s4Q", raw) for raw in checks],
                         [(b"HIASTC01", 14, role, 7, 0) for role, _ in COMPANIONS])
        self.assertEqual(recipe.published, [
            name for _, family in COMPANIONS
            for name in ("core-" + family + "-manifest.json", "core-" + family + ".image.bin")])

    def test_native_wrapper_validates_three_complete_compiler_bound_children(self):
        records = worker.recipes()
        self.assertEqual([(r.mode, r.role) for r in records], [(1, 11), (1, 12), (1, 13), (2, 0)])
        for record in records[:3]:
            self.assertEqual(record.pieces, ["source", "image", "compiler", "abi", "bridge", "selection"])
            self.assertEqual(record.compiler_slot, 0)
            self.assertEqual(record.slots[0], (1, 2, b""))
        wrapper = records[-1]
        self.assertEqual(wrapper.output_path, "core-worker.json")
        for index, role in enumerate((11, 12, 13), 1):
            self.assertIn((3, index, 1, role, b""), wrapper.validators)
            self.assertIn((6, index, 0, 4, b""), wrapper.validators)
        self.assertEqual(wrapper.pieces[-1], "compiler")

    def test_worker_report_retains_original_page_outputs_and_adds_complete_core(self):
        from tools.generate_hia_worker_install_recipes import WorkerRecipe, report
        recipe = WorkerRecipe()
        report(recipe, {})
        self.assertEqual(recipe.published[:11], [
            "report/policy/worker-report.image.bin", "report/policy/manifest.json",
            "report/wire/json-wire.image.bin", "report/wire/manifest.json",
            "report/manifest.json", "report.json",
            "page/policy/artifact-page-policy.image.bin", "page/policy/manifest.json",
            "page/wire/json-wire.image.bin", "page/wire/manifest.json", "page/manifest.json",
        ])
        self.assertEqual(recipe.published[11:], [
            path for _, family in COMPANIONS for path in
            ("core/" + family + "/core-" + family + ".image.bin", "core/" + family + "/manifest.json")])

    def test_native_profile_binds_core_outside_page_before_store(self):
        from tools.generate_hia_worker_install_recipes import WorkerRecipe, profile
        recipe = WorkerRecipe()
        profile(recipe, {"families": []})
        self.assertEqual(recipe.published[-3:], ["page-worker.json", "core-worker.json", "worker.json"])
        from tools.generate_hia_worker_install_bind import policy_source
        value = policy_source()
        # The actual HIA template hashes the Core wrapper input. The Page owner remains separate.
        self.assertIn("core-worker.json", (ROOT / "tools/generate_hia_worker_install_bind.py").read_text())
        self.assertTrue(value)
