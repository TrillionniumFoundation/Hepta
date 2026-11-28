"""Exact original emission and cache admission controls for cold bulk-word."""
import ast
import copy
from hashlib import sha256
from pathlib import Path
import unittest

from hepta.hia_agent_assembly import render_assembly
from tools import generate_hia_seed_cold_bulk_word_backend as author
from tools import generate_hia_seed_cold_endian_shift_backend as shared
from tools.generate_hia_worker_config_json import document

ROOT = Path(__file__).resolve().parents[1]
ORIGINAL = "7943019c96438fd6f39bcc3905061a4be8e56d86516fe28c5e4f82c0b96ff565"
ADDED = {"generate_cached", "instruction_cached", "scalar_cached",
         "mark_shift_entries", "scalar_cache_reset", "scalar_cached_load",
         "scalar_cache_result", "scalar_cache_eligible"}


class ColdBulkScalarCacheSourceTests(unittest.TestCase):
    def test_complete_original_fallback_and_admission_remain_unchanged(self):
        parent = author.word_program()
        self.assertEqual(sha256(parent.encode()).hexdigest(), ORIGINAL)
        original = ast.parse(parent)
        current = ast.parse(author.program())
        before = {node.name: node for node in original.body}
        after = {node.name: node for node in current.body}
        self.assertEqual(set(after) - set(before), ADDED)
        for name in before:
            if name != "generate":
                self.assertEqual(ast.dump(before[name]), ast.dump(after[name]), name)
        guard, *retained = after["generate"].body
        self.assertEqual(ast.dump(guard), ast.dump(ast.parse(
            "if scalar_cache_eligible(s,w) != 0:\n"
            "    return generate_cached(s,o,w)\n").body[0]))
        self.assertEqual([ast.dump(node) for node in retained],
                         [ast.dump(node) for node in before["generate"].body])
        inverse = copy.deepcopy(current)
        inverse.body = [node for node in inverse.body if node.name not in ADDED]
        next(node for node in inverse.body if node.name == "generate").body.pop(0)
        self.assertEqual(ast.dump(inverse), ast.dump(original))

    def test_modified_parent_reapplication_and_cross_profile_admission_refuse(self):
        parent = author.word_program()
        changed = [
            parent + "\n",
            parent.replace("registers > 2048", "registers > 4096"),
            parent.replace("length(w) < 1048576", "length(w) < 1048568"),
            parent.replace("normalize(o, w, width)", "normalize(o, w, 64)"),
            author.program(),
        ]
        for source in changed:
            with self.subTest(digest=sha256(source.encode()).hexdigest()):
                self.assertNotEqual(source, parent)
                with self.assertRaises(ValueError):
                    author.cached_program(source)
        marked = author.marked_program(parent)
        with self.assertRaises(ValueError):
            shared.cache_program(marked)
        with self.assertRaises(ValueError):
            shared.cache_program(shared.shift_program(), profile="bulk-word")
        with self.assertRaises(ValueError):
            shared.cache_program(marked, profile="unknown")

    def test_only_an_actual_resource26_site_enables_cache(self):
        node = next(node for node in ast.parse(author.program()).body
                    if node.name == "scalar_cache_eligible")
        namespace = {"readbuf": object, "mutbuf": object, "u64": int,
                     "word": lambda view, at: view[at],
                     "get": lambda view, at: view[at]}
        exec(compile(ast.fix_missing_locations(ast.Module(body=[node], type_ignores=[])),
                     "<actual bulk cache admission>", "exec"), namespace)
        eligible = namespace["scalar_cache_eligible"]
        workspace = {40: 128, 48: 256}
        source = {128: 32, 136: 26, 192: 38, 200: 512, 512: 24}
        self.assertEqual(eligible(source, workspace), 0)
        for code in (3, 4, 5, 7, 10, 24):
            source[512] = code
            self.assertEqual(eligible(source, workspace), 0)
        source[512] = 26
        self.assertEqual(eligible(source, workspace), 1)
        source[192] = 32
        self.assertEqual(eligible(source, workspace), 0)
        workspace[48] = workspace[40]
        self.assertEqual(eligible(source, workspace), 0)
        entry = next(node for node in ast.parse(author.program()).body
                     if node.name == "seed_cold_bulk_word_backend")
        original = next(node for node in ast.parse(author.word_program()).body
                        if node.name == "seed_cold_bulk_word_backend")
        self.assertEqual(ast.dump(entry), ast.dump(original))

    def test_native_source_is_exact_author_output_and_old_endian_output_is_unchanged(self):
        raw = render_assembly(document(author.program(), "seed_cold_bulk_word_backend")).encode()
        self.assertEqual(raw, (ROOT / "examples/hia_bootstrap/seed_cold_bulk_word_backend.hepta").read_bytes())
        endian = render_assembly(document(shared.program(), "seed_cold_endian_shift_backend")).encode()
        self.assertEqual(sha256(endian).hexdigest(),
                         "e41c77c3942dcdab270e8b39f701de29fdb603551a0af0085850be3173219bbd")
        self.assertEqual(endian, (ROOT / "examples/hia_bootstrap/seed_cold_endian_shift_backend.hepta").read_bytes())

    def test_operational_profiles_are_exact_and_bootstrap_choices_are_retained(self):
        from types import SimpleNamespace
        from tools.generate_hia_cold_toolchain_build import Stage, OPERATIONAL_PROFILES
        from tools.hia_native_cold_preseed import Builder, OPERATIONAL_PROFILES as PRESEED
        expected = {
            "source_contract_generate": "v1",
            "cold_master": "word",
            "cold_source_export": "v1",
            "cold_plan_inventory": "v1",
            "cold_descriptor_compose": "v1",
            "cold_cli_bind": "v1",
        }
        self.assertEqual(OPERATIONAL_PROFILES, expected)
        self.assertEqual(PRESEED, expected)
        stage = object.__new__(Stage)
        stage.build = SimpleNamespace(root=ROOT)
        for role, profile in expected.items():
            self.assertEqual(stage.profile(role), profile)
            self.assertEqual(stage.operational_profile(role), "cold-bulk-word")
        for cls in (Stage, Builder):
            instance = object.__new__(cls)
            for role, profile in expected.items():
                instance.profile = lambda name, selected=profile: selected
                self.assertEqual(instance.operational_profile(role), "cold-bulk-word")
                for wrong in {"v1", "word", "div", "div-bulk", "cold-endian",
                              "cold-bulk", "cold-bulk-word", "owned", "vm"} - {profile}:
                    instance.profile = lambda name, selected=wrong: selected
                    with self.assertRaises(ValueError):
                        instance.operational_profile(role)
            for role in ("probe", "seed_backend", "seed_front_bulk/evaluate_reference_wire",
                         "subprocess", "cold_replay_owner", "cold_cli"):
                for profile in ("v1", "word", "div", "cold-bulk", "cold-endian", "vm"):
                    instance.profile = lambda name, selected=profile: selected
                    self.assertEqual(instance.operational_profile(role), profile)


if __name__ == "__main__":
    unittest.main()
