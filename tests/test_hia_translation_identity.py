"""Dependency identity regressions, with real SMT replay tests kept separate.

Virtual source-read mutations never edit the shared checkout or replace rule
implementations. They test provenance invalidation, not altered semantics.
Only the separately gated class claims to execute the actual SMT validator.
"""
from __future__ import annotations

import ast
from contextlib import contextmanager
from copy import deepcopy
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

from hepta import hia_translation_validation as validator
from hepta.hia_program import HIAProgramRejected, verify_program


SOURCE_ROOT = Path(validator.__file__).parent


def scalar(value=7):
    return {
        "schema": "hepta.hia.program.v1", "module": "translation_identity",
        "functions": [{"name": "value", "params": [], "returns": ["u8"],
            "effects": [], "entry": "entry", "blocks": [{"id": "entry", "params": [],
                "ops": [{"op": "const", "args": [], "out": [{"name": "answer", "type": "u8"}],
                         "attrs": {"value": value}}],
                "term": {"op": "ret", "values": ["answer"]}}]}],
    }


@contextmanager
def changed_source(name, *, unavailable=False):
    """Inject one on-disk identity observation without touching any file."""
    original = Path.read_bytes
    selected = SOURCE_ROOT / name

    def read(path):
        if path == selected:
            if unavailable:
                raise OSError("injected unreadable semantic dependency")
            return original(path) + b"\n# changed semantic dependency revision\n"
        return original(path)

    with patch.object(Path, "read_bytes", read):
        yield


class TranslationIdentityBoundaryTests(unittest.TestCase):
    def test_identity_covers_the_actual_transitive_local_import_graph(self):
        # Derive dependencies independently from all relative imports, including
        # imports inside admission/replay functions and circular helper imports.
        pending, visited = ["hia_translation_validation.py"], set()
        while pending:
            name = pending.pop()
            if name in visited:
                continue
            visited.add(name)
            for node in ast.walk(ast.parse((SOURCE_ROOT / name).read_bytes())):
                if not isinstance(node, ast.ImportFrom) or not node.level:
                    continue
                self.assertEqual(node.level, 1, "new parent-package dependency needs an explicit identity review")
                modules = [node.module] if node.module else [item.name for item in node.names]
                for module in modules:
                    dependency = module.replace(".", "/") + ".py"
                    self.assertTrue((SOURCE_ROOT / dependency).is_file(), dependency)
                    pending.append(dependency)
        self.assertEqual(visited, set(validator._SEMANTIC_IMPLEMENTATION_INPUTS))
        self.assertEqual(len(validator._SEMANTIC_IMPLEMENTATION_INPUTS), len(visited))

    def test_each_external_rule_and_vm_dependency_changes_checker_identity(self):
        before = validator._implementation_digest()
        for name in validator._SEMANTIC_IMPLEMENTATION_INPUTS:
            with self.subTest(source=name), changed_source(name):
                self.assertNotEqual(validator._implementation_digest(), before)
        self.assertEqual(validator._implementation_digest(), before)

    def test_unknown_receipts_also_record_the_actual_dependency_revision(self):
        core = scalar()
        with patch.object(validator, "_z3_module", side_effect=ImportError("explicit solver-unavailable control")):
            before = validator.validate_translation(core, core)
            self.assertEqual(before["status"], "unknown")
            self.assertEqual(before["reason"], "solver_unavailable")
            self.assertTrue(all(before["structural_verification"].values()))
            for name in ("hia_opcodes.py", "hia_program_runtime.py", "hia_semantic_kernel.py"):
                with self.subTest(source=name), changed_source(name):
                    after = validator.validate_translation(core, core)
                    self.assertEqual(after["status"], "unknown")
                    self.assertEqual(after["reason"], "solver_unavailable")
                    self.assertNotEqual(before["validator_sha256"], after["validator_sha256"])
                    self.assertFalse(after["claims"]["all_input_behavior_equivalence_proved"])

    def test_unreadable_dependency_cannot_grant_identity_or_proof(self):
        with changed_source("hia_program_runtime.py", unavailable=True):
            with self.assertRaisesRegex(OSError, "unreadable semantic dependency"):
                validator.validate_translation(scalar(), scalar())

    def test_actual_core_admission_is_not_replaced_by_the_source_fingerprint(self):
        invalid = scalar()
        invalid["functions"][0]["blocks"][0]["ops"][0]["attrs"]["value"] = 256
        with patch.object(validator, "_z3_module", side_effect=AssertionError("invalid Core reached SMT")):
            result = validator.validate_translation(invalid, scalar())
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["reason"], "invalid_before_program")
        self.assertFalse(result["claims"]["canonical_core_reverified"])


@unittest.skipUnless(importlib.util.find_spec("z3") is not None,
                     "actual Z3 required; skipped replay is not a passed SMT qualification")
class TranslationIdentitySMTTests(unittest.TestCase):
    def test_old_receipts_are_rejected_after_each_semantic_dependency_changes(self):
        core = scalar()
        original = validator.validate_translation(core, core)
        self.assertEqual(original["status"], "proved", original)
        actual_validate = validator.validate_translation
        for name in validator._SEMANTIC_IMPLEMENTATION_INPUTS:
            with self.subTest(source=name):
                fresh = []

                def replay(*args, **kwargs):
                    result = actual_validate(*args, **kwargs)
                    fresh.append(result)
                    return result

                with changed_source(name), patch.object(validator, "validate_translation", side_effect=replay):
                    with self.assertRaisesRegex(HIAProgramRejected, "not bound to the current"):
                        validator.verify_translation_receipt(core, core, original)
                self.assertEqual(len(fresh), 1)
                self.assertEqual(fresh[0]["status"], "proved", fresh)
                self.assertTrue(all(fresh[0]["structural_verification"].values()))
                self.assertNotEqual(fresh[0]["validator_sha256"], original["validator_sha256"])
        self.assertEqual(validator.verify_translation_receipt(core, core, original)["status"], "proved")

    def test_matching_forged_identity_cannot_replace_actual_proof_replay(self):
        before, wrong = scalar(), scalar(8)
        forged = deepcopy(validator.validate_translation(before, before))
        self.assertEqual(forged["status"], "proved", forged)
        checked = verify_program(wrong)
        forged.update(after_sha256=checked.sha256, after_input_sha256=checked.input_sha256,
                      validator_sha256=validator._implementation_digest())
        actual_validate = validator.validate_translation
        fresh = []

        def replay(*args, **kwargs):
            result = actual_validate(*args, **kwargs)
            fresh.append(result)
            return result

        with patch.object(validator, "validate_translation", side_effect=replay):
            with self.assertRaisesRegex(HIAProgramRejected, "could not be recomputed"):
                validator.verify_translation_receipt(before, wrong, forged)
        self.assertEqual(len(fresh), 1)
        self.assertEqual(fresh[0]["status"], "disproved", fresh)
        self.assertEqual(fresh[0]["counterexample"]["before"]["values"], [7])
        self.assertEqual(fresh[0]["counterexample"]["after"]["values"], [8])


if __name__ == "__main__":
    unittest.main()
