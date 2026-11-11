"""Identity-build admission and custody controls; compilation is explicitly stubbed.

These fixtures exercise the real shared cold admission gate. They do not execute
native code or qualify a compiler, worker, or complete candidate.
"""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import build_hia_agent_identity as builder
from tools import build_hia_json_preflight as admission
from tools.hia_selfhost_contract import PROFILE


class AgentIdentitySourceBindingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hia-identity-source-binding-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source_name = "examples/hia_bootstrap/agent_identity.hepta"
        self.source = self.root / self.source_name
        self.source.parent.mkdir(parents=True)
        self.source.write_bytes(b"synthetic identity source; never executed\n")
        self.compiler = self.root / "compiler.bin"
        self.compiler.write_bytes(b"synthetic compiler; never executed\n")
        self.sources = {
            self.source_name: sha256(self.source.read_bytes()).hexdigest(),
            "hepta/another_dependency.py": "a" * 64,
        }
        checks = (
            "export_manifest_matches_qualification", "isolated_python_without_site",
            "nested_full_qualification_pass", "nested_process_exit_zero", "no_ancestor_git_identity",
            "no_bytecode_cache_created", "no_inherited_home_or_python_cache",
            "no_inherited_seed_or_successor_images", "origin_hashes_preserved",
            "owned_process_tree_cleanup_confirmed", "source_export_hashes_preserved",
        )
        self.report = {
            "schema": "hepta.hia.selfhost-cold-replay.v1", "profile": PROFILE,
            "status": "COLD_SELFHOST_REPLAY_PASS", "returncode": 0,
            "checks": dict.fromkeys(checks, True), "source_manifest": deepcopy(self.sources),
            "generation_sha256": [sha256(self.compiler.read_bytes()).hexdigest()] * 3,
        }
        self.cold = self.root / "cold.json"
        self.cold.write_text(json.dumps(self.report))
        for target, attribute, value in (
            (builder, "ROOT", self.root),
            (admission, "current_sources", lambda: deepcopy(self.sources)),
        ):
            context = patch.object(target, attribute, value)
            context.start()
            self.addCleanup(context.stop)
        context = patch("tools.qualify_hia_selfhost.compile_stage", side_effect=self.compile_fixture)
        self.compile = context.start()
        self.addCleanup(context.stop)

    def compile_fixture(self, output, name, compiler, source):
        self.assertEqual(name, "agent-identity")
        self.assertEqual(compiler, self.compiler)
        image = output / "image.bin"
        image.write_bytes(b"synthetic emitted bytes; never executed\n")
        return image, {"compilation_stubbed": True, "native_execution_performed": False}

    def assert_no_publication(self, output):
        self.assertFalse((output / "manifest.json").exists())
        self.assertFalse((output / "build.json").exists())

    def test_matching_source_retains_full_map_without_expanding_native_claims(self):
        output = self.root / "output"
        manifest_path = builder.build(output, self.compiler, self.cold)
        self.compile.assert_called_once()
        manifest = json.loads(manifest_path.read_bytes())
        report = json.loads((output / "build.json").read_bytes())
        self.assertEqual(manifest["schema"], "hepta.hia.agent-identity-native.v1")
        self.assertEqual(manifest["source_sha256"], self.sources[self.source_name])
        self.assertEqual(manifest["compiler_sha256"], self.report["generation_sha256"][0])
        self.assertEqual(report["source_manifest"], self.sources)
        self.assertEqual(report["cold_report_sha256"], sha256(self.cold.read_bytes()).hexdigest())
        self.assertFalse(report["production_activated"])
        self.assertFalse(report["whole_agent_protocol_and_persistence_replaced"])
        self.assertFalse(report["all_input_equivalence_proved"])
        self.assertFalse(report["whole_stack_rewritten_in_hia"])

    def test_foreign_profile_or_source_map_is_rejected_before_any_output(self):
        cases = (
            {"profile": "different-support-domain"},
            {"source_manifest": {}},
            {"source_manifest": {**self.sources, self.source_name: "0" * 64}},
            {"source_manifest": {**self.sources, "hepta/another_dependency.py": "b" * 64}},
        )
        for index, changes in enumerate(cases):
            with self.subTest(changes=changes):
                self.cold.write_text(json.dumps({**self.report, **changes}))
                output = self.root / ("refused-" + str(index))
                with self.assertRaises(ValueError):
                    builder.build(output, self.compiler, self.cold)
                self.assertFalse(output.exists())
        self.compile.assert_not_called()

    def test_helper_absent_from_map_or_different_from_admitted_bytes_is_rejected(self):
        for index, declared in enumerate((
            {name: value for name, value in self.sources.items() if name != self.source_name},
            {**self.sources, self.source_name: "0" * 64},
        )):
            with self.subTest(declared=declared):
                self.cold.write_text(json.dumps({**self.report, "source_manifest": declared}))
                output = self.root / ("helper-refused-" + str(index))
                with patch.object(admission, "current_sources", return_value=declared):
                    with self.assertRaisesRegex(ValueError, "source differs"):
                        builder.build(output, self.compiler, self.cold)
                self.assertFalse(output.exists())
        self.compile.assert_not_called()

    def test_complete_source_map_is_rechecked_after_compilation(self):
        def drift(output, name, compiler, source):
            result = self.compile_fixture(output, name, compiler, source)
            self.sources["hepta/another_dependency.py"] = "b" * 64
            return result

        self.compile.side_effect = drift
        output = self.root / "drifted-source"
        with self.assertRaisesRegex(ValueError, "build inputs changed"):
            builder.build(output, self.compiler, self.cold)
        self.compile.assert_called_once()
        self.assert_no_publication(output)

    def test_direct_input_drift_during_compilation_never_publishes_receipts(self):
        for index, changed in enumerate((self.source, self.compiler, self.cold)):
            with self.subTest(changed=changed.name):
                original = changed.read_bytes()

                def drift(output, name, compiler, source):
                    result = self.compile_fixture(output, name, compiler, source)
                    changed.write_bytes(original + b"changed")
                    return result

                self.compile.side_effect = drift
                output = self.root / ("drifted-input-" + str(index))
                try:
                    with self.assertRaisesRegex(ValueError, "build inputs changed"):
                        builder.build(output, self.compiler, self.cold)
                    self.assert_no_publication(output)
                finally:
                    changed.write_bytes(original)
        self.assertEqual(self.compile.call_count, 3)


if __name__ == "__main__":
    unittest.main()
