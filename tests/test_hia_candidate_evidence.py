"""Candidate identity and retained-evidence boundaries, without native qualification.

The original preflight suite remains separate. Synthetic reports below check
rejections and HOLD propagation; they never represent native executions.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from tools import hia_candidate_preflight as preflight


def snapshot(path, label, limit=preflight.MAX_JSON_BYTES):
    """Real bounded bytes for these source-only tests, not runtime qualification."""
    raw = preflight.bootstrap_read(path, limit)
    return raw, {"sha256": preflight.sha256(raw)}


def read_pinned(path, expected, label, limit=preflight.MAX_JSON_BYTES):
    raw, metadata = snapshot(path, label, limit)
    if metadata["sha256"] != expected:
        raise ValueError(label + " digest changed")
    return raw, metadata


class NativeInventoryBoundary(unittest.TestCase):
    def test_actual_current_worker_manifest_matches_native_asset_inventory(self):
        root = Path(__file__).resolve().parents[1]
        with mock.patch.object(preflight, "snapshot", snapshot):
            entries = preflight.worker_inventory(root)
        manifest = preflight.installed_pins(root, Path(sys.executable))
        self.assertEqual(preflight.sha256(preflight.canonical(entries)), manifest["worker_sha256"])
        assets = preflight.native_source_files((root / "hepta/hia_agent_contract.py").read_bytes())
        self.assertTrue(assets)
        self.assertTrue(set(assets) <= set(entries))

    def test_literal_assets_are_bounded_and_cross_inventory_unique(self):
        valid = ("NATIVE_SOURCE_FILES = ('examples/hia_bootstrap/native.hiaasm',)\n"
                 "PUBLICATION_BUILD_FILES = ('tools/adapter.S', 'tools/builder.py')\n")
        self.assertEqual(preflight.native_source_files(valid), (
            "examples/hia_bootstrap/native.hiaasm", "tools/adapter.S", "tools/builder.py"))
        invalid = [valid + "NATIVE_SOURCE_FILES = ()\n",
                   "NATIVE_SOURCE_FILES = get_files()\n",
                   "NATIVE_SOURCE_FILES = ('../outside.hiaasm',)\n",
                   "PUBLICATION_BUILD_FILES = ('/tmp/arbitrary.py',)\n",
                   valid.replace("tools/adapter.S", "examples/hia_bootstrap/native.hiaasm")]
        for source in invalid:
            with self.subTest(source=source), self.assertRaises(ValueError):
                preflight.native_source_files(source)

    def test_historical_worker_without_native_assets_keeps_its_identity_domain(self):
        self.assertEqual(preflight.native_source_files("DISCOVERY_FILES = ()\n"), ())

    def test_native_helper_config_is_explicit_paired_pinned_and_within_policy(self):
        from tests.test_hia_candidate_preflight import PINS, config
        pins = {**PINS, preflight.NATIVE_HELPER_PIN: "a" * 64}
        value = config()
        value["hia_worker"].update(native_helpers_manifest="/srv/helpers.json", **pins)
        self.assertEqual(preflight.validate_config(value, pins)["native_helpers_manifest"], "/srv/helpers.json")
        for field in ("native_helpers_manifest", preflight.NATIVE_HELPER_PIN):
            incomplete = copy.deepcopy(value)
            del incomplete["hia_worker"][field]
            with self.subTest(field=field), self.assertRaises(ValueError):
                preflight.validate_config(incomplete, pins)
        value["hia_worker"]["native_helpers_manifest"] = "/srv/private/helpers.json"
        with self.assertRaisesRegex(ValueError, "read policy"):
            preflight.validate_config(value, pins)

    def test_manifest_command_carries_both_explicit_selection_arguments(self):
        from tests.test_hia_candidate_preflight import PINS
        pins = {**PINS, preflight.NATIVE_HELPER_PIN: "a" * 64}
        completed = subprocess.CompletedProcess([], 0, preflight.json_bytes(pins), b"")
        with mock.patch.object(preflight, "require_uncached_worker_source"), \
             mock.patch.object(preflight.subprocess, "run", return_value=completed) as run:
            actual = preflight.installed_pins(Path("/srv/source"), Path("/usr/bin/python3"),
                native_helpers=("/srv/helpers.json", "a" * 64))
        self.assertEqual(actual, pins)
        self.assertEqual(run.call_args.args[0][-4:], ["--native-helpers-manifest", "/srv/helpers.json",
                                                     "--expected-native-helpers-sha256", "a" * 64])

    def test_asset_git_identity_detects_hidden_source_change_and_ancestor_symlink(self):
        with tempfile.TemporaryDirectory(prefix="hia-native-inventory-") as directory:
            root = Path(directory)
            files = {"hepta/hia_agent_worker.py": b"", "hepta/hia_agent_store.py": b"",
                     "hepta/hia_agent_contract.py": (
                         "DISCOVERY_FILES = " + repr(tuple(sorted(preflight.REQUIRED_WORKER_DOCS))) + "\n"
                         "NATIVE_SOURCE_FILES = ('examples/hia_bootstrap/native.hiaasm',)\n").encode(),
                     "examples/hia_bootstrap/native.hiaasm": b"original native source\n",
                     **{"docs/" + name: b"{}\n" for name in preflight.REQUIRED_WORKER_DOCS}}
            for name, raw in files.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(raw)

            def git(*args):
                return subprocess.check_output(["git", "-C", str(root), *args], text=True)

            git("init", "-q")
            git("add", ".")
            git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "fixture")
            revision = git("rev-parse", "HEAD").strip()
            with mock.patch.object(preflight, "snapshot", snapshot):
                original = preflight.worker_inventory(root)
                self.assertTrue(preflight.worker_matches_commit(root, revision, original))
                asset = root / "examples/hia_bootstrap/native.hiaasm"
                git("update-index", "--assume-unchanged", "examples/hia_bootstrap/native.hiaasm")
                asset.write_bytes(b"changed native source\n")
                self.assertEqual(git("status", "--porcelain"), "")
                altered = preflight.worker_inventory(root)
                self.assertNotEqual(original, altered)
                self.assertFalse(preflight.worker_matches_commit(root, revision, altered))
                actual = asset.parent.with_name("actual")
                asset.parent.rename(actual)
                asset.parent.symlink_to(actual, target_is_directory=True)
                with self.assertRaisesRegex(ValueError, "symbolic links"):
                    preflight.worker_inventory(root)


class RetainedEvidenceBoundary(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hia-evidence-binding-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.source.mkdir()
        names = ("agent_stdio_dispatch", "agent_stdio_packer", "core_json_frontend")
        self.sources = {}
        for name in names:
            path = "examples/hia_bootstrap/" + name + ".hiaasm"
            raw = ("synthetic source " + name).encode()
            destination = self.source / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(raw)
            self.sources[path] = preflight.sha256(raw)
        contract = {"schema": "hepta.hia.selfhost-core-support.v1", "profile": "fixture-profile",
                    "target": {"triple": "x86_64-unknown-linux-gnu"}, "abi": {"entry": "f0"},
                    "support": [], "syntax": {}, "limits": {}, "source_identity": {"files": self.sources.copy()}}
        path = self.source / preflight.SUPPORT_CONTRACT
        path.parent.mkdir()
        path.write_bytes(preflight.json_bytes(contract))
        self.sources[preflight.SUPPORT_CONTRACT] = preflight.sha256(path.read_bytes())

        def git(*args):
            return subprocess.check_output(["git", "-C", str(self.source), *args], text=True)

        git("init", "-q")
        git("add", ".")
        git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "fixture")
        self.revision = git("rev-parse", "HEAD").strip()
        for name, function in (("snapshot", snapshot), ("read_pinned", read_pinned)):
            patch = mock.patch.object(preflight, name, function)
            patch.start()
            self.addCleanup(patch.stop)
        self.support = preflight.native_support_identity(self.source, self.sources)
        required = ("export_manifest_matches_qualification", "isolated_python_without_site",
                    "nested_full_qualification_pass", "nested_process_exit_zero", "no_ancestor_git_identity",
                    "no_bytecode_cache_created", "no_inherited_home_or_python_cache",
                    "no_inherited_seed_or_successor_images", "origin_hashes_preserved",
                    "owned_process_tree_cleanup_confirmed", "source_export_hashes_preserved")
        self.compiler = "a" * 64
        self.cold = {"schema": "hepta.hia.selfhost-cold-replay.v1", "profile": "fixture-profile",
                     "source_manifest": self.sources, "status": "COLD_SELFHOST_REPLAY_PASS",
                     "returncode": 0, "checks": {key: True for key in required},
                     "qualification_wall_limit_seconds": 180, "cleanup_wall_limit_seconds": 3,
                     "generation_sha256": [self.compiler] * 3,
                     "process_owner": {"status": "OWNED_PROCESS_COMPLETED", "timed_out": False,
                                       "exit_observed_before_deadline": True, "cleanup": {"complete": True}}}

    def reference(self, name, value):
        raw = value if type(value) is bytes else preflight.json_bytes(value)
        path = self.root / name
        path.write_bytes(raw)
        return {"path": str(path), "sha256": preflight.sha256(raw)}

    def qualify(self, artifacts):
        bundle = self.reference("bundle.json", {"schema": preflight.EVIDENCE_SCHEMA, "artifacts": artifacts})
        return preflight.qualification_evidence(self.source, self.revision, self.support, bundle)

    def language(self):
        checks = {name: True for name in (
            "reference_vm_matches_all_scalar_oracles", "inventory_matches_actual_compiler_source",
            "original_fixed_point", "modified_fixed_point", "source_bound_before_execution", "source_closure_unchanged")}
        report = {"schema": "hepta.hia.selfhost-language-qualification.v1", "profile": "fixture-profile",
                  "source_manifest": self.sources, "status": "SELFHOST_LANGUAGE_COVERAGE_PASS", "checks": checks,
                  "counts": {"checks_total": len(checks), "checks_passed": len(checks), "compilers": 2},
                  "generations": [{"produced_sha256": self.compiler}] * 3}
        reference = self.reference("language.json", report)
        assertions = {"schema": "hepta.hia.selfhost-language-native-assertions.v1",
                      "report_sha256": reference["sha256"], "passed": True, "tests_run": 10,
                      "errors": [], "failures": [], "skipped": []}
        return reference, assertions

    def test_no_reports_cannot_qualify_a_source_pin(self):
        result = preflight.qualification_evidence(self.source, self.revision, self.support)
        self.assertEqual(result["status"], "HOLD")
        self.assertFalse(result["whole_candidate_qualified"])
        self.assertEqual(result["gates"]["cold"]["status"], "missing")

    def test_original_timeout_is_retained_as_failed(self):
        self.cold.update(status="FAIL", returncode=-15)
        self.cold["process_owner"].update(status="QUALIFICATION_TIMEOUT", timed_out=True)
        result = self.qualify({"cold": self.reference("cold.json", self.cold)})
        self.assertEqual(result["gates"]["cold"], {"status": "failed", "original_status": "FAIL"})
        self.assertEqual(result["status"], "HOLD")

    def test_partial_checks_changed_deadline_unknown_cleanup_or_non_integer_exit_cannot_pass(self):
        for changed in ({"checks": {}}, {"qualification_wall_limit_seconds": 181},
                        {"process_owner": {}}, {"process_owner": []}, {"returncode": True},
                        {"generation_sha256": []}, {"generation_sha256": [{}, {}, {}]}):
            with self.subTest(changed=changed):
                report = {**self.cold, **changed}
                result = self.qualify({"cold": self.reference("cold.json", report)})
                self.assertEqual(result["gates"]["cold"]["status"], "failed")

    def test_passing_cold_does_not_claim_native_worker_or_whole_candidate(self):
        result = self.qualify({"cold": self.reference("cold.json", self.cold)})
        self.assertEqual(result["gates"]["cold"]["status"], "passed")
        self.assertEqual(result["gates"]["native_worker"]["status"], "not_established")
        self.assertFalse(result["whole_candidate_qualified"])

    def test_different_source_or_support_profile_is_rejected(self):
        for changed in ({"source_manifest": {}}, {"profile": "another-profile"}):
            with self.subTest(changed=changed), self.assertRaisesRegex(ValueError, "different source"):
                self.qualify({"cold": self.reference("cold.json", {**self.cold, **changed})})

    def test_changed_original_bytes_are_not_repaired_or_reinterpreted(self):
        reference = self.reference("cold.json", self.cold)
        Path(reference["path"]).write_bytes(b"{}")
        with self.assertRaisesRegex(ValueError, "digest changed"):
            self.qualify({"cold": reference})

    def test_native_source_drift_is_rejected_even_when_report_is_unchanged(self):
        source = self.source / "examples/hia_bootstrap/core_json_frontend.hiaasm"
        source.write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "digest changed"):
            self.qualify({"cold": self.reference("cold.json", self.cold)})

    def test_unattached_assertions_and_unknown_artifacts_are_rejected(self):
        for artifacts in ({"language_assertions": self.reference("assertions.json", {})},
                          {"unrecognized": self.reference("other.json", {})}):
            with self.subTest(artifacts=artifacts), self.assertRaises(ValueError):
                self.qualify(artifacts)

    def test_language_requires_native_assertions_and_identical_cold_compiler(self):
        cold = self.reference("cold.json", self.cold)
        language, assertions = self.language()
        missing = self.qualify({"cold": cold, "language": language})
        self.assertEqual(missing["gates"]["language"]["status"], "failed")
        good = self.qualify({"cold": cold, "language": language,
                             "language_assertions": self.reference("assertions.json", assertions)})
        self.assertEqual(good["gates"]["language"]["status"], "passed")
        self.assertEqual(good["status"], "HOLD")
        assertions["report_sha256"] = "0" * 64
        mismatched = self.qualify({"cold": cold, "language": language,
                                  "language_assertions": self.reference("assertions.json", assertions)})
        self.assertEqual(mismatched["gates"]["language"]["status"], "failed")

    def test_native_image_build_is_bound_without_claiming_execution(self):
        cold = self.reference("cold.json", self.cold)
        # This is deliberately data, not executed native code. Even a consistent
        # captured build record must leave the separate worker gate unresolved.
        raw = bytearray(177)
        raw[:16] = b"\x7fELF\x02\x01\x01" + bytes(9)
        struct.pack_into("<HHIQQQIHHHHHH", raw, 16, 2, 62, 1, 0x4000b0, 64, 0, 0, 64, 56, 2, 0, 0, 0)
        struct.pack_into("<IIQQQQQQ", raw, 64, 1, 5, 0, 0x400000, 0x400000, len(raw), len(raw), 4096)
        struct.pack_into("<IIQQQQQQ", raw, 120, 0x6474e551, 6, 0, 0, 0, 0, 0, 16)
        raw[176] = 0xc3
        raw = bytes(raw)
        image = self.reference("image.bin", raw)
        build = {"schema": "hepta.hia.agent-stdio-build.v1", "status": "NATIVE_AGENT_STDIO_BUILT",
                 "source_sha256": {name: value for name, value in self.sources.items() if name.endswith(".hiaasm")},
                 "compiler_sha256": self.compiler, "cold_report_sha256": cold["sha256"], "output_profile": "flat",
                 "executable": {"sha256": image["sha256"], "bytes": len(raw), "machine": "EM_X86_64",
                                "elf_type": "ET_EXEC", "entry": 0x4000b0,
                                "program_headers": ["PT_LOAD_RX", "PT_GNU_STACK_RW"], "interpreter": None,
                                "dynamic_loader": False, "libc": False}}
        result = self.qualify({"cold": cold, "native_image": image, "native_build": self.reference("build.json", build)})
        self.assertEqual(result["gates"]["native_image_build"]["status"], "passed")
        self.assertFalse(result["gates"]["native_image_build"]["native_worker_execution_qualified"])
        self.assertFalse(result["whole_candidate_qualified"])
        replaced = self.reference("image.bin", raw + b"replacement")
        result = self.qualify({"cold": cold, "native_image": replaced, "native_build": self.reference("build.json", build)})
        self.assertEqual(result["gates"]["native_image_build"]["status"], "failed")

    def test_incomplete_image_custody_stays_incomplete(self):
        result = self.qualify({"native_image": self.reference("image.bin", b"unqualified")})
        self.assertEqual(result["gates"]["native_image_build"]["status"], "incomplete")
        self.assertFalse(result["whole_candidate_qualified"])


if __name__ == "__main__":
    unittest.main()
