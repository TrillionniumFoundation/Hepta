"""Native CI binding controls; synthetic compiler bytes are never executed.

Git custody is real. Complete cold admission is mocked only where these
controls isolate the subsequent development-bridge binding; these methods
cannot qualify a cold compiler, transport component or release.
"""
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tools import hia_cold_native_transport_cold as binding
from tools.hia_cold_compiler import compiler_from_cold_report
from tools.hia_cold_native_transport_bridge import SOURCE_INPUTS, SCHEMA
from tools.hia_cold_native_transport_evidence import data_pin
from tools.hia_native_worker_source_authority import SOURCE_SUFFIXES


class NativeTransportColdBindingTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="hia-native-ci-binding-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.root = self.base / "authoring"
        self.root.mkdir()
        self.inputs = {name: ("unexecuted captured input " + name).encode()
                       for name in binding.TRANSPORT_INPUTS}
        for name, raw in self.inputs.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        self.git("init", "-q")
        self.git("add", ".")
        self.git("-c", "user.name=Control", "-c", "user.email=control@example.invalid",
                 "commit", "-qm", "Synthetic custody inputs, never executed")
        self.head = self.git("rev-parse", "HEAD").strip()
        self.sources = {name: sha256(raw).hexdigest() for name, raw in self.inputs.items()
                        if Path(name).suffix in SOURCE_SUFFIXES}
        self.image = b"\x7fELFsynthetic compiler location control; never executed"
        self.cold = self.base / "cold.json"
        self.report = {"schema": binding.NATIVE_SCHEMA, "source_manifest": self.sources,
                       "generation_sha256": [sha256(self.image).hexdigest()] * 3}
        self.cold_raw = json.dumps(self.report).encode()
        self.cold.write_bytes(self.cold_raw)
        rows = []
        for name in ("B1", "B2", "B3"):
            path = self.base / (name + ".flat")
            path.write_bytes(self.image)
            rows.append({"name": name, "produced_image": str(path),
                         "produced_bytes": len(self.image), "produced_sha256": sha256(self.image).hexdigest()})
        self.compiler = self.base / "B3.flat"
        self.index = {"schema": "hepta.hia.native-cold-generation-index.v1",
                      "source_head": self.head,
                      "native_report": {"path": str(self.cold), **data_pin(self.cold_raw)},
                      "generations": rows, "location_index_only": True,
                      "hosted_qualification_claimed": False}
        self.cold.with_suffix(".generations.json").write_text(json.dumps(self.index))
        custody = binding.capture_transport_custody(self.image, self.cold_raw,
                                                    self.sources, self.inputs, root=self.root)
        self.manifest_path = self.base / "manifest.json"
        self.manifest = {"schema": SCHEMA, "status": "BUILT_NOT_QUALIFIED_EXPLICIT_DEVELOPMENT",
                         "scope": "MATCHING_SOURCE_COLD_COMPILER", "whole_native": False,
                         "development_observation_only": True, "host_bridge_is_native_release": False,
                         "source_root": str(self.root), "inputs": {k: data_pin(self.inputs[k]) for k in SOURCE_INPUTS},
                         "development_inputs": {k: data_pin(self.inputs[k]) for k in binding.DEVELOPMENT_INPUTS},
                         "compiler": {"path": str(self.compiler), "pin": data_pin(self.image)},
                         "cold_report": {"path": str(self.cold), "pin": data_pin(self.cold_raw)},
                         "cold_source": self.sources, "component_input_custody": custody}
        self.manifest_path.write_text(json.dumps(self.manifest))

    def git(self, *args):
        return subprocess.check_output(["git", *args], cwd=self.root, text=True,
                                       stderr=subprocess.STDOUT)

    def read(self, manifest=None):
        if manifest is not None:
            self.manifest_path.write_text(json.dumps(manifest))
        with patch.object(binding, "ROOT", self.root), \
                patch("tools.build_hia_json_preflight.admit_cold_build", return_value=self.sources) as admit:
            value = binding.read_native_transport_binding(self.manifest_path, self.cold)
        admit.assert_called_once_with(self.image, self.cold_raw)
        return value

    def test_actual_git_custody_keeps_host_bridge_outside_native_authority(self):
        result = self.read()
        self.assertEqual(result["source_head"], self.head)
        self.assertEqual(result["compiler"], str(self.compiler))
        self.assertFalse(result["host_bridge_is_native_release"])
        self.assertEqual(result["scope"], "EXPLICIT_DEVELOPMENT_REGRESSION_ONLY")
        custody = self.manifest["component_input_custody"]
        self.assertEqual(set(custody["native_inputs"]), set(self.sources))
        self.assertFalse(custody["host_authoring_is_native_qualified"])
        self.assertFalse(custody["whole_native_delivery_qualified"])
        self.assertEqual(self.cold.read_bytes(), self.cold_raw)

    def test_missing_extra_and_redirected_input_roots_are_rejected(self):
        for mutation in ("missing", "extra", "directory", "development-missing", "development-extra"):
            changed = deepcopy(self.manifest)
            if mutation == "missing":
                changed["inputs"].pop(SOURCE_INPUTS[0])
            elif mutation == "extra":
                changed["inputs"]["tools/arbitrary.py"] = data_pin(b"unused")
            elif mutation == "directory":
                changed["source_root"] = str(self.base)
            elif mutation == "development-missing":
                changed["development_inputs"].pop(binding.DEVELOPMENT_INPUTS[0])
            else:
                changed["development_inputs"]["tools/arbitrary.py"] = data_pin(b"unused")
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.read(changed)

    def test_c_python_and_header_inputs_cannot_be_relabelled_as_native(self):
        for name in ("tools/hia_cold_native_transport.c", "tools/hia_cold_native_transport.h",
                     "tools/hia_cold_native_transport_bridge.py"):
            sources = {**self.sources, name: sha256(self.inputs[name]).hexdigest()}
            cold = json.dumps({**self.report, "source_manifest": sources}).encode()
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "cannot enter native"):
                binding.capture_transport_custody(self.image, cold, sources, self.inputs, root=self.root)

    def test_hia_implementation_cannot_be_relabelled_as_host_authoring(self):
        sources = dict(self.sources)
        sources.pop("examples/hia_bootstrap/cold_native_transport.hepta")
        cold = json.dumps({**self.report, "source_manifest": sources}).encode()
        with self.assertRaisesRegex(ValueError, "absent from cold authority"):
            binding.capture_transport_custody(self.image, cold, sources, self.inputs, root=self.root)

    def test_modified_git_bytes_or_modes_cannot_borrow_the_original_binding(self):
        name = "tools/hia_cold_native_transport.c"
        path = self.root / name
        original = path.read_bytes()
        path.write_bytes(original + b" modified")
        changed = {**self.inputs, name: path.read_bytes()}
        with self.assertRaises(ValueError):
            binding.capture_transport_custody(self.image, self.cold_raw, self.sources, changed, root=self.root)
        path.write_bytes(original)
        path.chmod(0o755)
        with self.assertRaises(ValueError):
            binding.capture_transport_custody(self.image, self.cold_raw, self.sources, self.inputs, root=self.root)

    def test_other_native_campaign_commit_is_not_current_authoring_custody(self):
        self.index["source_head"] = "0" * 40
        self.cold.with_suffix(".generations.json").write_text(json.dumps(self.index))
        with self.assertRaisesRegex(ValueError, "authoring commit differs"):
            self.read()

    def test_false_release_claims_or_custody_scope_are_rejected(self):
        for field, value in (("whole_native", True), ("development_observation_only", False),
                             ("host_bridge_is_native_release", True), ("scope", "DEVELOPMENT_COMPILER")):
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.read({**self.manifest, field: value})
        changed = deepcopy(self.manifest)
        changed["component_input_custody"]["host_authoring_is_native_qualified"] = True
        with self.assertRaises(ValueError):
            self.read(changed)

    def test_manifest_cannot_substitute_compiler_report_or_source_map(self):
        for field, value in (("compiler", {"path": str(self.base / "B2.flat"), "pin": data_pin(self.image)}),
                             ("cold_report", {"path": str(self.cold), "pin": data_pin(b"different")}),
                             ("cold_source", {})):
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.read({**self.manifest, field: value})

    def test_unqualified_cold_cannot_reach_transport_selection(self):
        with patch.object(binding, "ROOT", self.root), \
                patch("tools.build_hia_json_preflight.admit_cold_build",
                      side_effect=ValueError("complete actual native cold required")):
            with self.assertRaisesRegex(ValueError, "complete actual native cold required"):
                binding.read_native_transport_binding(self.manifest_path, self.cold)

    def test_v1_and_v2_locators_read_their_original_physical_generations(self):
        with patch("tools.build_hia_json_preflight.admit_cold_build", return_value=self.sources):
            self.assertEqual(compiler_from_cold_report(self.cold), self.compiler)
            legacy = self.base / "legacy.json"
            nested = self.base / "legacy-nested.json"
            raw = json.dumps({"generations": self.index["generations"]}).encode()
            nested.write_bytes(raw)
            legacy.write_text(json.dumps({"schema": "hepta.hia.selfhost-cold-replay.v1",
                "nested_report": str(nested), "nested_report_sha256": sha256(raw).hexdigest()}))
            self.assertEqual(compiler_from_cold_report(legacy), self.compiler)
            with self.assertRaises(ValueError):
                compiler_from_cold_report(legacy, generation_index=self.cold.with_suffix(".generations.json"))
        with patch.object(binding, "ROOT", self.root), self.assertRaises(ValueError):
            binding.read_native_transport_binding(self.manifest_path, legacy)

    def test_native_campaign_builds_a_separate_development_bridge_after_admission(self):
        from tools import qualify_hia_cold_native_transport as driver
        output = self.base / "campaign"
        success = {"exit_code": 0, "timed_out": False, "interruption": None,
                   "owned_cleanup": {"reaped": True, "after": [], "signals": []}}
        native = {**self.report, "status": "NATIVE_COLD_SELFHOST_REPLAY_PASS",
                  "qualification_wall_limit_seconds": 180, "cleanup_wall_limit_seconds": 3}
        def run(command, **kwargs):
            self.assertEqual(kwargs["timeout_seconds"], 900)
            cold_path = output / "cold.json"
            if Path(command[4]).name == "replay_hia_native_cold.py":
                cold_raw = json.dumps(native).encode()
                cold_path.write_bytes(cold_raw)
                index = {**self.index, "native_report": {"path": str(cold_path), **data_pin(cold_raw)}}
                cold_path.with_suffix(".generations.json").write_text(json.dumps(index))
            else:
                self.assertEqual(Path(command[4]).name, "build_hia_cold_native_transport.py")
                self.assertEqual(command[command.index("--cold-report") + 1], str(cold_path))
                self.assertNotIn("--development", command)
                cold_raw = cold_path.read_bytes()
                directory = output / "native-transport-build"
                directory.mkdir()
                manifest = {**self.manifest,
                    "cold_report": {"path": str(cold_path), "pin": data_pin(cold_raw)},
                    "component_input_custody": binding.capture_transport_custody(
                        self.image, cold_raw, self.sources, self.inputs, root=self.root)}
                (directory / "manifest.json").write_text(json.dumps(manifest))
            return success
        with patch.object(binding, "ROOT", self.root), patch.object(driver, "ROOT", self.root), \
                patch.object(driver, "run_owned", side_effect=run) as owned, \
                patch("tools.build_hia_json_preflight.admit_cold_build", return_value=self.sources), \
                patch("tools.build_hia_cold_native_transport.current_python_library", return_value=self.compiler), \
                patch.object(driver.shutil, "which", return_value="/usr/bin/gcc"):
            result = driver.qualify(output, scope="cold")
        self.assertEqual(owned.call_count, 2)
        self.assertEqual(result["status"], "NATIVE_COLD_PASS_DEVELOPMENT_TRANSPORT_BUILT_INDEPENDENT_READER_REQUIRED")
        self.assertFalse(result["whole_native"])
        self.assertFalse(result["qualification_complete"])
        self.assertFalse(result["host_bridge_is_native_release"])
        self.assertTrue(result["independent_cold_readback_required"])
        self.assertEqual(json.loads((output / "cold.json").read_bytes()), native)


class NativeTransportCampaignTests(unittest.TestCase):
    def test_failed_or_legacy_cold_never_starts_a_transport_build(self):
        from tools import qualify_hia_cold_native_transport as driver
        success = {"exit_code": 0, "timed_out": False, "interruption": None,
                   "owned_cleanup": {"reaped": True, "after": [], "signals": []}}
        for returned in (None, {"schema": "hepta.hia.selfhost-cold-replay.v1",
                               "status": "COLD_SELFHOST_REPLAY_PASS"},
                         {"schema": binding.NATIVE_SCHEMA, "status": "FAIL"}):
            with self.subTest(report=returned), tempfile.TemporaryDirectory(prefix="hia-native-ci-campaign-") as temporary:
                output = Path(temporary) / "new"
                def run(command, **kwargs):
                    self.assertEqual(Path(command[4]).name, "replay_hia_native_cold.py")
                    self.assertNotIn("--native-transport", command)
                    self.assertEqual(kwargs["timeout_seconds"], 900)
                    if returned is not None:
                        (output / "cold.json").write_text(json.dumps(returned))
                    return success if returned is not None else {**success, "exit_code": 1}
                with patch.object(driver, "run_owned", side_effect=run) as owned:
                    with self.assertRaisesRegex(ValueError, "native source cold replay did not qualify"):
                        driver.qualify(output, scope="cold")
                self.assertEqual(owned.call_count, 1)
                result = json.loads((output / "report.json").read_text())
                self.assertEqual(result["status"], "HOLD")
                self.assertFalse(result["whole_native"])
                self.assertFalse(result["qualification_complete"])
                self.assertFalse((output / "native-transport-build").exists())


if __name__ == "__main__":
    unittest.main()
