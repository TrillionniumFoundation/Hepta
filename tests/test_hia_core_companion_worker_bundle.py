"""Physical eight-field custody controls; executable mapping is a bounded test double.

These tests qualify admission and live-scope identity. They do not execute a
native instruction or claim the final v3/Core/Page installation gate.
"""
from __future__ import annotations

from contextlib import ExitStack, contextmanager
from hashlib import sha256
import importlib
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from types import MappingProxyType, SimpleNamespace
import unittest
from unittest.mock import patch

from hepta import hia_core_companion_worker_bundle as bundle
from hepta import hia_json_preflight_native as image_api
from hepta import hia_native_helpers as authority
from hepta import hia_worker_scheduling_bundle as scheduling


def encoded(value):
    return (json.dumps(value, sort_keys=True) + "\n").encode()


class CoreCompanionWorkerCustodyTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory(prefix="core-companion-custody-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.compiler = "a" * 64
        self.mapped = []
        self.before_mapping = None
        self.after_mapping = None
        self.selection = {}
        self.manifests = {}
        self.images = {}
        entries = []
        for kind in bundle.KINDS:
            module = importlib.import_module("hepta.hia_core_" + kind + "_selection")
            inputs = module.current_inputs()
            own = self.root / kind
            own.mkdir()
            for name, raw in inputs.items():
                p = own / name
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(raw)
                p.chmod(0o600)
            self.stack.enter_context(patch.object(
                module, "_source_resource_path", side_effect=lambda name, root=own: root / name))
            self.stack.enter_context(patch.object(module, "__file__", str(own / module.SELECTION_SOURCE)))
            self.stack.enter_context(patch.object(module.primitive, "__file__", str(own / module.BRIDGE_SOURCE)))
            raw = b"no executed instruction: " + kind.encode()
            image = own / ("core-" + kind + ".image.bin")
            image.write_bytes(raw)
            image.chmod(0o600)
            manifest = {
                "schema": module.SCHEMA, "compiler_sha256": self.compiler,
                "image_path": image.name, "image_sha256": sha256(raw).hexdigest(),
                "source_sha256": sha256(inputs[module.HIA_SOURCE]).hexdigest(),
                "abi_sha256": sha256(inputs[module.ABI_SOURCE]).hexdigest(),
                "bridge_sha256": sha256(inputs[module.BRIDGE_SOURCE]).hexdigest(),
                "selection_sha256": sha256(inputs[module.SELECTION_SOURCE]).hexdigest(),
            }
            path = own / "manifest.json"
            path.write_bytes(encoded(manifest))
            path.chmod(0o600)
            entries.append({"kind": kind, "manifest_path": str(path),
                            "manifest_sha256": sha256(path.read_bytes()).hexdigest()})
            self.selection[kind] = module
            self.manifests[kind] = path
            self.images[kind] = image
        self.base = self.root / "scheduler.json"
        self.base.write_bytes(encoded({"schema": "hepta.hia.native-helpers.v3"}))
        self.base.chmod(0o600)
        self.record = {
            "schema": bundle.SCHEMA, "target": authority.TARGET, "abi": authority.ABI,
            "compiler_sha256": self.compiler, "base_bundle": str(self.base),
            "base_bundle_sha256": sha256(self.base.read_bytes()).hexdigest(),
            "companions": entries,
        }
        self.manifest = self.root / "core-worker.json"
        self.save_record()
        real_type = image_api.NativeHiaJsonImage
        def mapping(raw, digest):
            self.assertEqual(sha256(raw).hexdigest(), digest)
            # Use the actual image type and its current attribute API; do not
            # fabricate the removed historical _bind_manifest_source method.
            image = real_type.__new__(real_type)
            image.image_sha256 = digest
            image._entry = lambda *_args: self.fail("source control executed an image")
            self.mapped.append(image)
            if self.after_mapping is not None:
                self.after_mapping(len(self.mapped))
            return image
        self.stack.enter_context(patch.object(image_api, "NativeHiaJsonImage", side_effect=mapping))
        self.stack.enter_context(patch.object(
            self.selection["unpack"].primitive, "CpythonLeaves",
            return_value=SimpleNamespace(profile=31404)))
        test = self
        def captured_scheduler(owner, snapshot, digest, *, page_companion=None, core_companions=None):
            test.assertIsNone(page_companion)
            test.assertIs(type(core_companions), bundle.NativeCoreCompanionWorkerBinding)
            test.assertEqual(sha256(snapshot.raw).hexdigest(), digest)
            owner.owner = (os.getpid(), authority.threading.get_ident())
            owner._core_companions = core_companions
            owner._page_companion = None
            owner._complete_input_capture = True
            owner._companion_selections = MappingProxyType(core_companions.check_scheduling_companion())
            owner.snapshots = [(snapshot, authority.MAX_BUNDLE_BYTES)]
            owner.selections = dict(owner._companion_selections)
            owner.images = {}
            owner.bundles = {}
            if test.before_mapping is not None:
                test.before_mapping()
            core_companions.map_scheduling_companions(owner, test.compiler)
            owner.core_arguments = core_companions.scheduler_arguments(owner)
        self.stack.enter_context(patch.object(
            scheduling.NativeWorkerSchedulingBinding, "__init__", captured_scheduler))

    def save_record(self):
        self.manifest.write_bytes(encoded(self.record))
        self.manifest.chmod(0o600)

    def rebind_manifest(self, kind, value):
        path = self.manifests[kind]
        path.write_bytes(encoded(value))
        self.record["companions"][bundle.KINDS.index(kind)]["manifest_sha256"] = sha256(path.read_bytes()).hexdigest()
        self.save_record()

    def admit(self):
        snapshot = authority._read(self.manifest, authority.MAX_BUNDLE_BYTES)
        return bundle.NativeCoreCompanionWorkerBinding(snapshot, sha256(snapshot.raw).hexdigest())

    @contextmanager
    def active(self, binding):
        values = {key: value for key, value in os.environ.items()
                  if not (key.startswith("HEPTA_HIA_") and key.endswith("_MANIFEST"))}
        values.update(binding.selections)
        with patch.object(authority, "_ACTIVE", binding), patch.object(
                authority, "_SCOPE_OWNER", binding.owner), patch.dict(os.environ, values, clear=True):
            yield

    def test_current_image_api_maps_three_complete_source_bound_owners(self):
        binding = self.admit()
        self.assertEqual(len(self.mapped), 3)
        self.assertEqual(set(binding.selections), set(bundle.SELECTORS))
        arguments = binding.base_binding.core_arguments
        self.assertIs(arguments["numeric_compare"], binding._owners["compare"])
        self.assertIs(arguments["integer"], binding._owners["integer"])
        self.assertIs(arguments["unpack"], binding._owners["unpack"])
        with self.active(binding):
            binding.check()
            for kind in bundle.KINDS:
                module = self.selection[kind]
                with patch.object(module, "_load", side_effect=AssertionError("cache must not supply Worker owners")):
                    selected = getattr(module, "installed_" + kind)(self.manifests[kind], self.compiler)
                self.assertIs(selected, binding._owners[kind])
                self.assertEqual(selected.image.admitted_source_sha256,
                                 json.loads(self.manifests[kind].read_bytes())["source_sha256"])

    def test_five_field_downgrade_is_rejected_before_any_mapping(self):
        value = json.loads(self.manifests["compare"].read_bytes())
        for name in ("abi_sha256", "bridge_sha256", "selection_sha256"):
            del value[name]
        self.rebind_manifest("compare", value)
        with self.assertRaises(ValueError):
            self.admit()
        self.assertEqual(self.mapped, [])

    def test_rebound_compiler_and_unknown_kind_are_rejected_before_mapping(self):
        value = json.loads(self.manifests["integer"].read_bytes())
        value["compiler_sha256"] = "b" * 64
        self.rebind_manifest("integer", value)
        with self.assertRaises(ValueError):
            self.admit()
        self.assertEqual(self.mapped, [])

    def test_duplicate_or_partial_companion_composition_is_rejected(self):
        self.record["companions"][1]["kind"] = "compare"
        self.save_record()
        with self.assertRaises(ValueError):
            self.admit()
        self.record["companions"].pop()
        self.save_record()
        with self.assertRaises(ValueError):
            self.admit()
        self.assertEqual(self.mapped, [])

    def test_legacy_five_field_base_cannot_select_companions(self):
        self.base.write_bytes(encoded({"schema": "hepta.hia.native-helpers.v1"}))
        self.record["base_bundle_sha256"] = sha256(self.base.read_bytes()).hexdigest()
        self.save_record()
        with self.assertRaises(ValueError):
            self.admit()
        self.assertEqual(self.mapped, [])

    def test_unknown_physical_abi_and_changed_loaded_bridge_are_rejected(self):
        module = self.selection["compare"]
        path = Path(module.primitive.__file__)
        path.write_bytes(path.read_bytes() + b"\n# changed after import\n")
        value = json.loads(self.manifests["compare"].read_bytes())
        value["bridge_sha256"] = sha256(path.read_bytes()).hexdigest()
        self.rebind_manifest("compare", value)
        with self.assertRaises(ValueError):
            self.admit()
        self.assertEqual(self.mapped, [])

    def test_loose_permissions_and_hardlinked_image_are_rejected(self):
        self.images["compare"].chmod(0o664)
        with self.assertRaises(ValueError):
            self.admit()
        self.images["compare"].chmod(0o600)
        os.link(self.images["compare"], self.root / "second-name")
        with self.assertRaises(ValueError):
            self.admit()
        self.assertEqual(self.mapped, [])

    def test_late_source_change_between_capture_and_mapping_is_rejected(self):
        path = Path(self.selection["integer"].__file__)
        self.before_mapping = lambda: path.write_bytes(path.read_bytes() + b"\n# late\n")
        with self.assertRaises(ValueError):
            self.admit()
        self.assertEqual(self.mapped, [])

    def test_late_image_change_is_rejected_before_binding_returns(self):
        def change(number):
            if number == 1:
                self.images["integer"].write_bytes(b"late mapped input")
        self.after_mapping = change
        with self.assertRaises(ValueError):
            self.admit()
        self.assertGreater(len(self.mapped), 0)

    def test_imported_custody_reader_cannot_claim_changed_physical_self(self):
        copied = self.root / "reader.py"
        copied.write_bytes(bundle._EXECUTED_SOURCE + b"\n# not executed bytes\n")
        copied.chmod(0o600)
        with patch.object(bundle, "__file__", str(copied)), self.assertRaises(ValueError):
            self.admit()
        self.assertEqual(self.mapped, [])

    def test_warm_selected_owner_cannot_hide_late_source_change(self):
        binding = self.admit()
        module = self.selection["compare"]
        with self.active(binding):
            module.installed_compare(self.manifests["compare"], self.compiler)
            path = Path(module.__file__)
            path.write_bytes(path.read_bytes() + b"\n# changed warm source\n")
            with self.assertRaises(ValueError):
                module.installed_compare(self.manifests["compare"], self.compiler)

    def test_escaped_session_is_sealed_before_an_entry_call(self):
        binding = self.admit()
        module = self.selection["compare"].primitive
        with self.active(binding):
            session = module.NumericCompareSession(binding._owners["compare"].image, 1, 1, 1)
        with self.assertRaises(ValueError):
            session.step(session.next_packet)
        self.assertTrue(session._closed)
        self.assertEqual(session.actual_steps, [])

    def test_replaced_owner_or_image_is_not_an_admitted_scheduler(self):
        binding = self.admit()
        original = binding._owners["compare"].image
        binding._owners["compare"].image = self.mapped[1]
        with self.assertRaises(ValueError):
            binding.check_image(original)

    def test_exact_typed_extension_does_not_accept_duck_typed_callback(self):
        fake = SimpleNamespace(check_scheduling_companion=lambda: {})
        with self.assertRaises(ValueError):
            scheduling._companion_selections(None, fake)

    def test_physical_base_late_change_and_unexpected_selector_are_rejected(self):
        binding = self.admit()
        with self.active(binding):
            os.environ["HEPTA_HIA_UNDECLARED_MANIFEST"] = "unexpected"
            with self.assertRaises(ValueError):
                binding.check()
            del os.environ["HEPTA_HIA_UNDECLARED_MANIFEST"]
            self.base.write_bytes(self.base.read_bytes() + b" ")
            with self.assertRaises(ValueError):
                binding.check()


if __name__ == "__main__":
    unittest.main(verbosity=2)
