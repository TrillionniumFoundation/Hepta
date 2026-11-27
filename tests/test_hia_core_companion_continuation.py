"""Source-admission and owner-composition controls; no native execution claim."""
from __future__ import annotations
from contextlib import contextmanager, ExitStack
from hashlib import sha256
import importlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from hepta import hia_native_continuation_selection as continuation
from hepta import hia_native_continuation_inprocess as inprocess
from hepta.hia_agent_contract import CONTINUATION_BUILD_FILES

ROOT = Path(__file__).resolve().parents[1]


class CoreCompanionContinuationTests(unittest.TestCase):
    @contextmanager
    def fixture(self, kind="core-lowering"):
        with tempfile.TemporaryDirectory(prefix="core-continuation-physical-source-") as temporary:
            root = Path(temporary).resolve()
            source = root / "source"
            selections = []
            for family in ("unpack", "compare", "integer"):
                module = importlib.import_module("hepta.hia_core_" + family + "_selection")
                selections.append(module)
                for name, raw in module.current_inputs().items():
                    path = source / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(raw)
            bundle = root / "bundle"
            (bundle / "policy").mkdir(parents=True)
            compiler_sha = "1" * 64
            policy_raw = (json.dumps({"compiler_sha256": compiler_sha}, sort_keys=True) + "\n").encode()
            (bundle / "policy/manifest.json").write_bytes(policy_raw)
            image = b"source-composition-control-not-a-native-image"
            (bundle / "continuation.image.bin").write_bytes(image)
            loaded = SimpleNamespace(images=(object(), object()), abi={"pool_bytes": 64})
            policy = SimpleNamespace(_admitted_bundle=loaded, unpack=object(),
                                     numeric_compare=object(), integer=object())
            calls = []

            def factory(images, pool, abi, namespace, **owners):
                calls.append(dict(owners))
                return SimpleNamespace(**owners)

            def installed(path, namespace):
                # Actual source admission executes before every continuation cache lookup.
                for module in selections:
                    module.current_inputs()
                return policy

            module_name, _ = continuation._FAMILIES[kind]
            selector = importlib.import_module("hepta.hia_" + module_name + "_selection")
            families = dict(continuation._FAMILIES)
            families[kind] = module_name, factory
            resources = {name: sha256(continuation._source_resource_path(name).read_bytes()).hexdigest()
                         for name in CONTINUATION_BUILD_FILES}
            runtime = {"hepta/" + name: sha256((Path(continuation.__file__).parent / name).read_bytes()).hexdigest()
                       for name in continuation._RUNTIME}
            manifest = {
                "schema": continuation.INPROCESS_SCHEMA, "kind": kind,
                "policy_bundle": "policy/manifest.json",
                "policy_bundle_sha256": sha256(policy_raw).hexdigest(),
                "compiler_sha256": compiler_sha,
                "image_path": "continuation.image.bin", "image_sha256": sha256(image).hexdigest(),
                "resource_sha256": resources, "runtime_sha256": runtime,
            }
            path = bundle / "manifest.json"
            path.write_text(json.dumps(manifest, sort_keys=True) + "\n")
            with ExitStack() as stack:
                stack.enter_context(patch.object(continuation, "_FAMILIES", families))
                stack.enter_context(patch.object(continuation, "_OWNER_CACHE", []))
                stack.enter_context(patch.object(selector, "installed_" + module_name, side_effect=installed))
                stack.enter_context(patch.object(inprocess, "InProcessContinuation",
                                                 side_effect=lambda *a, **k: object()))
                for module in selections:
                    stack.enter_context(patch.object(module, "_source_resource_path",
                                                     side_effect=lambda name: source / name))
                    stack.enter_context(patch.object(module, "__file__",
                                                     str(source / module.SELECTION_SOURCE)))
                    stack.enter_context(patch.object(module.primitive, "__file__",
                                                     str(source / module.BRIDGE_SOURCE)))
                yield SimpleNamespace(path=path, namespace={}, policy=policy,
                                      calls=calls, source=source, selections=selections)

    def test_current_companion_owners_are_transferred_and_cache_identity_is_complete(self):
        with self.fixture() as f:
            first = continuation.installed_native_continuation(f.path, f.namespace, kind="core-lowering")
            for name in ("unpack", "numeric_compare", "integer"):
                self.assertIs(getattr(first, name), getattr(f.policy, name))
            self.assertIs(continuation.installed_native_continuation(
                f.path, f.namespace, kind="core-lowering"), first)
            previous = first
            for name in ("unpack", "numeric_compare", "integer"):
                old = getattr(previous, name)
                setattr(f.policy, name, object())
                current = continuation.installed_native_continuation(f.path, f.namespace, kind="core-lowering")
                self.assertIsNot(current, previous)
                self.assertIs(getattr(previous, name), old)
                for captured in ("unpack", "numeric_compare", "integer"):
                    self.assertIs(getattr(current, captured), getattr(f.policy, captured))
                previous = current
            self.assertEqual(len(f.calls), 4)

    def test_warm_continuation_cannot_hide_changed_physical_companion_sources(self):
        with self.fixture() as f:
            first = continuation.installed_native_continuation(f.path, f.namespace, kind="core-lowering")
            for module in f.selections:
                for name in (module.BRIDGE_SOURCE, module.SELECTION_SOURCE):
                    path = f.source / name
                    raw = path.read_bytes()
                    try:
                        path.write_bytes(raw + b"\n# independently changed after first owner\n")
                        with self.assertRaises(ValueError):
                            continuation.installed_native_continuation(f.path, f.namespace, kind="core-lowering")
                        self.assertEqual(len(f.calls), 1)
                    finally:
                        path.write_bytes(raw)
                    self.assertIs(continuation.installed_native_continuation(
                        f.path, f.namespace, kind="core-lowering"), first)

    def test_other_continuation_owner_keeps_original_constructor_and_cache(self):
        with self.fixture("core-emitter") as f:
            first = continuation.installed_native_continuation(f.path, f.namespace, kind="core-emitter")
            self.assertEqual(f.calls, [{}])
            self.assertIs(continuation.installed_native_continuation(
                f.path, f.namespace, kind="core-emitter"), first)
            self.assertEqual(f.calls, [{}])


if __name__ == "__main__":
    unittest.main()
