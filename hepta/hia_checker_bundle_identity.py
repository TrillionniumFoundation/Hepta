"""Typed identity observations for the published multi-image native families.

This module consumes actual selected owners and their immutable custody records.
It neither loads code from an evidence document nor invokes a policy entry.
Disk-backed external continuations retain their original per-run file/seal checks.
"""
from __future__ import annotations

from hashlib import sha256
import importlib
import json
import mmap
from pathlib import Path


# selector -> selection module, public loader, family, namespace module, factory
BUNDLE_NATIVE_OWNERS = {
    "HEPTA_HIA_CORE_LOWERING_MANIFEST": (
        "hia_core_lowering_selection", "installed_core_lowering", "core-lowering",
        "hia_program_native", "NativeCoreLowering"),
    "HEPTA_HIA_CORE_EMITTER_MANIFEST": (
        "hia_core_emitter_selection", "installed_core_emitter", "core-emitter",
        "hia_program_native", "NativeCoreEmitter"),
    "HEPTA_HIA_BYTE_WRAPPER_MANIFEST": (
        "hia_byte_wrapper_selection", "installed_byte_wrapper", "byte-wrapper",
        "hia_native_byte_abi", "NativeByteWrapper"),
    "HEPTA_HIA_MACHINE_OBJECT_MANIFEST": (
        "hia_machine_object_selection", "installed_machine_object", "machine-object",
        "hia_machine_elf", "NativeMachineObject"),
    "HEPTA_HIA_EXECUTION_OBSERVATION_MANIFEST": (
        "hia_execution_observation_selection", "installed_execution_observation",
        "execution-observation", "hia_opcodes", "NativeExecutionObservation"),
}


def _module(name):
    return importlib.import_module("." + name, __package__)


def _bytes(raw, bound, label):
    if type(raw) is not bytes or not 0 < len(raw) <= bound:
        raise ValueError("bundle custody requires exact bounded " + label + " bytes")
    return raw


def _digest(value):
    return (type(value) is str and len(value) == 64
            and all(character in "0123456789abcdef" for character in value))


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate bundle custody manifest field")
        result[key] = value
    return result


def _json(raw, bound, label):
    return json.loads(_bytes(raw, bound, label), object_pairs_hook=_pairs)


def _hash(raw):
    return sha256(raw).hexdigest()


def _mapping(image):
    from .hia_json_preflight_native import NativeHiaJsonImage, MAX_IMAGE_BYTES
    if type(image) is not NativeHiaJsonImage or type(image._mapping) is not mmap.mmap:
        raise ValueError("bundle custody unit is not its exact admitted mapping type")
    raw = _bytes(image._mapping[:], MAX_IMAGE_BYTES, "mapped image")
    if not _digest(image.image_sha256) or _hash(raw) != image.image_sha256:
        raise ValueError("bundle custody actual mapping identity differs")
    return raw, {"image_sha256": image.image_sha256, "image_bytes": len(raw)}


def capture_observation(selector):
    """Return the real published family's current scope, including None."""
    if selector not in BUNDLE_NATIVE_OWNERS:
        raise ValueError("unknown bundle checker family")
    module = _module(BUNDLE_NATIVE_OWNERS[selector][0])
    value = module.captured_selected_owner()
    if (type(value) is not tuple or len(value) != 2 or type(value[0]) is not bool
            or (not value[0] and value[1] is not None)):
        raise ValueError("bundle checker scope observation is malformed")
    return value


def admit_ambient(selector, path):
    """Use the unchanged public loader and its actual namespace."""
    module_name, loader_name, _kind, namespace_name, _factory = BUNDLE_NATIVE_OWNERS[selector]
    module = _module(module_name)
    namespace = vars(_module(namespace_name))
    return getattr(module, loader_name)(path, namespace)


def _input_hashes(rows, expected_names, label):
    if (type(rows) is not tuple or any(type(row) is not tuple or len(row) != 3
                                     for row in rows)):
        raise ValueError("continuation custody " + label + " rows differ")
    if tuple(row[0] for row in rows) != tuple(expected_names):
        raise ValueError("continuation custody " + label + " order differs")
    result = {}
    for name, path, raw in rows:
        if type(name) is not str or type(path) is not str or not path:
            raise ValueError("continuation custody source path differs")
        result[name] = _hash(_bytes(raw, 8 << 20, label))
    return result


def bundle_identity(selector, owner):
    """Bind the exact pool, ordered units and optional real continuation."""
    if selector not in BUNDLE_NATIVE_OWNERS:
        raise ValueError("unknown bundle checker family")
    selection_name, _loader, kind, namespace_name, factory_name = BUNDLE_NATIVE_OWNERS[selector]
    selection = _module(selection_name)
    continuation_module = _module("hia_native_continuation_selection")
    base_factory = getattr(selection, factory_name)
    continuation_factory = continuation_module._FAMILIES[kind][1]
    if type(owner) not in (base_factory, continuation_factory):
        raise ValueError("bundle checker requires its actual reviewed owner type")
    if type(owner.namespace) is not dict:
        raise ValueError("bundle checker owner namespace is not its admitted dictionary")
    loaded = owner._admitted_bundle
    if type(loaded) is not selection._Loaded:
        raise ValueError("bundle checker requires its actual admitted Loaded record")
    custody = loaded.custody
    if type(custody) is not selection._BundleCustody:
        raise ValueError("bundle checker has no complete captured input custody")
    if any(type(value) is not str or not value
           for value in (custody.bundle_path, custody.abi_path)):
        raise ValueError("bundle custody fixed input paths differ")
    abi_raw = _bytes(custody.abi_raw, 8 << 20, "ABI")
    abi = selection.checked_abi(abi_raw)
    if (type(loaded.abi) is not dict or abi != loaded.abi
            or not _digest(loaded.abi_sha256) or _hash(abi_raw) != loaded.abi_sha256
            or not _digest(loaded.bundle_sha256)
            or type(loaded.source_hashes) is not tuple
            or any(type(row) is not tuple or len(row) != 2
                   or type(row[0]) is not str or not _digest(row[1])
                   for row in loaded.source_hashes)):
        raise ValueError("bundle custody ABI differs from actual loaded owner")
    names = (kind.replace("-", "_") + "_pool", *abi["units"])
    if (type(loaded.names) is not tuple or loaded.names != names
            or type(loaded.images) is not tuple or len(loaded.images) != len(names)
            or type(owner.images) is not tuple or len(owner.images) != len(names) - 1
            or owner._pool_image is not loaded.images[0]
            or any(actual is not admitted for actual, admitted
                   in zip(owner.images, loaded.images[1:]))):
        raise ValueError("bundle custody is not the pool and units actually used")
    if (owner.modes is not loaded.abi["modes"]
            or type(owner.workspace_bytes) is not int
            or owner.workspace_bytes != loaded.abi["workspace_bytes"]
            or type(owner.output_bytes) is not int
            or owner.output_bytes != loaded.abi["output_bytes"]):
        raise ValueError("bundle custody differs from actual dispatch metadata")
    from types import MappingProxyType
    literals = owner.literals
    if (type(literals) is not tuple or len(literals) != loaded.abi["literal_count"]
            or literals is not owner._literal_index_values
            or type(owner._literal_indexes) is not MappingProxyType
            or dict(owner._literal_indexes) != {id(value): index
                for index, value in enumerate(literals, 1)}):
        raise ValueError("bundle custody differs from actual retained literal identities")
    record = _json(custody.bundle_raw, 16384, "bundle manifest")
    fields = {"schema", "abi_sha256", "compiler_sha256", "unit_manifests"}
    if (type(record) is not dict or set(record) != fields
            or record["schema"] != selection.SCHEMA
            or record["abi_sha256"] != loaded.abi_sha256
            or not _digest(record["compiler_sha256"])
            or record["unit_manifests"] != {name: name + "/manifest.json" for name in names}
            or _hash(custody.bundle_raw) != loaded.bundle_sha256):
        raise ValueError("bundle custody parent manifest identity differs")
    if (type(custody.units) is not tuple or len(custody.units) != len(names)
            or any(type(row) is not tuple or len(row) != 7 for row in custody.units)):
        raise ValueError("bundle custody complete unit records differ")
    sources = {"abi": loaded.abi_sha256}
    images, children, actual_hashes = {}, {}, []
    for expected_name, image, row in zip(names, loaded.images, custody.units):
        name, source_path, source_raw, manifest_path, manifest_raw, image_path, image_raw = row
        if (name != expected_name or any(type(path) is not str or not path
                                        for path in (source_path, manifest_path, image_path))):
            raise ValueError("bundle custody named unit path/order differs")
        source_sha = _hash(_bytes(source_raw, 8 << 20, "unit source"))
        child = _json(manifest_raw, 16384, "unit manifest")
        expected = {"schema", "source_sha256", "image_path", "image_sha256", "compiler_sha256"}
        if (type(child) is not dict or set(child) != expected
                or child["schema"] != selection.UNIT_SCHEMA
                or child["source_sha256"] != source_sha
                or child["compiler_sha256"] != record["compiler_sha256"]
                or type(child["image_path"]) is not str or not child["image_path"]
                or child["image_path"] in (".", "..")
                or Path(child["image_path"]).name != child["image_path"]
                or any(ord(char) < 32 for char in child["image_path"])
                or not _digest(child["image_sha256"])):
            raise ValueError("bundle custody unit manifest differs")
        actual_raw, actual = _mapping(image)
        if (type(image_raw) is not bytes or image_raw != actual_raw
                or child["image_sha256"] != actual["image_sha256"]
                or image.admitted_source_sha256 != source_sha):
            raise ValueError("bundle custody source or executable differs from actual mapping")
        sources[name], images[name] = source_sha, actual
        children[name] = _hash(manifest_raw)
        actual_hashes.append((name, source_sha))
    if tuple(actual_hashes) != loaded.source_hashes:
        raise ValueError("bundle custody sources differ from original complete admission")
    result = {"manifest_sha256": loaded.bundle_sha256, "schema": selection.SCHEMA,
              "sources": sources, "images": images, "child_manifests": children}
    if type(owner) is base_factory:
        if (getattr(owner, "_continuation", None) is not None
                or getattr(owner, "_native_continuation_identity", b"") != b""):
            raise ValueError("ordinary bundle has an unreviewed continuation engine")
        return result
    retained = owner._continuation_custody
    if type(retained) is not continuation_module._ContinuationCustody:
        raise ValueError("continuation has no actual captured input custody")
    if any(type(path) is not str or not path for path in (
            retained.manifest_path, retained.policy_path, retained.image_path)):
        raise ValueError("continuation custody input paths differ")
    outer = _json(retained.manifest_raw, 16384, "continuation manifest")
    fields = {"schema", "kind", "policy_bundle", "policy_bundle_sha256", "compiler_sha256",
              "image_path", "image_sha256", "resource_sha256", "runtime_sha256"}
    schemas = (continuation_module.SCHEMA, continuation_module.INPROCESS_SCHEMA)
    if (type(outer) is not dict or set(outer) != fields or outer["schema"] not in schemas
            or outer["kind"] != kind or outer["policy_bundle"] != "policy/manifest.json"
            or outer["compiler_sha256"] != record["compiler_sha256"]
            or outer["policy_bundle_sha256"] != loaded.bundle_sha256
            or retained.policy_raw != custody.bundle_raw
            or not _digest(outer["image_sha256"])):
        raise ValueError("continuation custody parent/policy binding differs")
    from .hia_agent_contract import CONTINUATION_BUILD_FILES
    resource_hashes = _input_hashes(retained.resource_inputs, CONTINUATION_BUILD_FILES, "resources")
    runtime_names = tuple("hepta/" + name for name in continuation_module._RUNTIME)
    runtime_hashes = _input_hashes(retained.runtime_inputs, runtime_names, "runtime")
    if (outer["resource_sha256"] != resource_hashes
            or outer["runtime_sha256"] != runtime_hashes):
        raise ValueError("continuation custody complete source identities differ")
    from .hia_native_continuation import MAX_EXECUTABLE, NativeContinuation
    image_raw = _bytes(retained.image_raw, MAX_EXECUTABLE, "continuation executable")
    if _hash(image_raw) != outer["image_sha256"]:
        raise ValueError("continuation custody executable bytes differ")
    engine = owner._continuation
    if outer["schema"] == continuation_module.INPROCESS_SCHEMA:
        from .hia_native_continuation_inprocess import InProcessContinuation
        if (outer["image_path"] != "continuation.image.bin" or type(engine) is not InProcessContinuation
                or type(engine._mapping) is not mmap.mmap or engine._mapping[:] != image_raw
                or type(engine.pool_bytes) is not int or engine.pool_bytes != loaded.abi["pool_bytes"]):
            raise ValueError("continuation custody differs from actual immutable engine")
        images["continuation"] = {"image_sha256": outer["image_sha256"],
                                  "image_bytes": len(image_raw)}
    else:
        if (kind != "execution-observation" or outer["image_path"] != "continuation.native"
                or type(engine) is not NativeContinuation
                or str(engine.path) != retained.image_path
                or engine.sha256 != outer["image_sha256"]
                or engine.pool_bytes != loaded.abi["pool_bytes"]):
            raise ValueError("external continuation custody differs from its actual run guard")
        result["external_executables"] = {"continuation": {
            "image_sha256": engine.sha256, "image_bytes": len(image_raw),
            "execution_custody": "owned file revalidated and sealed on each original run"}}
    expected_identity = ("\0".join((outer["schema"], _hash(retained.manifest_raw),
        outer["image_sha256"], *resource_hashes.values(), *runtime_hashes.values()))).encode("ascii")
    if owner._native_continuation_identity != expected_identity:
        raise ValueError("continuation identity differs from the actual admitted source order")
    sources.update({"continuation-resource:" + name: value for name, value in resource_hashes.items()})
    sources.update({"continuation-runtime:" + name: value for name, value in runtime_hashes.items()})
    children["policy"] = loaded.bundle_sha256
    result["manifest_sha256"], result["schema"] = _hash(retained.manifest_raw), outer["schema"]
    return result
