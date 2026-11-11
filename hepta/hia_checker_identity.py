"""Identity of the Core checker and its explicitly selected native owners.

Source bytes alone cannot identify a checker which delegates to native images.
This module records both the reviewed Python dependency closure and the actual
immutable mappings returned by the existing native loaders. It neither executes
those mappings nor treats an image/manifest digest as a correctness theorem.
The host Python/loader and absence of hostile process mutation remain assumed.
"""
from __future__ import annotations

from hashlib import sha256
import importlib
import json
import os
from pathlib import Path


CORE_SOURCE_FILES = (
    "hia_checker_identity.py", "hia_native_helpers.py", "hia_program.py", "hia_program_composite.py",
    "hia_capability_flow.py", "hia_opcodes.py", "hia_schema.py",
    "hia_json_preflight.py", "hia_json_decode.py", "hia_json_preflight_native.py",
    "hia_json_decode_native.py", "hia_json_canonical_native.py",
    "hia_sha256_native.py", "hia_sha256_stream_native.py",
    "hia_function_shape_native.py", "hia_program_shape_native.py",
    "hia_instruction_policy_native.py", "hia_core_admission_native.py",
    "hia_capability_renaming_native.py", "hia_composite_types_native.py",
    "hia_task_helpers_native.py", "hia_composite_functions_native.py",
    "hia_composite_functions_errors.py", "hia_composite_function_tokens.py",
    "hia_composite_constructor_native.py", "hia_composite_constructor_errors.py",
    "hia_composite_outer_native.py",
)

# Exact verifier selectors, not every unrelated HEPTA setting in the process.
# New checker delegations must extend this inventory before proof qualification.
NATIVE_OWNERS = {
    "HEPTA_HIA_JSON_PREFLIGHT_MANIFEST": ("hia_json_preflight_native", "installed_preflight"),
    "HEPTA_HIA_JSON_DECODE_MANIFEST": ("hia_json_decode_native", "installed_decoder"),
    "HEPTA_HIA_JSON_CANONICAL_MANIFEST": ("hia_json_canonical_native", "installed_canonicalizer"),
    "HEPTA_HIA_SHA256_MANIFEST": ("hia_sha256_native", "installed_hasher"),
    "HEPTA_HIA_SHA256_STREAM_MANIFEST": ("hia_sha256_stream_native", "installed_stream_hasher"),
    "HEPTA_HIA_CAPABILITY_RENAMING_MANIFEST": ("hia_capability_renaming_native", "installed_capability_renaming"),
    "HEPTA_HIA_FUNCTION_SHAPE_MANIFEST": ("hia_function_shape_native", "installed_function_shape"),
    "HEPTA_HIA_PROGRAM_SHAPE_MANIFEST": ("hia_program_shape_native", "installed_program_shape"),
    "HEPTA_HIA_INSTRUCTION_POLICY_MANIFEST": ("hia_instruction_policy_native", "installed_instruction_policy"),
    "HEPTA_HIA_CORE_ADMISSION_MANIFEST": ("hia_core_admission_native", "installed_core_admission"),
    "HEPTA_HIA_COMPOSITE_TYPES_MANIFEST": ("hia_composite_types_native", "installed_composite_types"),
    "HEPTA_HIA_TASK_HELPERS_MANIFEST": ("hia_task_helpers_native", "installed_task_helpers"),
    "HEPTA_HIA_COMPOSITE_FUNCTIONS_MANIFEST": ("hia_composite_functions_native", "installed_composite_functions"),
    "HEPTA_HIA_COMPOSITE_CONSTRUCTOR_MANIFEST": ("hia_composite_constructor_native", "installed_composite_constructor"),
    "HEPTA_HIA_COMPOSITE_OUTER_MANIFEST": ("hia_composite_outer_native", "installed_composite_outer"),
}


def checker_source_identity(extra_files=()):
    """Hash the same Core closure for each consumer, retaining its own inputs."""
    names = set(CORE_SOURCE_FILES) | set(extra_files)
    return {name: sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
            for name in sorted(names)}


def _manifest_bytes(path):
    with Path(path).open("rb") as stream:
        raw = stream.read(65537)
    if len(raw) > 65536:
        raise ValueError("checker native manifest exceeds its fixed identity bound")
    return raw


def _mapped_identity(image):
    # A cached immutable image can intentionally survive replacement of its
    # backing file. Identify that loaded mapping, not whatever now occupies the
    # old pathname. The existing loader performs all schema and source checks.
    from .hia_json_preflight_native import NativeHiaJsonImage, MAX_IMAGE_BYTES
    if not isinstance(image, NativeHiaJsonImage):
        raise ValueError("checker owner did not return its native image")
    raw = image._mapping[:]
    if not 0 < len(raw) <= MAX_IMAGE_BYTES or sha256(raw).hexdigest() != image.image_sha256:
        raise ValueError("checker native mapping differs from its loaded identity")
    return {"image_sha256": image.image_sha256, "image_bytes": len(raw)}


def checker_native_selection():
    """Bind every selected verifier owner without invoking a native entrypoint.

    Configured owners are conservatively bound even when a particular input
    does not visit them. No serialized receipt can select code for this call.
    """
    selected = {key: os.environ.get(key) or None for key in sorted(NATIVE_OWNERS)}
    result = {}
    for key, path in selected.items():
        if path is None:
            result[key] = None
            continue
        module_name, loader_name = NATIVE_OWNERS[key]
        module = importlib.import_module("." + module_name, __package__)
        raw = _manifest_bytes(path)
        sources = ({"image": module.SOURCE} if hasattr(module, "SOURCE") else module.SOURCES)
        source_identity = {name: sha256(source.read_bytes()).hexdigest()
                           for name, source in sorted(sources.items())}
        children = {}
        if hasattr(module, "SOURCES"):
            value = json.loads(raw)
            children = {name: _manifest_bytes(Path(path).parent / component)
                        for name, component in sorted(value["kernels"].items())}
        owner = getattr(module, loader_name)(path)
        images = {"image": owner} if hasattr(owner, "_mapping") else owner.images
        if set(images) != set(sources):
            raise ValueError("checker native image/source inventory differs")
        image_identity = {name: _mapped_identity(image) for name, image in sorted(images.items())}
        # Bundle loading follows each separately validated child manifest.
        # Retain those exact bytes too; parent pathname text is not their identity.
        if hasattr(owner, "images"):
            if children != {name: _manifest_bytes(Path(path).parent / component)
                            for name, component in sorted(value["kernels"].items())}:
                raise ValueError("checker child manifest changed during identity capture")
        if (raw != _manifest_bytes(path)
                or source_identity != {name: sha256(source.read_bytes()).hexdigest()
                                       for name, source in sorted(sources.items())}):
            raise ValueError("checker native manifest/source changed during identity capture")
        result[key] = {"manifest_sha256": sha256(raw).hexdigest(), "schema": module.SCHEMA,
                       "sources": source_identity, "images": image_identity,
                       "child_manifests": {name: sha256(child).hexdigest()
                                           for name, child in children.items()}}
    if selected != {key: os.environ.get(key) or None for key in sorted(NATIVE_OWNERS)}:
        raise ValueError("checker native selection changed during identity capture")
    return result


def checker_digest(extra_files=()):
    identity = {"source_identity": checker_source_identity(extra_files),
                "native_selection": checker_native_selection()}
    return sha256(json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
