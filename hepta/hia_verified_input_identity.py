"""Proof-local identities for the complete primitive Core input path.

The trusted Python/import contract is the same as hia_loaded_source. The
bounded list below follows primitive parsing, canonicalization, hashing,
declaration, instruction and capability admission, including their explicitly
selected native adapters. It is not a package-wide source scan. Native helper
identities describe the actual immutable mappings selected during this proof;
they do not assert a semantic refinement proof for operator-selected helpers.
"""
from __future__ import annotations

from contextlib import contextmanager
import ctypes
from functools import wraps
from hashlib import sha256
import mmap
import os
from pathlib import Path
import threading

from .hia_loaded_source import loaded_source_identity, _read_source


PROFILE = "hia.primitive-input-execution.v1"
INPUT_SOURCE_FILES = (
    "hia_verified_input_identity.py", "hia_program.py", "hia_json_preflight.py",
    "hia_json_decode.py", "hia_json_decode_native.py", "hia_json_canonical_native.py",
    "hia_sha256_native.py", "hia_sha256_stream_native.py", "hia_core_admission_native.py",
    "hia_program_shape_native.py", "hia_function_shape_native.py", "hia_instruction_policy_native.py",
    "hia_capability_flow.py", "hia_capability_renaming_native.py", "hia_json_preflight_native.py",
    "hia_native_helpers.py", "hia_worker_bundle.py", "hia_worker_scheduling_bundle.py",
    "hia_opcodes.py", "hia_schema.py",
    "hia_safe_core_x64_decode_native.py", "hia_safe_core_elf_inventory_native.py",
    "hia_cnf_native.py",
)
SELECTORS = (
    "HEPTA_HIA_JSON_PREFLIGHT_MANIFEST", "HEPTA_HIA_JSON_DECODE_MANIFEST",
    "HEPTA_HIA_JSON_CANONICAL_MANIFEST", "HEPTA_HIA_SHA256_MANIFEST",
    "HEPTA_HIA_SHA256_STREAM_MANIFEST", "HEPTA_HIA_CORE_ADMISSION_MANIFEST",
    "HEPTA_HIA_PROGRAM_SHAPE_MANIFEST", "HEPTA_HIA_FUNCTION_SHAPE_MANIFEST",
    "HEPTA_HIA_INSTRUCTION_POLICY_MANIFEST", "HEPTA_HIA_CAPABILITY_RENAMING_MANIFEST",
    "HEPTA_HIA_SAFE_CORE_X64_DECODE_MANIFEST", "HEPTA_HIA_SAFE_CORE_ELF_INVENTORY_MANIFEST",
    "HEPTA_HIA_CNF_MANIFEST",
)


class VerifiedInputRejected(ValueError):
    pass


def _require(condition, message):
    if not condition:
        raise VerifiedInputRejected("E_HIA_VERIFIED_INPUT: " + message)


def _selectors():
    # Preserve absent versus explicitly empty, since the selected admission
    # policies intentionally give those two states different meanings.
    return {name: os.environ.get(name) for name in SELECTORS}


def _bundle_identity():
    from .hia_native_helpers import native_helpers_identity
    return native_helpers_identity()


def _mapped_image_identity(selected, source, schema, factory):
    from .hia_json_preflight_native import NativeHiaJsonImage, MAX_IMAGE_BYTES
    _require(type(factory) is type and type(selected) is factory and
             issubclass(factory, NativeHiaJsonImage), "selected helper has no reviewed native image owner")
    module = factory.__module__
    _require(module.startswith("hepta.") and module.rsplit(".", 1)[-1] + ".py" in INPUT_SOURCE_FILES,
             "selected helper is outside primitive input dependencies")
    mapping = selected._mapping
    _require(type(mapping) is mmap.mmap and not mapping.closed and
             0 < len(mapping) <= MAX_IMAGE_BYTES, "selected native mapping is unavailable or unbounded")
    size = len(mapping)
    address = ctypes.cast(selected._entry, ctypes.c_void_p).value
    _require(type(address) is int and address == selected._image_address and size == selected._image_size,
             "selected native callable does not address its captured mapping")
    mapped_range = None
    for line in Path("/proc/self/maps").read_text().splitlines():
        fields = line.split(None, 5)
        low, high = (int(value, 16) for value in fields[0].split("-"))
        if low <= address and address + size <= high:
            _require(fields[1].startswith("r-x") and "w" not in fields[1],
                     "selected native code is not readable executable and nonwritable")
            mapped_range = (low, high, fields[1])
            break
    _require(mapped_range is not None, "selected native entry has no complete executable mapping")
    actual = sha256(mapping[:]).hexdigest()
    _require(actual == selected.image_sha256, "selected native mapping differs from its admitted image")
    source_path = Path(source).resolve(strict=True)
    source_digest = sha256(_read_source(source_path)).hexdigest()
    _require(source_digest == getattr(selected, "admitted_source_sha256", None),
             "selected native mapping lacks its actual admitted source binding")
    return {
        "schema": schema, "factory": module + "." + factory.__name__,
        "source_path": str(source_path), "source_sha256": source_digest,
        "mapped_image_sha256": actual, "image_bytes": size, "entry_address": address,
        # Adjacent anonymous mappings may coalesce in /proc without changing
        # this image. Bind the actual image interval, not unrelated VMA ends.
        "mapping": {"start": address, "end": address + size, "permissions": mapped_range[2]},
        "native_semantic_refinement_proved": False,
    }


class _InputScope:
    def __init__(self):
        self.owner = (os.getpid(), threading.get_ident())
        # This happens before the consumer's first verify_program call.
        self.sources = loaded_source_identity(__name__, INPUT_SOURCE_FILES)
        self.selectors = _selectors()
        self.bundle = _bundle_identity()
        self.images = {}

    def check_route(self):
        _require(self.owner == (os.getpid(), threading.get_ident()), "input proof scope changed process or thread")
        _require(self.selectors == _selectors(), "primitive input selection changed during validation")
        _require(self.bundle == _bundle_identity(), "pinned native helper bundle changed during validation")

    def observe(self, manifest_path, source, schema, factory, selected):
        self.check_route()
        identity = _mapped_image_identity(selected, source, schema, factory)
        key = (str(manifest_path), str(Path(source).resolve(strict=True)), schema, factory)
        previous = self.images.get(key)
        if previous is None:
            self.images[key] = (selected, source, schema, factory, identity)
        else:
            _require(previous[0] is selected and previous[4] == identity,
                     "one selected input helper changed its actual mapping or source")

    def finish(self):
        self.check_route()
        _require(self.sources == loaded_source_identity(__name__, INPUT_SOURCE_FILES),
                 "primitive input execution source changed during validation")
        records = []
        for key, (selected, source, schema, factory, original) in self.images.items():
            _require(original == _mapped_image_identity(selected, source, schema, factory),
                     "selected native helper changed after execution")
            records.append({"manifest_path": key[0], **original})
        records.sort(key=lambda record: (record["factory"], record["manifest_path"]))
        return {"profile": PROFILE, "python_sources": dict(self.sources),
                "selectors": dict(self.selectors), "native_bundle": dict(self.bundle),
                "native_helpers": records,
                "native_helper_semantics": "operator-selected trusted code; actual mappings identified, not independently refined"}


@contextmanager
def input_execution_scope():
    from .hia_json_preflight_native import _INPUT_IMAGE_OBSERVERS
    scope = _InputScope()
    token = _INPUT_IMAGE_OBSERVERS.set((*_INPUT_IMAGE_OBSERVERS.get(), scope.observe))
    try:
        yield scope
    finally:
        _INPUT_IMAGE_OBSERVERS.reset(token)


def bind_input_execution(function):
    """Keep actual route capture alive through all final report hashing."""
    @wraps(function)
    def checked(*args, **kwargs):
        with input_execution_scope() as scope:
            report = function(*args, **kwargs)
            report["checker"]["input_execution"] = scope.finish()
            return report
    return checked


from .hia_loaded_source import register_loaded_module as _register_loaded_source
_register_loaded_source(__name__)
