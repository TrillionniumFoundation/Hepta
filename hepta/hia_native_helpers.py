"""Explicit pinned native helpers for the one-request MCP worker.

This is executable-code custody, not a proof of the selected HIA programs.
The operator pins the whole bundle. Callers cannot select paths or images.
The hosted worker, journal and transport retain their existing responsibilities.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from hashlib import sha256
import importlib
import json
import os
from pathlib import Path
import re
import stat

SCHEMA = "hepta.hia.native-helpers.v1"
TARGET = "linux-x86_64-lp64"
ABI = "hia-byte-six-argument-v1"
MAX_BUNDLE_BYTES = 65536
MAX_MANIFEST_BYTES = 16384
MAX_IMAGE_BYTES = 1 << 20
MAX_SOURCE_BYTES = 8 << 20

# Each entry owns one image with the existing six-argument byte ABI.
# Composed heap dependencies are admitted as one complete selector set below.
# Other multi-image and external executable contracts need separate closure.
HELPERS = {
    "HEPTA_HIA_PROOF_CONTRACT_MANIFEST": ("hia_proof_contract_native", "NativeProofContractImage"),
    "HEPTA_HIA_SERVICE_VERIFICATION_MANIFEST": ("hia_service_verification_native", "NativeVerificationImage"),
    "HEPTA_HIA_SERVICE_EMISSION_MANIFEST": ("hia_service_emission_native", "NativeEmissionImage"),
    "HEPTA_HIA_NATIVE_BYTE_ABI_MANIFEST": ("hia_native_byte_abi_native", "NativeByteABI"),
    "HEPTA_HIA_NATIVE_BUILD_MANIFEST": ("hia_native_build_native", "NativeBuild"),
    "HEPTA_HIA_CORE_EMITTER_MANIFEST": ("hia_core_emitter_native", "NativeCoreEmitter"),
    "HEPTA_HIA_CORE_LOWERING_MANIFEST": ("hia_core_lowering_native", "NativeCoreLowering"),
    "HEPTA_HIA_SERVICE_CONTEXT_MANIFEST": ("hia_service_context_native", "NativeContextImage"),
    "HEPTA_HIA_MACHINE_ELF_MANIFEST": ("hia_machine_elf_native", "NativeMachineElf"),
    "HEPTA_HIA_MACHINE_PLAN_MANIFEST": ("hia_machine_plan_native", "NativeMachinePlan"),
    "HEPTA_HIA_MACHINE_ENCODING_MANIFEST": ("hia_machine_encoding_native", "NativeMachineEncoding"),
    "HEPTA_HIA_MACHINE_STATE_MANIFEST": ("hia_machine_state_native", "NativeMachineState"),
    "HEPTA_HIA_MACHINE_INSTRUCTIONS_MANIFEST": ("hia_machine_instructions_native", "NativeMachineInstructions"),
    "HEPTA_HIA_PROGRAM_EXECUTION_MANIFEST": ("hia_program_execution_native", "NativeProgramExecution"),
    "HEPTA_HIA_STATIC_BUDGET_MANIFEST": ("hia_static_budget_native", "NativeStaticBudget"),
    "HEPTA_HIA_HEAP_BOUND_MANIFEST": ("hia_heap_bound_native", "NativeHeapController"),
    "HEPTA_HIA_HEAP_LIVE_ENGINE_MANIFEST": ("hia_heap_live_native", "NativeLiveHeap"),
    "HEPTA_HIA_HEAP_PAYLOAD_MANIFEST": ("hia_heap_payload_native", "NativePayloadHeap"),
    "HEPTA_HIA_WORKER_REQUEST_MANIFEST": ("hia_worker_request_native", "NativeWorkerRequest"),
    "HEPTA_HIA_AGENT_IDENTITY_MANIFEST": ("hia_agent_identity_native", "NativeAgentIdentity"),
    "HEPTA_HIA_AGENT_SNAPSHOT_MANIFEST": ("hia_agent_snapshot_json_native", "NativeAgentSnapshotJson"),
    "HEPTA_HIA_AGENT_DATA_JSON_MANIFEST": ("hia_agent_data_json_native", "NativeAgentDataJson"),
    "HEPTA_HIA_AGENT_BINARY64_MANIFEST": ("hia_agent_binary64_native", "NativeAgentBinary64"),
    "HEPTA_HIA_AGENT_BINARY64_FORMAT_MANIFEST": ("hia_agent_binary64_format_native", "NativeAgentBinary64Format"),
    "HEPTA_HIA_AGENT_SLICE_MANIFEST": ("hia_agent_slice_native", "NativeAgentSlice"),
    "HEPTA_HIA_JSON_PREFLIGHT_MANIFEST": ("hia_json_preflight_native", "NativeJsonPreflight"),
    "HEPTA_HIA_JSON_DECODE_MANIFEST": ("hia_json_decode_native", "NativeJsonDecoder"),
    "HEPTA_HIA_JSON_CANONICAL_MANIFEST": ("hia_json_canonical_native", "NativeJsonCanonicalizer"),
    "HEPTA_HIA_SHA256_MANIFEST": ("hia_sha256_native", "NativeSha256"),
    "HEPTA_HIA_SHA256_STREAM_MANIFEST": ("hia_sha256_stream_native", "NativeSha256Stream"),
    "HEPTA_HIA_CAPABILITY_RENAMING_MANIFEST": ("hia_capability_renaming_native", "NativeCapabilityRenaming"),
    "HEPTA_HIA_FUNCTION_SHAPE_MANIFEST": ("hia_function_shape_native", "NativeFunctionShape"),
    "HEPTA_HIA_INSTRUCTION_POLICY_MANIFEST": ("hia_instruction_policy_native", "NativeInstructionPolicy"),
    "HEPTA_HIA_PROGRAM_SHAPE_MANIFEST": ("hia_program_shape_native", "NativeProgramShape"),
    "HEPTA_HIA_CORE_ADMISSION_MANIFEST": ("hia_core_admission_native", "NativeCoreAdmission"),
    "HEPTA_HIA_CORE_PATCH_MANIFEST": ("hia_core_patch_native", "NativeCorePatch"),
    "HEPTA_HIA_TASK_HELPERS_MANIFEST": ("hia_task_helpers_native", "NativeTaskHelpers"),
}
_ACTIVE = None


def _digest(value):
    return type(value) is str and re.fullmatch("[0-9a-f]{64}", value) is not None


def _path(value, parent=None):
    if type(value) is not str or not value or any(ord(c) < 32 for c in value):
        raise ValueError("native helper path must be explicit text without control characters")
    path = Path(value)
    if ".." in path.parts or (not path.is_absolute() and parent is None):
        raise ValueError("native helper path must be absolute or relative to its pinned manifest")
    return path if path.is_absolute() else parent / path


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate native helper manifest field")
        result[key] = value
    return result


def _decode(raw):
    def reject_constant(_value):
        raise ValueError("nonfinite native helper manifest value")
    return json.loads(raw, object_pairs_hook=_pairs, parse_constant=reject_constant)


@dataclass(frozen=True)
class _Snapshot:
    path: Path
    raw: bytes
    identity: tuple


def _read(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_uid not in (0, os.getuid()) or before.st_mode & 0o022
                or not 0 < before.st_size <= limit):
            raise ValueError("native helper input must be an owned bounded ordinary file")
        raw = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_mode", "st_uid", "st_nlink")
    identity = tuple(getattr(before, name) for name in fields)
    if len(raw) != before.st_size or identity != tuple(getattr(after, name) for name in fields):
        raise ValueError("native helper input changed while being read")
    return _Snapshot(path, raw, identity)


def _selectors():
    return {key: value for key, value in os.environ.items()
            if key.startswith("HEPTA_HIA_") and key.endswith("_MANIFEST") and value}


class NativeHelpersBinding:
    def __init__(self, path, expected_sha256):
        if not _digest(expected_sha256):
            raise ValueError("an exact native helper bundle SHA256 is required")
        bundle = _read(_path(path), MAX_BUNDLE_BYTES)
        if sha256(bundle.raw).hexdigest() != expected_sha256:
            raise ValueError("native helper bundle identity mismatch")
        value = _decode(bundle.raw)
        if (type(value) is not dict or set(value) != {"schema", "target", "abi", "helpers"}
                or value["schema"] != SCHEMA or value["target"] != TARGET or value["abi"] != ABI
                or type(value["helpers"]) is not list or not 1 <= len(value["helpers"]) <= len(HELPERS)):
            raise ValueError("unsupported native helper bundle schema, target or ABI")
        self.sha256 = expected_sha256
        self.snapshots = [(bundle, MAX_BUNDLE_BYTES)]
        self.selections = {}
        self.images = {}
        entries = {}
        for entry in value["helpers"]:
            if (type(entry) is not dict or set(entry) != {"selector", "manifest_path", "manifest_sha256"}
                    or type(entry["selector"]) is not str or entry["selector"] not in HELPERS
                    or entry["selector"] in entries or not _digest(entry["manifest_sha256"])):
                raise ValueError("unknown, duplicate or unpinned native helper selection")
            entries[entry["selector"]] = (_path(entry["manifest_path"], bundle.path.parent), entry["manifest_sha256"])
        # Refuse an incomplete transitive executable set before importing any
        # selected adapter or creating any executable mapping.
        if ("HEPTA_HIA_MACHINE_STATE_MANIFEST" in entries
                and "HEPTA_HIA_MACHINE_ENCODING_MANIFEST" not in entries):
            raise ValueError("native Code state requires its pinned instruction-byte helper")
        if ("HEPTA_HIA_MACHINE_INSTRUCTIONS_MANIFEST" in entries and not {
                "HEPTA_HIA_MACHINE_STATE_MANIFEST",
                "HEPTA_HIA_MACHINE_ENCODING_MANIFEST"} <= entries.keys()):
            raise ValueError("native Code instructions require both pinned state and byte helpers")
        patch_entry = entries.get("HEPTA_HIA_CORE_PATCH_MANIFEST")
        admission_entry = entries.get("HEPTA_HIA_CORE_ADMISSION_MANIFEST")
        if patch_entry is not None and (admission_entry is None
                or admission_entry[0].resolve(strict=True) !=
                patch_entry[0].resolve(strict=True).parent / "admission-manifest.json"):
            raise ValueError("native Core patch requires its exact adjacent admission helper")
        if "HEPTA_HIA_HEAP_BOUND_MANIFEST" in entries and not {
                "HEPTA_HIA_HEAP_LIVE_ENGINE_MANIFEST",
                "HEPTA_HIA_STATIC_BUDGET_MANIFEST",
                "HEPTA_HIA_HEAP_PAYLOAD_MANIFEST"} <= entries.keys():
            raise ValueError("native heap controller requires its complete pinned dependency set")
        for selector, (manifest_path, manifest_sha256) in entries.items():
            manifest = _read(manifest_path, MAX_MANIFEST_BYTES)
            if sha256(manifest.raw).hexdigest() != manifest_sha256:
                raise ValueError("native helper manifest identity mismatch")
            record = _decode(manifest.raw)
            module_name, factory_name = HELPERS[selector]
            module = importlib.import_module("." + module_name, __package__)
            factory = getattr(module, factory_name)
            if (type(record) is not dict or set(record) != {
                    "schema", "source_sha256", "image_path", "image_sha256", "compiler_sha256"}
                    or record["schema"] != module.SCHEMA
                    or any(not _digest(record[key]) for key in ("source_sha256", "image_sha256", "compiler_sha256"))):
                raise ValueError("native helper manifest does not match its selected contract")
            source = _read(module.SOURCE, MAX_SOURCE_BYTES)
            image = _read(_path(record["image_path"], manifest_path.parent), MAX_IMAGE_BYTES)
            if sha256(source.raw).hexdigest() != record["source_sha256"]:
                raise ValueError("native helper source identity mismatch")
            if sha256(image.raw).hexdigest() != record["image_sha256"]:
                raise ValueError("native helper executable identity mismatch")
            mapped = factory(image.raw, record["image_sha256"])
            # Bind the same source bytes already admitted with this image;
            # selected callers must not infer custody from a later file read.
            from .hia_json_preflight_native import NativeHiaJsonImage
            if issubclass(type(mapped), NativeHiaJsonImage):
                mapped._bind_manifest_source(record["source_sha256"])
            key = (str(manifest_path.resolve(strict=True)), str(module.SOURCE.resolve(strict=True)), module.SCHEMA, factory)
            if key in self.images:
                raise ValueError("duplicate native helper image binding")
            self.images[key] = mapped
            self.selections[selector] = str(manifest_path)
            self.snapshots.extend(((manifest, MAX_MANIFEST_BYTES), (source, MAX_SOURCE_BYTES), (image, MAX_IMAGE_BYTES)))
        self.check_files()

    def check_files(self):
        for original, limit in self.snapshots:
            if _read(original.path, limit) != original:
                raise ValueError("native helper inputs changed; observe the original operation")

    def check(self):
        if _selectors() != self.selections:
            raise ValueError("native helper selection changed; observe the original operation")
        self.check_files()


@contextmanager
def native_helpers_scope(path=None, expected_sha256=None):
    global _ACTIVE
    if (path is None) != (expected_sha256 is None):
        raise ValueError("native helper manifest and expected SHA256 must be supplied together")
    if _ACTIVE is not None or _selectors():
        raise ValueError("worker native helper selection must come only from its explicit pinned bundle")
    if path is None:
        yield None
        return
    binding = NativeHelpersBinding(path, expected_sha256)
    previous = {key: os.environ.get(key) for key in binding.selections}
    try:
        os.environ.update(binding.selections)
        _ACTIVE = binding
        binding.check()
        yield binding
    finally:
        _ACTIVE = None
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def native_helpers_identity():
    if _ACTIVE is None:
        return {}
    _ACTIVE.check()
    return {"native_helpers_sha256": _ACTIVE.sha256}


def pinned_image(manifest_path, source, schema, factory):
    if _ACTIVE is None:
        return None
    key = (str(Path(manifest_path).resolve(strict=True)), str(source.resolve(strict=True)), schema, factory)
    try:
        return _ACTIVE.images[key]
    except KeyError as exc:
        raise ValueError("native helper executable is outside the pinned worker bundle") from exc
