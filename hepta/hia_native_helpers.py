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
import threading

SCHEMA = "hepta.hia.native-helpers.v1"
TARGET = "linux-x86_64-lp64"
ABI = "hia-byte-six-argument-v1"
MAX_BUNDLE_BYTES = 65536
MAX_MANIFEST_BYTES = 16384
MAX_IMAGE_BYTES = 1 << 20
MAX_SOURCE_BYTES = 8 << 20

# Only single-image contracts with the existing six-argument byte ABI.
# Multi-image and external executable contracts need a separate custody closure.
HELPERS = {
    "HEPTA_HIA_GENERATION_RETENTION_MANIFEST": ("hia_generation_retention_native", "NativeGenerationImage"),
    "HEPTA_HIA_SCALAR_PROFILE_MANIFEST": ("hia_scalar_profile_native", "NativeScalarProfile"),
    "HEPTA_HIA_BOUNDED_MEMORY_MANIFEST": ("hia_bounded_memory_native", "NativeBoundedMemory"),
    "HEPTA_HIA_NATIVE_MAPPING_MANIFEST": ("native_mapping_native", "NativeMappingImage"),
    "HEPTA_HIA_PUBLICATION_MEASUREMENT_MANIFEST": ("hia_publication_measurement_native", "NativePublicationMeasurement"),
    "HEPTA_HIA_WORKER_REQUEST_MANIFEST": ("hia_worker_request_native", "NativeWorkerRequest"),
    "HEPTA_HIA_AGENT_IDENTITY_MANIFEST": ("hia_agent_identity_native", "NativeAgentIdentity"),
    "HEPTA_HIA_AGENT_SNAPSHOT_MANIFEST": ("hia_agent_snapshot_native", "NativeAgentSnapshot"),
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
    "HEPTA_HIA_AGENT_JOURNAL_MANIFEST": ("hia_agent_journal_native", "NativeAgentJournal"),
    "HEPTA_HIA_EXECUTION_BUDGET_MANIFEST": ("hia_execution_budget_native", "NativeExecutionBudgetImage"),
    "HEPTA_HIA_CANDIDATE_BUDGET_MANIFEST": ("hia_candidate_budget_native", "NativeCandidateBudgetImage"),
    "HEPTA_HIA_SLOT_LEDGER_MANIFEST": ("hia_slot_ledger_native", "NativeSlotLedger"),
    "HEPTA_HIA_RETIREMENT_STATE_MANIFEST": ("hia_retirement_state_native", "NativeRetirementImage"),
}
# The ordinary CLI and Agent use different methods on the same patch image.
# Admit only these named views of its captured bytes, never arbitrary subclasses
# or a factory chosen by a manifest. All views retain exact four-part cache keys.
FACTORY_VIEWS = {
    "HEPTA_HIA_CORE_PATCH_MANIFEST": (
        ("hia_agent_candidate_native", "NativeAgentCandidatePatch"),
    ),
}
_ACTIVE = None
_SCOPE_LOCK = threading.Lock()
_SCOPE_OWNER = None
_SCHEDULER_BUILD = None


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



def check_native_scheduling_scope(owner=None, *, engine=None, constructing=False,
                                  host_scheduler=False, observing=False):
    """The existing v1/v2 worker pins do not register these five schedulers.

    Keep standalone explicit scheduling unchanged. A worker scope must refuse
    unsupported scheduling before mapping, pool execution or foreign effects,
    not merely discover an extra selector at terminal attestation. The separately
    registered worker-report/wire companions use their existing v2 custody.
    """
    _check_scope_owner()
    bound = getattr(owner, '_worker_scheduling_binding', None)
    if bound is not None and (bound is not _ACTIVE or _SCOPE_OWNER is None):
        raise ValueError('native scheduling owner belongs to its original worker scope')
    if _SCOPE_OWNER is not None:
        if constructing and _SCHEDULER_BUILD is not None:
            binding, selected = _SCHEDULER_BUILD
            binding.check_owner()
            if owner is selected and owner is not None:
                return
        if not constructing and _ACTIVE is not None:
            check = getattr(_ACTIVE, 'check_scheduling', None)
            if check is not None and owner is not None:
                check(owner, engine=engine, host_scheduler=host_scheduler,
                      observing=observing)
                return
        raise ValueError('native scheduling bundle is outside the pinned worker bundle')


def pinned_scheduling(manifest_path, kind, namespace):
    """Only the v3 administrator capsule registers these five fixed owners."""
    _check_scope_owner()
    if _SCOPE_OWNER is None:
        return None
    lookup = getattr(_ACTIVE, 'scheduling_owner', None)
    if lookup is None:
        raise ValueError('native scheduling bundle is outside the pinned worker bundle')
    return lookup(manifest_path, kind, namespace)


def _manifest_environment():
    return {key: value for key, value in os.environ.items()
            if key.startswith("HEPTA_HIA_") and key.endswith("_MANIFEST")}


def _selectors():
    return {key: value for key, value in _manifest_environment().items() if value}


def _check_scope_owner():
    if _SCOPE_OWNER is not None and _SCOPE_OWNER != (os.getpid(), threading.get_ident()):
        raise ValueError("native helper worker scope belongs to its original process and thread")


class NativeHelpersBinding:
    def __init__(self, path, expected_sha256):
        self.owner = (os.getpid(), threading.get_ident())
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
        patch_entry = entries.get("HEPTA_HIA_CORE_PATCH_MANIFEST")
        admission_entry = entries.get("HEPTA_HIA_CORE_ADMISSION_MANIFEST")
        if patch_entry is not None and (admission_entry is None
                or admission_entry[0].resolve(strict=True) !=
                patch_entry[0].resolve(strict=True).parent / "admission-manifest.json"):
            raise ValueError("native Core patch requires its exact adjacent admission helper")
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
            factories = [factory]
            for view_module_name, view_factory_name in FACTORY_VIEWS.get(selector, ()):
                view_module = importlib.import_module("." + view_module_name, __package__)
                if (view_module.SOURCE.resolve(strict=True) != module.SOURCE.resolve(strict=True)
                        or view_module.SCHEMA != module.SCHEMA):
                    raise ValueError("native helper factory view identity differs from its captured image")
                factories.append(getattr(view_module, view_factory_name))
            keys = [(str(manifest_path.resolve(strict=True)),
                     str(module.SOURCE.resolve(strict=True)), module.SCHEMA, view)
                    for view in factories]
            if len(set(keys)) != len(keys) or any(key in self.images for key in keys):
                raise ValueError("duplicate native helper image binding")
            # Every declared view is checked before its first executable mapping.
            # Both factories receive the same captured, hash-verified bytes.
            for key, view in zip(keys, factories):
                self.images[key] = view(image.raw, record["image_sha256"])
            self.selections[selector] = str(manifest_path)
            self.snapshots.extend(((manifest, MAX_MANIFEST_BYTES), (source, MAX_SOURCE_BYTES), (image, MAX_IMAGE_BYTES)))
        self.check_files()

    def check_owner(self):
        if self.owner != (os.getpid(), threading.get_ident()):
            raise ValueError("native helper binding belongs to its original process and thread")

    def check_files(self):
        self.check_owner()
        for original, limit in self.snapshots:
            if _read(original.path, limit) != original:
                raise ValueError("native helper inputs changed; observe the original operation")

    def check(self):
        self.check_owner()
        if _selectors() != self.selections:
            raise ValueError("native helper selection changed; observe the original operation")
        self.check_files()


@contextmanager
def native_helpers_scope(path=None, expected_sha256=None):
    global _ACTIVE, _SCOPE_OWNER
    # The worker handles one request in one process. Hold the scope even when
    # no bundle is selected, so another request cannot change its routing.
    if not _SCOPE_LOCK.acquire(blocking=False):
        raise ValueError("native helper worker scope already belongs to another request")
    owner = (os.getpid(), threading.get_ident())
    _SCOPE_OWNER = owner
    previous = _manifest_environment()
    try:
        if (path is None) != (expected_sha256 is None):
            raise ValueError("native helper manifest and expected SHA256 must be supplied together")
        if _ACTIVE is not None or _selectors():
            raise ValueError("worker native helper selection must come only from its explicit pinned bundle")
        if path is None:
            yield None
            return
        if not _digest(expected_sha256):
            raise ValueError("an exact native helper bundle SHA256 is required")
        captured = _read(_path(path), MAX_BUNDLE_BYTES)
        if sha256(captured.raw).hexdigest() != expected_sha256:
            raise ValueError("native helper bundle identity mismatch")
        record = _decode(captured.raw)
        if type(record) is dict and record.get('schema') == 'hepta.hia.native-helpers.v3':
            from .hia_worker_scheduling_bundle import NativeWorkerSchedulingBinding
            binding = NativeWorkerSchedulingBinding(captured, expected_sha256)
        elif type(record) is dict and record.get('schema') == 'hepta.hia.native-helpers.v2':
            from .hia_worker_bundle import NativeWorkerBundleBinding
            binding = NativeWorkerBundleBinding(captured, expected_sha256)
        else:
            binding = NativeHelpersBinding(path, expected_sha256)
        _ACTIVE = binding
        os.environ.update(binding.selections)
        binding.check()
        yield binding
    finally:
        if owner != (os.getpid(), threading.get_ident()):
            raise ValueError("native helper worker scope belongs to its original process and thread")
        # Restore the complete selector namespace, including empty values and
        # any unexpected selector which caused terminal attestation to refuse.
        for key in _manifest_environment().keys() | previous.keys():
            if key not in previous:
                os.environ.pop(key, None)
            else:
                os.environ[key] = previous[key]
        _ACTIVE = None
        _SCOPE_OWNER = None
        _SCOPE_LOCK.release()


def native_helpers_identity():
    _check_scope_owner()
    if _ACTIVE is None:
        if _SCOPE_OWNER is not None and _selectors():
            raise ValueError("native helper selection changed in an unselected worker scope")
        return {}
    _ACTIVE.check()
    return {"native_helpers_sha256": _ACTIVE.sha256}


def pinned_image(manifest_path, source, schema, factory):
    _check_scope_owner()
    if _ACTIVE is None:
        if _SCOPE_OWNER is not None:
            raise ValueError("native helper executable is outside the pinned worker bundle")
        return None
    _ACTIVE.check_owner()
    key = (str(Path(manifest_path).resolve(strict=True)), str(source.resolve(strict=True)), schema, factory)
    try:
        return _ACTIVE.images[key]
    except KeyError as exc:
        raise ValueError("native helper executable is outside the pinned worker bundle") from exc


def pinned_bundle(manifest_path, schema, factory):
    """Return only a statically registered multi-image owner from this scope."""
    _check_scope_owner()
    if _ACTIVE is None:
        if _SCOPE_OWNER is not None:
            raise ValueError("native helper executable is outside the pinned worker bundle")
        return None
    _ACTIVE.check_owner()
    key = (str(Path(manifest_path).resolve(strict=True)), schema, factory)
    try:
        return getattr(_ACTIVE, 'bundles', {})[key]
    except KeyError as exc:
        raise ValueError("native helper bundle is outside the pinned worker bundle") from exc
