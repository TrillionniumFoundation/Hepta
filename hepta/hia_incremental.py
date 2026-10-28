"""Session-local incremental checks for the closed primitive HIA profiles.

The cache contains only results this process actually verified. It cannot be
loaded from a report, hash, pickled session or a caller's VerifiedProgram.
Every candidate is strictly decoded and its entire global/CFG/SSA shape is
checked. A body is reused only when its exact bytes and every direct callee
interface are unchanged under the same verifier/registry policy.

Execution, native emission and publication retain their existing full checks.
This module certifies static admission only, not behavior equivalence, test
selection, compiler refinement or model productivity.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from threading import RLock
from types import MappingProxyType
from weakref import WeakKeyDictionary

from . import hia_program as core
from . import hia_schema as registry
from .hia_program_tools import (HIAEditRejected, _check_patch_interface,
                                _prepare_program_patch)

REPORT_SCHEMA = "hepta.hia.incremental-verification.v1"
PATCH_REPORT_SCHEMA = "hepta.hia.incremental-patch-result.v1"
DEPENDENCY_CONTRACT = "closed-body-and-direct-callee-interface.v1"
# An added primitive version never opts itself into cached admission merely by
# appearing in the shared registry. Its dependency contract must be reviewed.
_SCHEMAS = frozenset(f"hepta.hia.program.v{v}" for v in range(1, 8))
_SESSIONS = WeakKeyDictionary()


class HIAIncrementalRejected(ValueError):
    pass


def _reject(message):
    raise HIAIncrementalRejected("E_HIA_INCREMENTAL: " + message)


def _wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _policy():
    """Bind a live cache to actual checker code, constants and capabilities.

    Reloading the checker or replacing a checker method invalidates a session.
    The registry bytes cover future capabilities, including nominal profiles.
    This is local cache invalidation, not source/toolchain attestation.
    """
    functions = tuple((name, value, getattr(value, "__code__", None))
                      for name, value in sorted(vars(core).items())
                      if callable(value) and getattr(value, "__module__", None)
                      == core.__name__)
    methods = tuple((name, value, getattr(value, "__code__", None))
                    for name, value in sorted(vars(core._BlockCheck).items())
                    if callable(value))
    constants = _wire({
        "word_bits": core.WORD_BITS, "widths": core.WIDTHS,
        "scalars": sorted(core.SCALARS), "owners": sorted(core.OWNERS),
        "byte_resources": sorted(core.BYTE_RESOURCES),
        "resources": sorted(core.RESOURCES), "types": sorted(core.TYPES),
        "effects": sorted(core.EFFECTS), "traps": sorted(core.TRAP_CODES),
        "reserved": sorted(core._RESERVED_FUNCTIONS),
        "identifier_pattern": core._IDENT.pattern,
        "limits": [core.MAX_BYTES, core.MAX_NODES, core.MAX_DEPTH,
                   core.MAX_FUNCTIONS, core.MAX_BLOCKS],
        "registry": registry.schema_registry(),
    })
    return (DEPENDENCY_CONTRACT, functions, methods, constants,
            core.supports_feature, core.preflight_hia_json)


@dataclass(frozen=True, slots=True)
class _Snapshot:
    canonical_bytes: bytes
    structured_bytes: bytes | None
    envelope: bytes
    functions: object
    interfaces: object
    dependencies: object
    policy: tuple


def _snapshot(verified, policy):
    """Called only after this module completed actual verification."""
    document = verified.as_dict()
    functions = {f["name"]: f for f in document["functions"]}
    return _Snapshot(
        verified.canonical_bytes, verified.structured_bytes,
        _wire({key: value for key, value in document.items()
               if key != "functions"}),
        MappingProxyType({name: _wire(fn) for name, fn in functions.items()}),
        MappingProxyType(core._function_interfaces(functions)),
        MappingProxyType({name: frozenset(
            op["attrs"]["function"] for block in fn["blocks"]
            for op in block["ops"] if op["op"] == "call")
            for name, fn in functions.items()}), policy)


class _Record:
    __slots__ = ("snapshot", "lock", "report_bytes")

    def __init__(self, snapshot):
        self.snapshot = snapshot
        self.lock = RLock()
        self.report_bytes = None


def _record(session):
    # A subclass cannot substitute snapshot or verification methods. Creating
    # the Python object without running __init__ does not register a cache.
    if type(session) is not IncrementalVerifier or session not in _SESSIONS:
        _reject("session was not locally initialized or has been closed")
    return _SESSIONS[session]


def _report(before):
    return {
        "schema": REPORT_SCHEMA, "dependency_contract": DEPENDENCY_CONTRACT,
        "status": "checking", "before_sha256": sha256(before.canonical_bytes).hexdigest(),
        "after_sha256": None, "mode": None, "fallback_reason": None,
        "global_structure_checked": False,
        "function_shapes_checked": None, "operation_shapes_checked": None,
        "blocks_in_completed_bodies": 0, "operations_in_completed_bodies": 0,
        "count_scope": "primitive core; normalization and decoding are not counted",
        "functions_body_attempted": [], "functions_body_completed": [],
        "functions_body_reused": [], "dependency_invalidations": {},
        "claims": {
            "external_cache_or_receipt_accepted": False,
            "caller_digest_grants_admission": False,
            "public_consumers_still_reverify": True,
            "behavior_equivalence_proved": False,
            "native_executed": False,
            "model_productivity_proved": False,
        },
    }


class IncrementalVerifier:
    """A bounded, in-memory verification session with atomic failed attempts.

    Constructing a session performs full verification, even for a manually
    constructed VerifiedProgram. verify() returns (candidate, work_report).
    On rejection the prior verified baseline remains available; last_report
    describes the failed attempt without pretending partial checks completed.

    Function-local checking receives immutable interfaces containing only
    parameter types, return types and declared effects. The closed primitive
    language has no global storage or hidden callees. Consequently a callee's
    unchanged interface does not require rechecking its caller for admission.
    A changed body can still alter observable behavior transitively: use the
    separate patch-impact observer when selecting behavioral tests.
    """
    __slots__ = ("__weakref__",)

    def __init__(self, document):
        if type(self) is not IncrementalVerifier:
            _reject("subclassed sessions are not supported")
        if self in _SESSIONS:
            _reject("an initialized session cannot be reseeded")
        policy = _policy()
        checked = core.verify_program(document)
        if policy != _policy():
            _reject("verifier or registry changed while initializing session")
        _SESSIONS[self] = _Record(_snapshot(checked, policy))

    def __reduce__(self):
        raise TypeError("incremental verifier sessions cannot be serialized")

    def __copy__(self):
        raise TypeError("incremental verifier sessions cannot be copied")

    def __deepcopy__(self, memo):
        raise TypeError("incremental verifier sessions cannot be copied")

    @property
    def base_sha256(self):
        record = _record(self)
        with record.lock:
            _record(self)
            return sha256(record.snapshot.canonical_bytes).hexdigest()

    @property
    def last_report(self):
        record = _record(self)
        with record.lock:
            _record(self)
            return (json.loads(record.report_bytes)
                    if record.report_bytes is not None else None)

    def close(self):
        record = _record(self)
        with record.lock:
            _record(self)
            del _SESSIONS[self]

    def verify(self, document):
        record = _record(self)
        with record.lock:
            _record(self)
            return self._verify_locked(record, document)

    def apply_patch(self, request):
        """Apply the existing bounded atomic patch grammar to this local base.

        A stale digest, invalid candidate or forbidden interface change leaves
        the session baseline unchanged. The distinct receipt never claims the
        old editor's whole-module-body recheck when bodies were actually reused.
        """
        record = _record(self)
        with record.lock:
            _record(self)
            snapshot = record.snapshot
            original = core.VerifiedProgram(snapshot.canonical_bytes,
                                            snapshot.structured_bytes)
            try:
                candidate, schema, policy, count = _prepare_program_patch(original, request)
            except HIAEditRejected as exc:
                report = _report(snapshot)
                self._failed(record, report, exc)
                raise
            return self._verify_locked(record, candidate,
                                       patch=(original, schema, policy, count))

    def _verify_locked(self, record, document, *, patch=None):
        before = record.snapshot
        report = _report(before)
        try:
            policy = _policy()
            checked = self._check(document, before, report)
            if policy != _policy():
                # A live reload/registry change cannot upgrade cached old
                # results to the new policy. Recheck these same immutable
                # bytes once; continuous changes fail closed.
                policy = _policy()
                report = _report(before)
                checked = self._full(checked, report,
                                     "verifier_or_registry_changed_during_check")
                if policy != _policy():
                    _reject("verifier or registry changed during fallback")
            if patch is not None:
                original, schema, interface_policy, count = patch
                changes = _check_patch_interface(original, checked, interface_policy)
            # Capture only a fully accepted result; caller-owned output and
            # receipt dictionaries never back the retained cache.
            following = _snapshot(checked, policy)
            report.update(status="verified_unpublished", after_sha256=checked.sha256)
            report["sha256"] = sha256(_wire(report)).hexdigest()
            report_bytes = _wire(report)
            if patch is not None:
                receipt = {
                    "schema": PATCH_REPORT_SCHEMA, "status": "verified_unpublished",
                    "before_sha256": original.sha256, "after_sha256": checked.sha256,
                    "original_input_sha256": original.input_sha256,
                    "request_schema": schema, "interface_policy": interface_policy,
                    "interface_changes": changes, "edits": count,
                    "edit_domain": "independently_verified_normalized_core",
                    "verification": json.loads(report_bytes),
                    "claims": {"entire_candidate_admitted": True,
                               "all_candidate_bodies_rechecked": report["functions_body_reused"] == [],
                               "interface_preserved": changes == [],
                               "external_callers_revalidated": False,
                               "behavior_equivalence_proved": False,
                               "native_executed": False},
                }
                receipt["sha256"] = sha256(_wire(receipt)).hexdigest()
            record.snapshot, record.report_bytes = following, report_bytes
            return checked, receipt if patch is not None else json.loads(report_bytes)
        except (core.HIAProgramRejected, HIAIncrementalRejected, HIAEditRejected) as exc:
            self._failed(record, report, exc)
            raise

    @staticmethod
    def _failed(record, report, exc):
        report.update(status="rejected", error={
            "code": getattr(exc, "code", "E_HIA_EDIT" if isinstance(exc, HIAEditRejected)
                            else "E_HIA_INCREMENTAL"), "message": str(exc)})
        report["sha256"] = sha256(_wire(report)).hexdigest()
        record.report_bytes = _wire(report)

    def _check(self, document, before, report):
        if (isinstance(document, core.VerifiedProgram)
                and document.structured_bytes is not None):
            # Full verification preserves the nominal input/core binding. A
            # forged dataclass cannot supply trusted normalized bytes.
            return self._full(document, report, "structured_candidate")
        data, raw = core._decode(document)
        schema = data.get("schema") if type(data) is dict else None
        if type(schema) is not str or schema not in _SCHEMAS:
            return self._full(raw, report, "schema_outside_incremental_contract")
        if schema == core.SCHEMA_V2 and "types" in data:
            return self._full(raw, report, "ambiguous_legacy_namespace")
        if before.structured_bytes is not None:
            return self._full(raw, report, "structured_base")
        if before.policy != _policy():
            return self._full(raw, report, "verifier_or_registry_changed")
        envelope = _wire({key: value for key, value in data.items() if key != "functions"})
        if before.envelope != envelope:
            return self._full(raw, report, "module_envelope_changed")

        report["mode"] = "incremental"
        functions, blocks = core._primitive_structure(data)
        interfaces = core._function_interfaces(functions)
        report["global_structure_checked"] = True
        report["function_shapes_checked"] = len(functions)
        report["operation_shapes_checked"] = sum(len(b["ops"]) for fn in functions.values()
                                                  for b in fn["blocks"])
        for name, fn in functions.items():
            unchanged = before.functions.get(name) == _wire(fn)
            invalidations = (sorted(callee for callee in before.dependencies[name]
                                    if before.interfaces.get(callee) != interfaces.get(callee))
                             if unchanged else [])
            if unchanged and not invalidations:
                report["functions_body_reused"].append(name)
                continue
            if invalidations:
                report["dependency_invalidations"][name] = invalidations
            report["functions_body_attempted"].append(name)
            core._verify_function(schema, fn, blocks[name], interfaces)
            report["functions_body_completed"].append(name)
            report["blocks_in_completed_bodies"] += len(fn["blocks"])
            report["operations_in_completed_bodies"] += sum(len(b["ops"]) for b in fn["blocks"])
        return core.VerifiedProgram(raw)

    @staticmethod
    def _full(document, report, reason):
        report.update(mode="full", fallback_reason=reason,
                      global_structure_checked=None,
                      functions_body_attempted=None, functions_body_completed=None,
                      blocks_in_completed_bodies=None, operations_in_completed_bodies=None)
        checked = core.verify_program(document)
        functions = checked.as_dict()["functions"]
        report.update(global_structure_checked=True,
                      function_shapes_checked=len(functions),
                      operation_shapes_checked=sum(len(b["ops"]) for fn in functions
                                                   for b in fn["blocks"]),
                      blocks_in_completed_bodies=sum(len(fn["blocks"]) for fn in functions),
                      operations_in_completed_bodies=sum(len(b["ops"]) for fn in functions
                                                         for b in fn["blocks"]),
                      functions_body_attempted=[fn["name"] for fn in functions],
                      functions_body_completed=[fn["name"] for fn in functions])
        return checked
