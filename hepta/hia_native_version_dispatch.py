"""Bounded native entry dispatch using Core builds and sealed subprocess images.

This is an explicit host-owned lifecycle. It is not in-process instruction
patching, NDU activation authority, persistent foreign state, or general FFI.
The existing Linux native observer owns child isolation and process cleanup.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import re
import tempfile
from threading import Condition, Thread
from time import monotonic

from .hia_native_differential import _observe_native, _pin_native_artifact
from .hia_program import verify_program
from .hia_program_llvm import compile_program_llvm, emit_program_llvm
from .hia_schema import SCHEMA, SCHEMA_V2, SCHEMA_V3, SCHEMA_V4, SCHEMA_V5, SCHEMA_V6
from .hia_ndu import PASS_ID, make_plan, prepare_candidate

_SCHEMAS = frozenset((SCHEMA, SCHEMA_V2, SCHEMA_V3, SCHEMA_V4, SCHEMA_V5, SCHEMA_V6))
_WORDS = {"i32": (-2**31, 2**31 - 1), "u32": (0, 2**32 - 1)}
_FINISHED = frozenset(("staged", "cancelled", "failed"))


class HIANativeDispatchRejected(ValueError):
    """Admission or lifecycle request outside the bounded native contract."""


def _reject(message):
    raise HIANativeDispatchRejected("E_HIA_NATIVE_DISPATCH: " + message)


def _seconds(value, *, zero=False):
    if (type(value) not in (int, float) or not (0 if zero else 0.0) <= value <= 60
            or (not zero and value == 0)):
        _reject("wait timeout must be a finite number in " + ("0..60" if zero else "(0,60]"))
    return float(value)


def _checked(payload):
    if type(payload) is not bytes:
        _reject("immutable Core bytes are required")
    core = verify_program(payload)
    if core.structured_bytes is not None or core.as_dict()["schema"] not in _SCHEMAS:
        _reject("native dispatch supports primitive v1-v6 only")
    exports = core.scalar_entrypoints
    functions = {fn["name"]: fn for fn in core.as_dict()["functions"]}
    if not 1 <= len(exports) <= 32:
        _reject("one to 32 scalar public entries are required")
    signatures = []
    for name in exports:
        function = functions[name]
        returns, params = function["returns"], function["params"]
        if (len(returns) != 1 or returns[0] not in _WORDS or len(params) > 16
                or any(param["type"] != returns[0] for param in params)):
            _reject("native observer requires homogeneous i32/u32 ABI wrappers")
        signatures.append((name, returns[0], len(params)))
    return core, tuple(sorted(signatures))


@dataclass(frozen=True)
class _NativeVersion:
    core_bytes: bytes
    core_sha256: str
    artifact_sha256: str
    artifact_bytes: int
    descriptor: int
    signatures: tuple
    native_receipt_json: str

    def receipt(self):
        return json.loads(self.native_receipt_json)


def _build_version(core_bytes, clang, *, diagnostic_loan_site=None):
    """Compile exact verified Core and transfer one sealed descriptor on success."""
    core, signatures = _checked(core_bytes)
    ir = emit_program_llvm(core) if diagnostic_loan_site is None else None
    fd = None
    try:
        with tempfile.TemporaryDirectory(prefix="hepta-native-version-") as directory:
            artifact = Path(directory) / "program.so"
            if diagnostic_loan_site is None:
                receipt = compile_program_llvm(ir, program=core, output=artifact, clang=clang)
                ir_sha256 = ir.sha256
                expected_exports = sorted(name for name, _, _ in signatures)
            else:
                from .hia_native_loan_probe import CONFIGURE, compile_probe
                probe_ir, receipt = compile_probe(core, diagnostic_loan_site, artifact, clang)
                ir_sha256 = probe_ir["sha256"]
                expected_exports = sorted([name for name, _, _ in signatures] + [CONFIGURE])
            raw, _identity, fd = _pin_native_artifact(artifact)
            digest = sha256(raw).hexdigest()
            if (receipt.get("ok") is not True
                    or receipt.get("status") != "native_compiled_not_executed"
                    or receipt.get("kind") != "shared"
                    or receipt.get("core_sha256") != core.sha256
                    or receipt.get("llvm_ir_sha256") != ir_sha256
                    or receipt.get("artifact_sha256") != digest
                    or receipt.get("artifact_bytes") != len(raw)
                    or sorted(receipt.get("exports", [])) != expected_exports):
                _reject("compiled Core, ABI or sealed artifact receipt mismatch")
            result = _NativeVersion(core.canonical_bytes, core.sha256, digest,
                                    len(raw), fd, signatures,
                                    json.dumps(receipt, sort_keys=True, allow_nan=False))
        # Filesystem cleanup happens before descriptor ownership transfers.
        fd = None
        return result
    finally:
        if fd is not None:
            os.close(fd)


class NativeVersionDispatcher:
    """A baseline and one reproduced candidate, one background build, finite calls.

    Candidate staging never activates it. Build cancellation withdraws
    publication; an already running compiler retains its existing bounded
    subprocess timeout. Each actual native child uses its pinned sealed image.
    Closed dispatchers reject new work while already admitted work drains.
    """

    def __init__(self, baseline: bytes, *, clang="clang", max_in_flight=4, diagnostic_loan_site=None):
        if platform.system() != "Linux" or platform.machine().lower() not in {"x86_64", "amd64"}:
            _reject("Linux x86-64 native observer required")
        if type(clang) is not str or not clang or len(clang) > 4096:
            _reject("an explicit compiler command string is required")
        if type(max_in_flight) is not int or not 1 <= max_in_flight <= 16:
            _reject("max_in_flight must be an integer in 1..16")
        checked, _ = _checked(baseline)
        if diagnostic_loan_site is not None:
            from .hia_native_loan_probe import checked_site
            diagnostic_loan_site = checked_site(diagnostic_loan_site)
        self._diagnostic_loan_site = diagnostic_loan_site
        version = self._build(checked.canonical_bytes, clang)
        self._baseline = version
        self._clang = clang
        self._versions = {version.core_sha256: version}
        self._calls = {version.core_sha256: 0}
        self._draining = set()
        self._active = version.core_sha256
        self._generation = 0
        self._total_calls = 0
        self._max_in_flight = max_in_flight
        self._retired_versions = 0
        self._released_artifacts = 0
        self._discarded_build_artifacts = 0
        self._closed = False
        self._job_counter = 0
        self._job = None
        self._worker = None
        self._condition = Condition()
        self._exports = {name: (word, arity) for name, word, arity in version.signatures}

    def _build(self, core_bytes, clang):
        # Preserve the ordinary two-argument boundary for existing build controls.
        if self._diagnostic_loan_site is None:
            return _build_version(core_bytes, clang)
        return _build_version(core_bytes, clang, diagnostic_loan_site=self._diagnostic_loan_site)

    def _require_open(self):
        if self._closed:
            _reject("dispatcher is closing or closed")

    def _release_locked(self, identity):
        version = self._versions.pop(identity)
        self._calls.pop(identity)
        self._draining.discard(identity)
        os.close(version.descriptor)
        self._released_artifacts += 1

    def _retire_locked(self):
        for identity in tuple(self._draining):
            if identity != self._active and self._calls[identity] == 0:
                self._release_locked(identity)
                self._retired_versions += 1
        if self._closed:
            for identity in tuple(self._versions):
                if self._calls[identity] == 0:
                    self._release_locked(identity)
        self._condition.notify_all()

    def _job_receipt_locked(self):
        if self._job is None:
            return None
        # The job contains only detached JSON data, never a Future, FD or code hook.
        return json.loads(json.dumps(self._job, sort_keys=True, allow_nan=False))

    def stage_candidate_async(self, candidate: bytes, *, pass_id=PASS_ID):
        checked, signatures = _checked(candidate)
        baseline, _ = _checked(self._baseline.core_bytes)
        plan = make_plan(baseline, entry=sorted(baseline.scalar_entrypoints)[0], pass_id=pass_id)
        prepared = prepare_candidate(baseline, plan)
        if checked.canonical_bytes == baseline.canonical_bytes:
            relation = "baseline"
        elif checked.canonical_bytes == prepared.candidate.canonical_bytes:
            # Replay again with the actual exchanged bytes; validity alone is
            # never evidence that this is the declared transformation.
            prepare_candidate(baseline, plan, candidate_bytes=checked.canonical_bytes)
            relation = "reproduced_registered_rewrite"
        else:
            _reject("candidate is neither baseline nor its exact reproduced rewrite")
        if signatures != self._baseline.signatures:
            _reject("candidate public ABI differs from the baseline")
        with self._condition:
            self._require_open()
            if self._worker is not None:
                _reject("one background compilation is already in flight")
            if checked.sha256 not in self._versions and len(self._versions) >= 2:
                _reject("two-version inventory is full")
            self._job_counter += 1
            job = {"schema": "hepta.hia.native-version-build.v2", "job_id": self._job_counter,
                   "baseline_sha256": baseline.sha256, "candidate_sha256": checked.sha256,
                   "relation": relation, "rewrite_replacements": prepared.replacements,
                   "pass_id": pass_id, "plan_sha256": prepared.plan_sha256,
                   "generation_at_submission": self._generation, "status": "queued",
                   "cancel_requested": False, "activated": False,
                   "build_attempt_started": False, "native_artifact_built": False, "published": False}
            self._job = job
            if checked.sha256 in self._versions:
                version = self._versions[checked.sha256]
                job.update(status="staged", published=True, already_staged=True,
                           artifact_sha256=version.artifact_sha256,
                           native_bytes_equal_baseline=version.artifact_sha256 == self._baseline.artifact_sha256)
            else:
                worker = Thread(target=self._compile_candidate,
                                args=(job, checked.canonical_bytes),
                                name="hia-native-compile-" + str(job["job_id"]), daemon=False)
                self._worker = worker
                try:
                    worker.start()
                except BaseException:
                    self._worker = None
                    job.update(status="failed", diagnostic={"type": "ThreadStartFailure"})
                    self._condition.notify_all()
                    raise
            return self._job_receipt_locked()

    def _compile_candidate(self, job, core_bytes):
        built = None
        try:
            with self._condition:
                if self._closed or job["cancel_requested"]:
                    job["status"] = "cancelled"
                    return
                job.update(status="compiling", build_attempt_started=True)
            built = self._build(core_bytes, self._clang)
            receipt, baseline_receipt = built.receipt(), self._baseline.receipt()
            with self._condition:
                job.update(native_artifact_built=True, artifact_sha256=built.artifact_sha256,
                           native_receipt=receipt)
            if (receipt["toolchain"]["sha256"] != baseline_receipt["toolchain"]["sha256"]
                    or receipt["implementation_sha256"] != baseline_receipt["implementation_sha256"]):
                _reject("compiler or Core implementation identity changed between versions")
            with self._condition:
                job.update(artifact_sha256=built.artifact_sha256,
                           native_bytes_equal_baseline=built.artifact_sha256 == self._baseline.artifact_sha256,
                           native_receipt=receipt)
                if self._closed or job["cancel_requested"]:
                    job["status"] = "cancelled"
                else:
                    if built.core_sha256 in self._versions or len(self._versions) >= 2:
                        _reject("native version inventory changed during compilation")
                    self._versions[built.core_sha256] = built
                    self._calls[built.core_sha256] = 0
                    job.update(status="staged", published=True)
                    built = None  # Ownership is now in the version inventory.
        except BaseException as error:
            with self._condition:
                job.update(status="failed", diagnostic={"type": type(error).__name__,
                                                        "message": str(error)[:4096]})
        finally:
            if built is not None:
                os.close(built.descriptor)
                with self._condition:
                    self._discarded_build_artifacts += 1
            with self._condition:
                self._worker = None
                self._retire_locked()

    def _require_job(self, job_id):
        if type(job_id) is not int or self._job is None or self._job["job_id"] != job_id:
            _reject("unknown or no longer retained build job")

    def wait_candidate(self, job_id: int, *, timeout=60.0):
        deadline = monotonic() + _seconds(timeout, zero=True)
        with self._condition:
            self._require_job(job_id)
            while self._job["status"] not in _FINISHED or self._worker is not None:
                remaining = deadline - monotonic()
                if remaining <= 0:
                    break
                self._condition.wait(remaining)
                self._require_job(job_id)
            return self._job_receipt_locked()

    def cancel_candidate(self, job_id: int):
        with self._condition:
            self._require_job(job_id)
            changed = self._job["status"] not in _FINISHED and not self._job["cancel_requested"]
            if changed:
                self._job["cancel_requested"] = True
            return {"schema": "hepta.hia.native-version-cancel.v1", "job_id": job_id,
                    "cancel_requested": self._job["cancel_requested"], "changed": changed,
                    "compiler_preempted": False, "active_version_changed": False}

    def _check_generation(self, expected):
        if type(expected) is not int or expected < 0 or expected != self._generation:
            _reject("stale or invalid expected generation")

    def _activate_locked(self, identity, expected_generation):
        self._require_open()
        self._check_generation(expected_generation)
        if identity not in self._versions:
            _reject("candidate is not compiled and staged or has retired")
        previous = self._active
        changed = previous != identity
        if changed:
            self._active = identity
            self._generation += 1
            self._draining.discard(identity)
            if previous != self._baseline.core_sha256:
                self._draining.add(previous)
            self._retire_locked()
        return {"schema": "hepta.hia.native-version-activation.v1", "generation": self._generation,
                "previous_sha256": previous, "active_sha256": self._active,
                "changed": changed, "future_calls_only": True,
                "external_state_migrated": False, "ndu_authorized_activation": False,
                "in_process_native_hot_patch": False}

    def activate(self, candidate_sha256: str, *, expected_generation: int):
        if type(candidate_sha256) is not str or re.fullmatch(r"[0-9a-f]{64}", candidate_sha256) is None:
            _reject("candidate identity must be a lowercase SHA-256")
        with self._condition:
            return self._activate_locked(candidate_sha256, expected_generation)

    def rollback(self, *, expected_generation: int):
        with self._condition:
            return self._activate_locked(self._baseline.core_sha256, expected_generation)

    def _admit_call(self, function, arguments, timeout):
        if type(timeout) not in (int, float) or not 0 < timeout <= 10:
            _reject("native child timeout must be a finite number in (0,10]")
        if type(function) is not str or function not in self._exports or type(arguments) not in (list, tuple):
            _reject("a declared scalar entry and exact argument sequence are required")
        word, arity = self._exports[function]
        arguments = tuple(arguments)
        low, high = _WORDS[word]
        if len(arguments) != arity or any(type(value) is not int or not low <= value <= high for value in arguments):
            _reject("arguments differ from the verified native ABI")
        with self._condition:
            self._require_open()
            if self._total_calls >= self._max_in_flight:
                _reject("concurrent native call budget exhausted")
            version = self._versions[self._active]
            generation = self._generation
            self._calls[version.core_sha256] += 1
            self._total_calls += 1
        return version, generation, word, arguments

    def _release_call(self, version):
        with self._condition:
            self._calls[version.core_sha256] -= 1
            self._total_calls -= 1
            self._retire_locked()

    def start_loan_probe(self, function: str, arguments, *, timeout=8.0):
        """Start one diagnostic call, held at its first selected native loan.

        The returned fixed-protocol handle has no executor callback API. It
        keeps the same dispatch reference as an ordinary native call, including
        during rollback or close. Unresumed calls retain the finite timeout.
        """
        if self._diagnostic_loan_site is None:
            _reject("loan observation requires explicitly compiled diagnostic images")
        version, generation, word, arguments = self._admit_call(function, arguments, timeout)
        try:
            from .hia_native_loan_probe import NativeLoanExecution
            return NativeLoanExecution(version=version, generation=generation, function=function,
                word=word, arguments=arguments, timeout=float(timeout), release=lambda: self._release_call(version))
        except BaseException:
            self._release_call(version)
            raise

    def execute(self, function: str, arguments, *, timeout=3.0):
        if self._diagnostic_loan_site is not None:
            _reject("diagnostic images require start_loan_probe and an explicit acknowledgement")
        version, generation, word, arguments = self._admit_call(function, arguments, timeout)
        try:
            outcome, value = _observe_native(Path("/proc/self/fd/" + str(version.descriptor)),
                function, word, list(arguments), timeout=float(timeout), pinned_fd=version.descriptor)
            return {"schema": "hepta.hia.native-version-execution.v1", "generation": generation,
                    "program_sha256": version.core_sha256, "artifact_sha256": version.artifact_sha256,
                    "status": "returned" if outcome == "value" else "trapped", "value": value,
                    "native_observation": outcome,
                    "claims": {"actual_native_child_executed": True, "sealed_image_used": True,
                               "native_trap_reason_proved": False, "external_state_migrated": False,
                               "general_backend_refinement_proved": False}}
        finally:
            self._release_call(version)

    def _drained_locked(self):
        return not self._versions and self._worker is None and self._total_calls == 0

    def close(self, *, wait=True, timeout=60.0):
        if type(wait) is not bool:
            _reject("wait must be a boolean")
        deadline = monotonic() + _seconds(timeout, zero=True)
        with self._condition:
            self._closed = True
            worker = self._worker
            if self._job is not None and self._job["status"] not in _FINISHED:
                self._job["cancel_requested"] = True
            self._retire_locked()
            while wait and not self._drained_locked():
                remaining = deadline - monotonic()
                if remaining <= 0:
                    break
                self._condition.wait(remaining)
            drained = self._drained_locked()
        # Join outside the lock; no compiler result or admitted native call is
        # abandoned when a caller chooses a non-waiting or timed-out close.
        if wait and drained and worker is not None:
            worker.join(max(0.0, deadline - monotonic()))
        return {"schema": "hepta.hia.native-version-close.v1",
                "status": "closed" if drained else "closing", "drained": drained,
                "new_admission_disabled": True, "compiler_preempted": False}

    def snapshot(self):
        with self._condition:
            return {"schema": "hepta.hia.native-version-snapshot.v1",
                    "generation": self._generation, "baseline_sha256": self._baseline.core_sha256,
                    "active_sha256": self._active, "new_admission_disabled": self._closed,
                    "drained": self._drained_locked(), "in_flight": self._total_calls,
                    "max_in_flight": self._max_in_flight, "retired_versions": self._retired_versions,
                    "released_artifacts": self._released_artifacts,
                    "discarded_build_artifacts": self._discarded_build_artifacts,
                    "background_build_active": self._worker is not None,
                    "build_job": self._job_receipt_locked(),
                    "versions": [{"sha256": identity, "artifact_sha256": version.artifact_sha256,
                                  "artifact_bytes": version.artifact_bytes, "in_flight": self._calls[identity],
                                  "state": ("closing" if self._closed else "active" if identity == self._active else
                                            "baseline_retained" if identity == self._baseline.core_sha256 else
                                            "draining" if identity in self._draining else "staged")}
                                 for identity, version in sorted(self._versions.items())],
                    "claims": {"native_entry_version_dispatch": True,
                               "diagnostic_loan_instrumentation": self._diagnostic_loan_site is not None,
                               "in_process_native_hot_patch": False, "foreign_callbacks_supported": False,
                               "shared_external_state_supported": False, "crash_durable": False,
                               "distributed_fencing": False, "production_p6_qualified": False}}

    def __enter__(self):
        with self._condition:
            self._require_open()
        return self

    def __exit__(self, exception_type, exception, traceback):
        closed = self.close(wait=True)
        if not closed["drained"] and exception_type is None:
            _reject("close deadline elapsed while admitted work remains tracked")
        return False
