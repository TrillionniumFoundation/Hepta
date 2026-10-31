"""Finite native version selection at quiescent pure-scalar call boundaries.

No serialized proof, producer performance number, or external shared object is
deployment authority. Programs are reverified and built here; immutable memfds
bind the bytes actually loaded. General live-state/owner migration is excluded.
"""
from __future__ import annotations

import ctypes
from collections import Counter, deque
from dataclasses import dataclass, field
from hashlib import sha256
import json
import os
from pathlib import Path
import secrets
import threading
import time

from .hia_native_differential import _pin_native_artifact
from .native_mapping_identity import NativeMappingRejected, verify_loaded_symbols
from .hia_optimization import (build_optimized_native, checker_identity,
                               verify_optimization, _policy as _admit_optimizer_policy)
from .hia_program import verify_program
from .hia_program_llvm import _implementation_hash
from .hia_prepared import _issue, _reuse

PROFILE = "hepta.hia.adaptive-empty-state-u64.v1"
_TOTAL = frozenset({"const", "select", "bit.not", "bit.and", "bit.or", "bit.xor",
                    "bool.not", "bool.and", "bool.or",
                    *["compare." + op for op in ("eq", "ne", "lt", "le", "gt", "ge")],
                    "int.add.wrap", "int.sub.wrap", "int.mul.wrap"})
_MAX_BATCH = 65536
_MAX_IMAGES = 16


class AdaptiveRejected(ValueError):
    pass


def _version_token(token):
    """Reject untrusted native image keys before any mapping/lock operation.

    The runtime itself issues only "baseline" and 32-character lowercase hex
    labels. Permit bounded printable ASCII for compatibility with existing
    internally recorded test labels, but never hash arbitrary caller objects
    or extremely long strings.
    """
    if (type(token) is not str or not 1 <= len(token) <= 64
            or not token.isascii() or not token.isprintable()):
        raise AdaptiveRejected("E_ADAPT_AUTHORITY: bounded built-in ASCII image token required")
    return token


def _selection_mode(mode):
    """Do not dispatch caller-provided __eq__ while holding the owner lock."""
    if type(mode) is not str or mode not in {"auto", "explicit"}:
        raise AdaptiveRejected("E_ADAPT_AUTHORITY: known built-in selection mode required")
    return mode


def _digest(value):
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def _identity():
    return _digest({"runtime": sha256(Path(__file__).read_bytes()).hexdigest(),
                    "pinning": sha256(Path(__file__).with_name("hia_native_differential.py").read_bytes()).hexdigest(),
                    "mapping": sha256(Path(__file__).with_name("native_mapping_identity.py").read_bytes()).hexdigest(),
                    "prepared": sha256(Path(__file__).with_name("hia_prepared.py").read_bytes()).hexdigest(),
                    "optimization": checker_identity(), "native": _implementation_hash()})


def _profile(document):
    checked = verify_program(document)
    data = checked.as_dict()
    if len(data["functions"]) != 1:
        raise AdaptiveRejected("E_ADAPT_PROFILE: exactly one function is admitted")
    fn = data["functions"][0]
    if (fn["effects"] != [] or not 1 <= len(fn["params"]) <= 8
            or any(p["type"] != "u64" for p in fn["params"])
            or fn["returns"] != ["u64"] or len(fn["blocks"]) != 1
            or checked.scalar_entrypoints != frozenset({fn["name"]})):
        raise AdaptiveRejected("E_ADAPT_PROFILE: pure u64 ABI, one block and empty resource state required")
    block = fn["blocks"][0]
    if block["term"]["op"] != "ret" or len(block["ops"]) > 4096:
        raise AdaptiveRejected("E_ADAPT_PROFILE: a bounded total straight-line body is required")
    for op in block["ops"]:
        if op["op"] not in _TOTAL or any(out["type"] not in {"u64", "bool"} for out in op["out"]):
            raise AdaptiveRejected("E_ADAPT_PROFILE: possible trap, call, owner or loan operation rejected")
    state = {"schema": "hepta.hia.adaptive-state.v1", "core_schema": data["schema"],
             "target": "x86_64-unknown-linux-gnu", "calling_convention": "C-Linux-LP64",
             "entry": fn["name"], "params": fn["params"], "returns": fn["returns"],
             "persistent_values": [], "live_owners": [], "live_loans": [], "effects": [],
             "continuation": "entry-with-no-active-call-frames"}
    return checked, state


@dataclass(eq=False)
class _NativeRelease:
    """One attempt for each owned loader reference and descriptor.

    An exception cannot tell us whether the kernel/loader already released a
    capability. Keep that outcome pending; never retry its numeric identity.
    Callers revoke their active function references before invoking this record.
    This class does not own or remove publication paths.
    """
    library: object
    fd: int | None
    functions: dict = field(default_factory=dict)
    attempted: bool = False
    native: dict = field(default_factory=dict)

    @property
    def complete(self):
        return (self.attempted and all(self.native.get(name, {}).get("status")
                in {"closed", "not_acquired"} for name in ("library", "fd")))

    def attempt(self):
        if self.attempted:
            return self.snapshot()
        self.attempted = True
        self.native = {"library": {"status": "not_acquired" if self.library is None else "unknown"},
                       "fd": {"status": "not_acquired" if self.fd is None else "unknown"}}
        self.functions.clear()
        if self.library is not None:
            try:
                import _ctypes
                for name, value in list(vars(self.library).items()):
                    if isinstance(value, ctypes._CFuncPtr):
                        delattr(self.library, name)
                _ctypes.dlclose(self.library._handle)
                self.native["library"] = {"status": "closed"}
                self.library = None
            except BaseException as error:
                self.native["library"] = self._unknown(error)
        # Loader failure cannot skip the independently owned descriptor.
        if self.fd is not None:
            try:
                os.close(self.fd)
                self.native["fd"] = {"status": "closed"}
                self.fd = None
            except BaseException as error:
                self.native["fd"] = self._unknown(error)
        return self.snapshot()

    @staticmethod
    def _unknown(error):
        return {"status": "unknown", "error": {"type": type(error).__name__,
                "message": str(error), "errno": getattr(error, "errno", None)}}

    def snapshot(self):
        return {"native_attempted": self.attempted,
                "native": json.loads(json.dumps(self.native)),
                "native_release_succeeded": self.complete,
                "native_retry_permitted": False}


@dataclass
class _Image:
    program: object
    state: dict
    artifact: Path
    artifact_sha256: str
    fd: int
    library: object
    function: object
    preparation_ns: int
    receipt: dict
    loaded_mapping: dict
    release: _NativeRelease


def _load_image(program, state, path, receipt, started, *, on_release=None):
    original, _, fd = _pin_native_artifact(path)
    library = None
    release = _NativeRelease(None, fd)
    try:
        native = receipt["native"]
        if (sha256(original).hexdigest() != native["artifact_sha256"]
                or native["core_sha256"] != program.sha256
                or native["target"] != state["target"] or native["kind"] != "shared"):
            raise AdaptiveRejected("E_ADAPT_ARTIFACT: actual executable bytes do not match the internal build")
        library = ctypes.CDLL("/proc/self/fd/" + str(fd), mode=os.RTLD_LOCAL | os.RTLD_NOW)
        release.library = library
        function = getattr(library, state["entry"])
        release.functions[state["entry"]] = function
        try:
            loaded_mapping = verify_loaded_symbols(fd, {state["entry"]: function})
        except NativeMappingRejected as error:
            raise AdaptiveRejected("E_ADAPT_MAPPING: resolved native code does not match its sealed artifact") from error
        loaded_mapping["checker_sha256"] = sha256(
            Path(__file__).with_name("native_mapping_identity.py").read_bytes()).hexdigest()
        function.argtypes = [ctypes.c_uint64] * len(state["params"])
        function.restype = ctypes.c_uint64
        return _Image(program, state, path, native["artifact_sha256"], fd, library,
                      function, time.monotonic_ns() - started, receipt, loaded_mapping, release)
    except BaseException as error:
        if on_release is None:
            release.attempt()
        else:
            on_release(release)
        error.native_cleanup = release.snapshot()
        raise


class AdaptiveRuntime:
    """Host-controlled finite dispatcher; Python host/compiler/loader are trusted.

    Explicit selection is an operator action. Automatic profitable selection is
    not implemented: the fully charged finite shadow experiment cannot repay
    itself. Automatic requests conservatively retain the current version.
    """
    def _admit_profile(self, document):
        return _profile(document)

    def __init__(self, base, directory, *, clang="clang", policy=None):
        started = time.monotonic_ns()
        # A JSON roundtrip before policy admission erases untrusted dict/list/str
        # subclass identity and may allocate unbounded producer-owned data.
        # Admit exact built-ins and freeze a bounded policy BEFORE native setup.
        self._policy = _admit_optimizer_policy(policy)
        self._identity = _identity()
        self._clang = clang
        self._root = Path(directory).absolute()
        if self._root.exists() or self._root.is_symlink():
            raise AdaptiveRejected("E_ADAPT_PATH: a new private build directory is required")
        self._root.mkdir(mode=0o700, parents=True)
        checked, state = self._admit_profile(base)
        if self._policy.get("target") != state["target"]:
            raise AdaptiveRejected("E_ADAPT_TARGET: runtime only executes the qualified host ABI")
        path = self._root / "baseline.so"
        receipt = build_optimized_native(checked, checked, path, policy=self._policy, clang=clang)
        self._lock = threading.RLock()
        self._active = self._generation = self._calls = self._preparing = 0
        self._shadow_calls = self._event_count = 0
        self._closed = False
        self._images = {}
        self._admissions = {}
        self._admission_scope = secrets.token_hex(16)
        self._measurements = {}
        self._events = deque(maxlen=4096)
        self._event_counts = Counter()
        self._pending_native_releases = {}
        self._native_release_history = deque(maxlen=64)
        self._preparing_tokens = set()
        self._current = "baseline"
        image = None
        try:
            image = _load_image(checked, state, path, receipt, started,
                on_release=lambda release: self._record_release("baseline", release))
            admission = _issue(image, parent=None, implementation=self._identity,
                               policy=self._policy, scope=self._admission_scope)
            if _identity() != self._identity:
                raise AdaptiveRejected("E_ADAPT_STALE: implementation changed during baseline admission")
            self._images[self._current] = image
            self._admissions[self._current] = admission
            self._event("baseline_loaded", token="baseline", artifact_sha256=receipt["native"]["artifact_sha256"])
        except BaseException:
            # __init__ has not returned: no caller owns this native image yet.
            # Even failed dictionary publication or event recording must release
            # the successfully loaded image exactly once.
            self._images.clear()
            self._admissions.clear()
            self._closed = True
            if image is not None:
                self._retire_image("baseline", image)
            raise

    def _event(self, kind, **fields):
        self._event_count += 1
        self._event_counts[kind] += 1
        self._events.append({"event": kind, "monotonic_ns": time.monotonic_ns(),
                             "generation": self._generation, **fields})

    def _open(self):
        if self._closed:
            raise AdaptiveRejected("E_ADAPT_CLOSED: runtime is closed")

    def __enter__(self):
        return self

    def __exit__(self, *exception):
        self.close()

    def snapshot(self):
        with self._lock:
            image = self._images.get(self._current)
            return {"profile": PROFILE, "current": self._current, "generation": self._generation,
                    "active_calls": self._active, "completed_native_calls": self._calls,
                    "completed_shadow_calls": self._shadow_calls,
                    "closed": self._closed, "preparing": self._preparing,
                    "automatic_profitable_selection_supported": False,
                    "measurement_mode": "conservative_shadow_only",
                    "state_schema": json.loads(json.dumps(image.state)) if image else None,
                    "state_sha256": _digest(image.state) if image else None,
                    # Retain each admitted image's own kernel observation;
                    # a state/ABI hash cannot stand in for its loaded mapping.
                    # This detached copy is evidence, never a capability.
                    "native_images": {token: {
                        "core_sha256": admitted.program.sha256,
                        "artifact_sha256": admitted.artifact_sha256,
                        "state_sha256": _digest(admitted.state),
                        "loaded_mapping": json.loads(json.dumps(admitted.loaded_mapping)),
                        "mapping_observation": "native_admission_before_first_call",
                        "serialized_evidence_is_authority": False,
                    } for token, admitted in self._images.items()},
                    "event_count": self._event_count, "event_counts": dict(self._event_counts),
                    "raw_events_dropped": self._event_count - len(self._events),
                    "events": json.loads(json.dumps(list(self._events))),
                    "cleanup": self._cleanup_snapshot()}

    def _cleanup_snapshot(self):
        return {"owned_native_release_complete": self._closed and not self._images
                    and not self._preparing and not self._pending_native_releases,
                "pending_resource_count": len(self._pending_native_releases),
                "pending": [{"token": token, **release.snapshot()}
                            for release, token in self._pending_native_releases.items()],
                "recent_attempts": json.loads(json.dumps(list(self._native_release_history))),
                "native_release_failures_are_retried": False,
                "publication_paths_removed": False}

    def _record_release(self, token, release):
        with self._lock:
            first = not release.attempted
            # Capability identity, not a producer/random label, owns the
            # pending slot. Reusing a label cannot overwrite another debt.
            self._pending_native_releases.setdefault(release, token)
            result = release.attempt()
            if release.complete:
                del self._pending_native_releases[release]
            if first:
                self._native_release_history.append({"token": token, **result})
            return result

    def _retire_image(self, token, image):
        # Remove every active reference before a possibly successful unload.
        image.function = image.library = image.fd = None
        return self._record_release(token, image.release)

    def prepare(self, candidate):
        started = time.monotonic_ns()
        image = None
        committed = False
        with self._lock:
            self._open()
            if len(self._images) + self._preparing + len(self._pending_native_releases) >= _MAX_IMAGES:
                raise AdaptiveRejected("E_ADAPT_BUDGET: sixteen loaded versions maximum")
            base = self._images[self._current]
            parent_proof = self._admissions[self._current]
            self._preparing += 1
        token, reserved = None, False
        try:
            token = secrets.token_hex(16)
            with self._lock:
                if (token in self._images or token in self._preparing_tokens
                        or token in self._pending_native_releases.values()):
                    raise AdaptiveRejected("E_ADAPT_TOKEN: native capability label is already owned")
                self._preparing_tokens.add(token)
                reserved = True
            path = self._root / (token + ".so")
            checked, state = self._admit_profile(candidate)
            if state != base.state:
                raise AdaptiveRejected("E_ADAPT_STATE: complete state schema or ABI differs")
            receipt = build_optimized_native(base.program, checked, path, policy=self._policy, clang=self._clang)
            image = _load_image(checked, state, path, receipt, started,
                on_release=lambda release: self._record_release(token, release))
            if _identity() != self._identity:
                raise AdaptiveRejected("E_ADAPT_STALE: implementation changed during candidate admission")
            admission = _issue(image, parent=parent_proof, implementation=self._identity,
                               policy=self._policy, scope=self._admission_scope)
            with self._lock:
                self._open()
                try:
                    self._images[token] = image
                    self._admissions[token] = admission
                    self._event("prepared", token=token, artifact_sha256=image.artifact_sha256,
                                preparation_ns=image.preparation_ns)
                    committed = True
                except BaseException:
                    # Roll back while still holding the lock: another caller
                    # must never select a partially published or disposed image.
                    committed = False
                    self._images.pop(token, None)
                    self._admissions.pop(token, None)
                    raise
            return token
        except BaseException as error:
            if image is not None and not committed:
                self._retire_image(token, image)
            with self._lock:
                try:
                    # If interruption occurs only after a complete publication,
                    # the runtime retains ownership and its sixteen-image cap.
                    # It may already be observed by another thread; do not free
                    # a committed image behind that thread's function pointer.
                    self._event("prepare_return_interrupted" if committed else "prepare_rejected",
                                reason=str(error), elapsed_ns=time.monotonic_ns() - started)
                except BaseException:
                    # Diagnostics must not replace the original failure after
                    # native ownership has already been resolved.
                    pass
            raise
        finally:
            with self._lock:
                self._preparing -= 1
                if reserved:
                    self._preparing_tokens.remove(token)

    @staticmethod
    def _arguments(vectors, arity):
        if type(vectors) is not list or not 1 <= len(vectors) <= _MAX_BATCH:
            raise AdaptiveRejected("E_ADAPT_ARGUMENT: bounded nonempty native call batch required")
        # The caller can mutate exact built-in lists from another thread. Take
        # bounded snapshots before validation, then dispatch only the captured
        # scalar values. The extra element detects overlength without copying
        # an unbounded batch grown after the first length check.
        frozen = tuple(vectors[:_MAX_BATCH + 1])
        if not 1 <= len(frozen) <= _MAX_BATCH:
            raise AdaptiveRejected("E_ADAPT_ARGUMENT: bounded nonempty native call batch required")
        copied = []
        for args in frozen:
            if type(args) not in {list, tuple}:
                raise AdaptiveRejected("E_ADAPT_ARGUMENT: exact u64 argument domain required")
            # Rows are captured sequentially, not atomically as one nested
            # transaction. Each row checked here is exactly the row used by
            # call_many and measure, even if its producer later changes it.
            args = tuple(args[:arity + 1])
            if (len(args) != arity
                    or any(type(v) is not int or not 0 <= v < 2**64 for v in args)):
                raise AdaptiveRejected("E_ADAPT_ARGUMENT: exact u64 argument domain required")
            copied.append(args)
        return copied

    def call(self, *args):
        return self.call_many([args])[0]

    def call_many(self, vectors):
        with self._lock:
            self._open()
            token, image = self._current, self._images[self._current]
            args = self._arguments(vectors, len(image.state["params"]))
            self._active += 1
        completed, results = 0, []
        try:
            for row in args:
                # Exactly one dispatch per original call. No retry, rollback
                # execution or replay on a host interruption/native failure.
                results.append(int(image.function(*row)))
                completed += 1
            return results
        finally:
            with self._lock:
                self._calls += completed
                self._active -= 1
                self._event("call_batch_finished", token=token, requested=len(args), completed=completed,
                            replayed_calls=0)

    def measure(self, token, vectors, *, expires_after_ns=60_000_000_000):
        """Shadow pure calls; store measured costs internally, never accept them.

        Baseline and candidate timing are paired actual native executions. All
        shadow/profile wall time is charged, as is prepare/build/verify/load.
        This fully charged finite experiment cannot repay its own profiling
        cost. It is a shadow observation, not a profitable deployment policy.
        """
        if type(expires_after_ns) is not int or not 0 <= expires_after_ns <= 60_000_000_000:
            raise AdaptiveRejected("E_ADAPT_EVIDENCE: bounded evidence lifetime required")
        token = _version_token(token)
        started = time.monotonic_ns()
        with self._lock:
            self._open()
            if token not in self._images:
                raise AdaptiveRejected("E_ADAPT_AUTHORITY: an internally prepared token is required")
            candidate, base = self._images[token], self._images[self._current]
            epoch, current = self._generation, self._current
            args = self._arguments(vectors, len(base.state["params"]))
            self._measurements.pop(token, None)
            self._active += 1
        times = {"baseline_ns": 0, "candidate_ns": 0}
        count = executed = 0
        try:
            for index, row in enumerate(args):
                values = {}
                # Alternate order to avoid a fixed first-position advantage.
                order = (("baseline", base), ("candidate", candidate))
                if index % 2:
                    order = tuple(reversed(order))
                for label, image in order:
                    before = time.monotonic_ns()
                    values[label] = int(image.function(*row))
                    executed += 1
                    times[label + "_ns"] += time.monotonic_ns() - before
                if values["baseline"] != values["candidate"]:
                    raise AdaptiveRejected("E_ADAPT_NATIVE: observed output mismatch")
                count += 1
        finally:
            with self._lock:
                self._active -= 1
                self._shadow_calls += executed
                self._event("measurement_calls", token=token, completed_pairs=count,
                            executed_native_calls=executed,
                            original_requests_replayed=0)
        elapsed = time.monotonic_ns() - started
        evidence = {"token": token, "generation": epoch, "baseline": current,
                    "state_sha256": _digest(base.state), "identity": self._identity,
                    "artifact_sha256": candidate.artifact_sha256, "pairs": count, **times,
                    "preparation_cost_ns": candidate.preparation_ns,
                    "measurement_cost_ns": elapsed,
                    "net_before_switch_ns": times["baseline_ns"] - times["candidate_ns"]
                                            - candidate.preparation_ns - elapsed,
                    "expires_ns": time.monotonic_ns() + expires_after_ns,
                    "costs_estimated_by_producer": False,
                    "automatic_profitable_selection_supported": False,
                    "measurement_mode": "conservative_shadow_only"}
        with self._lock:
            self._open()
            if (self._generation != epoch or self._current != current or
                    _identity() != self._identity):
                self._event("measurement_discarded", token=token, reason="generation_or_implementation_changed")
                raise AdaptiveRejected("E_ADAPT_STALE: measurement is no longer bound to the active generation")
            self._measurements[token] = evidence
            self._event("measured", token=token, net_before_switch_ns=evidence["net_before_switch_ns"])
        return json.loads(json.dumps(evidence))

    def select(self, token, *, mode="auto"):
        token = _version_token(token)
        mode = _selection_mode(mode)
        started = time.monotonic_ns()
        with self._lock:
            self._open()
            if token not in self._images:
                raise AdaptiveRejected("E_ADAPT_AUTHORITY: an internally prepared token is required")
            if self._active:
                self._event("selection_refused", token=token, reason="active_native_call")
                return {"selected": False, "reason": "active_native_call", "current": self._current}
            epoch, current = self._generation, self._current
            candidate, base = self._images[token], self._images[current]
            evidence = self._measurements.get(token)
            if mode == "auto":
                fresh = (evidence and evidence["generation"] == epoch and evidence["baseline"] == current
                         and evidence["identity"] == self._identity
                         and evidence["artifact_sha256"] == candidate.artifact_sha256
                         and evidence["expires_ns"] > time.monotonic_ns())
                detail = "conservative_shadow_costs_not_deployment_benefit" if fresh else "missing_or_expired_internal_measurement"
                reason = "automatic_profitable_selection_not_implemented"
                self._event("selection_refused", token=token, reason=reason, evidence_reason=detail,
                            selection_cost_ns=time.monotonic_ns() - started)
                return {"selected": False, "reason": reason, "evidence_reason": detail,
                        "current": self._current, "automatic_profitable_selection_supported": False}
        if _identity() != self._identity or candidate.state != base.state:
            reason = "stale_implementation_or_state"
        else:
            try:
                proof = _reuse(self._admissions[current], base, self._admissions[token], candidate,
                               implementation=self._identity, policy=self._policy, scope=self._admission_scope)
                reason = None
            except (ValueError, KeyError):
                reason = "prepared_equivalence_binding_changed"
        with self._lock:
            self._open()
            if self._active or self._generation != epoch or self._current != current:
                reason = "safe_point_changed"
            if _identity() != self._identity:
                reason = "stale_implementation_or_state"
            # The descriptor is sealed and private; checking the exact loaded
            # bytes does not reopen the mutable publication pathname.
            if sha256(os.pread(candidate.fd, os.fstat(candidate.fd).st_size, 0)).hexdigest() != candidate.artifact_sha256:
                reason = "loaded_artifact_changed"
            try:
                verify_loaded_symbols(candidate.fd, {candidate.state["entry"]: candidate.function})
            except NativeMappingRejected:
                reason = "loaded_function_mapping_changed"
            selection_ns = time.monotonic_ns() - started
            if reason:
                self._event("selection_refused", token=token, reason=reason, selection_cost_ns=selection_ns)
                return {"selected": False, "reason": reason, "current": self._current}
            self._current = token
            self._generation += 1
            self._event("selected", token=token, previous=current, mode=mode,
                        selection_cost_ns=time.monotonic_ns() - started,
                        proof_reuse=proof,
                        performance_claim=False)
            return {"selected": True, "current": token, "previous": current, "mode": mode,
                    "proof_reuse": proof}

    @staticmethod
    def _dispose(image):
        # The image is unpublished, or the caller holds the lock at active==0.
        # No function pointer escapes the dispatcher or executes during dlclose.
        image.function = image.library = image.fd = None
        return image.release.attempt()

    def close(self):
        with self._lock:
            if self._closed:
                return
            if self._active or self._preparing:
                raise AdaptiveRejected("E_ADAPT_BUSY: active native calls/builds prevent close")
            images = tuple(self._images.items())
            self._images.clear()
            self._measurements.clear()
            self._admissions.clear()
            self._closed = True
            for token, image in images:
                self._retire_image(token, image)
            self._event("closed")
