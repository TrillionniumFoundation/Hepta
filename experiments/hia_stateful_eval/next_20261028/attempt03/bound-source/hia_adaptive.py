"""Finite native version selection at quiescent pure-scalar call boundaries.

No serialized proof, producer performance number, or external shared object is
deployment authority. Programs are reverified and built here; immutable memfds
bind the bytes actually loaded. General live-state/owner migration is excluded.
"""
from __future__ import annotations

import ctypes
from collections import Counter, deque
from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import secrets
import threading
import time

from .hia_native_differential import _pin_native_artifact
from .hia_optimization import (DEFAULT_POLICY, build_optimized_native,
                               checker_identity, verify_optimization)
from .hia_program import verify_program
from .hia_program_llvm import _implementation_hash

PROFILE = "hepta.hia.adaptive-empty-state-u64.v1"
_TOTAL = frozenset({"const", "select", "bit.not", "bit.and", "bit.or", "bit.xor",
                    "bool.not", "bool.and", "bool.or",
                    *["compare." + op for op in ("eq", "ne", "lt", "le", "gt", "ge")],
                    "int.add.wrap", "int.sub.wrap", "int.mul.wrap"})
_MAX_BATCH = 65536


class AdaptiveRejected(ValueError):
    pass


def _digest(value):
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def _identity():
    return _digest({"runtime": sha256(Path(__file__).read_bytes()).hexdigest(),
                    "pinning": sha256(Path(__file__).with_name("hia_native_differential.py").read_bytes()).hexdigest(),
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


def _load_image(program, state, path, receipt, started):
    original, _, fd = _pin_native_artifact(path)
    library = None
    try:
        native = receipt["native"]
        if (sha256(original).hexdigest() != native["artifact_sha256"]
                or native["core_sha256"] != program.sha256
                or native["target"] != state["target"] or native["kind"] != "shared"):
            raise AdaptiveRejected("E_ADAPT_ARTIFACT: actual executable bytes do not match the internal build")
        library = ctypes.CDLL("/proc/self/fd/" + str(fd), mode=os.RTLD_LOCAL | os.RTLD_NOW)
        function = getattr(library, state["entry"])
        function.argtypes = [ctypes.c_uint64] * len(state["params"])
        function.restype = ctypes.c_uint64
        return _Image(program, state, path, native["artifact_sha256"], fd, library,
                      function, time.monotonic_ns() - started, receipt)
    except Exception:
        if library is not None:
            import _ctypes
            _ctypes.dlclose(library._handle)
        os.close(fd)
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
        self._identity = _identity()
        self._policy = json.loads(json.dumps(DEFAULT_POLICY if policy is None else policy))
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
        self._measurements = {}
        self._events = deque(maxlen=4096)
        self._event_counts = Counter()
        self._current = "baseline"
        self._images[self._current] = _load_image(checked, state, path, receipt, started)
        if _identity() != self._identity:
            self.close()
            raise AdaptiveRejected("E_ADAPT_STALE: implementation changed during baseline admission")
        self._event("baseline_loaded", token="baseline", artifact_sha256=receipt["native"]["artifact_sha256"])

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
                    "event_count": self._event_count, "event_counts": dict(self._event_counts),
                    "raw_events_dropped": self._event_count - len(self._events),
                    "events": json.loads(json.dumps(list(self._events)))}

    def prepare(self, candidate):
        started = time.monotonic_ns()
        with self._lock:
            self._open()
            if len(self._images) + self._preparing >= 16:
                raise AdaptiveRejected("E_ADAPT_BUDGET: sixteen loaded versions maximum")
            base = self._images[self._current]
            self._preparing += 1
        token = secrets.token_hex(16)
        path = self._root / (token + ".so")
        image = None
        try:
            checked, state = self._admit_profile(candidate)
            if state != base.state:
                raise AdaptiveRejected("E_ADAPT_STATE: complete state schema or ABI differs")
            receipt = build_optimized_native(base.program, checked, path, policy=self._policy, clang=self._clang)
            image = _load_image(checked, state, path, receipt, started)
            if _identity() != self._identity:
                raise AdaptiveRejected("E_ADAPT_STALE: implementation changed during candidate admission")
            with self._lock:
                self._open()
                self._images[token] = image
                self._event("prepared", token=token, artifact_sha256=image.artifact_sha256,
                            preparation_ns=image.preparation_ns)
            return token
        except Exception as error:
            if image is not None:
                self._dispose(image)
            with self._lock:
                self._event("prepare_rejected", reason=str(error), elapsed_ns=time.monotonic_ns() - started)
            raise
        finally:
            with self._lock:
                self._preparing -= 1

    @staticmethod
    def _arguments(vectors, arity):
        if type(vectors) is not list or not 1 <= len(vectors) <= _MAX_BATCH:
            raise AdaptiveRejected("E_ADAPT_ARGUMENT: bounded nonempty native call batch required")
        copied = []
        for args in vectors:
            if (type(args) not in {list, tuple} or len(args) != arity
                    or any(type(v) is not int or not 0 <= v < 2**64 for v in args)):
                raise AdaptiveRejected("E_ADAPT_ARGUMENT: exact u64 argument domain required")
            copied.append(tuple(args))
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
        started = time.monotonic_ns()
        with self._lock:
            self._open()
            if type(token) is not str or token not in self._images:
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
        started = time.monotonic_ns()
        with self._lock:
            self._open()
            if (type(token) is not str or token not in self._images
                    or type(mode) is not str or mode not in {"auto", "explicit"}):
                raise AdaptiveRejected("E_ADAPT_AUTHORITY: prepared token and known selection mode required")
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
            proof = verify_optimization(base.program, candidate.program, self._policy)
            reason = None if proof["status"] == "verified" else "equivalence_" + proof["status"]
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
            selection_ns = time.monotonic_ns() - started
            if reason:
                self._event("selection_refused", token=token, reason=reason, selection_cost_ns=selection_ns)
                return {"selected": False, "reason": reason, "current": self._current}
            self._current = token
            self._generation += 1
            self._event("selected", token=token, previous=current, mode=mode,
                        selection_cost_ns=time.monotonic_ns() - started,
                        performance_claim=False)
            return {"selected": True, "current": token, "previous": current, "mode": mode}

    @staticmethod
    def _dispose(image):
        # No function pointer escapes the dispatcher. Caller holds the lock at
        # active==0, so native code cannot still be executing during dlclose.
        import _ctypes
        _ctypes.dlclose(image.library._handle)
        os.close(image.fd)

    def close(self):
        with self._lock:
            if self._closed:
                return
            if self._active or self._preparing:
                raise AdaptiveRejected("E_ADAPT_BUSY: active native calls/builds prevent close")
            for image in self._images.values():
                self._dispose(image)
            self._images.clear()
            self._closed = True
            self._event("closed")
