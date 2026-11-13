"""Explicit scalar state across independently verified native generations.

The existing runtime owns code, proofs, sealed artifacts and generation leases.
This coordinator owns one scalar value. Each transition calls a total native
function with that value as argument zero and commits its scalar result once.
There is no heap/loan/stack migration, receipt import or persistent recovery.
"""
from __future__ import annotations

from collections import deque
from hashlib import sha256
import json
import secrets
import threading

from .hia_multiversion import ScalarMultiversionRuntime
from .hia_program import scalar_value_valid


PROFILE = "hepta.hia.scalar-state-session.v1"
_MAX_NATIVE_CALLS = 1_000_000


class ScalarStateRejected(ValueError):
    pass


class ScalarTransitionCancelled(ScalarStateRejected):
    pass


def _reject(message):
    raise ScalarStateRejected("E_HIA_SCALAR_STATE: " + message)


def _digest(value):
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                             allow_nan=False).encode()).hexdigest()


class ScalarTransitionCancellation:
    """Single-use cooperative cancellation, synchronized with state commit.

    A successful cancel prevents this token from subsequently committing state.
    An accepted native invocation may finish; its result is then discarded.
    This token never cancels a native thread or owns the underlying runtime.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._status = "fresh"
        self._reserved = False

    def cancel(self):
        with self._lock:
            if self._status in {"committed", "failed"}:
                return False
            self._status = "cancelled"
            return True

    def status(self):
        with self._lock:
            return self._status

    def _reserve(self):
        with self._lock:
            if self._reserved:
                _reject("a cancellation token belongs to one transition")
            self._reserved = True
            if self._status == "cancelled":
                raise ScalarTransitionCancelled("E_HIA_SCALAR_STATE: transition was cancelled")
            if self._status != "fresh":
                _reject("a cancellation token belongs to one transition")
            self._status = "running"

    def _failed(self):
        with self._lock:
            if self._status == "running":
                self._status = "failed"

    def __copy__(self):
        _reject("cancellation tokens have one synchronization owner")

    def __deepcopy__(self, memo):
        return self.__copy__()


class ScalarStateSession:
    """Serialize a bounded sequence of pure, typed native state transitions.

    Version publication may overlap a transition: its lease retains the exact
    old code until completion, and every generation was proved equivalent for
    all state/input values by ScalarMultiversionRuntime. Code rollback preserves
    committed application state. The caller continues to own the code runtime.
    """

    def __init__(self, runtime, function, initial_state, *, max_native_calls=65536):
        if type(runtime) is not ScalarMultiversionRuntime:
            _reject("the existing verified scalar runtime is required")
        if (type(max_native_calls) is not int
                or not 1 <= max_native_calls <= _MAX_NATIVE_CALLS):
            _reject("native call budget must be an exact integer from 1 to 1000000")
        if type(function) is not str:
            _reject("function must name an actual exported transition")
        with runtime.lease() as lease:
            matches = [item for item in lease.info.abi if item.function == function]
            if len(matches) != 1:
                _reject("unknown transition function")
            signature = matches[0]
            if not signature.parameters or signature.parameters[0] != signature.result:
                _reject("argument zero and the result must have one identical scalar state type")
            if not scalar_value_valid(initial_state, signature.result):
                _reject("initial state differs from its exact scalar type")
            anchor = lease.info.program_sha256
        self._runtime, self._signature = runtime, signature
        self._lock = threading.Lock()
        self._id = secrets.token_hex(16)
        self._contract = {"profile": PROFILE, "anchor_program_sha256": anchor,
                          "function": function, "parameters": list(signature.parameters),
                          "result": signature.result, "state_parameter": 0,
                          "storage": "host-owned-single-scalar", "heap_owners": [], "loans": []}
        self._contract_sha256 = _digest(self._contract)
        # One assignment publishes coherent value/revision/last-transition data.
        # This is in-process cooperative cancellation, not crash recovery.
        self._record = (initial_state, 0, None)
        self._max_native_calls = max_native_calls
        self._native_calls = self._failures = self._cancelled_after = 0
        self._cancelled_before = self._stale = self._event_count = 0
        self._closed = False
        self._events = deque(maxlen=128)

    def _event(self, kind, **fields):
        self._event_count += 1
        self._events.append({"event": kind, "revision": self._record[1], **fields})

    def step(self, arguments, *, expected_revision, cancellation=None):
        """Apply one transition or retain state; never replay a native call.

        The revision is mandatory. A caller uncertain whether its result was
        delivered can inspect snapshot/last_transition before retrying; the old
        revision cannot apply the same transition again after commit.
        """
        if (type(expected_revision) is not int or not 0 <= expected_revision < 2**63
                or type(arguments) not in {list, tuple}):
            _reject("an exact revision and scalar argument sequence are required")
        arguments = tuple(arguments)
        parameters = self._signature.parameters[1:]
        if (len(arguments) != len(parameters)
                or any(not scalar_value_valid(value, typ)
                       for value, typ in zip(arguments, parameters))):
            _reject("transition arguments differ from the exact scalar ABI")
        if cancellation is None:
            cancellation = ScalarTransitionCancellation()
        if type(cancellation) is not ScalarTransitionCancellation:
            _reject("an actual single-use transition cancellation token is required")
        with self._lock:
            if self._closed:
                _reject("state session is closed")
            if expected_revision != self._record[1]:
                self._stale += 1
                _reject("stale state revision")
            if self._native_calls >= self._max_native_calls:
                _reject("native call budget exhausted, including cancelled and failed work")
            try:
                cancellation._reserve()
            except ScalarTransitionCancelled:
                self._cancelled_before += 1
                self._event("cancelled_before_execution")
                raise
            executed = committed = discarded = False
            try:
                with self._runtime.lease() as lease:
                    if self._signature not in lease.info.abi:
                        _reject("leased generation changed the state transition ABI")
                    with cancellation._lock:
                        if cancellation._status == "cancelled":
                            self._cancelled_before += 1
                            self._event("cancelled_before_execution")
                            raise ScalarTransitionCancelled("E_HIA_SCALAR_STATE: transition was cancelled")
                    before, revision, _ = self._record
                    self._native_calls += 1
                    executed = True
                    value = lease.call(self._signature.function, (before, *arguments))
                    if not scalar_value_valid(value, self._signature.result):
                        _reject("native result differs from the exact scalar state type")
                    transition = {"schema": PROFILE, "session": self._id,
                                  "state_contract_sha256": self._contract_sha256,
                                  "revision_before": revision, "revision_after": revision + 1,
                                  "state_before": before, "state_after": value,
                                  "generation": lease.info.generation,
                                  "selection_epoch": lease.selection_epoch,
                                  "program_sha256": lease.info.program_sha256,
                                  "artifact_sha256": lease.info.artifact_sha256,
                                  "native_calls": 1, "replayed_calls": 0}
                    record = (value, revision + 1, transition)
                    with cancellation._lock:
                        if cancellation._status == "cancelled":
                            self._cancelled_after += 1
                            discarded = True
                            self._event("cancelled_after_execution", generation=lease.info.generation)
                            raise ScalarTransitionCancelled("E_HIA_SCALAR_STATE: native result discarded after cancellation")
                        try:
                            self._record = record
                        finally:
                            if self._record is record:
                                committed = True
                                cancellation._status = "committed"
                    self._event("committed", generation=lease.info.generation)
                    return dict(transition)
            except BaseException:
                cancellation._failed()
                if executed and not committed and not discarded:
                    self._failures += 1
                    self._event("native_transition_failed",
                                cancellation_requested=cancellation.status() == "cancelled")
                raise

    def snapshot(self):
        with self._lock:
            value, revision, last_transition = self._record
            return {"schema": PROFILE, "session": self._id, "closed": self._closed,
                    "state_contract": json.loads(json.dumps(self._contract)),
                    "state_contract_sha256": self._contract_sha256,
                    "state": value, "revision": revision,
                    "native_calls": self._native_calls, "max_native_calls": self._max_native_calls,
                    "failed_native_calls": self._failures,
                    "cancelled_before_execution": self._cancelled_before,
                    "cancelled_after_execution": self._cancelled_after,
                    "stale_revisions_rejected": self._stale,
                    "last_transition": dict(last_transition) if last_transition else None,
                    "events": [dict(event) for event in self._events],
                    "events_dropped": self._event_count - len(self._events),
                    "claims": {"explicit_scalar_state": True,
                               "state_preserved_across_equivalent_generations": True,
                               "cooperative_cancellation_before_commit": True,
                               "live_heap_or_loan_migration": False, "stack_migration": False,
                               "crash_recovery": False, "automatic_profitability_established": False}}

    def close(self):
        # Wait for an already running transition. The caller retains ownership
        # of the shared code runtime, so closing a session does not close it.
        with self._lock:
            self._closed = True

    def __enter__(self):
        with self._lock:
            if self._closed:
                _reject("state session is closed")
        return self

    def __exit__(self, *unused):
        self.close()

    def __copy__(self):
        _reject("state sessions have one serialized state owner")

    def __deepcopy__(self, memo):
        return self.__copy__()
