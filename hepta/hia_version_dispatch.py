"""Bounded, host-controlled version dispatch for the actual HIA interpreter.

Only a frozen baseline and the exact existing byte-swap rewrite may be staged.
This module neither evaluates NDU advice nor grants native execution authority.
Each call pins immutable Core bytes; a generation change affects later calls.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from threading import Lock

from .hia_program import verify_program
from .hia_program_runtime import execute_program
from .hia_schema import SCHEMA, SCHEMA_V2, SCHEMA_V3, SCHEMA_V4, SCHEMA_V5, SCHEMA_V6
from .hia_swap_opt import rewrite_byte_swap


_SCHEMAS = frozenset((SCHEMA, SCHEMA_V2, SCHEMA_V3, SCHEMA_V4, SCHEMA_V5, SCHEMA_V6))


class HIAVersionDispatchRejected(ValueError):
    """A request is outside the local version-dispatch contract."""


def _reject(message):
    raise HIAVersionDispatchRejected("E_HIA_DISPATCH: " + message)


def _checked_core(payload):
    if type(payload) is not bytes:
        _reject("immutable program bytes are required")
    checked = verify_program(payload)
    if checked.structured_bytes is not None or checked.as_dict()["schema"] not in _SCHEMAS:
        _reject("dispatch supports primitive v1-v6 only")
    if not checked.scalar_entrypoints:
        _reject("at least one scalar public export is required")
    return checked


@dataclass(frozen=True)
class _Version:
    core_bytes: bytes
    sha256: str


class LocalVersionDispatcher:
    """Two-version interpreter dispatch with compare-and-swap activation.

    The host must call stage_candidate and activate explicitly. No caller
    proof, reward, authorization flag or executable callback is accepted.
    Python process integrity is an external assumption, not an auth boundary.
    """

    def __init__(self, baseline: bytes, *, max_in_flight: int = 64):
        if type(max_in_flight) is not int or not 1 <= max_in_flight <= 1024:
            _reject("max_in_flight must be an integer in 1..1024")
        checked = _checked_core(baseline)
        version = _Version(checked.canonical_bytes, checked.sha256)
        self._baseline = version
        self._exports = {fn["name"]: len(fn["params"])
                         for fn in checked.as_dict()["functions"]
                         if fn["name"] in checked.scalar_entrypoints}
        self._versions = {version.sha256: version}
        self._calls = {version.sha256: 0}
        self._draining = set()
        self._active = version.sha256
        self._generation = 0
        self._retired_versions = 0
        self._total_calls = 0
        self._max_in_flight = max_in_flight
        self._lock = Lock()

    def stage_candidate(self, candidate: bytes) -> dict:
        """Reverify bytes and reproduce the allowed rewrite from the baseline.

        A type-safe but behavior-changing edit is not an admissible candidate.
        A baseline identity is an explicit no-change choice. Staging alone
        cannot change the active generation or start any program execution.
        """
        checked = _checked_core(candidate)
        baseline = _checked_core(self._baseline.core_bytes)
        rewrite = rewrite_byte_swap(baseline)
        if checked.canonical_bytes == baseline.canonical_bytes:
            relation = "baseline"
        elif checked.canonical_bytes == rewrite.program.canonical_bytes:
            relation = "reproduced_byte_swap"
        else:
            _reject("candidate is neither the baseline nor its exact allowed rewrite")
        version = _Version(checked.canonical_bytes, checked.sha256)
        with self._lock:
            if version.sha256 not in self._versions:
                # The immutable baseline has only one deterministic candidate.
                if len(self._versions) >= 2:
                    _reject("two-version retention limit exceeded")
                self._versions[version.sha256] = version
                self._calls[version.sha256] = 0
            return {"schema": "hepta.hia.local-version-stage.v1",
                    "baseline_sha256": baseline.sha256,
                    "candidate_sha256": version.sha256,
                    "relation": relation,
                    "rewrite_replacements": rewrite.replacements,
                    "generation": self._generation,
                    "activated": False,
                    "claims": {"core_reverified": True,
                               "candidate_relation_reproduced": True,
                               "general_semantic_equivalence_proved": False,
                               "ndu_authorized_activation": False}}

    def _check_generation(self, expected_generation):
        if (type(expected_generation) is not int or expected_generation < 0
                or expected_generation != self._generation):
            _reject("stale or invalid expected generation")

    def _retire_drained(self):
        # Baseline bytes stay available for rollback. Removing a candidate
        # from dispatch does not claim deterministic Python heap reclamation.
        for identity in tuple(self._draining):
            if identity != self._active and self._calls[identity] == 0:
                del self._versions[identity]
                del self._calls[identity]
                self._draining.remove(identity)
                self._retired_versions += 1

    def _activate_locked(self, identity, expected_generation):
        self._check_generation(expected_generation)
        if identity not in self._versions:
            _reject("candidate is not staged or has already retired")
        previous = self._active
        changed = previous != identity
        if changed:
            self._active = identity
            self._generation += 1
            self._draining.discard(identity)
            if previous != self._baseline.sha256:
                self._draining.add(previous)
            self._retire_drained()
        return {"schema": "hepta.hia.local-version-activation.v1",
                "generation": self._generation,
                "previous_sha256": previous, "active_sha256": self._active,
                "changed": changed, "future_calls_only": True,
                "state_migrated": False, "native_hot_swap": False}

    def activate(self, candidate_sha256: str, *, expected_generation: int) -> dict:
        """Explicit host action; only a previously revalidated identity exists."""
        if (type(candidate_sha256) is not str
                or re.fullmatch(r"[0-9a-f]{64}", candidate_sha256) is None):
            _reject("candidate identity must be a lowercase SHA-256")
        with self._lock:
            return self._activate_locked(candidate_sha256, expected_generation)

    def rollback(self, *, expected_generation: int) -> dict:
        """Route later calls to the retained baseline without undoing effects."""
        with self._lock:
            return self._activate_locked(self._baseline.sha256, expected_generation)

    def execute(self, function: str, arguments, *, max_steps=1_000_000,
                max_heap_bytes=16 * 1024 * 1024, allocation_fail_at=None,
                max_call_depth=256) -> dict:
        """Pin one version, run the actual VM outside the lock, then unpin.

        Core trap/budget/input exceptions propagate unchanged. Their existing
        reports retain the selected program identity and stopped resources;
        releasing a dispatcher reference does not invent a Core destructor.
        """
        if (type(function) is not str or function not in self._exports
                or type(arguments) not in (list, tuple)
                or len(arguments) != self._exports[function]):
            _reject("a scalar exported entry and its argument count are required")
        argument_snapshot = tuple(arguments)
        with self._lock:
            if self._total_calls >= self._max_in_flight:
                _reject("concurrent call budget exhausted")
            version = self._versions[self._active]
            generation = self._generation
            self._calls[version.sha256] += 1
            self._total_calls += 1
        try:
            execution = execute_program(
                version.core_bytes, function, argument_snapshot,
                max_steps=max_steps, max_heap_bytes=max_heap_bytes,
                allocation_fail_at=allocation_fail_at, max_call_depth=max_call_depth)
            return {"schema": "hepta.hia.local-version-execution.v1",
                    "generation": generation, "program_sha256": version.sha256,
                    "execution": execution,
                    "claims": {"actual_core_interpreter_executed": True,
                               "native_executed": False, "state_migrated": False}}
        finally:
            with self._lock:
                self._calls[version.sha256] -= 1
                self._total_calls -= 1
                self._retire_drained()

    def snapshot(self) -> dict:
        """Return detached accounting metadata, never mutable program state."""
        with self._lock:
            return {"schema": "hepta.hia.local-version-snapshot.v1",
                    "generation": self._generation,
                    "baseline_sha256": self._baseline.sha256,
                    "active_sha256": self._active,
                    "in_flight": self._total_calls,
                    "max_in_flight": self._max_in_flight,
                    "retired_versions": self._retired_versions,
                    "versions": [{"sha256": identity,
                                  "in_flight": self._calls[identity],
                                  "state": ("active" if identity == self._active else
                                            "baseline_retained" if identity == self._baseline.sha256 else
                                            "draining" if identity in self._draining else "staged")}
                                 for identity in sorted(self._versions)],
                    "claims": {"process_local_only": True,
                               "crash_durable": False, "distributed_fencing": False,
                               "native_hot_swap": False, "foreign_state_supported": False}}
