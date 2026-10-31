"""Owned native state and committed finite work over verified scalar transitions.

The owner adapter is a small trusted runtime, not a new foreign-buffer Core ABI.
Only internally compiled pure (u64,u64)->u64 functions can reach its native
driver. Application queues commit once in this live process; crash recovery and
external transactional exactly-once delivery are deliberately not claimed.
"""
from __future__ import annotations

import ctypes
from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile
import time

from .hia_adaptive import (AdaptiveRejected, AdaptiveRuntime, _digest, _identity,
                           _TOTAL, _NativeRelease)
from .hia_program import verify_program
from .hia_native_differential import _pin_native_artifact
from .native_tool_identity import digest_executable
from .native_mapping_identity import NativeMappingRejected, verify_loaded_symbols
from .elf_shared_abi import inspect_owned_shared_elf

STATE_PROFILE = "hepta.hia.owned-u64-transition-runtime.v1"
_MAX_STEPS = 1_000_000_000
_MAX_ITEMS = 128
_EXPORTS = frozenset({"hs_new", "hs_clone", "hs_free", "hs_identity", "hs_read", "hs_write",
                      "hs_reset", "hs_apply", "hs_cancel", "hs_progress", "hs_live", "hs_allocations",
                      "hs_frees", "hs_refusals"})

# No producer C source, artifact, pointer, callback or allocator is accepted.
# These routines are part of the trusted host adapter. The HIA transition keeps
# the ordinary scalar-only ABI and cannot inspect the owner's pointer/length.
_DRIVER_SOURCE = r'''
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
typedef uint64_t (*transition_fn)(uint64_t, uint64_t);
typedef struct {
  uint64_t *data;
  uint64_t size;
  _Atomic uint64_t progress;
  _Atomic unsigned cancel;
} state;
static _Atomic uint64_t live, allocations, frees, refusals;
state *hs_new(uint64_t n, unsigned fail_at) {
  if (n == 0 || n > 65536) return NULL;
  if (fail_at == 1) { atomic_fetch_add(&refusals, 1); return NULL; }
  state *s = calloc(1, sizeof(state));
  if (!s) { atomic_fetch_add(&refusals, 1); return NULL; }
  atomic_fetch_add(&live, 1); atomic_fetch_add(&allocations, 1);
  s->data = fail_at == 2 ? NULL : calloc(n, sizeof(uint64_t));
  if (!s->data) {
    free(s); atomic_fetch_sub(&live, 1); atomic_fetch_add(&frees, 1);
    atomic_fetch_add(&refusals, 1); return NULL;
  }
  atomic_fetch_add(&live, 1); atomic_fetch_add(&allocations, 1);
  s->size = n; return s;
}
state *hs_clone(state *s) {
  state *copy = hs_new(s->size, 0);
  if (copy) memcpy(copy->data, s->data, s->size * sizeof(uint64_t));
  return copy;
}
void hs_free(state *s) {
  if (!s) return;
  free(s->data); free(s);
  atomic_fetch_sub(&live, 2); atomic_fetch_add(&frees, 2);
}
uint64_t hs_identity(state *s) { return (uint64_t)(uintptr_t)s->data; }
uint64_t hs_read(state *s, uint64_t i) { return s->data[i]; }
void hs_write(state *s, uint64_t i, uint64_t v) { s->data[i] = v; }
void hs_reset(state *s) {
  atomic_store(&s->progress, 0); atomic_store(&s->cancel, 0);
}
int hs_apply(state *s, uint64_t slot, uint64_t count, uint64_t delta, transition_fn f) {
  if (!s || !f || slot >= s->size) return -1;
  uint64_t initial = atomic_load_explicit(&s->progress, memory_order_relaxed);
  for (uint64_t i = 0; i < count; ++i) {
    if (atomic_load_explicit(&s->cancel, memory_order_relaxed)) return 0;
    s->data[slot] = f(s->data[slot], delta);
    atomic_store_explicit(&s->progress, initial+i+1, memory_order_release);
  }
  return 1;
}
void hs_cancel(state *s) { atomic_store_explicit(&s->cancel, 1, memory_order_release); }
uint64_t hs_progress(state *s) { return atomic_load_explicit(&s->progress, memory_order_acquire); }
uint64_t hs_live(void) { return atomic_load(&live); }
uint64_t hs_allocations(void) { return atomic_load(&allocations); }
uint64_t hs_frees(void) { return atomic_load(&frees); }
uint64_t hs_refusals(void) { return atomic_load(&refusals); }
'''


def _adapter_identity():
    return _digest({"adapter": sha256(Path(__file__).read_bytes()).hexdigest(),
                    "continuation": sha256(Path(__file__).with_name("hia_continuation.py").read_bytes()).hexdigest(),
                    "queue_commit": sha256(Path(__file__).with_name("hia_queue_commit.py").read_bytes()).hexdigest(),
                    "scalar_runtime": _identity()})


def _u64(value):
    if type(value) is not int or not 0 <= value < 2**64:
        raise AdaptiveRejected("E_STATE_VALUE: exact u64 required")
    return value


def _driver(directory, clang, *, on_release=None):
    compiler = Path(shutil.which(clang) or clang).resolve(strict=True)
    identity = digest_executable(compiler)
    source, output = directory / "owned-driver.c", directory / "owned-driver.so"
    # The compiler reads our immutable source through stdin, never a producer-
    # writable source pathname. Its output is staged in a private directory;
    # the sealed snapshot is obtained before publishing audit copies.
    with tempfile.TemporaryDirectory(prefix=".owned-driver-", dir=directory) as private:
        staged = Path(private) / "driver.so"
        argv = [str(compiler), "-std=c11", "-O3", "-fPIC", "-shared", "-x", "c", "-", "-o", str(staged)]
        built = subprocess.run(argv, input=_DRIVER_SOURCE, capture_output=True, text=True, timeout=30)
        if built.returncode:
            raise AdaptiveRejected("E_STATE_DRIVER: " + built.stderr[:2000])
        actual, _, fd = _pin_native_artifact(staged)
    library = None
    release = _NativeRelease(None, fd)
    try:
        inventory = inspect_owned_shared_elf(actual, tuple(sorted(_EXPORTS)))
        if digest_executable(compiler) != identity:
            raise AdaptiveRejected("E_STATE_DRIVER: compiler changed")
        library = ctypes.CDLL("/proc/self/fd/" + str(fd), mode=os.RTLD_LOCAL | os.RTLD_NOW)
        release.library = library
        functions = {name: getattr(library, name) for name in sorted(_EXPORTS)}
        release.functions = functions
        try:
            loaded_mapping = verify_loaded_symbols(fd, functions)
        except NativeMappingRejected as error:
            raise AdaptiveRejected("E_STATE_DRIVER_MAPPING: loaded driver differs from its sealed artifact") from error
        pointer, word = ctypes.c_void_p, ctypes.c_uint64
        signatures = {
            "hs_new": ([word, ctypes.c_uint], pointer), "hs_clone": ([pointer], pointer),
            "hs_free": ([pointer], None), "hs_identity": ([pointer], word),
            "hs_read": ([pointer, word], word), "hs_write": ([pointer, word, word], None),
            "hs_reset": ([pointer], None), "hs_apply": ([pointer, word, word, word, pointer], ctypes.c_int),
            "hs_cancel": ([pointer], None), "hs_progress": ([pointer], word),
            **{name: ([], word) for name in ("hs_live", "hs_allocations", "hs_frees", "hs_refusals")},
        }
        for name, (args, result) in signatures.items():
            function = functions[name]
            function.argtypes, function.restype = args, result
        with source.open("x") as audit:
            audit.write(_DRIVER_SOURCE)
        with output.open("xb") as audit:
            audit.write(actual)
        return library, fd, {"source_sha256": sha256(_DRIVER_SOURCE.encode()).hexdigest(),
                             "artifact_sha256": sha256(actual).hexdigest(), "compiler_sha256": identity,
                             "command": argv, "binary_inventory": inventory, "loaded_mapping": loaded_mapping}
    except BaseException as error:
        if on_release is None:
            release.attempt()
        else:
            on_release(release)
        error.native_cleanup = release.snapshot()
        raise


@dataclass(frozen=True)
class _Work:
    slot: int
    delta: int
    iterations: int


_QUEUE_ITEM_KEYS = frozenset({"slot", "delta", "iterations"})


def _snapshot_queue_work_item(item):
    """Capture one bounded caller-owned work item before validating/using it.

    Producer dictionaries are outside the runtime lock. Their key set must not
    be checked before subsequently fetching values from that same mutable dict.
    Copy no more than three entries; validate, hash and execute only the frozen
    scalar values. This is not an atomic snapshot of unrelated producer writes.
    """
    if type(item) is not dict or len(item) > 3:
        raise AdaptiveRejected("E_STATE_QUEUE: exact slot/delta/iterations fields required")
    captured = {}
    try:
        for key, value in item.items():
            if (type(key) is not str or key not in _QUEUE_ITEM_KEYS
                    or key in captured or len(captured) >= 3):
                raise AdaptiveRejected("E_STATE_QUEUE: exact slot/delta/iterations fields required")
            captured[key] = value
    except RuntimeError as exc:
        raise AdaptiveRejected("E_STATE_QUEUE: caller work item changed during capture") from exc
    if set(captured) != _QUEUE_ITEM_KEYS:
        raise AdaptiveRejected("E_STATE_QUEUE: exact slot/delta/iterations fields required")
    return captured["slot"], captured["delta"], captured["iterations"]


class _Lease:
    __slots__ = ("_runtime", "_token")

    def __init__(self, runtime, token):
        self._runtime, self._token = runtime, token

    def read(self, index):
        return self._runtime._access(self._token, index)

    def write(self, index, value):
        self._runtime._access(self._token, index, _u64(value))

    def close(self):
        self._runtime._end_loan(self._token)

    def __enter__(self):
        return self

    def __exit__(self, *exception):
        self.close()


class OwnedAdaptiveRuntime(AdaptiveRuntime):
    """One live exclusive owner, safe native transitions and immutable work queues.

    Handles expose checked scalar access, never pointers or writable views.
    Automatic selection uses an empirical forecast over a real submitted queue.
    It is not a guarantee of future performance or a whole-heap migration.
    """
    def _admit_profile(self, document):
        checked = verify_program(document)
        data = checked.as_dict()
        functions = {fn["name"]: fn for fn in data["functions"]}
        if not 1 <= len(functions) <= 16:
            raise AdaptiveRejected("E_STATE_PROFILE: one to sixteen total scalar functions required")
        entry = next(iter(functions)) if len(functions) == 1 else "transition"
        if entry not in functions:
            raise AdaptiveRejected("E_STATE_PROFILE: helper programs need an explicit transition function")
        graph = {}
        for name, fn in functions.items():
            if (fn["effects"] or len(fn["blocks"]) != 1 or fn["returns"] != ["u64"]
                    or not 1 <= len(fn["params"]) <= 8 or any(p["type"] != "u64" for p in fn["params"])
                    or fn["blocks"][0]["term"]["op"] != "ret"):
                raise AdaptiveRejected("E_STATE_PROFILE: finite total scalar helper signatures only")
            calls = []
            for op in fn["blocks"][0]["ops"]:
                if (op["op"] not in _TOTAL | {"call"}
                        or any(out["type"] not in {"u64", "bool"} for out in op["out"])):
                    raise AdaptiveRejected("E_STATE_PROFILE: trap, memory, resource or external effect rejected")
                if op["op"] == "call":
                    calls.append(op["attrs"]["function"])
            graph[name] = calls
        budgets = {}
        def expanded(name, active):
            if name in active:
                raise AdaptiveRejected("E_STATE_PROFILE: recursive/native-unbounded calls reject")
            if name not in budgets:
                cost = len(functions[name]["blocks"][0]["ops"])
                for callee in graph[name]:
                    cost += expanded(callee, active | {name})
                    if cost > 4096:
                        raise AdaptiveRejected("E_STATE_PROFILE: expanded instruction budget exceeded")
                if cost > 4096:
                    raise AdaptiveRejected("E_STATE_PROFILE: expanded instruction budget exceeded")
                budgets[name] = cost
            return budgets[name]
        for name in functions:
            expanded(name, set())
        fn = functions[entry]
        state = {"schema": "hepta.hia.total-scalar-helper-abi.v1", "core_schema": data["schema"],
                 "target": "x86_64-unknown-linux-gnu", "calling_convention": "C-Linux-LP64",
                 "entry": entry, "params": fn["params"], "returns": fn["returns"],
                 "interfaces": [{k: f[k] for k in ("name", "params", "returns", "effects")}
                                for f in data["functions"]],
                 "persistent_values": [], "live_owners": [], "live_loans": [], "effects": [],
                 "continuation": "native-adapter-entry-no-active-frames"}
        return checked, state

    def __init__(self, base, directory, values, *, clang="clang", policy=None):
        construction_started = time.monotonic_ns()
        if type(values) not in {list, tuple} or not 1 <= len(values) <= 65536:
            raise AdaptiveRejected("E_STATE_SIZE: one to 65536 u64 state cells required")
        # Capture a bounded prefix before validating or allocating. Another
        # thread may grow a caller-owned list after the first size check.
        values = tuple(values[:65537])
        if not 1 <= len(values) <= 65536:
            raise AdaptiveRejected("E_STATE_SIZE: one to 65536 u64 state cells required")
        values = tuple(_u64(value) for value in values)
        self._state = None
        self._driver = None
        self._driver_release = None
        self._owner_release = {"attempted": False, "status": "not_acquired"}
        self._final_ledger = None
        self._final_ledger_error = None
        self._loans = {}
        self._queues = {}
        self._revision = 0
        self._state_poisoned = False
        self._cost_accounting_complete = True
        self._state_identity = _adapter_identity()
        super().__init__(base, directory, clang=clang, policy=policy)
        try:
            if len(self._images["baseline"].state["params"]) != 2:
                raise AdaptiveRejected("E_STATE_ABI: transition requires exactly state and delta u64 arguments")
            started = time.monotonic_ns()
            self._driver, self._driver_fd, self._driver_receipt = _driver(self._root, clang,
                on_release=lambda release: self._record_release("owner-driver", release))
            self._driver_release = _NativeRelease(self._driver, self._driver_fd,
                {name: getattr(self._driver, name) for name in _EXPORTS})
            self._state = self._driver.hs_new(len(values), 0)
            if not self._state:
                raise AdaptiveRejected("E_STATE_ALLOCATION: native owner allocation failed")
            self._owner_release = {"attempted": False, "status": "owned"}
            self._size = len(values)
            self._owner_id = secrets.token_hex(16)
            self._allocation_address = int(self._driver.hs_identity(self._state))
            self._allocation_identity = _digest({"owner": self._owner_id, "address": self._allocation_address})
            for index, value in enumerate(values):
                self._driver.hs_write(self._state, index, value)
            self._owner_schema = {"schema": STATE_PROFILE, "target": "x86_64-unknown-linux-gnu",
                                  "owner": "exclusive-native-u64-array", "cells": len(values),
                                  "word_bits": 64, "endianness": "little", "persistent_fields": ["cells"],
                                  "transition_abi": ["u64", "u64", "u64"],
                                  "safepoint": "no-active-call-and-no-live-loan"}
            self._driver_preparation_ns = time.monotonic_ns() - started
            # Conservatively charge even initial baseline/driver construction
            # to the first deployment. Each later failed or successful prepare
            # is also charged once; producer forecasts cannot waive this debt.
            self._cumulative_deployment_cost_ns = 0
            self._event("state_owner_created", owner_id=self._owner_id, cells=self._size,
                        allocation_identity=self._allocation_identity)
            if _adapter_identity() != self._state_identity:
                raise AdaptiveRejected("E_STATE_STALE: adapter changed during initialization")
            self._unamortized_preparation_ns = time.monotonic_ns() - construction_started
        except BaseException:
            self.close()
            raise

    def _state_open(self):
        self._open()
        if self._state_poisoned or self._state is None or _adapter_identity() != self._state_identity:
            raise AdaptiveRejected("E_STATE_STALE: owner unavailable or implementation changed")

    def _values(self, state=None):
        pointer = self._state if state is None else state
        return tuple(int(self._driver.hs_read(pointer, index)) for index in range(self._size))

    def snapshot(self):
        with self._lock:
            result = super().snapshot()
            result.update(profile=STATE_PROFILE, state_revision=self._revision,
                          live_loans=len(self._loans), owner_id=getattr(self, "_owner_id", None),
                          allocation_identity=getattr(self, "_allocation_identity", None),
                          owner_state_schema=json.loads(json.dumps(getattr(self, "_owner_schema", None))),
                          state_values=list(self._values()) if self._state and not self._active else None,
                          actual_progress=int(self._driver.hs_progress(self._state)) if self._state else None,
                          automatic_profitable_selection_supported=True,
                          performance_policy="committed-queue-empirical-forecast-not-a-guarantee",
                          persistent_owner_switching_supported=True,
                          cancelled_queue_continuation_supported=True,
                          state_poisoned=self._state_poisoned,
                          cost_accounting_complete=self._cost_accounting_complete,
                          general_heap_or_stack_migration_supported=False,
                          crash_recovery_or_external_transaction_exactly_once=False,
                          native_ledger=self._ledger() if self._driver else
                              json.loads(json.dumps(self._final_ledger)))
            owner_pending = self._owner_release["status"] == "unknown"
            driver_blocked = (self._driver_release is not None and owner_pending
                              and not self._driver_release.attempted)
            result["cleanup"].update(
                owner_release=json.loads(json.dumps(self._owner_release)),
                owner_release_retry_permitted=False,
                driver_release=self._driver_release.snapshot() if self._driver_release else None,
                driver_release_blocked_by_owner_uncertainty=driver_blocked,
                final_ledger_error=json.loads(json.dumps(self._final_ledger_error)))
            result["cleanup"]["pending_resource_count"] += int(owner_pending) + int(driver_blocked)
            result["cleanup"]["owned_native_release_complete"] = (
                result["cleanup"]["owned_native_release_complete"]
                and self._owner_release["status"] in {"freed", "not_acquired"}
                and (self._driver_release is None or self._driver_release.complete))
            return result

    def _ledger(self):
        return {name: int(getattr(self._driver, "hs_" + name)())
                for name in ("live", "allocations", "frees", "refusals")}

    def borrow(self, *, mutable=False):
        if type(mutable) is not bool:
            raise AdaptiveRejected("E_STATE_LOAN: Boolean loan mode required")
        with self._lock:
            self._state_open()
            if self._active or (self._loans and (mutable or any(row["mutable"] for row in self._loans.values()))):
                raise AdaptiveRejected("E_STATE_LOAN: conflicting native activity or exclusive loan")
            token = secrets.token_hex(16)
            self._loans[token] = {"mutable": mutable, "generation": self._generation,
                                  "owner": self._owner_id}
            self._event("state_loan_created", mutable=mutable)
            return _Lease(self, token)

    def _access(self, token, index, value=None):
        with self._lock:
            self._state_open()
            loan = self._loans.get(token)
            if (not loan or loan["generation"] != self._generation or loan["owner"] != self._owner_id
                    or self._active):
                raise AdaptiveRejected("E_STATE_STALE_LOAN: alias is no longer live")
            if type(index) is not int or not 0 <= index < self._size:
                raise AdaptiveRejected("E_STATE_BOUNDS: cell outside owned extent")
            if value is None:
                return int(self._driver.hs_read(self._state, index))
            if not loan["mutable"]:
                raise AdaptiveRejected("E_STATE_LOAN: read-only alias cannot mutate")
            self._driver.hs_write(self._state, index, _u64(value))
            self._revision += 1

    def _end_loan(self, token):
        with self._lock:
            if token in self._loans:
                del self._loans[token]
                self._event("state_loan_ended")

    def call(self, *args):
        raise AdaptiveRejected("E_STATE_QUEUE: application state changes require committed work")

    def call_many(self, vectors):
        raise AdaptiveRejected("E_STATE_QUEUE: application state changes require committed work")

    def measure(self, *args, **kwargs):
        raise AdaptiveRejected("E_STATE_QUEUE: use queue-bound calibration, not scalar shadow telemetry")

    def prepare(self, candidate):
        started = time.monotonic_ns()
        try:
            return super().prepare(candidate)
        finally:
            with self._lock:
                self._unamortized_preparation_ns += time.monotonic_ns() - started

    def select(self, token, *, mode="auto"):
        started = time.monotonic_ns()
        try:
            return self._select_owned(token, mode=mode)
        finally:
            with self._lock:
                self._unamortized_preparation_ns += time.monotonic_ns() - started

    def _select_owned(self, token, *, mode="auto"):
        with self._lock:
            self._state_open()
            if self._loans:
                return {"selected": False, "reason": "live_state_loan", "current": self._current}
            if mode == "auto":
                return {"selected": False, "reason": "committed_queue_required", "current": self._current}
            identity, values = self._allocation_address, self._values() if not self._active else None
            result = super().select(token, mode=mode)
            if result["selected"]:
                if int(self._driver.hs_identity(self._state)) != identity or self._values() != values:
                    raise AdaptiveRejected("E_STATE_INVARIANT: version switch changed persistent owner")
                self._event("state_version_switched", owner_id=self._owner_id,
                            allocation_identity=self._allocation_identity)
            return result

    def _restore_admitted(self, token):
        """Roll back to a previously admitted image, without a new proposal.

        A second fallible optimization proof must not prevent rollback after
        the performance budget is exhausted. The old image remains a checked,
        sealed capability in this runtime; no new code is admitted here.
        """
        self._open()
        if self._active or self._loans or token not in self._images:
            raise AdaptiveRejected("E_STATE_ROLLBACK: previously admitted quiescent image required")
        image = self._images[token]
        if (image.state != self._images[self._current].state
                or int(self._driver.hs_identity(self._state)) != self._allocation_address
                or sha256(os.pread(image.fd, os.fstat(image.fd).st_size, 0)).hexdigest() != image.artifact_sha256):
            raise AdaptiveRejected("E_STATE_ROLLBACK: old artifact or fixed owner schema changed")
        try:
            verify_loaded_symbols(image.fd, {image.state["entry"]: image.function})
        except NativeMappingRejected as error:
            raise AdaptiveRejected("E_STATE_ROLLBACK: old function no longer belongs to its sealed image") from error
        previous = self._current
        self._current = token
        self._generation += 1
        self._event("state_version_rollback", previous=previous, token=token,
                    allocation_identity=self._allocation_identity)
        return {"selected": True, "current": token, "previous": previous,
                "authority": "previously_admitted_sealed_image"}

    def submit_queue(self, items):
        started = time.monotonic_ns()
        if type(items) is not list or not 1 <= len(items) <= _MAX_ITEMS:
            raise AdaptiveRejected("E_STATE_QUEUE: one to 128 explicit work items required")
        # The producer does not hold this runtime's lock. Freeze the bounded
        # outer sequence so later growth cannot add work beyond this contract.
        items = tuple(items[:_MAX_ITEMS + 1])
        if not 1 <= len(items) <= _MAX_ITEMS:
            raise AdaptiveRejected("E_STATE_QUEUE: one to 128 explicit work items required")
        with self._lock:
            self._state_open()
            if len(self._queues) >= 32 or any(row["status"] in {"submitted", "running"} for row in self._queues.values()):
                raise AdaptiveRejected("E_STATE_QUEUE: one pending queue and 32 retained queues maximum")
            work = []
            for item in items:
                slot, delta, iterations = _snapshot_queue_work_item(item)
                if (type(slot) is not int or not 0 <= slot < self._size or type(iterations) is not int
                        or not 1 <= iterations <= _MAX_STEPS):
                    raise AdaptiveRejected("E_STATE_QUEUE: invalid finite slot or iteration count")
                work.append(_Work(slot, _u64(delta), iterations))
            if sum(item.iterations for item in work) > _MAX_STEPS:
                raise AdaptiveRejected("E_STATE_QUEUE: finite committed work budget exceeded")
            frozen = tuple(work)
            token = secrets.token_hex(16)
            self._queues[token] = {"items": frozen, "sha256": _digest([
                {"slot": item.slot, "delta": item.delta, "iterations": item.iterations} for item in frozen]),
                                   "status": "submitted",
                                   "revision": self._revision, "owner": self._owner_id,
                                   "initial_values": self._values(), "receipt": None}
            self._unamortized_preparation_ns += time.monotonic_ns() - started
            return token

    def cancel(self, token):
        with self._lock:
            self._state_open()
            row = self._queues.get(token)
            if row is None:
                raise AdaptiveRejected("E_STATE_QUEUE: unknown queue token")
            if row["status"] == "submitted":
                row["status"] = "cancelled"
            elif row["status"] == "running":
                self._driver.hs_cancel(self._state)
            else:
                raise AdaptiveRejected("E_STATE_QUEUE: terminal queue cannot be replayed or cancelled again")

    def queue_status(self, token):
        """Detached observation, including terminal partial progress after errors."""
        with self._lock:
            self._state_open()
            row = self._queues.get(token)
            if row is None:
                raise AdaptiveRejected("E_STATE_QUEUE: unknown queue token")
            return json.loads(json.dumps({"status": row["status"], "queue_sha256": row["sha256"],
                                          "receipt": row["receipt"],
                                          "continued_by": row.get("continued_by"),
                                          "continuation": row.get("continuation")}))

    def continue_queue(self, token):
        """Register only the unexecuted suffix of a cancelled live queue."""
        from .hia_continuation import continue_owned_queue
        return continue_owned_queue(self, token)

    def _apply_items(self, state, items, image):
        function = ctypes.cast(image.function, ctypes.c_void_p)
        for item in items:
            result = self._driver.hs_apply(state, item.slot, item.iterations, item.delta, function)
            if result == 0:
                return False
            if result != 1:
                raise AdaptiveRejected("E_STATE_DRIVER: rejected a validated work item")
        return True

    def _calibrate(self, row, candidate, *, rounds, sample_limit):
        if type(rounds) is not int or not 3 <= rounds <= 9 or type(sample_limit) is not int or not 10000 <= sample_limit <= 2_000_000:
            raise AdaptiveRejected("E_STATE_MEASURE: bounded internal calibration required")
        start = time.monotonic_ns()
        total = sum(item.iterations for item in row["items"])
        samples = tuple(_Work(item.slot, item.delta, min(item.iterations, max(1, sample_limit * item.iterations // total)))
                        for item in row["items"])
        denominator = sum(item.iterations for item in samples)
        baseline = self._images[self._current]
        selected = self._images[candidate]
        observations = []
        live_before = self._ledger()["live"]
        for index in range(rounds):
            pair = {}
            states = {}
            order = (("baseline", baseline), ("candidate", selected))
            for label, image in order if index % 2 == 0 else reversed(order):
                clone = self._driver.hs_clone(self._state)
                if not clone:
                    raise AdaptiveRejected("E_STATE_ALLOCATION: calibration clone failed")
                try:
                    before = time.monotonic_ns()
                    self._apply_items(clone, samples, image)
                    pair[label + "_ns"] = time.monotonic_ns() - before
                    states[label] = self._values(clone)
                finally:
                    self._driver.hs_free(clone)
            if states["baseline"] != states["candidate"]:
                raise AdaptiveRejected("E_STATE_NATIVE: actual calibration states differ")
            observations.append(pair)
        if self._ledger()["live"] != live_before:
            raise AdaptiveRejected("E_STATE_LEAK: calibration did not release its temporary owners")
        saving = min(pair["baseline_ns"] - pair["candidate_ns"] for pair in observations)
        # Integer arithmetic avoids a producer-selected horizon or float wrap.
        projected_saving = saving * total // denominator
        baseline_estimate = min(pair["baseline_ns"] for pair in observations) * total // denominator
        return {"queue_sha256": row["sha256"], "owner": row["owner"], "revision": row["revision"],
                "generation": self._generation, "candidate": candidate,
                "artifact_sha256": selected.artifact_sha256, "sample_steps": denominator,
                "committed_steps": total, "rounds": observations,
                "projected_saving_ns": projected_saving, "baseline_estimate_ns": baseline_estimate,
                "measurement_cost_ns": time.monotonic_ns() - start,
                "basis": "minimum-observed-paired-saving; forecast-not-guaranteed",
                "expires_ns": time.monotonic_ns() + 60_000_000_000}

    def _plan_queue(self, row, candidate, *, rounds, sample_limit, preparation_started, candidate_cost):
        original = self._current
        measurement, selected, reason = None, False, "no_candidate"
        try:
            if candidate is not None:
                if type(candidate) is not str or candidate not in self._images or candidate == original:
                    raise AdaptiveRejected("E_STATE_AUTHORITY: a different internally prepared version is required")
                measurement = self._calibrate(row, candidate, rounds=rounds, sample_limit=sample_limit)
                if measurement["projected_saving_ns"] > candidate_cost + measurement["measurement_cost_ns"]:
                    choice = self._select_owned(candidate, mode="explicit")
                    selected = choice["selected"]
                    reason = "positive_empirical_queue_forecast" if selected else choice["reason"]
                else:
                    reason = "nonpositive_empirical_queue_forecast"
                spent = time.monotonic_ns() - preparation_started
                if selected and (measurement["expires_ns"] <= time.monotonic_ns()
                                 or measurement["projected_saving_ns"] <= candidate_cost + spent):
                    self._restore_admitted(original)
                    selected, reason = False, "forecast_exhausted_by_actual_preparation_and_switch_cost"
            return original, measurement, selected, reason
        except BaseException:
            try:
                if self._current != original:
                    self._restore_admitted(original)
            finally:
                self._unamortized_preparation_ns += time.monotonic_ns() - preparation_started
                self._event("state_queue_preparation_failed", application_steps=0)
            raise

    def execute_committed(self, token, *, candidate=None, rounds=5, sample_limit=200000):
        from .hia_queue_commit import execute_owned_queue
        return execute_owned_queue(self, token, candidate=candidate, rounds=rounds, sample_limit=sample_limit)

    def audit_counterfactual(self, token):
        """Post-decision evaluation only; never authorizes a selection.

        A separate initial-state owner executes the original immutable queue.
        This extra baseline run is experiment overhead, explicitly separate
        from deployment cost, and is never a replay on application state.
        """
        with self._lock:
            self._state_open()
            row = self._queues.get(token)
            if not row or row["status"] != "completed" or not row["receipt"]:
                raise AdaptiveRejected("E_STATE_AUDIT: a completed internal execution is required")
            if self._active or self._loans:
                raise AdaptiveRejected("E_STATE_BUSY: audit requires quiescence")
            start = time.monotonic_ns()
            clone = self._driver.hs_new(self._size, 0)
            if not clone:
                raise AdaptiveRejected("E_STATE_ALLOCATION: audit clone failed")
            try:
                for index, value in enumerate(row["initial_values"]):
                    self._driver.hs_write(clone, index, value)
                before = time.monotonic_ns()
                self._apply_items(clone, row["items"], self._images[row["receipt"]["original_version"]])
                execution_ns = time.monotonic_ns() - before
                values = self._values(clone)
                if list(values) != row["receipt"]["final_values"]:
                    raise AdaptiveRejected("E_STATE_AUDIT: actual counterfactual state differs")
            finally:
                self._driver.hs_free(clone)
            audit_cost = time.monotonic_ns() - start
            deployment = row["receipt"]["deployment_cost_ns"]
            observation = {"schema": "hepta.hia.owned-queue-counterfactual.v1", "queue_sha256": row["sha256"],
                    "baseline_native_execution_ns": execution_ns, "deployment_cost_ns": deployment,
                    "measured_deployment_net_ns": execution_ns - deployment,
                    "audit_experiment_cost_ns": audit_cost,
                    "total_experiment_cost_ns": deployment + audit_cost,
                    "final_state_matches": True, "decision_authority": False,
                    "application_work_replayed": False}
            row["counterfactual_audit"] = observation
            self._event("state_counterfactual_audited", token=token,
                        measured_deployment_net_ns=execution_ns - deployment,
                        audit_experiment_cost_ns=audit_cost)
            return json.loads(json.dumps(observation))

    def close(self):
        with self._lock:
            if self._loans:
                raise AdaptiveRejected("E_STATE_BUSY: live aliases prevent owner destruction")
            super().close()
            if self._driver is None:
                return
            driver, state = self._driver, self._state
            # Revoke active access even if free/dlclose/close reports an
            # ambiguous outcome. No later snapshot or close may call this DLL.
            self._driver = self._state = None
            self._driver_fd = None
            if state:
                self._owner_release = {"attempted": True, "status": "unknown"}
                try:
                    driver.hs_free(state)
                    self._owner_release["status"] = "freed"
                except BaseException as error:
                    self._owner_release["error"] = _NativeRelease._unknown(error)["error"]
                    # The owner may still exist. Keep its driver's loader
                    # reference and fd alive, without replaying free or reading
                    # a potentially freed pointer. The pending state is final.
                    return
            try:
                self._final_ledger = {name: int(getattr(driver, "hs_" + name)())
                    for name in ("live", "allocations", "frees", "refusals")}
            except BaseException as error:
                self._final_ledger_error = _NativeRelease._unknown(error)["error"]
            self._record_release("owner-driver", self._driver_release)
