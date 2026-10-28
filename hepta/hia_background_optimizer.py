"""Finite, snapshot-bound background optimization for scalar native generations.

The original NDU evaluator proposes; independent translation validation and the
native runtime admit. A single worker processes at most eight outstanding jobs.
No resource state, live stack, layout or native instruction is patched in place.
"""
from __future__ import annotations

from collections import deque
from concurrent.futures import Future, InvalidStateError
from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
import threading
import time

from .hia_multiversion import (PublicationCancellation, ScalarMultiversionRuntime)
from .hia_ndu_optimizer import SCHEMA as RANK_SCHEMA, rank_candidates
from .hia_program import _structure, verify_program
from .hia_program_llvm import TARGET


SCHEMA = "hepta.hia.background-optimization.v1"


class BackgroundOptimizationRejected(ValueError):
    """Malformed submissions, untracked incumbents or exhausted finite capacity."""


def _reject(message):
    raise BackgroundOptimizationRejected("E_HIA_BACKGROUND: " + message)


def _pack(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def _digest(value):
    return sha256(_pack(value)).hexdigest()


def _integer(value, name, minimum=0):
    if type(value) is not int or not minimum <= value < 2**63:
        _reject(name + " must be an exact bounded integer")
    return value


class _OptimizationFuture(Future):
    """Remain cancellable while work runs, until the runtime commits selection.

    The standard Future remains pending until commit/completion. Its public
    cancel method additionally shares the runtime's atomic cancellation token.
    In particular successful cancel cannot race with a later pointer swap.
    """
    def __init__(self, cancellation):
        super().__init__()
        self._publication_cancellation = cancellation
        # An Executor normally performs this cancelled -> notified transition
        # when it dequeues work. Our work remains cancellable while preparing,
        # so notify wait/as_completed before any user completion callback runs.
        self.add_done_callback(self._notify_cancelled_waiters)

    @staticmethod
    def _notify_cancelled_waiters(future):
        if future.cancelled():
            future.set_running_or_notify_cancel()

    def cancel(self):
        if self.done():
            return super().cancel()
        if not self._publication_cancellation.cancel():
            return False
        # Future owns its state transition. No coordinator/token lock may be
        # held while it invokes arbitrary completion callbacks (which may join
        # the worker through shutdown). A concurrent normal completion can win,
        # in which case cancel returns False; the token still forbids a swap.
        return super().cancel()

    def _complete(self, result):
        if not self.done():
            try:
                self.set_result(result)
            except InvalidStateError:
                if not self.cancelled():
                    raise


@dataclass
class _Job:
    number: int
    baseline: object
    generation: int
    epoch: int
    payload: bytes
    future: _OptimizationFuture
    cancellation: PublicationCancellation
    submitted_ns: int
    submit_work_ns: int = 0
    enqueued_ns: int = 0


class BackgroundOptimizer:
    """Own one finite worker; the caller continues to own the native runtime.

    Observations must identify exact program hashes and the current incumbent.
    They remain trusted host measurements, not independently attested timings.
    A caller cannot supply a proof receipt or an admission flag. Each publication
    repeats proof and native preparation against the runtime's original baseline.
    """
    def __init__(self, runtime, baseline, *, function, bridge, max_pending=8,
                 timeout_ms=2000, bridge_timeout_s=10.0):
        if not isinstance(runtime, ScalarMultiversionRuntime):
            _reject("a ScalarMultiversionRuntime is required")
        if type(max_pending) is not int or not 1 <= max_pending <= 8:
            _reject("max_pending must be an exact integer from one to eight")
        if type(timeout_ms) is not int or not 1 <= timeout_ms <= 5000:
            _reject("translation validation timeout must be 1..5000 milliseconds")
        if (type(bridge_timeout_s) not in (int, float)
                or not 0 < bridge_timeout_s <= 60):
            _reject("bridge timeout must be finite and at most sixty seconds")
        if type(bridge) is not dict or set(bridge) != {"binary", "build_receipt"}:
            _reject("bridge requires binary and build_receipt paths")
        self._bridge = {name: Path(path).resolve() for name, path in bridge.items()}
        self._baseline = verify_program(baseline)
        if type(function) is not str or function not in self._baseline.scalar_entrypoints:
            _reject("function must name a public scalar entrypoint")
        snapshot = runtime.snapshot()
        originals = [row for row in snapshot["generations"] if row["baseline"]]
        if (snapshot["closed"] or len(originals) != 1
                or originals[0]["program_sha256"] != self._baseline.sha256
                or originals[0]["input_sha256"] != self._baseline.input_sha256):
            _reject("supplied immutable baseline does not bind the runtime baseline")
        self._runtime, self._function = runtime, function
        self._last_program = self._baseline
        self._current_program(snapshot)
        self._max_pending, self._timeout = max_pending, timeout_ms
        self._bridge_timeout = bridge_timeout_s
        self._condition = threading.Condition()
        self._queue, self._pending = deque(), {}
        self._next, self._active, self._closed = 1, None, False
        self._worker = threading.Thread(target=self._work, name="hia-background-optimizer", daemon=True)
        self._worker.start()

    def _current_program(self, snapshot):
        if snapshot["closed"]:
            _reject("runtime is closed")
        current = next((row for row in snapshot["generations"]
                        if row["generation"] == snapshot["current_generation"]), None)
        if current is not None:
            for program in (self._baseline, self._last_program):
                if (current["program_sha256"] == program.sha256
                        and current["input_sha256"] == program.input_sha256):
                    return program
        _reject("current native source is untracked; observations cannot be silently rebased")

    def submit(self, candidates, observations, objective):
        """Freeze inputs and the exact current generation; return a Future.

        Capacity includes the running job. Cancelling does not free a queue slot
        until the worker observes that cancellation. Queue wait is recorded;
        stale observations are rejected rather than reapplied to a newer head.
        """
        started = time.perf_counter_ns()
        with self._condition:
            if self._closed:
                _reject("coordinator is shut down")
            if len(self._pending) >= self._max_pending:
                _reject("finite outstanding job capacity is exhausted")
            payload = {"candidates": candidates, "observations": observations, "objective": objective}
            _structure(payload)  # Bound bytes/nodes/depth before copying caller-owned JSON.
            packed = _pack(payload)
            frozen = json.loads(packed)
            if type(frozen["objective"]) is not dict or frozen["objective"].get("target") != TARGET:
                _reject("objective target must match the native runtime target")
            snapshot = self._runtime.snapshot()
            baseline = self._current_program(snapshot)
            measured = frozen["observations"]
            if (type(measured) is not dict or type(measured.get("abstain")) is not dict
                    or measured["abstain"].get("program_sha256") != baseline.sha256):
                _reject("incumbent observation does not bind the current source")
            cancellation = PublicationCancellation()
            future = _OptimizationFuture(cancellation)
            job = _Job(self._next, baseline, snapshot["current_generation"],
                       snapshot["selection_epoch"], packed, future, cancellation, started)
            self._next += 1
            self._pending[job.number] = job
            self._queue.append(job)
            job.enqueued_ns = time.perf_counter_ns()
            job.submit_work_ns = job.enqueued_ns - started
            self._condition.notify()
            return future

    def _same_snapshot(self, job):
        snapshot = self._runtime.snapshot()
        return (not snapshot["closed"] and snapshot["current_generation"] == job.generation
                and snapshot["selection_epoch"] == job.epoch)

    def _report(self, job, status, reason):
        return {"schema": SCHEMA, "job": job.number, "status": status, "reason": reason,
                "expected_generation": job.generation, "expected_selection_epoch": job.epoch,
                "decision_generation": job.epoch + 1, "function": self._function,
                "before_sha256": job.baseline.sha256,
                "before_input_sha256": job.baseline.input_sha256,
                "original_baseline_sha256": self._baseline.sha256,
                "selected_id": "abstain", "ranking": None, "publication": None,
                "costs": {"submit_work_ns": job.submit_work_ns},
                "claims": {"state_layout_migration": False, "general_live_code_patch": False,
                           "performance_improvement_established": False,
                           "measurements_independently_attested": False,
                           "backend_refinement_proved": False, "global_optimality_established": False}}

    def _decision(self, job, inputs, report, rank_wall_ns):
        expected = {"schema": RANK_SCHEMA, "before_sha256": job.baseline.sha256,
                    "before_input_sha256": job.baseline.input_sha256,
                    "function": self._function, "generation": job.epoch + 1,
                    "observations_sha256": _digest(inputs["observations"])}
        if type(report) is not dict or any(report.get(k) != v for k, v in expected.items()):
            _reject("ranking does not bind the submitted incumbent, observations and generation")
        if type(report["generation"]) is not int or _pack(report.get("objective")) != _pack(inputs["objective"]):
            _reject("ranking objective or generation has changed")
        objective_sha = _digest({"schema": RANK_SCHEMA, "objective": inputs["objective"],
                                 "function": self._function, "before_sha256": job.baseline.sha256,
                                 "before_input_sha256": job.baseline.input_sha256})
        if report.get("objective_sha256") != objective_sha:
            _reject("ranking objective digest does not bind this snapshot")
        selected, admitted = report.get("selected_id"), report.get("admitted")
        if type(admitted) is not bool or type(selected) is not str:
            _reject("ranking admission fields have the wrong exact types")
        costs = report.get("costs")
        if type(costs) is not dict:
            _reject("ranking lacks measured search costs")
        actual = _integer(costs.get("actual_adapter_ns"), "actual ranking cost")
        if actual > rank_wall_ns:
            _reject("reported ranking duration exceeds the observed invocation")
        total = _integer(costs.get("total_search_ns"), "total search cost")
        supplied = sum(_integer(row["search_ns"], "supplied search cost")
                       for row in inputs["observations"].values())
        if _integer(costs.get("supplied_search_ns"), "reported supplied search cost") != supplied or total != supplied + actual:
            _reject("ranking search costs do not bind the submitted observations")
        if not admitted:
            if selected != "abstain" or type(report.get("net_margin_ns")) is not int or report["net_margin_ns"] != 0:
                _reject("nonadmission must select abstain with zero margin")
            return None, actual, total
        candidates = {row["id"]: row for row in inputs["candidates"]}
        if selected == "abstain" or selected not in candidates:
            _reject("ranking selected an unavailable candidate")
        # Reverify the frozen submitted source; the ranker cannot substitute a
        # different program merely by returning an admitted/ok boolean.
        candidate = verify_program(candidates[selected]["program"])
        ranked = verify_program(report.get("selected_program"))
        if candidate.sha256 != ranked.sha256:
            _reject("ranking selected source differs from the submitted candidate")
        observed = inputs["observations"][selected]
        incumbent = inputs["observations"]["abstain"]
        if observed["program_sha256"] != candidate.sha256 or incumbent["program_sha256"] != job.baseline.sha256:
            _reject("measured costs belong to a different program")
        calls = _integer(inputs["objective"]["expected_calls"], "expected calls", 1)
        cap = _integer(inputs["objective"]["resource_cap_ns"], "resource cap")
        lower = max(0, _integer(incumbent["runtime_ns"], "incumbent runtime")
                    - _integer(incumbent["uncertainty_ns"], "incumbent uncertainty"))
        upper = (_integer(observed["runtime_ns"], "candidate runtime")
                 + _integer(observed["uncertainty_ns"], "candidate uncertainty"))
        margin = (lower - upper) * calls - total
        if (type(report.get("net_margin_ns")) is not int or report["net_margin_ns"] != margin
                or margin <= 0 or total > cap):
            _reject("ranking has no positive bound net margin within its search budget")
        return candidate, actual, total

    def _execute(self, job):
        started = time.perf_counter_ns()
        result = self._report(job, "stale", "incumbent_snapshot_changed")
        result["costs"]["queue_wait_ns"] = started - job.enqueued_ns
        if not self._same_snapshot(job):
            return result
        inputs = json.loads(job.payload)
        if job.cancellation.cancelled():
            return result
        ranking_started = time.perf_counter_ns()
        ranking = rank_candidates(job.baseline, inputs["candidates"], inputs["observations"],
                                  function=self._function, bridge=dict(self._bridge),
                                  objective=inputs["objective"], generation=job.epoch + 1,
                                  timeout_ms=self._timeout, bridge_timeout_s=self._bridge_timeout)
        rank_wall_ns = time.perf_counter_ns() - ranking_started
        result["ranking"] = ranking
        result["costs"]["rank_call_wall_ns"] = rank_wall_ns
        if job.cancellation.cancelled():
            return result
        candidate, charged_rank_ns, search_ns = self._decision(job, inputs, ranking, rank_wall_ns)
        if candidate is None:
            result.update(status="abstained", reason=ranking.get("reason", "ranker_abstained"))
            return result
        if not self._same_snapshot(job):
            return result
        # The ranker already charges actual_adapter_ns. Charge the surrounding
        # invocation/report work exactly once, including ranker return overhead.
        handoff_ns = time.perf_counter_ns()
        outside_ns = job.submit_work_ns + handoff_ns - started - charged_rank_ns
        margin = ranking["net_margin_ns"] - outside_ns
        cap_margin = inputs["objective"]["resource_cap_ns"] - search_ns - outside_ns
        prepare_budget = min(margin - 1, cap_margin)
        result["costs"].update(coordinator_before_publish_ns=outside_ns,
                               publication_budget_ns=max(0, prepare_budget))
        if prepare_budget <= 0:
            result.update(status="abstained", reason="coordinator_work_exhausted_net_or_resource_budget")
            return result
        publication_started = time.perf_counter_ns()
        publication = self._runtime.publish_if_current(
            candidate, job.generation, expected_epoch=job.epoch,
            max_prepare_ns=prepare_budget, cancellation=job.cancellation,
            preparation_started_ns=handoff_ns)
        publication_finished = time.perf_counter_ns()
        publication_wall = publication_finished - publication_started
        with self._condition:
            self._last_program = candidate
        result.update(status="published", reason="fresh_proof_native_prepare_and_conditional_swap_passed",
                      selected_id=ranking["selected_id"], publication=publication)
        result["costs"].update(publication_call_wall_ns=publication_wall,
                               publication_prepare_ns=publication["prepare_ns"],
                               net_margin_before_postcommit_reporting_ns=margin - publication["prepare_ns"],
                               search_and_preparation_ns=search_ns + outside_ns + publication["prepare_ns"],
                               publication_handoff_ns=publication_started - handoff_ns,
                               postcommit_runtime_return_ns=publication_finished - handoff_ns - publication["prepare_ns"])
        return result

    def _work(self):
        while True:
            with self._condition:
                while not self._queue and not self._closed:
                    self._condition.wait()
                if not self._queue:
                    return
                job = self._queue.popleft()
                self._active = job.number
            result = None
            try:
                if not job.cancellation.cancelled():
                    result = self._execute(job)
            except Exception as error:
                status = "rejected" if self._same_snapshot(job) else "stale"
                result = self._report(job, status, type(error).__name__)
                result["detail"] = str(error)[:2048]
            finally:
                with self._condition:
                    self._active = None
                    self._pending.pop(job.number, None)
                    self._condition.notify_all()
            if result is not None:
                result["costs"]["job_wall_before_future_completion_ns"] = time.perf_counter_ns() - job.submitted_ns
                job.future._complete(result)

    def snapshot(self):
        with self._condition:
            return {"schema": SCHEMA, "closed": self._closed, "max_pending": self._max_pending,
                    "outstanding": len(self._pending), "queued": len(self._queue),
                    "active_job": self._active, "worker_alive": self._worker.is_alive()}

    def shutdown(self, wait=True, *, cancel_pending=True):
        """Stop new submissions; cancel accepted jobs or drain the finite queue."""
        if type(wait) is not bool or type(cancel_pending) is not bool:
            _reject("shutdown flags must be exact booleans")
        with self._condition:
            self._closed = True
            pending = list(self._pending.values()) if cancel_pending else []
            self._condition.notify_all()
        for job in pending:
            job.future.cancel()
        if wait and threading.current_thread() is not self._worker:
            self._worker.join()

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        self.shutdown()

    def __copy__(self):
        _reject("background coordinator has one shutdown owner")

    def __deepcopy__(self, memo):
        return self.__copy__()
