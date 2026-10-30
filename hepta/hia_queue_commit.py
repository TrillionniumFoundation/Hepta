"""Exception-safe activation and irrevocable cost settlement for owned queues.

Native progress is never rolled back. Diagnostics can fail after real work, but
cannot erase its resource state or known costs. An unexpected failure to obtain
complete progress/cost evidence poisons further execution while leaving close
available to release the live owner.
"""
from __future__ import annotations

import json
import time

from .hia_adaptive import AdaptiveRejected


def execute_owned_queue(self, token, *, candidate=None, rounds=5, sample_limit=200000):
    preparation_started = time.monotonic_ns()
    start_snapshot = None
    application_started = False
    execution_started = None
    error = None
    complete = False
    receipt = None
    try:
        with self._lock:
            self._state_open()
            row = self._queues.get(token)
            if row is None or row["status"] != "submitted":
                raise AdaptiveRejected("E_STATE_REPLAY: only a registered unexecuted queue may run")
            if self._active or self._loans:
                raise AdaptiveRejected("E_STATE_BUSY: native calls or aliases prevent queue execution")
            if row["revision"] != self._revision or row["owner"] != self._owner_id:
                row["status"] = "stale"
                raise AdaptiveRejected("E_STATE_STALE: owner changed since work was committed")
            candidate_cost = self._unamortized_preparation_ns
            original, measurement, selected, reason = self._plan_queue(
                row, candidate, rounds=rounds, sample_limit=sample_limit,
                preparation_started=preparation_started, candidate_cost=candidate_cost)
            active_before = self._active
            start_snapshot = (self._event_count, self._event_counts.copy(), self._events.copy())
            try:
                self._driver.hs_reset(self._state)
                image = self._images[self._current]
                self._event("state_queue_started", token=token, steps=sum(item.iterations for item in row["items"]),
                            selected=selected, reason=reason)
                queue_overhead = time.monotonic_ns() - preparation_started
                row["version"] = self._current
                row["status"] = "running"
                self._unamortized_preparation_ns = 0
                self._active += 1
                execution_started = time.monotonic_ns()
                # Commit activation while still holding the same lock. Later
                # concurrent prepares retain their own new cost debt/events;
                # a post-lock interruption settles a known zero native prefix.
                application_started = True
            except BaseException:
                self._active = active_before
                row["status"] = "submitted"
                row.pop("version", None)
                self._event_count, self._event_counts, self._events = start_snapshot
                self._unamortized_preparation_ns = candidate_cost
                try:
                    self._unamortized_preparation_ns += time.monotonic_ns() - preparation_started
                except BaseException:
                    self._state_poisoned = True
                    self._cost_accounting_complete = False
                finally:
                    # Startup rollback completed under the lock, so another
                    # prepare can now publish without its debt being erased.
                    start_snapshot = None
                raise
        # The outer try also covers lock exit and the first actual native call.
        complete = self._apply_items(self._state, row["items"], image)
    except BaseException as caught:
        error = caught
    finally:
        if start_snapshot is not None:
            with self._lock:
                # The synchronous native call has returned (or never began).
                # Release activity before any fallible clock or diagnostic.
                self._active = active_before
                if not application_started:
                    row["status"] = "submitted"
                    row.pop("version", None)
                    self._event_count, self._event_counts, self._events = start_snapshot
                    self._unamortized_preparation_ns = candidate_cost
                    try:
                        self._unamortized_preparation_ns += time.monotonic_ns() - preparation_started
                    except BaseException as caught:
                        self._state_poisoned = True
                        self._cost_accounting_complete = False
                        if error is None:
                            error = caught
                else:
                    charged = False
                    try:
                        execution_ns = time.monotonic_ns() - execution_started
                        finalization_started = time.monotonic_ns()
                        progress = int(self._driver.hs_progress(self._state))
                        committed_steps = sum(item.iterations for item in row["items"])
                        if not 0 <= progress <= committed_steps:
                            raise AdaptiveRejected("E_STATE_PROGRESS: native progress exceeds the registered queue")
                        self._revision += progress
                        self._calls += progress
                        row["status"] = "failed" if error else "completed" if complete else "cancelled"
                        remaining = progress
                        item_observations = []
                        for index, item in enumerate(row["items"]):
                            committed = min(remaining, item.iterations)
                            item_observations.append({"item": index, "requested": item.iterations,
                                                      "committed": committed, "replayed": 0})
                            remaining -= committed
                        deployment = candidate_cost + queue_overhead + execution_ns
                        receipt = {"schema": "hepta.hia.owned-queue-execution.v1", "queue": token,
                            "continuation": row.get("continuation"),
                            "queue_sha256": row["sha256"], "status": row["status"], "version": row["version"],
                            "original_version": original, "automatic_selection": selected,
                            "selection_reason": reason, "measurement": measurement,
                            "committed_steps": committed_steps, "executed_steps": progress, "replayed_steps": 0,
                            "item_progress": item_observations,
                            "unamortized_preparation_ns": candidate_cost,
                            "preparation_includes_initial_baseline_driver_and_all_prepare_attempts": True,
                            "calibration_verification_switch_ns": queue_overhead,
                            "application_execution_ns": execution_ns, "deployment_cost_ns": deployment,
                            "observed_net_against_baseline_forecast_ns":
                                measurement["baseline_estimate_ns"] - deployment if measurement else None,
                            "forecast_is_guaranteed": False, "owner_id": self._owner_id,
                            "allocation_identity": self._allocation_identity,
                            "final_values": list(self._values()), "native_ledger": self._ledger(),
                            "error": repr(error) if error else None, "diagnostic_errors": [],
                            "cost_accounting_complete": True}
                        row["receipt"] = receipt
                        try:
                            self._event("state_queue_finished", token=token, status=row["status"], progress=progress,
                                        selected=selected, replayed_steps=0)
                        except BaseException as caught:
                            receipt["diagnostic_errors"].append(repr(caught))
                            if error is None:
                                error = caught
                        finalization_ns = time.monotonic_ns() - finalization_started
                        receipt["commit_bookkeeping_ns"] = finalization_ns
                        receipt["deployment_cost_ns"] += finalization_ns
                        if measurement:
                            receipt["observed_net_against_baseline_forecast_ns"] -= finalization_ns
                        if selected and receipt["observed_net_against_baseline_forecast_ns"] <= 0:
                            restore_started = time.monotonic_ns()
                            try:
                                restoration = self._restore_admitted(original)
                                receipt["restored_after_forecast_loss"] = restoration["selected"]
                            except BaseException as caught:
                                receipt["restored_after_forecast_loss"] = self._current == original
                                receipt["diagnostic_errors"].append(repr(caught))
                                if error is None:
                                    error = caught
                            finally:
                                receipt["restoration_cost_ns"] = time.monotonic_ns() - restore_started
                                receipt["deployment_cost_ns"] += receipt["restoration_cost_ns"]
                                receipt["observed_net_against_baseline_forecast_ns"] -= receipt["restoration_cost_ns"]
                        self._cumulative_deployment_cost_ns += receipt["deployment_cost_ns"]
                        charged = True
                        receipt["cumulative_deployment_cost_ns"] = self._cumulative_deployment_cost_ns
                    except BaseException as caught:
                        # Complete accounting/progress is now unavailable. Do
                        # not silently continue or claim an economic advantage.
                        self._state_poisoned = True
                        self._cost_accounting_complete = False
                        row["status"] = "failed"
                        if receipt is not None:
                            receipt["status"] = "failed"
                            receipt["cost_accounting_complete"] = False
                            receipt["finalization_error"] = repr(caught)
                            if not charged:
                                self._cumulative_deployment_cost_ns += receipt["deployment_cost_ns"]
                            receipt["cumulative_deployment_cost_ns"] = self._cumulative_deployment_cost_ns
                        if error is None:
                            error = caught
    if error is not None:
        raise error
    return json.loads(json.dumps(receipt))
