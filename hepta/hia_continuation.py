"""Single-use continuation of a cancelled, quiescent owned-state queue.

The original queue never executes again. Its observed committed prefix is
removed from an internally registered suffix. This is a live-process scalar
state contract; no external-effect replay or durable crash recovery is inferred.
"""
from __future__ import annotations

from dataclasses import replace
import secrets
import time

from .hia_adaptive import AdaptiveRejected, _digest


def continue_owned_queue(runtime, token):
    started = time.monotonic_ns()
    with runtime._lock:
        runtime._state_open()
        try:
            if type(token) is not str:
                raise AdaptiveRejected("E_STATE_CONTINUATION: internal queue token required")
            row = runtime._queues.get(token)
            if row is None or row["status"] != "cancelled" or "continued_by" in row:
                raise AdaptiveRejected("E_STATE_CONTINUATION: only a cancelled, unclaimed queue may continue")
            if runtime._active or runtime._loans:
                raise AdaptiveRejected("E_STATE_BUSY: continuation requires no native call or live loan")
            if row["generation"] != runtime._generation:
                raise AdaptiveRejected("E_STATE_FENCE: cancelled queue belongs to a stale owner generation")
            if len(runtime._queues) >= 32 or any(
                    other["status"] in {"submitted", "running"} for other in runtime._queues.values()):
                raise AdaptiveRejected("E_STATE_QUEUE: one pending queue and 32 retained queues maximum")
            receipt = row["receipt"]
            progress = receipt["executed_steps"] if receipt is not None else 0
            total = sum(item.iterations for item in row["items"])
            if type(progress) is not int or not 0 <= progress < total:
                raise AdaptiveRejected("E_STATE_CONTINUATION: a known incomplete native prefix is required")
            values = runtime._values()
            expected_values = tuple(receipt["final_values"]) if receipt is not None else row["initial_values"]
            if (row["owner"] != runtime._owner_id or runtime._revision != row["revision"] + progress
                    or values != expected_values
                    or int(runtime._driver.hs_identity(runtime._state)) != runtime._allocation_address):
                raise AdaptiveRejected("E_STATE_STALE: owner changed after cancellation")
            remaining, prefix = [], progress
            for item in row["items"]:
                committed = min(prefix, item.iterations)
                prefix -= committed
                if committed < item.iterations:
                    remaining.append(replace(item, iterations=item.iterations - committed))
            frozen = tuple(remaining)
            child = secrets.token_hex(16)
            if child in runtime._queues:
                raise AdaptiveRejected("E_STATE_CONTINUATION: queue identity collision")
            ancestry = row.get("continuation", {})
            continuation = {
                "parent_queue": token, "parent_queue_sha256": row["sha256"],
                "root_queue": ancestry.get("root_queue", token),
                "root_queue_sha256": ancestry.get("root_queue_sha256", row["sha256"]),
                "prior_executed_steps": ancestry.get("prior_executed_steps", 0) + progress,
                "parent_executed_steps": progress,
                "remaining_steps": total - progress,
                "same_live_owner": True, "external_effect_replay_authority": False,
            }
            registered = {
                "items": frozen, "sha256": _digest([
                    {"slot": item.slot, "delta": item.delta, "iterations": item.iterations} for item in frozen]),
                "status": "submitted", "revision": runtime._revision,
                "generation": runtime._generation,
                "owner": runtime._owner_id, "initial_values": values, "receipt": None,
                "continuation": continuation,
            }
            events_before = (runtime._event_count, runtime._event_counts.copy(), runtime._events.copy())
            # No native work occurs during registration. Roll back both sides
            # under the lock if any publication step fails. A later failure to
            # return leaves the complete relation discoverable via queue_status.
            try:
                runtime._queues[child] = registered
                row["continued_by"] = child
                runtime._event("state_queue_continued", parent=token, child=child,
                               committed_prefix=progress, remaining_steps=total-progress)
            except BaseException:
                runtime._queues.pop(child, None)
                row.pop("continued_by", None)
                runtime._event_count, runtime._event_counts, runtime._events = events_before
                raise
            return child
        finally:
            runtime._unamortized_preparation_ns += time.monotonic_ns() - started
