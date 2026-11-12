#!/usr/bin/env python3
"""Execute a real native cancelled prefix, switch, and single-use suffix.

Cancellation is deliberately injected at a known native-call boundary. The
driver actually executes both prefix and suffix; no timing superiority or
external-I/O exactly-once guarantee is inferred from this correctness control.
"""
from __future__ import annotations

import argparse
import ctypes
from hashlib import sha256
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hepta.hia_adaptive import AdaptiveRejected
from hepta.hia_stateful import OwnedAdaptiveRuntime
from tools.qualify_hia_stateful import programs, expected


def qualify(directory, *, clang="clang", cancelled_prefix=6):
    if type(cancelled_prefix) is not int or not 1 <= cancelled_prefix < 40:
        raise ValueError("fixed fixture requires an incomplete prefix of 1..39 updates")
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=False)
    paths = sorted((ROOT / "hepta").glob("*.py")) + [Path(__file__), ROOT / "tools/qualify_hia_stateful.py"]
    sources = {str(path.relative_to(ROOT)): sha256(path.read_bytes()).hexdigest() for path in paths}
    started = time.monotonic_ns()
    base, candidate = programs()
    initial = [11, 17]
    items = [{"slot": 0, "delta": 13, "iterations": 17},
             {"slot": 1, "delta": 7, "iterations": 23}]
    runtime = OwnedAdaptiveRuntime(base, directory / "runtime", initial, clang=clang)
    controls = {}
    try:
        version = runtime.prepare(candidate)
        owner = runtime.snapshot()
        queue = runtime.submit_queue(items)
        original = runtime._apply_items

        def cancel_after_native_prefix(state, work, image):
            remaining = cancelled_prefix
            for item in work:
                count = min(remaining, item.iterations)
                if count:
                    result = runtime._driver.hs_apply(state, item.slot, count, item.delta,
                                                      ctypes.cast(image.function, ctypes.c_void_p))
                    if result != 1:
                        raise ValueError("actual native prefix failed")
                remaining -= count
            runtime._driver.hs_cancel(state)
            return False

        runtime._apply_items = cancel_after_native_prefix
        try:
            prefix = runtime.execute_committed(queue)
        finally:
            runtime._apply_items = original
        controls["actual_cancelled_prefix"] = (prefix["status"] == "cancelled"
            and prefix["executed_steps"] == cancelled_prefix
            and prefix["final_values"] == expected(initial, items, cancelled_prefix))
        switched = runtime.select(version, mode="explicit")
        controls["actual_verified_version_switch"] = switched["selected"]
        child = runtime.continue_queue(queue)
        child_status = runtime.queue_status(child)
        controls["exact_registered_suffix"] = (
            child_status["continuation"]["prior_executed_steps"] == cancelled_prefix
            and child_status["continuation"]["remaining_steps"] == 40-cancelled_prefix)
        for name, action in (("original_replay_refused", lambda: runtime.execute_committed(queue)),
                             ("second_continuation_refused", lambda: runtime.continue_queue(queue))):
            try:
                action()
            except AdaptiveRejected:
                controls[name] = True
            else:
                controls[name] = False
        suffix = runtime.execute_committed(child)
        controls["actual_suffix_and_complete_oracle"] = (
            suffix["status"] == "completed" and suffix["executed_steps"] == 40-cancelled_prefix
            and suffix["final_values"] == expected(initial, items)
            and prefix["executed_steps"] + suffix["executed_steps"] == 40
            and prefix["replayed_steps"] == suffix["replayed_steps"] == 0)
        after = runtime.snapshot()
        controls["same_owner_and_allocation"] = all(owner[key] == after[key]
            for key in ("owner_id", "allocation_identity", "owner_state_schema"))
        counterfactual = runtime.audit_counterfactual(child)
        controls["suffix_counterfactual_agrees"] = counterfactual["final_state_matches"]
        result = {"prefix": prefix, "suffix": suffix, "switched": switched,
                  "counterfactual": counterfactual, "events": after["events"],
                  "driver": runtime._driver_receipt,
                  "builds": {key: value.receipt for key, value in runtime._images.items()}}
    finally:
        runtime.close()
    controls["all_native_resources_released"] = (
        runtime._final_ledger["live"] == 0
        and runtime._final_ledger["allocations"] == runtime._final_ledger["frees"])
    controls["sources_unchanged"] = all(sha256((ROOT/path).read_bytes()).hexdigest() == digest
                                        for path, digest in sources.items())
    result.update(schema="hepta.hia.owned-continuation.qualification.v1",
                  passed=all(controls.values()), controls=controls,
                  final_native_ledger=runtime._final_ledger, source_sha256=sources,
                  elapsed_ns=time.monotonic_ns()-started,
                  cancellation="injected at real native-call boundary after actual registered prefix",
                  cancelled_prefix=cancelled_prefix,
                  performance_advantage_established=False, external_effect_replay_authority=False,
                  crash_recovery_supported=False, safety_certificate=False)
    (directory/"RESULT.json").write_text(json.dumps(result, indent=2, sort_keys=True)+"\n")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workdir", type=Path, required=True)
    parser.add_argument("--clang", default="clang")
    parser.add_argument("--cancelled-prefix", type=int, default=6)
    args = parser.parse_args()
    report = qualify(args.workdir, clang=args.clang, cancelled_prefix=args.cancelled_prefix)
    print(json.dumps({"passed": report["passed"], "controls": report["controls"]}, indent=2))
    raise SystemExit(0 if report["passed"] else 1)
