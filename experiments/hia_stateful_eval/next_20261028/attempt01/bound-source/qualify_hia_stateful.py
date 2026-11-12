"""Native owned-state adaptation; queue forecasts and full deployment costs.

Counterfactual baseline replay uses a separate owner and is charged as explicit
experiment overhead. No general heap migration or external transaction claim.
"""
from __future__ import annotations

import argparse
import copy
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from hepta.hia_adaptive import AdaptiveRejected
from hepta.hia_stateful import OwnedAdaptiveRuntime


def programs():
    pair = lambda name: {"name": name, "type": "u64"}
    def function(name, ops, result):
        return {"name": name, "params": [pair("x"), pair("y")], "returns": ["u64"],
                "effects": [], "entry": "entry", "blocks": [{"id": "entry", "params": [pair("x"), pair("y")],
                "ops": ops, "term": {"op": "ret", "values": [result]}}]}
    def op(name, arguments, output, attrs=None):
        return {"op": name, "args": arguments, "out": [pair(output)], "attrs": attrs or {}}
    helper = function("add_step", [
        op("const", [], "two", {"value": 2}), op("bit.xor", ["x", "y"], "xor"),
        op("bit.and", ["x", "y"], "and"), op("int.mul.wrap", ["and", "two"], "double"),
        op("int.add.wrap", ["xor", "double"], "r")], "r")
    entry = function("transition", [op("call", [before, "y"], after, {"function": "add_step"})
                                     for before, after in (("x", "a"), ("a", "b"), ("b", "c"), ("c", "r"))], "r")
    base = {"schema": "hepta.hia.program.v1", "module": "stateful_native", "functions": [helper, entry]}
    candidate = copy.deepcopy(base)
    candidate["functions"][0]["blocks"][0]["ops"] = [op("int.add.wrap", ["x", "y"], "r")]
    return base, candidate


def expected(values, items, progress=None):
    result = list(values)
    remaining = sum(item["iterations"] for item in items) if progress is None else progress
    for item in items:
        count = min(remaining, item["iterations"])
        result[item["slot"]] = (result[item["slot"]] + 4 * item["delta"] * count) % 2**64
        remaining -= count
    if remaining:
        raise ValueError("Native progress exceeds the internally committed queue")
    return result


def _require(value, message):
    if not value:
        raise ValueError(message)


def qualify(directory, *, clang="clang", performance_steps=0):
    work = Path(directory).absolute()
    if work.exists():
        raise ValueError("A new stateful qualification directory is required")
    work.mkdir(parents=True)
    base, candidate = programs()
    for name, document in (("baseline", base), ("candidate", candidate)):
        (work / (name + ".core.json")).write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    report = {"schema": "hepta.hia.owned-state-qualification.v1", "ok": False, "controls": {},
              "profile": "exclusive-u64-array; total scalar transition; live-process committed queue",
              "general_heap_migration": False, "external_or_crash_exactly_once": False,
              "performance": {"status": "not_requested", "guaranteed": False},
              "source_bindings": {str(path.relative_to(ROOT)): sha256(path.read_bytes()).hexdigest()
                                  for path in (ROOT / "hepta/hia_stateful.py", ROOT / "hepta/hia_adaptive.py", Path(__file__))}}
    runtime, thread = None, None
    try:
        initial = [2**64 - 1, 17, 0]
        runtime = OwnedAdaptiveRuntime(base, work / "runtime", initial, clang=clang)
        token = runtime.prepare(candidate)
        report["builds"] = {key: image.receipt for key, image in runtime._images.items()}
        report["driver"] = runtime._driver_receipt
        report["distinct_native_artifacts"] = runtime._images[token].artifact_sha256 != runtime._images["baseline"].artifact_sha256
        _require(report["distinct_native_artifacts"], "Two actually distinct native implementations required")
        snapshots = work / "native-snapshots"; snapshots.mkdir()
        report["native_snapshots"] = {}
        for name, key in (("baseline", "baseline"), ("candidate", token)):
            image = runtime._images[key]
            binary = os.pread(image.fd, os.fstat(image.fd).st_size, 0)
            _require(sha256(binary).hexdigest() == image.artifact_sha256, "Loaded artifact binding changed")
            (snapshots / (name + ".so")).write_bytes(binary)
            report["native_snapshots"][name] = {"sha256": image.artifact_sha256, "bytes": len(binary)}
        before = runtime.snapshot()
        lease = runtime.borrow(mutable=True)
        _require(lease.read(0) == initial[0], "Actual owner read differs")
        lease.write(1, 19); initial[1] = 19
        _require(not runtime.select(token, mode="explicit")["selected"], "Live alias allowed switching")
        try:
            runtime.close()
        except AdaptiveRejected:
            report["controls"]["close_with_live_alias_refused"] = True
        else:
            raise ValueError("Destroyed native owner while alias was live")
        lease.close()
        for access in (lambda: lease.read(0), lambda: lease.write(0, 7)):
            try:
                access()
            except AdaptiveRejected:
                pass
            else:
                raise ValueError("Ended alias retained authority")
        report["controls"]["ended_alias_access_refused"] = True
        switched = runtime.select(token, mode="explicit")
        after = runtime.snapshot()
        _require(switched["selected"] and before["owner_id"] == after["owner_id"]
                 and before["allocation_identity"] == after["allocation_identity"]
                 and after["state_values"] == initial and after["native_ledger"]["live"] == 2,
                 "Actual owner identity/value did not survive version switch")
        report["owner_before"], report["owner_after"] = before, after
        report["controls"]["persistent_owner_survives_actual_switch"] = True
        _require(runtime.select("baseline", mode="explicit")["selected"], "Could not return to base")
        live = runtime._ledger()["live"]
        for fail_at in (1, 2):
            _require(not runtime._driver.hs_new(3, fail_at), "Injected actual allocation refusal accepted")
            _require(runtime._ledger()["live"] == live, "Native partial-allocation refusal leaked")
        report["controls"]["allocation_refusal_cleanup"] = True
        # Producer data is copied before execution; no caller telemetry can
        # authorize selection. A short genuine queue cannot amortize prep.
        items = [{"slot": 0, "delta": 7, "iterations": 9}, {"slot": 1, "delta": 2**64 - 1, "iterations": 7}]
        original_items = copy.deepcopy(items)
        queue = runtime.submit_queue(items)
        items[0]["iterations"] = 1_000_000_000
        negative = runtime.execute_committed(queue, candidate=token, rounds=3, sample_limit=10000)
        _require(not negative["automatic_selection"] and negative["executed_steps"] == 16
                 and negative["final_values"] == expected(initial, original_items), "Negative-gain or immutable queue gate failed")
        report["negative_gain_execution"] = negative
        report["negative_gain_audit"] = runtime.audit_counterfactual(queue)
        try:
            runtime.execute_committed(queue, candidate=token)
        except AdaptiveRejected:
            report["controls"]["completed_queue_replay_refused"] = True
        else:
            raise ValueError("Completed work replayed on application owner")
        current_values = negative["final_values"]
        long_items = [{"slot": 2, "delta": 13, "iterations": 1_000_000_000}]
        pending = runtime.submit_queue(long_items)
        results, errors = [], []
        def worker():
            try:
                results.append(runtime.execute_committed(pending))
            except BaseException as error:
                errors.append(repr(error))
        thread = threading.Thread(target=worker); thread.start()
        deadline = time.monotonic() + 10
        while True:
            snapshot = runtime.snapshot()
            if snapshot["active_calls"] and snapshot["actual_progress"] >= 10000:
                break
            if time.monotonic() >= deadline:
                raise ValueError("Actual native queue never exposed positive progress")
            time.sleep(0.001)
        _require(not runtime.select(token, mode="explicit")["selected"], "Mid-call switch accepted")
        for action in (runtime.close, runtime.borrow, lambda: runtime.execute_committed(pending)):
            try:
                action()
            except AdaptiveRejected:
                pass
            else:
                raise ValueError("Active native owner boundary accepted unsafe action")
        runtime.cancel(pending)
        thread.join(timeout=15)
        _require(not thread.is_alive() and not errors and len(results) == 1, "Native cancellation did not terminate")
        partial = results[0]
        _require(partial["status"] == "cancelled" and 0 < partial["executed_steps"] < 1_000_000_000
                 and partial["final_values"] == expected(current_values, long_items, partial["executed_steps"]),
                 "Partial native mutation lost exact commit prefix")
        try:
            runtime.execute_committed(pending)
        except AdaptiveRejected:
            report["controls"]["partial_cancelled_queue_replay_refused"] = True
        else:
            raise ValueError("Partly committed application work replayed")
        report["partial_execution"] = partial
        report["controls"]["active_call_switch_close_and_borrow_refused"] = True
        _require(runtime.snapshot()["native_ledger"]["live"] == 2, "Auxiliary state owners leaked")
        if performance_steps:
            if type(performance_steps) is not int or not 1 <= performance_steps <= 1_000_000_000:
                raise ValueError("Bounded explicit performance queue required")
            # Fresh runtime includes baseline + driver + candidate preparation
            # in this queue's cost, without prior correctness queues amortizing it.
            perf = OwnedAdaptiveRuntime(base, work / "performance-runtime", [29, 31], clang=clang)
            try:
                candidate_token = perf.prepare(candidate)
                work_items = [{"slot": 0, "delta": 0xD7A192456BBEFE51, "iterations": performance_steps}]
                performance_queue = perf.submit_queue(work_items)
                execution = perf.execute_committed(performance_queue, candidate=candidate_token,
                                                   rounds=5, sample_limit=500000)
                audit = perf.audit_counterfactual(performance_queue)
                _require(execution["final_values"] == expected([29, 31], work_items), "Performance state oracle failed")
                report["performance"] = {"status": "actual_native_measured", "guaranteed": False,
                                         "execution": execution, "counterfactual_audit": audit,
                                         "automatic_selected": execution["automatic_selection"],
                                         "deployment_net_positive": audit["measured_deployment_net_ns"] > 0,
                                         "experiment_total_includes_baseline_audit": True,
                                         "performance_not_generalized_beyond_this_queue": True}
            finally:
                perf.close()
                report["performance"]["final_native_ledger"] = perf._final_ledger
        runtime.close()
        report["final_native_ledger"] = runtime._final_ledger
        _require(runtime._final_ledger["live"] == 0 and runtime._final_ledger["allocations"] == runtime._final_ledger["frees"],
                 "Final native owners were not released exactly once")
        report["ok"] = all(report["controls"].values())
    except BaseException as error:
        report["error"] = {"kind": type(error).__name__, "message": str(error)}
    finally:
        if thread is not None and thread.is_alive():
            try:
                runtime.cancel(pending)
            except Exception:
                pass
            thread.join(timeout=15)
        if runtime is not None:
            try:
                runtime.close()
            except Exception as error:
                report["close_error"] = repr(error)
                report["ok"] = False
    (work / "qualification.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workdir", required=True)
    parser.add_argument("--clang", default="clang")
    parser.add_argument("--performance-steps", type=int, default=0)
    args = parser.parse_args()
    report = qualify(args.workdir, clang=args.clang, performance_steps=args.performance_steps)
    print(json.dumps({"ok": report["ok"], "controls": report["controls"], "error": report.get("error"),
                      "performance": report["performance"]}))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
