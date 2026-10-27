"""Actual native empty-state version switching, concurrency and tamper controls."""
from __future__ import annotations

import argparse
import copy
import errno
from hashlib import sha256
import json
import os
from pathlib import Path
import random
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from hepta.hia_adaptive import AdaptiveRejected, AdaptiveRuntime, _load_image


def programs():
    pair = lambda name, typ="u64": {"name": name, "type": typ}
    base = {"schema": "hepta.hia.program.v1", "module": "adaptive_native",
            "functions": [{"name": "calculate", "params": [pair("x"), pair("y")],
                           "returns": ["u64"], "effects": [], "entry": "entry",
                           "blocks": [{"id": "entry", "params": [pair("x"), pair("y")],
                                       "ops": [
                                           {"op": "const", "args": [], "out": [pair("zero")], "attrs": {"value": 0}},
                                           {"op": "int.add.wrap", "args": ["x", "zero"], "out": [pair("a")], "attrs": {}},
                                           {"op": "int.add.wrap", "args": ["a", "y"], "out": [pair("r")], "attrs": {}}],
                                       "term": {"op": "ret", "values": ["r"]}}]}]}
    candidate = copy.deepcopy(base)
    # A genuinely different native implementation under the qualified Clang20
    # build: x+y == (x^y) + 2*(x&y) modulo 2**64. Unlike x+0 -> x|0,
    # this does not collapse to the identical native artifact in that toolchain.
    candidate["functions"][0]["blocks"][0]["ops"] = [
        {"op": "const", "args": [], "out": [pair("two")], "attrs": {"value": 2}},
        {"op": "bit.xor", "args": ["x", "y"], "out": [pair("xor")], "attrs": {}},
        {"op": "bit.and", "args": ["x", "y"], "out": [pair("and")], "attrs": {}},
        {"op": "int.mul.wrap", "args": ["and", "two"], "out": [pair("double")], "attrs": {}},
        {"op": "int.add.wrap", "args": ["xor", "double"], "out": [pair("r")], "attrs": {}}]
    return base, candidate


def qualify(directory, *, clang="clang"):
    work = Path(directory).absolute()
    if work.exists():
        raise ValueError("A new adaptive qualification directory is required")
    work.mkdir(parents=True)
    base, candidate = programs()
    for name, document in (("baseline", base), ("candidate", candidate)):
        (work / (name + ".core.json")).write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    runtime, threads = None, []
    report = {"schema": "hepta.hia.adaptive-native-qualification.v1", "ok": False,
              "scope": "empty-state pure-u64 actual native execution",
              "controls": {}, "automatic_benefit_established": False,
              "automatic_profitable_selection_supported": False,
              "measurement_mode": "conservative_shadow_only",
              "general_live_state_or_owner_migration": False}
    try:
        runtime = AdaptiveRuntime(base, work / "runtime", clang=clang)
        token = runtime.prepare(candidate)
        report["builds"] = {key: image.receipt for key, image in runtime._images.items()}
        report["distinct_native_artifacts"] = (
            runtime._images[token].artifact_sha256 != runtime._images["baseline"].artifact_sha256)
        if not report["distinct_native_artifacts"]:
            raise ValueError("Qualification requires two distinct actual native artifacts")
        snapshots = work / "native-snapshots"
        snapshots.mkdir()
        report["retained_native_artifacts"] = {}
        for name, key in (("baseline", "baseline"), ("candidate", token)):
            image = runtime._images[key]
            actual = os.pread(image.fd, os.fstat(image.fd).st_size, 0)
            if sha256(actual).hexdigest() != image.artifact_sha256:
                raise ValueError("Sealed snapshot no longer matches admitted artifact")
            snapshot_path = snapshots / (name + ".so")
            snapshot_path.write_bytes(actual)
            report["retained_native_artifacts"][name] = {
                "path": str(snapshot_path.relative_to(work)), "sha256": image.artifact_sha256,
                "bytes": len(actual), "origin": "actual sealed descriptor before tamper controls"}
        rng = random.Random(271027)
        vectors = [[0, 0], [2**64 - 1, 1], [2**64 - 1, 2**64 - 1]]
        vectors += [[rng.randrange(2**64), rng.randrange(2**64)] for _ in range(128)]
        expected = [(x + y) % 2**64 for x, y in vectors]
        before = runtime.call_many(vectors)
        if before != expected:
            raise ValueError("Baseline native output disagrees with independent integer oracle")
        report["automatic_without_measurement"] = runtime.select(token)
        if report["automatic_without_measurement"]["selected"]:
            raise ValueError("A producer candidate acquired automatic authority without measured costs")
        report["explicit_selection"] = runtime.select(token, mode="explicit")
        if not report["explicit_selection"]["selected"]:
            raise ValueError("Safe explicit version selection failed")
        after = runtime.call_many(vectors)
        if after != expected:
            raise ValueError("Selected native output disagrees with independent integer oracle")
        report["native_pairs"] = len(vectors)
        report["native_values"] = after

        # A public evidence dictionary is not a prepared in-process version.
        try:
            runtime.select({"status": "verified", "benefit": 2**63}, mode="explicit")
        except AdaptiveRejected:
            report["controls"]["producer_receipt_not_authority"] = True
        else:
            raise ValueError("Forged producer receipt was accepted")
        bad = copy.deepcopy(candidate)
        bad["functions"][0]["blocks"][0]["ops"][-1]["op"] = "int.sub.wrap"
        current = runtime.snapshot()["current"]
        try:
            runtime.prepare(bad)
        except ValueError:
            report["controls"]["inequivalent_candidate_refused"] = runtime.snapshot()["current"] == current
        else:
            raise ValueError("Inequivalent executable was admitted")

        image = runtime._images[token]
        tampered = work / "changed.so"
        tampered.write_bytes(image.artifact.read_bytes() + b"changed")
        try:
            _load_image(image.program, image.state, tampered, image.receipt, time.monotonic_ns())
        except AdaptiveRejected:
            report["controls"]["tamper_before_load_refused"] = True
        else:
            raise ValueError("Changed native bytes were loaded")
        try:
            os.write(image.fd, b"x")
        except OSError as error:
            if error.errno != errno.EPERM:
                raise
            report["controls"]["actual_memfd_seal_rejects_write"] = True
        else:
            raise ValueError("Loaded native snapshot was writable")
        image.artifact.write_bytes(b"not the loaded artifact")
        if runtime.call(2**64 - 1, 2) != 1:
            raise ValueError("Publication path mutation changed sealed native execution")
        report["controls"]["path_tamper_after_load_does_not_rebind"] = True

        barrier = threading.Barrier(5)
        worker_results, errors = [], []
        def worker(number):
            try:
                barrier.wait(timeout=10)
                observed = runtime.call_many([[number, 13]] * 65536)
                worker_results.append({"worker": number, "calls": len(observed),
                                       "correct": all(value == number + 13 for value in observed)})
            except Exception as error:
                errors.append(repr(error))
        for index in range(4):
            thread = threading.Thread(target=worker, args=(index,))
            threads.append(thread); thread.start()
        barrier.wait(timeout=10)
        deadline = time.monotonic() + 10
        while runtime.snapshot()["active_calls"] == 0:
            if time.monotonic() >= deadline:
                raise ValueError("Real native worker never entered dispatcher")
            time.sleep(0.001)
        report["during_active_calls"] = runtime.select("baseline", mode="explicit")
        if report["during_active_calls"]["selected"]:
            raise ValueError("Selected a new version with real native calls active")
        try:
            runtime.close()
        except AdaptiveRejected:
            report["controls"]["active_close_refused"] = True
        else:
            raise ValueError("Closed a live native library")
        for thread in threads:
            thread.join(timeout=20)
        if any(thread.is_alive() for thread in threads) or errors or len(worker_results) != 4:
            raise ValueError("Native worker completion failed: " + repr(errors))
        if not all(row["correct"] for row in worker_results):
            raise ValueError("Concurrent native result mismatch")
        report["concurrent_workers"] = sorted(worker_results, key=lambda row: row["worker"])
        report["return_to_baseline"] = runtime.select("baseline", mode="explicit")
        if not report["return_to_baseline"]["selected"]:
            raise ValueError("Quiescent explicit return to original version failed")

        report["measurement"] = runtime.measure(token, vectors)
        # Changing the returned copy must not authorize a version selection.
        report["measurement"]["net_before_switch_ns"] = 2**63
        if runtime._measurements[token]["net_before_switch_ns"] == 2**63:
            raise ValueError("The returned telemetry dictionary aliases internal measurements")
        report["automatic_after_measuring"] = runtime.select(token)
        if report["automatic_after_measuring"]["selected"]:
            raise ValueError("Externally changed telemetry authorized automatic selection")
        report["controls"]["telemetry_copy_not_authority"] = True
        report["measurement"] = copy.deepcopy(runtime._measurements[token])
        runtime.measure(token, vectors[:8], expires_after_ns=0)
        report["expired_evidence"] = runtime.select(token)
        if report["expired_evidence"]["selected"]:
            raise ValueError("Expired internal measurements were accepted")
        report["controls"]["expired_measurement_refused"] = True
        report["final"] = runtime.snapshot()
        report["ok"] = all(report["controls"].values())
    except Exception as error:
        report["error"] = {"kind": type(error).__name__, "message": str(error)}
    finally:
        for thread in threads:
            thread.join(timeout=20)
        if runtime is not None:
            report["final"] = runtime.snapshot()
            runtime.close()
    (work / "qualification.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workdir", required=True)
    parser.add_argument("--clang", default="clang")
    args = parser.parse_args()
    report = qualify(args.workdir, clang=args.clang)
    print(json.dumps({"ok": report["ok"], "controls": report["controls"], "error": report.get("error"),
                      "native_pairs": report.get("native_pairs"),
                      "concurrent_workers": report.get("concurrent_workers")}))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
