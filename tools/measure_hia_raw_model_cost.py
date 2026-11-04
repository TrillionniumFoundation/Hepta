#!/usr/bin/env python3
"""Frozen paired one-shot cost comparison of native exact DP and original NDU.

No Python continuation search is run. Registration fixes every model, slot,
order and analysis rule before timing. The existing release binary is reused.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import gzip
from hashlib import file_digest, sha256
import json
import os
from pathlib import Path
import random
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from hepta.hia_ndu_cost import digest, validate_model
from hepta.hia_ndu_raw_model import UPSTREAM, invoke
from hepta.hia_native_differential import _pin_native_artifact

SCHEMA = "hepta.hia.ndu.raw-model.paired-cost.v1"
ROUNDS = 31
BOOTSTRAPS = 10_000
BOOTSTRAP_SEED = 20261103
MODES = ("exact_dp", "ndu")


def _sha(path):
    with Path(path).open("rb") as stream:
        return file_digest(stream, "sha256").hexdigest()


def _write(path, value):
    with Path(path).open("x", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True, indent=2, allow_nan=False)
        stream.write("\n")


def _git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def cases():
    """Authored fixed model families; no search, learned data or timed outcome."""
    result = []
    for family in ("opportunity", "no-opportunity", "memory-pressure", "invalidation", "abstain", "ties"):
        for horizon in range(1, 5):
            model = {
                "schema": "hepta.hia.ndu.full-cost.v2", "objective_digest": digest("raw-model-cost-v1"), "generation": 1,
                "baseline": {"source_sha256": digest("cost-baseline"), "verification_sha256": digest("cost-base-proof"),
                             "latency_ns": [5_000_000] * horizon},
                "variants": [{"id": name, "source_sha256": digest("cost-" + name),
                    "verification_sha256": digest("cost-proof-" + name), "support_sha256": digest("cost-support-" + name),
                    "status": "verified", "valid": [True] * horizon,
                    "prepare_ns": 100_000, "proof_ns": 80_000, "retire_ns": 20_000,
                    "holding_ns": 10_000, "resident_bytes": 4096, "latency_ns": [latency] * horizon}
                    for name, latency in (("a", 1_000_000), ("b", 2_000_000))],
                "ready": [], "memory_budget_bytes": 8192, "budget_ns": 100_000_000,
                "sunk_cost_ns": 0, "completion_value_ns": 200_000_000,
                "decision": {"gate_ns": 500, "search_ns": 7000, "native_ns": 11_000,
                    "transport_ns": 13_000, "validation_ns": 17_000, "startup_ns": 19_000, "close_ns": 23_000},
                "session_ready": False, "observation_sha256": digest([family, horizon]),
            }
            if family == "no-opportunity":
                model["baseline"]["latency_ns"] = [10_000] * horizon
            elif family == "memory-pressure":
                model["memory_budget_bytes"] = 4096
                model["ready"] = ["b"]
                model["session_ready"] = True
                model["variants"][0]["latency_ns"] = [100_000 if i % 2 == 0 else 4_000_000 for i in range(horizon)]
                model["variants"][1]["latency_ns"] = [4_000_000 if i % 2 == 0 else 100_000 for i in range(horizon)]
            elif family == "invalidation":
                model["ready"] = ["a", "b"]
                model["session_ready"] = True
                model["variants"][0]["valid"] = [i % 2 == 0 for i in range(horizon)]
                model["variants"][1]["status"] = "rejected"
            elif family == "abstain":
                model["completion_value_ns"] = 0
                model["budget_ns"] = 500_000
            elif family == "ties":
                model["decision"] = dict.fromkeys(model["decision"], 0)
                model["baseline"]["latency_ns"] = [1_000_000] * horizon
                for variant in model["variants"]:
                    variant.update(prepare_ns=0, proof_ns=0, retire_ns=0, holding_ns=0,
                                   latency_ns=[1_000_000] * horizon)
            model = validate_model(model)
            result.append({"id": f"{family}-h{horizon}", "model": model, "model_sha256": digest(model)})
    return result


def schedule(case_rows):
    rows = []
    for round_id in range(ROUNDS):
        for case_index, case in enumerate(case_rows):
            modes = MODES if (round_id + case_index) % 2 == 0 else MODES[::-1]
            for mode in modes:
                rows.append({"slot": len(rows), "round": round_id, "case_id": case["id"], "mode": mode})
    return rows


def source_inventory():
    names = ["tools/measure_hia_raw_model_cost.py", "hepta/hia_ndu_raw_model.py", "hepta/hia_ndu_cost.py",
             "hepta/hia_ndu.py", "hepta/hia_native_differential.py",
             "tools/build_hia_ndu_bridge.py", "tools/build_hia_raw_model_bridge.py"]
    paths = [ROOT / name for name in names]
    paths += [p for p in (ROOT / "rust/hia-ndu-raw-model").rglob("*") if p.is_file()]
    return {str(p.relative_to(ROOT)): _sha(p) for p in sorted(paths)}


def build_cost_observation(manifest, receipt_path=None):
    """Accept an observed successful build cost, keeping old receipts unknown.

    A present but malformed measurement refuses registration; it cannot become
    a zero cost or silently lose its failed-build status. When a receipt path
    is supplied, both original compiler streams must still match that receipt.
    """
    cost = manifest.get("build_cost")
    if cost is None:
        return {"wall_ns": None, "status": "inherited release receipt lacks complete timing; no rebuild in this study",
                "scope": None}
    command = manifest.get("build_command_evidence")
    if (type(cost) is not dict or cost.get("schema") != "hepta.hia.ndu.build-cost.v1"
            or cost.get("completed") is not True or type(cost.get("wall_ns")) is not int
            or cost["wall_ns"] <= 0 or type(cost.get("cargo_wall_ns")) is not int
            or not 0 < cost["cargo_wall_ns"] <= cost["wall_ns"]
            or type(cost.get("parent_cpu_ns")) is not int or cost["parent_cpu_ns"] < 0
            or (cost.get("child_cpu_ns") is not None and
                (type(cost["child_cpu_ns"]) is not int or cost["child_cpu_ns"] < 0))
            or type(cost.get("scope")) is not str or not cost["scope"]
            or cost.get("fully_cold_machine_claim") is not False
            or type(command) is not dict or command.get("schema") != "hepta.hia.ndu.build-command.v1"
            or type(command.get("returncode")) is not int or command["returncode"] != 0
            or command.get("launch_error") is not None
            or command.get("original_streams_retained") is not True
            or type(command.get("wall_ns")) is not int or command["wall_ns"] != cost["cargo_wall_ns"]
            or type(command.get("argv")) is not list or not command["argv"]
            or any(type(arg) is not str for arg in command["argv"])
            or command.get("argv") != manifest.get("build_command")):
        raise ValueError("invalid or unsuccessful recorded native build cost")
    for name in ("stdout", "stderr"):
        row = command.get(name)
        if (type(row) is not dict or row.get("path") != "command-evidence/cargo." + name
                or type(row.get("bytes")) is not int or row["bytes"] < 0
                or type(row.get("sha256")) is not str or len(row["sha256"]) != 64
                or any(c not in "0123456789abcdef" for c in row["sha256"])):
            raise ValueError("invalid recorded compiler stream identity")
        if receipt_path is not None:
            root = Path(receipt_path).resolve(strict=True).parent
            path = root / row["path"]
            if (path.is_symlink() or not path.resolve(strict=True).is_relative_to(root)
                    or path.stat().st_size != row["bytes"] or _sha(path) != row["sha256"]):
                raise ValueError("recorded compiler stream changed")
    return {"wall_ns": cost["wall_ns"], "status": "observed successful source-preserving build; compiler stream identities retained",
            "scope": cost["scope"]}


def amortization(build_wall_ns, totals):
    counts = [1, 10, 100, 1000]
    return {"common_build_symbol": "B (unknown)" if build_wall_ns is None else "B (observed build wall time)",
            "common_build_wall_ns": build_wall_ns,
            "formula": "per call = B/N + measured mean call; same existing build for both modes; no machine-cold claim",
            "reuse_counts": counts,
            "per_call_ns": {str(n): {mode: None if build_wall_ns is None else
                                     build_wall_ns / n + totals[mode]["mean_ns"] for mode in MODES} for n in counts},
            "standalone_arm_build_plus_calls_ns": {mode: None if build_wall_ns is None else
                                                   build_wall_ns + totals[mode]["sum_ns"] for mode in MODES},
            "scope": "each arm charged the same one-time observed build; application execution and unobserved lifecycle costs remain excluded",
            "machine_cold_claim": False, "persistent_process_claim": False,
            "full_lifecycle_cost_complete": False}


def freeze(args):
    args.output.mkdir(parents=True, exist_ok=False)
    if _git("status", "--porcelain=v1", "--untracked-files=no"):
        raise ValueError("freeze requires unchanged tracked source")
    binary, build = args.binary.resolve(strict=True), args.build.resolve(strict=True)
    manifest = json.loads(build.read_bytes())
    if manifest.get("upstream", {}).get("commit") != UPSTREAM or manifest.get("binary_sha256") != _sha(binary):
        raise ValueError("binary/upstream build binding mismatch")
    if "--release" not in manifest.get("build_command", []):
        raise ValueError("this protocol requires the recorded release build")
    expected_adapter = {str(p.relative_to(ROOT / "rust/hia-ndu-raw-model")): _sha(p)
                        for p in (ROOT / "rust/hia-ndu-raw-model").rglob("*") if p.is_file()}
    if manifest.get("adapter_files") != expected_adapter:
        raise ValueError("adapter source does not match the release build")
    build_cost = build_cost_observation(manifest, build)
    case_rows = cases()
    protocol = {"schema": SCHEMA, "frozen_at_utc": datetime.now(timezone.utc).isoformat(),
        "source_head": _git("rev-parse", "HEAD"), "source_tree": _git("rev-parse", "HEAD^{tree}"),
        "source_files": source_inventory(), "binary": str(binary), "binary_sha256": _sha(binary),
        "build_receipt": str(build), "build_receipt_sha256": _sha(build),
        "cases": case_rows, "schedule": schedule(case_rows), "rounds": ROUNDS,
        "cold_process_identity_probes": 3, "timeout_seconds": 10,
        "analysis": {"primary": "observed wall time around the complete invoke() call; all attempted slots retained",
            "secondary": "native search, request construction, evaluation and pre-output service clocks",
            "order": "fixed case order; exact_dp then ndu iff (round + case_index) is even",
            "bootstrap": "paired round-block resampling, ratio of total end-to-end times, percentile 2.5/97.5",
            "bootstrap_samples": BOOTSTRAPS, "bootstrap_seed": BOOTSTRAP_SEED,
            "positive_gate": "all slots successful, same complete bundle/winner/action, observed NDU/DP ratio <1 and bootstrap upper <1",
            "outlier_removal": False, "early_stopping": False, "rerun_failed_slots": False},
        "cost_scope": {"each_call": "request validation, source/build reading, hashing, sealed-image preparation, process launch/exit, native work, output parsing and witness replay",
            "cold_start": "each measurement uses a fresh process; OS page cache and parent Python process are not cold",
            "identity_probe": "sealed --identity spawn-to-exit roundtrip, not pure OS startup latency",
            "build_wall_ns": build_cost["wall_ns"], "build_cost_status": build_cost["status"],
            "build_scope": build_cost["scope"],
            "amortization": "same existing binary and build are shared; common build B contributes B/N to either mode; missing B remains unknown",
            "excluded": "imports, acquisition work outside the recorded build, actual optimized-program execution and unknown lifetime costs"},
        "claims": {"global_program_optimality": False, "production_activation_allowed": False, "safety_certificate": False}}
    _write(args.output / "REGISTRATION.json", protocol)
    print(json.dumps({"registration": str(args.output / "REGISTRATION.json"), "sha256": _sha(args.output / "REGISTRATION.json"),
                      "cases": len(case_rows), "paired_blocks": len(case_rows) * ROUNDS,
                      "planned_calls": len(protocol["schedule"])}, indent=2))


def _quantile(values, q):
    values = sorted(values)
    position = (len(values) - 1) * q
    low = int(position)
    high = min(low + 1, len(values) - 1)
    return values[low] + (position - low) * (values[high] - values[low])


def _summary(values):
    return {"count": len(values), "sum_ns": sum(values), "mean_ns": statistics.mean(values),
            "median_ns": statistics.median(values), "p95_ns": _quantile(values, .95), "maximum_ns": max(values)}


def analyze(protocol, observations):
    expected = protocol["schedule"]
    if len(observations) != len(expected) or any({k: o[k] for k in ("slot", "round", "case_id", "mode")} != e
                                               for o, e in zip(observations, expected)):
        raise ValueError("incomplete, reordered or substituted schedule")
    pairs = {}
    for row in observations:
        pairs.setdefault((row["round"], row["case_id"]), {})[row["mode"]] = row
    identical = all(all(p[m]["status"] == "success" for m in MODES)
                    and all(p["exact_dp"][k] == p["ndu"][k] for k in ("bundle_sha256", "winner_ids", "first_action_sha256"))
                    for p in pairs.values())
    totals = {mode: _summary([o["outer_observed_ns"] for o in observations if o["mode"] == mode]) for mode in MODES}
    rounds = [(sum(o["outer_observed_ns"] for o in observations if o["round"] == r and o["mode"] == "exact_dp"),
               sum(o["outer_observed_ns"] for o in observations if o["round"] == r and o["mode"] == "ndu")) for r in range(protocol["rounds"])]
    rng = random.Random(protocol["analysis"]["bootstrap_seed"])
    ratios = []
    for _ in range(protocol["analysis"]["bootstrap_samples"]):
        selected = [rounds[rng.randrange(len(rounds))] for _ in rounds]
        ratios.append(sum(r[1] for r in selected) / sum(r[0] for r in selected))
    ratio = totals["ndu"]["sum_ns"] / totals["exact_dp"]["sum_ns"]
    interval = [_quantile(ratios, .025), _quantile(ratios, .975)]
    stage = {}
    for mode in MODES:
        good = [o for o in observations if o["mode"] == mode and o["status"] == "success"]
        stage[mode] = {key: _summary([o["native_measured"][key] for o in good])
                       for key in ("search_ns", "request_construction_ns", "evaluation_ns", "service_before_output_ns")} if good else {}
    return {"attempted_calls": len(observations), "successful_calls": sum(o["status"] == "success" for o in observations),
        "failed_calls": sum(o["status"] != "success" for o in observations), "pairs": len(pairs),
        "all_paired_decisions_and_witnesses_equal": identical, "additional_decision_quality_observed": False if identical else None,
        "end_to_end": totals, "native_stages_successful_calls_only": stage,
        "ndu_over_exact_dp_cost_ratio": ratio, "paired_round_bootstrap_95_ratio_interval": interval,
        "incremental_ndu_mean_call_ns": totals["ndu"]["mean_ns"] - totals["exact_dp"]["mean_ns"],
        "positive_finite_service_cost_gate": identical and ratio < 1 and interval[1] < 1,
        "statistical_scope": "descriptive resampling of 31 consecutive round blocks over these fixed cases; no independent-host or general workload inference",
        "full_lifecycle_advantage_established": False}


def execute(args):
    started = time.monotonic_ns()
    registration = args.output / "REGISTRATION.json"
    registration_digest = _sha(registration)
    protocol = json.loads(registration.read_bytes())
    if protocol["schema"] != SCHEMA or protocol["cases"] != cases() or protocol["schedule"] != schedule(cases()):
        raise ValueError("registration differs from the fixed protocol")
    if (protocol["rounds"] != ROUNDS or protocol["cold_process_identity_probes"] != 3
            or protocol["timeout_seconds"] != 10
            or protocol["analysis"]["bootstrap_samples"] != BOOTSTRAPS
            or protocol["analysis"]["bootstrap_seed"] != BOOTSTRAP_SEED
            or protocol["analysis"]["outlier_removal"] is not False
            or protocol["analysis"]["early_stopping"] is not False
            or protocol["analysis"]["rerun_failed_slots"] is not False):
        raise ValueError("registered analysis or execution bounds changed")
    if (protocol["source_head"] != _git("rev-parse", "HEAD") or protocol["source_tree"] != _git("rev-parse", "HEAD^{tree}")
            or protocol["source_files"] != source_inventory() or _git("status", "--porcelain=v1", "--untracked-files=no")):
        raise ValueError("source changed after registration")
    binary, build = Path(protocol["binary"]), Path(protocol["build_receipt"])
    if _sha(binary) != protocol["binary_sha256"] or _sha(build) != protocol["build_receipt_sha256"]:
        raise ValueError("native build changed after registration")
    build_cost = build_cost_observation(json.loads(build.read_bytes()), build)
    if (type(protocol["cost_scope"]["build_wall_ns"]) is not type(build_cost["wall_ns"])
            or protocol["cost_scope"]["build_wall_ns"] != build_cost["wall_ns"]
            or protocol["cost_scope"]["build_cost_status"] != build_cost["status"]
            or protocol["cost_scope"]["build_scope"] != build_cost["scope"]):
        raise ValueError("recorded build cost differs from frozen registration")
    observations, probes = [], []
    models = {row["id"]: row["model"] for row in protocol["cases"]}
    raw_path = args.output / "ORIGINAL.jsonl"
    with raw_path.open("x", encoding="utf-8") as log:
        def record(row):
            log.write(json.dumps(row, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n")
            log.flush()
        for i in range(protocol["cold_process_identity_probes"]):
            image, _, fd = _pin_native_artifact(binary)
            try:
                if sha256(image).hexdigest() != protocol["binary_sha256"]:
                    raise ValueError("cold-probe image mismatch")
                before = time.monotonic_ns()
                run = subprocess.run(["/proc/self/fd/" + str(fd), "--identity"], pass_fds=(fd,), capture_output=True,
                                     timeout=protocol["timeout_seconds"], check=False)
                elapsed = time.monotonic_ns() - before
            finally:
                os.close(fd)
            identity = json.loads(run.stdout)
            if run.returncode != 0 or identity.get("upstream_commit") != UPSTREAM or identity.get("authority") != "DENY_ALL":
                raise ValueError("native identity probe failed")
            row = {"event": "cold-process-identity", "index": i, "spawn_to_exit_ns": elapsed,
                   "stdout": run.stdout.decode(), "stderr": run.stderr.decode(), "returncode": run.returncode}
            probes.append(row)
            record(row)
        for slot in protocol["schedule"]:
            record({"event": "call-start", **slot})
            before = time.monotonic_ns()
            try:
                response, receipt = invoke(binary, build, models[slot["case_id"]], mode=slot["mode"],
                                           timeout=protocol["timeout_seconds"])
                elapsed = time.monotonic_ns() - before
                row = {"event": "call-finish", **slot, "status": "success", "outer_observed_ns": elapsed,
                       "invoke_reported_ns": receipt["outer_wall_ns"], "native_measured": response["measured"],
                       "bundle_sha256": digest(response["bundle"]), "winner_ids": response["pareto_candidate_ids"],
                       "first_action_sha256": digest(response["selected_first_action"]), "original": receipt}
            except Exception as error:
                row = {"event": "call-finish", **slot, "status": "failure", "outer_observed_ns": time.monotonic_ns() - before,
                       "error": f"{type(error).__name__}: {error}",
                       "raw_stream_status": "not returned by invoke; failure and complete observed call time retained"}
            observations.append(row)
            record(row)
    result = analyze(protocol, observations)
    unchanged = (protocol["source_files"] == source_inventory() and protocol["source_head"] == _git("rev-parse", "HEAD")
                 and protocol["binary_sha256"] == _sha(binary) and protocol["build_receipt_sha256"] == _sha(build)
                 and registration_digest == _sha(registration)
                 and build_cost == build_cost_observation(json.loads(build.read_bytes()), build))
    raw = raw_path.read_bytes()
    compressed = gzip.compress(raw, mtime=0)
    archive = args.output / "ORIGINAL.jsonl.gz"
    with archive.open("xb") as stream:
        stream.write(compressed)
    result.update({"schema": SCHEMA, "registration_sha256": registration_digest,
        "source_head": protocol["source_head"], "binary_sha256": protocol["binary_sha256"],
        "inputs_unchanged": unchanged, "measurement_complete": unchanged and result["failed_calls"] == 0,
        "cold_process_identity_probes": probes, "build_wall_ns": build_cost["wall_ns"],
        "build_cost_observed": build_cost["wall_ns"] is not None,
        "build_scope": build_cost["scope"],
        "build_cost_status": protocol["cost_scope"]["build_cost_status"],
        "amortization": amortization(build_cost["wall_ns"], result["end_to_end"]),
        "original_records": {"file": archive.name, "bytes": len(raw), "sha256": sha256(raw).hexdigest(),
                             "gzip_sha256": sha256(compressed).hexdigest(), "record_count": len(raw.splitlines())},
        "campaign_wall_before_final_report_ns": time.monotonic_ns() - started,
        "campaign_scope": "registration/source admission, three identity probes, all calls, original-record capture, analysis and compression; excludes final report write/imports/build",
        "authority": "DENY_ALL", "safety_certificate": False, "production_activation_allowed": False})
    _write(args.output / "RESULT.json", result)
    print(json.dumps({key: result[key] for key in ("measurement_complete", "attempted_calls", "failed_calls",
        "all_paired_decisions_and_witnesses_equal", "ndu_over_exact_dp_cost_ratio",
        "paired_round_bootstrap_95_ratio_interval", "incremental_ndu_mean_call_ns", "positive_finite_service_cost_gate")}, indent=2))
    if not result["measurement_complete"]:
        raise SystemExit(1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    registration = sub.add_parser("freeze")
    registration.add_argument("--binary", type=Path, required=True)
    registration.add_argument("--build", type=Path, required=True)
    registration.add_argument("--output", type=Path, required=True)
    run = sub.add_parser("run")
    run.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    freeze(args) if args.command == "freeze" else execute(args)


if __name__ == "__main__":
    main()
