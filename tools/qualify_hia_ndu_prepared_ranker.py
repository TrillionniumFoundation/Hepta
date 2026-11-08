#!/usr/bin/env python3
"""Freeze then execute a bounded original-native ranking transport experiment.

The three registered arms are one-shot NDU, prepared-image NDU and an exact
ordinary enumerator for this supplied one-axis finite model. Preparation and
close are inside each cell's measured interval. This does not measure task
delivery, learning, a macro Agent lifecycle or economic NDU benefit.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
from hashlib import sha256
import itertools
import json
import platform
from pathlib import Path
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from hepta.hia_ndu_optimizer import _bridge_identity, _bytes, _native_rank
from hepta.hia_ndu_prepared_ranker import PreparedNduRanker, PROFILE
from hepta.hia_ndu_scalar_selection import resolve_scalar_selection

ARMS = ("one_shot_ndu", "prepared_ndu", "ordinary_scalar")
HORIZONS = (1, 4, 16, 64)
ORDERS = tuple(itertools.permutations(ARMS))
MAX_WALL_NS = 120_000_000_000
PER_CALL_TIMEOUT_S = 1.0
SOURCE_PATHS = (
    "hepta/hia_ndu_prepared_ranker.py",
    "hepta/hia_ndu_optimizer.py",
    "hepta/hia_ndu_scalar_selection.py",
    "hepta/hia_rust_crosscheck.py",
    "tools/build_hia_ndu_bridge.py",
    "tools/qualify_hia_ndu_prepared_ranker.py",
)


def _write(path, value):
    with path.open("xb") as stream:
        stream.write(json.dumps(value, sort_keys=True, indent=2, allow_nan=False).encode() + b"\n")


def _utc():
    return datetime.now(timezone.utc).isoformat()


def _source_files():
    paths = set(SOURCE_PATHS)
    paths.update(str(path.relative_to(ROOT)) for path in
                 (ROOT / "rust/hia-ndu-bridge").rglob("*") if path.is_file())
    return {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in sorted(paths)}


def _git():
    def command(*args):
        return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()
    return {"head": command("rev-parse", "HEAD"),
            "status": command("status", "--porcelain=v1", "--untracked-files=no")}


def requests():
    """All inputs disclosed before native execution; no measured future values."""
    result = []
    for index in range(max(HORIZONS)):
        count = (2, 8, 32)[index % 3]
        rows = [{"id": "abstain", "cost_q32": 100 + index,
                 "uncertainty_q32": 0, "resource_q32": 0,
                 "hard_violation": False, "support_sha256": sha256(b"incumbent").hexdigest()}]
        for candidate in range(1, count):
            rows.append({"id": "candidate%03d" % candidate,
                         "cost_q32": 10 + ((index * 13 + candidate * 7) % 97),
                         "uncertainty_q32": candidate % 3,
                         "resource_q32": (candidate % 7) * 1_000_000,
                         "hard_violation": candidate % 5 == 0,
                         "support_sha256": sha256((str(index) + ":" + str(candidate)).encode()).hexdigest()})
        if index % 4 == 0:
            rows[0]["cost_q32"] = rows[1]["cost_q32"] = 0
        elif index % 4 == 1 and count > 2:
            rows[1]["cost_q32"] = rows[2]["cost_q32"] = 0
        elif index % 4 == 2:
            for row in rows[1:]:
                row["hard_violation"] = True
        result.append({"schema": "hepta.hia.ndu-request.v1",
                       "objective_sha256": sha256(b"frozen supplied scalar transport mechanism 20261108").hexdigest(),
                       "generation": index + 1, "resource_cap_q32": 3_000_000,
                       "candidates": rows})
    return result


def ordinary_scalar(raw):
    """Independent exact minimum on the registered valid scalar inputs.

    Native uncertainty metadata does not add another ranking dimension in
    this fixed profile. Feasibility and the incumbent-first tie policy match
    the declared native scalar model. This is an ordinary control, not NDU.
    """
    request = json.loads(raw)
    feasible = [row for row in request["candidates"] if not row["hard_violation"]
                and row["resource_q32"] <= request["resource_cap_q32"]]
    minimum = min(row["cost_q32"] for row in feasible)
    frontier = sorted(row["id"] for row in feasible if row["cost_q32"] == minimum)
    return {"schema": "hepta.hia.scalar-ordinary-benchmark.v1",
            "request_sha256": sha256(raw).hexdigest(), "frontier": frontier,
            "selected_id": "abstain" if "abstain" in frontier else frontier[0],
            "native_ndu_evaluated": False, "authority": "ADVISORY_ONLY"}


def schedule():
    return [{"horizon": horizon, "pair": index + 1, "arms": list(order)}
            for horizon in HORIZONS for index, order in enumerate(ORDERS)]


def register(bridge, output):
    started = time.perf_counter_ns()
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    image, identity = _bridge_identity(bridge)
    source = _git()
    if source["status"]:
        raise ValueError("commit source before registering a timing experiment")
    receipt_path = Path(bridge["build_receipt"]).resolve()
    receipt_bytes = receipt_path.read_bytes()
    receipt = json.loads(receipt_bytes)
    registration = {
        "schema": "hepta.hia.ndu-prepared-ranking-registration.v1",
        "registered_utc": _utc(), "source_git": source, "source_files": _source_files(),
        "bridge": {key: str(Path(value).resolve()) for key, value in bridge.items()},
        "native_identity": identity, "native_binary_bytes": len(image.data),
        "original_build_receipt_sha256": sha256(receipt_bytes).hexdigest(),
        "original_build_cost": receipt.get("build_cost"),
        "prepared_profile": PROFILE, "arms": list(ARMS), "schedule": schedule(),
        "requests": requests(), "per_call_timeout_s": PER_CALL_TIMEOUT_S,
        "whole_campaign_wall_budget_ns": MAX_WALL_NS,
        "maximum_native_calls": 2 * len(ORDERS) * sum(HORIZONS),
        "maximum_ordinary_calls": len(ORDERS) * sum(HORIZONS),
        "timing_boundary": "each cell begins before preparation and ends after all original response observation, selection checks, actual attempt records and prepared close/receipt; cell-summary write is outside that cell but inside the campaign interval",
        "warmup_calls": 0, "automatic_retries": 0,
        "analysis": "all six orders retained per horizon; report every paired difference without selection, descriptive statistics only; no significance or economic threshold",
        "shared_host": True, "other_sessions_excluded": False,
        "prior_source_acquisition_and_original_build_in_cell_cost": False,
        "provider_model_calls": 0, "monetary_cost": None,
        "economic_benefit_established": False, "production_activation_allowed": False,
        "registration_preparation_wall_ns": None,
    }
    # Retain the actual source bytes before any measured native invocation.
    # An auditor need not have this isolated local Git commit to rehash them.
    for name, expected in registration["source_files"].items():
        body = (ROOT / name).read_bytes()
        if sha256(body).hexdigest() != expected:
            raise ValueError("source changed during registration")
        target = output / "frozen-source" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(body)
    registration["registration_preparation_wall_ns"] = time.perf_counter_ns() - started
    _write(output / "registration.json", registration)
    raw = (output / "registration.json").read_bytes()
    checksum = sha256(raw).hexdigest()
    (output / "registration.sha256").write_text(checksum + "\n")
    (output / "original-build-receipt.json").write_bytes(receipt_bytes)
    return {"registration_sha256": checksum, "planned_cells": len(schedule()) * len(ARMS),
            "maximum_native_calls": registration["maximum_native_calls"]}


def _jsonable(value):
    if type(value) is bytes:
        return {"encoding": "base64", "bytes": len(value), "sha256": sha256(value).hexdigest(),
                "data": base64.b64encode(value).decode()}
    if type(value) is dict:
        return {key: _jsonable(item) for key, item in value.items()}
    if type(value) in (list, tuple):
        return [_jsonable(item) for item in value]
    return value


def _cell(arm, horizon, pair, bridge, raw_requests, output, deadline):
    started = time.perf_counter_ns()
    record = {"arm": arm, "horizon": horizon, "pair": pair, "status": "started",
              "planned_calls": horizon, "completed_calls": 0, "calls": [],
              "native_calls_started": 0, "error": None}
    owner = None
    interrupted = None
    path = output / ("h%02d-p%02d-%s-originals.jsonl" % (horizon, pair, arm))
    try:
        with path.open("xb") as originals:
            if arm == "prepared_ndu":
                owner = PreparedNduRanker(bridge, max_requests=horizon)
            for index, raw in enumerate(raw_requests[:horizon]):
                call_started = time.perf_counter_ns()
                row = {"index": index, "request_sha256": sha256(raw).hexdigest(),
                       "status": "started", "native_observations": 0, "error": None}
                record["calls"].append(row)

                def observe(value):
                    row["native_observations"] += 1
                    pump = value.get("pump")
                    record["native_calls_started"] += bool(pump and pump["started"])
                    originals.write(_bytes({"index": index, "kind": "original_native_transport",
                                            "observation": _jsonable(value)}) + b"\n")
                    originals.flush()

                try:
                    remaining = deadline - time.perf_counter_ns()
                    if remaining <= 0:
                        raise TimeoutError("registered whole-campaign budget exhausted")
                    if arm == "ordinary_scalar":
                        result = ordinary_scalar(raw)
                        selected = result["selected_id"]
                    else:
                        request = json.loads(raw)
                        timeout = min(PER_CALL_TIMEOUT_S, remaining / 1_000_000_000)
                        if owner is None:
                            response, identity = _native_rank(bridge, request, timeout_s=timeout,
                                                              observer=observe)
                        else:
                            response, identity = owner.rank(request, timeout_s=timeout, observer=observe)
                        selection = resolve_scalar_selection(request, response)
                        selected = selection["selected_id"]
                        result = {"native_response": response, "native_identity": identity,
                                  "selection": selection}
                    # This independent check is charged equally to all arms.
                    reference = ordinary_scalar(raw)
                    if selected != reference["selected_id"]:
                        raise ValueError("selection differs from frozen scalar ordinary reference")
                    originals.write(_bytes({"index": index, "kind": "result",
                                            "request": json.loads(raw), "result": result}) + b"\n")
                    originals.flush()
                    row.update(status="completed", selected_id=selected,
                               result_sha256=sha256(_bytes(result)).hexdigest())
                    record["completed_calls"] += 1
                except BaseException as error:
                    row.update(status="failed", error={"type": type(error).__name__, "message": str(error)[:2048]})
                    raise
                finally:
                    row["wall_ns"] = time.perf_counter_ns() - call_started
            record["status"] = "completed"
    except BaseException as error:
        record.update(status="failed", error={"type": type(error).__name__, "message": str(error)[:2048]})
        if not isinstance(error, Exception):
            interrupted = error
    finally:
        if owner is not None:
            try:
                owner.close()
            except BaseException as error:
                record.update(status="failed", close_error={"type": type(error).__name__, "message": str(error)[:2048]})
            record["prepared_cost"] = owner.receipt()
        record["wall_ns"] = time.perf_counter_ns() - started
        record["unexecuted_calls"] = horizon - len(record["calls"])
    record["originals"] = {"path": path.name, "sha256": sha256(path.read_bytes()).hexdigest(),
                           "bytes": path.stat().st_size}
    _write(output / ("h%02d-p%02d-%s.json" % (horizon, pair, arm)), record)
    if interrupted is not None:
        raise interrupted
    return record


def analyze(cells):
    result = []
    for horizon in HORIZONS:
        rows = [row for row in cells if row["horizon"] == horizon]
        complete = (len(rows) == len(ORDERS) * len(ARMS)
                    and all(row["status"] == "completed" and row["completed_calls"] == horizon for row in rows))
        comparison = {"horizon": horizon, "all_registered_cells_completed": complete,
                      "pairs": [], "prepared_saving_summary_ns": None}
        for pair in range(1, len(ORDERS) + 1):
            group = {row["arm"]: row for row in rows if row["pair"] == pair}
            valid = (set(group) == set(ARMS)
                     and all(row["status"] == "completed" and row["completed_calls"] == horizon for row in group.values()))
            comparison["pairs"].append({"pair": pair, "complete": valid,
                "all_attempt_arm_wall_ns": {arm: row.get("wall_ns") for arm, row in group.items()},
                "one_shot_minus_prepared_ns": group["one_shot_ndu"]["wall_ns"] - group["prepared_ndu"]["wall_ns"] if valid else None,
                "ordinary_minus_prepared_ns": group["ordinary_scalar"]["wall_ns"] - group["prepared_ndu"]["wall_ns"] if valid else None})
        if complete:
            differences = [row["one_shot_minus_prepared_ns"] for row in comparison["pairs"]]
            comparison["prepared_saving_summary_ns"] = {
                "observations": len(differences), "sum": sum(differences),
                "mean": statistics.mean(differences), "median": statistics.median(differences),
                "min": min(differences), "max": max(differences),
                "sample_stdev": statistics.stdev(differences),
                "positive_pairs": sum(value > 0 for value in differences)}
        result.append(comparison)
    return result


def run(directory, expected_registration_sha256):
    started = time.perf_counter_ns()
    output = Path(directory).resolve()
    raw = (output / "registration.json").read_bytes()
    if sha256(raw).hexdigest() != expected_registration_sha256:
        raise ValueError("registration differs from the explicit precommitted digest")
    reg = json.loads(raw)
    if (reg["schedule"] != schedule() or reg["requests"] != requests()
            or reg["source_files"] != _source_files() or reg["source_git"] != _git()
            or reg["whole_campaign_wall_budget_ns"] != MAX_WALL_NS
            or reg["per_call_timeout_s"] != PER_CALL_TIMEOUT_S):
        raise ValueError("source, task inventory, order or registered budget changed")
    # Exclusive creation makes an uncertain run observable, never silently replayed.
    _write(output / "run-started.json", {"started_utc": _utc(),
           "registration_sha256": expected_registration_sha256})
    before_source = _source_files()
    _, identity = _bridge_identity(reg["bridge"])
    if identity != reg["native_identity"]:
        raise ValueError("original native build changed after registration")
    raw_requests = [_bytes(request) for request in reg["requests"]]
    deadline = started + MAX_WALL_NS
    cells = []
    with (output / "cell-ledger.jsonl").open("xb") as journal:
        for group in reg["schedule"]:
            for arm in group["arms"]:
                if time.perf_counter_ns() >= deadline:
                    record = {"arm": arm, "horizon": group["horizon"], "pair": group["pair"],
                              "status": "not_started_budget_exhausted", "wall_ns": None,
                              "completed_calls": 0, "native_calls_started": 0}
                else:
                    record = _cell(arm, group["horizon"], group["pair"], reg["bridge"],
                                   raw_requests, output, deadline)
                cells.append(record)
                journal.write(_bytes(record) + b"\n")
                journal.flush()
    unchanged = before_source == _source_files() and reg["source_git"] == _git()
    report = {"schema": "hepta.hia.ndu-prepared-ranking-result.v1",
              "registration_sha256": expected_registration_sha256, "finished_utc": _utc(),
              "source_unchanged": unchanged, "source_git": reg["source_git"],
              "source_files": before_source, "native_identity": identity,
              "planned_cells": len(reg["schedule"]) * len(ARMS),
              "completed_cells": sum(row["status"] == "completed" for row in cells),
              "failed_cells": sum(row["status"] == "failed" for row in cells),
              "unstarted_cells": sum(row["status"].startswith("not_started") for row in cells),
              "original_native_calls": sum(row["native_calls_started"] for row in cells),
              "automatic_retries": 0, "analysis": analyze(cells),
              "actual_campaign_wall_ns_to_summary": time.perf_counter_ns() - started,
              "nested_cell_wall_added_again": False,
              "host": {"system": platform.system(), "release": platform.release(),
                       "machine": platform.machine(), "python": platform.python_version()},
              "shared_host": True, "other_sessions_excluded": False,
              "scope": "original native supplied-scalar ranking and explicit sealed-image transport reuse, complete registered cells required for each horizon summary",
              "limitations": ["synthetic finite cost tables, no real task or model invocation",
                  "shared nonexclusive host; counterbalanced orders do not prove stationarity",
                  "prepared snapshot semantics deliberately differ from live origin-path monitoring",
                  "source acquisition and retained original native build excluded from cells",
                  "final summary write and caller startup excluded from campaign timer",
                  "monetary, energy, authoring and complete engineering costs unknown"],
              "whole_lifecycle_cost_complete": False, "ndu_incremental_value_established": False,
              "economic_benefit_established": False, "p2_acceptance": "HOLD",
              "authority": "DENY_ALL", "production_activation_allowed": False}
    report["mechanism_execution_complete"] = (unchanged and report["completed_cells"] == report["planned_cells"]
        and report["original_native_calls"] == reg["maximum_native_calls"])
    _write(output / "result.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    freeze = sub.add_parser("register")
    freeze.add_argument("--binary", required=True)
    freeze.add_argument("--build-receipt", required=True)
    freeze.add_argument("--output", required=True)
    execute = sub.add_parser("run")
    execute.add_argument("--directory", required=True)
    execute.add_argument("--registration-sha256", required=True)
    args = parser.parse_args()
    if args.command == "register":
        result = register({"binary": args.binary, "build_receipt": args.build_receipt}, args.output)
    else:
        report = run(args.directory, args.registration_sha256)
        result = {key: report[key] for key in ("mechanism_execution_complete", "planned_cells",
                  "completed_cells", "failed_cells", "original_native_calls", "p2_acceptance")}
        result["analysis"] = report["analysis"]
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0 if args.command == "register" or result["mechanism_execution_complete"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
