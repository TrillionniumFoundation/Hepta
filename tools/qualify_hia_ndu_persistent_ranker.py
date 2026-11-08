#!/usr/bin/env python3
"""Register then measure bounded native process reuse against prepared and ordinary arms."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from hashlib import sha256
import itertools
import json
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from hepta.hia_ndu_optimizer import _bridge_identity, _bytes
from hepta.hia_ndu_prepared_ranker import PreparedNduRanker
from hepta.hia_ndu_persistent_ranker import PersistentNduRanker, PROFILE
from hepta.hia_ndu_scalar_selection import resolve_scalar_selection
from tools.qualify_hia_ndu_prepared_ranker import requests, ordinary_scalar, _jsonable

ARMS = ("prepared_ndu", "persistent_ndu", "ordinary_scalar")
HORIZONS = (1, 4, 16, 64)
ORDERS = tuple(itertools.permutations(ARMS))
MAX_WALL_NS = 120_000_000_000
PER_CALL_TIMEOUT_S = 1.0
MAX_SESSION_LIFETIME_S = 60.0
SOURCE_PATHS = (
    "hepta/hia_ndu_prepared_ranker.py", "hepta/hia_ndu_persistent_ranker.py",
    "hepta/hia_ndu_optimizer.py", "hepta/hia_ndu_scalar_selection.py",
    "hepta/hia_rust_crosscheck.py", "tools/build_hia_ndu_bridge.py",
    "tools/qualify_hia_ndu_prepared_ranker.py",
    "tools/qualify_hia_ndu_persistent_ranker.py",
    "tools/replay_hia_ndu_persistent_ranker.py",
    "tests/test_hia_ndu_persistent_ranker.py",
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
    sources = _source_files()
    subprocess.check_call(["git", "ls-files", "--error-unmatch", *sources],
                          cwd=ROOT, stdout=subprocess.DEVNULL)
    receipt_path = Path(bridge["build_receipt"]).resolve()
    receipt_bytes = receipt_path.read_bytes()
    receipt = json.loads(receipt_bytes)
    registration = {
        "schema": "hepta.hia.ndu-persistent-ranking-registration.v1",
        "registered_utc": _utc(), "source_git": source, "source_files": sources,
        "bridge": {key: str(Path(value).resolve()) for key, value in bridge.items()},
        "native_identity": identity, "native_binary_bytes": len(image.data),
        "original_build_receipt_sha256": sha256(receipt_bytes).hexdigest(),
        "original_build_cost": receipt.get("build_cost"),
        "persistent_profile": PROFILE, "arms": list(ARMS), "schedule": schedule(),
        "requests": requests(), "per_call_timeout_s": PER_CALL_TIMEOUT_S,
        "maximum_session_lifetime_s": MAX_SESSION_LIFETIME_S,
        "whole_campaign_wall_budget_ns": MAX_WALL_NS,
        "maximum_native_processes": len(ORDERS) * (sum(HORIZONS) + len(HORIZONS)),
        "maximum_native_evaluations": 2 * len(ORDERS) * sum(HORIZONS),
        "maximum_ordinary_calls": len(ORDERS) * sum(HORIZONS),
        "timing_boundary": "each cell begins before owner preparation and ends after all original response observation, selection checks, actual attempt records, owner close/receipt and original stream close; cell-summary write is outside that cell but inside the campaign interval",
        "warmup_calls_inside_registered_campaign": 0, "automatic_retries": 0,
        "prior_functional_validation": "native protocol controls ran before registration; their observations are not campaign cells; host caches are not reset or independently measured",
        "analysis": "all six orders retained per horizon; report every paired difference without selection; descriptive statistics only, no significance or economic threshold",
        "shared_host": True, "other_sessions_excluded": False,
        "prior_source_acquisition_and_original_build_in_cell_cost": False,
        "provider_model_calls": 0, "monetary_cost": None,
        "economic_benefit_established": False, "production_activation_allowed": False,
        "registration_preparation_wall_ns": None,
    }
    for name, expected in sources.items():
        body = (ROOT / name).read_bytes()
        if sha256(body).hexdigest() != expected:
            raise ValueError("source changed during registration")
        target = output / "frozen-source" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(body)
    registration["registration_preparation_wall_ns"] = time.perf_counter_ns() - started
    _write(output / "registration.json", registration)
    checksum = sha256((output / "registration.json").read_bytes()).hexdigest()
    (output / "registration.sha256").write_text(checksum + "\n")
    (output / "original-build-receipt.json").write_bytes(receipt_bytes)
    return {"registration_sha256": checksum, "planned_cells": len(schedule()) * len(ARMS),
            "maximum_native_processes": registration["maximum_native_processes"],
            "maximum_native_evaluations": registration["maximum_native_evaluations"]}


def _cell(arm, horizon, pair, bridge, raw_requests, output, deadline):
    started = time.perf_counter_ns()
    record = {"arm": arm, "horizon": horizon, "pair": pair, "status": "started",
              "planned_calls": horizon, "completed_calls": 0, "calls": [],
              "native_processes_started": 0, "native_responses_checked": 0, "error": None}
    path = output / ("h%02d-p%02d-%s-originals.jsonl" % (horizon, pair, arm))
    owner = None
    originals = None
    current_index = -1
    persistent_pids = set()
    interrupted = None

    def write_original(value):
        originals.write(_bytes(_jsonable(value)) + b"\n")
        originals.flush()

    def persistent_observer(event):
        observation = event["observation"]
        pid = (observation.get("cleanup") or {}).get("pid") if event["phase"] == "close" else observation.get("worker_pid")
        if pid is not None:
            persistent_pids.add(pid)
            record["native_processes_started"] = len(persistent_pids)
        write_original({"index": current_index, "kind": "original_persistent_transport", "event": event})

    def prepared_observer(value):
        pump = value.get("pump")
        record["native_processes_started"] += bool(pump and pump["started"])
        write_original({"index": current_index, "kind": "original_prepared_transport", "observation": value})

    try:
        originals = path.open("xb")
        remaining = deadline - time.perf_counter_ns()
        if remaining <= 0:
            raise TimeoutError("registered whole-campaign budget exhausted before preparation")
        if arm == "prepared_ndu":
            owner = PreparedNduRanker(bridge, max_requests=horizon)
        elif arm == "persistent_ndu":
            owner = PersistentNduRanker(
                bridge, max_requests=horizon,
                startup_timeout_s=min(PER_CALL_TIMEOUT_S, remaining / 1_000_000_000),
                lifetime_s=min(MAX_SESSION_LIFETIME_S, remaining / 1_000_000_000),
                observer=persistent_observer)
        for current_index, raw in enumerate(raw_requests[:horizon]):
            call_started = time.perf_counter_ns()
            row = {"index": current_index, "request_sha256": sha256(raw).hexdigest(),
                   "status": "started", "error": None}
            record["calls"].append(row)
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
                    kwargs = {"timeout_s": timeout}
                    if arm == "prepared_ndu":
                        kwargs["observer"] = prepared_observer
                    response, identity = owner.rank(request, **kwargs)
                    record["native_responses_checked"] += 1
                    selection = resolve_scalar_selection(request, response)
                    selected = selection["selected_id"]
                    result = {"native_response": response, "native_identity": identity,
                              "selection": selection}
                reference = ordinary_scalar(raw)
                if selected != reference["selected_id"]:
                    raise ValueError("selection differs from the frozen scalar ordinary reference")
                write_original({"index": current_index, "kind": "result",
                                "request": json.loads(raw), "result": result})
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
            receipt = owner.receipt()
            record["owner_cost"] = receipt
            if not receipt["complete"] or arm == "persistent_ndu" and not receipt["session_accepted"]:
                record.update(status="failed", incomplete_owner=True)
        if originals is not None:
            originals.close()
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
        complete = len(rows) == len(ORDERS) * len(ARMS) and all(
            row["status"] == "completed" and row["completed_calls"] == horizon for row in rows)
        comparison = {"horizon": horizon, "all_registered_cells_completed": complete,
                      "pairs": [], "persistent_saving_summary_ns": None}
        for pair in range(1, len(ORDERS) + 1):
            group = {row["arm"]: row for row in rows if row["pair"] == pair}
            valid = set(group) == set(ARMS) and all(
                row["status"] == "completed" and row["completed_calls"] == horizon for row in group.values())
            comparison["pairs"].append({
                "pair": pair, "complete": valid,
                "all_attempt_arm_wall_ns": {arm: row.get("wall_ns") for arm, row in group.items()},
                "prepared_minus_persistent_ns": group["prepared_ndu"]["wall_ns"] - group["persistent_ndu"]["wall_ns"] if valid else None,
                "ordinary_minus_persistent_ns": group["ordinary_scalar"]["wall_ns"] - group["persistent_ndu"]["wall_ns"] if valid else None})
        if complete:
            differences = [row["prepared_minus_persistent_ns"] for row in comparison["pairs"]]
            comparison["persistent_saving_summary_ns"] = {
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
            or reg["per_call_timeout_s"] != PER_CALL_TIMEOUT_S
            or reg["maximum_session_lifetime_s"] != MAX_SESSION_LIFETIME_S):
        raise ValueError("source, tasks, order or registered budget changed")
    _write(output / "run-started.json", {"started_utc": _utc(),
                                      "registration_sha256": expected_registration_sha256})
    before_source = _source_files()
    _, identity = _bridge_identity(reg["bridge"])
    if identity != reg["native_identity"]:
        raise ValueError("native build changed after registration")
    raw_requests = [_bytes(request) for request in reg["requests"]]
    deadline = started + MAX_WALL_NS
    cells = []
    with (output / "cell-ledger.jsonl").open("xb") as journal:
        for group in reg["schedule"]:
            for arm in group["arms"]:
                if time.perf_counter_ns() >= deadline:
                    record = {"arm": arm, "horizon": group["horizon"], "pair": group["pair"],
                              "status": "not_started_budget_exhausted", "wall_ns": None,
                              "completed_calls": 0, "native_processes_started": 0, "native_responses_checked": 0}
                else:
                    record = _cell(arm, group["horizon"], group["pair"], reg["bridge"], raw_requests, output, deadline)
                cells.append(record)
                journal.write(_bytes(record) + b"\n")
                journal.flush()
    unchanged = before_source == _source_files() and reg["source_git"] == _git()
    report = {
        "schema": "hepta.hia.ndu-persistent-ranking-result.v1",
        "registration_sha256": expected_registration_sha256, "finished_utc": _utc(),
        "source_unchanged": unchanged, "source_git": reg["source_git"], "source_files": before_source,
        "native_identity": identity, "planned_cells": len(reg["schedule"]) * len(ARMS),
        "completed_cells": sum(row["status"] == "completed" for row in cells),
        "failed_cells": sum(row["status"] == "failed" for row in cells),
        "unstarted_cells": sum(row["status"].startswith("not_started") for row in cells),
        "native_processes_started": sum(row["native_processes_started"] for row in cells),
        "native_responses_checked": sum(row["native_responses_checked"] for row in cells),
        "automatic_retries": 0, "analysis": analyze(cells),
        "actual_campaign_wall_ns_to_summary": time.perf_counter_ns() - started,
        "nested_cell_wall_added_again": False,
        "host": {"system": platform.system(), "release": platform.release(),
                 "machine": platform.machine(), "python": platform.python_version()},
        "shared_host": True, "other_sessions_excluded": False,
        "scope": "original native supplied-scalar ranking and explicit bounded persistent process transport; complete registered cells required for each horizon summary",
        "limitations": [
            "synthetic finite cost tables, no real task or model invocation",
            "shared nonexclusive host; counterbalanced orders do not prove stationarity",
            "prepared and persistent bind the same admitted immutable executable snapshot",
            "a persistent round is advisory until the owner closes successfully",
            "source acquisition and retained native build excluded from cells",
            "final summary write and caller startup excluded from campaign timer",
            "monetary, energy, authoring and complete engineering costs unknown"],
        "whole_lifecycle_cost_complete": False, "ndu_incremental_value_established": False,
        "economic_benefit_established": False, "p2_acceptance": "HOLD",
        "authority": "DENY_ALL", "production_activation_allowed": False}
    report["mechanism_execution_complete"] = (
        unchanged and report["completed_cells"] == report["planned_cells"]
        and report["native_processes_started"] == reg["maximum_native_processes"]
        and report["native_responses_checked"] == reg["maximum_native_evaluations"])
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
        result = {key: report[key] for key in (
            "mechanism_execution_complete", "planned_cells", "completed_cells", "failed_cells",
            "native_processes_started", "native_responses_checked", "p2_acceptance", "analysis")}
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0 if args.command == "register" or result["mechanism_execution_complete"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
