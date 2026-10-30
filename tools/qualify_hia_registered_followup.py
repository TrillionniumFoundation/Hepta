"""Preregister and measure the finite stream-NDU and owned-runtime follow-ups.

Registering never executes a workload. Every later run needs a new output path,
the same sources/protocol/tools/environment, and an exclusive experiment lane.
Scientific losses remain completed outcomes and cannot become safety receipts.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hepta.hia_optimization import _solver_identity
from hepta.hia_stateful import OwnedAdaptiveRuntime
from tools.qualify_hia_optimizer_bench import identity, wire, sha, write_new, require
from tools.qualify_hia_stateful import programs, expected

ENVIRONMENT_KEYS = ("PATH", "LD_LIBRARY_PATH", "LD_PRELOAD", "LD_AUDIT", "LIBRARY_PATH",
                    "CPATH", "C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH", "SOURCE_DATE_EPOCH",
                    "LANG", "LC_ALL", "PYTHONPATH", "PYTHONHOME", "PYTHONHASHSEED",
                    "PYTHONDONTWRITEBYTECODE")


def inputs(protocol_path, clang, native_identity=None):
    path = Path(protocol_path).resolve(strict=True)
    protocol = json.loads(path.read_bytes())
    kind = protocol.get("kind")
    require(protocol.get("schema") == "hepta.hia.registered-followup.protocol.v1"
            and kind in {"stream-ndu", "prepared-runtime"}, "Unsupported follow-up protocol")
    paths = {*ROOT.joinpath("hepta").glob("*.py"), Path(__file__), path,
             ROOT / "tools/qualify_hia_optimizer_bench.py",
             ROOT / "tools/qualify_hia_stateful.py"}
    if kind == "stream-ndu":
        require(native_identity is not None, "Actual native build identity required")
        paths.update(ROOT / name for name in ("tools/qualify_hia_ndu_graph.py",
            "tools/qualify_hia_ndu_loop.py", "tools/build_hia_ndu_bridge.py",
            "tests/test_hia_ndu_graph.py", "experiments/hia_optimizer_eval/kernels.hepta"))
    else:
        require(native_identity is None, "Runtime follow-up does not execute a native NDU search")
    import z3
    result = {"protocol": protocol,
        "source_bindings": {str(p.relative_to(ROOT)): identity(p)["sha256"] for p in sorted(paths)},
        "clang": identity(clang),
        "python": {"executable": identity(sys.executable), "version": sys.version},
        "solver": _solver_identity(z3),
        "environment": {k: os.environ.get(k) for k in ENVIRONMENT_KEYS}}
    if native_identity is not None:
        manifest = json.loads(Path(native_identity).read_bytes())
        result["native_build"] = {"manifest": identity(native_identity),
                                  "binary": identity(manifest["binary"]), "value": manifest}
    return result


def register(path, *, protocol_path, clang, native_identity=None):
    result = {"schema": "hepta.hia.registered-followup.registration.v1",
        "inputs": inputs(protocol_path, clang, native_identity), "registered_utc_ns": time.time_ns(),
        "registered_before_workloads": True, "manual_development_cost_ns": None,
        "git_base": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "git_status": subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True),
        "dependency_scope": "Python and tool executables, SMT library/bindings, source closure and declared environment; entire sysroot/OS closure is trusted"}
    result["registration_sha256"] = sha(wire(result))
    write_new(path, result)
    return result


def require_registration(path, *, protocol_path, clang, native_identity=None):
    value = json.loads(Path(path).read_bytes())
    require(value.get("schema") == "hepta.hia.registered-followup.registration.v1", "Invalid registration")
    require(value["registration_sha256"] == sha(wire({k: v for k, v in value.items()
                                                       if k != "registration_sha256"})),
            "Registration bytes changed")
    require(value["inputs"] == inputs(protocol_path, clang, native_identity),
            "Source/protocol/tool/runtime/identity changed after registration")
    return value


def retain_sources(destination, bindings):
    """Preserve exact registered bytes, including this runner and its protocol."""
    total = 0
    for relative, expected_sha in bindings.items():
        raw = (ROOT / relative).read_bytes()
        require(sha(raw) == expected_sha, "Registered source changed during snapshot")
        output = destination / "sources" / relative
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("xb") as stream:
            stream.write(raw)
        total += len(raw)
    return {"files": len(bindings), "bytes": total, "all_bytes_match_registration": True}


def runtime_sample(directory, *, clang, profile):
    """Full fresh-runtime API interval; exclude only the separate audit API.

    Includes fixture/proposal construction, all proof/build/calibration/switch,
    execution, state/resource checks and final close. Baseline-only execution
    deliberately gets no setup charge, making the declared comparison stricter.
    """
    started = time.monotonic_ns()
    base, candidate = programs()
    initial, items = list(profile["initial"]), deepcopy(profile["items"])
    runtime = OwnedAdaptiveRuntime(base, directory, initial, clang=clang)
    try:
        token = runtime.prepare(candidate)
        queue = runtime.submit_queue(items)
        execution = runtime.execute_committed(queue, candidate=token,
            rounds=profile["calibration_rounds"], sample_limit=profile["calibration_sample_steps"])
        audit_started = time.monotonic_ns()
        audit = runtime.audit_counterfactual(queue)
        audit_finished = time.monotonic_ns()
        require(execution["final_values"] == expected(initial, items), "Independent queue oracle differs")
        require(execution["executed_steps"] == sum(i["iterations"] for i in items)
                and execution["replayed_steps"] == 0, "Committed queue progress/replay mismatch")
        snapshot = runtime.snapshot()
        require(execution.get("cost_accounting_complete") is True
                and snapshot.get("cost_accounting_complete") is True
                and snapshot.get("state_poisoned") is False,
                "Runtime cost/progress accounting is incomplete; no net-benefit qualification")
        record = {"profile": profile, "execution": execution, "audit": audit, "snapshot": snapshot,
                  "builds": {key: image.receipt for key, image in runtime._images.items()},
                  "driver": runtime._driver_receipt}
    finally:
        runtime.close()
    finished = time.monotonic_ns()
    audit_api = audit_finished - audit_started
    deployment = finished - started - audit_api
    require(deployment >= execution["deployment_cost_ns"], "Outer envelope omits internal deployment cost")
    ledger = runtime._final_ledger
    require(ledger["live"] == 0 and ledger["allocations"] == ledger["frees"], "Native resources leaked")
    net = audit["baseline_native_execution_ns"] - deployment
    record.update(status="measured", final_native_ledger=ledger,
        total_experiment_api_ns=finished - started, audit_entire_api_ns=audit_api,
        deployment_entire_api_ns=deployment, baseline_native_execution_ns=audit["baseline_native_execution_ns"],
        additional_outer_overhead_ns=deployment - execution["deployment_cost_ns"], measured_net_ns=net,
        deployment_net_positive=net > 0, automatic_selected=execution["automatic_selection"],
        application_effect_scope="exclusive internal u64 owner; no external I/O effects",
        excluded_from_deployment=["separate post-decision counterfactual audit API",
            "Python process startup/imports", "toolchain installation", "manual development",
            "final report encoding/write; measured separately by runner"],
        unexecuted_external_llm_ndu_search_cost_ns=None)
    return record


def run(output, *, registration_path, protocol_path, clang, native_identity=None):
    started = time.monotonic_ns()
    registered = require_registration(registration_path, protocol_path=protocol_path,
                                      clang=clang, native_identity=native_identity)
    destination = Path(output).resolve()
    destination.mkdir(parents=True, exist_ok=False)
    protocol = registered["inputs"]["protocol"]
    write_new(destination / "REGISTRATION.json", registered)
    before_affinity = sorted(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else None
    selected_cpu = min(before_affinity) if before_affinity else None
    if selected_cpu is not None:
        os.sched_setaffinity(0, {selected_cpu})
    host = {"platform": platform.platform(), "machine": platform.machine(), "python": sys.version,
            "started_utc_ns": time.time_ns(), "affinity_before": before_affinity,
            "selected_cpu": selected_cpu, "physical_machine_exclusive": False}
    write_new(destination / "HOST.json", host)
    result = {"schema": "hepta.hia.registered-followup.result.v1", "kind": protocol["kind"],
              "registration_sha256": registered["registration_sha256"], "host": host,
              "status": "running", "all_costs_known": False, "global_optimality_claim": False}
    try:
        result["retained_sources"] = retain_sources(destination, registered["inputs"]["source_bindings"])
        if native_identity is not None:
            native = registered["inputs"]["native_build"]
            raw = Path(native["binary"]["path"]).read_bytes()
            require(sha(raw) == native["binary"]["sha256"], "Native binary changed during evidence snapshot")
            with (destination / "native-evaluator.bin").open("xb") as stream:
                stream.write(raw)
            write_new(destination / "NATIVE_BUILD_IDENTITY.json", native["value"])
        if protocol["kind"] == "stream-ndu":
            from tools.qualify_hia_ndu_graph import qualify
            measured = qualify(destination / "graph", identity=native_identity, clang=clang,
                               protocol=protocol["graph"])
            result["measurement"] = measured
            result["implementation_gate_passed"] = bool(measured["all_episodes_completed"]
                and measured["all_outputs_correct"] and measured["all_actual_budgets_passed"])
            # Whole strategy costs, rather than a median that can conceal one
            # expensive completed group, determine the later aggregate gate.
            result["finite_net_benefit_gate_passed"] = False
            result["statistical_superiority_established"] = False
        else:
            result["samples"] = []
            for index, profile in enumerate(protocol["queues"]):
                sample_started = time.monotonic_ns()
                require_registration(registration_path, protocol_path=protocol_path, clang=clang)
                try:
                    row = runtime_sample(destination / ("runtime-" + str(index)), clang=clang, profile=profile)
                except BaseException as error:
                    failed = {"status": "failed-retained", "index": index, "profile": profile,
                              "observed_wall_ns": time.monotonic_ns() - sample_started,
                              "error": {"type": type(error).__name__, "message": str(error)},
                              "unavailable_state_or_subphase_measurements": None}
                    result["samples"].append(failed)
                    write_new(destination / ("sample-" + str(index) + ".json"), failed)
                    raise
                row["runner_until_record_ns"] = time.monotonic_ns() - sample_started
                save_started = time.monotonic_ns()
                write_new(destination / ("sample-" + str(index) + ".json"), row)
                row["sample_report_encoding_write_ns"] = time.monotonic_ns() - save_started
                row["runner_complete_sample_ns"] = time.monotonic_ns() - sample_started
                row["deployment_plus_validation_and_evidence_ns"] = (
                    row["runner_complete_sample_ns"] - row["audit_entire_api_ns"])
                row["net_after_validation_and_evidence_ns"] = (row["baseline_native_execution_ns"]
                    - row["deployment_plus_validation_and_evidence_ns"])
                result["samples"].append(row)
            rows = result["samples"]
            result["implementation_gate_passed"] = all(r["status"] == "measured" for r in rows)
            result["finite_net_benefit_gate_passed"] = False
            result["median_deployment_api_ns"] = statistics.median(r["deployment_entire_api_ns"] for r in rows)
            result["median_baseline_execution_ns"] = statistics.median(r["baseline_native_execution_ns"] for r in rows)
            result["median_measured_net_ns"] = statistics.median(r["measured_net_ns"] for r in rows)
            result["statistical_superiority_established"] = False
        require_registration(registration_path, protocol_path=protocol_path,
                             clang=clang, native_identity=native_identity)
        if protocol["kind"] == "stream-ndu":
            measured = result["measurement"]
            wrapper_ns = time.monotonic_ns() - started - measured["study_wall_ns"]
            totals = measured["standalone_total_cost_ns"]
            charged = dict(totals, ndu=totals["ndu"] + wrapper_ns)
            result["wrapper_cost"] = {"observed_wall_ns": wrapper_ns,
                "charged_to": "ndu", "conservative_surcharge": True,
                "scope": "all outer registration/identity/host/report preparation through final input revalidation",
                "shared_parts_are_not_removed_from_ndu": True,
                "excluded": "final aggregate result encoding/write and affinity restoration"}
            result["standalone_total_cost_with_wrapper_ns"] = charged
            result["finite_net_benefit_gate_passed"] = bool(result["implementation_gate_passed"]
                and measured["setup_accounting"]["cost_complete_within_scope"]
                and charged["ndu"] < charged["fixed-best-plan"]
                and charged["ndu"] < charged["light"])
        else:
            rows = result["samples"]
            common_ns = time.monotonic_ns() - started - sum(r["runner_complete_sample_ns"] for r in rows)
            result["shared_wrapper_ns"] = common_ns
            result["shared_wrapper_cost_policy"] = "actual common registration/source snapshot/host/final validation costs allocated equally across all fixed groups"
            for row in rows:
                row["shared_wrapper_allocated_ns"] = common_ns / len(rows)
                row["complete_measured_deployment_ns"] = (row["deployment_plus_validation_and_evidence_ns"]
                                                           + row["shared_wrapper_allocated_ns"])
                row["complete_measured_net_ns"] = (row["baseline_native_execution_ns"]
                                                   - row["complete_measured_deployment_ns"])
            result["finite_net_benefit_gate_passed"] = all(r["automatic_selected"]
                and r["deployment_net_positive"] and r["complete_measured_net_ns"] > 0 for r in rows)
        result.update(status="completed", bound_inputs_unchanged=True)
    except BaseException as error:
        result.update(status="failed-retained", error={"type": type(error).__name__, "message": str(error)},
                      implementation_gate_passed=False, finite_net_benefit_gate_passed=False)
    finally:
        result["runner_wall_ns_before_final_report"] = time.monotonic_ns() - started
        if before_affinity is not None:
            os.sched_setaffinity(0, set(before_affinity))
        write_new(destination / "RESULT.json", result)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("register", "run"))
    parser.add_argument("--protocol", required=True, type=Path)
    parser.add_argument("--registration", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--clang", default=os.environ.get("CLANG", "clang"))
    parser.add_argument("--native-identity", type=Path)
    args = parser.parse_args()
    common = {"protocol_path": args.protocol, "clang": args.clang, "native_identity": args.native_identity}
    if args.operation == "register":
        value = register(args.registration, **common)
        print(json.dumps({"registration_sha256": value["registration_sha256"]}))
    else:
        if args.output is None:
            parser.error("run requires --output")
        value = run(args.output, registration_path=args.registration, **common)
        print(json.dumps({k: value.get(k) for k in ("status", "implementation_gate_passed",
                                                  "finite_net_benefit_gate_passed", "error")}))
        raise SystemExit(0 if value["status"] == "completed" else 1)
