#!/usr/bin/env python3
"""Prospective real-workload eight-arm NDU/DP comparison with explicit costs."""
from __future__ import annotations

import argparse
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hepta.hia_ndu_session import STREAM_SOURCE_PIN
from tools.hia_agent_codex_transport import canonical, identity, save
from tools.qualify_hia_ndu_graph import ARMS, PROTOCOL as BASE_PROTOCOL, qualify

HERE = ROOT / "benchmarks/hia_ndu_converged_holdout"


def protocol():
    return json.loads((HERE / "PROTOCOL.json").read_text())


def bindings():
    paths = list((ROOT / "hepta").glob("*.py")) + [Path(__file__), HERE / "PROTOCOL.json",
        ROOT / "tools/hia_agent_codex_transport.py", ROOT / "tools/qualify_hia_ndu_graph.py",
        ROOT / "tools/qualify_hia_ndu_loop.py", ROOT / "tools/build_hia_recursive_ndu_bridge.py",
        ROOT / "tests/test_hia_ndu_graph.py", ROOT / "tests/test_hia_ndu_convergence.py",
        ROOT / "tests/test_hia_ndu_converged_holdout.py", ROOT / "experiments/hia_optimizer_eval/kernels.hepta"]
    return {str(path.relative_to(ROOT)): identity(path)["sha256"] for path in sorted(paths)}


def validate_build(identity_path, envelope_path):
    manifest_raw = Path(identity_path).read_bytes()
    manifest, envelope = json.loads(manifest_raw), json.loads(Path(envelope_path).read_bytes())
    native = manifest["identity"]
    if (native.get("source_commit") != STREAM_SOURCE_PIN or not native.get("rustc", "").startswith("rustc 1.90.0 ")
            or envelope.get("schema") != "hepta.hia.ndu.outer-build-cost.v1"
            or envelope.get("identity_sha256") != sha256(manifest_raw).hexdigest()
            or envelope.get("binary_sha256") != manifest.get("binary_sha256")
            or envelope.get("native_source_pin") != STREAM_SOURCE_PIN
            or envelope.get("returncode") != 0 or envelope.get("source_unchanged") is not True
            or envelope.get("target_cache") != "empty" or manifest.get("build_cost", {}).get("target_cache") != "empty"
            or type(envelope.get("wall_ns")) is not int or envelope["wall_ns"] < manifest["build_cost"]["wall_ns"]
            or envelope.get("authority") != "DENY_ALL" or envelope.get("safety_certificate") is not False):
        raise ValueError("original pinned empty-target outer build receipt required")
    if identity(manifest["binary"])["sha256"] != manifest["binary_sha256"]:
        raise ValueError("native executable changed")
    return manifest, envelope


def freeze(identity_path, envelope_path, clang):
    source = bindings()
    manifest, envelope = validate_build(identity_path, envelope_path)
    for name, digest in source.items():
        raw = subprocess.check_output(["git", "show", "HEAD:"+name], cwd=ROOT)
        if sha256(raw).hexdigest() != digest:
            raise ValueError("uncommitted source: " + name)
    if (HERE / "FREEZE.json").exists():
        raise ValueError("never replace an existing holdout registration")
    record = {"schema": "hepta.hia.ndu.converged-holdout.freeze.v1",
        "code_commit": subprocess.check_output(["git","rev-parse","HEAD"],cwd=ROOT,text=True).strip(),
        "created_unix_ns": time.time_ns(), "bindings": source,
        "native_identity": identity(identity_path), "native_envelope": identity(envelope_path),
        "native_binary": identity(manifest["binary"]), "clang": identity(clang),
        "historical_build_outer_ns": envelope["wall_ns"], "new_calibration_or_holdout_runs_before_freeze": 0}
    save(HERE / "FREEZE.json", record)
    print(json.dumps({"freeze": identity(HERE / "FREEZE.json"), "code_commit": record["code_commit"]}))
    return 0


def verify_freeze():
    frozen = json.loads((HERE / "FREEZE.json").read_text())
    if bindings() != frozen["bindings"]:
        raise ValueError("registered source drift")
    for key in ("native_identity", "native_envelope", "native_binary", "clang"):
        if identity(frozen[key]["path"]) != frozen[key]:
            raise ValueError("registered tool/build identity drift: " + key)
    validate_build(frozen["native_identity"]["path"], frozen["native_envelope"]["path"])
    return frozen


def cost_report(result, *, build_outer_ns, wrapper_overhead_ns, retained_bytes):
    """Do not hide old build cost or invent numbers for unmeasured acquisition."""
    native_arms = ("ndu", "ndu-compact")
    inner = result["setup_accounting"]["native_build_cost"]["wall_ns"]
    if build_outer_ns < inner or wrapper_overhead_ns < 0:
        raise ValueError("cost scope would subtract unaccounted work")
    startup = {}
    marginal, full = {}, {}
    for arm, original in result["standalone_total_cost_ns"].items():
        marginal[arm] = original + wrapper_overhead_ns - (inner if arm in native_arms else 0)
        full[arm] = marginal[arm] + (build_outer_ns if arm in native_arms else 0)
        setup = result["shared_setup_wall_ns"] + wrapper_overhead_ns + result["setup_accounting"]["controller_setup_ns"][arm]
        startup[arm] = setup + (build_outer_ns if arm in native_arms else 0)
    comparisons = ("fixed-best-plan", "q32-dp", "light")
    success = result["all_episodes_completed"] and result["all_outputs_correct"] and result["all_actual_budgets_passed"]
    advantages = {arm: {baseline: full[baseline]-full[arm] for baseline in comparisons} for arm in native_arms}
    return {"original_empty_target_native_build_outer_ns": build_outer_ns,
        "original_inner_native_build_ns": inner, "wrapper_overhead_charged_once_per_standalone_arm_ns": wrapper_overhead_ns,
        "startup_cost_ns": startup, "already_built_marginal_total_ns": marginal, "standalone_with_original_build_total_ns": full,
        "observed_two_episode_amortized_ns": {arm: total/len([e for e in result["episodes"] if e["arm"] == arm]) for arm,total in full.items()},
        "native_net_savings_ns": advantages,
        "measured_scope_net_gain": bool(success and all(value > 0 for by_baseline in advantages.values() for value in by_baseline.values())),
        "cost_complete_within_declared_execution_scope": True,
        "all_lifetime_costs_known": False,
        "unknown_costs": {"toolchain_acquisition_ns": None, "dependency_cache_acquisition_ns": None, "human_work_ns": None,
                          "long_term_evidence_storage_ns": None},
        "retained_evidence_bytes": retained_bytes,
        "scope_exclusions": ["this final wrapper result encoding/write", "persistent evidence retention", "toolchain/dependency acquisition", "human work"],
        "complete_lifetime_net_gain_proved": False, "strongest_cross_language_static_baseline_beaten": False,
        "long_term_amortization_measured": False, "statistical_superiority_established": False,
        "global_optimality_claim": False, "safety_from_ndu_claim": False}


def run(output, registration_commit):
    start = time.monotonic_ns()
    frozen = verify_freeze()
    registered = subprocess.check_output(["git", "show", registration_commit+":benchmarks/hia_ndu_converged_holdout/FREEZE.json"], cwd=ROOT)
    if registered != (HERE / "FREEZE.json").read_bytes():
        raise ValueError("commit does not bind current holdout freeze")
    subprocess.run(["git","merge-base","--is-ancestor",registration_commit,"HEAD"],cwd=ROOT,check=True)
    root = Path(output).resolve()
    root.mkdir(parents=True, exist_ok=False)
    cfg = protocol()
    actual = deepcopy(BASE_PROTOCOL)
    actual.update(cfg)
    actual["native_profile"] = {"source_pin": STREAM_SOURCE_PIN, "rustc": "1.90.0", "environment": "explicit frozen stream manifest"}
    result = {"schema": "hepta.hia.ndu.converged-holdout.result.v1", "registration_commit": registration_commit,
              "freeze": identity(HERE / "FREEZE.json"), "status": "incomplete", "previous_negative_results_replaced": False}
    save(root / "PLAN.json", {**result, "frozen": frozen, "protocol": cfg, "observations_before_plan": 0})
    try:
        graph = qualify(root / "graph", identity=frozen["native_identity"]["path"], clang=frozen["clang"]["path"],
                        protocol=actual, decision_cache_entries=0)
        verify_freeze()
        retained_bytes = sum(p.stat().st_size for p in root.rglob("*") if p.is_file())
        outer_ns = time.monotonic_ns()-start
        result.update(status="complete", graph_result=identity(root / "graph/RESULT.json"), graph=graph,
                      source_unchanged=True, outer_execution_ns=outer_ns,
                      costs=cost_report(graph, build_outer_ns=frozen["historical_build_outer_ns"],
                                        wrapper_overhead_ns=outer_ns-graph["study_wall_ns"], retained_bytes=retained_bytes))
    except Exception as exc:
        result.update(error={"type": type(exc).__name__, "message": str(exc)}, outer_execution_ns=time.monotonic_ns()-start,
                      complete_lifetime_net_gain_proved=False)
    save(root / "RESULT.json", result)
    print(json.dumps({"status": result["status"], "costs": result.get("costs"), "error": result.get("error")}), flush=True)
    return 0 if result["status"] == "complete" else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p=sub.add_parser("freeze"); p.add_argument("--identity",required=True); p.add_argument("--build-envelope",required=True);p.add_argument("--clang",required=True)
    p=sub.add_parser("run");p.add_argument("--output",required=True);p.add_argument("--registration-commit",required=True)
    args=parser.parse_args(argv)
    return freeze(args.identity,args.build_envelope,args.clang) if args.command == "freeze" else run(args.output,args.registration_commit)


if __name__ == "__main__":
    raise SystemExit(main())
