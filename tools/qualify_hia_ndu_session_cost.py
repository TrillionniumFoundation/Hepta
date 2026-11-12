#!/usr/bin/env python3
"""Compare exact historical/current transports using the same native NDU ELF.

This is a transport lifecycle experiment, not a new compiler-vs-DP experiment.
Both arms call the original Rust evaluator on every request. Its build cost is
charged once to each standalone arm; no cold cost is silently amortized away.
The historical compiler-loop negative result remains unchanged.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time
import types

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from hepta.hia_ndu import finite_plan_request

BASELINE_COMMIT = "0e1f5dd9bf0f54c492d96bd5dd1ae52e8c804997"
BASELINE_SHA256 = "0458724d443bf6b581fbf8f7411513867fa0f8841172675d4aedff0cecf57fc8"
ARMS = ("historical-session", "sealed-session")


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(value):
    return sha256(encoded(value)).hexdigest()


def save(path, value):
    path.write_bytes(json.dumps(value, indent=2, sort_keys=True, allow_nan=False).encode() + b"\n")


def requests(count):
    result = []
    states = {name: {"source_sha256": str(i) * 64, "verification_sha256": str(i + 3) * 64,
                     "status": "rejected" if name == "refused" else "verified"}
              for i, name in enumerate(("base", "fast", "refused"), 1)}
    transitions = [
        {"id": "install-" + target + "-from-" + source, "source": source, "target": target,
         "setup_ns": 20_000_000, "status": states[target]["status"],
         "verification_sha256": states[target]["verification_sha256"], "support_sha256": "a" * 64}
        for source, target in (("base", "fast"), ("base", "refused"),
                               ("fast", "base"), ("fast", "refused"))]
    for index in range(count):
        bundle = finite_plan_request(objective_digest="b" * 64,
            snapshot_digest=digest({"registered-request": index}), generation=index + 1,
            initial_state="base", states=states, transitions=transitions,
            batch_costs_ns={"base": [10_000_000, (100 + index) * 1_000_000, 200_000_000],
                            "fast": [(40 + index % 7) * 1_000_000, 1_000_000, 2_000_000],
                            "refused": [0, 0, 0]},
            remaining_budget_ns=1_000_000_000, completion_value_ns=1_000_000_000,
            decision_cost_ns=1_000_000, observations=[])
        result.append(bundle["request"])
    return result


def summarize(rows, *, groups, request_count, shared_cost_ns, build_cost):
    """Keep paired failures and unknown costs; never turn missing work into zero."""
    expected = {(group, arm) for group in range(groups) for arm in ARMS}
    actual = [(row["group"], row["arm"]) for row in rows]
    matrix_complete = len(actual) == len(expected) and set(actual) == expected
    complete = matrix_complete and all(row["status"] == "completed"
        and row["requests_completed"] == request_count and len(row["response_sha256"]) == request_count
        and row["snapshot"]["requests"] == request_count and row["snapshot"]["closed"]
        for row in rows)
    matched = complete and all(
        next(row["response_sha256"] for row in rows if row["group"] == group and row["arm"] == ARMS[0]) ==
        next(row["response_sha256"] for row in rows if row["group"] == group and row["arm"] == ARMS[1])
        for group in range(groups))
    known_build = (type(build_cost) is dict and type(build_cost.get("wall_ns")) is int
                   and build_cost["wall_ns"] >= 0 and build_cost.get("target_cache") == "empty")
    session_costs = {arm: sum(row["outer_wall_ns"] for row in rows if row["arm"] == arm) for arm in ARMS}
    totals = {arm: shared_cost_ns + session_costs[arm] + build_cost["wall_ns"] if known_build else None
              for arm in ARMS}
    return {"matrix_complete": matrix_complete, "all_sessions_completed": complete,
            "all_actual_native_responses_match": matched, "session_cost_ns": session_costs,
            "shared_setup_charged_once_per_arm_ns": shared_cost_ns,
            "native_build_charged_once_per_arm_ns": build_cost["wall_ns"] if known_build else None,
            "standalone_total_cost_ns": totals,
            "complete_within_declared_scope": known_build and matched,
            "sealed_transport_observed_total_lower": bool(known_build and matched
                and totals[ARMS[1]] < totals[ARMS[0]]),
            "compiler_vs_fixed_or_light_acceptance_changed": False,
            "native_ndu_advantage_established": False,
            "statistical_superiority_established": False,
            "authority": "DENY_ALL", "safety_certificate": False}


def load_session(source, name):
    module = types.ModuleType("hepta." + name)
    module.__package__ = "hepta"
    # The exact admitted bytes are compiled for each arm; no baseline method is
    # recreated in the new class or replaced by a synthetic evaluator.
    exec(compile(source, name + ".py", "exec"), module.__dict__)
    return module.NduSession


def qualify(output, *, identity, groups=5, request_count=32):
    if type(groups) is not int or not 1 <= groups <= 16:
        raise ValueError("groups must be in 1..16")
    if type(request_count) is not int or not 1 <= request_count <= 256:
        raise ValueError("requests must fit the native 256-request session bound")
    start = time.monotonic_ns()
    root = Path(output).resolve()
    root.mkdir(parents=True, exist_ok=False)
    identity_path = Path(identity).resolve(strict=True)
    manifest_raw = identity_path.read_bytes()
    manifest = json.loads(manifest_raw)
    baseline = subprocess.run(["git", "show", BASELINE_COMMIT + ":hepta/hia_ndu_session.py"],
                              cwd=ROOT, capture_output=True, check=True, timeout=30).stdout
    if sha256(baseline).hexdigest() != BASELINE_SHA256:
        raise ValueError("historical session source does not match the fixed baseline")
    current_path = ROOT / "hepta/hia_ndu_session.py"
    current = current_path.read_bytes()
    frozen_paths = [current_path, ROOT / "hepta/hia_ndu.py",
                    ROOT / "hepta/hia_native_differential.py", Path(__file__)]
    source_identity = {str(path.relative_to(ROOT)): sha256(path.read_bytes()).hexdigest()
                       for path in frozen_paths}
    source_folder = root / "sources"
    source_folder.mkdir()
    (source_folder / "historical-session.py").write_bytes(baseline)
    for path in frozen_paths:
        target = source_folder / path.relative_to(ROOT)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(path.read_bytes())
    corpus = requests(request_count)
    protocol = {"schema": "hepta.hia.ndu.session-cost.protocol.v1",
        "scope": "same native ELF, paired historical/current transport lifecycles",
        "groups": groups, "requests_per_session": request_count,
        "order": "historical/current on even groups; current/historical on odd groups",
        "sample_exclusion": "none; every attempted session and failure retained",
        "same_information": "identical immutable request bytes within every pair",
        "acceptance": "all actual native responses match; new complete observed standalone total below old",
        "cost_scope": "source admission, request preparation, import, startup, actual evaluation, close, evidence writes; one native empty-target build charged per arm",
        "excluded": ["interpreter process startup", "final aggregate report write", "toolchain installation",
                     "preexisting dependency acquisition", "human engineering cost"],
        "costs_unknown_are_not_zero": True, "full_economic_cost_known": False,
        "compiler_loop_acceptance_unchanged": True, "global_optimality_claim": False}
    registration = {"schema": "hepta.hia.ndu.session-cost.registration.v1",
        "recorded_utc": datetime.now(timezone.utc).isoformat(),
        "protocol_sha256": digest(protocol), "baseline_commit": BASELINE_COMMIT,
        "baseline_session_sha256": sha256(baseline).hexdigest(), "source_identity": source_identity,
        "manifest_sha256": sha256(manifest_raw).hexdigest(), "binary_sha256": manifest["binary_sha256"],
        "native_identity": manifest["identity"], "corpus_sha256": digest(corpus),
        "registration_before_first_session": True, "prior_negative_compiler_result_known": True,
        "authority": "DENY_ALL", "safety_certificate": False}
    save(root / "PROTOCOL.json", protocol)
    save(root / "REGISTRATION.json", registration)
    save(root / "REQUESTS.json", corpus)
    (root / "NATIVE_BUILD_IDENTITY.json").write_bytes(manifest_raw)
    classes = {ARMS[0]: load_session(baseline, "_session_cost_historical"),
               ARMS[1]: load_session(current, "_session_cost_current")}
    rows = []
    for group in range(groups):
        order = ARMS if group % 2 == 0 else ARMS[::-1]
        for arm in order:
            before = time.monotonic_ns()
            row = {"group": group, "arm": arm, "status": "running", "requests_completed": 0,
                   "response_sha256": [], "snapshot": None, "errors": []}
            session, responses = None, []
            try:
                session = classes[arm](manifest["binary"], identity_path, timeout=10.0)
                for value in corpus:
                    response = session.evaluate(value)
                    responses.append(response)
                    row["response_sha256"].append(digest(response))
                    row["requests_completed"] += 1
                row["status"] = "completed"
            except Exception as error:
                row["status"] = "failed"
                row["errors"].append(type(error).__name__ + ": " + str(error))
            finally:
                if session is not None:
                    try:
                        session.close()
                        row["snapshot"] = session.snapshot()
                    except Exception as error:
                        row["status"] = "failed"
                        row["errors"].append("close: " + type(error).__name__ + ": " + str(error))
            row["session_through_close_ns"] = time.monotonic_ns() - before
            save(root / f"group-{group}-{arm}.json", {"observation": row, "responses": responses})
            row["outer_wall_ns"] = time.monotonic_ns() - before
            row["evidence_write_ns"] = row["outer_wall_ns"] - row["session_through_close_ns"]
            rows.append(row)
    if (any(sha256((ROOT / name).read_bytes()).hexdigest() != expected
            for name, expected in source_identity.items())
            or sha256(identity_path.read_bytes()).hexdigest() != registration["manifest_sha256"]):
        raise RuntimeError("source/manifest drift; retain the attempt without qualification")
    elapsed = time.monotonic_ns() - start
    shared = elapsed - sum(row["outer_wall_ns"] for row in rows)
    result = {"schema": "hepta.hia.ndu.session-cost.result.v1",
        "registration": registration, "protocol": protocol,
        "host": {"platform": platform.platform(), "machine": platform.machine(), "python": sys.version,
                 "cpu_affinity": sorted(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else None},
        "sessions": rows, "study_wall_ns": elapsed,
        "acceptance": summarize(rows, groups=groups, request_count=request_count,
                                shared_cost_ns=shared, build_cost=manifest.get("build_cost")),
        "scope": "transport efficiency only; not an instruction, application, compiler or safety advantage"}
    save(root / "RESULT.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--identity", type=Path, required=True)
    parser.add_argument("--groups", type=int, default=5)
    parser.add_argument("--requests", type=int, default=32)
    args = parser.parse_args()
    result = qualify(args.output, identity=args.identity, groups=args.groups, request_count=args.requests)
    print(json.dumps(result["acceptance"], indent=2, sort_keys=True))
    return 0 if result["acceptance"]["all_actual_native_responses_match"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
