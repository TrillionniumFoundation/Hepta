#!/usr/bin/env python3
"""Qualify explicit preparation/residency coupling with independent controls.

The fixture costs are declared model inputs. Only native transport/build costs
are measured here. Success establishes finite-model agreement, never an
application speedup, execution-safety credential or incremental NDU advantage.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import platform
import re
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hepta.hia_ndu_stateful import (SCHEMA, build_request, digest, observe_refusal,
                                    separability_diagnostic, validate_model, wire)
from tools.qualify_hia_ndu_stateful_reference import (
    exact_dp_control, exhaustive_oracle, fixed_configuration_control, greedy_control)

SCALE = 1_000_000
PROTOCOL_PATH = ROOT / "benchmarks/hia_ndu_stateful/PROTOCOL.json"
SOURCE_PATHS = (
    "hepta/hia_ndu_stateful.py", "hepta/hia_ndu.py", "hepta/hia_ndu_response.py",
    "hepta/hia_planning.py", "hepta/hia_ndu_session.py", "hepta/hia_native_differential.py",
    "hepta/hia_translation_validation.py", "hepta/hia_program.py", "hepta/hia_schema.py",
    "hepta/hia_opcodes.py", "hepta/hia_json_preflight.py", "hepta/hia_bounded_memory.py",
    "hepta/hia_program_runtime.py",
    "hepta/hia_program_tools.py", "hepta/artifact_publication.py",
    "tools/qualify_hia_ndu_stateful.py", "tools/qualify_hia_ndu_stateful_reference.py",
    "tests/test_hia_ndu_stateful.py", "benchmarks/hia_ndu_stateful/PROTOCOL.json")


def require(condition, message):
    if not condition:
        raise ValueError("stateful qualification: " + message)


def fixtures():
    """Deterministic discriminating models; digests are not code proofs."""
    def variant(name, preparation, latency, holding=None, resident=16):
        return {"id": name, "source_sha256": digest(["declared-model-source", name]),
                "verification_sha256": digest(["modeled-admission-only-not-code-proof", name]),
                "support_sha256": digest(["declared-cost-estimates", name]),
                "status": "verified", "preparation_ns": preparation * SCALE,
                "holding_ns": [value * SCALE for value in (holding or [0] * 4)],
                "resident_bytes": resident, "latency_ns": [value * SCALE for value in latency]}

    def model(name, baseline, variants, **changes):
        result = {"schema": SCHEMA, "name": name, "generation": 1,
                  "objective_digest": digest(["stateful-model-objective", name]),
                  "baseline": {"source_sha256": digest(["declared-baseline", name]),
                               "verification_sha256": digest(["modeled-baseline-admission", name]),
                               "latency_ns": [value * SCALE for value in baseline]},
                  "variants": variants, "initial_ready": [], "memory_budget_bytes": 128,
                  "budget_ns": 2000 * SCALE, "completion_value_ns": 3000 * SCALE,
                  "sunk_cost_ns": 0, "observations": [], "cost_basis": "declared-model-only"}
        result.update(changes)
        return validate_model(result)

    delayed = model("delayed-payback", [100] * 4,
                    [variant("fast", 120, [50, 1, 1, 1])])
    holding = model("holding-delay", [10, 10, 100, 100],
                    [variant("late", 20, [9, 9, 1, 1], [30, 30, 2, 2])])
    memory = model("memory-exclusion", [80] * 4,
                   [variant("early", 20, [1, 1, 70, 70], [1] * 4, 64),
                    variant("late", 20, [70, 70, 1, 1], [1] * 4, 64)],
                   memory_budget_bytes=64)
    refusal = observe_refusal(delayed, variant_id="fast", actual_attempt_ns=30 * SCALE,
                              observation_digest=digest("fixture-refusal-not-a-host-measurement"))
    refusal["name"] = "observed-refusal"
    prepared = model("prepared-separable", [90] * 4,
                     [variant("odd", 100, [1, 9, 1, 9]),
                      variant("even", 100, [9, 1, 9, 1])],
                     initial_ready=["even", "odd"], sunk_cost_ns=200 * SCALE)
    larger = model("larger-preparation", [100] * 4,
                   [variant("early", 40, [70, 30, 100, 100], [1] * 4),
                    variant("middle", 30, [95, 95, 20, 20], [2] * 4),
                    variant("late", 20, [90, 90, 90, 10], [1] * 4)])
    return [validate_model(item) for item in [delayed, holding, memory, refusal, prepared, larger]]


def canonical_schedules(reference):
    return {tuple(tuple(ready) for ready in row["schedule"]) for row in reference["winners"]}


def bundle_schedules(bundle, identities):
    """Collapse only stop/hold syntax with the same delivered prepared states."""
    states = bundle["stateful_binding"]["states"]
    return {tuple(tuple(states[action["target"]]["ready"]) for action in bundle["plans"][name]["actions"])
            for name in identities if name != "abstain"}


def assert_agreement(bundle, response, reference, *, native):
    identities = response["pareto_candidate_ids"]
    require(bundle_schedules(bundle, identities) == canonical_schedules(reference),
            "complete winning prepared-set sequences differ from independent oracle")
    require(("abstain" in identities) == reference["abstain_is_optimal"], "abstention differs")
    if native:
        values = {row["id"]: row["values_q32"][0] for row in response["paths"]}
    else:
        values = response["values_q32"]
    require(all(values[name] == reference["best_value_q32"] for name in identities),
            "Q32 continuation value differs")
    require(response["authority"] == "DENY_ALL" and response["safety_certificate"] is False,
            "response attempted to confer authority")


def timed(ledger, name, operation):
    started = time.monotonic_ns()
    outcome = "passed"
    try:
        return operation()
    except BaseException:
        outcome = "failed"
        raise
    finally:
        ledger.append({"operation": name, "wall_ns": time.monotonic_ns() - started,
                       "status": outcome})


def source_identity(expected_head=None):
    """Require actual committed bytes for native qualification; never fake HEAD."""
    files = {}
    for name in SOURCE_PATHS:
        files[name] = sha256((ROOT / name).read_bytes()).hexdigest()
    head_run = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, check=False)
    head = head_run.stdout.decode().strip() if head_run.returncode == 0 else None
    status_run = subprocess.run(["git", "status", "--porcelain=v1", "--untracked-files=all"],
                                cwd=ROOT, capture_output=True, check=False)
    status = status_run.stdout.decode() if status_run.returncode == 0 else None
    if expected_head is not None:
        require(re.fullmatch("[0-9a-f]{40}", expected_head) is not None, "expected HEAD must be exact")
        require(head == expected_head and status == "", "formal native run needs exact clean HEAD")
        for name, expected in files.items():
            blob = subprocess.run(["git", "cat-file", "blob", head + ":" + name],
                                  cwd=ROOT, capture_output=True, check=False)
            require(blob.returncode == 0 and sha256(blob.stdout).hexdigest() == expected,
                    "declared source differs from committed Git blob: " + name)
    return {"head": head, "status_porcelain": status, "files_sha256": files,
            "inventory_sha256": digest(files), "formal_source_admitted": expected_head is not None}


def control_case(model, ledger):
    name = model["name"]
    oracle = timed(ledger, name + ".independent-oracle", lambda: exhaustive_oracle(model))
    exact = timed(ledger, name + ".independent-dp", lambda: exact_dp_control(model))
    require(exact["best_value_q32"] == oracle["best_value_q32"]
            and canonical_schedules(exact) == canonical_schedules(oracle)
            and exact["abstain_is_optimal"] == oracle["abstain_is_optimal"], "independent DP/oracle disagreement")
    fixed = timed(ledger, name + ".fixed-combinations", lambda: fixed_configuration_control(model))
    greedy = timed(ledger, name + ".same-information-greedy", lambda: greedy_control(model))
    production = timed(ledger, name + ".production-q32",
                       lambda: build_request(model, search="dynamic-light"))
    assert_agreement(production, production["advice"], oracle, native=False)
    return {"name": name, "model": model, "model_sha256": digest(model), "oracle": oracle,
            "independent_exact_dp": exact, "strong_fixed_configuration": fixed,
            "same_information_greedy": greedy, "production_exact_q32": production,
            "separability": separability_diagnostic(model),
            "modeled_costs_are_application_measurements": False}


def translation_refusal_probe():
    """Obtain a genuine safe-structure/wrong-behavior refusal before replanning."""
    from hepta.hia_translation_validation import validate_translation
    params = [{"name": "a", "type": "u64"}, {"name": "z", "type": "u64"}]
    before = {"schema": "hepta.hia.program.v1", "module": "stateful_refusal",
              "functions": [{"name": "calculate", "params": params, "returns": ["u64"],
                  "effects": [], "entry": "entry", "blocks": [
                      {"id": "entry", "params": deepcopy(params), "ops": [
                          {"op": "int.add.wrap", "args": ["a", "z"],
                           "out": [{"name": "r", "type": "u64"}], "attrs": {}}],
                       "term": {"op": "ret", "values": ["r"]}}]}]}
    after = deepcopy(before)
    after["functions"][0]["blocks"][0]["ops"][0]["op"] = "int.sub.wrap"
    started = time.monotonic_ns()
    receipt = validate_translation(before, after, timeout_ms=2000)
    elapsed = time.monotonic_ns() - started
    # A missing solver, timeout or unsupported operation never becomes a fake
    # rejection receipt. Return the real failed/pending evidence for the caller.
    result = {"schema": "hepta.hia.ndu.stateful-translation-refusal.v1",
              "before": before, "after": after, "receipt": receipt,
              "actual_attempt_ns": elapsed, "status": "pending-or-failed",
              "native_application_executed": False, "authority": "DENY_ALL",
              "safety_certificate": False}
    if not (receipt["status"] == "disproved"
            and receipt["reason"] == "behavioral_counterexample_replayed"
            and receipt["structural_verification"] == {"before": True, "after": True}
            and receipt["solver"]["result"] == "sat"
            and receipt["counterexample"]["before"] != receipt["counterexample"]["after"]):
        return result, None
    # Record actual loaded solver inputs, not an invented solver identity.
    import z3
    solver_inputs = {str(Path(module.__file__).resolve()):
                     sha256(Path(module.__file__).resolve().read_bytes()).hexdigest()
                     for name, module in list(sys.modules.items())
                     if (name == "z3" or name.startswith("z3.")) and getattr(module, "__file__", None)}
    if Path("/proc/self/maps").is_file():
        for line in Path("/proc/self/maps").read_text().splitlines():
            fields = line.split(maxsplit=5)
            if len(fields) == 6 and "/libz3" in fields[5] and Path(fields[5]).is_file():
                path = Path(fields[5]).resolve()
                solver_inputs[str(path)] = sha256(path.read_bytes()).hexdigest()
    result["solver_inputs_sha256"] = solver_inputs
    result["solver_version"] = z3.get_version_string()
    model = fixtures()[0]
    model["name"] = "actual-translation-refusal"
    model["baseline"]["source_sha256"] = receipt["before_sha256"]
    model["baseline"]["verification_sha256"] = digest(
        {"canonical_before": receipt["before_sha256"], "structurally_verified": True})
    model["variants"][0]["source_sha256"] = receipt["after_sha256"]
    model["variants"][0]["verification_sha256"] = digest("not-yet-translation-admitted")
    model["variants"][0]["status"] = "unknown"
    # Costs of the model remain declared, while this rejected proof attempt is
    # separately observed real work. No candidate is made executable here.
    observation = digest({"receipt": receipt, "actual_attempt_ns": elapsed,
                          "solver_inputs_sha256": solver_inputs})
    successor = observe_refusal(model, variant_id="fast", actual_attempt_ns=elapsed,
                                observation_digest=observation)
    result.update(status="actual-refusal-observed", predecessor_model=model,
                  successor_model_sha256=digest(successor), observation_digest=observation,
                  measured_attempt_scope="existing validate_translation call, including actual structural checks, solver and interpreter replay")
    return result, successor


def native_arm(cases, executable, manifest_path, search, protocol):
    started = time.monotonic_ns()
    result = {"search": search, "ledger": [], "cases": [], "result_cache_entries": 0,
              "status": "running", "authority": "DENY_ALL", "safety_certificate": False}
    session = None
    try:
        from hepta.hia_ndu import NduBridgeError
        from hepta.hia_ndu_session import NduSession
        session = timed(result["ledger"], "session-admission-and-startup",
                        lambda: NduSession.for_stream_profile(executable, manifest_path,
                            timeout=10.0, image_check=protocol["image_check"]))
        require(session.manifest["identity"]["source_commit"] == protocol["native_source_commit"],
                "native source pin differs from protocol")
        result["binary_sha256"] = session.manifest["binary_sha256"]
        result["native_identity"] = session.manifest["identity"]
        for case in cases:
            row = {"name": case["name"], "model_sha256": case["model_sha256"]}
            result["cases"].append(row)
            try:
                bundle = timed(result["ledger"], case["name"] + ".request-construction",
                               lambda: build_request(case["model"], search=search))
            except NduBridgeError as error:
                if search == "enumerate" and "complete enumeration exceeds" in str(error):
                    row.update(status="unsupported-complete-enumeration",
                               error=str(error), native_evaluation=False, partial_optimum_claim=False)
                    continue
                raise
            row["bundle"] = bundle
            response = timed(result["ledger"], case["name"] + ".native-evaluation",
                             lambda: session.evaluate(bundle["request"]))
            row["response"] = response
            timed(result["ledger"], case["name"] + ".independent-oracle-comparison",
                  lambda: assert_agreement(bundle, response, case["oracle"], native=True))
            row.update(status="passed", native_evaluation=True,
                       complete_finite_winning_schedules_agree=True)
        result["status"] = "passed"
    except BaseException as error:
        result.update(status="failed", error=type(error).__name__ + ": " + str(error))
        if session is not None and getattr(session, "_last_received_frame", b""):
            # A malformed/failed native reply remains evidence instead of being
            # discarded in favor of the successful attempts.
            result["last_raw_response_frame_hex"] = session._last_received_frame.hex()
    finally:
        if session is not None:
            try:
                timed(result["ledger"], "session-shutdown", session.close)
            except BaseException as error:
                result.update(status="failed", shutdown_error=type(error).__name__ + ": " + str(error))
            result["session"] = session.snapshot()
        result["wall_ns"] = time.monotonic_ns() - started
    return result


def load_build_envelope(path, protocol, arms):
    if path is None:
        return {"status": "unavailable", "cost_ns": None, "cold_total_claim_allowed": False}
    raw = path.read_bytes()
    value = json.loads(raw)
    require(value["schema"] == "hepta.hia.ndu.stateful-native-build-cost.v1"
            and value["native_source_commit"] == protocol["native_source_commit"]
            and value["exit_code"] == 0 and type(value["observed_outer_wall_ns"]) is int
            and value["observed_outer_wall_ns"] > 0, "invalid actual build envelope")
    require(all(arm.get("binary_sha256") == value["binary_sha256"] for arm in arms),
            "build envelope does not bind the measured native executable")
    return {"status": "observed", "sha256": sha256(raw).hexdigest(), "evidence": value,
            "cost_ns": value["observed_outer_wall_ns"], "source_retrieval_included": False,
            "fully_cold_machine_claim": False}


def qualify(args):
    started = time.monotonic_ns()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    report = {"schema": "hepta.hia.ndu.stateful-study.v1", "status": "running", "mode": args.mode,
              "ledger": [], "cases": [], "native_arms": [],
              "claims": {"native_application_speedup_established": False,
                         "incremental_ndu_value_established": False, "learned_fbsde_evaluated": False,
                         "unrestricted_global_optimality": False},
              "authority": "DENY_ALL", "safety_certificate": False}
    try:
        require(args.mode != "native" or (args.bridge and args.identity and args.expected_head),
                "native mode requires original bridge, manifest and exact committed source HEAD")
        protocol_raw = PROTOCOL_PATH.read_bytes()
        protocol = json.loads(protocol_raw)
        report["protocol"] = protocol
        report["protocol_sha256"] = sha256(protocol_raw).hexdigest()
        report["source_before"] = timed(report["ledger"], "source-admission-before",
                                       lambda: source_identity(args.expected_head))
        report["host"] = {"python": sys.version, "python_executable": sys.executable,
                          "python_sha256": sha256(Path(sys.executable).resolve().read_bytes()).hexdigest(),
                          "platform": platform.platform(), "machine": platform.machine(),
                          "clock": vars(time.get_clock_info("monotonic"))}
        models = timed(report["ledger"], "model-generation", fixtures)
        require([model["name"] for model in models] == protocol["cases"], "case inventory differs")
        for model in models:
            report["cases"].append(control_case(model, report["ledger"]))
        if args.mode == "native":
            refusal, successor = timed(report["ledger"], "actual-translation-refusal",
                                       translation_refusal_probe)
            report["actual_refusal"] = refusal
            require(successor is not None, "real translation refusal not established; retain solver evidence")
            report["cases"].append(control_case(successor, report["ledger"]))
            for search in protocol["native_arms"]:
                arm = native_arm(report["cases"], args.bridge, args.identity, search, protocol)
                report["native_arms"].append(arm)
            report["native_build"] = load_build_envelope(args.build_envelope, protocol, report["native_arms"])
            require(all(arm["status"] == "passed" for arm in report["native_arms"]),
                    "at least one real native arm failed; partial evidence retained")
            require(all(row["status"] == "passed" for row in report["native_arms"][1]["cases"]),
                    "compact native path did not cover every model")
            report["native_status"] = "actual-original-evaluator-agrees-on-finite-models"
        else:
            report["native_status"] = "pending-original-native-evaluation"
            report["native_build"] = {"status": "not-invoked", "cost_ns": None}
            report["actual_refusal"] = {"status": "not-invoked-in-controls-mode"}
        report["source_after"] = timed(report["ledger"], "source-admission-after",
                                      lambda: source_identity(args.expected_head))
        require(report["source_before"] == report["source_after"], "source changed during the study")
        report["status"] = "passed"
    except BaseException as error:
        report.update(status="failed", error=type(error).__name__ + ": " + str(error))
    report["wall_ns_before_final_encoding"] = time.monotonic_ns() - started
    report["accounting_scope"] = {
        "actual_controller_and_native_costs_ns": True,
        "fixture_ns_are_declared_model_costs": True,
        "native_application_execution": False,
        "outer_process_startup_imports_final_encoding_and_storage": "excluded; require separate outer receipt",
        "training_cost": "not performed; no model credentials or learned policy",
        "native_build_cost": "separate observed envelope, or explicitly unavailable",
        "source_retrieval_cost": "not included",
        "failed_attempts_included": True,
        "modeled_utility_minus_actual_host_cost_is_real_speedup": False}
    path = output / "REPORT.json"
    with path.open("x") as stream:
        stream.write(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report, path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--mode", choices=("controls", "native"), default="controls")
    parser.add_argument("--expected-head")
    parser.add_argument("--bridge", type=Path)
    parser.add_argument("--identity", type=Path)
    parser.add_argument("--build-envelope", type=Path)
    report, path = qualify(parser.parse_args())
    print(json.dumps({"status": report["status"], "native_status": report.get("native_status"),
                      "report": str(path), "error": report.get("error")}))
    raise SystemExit(0 if report["status"] == "passed" else 1)


if __name__ == "__main__":
    main()
