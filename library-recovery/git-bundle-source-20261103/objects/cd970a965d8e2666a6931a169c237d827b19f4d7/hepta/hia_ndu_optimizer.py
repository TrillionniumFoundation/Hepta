"""Finite, proof-gated proposals ranked by the original native NDU evaluator.

Measurements are explicit trusted-host observations, not safety certificates.
Every proposal is reverified and compared with the incumbent by the independent
translation validator. NDU is advisory; a selected proposal is proved again.
The conservative cost includes all supplied search costs and this invocation's
actual wall time. Native publication must additionally pay its preparation cost.
"""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import re
import stat
import subprocess
import time

from .hia_program import verify_program
from .hia_translation_validation import PROFILE as PROOF_PROFILE, SCHEMA as PROOF_SCHEMA, validate_translation

SCHEMA = "hepta.hia.ndu-optimization.v1"
ROOT = Path(__file__).resolve().parents[1]
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[a-zA-Z][a-zA-Z0-9_.:-]{0,63}\Z")
_MAX_INT = (1 << 63) - 1


class OptimizationRejected(ValueError):
    """Malformed inputs or a broken proof/evaluator identity fail closed."""


def _reject(message):
    raise OptimizationRejected("E_HIA_NDU: " + message)


def _bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def _digest(value):
    return sha256(_bytes(value)).hexdigest()


def _integer(value, name, *, minimum=0, maximum=_MAX_INT):
    if type(value) is not int or not minimum <= value <= maximum:
        _reject(name + " must be a bounded exact integer")
    return value


def ns_to_ms_q32(value):
    """Exact nonnegative ns -> signed Q32.32 milliseconds, ties to even.

    Overflow rejects; no clipping, float conversion or hidden renormalization.
    """
    _integer(value, "nanoseconds")
    quotient, remainder = divmod(value * (1 << 32), 1_000_000)
    if remainder * 2 > 1_000_000 or remainder * 2 == 1_000_000 and quotient % 2:
        quotient += 1
    if quotient > _MAX_INT:
        _reject("cost exceeds the Q32.32 millisecond range")
    return quotient


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _reject("duplicate JSON key")
        result[key] = value
    return result


def _json(data):
    try:
        return json.loads(data, object_pairs_hook=_unique_object,
                          parse_constant=lambda value: _reject("non-finite JSON number"))
    except (TypeError, UnicodeError, json.JSONDecodeError) as error:
        _reject("invalid JSON: " + str(error))


def _read_file(path, limit):
    with path.open("rb") as stream:
        before = stream.fileno()
        import os
        info = os.fstat(before)
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= limit:
            _reject("expected bounded regular file: " + str(path))
        data = stream.read(limit + 1)
        after = os.fstat(before)
        if (info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            _reject("file changed during read")
        if len(data) != info.st_size:
            _reject("file length changed during read")
        return data


def _bridge_identity(bridge):
    if type(bridge) is not dict or set(bridge) != {"binary", "build_receipt"}:
        _reject("bridge requires binary and build_receipt paths")
    binary = Path(bridge["binary"]).resolve()
    receipt_path = Path(bridge["build_receipt"]).resolve()
    receipt_bytes = _read_file(receipt_path, 4 * 1024 * 1024)
    receipt = _json(receipt_bytes)
    locked = _json((ROOT / "rust/hia-ndu-bridge/upstream.json").read_bytes())
    expected = {"schema": "hepta.hia.ndu-build.v1", "upstream": locked,
                "original_rust_sources_unchanged": True,
                "all_original_non_manifest_inputs_unchanged": True,
                "build_inputs_unchanged": True, "locked_dependencies": True,
                "isolated_production_manifests": True, "production_activation": False}
    if type(receipt) is not dict or any(receipt.get(k) != v for k, v in expected.items()):
        _reject("bridge build receipt has wrong source, scope or build gates")
    adapter = ROOT / "rust/hia-ndu-bridge"
    inputs = {str(p.relative_to(adapter)): sha256(p.read_bytes()).hexdigest()
              for p in sorted(adapter.rglob("*")) if p.is_file()}
    if (receipt.get("adapter_files") != inputs
            or receipt.get("cargo_lock_sha256") != inputs.get("Cargo.lock")
            or receipt.get("builder_sha256") != sha256((ROOT / "tools/build_hia_ndu_bridge.py").read_bytes()).hexdigest()):
        _reject("bridge adapter, lock or builder differs from the recorded build")
    data = _read_file(binary, 128 * 1024 * 1024)
    binary_sha = sha256(data).hexdigest()
    if binary_sha != receipt.get("binary_sha256"):
        _reject("bridge executable differs from the recorded build")
    return binary, {"upstream_commit": locked["commit"], "binary_sha256": binary_sha,
                    "build_receipt_sha256": sha256(receipt_bytes).hexdigest(),
                    "build_inputs_sha256": _digest(receipt.get("build_inputs")),
                    "source_attestation": "trusted_local_build_receipt"}


def _native_rank(bridge, request, *, timeout_s):
    binary, identity = _bridge_identity(bridge)
    data = _bytes(request)
    if len(data) > 1024 * 1024:
        _reject("native request exceeds byte limit")
    try:
        completed = subprocess.run([str(binary)], input=data, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, timeout=timeout_s, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        _reject("native evaluator could not complete: " + str(error))
    # The pinned bridge itself bounds input/candidates and its resulting output.
    # This is a trusted local executable, not a sandbox for arbitrary binaries.
    if completed.returncode or len(completed.stdout) > 1024 * 1024 or len(completed.stderr) > 1024 * 1024:
        _reject("native evaluator failed or exceeded output bounds")
    if sha256(_read_file(binary, 128 * 1024 * 1024)).hexdigest() != identity["binary_sha256"]:
        _reject("native evaluator changed during invocation")
    response = _json(completed.stdout)
    expected = {"schema": "hepta.hia.ndu-response.v1", "upstream_commit": identity["upstream_commit"],
                "entry_point": "codex_hepta_ndu::evaluate_candidates_with_policy",
                "objective_sha256": request["objective_sha256"], "generation": request["generation"],
                "request_sha256": sha256(data).hexdigest(), "authority": "ADVISORY_ONLY",
                "proves_program_safety": False, "global_optimality_established": False}
    if type(response) is not dict or any(response.get(k) != v for k, v in expected.items()):
        _reject("native evaluator response does not bind the exact request")
    for key in ("evaluation_digest_v2", "evaluation_policy_digest", "utility_profile_digest"):
        if type(response.get(key)) is not str or not _HEX.fullmatch(response[key]):
            _reject("native evaluator returned a malformed digest")
    recommendation = response.get("advisory_recommendation")
    rows = {row["id"]: row for row in request["candidates"]}
    if recommendation is not None and (recommendation not in rows or rows[recommendation]["hard_violation"]):
        _reject("native evaluator recommended an unavailable or unproved candidate")
    return response, identity


def _same_other_functions(before, after, function):
    def remainder(program):
        document = program.as_dict()
        document["functions"] = [fn for fn in document["functions"] if fn["name"] != function]
        return document
    return remainder(before) == remainder(after)


def _fresh_proof(before, after, function, timeout_ms):
    proof = validate_translation(before, after, function=function, timeout_ms=timeout_ms)
    expected = {"schema": PROOF_SCHEMA, "profile": PROOF_PROFILE, "status": "proved",
                "scope": "selected_public_scalar_function", "function": function,
                "before_sha256": before.sha256, "after_sha256": after.sha256,
                "before_input_sha256": before.input_sha256, "after_input_sha256": after.input_sha256}
    proved = type(proof) is dict and all(proof.get(k) == v for k, v in expected.items())
    return proved, proof


def rank_candidates(baseline, candidates, observations, *, function, bridge, objective,
                    generation=1, timeout_ms=2000, bridge_timeout_s=10.0):
    """Return a fresh, bounded decision; never execute or publish a candidate.

    observations: id -> {runtime_ns, uncertainty_ns, search_ns, program_sha256}.
    Runtime costs are per call; uncertainty is an absolute conservative radius.
    Search costs include generation, compilation and measurement already incurred.
    Every row's search cost is charged once to the entire search, including losing
    candidates and baseline measurement. The incumbent ('abstain') already exists.
    """
    started = time.perf_counter_ns()
    before = verify_program(baseline)
    if type(function) is not str or function not in before.scalar_entrypoints:
        _reject("function must name an existing public scalar entrypoint")
    _integer(generation, "generation", minimum=1, maximum=(1 << 64) - 1)
    _integer(timeout_ms, "timeout_ms", minimum=1, maximum=5000)
    if type(bridge_timeout_s) not in (int, float) or not 0 < bridge_timeout_s <= 60:
        _reject("bridge timeout must be finite and at most sixty seconds")
    if type(objective) is not dict or set(objective) != {"expected_calls", "resource_cap_ns", "target", "measurement_profile"}:
        _reject("objective has an unexpected shape")
    objective = _json(_bytes(objective))
    calls = _integer(objective["expected_calls"], "expected_calls", minimum=1)
    cap = _integer(objective["resource_cap_ns"], "resource_cap_ns")
    for field in ("target", "measurement_profile"):
        if type(objective[field]) is not str or not 1 <= len(objective[field]) <= 256:
            _reject("objective " + field + " must be bounded text")
    ns_to_ms_q32(cap)
    if type(candidates) is not list or len(candidates) > 32:
        _reject("at most thirty-two finite proposals are allowed")
    prepared, seen = [], {"abstain"}
    for raw in candidates:
        if type(raw) is not dict or set(raw) != {"id", "action", "program"}:
            _reject("candidate requires only id, action and program")
        cid, action = raw["id"], raw["action"]
        if type(cid) is not str or not _ID.fullmatch(cid) or cid in seen:
            _reject("candidate id is invalid, reserved or duplicated")
        if type(action) is not str or not 1 <= len(action) <= 256:
            _reject("candidate action must be bounded text")
        seen.add(cid)
        try:
            program = verify_program(raw["program"])
        except (TypeError, ValueError) as error:
            prepared.append({"id": cid, "action": action, "program": None,
                             "reason": "canonical_verifier_rejected", "detail": str(error)[:1024]})
        else:
            prepared.append({"id": cid, "action": action, "program": program})
    if type(observations) is not dict or set(observations) != seen:
        _reject("observations must cover exactly abstain and all proposals")
    observed = {}
    for cid, observation in observations.items():
        if type(observation) is not dict or set(observation) != {"runtime_ns", "uncertainty_ns", "search_ns", "program_sha256"}:
            _reject("observation has an unexpected shape")
        if type(observation["program_sha256"]) is not str or not _HEX.fullmatch(observation["program_sha256"]):
            _reject("observation must identify exact canonical program bytes")
        observed[cid] = dict(observation)
        for field in ("runtime_ns", "uncertainty_ns", "search_ns"):
            _integer(observation[field], field)
    if observed["abstain"]["program_sha256"] != before.sha256:
        _reject("baseline measurement belongs to a different program")
    candidate_reports, checked = [], {}
    for candidate in prepared:
        cid, program = candidate["id"], candidate["program"]
        report = {"id": cid, "action": candidate["action"], "core_verified": program is not None,
                  "observation": observed[cid], "equivalence_proved": False, "proof": None}
        if program is None:
            report.update({k: candidate[k] for k in ("reason", "detail")})
        elif observed[cid]["program_sha256"] != program.sha256:
            _reject("candidate measurement belongs to a different program: " + cid)
        elif not _same_other_functions(before, program, function):
            report["reason"] = "unselected_function_or_module_changed"
        else:
            proved, proof = _fresh_proof(before, program, function, timeout_ms)
            report.update(equivalence_proved=proved, proof=proof,
                          reason="proved" if proved else "behavior_not_proved")
            if proved:
                checked[cid] = program
        candidate_reports.append(report)
    supplied_search_ns = sum(row["search_ns"] for row in observed.values())
    _integer(supplied_search_ns, "aggregate measured search cost")
    elapsed_before_rank = time.perf_counter_ns() - started
    search_at_rank = supplied_search_ns + elapsed_before_rank
    base_lower = max(0, observed["abstain"]["runtime_ns"] - observed["abstain"]["uncertainty_ns"])
    objective_sha = _digest({"schema": SCHEMA, "objective": objective, "function": function,
                             "before_sha256": before.sha256, "before_input_sha256": before.input_sha256})
    rows = [{"id": "abstain", "cost_q32": ns_to_ms_q32(base_lower * calls),
             "uncertainty_q32": ns_to_ms_q32(observed["abstain"]["uncertainty_ns"] * calls),
             "resource_q32": 0, "hard_violation": False,
             "support_sha256": _digest({"program": before.sha256, "observation": observed["abstain"]})}]
    for report in candidate_reports:
        cid, observation = report["id"], observed[report["id"]]
        robust_total = (observation["runtime_ns"] + observation["uncertainty_ns"]) * calls + search_at_rank
        rows.append({"id": cid, "cost_q32": ns_to_ms_q32(robust_total),
                     "uncertainty_q32": ns_to_ms_q32(observation["uncertainty_ns"] * calls),
                     "resource_q32": ns_to_ms_q32(search_at_rank),
                     "hard_violation": not report["equivalence_proved"],
                     "support_sha256": _digest(report)})
    request = {"schema": "hepta.hia.ndu-request.v1", "objective_sha256": objective_sha,
               "generation": generation, "resource_cap_q32": ns_to_ms_q32(cap), "candidates": rows}
    response, bridge_info = _native_rank(bridge, request, timeout_s=bridge_timeout_s)
    selected = response["advisory_recommendation"] or "abstain"
    final_proof, reason = None, "native_evaluator_abstained"
    if selected != "abstain":
        if selected not in checked:
            _reject("advisory result has no independently proved program")
        proved, final_proof = _fresh_proof(before, checked[selected], function, timeout_ms)
        if not proved:
            selected, reason = "abstain", "selected_candidate_fresh_proof_failed"
    actual_adapter_ns = time.perf_counter_ns() - started
    total_search_ns = supplied_search_ns + actual_adapter_ns
    margin = 0
    if selected != "abstain":
        row = observed[selected]
        margin = base_lower * calls - (row["runtime_ns"] + row["uncertainty_ns"]) * calls - total_search_ns
        if total_search_ns > cap:
            selected, reason = "abstain", "actual_search_budget_exceeded"
        elif margin <= 0:
            selected, reason = "abstain", "no_robust_net_saving_after_search"
        else:
            reason = "fresh_proof_and_robust_cost_gate_passed"
    admitted = selected != "abstain"
    return {"schema": SCHEMA, "before_sha256": before.sha256, "before_input_sha256": before.input_sha256,
            "function": function, "generation": generation, "objective": objective,
            "objective_sha256": objective_sha, "observations_sha256": _digest(observed),
            "selected_id": selected, "admitted": admitted, "reason": reason,
            "selected_program": (checked[selected] if admitted else before).as_dict(),
            "net_margin_ns": max(0, margin) if admitted else 0,
            "costs": {"supplied_search_ns": supplied_search_ns, "actual_adapter_ns": actual_adapter_ns,
                      "total_search_ns": total_search_ns, "search_at_native_rank_ns": search_at_rank,
                      "publication_preparation_included": False},
            "candidate_reports": candidate_reports, "selected_fresh_proof": final_proof,
            "native_request": request, "request_sha256": sha256(_bytes(request)).hexdigest(),
            "native_response": response, "bridge": bridge_info,
            "claims": {"ndu_is_advisory": True, "unproved_candidate_admitted": False,
                       "all_other_functions_unchanged": True, "resource_bounds_proved": False,
                       "measurements_independently_attested": False, "native_backend_refinement_proved": False,
                       "global_optimality_established": False, "incremental_advantage_established": False},
            "cost_model": "incumbent lower bound versus candidate upper bound; all search charged once; trusted host observations"}
