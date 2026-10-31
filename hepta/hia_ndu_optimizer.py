"""Finite, proof-gated proposals ranked by the original native NDU evaluator.

Measurements are explicit trusted-host observations, not safety certificates.
Every proposal is reverified and compared with the incumbent by the independent
translation validator. NDU is advisory; a selected proposal is proved again.
The conservative cost includes all supplied search costs and this invocation's
actual wall time. Native publication must additionally pay its preparation cost.
Proof admission and solver timeouts use the shared remaining search budget and
possible net saving. Solver/host overhead may still overshoot; final admission
then keeps the incumbent. This is not a hard physical execution-time bound.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

from .hia_program import verify_program
from .hia_rust_crosscheck import HIARustCrosscheckRejected, _run_bounded_shadow
from .hia_translation_validation import PROFILE as PROOF_PROFILE, SCHEMA as PROOF_SCHEMA, validate_translation

SCHEMA = "hepta.hia.ndu-optimization.v1"
ROOT = Path(__file__).resolve().parents[1]
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[a-zA-Z][a-zA-Z0-9_.:-]{0,63}\Z")
_MAX_INT = (1 << 63) - 1


class OptimizationRejected(ValueError):
    """Malformed inputs or a broken proof/evaluator identity fail closed."""


class _NativeBudgetExhausted(OptimizationRejected):
    """The admitted native image was not launched before its budget expired."""


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
    """Read one bounded regular inode without blocking on an unwritten FIFO."""
    if sys.platform != "linux":
        _reject("native evaluator identity requires Linux")
    fd = None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= limit:
            _reject("expected bounded regular file: " + str(path))
        chunks = []
        remaining = info.st_size + 1
        while remaining:
            chunk = os.read(fd, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        after = os.fstat(fd)
        identity = lambda value: (value.st_dev, value.st_ino, value.st_size,
                                  value.st_mtime_ns, value.st_ctime_ns)
        if identity(info) != identity(after):
            _reject("file changed during read")
        if len(data) != info.st_size:
            _reject("file length changed during read")
        return data
    except OSError as error:
        raise OptimizationRejected("E_HIA_NDU: bounded regular file read failed") from error
    finally:
        if fd is not None:
            os.close(fd)


@dataclass(frozen=True)
class _VerifiedBridgeImage:
    path: Path
    data: bytes


def _seal_bridge_image(raw):
    """Transfer ownership of a sealed descriptor for already-verified bytes.

    No pathname is reopened here. A mutable-path ABA after build admission
    therefore cannot replace the executable passed to the child. The trusted
    host's interpreter/ELF loader and libraries remain outside this byte pin.
    """
    fd = None
    transferred = False
    try:
        import fcntl
        fd = os.memfd_create("hepta-ndu-ranking", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        os.fchmod(fd, 0o700)
        remaining = memoryview(raw)
        while remaining:
            count = os.write(fd, remaining)
            if count <= 0:
                _reject("sealed native snapshot write made no progress")
            remaining = remaining[count:]
        # Linux UAPI values also support Python built against older headers;
        # the kernel operations and complete seal/byte readback are mandatory.
        seals = (getattr(fcntl, "F_SEAL_WRITE", 0x0008)
                 | getattr(fcntl, "F_SEAL_GROW", 0x0004)
                 | getattr(fcntl, "F_SEAL_SHRINK", 0x0002)
                 | getattr(fcntl, "F_SEAL_SEAL", 0x0001))
        fcntl.fcntl(fd, getattr(fcntl, "F_ADD_SEALS", 1033), seals)
        if (os.fstat(fd).st_size != len(raw)
                or fcntl.fcntl(fd, getattr(fcntl, "F_GET_SEALS", 1034)) & seals != seals
                or os.pread(fd, len(raw), 0) != raw):
            _reject("sealed executable snapshot does not retain the admitted bytes and seals")
        transferred = True
        return fd
    except (OSError, AttributeError, ImportError) as error:
        raise OptimizationRejected("E_HIA_NDU: sealed executable snapshot unavailable") from error
    finally:
        if fd is not None and not transferred:
            os.close(fd)


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
    return _VerifiedBridgeImage(binary, data), {
        "upstream_commit": locked["commit"], "binary_sha256": binary_sha,
        "build_receipt_sha256": sha256(receipt_bytes).hexdigest(),
        "build_inputs_sha256": _digest(receipt.get("build_inputs")),
        "source_attestation": "trusted_local_build_receipt"}


def _native_rank(bridge, request, *, timeout_s):
    # Identity admission and sealing belong to this call's budget too. Starting
    # a fresh subprocess timeout after those operations would renew spent time.
    # The shared runner's execution timer starts after ownership checks/Popen;
    # startup and scheduling are not preemptible here. All observed time still
    # reaches the final search-cost gate; this is not a hard wall-clock quota.
    deadline = time.perf_counter_ns() + int(timeout_s * 1_000_000_000)

    def remaining_seconds():
        remaining = deadline - time.perf_counter_ns()
        if remaining <= 0:
            raise _NativeBudgetExhausted("E_HIA_NDU: native budget exhausted before process start")
        return remaining / 1_000_000_000

    image, identity = _bridge_identity(bridge)
    data = _bytes(request)
    if len(data) > 1024 * 1024:
        _reject("native request exceeds byte limit")
    remaining_seconds()
    try:
        fd = _seal_bridge_image(image.data)
        try:
            stdout, stderr, returncode = _run_bounded_shadow(
                ["/proc/self/fd/" + str(fd)], data, remaining_seconds(),
                maximum_output=1024 * 1024 + 1, pass_fds=(fd,))
        finally:
            os.close(fd)
    except (OSError, HIARustCrosscheckRejected) as error:
        _reject("native evaluator could not complete: " + str(error))
    # The pump bounds output during execution and owns process-group cleanup.
    # This remains a trusted local bridge, not a sandbox for arbitrary code.
    if returncode or len(stdout) > 1024 * 1024 or len(stderr) > 1024 * 1024:
        _reject("native evaluator failed or exceeded output bounds")
    if sha256(_read_file(image.path, 128 * 1024 * 1024)).hexdigest() != identity["binary_sha256"]:
        _reject("native evaluator changed during invocation")
    response = _json(stdout)
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
    Every proof, including the final selected proof, shares that same cap. A
    sub-millisecond allowance cannot launch the solver's minimum 1 ms timeout.
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
    supplied_search_ns = sum(row["search_ns"] for row in observed.values())
    _integer(supplied_search_ns, "aggregate measured search cost")
    base_lower = max(0, observed["abstain"]["runtime_ns"] - observed["abstain"]["uncertainty_ns"])
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
            spent_lower = supplied_search_ns + time.perf_counter_ns() - started
            candidate_upper = (observed[cid]["runtime_ns"] + observed[cid]["uncertainty_ns"]) * calls
            remaining_budget = cap - spent_lower
            remaining_margin = base_lower * calls - candidate_upper - spent_lower
            # Already paid cost cannot decrease. These tests may refuse work,
            # never approve a candidate or claim behavioral equivalence.
            # Keep canonical admission and measurement bindings above. Native
            # advice below is available only inside the same remaining budget;
            # retaining the incumbent never needs a fabricated NDU receipt.
            report["preproof_cost_lower_bound_ns"] = spent_lower
            report["proof_remaining_budget_ns"] = remaining_budget
            report["proof_remaining_margin_ns"] = remaining_margin
            if remaining_budget <= 0:
                report["reason"] = "search_budget_exhausted_before_proof"
            elif remaining_margin <= 0:
                report["reason"] = "cost_dominated_before_proof"
            elif remaining_budget < 1_000_000:
                report["reason"] = "search_budget_insufficient_for_proof"
            elif remaining_margin <= 1_000_000:
                report["reason"] = "cost_margin_insufficient_for_proof"
            else:
                # Round down and leave a strictly positive possible net margin;
                # never turn a fractional millisecond into extra solver budget.
                proof_timeout_ms = min(timeout_ms, remaining_budget // 1_000_000,
                                       (remaining_margin - 1) // 1_000_000)
                proof_started = time.perf_counter_ns()
                proved, proof = _fresh_proof(before, program, function, proof_timeout_ms)
                report.update(equivalence_proved=proved, proof=proof,
                              proof_timeout_ms=proof_timeout_ms,
                              proof_wall_ns=time.perf_counter_ns() - proof_started,
                              reason="proved" if proved else "behavior_not_proved")
                if proved:
                    checked[cid] = program
        candidate_reports.append(report)
    elapsed_before_rank = time.perf_counter_ns() - started
    search_at_rank = supplied_search_ns + elapsed_before_rank
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
    remaining_native_ns = cap - supplied_search_ns - (time.perf_counter_ns() - started)
    native_admission = {"invoked": False, "remaining_budget_ns": remaining_native_ns,
                        "timeout_s": None, "reason": "search_budget_exhausted_before_native"}
    response, bridge_info, selected = None, None, "abstain"
    final_proof, reason = None, native_admission["reason"]
    if remaining_native_ns > 0:
        native_admission["timeout_s"] = min(bridge_timeout_s, remaining_native_ns / 1_000_000_000)
        try:
            response, bridge_info = _native_rank(bridge, request, timeout_s=native_admission["timeout_s"])
        except _NativeBudgetExhausted:
            native_admission["reason"] = reason = "native_identity_admission_exhausted_budget"
        else:
            native_admission.update(invoked=True, reason="actual_native_response_received")
            selected = response["advisory_recommendation"] or "abstain"
            reason = "native_evaluator_abstained"
    final_proof_admission = None
    if selected != "abstain":
        if selected not in checked:
            _reject("advisory result has no independently proved program")
        spent_lower = supplied_search_ns + time.perf_counter_ns() - started
        row = observed[selected]
        remaining_budget = cap - spent_lower
        remaining_margin = base_lower * calls - (row["runtime_ns"] + row["uncertainty_ns"]) * calls - spent_lower
        final_proof_admission = {"candidate_id": selected, "spent_search_ns": spent_lower,
                                 "remaining_budget_ns": remaining_budget,
                                 "remaining_margin_ns": remaining_margin,
                                 "solver_started": False}
        if remaining_budget < 0:
            selected, reason = "abstain", "actual_search_budget_exceeded"
        elif remaining_margin <= 0:
            selected, reason = "abstain", "no_robust_net_saving_after_search"
        elif remaining_budget < 1_000_000:
            selected, reason = "abstain", "selected_proof_budget_insufficient"
        elif remaining_margin <= 1_000_000:
            selected, reason = "abstain", "selected_proof_margin_insufficient"
        else:
            proof_timeout_ms = min(timeout_ms, remaining_budget // 1_000_000,
                                   (remaining_margin - 1) // 1_000_000)
            final_proof_admission.update(solver_started=True, timeout_ms=proof_timeout_ms)
            proof_started = time.perf_counter_ns()
            proved, final_proof = _fresh_proof(before, checked[selected], function, proof_timeout_ms)
            final_proof_admission["wall_ns"] = time.perf_counter_ns() - proof_started
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
            "selected_proof_admission": final_proof_admission,
            "native_rank_admission": native_admission,
            "native_request": request, "request_sha256": sha256(_bytes(request)).hexdigest(),
            "native_response": response, "bridge": bridge_info,
            "claims": {"ndu_is_advisory": True, "unproved_candidate_admitted": False,
                       "all_other_functions_unchanged": True, "resource_bounds_proved": False,
                       "measurements_independently_attested": False, "native_backend_refinement_proved": False,
                       "global_optimality_established": False, "incremental_advantage_established": False},
            "cost_model": "incumbent lower bound versus candidate upper bound; all search charged once; trusted host observations"}
