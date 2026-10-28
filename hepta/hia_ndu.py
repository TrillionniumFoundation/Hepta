"""A bounded compiler-candidate protocol for the real, pinned NDU evaluator.

The optimizer and the evaluator are separate trust boundaries. A registered
rewrite is reproduced from immutable Core bytes; timing samples are evidence,
not a proof. NDU advice never installs code or authorizes execution.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
import re
from statistics import median
from time import perf_counter_ns
from types import MappingProxyType

from .clang_capture import run_bounded
from .hia_program import VerifiedProgram, verify_program
from .hia_program_runtime import HIAProgramBudgetExceeded, HIAProgramTrap, execute_program
from .hia_schema import SCHEMA, SCHEMA_V2, SCHEMA_V3, SCHEMA_V4, SCHEMA_V5, SCHEMA_V6
from .hia_swap_opt import rewrite_byte_swap
from .hia_fill_loop_opt import PASS_ID as FILL_LOOP_PASS_ID, rewrite_full_view_fill_loop
from .hia_checked_reduction_opt import PASS_ID as REDUCTION_PASS_ID, rewrite_checked_unsigned_reduction
from .native_tool_identity import digest_executable

UPSTREAM_COMMIT = "f8c9419df6ddeb36ff8b522a50219981fb8d9345"
PLAN_SCHEMA = "hepta.hia.ndu-plan.v1"
PASS_ID = "byte-swap.v1"
_REWRITES = MappingProxyType({PASS_ID: rewrite_byte_swap,
                             FILL_LOOP_PASS_ID: rewrite_full_view_fill_loop,
                             REDUCTION_PASS_ID: rewrite_checked_unsigned_reduction})
_CANDIDATE_IDS = MappingProxyType({PASS_ID: "byte_swap", FILL_LOOP_PASS_ID: "fill_loop",
                                 REDUCTION_PASS_ID: "checked_reduction"})
REGISTERED_PASSES = tuple(_REWRITES)
DECISION_RESERVE_NS = 2_000_000_000
_SCHEMAS = {SCHEMA, SCHEMA_V2, SCHEMA_V3, SCHEMA_V4, SCHEMA_V5, SCHEMA_V6}
_HEX = re.compile(r"[0-9a-f]{64}")


class HIANDURejected(ValueError):
    """A candidate, plan, tool identity, or measurement violates this profile."""


def _reject(message):
    raise HIANDURejected("E_HIA_NDU: " + message)


def _integer(value, lower, upper, label):
    if type(value) is not int or not lower <= value <= upper:
        _reject(label + " is outside the bounded integer profile")
    return value


def _digest(value, label):
    if type(value) is not str or _HEX.fullmatch(value) is None or value == "0" * 64:
        _reject(label + " must be a nonzero lowercase SHA-256")
    return value


def _object(value, keys, label):
    if type(value) is not dict or set(value) != set(keys):
        _reject(label + " has missing or unknown fields")


def canonical(value):
    """Encode already validated protocol values, with no NaN representation."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def identity(value):
    return sha256(canonical(value)).hexdigest()


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _reject("duplicate JSON field")
        result[key] = value
    return result


def read_json(payload, *, limit=1_048_576):
    if type(payload) not in (str, bytes) or len(payload) > limit:
        _reject("bounded JSON bytes required")
    try:
        return json.loads(payload, object_pairs_hook=_pairs,
                          parse_constant=lambda _: _reject("nonfinite JSON number"))
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise HIANDURejected("E_HIA_NDU: invalid protocol JSON") from exc


def make_plan(baseline, *, entry, generation=1, horizon_calls=100_000_000, pass_id=PASS_ID):
    checked = verify_program(baseline)
    if type(pass_id) is not str or pass_id not in _REWRITES:
        _reject("unregistered transformation")
    return {"schema": PLAN_SCHEMA, "baseline_sha256": checked.sha256,
            "pass_id": pass_id, "entry": entry, "generation": generation,
            "objective": {"horizon_calls": horizon_calls,
                          "maximum_live_bytes": 16 * 1024 * 1024,
                          "maximum_artifact_bytes": 64 * 1024 * 1024,
                          "maximum_search_ns": 60_000_000_000,
                          "minimum_gain_ppm": 20_000,
                          "maximum_mad_ppm": 50_000}}


def _objective(objective):
    _object(objective, ("horizon_calls", "maximum_live_bytes", "maximum_artifact_bytes",
                        "maximum_search_ns", "minimum_gain_ppm", "maximum_mad_ppm"), "objective")
    for key, lo, hi in (("horizon_calls", 1, 1_000_000_000_000),
                       ("maximum_live_bytes", 1, 1 << 30),
                       ("maximum_artifact_bytes", 1, 64 << 20),
                       ("maximum_search_ns", 1, 3_600_000_000_000),
                       ("minimum_gain_ppm", 0, 1_000_000),
                       ("maximum_mad_ppm", 1, 50_000)):
        _integer(objective[key], lo, hi, key)


@dataclass(frozen=True, slots=True)
class PreparedCandidate:
    baseline: VerifiedProgram
    candidate: VerifiedProgram
    plan_bytes: bytes
    replacements: int

    @property
    def plan(self):
        return read_json(self.plan_bytes)

    @property
    def plan_sha256(self):
        return sha256(self.plan_bytes).hexdigest()

    @property
    def candidate_id(self):
        return _CANDIDATE_IDS[self.plan["pass_id"]]


def prepare_candidate(baseline, plan, *, candidate_bytes=None):
    """Reverify both programs and reproduce the exact registered transformation.

    A caller's nominal VerifiedProgram or "feasible" flag is not a witness.
    Composite/v7 programs remain outside this adapter's registered contract.
    The public byte-swap API separately preserves v7 and rejects composites.
    """
    checked = verify_program(baseline)
    if checked.structured_bytes is not None or checked.as_dict()["schema"] not in _SCHEMAS:
        _reject("the candidate adapter supports primitive v1-v6 only")
    _object(plan, ("schema", "baseline_sha256", "pass_id", "entry", "generation", "objective"), "plan")
    if (plan["schema"] != PLAN_SCHEMA or type(plan["pass_id"]) is not str
            or plan["pass_id"] not in _REWRITES):
        _reject("unregistered plan schema or transformation")
    if _digest(plan["baseline_sha256"], "baseline identity") != checked.sha256:
        _reject("stale baseline identity")
    if type(plan["entry"]) is not str or plan["entry"] not in checked.scalar_entrypoints:
        _reject("a scalar public entry is required")
    _integer(plan["generation"], 1, (1 << 63) - 1, "generation")
    _objective(plan["objective"])
    rewrite = _REWRITES[plan["pass_id"]](checked)
    candidate = verify_program(rewrite.program.canonical_bytes)
    if candidate_bytes is not None:
        if type(candidate_bytes) is not bytes:
            _reject("candidate exchange requires immutable bytes")
        supplied = verify_program(candidate_bytes)
        if supplied.canonical_bytes != candidate.canonical_bytes:
            _reject("candidate differs from the reproduced registered rewrite")
    return PreparedCandidate(checked, candidate, canonical(plan), rewrite.replacements)


def assess_samples(raw_samples, *, calls_per_sample, objective, search_cost_ns,
                   baseline_artifact_sha256=None, candidate_artifact_sha256=None):
    """Conservative measurement policy; this is not a statistical proof.

    Raw samples are never trimmed. The median saving must exceed three median
    absolute deviations and the requested relative margin. Individual timing
    noise is capped at five percent or a tighter caller-selected limit.
    """
    _objective(objective)
    if type(raw_samples) is not list or not 15 <= len(raw_samples) <= 63 or len(raw_samples) % 2 != 1:
        _reject("15..63 odd paired samples required")
    _integer(calls_per_sample, 1, 64_000_000, "calls_per_sample")
    _integer(search_cost_ns, 0, 3_600_000_000_000, "search cost")
    baseline, candidate = [], []
    for sample in raw_samples:
        if type(sample) is not dict:
            _reject("sample must be an object")
        baseline.append(_integer(sample.get("baseline_ns"), 1, 60_000_000_000, "baseline sample"))
        candidate.append(_integer(sample.get("candidate_ns"), 1, 60_000_000_000, "candidate sample"))
    med_b, med_c = int(median(baseline)), int(median(candidate))
    deviations_b = int(median([abs(v - med_b) for v in baseline]))
    deviations_c = int(median([abs(v - med_c) for v in candidate]))
    savings = [b - c for b, c in zip(baseline, candidate)]
    saving = int(median(savings))
    saving_mad = int(median([abs(v - saving) for v in savings]))
    reasons = []
    identity_checked = baseline_artifact_sha256 is not None or candidate_artifact_sha256 is not None
    native_changed = None
    if identity_checked:
        baseline_identity = _digest(baseline_artifact_sha256, "baseline artifact identity")
        candidate_identity = _digest(candidate_artifact_sha256, "candidate artifact identity")
        native_changed = baseline_identity != candidate_identity
        if not native_changed:
            reasons.append("identical_native_artifacts")
    for label, mad, mid in (("baseline", deviations_b, med_b), ("candidate", deviations_c, med_c)):
        if mad * 1_000_000 > objective["maximum_mad_ppm"] * mid:
            reasons.append(label + "_timing_noise")
    if saving <= 0 or saving * 1_000_000 < objective["minimum_gain_ppm"] * med_b:
        reasons.append("insufficient_measured_gain")
    if saving <= 3 * saving_mad:
        reasons.append("paired_saving_not_above_noise_margin")
    cost = search_cost_ns + DECISION_RESERVE_NS
    if cost > objective["maximum_search_ns"]:
        reasons.append("search_cost_budget")
    horizon = objective["horizon_calls"]
    projected_b = (med_b * horizon + calls_per_sample - 1) // calls_per_sample
    projected_c = (med_c * horizon + calls_per_sample - 1) // calls_per_sample + cost
    _integer(projected_b, 1, 1_000_000_000_000_000_000, "projected baseline cost")
    _integer(projected_c, 1, 1_000_000_000_000_000_000, "projected candidate cost")
    if projected_c >= projected_b:
        reasons.append("experiment_cost_not_recovered")
    return {"schema": "hepta.hia.ndu-measurement-policy.v2", "eligible": not reasons,
            "reasons": reasons, "samples": len(raw_samples), "calls_per_sample": calls_per_sample,
            "native_artifact_identity_checked": identity_checked,
            "native_artifact_changed": native_changed,
            "baseline_median_ns": med_b, "candidate_median_ns": med_c,
            "baseline_mad_ns": deviations_b, "candidate_mad_ns": deviations_c,
            "paired_saving_median_ns": saving, "paired_saving_mad_ns": saving_mad,
            "measured_search_cost_ns": search_cost_ns, "decision_reserve_ns": DECISION_RESERVE_NS,
            "projected_baseline_total_ns": projected_b,
            "projected_candidate_total_ns": projected_c,
            "projection_is_workload_assumption": True,
            "statistical_confidence_proved": False, "trimming_or_adaptive_repeats": False}


def observe_semantics(prepared, cases, *, negative_cases=()):
    """Record actual VM observations, including injected allocation failure.

    This finite regression corpus is additional evidence for the registered
    local rewrite. It does not establish equivalence on all inputs, host step
    budgets, execution time, or native allocator/foreign effects.
    """
    if not isinstance(prepared, PreparedCandidate):
        _reject("prepared candidate required")
    checked = prepare_candidate(prepared.baseline, prepared.plan,
                                candidate_bytes=prepared.candidate.canonical_bytes)
    if type(cases) is not list or not 1 <= len(cases) <= 64:
        _reject("1..64 positive cases required")
    if type(negative_cases) not in (list, tuple) or len(negative_cases) > 64:
        _reject("at most 64 negative cases required")
    rows, peak, matched = [], {"baseline": 0, "candidate": 0}, True
    for group, corpus in (("positive", cases), ("negative", negative_cases)):
        for arguments in corpus:
            if type(arguments) is not list or len(arguments) > 16:
                _reject("finite scalar case list required")
            for fail_at in (None, 1):
                observations = {}
                for key, core in (("baseline", checked.baseline), ("candidate", checked.candidate)):
                    try:
                        report = execute_program(core, checked.plan["entry"], arguments,
                                                 allocation_fail_at=fail_at)
                    except (HIAProgramTrap, HIAProgramBudgetExceeded) as exc:
                        report = exc.report
                    observation = {"status": report["status"], "resources": report["resources"]}
                    if "values" in report:
                        observation["values"] = report["values"]
                    if "error" in report:
                        observation["trap_code"] = report["error"]["code"]
                    observations[key] = observation
                    # The runtime counter name is fixed by the existing Core VM.
                    resources = report["resources"]
                    peak[key] = max(peak[key], resources["peak_bytes"])
                agrees = observations["baseline"] == observations["candidate"]
                if group == "positive" and fail_at is None:
                    agrees = agrees and observations["baseline"]["status"] == "returned"
                # Interpreter instruction budgets are not semantic equivalence.
                if any(row["status"] == "budget_exceeded" for row in observations.values()):
                    agrees = False
                matched = matched and agrees
                rows.append({"group": group, "arguments": list(arguments),
                             "allocation_fail_at": fail_at, "match": agrees, **observations})
    return {"schema": "hepta.hia.ndu-semantic-observations.v1", "ok": matched,
            "baseline_sha256": checked.baseline.sha256,
            "candidate_sha256": checked.candidate.sha256,
            "observations": rows, "peak_live_bytes": peak,
            "compared": ["returned_values", "trap_code", "full_resource_ledger"],
            "excluded": ["instruction_step_budget_equivalence", "native_failure_trace",
                         "foreign_state", "all_input_equivalence", "compiler_refinement"]}


def invoke_ndu(request, *, bridge, expected_binary_sha256):
    """Execute the identified real Rust bridge, then bind all echoed identities.

    The host's installation and source/toolchain trust remain in the TCB. A
    content hash identifies bytes; it is not remote attestation or authority.
    """
    expected = _digest(expected_binary_sha256, "NDU bridge identity")
    path = Path(bridge).resolve(strict=True)
    if digest_executable(path) != expected:
        _reject("NDU executable identity mismatch")
    payload = canonical(request)
    if len(payload) > 1_048_576:
        _reject("NDU request byte budget")
    # Retain and compare the exact submitted snapshot, not the mutable caller's
    # original object. Subsequent caller edits cannot relabel this receipt.
    request = read_json(payload)
    started = perf_counter_ns()
    result = run_bounded([str(path)], input_text=payload.decode(), timeout=1,
                         stdin_limit=1_048_576, stdout_limit=1_048_576, stderr_limit=65_536)
    elapsed = perf_counter_ns() - started
    if digest_executable(path) != expected:
        _reject("NDU executable changed during evaluation")
    reply = read_json(result.stdout)
    if result.returncode != 0 or type(reply) is not dict or reply.get("ok") is not True:
        _reject("NDU rejected the candidate set: " + str(reply.get("error") if type(reply) is dict else "invalid reply"))
    if (reply.get("schema") != "hepta.hia.ndu-response.v1"
            or reply.get("upstream_commit") != UPSTREAM_COMMIT
            or reply.get("authority") != "DENY_ALL"
            or reply.get("objective_sha256") != request["objective_sha256"]
            or type(reply.get("generation")) is not int
            or reply.get("generation") != request["generation"]):
        _reject("NDU response identity or authority mismatch")
    expected_bindings = {item["id"]: item for item in request["candidates"]}
    bindings = reply.get("bindings")
    if type(bindings) is not list or len(bindings) != len(expected_bindings):
        _reject("NDU response candidate coverage mismatch")
    seen = set()
    for binding in bindings:
        if type(binding) is not dict or type(binding.get("id")) is not str:
            _reject("invalid candidate binding")
        key = binding["id"]
        if key not in expected_bindings or key in seen:
            _reject("unexpected or duplicated candidate binding")
        seen.add(key)
        for field in ("core_sha256", "artifact_sha256", "evidence_sha256"):
            if binding.get(field) != expected_bindings[key][field]:
                _reject("NDU response changed " + field)
        support = sha256(b"hia.compiler.support.v1" + b"".join(
            bytes.fromhex(expected_bindings[key][field])
            for field in ("core_sha256", "artifact_sha256", "evidence_sha256"))).hexdigest()
        if _digest(binding.get("support_sha256"), "support identity") != support:
            _reject("NDU support digest does not bind the candidate evidence")
    for field in ("evaluation_sha256", "evaluation_policy_sha256", "utility_profile_sha256"):
        _digest(reply.get(field), field)
    recommendation = reply.get("advisory_recommendation")
    if recommendation is not None and (type(recommendation) is not str or recommendation not in expected_bindings):
        _reject("NDU recommended an unknown candidate")
    if recommendation not in (None, "abstain") and not expected_bindings[recommendation]["feasible"]:
        _reject("NDU recommended a host-rejected candidate")
    return {"request": request, "request_sha256": sha256(payload).hexdigest(), "response": reply,
            "binary_sha256": expected, "elapsed_ns": elapsed,
            "source_attestation_claimed": False, "activated": False}
