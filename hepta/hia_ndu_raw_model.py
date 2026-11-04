"""Raw-model native planning and linear witness admission, without Python search.

This is a separate experimental profile. It never loads selected program code
or changes the original v2 controller. The native modes share their recurrence,
model, binary and cost semantics; only the `ndu` mode calls the original NDU.
Returned witnesses are checked for feasibility, not re-optimized in Python.
"""
from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import time

from .hia_ndu import Q32, _read_json, candidate, event
from .hia_ndu_cost import CostModelError, _action, _parts, digest, validate_model
from .hia_native_differential import _pin_native_artifact

UPSTREAM = "8e52e1187f47f6d4edc8d942fc7cb7eca4bc447d"
REQUEST_SCHEMA = "hepta.hia.ndu.raw-model.request.v1"
RESPONSE_SCHEMA = "hepta.hia.ndu.raw-model.response.v1"
MAX_BYTES = 1_048_576


def _require(ok, reason):
    if not ok:
        raise CostModelError("raw-model v1: " + reason)


def request_bytes(raw, mode):
    _require(type(mode) is str and mode in {"exact_dp", "ndu"}, "unknown native mode")
    model = validate_model(raw)
    value = {"schema": REQUEST_SCHEMA, "mode": mode, "model": model}
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    _require(len(payload) <= MAX_BYTES, "request bound")
    return model, payload


def validate_response(model, mode, payload, response):
    """Replay supplied schedules in O(frontier * horizon), with no DP search.

    A successful check establishes arithmetic, costs, generation and resources
    of the supplied witnesses. Completeness/optimality is a claim of the pinned
    native implementation and is independently compared only in qualification.
    Program legality still belongs to HIA's existing artifact admission path.
    """
    _require(type(response) is dict and response.get("schema") == RESPONSE_SCHEMA, "response schema")
    for key, expected in (("mode", mode), ("request_sha256", sha256(payload).hexdigest()),
                          ("model_sha256", digest(model)), ("generation", model["generation"]),
                          ("upstream_commit", UPSTREAM), ("authority", "DENY_ALL")):
        _require(type(response.get(key)) is type(expected) and response[key] == expected, "response " + key)
    _require(response.get("safety_certificate") is False
             and response.get("production_activation_allowed") is False
             and response.get("python_search_performed") is False
             and response.get("global_program_optimality") is False
             and response.get("native_evaluation") is (mode == "ndu"), "response claim boundary")
    native = response.get("ndu_evaluation")
    _require((mode == "exact_dp" and native is None) or
             (mode == "ndu" and type(native) is dict and native.get("entry_points") == [
                 "codex_hepta_ndu::evaluate_recursive_utility", "codex_hepta_ndu::evaluate_candidates_with_policy"]
              and native.get("authority") == "DENY_ALL" and native.get("safety_certificate") is False), "NDU mode provenance")
    bundle = response.get("bundle")
    _require(type(bundle) is dict and bundle.get("authority") == "DENY_ALL"
             and bundle.get("safety_certificate") is False and bundle.get("search_complete") is True, "bundle envelope")
    plans = bundle.get("plans")
    _require(type(plans) is dict and len(plans) <= 5, "first-action frontier bound")
    variants, sets, horizon = _parts(model)
    d = model["decision"]
    call = sum(d[k] for k in ("search_ns", "native_ns", "transport_ns", "validation_ns"))
    call += 0 if model["session_ready"] else d["startup_ns"]
    common = call + d["close_ns"]
    first_actions = set()
    for identity, plan in plans.items():
        _require(type(plan) is dict and set(plan) == {"actions", "close_ns", "total_ns", "current_committed_ns"}, "plan fields")
        _require(type(identity) is str and identity == "cost-" + digest(plan)[:24], "plan digest")
        _require(type(plan["actions"]) is list and len(plan["actions"]) == horizon, "complete horizon")
        ready = tuple(sorted(model["ready"]))
        total = 0
        first = plan["actions"][0]
        _require(type(first) is dict and first.get("mode") in {"skip", "invoke"}, "first mode")
        committed = call if first["mode"] == "skip" else 0
        session = True if first["mode"] == "skip" else model["session_ready"]
        for batch, action in enumerate(plan["actions"]):
            _require(type(action) is dict and action.get("mode") in {"skip", "invoke"}, "action mode")
            target = action.get("ready_after")
            _require(type(target) is list and all(type(v) is str for v in target), "resident set")
            target = tuple(target)
            _require(target in sets, "resident quota or order")
            expected = _action(model, variants, ready, batch, session, action["mode"], target)
            _require(expected is not None and action == expected
                     and digest(action) == digest(expected), "invalid action witness")
            ready, session = tuple(expected["ready_after"]), expected["session_after"]
            total += expected["total_ns"]
        total += d["close_ns"] + committed
        _require(type(plan["total_ns"]) is int and plan["total_ns"] == total <= model["budget_ns"]
                 and type(plan["close_ns"]) is int and plan["close_ns"] == d["close_ns"]
                 and type(plan["current_committed_ns"]) is int and plan["current_committed_ns"] == committed
                 and total >= common, "cost or budget mismatch")
        key = first["mode"], tuple(first["ready_after"])
        _require(key not in first_actions, "duplicate first action")
        first_actions.add(key)
    support = {"model": model, "recurrence": "batch,resident-set,session-ready,remaining-budget",
               "scope": "scalar completion-minus-total-cost; zero risk and uncertainty",
               "compaction": "one minimum-cost witness per first action; complete first-action frontier",
               "verification": "independent caller admission, not authenticated by model digests",
               "committed_and_reserved_ns": common,
               "native_resource_budget_ns": max(0, model["budget_ns"] - common), "plans": plans}
    _require(bundle.get("support") == support and digest(bundle["support"]) == digest(support), "support binding")
    def first_order(item):
        a = item[1]["actions"][0]
        return a["mode"] != "skip", 0 if a["mode"] == "skip" else len(a["ready_after"]), a["ready_after"]
    support_hash = digest(support)
    verification = digest([model["baseline"]["verification_sha256"], [v["verification_sha256"] for v in model["variants"]]])
    rows, values = [], {}
    for identity in [key for key, _ in sorted(plans.items(), key=first_order)] + ["abstain"]:
        abstain = identity == "abstain"
        variable = 0 if abstain else plans[identity]["total_ns"] - common
        terminal = 0 if abstain else model["completion_value_ns"] * Q32 // 1_000_000
        instant = -(variable * Q32 // 1_000_000)
        rows.append(candidate(candidate_id=identity, verified=True,
            verification_digest=digest("literal-no-delivery") if abstain else verification,
            support_digest=support_hash,
            events=[event(identity=identity + support_hash, instant_q32=instant, preference_digest=model["objective_digest"])],
            terminal_q32=terminal, resource_cost_q32=variable * Q32 // 1000))
        values[identity] = terminal + instant
    expected_request = {"schema": "hepta.hia.ndu.request.v1", "objective_digest": model["objective_digest"],
        "snapshot_digest": digest(model), "generation": model["generation"],
        "utility_unit": "completion-minus-wall-milliseconds", "resource_unit": "microseconds",
        "risk_unit": "probability", "risk_ceiling_q32": Q32,
        "resource_budget_q32": max(0, model["budget_ns"] - common) * Q32 // 1000, "candidates": rows}
    _require(bundle.get("request") == expected_request and digest(bundle["request"]) == digest(expected_request), "inner request mismatch")
    # Scoring already supplied <=6 paths is not a continuation search. It
    # checks output integrity under this scalar profile, including abstain ties.
    expected_winners = sorted(k for k, v in values.items() if v == max(values.values()))
    _require(response.get("pareto_candidate_ids") == expected_winners, "winner mismatch")
    action = None
    if "abstain" not in expected_winners:
        first = [plans[k]["actions"][0] for k in expected_winners]
        if len({(tuple(a["ready_after"]), a["dispatch"]) for a in first}) == 1:
            action = first[0]
    # Python equality conflates JSON numbers and booleans (0 == False,
    # 1 == True) and integer/float values. Bind this projection to the same
    # canonical, type-sensitive representation as the replayed action witness.
    _require("selected_first_action" in response
             and response["selected_first_action"] == action
             and digest(response["selected_first_action"]) == digest(action), "selected action mismatch")
    return response


def invoke(executable, manifest_path, raw, *, mode="exact_dp", timeout=10.0):
    """One measured Linux sealed-image call; original NDU is explicit opt-in.

    Exact DP is the default for this finite scalar profile: the paired study
    found no additional decision benefit from NDU. Neither mode dispatches the
    returned plan, and the historical v2 controller remains unchanged.
    """
    started = time.monotonic_ns()
    _require(type(timeout) in (int, float) and 0 < timeout <= 120, "timeout bound")
    model, payload = request_bytes(raw, mode)
    manifest = _read_json(Path(manifest_path).read_bytes())
    _require(manifest.get("schema") == "hepta.hia.ndu-build.v1"
             and manifest.get("upstream", {}).get("commit") == UPSTREAM
             and manifest.get("original_rust_sources_unchanged") is True
             and manifest.get("all_original_non_manifest_inputs_unchanged") is True, "build source binding")
    expected_sources = Path(__file__).resolve().parents[1] / "rust/hia-ndu-raw-model"
    expected = {str(p.relative_to(expected_sources)): sha256(p.read_bytes()).hexdigest()
                for p in expected_sources.rglob("*") if p.is_file()}
    _require(manifest.get("adapter_files") == expected, "raw adapter source binding")
    _require(Path("/proc/self/fd").exists() and hasattr(os, "memfd_create"), "qualified Linux sealed image unavailable")
    image, _, fd = _pin_native_artifact(Path(executable))
    try:
        _require(sha256(image).hexdigest() == manifest.get("binary_sha256"), "binary digest")
        run = subprocess.run(["/proc/self/fd/" + str(fd)], input=payload, capture_output=True,
                             pass_fds=(fd,), timeout=timeout, check=False)
    finally:
        os.close(fd)
    _require(run.returncode == 0, "native rejection: " + run.stderr.decode("utf-8", "replace")[:2000])
    _require(len(run.stdout) <= MAX_BYTES and len(run.stderr) <= 16384, "native output bound")
    response = validate_response(model, mode, payload, _read_json(run.stdout))
    return response, {"outer_wall_ns": time.monotonic_ns() - started,
                      "request_sha256": sha256(payload).hexdigest(), "request_bytes": payload.decode(),
                      "stdout": run.stdout.decode(), "stderr": run.stderr.decode(),
                      "binary_sha256": manifest["binary_sha256"], "mode": mode,
                      "includes": "input/source/image validation, spawn, native planning/evaluation, response replay",
                      "excludes": "build, imports, caller reporting, program execution; no full-lifecycle claim"}
