"""Offline, identical-model beam/NDU replay; never feeds a workload decision."""
from __future__ import annotations
import time
from .hia_ndu_dynamic import (REQUEST_SCHEMA, digest, require, validate_model,
    validate_response, wire)


def matched_model_audit(rows, beam_session):
    """Reconstruct beam for each *actual* NDU model, not the other online arm.

    The ordinary online beam arm has its own calibration, elapsed cost and
    state, so its materialized candidates need not match an NDU request. This
    audit freezes every supplied NDU model byte-for-byte and only changes the
    request's mode. It compares plan dictionaries and selected first actions.
    The actual NDU response is independently revalidated before comparison.
    Search/inference timing is not compared; no workload is re-executed.
    """
    started = time.monotonic_ns()
    require(type(rows) is list and len(rows) <= 4096, "bounded actual-model audit")
    output = []
    for row in rows:
        if row["policy"] != "beam_ndu":
            continue
        item = {"episode": row["episode"], "step": row["step"], "matched": False}
        before = time.monotonic_ns()
        try:
            model = validate_model(row["model"])
            original = row["response"]
            payload = wire({"schema": REQUEST_SCHEMA, "mode": "beam_ndu", "model": model})
            validate_response(model, "beam_ndu", payload, original)
            baseline, receipt = beam_session.evaluate(model, "beam")
            same_plans = wire(baseline["bundle"]["plans"]) == wire(original["bundle"]["plans"])
            same_action = wire(baseline["selected_first_action"]) == wire(original["selected_first_action"])
            item.update(model_sha256=digest(model),
                original_plans_sha256=digest(original["bundle"]["plans"]),
                counterfactual_plans_sha256=digest(baseline["bundle"]["plans"]),
                original_action_sha256=digest(original["selected_first_action"]),
                counterfactual_action_sha256=digest(baseline["selected_first_action"]),
                same_plans=same_plans, same_selected_action=same_action,
                matched=same_plans and same_action, beam_call_receipt=receipt)
        except Exception as exc:
            item["error"] = {"type": type(exc).__name__, "message": str(exc)}
        item["wall_ns"] = time.monotonic_ns() - before
        output.append(item)
    return {"schema": "hepta.hia.result-cache.matched-model-audit.v1", "rows": output,
            "actual_ndu_models": len(output), "nonvacuous": bool(output),
            "all_match": all(item["matched"] for item in output),
            "wall_ns": time.monotonic_ns() - started,
            "scope": "offline beam counterfactual for every recorded actual NDU model; does not equate independently calibrated online arms",
            "service_timings_modified": False, "workload_reexecuted": False,
            "runtime_optimality_proved": False, "authority": "DENY_ALL"}
