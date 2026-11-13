"""Conservative paired evidence for HIA/NDU comparisons (not an authority).

This supplements the existing complete-cost verifier with an exact, finite
one-sided sign test on *registered task-level* paired net costs. Each arm's
one-time cost is allocated evenly across its registered task count solely for
this diagnostic; the original full-cost totals remain authoritative for the
arithmetic comparison. No p-value can certify independent tasks, provenance,
hardware stability, semantic equivalence, or generalization.
"""
from __future__ import annotations

from math import comb
import json

from .hia_full_cost_gate import FullCostRejected, assess_full_cost

SCHEMA = "hepta.hia.paired-holdout-evidence.v1"
CONTROLS = ("baseline", "fixed", "dp")
MIN_NON_TIED_TRIALS = 8
# One-sided alpha = 0.05, with Bonferroni correction across three controls.
ALPHA_DENOMINATOR = 20
COMPARISONS = len(CONTROLS)


def assess_paired_holdout(raw):
    """Return strict task-level diagnostic; never infer execution permission.

    The original finite gate must first admit the *same immutable wire*. No
    mutable dict or separately supplied best-control total is accepted. The
    paired cost includes exact per-trial execution/controller/failed costs and
    each arm's complete one-time ledger (without rounding nanoseconds).
    """
    verified = assess_full_cost(raw)
    # The original gate has already rejected duplicate keys, excess bytes,
    # malformed types, omissions, task drift, and all invalid cost domains.
    source = raw.decode("utf-8") if type(raw) is bytes else raw
    data = json.loads(source)
    trial_ids = tuple(row["id"] for row in data["registered_trials"])
    arms = {arm["strategy"]: arm for arm in data["arms"]}
    count = len(trial_ids)

    def one_time(arm):
        return sum(arm["one_time_ns"].values())

    def trial_cost(arm, trial_id):
        row = next(row for row in arm["observations"]
                   if row["trial_id"] == trial_id)
        return (row["execution_ns"] + row["controller_ns"]
                + row["failed_attempt_ns"])

    ndu = arms["ndu"]
    comparisons = {}
    supported = True
    for name in CONTROLS:
        control = arms[name]
        # Multiplying by task count avoids rounding an amortized one-time
        # allocation. The sum of these scaled deltas equals n * full saving
        # against this particular control.
        fixed_delta = one_time(control) - one_time(ndu)
        deltas = [
            count * (trial_cost(control, tid) - trial_cost(ndu, tid))
            + fixed_delta
            for tid in trial_ids
        ]
        wins = sum(delta > 0 for delta in deltas)
        losses = sum(delta < 0 for delta in deltas)
        ties = count - wins - losses
        non_ties = wins + losses
        # Exact rational p = P[Binomial(non_ties, 1/2) >= wins].
        # Bonferroni is deliberately conservative for dependent control arms;
        # independence of *task units* is still an unproved assumption.
        tail = sum(comb(non_ties, k) for k in range(wins, non_ties + 1))
        denominator = 1 << non_ties
        passes = (non_ties >= MIN_NON_TIED_TRIALS
                  and ALPHA_DENOMINATOR * COMPARISONS * tail <= denominator
                  and wins > losses)
        supported &= passes
        comparisons[name] = {
            "wins": wins, "losses": losses, "ties": ties,
            "non_tied_trials": non_ties,
            "strict_net_advantage_ns": verified["arm_total_ns"][name]
                                       - verified["arm_total_ns"]["ndu"],
            "one_sided_sign_p_numerator": tail,
            "one_sided_sign_p_denominator": denominator,
            "bonferroni_family_size": COMPARISONS,
            "passes_conditional_threshold": passes,
            "largest_task_regression_scaled_ns": max(
                (max(0, -delta) for delta in deltas), default=0),
        }

    # Statistical support alone is NEVER a full-cost win. In particular,
    # an unaccounted human, build, proof, or switch cost still blocks.
    passed = bool(verified["economic_scope_positive"] and supported)
    reasons = []
    if not verified["economic_scope_positive"]:
        reasons.append("full_cost_gate_not_positive")
    if not supported:
        reasons.append("paired_sign_threshold_not_met")
    return {
        "schema": SCHEMA, "input_sha256": verified["input_sha256"],
        "registered_trials": count,
        "existing_full_cost_verdict": verified,
        "paired_comparisons": comparisons,
        "paired_evidence_supported": passed,
        "reasons": reasons,
        "method": {
            "test": "exact_one_sided_paired_sign",
            "familywise_alpha_numerator": 1,
            "familywise_alpha_denominator": ALPHA_DENOMINATOR,
            "bonferroni_comparisons": COMPARISONS,
            "minimum_non_tied_trials": MIN_NON_TIED_TRIALS,
            "one_time_cost_treatment": "equal_allocation_over_registered_tasks",
            "rounding_of_paired_costs": "none",
        },
        "limitations": {
            "task_independence_verified": False,
            "representative_held_out_workload_verified": False,
            "preregistration_authenticated": False,
            "observer_authenticated": False,
            "machine_code_equivalence_proved": False,
            "statistical_generalization_proved": False,
            "future_net_benefit_proved": False,
        },
        "authority": "DENY_ALL", "safety_certificate": False,
        "production_activation_allowed": False,
    }
