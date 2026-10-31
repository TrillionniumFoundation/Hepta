"""Strict finite HIA/NDU full-cost comparison. Arithmetic only, never authority.

A complete, *immutable* JSON wire is required: dict input is intentionally not
accepted, so a caller cannot modify a checked tree between admission and use.
Four strategies receive identical registered tasks and candidate-bank identity.
All declared one-time, execution, failed-attempt and controller costs count.
This is an audit of supplied observations, not trusted measurement attestation,
code-safety proof, future-performance bound or release permission.
"""
from __future__ import annotations

from hashlib import sha256
import json
import re

SCHEMA = "hepta.hia.full-cost-comparison.v1"
MAX_INPUT_BYTES = 262_144
MAX_TRIALS = 128
MAX_NS = 10**17
MAX_BYTES = 1 << 48
_STRATEGIES = frozenset({"baseline", "fixed", "dp", "ndu"})
_COSTS = frozenset({"toolchain", "dependencies", "controller_build",
    "candidate_build", "calibration", "search", "verification", "measurement",
    "publication", "switch", "rollback"})
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,63}\Z")


class FullCostRejected(ValueError):
    """Noncanonical, incomplete or unfair comparison input."""


def _fail(message):
    raise FullCostRejected("E_HIA_FULL_COST: " + message)


def _shape(value, fields, label):
    if type(value) is not dict or set(value) != set(fields):
        _fail(label + " must have exactly the registered fields")


def _integer(value, label, minimum=0, maximum=MAX_NS):
    if type(value) is not int or not minimum <= value <= maximum:
        _fail(label + " must be a bounded exact integer")
    return value


def _digest(value, label):
    if type(value) is not str or _DIGEST.fullmatch(value) is None or value == "0" * 64:
        _fail(label + " must be a nonzero lowercase SHA-256 digest")
    return value


def _id(value, label):
    if type(value) is not str or _ID.fullmatch(value) is None:
        _fail(label + " must be a bounded stable identifier")
    return value


def _no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _fail("duplicate JSON key")
        result[key] = value
    return result


def _invalid_constant(_value):
    _fail("nonfinite JSON constant")


def _wire(raw):
    if type(raw) is bytes:
        if len(raw) > MAX_INPUT_BYTES:
            _fail("input byte limit exceeded")
        try:
            source = raw.decode("utf-8")
        except UnicodeError as error:
            raise FullCostRejected("E_HIA_FULL_COST: invalid UTF-8") from error
    elif type(raw) is str:
        try:
            encoded = raw.encode("utf-8")
        except UnicodeError as error:
            raise FullCostRejected("E_HIA_FULL_COST: invalid UTF-8") from error
        if len(encoded) > MAX_INPUT_BYTES:
            _fail("input byte limit exceeded")
        source = raw
    else:
        _fail("input must be immutable JSON bytes or string, not mutable objects")
    try:
        parsed = json.loads(source, object_pairs_hook=_no_duplicates,
                            parse_constant=_invalid_constant)
    except FullCostRejected:
        raise
    except (ValueError, TypeError, RecursionError, OverflowError) as error:
        raise FullCostRejected("E_HIA_FULL_COST: invalid bounded JSON") from error
    return parsed, sha256(source.encode("utf-8")).hexdigest()


def assess_full_cost(raw):
    """Evaluate observed-scope NDU benefit against *all* three strong controls.

    No sample deletion, median-only claim, future amortization or missing costs.
    The receipt is always DENY_ALL, even when observed arithmetic is positive.
    """
    data, input_digest = _wire(raw)
    _shape(data, {"schema", "source_digest", "objective_digest", "hardware_digest",
                  "workload_digest", "candidate_bank_digest", "generation",
                  "registered_trials", "minimum_gain_ppm", "minimum_gain_ns",
                  "maximum_peak_rss_bytes", "maximum_p99_ns", "arms"}, "comparison")
    if data["schema"] != SCHEMA:
        _fail("unsupported comparison schema")
    for key in ("source_digest", "objective_digest", "hardware_digest",
                "workload_digest", "candidate_bank_digest"):
        _digest(data[key], key)
    _integer(data["generation"], "generation", 1, (1 << 32) - 1)
    _integer(data["minimum_gain_ppm"], "minimum_gain_ppm", 1, 1_000_000)
    _integer(data["minimum_gain_ns"], "minimum_gain_ns", 1)
    _integer(data["maximum_peak_rss_bytes"], "maximum_peak_rss_bytes", 1, MAX_BYTES)
    _integer(data["maximum_p99_ns"], "maximum_p99_ns", 1)
    trials = data["registered_trials"]
    if type(trials) is not list or not 8 <= len(trials) <= MAX_TRIALS:
        _fail("comparison requires 8..128 preregistered trials")
    expected = {}
    for trial in trials:
        _shape(trial, {"id", "input_digest", "expected_result_digest"}, "trial")
        tid = _id(trial["id"], "trial id")
        if tid in expected:
            _fail("duplicate trial")
        expected[tid] = (_digest(trial["input_digest"], "trial input"),
                         _digest(trial["expected_result_digest"], "reference result"))
    if list(expected) != sorted(expected):
        _fail("registered trial order must be canonical")
    arms = data["arms"]
    if type(arms) is not list or len(arms) != len(_STRATEGIES):
        _fail("exactly four strategy arms are required")
    totals, peaks, unknown, observers = {}, {}, {}, set()
    for arm in arms:
        _shape(arm, {"strategy", "core_digest", "artifact_digest", "toolchain_digest",
                     "observer_digest", "candidate_bank_digest", "one_time_ns",
                     "unknown_costs", "observations"}, "arm")
        name = arm["strategy"]
        if type(name) is not str or name not in _STRATEGIES or name in totals:
            _fail("duplicate, invalid or missing strategy")
        for key in ("core_digest", "artifact_digest", "toolchain_digest", "observer_digest"):
            _digest(arm[key], name + "." + key)
        if arm["candidate_bank_digest"] != data["candidate_bank_digest"]:
            _fail("unequal candidate banks or registration drift")
        observers.add(arm["observer_digest"])
        costs = arm["one_time_ns"]
        _shape(costs, _COSTS, name + " one-time ledger")
        total = sum(_integer(v, name + "." + k) for k, v in costs.items())
        rows = arm["observations"]
        if type(rows) is not list or len(rows) != len(expected):
            _fail("missing/extra task observations")
        seen = set()
        peak_rss = peak_p99 = 0
        for row in rows:
            _shape(row, {"trial_id", "input_digest", "result_digest", "execution_ns",
                         "controller_ns", "failed_attempt_ns", "peak_rss_bytes",
                         "p99_ns", "completed"}, "observation")
            tid = _id(row["trial_id"], "observed trial")
            if tid not in expected or tid in seen:
                _fail("unknown or repeated observed trial")
            seen.add(tid)
            if (row["input_digest"], row["result_digest"]) != expected[tid]:
                _fail("task input or output differs from registered oracle")
            if row["completed"] is not True:
                _fail("failed, skipped or unfinished work cannot count as a successful arm")
            for key in ("execution_ns", "controller_ns", "failed_attempt_ns"):
                total += _integer(row[key], name + "." + key,
                                  minimum=1 if key == "execution_ns" else 0)
            peak_rss = max(peak_rss, _integer(row["peak_rss_bytes"],
                                              name + ".peak_rss_bytes", 1, MAX_BYTES))
            peak_p99 = max(peak_p99, _integer(row["p99_ns"], name + ".p99_ns", 1))
        if total > MAX_NS:
            _fail("complete arm total exceeds finite profile")
        costs_unknown = arm["unknown_costs"]
        if (type(costs_unknown) is not list or len(costs_unknown) > 16
                or any(type(v) is not str or _ID.fullmatch(v) is None for v in costs_unknown)
                or len(set(costs_unknown)) != len(costs_unknown)):
            _fail("unknown-cost ledger must list unique bounded categories")
        unknown[name] = costs_unknown
        totals[name] = total
        peaks[name] = {"peak_rss_bytes": peak_rss, "p99_ns": peak_p99}
    if set(totals) != _STRATEGIES:
        _fail("missing required control strategies")
    best = min((totals[name], name) for name in ("baseline", "fixed", "dp"))
    saving = best[0] - totals["ndu"]
    fraction_ppm = saving * 1_000_000 // best[0]
    reasons = []
    if any(unknown.values()):
        reasons.append("unaccounted_costs")
    if len(observers) != 1:
        reasons.append("different_observation_sources")
    if saving < data["minimum_gain_ns"]:
        reasons.append("no_absolute_full_cost_advantage")
    if saving * 1_000_000 < best[0] * data["minimum_gain_ppm"]:
        reasons.append("no_relative_full_cost_advantage")
    if peaks["ndu"]["peak_rss_bytes"] > data["maximum_peak_rss_bytes"]:
        reasons.append("memory_limit_exceeded")
    if peaks["ndu"]["p99_ns"] > data["maximum_p99_ns"]:
        reasons.append("p99_limit_exceeded")
    return {"schema": "hepta.hia.full-cost-verdict.v1", "input_sha256": input_digest,
            "objective_digest": data["objective_digest"],
            "source_digest": data["source_digest"], "workload_digest": data["workload_digest"],
            "candidate_bank_digest": data["candidate_bank_digest"],
            "generation": data["generation"], "registered_trials": len(expected),
            "arm_total_ns": totals, "arm_observed_limits": peaks,
            "best_control": best[1], "best_control_total_ns": best[0],
            "ndu_full_cost_saving_ns": saving, "ndu_saving_ppm": fraction_ppm,
            "unknown_costs": unknown, "economic_scope_positive": not reasons,
            "reasons": reasons, "authority": "DENY_ALL", "safety_certificate": False,
            "production_activation_allowed": False,
            "claims": {"input_observations_authenticated": False,
                       "objective_independently_verified": False,
                       "machine_code_equivalence_proved": False,
                       "statistical_generalization_proved": False,
                       "unrestricted_global_optimality_proved": False,
                       "future_workload_benefit_proved": False}}
