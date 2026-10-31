"""Independent recomputation of native ELF sample -> paired full-cost evidence.

Checks the complete bounded *observer report*, not a supplied per-arm summary
alone. This is a consistency/replay check of user-provided measurements, not
attestation of an observer, its compiler, task oracle or any sandbox.
"""
from __future__ import annotations

from hashlib import sha256
import json
import re

from .hia_bounded_wire import WireBudgetExceeded, checked_utf8_wire
from .hia_paired_holdout import assess_paired_holdout

SCHEMA = "hepta.hia.native-paired-replay.v1"
OBSERVER_SCHEMA = "hepta.hia.native-observation.v1"
MAX_REPORT_BYTES = 8 * 1024 * 1024
ARMS = ("baseline", "fixed", "dp", "ndu")
EMPTY_SHA256 = sha256(b"").hexdigest()
_HEX_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


class NativePairedReplayRejected(ValueError):
    pass


def _fail(reason):
    raise NativePairedReplayRejected("E_HIA_NATIVE_PAIRED_REPLAY: " + reason)


def _shape(value, fields, where):
    if type(value) is not dict or set(value) != set(fields):
        _fail(where + " has missing/extra fields")


def _integer(value, low, high, where):
    if type(value) is not int or not low <= value <= high:
        _fail(where + " is not a bounded exact integer")
    return value


def _pairs(pairs):
    d = {}
    for key, value in pairs:
        if key in d:
            _fail("duplicate JSON field")
        d[key] = value
    return d


def _read(raw):
    if type(raw) is bytes:
        wire = raw
    elif type(raw) is str:
        try:
            wire = checked_utf8_wire(raw, MAX_REPORT_BYTES)
        except WireBudgetExceeded:
            _fail("native observer evidence exceeds byte limit")
        except UnicodeError as exc:
            raise NativePairedReplayRejected(
                "E_HIA_NATIVE_PAIRED_REPLAY: invalid UTF-8") from exc
    else:
        _fail("immutable bytes/string input required")
    if len(wire) > MAX_REPORT_BYTES:
        _fail("native observer evidence exceeds byte limit")
    try:
        return json.loads(wire.decode("utf-8"), object_pairs_hook=_pairs,
                          parse_constant=lambda _: _fail("nonfinite JSON"))
    except NativePairedReplayRejected:
        raise
    except (ValueError, UnicodeError, TypeError, RecursionError, OverflowError) as exc:
        raise NativePairedReplayRejected(
            "E_HIA_NATIVE_PAIRED_REPLAY: malformed bounded JSON") from exc


def replay_native_paired(raw):
    """Check direct-child raw samples, exact aggregates and original gate."""
    report = _read(raw)
    _shape(report, {"schema", "registration_sha256", "observer_digest",
                    "host", "frozen_binaries", "raw_samples", "failures",
                    "complete", "authority", "safety_certificate",
                    "production_activation_allowed", "claims",
                    "full_cost_input", "full_cost_verdict"}, "complete report")
    if (report["schema"] != OBSERVER_SCHEMA or report["complete"] is not True
            or report["failures"] != [] or report["authority"] != "DENY_ALL"
            or report["safety_certificate"] is not False
            or report["production_activation_allowed"] is not False):
        _fail("failed/incomplete or authority-escalated observer report")
    for field in ("registration_sha256", "observer_digest"):
        value = report[field]
        if (type(value) is not str or _HEX_DIGEST.fullmatch(value) is None
                or value == "0" * 64):
            _fail(field + " is not a valid nonzero digest")
    _shape(report["host"], {"system", "machine", "release"}, "host")
    if (report["host"]["system"] != "Linux"
            or any(type(report["host"][key]) is not str
                   or not 1 <= len(report["host"][key]) <= 256
                   for key in ("machine", "release"))):
        _fail("host does not match supported Linux observer profile")
    _shape(report["claims"], {
        "registered_reference_independently_verified",
        "one_time_costs_independently_attested",
        "process_tree_resource_accounting",
        "compiler_refinement_proved",
        "future_performance_proved"}, "observer claims")
    if any(value is not False for value in report["claims"].values()):
        _fail("observer cannot claim unaudited attestation")
    # Canonicalize only *after* a complete bounded parse. The original cost
    # gate independently rechecks all cost, input, output and identity fields.
    try:
        cost_wire = json.dumps(
            report["full_cost_input"], sort_keys=True, separators=(",", ":"),
            ensure_ascii=False, allow_nan=False).encode("utf-8")
        paired = assess_paired_holdout(cost_wire)
    except (ValueError, TypeError, OverflowError) as exc:
        raise NativePairedReplayRejected(
            "E_HIA_NATIVE_PAIRED_REPLAY: original cost gate rejected evidence") from exc
    if report["full_cost_verdict"] != paired["existing_full_cost_verdict"]:
        _fail("reported original full-cost verdict differs on replay")
    data = report["full_cost_input"]
    trials = {t["id"]: t for t in data["registered_trials"]}
    arms = {arm["strategy"]: arm for arm in data["arms"]}
    samples = report["raw_samples"]
    frozen = report["frozen_binaries"]
    if (type(samples) is not dict or set(samples) != set(ARMS)
            or type(frozen) is not list or len(frozen) != 4):
        _fail("missing or extra native strategy samples/binaries")
    seen_repetitions = None
    total_samples = 0
    for index, name in enumerate(ARMS):
        arm = arms[name]
        if arm["observer_digest"] != report["observer_digest"]:
            _fail("reported observer identity differs from full-cost arm")
        entry = frozen[index]
        _shape(entry, {"strategy", "sha256", "freeze_ns"}, "ELF identity")
        if (entry["strategy"] != name
                or entry["sha256"] != arm["artifact_digest"]):
            _fail("frozen executable differs from original cost arm")
        freeze_ns = _integer(entry["freeze_ns"], 0, 10**17, "freeze_ns")
        if arm["one_time_ns"]["measurement"] < freeze_ns:
            _fail("measured ELF freeze work was omitted from costs")
        by_trial = samples[name]
        if type(by_trial) is not dict or set(by_trial) != set(trials):
            _fail("task set does not equal registered task IDs")
        summed = {row["trial_id"]: row for row in arm["observations"]}
        for tid, task in trials.items():
            raw_rows = by_trial[tid]
            if type(raw_rows) is not list or not 2 <= len(raw_rows) <= 128:
                _fail("missing/invalid native repetitions")
            if seen_repetitions is None:
                seen_repetitions = len(raw_rows)
            elif len(raw_rows) != seen_repetitions:
                _fail("different repetition counts across arms or tasks")
            total_samples += len(raw_rows)
            times = []
            peak_rss = 0
            for repeat, sample in enumerate(raw_rows):
                _shape(sample, {"execution_ns", "exit_code", "timed_out",
                                "peak_rss_bytes", "stdout_bytes", "stderr_bytes",
                                "stdout_digest", "stderr_digest",
                                "repetition", "valid"}, "raw native sample")
                if (sample["valid"] is not True
                        or sample["timed_out"] is not False
                        or type(sample["exit_code"]) is not int
                        or sample["exit_code"] != 0
                        or type(sample["stdout_digest"]) is not str
                        or sample["stdout_digest"] != task["expected_result_digest"]
                        or sample["stderr_digest"] != EMPTY_SHA256):
                    _fail("invalid output, crash, timeout or stderr disguised as success")
                _integer(sample["repetition"], repeat, repeat, "repetition index")
                _integer(sample["stdout_bytes"], 0, 65536, "stdout_bytes")
                _integer(sample["stderr_bytes"], 0, 0, "stderr_bytes")
                times.append(_integer(
                    sample["execution_ns"], 1, 10**17, "execution_ns"))
                peak_rss = max(peak_rss, _integer(
                    sample["peak_rss_bytes"], 1, 1 << 48, "peak RSS"))
            times.sort()
            p99_rank = (99 * len(times) + 99) // 100
            expected = {
                "trial_id": tid, "input_digest": task["input_digest"],
                "result_digest": task["expected_result_digest"],
                "execution_ns": sum(times), "controller_ns": 0,
                "failed_attempt_ns": 0, "peak_rss_bytes": peak_rss,
                "p99_ns": times[p99_rank - 1], "completed": True}
            if summed[tid] != expected:
                _fail("native raw samples differ from reported task summary")
    if total_samples > 4096:
        _fail("campaign exceeds original native process budget")
    return {
        "schema": SCHEMA,
        "raw_report_sha256": sha256(
            raw if type(raw) is bytes else raw.encode("utf-8")).hexdigest(),
        "registered_trials": len(trials),
        "repetitions_per_task_arm": seen_repetitions,
        "actual_direct_child_samples": total_samples,
        "raw_summary_replay_consistent": True,
        "paired_evidence": paired,
        "limitations": {
            "observations_independently_attested": False,
            "source_to_machine_refinement_proved": False,
            "process_tree_rss_measured": False,
            "task_independence_verified": False,
        },
        "authority": "DENY_ALL", "safety_certificate": False,
        "production_activation_allowed": False,
    }
