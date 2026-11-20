"""Inputs for the independently frozen evaluation oracle, not a native port script."""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256

from tests.hia_evaluation_oracle import Scenario, returned, trapped


def native_normal(*, value=7, mismatch=False, completed=1, observations=None, total="100"):
    return {"status": "returned", "returncode": 0, "report": {
        "completed_cases": completed, "total_native_ns": total,
        "observations": ([{"status": "returned", "values": [value], "mismatch": mismatch}]
                         if observations is None else observations)}}


def failed(status):
    return {"status": status, "returncode": -9, "report": None}


def buffer_case(name, *, trap=False):
    buffer = {"argument": 0, "kind": "mutbuf", "byte_length": 1,
              "sha256": sha256(b"\x07").hexdigest()}
    row = trapped(buffers=[buffer]) if trap else returned(buffers=[buffer])
    signature = {"params": ["mutbuf"], "returns": ["u8"],
                 "abi": "hepta.hia.agent.borrowed-byte-snapshots.v1", "max_buffer_bytes": 1}
    return Scenario(name,
        cases=[{"function": "transform", "arguments": [{"bytes_hex": "00"}]}],
        reference_rows={"baseline": [deepcopy(row)], "candidate": [deepcopy(row)]},
        metadata_changes={label: {"signatures": {"transform": deepcopy(signature)}}
                          for label in ("baseline", "candidate")},
        context_changes={"foreign_buffer_exports": [["transform", 1]]},
        workload_changes={"schema": "hepta.hia.agent.workload.v2",
            "foreign_buffer_exports": [{"function": "transform", "max_buffer_bytes": 1}]})


def scenarios():
    result = [
        Scenario("artifact_improved"),
        Scenario("artifact_equal", candidate_bytes=b"C" * 32),
        Scenario("artifact_regressed", candidate_bytes=b"C" * 64),
        Scenario("zero_baseline", baseline_bytes=b"", candidate_bytes=b""),
        Scenario("ratio_equal_threshold", minimum_ratio=0.5),
        Scenario("ratio_below_threshold", minimum_ratio=0.5000000000000001),
        Scenario("latency_improved", metric="latency_ns"),
        Scenario("unbound_baseline", context_changes={"baseline_core_sha256": None}),
        Scenario("deadline_expired_before_planning", wall_schedule=(1_001_000_000, 1_002_000_000, 61_000_000_000)),
        Scenario("zero_total_budget", context_changes={"budget": {"max_total_wall_ms": 0}}),
        Scenario("late_native_deadline", wall_schedule=(1_001_000_000, 1_002_000_000, 1_003_000_000, 61_000_000_000),
                 native_results={("baseline", "normal"): failed("budget_exceeded")}),
    ]
    for label in ("baseline", "candidate"):
        for status in ("budget_exceeded", "faulted", "invalid_report"):
            result.append(Scenario("reference_" + label + "_" + status,
                                   reference_results={label: failed(status)}))
            result.append(Scenario("native_" + label + "_" + status,
                                   native_results={(label, "normal"): failed(status)}))
        for status in ("budget_exceeded", "trapped"):
            row = {"status": status, "ledger": {"resources": {}}}
            result.append(Scenario("reference_incomplete_" + label + "_" + status,
                reference_results={label: {"status": "returned", "report": {
                    "complete": False, "observations": [row]}}}))
        rows = {"baseline": [returned()], "candidate": [returned()]}
        rows[label] = [{"status": "budget_exceeded", "ledger": {"resources": {}}}]
        result.append(Scenario("row_budget_" + label, reference_rows=rows))
    result.extend([
        Scenario("reference_value_difference", reference_rows={"baseline": [returned(7)], "candidate": [returned(8)]}),
        Scenario("reference_resources_difference", reference_rows={
            "baseline": [returned(resources={"peak": 1})], "candidate": [returned(resources={"peak": 2})]}),
        Scenario("declared_value_mismatch", cases=[{"function": "transform", "arguments": [0],
                                                 "expected": {"status": "returned", "values": [9]}}]),
        Scenario("declared_value_matches", cases=[{"function": "transform", "arguments": [0],
                                                 "expected": {"status": "returned", "values": [7]}}]),
        Scenario("native_wrong_value", native_results={("candidate", "normal"): native_normal(value=8)}),
        Scenario("native_mismatch_flag", native_results={("baseline", "normal"): native_normal(mismatch=True)}),
        Scenario("native_completed_count_mismatch", native_results={("baseline", "normal"): native_normal(completed=0)}),
        Scenario("native_observations_count_mismatch", native_results={("candidate", "normal"): native_normal(observations=[])}),
        Scenario("latency_zero", metric="latency_ns", native_results={
            ("baseline", "normal"): native_normal(total="0"), ("candidate", "normal"): native_normal(total="0")}),
        Scenario("latency_integer_conversion", metric="latency_ns", native_results={
            ("baseline", "normal"): native_normal(total="\u2003+\u0661_\u0660\u2003"),
            ("candidate", "normal"): native_normal(total=b" 5 ")}),
        Scenario("latency_invalid_integer", metric="latency_ns", native_results={
            ("candidate", "normal"): native_normal(total="not an integer")}),
        Scenario("latency_ratio_overflow", metric="latency_ns", native_results={
            ("baseline", "normal"): native_normal(total="1"),
            ("candidate", "normal"): native_normal(total=str(2**2048))}),
        Scenario("empty_workload_schema_error", cases=[]),
        Scenario("unknown_public_entry", cases=[{"function": "absent", "arguments": [0]}]),
        Scenario("bad_argument_type", cases=[{"function": "transform", "arguments": [True]}]),
        Scenario("bad_memory_decimal", context_changes={"budget": {"max_memory_bytes": "-1"}}),
        Scenario("wrong_frozen_baseline", context_changes={"baseline_core_sha256": "c" * 64}),
        Scenario("different_abi", metadata_changes={"candidate": {"signatures": {
            "transform": {"params": ["u16"], "returns": ["u8"]}}}}),
    ])
    for label in ("baseline", "candidate"):
        result.append(Scenario("nonshared_" + label, metadata_changes={label: {"output_kind": "object"}}))
    matching_traps = {"baseline": [trapped()], "candidate": [trapped()]}
    result.extend([
        Scenario("matching_trap_artifacts", reference_rows=matching_traps),
        Scenario("matching_trap_latency", metric="latency_ns", reference_rows=matching_traps),
        Scenario("different_first_trap", reference_rows={"baseline": [trapped("FIRST")], "candidate": [trapped("SECOND")]}),
        Scenario("reference_return_vs_trap", reference_rows={"baseline": [returned()], "candidate": [trapped()]}),
    ])
    for label in ("baseline", "candidate"):
        for status in ("returned", "budget_exceeded", "faulted", "invalid_report"):
            result.append(Scenario("native_trap_" + label + "_" + status, reference_rows=matching_traps,
                native_results={(label, "traps"): failed(status)}))
    mixed = [{"function": "transform", "arguments": [index]} for index in range(4)]
    mixed_rows = [returned(7), trapped("FIRST"), returned(9), trapped("SECOND")]
    result.append(Scenario("mixed_normal_and_two_traps", cases=mixed,
        reference_rows={"baseline": mixed_rows, "candidate": mixed_rows}))
    result.append(Scenario("mixed_first_trap_failure_skips_second_and_candidate", cases=mixed,
        reference_rows={"baseline": mixed_rows, "candidate": mixed_rows},
        native_results={("baseline", "traps"): [failed("invalid_report")]}))
    result.append(Scenario("mixed_candidate_trap_failure_keeps_baseline", cases=mixed,
        reference_rows={"baseline": mixed_rows, "candidate": mixed_rows},
        native_results={("candidate", "traps"): [failed("budget_exceeded")]}))
    for trap in (False, True):
        name = "trap" if trap else "return"
        result.append(buffer_case("buffer_" + name + "_matches", trap=trap))
        ignored = buffer_case("buffer_" + name + "_declared_scalar_scope", trap=trap)
        ignored.cases[0]["expected"] = {"status": "trapped"} if trap else {"status": "returned", "values": [7]}
        result.append(ignored)
        declared = buffer_case("buffer_" + name + "_declared_full_scope", trap=trap)
        declared.cases[0]["expected"] = {key: deepcopy(value) for key, value in declared.reference_rows["baseline"][0].items()
                                         if key in ("status", "values", "buffers")}
        result.append(declared)
        mismatch = deepcopy(declared); mismatch.name = "buffer_" + name + "_declared_mismatch"
        mismatch.cases[0]["expected"]["buffers"][0]["sha256"] = "f" * 64
        result.append(mismatch)
        ref_diff = buffer_case("buffer_" + name + "_reference_differs", trap=trap)
        ref_diff.reference_rows["candidate"][0]["buffers"][0]["sha256"] = "f" * 64
        result.append(ref_diff)
    for suffix, snapshots in (("missing", None), ("empty", []), ("null_entry", [None]), ("wrong", [{"buffers": []}])):
        case = buffer_case("buffer_trap_snapshots_" + suffix, trap=True)
        outcome = failed("trapped")
        if snapshots is not None:
            outcome["buffer_snapshots"] = snapshots
        case.native_results[("baseline", "traps")] = outcome
        result.append(case)
    # Simultaneous invalid inputs freeze which check or foreign effect wins.
    result.extend([
        Scenario("build_validation_before_output_kind", metadata_changes={"baseline": {"output_kind": "object"}},
                 failure=("build_receipt", 1, "ValueError")),
        Scenario("output_kind_before_abi_and_baseline", metadata_changes={"baseline": {"output_kind": "object"},
                 "candidate": {"signatures": {"transform": {"params": [], "returns": []}}}},
                 context_changes={"baseline_core_sha256": "c" * 64}),
        Scenario("abi_before_frozen_baseline", metadata_changes={"candidate": {"signatures": {
                 "transform": {"params": [], "returns": []}}}}, context_changes={"baseline_core_sha256": "c" * 64}),
        Scenario("baseline_before_claims", context_changes={"baseline_core_sha256": "c" * 64},
                 failure=("required_claims", 1, "ValueError")),
        Scenario("claims_before_workload", cases=[], failure=("required_claims", 1, "ValueError")),
    ])
    for effect, occurrence in (("monotonic_ns", 1), ("context", 1), ("native", 1), ("native", 2),
            ("build_receipt", 1), ("program_sha256", 1), ("required_claims", 1), ("get_json", 1),
            ("execute", 1), ("fetchone", 1), ("time_ns", 1), ("run_reference_batch", 1),
            ("run_reference_batch", 2), ("claim", 1), ("budget_run", 1), ("budget_run", 2),
            ("complete", 1), ("native_ns", 1), ("json", 1), ("cost_ledger", 1), ("json", 2), ("json", 3)):
        result.append(Scenario("foreign_error_" + effect + "_" + str(occurrence),
                               failure=(effect, occurrence, "ValueError")))
    for effect, occurrence in (("run_reference_batch", 1), ("claim", 1), ("budget_run", 1),
                              ("complete", 1), ("json", 1), ("cost_ledger", 1)):
        result.append(Scenario("interrupted_" + effect + "_" + str(occurrence),
                               failure=(effect, occurrence, "KeyboardInterrupt")))
    names = [case.name for case in result]
    if len(names) != len(set(names)):
        raise AssertionError("independent fixture names are not unique")
    return result
