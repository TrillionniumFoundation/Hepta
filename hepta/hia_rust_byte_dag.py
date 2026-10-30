"""Explicit raw-Core admission and execution by the finite Rust byte-DAG mode.

Python checks bounded wire syntax and binds the actual pinned process response.
It imports no Core verifier, normalizer, static analyzer or evaluator. Semantic
admission belongs to the selected Rust mode. This is not a receipt importer,
native executor or replacement for default/source/nominal production admission.
"""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import re

from .hia_json_preflight import preflight_hia_json
from . import hia_rust_crosscheck as _transport

MAX_CORE_BYTES = 8 * 1024 * 1024
MAX_REPORT_BYTES = 8 * 1024 * 1024
PROFILE = "raw-byte-dag-v1"
HEAP_PROFILE = "raw-byte-dag-finite-heap-v1"
_METRICS = {"max_allocator_interactions", "max_vm_ticks", "max_call_depth"}
_CLAIMS = {
    "raw_primitive_core_admitted_by_rust": True,
    "all_functions_checked_before_execution": True,
    "static_limits_checked_before_execution": True,
    "single_immutable_core_snapshot_used": True,
    "python_verifier_required_for_this_mode": False,
    "rust_interpreter_admission_authority_for_this_profile": True,
    "default_production_admission_changed": False,
    "nominal_or_source_lowering_supported": False,
    "native_execution_authorized": False,
    "whole_language_soundness_proved": False,
    "native_backend_refinement_proved": False,
    "process_rss_or_native_time_bounded": False,
    "successful_return_or_cleanup_guaranteed": False,
}
_RESOURCE_FIELDS = {
    "allocations", "frees", "allocation_attempts", "owners_created", "owners_dropped",
    "live_owners", "live_bytes", "peak_bytes", "loans_started", "loans_ended", "live_local_loans",
}
_CHAIN_FIELDS = {
    "chains_created", "chains_consumed", "live_chains", "chain_nodes_created",
    "chain_nodes_dropped", "live_chain_nodes",
}
_HEAP_CLAIMS = {
    "whole_module_independently_checked": True,
    "exact_scalar_invocation_only": True,
    "owned_call_transfer_accounted": True,
    "external_borrow_payload_counted_in_caller": True,
    "allocation_failure_and_stop_prefixes_in_bound": True,
    "analysis_work_limits_enforced": True,
    "allocation_failure_index_specialized": False,
    "branch_reachability_proved": False,
    "all_function_input_extents_bounded": False,
    "caller_supplied_resource_extents_trusted": False,
    "borrowed_lengths_assumed_exact": False,
    "cleanup_after_trap_or_budget_stop_proved": False,
    "recursive_chain_storage_bounded": False,
    "process_rss_or_native_stack_bytes_bounded": False,
    "source_or_native_backend_refinement_proved": False,
    "whole_language_soundness_proved": False,
    "native_execution_authorized": False,
    "execution_used_to_establish_bound": False,
}
_HEAP_WORK_LIMITS = {
    "contexts": ("max_contexts", 1024),
    "transfer_steps": ("max_transfer_steps", 32768),
    "peak_analysis_call_depth": ("max_analysis_call_depth", 64),
    "abstract_value_events": ("max_abstract_value_events", 262144),
}


class HIARustByteDagRejected(ValueError):
    """Wire policy, independent Rust admission or actual-process binding failed."""


def _reject(message):
    raise HIARustByteDagRejected("E_HIA_RUST_BYTE_DAG: " + message)


def _canonical(value):
    # Rust serde_json emits UTF-8 and sorts its object keys. This is a JSON
    # representation identity check, not a Python semantic normalization.
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _equal(actual, expected, label):
    if _canonical(actual) != _canonical(expected):
        _reject(label + " differs from the exact invocation contract")


def _keys(value, expected, label):
    if type(value) is not dict or set(value) != expected:
        _reject(label + " has unexpected or missing fields")


def _unsigned(value, label):
    if type(value) is not int or not 0 <= value < 1 << 64:
        _reject(label + " must be an exact unsigned u64 integer")
    return value


def _wire_integer(token):
    if len(token) > 20:
        _reject("raw JSON integer exceeds the bounded Rust wire range")
    value = int(token)
    if not -(1 << 63) <= value < 1 << 64:
        _reject("raw JSON integer exceeds the bounded Rust wire range")
    return value


def _raw_snapshot(raw_core):
    if type(raw_core) is not bytes or not 0 < len(raw_core) <= MAX_CORE_BYTES:
        _reject("raw Core must be bounded immutable bytes")
    try:
        text = raw_core.decode("utf-8")
        preflight_hia_json(text, max_nodes=262144, max_depth=64)
        body = json.loads(text, parse_int=_wire_integer)
        canonical = _canonical(body)
    except (ValueError, UnicodeError, RecursionError, OverflowError) as exc:
        raise HIARustByteDagRejected("E_HIA_RUST_BYTE_DAG: malformed bounded raw JSON") from exc
    if len(canonical) > MAX_CORE_BYTES:
        _reject("canonical raw JSON exceeds the wire budget")
    return body, sha256(canonical).hexdigest()


def _scalar_result(value, typ):
    if typ == "bool":
        return type(value) is bool
    if typ == "unit":
        return value is None
    widths = {"i8": 8, "i16": 16, "i32": 32, "i64": 64, "isize": 64,
              "u8": 8, "u16": 16, "u32": 32, "u64": 64, "usize": 64}
    if type(value) is not int or typ not in widths:
        return False
    bits = widths[typ]
    return (-(1 << (bits - 1)) <= value < 1 << (bits - 1) if typ.startswith("i")
            else 0 <= value < 1 << bits)


def _validate_runtime(runtime, request, body, entry_bound):
    _keys(runtime, {"schema", "request", "request_sha256", "execution"}, "v4 runtime envelope")
    expected_request = {
        "schema": "hepta.hia.rust-execution-request.v4", "mode": "owned",
        "program_sha256": request["program_sha256"], "function": request["function"],
        "arguments": request["arguments"], "policy": request["execution_policy"],
    }
    _equal({k: runtime[k] for k in ("schema", "request", "request_sha256")}, {
        "schema": "hepta.hia.rust-bound-execution.v4", "request": expected_request,
        "request_sha256": sha256(_canonical(expected_request)).hexdigest(),
    }, "v4 request binding")
    run = runtime["execution"]
    if type(run) is not dict or run.get("status") not in {"returned", "trapped", "budget_exceeded"}:
        _reject("unknown execution outcome")
    outcome = "values" if run["status"] == "returned" else "error"
    fixed_keys = {"schema", "function", "program_sha256", "max_steps", "max_call_depth",
                  "profile", "claims", "max_heap_bytes", "allocation_fail_at"}
    _keys(run, fixed_keys | {"status", "steps", "resources", outcome}, "Rust execution")
    profile, claims = _transport._execution_claims({"schema": body["schema"], "functions": []})
    _equal({key: run[key] for key in fixed_keys}, {
        "schema": "hepta.hia.rust-byte-owner-execution.v2",
        "function": request["function"], "program_sha256": request["program_sha256"],
        "profile": profile, "claims": claims, **request["execution_policy"],
    }, "runtime profile/claims/policy")
    steps = _unsigned(run["steps"], "execution steps")
    if not 1 <= steps <= entry_bound["max_vm_ticks"]:
        _reject("execution ticks escape the admitted structural bound")
    ledger = run["resources"]
    chains = _CHAIN_FIELDS if body["schema"] in {"hepta.hia.program.v7", "hepta.hia.program.v8"} else set()
    _keys(ledger, _RESOURCE_FIELDS | chains, "resource ledger")
    for field, value in ledger.items():
        _unsigned(value, "resource " + field)
    if (any(ledger[field] != 0 for field in chains)
            or not ledger["live_bytes"] <= ledger["peak_bytes"] <= run["max_heap_bytes"]
            or ledger["frees"] > ledger["allocations"]
            or ledger["allocations"] > ledger["allocation_attempts"]
            or ledger["owners_dropped"] > ledger["owners_created"]
            or ledger["live_owners"] != ledger["owners_created"] - ledger["owners_dropped"]
            or ledger["allocation_attempts"] + ledger["frees"] > entry_bound["max_allocator_interactions"]):
        _reject("resource ledger escapes the byte-only contract")
    if outcome == "values":
        entry = next(fn for fn in body["functions"] if fn["name"] == request["function"])
        values, returns = run["values"], entry["returns"]
        if (type(values) is not list or len(values) != len(returns)
                or any(not _scalar_result(v, typ) for v, typ in zip(values, returns))
                or any(ledger[field] for field in ("live_bytes", "live_owners", "live_local_loans"))
                or ledger["allocations"] != ledger["frees"]
                or ledger["loans_started"] != ledger["loans_ended"]):
            _reject("successful scalar return has an invalid result or retained resources")
    else:
        _keys(run["error"], {"code"}, "execution error")
        permitted = ({"steps", "heap", "calls"} if run["status"] == "budget_exceeded" else
                     {"user", "overflow", "division_by_zero", "bounds", "allocation"})
        if run["error"]["code"] not in permitted:
            _reject("unknown execution error code")
        if (run["status"] == "budget_exceeded" and run["error"]["code"] == "calls"
                and entry_bound["max_call_depth"] <= run["max_call_depth"]):
            _reject("call-depth stop contradicts the structural depth bound")
    stopped_on_ticks = run["status"] == "budget_exceeded" and run["error"]["code"] == "steps"
    if (steps != run["max_steps"] + 1 if stopped_on_ticks else steps > run["max_steps"]):
        _reject("runtime tick limit and outcome disagree")


def _validate_heap_report(heap, request, body, budget, entry_bound, runtime):
    """Bind a producer's independently computed facts; do not recompute semantics."""
    _keys(heap, {"schema", "profile", "status", "program_sha256", "core_schema",
                 "function", "arguments", "limit_bytes", "peak_bound_bytes",
                 "static_budget_sha256", "analysis_work", "claims"} | _METRICS,
          "finite invocation heap bound")
    if body["schema"] not in {"hepta.hia.program.v7", "hepta.hia.program.v8"}:
        _reject("finite invocation heap bound is outside primitive v7/v8")
    borrowed_extents = body["schema"] == "hepta.hia.program.v8"
    expected = {
        "schema": "hepta.hia.rust-finite-entry-heap.v1",
        "profile": ("acyclic-byte-owner-transfer-caller-borrowed-extents-v8" if borrowed_extents
                    else "acyclic-byte-owner-transfer-v7"),
        "status": "conservative_finite_invocation_payload_bound_not_authority",
        "program_sha256": request["program_sha256"], "core_schema": body["schema"],
        "function": request["function"], "arguments": request["arguments"],
        "limit_bytes": request["heap_policy"]["max_live_heap_bytes"],
        "static_budget_sha256": sha256(_canonical(budget)).hexdigest(),
        "claims": {**_HEAP_CLAIMS,
                   "borrowed_extents_derived_from_caller_roots": borrowed_extents,
                   "parameter_bound_returned_loans_checked": borrowed_extents},
        **{metric: entry_bound[metric] for metric in _METRICS},
    }
    _equal({key: heap[key] for key in expected}, expected, "finite heap invocation/claims")
    peak = _unsigned(heap["peak_bound_bytes"], "finite heap peak bound")
    if not runtime["execution"]["resources"]["peak_bytes"] <= peak <= heap["limit_bytes"]:
        _reject("Machine payload prefix escapes the admitted finite heap bound")
    work = heap["analysis_work"]
    _keys(work, set(_HEAP_WORK_LIMITS) | {v[0] for v in _HEAP_WORK_LIMITS.values()},
          "finite heap analysis work")
    for actual, (limit_name, limit) in _HEAP_WORK_LIMITS.items():
        _equal(work[limit_name], limit, "finite heap work limit " + limit_name)
        if not 1 <= _unsigned(work[actual], actual) <= limit:
            _reject("finite heap analysis work escapes its fixed limit")
    if work["peak_analysis_call_depth"] > work["contexts"]:
        _reject("finite heap analysis depth exceeds its context inventory")


def _validate_report(raw, request, body):
    # Bound response tree construction as well as bytes. A valid result may
    # contain a long scalar return list in addition to two bound request copies.
    preflight_hia_json(raw.decode("utf-8"), max_nodes=1048576, max_depth=64)
    report = _transport._report_line(raw, MAX_REPORT_BYTES)
    heap_mode = request["profile"] == HEAP_PROFILE
    _keys(report, {"schema", "profile", "status", "request_sha256", "request",
                   "static_budget", "runtime", "claims"} | ({"heap_bound"} if heap_mode else set()),
          "byte-DAG envelope")
    claims = {**_CLAIMS, **({"finite_entry_live_payload_limit_checked_before_execution": True}
                          if heap_mode else {})}
    _equal({k: report[k] for k in ("schema", "profile", "status", "request_sha256", "request", "claims")}, {
        "schema": ("hepta.hia.rust-byte-dag-heap-run.v1" if heap_mode else "hepta.hia.rust-byte-dag-run.v1"),
        "profile": HEAP_PROFILE if heap_mode else PROFILE,
        "status": "admitted_and_observed", "request": request,
        "request_sha256": sha256(_canonical(request)).hexdigest(), "claims": claims,
    }, "raw byte-DAG request/authority binding")
    if (type(body) is not dict or body.get("schema") not in {
            f"hepta.hia.program.v{version}" for version in range(1, 9)}
            or type(body.get("functions")) is not list or not 1 <= len(body["functions"]) <= 1024):
        _reject("Rust response claims admission outside the primitive module profile")
    budget = report["static_budget"]
    _keys(budget, {"schema", "profile", "status", "program_sha256", "core_schema", "functions", "claims"},
          "independent static bounds")
    _equal({key: budget[key] for key in budget if key != "functions"}, {
        "schema": "hepta.hia.rust-static-budget.v1", "profile": _transport._STATIC_BUDGET_PROFILE,
        "status": "conservative_structural_upper_bounds_not_authority",
        "program_sha256": request["program_sha256"], "core_schema": body["schema"],
        "claims": _transport._STATIC_BUDGET_CLAIMS,
    }, "static profile/identity/claims")
    rows = budget["functions"]
    if type(rows) is not list or len(rows) != len(body["functions"]):
        _reject("incomplete static function inventory")
    entry_bound = None
    for row, function in zip(rows, body["functions"]):
        _keys(row, _METRICS | {"function"}, "static function row")
        if row["function"] != function["name"]:
            _reject("static function inventory differs from raw Core")
        for metric in _METRICS:
            if _unsigned(row[metric], metric) > request["static_policy"][metric]:
                _reject("observed bound exceeds the explicit static limit")
        if row["max_vm_ticks"] < 2 or row["max_call_depth"] < 1:
            _reject("static bounds omit function entry/termination")
        if row["function"] == request["function"]:
            entry_bound = row
    if entry_bound is None:
        _reject("selected entry has no static bound")
    _validate_runtime(report["runtime"], request, body, entry_bound)
    if heap_mode:
        _validate_heap_report(report["heap_bound"], request, body, budget, entry_bound, report["runtime"])
    return report


def execute_rust_byte_dag(raw_core: bytes, function: str, arguments: list | tuple,
                         executable: str | Path, *, executable_sha256: str,
                         static_policy: dict, max_steps: int = 1_000_000,
                         max_heap_bytes: int = 16 * 1024 * 1024, max_call_depth: int = 256,
                         allocation_fail_at: int | None = None, timeout: float = 30.0,
                         max_static_live_heap_bytes: int | None = None):
    """Run the actual pinned Rust binary as this raw byte-DAG mode's authority.

    static_policy requires all three unsigned u64 metrics and applies to every
    function. Runtime limits retain exact v4 semantics and may stop before the
    structural upper bound. Input must be raw primitive JSON bytes; no Python
    semantic verifier or nominal normalizer is called, even on invalid Core.

    max_static_live_heap_bytes explicitly selects raw-byte-dag-finite-heap-v1:
    the same Rust admission snapshot independently derives a logical payload
    bound for this exact scalar v7/v8 invocation, covering allocator failure and
    stop prefixes without executing the Machine to establish the bound. The
    default None preserves raw-byte-dag-v1. This does not bound RSS or authorize
    a native backend, source lowering or imported resource extents.

    The executable pin, loader/libraries/kernel and caller process are trusted.
    Exact request checks reject stale/cross-policy replies; they are not a
    cryptographic proof against a hostile selected executable or replaced
    process transport. Python/Rust semantic parity is tested separately.
    """
    if (type(timeout) not in (int, float) or not 0 < timeout <= 120
            or type(max_steps) is not int or not 1 <= max_steps <= 10_000_000
            or type(max_heap_bytes) is not int or not 0 <= max_heap_bytes <= 1024 * 1024 * 1024
            or type(max_call_depth) is not int or not 1 <= max_call_depth <= 256
            or allocation_fail_at is not None and
               (type(allocation_fail_at) is not int or allocation_fail_at < 1)):
        _reject("runtime policy is outside the explicit v4 profile")
    if max_static_live_heap_bytes is not None and (
            type(max_static_live_heap_bytes) is not int or not 0 <= max_static_live_heap_bytes < 1 << 63):
        _reject("static live heap limit requires an exact integer in 0..2^63-1")
    if type(function) is not str or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", function) is None:
        _reject("function must be a bounded ASCII entry name")
    if (type(arguments) not in (list, tuple) or len(arguments) > _transport.MAX_ARGUMENTS
            or any(type(value) not in (int, bool, type(None)) or type(value) is int
                   and not -(1 << 63) <= value < 1 << 64 for value in arguments)):
        _reject("arguments require bounded exact scalar wire values")
    arguments = list(arguments)
    argument_wire = _canonical(arguments)
    if len(argument_wire) > _transport.MAX_ARGUMENT_BYTES:
        _reject("arguments exceed the bounded wire size")
    _keys(static_policy, _METRICS, "static policy")
    for metric, value in static_policy.items():
        _unsigned(value, metric)
    # Snapshot the caller's mutable containers before launching the process.
    static_policy = dict(static_policy)
    body, program_sha256 = _raw_snapshot(raw_core)
    try:
        policy = _transport._execution_wire_policy({
            "max_steps": max_steps, "max_heap_bytes": max_heap_bytes,
            "max_call_depth": max_call_depth, "allocation_fail_at": allocation_fail_at,
        }, 4)
        heap_mode = max_static_live_heap_bytes is not None
        request = {"schema": ("hepta.hia.rust-byte-dag-heap-request.v1" if heap_mode
                              else "hepta.hia.rust-byte-dag-request.v1"),
            "profile": HEAP_PROFILE if heap_mode else PROFILE,
            "input_sha256": sha256(raw_core).hexdigest(), "program_sha256": program_sha256,
            "function": function, "arguments": arguments, "static_policy": static_policy,
            "execution_policy": policy}
        launch_arguments = ["--byte-dag-heap-admit-run" if heap_mode else "--byte-dag-admit-run",
            function, argument_wire.decode("ascii"), _canonical(static_policy).decode("ascii")]
        if heap_mode:
            request["heap_policy"] = {"max_live_heap_bytes": max_static_live_heap_bytes}
            launch_arguments.append(_canonical(request["heap_policy"]).decode("ascii"))
        launch_arguments.append(_canonical(policy).decode("ascii"))
        raw_executable = _transport._verified_executable_bytes(Path(executable), executable_sha256)
        stdout, stderr, returncode = _transport._run_pinned_shadow(raw_executable, launch_arguments,
            raw_core, timeout, maximum_output=MAX_REPORT_BYTES)
        if returncode != 0 or stderr:
            _reject("Rust rejected raw admission/execution or emitted unexpected diagnostics")
        report = _validate_report(stdout, request, body)
    except (ValueError, TypeError, KeyError, IndexError, StopIteration, UnicodeError,
            RecursionError, OverflowError) as exc:
        if isinstance(exc, HIARustByteDagRejected):
            raise
        raise HIARustByteDagRejected("E_HIA_RUST_BYTE_DAG: process or response contract rejected") from exc
    return {"schema": ("hepta.hia.rust-byte-dag-heap-invocation.v1" if heap_mode
                       else "hepta.hia.rust-byte-dag-invocation.v1"),
            "executable_sha256": executable_sha256, "rust_report": report}
