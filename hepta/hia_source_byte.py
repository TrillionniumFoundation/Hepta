"""Source-replayed finite HIA byte-path experiment; no new ownership interpreter.

The existing Resource IR/Boolean/byte oracles remain the *only* operational
components. This entrypoint re-derives their input graph from actual checked
Hepta project source before admitting external test actions. The actions are
NOT source-derived SSA operands or a native correctness proof.
"""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import re

from .hia_byte_trace import replay_byte_memory_path
from .pipeline import analyze_project
from .resource_ir import verify_resource_ir
from .resource_lowering import lower_resource_ir
from .semantic_ir import lower_checked_program


class HIASourceByteRejected(ValueError):
    """Cannot bind a finite byte-oracle observation to current checked source."""


def _reject(reason: str) -> None:
    raise HIASourceByteRejected("E_HIA_SOURCE_BYTE: " + reason)


_HASH = re.compile(r"[0-9a-f]{64}\Z")
_MAX_INPUT_BYTES = 1024 * 1024
_MAX_REPORT_BYTES = 8 * 1024 * 1024
_BYTE_CLAIMS = {
    "memory_bytes_match_original_source_proved": False,
    "full_memory_ssa_proved": False,
    "interprocedural_aliasing_proved": False,
    "pointer_provenance_proved": False,
    "allocator_failure_semantics_proved": False,
    "native_llvm_backend_refinement_proved": False,
    "whole_language_soundness_proved": False,
}
_CLAIMS = {
    "resource_projection_replayed_from_checked_source": True,
    "boolean_arguments_bound_to_source_parameters": True,
    "external_byte_actions_are_source_values": False,
    "memory_byte_semantics_match_source_proved": False,
    "source_to_resource_ir_refinement_proved": False,
    "native_backend_refinement_proved": False,
    "pointer_provenance_proved": False,
    "whole_language_soundness_proved": False,
}


def _encode(value: object) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, ensure_ascii=False,
                          separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError, OverflowError) as exc:
        raise HIASourceByteRejected("E_HIA_SOURCE_BYTE: malformed or unbounded input") from exc


def replay_source_byte_path(source: str | Path, function: str, *,
                            boolean_arguments: dict[str, bool],
                            actions: tuple[dict, ...],
                            rustc: str | None = None, native: bool = True,
                            locked: bool = False, fuel: int = 4096) -> dict:
    """Replay one complete resource/byte path bound to an actual Hepta source.

    boolean_arguments uses source parameter names, not internal p0/p1 slots.
    Native=True mandates a real successful Rust validation receipt. The
    opt-in native=False mode is reported as frontend-only, never upgraded.
    Dynamic allocation sizes, indices and write values remain external test
    inputs in both modes; they have no executable Hepta expression provenance.
    """
    if (not isinstance(source, (str, Path)) or not str(source)
            or type(function) is not str or not function or len(function) > 1024
            or type(native) is not bool or type(locked) is not bool
            or type(fuel) is not int or not 1 <= fuel <= 10000
            or type(boolean_arguments) is not dict or len(boolean_arguments) > 16
            or type(actions) is not tuple or len(actions) > 10000
            or any(type(key) is not str or not key or type(value) is not bool
                   for key, value in boolean_arguments.items())
            or any(type(item) is not dict for item in actions)):
        _reject("strict source, mode, bool arguments and bounded byte actions required")
    encoded_inputs = _encode({"arguments": boolean_arguments, "actions": actions})
    if len(encoded_inputs) > _MAX_INPUT_BYTES:
        _reject("input byte action stream exceeds 1 MiB bound")
    # Deep-copy caller-owned action dictionaries: concurrent mutations of the
    # caller object must not alter our value-oracle inputs after admission.
    frozen = json.loads(encoded_inputs)
    booleans = frozen["arguments"]
    actions_snapshot = tuple(frozen["actions"])
    try:
        result = analyze_project(Path(source), backend="rust", native=native,
                                 rustc=rustc, locked=locked, crate_type="rlib")
        report = result.report
        if (type(report) is not dict or report.get("ok") is not True
                or result.program is None or result.checked is None
                or getattr(result.checked, "ok", None) is not True
                or result.project is None):
            _reject("actual checked-source project validation required")
        reference = report.get("checks")
        if type(reference) is not dict:
            _reject("missing explicit Rust native/frontend reference state")
        if native:
            if (reference.get("rust_borrows_types") != "rustc_checked"
                    or report.get("status") not in {
                        "checked", "checked_with_external_assumptions"}
                    or type(report.get("backend")) is not dict
                    or report["backend"].get("ok") is not True):
                _reject("fresh successful pinned native Rust reference required")
        elif (report.get("status") != "frontend_only"
              or reference.get("rust_borrows_types") != "not_run"):
            _reject("frontend-only cannot borrow native Rust verification")
        project = result.project
        if (type(project.identity) is not str or _HASH.fullmatch(project.identity) is None
                or project.unchanged() is not True):
            _reject("complete, unchanged source graph identity required")
        candidate_fns = [fn for fn in result.program.functions
                         if getattr(fn, "name", None) == function]
        if len(candidate_fns) != 1 or candidate_fns[0].extern_c:
            _reject("one implemented source function required")
        fn = candidate_fns[0]
        source_params = fn.params
        if (len(source_params) > 16 or any(
                param.mode != "value" or str(param.type) != "bool" or
                type(param.name) is not str or not param.name
                for param in source_params)):
            _reject("only source-declared by-value bool parameters may select paths")
        names = [param.name for param in source_params]
        if len(set(names)) != len(names) or set(booleans) != set(names):
            _reject("must supply exactly the checked source bool parameters")
        canonical = lower_checked_program(result.program, result.checked,
                                          project_sha256=project.identity)
        if (type(canonical) is not dict or canonical.get("schema") != "hepta.hsir.v0"
                or canonical.get("profile") != "checked_typed_ast_not_verified_mir"
                or canonical.get("all_expressions_typed") is not True
                or canonical.get("untyped_expressions") != []
                or any(type(canonical.get(key)) is not list or canonical[key]
                       for key in ("external_obligations", "foreign_assumptions",
                                   "volatile_accesses"))):
            _reject("typed canonical source or closed foreign profile required")
        graph = lower_resource_ir(result.program, result.checked,
                                  project_sha256=project.identity)
        if (type(graph) is not dict
                or graph.get("source_sha256") != canonical.get("source_sha256")
                or graph.get("project_sha256") != project.identity
                or graph.get("obligations") != {}):
            _reject("Resource IR is not bound to current checked source identity")
        functions = graph.get("functions")
        if type(functions) is not list:
            _reject("missing source-derived Resource IR inventory")
        selected = [resource_fn for resource_fn in functions
                    if type(resource_fn) is dict and resource_fn.get("name") == function]
        if len(selected) != 1:
            _reject("Resource IR function inventory disagrees with source")
        slots = selected[0].get("params")
        if (type(slots) is not list or len(slots) != len(names)
                or any(type(param) is not dict or
                       param.get("id") != f"p{index}" or
                       param.get("type") != "bool" or
                       param.get("mode") != "value"
                       for index, param in enumerate(slots))):
            _reject("Resource IR parameter identity/order differs from checked source")
        bound = {f"p{index}": booleans[name] for index, name in enumerate(names)}
        verified = verify_resource_ir(graph)
        if (type(verified) is not dict or verified.get("ok") is not True
                or verified.get("status") != "resource_cfg_verified"):
            _reject("independent resource verifier refused this source graph")
        # The actual independent verifier and Boolean/byte interpreter re-run
        # the Resource IR qualification; a supplied sealed receipt is absent.
        witness = replay_byte_memory_path(
            graph, verified, function, inputs=bound,
            actions=actions_snapshot, fuel=fuel)
        if type(witness) is not dict:
            _reject("byte oracle did not return a structured trace")
        trace_hash = witness.get("trace_sha256")
        witness_claims = witness.get("claims")
        if (type(trace_hash) is not str or _HASH.fullmatch(trace_hash) is None
                or type(witness_claims) is not dict
                or set(witness_claims) != set(_BYTE_CLAIMS)
                or any(witness_claims[key] is not value
                       for key, value in _BYTE_CLAIMS.items())
                or witness.get("function") != function
                or witness.get("schema") != "hepta.hia-byte-memory-trace.v0"
                or witness.get("status") != "finite_external_byte_actions_over_verified_resource_path"):
            _reject("byte oracle returned an incompatible or elevated proof profile")
        # Follow the EXISTING byte interpreter's canonical wire encoding,
        # including its default ensure_ascii=True. A self-rehashed but
        # semantically false receipt still fails strict claims and source replay.
        trace_payload = {key: value for key, value in witness.items()
                         if key != "trace_sha256"}
        trace_bytes = json.dumps(trace_payload, sort_keys=True,
                                 separators=(",", ":"), allow_nan=False).encode("utf-8")
        if (len(trace_bytes) > _MAX_REPORT_BYTES
                or sha256(trace_bytes).hexdigest() != trace_hash
                or project.unchanged() is not True
                or verified.get("ir_sha256") != witness.get("resource_ir_sha256")
                or witness.get("external_allocation_extents_and_memory_actions") is not True):
            _reject("source changed or byte oracle evidence does not match its exact bytes")
        output = {
            "schema": "hepta.hia-source-byte-path.v1",
            "status": "finite_checked_source_resource_path_external_byte_actions",
            "reference": "pinned_rustc_checked" if native else "frontend_only",
            "source_sha256": canonical["source_sha256"],
            "project_sha256": project.identity,
            "resource_ir_sha256": verified["ir_sha256"],
            "function": function,
            "boolean_arguments": booleans,
            "byte_action_input_sha256": sha256(encoded_inputs).hexdigest(),
            "byte_trace_sha256": witness["trace_sha256"],
            "byte_trace": witness,
            "claims": dict(_CLAIMS),
        }
        encoded = _encode(output)
        if len(encoded) > _MAX_REPORT_BYTES:
            _reject("bounded source witness report exceeds 8 MiB")
        output["receipt_sha256"] = sha256(encoded).hexdigest()
        return output
    except HIASourceByteRejected:
        raise
    except (ValueError, OSError, UnicodeError, TypeError, AttributeError,
            KeyError, RecursionError, OverflowError) as exc:
        raise HIASourceByteRejected(
            "E_HIA_SOURCE_BYTE: unable to qualify current source and finite path: " + str(exc)) from exc
