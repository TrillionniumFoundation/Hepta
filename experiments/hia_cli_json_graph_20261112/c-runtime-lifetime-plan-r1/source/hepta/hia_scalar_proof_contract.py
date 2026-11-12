"""Scope for the public scalar SMT validators, including non-proof outcomes.

These fields describe the checker that ran and the property it attempted. They
are not a proof of the Python implementation, an ISA theorem, or permission to
execute code. Existing result fields remain available to existing consumers.
"""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import platform
import time

SCHEMA = "hepta.hia.scalar-proof-scope.v1"
FIELDS = ("subject", "property", "profile", "assumptions", "checker", "unproved_obligations")
PROVED_MEANING = (
    "The identified SMT checker established only the stated property for the "
    "identified Core subject within this profile and under these assumptions. "
    "Unproved obligations remain open; this is neither global safety nor execution authority."
)

_PROPERTIES = {
    "validate_translation": (
        "all_input_return_and_first_trap_equivalence",
        "For every well-typed argument tuple, the selected before and after functions "
        "have the same return values or the same first specified Core trap code."),
    "validate_scalar_calls": (
        "all_input_call_closure_return_and_first_trap_equivalence",
        "For every well-typed argument tuple, the selected before and after direct-call "
        "closures have the same return values or the same first specified Core trap code."),
    "validate_bounded_translation": (
        "all_input_feedback_bound_and_return_and_first_trap_equivalence",
        "For every well-typed argument tuple, the original selected function traverses "
        "the identified feedback edge at most max_backedges times, and the candidate "
        "preserves its return values or first specified Core trap code. The bound is "
        "a checked obligation, not an assumed loop bound."),
    "validate_scalar_totality": (
        "all_input_normal_return",
        "For every well-typed argument tuple, the selected function reaches a normal "
        "Core return with no specified Core trap or missing symbolic outcome."),
    "validate_scalar_call_totality": (
        "all_input_call_closure_normal_return",
        "For every well-typed argument tuple, the selected direct-call closure reaches "
        "a normal Core return with no specified Core trap or missing symbolic outcome."),
}
_MODULES = {
    "validate_translation": "hia_translation_validation",
    "validate_scalar_calls": "hia_scalar_call_validation",
    "validate_bounded_translation": "hia_bounded_unroll",
    "validate_scalar_totality": "hia_scalar_totality",
    "validate_scalar_call_totality": "hia_scalar_totality",
}
_DEPENDENCIES = (
    "hia_scalar_proof_contract.py", "hia_translation_validation.py",
    "hia_program.py", "hia_capability_flow.py", "hia_opcodes.py", "hia_schema.py",
    "hia_json_preflight.py", "hia_program_composite.py", "hia_program_runtime.py",
    "hia_bounded_memory.py", "hia_optimization.py", "hia_program_llvm.py",
)


def _item(identity, statement):
    return {"id": identity, "statement": statement}


def _source_identity(name):
    names = set(_DEPENDENCIES) | {_MODULES[name] + ".py"}
    if name == "validate_scalar_call_totality":
        names.add("hia_scalar_call_validation.py")
    return {n: sha256(Path(__file__).with_name(n).read_bytes()).hexdigest() for n in sorted(names)}


def begin_scalar_proof(name):
    """Observe named checker inputs before checking; an absent identity fails closed."""
    scope = {"name": name, "source_identity": None}
    try:
        scope["source_identity"] = _source_identity(name)
    except (OSError, ValueError) as error:
        scope["identity_error"] = type(error).__name__
    return scope


def _solver_identity(result):
    solver = result.get("bound_solver") if "bound_solver" in result else result.get("solver")
    if not isinstance(solver, dict):
        return None
    if isinstance(solver.get("identity"), dict):
        return solver["identity"]
    if "binding_sha256" in solver and "library_sha256" in solver:
        return solver
    return None


def _unestablished(result, reason):
    result.update(status="unknown", reason=reason, counterexample=None)
    for key, value in result.get("claims", {}).items():
        if value is True:
            result["claims"][key] = False


def finish_scalar_proof(result, scope, *, started_ns=None, deadline_ms=None):
    """Bind the actual outcome without promoting checks, tests, or unknowns to proofs."""
    name = scope["name"]
    identity = scope["source_identity"]
    solver = _solver_identity(result)
    if result["status"] in {"proved", "disproved"}:
        try:
            if identity is None or identity != _source_identity(name):
                _unestablished(result, "scope_checker_identity_changed_or_unavailable")
            elif solver is None:
                _unestablished(result, "scope_solver_identity_unavailable")
        except (OSError, ValueError):
            _unestablished(result, "scope_checker_identity_unavailable")
    if started_ns is not None:
        result["wall_ns"] = time.monotonic_ns() - started_ns
        if (type(deadline_ms) is int and deadline_ms > 0
                and result["wall_ns"] > deadline_ms * 1_000_000
                and result["status"] in {"proved", "disproved"}):
            _unestablished(result, "proof_deadline_exhausted")
    totality = name in {"validate_scalar_totality", "validate_scalar_call_totality"}
    subject = {"kind": "canonical_core" if totality else "canonical_core_comparison",
               "function": result.get("function"),
               "selection": "selected_public_scalar_call_closure" if "call" in name
                            else "selected_public_scalar_function"}
    keys = ("program_sha256", "input_sha256") if totality else (
        "before_sha256", "after_sha256", "before_input_sha256", "after_input_sha256")
    subject.update({key: result.get(key) for key in keys})
    if "call_closures" in result:
        subject["call_closures"] = deepcopy(result["call_closures"])
    if "call_closure" in result:
        subject["call_closure"] = deepcopy(result["call_closure"])
    if name == "validate_bounded_translation":
        subject.update(reference_sha256=result.get("reference_sha256"),
                       feedback_edge=deepcopy(result.get("feedback_edge")),
                       max_backedges=result.get("max_backedges"))
    property_id, statement = _PROPERTIES[name]
    assumptions = [
        _item("typed_inputs", "The quantified domain is every argument tuple of the selected verified Core signature and its fixed-width scalar types."),
        _item("core_semantics", "The qualified primitive v1-v7 Core scalar semantics, trap ordering and the declared profile limits define the observations."),
        _item("trusted_implementation", "The listed Python checker, verifier, encoder and counterexample replay implementations are trusted; their correctness is not machine-proved."),
        _item("loaded_source", "The executing imported code corresponds to the recorded on-disk source inventory; no concurrent code, solver or process tampering occurs. Source hashes do not attest loaded memory."),
        _item("solver", "The identified Z3 Python binding and native library correctly answer the generated bit-vector queries; Python, the host OS and hardware execute them correctly."),
        _item("point_of_use", "Consumers rebind the exact Core and recompute the required proof at use; a serialized result never grants execution authority."),
    ]
    obligations = [
        _item("checker_soundness", "A machine-checked correctness theorem for the Python verifier, SMT encoders, replay and Z3 remains open."),
        _item("whole_language", "No theorem for all HIA programs or constructs outside this scalar profile is established."),
        _item("other_exports", "Behavior or totality of other public exports is not established by this selected-entry proof."),
        _item("core_to_machine", "Compilation, actual native bytes and ISA refinement are not checked by this Core query."),
        _item("abi_ffi_loading", "ABI, FFI, linking, loading and host-memory contracts require separate validation."),
        _item("resources", "Physical resource quotas, VM instruction budgets, wall time, energy and performance gains are not proved."),
        _item("concurrency", "Concurrency, signals, faults, side channels and hostile process modification are outside this proof."),
    ]
    if not totality:
        obligations.append(_item("normal_return_totality", "Equivalence may preserve a trap; it does not establish that every input returns normally."))
    if result["status"] != "proved":
        obligations.append(_item("requested_property", "The requested property is not established by this result; inspect status, reason and any replayed counterexample."))
    result.update(proof_scope_schema=SCHEMA, proved_meaning=PROVED_MEANING,
        subject=subject, property={"id": property_id, "statement": statement},
        assumptions=assumptions, unproved_obligations=obligations,
        checker={"name": "hepta." + _MODULES[name] + "." + name,
                 "kind": "trusted_executable_smt_checker",
                 "method": "SMT unsatisfiability; concrete canonical-interpreter replay for counterexamples",
                 "source_identity": deepcopy(identity),
                 "source_identity_sha256": sha256(json.dumps(identity, sort_keys=True,
                     separators=(",", ":")).encode()).hexdigest() if identity is not None else None,
                 "source_identity_error": scope.get("identity_error"),
                 "runtime": {"implementation": platform.python_implementation(), "version": platform.python_version()},
                 "solver": deepcopy(solver), "machine_checked_implementation": False},
        execution_authority=False)
    return result


def _same_plain_json(left, right):
    # Scope is an inert JSON contract. Python subclasses must not spoof
    # equality to remove assumptions or turn a different subject into a match.
    if type(left) is not type(right):
        return False
    if type(right) is dict:
        return (len(left) == len(right) and all(type(key) is str for key in left)
                and all(key in left and _same_plain_json(left[key], value)
                        for key, value in right.items()))
    if type(right) is list:
        return len(left) == len(right) and all(_same_plain_json(a, b) for a, b in zip(left, right))
    return type(right) in (str, int, float, bool, type(None)) and left == right


def same_scalar_proof_scope(receipt, fresh):
    """Require the newly recomputed scope, not a caller's broadened description."""
    if not all(key in receipt and _same_plain_json(receipt[key], fresh[key])
               for key in (*FIELDS, "proof_scope_schema", "proved_meaning", "execution_authority")):
        return False
    if fresh.get("equivalence") is not None:
        return (type(receipt.get("equivalence")) is dict
                and same_scalar_proof_scope(receipt["equivalence"], fresh["equivalence"]))
    return True
