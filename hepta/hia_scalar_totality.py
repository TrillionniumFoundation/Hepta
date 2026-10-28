"""Fresh all-input normal-return proofs for the finite scalar HIA encoder.

This is distinct from equivalence: a program can be equivalent to itself and
still trap. Only UNSAT of ``outcome_tag != 0`` proves normal return. The tag's
negative missing-path sentinel is included, so incomplete execution cannot
vacuously establish totality. Consumers must recompute; a receipt is evidence,
not admission authority. Native runtimes may impose a narrower opcode profile.
"""
from __future__ import annotations

from hashlib import sha256
from pathlib import Path

from .hia_program import HIAProgramRejected, verify_program
from . import hia_translation_validation as semantics

SCHEMA = "hepta.hia.scalar-totality.v1"
PROFILE = "hia.scalar-acyclic-bitvector-totality.v1"


def _implementation_digest():
    return sha256(Path(__file__).read_bytes()).hexdigest()


def validate_scalar_totality(document, *, function=None, timeout_ms=2000):
    """Prove one public scalar function returns normally on every typed input.

    Canonical validation and the existing acyclic scalar profile run first.
    Every invocation constructs a new independent Z3 context and solver. SAT
    becomes ``disproved`` only after the canonical VM replays the same first
    trap. Unsupported programs, missing paths, solver exhaustion/unavailability
    and disagreements remain ``unknown``. No proof of LLVM or of resources is
    implied by this scalar normal-return property.
    """
    result = {
        "schema": SCHEMA, "profile": PROFILE, "status": "unknown",
        "function": function, "scope": "selected_public_scalar_function",
        "program_sha256": None, "input_sha256": None,
        "validator_sha256": _implementation_digest(),
        "encoder_sha256": semantics._implementation_digest(),
        "encoder_profile": semantics.PROFILE,
        "structural_verification": False, "reason": None, "counterexample": None,
        "solver": {"name": "z3", "version": None, "result": "not_run",
                   "timeout_ms": timeout_ms},
        "claims": {
            "all_inputs_return_normally_proved": False,
            "canonical_core_reverified": False,
            "resource_bounds_proved": False,
            "encoder_refinement_machine_proved": False,
            "native_backend_refinement_proved": False,
            "serialized_receipt_authorizes_execution": False,
        },
        "limits": [
            "Only the selected public scalar function is proved total.",
            "The canonical verifier, scalar encoder and Z3 are trusted implementations.",
            "Acyclic control flow only; calls, resources and floating point are outside the profile.",
            "Native execution, physical time and resource quotas are not proved by this query.",
            "Consumers must recompute on exact bytes before admitting executable code.",
        ],
    }
    if type(timeout_ms) is not int or not 1 <= timeout_ms <= semantics.MAX_TIMEOUT_MS:
        result["reason"] = "invalid_solver_timeout"
        return result
    try:
        program = verify_program(document)
    except HIAProgramRejected as exc:
        result["reason"] = "invalid_program"
        result["validation_error"] = {"code": exc.code, "message": str(exc)}
        return result
    result.update(program_sha256=program.sha256, input_sha256=program.input_sha256,
                  structural_verification=True)
    result["claims"]["canonical_core_reverified"] = True
    functions = {fn["name"]: fn for fn in program.as_dict()["functions"]}
    if function is None and len(functions) == 1:
        function = next(iter(functions))
    result["function"] = function
    if type(function) is not str or function not in functions:
        result["reason"] = "missing_or_ambiguous_function"
        return result
    if function not in program.scalar_entrypoints:
        result["reason"] = "not_a_public_scalar_entrypoint"
        return result
    fn = functions[function]
    try:
        graph = semantics._profile(fn)
    except semantics._OutsideProfile as exc:
        result["reason"] = str(exc)
        return result
    try:
        z = semantics._z3_module()
    except (ImportError, OSError):
        result["reason"] = "solver_unavailable"
        return result
    result["solver"]["version"] = z.get_version_string()
    try:
        encoder = semantics._Encoder(z)
        inputs = [encoder.input(i, p["type"]) for i, p in enumerate(fn["params"])]
        tag, _values = encoder.function(fn, inputs, *graph)
        solver = z.Solver(ctx=encoder.context)
        solver.set(timeout=timeout_ms)
        solver.add(tag != 0)
        verdict = solver.check()
        result["solver"]["result"] = str(verdict)
        if verdict == z.unsat:
            result["status"] = "proved"
            result["reason"] = "nonreturning_outcome_unsatisfiable"
            result["claims"]["all_inputs_return_normally_proved"] = True
        elif verdict == z.sat:
            model = solver.model()
            actual_tag = model.eval(tag, model_completion=True).as_long()
            if actual_tag < 0:
                result["reason"] = "incomplete_symbolic_execution"
            else:
                arguments = [encoder.concrete(model, value, param["type"])
                             for value, param in zip(inputs, fn["params"])]
                expected_code = next((code for code, number in semantics._TRAP_TAGS.items()
                                      if number == actual_tag), None)
                observed = semantics._execute_observation(program, function, arguments)
                if expected_code is None or observed != {"status": "trapped", "code": expected_code}:
                    result["reason"] = "counterexample_replay_disagrees_with_encoder"
                else:
                    result["status"] = "disproved"
                    result["reason"] = "nonreturning_counterexample_replayed"
                    result["counterexample"] = {
                        "arguments": arguments, "parameter_types": semantics._signature(fn)[0],
                        "observation": observed, "outcome_tag": actual_tag,
                    }
        else:
            result["reason"] = "solver_unknown"
            result["solver"]["reason_unknown"] = solver.reason_unknown()
    except z.Z3Exception as exc:
        result["reason"] = "solver_error"
        result["solver"]["error"] = str(exc)
    if (result["validator_sha256"] != _implementation_digest()
            or result["encoder_sha256"] != semantics._implementation_digest()):
        result.update(status="unknown", reason="implementation_changed_during_proof", counterexample=None)
        result["claims"]["all_inputs_return_normally_proved"] = False
    return result
