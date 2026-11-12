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
import time

from .hia_scalar_proof_contract import begin_scalar_proof, finish_scalar_proof
from .hia_program import HIAProgramRejected, verify_program
from . import hia_translation_validation as semantics

SCHEMA = "hepta.hia.scalar-totality.v1"
PROFILE = "hia.scalar-acyclic-bitvector-totality.v1"
CALL_SCHEMA = "hepta.hia.scalar-call-totality.v1"
CALL_PROFILE = "hia.scalar-acyclic-direct-calls-bitvector-totality.v1"


def _primitive_implementation_identity():
    """Bind verification, symbolic semantics and independent VM replay inputs."""
    names = ("hia_scalar_totality.py", "hia_translation_validation.py",
             "hia_program.py", "hia_capability_flow.py", "hia_opcodes.py", "hia_schema.py",
             "hia_json_preflight.py", "hia_program_composite.py",
             "hia_program_runtime.py", "hia_bounded_memory.py",
             "hia_optimization.py", "hia_program_llvm.py")
    from .hia_checker_identity import checker_source_identity
    return checker_source_identity(names)


def _call_implementation_identity():
    """Bind the existing primitive checker, call encoder and replay closure."""
    names = ("hia_scalar_totality.py", "hia_scalar_call_validation.py",
             "hia_translation_validation.py", "hia_program.py", "hia_capability_flow.py", "hia_opcodes.py",
             "hia_schema.py", "hia_json_preflight.py", "hia_program_runtime.py",
             "hia_bounded_memory.py", "hia_optimization.py", "hia_program_llvm.py")
    from .hia_checker_identity import checker_source_identity
    return checker_source_identity(names)


def _implementation_digest():
    return sha256(Path(__file__).read_bytes()).hexdigest()


def validate_scalar_totality(document, *, function=None, timeout_ms=2000):
    """Prove one public scalar function returns normally on every typed input.

    Canonical validation and the existing acyclic scalar profile run first.
    Every invocation constructs an independent context with the pinned Z3
    binding/library identity. SAT becomes ``disproved`` only after the
    canonical VM replays the same first trap. The deadline includes source
    checking, encoding, solver work, replay and final identity checks.

    Unsupported programs, missing paths, solver exhaustion/unavailability,
    implementation drift and disagreements remain ``unknown``. These checks
    are not a machine proof of the encoder or of native/resource behavior.
    """
    started = time.monotonic_ns()
    scope = begin_scalar_proof("validate_scalar_totality")
    from .hia_optimization import PINNED_Z3_VERSION, _solver_identity
    result = {
        "schema": SCHEMA, "profile": PROFILE, "status": "unknown",
        "function": function, "scope": "selected_public_scalar_function",
        "program_sha256": None, "input_sha256": None,
        "validator_sha256": None, "encoder_sha256": None,
        "encoder_profile": semantics.PROFILE, "implementation": None,
        "structural_verification": False, "reason": None, "counterexample": None,
        "solver": {"name": "z3", "version": None, "result": "not_run",
                   "timeout_ms": timeout_ms},
        "execution_authority": False,
        "claims": {
            "all_inputs_return_normally_proved": False,
            "all_programs_of_this_profile_proved": False,
            "canonical_core_reverified": False,
            "resource_bounds_proved": False,
            "encoder_refinement_machine_proved": False,
            "native_backend_refinement_proved": False,
            "serialized_receipt_authorizes_execution": False,
        },
        "limits": [
            "Only the selected public scalar function is proved total.",
            "The canonical verifier, scalar encoder, independent replay and pinned Z3 are trusted implementations.",
            "Acyclic control flow only; calls, resources and floating point are outside the profile.",
            "The whole proof deadline includes encoding, solver work, replay and identity rechecks; it is not a hard process timeout.",
            "Native execution, physical time and resource quotas are not proved by this query.",
            "Consumers must recompute on exact bytes before admitting executable code.",
        ],
    }
    if type(timeout_ms) is not int or not 1 <= timeout_ms <= semantics.MAX_TIMEOUT_MS:
        result["reason"] = "invalid_solver_timeout"
        return finish_scalar_proof(result, scope, started_ns=started, deadline_ms=timeout_ms)
    solver_identity = z = None
    try:
        result["validator_sha256"] = _implementation_digest()
        result["encoder_sha256"] = semantics._implementation_digest()
        result["implementation"] = _primitive_implementation_identity()
        program = verify_program(document)
        result.update(program_sha256=program.sha256, input_sha256=program.input_sha256,
                      structural_verification=True)
        result["claims"]["canonical_core_reverified"] = True
        if program.as_dict()["schema"] not in semantics.QUALIFIED_CORE_SCHEMAS:
            raise semantics._OutsideProfile("core_schema_outside_qualified_v1_v7_profile")
        functions = {fn["name"]: fn for fn in program.as_dict()["functions"]}
        if function is None and len(functions) == 1:
            function = next(iter(functions))
        result["function"] = function
        if type(function) is not str or function not in functions:
            raise semantics._OutsideProfile("missing_or_ambiguous_function")
        if function not in program.scalar_entrypoints:
            raise semantics._OutsideProfile("not_a_public_scalar_entrypoint")
        fn = functions[function]
        graph = semantics._profile(fn)
        z = semantics._z3_module()
        result["solver"]["version"] = z.get_version_string()
        if z.get_version_string() != PINNED_Z3_VERSION:
            raise semantics._OutsideProfile("pinned_solver_required")
        solver_identity = _solver_identity(z)
        result["solver"]["identity"] = solver_identity
        encoder = semantics._Encoder(z)
        inputs = [encoder.input(i, p["type"]) for i, p in enumerate(fn["params"])]
        tag, _values = encoder.function(fn, inputs, *graph)
        remaining_ms = timeout_ms - (time.monotonic_ns() - started + 999999) // 1000000
        if remaining_ms <= 0:
            raise semantics._OutsideProfile("proof_deadline_exhausted")
        solver = z.Solver(ctx=encoder.context)
        solver.set(timeout=remaining_ms)
        solver.add(tag != 0)
        query = solver.sexpr()
        result["solver"]["query_sha256"] = sha256(query.encode()).hexdigest()
        verdict = solver.check()
        result["solver"]["result"] = str(verdict)
        if verdict == z.unsat:
            result.update(status="proved", reason="nonreturning_outcome_unsatisfiable")
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
                    result.update(status="disproved", reason="nonreturning_counterexample_replayed",
                                  counterexample={"arguments": arguments,
                                      "parameter_types": semantics._signature(fn)[0],
                                      "observation": observed, "outcome_tag": actual_tag})
        else:
            result["reason"] = "solver_unknown"
            result["solver"]["reason_unknown"] = solver.reason_unknown()
    except HIAProgramRejected as exc:
        result.update(reason="invalid_program", validation_error={"code": exc.code, "message": str(exc)})
    except semantics._OutsideProfile as exc:
        result["reason"] = str(exc)
    except ImportError:
        result["reason"] = "solver_unavailable"
    except OSError as exc:
        result.update(reason="solver_or_implementation_unavailable", error_type=type(exc).__name__)
    except Exception as exc:
        # Exceptions from the checker, encoder, solver and independent replay
        # are incomplete evidence, including errors after an UNSAT result.
        result.update(status="unknown", reason="solver_error" if z is not None
                      and isinstance(exc, z.Z3Exception) else "proof_error",
                      error_type=type(exc).__name__, error=str(exc), counterexample=None)
        if result["reason"] == "solver_error":
            result["solver"]["error"] = str(exc)
    finally:
        if result["status"] in {"proved", "disproved"}:
            try:
                if (result["validator_sha256"] != _implementation_digest()
                        or result["encoder_sha256"] != semantics._implementation_digest()
                        or result["implementation"] != _primitive_implementation_identity()
                        or solver_identity != _solver_identity(z)):
                    result.update(status="unknown", reason="implementation_changed_during_proof",
                                  counterexample=None)
            except Exception as exc:
                result.update(status="unknown", reason="implementation_identity_unavailable",
                              error_type=type(exc).__name__, counterexample=None)
        finish_scalar_proof(result, scope, started_ns=started, deadline_ms=timeout_ms)
        result["claims"]["all_inputs_return_normally_proved"] = result["status"] == "proved"
    return result


def validate_scalar_call_totality(document, *, function, timeout_ms=10000):
    """Prove normal return for one bounded direct-call closure on all inputs.

    The existing independent call encoder reads original callee bodies; no
    inlining proposal or equivalence receipt participates. A callee need not
    be total on every possible input: its traps are guarded by the caller's
    actual path and argument expressions. The whole selected closure must be
    acyclic and fit the existing function/block/operation/expansion limits.

    This is a separate evidence profile. It does not widen native admission,
    prove an arbitrary program or authorize execution from a saved receipt.
    """
    started = time.monotonic_ns()
    scope = begin_scalar_proof("validate_scalar_call_totality")
    from . import hia_scalar_call_validation as calls
    from .hia_optimization import PINNED_Z3_VERSION, _solver_identity
    result = {
        "schema": CALL_SCHEMA, "profile": CALL_PROFILE, "status": "unknown",
        "function": function, "scope": "selected_public_scalar_call_closure",
        "program_sha256": None, "input_sha256": None,
        "encoder_profile": calls.PROFILE, "implementation": None,
        "structural_verification": False, "reason": None, "counterexample": None,
        "solver": {"name": "z3", "version": None, "result": "not_run",
                   "timeout_ms": timeout_ms},
        "call_closure": [], "call_expansions": 0, "execution_authority": False,
        "claims": {"all_inputs_return_normally_proved": False,
                   "canonical_core_reverified": False,
                   "all_programs_of_this_profile_proved": False,
                   "resource_bounds_proved": False,
                   "encoder_refinement_machine_proved": False,
                   "native_backend_refinement_proved": False,
                   "serialized_receipt_authorizes_execution": False},
        "limits": {"functions": calls.MAX_FUNCTIONS, "blocks": calls.MAX_BLOCKS,
                   "operations": calls.MAX_OPERATIONS,
                   "call_expansions": calls.MAX_CALL_EXPANSIONS},
        "trusted_components": ["canonical Core checker", "scalar and call SMT encoders",
                               "pinned Z3 solver", "canonical VM counterexample replay"],
    }
    if type(timeout_ms) is not int or not 1 <= timeout_ms <= 10000:
        result["reason"] = "invalid_solver_timeout"
        return finish_scalar_proof(result, scope, started_ns=started, deadline_ms=timeout_ms)
    solver_identity = z = None
    try:
        result["implementation"] = _call_implementation_identity()
        program = verify_program(document)
        result.update(program_sha256=program.sha256, input_sha256=program.input_sha256,
                      structural_verification=True)
        result["claims"]["canonical_core_reverified"] = True
        if (program.structured_bytes is not None
                or program.as_dict()["schema"] not in semantics.QUALIFIED_CORE_SCHEMAS):
            raise semantics._OutsideProfile("public_primitive_v1_v7_scalar_function_required")
        if type(function) is not str or function not in program.scalar_entrypoints:
            raise semantics._OutsideProfile("not_a_public_scalar_entrypoint")
        functions, graphs = calls._closure(program.as_dict(), function)
        fn = functions[function]
        result["call_closure"] = sorted(graphs)
        z = semantics._z3_module()
        result["solver"]["version"] = z.get_version_string()
        if z.get_version_string() != PINNED_Z3_VERSION:
            raise semantics._OutsideProfile("pinned_solver_required")
        solver_identity = _solver_identity(z)
        result["solver"]["identity"] = solver_identity
        encoder = calls._Calls(z)
        encoder.configure(functions, graphs)
        inputs = [encoder.input(i, p["type"]) for i, p in enumerate(fn["params"])]
        tag, _values = encoder.function(fn, inputs, *graphs[function])
        result["call_expansions"] = encoder.expansions
        # A missing callee path must not be hidden by a returning caller tag.
        incomplete = encoder.any(encoder.incomplete)
        remaining_ms = timeout_ms - (time.monotonic_ns() - started + 999999) // 1000000
        if remaining_ms <= 0:
            raise semantics._OutsideProfile("proof_deadline_exhausted")
        solver = z.Solver(ctx=encoder.context)
        solver.set(timeout=remaining_ms)
        solver.add(z.Or(tag != 0, incomplete))
        result["solver"]["query_sha256"] = sha256(solver.sexpr().encode()).hexdigest()
        verdict = solver.check()
        result["solver"]["result"] = str(verdict)
        if verdict == z.unsat:
            result.update(status="proved", reason="nonreturning_call_closure_unsatisfiable")
            result["claims"]["all_inputs_return_normally_proved"] = True
        elif verdict == z.sat:
            model = solver.model()
            actual_tag = model.eval(tag, model_completion=True).as_long()
            if actual_tag < 0 or z.is_true(model.eval(incomplete, model_completion=True)):
                result["reason"] = "incomplete_symbolic_execution"
            else:
                arguments = [encoder.concrete(model, value, param["type"])
                             for value, param in zip(inputs, fn["params"])]
                expected_code = next((code for code, number in semantics._TRAP_TAGS.items()
                                      if number == actual_tag), None)
                observed = calls._observe(program, function, arguments)
                if expected_code is None or observed != {"status": "trapped", "code": expected_code}:
                    result["reason"] = "counterexample_replay_disagrees_with_encoder"
                else:
                    result.update(status="disproved", reason="nonreturning_counterexample_replayed",
                                  counterexample={"arguments": arguments,
                                      "parameter_types": semantics._signature(fn)[0],
                                      "observation": observed, "outcome_tag": actual_tag})
        else:
            result["reason"] = "solver_unknown"
            result["solver"]["reason_unknown"] = solver.reason_unknown()
    except HIAProgramRejected as exc:
        result.update(reason="invalid_program", validation_error={"code": exc.code, "message": str(exc)})
    except semantics._OutsideProfile as exc:
        result["reason"] = str(exc)
    except (ImportError, OSError) as exc:
        result.update(reason="solver_or_implementation_unavailable", error_type=type(exc).__name__)
    except Exception as exc:
        # Unexpected encoder/solver/replay errors are incomplete evidence.
        result.update(status="unknown", reason="proof_error", error_type=type(exc).__name__,
                      error=str(exc), counterexample=None)
    finally:
        if result["status"] in {"proved", "disproved"}:
            try:
                if (result["implementation"] != _call_implementation_identity()
                        or solver_identity != _solver_identity(z)):
                    result.update(status="unknown", reason="implementation_changed_during_proof",
                                  counterexample=None)
            except Exception as exc:
                result.update(status="unknown", reason="implementation_identity_unavailable",
                              error_type=type(exc).__name__, counterexample=None)
        finish_scalar_proof(result, scope, started_ns=started, deadline_ms=timeout_ms)
        result["claims"]["all_inputs_return_normally_proved"] = result["status"] == "proved"
    return result
