"""Subject-bound conclusions for the Agent verifier.

A status is meaningful only with its complete scope. This module describes the
existing checkers and checks retained bindings; it does not add a proof of those
checkers, the backend, or arbitrary native execution.
"""
from __future__ import annotations

from copy import deepcopy
import platform

from .hia_agent_store import reject


PROOF_SCHEMA = "hepta.hia.agent.proof-result.v1"
PROVED_MEANING = (
    "The identified checker established this property for this exact subject "
    "within this profile and under these assumptions. Unproved obligations "
    "remain open; this status is neither global safety nor execution authority."
)
PROOF_FIELDS = (
    "subject", "property", "profile", "assumptions", "checker",
    "unproved_obligations",
)

_CHECKERS = {
    "core_admission": "hepta.hia_program.verify_program",
    "canonical_core_identity": "hepta.hia_agent_service.HIAAgentService._behavior_equivalence",
    "finite_domain": "hepta.hia_agent_service.HIAAgentService._behavior_equivalence",
    "compositional_scalar_effect": "hepta.hia_optimization.verify_optimization",
    "context_budget_exhausted": "hepta.hia_agent_service.HIAAgentService._behavior_equivalence",
    "checked_explicit_machine_choices": "hepta.hia_machine_plan.preservation_checks",
    "canonical_lowering_unsupported": "hepta.hia_agent_service.HIAAgentService._hia_verify",
    "complete_native_rederivation": "hepta.hia_agent_service.HIAAgentService._compile",
}
_PROPERTIES = {
    "core_admission": "The installed whole-program verifier accepts these exact canonical Core bytes; this is an admission predicate, not a language soundness theorem.",
    "canonical_core_identity": "The admitted base and candidate have identical canonical Core bytes and are reflexively equivalent under the same Core semantics, including traps and modeled resources.",
    "finite_domain": "For every input in the declared pure acyclic scalar domain, base and candidate agree on return status, values, first trap and modeled Core resources.",
    "compositional_scalar_effect": "Within the qualified structural Core profile, base and candidate preserve scalar values, ordered effects, first traps and modeled resource traces; VM instruction ticks are excluded.",
    "context_budget_exhausted": "The base-to-candidate Core behavioral equivalence obligation requested before the frozen verification deadline.",
    "checked_explicit_machine_choices": "The exact Agent plan preserves the checked canonical CFG, scalar value lifetimes and path effects, conditional on correctness of the canonical lowering and encoder.",
    "canonical_lowering_unsupported": "The exact candidate's canonical lowering refines its Core semantics to the target machine; this profile has no checker establishing this property.",
    "complete_native_rederivation": "The retained native bytes and object identity equal complete reemission and linkage by the same installed implementation with the checked symbol and ABI inventory.",
}


def _item(identity, statement):
    return {"id": identity, "statement": statement}


def _require(condition, message):
    if not condition:
        reject("E_HIA_PROOF_SCOPE", message, "verification")


def proof_subject(record, target_profile):
    """Bind a selected Core/plan/native subject to exact programs and context."""
    return {
        **deepcopy(record["subject"]),
        "context": deepcopy(record["context"]),
        "target_profile": deepcopy(target_profile),
        "candidate": deepcopy(record["candidate"]),
        "candidate_core_sha256": record["candidate_core_sha256"],
        "base_program": deepcopy(record["base_program"]),
        "base_core_sha256": record["base_core_sha256"],
    }


def _method(claim, status, subject, evidence):
    """Reject a conclusion that contradicts the retained checker's own result."""
    _require(type(evidence) is dict, "verification evidence must be a retained object")
    core = subject["candidate_core_sha256"]
    base = subject["base_core_sha256"]
    if claim == "core_admission":
        _require(status == "proved" and evidence.get("checker") == _CHECKERS["core_admission"]
                 and evidence.get("core_sha256") == core, "Core admission evidence differs")
        return "core_admission"
    if claim == "behavior_equivalence":
        _require(base is not None and subject["base_program"] is not None,
                 "equivalence lacks an exact base program")
        method = evidence.get("method")
        if method == "canonical_core_identity":
            _require(status == "proved" and base == core
                     and evidence.get("base_sha256") == base
                     and evidence.get("candidate_sha256") == core
                     and evidence.get("all_inputs") is True, "Core identity evidence differs")
            return method
        if method == "finite_domain":
            checked, required = evidence.get("checked"), evidence.get("required")
            _require(type(checked) is int and type(required) is int
                     and 0 <= checked <= required <= 4096 and required > 0,
                     "finite-domain accounting differs")
            if status == "proved":
                _require(evidence.get("complete") is True and checked == required
                         and evidence.get("all_inputs_in_declared_widths") is True
                         and evidence.get("base_sha256") == base
                         and evidence.get("candidate_sha256") == core
                         and type(evidence.get("transcript_sha256")) is str,
                         "incomplete finite-domain evidence cannot prove equivalence")
            elif status == "refuted":
                _require("counterexample" in evidence and evidence.get("before") != evidence.get("after"),
                         "finite-domain refutation lacks a differing observation")
            else:
                _require(status == "unknown" and evidence.get("complete") is False
                         and "counterexample" not in evidence, "finite-domain status differs")
            return method
        if method == "context_budget_exhausted":
            _require(status == "unknown", "exhausted verification budget cannot prove equivalence")
            return method
        if evidence.get("schema") == "hepta.hia.optimization-verification.v1":
            mapping = {"verified": "proved", "rejected": "refuted",
                       "unknown": "unknown", "timeout": "unknown"}
            _require(status == mapping.get(evidence.get("status"))
                     and evidence.get("base_sha256") == base
                     and evidence.get("candidate_sha256") == core,
                     "compositional checker conclusion or program binding differs")
            if status == "proved":
                _require(type(evidence.get("checker_sha256")) is str
                         and type(evidence.get("solver")) is dict
                         and type(evidence.get("claims")) is dict
                         and evidence["claims"].get("core_scalar_effect_equivalence_checked") is True
                         and type(evidence.get("resource_delta")) is dict
                         and evidence["resource_delta"].get("resource_trace_equivalence_checked") is True
                         and type(evidence.get("obligations")) is list
                         and all(type(item) is dict and item.get("result") == "unsat" for item in evidence["obligations"]),
                         "compositional proof lacks its identified solver or discharged obligations")
            return "compositional_scalar_effect"
        _require(False, "unrecognized behavioral equivalence evidence")
    if claim == "lowering_refinement":
        if subject["kind"] == "canonical_lowering":
            _require(status == "unsupported" and type(evidence.get("reason")) is str,
                     "canonical lowering cannot gain an unsupported refinement proof")
            return "canonical_lowering_unsupported"
        _require(subject["kind"] == "agent_machine_plan" and status == "proved"
                 and evidence.get("method") == "checked_explicit_machine_choices"
                 and evidence.get("core_sha256") == core
                 and type(evidence.get("plan")) is dict
                 and evidence["plan"].get("core_sha256") == core,
                 "conditional machine-plan evidence differs")
        return "checked_explicit_machine_choices"
    if claim == "encoding_check":
        _require(subject["kind"] == "native_artifact"
                 and evidence.get("method") == "complete_native_rederivation"
                 and evidence.get("actual_sha256") == subject["native_artifact"]["sha256"],
                 "encoding evidence belongs to a different native subject")
        _require(type(evidence.get("bytes_equal")) is bool and type(evidence.get("object_identity_equal")) is bool,
                 "encoding evidence lacks complete byte/object comparisons")
        equal = evidence["bytes_equal"] and evidence["object_identity_equal"]
        _require(status == ("proved" if equal else "refuted"),
                 "encoding conclusion differs from the actual byte/object comparison")
        return "complete_native_rederivation"
    _require(False, "unknown proof property")


def proof_result(*, claim, status, domain, subject, profile, installation, evidence):
    """Produce a self-contained description, never upgrade checker conclusions."""
    method = _method(claim, status, subject, evidence)
    assumptions = [
        _item("identified_checker_execution", "The identified Python runtime, checker source and hashing implementation execute their specified checks faithfully."),
    ]
    obligations = [
        _item("checker_soundness", "No machine-checked soundness proof of the Python checker, its models or optional solver is supplied."),
        _item("whole_language_soundness", "No safety theorem for the complete HIA language or arbitrary programs is established."),
        _item("core_to_machine_refinement", "No independent semantic refinement from this Core to actual executed machine instructions is established by this check."),
        _item("abi_ffi_loading", "Native caller validity, ABI/FFI implementations, loader mapping, symbol interposition and external memory liveness are not proved."),
        _item("native_resources", "Native stack, heap, wall-time and process resource bounds, including exhaustion behavior, are not proved."),
        _item("termination_outside_profile", "Termination outside the checker's stated domain is not established."),
        _item("concurrency_and_side_channels", "Concurrency, signals, hardware faults, timing and side-channel properties are not established."),
    ]
    if claim == "behavior_equivalence":
        assumptions.append(_item("same_core_environment", "Both programs use the same declared Core semantics and external-effect/allocation environment; this does not prove a deployed environment implements that model."))
    if method == "finite_domain":
        assumptions.append(_item("complete_finite_domain", "The input domain is the complete declared-width domain of the checked pure scalar acyclic functions, limited to 12 input bits and 4096 enumerated cases; the reference interpreter defines the observations."))
    if method == "compositional_scalar_effect":
        assumptions.extend([
            _item("structural_correspondence", "The qualified primitive Core v1-v7 profile requires identical signatures, CFG edges and ordered resource/call operations; corresponding effects share the same modeled state."),
            _item("identified_smt_solver", "When solving is performed, the identified pinned Z3 binding and native library correctly decide the retained bit-vector obligations."),
        ])
        obligations.append(_item("vm_tick_preservation", "VM instruction tick counts and native execution costs are not equivalence observables in this structural profile."))
    if method == "checked_explicit_machine_choices":
        assumptions.extend([
            _item("canonical_lowering_correctness", "The canonical Core lowering implements Core semantics."),
            _item("encoder_and_relocation_correctness", "The x86 encoder and relocation machinery implement their declared instructions."),
        ])
        obligations.append(_item("canonical_lowering_correctness", "The canonical lowering and encoder assumptions are not discharged by checking explicit machine choices."))
    if method == "complete_native_rederivation":
        assumptions.append(_item("same_implementation_rederivation", "The retained Core/plan is rechecked and emitted with the same identified lowering, encoder and linkage implementation; matching bytes can preserve a common implementation defect."))
        obligations.append(_item("independent_encoding_semantics", "Reemission equality is not an independent decoder/ISA semantics check or a verified backend."))
    if status != "proved":
        obligations.append(_item("requested_property", "The requested property is not established; this result is " + status + " and cannot satisfy a required proof."))

    solver = evidence.get("solver") if method == "compositional_scalar_effect" else None
    solver_fields = ("name", "version", "binding_sha256", "library_sha256")
    _require(solver is None or type(solver) is dict and all(type(solver.get(key)) is str for key in solver_fields),
             "solver identity is incomplete")
    solver_identity = None if solver is None else {key: solver[key] for key in solver_fields}
    return {
        "schema": PROOF_SCHEMA, "claim": claim, "status": status, "domain": domain,
        "subject": deepcopy(subject),
        "property": {"id": claim, "statement": _PROPERTIES[method]},
        "profile": deepcopy(profile), "validator": deepcopy(profile),
        "assumptions": assumptions,
        "checker": {
            "name": _CHECKERS[method], "method": method,
            "installation": deepcopy(installation),
            "python": {"implementation": platform.python_implementation(), "version": platform.python_version()},
            "auxiliary_checker_sha256": evidence.get("checker_sha256") if method == "compositional_scalar_effect" else None,
            "solver": solver_identity,
        },
        "unproved_obligations": obligations,
        "global_safety_proved": False, "execution_authority_granted": False,
    }


def assumptions_document(result):
    return {
        "schema": "hepta.hia.agent.proof-assumptions.v1",
        "subject": result["subject"], "property": result["property"],
        "profile": result["profile"], "checker": result["checker"],
        "assumptions": result["assumptions"], "assumptions_proved_here": False,
        "universal_core_to_machine_refinement_proved": False,
    }


def proof_contract_description():
    return {
        "schema": PROOF_SCHEMA, "proved_meaning": PROVED_MEANING,
        "required_scope_fields": list(PROOF_FIELDS),
        "all_statuses_require_scope": True,
        "unscoped_legacy_receipts_accepted": False,
        "sample_tests_are_proofs": False,
        "global_safety_proved": False, "execution_authority_granted": False,
        "encoding_check": "Same-implementation byte/object rederivation, not independent semantic validation.",
        "receipt_consumption": "Recheck exact subject/profile/checker, retained evidence conclusion and assumptions before satisfying any required claim.",
    }
