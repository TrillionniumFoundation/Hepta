"""Eight exact original proof-contract bodies for offline HIA authoring.

Recovery revision V79: the functions below are copied from the exact published
4b original. Production never imports this file or executes its Python body.
"""

def _item(identity, statement):
    return {"id": identity, "statement": statement}


def _require(condition, message):
    if not condition:
        reject("E_HIA_PROOF_SCOPE", message, "verification")


def _safe_core_method(status, subject, evidence):
    """Consume the independent checker's exact identity and ordered obligations."""
    from .hia_safe_core import (ARTIFACT_PROFILE, ARTIFACT_PROPERTY, ARTIFACT_OBLIGATIONS,
        SCHEMA, CLAIMS, ASSUMPTIONS, LIMITS, UNPROVED_OBLIGATIONS, _checker_source_identity,
        _solver_identity)
    _require(evidence.get("method") == SAFE_CORE_METHOD and evidence.get("outcome") == status
             and evidence.get("profile") == ARTIFACT_PROFILE
             and evidence.get("service_profile") == SAFE_CORE_SERVICE_PROFILE,
             "independent machine checker conclusion or profile differs")
    binding = evidence.get("artifact_binding")
    _require(type(binding) is dict and binding.get("candidate_core_sha256") == subject["candidate_core_sha256"]
             and binding.get("native_artifact") == subject["native_artifact"]
             and binding.get("build_receipt") == subject["build_receipt"]
             and binding.get("final_image_sha256") == subject["native_artifact"]["sha256"]
             and type(binding.get("object_artifact")) is dict
             and binding["object_artifact"].get("sha256") == binding.get("object_sha256"),
             "independent machine evidence belongs to different retained build inputs")
    identity = _checker_source_identity()
    _require(evidence.get("source_identity") == identity and evidence.get("checker_sha256") == digest(identity),
             "independent consumer source closure differs")
    validation = evidence.get("validation")
    if validation is None:
        _require(status in {"unknown", "unsupported"} and type(evidence.get("reason")) is str
                 and evidence.get("solver") is None,
                 "no independent checker result can establish a machine proof or refutation")
        return SAFE_CORE_METHOD
    _require(type(validation) is dict and binding.get("output_kind") == "shared"
             and binding.get("foreign_buffer_exports") == []
             and type(binding.get("entry_symbols")) is list and len(binding["entry_symbols"]) == 1,
             "machine validation exceeds the Agent shared scalar profile")
    entry = binding["entry_symbols"][0]
    raw_subject = {"core_sha256": subject["candidate_core_sha256"], "input_sha256": binding.get("input_sha256"),
        "object_sha256": binding["object_sha256"], "final_image_sha256": binding["final_image_sha256"],
        "entry_symbol": entry, "foreign_buffer_exports": []}
    solver = evidence.get("solver")
    try:
        import importlib
        actual_solver = _solver_identity(importlib.import_module("z3"))
    except Exception:
        _require(False, "the retained machine solver identity cannot be re-established")
    _require(solver == actual_solver and validation.get("solver") == solver,
             "independent machine solver binding or native library differs")
    checker = {"name": _CHECKERS[SAFE_CORE_METHOD], "source_identity": identity,
               "native_selection": checker_native_selection(),
               "solver": solver, "producer_reemission_used": False}
    _require(validation.get("schema") == SCHEMA and validation.get("profile") == ARTIFACT_PROFILE
             and validation.get("artifact_input_profile") == ARTIFACT_PROFILE
             and validation.get("validation_mode") == "independent_supplied_bytes"
             and validation.get("subject") == raw_subject
             and validation.get("property") == ARTIFACT_PROPERTY
             and validation.get("core_sha256") == raw_subject["core_sha256"]
             and validation.get("input_sha256") == raw_subject["input_sha256"]
             and validation.get("function") == entry and validation.get("foreign_buffer_exports") == []
             and validation.get("backend_implementation_sha256") is None
             and validation.get("source_identity") == identity and validation.get("checker") == checker
             and validation.get("assumptions") == ASSUMPTIONS and validation.get("limits") == LIMITS
             and validation.get("unproved_obligations") == UNPROVED_OBLIGATIONS,
             "raw machine checker scope or exact input identity differs")
    image = validation.get("image_binding")
    _require(type(image) is dict and image.get("object_sha256") == raw_subject["object_sha256"]
             and image.get("final_image_sha256") == raw_subject["final_image_sha256"]
             and image.get("entry_symbol") == entry,
             "raw object/final ELF binding differs")
    rows = validation.get("obligations")
    _require(type(rows) is list and 0 <= len(rows) <= len(ARTIFACT_OBLIGATIONS)
             and all(type(row) is dict for row in rows)
             and tuple((row.get("name"), row.get("expected")) for row in rows) == ARTIFACT_OBLIGATIONS[:len(rows)],
             "machine proof obligation order, names or expected outcomes differ")
    _require(all(type(row.get("query_sha256")) is str and len(row["query_sha256"]) == 64
                 and row.get("query_file") == f"{index:02d}-{row['name']}.smt2"
                 for index, row in enumerate(rows)), "machine proof lacks exact retained query identities")
    if status == "proved":
        _require(evidence.get("deadline_met") is True and "counterexample" not in evidence
                 and validation.get("ok") is True and validation.get("complete") is True
                 and validation.get("status") == "smt_validated" and validation.get("claims") == CLAIMS
                 and len(rows) == len(ARTIFACT_OBLIGATIONS)
                 and all(row.get("result") == row["expected"] for row in rows),
                 "incomplete, late or failing machine obligations cannot establish refinement")
    elif status == "refuted":
        counterexample = evidence.get("counterexample")
        _require(evidence.get("deadline_met") is True and validation.get("ok") is False
                 and validation.get("complete") is False and validation.get("status") == "refuted"
                 and validation.get("claims") == {} and len(rows) >= 2
                 and all(row.get("result") == row["expected"] for row in rows[:-1])
                 and rows[-1].get("result") == "sat" and rows[-1]["expected"] == "unsat"
                 and type(counterexample) is dict and counterexample.get("obligation") == rows[-1]["name"]
                 and type(counterexample.get("abi_words")) is list
                 and type(counterexample.get("initial_rsp")) is int,
                 "machine refutation lacks an actual violation counterexample")
    else:
        _require(status == "unknown" and type(evidence.get("reason")) is str
                 and (evidence.get("deadline_met") is False
                      or validation.get("complete") is False and validation.get("ok") is False
                         and validation.get("status") == "unknown"),
                 "machine checker failure cannot be upgraded to a completed result")
    return SAFE_CORE_METHOD


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
        if subject["kind"] == "native_artifact":
            return _safe_core_method(status, subject, evidence)
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


def proof_result(*, claim, status, domain, subject, profile, installation, evidence,
                 held_native_owners=()):
    """Produce a self-contained description, never upgrade checker conclusions."""
    native_selection = checker_native_selection(held_owners=held_native_owners)
    _require(evidence.get("native_checker_selection") == native_selection,
             "native checker selection differs from the actual verification owners")
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
    if method == SAFE_CORE_METHOD:
        from .hia_safe_core import ASSUMPTIONS
        _require(domain == SAFE_CORE_DOMAIN, "independent machine proof domain differs")
        assumptions.extend(_item("safe_core_assumption_" + str(index), statement)
                           for index, statement in enumerate(ASSUMPTIONS))
        assumptions.append(_item("agent_scalar_projection", "The Agent path admits only the final shared ELF of one unsigned scalar acyclic function and an empty foreign export manifest; the broader raw checker's borrowed-range support is not exposed here."))
        obligations = [item for item in obligations
                       if item["id"] not in {"core_to_machine_refinement", "abi_ffi_loading", "native_resources"}]
        obligations.extend([
            _item("complete_hardware_isa_refinement", "The independent Core/x86/ELF models are trusted; their refinement to the complete hardware ISA and actual CPU behavior is not kernel-proved."),
            _item("caller_ffi_loader_validity", "Modeled SysV saved state, stack alignment and memory bounds are checked; real caller validity, stack liveness, loader mapping, abort resolution and absence of hostile interposition remain assumptions."),
            _item("resources_outside_machine_model", "The model admits a live 16 KiB stack and acyclic execution; real stack exhaustion, heap/process resources, wall time and native execution costs are not proved."),
            _item("distinct_native_trap_codes", "Native traps are observed as nonreturning abort; preservation of individual HIA trap codes is not established."),
        ])
    if status != "proved":
        obligations.append(_item("requested_property", "The requested property is not established; this result is " + status + " and cannot satisfy a required proof."))

    solver = evidence.get("solver") if method in {"compositional_scalar_effect", SAFE_CORE_METHOD} else None
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
            "native_selection_sha256": digest(native_selection),
            "python": {"implementation": platform.python_implementation(), "version": platform.python_version()},
            "auxiliary_checker_sha256": evidence.get("checker_sha256") if method in {"compositional_scalar_effect", SAFE_CORE_METHOD} else None,
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
        "independent_native_refinement": {"method": SAFE_CORE_METHOD, "profile": SAFE_CORE_SERVICE_PROFILE,
            "domain": SAFE_CORE_DOMAIN, "retained_object_required": True,
            "producer_reemission_used": False, "whole_language_refinement": False},
        "receipt_consumption": "Recheck exact subject/profile/checker, retained evidence conclusion and assumptions before satisfying any required claim.",
    }
