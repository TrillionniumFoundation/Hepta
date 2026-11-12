"""Exact original seven Agent verification coordinator bodies.

Authoring input only. Runtime never imports this policy, interprets its AST,
or executes these retained Python business bodies. The generator emits and
runs ordinary HIA control, literals and one-use effect/retirement decisions.
"""

class HIAAgentService:
    def _subject(self, args, program, *, _connection=None):
        subject = args["subject"]
        if subject["kind"] != "core":
            self._profile(subject["backend_profile"], "backend", **_connection_arguments(_connection))
        if subject["kind"] == "canonical_lowering":
            self._profile(subject["lowering_profile"], "lowering", **_connection_arguments(_connection))
        if subject["kind"] == "agent_machine_plan":
            from .hia_program_native import validate_block_layout_plan
            self._profile(subject["plan_profile"], "plan", **_connection_arguments(_connection))
            plan, _ = self.store.get_json(subject["plan"], **_connection_arguments(_connection))
            validate(plan, PLAN_SCHEMA, "machine_plan")
            return validate_block_layout_plan(program, plan)
        if subject["kind"] == "native_artifact":
            receipt = self._build_receipt(subject["build_receipt"], args["context"],
                                          subject["native_artifact"], **_connection_arguments(_connection))
            if receipt["candidate"] != args["candidate"]:
                reject("E_HIA_SUBJECT", "native build receipt belongs to a different candidate", "verification")
        return None

    def _hia_verify(self, args):
        from .hia_checker_identity import checker_native_selection
        held_owners = self._held_checker_owners()
        native_selection = checker_native_selection(held_owners=held_owners)
        context = self._context(args["context"])
        self._profile(args["validation_profile"], "validation")
        program = self._program(args["candidate"])
        original = None if args["base_program"] is None else self._program(args["base_program"])
        plan = self._subject(args, program)
        binding = {"context": args["context"], "candidate": args["candidate"],
            "candidate_core_sha256": program.sha256, "base_program": args["base_program"],
            "base_core_sha256": None if original is None else original.sha256,
            "subject": args["subject"]}
        scoped_subject = proof_subject(binding, context["target_profile"])
        checks = []
        for claim in args["claims"]:
            if claim == "core_admission":
                status, domain, evidence = "proved", "Exact canonical Core accepted by the installed whole-program checker; no behavioral or native claim", {
                    "checker": "hepta.hia_program.verify_program", "core_sha256": program.sha256,
                    "input_sha256": program.input_sha256, "canonical_bytes": str(len(program.canonical_bytes))}
            elif claim == "behavior_equivalence":
                if original is None:
                    reject("E_HIA_SUBJECT", "behavior equivalence requires a base program", "verification")
                status, domain, evidence = self._behavior_equivalence(original, program, self._remaining_ms(context))
            elif claim == "lowering_refinement":
                if args["subject"]["kind"] == "native_artifact":
                    status, domain, evidence = self._independent_native_refinement(args, program, context)
                elif plan is None:
                    status, domain, evidence = "unsupported", "Whole Core-to-x86 refinement of canonical lowering is not proved by this profile", {
                        "reason": "native qualification and deterministic reemission are not a universal semantic refinement proof"}
                else:
                    from .hia_program_native import emit_program_machine
                    exports = tuple(map(tuple, context.get("foreign_buffer_exports", [])))
                    image = emit_program_machine(program, machine_plan=plan, foreign_buffer_exports=exports)
                    canonical = emit_program_machine(program, foreign_buffer_exports=exports)
                    from .hia_machine_plan import preservation_checks
                    choice_checks = preservation_checks(plan, program)
                    status, domain = "proved", "Checked explicit machine choices preserve canonical CFG, scalar value lifetimes and path effects, conditional on canonical lowering/encoder correctness"
                    evidence = {"method": "checked_explicit_machine_choices", "choice_checks": choice_checks, "core_sha256": program.sha256,
                        "plan": plan, "canonical_object_sha256": canonical.sha256,
                        "planned_object_sha256": image.sha256,
                        "same_slots": not any(plan.get("value_registers", {}).values()),
                        "same_frame_sizes": dict(canonical.function_frames) == dict(image.function_frames),
                        "canonical_frame_bytes": dict(canonical.function_frames),
                        "planned_frame_bytes": dict(image.function_frames),
                        "implicit_optimizer_used": False}
            elif claim == "encoding_check":
                subject = args["subject"]
                built = self._build_receipt(subject["build_receipt"], args["context"], subject["native_artifact"])
                actual, _ = self.store.get(subject["native_artifact"], kind="native")
                exports = tuple(map(tuple, context.get("foreign_buffer_exports", [])))
                reemitted, rebuilt = self._compile(program, built["output_kind"], built["machine_plan"], self._remaining_ms(context),
                    **({"foreign_buffer_exports": exports} if exports else {}))
                bytes_equal = actual == reemitted
                object_equal = rebuilt["object_sha256"] == built["native_build"]["object_sha256"]
                matches = bytes_equal and object_equal
                status = "proved" if matches else "refuted"
                domain = "Exact actual artifact equals reverified Core/plan reemission and linkage by the same installed implementation, with checked closed symbol/ABI inventory; no independent semantic refinement claim"
                evidence = {"method": "complete_native_rederivation", "actual_sha256": sha256(actual).hexdigest(),
                    "rederived_sha256": sha256(reemitted).hexdigest(), "bytes_equal": bytes_equal,
                    "object_identity_equal": object_equal,
                    "native_build": rebuilt, "no_llvm_or_external_assembler": True}
            else:
                reject("E_HIA_CLAIM", "unimplemented verification claim", "verification")
            evidence["native_checker_selection"] = native_selection
            scoped = proof_result(claim=claim, status=status, domain=domain, subject=scoped_subject,
                profile=args["validation_profile"], installation=self.identities, evidence=evidence,
                held_native_owners=held_owners)
            if evidence.get("method") == SAFE_CORE_METHOD and status == "proved" and self._remaining_ms(context) <= 0:
                status = "unknown"
                evidence.update(outcome=status, deadline_met=False,
                                reason="the frozen context deadline expired before proof publication")
                scoped = proof_result(claim=claim, status=status, domain=domain, subject=scoped_subject,
                    profile=args["validation_profile"], installation=self.identities, evidence=evidence,
                    held_native_owners=held_owners)
            checks.append({**scoped,
                "assumptions_artifact": self.store.json(assumptions_document(scoped), "verification-assumptions"),
                "evidence_artifact": self.store.json({**evidence, "proof_binding": scoped}, "verification-evidence")})
        receipt = self.store.json({"schema": "hepta.hia.agent.verification.v1", "context": args["context"],
            "candidate": args["candidate"], "candidate_core_sha256": program.sha256,
            "base_program": args["base_program"], "base_core_sha256": None if original is None else original.sha256,
            "validation_profile": args["validation_profile"], "subject": args["subject"],
            "checks": checks, "installation": self.identities}, "verification-receipt")
        return {"candidate": args["candidate"], "subject": args["subject"],
                "verification_receipt": receipt, "checks": checks, "adopted": False}

    def _verification(self, ref, context, candidate=None, *, _connection=None):
        record, _ = self.store.get_json(ref, kind="verification-receipt", **_connection_arguments(_connection))
        if (record["context"] != context or record["installation"] != self.identities
                or candidate is not None and record["candidate"] != candidate):
            reject("E_HIA_RECEIPT_BINDING", "verification receipt belongs to a different context, candidate or implementation", "verification")
        self._profile(record["validation_profile"], "validation", **_connection_arguments(_connection))
        program = self._program(record["candidate"], **_connection_arguments(_connection))
        if program.sha256 != record["candidate_core_sha256"]:
            reject("E_HIA_RECEIPT_BINDING", "verification Core identity changed", "verification")
        original = None if record["base_program"] is None else self._program(record["base_program"], **_connection_arguments(_connection))
        if record["base_core_sha256"] != (None if original is None else original.sha256):
            reject("E_HIA_RECEIPT_BINDING", "verification base Core identity changed", "verification")
        self._subject(record, program, **_connection_arguments(_connection))
        context_record = self._context(context, **_connection_arguments(_connection))
        subject = proof_subject(record, context_record["target_profile"])
        checks_schema = self.tools["hia_verify"]["outputSchema"]["properties"]["result"]["properties"]["checks"]
        try:
            validate(record["checks"], checks_schema, "verification.checks")
        except AgentRejected as exc:
            reject("E_HIA_PROOF_SCOPE", "missing or invalid proof scope; rerun verification with a fresh request key: " + str(exc), "verification")
        if len({check["claim"] for check in record["checks"]}) != len(record["checks"]):
            reject("E_HIA_PROOF_SCOPE", "verification repeats a proof property", "verification")
        for check in record["checks"]:
            evidence, _ = self.store.get_json(check["evidence_artifact"], kind="verification-evidence", **_connection_arguments(_connection))
            assumptions, _ = self.store.get_json(check["assumptions_artifact"], kind="verification-assumptions", **_connection_arguments(_connection))
            if evidence.get("method") == SAFE_CORE_METHOD:
                self._check_native_refinement_evidence(evidence, record["subject"], context, program, **_connection_arguments(_connection))
            expected = proof_result(claim=check["claim"], status=check["status"], domain=check["domain"],
                subject=subject, profile=record["validation_profile"], installation=self.identities, evidence=evidence,
                held_native_owners=self._held_checker_owners())
            actual = {key: value for key, value in check.items()
                      if key not in {"assumptions_artifact", "evidence_artifact"}}
            if (actual != expected or evidence.get("proof_binding") != expected
                    or assumptions != assumptions_document(expected)):
                reject("E_HIA_PROOF_SCOPE", "proof scope or retained checker conclusion differs; rerun verification with a fresh request key", "verification")
        return record

    def _replay_verification(self, response, arguments, *, _connection=None):
        """Observe an original result only if its complete scope remains valid."""
        try:
            validate(response, self.tools["hia_verify"]["outputSchema"], "replayed verification")
        except AgentRejected as exc:
            reject("E_HIA_PROOF_SCOPE", "cached proof lacks current scope; rerun verification with a fresh request key: " + str(exc), "verification")
        if installation_manifest() != self.identities:
            reject("E_HIA_IMPLEMENTATION_STALE", "installed implementation changed during verification replay")
        result = response["result"]
        retained = self._verification(result["verification_receipt"], arguments["context"], arguments["candidate"], **_connection_arguments(_connection))
        if (result["candidate"] != retained["candidate"] or result["subject"] != retained["subject"]
                or result["checks"] != retained["checks"] or retained["subject"] != arguments["subject"]
                or retained["base_program"] != arguments["base_program"]
                or retained["validation_profile"] != arguments["validation_profile"]
                or [check["claim"] for check in retained["checks"]] != arguments["claims"]):
            reject("E_HIA_PROOF_SCOPE", "cached proof differs from the original subject or retained conclusion; rerun verification with a fresh request key", "verification")

    def _required_claims(self, context, candidate_artifact, refs, baseline_core_sha=None, *, _connection=None):
        _data, native, _program = self._native(candidate_artifact, context["ref"], **_connection_arguments(_connection))
        objective, _ = self.store.get_json(context["objective"], **_connection_arguments(_connection))
        receipts = [self._verification(ref, context["ref"], native["candidate"], **_connection_arguments(_connection)) for ref in refs]
        for claim in objective["required_claims"]:
            qualified = False
            for receipt in receipts:
                if not any(c["claim"] == claim and c["status"] == "proved" for c in receipt["checks"]):
                    continue
                subject = receipt["subject"]
                if claim == "encoding_check":
                    if subject["kind"] != "native_artifact" or subject["native_artifact"] != candidate_artifact:
                        continue
                    self._build_receipt(subject["build_receipt"], context["ref"], candidate_artifact, **_connection_arguments(_connection))
                elif claim == "behavior_equivalence":
                    if receipt["base_core_sha256"] != baseline_core_sha:
                        continue
                elif claim == "lowering_refinement":
                    if subject["kind"] == "native_artifact":
                        if subject["native_artifact"] != candidate_artifact:
                            continue
                        self._build_receipt(subject["build_receipt"], context["ref"], candidate_artifact, **_connection_arguments(_connection))
                    elif native["machine_plan"] is None or subject["kind"] != "agent_machine_plan" or subject["plan"] != native["codegen"]["plan"]:
                        continue
                qualified = True
            if not qualified:
                reject("E_HIA_CLAIM_REQUIRED", "missing exact proved acceptance claim: " + claim, "verification")
        return objective

    def _check_native_refinement_evidence(self, evidence, subject, context, program, *, _connection=None):
        if subject.get("kind") != "native_artifact":
            reject("E_HIA_PROOF_SCOPE", "independent machine evidence requires its exact native subject", "verification")
        built, final_bytes, object_bytes, retained = self._build_inputs(
            subject["build_receipt"], context, subject["native_artifact"], **_connection_arguments(_connection))
        expected = self._native_refinement_binding(subject, built, retained, object_bytes, final_bytes)
        if program.sha256 != retained.sha256 or evidence.get("artifact_binding") != expected:
            reject("E_HIA_PROOF_SCOPE", "machine evidence differs from retained Core/object/final build bytes", "verification")
        validation = evidence.get("validation")
        if type(validation) is dict:
            from .hia_safe_core_elf import bind_final_artifact
            binding = bind_final_artifact(object_bytes, final_bytes, retained.as_dict()["functions"][0]["name"])
            if validation.get("image_binding") != binding["binding"]:
                reject("E_HIA_PROOF_SCOPE", "machine proof's ELF binding differs from the actual retained bytes", "verification")
        queries = evidence.get("queries")
        if type(queries) is not list:
            reject("E_HIA_PROOF_SCOPE", "machine proof lacks retained query identities", "verification")
        reports = [] if validation is None else validation.get("obligations", [])
        if validation is not None and len(queries) != len(reports):
            reject("E_HIA_PROOF_SCOPE", "machine proof query inventory differs", "verification")
        for index, query in enumerate(queries):
            if type(query) is not dict or set(query) != {"name", "sha256", "artifact"}:
                reject("E_HIA_PROOF_SCOPE", "machine proof query reference is invalid", "verification")
            data, _ = self.store.get(query["artifact"], kind="machine-validation-query", **_connection_arguments(_connection))
            if (sha256(data).hexdigest() != query["sha256"]
                    or validation is not None and (query["sha256"] != reports[index].get("query_sha256")
                        or query["name"] != reports[index].get("query_file"))):
                reject("E_HIA_PROOF_SCOPE", "machine proof query bytes differ", "verification")

    @staticmethod
    def _native_refinement_binding(subject, built, program, object_bytes, final_bytes):
        return {"candidate_core_sha256": program.sha256, "input_sha256": program.input_sha256,
            "native_artifact": subject["native_artifact"], "build_receipt": subject["build_receipt"],
            "object_artifact": built["object_artifact"], "object_sha256": sha256(object_bytes).hexdigest(),
            "final_image_sha256": sha256(final_bytes).hexdigest(), "output_kind": built["output_kind"],
            "entry_symbols": [fn["name"] for fn in program.as_dict()["functions"]],
            "foreign_buffer_exports": built["native_build"].get("foreign_buffer_exports")}
