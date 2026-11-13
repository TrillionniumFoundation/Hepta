"""Exact original nine-body Agent evaluation policy, used only by the HIA author.

Runtime does not import or execute these Python bodies. Complete branches,
loops, closures, effects and retirement are emitted as ordinary HIA control.
"""

class HIAAgentService:
    def _native(self, ref, context=None, *, _connection=None):
        data, metadata = self.store.get(ref, kind="native", **_connection_arguments(_connection))
        if metadata["installation"] != self.identities or context is not None and metadata["context"] != context:
            reject("E_HIA_RECEIPT_BINDING", "native artifact belongs to a different context or implementation")
        program = self._program(metadata["candidate"], **_connection_arguments(_connection))
        retained_context = self._context(metadata["context"], **_connection_arguments(_connection))
        exports = tuple(map(tuple, retained_context.get("foreign_buffer_exports", [])))
        if (metadata["core_sha256"] != program.sha256 or self._signature_values(program, exports) != metadata["signatures"]
                or metadata.get("foreign_buffer_exports", []) != [list(pair) for pair in exports]):
            reject("E_HIA_RECEIPT_BINDING", "native artifact's admitted Core identity differs")
        return data, metadata, program

    def _build_inputs(self, ref, context, artifact, *, _connection=None):
        """Capture and validate one immutable Core/object/final build observation."""
        record, _ = self.store.get_json(ref, kind="build-receipt", **_connection_arguments(_connection))
        if (record["context"] != context or record["native_artifact"] != artifact or record["installation"] != self.identities
                or record.get("target_profile") != self.profiles["target"]
                or record.get("backend_profile") != self.profiles["backend"]):
            reject("E_HIA_RECEIPT_BINDING", "build receipt belongs to a different native subject")
        data, metadata, program = self._native(artifact, context, **_connection_arguments(_connection))
        if any(record.get(name) != value for name, value in metadata.items()):
            reject("E_HIA_RECEIPT_BINDING", "build record differs from retained native metadata")
        built = record.get("native_build")
        if (type(built) is not dict or type(record.get("object_artifact")) is not dict
                or record["object_artifact"] != built.get("object_artifact")
                or record.get("object_sha256") != built.get("object_sha256")
                or built.get("core_sha256") != program.sha256
                or built.get("input_sha256") != program.input_sha256
                or built.get("implementation_sha256") != self.identities["backend_sha256"]
                or built.get("kind") != record["output_kind"]
                or built.get("foreign_buffer_exports") != record.get("foreign_buffer_exports", [])
                or built.get("artifact_sha256") != sha256(data).hexdigest()):
            reject("E_HIA_RECEIPT_BINDING", "build record differs from actual artifact bytes")
        object_bytes, object_metadata = self.store.get(record["object_artifact"], kind="build-object", **_connection_arguments(_connection))
        expected_metadata = {"schema": "hepta.hia.agent.build-object.v1", "core_sha256": program.sha256,
            "machine_plan_sha256": built.get("machine_plan_sha256"), "installation": self.identities}
        if (object_metadata != expected_metadata or sha256(object_bytes).hexdigest() != record["object_sha256"]
                or record["object_artifact"]["sha256"] != record["object_sha256"]
                or record["output_kind"] == "object" and object_bytes != data):
            reject("E_HIA_RECEIPT_BINDING", "retained object differs from its exact build binding")
        return record, data, object_bytes, program

    def _build_receipt(self, ref, context, artifact, *, _connection=None):
        return self._build_inputs(ref, context, artifact, **_connection_arguments(_connection))[0]

    def _cost_ledger(self, context, evaluation_wall_ns, native_wall_ns):
        rows = self.store.db.execute("SELECT * FROM costs WHERE context_id=? OR context_id IS NULL ORDER BY sequence LIMIT 10001",
                                     (context["ref"]["id"],)).fetchall()
        truncated = len(rows) > 10000
        rows = rows[:10000]
        entries = [{"sequence": row["sequence"], "tool": row["tool"], "request_id": row["request_id"],
                    "context_id": row["context_id"], "wall_ns": row["wall_ns"], "status": row["status"],
                    "details": decode_data(row["details"])} for row in rows]
        policy, _ = self.store.get_json(context["budget"]["cost_policy"])
        external = dict(policy["external_costs"])
        # A caller may record measured zero; an incomplete model ledger cannot
        # convert a placeholder zero into an observed zero-cost model call.
        if not policy["external_costs_complete"]:
            external = {name: None for name in external}
        attributed = sum(int(row["wall_ns"]) for row in rows if row["context_id"] == context["ref"]["id"])
        unscoped = sum(int(row["wall_ns"]) for row in rows if row["context_id"] is None)
        return {"schema": "hepta.hia.agent.cost-ledger.v1", "context": context["ref"],
            "entries": entries, "entries_truncated": truncated,
            "context_tool_wall_ns_before_evaluation": str(attributed),
            "unattributed_discovery_artifact_read_wall_ns": str(unscoped),
            "evaluation_wall_ns_through_report": str(evaluation_wall_ns),
            "native_child_wall_ns": str(native_wall_ns),
            "external_costs": external, "external_cost_source": "caller-supplied report, independently unmeasured",
            "external_costs_complete": policy["external_costs_complete"],
            "adoption_wall_ns": None, "future_execution_count": policy["expected_invocations"],
            "failed_attempts_retained": True, "full_search_cost_complete": False,
            "net_optimization_benefit_proved": False,
            "scope": "observed request prefix; unscoped calls cannot be uniquely attributed and adoption/future/model cost may be unknown"}

    def _hia_evaluate(self, args):
        from .hia_agent_runner import run_native_batch, run_reference_batch
        from .hia_agent_buffers import validate_cases
        started = time.monotonic_ns()
        context = self._context(args["context"])
        baseline_bytes, baseline_meta, baseline_program = self._native(args["baseline_artifact"], args["context"])
        candidate_bytes, candidate_meta, candidate_program = self._native(args["candidate_artifact"], args["context"])
        built = self._build_receipt(args["build_receipt"], args["context"], args["candidate_artifact"])
        if baseline_meta["output_kind"] != "shared" or candidate_meta["output_kind"] != "shared":
            reject("E_HIA_EXECUTION_PROFILE", "evaluation requires retained direct shared images", "execution")
        if baseline_meta["signatures"] != candidate_meta["signatures"]:
            reject("E_HIA_ABI", "baseline and candidate frozen public ABI differ", "execution")
        if context["baseline_core_sha256"] is not None and context["baseline_core_sha256"] != baseline_program.sha256:
            reject("E_HIA_BASELINE", "evaluation baseline differs from the frozen Core snapshot", "execution")
        objective = self._required_claims(context, args["candidate_artifact"],
                                         args["verification_receipts"], baseline_program.sha256)
        workload, _ = self.store.get_json(context["workload"])
        validate(workload, WORKLOAD_SCHEMA, "workload")
        validate_cases(baseline_meta["signatures"], workload["cases"])
        exports = tuple(map(tuple, context.get("foreign_buffer_exports", [])))
        observations, normal, trapping = [], [], []
        correct, complete, budget_exceeded = True, True, False
        reference_started = time.monotonic_ns()
        context_owner = getattr(self, '_native_context', None)
        if context_owner is None:
            context_row = self.store.db.execute("SELECT created_ns FROM contexts WHERE id=?", (args["context"]["id"],)).fetchone()
            context_deadline = int(context_row["created_ns"]) + context["budget"]["max_total_wall_ms"] * 1_000_000
        else:
            context_row, context_deadline = context_owner.capture_deadline(args, context)

        def remaining_total_ms():
            if context_owner is not None:
                return context_owner.remaining_captured(context_deadline)
            return max(0, (context_deadline - time.time_ns()) // 1_000_000)

        references = {}
        for label, program in (("baseline", baseline_program), ("candidate", candidate_program)):
            reference = run_reference_batch(program, workload["cases"], timeout_ms=remaining_total_ms(),
                memory_bytes=uint64(context["budget"]["max_memory_bytes"], "max_memory_bytes"),
                foreign_buffer_exports=exports)
            references[label] = reference
            if reference["status"] != "returned" or not reference["report"]["complete"]:
                complete = False
                budget_exceeded = reference["status"] == "budget_exceeded" or reference["report"] is not None and any(
                    row["status"] == "budget_exceeded" for row in reference["report"]["observations"])
                if not budget_exceeded:
                    correct = False
                break
        for index, case in enumerate(workload["cases"]):
            if not complete:
                break
            if remaining_total_ms() <= 0:
                complete, budget_exceeded = False, True
                break
            expected = references["baseline"]["report"]["observations"][index]
            candidate_reference = references["candidate"]["report"]["observations"][index]
            row = {"index": index, "function": case["function"], "arguments": case["arguments"],
                   "baseline_vm": expected, "candidate_vm": candidate_reference}
            observations.append(row)
            if "budget_exceeded" in {expected["status"], candidate_reference["status"]}:
                complete, budget_exceeded = False, True
                break
            expected_value = _value_observation(expected)
            if "expected" in case:
                declared_scope = expected_value if "buffers" in case["expected"] else {
                    key: value for key, value in expected_value.items() if key != "buffers"}
                if case["expected"] != declared_scope:
                    reject("E_HIA_WORKLOAD_EXPECTATION", "declared case expectation differs from baseline Core at index " + str(index), "execution")
            # A native result cannot excuse a reference-level first-trap or
            # resource behavior difference. This is an observation at this
            # workload, separate from an equivalence proof over all inputs.
            observables = lambda x: {"value": _value_observation(x), "first_trap": x.get("trap_code"),
                                     "resources": x["ledger"]["resources"]}
            if observables(expected) != observables(candidate_reference):
                correct = False
            prepared = {"function": case["function"], "arguments": case["arguments"], "expected": expected_value}
            if expected["status"] == "trapped":
                trapping.append((index, prepared))
            else:
                normal.append((index, prepared))
        reference_ns = time.monotonic_ns() - reference_started
        runs, native_started = {}, time.monotonic_ns()
        owner = digest({"tool": "hia_evaluate", "key": args["request_key"]})
        budget_claim = self.store.execution_budgets.claim(args["context"]["id"], owner,
            context["budget"]["max_native_wall_ms"], native_started)
        for label, data, metadata in (("baseline", baseline_bytes, baseline_meta), ("candidate", candidate_bytes, candidate_meta)):
            runs[label] = {"normal": None, "traps": [], "total_native_ns": "0"}
            if not complete:
                continue

            def run(cases, warmup, repetitions):
                return budget_claim.run(run_native_batch, data, metadata["signatures"], cases,
                    now=time.monotonic_ns(), total_ms=remaining_total_ms(),
                    warmup=int(warmup), repetitions=int(repetitions),
                    memory_bytes=uint64(context["budget"]["max_memory_bytes"], "max_memory_bytes"))

            if normal:
                outcome = run([case for _, case in normal], workload["warmup_iterations"], workload["repetitions"])
                runs[label]["normal"] = outcome
                if outcome["status"] != "returned":
                    correct = False
                    complete = False
                    budget_exceeded = outcome["status"] == "budget_exceeded"
                    continue
                report = outcome["report"]
                if report["completed_cases"] != len(normal) or len(report["observations"]) != len(normal):
                    reject("E_HIA_NATIVE_REPORT", "native report did not account for every planned case", "execution")
                runs[label]["total_native_ns"] = report["total_native_ns"]
                for (index, case), observed in zip(normal, report["observations"]):
                    value = _value_observation(observed)
                    observations[index][label + "_native"] = observed
                    if observed["mismatch"] or value != case["expected"]:
                        correct = False
            for index, case in trapping:
                outcome = run([case], 0, 1)
                runs[label]["traps"].append({"index": index, **outcome})
                observations[index][label + "_native"] = {"status": outcome["status"], "returncode": outcome["returncode"]}
                if "buffers" in case["expected"]:
                    actual_buffers = outcome.get("buffer_snapshots", [{}])[0].get("buffers")
                    observations[index][label + "_native"]["buffers"] = actual_buffers
                    if actual_buffers != case["expected"]["buffers"]:
                        correct = False
                if outcome["status"] != "trapped":
                    correct = False
                    if outcome["status"] in {"budget_exceeded", "faulted", "invalid_report"}:
                        complete = False
                        budget_exceeded = outcome["status"] == "budget_exceeded"
                        break
        # A nonterminal crash leaves the owner fenced and never refunds an
        # unknown native cost. Only the confirmed terminal path releases it.
        budget_claim.complete()
        native_ns = budget_claim.native_ns
        if complete:
            complete = len(observations) == len(workload["cases"]) and all(
                "baseline_native" in row and "candidate_native" in row for row in observations)
        if objective["metric"] == "artifact_bytes":
            before, after = len(baseline_bytes), len(candidate_bytes)
        else:
            before = int(runs.get("baseline", {}).get("total_native_ns", "0"))
            after = int(runs.get("candidate", {}).get("total_native_ns", "0"))
        ratio = (before - after) / before if before else 0.0
        if budget_exceeded:
            outcome = "budget_exceeded"
        elif not correct:
            outcome = "incorrect"
        elif not complete or objective["metric"] == "latency_ns" and trapping:
            outcome = "inconclusive"
        elif after < before and ratio >= objective["min_improvement_ratio"]:
            outcome = "improved"
        elif after > before:
            outcome = "regressed"
        else:
            outcome = "unchanged"
        measurements = self.store.json({"schema": "hepta.hia.agent.measurements.v1", "context": args["context"],
            "workload": context["workload"], "objective": context["objective"],
            "baseline_artifact": args["baseline_artifact"], "candidate_artifact": args["candidate_artifact"],
            "metric": objective["metric"], "baseline_value": str(before), "candidate_value": str(after),
            "improvement_ratio": ratio, "reference_wall_ns": str(reference_ns),
            "planned_cases": len(workload["cases"]), "observations": observations, "native_runs": runs,
            "reference_runs": references,
            "native_correctness_scope": "frozen workload return/trap behavior and all external snapshot bytes; VM first-trap/resource observations recorded separately",
            "universal_equivalence_or_native_refinement_proved": False,
            "measurement_scope": "same host and immutable workload, baseline then candidate; call latency includes ctypes FFI overhead; snapshot reset/hash outside call timing is included in subprocess wall cost",
            "outcome": outcome, "planned_workload_complete": complete}, "measurements")
        costs = self._cost_ledger(context, time.monotonic_ns() - started, native_ns)
        ledger = self.store.json(costs, "cost-ledger")
        receipt = self.store.json({"schema": "hepta.hia.agent.evaluation.v1", "context": args["context"],
            "installation": self.identities, "baseline_artifact": args["baseline_artifact"],
            "candidate_artifact": args["candidate_artifact"], "baseline_core_sha256": baseline_program.sha256,
            "candidate_core_sha256": candidate_program.sha256, "build_receipt": args["build_receipt"],
            "verification_receipts": args["verification_receipts"], "report_complete": True,
            "planned_workload_complete": complete, "termination_confirmed": True, "outcome": outcome,
            "measurements": measurements, "full_cost_ledger": ledger,
            "net_optimization_benefit_proved": False, "adopted": False}, "evaluation-receipt")
        return {"baseline_artifact": args["baseline_artifact"], "candidate_artifact": args["candidate_artifact"],
            "evaluation_receipt": receipt, "report_complete": True, "planned_workload_complete": complete,
            "termination_confirmed": True, "outcome": outcome, "measurements": measurements,
            "full_cost_ledger": ledger, "adopted": False}

    def _hia_adopt_native(self, args, *, _connection=None):
        """Existing foreign evidence checks, then the complete native ledger."""
        context = self._context(args["context"], **_connection_arguments(_connection))
        evaluation, _ = self.store.get_json(args["evaluation_receipt"], kind="evaluation-receipt", **_connection_arguments(_connection))
        if (evaluation["context"] != args["context"] or evaluation["candidate_artifact"] != args["candidate_artifact"]
                or evaluation["installation"] != self.identities):
            reject("E_HIA_RECEIPT_BINDING", "evaluation does not authorize this candidate/context", "adoption")
        self._build_receipt(evaluation["build_receipt"], args["context"], args["candidate_artifact"], **_connection_arguments(_connection))
        objective = self._required_claims(context, args["candidate_artifact"], args["verification_receipts"], evaluation["baseline_core_sha256"], **_connection_arguments(_connection))
        if (not evaluation["report_complete"] or not evaluation["planned_workload_complete"]
                or not evaluation["termination_confirmed"] or evaluation["outcome"] not in
                ({"improved", "unchanged"} if objective["allow_unchanged"] else {"improved"})):
            reject("E_HIA_EVALUATION_REQUIRED", "evaluation did not meet the frozen correctness/performance acceptance", "adoption")
        self.store.get(evaluation["measurements"], kind="measurements", **_connection_arguments(_connection))
        self.store.get(evaluation["full_cost_ledger"], kind="cost-ledger", **_connection_arguments(_connection))
        if objective.get("require_net_benefit", False):
            reject("E_HIA_COST_INCOMPLETE", "full model/discovery/adoption/future-use cost is not established by this prefix; net-benefit requirement cannot pass", "adoption")
        _data, metadata, _program = self._native(args["candidate_artifact"], args["context"], **_connection_arguments(_connection))
        _baseline_data, baseline, _baseline_program = self._native(evaluation["baseline_artifact"], args["context"], **_connection_arguments(_connection))
        if metadata["signatures"] != baseline["signatures"]:
            reject("E_HIA_ABI", "candidate and baseline are not ABI compatible", "adoption")
        retained = self.store.slot_ledger.operate(2, self, slot=args['target_slot'],
            context=args['context']['id'], expected=args['expected_current'],
            candidate=args['candidate_artifact'], baseline=evaluation['baseline_artifact'],
            abi=wire(metadata['signatures']), connection=_connection)
        snapshot, current = retained.snapshot(), retained.current()
        slot, candidate, baseline_ref = (snapshot['target_slot'], retained.reference(896), retained.reference(1072))
        receipt = self.store.json({"schema": "hepta.hia.agent.adoption.v1", "context": args["context"],
            "target_slot": slot, "previous": snapshot["current"], "current": current,
            "active_artifact": candidate, "retained_baseline": baseline_ref,
            "evaluation_receipt": args["evaluation_receipt"], "verification_receipts": args["verification_receipts"],
            "future_calls_only": True, "in_flight_versions_retained": True,
            "consumer_api": "acquire_slot -> invoke_lease -> release_slot"}, "adoption-receipt", **_connection_arguments(_connection))
        return {"target_slot": slot, "previous": snapshot["current"], "current": current,
                "active_artifact": candidate, "adoption_receipt": receipt, "future_calls_only": True}

    def invoke_lease(self, lease, function, arguments):
        from .hia_agent_runner import run_native_batch
        from .hia_agent_buffers import validate_arguments
        lease = self._lease(lease)
        data, metadata, _program = self._native(lease["artifact"])
        if metadata["output_kind"] != "shared":
            reject("E_HIA_ABI", "slot generation is not an executable shared image")
        signature = metadata["signatures"].get(function) if type(function) is str else None
        if signature is None:
            reject("E_HIA_ARGUMENTS", "call does not match the retained public ABI")
        # Freeze before validation: mutable caller dictionaries/lists must not
        # change between admission and the disposable child's invocation.
        arguments = decode_data(wire(list(arguments) if type(arguments) is tuple else arguments))
        validate_arguments(signature, arguments)
        context = self._context(metadata["context"])
        result = run_native_batch(data, metadata["signatures"], [{"function": function, "arguments": arguments}],
            timeout_ms=context["budget"]["max_native_wall_ms"],
            memory_bytes=uint64(context["budget"]["max_memory_bytes"], "max_memory_bytes"), capture_buffers=True)
        buffers = []
        for captured in result.pop("captured_buffers", []):
            data = captured.pop("data")
            buffers.append({**captured, "artifact": self.store.put(data, "invocation-buffer", {
                "lease": lease["id"], "generation": lease["generation"], "artifact": lease["artifact"],
                "function": function, "argument": captured["argument"], "termination_confirmed": True})})
        external = {"buffers": buffers} if signature.get("abi") else {}
        if result["status"] == "returned":
            observation = result["report"]["observations"][0]
            if observation["status"] == "returned":
                return {"status": "returned", "values": observation["values"], "generation": lease["generation"],
                        "artifact": lease["artifact"], "termination_confirmed": True, **external}
            return {"status": observation["status"], "generation": lease["generation"],
                    "artifact": lease["artifact"], "termination_confirmed": True, **external}
        return {"status": result["status"], "generation": lease["generation"], "artifact": lease["artifact"],
                "termination_confirmed": result["termination_confirmed"], **external}


def _connection_arguments(connection):
    """Pass only an explicitly supplied private effect connection onward."""
    return {} if connection is None else {'_connection': connection}


def _value_observation(observation):
    value = ({"status": "returned", "values": observation["values"]}
             if observation["status"] == "returned" else {"status": observation["status"]})
    if "buffers" in observation:
        value["buffers"] = observation["buffers"]
    return value
