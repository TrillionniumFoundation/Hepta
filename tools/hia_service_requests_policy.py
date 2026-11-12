"""Exact eight original request/discovery policies; authoring input only."""

class HIAAgentService:
    def _profiles(self):
        from .hia_proof_contract_selection import proof_contract_scope
        with proof_contract_scope(getattr(self, '_native_proof_contract', None)):
            from .hia_program_native import TARGET, PROFILE, SUPPORTED_OPCODES, CORE_SCHEMAS, IMPORTS
            from .hia_schema import schema_registry
            from .hia_safe_core import ARTIFACT_PROFILE, LIMITS
            common = {"implementation": self.identities, "catalog_sha256": self.catalog_sha256}
            bodies = {
                "compiler": {**common, "schema": "hepta.hia.agent.compiler-profile.v1",
                    "backend": "hia-direct", "implicit_profitability_optimizer": False,
                    "llvm_codegen": False, "external_assembler": False},
                "target": {"schema": "hepta.hia.agent.target-profile.v1", "triple": TARGET,
                    "isa": "x86-64", "abi": "SysV AMD64 LP64 scalar entries; opt-in synchronous borrowed-byte snapshots",
                    "operating_system": "Linux", "max_memory_bytes": str(4 * 1024**3),
                    "min_memory_bytes": str(64 * 1024**2), "features": ["baseline-x86-64"]},
                "backend": {**common, "schema": "hepta.hia.agent.backend-profile.v1", "profile": PROFILE,
                    "target": TARGET, "core_schemas": sorted(CORE_SCHEMAS), "opcodes": sorted(SUPPORTED_OPCODES),
                    "runtime_imports": sorted(IMPORTS), "external_abi": "v1 integer/bool scalar inputs and at most one scalar/unit result; v2 explicit readbuf/mutbuf snapshots and one u32 result",
                    "borrowed_byte_snapshots": {"workload_schema": "hepta.hia.agent.workload.v2",
                        "profile": "hepta.hia.agent.borrowed-byte-snapshots.v1",
                        "max_buffer_bytes": 1048576, "max_workload_buffer_bytes": 33554432,
                        "pointer_authority": "child-owned distinct synchronous allocations; caller supplies bytes only",
                        "observation": "all external bytes on return and confirmed abort; fresh initial bytes on every repetition",
                        "reference_limits": {"max_steps": 10000000, "max_heap_bytes": 16777216, "max_call_depth": 256},
                        "independent_native_refinement": "unsupported"},
                    "max_stack_frame_bytes": 65536, "max_exports": 128,
                    "object_emission_external_tool": False, "shared_linker": "GNU ld only",
                    "native_resource_limits": "disposable child wall/CPU/address-space limits; no VM tick guarantee",
                    "universal_backend_refinement_proved": False, "self_hosted": False},
                "artifact": {"schema": "hepta.hia.agent.artifact-profile.v1", "inline_utf8_characters": 65536,
                    "max_path_bytes": 8 * 1024**2, "path_root_count": len(self.artifact_roots),
                    "path_roots_sha256": digest([str(root) for root in self.artifact_roots]),
                    "symlink_capture": False, "path_authority": "administrator configured roots only"},
                "validation": {**common, "schema": "hepta.hia.agent.validation-profile.v1",
                    "core_admission": "existing whole-program verifier",
                    "behavior_equivalence": ["exact Core identity", "exhaustive pure acyclic scalar domain with at most 12 input bits",
                        "optional existing pinned-Z3 structural scalar/effect profile"],
                    "canonical_core_to_machine_refinement": "unsupported",
                    "independent_native_refinement": {"method": SAFE_CORE_METHOD,
                        "profile": SAFE_CORE_SERVICE_PROFILE, "artifact_profile": ARTIFACT_PROFILE,
                        "output_kind": "shared", "entry_abi": "one unsigned scalar acyclic function; no borrowed or foreign entries",
                        "foreign_buffer_exports": [], "limits": dict(LIMITS),
                        "inputs": "the exact retained build object, final ELF and canonical Core; no reemission",
                        "proof_scope": SAFE_CORE_DOMAIN},
                    "machine_plan_refinement": "separately checked layout, scratch-register, scalar register-lifetime and exact encoding choices relative to assumed-correct canonical lowering",
                    "encoding_check": "rederive entire object and linked image; validate retained identities and ABI",
                    "sample_tests_are_proofs": False, "proof_result_schema": PROOF_SCHEMA,
                    "proved_meaning": PROVED_MEANING, "unscoped_legacy_receipts_accepted": False},
                "lowering": {**common, "schema": "hepta.hia.agent.lowering-profile.v1",
                    "rules": "fixed stack slots; fixed scratch registers; source block order; explicit control transfers",
                    "selection_authority": "semantic implementation only", "profitability_passes": []},
                "plan": {**common, "schema": "hepta.hia.agent.plan-profile.v1", "plan_schema": PLAN_SCHEMA,
                    "choices": "v1 block permutation; v2 block/function permutation, r10/r11 bijection, exact immediate encodings and bounded function alignment; v3 checked scalar assignments to rbx/r12-r15 and explicit register-only CMOV selection",
                    "preserved": ["original Core", "checked scalar value locations", "logical operation and effect order within each block", "entry and CFG edges", "public ABI"],
                    "unchecked_bytes": False, "automatic_layout_search": False},
            }
            self.profiles, self.profile_artifacts = {}, {}
            for name, body in bodies.items():
                ref, artifact = self.store.profile("hia-" + name + "-v1", body)
                self.profiles[name], self.profile_artifacts[name] = ref, artifact
            self.resources = {
                "schema_registry": self.store.json(schema_registry(), "discovery"),
                "workload_schema": self.store.json(WORKLOAD_SCHEMA, "discovery"),
                "objective_schema": self.store.json(OBJECTIVE_SCHEMA, "discovery"),
                "cost_policy_schema": self.store.json(COST_POLICY_SCHEMA, "discovery"),
                "plan_schema": self.store.json(PLAN_SCHEMA, "discovery"),
                "proof_contract": self.store.json(proof_contract_description(), "discovery"),
            }
            for name, filename in (("assembly_grammar", "HIA_AGENT_ASSEMBLY.md"),
                                   ("core_language", "HIA_PROGRAM.md"),
                                   ("machine_plan_guide", "HIA_AGENT_MACHINE_PLANS.md"),
                                   ("proof_contract_guide", "HIA_AGENT_PROOF_RESULTS.md"),
                                   ("machine_validation_guide", "HIA_SAFE_CORE_MACHINE_VALIDATION.md"),
                                   ("buffer_lifecycle_guide", "HIA_AGENT_BUFFER_LIFECYCLE.md"),
                                   ("macro_policy_guide", "HIA_AGENT_MACRO_POLICY.md"),
                                   ("byte_bootstrap_guide", "HIA_DIRECT_BYTE_BOOTSTRAP.md"),
                                   ("self_hosting_core_guide", "HIA_SELF_HOSTING_CORE.md"),
                                   ("self_hosting_core_support", "HIA_SELFHOST_CORE_SUPPORT.json")):
                self.resources[name] = self.store.put(_agent_resource_path("docs/" + filename).read_bytes(), "discovery")
            from .hia_agent_macro_discovery import macro_policy_guidance
            self.resources["macro_policy"] = self.store.json(macro_policy_guidance(self.identities), "discovery")
            self.resources["examples"] = self.store.json(self._examples(), "discovery")
            self.resources["diagnostics"] = self.store.json({"schema": "hepta.hia.agent.diagnostics.v1",
                "phases": ["admission", "context", "verification", "codegen", "execution", "adoption"],
                "codes": {"E_HIA_SCHEMA": "repair the named input field", "E_HIA_CONTEXT_STALE": "rediscover installed source and create a new context",
                    "E_HIA_REQUEST_CONFLICT": "same key belongs to different arguments", "E_HIA_REQUEST_UNKNOWN": "observe the original runtime job; never relaunch",
                    "E_HIA_ARTIFACT_IDENTITY": "use the complete issued reference", "E_HIA_MACHINE_PLAN": "read plan_schema and supply only checked Core-bound machine choices",
                    "E_HIA_CLAIM_REQUIRED": "requested acceptance proof has no exact qualifying retained receipt",
                    "E_HIA_PROOF_SCOPE": "rerun verification with a fresh request key; proof scope or retained checker conclusion is missing or differs",
                    "E_HIA_GENERATION_STALE": "inspect current slot through the authorized consumer; use a fresh conditional request"}}, "discovery")
            self.manifest = self.store.json({"schema": "hepta.hia.agent.manifest.v1",
                "status": "implemented_bounded_profiles", "catalog_sha256": self.catalog_sha256,
                "installation": self.identities, "profiles": self.profiles,
                "profile_manifests": self.profile_artifacts, "resources": self.resources,
                "cold_start": ["read assembly_grammar/core_language and an exact opcode catalog",
                    "retain workload, objective and cost-policy JSON as artifacts", "freeze context using discovered profiles",
                    "import or patch an explicit Core candidate", "verify requested claims for the exact subject",
                    "emit using canonical lowering or a checked explicit machine plan", "verify actual encoding and, when admitted, independent native refinement",
                    "evaluate baseline and candidate on the entire frozen workload", "adopt only with qualifying receipts and expected generation/epoch"],
                "execution_authority": "administrator-installed runtime provider, never supplied context",
                "cold_start_learning_or_net_benefit_proved": False,
                "consumer_api": "HIAAgentService.acquire_slot/invoke_lease/release_slot",
                "initial_slot": "expected 0/0 retains the evaluation baseline at generation 0; candidate starts generation 1",
                "unknown_external_costs": "null and incomplete, never inferred as zero"}, "discovery")

    @staticmethod
    def _examples():
        from .hia_agent_assembly import assemble_program, render_assembly
        params = [{"name": "value", "type": "u8"}]
        document = {"schema": "hepta.hia.program.v6", "module": "discovery_identity",
            "functions": [{"name": "identity", "params": params, "returns": ["u8"], "effects": [],
                "entry": "entry", "blocks": [{"id": "entry", "params": params, "ops": [],
                    "term": {"op": "ret", "values": ["value"]}}]}]}
        program = verify_program(document)
        assembly = render_assembly(program)
        if assemble_program(assembly).sha256 != program.sha256:
            raise RuntimeError("discovery example does not round-trip")
        return {"schema": "hepta.hia.agent.examples.v1", "core": program.as_dict(),
                "assembly": assembly, "wrong_reference": "Returning an undefined value fails whole-program admission.",
                "workload": {"schema": "hepta.hia.agent.workload.v1", "cases": [
                    {"function": "identity", "arguments": [23], "expected": {"status": "returned", "values": [23]}}],
                    "warmup_iterations": 0, "repetitions": 1},
                "objective": {"schema": "hepta.hia.agent.objective.v1", "metric": "artifact_bytes",
                    "required_claims": ["core_admission", "encoding_check"], "allow_unchanged": True,
                    "min_improvement_ratio": 0.0},
                "cost_policy": {"schema": "hepta.hia.agent.cost-policy.v1", "external_costs": {
                    "model_tokens": None, "model_wall_ns": None, "discovery_wall_ns": None},
                    "external_costs_complete": False, "expected_invocations": "0"}}

    def _error(self, request_id, exc):
        code = getattr(exc, "code", "E_HIA_REJECTED")
        if type(code) is not str:
            code = "E_HIA_REJECTED"
        details = getattr(exc, "details_artifact", None)
        if getattr(exc, "pending_slot_snapshot", None) is not None:
            # A failed CAS rolls back its effect transaction first. Publish the
            # diagnostic afterwards so its issued reference remains readable.
            details = self.store.json(exc.pending_slot_snapshot, "slot-snapshot")
        return {"contract_version": VERSION, "request_id": request_id, "status": "rejected",
            "error": {"code": code[:128], "phase": getattr(exc, "phase", "admission"),
                "message": str(exc)[:4096] or type(exc).__name__,
                "retry_action": getattr(exc, "retry_action", "correct_input"),
                "details_artifact": details}}

    def _hia_describe(self, args):
        from .hia_opcodes import opcode_catalog
        if "cursor" in args:
            reject("E_HIA_CURSOR", "discovery has no further page for this bounded manifest")
        if "backend_profile" in args and args["backend_profile"] != self.profiles["backend"]["id"]:
            reject("E_HIA_PROFILE", "requested backend profile is unavailable")
        language_schema = args.get("language_schema", "hepta.hia.program.v8")
        language = opcode_catalog(language_schema)
        profile, language_ref = self.store.profile(language_schema, language)
        section = args["section"]
        resources = {
            "manifest": [self.manifest],
            "language": [self.resources["schema_registry"], self.resources["assembly_grammar"], self.resources["core_language"], language_ref],
            "backend": [self.profile_artifacts["backend"], self.profile_artifacts["lowering"], self.profile_artifacts["target"],
                        self.resources["byte_bootstrap_guide"], self.resources["self_hosting_core_guide"],
                        self.resources["self_hosting_core_support"], self.profile_artifacts["validation"],
                        self.resources["machine_validation_guide"], self.resources["proof_contract_guide"],
                        self.resources["buffer_lifecycle_guide"]],
            "examples": [self.resources["examples"]], "diagnostics": [self.resources["diagnostics"]],
            "plans": [self.profile_artifacts["plan"], self.resources["plan_schema"],
                      self.resources["machine_plan_guide"], self.resources["macro_policy"],
                      self.resources["macro_policy_guide"]],
        }[section]
        return {"catalog_sha256": self.catalog_sha256, "manifest": self.manifest,
            "language_catalogs": [profile], "backend_profiles": [self.profiles["backend"]],
            "artifact_profiles": [self.profiles["artifact"]], "resources": resources, "next_cursor": None}

    def _hia_artifact(self, args):
        self._profile(args["artifact_profile"], "artifact")
        source = args["source"]
        if source["kind"] == "utf8":
            data = source["text"].encode("utf-8")
        else:
            data = capture_path(source["path"], self.artifact_roots, int(source["max_bytes"]))
            expected = source["expected_sha256"]
            if expected is not None and expected != sha256(data).hexdigest():
                reject("E_HIA_ARTIFACT_CHANGED", "captured bytes differ from the expected digest")
        ref = self.store.put(data, "input")
        return {"artifact": ref, "byte_length": str(len(data)), "content_admitted_as_program": False,
                "execution_authority_granted": False}

    def _hia_read(self, args):
        ref = args["artifact"]
        data, _ = self.store.get(ref)
        offset = 0
        if "cursor" in args:
            row = self.store.db.execute("SELECT * FROM cursors WHERE id=?", (args["cursor"],)).fetchone()
            if row is None or row["artifact_id"] != ref["id"] or row["sha256"] != ref["sha256"]:
                reject("E_HIA_CURSOR", "cursor is not bound to this exact artifact")
            offset = row["offset"]
        limit = int(args.get("max_bytes", 65536))
        chunk = data[offset:offset + limit]
        encoding = "utf8"
        try:
            # Decode the complete artifact once to decide binary vs UTF-8, then
            # only trim a page boundary. Never silently discard invalid bytes.
            data.decode("utf-8")
            while True:
                try:
                    content = chunk.decode("utf-8")
                    break
                except UnicodeDecodeError:
                    chunk = chunk[:-1]
        except UnicodeDecodeError:
            encoding, content = "base64", base64.b64encode(chunk).decode("ascii")
        # MCP JSON escaping can expand control characters sixfold. Bound the
        # serialized page independently from the raw-byte content budget.
        # The runtime exposes both structuredContent and a text JSON rendering.
        # The latter escapes quotes/backslashes a second time. Budget both
        # representations, not merely the first escaped content string.
        while len(wire(content)) + len(wire(wire(content).decode("utf-8"))) > 230000:
            chunk = chunk[:max(1, len(chunk) // 2)]
            if encoding == "base64":
                content = base64.b64encode(chunk).decode("ascii")
            else:
                while True:
                    try:
                        content = chunk.decode("utf-8")
                        break
                    except UnicodeDecodeError:
                        chunk = chunk[:-1]
        next_cursor = None
        if offset + len(chunk) < len(data):
            next_cursor = "page-" + digest({"artifact": ref, "offset": offset + len(chunk)})
            self.store.db.execute("INSERT OR IGNORE INTO cursors VALUES (?,?,?,?)",
                (next_cursor, ref["id"], ref["sha256"], offset + len(chunk)))
        return {"artifact": ref, "encoding": encoding, "content": content, "next_cursor": next_cursor}

    def _hia_inspect(self, args):
        from .hia_program_tools import inspect_program
        from .hia_edit_query import prepare_edit
        from .hia_program_native import emit_program_machine
        program = self._program(args["program"])
        selector = args.get("selector", {})
        if "cursor" in args:
            reject("E_HIA_CURSOR", "inspection returns an immutable artifact; paginate it through hia_read")
        view, query = args["view"], None
        if view == "summary":
            result = inspect_program(program)
        elif view == "lowering":
            context = self._context(args["context"])
            image = emit_program_machine(program,
                foreign_buffer_exports=tuple(map(tuple, context.get("foreign_buffer_exports", []))))
            result = {"schema": "hepta.hia.agent.lowering-view.v1", "core_sha256": program.sha256,
                "text_sha256": sha256(image.text_bytes).hexdigest(), "object_sha256": image.sha256,
                "text_bytes": str(len(image.text_bytes)), "frames": dict(image.function_frames),
                "lowering_profile": self.profiles["lowering"], "optimizer_used": False,
                "object": self.store.put(image.object_bytes, "lowering-object")}
        elif view == "dependencies":
            if not all(k in selector for k in ("function", "block", "output")):
                reject("E_HIA_SELECTOR", "dependencies require function, block and output")
            prepared = prepare_edit(program, function=selector["function"], block=selector["block"],
                                    output=selector["output"], fields=["op", "args", "attrs"])
            result = prepared
            query = self.store.json(prepared, "edit-query")
        else:
            if "function" not in selector:
                reject("E_HIA_SELECTOR", "function view requires an exact function")
            functions = {fn["name"]: fn for fn in program.as_dict()["functions"]}
            if selector["function"] not in functions:
                reject("E_HIA_SELECTOR", "function is not in this program")
            result = functions[selector["function"]]
            if view == "block":
                blocks = {b["id"]: b for b in result["blocks"]}
                if selector.get("block") not in blocks:
                    reject("E_HIA_SELECTOR", "block is not in this function")
                result = blocks[selector["block"]]
        return {"program": args["program"], "view_artifact": self.store.json(result, "inspection"),
                "query_artifact": query, "next_cursor": None}

    def _hia_candidate(self, args):
        from .hia_agent_assembly import assemble_program
        from .hia_program_tools import apply_program_patch
        change, base, native_payloads = args["change"], None, None
        if change["kind"] == "import":
            data, _ = self.store.get(change["source"])
            program = assemble_program(data) if change["format"] == "hia-asm.v1" else verify_program(decode_json(data))
            diagnostics = {"schema": "hepta.hia.agent.candidate-diagnostics.v1", "whole_program_checked": True,
                           "input_sha256": program.input_sha256, "core_sha256": program.sha256}
        else:
            base = change["base_program"]
            selected = os.environ.get('HEPTA_HIA_CORE_PATCH_MANIFEST')
            if selected:
                from .hia_agent_candidate_native import apply_candidate_patch
                original_bytes, _ = self.store.get(base)
                patch_bytes, _ = self.store.get(change["patch"])
                native_payloads = apply_candidate_patch(selected, original_bytes, patch_bytes, change["patch_schema"])
            else:
                original = self._program(base)
                patch, _ = self.store.get_json(change["patch"])
                if patch.get("schema") != change["patch_schema"]:
                    reject("E_HIA_PATCH_SCHEMA", "patch artifact differs from declared patch schema")
                program, diagnostics = apply_program_patch(original, patch)
        candidate = self.store.put(native_payloads[0] if native_payloads is not None else program.canonical_bytes,
                                   "core", {"context": args["context"]})
        diagnostic_artifact = (self.store.put(native_payloads[1], "candidate-diagnostics") if native_payloads is not None
                               else self.store.json(diagnostics, "candidate-diagnostics"))
        return {"candidate": candidate, "base_program": base,
            "diagnostics": diagnostic_artifact, "core_admitted": True,
            "behavior_equivalence_proved": False, "adopted": False}
