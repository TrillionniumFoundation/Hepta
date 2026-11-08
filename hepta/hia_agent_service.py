"""Implemented HIA tool domain: explicit Agent decisions, direct native bytes.

The caller supplies context and candidate choices. This service does not search,
rank, fold, inline or invoke an optimizer implicitly. Its mutable state belongs
to the administrator-configured runtime authority, not a model-supplied user ID.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
from hashlib import sha256
import itertools
import json
import os
from pathlib import Path
import platform
import signal
import sqlite3
import tempfile
import time
import uuid

from .hia_agent_contract import (VERSION, ROOT, COST_POLICY_SCHEMA, OBJECTIVE_SCHEMA,
    PLAN_SCHEMA, WORKLOAD_SCHEMA, catalog, installation_manifest, validate)
from .hia_agent_store import (AgentRejected, AgentStore, capture_path, digest, keys,
    reject, uint64, wire, decode_data)
from .hia_program import verify_program
from .hia_program_tools import decode_json
from .hia_proof_contract import (PROOF_SCHEMA, PROVED_MEANING, proof_subject, proof_result,
    assumptions_document, proof_contract_description, SAFE_CORE_METHOD, SAFE_CORE_DOMAIN,
    SAFE_CORE_SERVICE_PROFILE)


def _now():
    return datetime.now(timezone.utc).isoformat()


def _signatures(program, foreign_buffer_exports=()):
    from .hia_program_native import WIDTHS
    from .hia_native_byte_abi import normalize_exports
    from .hia_agent_buffers import PROFILE as BUFFER_PROFILE
    document = program.as_dict()
    signatures = {fn["name"]: {"params": [p["type"] for p in fn["params"]],
                         "returns": fn["returns"]}
            for fn in document["functions"] if fn["name"] in program.scalar_entrypoints
            and all(p["type"] in set(WIDTHS) | {"bool"} for p in fn["params"])
            and len(fn["returns"]) <= 1
            and all(typ in set(WIDTHS) | {"bool", "unit"} for typ in fn["returns"])}
    exports = dict(normalize_exports(foreign_buffer_exports, program))
    for fn in document["functions"]:
        if fn["name"] in exports:
            signatures[fn["name"]] = {"params": [p["type"] for p in fn["params"]],
                "returns": fn["returns"], "abi": BUFFER_PROFILE,
                "max_buffer_bytes": exports[fn["name"]]}
    return signatures


def _vm_observation(program, case, *, steps=1_000_000, heap=16 * 1024 * 1024,
                    foreign_buffer_exports=()):
    from .hia_program_runtime import execute_program, HIAProgramBudgetExceeded, HIAProgramTrap
    if case["function"] in dict(foreign_buffer_exports):
        from .hia_agent_buffers import reference_observation
        return reference_observation(program, case, foreign_buffer_exports,
                                     steps=10_000_000, heap=heap)
    try:
        result = execute_program(program, case["function"], case["arguments"],
                                 max_steps=steps, max_heap_bytes=heap)
    except HIAProgramTrap as exc:
        return {"status": "trapped", "trap_code": exc.code, "ledger": exc.report}
    except HIAProgramBudgetExceeded as exc:
        return {"status": "budget_exceeded", "budget_code": exc.code, "ledger": exc.report}
    return {"status": "returned", "values": result["values"], "ledger": result}


def _value_observation(observation):
    value = ({"status": "returned", "values": observation["values"]}
             if observation["status"] == "returned" else {"status": observation["status"]})
    if "buffers" in observation:
        value["buffers"] = observation["buffers"]
    return value

class HIAAgentService:
    def __init__(self, state_root, *, artifact_roots=()):
        self.catalog, self.catalog_sha256 = catalog()
        self.tools = {t["name"]: t for t in self.catalog["tools"]}
        self.identities = installation_manifest()
        self.store = AgentStore(state_root)
        self.artifact_roots = tuple(Path(root).absolute().resolve(strict=True) for root in artifact_roots)
        if any(not root.is_dir() for root in self.artifact_roots):
            reject("E_HIA_PROFILE", "configured artifact roots must be directories")
        self._profiles()

    def close(self):
        self.store.close()

    def _profiles(self):
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
            self.resources[name] = self.store.put((ROOT / "docs" / filename).read_bytes(), "discovery")
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

    def call(self, tool, arguments):
        started = time.monotonic_ns()
        request_id = "unadmitted-" + uuid.uuid4().hex
        key, reserved, context_id, response = None, False, None, None
        try:
            # Snapshot before inspecting any mutable producer dictionaries.
            arguments = decode_data(wire(arguments))
            request_digest = digest({"tool": tool, "arguments": arguments})
            request_id = "r-" + request_digest
            if tool == "hia_resource_read":
                keys(arguments, ("uri",), ("max_bytes",), "resource read")
                arguments = {"catalog_sha256": self.catalog_sha256,
                    "artifact": self.store.resolve_uri(arguments["uri"]),
                    "max_bytes": arguments.get("max_bytes", 65536)}
                tool = "hia_read"
            if tool not in self.tools:
                reject("E_HIA_TOOL", "unknown HIA tool")
            # A syntactically valid key is claimed even when later validation
            # rejects the request. Changed retry arguments cannot reuse it.
            candidate_key = arguments.get("request_key") if type(arguments) is dict else None
            if type(candidate_key) is str and 1 <= len(candidate_key) <= 192:
                key = digest({"tool": tool, "key": candidate_key})
                with self.store.transaction():
                    previous = self.store.db.execute("SELECT * FROM requests WHERE key=?", (key,)).fetchone()
                    if previous is not None:
                        if previous["digest"] != request_digest:
                            reject("E_HIA_REQUEST_CONFLICT", "request key is already bound to different arguments")
                        if previous["state"] == "completed":
                            cached = decode_data(previous["response"])
                            if tool == "hia_verify" and cached.get("status") == "completed":
                                self._replay_verification(cached, arguments)
                            return cached
                        reject("E_HIA_REQUEST_UNKNOWN", "original request has durable intent but no confirmed terminal result",
                               retry_action="observe_original")
                    self.store.db.execute("INSERT INTO requests VALUES (?,?,?,?,?,?)",
                        (key, request_digest, tool, "running", None, str(time.time_ns())))
                    reserved = True
            validate(arguments, self.tools[tool]["inputSchema"])
            if tool != "hia_describe" and arguments["catalog_sha256"] != self.catalog_sha256:
                reject("E_HIA_CATALOG_STALE", "tool catalog digest differs from installed catalog")
            if installation_manifest() != self.identities:
                reject("E_HIA_IMPLEMENTATION_STALE", "installed implementation changed during this service session")
            if "context" in arguments:
                context = self._context(arguments["context"])
                context_id = arguments["context"]["id"]
                if tool not in {"hia_inspect", "hia_rollback"}:
                    self._budget(context, candidate=tool == "hia_candidate")
            # Slot effect and exact response journal commit together. A crash
            # cannot leave a changed slot with a replayable uncommitted result.
            if tool in {"hia_adopt", "hia_rollback"}:
                with self.store.transaction():
                    result = getattr(self, "_" + tool)(arguments)
                    response = {"contract_version": VERSION, "request_id": request_id,
                                "status": "completed", "result": result}
                    validate(response, self.tools[tool]["outputSchema"], "result")
                    if reserved:
                        self.store.db.execute("UPDATE requests SET state='completed',response=? WHERE key=?",
                                              (wire(response).decode(), key))
                        reserved = False
            else:
                result = getattr(self, "_" + tool)(arguments)
                response = {"contract_version": VERSION, "request_id": request_id,
                            "status": "completed", "result": result}
                validate(response, self.tools[tool]["outputSchema"], "result")
        except (ValueError, TypeError, OSError, OverflowError, RecursionError, sqlite3.Error) as exc:
            response = self._error(request_id, exc)
        finally:
            if response is not None:
                # Preserve every attempted request, including malformed, slower,
                # timed-out and rejected candidates; exact replay costs no effect.
                self.store.db.execute("INSERT INTO costs (context_id,tool,request_id,wall_ns,status,details) VALUES (?,?,?,?,?,?)",
                    (context_id, str(tool), request_id, str(time.monotonic_ns() - started), response["status"],
                     wire({"error": response.get("error"), "replayed": False}).decode()))
                if reserved:
                    self.store.db.execute("UPDATE requests SET state='completed',response=? WHERE key=?",
                                          (wire(response).decode(), key))
        return response

    def _profile(self, ref, name):
        return self.store.check_profile(ref, self.profiles[name])

    def _program(self, ref):
        data, _ = self.store.get(ref)
        return verify_program(decode_json(data))

    def _context(self, ref):
        keys(ref, ("id", "sha256"), label="context reference")
        row = self.store.db.execute("SELECT * FROM contexts WHERE id=?", (ref["id"],)).fetchone()
        if row is None or row["sha256"] != ref["sha256"]:
            reject("E_HIA_CONTEXT_IDENTITY", "context is not a retained server record", "context")
        context, _ = self.store.get_json(decode_data(row["artifact"]), kind="context")
        if context["installation"] != self.identities or context["catalog_sha256"] != self.catalog_sha256:
            reject("E_HIA_CONTEXT_STALE", "context binds a different installed implementation", "context")
        for name in ("compiler", "target"):
            self._profile(context[name + "_profile"], name)
        context["ref"] = ref
        return context

    def _budget(self, context, *, candidate=False):
        row = self.store.db.execute("SELECT * FROM contexts WHERE id=?", (context["ref"]["id"],)).fetchone()
        limits = context["budget"]
        if time.time_ns() - int(row["created_ns"]) > limits["max_total_wall_ms"] * 1_000_000:
            reject("E_HIA_BUDGET", "context total wall budget has expired", "context")
        if candidate:
            changed = self.store.db.execute("UPDATE contexts SET attempts=attempts+1 WHERE id=? AND attempts<?",
                (context["ref"]["id"], limits["max_candidates"])).rowcount
            if changed != 1:
                reject("E_HIA_BUDGET", "candidate attempt budget exhausted", "context")

    def _remaining_ms(self, context):
        row = self.store.db.execute("SELECT created_ns FROM contexts WHERE id=?", (context["ref"]["id"],)).fetchone()
        deadline = int(row["created_ns"]) + context["budget"]["max_total_wall_ms"] * 1_000_000
        return max(0, (deadline - time.time_ns()) // 1_000_000)

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

    def _hia_context(self, args):
        from .hia_agent_buffers import export_manifest, buffer_size, MAX_WORKLOAD_BUFFER_BYTES
        self._profile(args["compiler_profile"], "compiler")
        self._profile(args["target_profile"], "target")
        workload, _ = self.store.get_json(args["workload"])
        objective, _ = self.store.get_json(args["objective"])
        cost_policy, _ = self.store.get_json(args["budget"]["cost_policy"])
        validate(workload, WORKLOAD_SCHEMA, "workload")
        foreign_buffer_exports = export_manifest(workload)
        snapshot_bytes = sum(buffer_size(value) for case in workload["cases"]
                             for value in case["arguments"] if type(value) is dict)
        if snapshot_bytes > MAX_WORKLOAD_BUFFER_BYTES:
            reject("E_HIA_BUFFER_BUDGET", "frozen workload exceeds 32 MiB of external byte snapshots", "context")
        validate(objective, OBJECTIVE_SCHEMA, "objective")
        validate(cost_policy, COST_POLICY_SCHEMA, "cost_policy")
        for name in ("max_candidates", "max_model_tokens", "max_total_wall_ms", "max_native_wall_ms"):
            args["budget"][name] = int(args["budget"][name])
        uint64(cost_policy["expected_invocations"], "expected_invocations")
        memory = uint64(args["budget"]["max_memory_bytes"], "max_memory_bytes")
        if not 64 * 1024**2 <= memory <= 4 * 1024**3:
            reject("E_HIA_BUDGET", "execution profile admits 64 MiB..4 GiB address-space budgets", "context")
        if args["budget"]["max_native_wall_ms"] > args["budget"]["max_total_wall_ms"]:
            reject("E_HIA_BUDGET", "native wall budget exceeds total wall budget", "context")
        for name in ("model_wall_ns", "discovery_wall_ns"):
            if cost_policy["external_costs"][name] is not None:
                uint64(cost_policy["external_costs"][name], name)
        tokens = cost_policy["external_costs"]["model_tokens"]
        if tokens is not None and tokens > args["budget"]["max_model_tokens"]:
            reject("E_HIA_BUDGET", "reported model tokens exceed the frozen budget", "context")
        if cost_policy["external_costs_complete"] and any(v is None for v in cost_policy["external_costs"].values()):
            reject("E_HIA_COST", "complete external cost report cannot contain unknown fields", "context")
        baseline_sha = None
        if args["baseline_program"] is not None:
            baseline_sha = self._program(args["baseline_program"]).sha256
        sampled = _now()
        record = {"schema": "hepta.hia.agent.context.v1", "catalog_sha256": self.catalog_sha256,
            "installation": self.identities, "compiler_profile": args["compiler_profile"],
            "target_profile": args["target_profile"], "baseline_program": args["baseline_program"],
            "baseline_core_sha256": baseline_sha, "workload": args["workload"], "objective": args["objective"],
            "foreign_buffer_exports": [list(pair) for pair in foreign_buffer_exports],
            "budget": args["budget"], "sampled_at": sampled,
            "target_observation": {"system": platform.system(), "machine": platform.machine(),
                "cpu_count": os.cpu_count(), "observation_only": True},
            "resource_reservation_held": False, "context_is_execution_authority": False}
        manifest = self.store.json(record, "context")
        context = {"id": "ctx-" + uuid.uuid4().hex, "sha256": manifest["sha256"]}
        self.store.db.execute("INSERT INTO contexts VALUES (?,?,?,?,0)",
            (context["id"], context["sha256"], wire(manifest).decode(), str(time.time_ns())))
        self.store.db.execute("INSERT INTO execution_budgets VALUES (?,'0',NULL)", (context["id"],))
        return {"context": context, "manifest": manifest, "sampled_at": sampled,
            "compiler_profile": args["compiler_profile"], "target_profile": args["target_profile"],
            "resource_reservation_held": False, "context_is_execution_authority": False}

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
        change, base = args["change"], None
        if change["kind"] == "import":
            data, _ = self.store.get(change["source"])
            program = assemble_program(data) if change["format"] == "hia-asm.v1" else verify_program(decode_json(data))
            diagnostics = {"schema": "hepta.hia.agent.candidate-diagnostics.v1", "whole_program_checked": True,
                           "input_sha256": program.input_sha256, "core_sha256": program.sha256}
        else:
            base = change["base_program"]
            original = self._program(base)
            patch, _ = self.store.get_json(change["patch"])
            if patch.get("schema") != change["patch_schema"]:
                reject("E_HIA_PATCH_SCHEMA", "patch artifact differs from declared patch schema")
            program, diagnostics = apply_program_patch(original, patch)
        candidate = self.store.put(program.canonical_bytes, "core", {"context": args["context"]})
        return {"candidate": candidate, "base_program": base,
            "diagnostics": self.store.json(diagnostics, "candidate-diagnostics"), "core_admitted": True,
            "behavior_equivalence_proved": False, "adopted": False}

    def _behavior_equivalence(self, original, revised, timeout_ms):
        """A conservative proof decision, separate from workload testing."""
        from .hia_optimization import PURE, DEFAULT_POLICY, verify_optimization
        from .hia_program import WIDTHS, integer_range
        if timeout_ms <= 0:
            return "unknown", "Verification cannot exceed the frozen context deadline", {
                "method": "context_budget_exhausted", "reason": "context wall budget exhausted"}
        if original.canonical_bytes == revised.canonical_bytes:
            return "proved", "Reflexivity for the exact admitted canonical Core bytes, including resources and traps", {
                "method": "canonical_core_identity", "base_sha256": original.sha256,
                "candidate_sha256": revised.sha256, "all_inputs": True}
        left, right = original.as_dict(), revised.as_dict()
        signatures = _signatures(original)
        finite = signatures == _signatures(revised) and bool(signatures)
        # Only pure scalar functions without calls, allocation or ownership can
        # use finite value enumeration as complete semantic evidence. The
        # structural resource/effect checker is used for wider programs.
        for document in (left, right):
            for fn in document["functions"]:
                if len(fn["blocks"]) > 128 or sum(len(b["ops"]) for b in fn["blocks"]) > 4096:
                    finite = False
                if set(fn["effects"]) - {"trap"} or any(op["op"] not in PURE for b in fn["blocks"] for op in b["ops"]):
                    finite = False
                blocks = {b["id"]: b for b in fn["blocks"]}
                visiting, done = set(), set()

                def acyclic(name):
                    if name in visiting:
                        return False
                    if name in done:
                        return True
                    visiting.add(name)
                    term = blocks[name]["term"]
                    targets = ([term["target"]] if term["op"] == "jump" else
                               [term["then"]["target"], term["else"]["target"]] if term["op"] == "branch" else [])
                    if not all(acyclic(target) for target in targets):
                        return False
                    visiting.remove(name)
                    done.add(name)
                    return True
                if not acyclic(fn["entry"]):
                    finite = False
        interface = lambda d: {fn["name"]: {k: fn[k] for k in ("params", "returns", "effects")} for fn in d["functions"]}
        if interface(left) != interface(right):
            finite = False
        domains, total = {}, 0
        if finite:
            for name, signature in signatures.items():
                bits = sum(1 if typ == "bool" else WIDTHS.get(typ, 1000000) for typ in signature["params"])
                if bits > 12 or total + (1 << bits) > 4096:
                    finite = False
                    break
                domains[name] = [[False, True] if typ == "bool" else range(integer_range(typ)[0], integer_range(typ)[1] + 1)
                                 for typ in signature["params"]]
                total += 1 << bits
        if finite:
            transcript = sha256()
            checked = 0
            deadline = time.monotonic_ns() + min(10000, timeout_ms) * 1_000_000
            for name, input_domains in domains.items():
                for arguments in itertools.product(*input_domains):
                    if time.monotonic_ns() > deadline:
                        return "unknown", "Pure acyclic scalar finite domain; exhaustive enumeration deadline expired", {
                            "method": "finite_domain", "checked": checked, "required": total, "complete": False}
                    case = {"function": name, "arguments": list(arguments)}
                    before = _vm_observation(original, case, steps=10000)
                    after = _vm_observation(revised, case, steps=10000)
                    if "budget_exceeded" in {before["status"], after["status"]}:
                        return "unknown", "Pure acyclic scalar finite domain; reference budget prevented completeness", {
                            "method": "finite_domain", "checked": checked, "required": total, "complete": False}
                    observables = lambda row: {"status": row["status"], "values": row.get("values"),
                        "first_trap": row.get("trap_code"), "resources": row["ledger"]["resources"]}
                    first, second = observables(before), observables(after)
                    transcript.update(wire({"case": case, "before": first, "after": second}))
                    checked += 1
                    if first != second:
                        return "refuted", "All scalar inputs in a finite pure acyclic domain; return/first-trap/resource observations", {
                            "method": "finite_domain", "counterexample": case, "before": first, "after": second,
                            "checked": checked, "required": total, "complete": False}
            if time.monotonic_ns() > deadline:
                return "unknown", "Exhaustive scalar enumeration finished after its frozen verification deadline", {
                    "method": "finite_domain", "checked": checked, "required": total,
                    "complete": False, "deadline_met": False}
            return "proved", "Exhaustive complete pure acyclic scalar domain (at most 12 total input bits), including first trap and resource ledger", {
                "method": "finite_domain", "checked": checked, "required": total, "complete": True,
                "all_inputs_in_declared_widths": True, "transcript_sha256": transcript.hexdigest(),
                "base_sha256": original.sha256, "candidate_sha256": revised.sha256}
        report = verify_optimization(original, revised, {**DEFAULT_POLICY, "timeout_ms": min(5000, timeout_ms)})
        status = {"verified": "proved", "rejected": "refuted", "unknown": "unknown", "timeout": "unknown"}[report["status"]]
        return status, "Existing compositional v1-v7 scalar/effect/trap verifier with identical CFG/interface/ordered effects", report

    def _subject(self, args, program):
        subject = args["subject"]
        if subject["kind"] != "core":
            self._profile(subject["backend_profile"], "backend")
        if subject["kind"] == "canonical_lowering":
            self._profile(subject["lowering_profile"], "lowering")
        if subject["kind"] == "agent_machine_plan":
            from .hia_program_native import validate_block_layout_plan
            self._profile(subject["plan_profile"], "plan")
            plan, _ = self.store.get_json(subject["plan"])
            validate(plan, PLAN_SCHEMA, "machine_plan")
            return validate_block_layout_plan(program, plan)
        if subject["kind"] == "native_artifact":
            receipt = self._build_receipt(subject["build_receipt"], args["context"],
                                          subject["native_artifact"])
            if receipt["candidate"] != args["candidate"]:
                reject("E_HIA_SUBJECT", "native build receipt belongs to a different candidate", "verification")
        return None

    def _hia_verify(self, args):
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
            scoped = proof_result(claim=claim, status=status, domain=domain, subject=scoped_subject,
                profile=args["validation_profile"], installation=self.identities, evidence=evidence)
            if evidence.get("method") == SAFE_CORE_METHOD and status == "proved" and self._remaining_ms(context) <= 0:
                status = "unknown"
                evidence.update(outcome=status, deadline_met=False,
                                reason="the frozen context deadline expired before proof publication")
                scoped = proof_result(claim=claim, status=status, domain=domain, subject=scoped_subject,
                    profile=args["validation_profile"], installation=self.identities, evidence=evidence)
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

    def _verification(self, ref, context, candidate=None):
        record, _ = self.store.get_json(ref, kind="verification-receipt")
        if (record["context"] != context or record["installation"] != self.identities
                or candidate is not None and record["candidate"] != candidate):
            reject("E_HIA_RECEIPT_BINDING", "verification receipt belongs to a different context, candidate or implementation", "verification")
        self._profile(record["validation_profile"], "validation")
        program = self._program(record["candidate"])
        if program.sha256 != record["candidate_core_sha256"]:
            reject("E_HIA_RECEIPT_BINDING", "verification Core identity changed", "verification")
        original = None if record["base_program"] is None else self._program(record["base_program"])
        if record["base_core_sha256"] != (None if original is None else original.sha256):
            reject("E_HIA_RECEIPT_BINDING", "verification base Core identity changed", "verification")
        self._subject(record, program)
        context_record = self._context(context)
        subject = proof_subject(record, context_record["target_profile"])
        checks_schema = self.tools["hia_verify"]["outputSchema"]["properties"]["result"]["properties"]["checks"]
        try:
            validate(record["checks"], checks_schema, "verification.checks")
        except AgentRejected as exc:
            reject("E_HIA_PROOF_SCOPE", "missing or invalid proof scope; rerun verification with a fresh request key: " + str(exc), "verification")
        if len({check["claim"] for check in record["checks"]}) != len(record["checks"]):
            reject("E_HIA_PROOF_SCOPE", "verification repeats a proof property", "verification")
        for check in record["checks"]:
            evidence, _ = self.store.get_json(check["evidence_artifact"], kind="verification-evidence")
            assumptions, _ = self.store.get_json(check["assumptions_artifact"], kind="verification-assumptions")
            if evidence.get("method") == SAFE_CORE_METHOD:
                self._check_native_refinement_evidence(evidence, record["subject"], context, program)
            expected = proof_result(claim=check["claim"], status=check["status"], domain=check["domain"],
                subject=subject, profile=record["validation_profile"], installation=self.identities, evidence=evidence)
            actual = {key: value for key, value in check.items()
                      if key not in {"assumptions_artifact", "evidence_artifact"}}
            if (actual != expected or evidence.get("proof_binding") != expected
                    or assumptions != assumptions_document(expected)):
                reject("E_HIA_PROOF_SCOPE", "proof scope or retained checker conclusion differs; rerun verification with a fresh request key", "verification")
        return record

    def _replay_verification(self, response, arguments):
        """Observe an original result only if its complete scope remains valid."""
        try:
            validate(response, self.tools["hia_verify"]["outputSchema"], "replayed verification")
        except AgentRejected as exc:
            reject("E_HIA_PROOF_SCOPE", "cached proof lacks current scope; rerun verification with a fresh request key: " + str(exc), "verification")
        if installation_manifest() != self.identities:
            reject("E_HIA_IMPLEMENTATION_STALE", "installed implementation changed during verification replay")
        result = response["result"]
        retained = self._verification(result["verification_receipt"], arguments["context"], arguments["candidate"])
        if (result["candidate"] != retained["candidate"] or result["subject"] != retained["subject"]
                or result["checks"] != retained["checks"] or retained["subject"] != arguments["subject"]
                or retained["base_program"] != arguments["base_program"]
                or retained["validation_profile"] != arguments["validation_profile"]
                or [check["claim"] for check in retained["checks"]] != arguments["claims"]):
            reject("E_HIA_PROOF_SCOPE", "cached proof differs from the original subject or retained conclusion; rerun verification with a fresh request key", "verification")

    def _compile(self, program, kind, machine_plan, timeout_ms, *, foreign_buffer_exports=()):
        from .hia_program_native import emit_program_machine, compile_program_machine
        if timeout_ms <= 0:
            reject("E_HIA_BUDGET", "frozen context deadline expired before emission", "codegen")
        deadline = time.monotonic() + timeout_ms / 1000
        image = emit_program_machine(program, machine_plan=machine_plan, foreign_buffer_exports=foreign_buffer_exports)
        object_bytes = image.object_bytes
        if type(object_bytes) is not bytes:
            reject("E_HIA_RECEIPT_BINDING", "emission did not produce immutable object bytes", "codegen")
        commands = []
        with tempfile.TemporaryDirectory(prefix="build-", dir=self.store.root) as directory:
            output = Path(directory) / ("program.o" if kind == "object" else "program.so")
            result = compile_program_machine(image, program=program, output=output, kind=kind,
                linker="ld", command_log=commands, machine_plan=machine_plan, parent_death_guard=True,
                timeout_seconds=min(3600, max(0, deadline - time.monotonic())))
            data = output.read_bytes()
        result.pop("output", None)
        result["commands"] = commands
        if (result.get("object_sha256") != sha256(object_bytes).hexdigest()
                or result.get("core_sha256") != program.sha256
                or result.get("artifact_sha256") != sha256(data).hexdigest()
                or kind == "object" and data != object_bytes):
            reject("E_HIA_RECEIPT_BINDING", "native build metadata differs from the actual emitted bytes", "codegen")
        result["object_artifact"] = self.store.put(object_bytes, "build-object", {
            "schema": "hepta.hia.agent.build-object.v1", "core_sha256": program.sha256,
            "machine_plan_sha256": result["machine_plan_sha256"], "installation": self.identities})
        return data, result

    def _hia_emit(self, args):
        self._profile(args["backend_profile"], "backend")
        context = self._context(args["context"])
        program = self._program(args["candidate"])
        for ref in args["verification_receipts"]:
            self._verification(ref, args["context"], args["candidate"])
        codegen, plan = args["codegen"], None
        if codegen["kind"] == "canonical":
            self._profile(codegen["lowering_profile"], "lowering")
        else:
            self._profile(codegen["plan_profile"], "plan")
            plan, _ = self.store.get_json(codegen["plan"])
            validate(plan, PLAN_SCHEMA, "machine_plan")
            receipt = self._verification(codegen["verification_receipt"], args["context"], args["candidate"])
            expected_subject = {"kind": "agent_machine_plan", "backend_profile": args["backend_profile"],
                                "plan_profile": codegen["plan_profile"], "plan": codegen["plan"]}
            if receipt["subject"] != expected_subject or not any(c["claim"] == "lowering_refinement" and c["status"] == "proved" for c in receipt["checks"]):
                reject("E_HIA_PLAN_RECEIPT", "plan lacks an exact subject-bound qualified layout receipt", "codegen")
        exports = tuple(map(tuple, context.get("foreign_buffer_exports", [])))
        data, native_build = self._compile(program, args["output_kind"], plan, self._remaining_ms(context),
                                          **({"foreign_buffer_exports": exports} if exports else {}))
        metadata = {"context": args["context"], "candidate": args["candidate"],
            "core_sha256": program.sha256, "output_kind": args["output_kind"], "codegen": codegen,
            "machine_plan": plan, "installation": self.identities, "signatures": _signatures(program, exports),
            "foreign_buffer_exports": [list(pair) for pair in exports],
            "object_artifact": native_build["object_artifact"], "object_sha256": native_build["object_sha256"]}
        artifact = self.store.put(data, "native", metadata)
        receipt = self.store.json({"schema": "hepta.hia.agent.build.v1", **metadata,
            "native_artifact": artifact, "native_build": native_build,
            "backend_profile": args["backend_profile"], "target_profile": context["target_profile"],
            "verification_receipts": args["verification_receipts"]}, "build-receipt")
        return {"candidate": args["candidate"], "native_artifact": artifact, "build_receipt": receipt,
            "backend_profile": args["backend_profile"], "target_profile": context["target_profile"],
            "codegen_backend": "hia-direct", "llvm_codegen_used": False, "external_assembler_used": False,
            "linker_used": args["output_kind"] == "shared", "native_execution_observed": False, "adopted": False}

    def _native(self, ref, context=None):
        data, metadata = self.store.get(ref, kind="native")
        if metadata["installation"] != self.identities or context is not None and metadata["context"] != context:
            reject("E_HIA_RECEIPT_BINDING", "native artifact belongs to a different context or implementation")
        program = self._program(metadata["candidate"])
        retained_context = self._context(metadata["context"])
        exports = tuple(map(tuple, retained_context.get("foreign_buffer_exports", [])))
        if (metadata["core_sha256"] != program.sha256 or _signatures(program, exports) != metadata["signatures"]
                or metadata.get("foreign_buffer_exports", []) != [list(pair) for pair in exports]):
            reject("E_HIA_RECEIPT_BINDING", "native artifact's admitted Core identity differs")
        return data, metadata, program

    def _build_receipt(self, ref, context, artifact):
        return self._build_inputs(ref, context, artifact)[0]

    def _build_inputs(self, ref, context, artifact):
        """Capture and validate one immutable Core/object/final build observation."""
        record, _ = self.store.get_json(ref, kind="build-receipt")
        if (record["context"] != context or record["native_artifact"] != artifact or record["installation"] != self.identities
                or record.get("target_profile") != self.profiles["target"]
                or record.get("backend_profile") != self.profiles["backend"]):
            reject("E_HIA_RECEIPT_BINDING", "build receipt belongs to a different native subject")
        data, metadata, program = self._native(artifact, context)
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
        object_bytes, object_metadata = self.store.get(record["object_artifact"], kind="build-object")
        expected_metadata = {"schema": "hepta.hia.agent.build-object.v1", "core_sha256": program.sha256,
            "machine_plan_sha256": built.get("machine_plan_sha256"), "installation": self.identities}
        if (object_metadata != expected_metadata or sha256(object_bytes).hexdigest() != record["object_sha256"]
                or record["object_artifact"]["sha256"] != record["object_sha256"]
                or record["output_kind"] == "object" and object_bytes != data):
            reject("E_HIA_RECEIPT_BINDING", "retained object differs from its exact build binding")
        return record, data, object_bytes, program

    @staticmethod
    def _native_refinement_binding(subject, built, program, object_bytes, final_bytes):
        return {"candidate_core_sha256": program.sha256, "input_sha256": program.input_sha256,
            "native_artifact": subject["native_artifact"], "build_receipt": subject["build_receipt"],
            "object_artifact": built["object_artifact"], "object_sha256": sha256(object_bytes).hexdigest(),
            "final_image_sha256": sha256(final_bytes).hexdigest(), "output_kind": built["output_kind"],
            "entry_symbols": [fn["name"] for fn in program.as_dict()["functions"]],
            "foreign_buffer_exports": built["native_build"].get("foreign_buffer_exports")}

    def _independent_native_refinement(self, args, program, context):
        from .hia_safe_core import (ARTIFACT_PROFILE, ARTIFACT_OBLIGATIONS, SafeCoreRejected,
            _profile, _checker_source_identity, validate_safe_core_artifact)
        subject = args["subject"]
        built, final_bytes, object_bytes, retained = self._build_inputs(
            subject["build_receipt"], args["context"], subject["native_artifact"])
        if retained.sha256 != program.sha256:
            reject("E_HIA_RECEIPT_BINDING", "retained machine subject differs from the requested Core", "verification")
        identity = _checker_source_identity()
        evidence = {"method": SAFE_CORE_METHOD, "profile": ARTIFACT_PROFILE,
            "service_profile": SAFE_CORE_SERVICE_PROFILE,
            "artifact_binding": self._native_refinement_binding(subject, built, program, object_bytes, final_bytes),
            "source_identity": identity, "checker_sha256": digest(identity), "solver": None,
            "validation": None, "queries": [], "deadline_met": False}

        def finish(status, reason=None):
            evidence["outcome"] = status
            if reason is not None:
                evidence["reason"] = reason
            return status, SAFE_CORE_DOMAIN, evidence

        if built["output_kind"] != "shared" or built["native_build"].get("foreign_buffer_exports") != []:
            return finish("unsupported", "Agent machine validation admits final shared ELF with scalar entries only")
        try:
            _profile(program, foreign_buffer_exports=())
        except SafeCoreRejected as exc:
            return finish("unsupported", str(exc))
        remaining = min(60000, self._remaining_ms(context))
        if remaining < 100:
            return finish("unknown", "less than the minimum 100 ms remains in the frozen verification budget")
        status, reason = "unknown", None
        with tempfile.TemporaryDirectory(prefix="machine-proof-", dir=self.store.root) as directory:
            query_directory = Path(directory) / "queries"
            try:
                evidence["validation"] = validate_safe_core_artifact(program, object_bytes, final_bytes,
                    timeout_ms=remaining, query_directory=query_directory)
                status = "proved"
            except SafeCoreRejected as exc:
                evidence["validation"] = exc.validation
                counterexample = exc.counterexample
                violation_names = {name for name, expected in ARTIFACT_OBLIGATIONS if expected == "unsat"}
                if (type(counterexample) is dict and counterexample.get("obligation") in violation_names
                        and type(exc.validation) is dict and exc.validation.get("status") == "refuted"):
                    status = "refuted"
                    evidence["counterexample"] = counterexample
                reason = str(exc)
            except ValueError as exc:
                status, reason = "unsupported", str(exc)
            validation = evidence["validation"]
            if validation is not None:
                evidence["solver"] = validation["solver"]
            for path in sorted(query_directory.glob("*.smt2")):
                data = path.read_bytes()
                evidence["queries"].append({"name": path.name, "sha256": sha256(data).hexdigest(),
                    "artifact": self.store.put(data, "machine-validation-query")})
        evidence["deadline_met"] = self._remaining_ms(context) > 0
        if not evidence["deadline_met"]:
            status, reason = "unknown", "the frozen context deadline expired before proof publication"
        return finish(status, reason)

    def _check_native_refinement_evidence(self, evidence, subject, context, program):
        if subject.get("kind") != "native_artifact":
            reject("E_HIA_PROOF_SCOPE", "independent machine evidence requires its exact native subject", "verification")
        built, final_bytes, object_bytes, retained = self._build_inputs(
            subject["build_receipt"], context, subject["native_artifact"])
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
            data, _ = self.store.get(query["artifact"], kind="machine-validation-query")
            if (sha256(data).hexdigest() != query["sha256"]
                    or validation is not None and (query["sha256"] != reports[index].get("query_sha256")
                        or query["name"] != reports[index].get("query_file"))):
                reject("E_HIA_PROOF_SCOPE", "machine proof query bytes differ", "verification")

    def _required_claims(self, context, candidate_artifact, refs, baseline_core_sha=None):
        _data, native, _program = self._native(candidate_artifact, context["ref"])
        objective, _ = self.store.get_json(context["objective"])
        receipts = [self._verification(ref, context["ref"], native["candidate"]) for ref in refs]
        for claim in objective["required_claims"]:
            qualified = False
            for receipt in receipts:
                if not any(c["claim"] == claim and c["status"] == "proved" for c in receipt["checks"]):
                    continue
                subject = receipt["subject"]
                if claim == "encoding_check":
                    if subject["kind"] != "native_artifact" or subject["native_artifact"] != candidate_artifact:
                        continue
                    self._build_receipt(subject["build_receipt"], context["ref"], candidate_artifact)
                elif claim == "behavior_equivalence":
                    if receipt["base_core_sha256"] != baseline_core_sha:
                        continue
                elif claim == "lowering_refinement":
                    if subject["kind"] == "native_artifact":
                        if subject["native_artifact"] != candidate_artifact:
                            continue
                        self._build_receipt(subject["build_receipt"], context["ref"], candidate_artifact)
                    elif native["machine_plan"] is None or subject["kind"] != "agent_machine_plan" or subject["plan"] != native["codegen"]["plan"]:
                        continue
                qualified = True
            if not qualified:
                reject("E_HIA_CLAIM_REQUIRED", "missing exact proved acceptance claim: " + claim, "verification")
        return objective

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
        context_row = self.store.db.execute("SELECT created_ns FROM contexts WHERE id=?", (args["context"]["id"],)).fetchone()
        context_deadline = int(context_row["created_ns"]) + context["budget"]["max_total_wall_ms"] * 1_000_000

        def remaining_total_ms():
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
        runs, native_ns, native_started = {}, 0, time.monotonic_ns()
        owner = digest({"tool": "hia_evaluate", "key": args["request_key"]})
        with self.store.transaction():
            budget_row = self.store.db.execute("SELECT * FROM execution_budgets WHERE context_id=?", (args["context"]["id"],)).fetchone()
            if budget_row is None:
                reject("E_HIA_BUDGET", "context lacks an execution budget record", "execution")
            if budget_row["owner"] is not None:
                reject("E_HIA_BUDGET_BUSY", "context native budget has a live or uncertain owner; observe that operation", "execution", retry_action="stop")
            used_native_ns = int(budget_row["used_native_ns"])
            self.store.db.execute("UPDATE execution_budgets SET owner=? WHERE context_id=?", (owner, args["context"]["id"]))
        native_budget_ms = max(0, context["budget"]["max_native_wall_ms"] - used_native_ns // 1_000_000)
        for label, data, metadata in (("baseline", baseline_bytes, baseline_meta), ("candidate", candidate_bytes, candidate_meta)):
            runs[label] = {"normal": None, "traps": [], "total_native_ns": "0"}
            if not complete:
                continue

            def run(cases, warmup, repetitions):
                remaining = min(native_budget_ms - (time.monotonic_ns() - native_started) // 1_000_000,
                                remaining_total_ms())
                return run_native_batch(data, metadata["signatures"], cases,
                    warmup=int(warmup), repetitions=int(repetitions), timeout_ms=int(remaining),
                    memory_bytes=uint64(context["budget"]["max_memory_bytes"], "max_memory_bytes"))

            if normal:
                outcome = run([case for _, case in normal], workload["warmup_iterations"], workload["repetitions"])
                runs[label]["normal"] = outcome
                native_ns += int(outcome["wall_ns"])
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
                native_ns += int(outcome["wall_ns"])
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
        self.store.db.execute("UPDATE execution_budgets SET owner=NULL,used_native_ns=? WHERE context_id=? AND owner=?",
            (str(used_native_ns + native_ns), args["context"]["id"], owner))
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

    def _slot_snapshot(self, slot):
        row = self.store.db.execute("SELECT * FROM slots WHERE name=?", (slot,)).fetchone()
        if row is None:
            return {"target_slot": slot, "current": {"generation": "0", "epoch": "0"},
                    "active_artifact": None, "context": None, "in_flight_leases": 0,
                    "snapshot_is_adoption_authority": False}
        version = self.store.db.execute("SELECT artifact FROM versions WHERE slot=? AND generation=?",
                                        (slot, row["generation"])).fetchone()
        count = self.store.db.execute("SELECT COUNT(*) FROM leases WHERE slot=? AND active=1", (slot,)).fetchone()[0]
        return {"target_slot": slot, "current": {"generation": row["generation"], "epoch": row["epoch"]},
                "active_artifact": decode_data(version["artifact"]), "context": row["context_id"],
                "in_flight_leases": count, "snapshot_is_adoption_authority": False}

    def inspect_slot(self, target_slot):
        """Authorized local consumer observation; no user-derived authority."""
        return self._slot_snapshot(target_slot)

    def _conditional_slot(self, args):
        for name in ("generation", "epoch"):
            uint64(args["expected_current"][name], name)
        snapshot = self._slot_snapshot(args["target_slot"])
        if snapshot["current"] != args["expected_current"]:
            error = AgentRejected("E_HIA_GENERATION_STALE", "slot changed; read the retained current snapshot and choose a fresh conditional request",
                                  "adoption", retry_action="refresh_context")
            error.pending_slot_snapshot = snapshot
            raise error
        return snapshot

    def _hia_adopt(self, args):
        context = self._context(args["context"])
        evaluation, _ = self.store.get_json(args["evaluation_receipt"], kind="evaluation-receipt")
        if (evaluation["context"] != args["context"] or evaluation["candidate_artifact"] != args["candidate_artifact"]
                or evaluation["installation"] != self.identities):
            reject("E_HIA_RECEIPT_BINDING", "evaluation does not authorize this candidate/context", "adoption")
        self._build_receipt(evaluation["build_receipt"], args["context"], args["candidate_artifact"])
        objective = self._required_claims(context, args["candidate_artifact"], args["verification_receipts"], evaluation["baseline_core_sha256"])
        if (not evaluation["report_complete"] or not evaluation["planned_workload_complete"]
                or not evaluation["termination_confirmed"] or evaluation["outcome"] not in
                ({"improved", "unchanged"} if objective["allow_unchanged"] else {"improved"})):
            reject("E_HIA_EVALUATION_REQUIRED", "evaluation did not meet the frozen correctness/performance acceptance", "adoption")
        self.store.get(evaluation["measurements"], kind="measurements")
        self.store.get(evaluation["full_cost_ledger"], kind="cost-ledger")
        if objective.get("require_net_benefit", False):
            reject("E_HIA_COST_INCOMPLETE", "full model/discovery/adoption/future-use cost is not established by this prefix; net-benefit requirement cannot pass", "adoption")
        _data, metadata, _program = self._native(args["candidate_artifact"], args["context"])
        _baseline_data, baseline, _baseline_program = self._native(evaluation["baseline_artifact"], args["context"])
        if metadata["signatures"] != baseline["signatures"]:
            reject("E_HIA_ABI", "candidate and baseline are not ABI compatible", "adoption")
        snapshot = self._conditional_slot(args)
        abi = digest(metadata["signatures"])
        if snapshot["active_artifact"] is None:
            self.store.db.execute("INSERT INTO slots VALUES (?,?,?,?,?)",
                (args["target_slot"], args["context"]["id"], "0", "0", abi))
            self.store.db.execute("INSERT INTO versions VALUES (?,?,?)",
                (args["target_slot"], "0", wire(evaluation["baseline_artifact"]).decode()))
        else:
            current = self.store.db.execute("SELECT * FROM slots WHERE name=?", (args["target_slot"],)).fetchone()
            if current["abi_sha256"] != abi:
                reject("E_HIA_ABI", "candidate changes the live slot ABI", "adoption")
            active_data, _active_meta, _ = self._native(snapshot["active_artifact"])
            if sha256(active_data).hexdigest() != evaluation["baseline_artifact"]["sha256"]:
                reject("E_HIA_BASELINE", "evaluation baseline is not the currently active image", "adoption")
        generations = self.store.db.execute("SELECT generation FROM versions WHERE slot=?", (args["target_slot"],)).fetchall()
        generation = max(int(row["generation"]) for row in generations) + 1
        epoch = int(snapshot["current"]["epoch"]) + 1
        if max(generation, epoch) >= 1 << 64:
            reject("E_HIA_GENERATION_EXHAUSTED", "u64 generation or epoch space is exhausted", "adoption")
        current = {"generation": str(generation), "epoch": str(epoch)}
        self.store.db.execute("INSERT INTO versions VALUES (?,?,?)",
            (args["target_slot"], current["generation"], wire(args["candidate_artifact"]).decode()))
        self.store.db.execute("UPDATE slots SET generation=?,epoch=?,context_id=? WHERE name=?",
            (current["generation"], current["epoch"], args["context"]["id"], args["target_slot"]))
        receipt = self.store.json({"schema": "hepta.hia.agent.adoption.v1", "context": args["context"],
            "target_slot": args["target_slot"], "previous": snapshot["current"], "current": current,
            "active_artifact": args["candidate_artifact"], "retained_baseline": evaluation["baseline_artifact"],
            "evaluation_receipt": args["evaluation_receipt"], "verification_receipts": args["verification_receipts"],
            "future_calls_only": True, "in_flight_versions_retained": True,
            "consumer_api": "acquire_slot -> invoke_lease -> release_slot"}, "adoption-receipt")
        return {"target_slot": args["target_slot"], "previous": snapshot["current"], "current": current,
                "active_artifact": args["candidate_artifact"], "adoption_receipt": receipt, "future_calls_only": True}

    def _hia_rollback(self, args):
        uint64(args["retained_generation"], "retained_generation")
        snapshot = self._conditional_slot(args)
        if snapshot["active_artifact"] is None:
            reject("E_HIA_SLOT", "slot has no retained generation", "adoption")
        row = self.store.db.execute("SELECT artifact FROM versions WHERE slot=? AND generation=?",
                                    (args["target_slot"], args["retained_generation"])).fetchone()
        if row is None:
            reject("E_HIA_GENERATION", "requested generation is not retained", "adoption")
        artifact = decode_data(row["artifact"])
        _data, metadata, _program = self._native(artifact)
        current_row = self.store.db.execute("SELECT * FROM slots WHERE name=?", (args["target_slot"],)).fetchone()
        if digest(metadata["signatures"]) != current_row["abi_sha256"]:
            reject("E_HIA_ABI", "retained generation is not ABI compatible", "adoption")
        epoch = int(snapshot["current"]["epoch"]) + 1
        if epoch >= 1 << 64:
            reject("E_HIA_GENERATION_EXHAUSTED", "u64 epoch space is exhausted", "adoption")
        current = {"generation": args["retained_generation"], "epoch": str(epoch)}
        self.store.db.execute("UPDATE slots SET generation=?,epoch=?,context_id=? WHERE name=?",
            (current["generation"], current["epoch"], args["context"]["id"], args["target_slot"]))
        receipt = self.store.json({"schema": "hepta.hia.agent.rollback.v1", "context": args["context"],
            "target_slot": args["target_slot"], "previous": snapshot["current"], "current": current,
            "active_artifact": artifact, "reason": args["reason"], "future_calls_only": True,
            "past_effects_reversed": False, "in_flight_versions_retained": True}, "rollback-receipt")
        return {"target_slot": args["target_slot"], "previous": snapshot["current"], "current": current,
                "active_artifact": artifact, "rollback_receipt": receipt, "future_calls_only": True, "past_effects_reversed": False}

    def acquire_slot(self, target_slot):
        """Pin the observed active generation for a real future native call."""
        with self.store.transaction():
            snapshot = self._slot_snapshot(target_slot)
            if snapshot["active_artifact"] is None:
                reject("E_HIA_SLOT", "slot has no active generation")
            self._native(snapshot["active_artifact"])
            lease = {"id": "lease-" + uuid.uuid4().hex, "slot": target_slot,
                "generation": snapshot["current"]["generation"], "artifact": snapshot["active_artifact"]}
            self.store.db.execute("INSERT INTO leases VALUES (?,?,?,?,1)",
                (lease["id"], target_slot, lease["generation"], wire(lease["artifact"]).decode()))
            return lease

    def _lease(self, lease):
        keys(lease, ("id", "slot", "generation", "artifact"), label="generation lease")
        row = self.store.db.execute("SELECT * FROM leases WHERE id=?", (lease["id"],)).fetchone()
        if (row is None or row["active"] != 1 or row["slot"] != lease["slot"]
                or row["generation"] != lease["generation"] or decode_data(row["artifact"]) != lease["artifact"]):
            reject("E_HIA_LEASE", "lease is released, unknown or modified")
        return row

    def invoke_lease(self, lease, function, arguments):
        from .hia_agent_runner import run_native_batch
        from .hia_agent_buffers import validate_arguments
        self._lease(lease)
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

    def release_slot(self, lease):
        with self.store.transaction():
            self._lease(lease)
            self.store.db.execute("UPDATE leases SET active=0 WHERE id=?", (lease["id"],))
        return {"released": True, "generation": lease["generation"], "artifact_retained": True}
