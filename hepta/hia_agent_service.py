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
from types import MethodType
import platform
import signal
import tempfile
import time
import uuid

from .hia_native_delivery import (DeliveryRecord, NativeDeliveryUnknown,
    check_current as _delivery_check, delivery_lost as _delivery_lost,
    guarded as _delivery_guard)

from .hia_agent_contract import (VERSION, ROOT, COST_POLICY_SCHEMA, OBJECTIVE_SCHEMA,
    PLAN_SCHEMA, WORKLOAD_SCHEMA, catalog, installation_manifest, validate)
from .hia_agent_store import (AgentRejected, AgentStore, digest, keys, record_authority,
    reject, uint64, wire, decode_data, capture_path, _agent_resource_path)
from .hia_program import verify_program
from .hia_program_tools import decode_json
from .hia_sha256_native import payload_sha256
from .hia_worker_report_native import selected_json_equality, selected_json_inequality
from .hia_proof_contract import (PROOF_SCHEMA, PROVED_MEANING, proof_subject, proof_result,
    assumptions_document, proof_contract_description, SAFE_CORE_METHOD, SAFE_CORE_DOMAIN,
    SAFE_CORE_SERVICE_PROFILE)


def _now():
    return datetime.now(timezone.utc).isoformat()


def _retain_cost_ledger(store, ledger):
    """Publish already-encoded native records without serializing them again."""
    if type(ledger) is bytes:
        return store.put(ledger, 'cost-ledger')
    return store.json(ledger, 'cost-ledger')


def _owns_context_state(service):
    from .hia_agent_store import uses_native_store

    return (uses_native_store(service.store)
            or 'HEPTA_HIA_AGENT_IDENTITY_MANIFEST' in os.environ
            or 'HEPTA_HIA_AGENT_PAYLOAD_SCHEMA_MANIFEST' in os.environ)


def _reference_wall_window(created_ns, now_ns, total_ms):
    delta = created_ns + total_ms * 1_000_000 - now_ns
    return delta < 0, max(0, delta // 1_000_000)


def _build_input_bytes_differ(left, right):
    if 'HEPTA_HIA_AGENT_IDENTITY_MANIFEST' in os.environ:
        return not _exact_artifact_equal(left, right)
    return left != right


def _exact_artifact_equal(left: bytes, right: bytes) -> bool:
    from .hia_agent_store import _native_agent_identity

    policy = _native_agent_identity()
    return left == right if policy is None else policy.exact_bytes_equal(left, right)


def _build_input_digest(data: bytes) -> str:
    if ('HEPTA_HIA_SHA256_STREAM_MANIFEST' in os.environ
            or 'HEPTA_HIA_SHA256_MANIFEST' in os.environ):
        return payload_sha256(data).hex()
    return sha256(data).hexdigest()


def _reference_finite_function(function):
    from .hia_optimization import PURE

    eligible = len(function["blocks"]) <= 128 and sum(len(b["ops"]) for b in function["blocks"]) <= 4096
    if set(function["effects"]) - {"trap"} or any(
            op["op"] not in PURE for b in function["blocks"] for op in b["ops"]):
        eligible = False
    blocks = {b["id"]: b for b in function["blocks"]}
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

    return acyclic(function["entry"]) and eligible


def _signatures(program, foreign_buffer_exports=()):
    selected = os.environ.get('HEPTA_HIA_NATIVE_BUILD_ADMISSION_MANIFEST')
    if selected is not None:
        from .hia_native_build_admission_native import installed_native_build_admission, NativeBuildAdmissionFrame
        return NativeBuildAdmissionFrame(installed_native_build_admission(selected), 1,
                                         None, (program, foreign_buffer_exports)).finish()
    return _signatures_reference(program, foreign_buffer_exports)


def _signatures_reference(program, foreign_buffer_exports=()):
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


def _profile_documents(identities, catalog_sha256, root_count, roots_sha256):
    from .hia_program_native import TARGET, PROFILE, SUPPORTED_OPCODES, CORE_SCHEMAS, IMPORTS
    from .hia_safe_core import ARTIFACT_PROFILE, LIMITS
    common = {"implementation": identities, "catalog_sha256": catalog_sha256}
    return {
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
            "object_emission_external_tool": False, "shared_linker": "pinned HIA linker when selected; otherwise GNU ld",
            "native_resource_limits": "disposable child wall/CPU/address-space limits; no VM tick guarantee",
            "universal_backend_refinement_proved": False, "self_hosted": False},
        "artifact": {"schema": "hepta.hia.agent.artifact-profile.v1", "inline_utf8_characters": 65536,
            "max_path_bytes": 8 * 1024**2, "path_root_count": root_count,
            "path_roots_sha256": roots_sha256,
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


def _manifest_document(identities, catalog_sha256, profiles, profile_artifacts, resources):
    return {"schema": "hepta.hia.agent.manifest.v1",
        "status": "implemented_bounded_profiles", "catalog_sha256": catalog_sha256,
        "installation": identities, "profiles": profiles,
        "profile_manifests": profile_artifacts, "resources": resources,
        "cold_start": ["read assembly_grammar/core_language and an exact opcode catalog",
            "retain workload, objective and cost-policy JSON as artifacts", "freeze context using discovered profiles",
            "import or patch an explicit Core candidate", "verify requested claims for the exact subject",
            "emit using canonical lowering or a checked explicit machine plan", "verify actual encoding and, when admitted, independent native refinement",
            "evaluate baseline and candidate on the entire frozen workload", "adopt only with qualifying receipts and expected generation/epoch"],
        "execution_authority": "administrator-installed runtime provider, never supplied context",
        "cold_start_learning_or_net_benefit_proved": False,
        "consumer_api": "HIAAgentService.acquire_slot/invoke_lease/release_slot",
        "initial_slot": "expected 0/0 retains the evaluation baseline at generation 0; candidate starts generation 1",
        "unknown_external_costs": "null and incomplete, never inferred as zero"}


class HIAAgentService:
    _native_candidate_import = None

    def __init__(self, state_root, *, artifact_roots=(), native_store=None,
                 native_edit_query=None, native_candidate_import=None):
        from .hia_candidate_budget_native import selected_candidate_budget, NativeCandidateBudgetStore
        from .hia_slot_ledger_native import selected_slot_ledger, NativeSlotLedgerStore
        candidate_budget_image = selected_candidate_budget()
        slot_ledger_image = selected_slot_ledger()
        self.catalog, self.catalog_sha256 = catalog()
        self.tools = {t["name"]: t for t in self.catalog["tools"]}
        self._tool_roles = {name: index for index, name in enumerate(self.tools, 1)}
        self.identities = installation_manifest()
        self.store = AgentStore(state_root, native_store=native_store)
        self._native_edit_query = native_edit_query
        self._native_candidate_import = native_candidate_import
        self._candidate_budget = None
        self._slot_ledger = None
        try:
            self._candidate_budget = (NativeCandidateBudgetStore(self.store, candidate_budget_image)
                                      if candidate_budget_image is not None else None)
            self._slot_ledger = (NativeSlotLedgerStore(self.store, slot_ledger_image)
                                 if slot_ledger_image is not None else None)
            self.artifact_roots = tuple(Path(root).absolute().resolve(strict=True) for root in artifact_roots)
            if any(not root.is_dir() for root in self.artifact_roots):
                reject("E_HIA_PROFILE", "configured artifact roots must be directories")
            self._profiles()
        except BaseException as error:
            cleanups = ([self._candidate_budget.close] if self._candidate_budget is not None else [])
            for cleanup in [*cleanups, self.store.close]:
                try:
                    cleanup()
                except BaseException as failure:
                    error.add_note('service construction cleanup failed: ' + type(failure).__name__)
            raise

    def close(self):
        try:
            if self._candidate_budget is not None:
                self._candidate_budget.close()
        finally:
            self.store.close()

    def _profiles(self):
        selected = os.environ.get('HEPTA_HIA_AGENT_DISCOVERY_MANIFEST')
        if selected:
            from .hia_agent_discovery_native import installed_agent_discovery
            discovery = installed_agent_discovery(selected)
            registry_bytes = discovery.registry()
        else:
            from .hia_schema import schema_registry
            registry_bytes = wire(schema_registry())
        root_count = len(self.artifact_roots)
        roots_sha256 = digest([str(root) for root in self.artifact_roots])
        if selected:
            bodies = discovery.profile_bodies(self.identities, self.catalog_sha256, root_count, roots_sha256)
        else:
            reference = _profile_documents(self.identities, self.catalog_sha256, root_count, roots_sha256)
            bodies = {name: wire(body) for name, body in reference.items()}
        self.profiles, self.profile_artifacts = {}, {}
        for name, body in bodies.items():
            ref, artifact = self.store.profile_bytes("hia-" + name + "-v1", body)
            self.profiles[name], self.profile_artifacts[name] = ref, artifact
        self.resources = {"schema_registry": self.store.put(registry_bytes, "discovery")}
        if selected:
            resource_bodies = discovery.resources()
            macro_policy = discovery.macro_policy(self.identities)
        else:
            from .hia_agent_macro_discovery import macro_policy_guidance
            resource_bodies = {name: wire(body) for name, body in self._reference_resource_documents().items()}
            macro_policy = wire(macro_policy_guidance(self.identities))
        self.resources.update((name, self.store.put(body, "discovery")) for name, body in resource_bodies.items())
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
        self.resources["macro_policy"] = self.store.put(macro_policy, "discovery")
        if selected:
            body = discovery.manifest(self.identities, self.catalog_sha256, self.profiles,
                                      self.profile_artifacts, self.resources)
        else:
            body = wire(_manifest_document(self.identities, self.catalog_sha256, self.profiles,
                                           self.profile_artifacts, self.resources))
        self.manifest = self.store.put(body, "discovery")

    @staticmethod
    def _reference_resource_documents():
        diagnostics = {"schema": "hepta.hia.agent.diagnostics.v1",
            "phases": ["admission", "context", "verification", "codegen", "execution", "adoption"],
            "codes": {"E_HIA_SCHEMA": "repair the named input field", "E_HIA_CONTEXT_STALE": "rediscover installed source and create a new context",
                "E_HIA_REQUEST_CONFLICT": "same key belongs to different arguments", "E_HIA_REQUEST_UNKNOWN": "observe the original runtime job; never relaunch",
                "E_HIA_ARTIFACT_IDENTITY": "use the complete issued reference", "E_HIA_MACHINE_PLAN": "read plan_schema and supply only checked Core-bound machine choices",
                "E_HIA_CLAIM_REQUIRED": "requested acceptance proof has no exact qualifying retained receipt",
                "E_HIA_PROOF_SCOPE": "rerun verification with a fresh request key; proof scope or retained checker conclusion is missing or differs",
                "E_HIA_GENERATION_STALE": "inspect current slot through the authorized consumer; use a fresh conditional request"}}
        return {"workload_schema": WORKLOAD_SCHEMA, "objective_schema": OBJECTIVE_SCHEMA,
                "cost_policy_schema": COST_POLICY_SCHEMA, "plan_schema": PLAN_SCHEMA,
                "proof_contract": proof_contract_description(),
                "examples": HIAAgentService._examples(), "diagnostics": diagnostics}

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
        return {"contract_version": VERSION, "request_id": request_id, "status": "rejected",
                "error": self._error_details(exc)}

    def _error_details(self, exc):
        code = getattr(exc, "code", "E_HIA_REJECTED")
        if type(code) is not str:
            code = "E_HIA_REJECTED"
        details = getattr(exc, "details_artifact", None)
        if getattr(exc, "pending_slot_snapshot", None) is not None:
            # A failed CAS rolls back its effect transaction first. Publish the
            # diagnostic afterwards so its issued reference remains readable.
            details = self.store.json(exc.pending_slot_snapshot, "slot-snapshot")
        return {"code": code[:128], "phase": getattr(exc, "phase", "admission"),
                "message": str(exc)[:4096] or type(exc).__name__,
                "retry_action": getattr(exc, "retry_action", "correct_input"),
                "details_artifact": details}

    def call(self, tool, arguments):
        from .hia_program import native_verified_program_scope

        selected = os.environ.get('HEPTA_HIA_AGENT_JOURNAL_MANIFEST')
        if selected == '':
            raise ValueError('Agent journal selector must not be empty')
        importer = self._native_candidate_import
        recheck = None if importer is None else importer.recheck_for_request()
        delivery = DeliveryRecord(self)
        try:
            with delivery.foreign(observation=False), native_verified_program_scope(recheck):
                if selected:
                    from .hia_agent_journal_native import call_with_native_journal
                    result = call_with_native_journal(self, tool, arguments, selected)
                else:
                    result = self._reference_call(tool, arguments)
                delivery.check()
                return result
        except BaseException as error:
            delivery.failed(error)
            domain_errors = (ValueError, TypeError, OSError, OverflowError, RecursionError, self.store.database_error)
            if isinstance(error, domain_errors):
                delivery.propagate(error, NativeDeliveryUnknown, domain_errors)
            raise
        finally:
            delivery.retire()

    def _reference_call(self, tool, arguments):
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
                    previous = self.store.journal_lookup(key)
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
                    self.store.journal_reserve(key, request_digest, tool, str(time.time_ns()))
                    reserved = True
            self._validate_tool_arguments(tool, arguments)
            if tool != "hia_describe" and arguments["catalog_sha256"] != self.catalog_sha256:
                reject("E_HIA_CATALOG_STALE", "tool catalog digest differs from installed catalog")
            if installation_manifest() != self.identities:
                reject("E_HIA_IMPLEMENTATION_STALE", "installed implementation changed during this service session")
            if "context" in arguments:
                context = self._context(arguments["context"])
                _delivery_check()
                context_id = arguments["context"]["id"]
                if tool not in {"hia_inspect", "hia_rollback"}:
                    self._budget(context, candidate=tool == "hia_candidate")
                    _delivery_check()
            # Slot effect and exact response journal commit together. A crash
            # cannot leave a changed slot with a replayable uncommitted result.
            if tool in {"hia_adopt", "hia_rollback"}:
                with self.store.transaction():
                    result = getattr(self, "_" + tool)(arguments)
                    _delivery_check()
                    response = {"contract_version": VERSION, "request_id": request_id,
                                "status": "completed", "result": result}
                    self._validate_tool_response(tool, response)
                    if reserved:
                        self.store.journal_complete(*_delivery_guard((key, wire(response).decode())))
                        reserved = False
            else:
                result = getattr(self, "_" + tool)(arguments)
                _delivery_check()
                response = {"contract_version": VERSION, "request_id": request_id,
                            "status": "completed", "result": result}
                self._validate_tool_response(tool, response)
        except (ValueError, TypeError, OSError, OverflowError, RecursionError, self.store.database_error) as exc:
            _delivery_check()
            response = self._error(request_id, exc)
        finally:
            if response is not None and not _delivery_lost():
                # Preserve every attempted request, including malformed, slower,
                # timed-out and rejected candidates; exact replay costs no effect.
                self.store.journal_cost(*_delivery_guard((context_id, str(tool), request_id, str(time.monotonic_ns() - started),
                    response["status"], wire({"error": response.get("error"), "replayed": False}).decode())))
                if reserved:
                    self.store.journal_complete(*_delivery_guard((key, wire(response).decode())))
        return response

    def _validate_tool_arguments(self, tool, arguments):
        schema = self.tools[tool]['inputSchema']
        selected = os.environ.get('HEPTA_HIA_AGENT_SCHEMA_MANIFEST')
        if selected is None:
            validate(arguments, schema)
            return
        from .hia_agent_schema_native import installed_agent_schema
        if not installed_agent_schema(selected).accepts(
                arguments, self._tool_roles[tool], self.catalog_sha256):
            # The HIA decision is final. The reference walks a refused value
            # only to preserve the established human-readable field diagnostic.
            validate(arguments, schema)
            raise ValueError('native Agent input schema disagrees with the catalog')

    def _validate_tool_response(self, tool, response, label='result'):
        schema = self.tools[tool]['outputSchema']
        selector = ('HEPTA_HIA_AGENT_VERIFY_RESPONSE_SCHEMA_MANIFEST' if tool == 'hia_verify'
                    else 'HEPTA_HIA_AGENT_RESPONSE_SCHEMA_MANIFEST')
        selected = os.environ.get(selector)
        if selected is None:
            validate(response, schema, label)
            return
        if tool == 'hia_verify':
            from .hia_agent_verify_response_schema_native import (
                installed_agent_verify_response_schema as load)
        else:
            from .hia_agent_response_schema_native import installed_agent_response_schema as load
        if not load(selected).accepts(response, self._tool_roles[tool], self.catalog_sha256):
            validate(response, schema, label)
            raise ValueError('native Agent output schema disagrees with the catalog')

    def _validate_payload(self, value, raw, schema, label, role):
        if schema is PLAN_SCHEMA:
            from .hia_agent_plan_schema_native import SELECTOR, installed_agent_plan_schema as load
        else:
            from .hia_agent_payload_schema_native import SELECTOR, installed_agent_payload_schema as load

        selected = os.environ.get(SELECTOR)
        if selected is None:
            validate(value, schema, label)
        elif not load(selected).accepts_wire(raw, role, self.catalog_sha256):
            # Preserve the established field diagnostic on native refusal.
            validate(value, schema, label)
            raise ValueError('native Agent payload schema disagrees with the contract')

    def _read_machine_plan(self, ref):
        from .hia_agent_plan_schema_native import PLAN_ROLE

        plan, _, raw = self.store.get_json_with_wire(ref)
        self._validate_payload(plan, raw, PLAN_SCHEMA, "machine_plan", PLAN_ROLE)
        return plan

    def _profile(self, ref, name):
        return self.store.check_profile(ref, self.profiles[name])

    def _program(self, ref):
        data, _ = self.store.get(ref)
        return self._admit_retained_program(data)

    def _admit_retained_program(self, data):
        if self._native_candidate_import is None:
            return self._reference_import(data, 'core-json')
        program = self._native_candidate_import.retained_program(data)
        if program is None:
            self._reference_import(data, 'core-json')
            raise ValueError('native Agent retained-program refusal disagrees with hosted admission')
        return program

    def _context(self, ref):
        from .hia_service_context_selection import run_service_context, UNSELECTED
        result = run_service_context(2, self, ref)
        if result is UNSELECTED:
            if _owns_context_state(self):
                return self._context_owned(ref)
            return _NATIVE_SERVICE_CONTEXT_LOOKUP_REFERENCE(self, ref)
        return result

    def _context_reference(self, ref):
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

    def _context_owned(self, ref):
        keys(ref, ("id", "sha256"), label="context reference")
        row = self.store.context_lookup(ref["id"])
        stored = None if row is None else (row["id"], row["sha256"], "")
        if record_authority((ref["id"], ref["sha256"], ""), stored):
            reject("E_HIA_CONTEXT_IDENTITY", "context is not a retained server record", "context")
        context, _ = self.store.get_json(decode_data(row["artifact"]), kind="context")
        equal = selected_json_equality()
        if not equal((context["installation"], context["catalog_sha256"]),
                     (self.identities, self.catalog_sha256)):
            reject("E_HIA_CONTEXT_STALE", "context binds a different installed implementation", "context")
        for name in ("compiler", "target"):
            self._profile(context[name + "_profile"], name)
        context["ref"] = ref
        return context

    def _budget(self, context, *, candidate=False):
        from .hia_service_context_selection import run_service_context, UNSELECTED
        result = run_service_context(3, self, context, candidate=candidate)
        if result is UNSELECTED:
            if _owns_context_state(self):
                return self._budget_owned(context, candidate=candidate)
            return _NATIVE_SERVICE_CONTEXT_BUDGET_REFERENCE(self, context, candidate=candidate)
        return result

    def _budget_reference(self, context, *, candidate=False):
        row = self.store.db.execute("SELECT * FROM contexts WHERE id=?", (context["ref"]["id"],)).fetchone()
        limits = context["budget"]
        if time.time_ns() - int(row["created_ns"]) > limits["max_total_wall_ms"] * 1_000_000:
            reject("E_HIA_BUDGET", "context total wall budget has expired", "context")
        if candidate:
            self._consume_attempt(context)

    def _budget_owned(self, context, *, candidate=False):
        expired, _ = self._wall_window(context)
        if expired:
            reject("E_HIA_BUDGET", "context total wall budget has expired", "context")
        if candidate:
            self._consume_attempt(context)

    def _consume_attempt(self, context):
        if self._candidate_budget is not None:
            return self._candidate_budget.consume(context['ref']['id'], context['budget']['max_candidates'])
        return self._reference_consume_attempt(context)

    def _reference_consume_attempt(self, context):
        changed = self.store.db.execute("UPDATE contexts SET attempts=attempts+1 WHERE id=? AND attempts<?",
            (context["ref"]["id"], context['budget']['max_candidates'])).rowcount
        if changed != 1:
            reject("E_HIA_BUDGET", "candidate attempt budget exhausted", "context")

    def _remaining_ms(self, context):
        from .hia_service_context_selection import run_service_context, UNSELECTED
        result = run_service_context(4, self, context)
        if result is UNSELECTED:
            if _owns_context_state(self):
                return self._remaining_ms_owned(context)
            return _NATIVE_SERVICE_CONTEXT_REMAINING_REFERENCE(self, context)
        return result

    def _remaining_ms_reference(self, context):
        row = self.store.db.execute("SELECT created_ns FROM contexts WHERE id=?", (context["ref"]["id"],)).fetchone()
        deadline = int(row["created_ns"]) + context["budget"]["max_total_wall_ms"] * 1_000_000
        return max(0, (deadline - time.time_ns()) // 1_000_000)

    def _remaining_ms_owned(self, context):
        return self._wall_window(context)[1]

    def _wall_window(self, context, *, created_ns=None):
        from .hia_agent_store import _native_agent_identity

        if created_ns is None:
            created_ns = self.store.context_created_ns(context["ref"]["id"])
        now_ns = time.time_ns()
        total_ms = context["budget"]["max_total_wall_ms"]
        native = _native_agent_identity()
        if native is not None:
            return native.wall_window(created_ns, now_ns, total_ms)
        return _reference_wall_window(created_ns, now_ns, total_ms)

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

    def _hia_describe_with_components(self, args):
        from .hia_agent_describe_answer_native import (
            SELECTOR as answer_selector, installed_agent_describe_answer,
        )
        selected = os.environ.get('HEPTA_HIA_AGENT_DISCOVERY_MANIFEST')
        answer = os.environ.get(answer_selector)
        if answer is not None and not selected:
            raise ValueError('HIA discovery answer requires the native discovery plan')
        if selected:
            from .hia_agent_discovery_native import RESOURCE_ROLES, installed_agent_discovery
            language_schema, language, roles = installed_agent_discovery(selected).plan(
                args, self.profiles['backend']['id'])
            profile, language_ref = self.store.profile_bytes(language_schema, language)

            def reference(role):
                owner, name = role
                if owner is None:
                    return language_ref
                value = getattr(self, owner)
                return value if name is None else value[name]

            if answer is not None:
                return installed_agent_describe_answer(answer).render(
                    self.catalog_sha256, self.manifest, profile, self.profiles['backend'],
                    self.profiles['artifact'], roles, [reference(role) for role in RESOURCE_ROLES])
            resources = [reference(RESOURCE_ROLES[role]) for role in roles]
        else:
            profile, resources = self._reference_describe(args)
        return {"catalog_sha256": self.catalog_sha256, "manifest": self.manifest,
            "language_catalogs": [profile], "backend_profiles": [self.profiles["backend"]],
            "artifact_profiles": [self.profiles["artifact"]], "resources": resources, "next_cursor": None}

    def _reference_describe(self, args):
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
        return profile, resources

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

    def _hia_artifact_with_selected_components(self, args):
        from .hia_agent_store import _native_agent_identity

        self._profile(args["artifact_profile"], "artifact")
        source = args["source"]
        native = _native_agent_identity()
        if native is None:
            return self._reference_artifact(source)
        data, limit = native.artifact_input(source)
        if limit is None:
            ref, size = self.store.put(data, "input"), len(data)
        else:
            ref, size = self.store.capture(source["path"], self.artifact_roots,
                                           limit, source["expected_sha256"])
        return native.artifact_receipt(ref, size)

    def _reference_artifact(self, source):
        if source["kind"] == "utf8":
            data = source["text"].encode("utf-8")
            ref, size = self.store.put(data, "input"), len(data)
        else:
            store = self.store
            try:
                capture = store.capture
            except AttributeError:
                data = capture_path(source["path"], self.artifact_roots, int(source["max_bytes"]))
                expected = source["expected_sha256"]
                if expected is not None and expected != sha256(data).hexdigest():
                    reject("E_HIA_ARTIFACT_CHANGED", "captured bytes differ from the expected digest")
                ref, size = store.put(data, "input"), len(data)
            else:
                ref, size = capture(source["path"], self.artifact_roots,
                                    int(source["max_bytes"]), source["expected_sha256"])
        return {"artifact": ref, "byte_length": str(size), "content_admitted_as_program": False,
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

    def _hia_read_with_components(self, args):
        from functools import partial
        from .hia_agent_store import _native_agent_identity, uses_native_store
        from .hia_agent_read_page_native import SELECTOR, capture_retained_page, installed_agent_read_page
        from .hia_native_helpers import pinned_agent_read_page_executable

        ref = args["artifact"]
        executable = pinned_agent_read_page_executable()
        if executable is not None and uses_native_store(self.store):
            pager = installed_agent_read_page(os.environ[SELECTOR])
            from .hia_agent_read_request_native import SELECTOR as PLAN_SELECTOR, installed_agent_read_request
            selected_plan = os.environ.get(PLAN_SELECTOR)
            planner = installed_agent_read_request(selected_plan) if selected_plan is not None else None
            plan = planner.prepare(args, self.catalog_sha256) if planner is not None else None
            if plan is None:
                admit_record = partial(pager.admit_retained_artifact, executable=executable)
            else:
                admit_record = partial(pager.admit_planned_artifact, executable=executable, plan=plan)
            with capture_retained_page(self.store, ref, native_record=admit_record,
                                       encoded=plan.reference if plan is not None else None) as captured:
                if plan is None:
                    cursor, row = pager.lookup_captured_cursor(
                        self.store.db, args.get("cursor"), executable)
                else:
                    cursor = plan.cursor
                    row = self.store.db.cursor_lookup_frame(plan.cursor_query) if cursor is not None else None
                prelude = planner.page_prelude(plan, row) if planner is not None else None
                result, retained = pager.read_captured_bound_page(
                    captured, ref, cursor, row, args.get("max_bytes"), executable, prelude=prelude)
            if retained:
                self.store.db.cursor_retain_frame(retained)
            return result
        elif executable is not None and self.store._artifact_code is not None:
            with capture_retained_page(self.store, ref) as captured:
                native = _native_agent_identity()
                if native is None:
                    offset, limit = self._read_window(args, ref)
                else:
                    cursor_requested = "cursor" in args
                    row = self.store.cursor_lookup(args["cursor"]) if cursor_requested else None
                    offset, limit = native.read_window(
                        ref, cursor_requested=cursor_requested, row=row, max_bytes=args.get("max_bytes"))
                encoding, content, next_offset, next_cursor = installed_agent_read_page(
                    os.environ[SELECTOR]).read_captured_page(captured, offset, limit, executable)
        else:
            data, _ = self.store.get(ref)
            offset, limit = self._read_window(args, ref)
            selected = os.environ.get(SELECTOR)
            if selected:
                encoding, content, next_offset, next_cursor = installed_agent_read_page(
                    selected).read_issued_page(data, offset, limit, ref)
            else:
                encoding, content, next_offset = self._reference_read_page(data, offset, limit)
                next_cursor = ("page-" + digest({"artifact": ref, "offset": next_offset})
                               if next_offset is not None else None)
        if next_offset is not None:
            from .hia_agent_read_page_native import retain_page_cursor
            retain_page_cursor(self.store, next_cursor, ref, next_offset)
        native = _native_agent_identity()
        if native is not None:
            return native.page_receipt(ref, content, encoding, next_cursor)
        return {"artifact": ref, "encoding": encoding, "content": content, "next_cursor": next_cursor}

    def _read_window(self, args, ref):
        offset = 0
        if "cursor" in args:
            from .hia_agent_read_page_native import lookup_page_cursor
            row = lookup_page_cursor(self.store, args)
            stored = None if row is None else (row["artifact_id"], row["sha256"], "")
            if record_authority((ref["id"], ref["sha256"], ""), stored):
                reject("E_HIA_CURSOR", "cursor is not bound to this exact artifact")
            offset = row["offset"]
        return offset, int(args.get("max_bytes", 65536))

    @staticmethod
    def _reference_read_page(data, offset, limit):
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
        next_offset = offset + len(chunk)
        return encoding, content, next_offset if next_offset < len(data) else None

    def _hia_context(self, args):
        from .hia_service_context_selection import run_service_context, UNSELECTED
        result = run_service_context(1, self, args)
        if result is UNSELECTED:
            if _owns_context_state(self):
                return self._hia_context_owned(args)
            return _NATIVE_SERVICE_CONTEXT_FREEZE_REFERENCE(self, args)
        return result

    def _hia_context_reference(self, args):
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
        self.store.execution_budgets.create(context["id"])
        return {"context": context, "manifest": manifest, "sampled_at": sampled,
            "compiler_profile": args["compiler_profile"], "target_profile": args["target_profile"],
            "resource_reservation_held": False, "context_is_execution_authority": False}

    def _hia_context_owned(self, args):
        from .hia_agent_buffers import export_manifest, buffer_size, MAX_WORKLOAD_BUFFER_BYTES
        from .hia_agent_payload_schema_native import COST_POLICY_ROLE, OBJECTIVE_ROLE, WORKLOAD_ROLE
        from .hia_agent_store import _native_agent_identity

        context_policy = _native_agent_identity()
        self._profile(args["compiler_profile"], "compiler")
        self._profile(args["target_profile"], "target")
        workload, _, workload_raw = self.store.get_json_with_wire(args["workload"])
        objective, _, objective_raw = self.store.get_json_with_wire(args["objective"])
        cost_policy, _, cost_policy_raw = self.store.get_json_with_wire(args["budget"]["cost_policy"])
        self._validate_payload(workload, workload_raw, WORKLOAD_SCHEMA, "workload", WORKLOAD_ROLE)
        foreign_buffer_exports = (export_manifest(workload) if context_policy is None
                                  else context_policy.workload_exports(workload))
        snapshot_sizes = (buffer_size(value) for case in workload["cases"]
                          for value in case["arguments"] if type(value) is dict)
        if context_policy is not None:
            context_policy.context_snapshots(snapshot_sizes)
        elif sum(snapshot_sizes) > MAX_WORKLOAD_BUFFER_BYTES:
            reject("E_HIA_BUFFER_BUDGET", "frozen workload exceeds 32 MiB of external byte snapshots", "context")
        self._validate_payload(objective, objective_raw, OBJECTIVE_SCHEMA, "objective", OBJECTIVE_ROLE)
        self._validate_payload(cost_policy, cost_policy_raw, COST_POLICY_SCHEMA, "cost_policy", COST_POLICY_ROLE)
        for name in ("max_candidates", "max_model_tokens", "max_total_wall_ms", "max_native_wall_ms"):
            args["budget"][name] = int(args["budget"][name])
        uint64(cost_policy["expected_invocations"], "expected_invocations")
        memory = uint64(args["budget"]["max_memory_bytes"], "max_memory_bytes")
        if context_policy is not None:
            context_policy.context_limits(memory, args["budget"]["max_total_wall_ms"],
                                          args["budget"]["max_native_wall_ms"])
        else:
            if not 64 * 1024**2 <= memory <= 4 * 1024**3:
                reject("E_HIA_BUDGET", "execution profile admits 64 MiB..4 GiB address-space budgets", "context")
            if args["budget"]["max_native_wall_ms"] > args["budget"]["max_total_wall_ms"]:
                reject("E_HIA_BUDGET", "native wall budget exceeds total wall budget", "context")
        for name in ("model_wall_ns", "discovery_wall_ns"):
            if cost_policy["external_costs"][name] is not None:
                uint64(cost_policy["external_costs"][name], name)
        if context_policy is not None:
            context_policy.context_cost(args["budget"]["max_model_tokens"], cost_policy["external_costs"],
                                        cost_policy["external_costs_complete"])
        else:
            tokens = cost_policy["external_costs"]["model_tokens"]
            if tokens is not None and tokens > args["budget"]["max_model_tokens"]:
                reject("E_HIA_BUDGET", "reported model tokens exceed the frozen budget", "context")
            if cost_policy["external_costs_complete"] and any(v is None for v in cost_policy["external_costs"].values()):
                reject("E_HIA_COST", "complete external cost report cannot contain unknown fields", "context")
        baseline_sha = None
        if args["baseline_program"] is not None:
            baseline_sha = self._program(args["baseline_program"]).sha256
        sampled = _now()
        target = platform.system(), platform.machine(), os.cpu_count()
        exports = [list(pair) for pair in foreign_buffer_exports]
        if context_policy is None:
            manifest = self._reference_context_manifest(args, baseline_sha, exports, sampled, target)
            context_id = "ctx-" + uuid.uuid4().hex
        else:
            payload = context_policy.context_manifest(
                args, self.catalog_sha256, self.identities, baseline_sha, exports, sampled, target)
            manifest = self.store.put(payload, "context")
            context_id = context_policy.context_id(uuid.uuid4().bytes)
        context = {"id": context_id, "sha256": manifest["sha256"]}
        self.store.execution_budgets.create(context_id, context_record=(
            context["sha256"], wire(manifest).decode(), str(time.time_ns())))
        if context_policy is not None:
            return context_policy.context_receipt(args, context, manifest, sampled)
        return self._reference_context_receipt(args, context, manifest, sampled)

    def _reference_context_manifest(self, args, baseline_sha, exports, sampled, target):
        system, machine, cpu_count = target
        return self.store.json({"schema": "hepta.hia.agent.context.v1", "catalog_sha256": self.catalog_sha256,
            "installation": self.identities, "compiler_profile": args["compiler_profile"],
            "target_profile": args["target_profile"], "baseline_program": args["baseline_program"],
            "baseline_core_sha256": baseline_sha, "workload": args["workload"], "objective": args["objective"],
            "foreign_buffer_exports": exports,
            "budget": args["budget"], "sampled_at": sampled,
            "target_observation": {"system": system, "machine": machine,
                "cpu_count": cpu_count, "observation_only": True},
            "resource_reservation_held": False, "context_is_execution_authority": False}, "context")

    @staticmethod
    def _reference_context_receipt(args, context, manifest, sampled):
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

    def _hia_inspect_with_components(self, args):
        from .hia_program_tools import inspect_program
        from .hia_edit_query import prepare_edit
        from .hia_program_native import emit_program_machine
        program = self._program(args["program"])
        selector = args.get("selector", {})
        request_manifest = os.environ.get('HEPTA_HIA_INSPECTION_REQUEST_MANIFEST')
        if request_manifest is not None:
            from .hia_worker_inspection_request_native import installed_worker_inspection_request
            view, native_selector = installed_worker_inspection_request(request_manifest).project(
                args, self.catalog_sha256)
        else:
            if "cursor" in args:
                reject("E_HIA_CURSOR", "inspection returns an immutable artifact; paginate it through hia_read")
            view, native_selector = args["view"], None
        query, view_bytes = None, None
        selected = os.environ.get('HEPTA_HIA_AGENT_INSPECTION_MANIFEST')
        if selected and view in ("summary", "function", "block"):
            from .hia_agent_inspection_native import installed_agent_inspection
            image = installed_agent_inspection(selected)
            view_bytes = (image.summary(program) if view == "summary"
                          else image.view(program.canonical_bytes, view, selector))
        elif view == "summary":
            result = inspect_program(program)
        elif view == "lowering":
            context = self._context(args["context"])
            image = emit_program_machine(program,
                foreign_buffer_exports=tuple(map(tuple, context.get("foreign_buffer_exports", []))))
            profile = self.profiles["lowering"]
            object_ref = self.store.put(image.object_bytes, "lowering-object")
            if selected:
                from .hia_agent_inspection_native import installed_agent_inspection
                view_bytes = installed_agent_inspection(selected).lowering(image, profile, object_ref)
            else:
                result = {"schema": "hepta.hia.agent.lowering-view.v1", "core_sha256": program.sha256,
                    "text_sha256": payload_sha256(image.text_bytes).hex(), "object_sha256": image.sha256,
                    "text_bytes": str(len(image.text_bytes)), "frames": dict(image.function_frames),
                    "lowering_profile": profile, "optimizer_used": False, "object": object_ref}
        elif view == "dependencies":
            if native_selector is not None:
                site = native_selector
            else:
                if not all(k in selector for k in ("function", "block", "output")):
                    reject("E_HIA_SELECTOR", "dependencies require function, block and output")
                site = {name: selector[name] for name in ("function", "block", "output")}
            if self._native_edit_query is not None:
                view_bytes = self._native_edit_query.prepare(program, site)
                if view_bytes is None:
                    # A transport/extent refusal lacks a domain diagnostic.
                    # Retain the old error, but never accept a native refusal.
                    prepare_edit(program, **site, fields=["op", "args", "attrs"])
                    raise ValueError('native Agent dependency refusal disagrees with admitted Core')
                query = self.store.put(view_bytes, "edit-query")
            else:
                result = prepare_edit(program, **site, fields=["op", "args", "attrs"])
                query = self.store.json(result, "edit-query")
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
        artifact = (self.store.put(view_bytes, "inspection") if view_bytes is not None
                    else self.store.json(result, "inspection"))
        return {"program": args["program"], "view_artifact": artifact,
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

    def _hia_candidate_with_components(self, args):
        from .hia_agent_store import _native_agent_identity
        from .hia_program_tools import apply_program_patch
        change, base, native_payloads = args["change"], None, None
        if change["kind"] == "import":
            data, _ = self.store.get(change["source"])
            if self._native_candidate_import is not None:
                native_payloads = self._native_candidate_import.admit(data, change["format"])
                if native_payloads is None:
                    # Keep the existing specific diagnostic without allowing a
                    # hosted candidate to override a selected native refusal.
                    self._reference_import(data, change["format"])
                    raise ValueError('native Agent candidate refusal disagrees with hosted admission')
            else:
                program = self._reference_import(data, change["format"])
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
        native = _native_agent_identity()
        if native is not None:
            return native.candidate_receipt(base, candidate, diagnostic_artifact)
        return {"candidate": candidate, "base_program": base,
            "diagnostics": diagnostic_artifact, "core_admitted": True,
            "behavior_equivalence_proved": False, "adopted": False}

    @staticmethod
    def _reference_import(data, source_format):
        if source_format == "hia-asm.v1":
            from .hia_agent_assembly import assemble_program
            return assemble_program(data)
        return verify_program(decode_json(data))

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

    def _behavior_equivalence_with_components(self, original, revised, timeout_ms):
        """A conservative proof decision, separate from workload testing."""
        from .hia_agent_store import _native_agent_identity
        from .hia_optimization import DEFAULT_POLICY, NATIVE_CORE_SCHEMA, verify_optimization
        from .hia_program import WIDTHS, integer_range
        from .hia_scalar_reference_native import selected_scalar_reference
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
        policy = _native_agent_identity()
        eligible = _reference_finite_function if policy is None else policy.finite_function
        for document in (left, right):
            for fn in document["functions"]:
                if not eligible(fn):
                    finite = False
        interface = lambda d: {fn["name"]: {k: fn[k] for k in ("params", "returns", "effects")} for fn in d["functions"]}
        if interface(left) != interface(right):
            finite = False
        domains, total = {}, 0
        if finite:
            for name, signature in signatures.items():
                parameters = signature["params"]
                if policy is not None:
                    needed, total = policy.finite_domain(parameters, total)
                    if not needed:
                        finite = False
                        break
                else:
                    bits = sum(1 if typ == "bool" else WIDTHS.get(typ, 1000000) for typ in parameters)
                    if bits > 12 or total + (1 << bits) > 4096:
                        finite = False
                        break
                    needed = 1 << bits
                    total += needed
                domains[name] = parameters, needed
        if finite:
            native = selected_scalar_reference()
            stream = os.environ.get('HEPTA_HIA_SHA256_STREAM_MANIFEST')
            if stream:
                from .hia_sha256_stream_native import installed_stream_hasher
                transcript = installed_stream_hasher(stream).new()
            else:
                transcript = sha256()
            checked = 0
            deadline = time.monotonic_ns() + min(10000, timeout_ms) * 1_000_000
            for name, (types, required) in domains.items():
                if native is None:
                    input_domains = [[False, True] if typ == "bool" else
                                     range(integer_range(typ)[0], integer_range(typ)[1] + 1)
                                     for typ in types]
                    cases = itertools.product(*input_domains)
                else:
                    cases = (native.finite_arguments(types, ordinal, required)
                             for ordinal in range(required))
                for arguments in cases:
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
                    same = (first == second if native is None else
                            native.same_observation(wire(first), wire(second)))
                    if not same:
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
        if (report.get("solver") or {}).get("name") == "HIA":
            return status, "HIA native Boolean obligations for scalar CFG transitions, returns and checked overflow over all declared inputs", report
        if left["schema"] == right["schema"] == NATIVE_CORE_SCHEMA:
            return status, "The Core v8 scalar circuit profile did not establish a complete result", report
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

    def _subject_with_components(self, args, program):
        subject = args["subject"]
        if subject["kind"] != "core":
            self._profile(subject["backend_profile"], "backend")
        if subject["kind"] == "canonical_lowering":
            self._profile(subject["lowering_profile"], "lowering")
        if subject["kind"] == "agent_machine_plan":
            from .hia_program_native import validate_block_layout_plan
            self._profile(subject["plan_profile"], "plan")
            plan = self._read_machine_plan(subject["plan"])
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

    def _hia_verify_with_components(self, args):
        from .hia_agent_store import _native_agent_identity

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
                actual_object = rebuilt["object_sha256"]
                retained_object = built["native_build"]["object_sha256"]
                bytes_equal = _exact_artifact_equal(actual, reemitted)
                object_equal = _exact_artifact_equal(wire(actual_object), wire(retained_object))
                matches = bytes_equal and object_equal
                status = "proved" if matches else "refuted"
                domain = "Exact actual artifact equals reverified Core/plan reemission and linkage by the same installed implementation, with checked closed symbol/ABI inventory; no independent semantic refinement claim"
                evidence = {"method": "complete_native_rederivation", "actual_sha256": payload_sha256(actual).hex(),
                    "rederived_sha256": payload_sha256(reemitted).hex(), "bytes_equal": bytes_equal,
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
        native = _native_agent_identity()
        if native is not None:
            record = native.verification_record(binding, checks, self.identities, args["validation_profile"])
            receipt = self.store.put(record, "verification-receipt")
            return native.verification_result(binding, checks, receipt)
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

    def _verification_with_components(self, ref, context, candidate=None):
        record, _, raw = self.store.get_json_with_wire(ref, kind="verification-receipt")
        equal = selected_json_equality()
        if (not equal(record["context"], context) or not equal(record["installation"], self.identities)
                or candidate is not None and not equal(record["candidate"], candidate)):
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
        self._validate_retained_checks(record["checks"], raw)
        for check in record["checks"]:
            evidence, _ = self.store.get_json(check["evidence_artifact"], kind="verification-evidence")
            assumptions, _ = self.store.get_json(check["assumptions_artifact"], kind="verification-assumptions")
            if evidence.get("method") == SAFE_CORE_METHOD:
                self._check_native_refinement_evidence(evidence, record["subject"], context, program)
            expected = proof_result(claim=check["claim"], status=check["status"], domain=check["domain"],
                subject=subject, profile=record["validation_profile"], installation=self.identities, evidence=evidence)
            actual = {key: value for key, value in check.items()
                      if key not in {"assumptions_artifact", "evidence_artifact"}}
            if not equal((actual, evidence.get("proof_binding"), assumptions),
                         (expected, expected, assumptions_document(expected))):
                reject("E_HIA_PROOF_SCOPE", "proof scope or retained checker conclusion differs; rerun verification with a fresh request key", "verification")
        return record

    def _validate_retained_checks(self, checks, raw):
        from .hia_agent_verify_response_schema_native import (
            RETAINED_RECEIPT_ROLE, SELECTOR, installed_agent_verify_response_schema,
        )

        selected = os.environ.get(SELECTOR)
        if selected and installed_agent_verify_response_schema(selected).accepts_wire(
                raw, RETAINED_RECEIPT_ROLE, self.catalog_sha256):
            return
        # On refusal, retain the public diagnostics for malformed and repeated checks.
        checks_schema = self.tools["hia_verify"]["outputSchema"]["properties"]["result"]["properties"]["checks"]
        try:
            validate(checks, checks_schema, "verification.checks")
        except AgentRejected as exc:
            reject("E_HIA_PROOF_SCOPE", "missing or invalid proof scope; rerun verification with a fresh request key: " + str(exc), "verification")
        if len({check["claim"] for check in checks}) != len(checks):
            reject("E_HIA_PROOF_SCOPE", "verification repeats a proof property", "verification")
        if selected:
            raise ValueError("native proof receipt disagrees with the contract")

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

    def _replay_verification_with_components(self, response, arguments):
        """Observe an original result only if its complete scope remains valid."""
        try:
            self._validate_tool_response('hia_verify', response, 'replayed verification')
        except AgentRejected as exc:
            reject("E_HIA_PROOF_SCOPE", "cached proof lacks current scope; rerun verification with a fresh request key: " + str(exc), "verification")
        if installation_manifest() != self.identities:
            reject("E_HIA_IMPLEMENTATION_STALE", "installed implementation changed during verification replay")
        result = response["result"]
        retained = self._verification(result["verification_receipt"], arguments["context"], arguments["candidate"])
        equal = selected_json_equality()
        if not equal(
                (result["candidate"], result["subject"], result["checks"], retained["subject"],
                 retained["base_program"], retained["validation_profile"],
                 [check["claim"] for check in retained["checks"]]),
                (retained["candidate"], retained["subject"], retained["checks"], arguments["subject"],
                 arguments["base_program"], arguments["validation_profile"], arguments["claims"])):
            reject("E_HIA_PROOF_SCOPE", "cached proof differs from the original subject or retained conclusion; rerun verification with a fresh request key", "verification")

    def _compile(self, program, kind, machine_plan, timeout_ms, *, foreign_buffer_exports=()):
        selected = os.environ.get('HEPTA_HIA_EMISSION_MANIFEST')
        if selected is not None:
            from .hia_emission_native import installed_emission, EmissionFrame
            return EmissionFrame(installed_emission(selected), 1, self,
                (program, kind, machine_plan, timeout_ms, foreign_buffer_exports)).finish()
        if ('HEPTA_HIA_SHA256_STREAM_MANIFEST' in os.environ
                or 'HEPTA_HIA_SHA256_MANIFEST' in os.environ
                or 'HEPTA_HIA_AGENT_IDENTITY_MANIFEST' in os.environ):
            return HIAAgentService._compile_with_components(
                self, program, kind, machine_plan, timeout_ms,
                foreign_buffer_exports=foreign_buffer_exports)
        return self._compile_reference(program, kind, machine_plan, timeout_ms,
                                       foreign_buffer_exports=foreign_buffer_exports)

    def _compile_reference(self, program, kind, machine_plan, timeout_ms, *, foreign_buffer_exports=()):
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

    def _compile_with_components(self, program, kind, machine_plan, timeout_ms, *, foreign_buffer_exports=()):
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
        if (result.get("object_sha256") != payload_sha256(object_bytes).hex()
                or result.get("core_sha256") != program.sha256
                or result.get("artifact_sha256") != payload_sha256(data).hex()
                or kind == "object" and not _exact_artifact_equal(data, object_bytes)):
            reject("E_HIA_RECEIPT_BINDING", "native build metadata differs from the actual emitted bytes", "codegen")
        result["object_artifact"] = self.store.put(object_bytes, "build-object", {
            "schema": "hepta.hia.agent.build-object.v1", "core_sha256": program.sha256,
            "machine_plan_sha256": result["machine_plan_sha256"], "installation": self.identities})
        return data, result

    def _hia_emit(self, args):
        selected = os.environ.get('HEPTA_HIA_EMISSION_MANIFEST')
        if selected is not None:
            from .hia_emission_native import installed_emission, EmissionFrame
            return EmissionFrame(installed_emission(selected), 2, self, (args,)).finish()
        if ('HEPTA_HIA_AGENT_IDENTITY_MANIFEST' in os.environ
                or 'HEPTA_HIA_AGENT_PLAN_SCHEMA_MANIFEST' in os.environ):
            return HIAAgentService._hia_emit_with_components(self, args)
        return self._hia_emit_reference(args)

    def _hia_emit_reference(self, args):
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

    def _hia_emit_with_components(self, args):
        from .hia_agent_store import _native_agent_identity

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
            plan = self._read_machine_plan(codegen["plan"])
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
        native = _native_agent_identity()
        if native is not None:
            backend, target = args["backend_profile"], context["target_profile"]
            record = native.build_record(metadata, backend, target, artifact, native_build,
                                         args["verification_receipts"])
            receipt = self.store.put(record, "build-receipt")
            return native.build_result(args["candidate"], backend, target, receipt, artifact,
                                       linked=args["output_kind"] == "shared")
        receipt = self.store.json({"schema": "hepta.hia.agent.build.v1", **metadata,
            "native_artifact": artifact, "native_build": native_build,
            "backend_profile": args["backend_profile"], "target_profile": context["target_profile"],
            "verification_receipts": args["verification_receipts"]}, "build-receipt")
        return {"candidate": args["candidate"], "native_artifact": artifact, "build_receipt": receipt,
            "backend_profile": args["backend_profile"], "target_profile": context["target_profile"],
            "codegen_backend": "hia-direct", "llvm_codegen_used": False, "external_assembler_used": False,
            "linker_used": args["output_kind"] == "shared", "native_execution_observed": False, "adopted": False}

    def _native(self, ref, context=None):
        selected = os.environ.get('HEPTA_HIA_NATIVE_BUILD_ADMISSION_MANIFEST')
        if selected is not None:
            from .hia_native_build_admission_native import installed_native_build_admission, NativeBuildAdmissionFrame
            return NativeBuildAdmissionFrame(installed_native_build_admission(selected), 2,
                                             self, (ref, context)).finish()
        reference = self._native_reference
        if type(reference) is MethodType and reference.__func__ is _ADMISSION_NATIVE_REFERENCE:
            return HIAAgentService._native_with_components(reference.__self__, ref, context)
        return reference(ref, context)

    def _native_reference(self, ref, context=None):
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

    def _native_with_components(self, ref, context=None):
        data, metadata = self.store.get(ref, kind="native")
        differs = selected_json_inequality()
        if (differs(metadata["installation"], self.identities)
                or context is not None and differs(metadata["context"], context)):
            reject("E_HIA_RECEIPT_BINDING", "native artifact belongs to a different context or implementation")
        program = self._program(metadata["candidate"])
        retained_context = self._context(metadata["context"])
        exports = tuple(map(tuple, retained_context.get("foreign_buffer_exports", [])))
        if (differs(metadata["core_sha256"], program.sha256)
                or differs(_signatures(program, exports), metadata["signatures"])
                or differs(metadata.get("foreign_buffer_exports", []), [list(pair) for pair in exports])):
            reject("E_HIA_RECEIPT_BINDING", "native artifact's admitted Core identity differs")
        return data, metadata, program

    def _build_receipt(self, ref, context, artifact):
        selected = os.environ.get('HEPTA_HIA_NATIVE_BUILD_ADMISSION_MANIFEST')
        if selected is not None:
            from .hia_native_build_admission_native import installed_native_build_admission, NativeBuildAdmissionFrame
            return NativeBuildAdmissionFrame(installed_native_build_admission(selected), 4,
                                             self, (ref, context, artifact)).finish()
        return self._build_receipt_reference(ref, context, artifact)

    def _build_receipt_reference(self, ref, context, artifact):
        return self._build_inputs(ref, context, artifact)[0]

    def _build_inputs(self, ref, context, artifact):
        selected = os.environ.get('HEPTA_HIA_NATIVE_BUILD_ADMISSION_MANIFEST')
        if selected is not None:
            from .hia_native_build_admission_native import installed_native_build_admission, NativeBuildAdmissionFrame
            return NativeBuildAdmissionFrame(installed_native_build_admission(selected), 3,
                                             self, (ref, context, artifact)).finish()
        reference = self._build_inputs_reference
        if type(reference) is MethodType and reference.__func__ is _ADMISSION_INPUTS_REFERENCE:
            return HIAAgentService._build_inputs_with_components(reference.__self__, ref, context, artifact)
        return reference(ref, context, artifact)

    def _build_inputs_reference(self, ref, context, artifact):
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

    def _build_inputs_with_components(self, ref, context, artifact):
        """Capture and validate one immutable Core/object/final build observation."""
        record, _ = self.store.get_json(ref, kind="build-receipt")
        differs = selected_json_inequality()
        if (differs(record["context"], context)
                or differs(record["native_artifact"], artifact)
                or differs(record["installation"], self.identities)
                or differs(record.get("target_profile"), self.profiles["target"])
                or differs(record.get("backend_profile"), self.profiles["backend"])):
            reject("E_HIA_RECEIPT_BINDING", "build receipt belongs to a different native subject")
        data, metadata, program = self._native(artifact, context)
        if any(differs(record.get(name), value) for name, value in metadata.items()):
            reject("E_HIA_RECEIPT_BINDING", "build record differs from retained native metadata")
        built = record.get("native_build")
        if (type(built) is not dict or type(record.get("object_artifact")) is not dict
                or differs(record["object_artifact"], built.get("object_artifact"))
                or differs(record.get("object_sha256"), built.get("object_sha256"))
                or differs(built.get("core_sha256"), program.sha256)
                or differs(built.get("input_sha256"), program.input_sha256)
                or differs(built.get("implementation_sha256"), self.identities["backend_sha256"])
                or differs(built.get("kind"), record["output_kind"])
                or differs(built.get("foreign_buffer_exports"), record.get("foreign_buffer_exports", []))
                or differs(built.get("artifact_sha256"), _build_input_digest(data))):
            reject("E_HIA_RECEIPT_BINDING", "build record differs from actual artifact bytes")
        object_bytes, object_metadata = self.store.get(record["object_artifact"], kind="build-object")
        expected_metadata = {"schema": "hepta.hia.agent.build-object.v1", "core_sha256": program.sha256,
            "machine_plan_sha256": built.get("machine_plan_sha256"), "installation": self.identities}
        if (differs(object_metadata, expected_metadata)
                or differs(_build_input_digest(object_bytes), record["object_sha256"])
                or differs(record["object_artifact"]["sha256"], record["object_sha256"])
                or record["output_kind"] == "object" and _build_input_bytes_differ(object_bytes, data)):
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

    @staticmethod
    def _native_refinement_binding_with_components(subject, built, program, object_bytes, final_bytes):
        return {"candidate_core_sha256": program.sha256, "input_sha256": program.input_sha256,
            "native_artifact": subject["native_artifact"], "build_receipt": subject["build_receipt"],
            "object_artifact": built["object_artifact"], "object_sha256": payload_sha256(object_bytes).hex(),
            "final_image_sha256": payload_sha256(final_bytes).hex(), "output_kind": built["output_kind"],
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

    def _independent_native_refinement_with_components(self, args, program, context):
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
                evidence["queries"].append({"name": path.name, "sha256": payload_sha256(data).hex(),
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

    def _check_native_refinement_evidence_with_components(self, evidence, subject, context, program):
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
            if (payload_sha256(data).hex() != query["sha256"]
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

    def _required_claims_with_components(self, context, candidate_artifact, refs, baseline_core_sha=None):
        from .hia_agent_identity_native import CLAIM_BUILD_RECHECK
        from .hia_agent_store import _native_agent_identity

        _data, native, _program = self._native(candidate_artifact, context["ref"])
        objective, _ = self.store.get_json(context["objective"])
        receipts = [self._verification(ref, context["ref"], native["candidate"]) for ref in refs]
        policy = _native_agent_identity()
        if policy is not None:
            rechecks, missing = policy.required_claims(
                objective["required_claims"], receipts, candidate_artifact, native, baseline_core_sha)
            for index in rechecks:
                self._build_receipt(receipts[index]["subject"]["build_receipt"], context["ref"], candidate_artifact)
            if missing is not None:
                reject("E_HIA_CLAIM_REQUIRED", "missing exact proved acceptance claim: " + missing, "verification")
            return objective
        for claim in objective["required_claims"]:
            qualified = False
            for receipt in receipts:
                decision = self._reference_claim_eligibility(
                    claim, receipt, candidate_artifact, native, baseline_core_sha)
                if decision == CLAIM_BUILD_RECHECK:
                    self._build_receipt(receipt["subject"]["build_receipt"], context["ref"], candidate_artifact)
                if decision:
                    qualified = True
            if not qualified:
                reject("E_HIA_CLAIM_REQUIRED", "missing exact proved acceptance claim: " + claim, "verification")
        return objective

    @staticmethod
    def _reference_claim_eligibility(claim, receipt, candidate_artifact, native, baseline_core_sha):
        from .hia_agent_identity_native import CLAIM_NOT_QUALIFIED, CLAIM_QUALIFIED, CLAIM_BUILD_RECHECK

        if not any(c["claim"] == claim and c["status"] == "proved" for c in receipt["checks"]):
            return CLAIM_NOT_QUALIFIED
        subject = receipt["subject"]
        if claim == "behavior_equivalence":
            return CLAIM_QUALIFIED if receipt["base_core_sha256"] == baseline_core_sha else CLAIM_NOT_QUALIFIED
        if claim in ("encoding_check", "lowering_refinement"):
            if subject["kind"] == "native_artifact":
                return CLAIM_BUILD_RECHECK if subject["native_artifact"] == candidate_artifact else CLAIM_NOT_QUALIFIED
            if (claim == "lowering_refinement" and native["machine_plan"] is not None
                    and subject["kind"] == "agent_machine_plan" and subject["plan"] == native["codegen"]["plan"]):
                return CLAIM_QUALIFIED
            return CLAIM_NOT_QUALIFIED
        return CLAIM_QUALIFIED

    def _cost_ledger(self, context, evaluation_wall_ns, native_wall_ns):
        selected = os.environ.get('HEPTA_HIA_COST_LEDGER_MANIFEST')
        if selected is not None:
            from .hia_cost_ledger_native import installed_cost_ledger, CostLedgerFrame
            return CostLedgerFrame(installed_cost_ledger(selected), self, context,
                                   evaluation_wall_ns, native_wall_ns).finish()
        from .hia_agent_store import uses_native_store
        if uses_native_store(self.store) or 'HEPTA_HIA_AGENT_IDENTITY_MANIFEST' in os.environ:
            return self._native_cost_ledger_record(context, evaluation_wall_ns, native_wall_ns)
        ledger = self._cost_ledger_reference(context, evaluation_wall_ns, native_wall_ns)
        return wire(ledger) if isinstance(self.store, AgentStore) else ledger

    def _cost_ledger_reference(self, context, evaluation_wall_ns, native_wall_ns):
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

    def _native_cost_ledger_record(self, context, evaluation_wall_ns, native_wall_ns):
        from .hia_agent_store import _native_agent_identity

        rows = self.store.context_costs(context["ref"]["id"])
        observed_count = len(rows)
        policy_image = _native_agent_identity()
        retained = min(observed_count, 10000) if policy_image is None else policy_image.cost_window(observed_count)
        rows = rows[:retained]
        values = [(row["context_id"], decode_data(row["details"]), row["request_id"],
                   row["sequence"], row["status"], row["tool"], row["wall_ns"]) for row in rows]
        policy, _ = self.store.get_json(context["budget"]["cost_policy"])
        if policy_image is not None:
            totals = policy_image.observed_cost_totals(rows, context["ref"]["id"])
            return policy_image.cost_ledger_record(context["ref"], observed_count, policy, totals,
                                                   evaluation_wall_ns, native_wall_ns, values)
        fields = ("context_id", "details", "request_id", "sequence", "status", "tool", "wall_ns")
        entries = [dict(zip(fields, value, strict=True)) for value in values]
        return wire(self._reference_cost_receipt(context["ref"], entries, observed_count > retained, policy,
            self._reference_observed_cost_totals(rows, context["ref"]["id"]), evaluation_wall_ns, native_wall_ns))

    @staticmethod
    def _reference_cost_receipt(context_ref, entries, truncated, policy, totals, evaluation_wall_ns, native_wall_ns):
        external = dict(policy["external_costs"])
        # A caller may record measured zero; an incomplete model ledger cannot
        # convert a placeholder zero into an observed zero-cost model call.
        if not policy["external_costs_complete"]:
            external = {name: None for name in external}
        attributed, unscoped = totals
        return {"schema": "hepta.hia.agent.cost-ledger.v1", "context": context_ref,
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

    @staticmethod
    def _reference_observed_cost_totals(rows, context_id):
        return (sum(int(row["wall_ns"]) for row in rows if row["context_id"] == context_id),
                sum(int(row["wall_ns"]) for row in rows if row["context_id"] is None))

    def _hia_evaluate(self, args):
        selected = os.environ.get('HEPTA_HIA_EVALUATION_MANIFEST')
        if selected is not None:
            from .hia_evaluation_native import installed_evaluation, EvaluationFrame
            return EvaluationFrame(installed_evaluation(selected), self, args).finish()
        from inspect import getattr_static

        store = getattr_static(self, 'store', None)
        if getattr_static(store, 'get_json_with_wire', None) is None:
            return self._hia_evaluate_reference(args)
        return self._hia_evaluate_with_components(args)

    def _hia_evaluate_reference(self, args):
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

    def _hia_evaluate_with_components(self, args):
        from .hia_agent_runner import run_native_batch, run_reference_batch
        from .hia_agent_buffers import validate_cases
        from .hia_agent_identity_native import (
            DECLARED_OBSERVATION, REFERENCE_OBSERVATION, NATIVE_OBSERVATION,
            EVALUATION_NORMAL, EVALUATION_FINISH,
            REF_BATCH, REF_CLOCK, REF_CASE, REF_COMPARE_TRAP, REF_FINISH, REF_EXPECTATION,
        )
        from .hia_agent_payload_schema_native import WORKLOAD_ROLE
        from .hia_agent_store import _native_agent_identity
        started = time.monotonic_ns()
        context = self._context(args["context"])
        baseline_bytes, baseline_meta, baseline_program = self._native(args["baseline_artifact"], args["context"])
        candidate_bytes, candidate_meta, candidate_program = self._native(args["candidate_artifact"], args["context"])
        self._build_receipt(args["build_receipt"], args["context"], args["candidate_artifact"])
        if baseline_meta["output_kind"] != "shared" or candidate_meta["output_kind"] != "shared":
            reject("E_HIA_EXECUTION_PROFILE", "evaluation requires retained direct shared images", "execution")
        equal = selected_json_equality()
        if not equal(baseline_meta["signatures"], candidate_meta["signatures"]):
            reject("E_HIA_ABI", "baseline and candidate frozen public ABI differ", "execution")
        if (context["baseline_core_sha256"] is not None
                and not equal(context["baseline_core_sha256"], baseline_program.sha256)):
            reject("E_HIA_BASELINE", "evaluation baseline differs from the frozen Core snapshot", "execution")
        objective = self._required_claims(context, args["candidate_artifact"],
                                         args["verification_receipts"], baseline_program.sha256)
        workload, _, workload_raw = self.store.get_json_with_wire(context["workload"])
        self._validate_payload(workload, workload_raw, WORKLOAD_SCHEMA, "workload", WORKLOAD_ROLE)
        validate_cases(baseline_meta["signatures"], workload["cases"])
        policy = _native_agent_identity()
        agree = self._reference_observation_agreement if policy is None else policy.observation_agreement
        exports = tuple(map(tuple, context.get("foreign_buffer_exports", [])))
        observations, normal, trapping = [], [], []
        reference_started = time.monotonic_ns()
        created_ns = self.store.context_created_ns(args["context"]["id"])

        def remaining_total_ms():
            return self._wall_window(context, created_ns=created_ns)[1]

        references = {}
        def run_reference(arm):
            label, program = (("baseline", baseline_program), ("candidate", candidate_program))[arm]
            reference = run_reference_batch(program, workload["cases"], timeout_ms=remaining_total_ms(),
                memory_bytes=uint64(context["budget"]["max_memory_bytes"], "max_memory_bytes"),
                foreign_buffer_exports=exports)
            references[label] = reference
            status = reference["status"]
            report = reference["report"] if status != "budget_exceeded" else None
            complete = status == "returned" and report["complete"]
            exhausted = not complete and report is not None and any(
                row["status"] == "budget_exceeded" for row in report["observations"])
            return status, bool(complete), bool(exhausted)

        def read_case(index):
            case = workload["cases"][index]
            expected = references["baseline"]["report"]["observations"][index]
            candidate_reference = references["candidate"]["report"]["observations"][index]
            row = {"index": index, "function": case["function"], "arguments": case["arguments"],
                   "baseline_vm": expected, "candidate_vm": candidate_reference}
            observations.append(row)
            return expected["status"], candidate_reference["status"]

        def compare_case(index, trap):
            case = workload["cases"][index]
            row = observations[index]
            expected, candidate_reference = row["baseline_vm"], row["candidate_vm"]
            expected_value = _value_observation(expected)
            if "expected" in case and not agree(expected, case["expected"], mode=DECLARED_OBSERVATION):
                return False, False
            # A native result cannot excuse a reference-level first-trap or
            # resource behavior difference. This is an observation at this
            # workload, separate from an equivalence proof over all inputs.
            agrees = agree(expected, candidate_reference, mode=REFERENCE_OBSERVATION)
            prepared = {"function": case["function"], "arguments": case["arguments"], "expected": expected_value}
            cases = trapping if trap else normal
            cases.append((index, prepared))
            return True, agrees

        def expectation_refused(index):
            reject("E_HIA_WORKLOAD_EXPECTATION",
                   "declared case expectation differs from baseline Core at index " + str(index), "execution")

        case_count = len(workload["cases"])
        if policy is None:
            state = self._reference_evaluation_prepare(
                case_count, run_reference, remaining_total_ms, read_case, compare_case, expectation_refused)
        else:
            step, state = policy.evaluation_reference(case_count, (0, 0), (False, True, True))
            while step[0] != REF_FINISH:
                action, index = step
                if action == REF_EXPECTATION:
                    expectation_refused(index)
                if action == REF_BATCH:
                    evidence = run_reference(index)
                elif action == REF_CLOCK:
                    evidence = (remaining_total_ms() > 0, 0, 0)
                elif action == REF_CASE:
                    evidence = (*read_case(index), 0)
                else:
                    evidence = (*compare_case(index, action == REF_COMPARE_TRAP), 0)
                step, state = policy.evaluation_reference(case_count, step, state, evidence)
        reference_ns = time.monotonic_ns() - reference_started
        native_started = time.monotonic_ns()
        owner = digest({"tool": "hia_evaluate", "key": args["request_key"]})
        budget_claim = self.store.execution_budgets.claim(args["context"]["id"], owner,
            context["budget"]["max_native_wall_ms"], native_started)
        arms = (("baseline", baseline_bytes, baseline_meta), ("candidate", candidate_bytes, candidate_meta))
        runs = {label: {"normal": None, "traps": [], "total_native_ns": "0"} for label, _, _ in arms}

        def run(arm, cases, warmup, repetitions):
            _, data, metadata = arms[arm]
            return budget_claim.run(run_native_batch, data, metadata["signatures"], cases,
                now=time.monotonic_ns(), total_ms=remaining_total_ms(),
                warmup=int(warmup), repetitions=int(repetitions),
                memory_bytes=uint64(context["budget"]["max_memory_bytes"], "max_memory_bytes"))

        def run_normal(arm):
            label = arms[arm][0]
            outcome = run(arm, [case for _, case in normal], workload["warmup_iterations"], workload["repetitions"])
            runs[label]["normal"] = outcome
            status, agrees = outcome["status"], True
            if status == "returned":
                report = outcome["report"]
                if report["completed_cases"] != len(normal) or len(report["observations"]) != len(normal):
                    reject("E_HIA_NATIVE_REPORT", "native report did not account for every planned case", "execution")
                runs[label]["total_native_ns"] = report["total_native_ns"]
                for (index, case), observed in zip(normal, report["observations"]):
                    observations[index][label + "_native"] = observed
                    if observed["mismatch"] or not agree(observed, case["expected"], mode=NATIVE_OBSERVATION):
                        agrees = False
            return status, agrees

        def run_trap(arm, position):
            label = arms[arm][0]
            index, case = trapping[position]
            outcome = run(arm, [case], 0, 1)
            runs[label]["traps"].append({"index": index, **outcome})
            status, agrees = outcome["status"], True
            observed = {"status": status, "returncode": outcome["returncode"]}
            observations[index][label + "_native"] = observed
            if "buffers" in case["expected"]:
                observed["buffers"] = outcome.get("buffer_snapshots", [{}])[0].get("buffers")
                if status == "trapped":
                    agrees = agree(observed, case["expected"], mode=NATIVE_OBSERVATION)
            return status, agrees

        counts = len(normal), len(trapping)
        if policy is None:
            state = self._reference_evaluation_schedule(counts, state, run_normal, run_trap)
        else:
            step, state = policy.evaluation_schedule(counts, (0, 0, 0), state)
            while step[0] != EVALUATION_FINISH:
                action, arm, index = step
                status, agrees = run_normal(arm) if action == EVALUATION_NORMAL else run_trap(arm, index)
                step, state = policy.evaluation_schedule(counts, step, state, status=status, agrees=agrees)
        budget_exceeded, correct, complete = state
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
        threshold = objective["min_improvement_ratio"]
        latency = objective["metric"] == "latency_ns"
        if policy is not None:
            ratio, outcome = policy.evaluation_measurement(before, after, threshold,
                budget_exceeded=budget_exceeded, correct=correct, complete=complete,
                latency=latency, trapping=bool(trapping))
        else:
            ratio, outcome = self._reference_evaluation_measurement(before, after, threshold,
                budget_exceeded=budget_exceeded, correct=correct, complete=complete,
                latency=latency, trapping=bool(trapping))
        measurement_scope = ("same host and immutable workload, baseline then candidate; call latency includes ctypes FFI "
                             "overhead; snapshot reset/hash outside call timing is included in subprocess wall cost")
        native_outcomes = [result for run in runs.values() for result in (run["normal"], *run["traps"])
                           if result is not None]
        if native_outcomes and all(result.get("direct_call_executable_sha256") for result in native_outcomes):
            measurement_scope = ("same host and immutable workload, baseline then candidate; "
                                 "snapshot reset/hash outside call timing is included in subprocess wall cost")
            scopes = {run["normal"]["report"]["timing_scope"] for run in runs.values()
                      if run["normal"] and run["normal"]["report"] is not None}
            if scopes:
                measurement_scope += "; " + "; ".join(sorted(scopes))
        if policy is not None:
            measurement_record = policy.measurement_record(args, context, before=before, after=after, ratio=ratio,
                scope=measurement_scope, metric=objective["metric"], native_runs=runs, observations=observations,
                outcome=outcome, planned_cases=len(workload["cases"]), complete=complete,
                reference_runs=references, reference_ns=reference_ns)
            measurements = self.store.put(measurement_record, "measurements")
        else:
            measurements = self.store.json({"schema": "hepta.hia.agent.measurements.v1", "context": args["context"],
                "workload": context["workload"], "objective": context["objective"],
                "baseline_artifact": args["baseline_artifact"], "candidate_artifact": args["candidate_artifact"],
                "metric": objective["metric"], "baseline_value": str(before), "candidate_value": str(after),
                "improvement_ratio": ratio, "reference_wall_ns": str(reference_ns),
                "planned_cases": len(workload["cases"]), "observations": observations, "native_runs": runs,
                "reference_runs": references,
                "native_correctness_scope": "frozen workload return/trap behavior and all external snapshot bytes; VM first-trap/resource observations recorded separately",
                "universal_equivalence_or_native_refinement_proved": False,
                "measurement_scope": measurement_scope,
                "outcome": outcome, "planned_workload_complete": complete}, "measurements")
        costs = self._cost_ledger(context, time.monotonic_ns() - started, native_ns)
        ledger = _retain_cost_ledger(self.store, costs)
        if policy is not None:
            evaluation_record = policy.evaluation_record(args, baseline_program.sha256, candidate_program.sha256,
                self.identities, measurements, ledger, outcome, complete)
            receipt = self.store.put(evaluation_record, "evaluation-receipt")
            return policy.evaluation_result(args, receipt, measurements, ledger, outcome, complete)
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

    @staticmethod
    def _reference_evaluation_prepare(case_count, run_reference, remaining_ms, read_case,
                                      compare_case, expectation_refused):
        for arm in range(2):
            status, complete, exhausted = run_reference(arm)
            if status != "returned" or not complete:
                exceeded = status == "budget_exceeded" or exhausted
                return exceeded, exceeded, False
        correct = True
        for index in range(case_count):
            if remaining_ms() <= 0:
                return True, correct, False
            expected, candidate = read_case(index)
            if "budget_exceeded" in {expected, candidate}:
                return True, correct, False
            declared, agrees = compare_case(index, expected == "trapped")
            if not declared:
                expectation_refused(index)
            correct = correct and agrees
        return False, correct, True

    @staticmethod
    def _reference_evaluation_schedule(counts, state, run_normal, run_trap):
        normal, trapping = counts
        budget_exceeded, correct, complete = state
        if not complete:
            return state
        for arm in range(2):
            if normal:
                status, agrees = run_normal(arm)
                if status != "returned":
                    return status == "budget_exceeded", False, False
                correct = correct and agrees
            for index in range(trapping):
                status, agrees = run_trap(arm, index)
                if status in {"budget_exceeded", "faulted", "invalid_report"}:
                    return status == "budget_exceeded", False, False
                correct = correct and status == "trapped" and agrees
        return budget_exceeded, correct, complete

    @staticmethod
    def _reference_observation_agreement(left, right, *, mode):
        from .hia_agent_identity_native import DECLARED_OBSERVATION, REFERENCE_OBSERVATION

        value = _value_observation(left)
        if mode == DECLARED_OBSERVATION and "buffers" not in right:
            value.pop("buffers", None)
        if value != _value_observation(right):
            return False
        return mode != REFERENCE_OBSERVATION or (
            left.get("trap_code") == right.get("trap_code")
            and left["ledger"]["resources"] == right["ledger"]["resources"])

    @staticmethod
    def _reference_evaluation_measurement(before, after, threshold, *,
                                          budget_exceeded, correct, complete, latency, trapping):
        ratio = (before - after) / before if before else 0.0
        if budget_exceeded:
            outcome = "budget_exceeded"
        elif not correct:
            outcome = "incorrect"
        elif not complete or latency and trapping:
            outcome = "inconclusive"
        elif after < before and ratio >= threshold:
            outcome = "improved"
        elif after > before:
            outcome = "regressed"
        else:
            outcome = "unchanged"
        return ratio, outcome

    def _slot_snapshot(self, slot):
        if self._slot_ledger is not None:
            return self._slot_ledger.snapshot(slot)
        return self._reference_slot_snapshot(slot)

    def _reference_slot_snapshot(self, slot):
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
        if self._slot_ledger is not None:
            return self._slot_ledger.conditional(args, self._slot_snapshot)
        return self._reference_slot_conditional(args)

    def _reference_slot_conditional(self, args):
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
        from .hia_agent_store import _native_agent_identity

        context = self._context(args["context"])
        evaluation, _ = self.store.get_json(args["evaluation_receipt"], kind="evaluation-receipt")
        equal = selected_json_equality()
        if not equal((evaluation["context"], evaluation["candidate_artifact"], evaluation["installation"]),
                     (args["context"], args["candidate_artifact"], self.identities)):
            reject("E_HIA_RECEIPT_BINDING", "evaluation does not authorize this candidate/context", "adoption")
        self._build_receipt(evaluation["build_receipt"], args["context"], args["candidate_artifact"])
        objective = self._required_claims(context, args["candidate_artifact"], args["verification_receipts"], evaluation["baseline_core_sha256"])
        if self._slot_ledger is not None:
            self._slot_ledger.admit_evaluation(evaluation, objective)
        else:
            self._reference_adoption_evaluation(evaluation, objective)
        self.store.get(evaluation["measurements"], kind="measurements")
        self.store.get(evaluation["full_cost_ledger"], kind="cost-ledger")
        if self._slot_ledger is not None:
            self._slot_ledger.admit_net_benefit(objective)
        else:
            self._reference_adoption_net_benefit(objective)
        _data, metadata, _program = self._native(args["candidate_artifact"], args["context"])
        _baseline_data, baseline, _baseline_program = self._native(evaluation["baseline_artifact"], args["context"])
        if not equal(metadata["signatures"], baseline["signatures"]):
            reject("E_HIA_ABI", "candidate and baseline are not ABI compatible", "adoption")
        snapshot = self._conditional_slot(args)
        abi = digest(metadata["signatures"])
        if self._slot_ledger is not None:
            current = self._slot_ledger.adopt(args, snapshot, evaluation, abi, self._native)
        else:
            current = self._reference_slot_adopt(args, snapshot, evaluation, abi)
        native = _native_agent_identity()
        if native is not None:
            record = native.adoption_record(args, snapshot["current"], current, evaluation["baseline_artifact"])
            receipt = self.store.put(record, "adoption-receipt")
            return native.adoption_result(args, snapshot["current"], current, receipt)
        receipt = self.store.json({"schema": "hepta.hia.agent.adoption.v1", "context": args["context"],
            "target_slot": args["target_slot"], "previous": snapshot["current"], "current": current,
            "active_artifact": args["candidate_artifact"], "retained_baseline": evaluation["baseline_artifact"],
            "evaluation_receipt": args["evaluation_receipt"], "verification_receipts": args["verification_receipts"],
            "future_calls_only": True, "in_flight_versions_retained": True,
            "consumer_api": "acquire_slot -> invoke_lease -> release_slot"}, "adoption-receipt")
        return {"target_slot": args["target_slot"], "previous": snapshot["current"], "current": current,
                "active_artifact": args["candidate_artifact"], "adoption_receipt": receipt, "future_calls_only": True}

    def _reference_adoption_evaluation(self, evaluation, objective):
        if (not evaluation["report_complete"] or not evaluation["planned_workload_complete"]
                or not evaluation["termination_confirmed"] or evaluation["outcome"] not in
                ({"improved", "unchanged"} if objective["allow_unchanged"] else {"improved"})):
            reject("E_HIA_EVALUATION_REQUIRED", "evaluation did not meet the frozen correctness/performance acceptance", "adoption")

    def _reference_adoption_net_benefit(self, objective):
        if objective.get("require_net_benefit", False):
            reject("E_HIA_COST_INCOMPLETE", "full model/discovery/adoption/future-use cost is not established by this prefix; net-benefit requirement cannot pass", "adoption")

    def _reference_slot_adopt(self, args, snapshot, evaluation, abi):
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
            if payload_sha256(active_data).hex() != evaluation["baseline_artifact"]["sha256"]:
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
        return current

    def _hia_rollback(self, args):
        from .hia_agent_store import _native_agent_identity

        if self._slot_ledger is not None:
            self._slot_ledger.validate_u64(args["retained_generation"], "retained_generation")
        else:
            uint64(args["retained_generation"], "retained_generation")
        snapshot = self._conditional_slot(args)
        if self._slot_ledger is not None:
            current, artifact = self._slot_ledger.rollback(args, snapshot, self._native)
        else:
            current, artifact = self._reference_slot_rollback(args, snapshot)
        native = _native_agent_identity()
        if native is not None:
            record = native.rollback_record(args, snapshot["current"], current, artifact)
            receipt = self.store.put(record, "rollback-receipt")
            return native.rollback_result(args, snapshot["current"], current, artifact, receipt)
        receipt = self.store.json({"schema": "hepta.hia.agent.rollback.v1", "context": args["context"],
            "target_slot": args["target_slot"], "previous": snapshot["current"], "current": current,
            "active_artifact": artifact, "reason": args["reason"], "future_calls_only": True,
            "past_effects_reversed": False, "in_flight_versions_retained": True}, "rollback-receipt")
        return {"target_slot": args["target_slot"], "previous": snapshot["current"], "current": current,
                "active_artifact": artifact, "rollback_receipt": receipt, "future_calls_only": True, "past_effects_reversed": False}

    def _reference_slot_rollback(self, args, snapshot):
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
        return current, artifact

    def acquire_slot(self, target_slot):
        """Pin the observed active generation for a real future native call."""
        with self.store.transaction():
            if self._slot_ledger is not None:
                return self._slot_ledger.acquire(target_slot, self._slot_snapshot, self._native)
            return self._reference_slot_acquire(target_slot)

    def _reference_slot_acquire(self, target_slot):
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
        if self._slot_ledger is not None:
            return self._slot_ledger.lease(lease)
        return self._reference_slot_lease(lease)

    def _reference_slot_lease(self, lease):
        keys(lease, ("id", "slot", "generation", "artifact"), label="generation lease")
        row = self.store.db.execute("SELECT * FROM leases WHERE id=?", (lease["id"],)).fetchone()
        if (row is None or row["active"] != 1 or row["slot"] != lease["slot"]
                or row["generation"] != lease["generation"] or decode_data(row["artifact"]) != lease["artifact"]):
            reject("E_HIA_LEASE", "lease is released, unknown or modified")
        # Use the retained row after admission. The caller can keep and mutate
        # its lease dictionary while a native child runs; neither returned
        # identities nor captured-buffer metadata may read that alias later.
        return {"id": row["id"], "slot": row["slot"], "generation": row["generation"],
                "artifact": decode_data(row["artifact"])}

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

    def release_slot(self, lease):
        with self.store.transaction():
            if self._slot_ledger is not None:
                return self._slot_ledger.release(lease)
            return self._reference_slot_release(lease)

    def _reference_slot_release(self, lease):
        lease = self._lease(lease)
        self.store.db.execute("UPDATE leases SET active=0 WHERE id=?", (lease["id"],))
        return {"released": True, "generation": lease["generation"], "artifact_retained": True}


# Direct references preserve the original private self/provider dispatch on
# the unselected route; native continuations never invoke these policy bodies.
_NATIVE_SERVICE_CONTEXT_FREEZE_REFERENCE = HIAAgentService._hia_context_reference
_NATIVE_SERVICE_CONTEXT_LOOKUP_REFERENCE = HIAAgentService._context_reference
_NATIVE_SERVICE_CONTEXT_BUDGET_REFERENCE = HIAAgentService._budget_reference
_NATIVE_SERVICE_CONTEXT_REMAINING_REFERENCE = HIAAgentService._remaining_ms_reference

# Stable identities describe only the original selected bridges. Later public
# class/global replacements remain foreign callables and must be observed.
_NATIVE_BUILD_SIGNATURES_BRIDGE = _signatures
_NATIVE_BUILD_NATIVE_BRIDGE = HIAAgentService._native
_NATIVE_BUILD_INPUTS_BRIDGE = HIAAgentService._build_inputs
_NATIVE_BUILD_GLOBAL_BUILTINS = _signatures.__builtins__
_ADMISSION_NATIVE_REFERENCE = HIAAgentService._native_reference
_ADMISSION_INPUTS_REFERENCE = HIAAgentService._build_inputs_reference

# Preserve the original functions' bound builtins dictionary even if a caller
# later replaces the module's __builtins__ binding or an explicit provider.
_EMISSION_GLOBAL_BUILTINS = HIAAgentService._compile.__builtins__


# The original class method remains byte-for-byte retained. Its old AST checks
# pin that reference body; the public binding below is checked separately.
_NATIVE_SERVICE_ARTIFACT_REFERENCE = HIAAgentService._hia_artifact
_SERVICE_ARTIFACT_GLOBAL_BUILTINS = _NATIVE_SERVICE_ARTIFACT_REFERENCE.__builtins__


def _service_artifact_dispatch(self, args):
    selected = os.environ.get('HEPTA_HIA_SERVICE_ARTIFACT_MANIFEST')
    if selected is not None:
        from .hia_service_artifact_native import installed_service_artifact, ServiceArtifactFrame
        return ServiceArtifactFrame(installed_service_artifact(selected), self, args).finish()
    return HIAAgentService._hia_artifact_with_selected_components(self, args)


HIAAgentService._hia_artifact = _service_artifact_dispatch

# Keep the complete original read body and its bound builtins. The public
# caller still performs its original dynamic method lookup; an explicit user
# replacement remains an ordinary foreign callable.
_SERVICE_READ_REFERENCE = HIAAgentService._hia_read
_SERVICE_READ_GLOBAL_BUILTINS = _SERVICE_READ_REFERENCE.__builtins__
HIAAgentService._hia_read_reference = _SERVICE_READ_REFERENCE


def _selected_hia_read(self, arguments):
    selector = os.environ.get('HEPTA_HIA_SERVICE_READ_MANIFEST')
    if selector is None:
        if (not issubclass(type(self), HIAAgentService)
                and 'HEPTA_HIA_AGENT_READ_PAGE_MANIFEST' not in os.environ
                and 'HEPTA_HIA_AGENT_IDENTITY_MANIFEST' not in os.environ):
            # Detached historical receivers expose only Store. Keep an explicitly
            # supplied page delegate on the component path without invoking it early.
            from inspect import getattr_static
            if getattr_static(self, '_read_window', None) is None:
                return _SERVICE_READ_REFERENCE(self, arguments)
        return HIAAgentService._hia_read_with_components(self, arguments)
    from .hia_service_read_native import ServiceReadFrame, installed_service_read
    return ServiceReadFrame(installed_service_read(selector), self, arguments).finish()


HIAAgentService._hia_read = _selected_hia_read


# Retain both complete original methods and their actual bound builtin tables.
# Public method lookup remains dynamic at the original caller. A later
# instance/class override still takes precedence over these dispatchers.
_NATIVE_SERVICE_SLOT_ROLLBACK_REFERENCE = HIAAgentService._hia_rollback
_NATIVE_SERVICE_SLOT_ADOPT_REFERENCE = HIAAgentService._hia_adopt
_SERVICE_SLOT_ROLLBACK_GLOBAL_BUILTINS = _NATIVE_SERVICE_SLOT_ROLLBACK_REFERENCE.__builtins__
_SERVICE_SLOT_ADOPT_GLOBAL_BUILTINS = _NATIVE_SERVICE_SLOT_ADOPT_REFERENCE.__builtins__


def _service_slot_rollback_dispatch(self, args):
    selected = os.environ.get('HEPTA_HIA_SERVICE_SLOT_MANIFEST')
    if selected is not None:
        from .hia_service_slot_native import installed_service_slot, ServiceSlotFrame
        from .hia_service_slot_protocol import ROLLBACK
        frame = ServiceSlotFrame(installed_service_slot(selected), ROLLBACK, self, args)
        del self, args
        return frame.finish()
    call = {'callee': _NATIVE_SERVICE_SLOT_ROLLBACK_REFERENCE, 'self': self, 'args': args}
    del self, args
    return call.pop('callee')(call.pop('self'), call.pop('args'))


def _service_slot_adopt_dispatch(self, args):
    selected = os.environ.get('HEPTA_HIA_SERVICE_SLOT_MANIFEST')
    if selected is not None:
        from .hia_service_slot_native import installed_service_slot, ServiceSlotFrame
        from .hia_service_slot_protocol import ADOPT
        frame = ServiceSlotFrame(installed_service_slot(selected), ADOPT, self, args)
        del self, args
        return frame.finish()
    call = {'callee': _NATIVE_SERVICE_SLOT_ADOPT_REFERENCE, 'self': self, 'args': args}
    del self, args
    return call.pop('callee')(call.pop('self'), call.pop('args'))


HIAAgentService._hia_rollback = _service_slot_rollback_dispatch
HIAAgentService._hia_adopt = _service_slot_adopt_dispatch


# Complete inspect/candidate method-level control. The original methods above
# remain byte-exact, callable references for the explicit unselected route and
# independent original-body qualification; selected dispatch never invokes them.
_SERVICE_INSPECTION_INSPECT_REFERENCE = HIAAgentService._hia_inspect
_SERVICE_INSPECTION_CANDIDATE_REFERENCE = HIAAgentService._hia_candidate
_SERVICE_INSPECTION_GLOBAL_BUILTINS = {
    1: _SERVICE_INSPECTION_INSPECT_REFERENCE.__builtins__,
    2: _SERVICE_INSPECTION_CANDIDATE_REFERENCE.__builtins__,
}
_SERVICE_INSPECTION_LOCAL_NAMES = {
    1: (_SERVICE_INSPECTION_INSPECT_REFERENCE.__code__.co_varnames
        + _SERVICE_INSPECTION_INSPECT_REFERENCE.__code__.co_cellvars),
    2: (_SERVICE_INSPECTION_CANDIDATE_REFERENCE.__code__.co_varnames
        + _SERVICE_INSPECTION_CANDIDATE_REFERENCE.__code__.co_cellvars),
}
HIAAgentService._hia_inspect_reference = _SERVICE_INSPECTION_INSPECT_REFERENCE
HIAAgentService._hia_candidate_reference = _SERVICE_INSPECTION_CANDIDATE_REFERENCE


def _selected_hia_inspect(self, args):
    selector = os.environ.get('HEPTA_HIA_SERVICE_INSPECTION_MANIFEST')
    if selector is None:
        if (issubclass(type(self), HIAAgentService)
                or 'HEPTA_HIA_INSPECTION_REQUEST_MANIFEST' in os.environ
                or 'HEPTA_HIA_AGENT_INSPECTION_MANIFEST' in os.environ):
            callee = HIAAgentService._hia_inspect_with_components
        else:
            callee = _SERVICE_INSPECTION_INSPECT_REFERENCE
        call = {'callee': callee, 'self': self, 'args': args}
        del self, args
        return call.pop('callee')(call.pop('self'), call.pop('args'))
    from .hia_service_inspection_native import ServiceInspectionFrame, installed_service_inspection
    frame = ServiceInspectionFrame(installed_service_inspection(selector), 1, self, args)
    del self, args
    return frame.finish()


def _selected_hia_candidate(self, args):
    selector = os.environ.get('HEPTA_HIA_SERVICE_INSPECTION_MANIFEST')
    if selector is None:
        if (issubclass(type(self), HIAAgentService)
                or 'HEPTA_HIA_AGENT_IDENTITY_MANIFEST' in os.environ):
            callee = HIAAgentService._hia_candidate_with_components
        else:
            callee = _SERVICE_INSPECTION_CANDIDATE_REFERENCE
        call = {'callee': callee, 'self': self, 'args': args}
        del self, args
        return call.pop('callee')(call.pop('self'), call.pop('args'))
    from .hia_service_inspection_native import ServiceInspectionFrame, installed_service_inspection
    frame = ServiceInspectionFrame(installed_service_inspection(selector), 2, self, args)
    del self, args
    return frame.finish()


HIAAgentService._hia_inspect = _selected_hia_inspect
HIAAgentService._hia_candidate = _selected_hia_candidate


# Four complete service lease methods. The class bodies above remain retained
# original references; selected control never invokes them. Public identity and
# the actual binding below are admitted separately from old body AST checks.
_SERVICE_LEASE_ACQUIRE_REFERENCE = HIAAgentService.acquire_slot
_SERVICE_LEASE_LEASE_REFERENCE = HIAAgentService._lease
_SERVICE_LEASE_INVOKE_REFERENCE = HIAAgentService.invoke_lease
_SERVICE_LEASE_RELEASE_REFERENCE = HIAAgentService.release_slot
_SERVICE_LEASE_GLOBAL_BUILTINS = {
    1: _SERVICE_LEASE_ACQUIRE_REFERENCE.__builtins__,
    2: _SERVICE_LEASE_LEASE_REFERENCE.__builtins__,
    3: _SERVICE_LEASE_INVOKE_REFERENCE.__builtins__,
    4: _SERVICE_LEASE_RELEASE_REFERENCE.__builtins__,
}


def _service_lease_import_runner():
    from .hia_agent_runner import run_native_batch
    return run_native_batch


def _service_lease_import_validator():
    from .hia_agent_buffers import validate_arguments
    return validate_arguments


# Capture these original import primitives with the same module globals and
# bound builtin mapping as the original methods, before later monkeypatches.
_SERVICE_LEASE_IMPORT_RUNNER = _service_lease_import_runner
_SERVICE_LEASE_IMPORT_VALIDATOR = _service_lease_import_validator


def _service_lease_acquire_dispatch(self, target_slot):
    selected = os.environ.get('HEPTA_HIA_SERVICE_LEASE_MANIFEST')
    if selected is None:
        call = {'callee': _SERVICE_LEASE_ACQUIRE_REFERENCE, 'self': self, 'target_slot': target_slot}
        del self, target_slot
        return call.pop('callee')(call.pop('self'), call.pop('target_slot'))
    from .hia_service_lease_native import ServiceLeaseFrame, installed_service_lease
    frame = ServiceLeaseFrame(installed_service_lease(selected), 1, self, (target_slot,))
    del self, target_slot
    return frame.finish()


def _service_lease_lease_dispatch(self, lease):
    selected = os.environ.get('HEPTA_HIA_SERVICE_LEASE_MANIFEST')
    if selected is None:
        call = {'callee': _SERVICE_LEASE_LEASE_REFERENCE, 'self': self, 'lease': lease}
        del self, lease
        return call.pop('callee')(call.pop('self'), call.pop('lease'))
    from .hia_service_lease_native import ServiceLeaseFrame, installed_service_lease
    frame = ServiceLeaseFrame(installed_service_lease(selected), 2, self, (lease,))
    del self, lease
    return frame.finish()


def _service_lease_invoke_dispatch(self, lease, function, arguments):
    selected = os.environ.get('HEPTA_HIA_SERVICE_LEASE_MANIFEST')
    if selected is None:
        call = {'callee': _SERVICE_LEASE_INVOKE_REFERENCE, 'self': self, 'lease': lease, 'function': function, 'arguments': arguments}
        del self, lease, function, arguments
        return call.pop('callee')(call.pop('self'), call.pop('lease'), call.pop('function'), call.pop('arguments'))
    from .hia_service_lease_native import ServiceLeaseFrame, installed_service_lease
    frame = ServiceLeaseFrame(installed_service_lease(selected), 3, self, (lease, function, arguments))
    del self, lease, function, arguments
    return frame.finish()


def _service_lease_release_dispatch(self, lease):
    selected = os.environ.get('HEPTA_HIA_SERVICE_LEASE_MANIFEST')
    if selected is None:
        call = {'callee': _SERVICE_LEASE_RELEASE_REFERENCE, 'self': self, 'lease': lease}
        del self, lease
        return call.pop('callee')(call.pop('self'), call.pop('lease'))
    from .hia_service_lease_native import ServiceLeaseFrame, installed_service_lease
    frame = ServiceLeaseFrame(installed_service_lease(selected), 4, self, (lease,))
    del self, lease
    return frame.finish()

_service_lease_acquire_dispatch.__name__ = _SERVICE_LEASE_ACQUIRE_REFERENCE.__name__
_service_lease_acquire_dispatch.__qualname__ = _SERVICE_LEASE_ACQUIRE_REFERENCE.__qualname__
_service_lease_acquire_dispatch.__doc__ = _SERVICE_LEASE_ACQUIRE_REFERENCE.__doc__
HIAAgentService.acquire_slot = _service_lease_acquire_dispatch

_service_lease_lease_dispatch.__name__ = _SERVICE_LEASE_LEASE_REFERENCE.__name__
_service_lease_lease_dispatch.__qualname__ = _SERVICE_LEASE_LEASE_REFERENCE.__qualname__
_service_lease_lease_dispatch.__doc__ = _SERVICE_LEASE_LEASE_REFERENCE.__doc__
HIAAgentService._lease = _service_lease_lease_dispatch

_service_lease_invoke_dispatch.__name__ = _SERVICE_LEASE_INVOKE_REFERENCE.__name__
_service_lease_invoke_dispatch.__qualname__ = _SERVICE_LEASE_INVOKE_REFERENCE.__qualname__
_service_lease_invoke_dispatch.__doc__ = _SERVICE_LEASE_INVOKE_REFERENCE.__doc__
HIAAgentService.invoke_lease = _service_lease_invoke_dispatch

_service_lease_release_dispatch.__name__ = _SERVICE_LEASE_RELEASE_REFERENCE.__name__
_service_lease_release_dispatch.__qualname__ = _SERVICE_LEASE_RELEASE_REFERENCE.__qualname__
_service_lease_release_dispatch.__doc__ = _SERVICE_LEASE_RELEASE_REFERENCE.__doc__
HIAAgentService.release_slot = _service_lease_release_dispatch


# Complete discovery control. Both retained original bodies above remain
# byte-exact and callable only through the explicit unselected route.
_SERVICE_DISCOVERY_DESCRIBE_REFERENCE = HIAAgentService._hia_describe
_SERVICE_DISCOVERY_EXAMPLES_REFERENCE = HIAAgentService._examples
_SERVICE_DISCOVERY_GLOBAL_BUILTINS = {
    1: _SERVICE_DISCOVERY_DESCRIBE_REFERENCE.__builtins__,
    2: _SERVICE_DISCOVERY_EXAMPLES_REFERENCE.__builtins__,
}
_SERVICE_DISCOVERY_LOCAL_NAMES = {
    1: (_SERVICE_DISCOVERY_DESCRIBE_REFERENCE.__code__.co_varnames
        + _SERVICE_DISCOVERY_DESCRIBE_REFERENCE.__code__.co_cellvars),
    2: (_SERVICE_DISCOVERY_EXAMPLES_REFERENCE.__code__.co_varnames
        + _SERVICE_DISCOVERY_EXAMPLES_REFERENCE.__code__.co_cellvars),
}
# Host loading is private lazy plumbing. Each business import below still
# executes real interpreter opcodes in the original namespace and builtins.
_SERVICE_DISCOVERY_NAMESPACE = _SERVICE_DISCOVERY_DESCRIBE_REFERENCE.__globals__
_SERVICE_DISCOVERY_HOST_IMPORT = _SERVICE_DISCOVERY_DESCRIBE_REFERENCE.__builtins__['__import__']


def _service_discovery_import_describe(self, args):
    from .hia_opcodes import opcode_catalog
    return opcode_catalog


def _service_discovery_import_examples():
    from .hia_agent_assembly import assemble_program, render_assembly
    return assemble_program, render_assembly


_SERVICE_DISCOVERY_IMPORTS = {
    1: _service_discovery_import_describe,
    2: _service_discovery_import_examples,
}
HIAAgentService._hia_describe_reference = _SERVICE_DISCOVERY_DESCRIBE_REFERENCE
HIAAgentService._examples_reference = staticmethod(_SERVICE_DISCOVERY_EXAMPLES_REFERENCE)


def _selected_hia_describe(self, args):
    selector = os.environ.get('HEPTA_HIA_SERVICE_DISCOVERY_MANIFEST')
    if selector is None:
        if (issubclass(type(self), HIAAgentService)
                or 'HEPTA_HIA_AGENT_DISCOVERY_MANIFEST' in os.environ
                or 'HEPTA_HIA_AGENT_DESCRIBE_ANSWER_MANIFEST' in os.environ):
            callee = HIAAgentService._hia_describe_with_components
        else:
            callee = _SERVICE_DISCOVERY_DESCRIBE_REFERENCE
        call = {'callee': callee, 'self': self, 'args': args}
        del self, args
        return call.pop('callee')(call.pop('self'), call.pop('args'))
    native = _SERVICE_DISCOVERY_HOST_IMPORT(
        'hepta.hia_service_discovery_native', None, None,
        ('ServiceDiscoveryFrame', 'installed_service_discovery'), 0)
    frame = native.ServiceDiscoveryFrame(native.installed_service_discovery(selector), 1, self, args)
    del self, args
    return frame.finish()


def _selected_discovery_examples():
    selector = os.environ.get('HEPTA_HIA_SERVICE_DISCOVERY_MANIFEST')
    if selector is None:
        return _SERVICE_DISCOVERY_EXAMPLES_REFERENCE()
    native = _SERVICE_DISCOVERY_HOST_IMPORT(
        'hepta.hia_service_discovery_native', None, None,
        ('ServiceDiscoveryFrame', 'installed_service_discovery'), 0)
    return native.ServiceDiscoveryFrame(native.installed_service_discovery(selector), 2).finish()


_selected_hia_describe.__name__ = _SERVICE_DISCOVERY_DESCRIBE_REFERENCE.__name__
_selected_hia_describe.__qualname__ = _SERVICE_DISCOVERY_DESCRIBE_REFERENCE.__qualname__
_selected_discovery_examples.__name__ = _SERVICE_DISCOVERY_EXAMPLES_REFERENCE.__name__
_selected_discovery_examples.__qualname__ = _SERVICE_DISCOVERY_EXAMPLES_REFERENCE.__qualname__
HIAAgentService._hia_describe = _selected_hia_describe
HIAAgentService._examples = staticmethod(_selected_discovery_examples)


# Complete verification control. Retained original bodies remain source oracles
# and are reached only when this explicit selector is absent.
_SERVICE_VERIFICATION_REFERENCE_1 = HIAAgentService._behavior_equivalence
_SERVICE_VERIFICATION_REFERENCE_2 = HIAAgentService._subject
_SERVICE_VERIFICATION_REFERENCE_3 = HIAAgentService._hia_verify
_SERVICE_VERIFICATION_REFERENCE_4 = HIAAgentService._verification
_SERVICE_VERIFICATION_REFERENCE_5 = HIAAgentService._replay_verification
_SERVICE_VERIFICATION_REFERENCE_6 = HIAAgentService._native_refinement_binding
_SERVICE_VERIFICATION_REFERENCE_7 = HIAAgentService._independent_native_refinement
_SERVICE_VERIFICATION_REFERENCE_8 = HIAAgentService._check_native_refinement_evidence
_SERVICE_VERIFICATION_REFERENCE_9 = HIAAgentService._required_claims
_SERVICE_VERIFICATION_REFERENCES = {
    1: _SERVICE_VERIFICATION_REFERENCE_1,
    2: _SERVICE_VERIFICATION_REFERENCE_2,
    3: _SERVICE_VERIFICATION_REFERENCE_3,
    4: _SERVICE_VERIFICATION_REFERENCE_4,
    5: _SERVICE_VERIFICATION_REFERENCE_5,
    6: _SERVICE_VERIFICATION_REFERENCE_6,
    7: _SERVICE_VERIFICATION_REFERENCE_7,
    8: _SERVICE_VERIFICATION_REFERENCE_8,
    9: _SERVICE_VERIFICATION_REFERENCE_9,
}
_SERVICE_VERIFICATION_GLOBAL_BUILTINS = {
    mode: reference.__builtins__ for mode, reference in _SERVICE_VERIFICATION_REFERENCES.items()}
_SERVICE_VERIFICATION_LOCAL_NAMES = {
    mode: reference.__code__.co_varnames + reference.__code__.co_cellvars
    for mode, reference in _SERVICE_VERIFICATION_REFERENCES.items()}
_SERVICE_VERIFICATION_CELL_NAMES = {
    mode: frozenset(reference.__code__.co_cellvars)
    for mode, reference in _SERVICE_VERIFICATION_REFERENCES.items()}
_SERVICE_VERIFICATION_NAMESPACE = _SERVICE_VERIFICATION_REFERENCE_1.__globals__
_SERVICE_VERIFICATION_HOST_IMPORT = _SERVICE_VERIFICATION_REFERENCE_1.__builtins__['__import__']


def _service_verification_import_behavior_optimization(self, original, revised, timeout_ms):
    from .hia_optimization import PURE, DEFAULT_POLICY, verify_optimization
    return PURE, DEFAULT_POLICY, verify_optimization


def _service_verification_import_behavior_widths(self, original, revised, timeout_ms):
    from .hia_program import WIDTHS, integer_range
    return WIDTHS, integer_range


def _service_verification_import_subject_layout(self, args, program):
    from .hia_program_native import validate_block_layout_plan
    return validate_block_layout_plan


def _service_verification_import_verify_emitter(self, args):
    from .hia_program_native import emit_program_machine
    return emit_program_machine


def _service_verification_import_verify_checks(self, args):
    from .hia_machine_plan import preservation_checks
    return preservation_checks


def _service_verification_import_refinement_safe(self, args, program, context):
    from .hia_safe_core import (ARTIFACT_PROFILE, ARTIFACT_OBLIGATIONS, SafeCoreRejected,
        _profile, _checker_source_identity, validate_safe_core_artifact)
    return ARTIFACT_PROFILE, ARTIFACT_OBLIGATIONS, SafeCoreRejected, _profile, _checker_source_identity, validate_safe_core_artifact


def _service_verification_import_check_elf(self, evidence, subject, context, program):
    from .hia_safe_core_elf import bind_final_artifact
    return bind_final_artifact


_SERVICE_VERIFICATION_IMPORTS = {
    'behavior_optimization': _service_verification_import_behavior_optimization,
    'behavior_widths': _service_verification_import_behavior_widths,
    'subject_layout': _service_verification_import_subject_layout,
    'verify_emitter': _service_verification_import_verify_emitter,
    'verify_checks': _service_verification_import_verify_checks,
    'refinement_safe': _service_verification_import_refinement_safe,
    'check_elf': _service_verification_import_check_elf,
}


def _selected_service_verification_1(self, original, revised, timeout_ms):
    selector = os.environ.get('HEPTA_HIA_SERVICE_VERIFICATION_MANIFEST')
    if selector is None:
        if (issubclass(type(self), HIAAgentService)
                or 'HEPTA_HIA_AGENT_IDENTITY_MANIFEST' in os.environ
                or 'HEPTA_HIA_SCALAR_REFERENCE_MANIFEST' in os.environ
                or 'HEPTA_HIA_SHA256_STREAM_MANIFEST' in os.environ):
            callee = HIAAgentService._behavior_equivalence_with_components
        else:
            callee = _SERVICE_VERIFICATION_REFERENCE_1
        call = {'callee': callee, 'self': self, 'original': original, 'revised': revised, 'timeout_ms': timeout_ms}
        del self, original, revised, timeout_ms
        return call.pop('callee')(call.pop('self'), call.pop('original'), call.pop('revised'), call.pop('timeout_ms'))
    native = _SERVICE_VERIFICATION_HOST_IMPORT(
        'hepta.hia_service_verification_native', None, None,
        ('ServiceVerificationFrame', 'installed_service_verification'), 0)
    frame = native.ServiceVerificationFrame(native.installed_service_verification(selector), 1,
        {'self': self, 'original': original, 'revised': revised, 'timeout_ms': timeout_ms})
    del self, original, revised, timeout_ms
    return frame.finish()

_selected_service_verification_1.__name__ = _SERVICE_VERIFICATION_REFERENCE_1.__name__
_selected_service_verification_1.__qualname__ = _SERVICE_VERIFICATION_REFERENCE_1.__qualname__
_selected_service_verification_1.__doc__ = _SERVICE_VERIFICATION_REFERENCE_1.__doc__
HIAAgentService._behavior_equivalence_reference = _SERVICE_VERIFICATION_REFERENCE_1
HIAAgentService._behavior_equivalence = _selected_service_verification_1


def _selected_service_verification_2(self, args, program):
    selector = os.environ.get('HEPTA_HIA_SERVICE_VERIFICATION_MANIFEST')
    if selector is None:
        if (issubclass(type(self), HIAAgentService)):
            callee = HIAAgentService._subject_with_components
        else:
            callee = _SERVICE_VERIFICATION_REFERENCE_2
        call = {'callee': callee, 'self': self, 'args': args, 'program': program}
        del self, args, program
        return call.pop('callee')(call.pop('self'), call.pop('args'), call.pop('program'))
    native = _SERVICE_VERIFICATION_HOST_IMPORT(
        'hepta.hia_service_verification_native', None, None,
        ('ServiceVerificationFrame', 'installed_service_verification'), 0)
    frame = native.ServiceVerificationFrame(native.installed_service_verification(selector), 2,
        {'self': self, 'args': args, 'program': program})
    del self, args, program
    return frame.finish()

_selected_service_verification_2.__name__ = _SERVICE_VERIFICATION_REFERENCE_2.__name__
_selected_service_verification_2.__qualname__ = _SERVICE_VERIFICATION_REFERENCE_2.__qualname__
_selected_service_verification_2.__doc__ = _SERVICE_VERIFICATION_REFERENCE_2.__doc__
HIAAgentService._subject_reference = _SERVICE_VERIFICATION_REFERENCE_2
HIAAgentService._subject = _selected_service_verification_2


def _selected_service_verification_3(self, args):
    selector = os.environ.get('HEPTA_HIA_SERVICE_VERIFICATION_MANIFEST')
    if selector is None:
        if (issubclass(type(self), HIAAgentService)
                or 'HEPTA_HIA_AGENT_IDENTITY_MANIFEST' in os.environ
                or 'HEPTA_HIA_SHA256_STREAM_MANIFEST' in os.environ
                or 'HEPTA_HIA_SHA256_MANIFEST' in os.environ):
            callee = HIAAgentService._hia_verify_with_components
        else:
            callee = _SERVICE_VERIFICATION_REFERENCE_3
        call = {'callee': callee, 'self': self, 'args': args}
        del self, args
        return call.pop('callee')(call.pop('self'), call.pop('args'))
    native = _SERVICE_VERIFICATION_HOST_IMPORT(
        'hepta.hia_service_verification_native', None, None,
        ('ServiceVerificationFrame', 'installed_service_verification'), 0)
    frame = native.ServiceVerificationFrame(native.installed_service_verification(selector), 3,
        {'self': self, 'args': args})
    del self, args
    return frame.finish()

_selected_service_verification_3.__name__ = _SERVICE_VERIFICATION_REFERENCE_3.__name__
_selected_service_verification_3.__qualname__ = _SERVICE_VERIFICATION_REFERENCE_3.__qualname__
_selected_service_verification_3.__doc__ = _SERVICE_VERIFICATION_REFERENCE_3.__doc__
HIAAgentService._hia_verify_reference = _SERVICE_VERIFICATION_REFERENCE_3
HIAAgentService._hia_verify = _selected_service_verification_3


def _selected_service_verification_4(self, ref, context, candidate=None):
    selector = os.environ.get('HEPTA_HIA_SERVICE_VERIFICATION_MANIFEST')
    if selector is None:
        if (issubclass(type(self), HIAAgentService)
                or 'HEPTA_HIA_AGENT_IDENTITY_MANIFEST' in os.environ):
            callee = HIAAgentService._verification_with_components
        else:
            callee = _SERVICE_VERIFICATION_REFERENCE_4
        call = {'callee': callee, 'self': self, 'ref': ref, 'context': context, 'candidate': candidate}
        del self, ref, context, candidate
        return call.pop('callee')(call.pop('self'), call.pop('ref'), call.pop('context'), call.pop('candidate'))
    native = _SERVICE_VERIFICATION_HOST_IMPORT(
        'hepta.hia_service_verification_native', None, None,
        ('ServiceVerificationFrame', 'installed_service_verification'), 0)
    frame = native.ServiceVerificationFrame(native.installed_service_verification(selector), 4,
        {'self': self, 'ref': ref, 'context': context, 'candidate': candidate})
    del self, ref, context, candidate
    return frame.finish()

_selected_service_verification_4.__name__ = _SERVICE_VERIFICATION_REFERENCE_4.__name__
_selected_service_verification_4.__qualname__ = _SERVICE_VERIFICATION_REFERENCE_4.__qualname__
_selected_service_verification_4.__doc__ = _SERVICE_VERIFICATION_REFERENCE_4.__doc__
HIAAgentService._verification_reference = _SERVICE_VERIFICATION_REFERENCE_4
HIAAgentService._verification = _selected_service_verification_4


def _selected_service_verification_5(self, response, arguments):
    selector = os.environ.get('HEPTA_HIA_SERVICE_VERIFICATION_MANIFEST')
    if selector is None:
        if (issubclass(type(self), HIAAgentService)):
            callee = HIAAgentService._replay_verification_with_components
        else:
            callee = _SERVICE_VERIFICATION_REFERENCE_5
        call = {'callee': callee, 'self': self, 'response': response, 'arguments': arguments}
        del self, response, arguments
        return call.pop('callee')(call.pop('self'), call.pop('response'), call.pop('arguments'))
    native = _SERVICE_VERIFICATION_HOST_IMPORT(
        'hepta.hia_service_verification_native', None, None,
        ('ServiceVerificationFrame', 'installed_service_verification'), 0)
    frame = native.ServiceVerificationFrame(native.installed_service_verification(selector), 5,
        {'self': self, 'response': response, 'arguments': arguments})
    del self, response, arguments
    return frame.finish()

_selected_service_verification_5.__name__ = _SERVICE_VERIFICATION_REFERENCE_5.__name__
_selected_service_verification_5.__qualname__ = _SERVICE_VERIFICATION_REFERENCE_5.__qualname__
_selected_service_verification_5.__doc__ = _SERVICE_VERIFICATION_REFERENCE_5.__doc__
HIAAgentService._replay_verification_reference = _SERVICE_VERIFICATION_REFERENCE_5
HIAAgentService._replay_verification = _selected_service_verification_5


def _selected_service_verification_6(subject, built, program, object_bytes, final_bytes):
    selector = os.environ.get('HEPTA_HIA_SERVICE_VERIFICATION_MANIFEST')
    if selector is None:
        if ('HEPTA_HIA_SHA256_STREAM_MANIFEST' in os.environ
                or 'HEPTA_HIA_SHA256_MANIFEST' in os.environ):
            callee = HIAAgentService._native_refinement_binding_with_components
        else:
            callee = _SERVICE_VERIFICATION_REFERENCE_6
        call = {'callee': callee, 'subject': subject, 'built': built, 'program': program, 'object_bytes': object_bytes, 'final_bytes': final_bytes}
        del subject, built, program, object_bytes, final_bytes
        return call.pop('callee')(call.pop('subject'), call.pop('built'), call.pop('program'), call.pop('object_bytes'), call.pop('final_bytes'))
    native = _SERVICE_VERIFICATION_HOST_IMPORT(
        'hepta.hia_service_verification_native', None, None,
        ('ServiceVerificationFrame', 'installed_service_verification'), 0)
    frame = native.ServiceVerificationFrame(native.installed_service_verification(selector), 6,
        {'subject': subject, 'built': built, 'program': program, 'object_bytes': object_bytes, 'final_bytes': final_bytes})
    del subject, built, program, object_bytes, final_bytes
    return frame.finish()

_selected_service_verification_6.__name__ = _SERVICE_VERIFICATION_REFERENCE_6.__name__
_selected_service_verification_6.__qualname__ = _SERVICE_VERIFICATION_REFERENCE_6.__qualname__
_selected_service_verification_6.__doc__ = _SERVICE_VERIFICATION_REFERENCE_6.__doc__
HIAAgentService._native_refinement_binding_reference = staticmethod(_SERVICE_VERIFICATION_REFERENCE_6)
HIAAgentService._native_refinement_binding = staticmethod(_selected_service_verification_6)


def _selected_service_verification_7(self, args, program, context):
    selector = os.environ.get('HEPTA_HIA_SERVICE_VERIFICATION_MANIFEST')
    if selector is None:
        if (issubclass(type(self), HIAAgentService)
                or 'HEPTA_HIA_SHA256_STREAM_MANIFEST' in os.environ
                or 'HEPTA_HIA_SHA256_MANIFEST' in os.environ):
            callee = HIAAgentService._independent_native_refinement_with_components
        else:
            callee = _SERVICE_VERIFICATION_REFERENCE_7
        call = {'callee': callee, 'self': self, 'args': args, 'program': program, 'context': context}
        del self, args, program, context
        return call.pop('callee')(call.pop('self'), call.pop('args'), call.pop('program'), call.pop('context'))
    native = _SERVICE_VERIFICATION_HOST_IMPORT(
        'hepta.hia_service_verification_native', None, None,
        ('ServiceVerificationFrame', 'installed_service_verification'), 0)
    frame = native.ServiceVerificationFrame(native.installed_service_verification(selector), 7,
        {'self': self, 'args': args, 'program': program, 'context': context})
    del self, args, program, context
    return frame.finish()

_selected_service_verification_7.__name__ = _SERVICE_VERIFICATION_REFERENCE_7.__name__
_selected_service_verification_7.__qualname__ = _SERVICE_VERIFICATION_REFERENCE_7.__qualname__
_selected_service_verification_7.__doc__ = _SERVICE_VERIFICATION_REFERENCE_7.__doc__
HIAAgentService._independent_native_refinement_reference = _SERVICE_VERIFICATION_REFERENCE_7
HIAAgentService._independent_native_refinement = _selected_service_verification_7


def _selected_service_verification_8(self, evidence, subject, context, program):
    selector = os.environ.get('HEPTA_HIA_SERVICE_VERIFICATION_MANIFEST')
    if selector is None:
        if (issubclass(type(self), HIAAgentService)
                or 'HEPTA_HIA_SHA256_STREAM_MANIFEST' in os.environ
                or 'HEPTA_HIA_SHA256_MANIFEST' in os.environ):
            callee = HIAAgentService._check_native_refinement_evidence_with_components
        else:
            callee = _SERVICE_VERIFICATION_REFERENCE_8
        call = {'callee': callee, 'self': self, 'evidence': evidence, 'subject': subject, 'context': context, 'program': program}
        del self, evidence, subject, context, program
        return call.pop('callee')(call.pop('self'), call.pop('evidence'), call.pop('subject'), call.pop('context'), call.pop('program'))
    native = _SERVICE_VERIFICATION_HOST_IMPORT(
        'hepta.hia_service_verification_native', None, None,
        ('ServiceVerificationFrame', 'installed_service_verification'), 0)
    frame = native.ServiceVerificationFrame(native.installed_service_verification(selector), 8,
        {'self': self, 'evidence': evidence, 'subject': subject, 'context': context, 'program': program})
    del self, evidence, subject, context, program
    return frame.finish()

_selected_service_verification_8.__name__ = _SERVICE_VERIFICATION_REFERENCE_8.__name__
_selected_service_verification_8.__qualname__ = _SERVICE_VERIFICATION_REFERENCE_8.__qualname__
_selected_service_verification_8.__doc__ = _SERVICE_VERIFICATION_REFERENCE_8.__doc__
HIAAgentService._check_native_refinement_evidence_reference = _SERVICE_VERIFICATION_REFERENCE_8
HIAAgentService._check_native_refinement_evidence = _selected_service_verification_8


def _selected_service_verification_9(self, context, candidate_artifact, refs, baseline_core_sha=None):
    selector = os.environ.get('HEPTA_HIA_SERVICE_VERIFICATION_MANIFEST')
    if selector is None:
        if (issubclass(type(self), HIAAgentService)
                or 'HEPTA_HIA_AGENT_IDENTITY_MANIFEST' in os.environ):
            callee = HIAAgentService._required_claims_with_components
        else:
            callee = _SERVICE_VERIFICATION_REFERENCE_9
        call = {'callee': callee, 'self': self, 'context': context, 'candidate_artifact': candidate_artifact, 'refs': refs, 'baseline_core_sha': baseline_core_sha}
        del self, context, candidate_artifact, refs, baseline_core_sha
        return call.pop('callee')(call.pop('self'), call.pop('context'), call.pop('candidate_artifact'), call.pop('refs'), call.pop('baseline_core_sha'))
    native = _SERVICE_VERIFICATION_HOST_IMPORT(
        'hepta.hia_service_verification_native', None, None,
        ('ServiceVerificationFrame', 'installed_service_verification'), 0)
    frame = native.ServiceVerificationFrame(native.installed_service_verification(selector), 9,
        {'self': self, 'context': context, 'candidate_artifact': candidate_artifact, 'refs': refs, 'baseline_core_sha': baseline_core_sha})
    del self, context, candidate_artifact, refs, baseline_core_sha
    return frame.finish()

_selected_service_verification_9.__name__ = _SERVICE_VERIFICATION_REFERENCE_9.__name__
_selected_service_verification_9.__qualname__ = _SERVICE_VERIFICATION_REFERENCE_9.__qualname__
_selected_service_verification_9.__doc__ = _SERVICE_VERIFICATION_REFERENCE_9.__doc__
HIAAgentService._required_claims_reference = _SERVICE_VERIFICATION_REFERENCE_9
HIAAgentService._required_claims = _selected_service_verification_9


# Complete bootstrap/lifecycle/profile HIA owner. Retained definitions above
# remain byte-exact and are the sole unselected route.
import builtins as _service_bootstrap_builtins
import importlib as _service_bootstrap_importlib
import os as _service_bootstrap_os
_SERVICE_BOOTSTRAP_ITER = _service_bootstrap_builtins.iter
_SERVICE_BOOTSTRAP_BASE_EXCEPTION = _service_bootstrap_builtins.BaseException
_SERVICE_BOOTSTRAP_LOADER = _service_bootstrap_importlib.import_module
_SERVICE_BOOTSTRAP_REFERENCES = {
    1: HIAAgentService.__init__, 2: HIAAgentService.close,
    3: HIAAgentService._profiles, 4: HIAAgentService._profile,
    5: HIAAgentService._program,
}
_SERVICE_BOOTSTRAP_GLOBAL_BUILTINS = HIAAgentService.__init__.__builtins__
_SERVICE_BOOTSTRAP_LOCAL_LAYOUTS = {
    mode: method.__code__.co_varnames for mode, method in _SERVICE_BOOTSTRAP_REFERENCES.items()
}
def _service_bootstrap_literal_init_import_candidate(self, state_root, artifact_roots):
    from .hia_candidate_budget_native import selected_candidate_budget, NativeCandidateBudgetStore
    return (selected_candidate_budget, NativeCandidateBudgetStore)

def _service_bootstrap_literal_init_import_slot(self, state_root, artifact_roots, selected_candidate_budget, NativeCandidateBudgetStore):
    from .hia_slot_ledger_native import selected_slot_ledger, NativeSlotLedgerStore
    return (selected_slot_ledger, NativeSlotLedgerStore)

def _service_bootstrap_literal_init_catalog(self):
    self.catalog, self.catalog_sha256 = catalog()

def _service_bootstrap_literal_init_tools_iter(self):
    return _SERVICE_BOOTSTRAP_ITER(self.catalog['tools'])

def _service_bootstrap_literal_init_tools_put(result, t):
    try:
        result[t['name']] = t
    finally:
        # These are borrowed operands of the inline comprehension. A failed
        # lookup must not keep its temporary result in this capsule traceback.
        del result, t

def _service_bootstrap_literal_init_identities(self):
    self.identities = installation_manifest()

def _service_bootstrap_literal_init_store(self, state_root):
    self.store = AgentStore(state_root)

def _service_bootstrap_literal_init_budget_construct(self, NativeCandidateBudgetStore, candidate_budget_image):
    self._candidate_budget = NativeCandidateBudgetStore(self.store, candidate_budget_image)

def _service_bootstrap_literal_init_ledger_construct(self, NativeSlotLedgerStore, slot_ledger_image):
    self._slot_ledger = NativeSlotLedgerStore(self.store, slot_ledger_image)

def _service_bootstrap_literal_init_roots(self, artifact_roots, _make, _mode):
    self.artifact_roots = tuple(_make(_mode, _SERVICE_BOOTSTRAP_ITER(artifact_roots)))

def _service_bootstrap_literal_init_roots_invalid(self, _make, _mode):
    return 1 if any(_make(_mode, _SERVICE_BOOTSTRAP_ITER(self.artifact_roots))) else 0

def _service_bootstrap_literal_init_reject_roots():
    reject('E_HIA_PROFILE', 'configured artifact roots must be directories')

def _service_bootstrap_literal_init_profiles(self):
    self._profiles()

def _service_bootstrap_literal_init_cleanup_budget_bound(self):
    return [self._candidate_budget.close]

def _service_bootstrap_literal_init_cleanup_list(self, cleanups):
    return _SERVICE_BOOTSTRAP_ITER([*cleanups, self.store.close])

def _service_bootstrap_literal_init_cleanup_note(error, failure):
    error.add_note('service construction cleanup failed: ' + type(failure).__name__)

def _service_bootstrap_literal_close_budget_call(self):
    self._candidate_budget.close()

def _service_bootstrap_literal_close_store(self):
    self.store.close()

def _service_bootstrap_literal_profiles_import_program(self):
    from .hia_program_native import TARGET, PROFILE, SUPPORTED_OPCODES, CORE_SCHEMAS, IMPORTS
    return (TARGET, PROFILE, SUPPORTED_OPCODES, CORE_SCHEMAS, IMPORTS)

def _service_bootstrap_literal_profiles_import_schema(self, TARGET, PROFILE, SUPPORTED_OPCODES, CORE_SCHEMAS, IMPORTS):
    from .hia_schema import schema_registry
    return schema_registry

def _service_bootstrap_literal_profiles_import_safe(self, TARGET, PROFILE, SUPPORTED_OPCODES, CORE_SCHEMAS, IMPORTS, schema_registry):
    from .hia_safe_core import ARTIFACT_PROFILE, LIMITS
    return (ARTIFACT_PROFILE, LIMITS)

def _service_bootstrap_literal_profiles_common(self):
    return {'implementation': self.identities, 'catalog_sha256': self.catalog_sha256}

def _service_bootstrap_literal_profiles_bodies_expression(self, common, TARGET, PROFILE, CORE_SCHEMAS, SUPPORTED_OPCODES, IMPORTS, ARTIFACT_PROFILE, LIMITS):
    """One suspension replaces only the inlined path-root list comprehension."""
    try:
        _outcome = (1, {'compiler': {**common, 'schema': 'hepta.hia.agent.compiler-profile.v1', 'backend': 'hia-direct', 'implicit_profitability_optimizer': False, 'llvm_codegen': False, 'external_assembler': False}, 'target': {'schema': 'hepta.hia.agent.target-profile.v1', 'triple': TARGET, 'isa': 'x86-64', 'abi': 'SysV AMD64 LP64 scalar entries; opt-in synchronous borrowed-byte snapshots', 'operating_system': 'Linux', 'max_memory_bytes': str(4 * 1024 ** 3), 'min_memory_bytes': str(64 * 1024 ** 2), 'features': ['baseline-x86-64']}, 'backend': {**common, 'schema': 'hepta.hia.agent.backend-profile.v1', 'profile': PROFILE, 'target': TARGET, 'core_schemas': sorted(CORE_SCHEMAS), 'opcodes': sorted(SUPPORTED_OPCODES), 'runtime_imports': sorted(IMPORTS), 'external_abi': 'v1 integer/bool scalar inputs and at most one scalar/unit result; v2 explicit readbuf/mutbuf snapshots and one u32 result', 'borrowed_byte_snapshots': {'workload_schema': 'hepta.hia.agent.workload.v2', 'profile': 'hepta.hia.agent.borrowed-byte-snapshots.v1', 'max_buffer_bytes': 1048576, 'max_workload_buffer_bytes': 33554432, 'pointer_authority': 'child-owned distinct synchronous allocations; caller supplies bytes only', 'observation': 'all external bytes on return and confirmed abort; fresh initial bytes on every repetition', 'reference_limits': {'max_steps': 10000000, 'max_heap_bytes': 16777216, 'max_call_depth': 256}, 'independent_native_refinement': 'unsupported'}, 'max_stack_frame_bytes': 65536, 'max_exports': 128, 'object_emission_external_tool': False, 'shared_linker': 'GNU ld only', 'native_resource_limits': 'disposable child wall/CPU/address-space limits; no VM tick guarantee', 'universal_backend_refinement_proved': False, 'self_hosted': False}, 'artifact': {'schema': 'hepta.hia.agent.artifact-profile.v1', 'inline_utf8_characters': 65536, 'max_path_bytes': 8 * 1024 ** 2, 'path_root_count': len(self.artifact_roots), 'path_roots_sha256': digest((yield self.artifact_roots)), 'symlink_capture': False, 'path_authority': 'administrator configured roots only'}, 'validation': {**common, 'schema': 'hepta.hia.agent.validation-profile.v1', 'core_admission': 'existing whole-program verifier', 'behavior_equivalence': ['exact Core identity', 'exhaustive pure acyclic scalar domain with at most 12 input bits', 'optional existing pinned-Z3 structural scalar/effect profile'], 'canonical_core_to_machine_refinement': 'unsupported', 'independent_native_refinement': {'method': SAFE_CORE_METHOD, 'profile': SAFE_CORE_SERVICE_PROFILE, 'artifact_profile': ARTIFACT_PROFILE, 'output_kind': 'shared', 'entry_abi': 'one unsigned scalar acyclic function; no borrowed or foreign entries', 'foreign_buffer_exports': [], 'limits': dict(LIMITS), 'inputs': 'the exact retained build object, final ELF and canonical Core; no reemission', 'proof_scope': SAFE_CORE_DOMAIN}, 'machine_plan_refinement': 'separately checked layout, scratch-register, scalar register-lifetime and exact encoding choices relative to assumed-correct canonical lowering', 'encoding_check': 'rederive entire object and linked image; validate retained identities and ABI', 'sample_tests_are_proofs': False, 'proof_result_schema': PROOF_SCHEMA, 'proved_meaning': PROVED_MEANING, 'unscoped_legacy_receipts_accepted': False}, 'lowering': {**common, 'schema': 'hepta.hia.agent.lowering-profile.v1', 'rules': 'fixed stack slots; fixed scratch registers; source block order; explicit control transfers', 'selection_authority': 'semantic implementation only', 'profitability_passes': []}, 'plan': {**common, 'schema': 'hepta.hia.agent.plan-profile.v1', 'plan_schema': PLAN_SCHEMA, 'choices': 'v1 block permutation; v2 block/function permutation, r10/r11 bijection, exact immediate encodings and bounded function alignment; v3 checked scalar assignments to rbx/r12-r15 and explicit register-only CMOV selection', 'preserved': ['original Core', 'checked scalar value locations', 'logical operation and effect order within each block', 'entry and CFG edges', 'public ABI'], 'unchecked_bytes': False, 'automatic_layout_search': False}})
    except _SERVICE_BOOTSTRAP_BASE_EXCEPTION as _error:
        return (0, _error)
    return _outcome

def _service_bootstrap_literal_profiles_root_string(root):
    return str(root)

def _service_bootstrap_literal_profiles_dicts(self):
    self.profiles, self.profile_artifacts = ({}, {})

def _service_bootstrap_literal_profiles_profile(self, name, body):
    return self.store.profile('hia-' + name + '-v1', body)

def _service_bootstrap_literal_profiles_assign(self, name, ref, artifact):
    self.profiles[name], self.profile_artifacts[name] = (ref, artifact)

def _service_bootstrap_literal_profiles_resources(self, schema_registry):
    self.resources = {'schema_registry': self.store.json(schema_registry(), 'discovery'), 'workload_schema': self.store.json(WORKLOAD_SCHEMA, 'discovery'), 'objective_schema': self.store.json(OBJECTIVE_SCHEMA, 'discovery'), 'cost_policy_schema': self.store.json(COST_POLICY_SCHEMA, 'discovery'), 'plan_schema': self.store.json(PLAN_SCHEMA, 'discovery'), 'proof_contract': self.store.json(proof_contract_description(), 'discovery')}

def _service_bootstrap_literal_profiles_docs_iter():
    return _SERVICE_BOOTSTRAP_ITER((('assembly_grammar', 'HIA_AGENT_ASSEMBLY.md'), ('core_language', 'HIA_PROGRAM.md'), ('machine_plan_guide', 'HIA_AGENT_MACHINE_PLANS.md'), ('proof_contract_guide', 'HIA_AGENT_PROOF_RESULTS.md'), ('machine_validation_guide', 'HIA_SAFE_CORE_MACHINE_VALIDATION.md'), ('buffer_lifecycle_guide', 'HIA_AGENT_BUFFER_LIFECYCLE.md'), ('macro_policy_guide', 'HIA_AGENT_MACRO_POLICY.md'), ('byte_bootstrap_guide', 'HIA_DIRECT_BYTE_BOOTSTRAP.md'), ('self_hosting_core_guide', 'HIA_SELF_HOSTING_CORE.md'), ('self_hosting_core_support', 'HIA_SELFHOST_CORE_SUPPORT.json')))

def _service_bootstrap_literal_profiles_doc_store(self, name, filename):
    self.resources[name] = self.store.put(_agent_resource_path('docs/' + filename).read_bytes(), 'discovery')

def _service_bootstrap_literal_profiles_import_macro(self, TARGET, PROFILE, SUPPORTED_OPCODES, CORE_SCHEMAS, IMPORTS, schema_registry, ARTIFACT_PROFILE, LIMITS, common, bodies, name, body, ref, artifact, filename):
    from .hia_agent_macro_discovery import macro_policy_guidance
    return macro_policy_guidance

def _service_bootstrap_literal_profiles_macro(self, macro_policy_guidance):
    self.resources['macro_policy'] = self.store.json(macro_policy_guidance(self.identities), 'discovery')

def _service_bootstrap_literal_profiles_examples(self):
    self.resources['examples'] = self.store.json(self._examples(), 'discovery')

def _service_bootstrap_literal_profiles_diagnostics(self):
    self.resources['diagnostics'] = self.store.json({'schema': 'hepta.hia.agent.diagnostics.v1', 'phases': ['admission', 'context', 'verification', 'codegen', 'execution', 'adoption'], 'codes': {'E_HIA_SCHEMA': 'repair the named input field', 'E_HIA_CONTEXT_STALE': 'rediscover installed source and create a new context', 'E_HIA_REQUEST_CONFLICT': 'same key belongs to different arguments', 'E_HIA_REQUEST_UNKNOWN': 'observe the original runtime job; never relaunch', 'E_HIA_ARTIFACT_IDENTITY': 'use the complete issued reference', 'E_HIA_MACHINE_PLAN': 'read plan_schema and supply only checked Core-bound machine choices', 'E_HIA_CLAIM_REQUIRED': 'requested acceptance proof has no exact qualifying retained receipt', 'E_HIA_PROOF_SCOPE': 'rerun verification with a fresh request key; proof scope or retained checker conclusion is missing or differs', 'E_HIA_GENERATION_STALE': 'inspect current slot through the authorized consumer; use a fresh conditional request'}}, 'discovery')

def _service_bootstrap_literal_profiles_manifest(self):
    self.manifest = self.store.json({'schema': 'hepta.hia.agent.manifest.v1', 'status': 'implemented_bounded_profiles', 'catalog_sha256': self.catalog_sha256, 'installation': self.identities, 'profiles': self.profiles, 'profile_manifests': self.profile_artifacts, 'resources': self.resources, 'cold_start': ['read assembly_grammar/core_language and an exact opcode catalog', 'retain workload, objective and cost-policy JSON as artifacts', 'freeze context using discovered profiles', 'import or patch an explicit Core candidate', 'verify requested claims for the exact subject', 'emit using canonical lowering or a checked explicit machine plan', 'verify actual encoding and, when admitted, independent native refinement', 'evaluate baseline and candidate on the entire frozen workload', 'adopt only with qualifying receipts and expected generation/epoch'], 'execution_authority': 'administrator-installed runtime provider, never supplied context', 'cold_start_learning_or_net_benefit_proved': False, 'consumer_api': 'HIAAgentService.acquire_slot/invoke_lease/release_slot', 'initial_slot': 'expected 0/0 retains the evaluation baseline at generation 0; candidate starts generation 1', 'unknown_external_costs': 'null and incomplete, never inferred as zero'}, 'discovery')

def _service_bootstrap_literal_profile_result(self, ref, name):
    return self.store.check_profile(ref, self.profiles[name])

def _service_bootstrap_literal_program_get(self, ref):
    return self.store.get(ref)

def _service_bootstrap_literal_program_verify(data):
    return verify_program(decode_json(data))

def _service_bootstrap_literal_generator_root_value(root):
    return Path(root).absolute().resolve(strict=True)

def _service_bootstrap_literal_generator_dir_value(root):
    return not root.is_dir()

_SERVICE_BOOTSTRAP_IMPORT_PORTS = {
    'init_import_candidate': _service_bootstrap_literal_init_import_candidate,
    'init_import_slot': _service_bootstrap_literal_init_import_slot,
    'init_catalog': _service_bootstrap_literal_init_catalog,
    'init_tools_iter': _service_bootstrap_literal_init_tools_iter,
    'init_tools_put': _service_bootstrap_literal_init_tools_put,
    'init_identities': _service_bootstrap_literal_init_identities,
    'init_store': _service_bootstrap_literal_init_store,
    'init_budget_construct': _service_bootstrap_literal_init_budget_construct,
    'init_ledger_construct': _service_bootstrap_literal_init_ledger_construct,
    'init_roots': _service_bootstrap_literal_init_roots,
    'init_roots_invalid': _service_bootstrap_literal_init_roots_invalid,
    'init_reject_roots': _service_bootstrap_literal_init_reject_roots,
    'init_profiles': _service_bootstrap_literal_init_profiles,
    'init_cleanup_budget_bound': _service_bootstrap_literal_init_cleanup_budget_bound,
    'init_cleanup_list': _service_bootstrap_literal_init_cleanup_list,
    'init_cleanup_note': _service_bootstrap_literal_init_cleanup_note,
    'close_budget_call': _service_bootstrap_literal_close_budget_call,
    'close_store': _service_bootstrap_literal_close_store,
    'profiles_import_program': _service_bootstrap_literal_profiles_import_program,
    'profiles_import_schema': _service_bootstrap_literal_profiles_import_schema,
    'profiles_import_safe': _service_bootstrap_literal_profiles_import_safe,
    'profiles_common': _service_bootstrap_literal_profiles_common,
    'profiles_bodies_expression': _service_bootstrap_literal_profiles_bodies_expression,
    'profiles_root_string': _service_bootstrap_literal_profiles_root_string,
    'profiles_dicts': _service_bootstrap_literal_profiles_dicts,
    'profiles_profile': _service_bootstrap_literal_profiles_profile,
    'profiles_assign': _service_bootstrap_literal_profiles_assign,
    'profiles_resources': _service_bootstrap_literal_profiles_resources,
    'profiles_docs_iter': _service_bootstrap_literal_profiles_docs_iter,
    'profiles_doc_store': _service_bootstrap_literal_profiles_doc_store,
    'profiles_import_macro': _service_bootstrap_literal_profiles_import_macro,
    'profiles_macro': _service_bootstrap_literal_profiles_macro,
    'profiles_examples': _service_bootstrap_literal_profiles_examples,
    'profiles_diagnostics': _service_bootstrap_literal_profiles_diagnostics,
    'profiles_manifest': _service_bootstrap_literal_profiles_manifest,
    'profile_result': _service_bootstrap_literal_profile_result,
    'program_get': _service_bootstrap_literal_program_get,
    'program_verify': _service_bootstrap_literal_program_verify,
    'generator_root_value': _service_bootstrap_literal_generator_root_value,
    'generator_dir_value': _service_bootstrap_literal_generator_dir_value,
}

def _service_bootstrap_dispatch___init__(self, state_root, *, artifact_roots=(), native_store=None,
                                         native_edit_query=None, native_candidate_import=None):
    selected = _service_bootstrap_os.environ.get('HEPTA_HIA_SERVICE_BOOTSTRAP_MANIFEST')
    arguments = {'self': self, 'state_root': state_root, 'artifact_roots': artifact_roots}
    native_options = {'native_store': native_store, 'native_edit_query': native_edit_query,
                      'native_candidate_import': native_candidate_import}
    if selected is None:
        callee = _SERVICE_BOOTSTRAP_REFERENCES[1]
        if any(value is not None for value in native_options.values()):
            arguments.update(native_options)
        del self, state_root, artifact_roots, native_store, native_edit_query, native_candidate_import, native_options
        return callee(arguments.pop('self'), arguments.pop('state_root'), **arguments)
    if not selected:
        raise ValueError('service bootstrap selector must not be empty')
    adapter = _SERVICE_BOOTSTRAP_LOADER('hepta.hia_service_bootstrap_native')
    frame = adapter.ServiceBootstrapFrame(adapter.installed_service_bootstrap(selected), 1, arguments,
                                          service_options=native_options)
    del self, state_root, artifact_roots, native_store, native_edit_query, native_candidate_import, native_options
    return frame.finish()

HIAAgentService.__init__ = _service_bootstrap_dispatch___init__

def _service_bootstrap_dispatch_close(self):
    selected = _service_bootstrap_os.environ.get('HEPTA_HIA_SERVICE_BOOTSTRAP_MANIFEST')
    if selected is None:
        arguments = {'callee': _SERVICE_BOOTSTRAP_REFERENCES[2], 'self': self}
        del self
        return arguments.pop('callee')(arguments.pop('self'))
    adapter = _SERVICE_BOOTSTRAP_LOADER('hepta.hia_service_bootstrap_native')
    frame = adapter.ServiceBootstrapFrame(adapter.installed_service_bootstrap(selected), 2, {'self': self})
    del self
    return frame.finish()

HIAAgentService.close = _service_bootstrap_dispatch_close

def _service_bootstrap_dispatch__profiles(self):
    selected = _service_bootstrap_os.environ.get('HEPTA_HIA_SERVICE_BOOTSTRAP_MANIFEST')
    if selected is None:
        arguments = {'callee': _SERVICE_BOOTSTRAP_REFERENCES[3], 'self': self}
        del self
        return arguments.pop('callee')(arguments.pop('self'))
    if not selected:
        raise ValueError('service bootstrap selector must not be empty')
    adapter = _SERVICE_BOOTSTRAP_LOADER('hepta.hia_service_bootstrap_native')
    image = adapter.installed_service_bootstrap(selected)
    if 'HEPTA_HIA_AGENT_DISCOVERY_MANIFEST' in _service_bootstrap_os.environ:
        return _SERVICE_BOOTSTRAP_REFERENCES[3](self)
    frame = adapter.ServiceBootstrapFrame(image, 3, {'self': self})
    del self
    return frame.finish()

HIAAgentService._profiles = _service_bootstrap_dispatch__profiles

def _service_bootstrap_dispatch__profile(self, ref, name):
    selected = _service_bootstrap_os.environ.get('HEPTA_HIA_SERVICE_BOOTSTRAP_MANIFEST')
    if selected is None:
        arguments = {'callee': _SERVICE_BOOTSTRAP_REFERENCES[4], 'self': self, 'ref': ref, 'name': name}
        del self, ref, name
        return arguments.pop('callee')(arguments.pop('self'), arguments.pop('ref'), arguments.pop('name'))
    adapter = _SERVICE_BOOTSTRAP_LOADER('hepta.hia_service_bootstrap_native')
    frame = adapter.ServiceBootstrapFrame(adapter.installed_service_bootstrap(selected), 4, {'self': self, 'ref': ref, 'name': name})
    del self, ref, name
    return frame.finish()

HIAAgentService._profile = _service_bootstrap_dispatch__profile

def _service_bootstrap_dispatch__program(self, ref):
    selected = _service_bootstrap_os.environ.get('HEPTA_HIA_SERVICE_BOOTSTRAP_MANIFEST')
    if selected is None:
        arguments = {'callee': _SERVICE_BOOTSTRAP_REFERENCES[5], 'self': self, 'ref': ref}
        del self, ref
        return arguments.pop('callee')(arguments.pop('self'), arguments.pop('ref'))
    adapter = _SERVICE_BOOTSTRAP_LOADER('hepta.hia_service_bootstrap_native')
    frame = adapter.ServiceBootstrapFrame(adapter.installed_service_bootstrap(selected), 5, {'self': self, 'ref': ref})
    del self, ref
    return frame.finish()

HIAAgentService._program = _service_bootstrap_dispatch__program
