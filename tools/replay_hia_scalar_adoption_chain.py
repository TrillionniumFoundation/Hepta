#!/usr/bin/env python3
"""Reconstruct a v2 scalar artifact chain and recheck its original immutable bytes.

No service, compiler, native loader or adoption action is started by this reader.
Fresh model checks and saved-query replay remain distinct from recorded owner
calls. A selected manifest identifies evidence; it is not execution authority.
Historical v1 packets need the explicit --legacy-query-only mode.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path, PurePosixPath
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

TYPES = ("u8", "u32", "u64", "usize")
REQUIRED_CLAIMS = ("core_admission", "behavior_equivalence", "encoding_check", "lowering_refinement")
REQUIRED_PROFILES = {"compiler", "target", "backend", "artifact", "validation", "lowering", "plan"}
SPECIFICATION_OBLIGATIONS = (
    ("unsigned_input_domain_nonvacuous", "sat"),
    ("core_always_returns_and_preserves_caller_bytes", "unsat"),
    ("core_equals_unbounded_sum_capped_at_limit", "unsat"),
)
MACHINE_OBLIGATIONS = (
    ("caller_contract_nonvacuous", "sat"),
    ("machine_memory_access_bounds", "unsat"),
    ("sysv_stack_alignment_and_preservation", "unsat"),
    ("all_inputs_reach_a_terminal_model_outcome", "unsat"),
    ("core_to_final_image_return_abort_and_caller_bytes", "unsat"),
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


class Packet:
    """Read the selected manifest once and retain the exact hashed file bytes."""

    def __init__(self, source, expected_manifest_sha256):
        source = Path(source).resolve(strict=True)
        manifest_bytes = (source / "original-files.json").read_bytes()
        require(sha256(manifest_bytes).hexdigest() == expected_manifest_sha256, "selected manifest differs")
        manifest = json.loads(manifest_bytes)
        require(type(manifest) is list and 1 <= len(manifest) <= 2048, "manifest inventory bound")
        self.files = {}
        total = 0
        for row in manifest:
            name = row["path"]
            require(type(name) is str, "manifest member name must be text")
            path = PurePosixPath(name)
            require(name == str(path) and not path.is_absolute() and path.parts
                    and all(part not in {".", ".."} for part in path.parts)
                    and name not in self.files, "noncanonical or duplicate manifest member")
            requested = source
            for part in path.parts:
                requested /= part
                require(not requested.is_symlink(), "symlink in artifact path")
            require(requested.is_file() and requested.stat().st_size <= 16 * 1024**2,
                    "artifact path or size")
            content = requested.read_bytes()
            total += len(content)
            require(total <= 128 * 1024**2, "packet exceeds the complete-read byte budget")
            require(len(content) == row["bytes"] and sha256(content).hexdigest() == row["sha256"],
                    "retained artifact bytes differ: " + name)
            self.files[name] = content
        self.manifest_sha256 = expected_manifest_sha256
        self.total_bytes = total

    def read(self, name):
        require(name in self.files, "unmanifested evidence: " + name)
        return self.files[name]

    def json(self, name):
        return json.loads(self.read(name))

    def artifact(self, family, name, expected=None):
        require(name in family["exports"] and PurePosixPath(name).name == name,
                "missing exported original artifact: " + name)
        reference = family["exports"][name]
        require(type(reference) is dict and set(reference) == {"id", "sha256", "uri"}
                and all(type(value) is str and value for value in reference.values()),
                "invalid original artifact reference")
        if expected is not None:
            require(reference == expected, "original artifact reference differs: " + name)
        data = self.read(family["type"] + "/" + name)
        require(sha256(data).hexdigest() == reference["sha256"], "artifact digest differs: " + name)
        return json.loads(data) if name.endswith(".json") else data

    def reference(self, family, reference):
        names = [name for name, actual in family["exports"].items() if actual == reference]
        require(names, "receipt dependency lacks original exported bytes")
        values = [self.artifact(family, name, reference) for name in names]
        require(all(value == values[0] for value in values), "aliased artifact observations differ")
        return values[0]


def _query_inventory(rows, expected):
    require(type(rows) is list and tuple((q["name"], q["expected"]) for q in rows) == expected,
            "proof obligation inventory differs")
    require(all(q["result"] == q["expected"] for q in rows), "recorded proof was not complete")


def _check_proof(packet, family, filename, claims, subject, context, installation):
    from hepta.hia_proof_contract import proof_subject, proof_result, assumptions_document

    record = packet.artifact(family, filename)
    require(record["schema"] == "hepta.hia.agent.verification.v1"
            and record["candidate"] == family["candidate"]
            and record["candidate_core_sha256"] == family["candidate"]["sha256"]
            and record["context"] == family["context"] and record["installation"] == installation
            and record["validation_profile"] == packet.artifact(family, "installation-manifest.json")["profiles"]["validation"]
            and record["subject"] == subject
            and tuple(check["claim"] for check in record["checks"]) == claims,
            "proof receipt does not describe the selected chain: " + filename)
    expected_subject = proof_subject(record, context["target_profile"])
    for check in record["checks"]:
        require(check["status"] == "proved" and check["subject"] == expected_subject,
                "proof conclusion or complete subject differs")
        evidence = packet.reference(family, check["evidence_artifact"])
        expected = proof_result(claim=check["claim"], status="proved", domain=check["domain"],
            subject=expected_subject, profile=record["validation_profile"],
            installation=installation, evidence=evidence)
        require(all(check.get(key) == value for key, value in expected.items())
                and evidence["proof_binding"] == expected,
                "proof scope differs from its retained checker evidence")
        require(packet.reference(family, check["assumptions_artifact"]) == assumptions_document(expected),
                "proof assumptions differ from the complete scoped result")
    return record


def _check_journal(packet, family, context, evaluation, adoption, rollback):
    events = [json.loads(line) for line in packet.read(family["type"] + "/calls.jsonl").splitlines()]
    require(len(events) == 2 * family["tool_call_count"], "tool journal is incomplete")
    responses = []
    request_keys = set()
    for index in range(0, len(events), 2):
        intent, response = events[index:index + 2]
        require(intent["phase"] == "intent" and response["phase"] == "response"
                and intent["sequence"] == response["sequence"] == index // 2 + 1
                and intent["tool"] == response["tool"] and intent["arguments"] == response["arguments"]
                and response["response"]["status"] == "completed", "tool intent/response journal differs")
        request_key = intent["arguments"].get("request_key")
        if request_key is not None:
            require(type(request_key) is str and 0 < len(request_key) <= 192
                    and request_key not in request_keys, "journal mutation request identity differs")
            request_keys.add(request_key)
        responses.append(response)
    expected = {
        "hia_evaluate": {"baseline_artifact": evaluation["baseline_artifact"],
            "candidate_artifact": evaluation["candidate_artifact"],
            "build_receipt": evaluation["build_receipt"],
            "verification_receipts": evaluation["verification_receipts"]},
        "hia_adopt": {"target_slot": adoption["target_slot"], "expected_current": adoption["previous"],
            "candidate_artifact": adoption["active_artifact"],
            "evaluation_receipt": adoption["evaluation_receipt"],
            "verification_receipts": adoption["verification_receipts"]},
        "hia_rollback": {"target_slot": rollback["target_slot"], "expected_current": rollback["previous"],
            "retained_generation": rollback["current"]["generation"], "reason": rollback["reason"]},
    }
    sequences = []
    for tool, key in (("hia_evaluate", "evaluation"), ("hia_adopt", "adoption"), ("hia_rollback", "rollback")):
        selected = [row for row in responses if row["tool"] == tool]
        require(len(selected) == 1 and selected[0]["response"]["result"] == family[key],
                "recorded " + tool + " response differs from the selected result")
        row = selected[0]
        arguments = row["arguments"]
        fields = {**expected[tool], "catalog_sha256": context["catalog_sha256"],
                  "context": family["context"]}
        require(set(arguments) == set(fields) | {"request_key"}
                and type(arguments["request_key"]) is str and arguments["request_key"] in request_keys
                and all(arguments[name] == value for name, value in fields.items()),
                "journal request differs from its original receipt: " + tool)
        sequences.append(row["sequence"])
    require(sequences[0] < sequences[1] < sequences[2], "journal operation order differs")
    return len(responses)


def check_family(packet, report, family):
    """Reconstruct chain edges from original artifacts, not from summary links."""
    from hepta.hia_program import verify_program
    from hepta.hia_machine_plan import preservation_checks
    from tools.qualify_hia_scalar_adoption_chain import SPECIFICATION, witness_vectors

    typ = family["type"]
    require(typ in TYPES and family["status"] == "passed" and family["phase"] == "complete",
            "incomplete or unsupported family")
    require(type(family.get("exports")) is dict and 1 <= len(family["exports"]) <= 128,
            "v2 original artifact inventory is required")
    for name in family["exports"]:
        packet.artifact(family, name)
    installation = report["source"]["installation"]
    manifest = packet.artifact(family, "installation-manifest.json")
    require(manifest["installation"] == installation, "recorded installation manifest differs")
    require(set(manifest["profiles"]) == set(manifest["profile_manifests"]) == REQUIRED_PROFILES,
            "original profile inventory differs")
    for name, reference in manifest["profile_manifests"].items():
        packet.artifact(family, "profile-" + name + ".json", reference)
        require(reference["sha256"] == manifest["profiles"][name]["sha256"], "profile definition digest differs")
    context = packet.artifact(family, "context.json")
    require(sha256(packet.read(typ + "/context.json")).hexdigest() == family["context"]["sha256"]
            and context["installation"] == installation and context["baseline_program"] == family["candidate"]
            and context["baseline_core_sha256"] == family["candidate"]["sha256"]
            and context["foreign_buffer_exports"] == []
            and context["compiler_profile"] == manifest["profiles"]["compiler"]
            and context["catalog_sha256"] == manifest["catalog_sha256"] == installation["catalog_sha256"]
            and context["target_profile"] == manifest["profiles"]["target"],
            "context, baseline or scalar scope differs")
    document = packet.artifact(family, "core.hia.json", family["candidate"])
    core = verify_program(document)
    source_core = verify_program(packet.json(typ + "/source.hia.json"))
    require(core.canonical_bytes == packet.read(typ + "/core.hia.json")
            and source_core.canonical_bytes == core.canonical_bytes
            and core.sha256 == family["candidate"]["sha256"], "original source and admitted Core differ")
    abi = {"capped_add": {"params": [typ, typ, typ], "returns": [typ]}}
    function = core.as_dict()["functions"]
    require(len(function) == 1 and function[0]["name"] == "capped_add"
            and [item["type"] for item in function[0]["params"]] == abi["capped_add"]["params"]
            and function[0]["returns"] == [typ], "Core does not have the selected scalar ABI")
    spec = packet.json(typ + "/specification/specification.json")
    require(spec == family["specification"] and spec["type"] == typ
            and spec["specification"] == report["specification"] == SPECIFICATION
            and spec["core_sha256"] == core.sha256 and spec["input_sha256"] == core.input_sha256
            and spec["qualification_source_sha256"] == report["source"]["qualification_source_sha256"]
            and spec["status"] == "proved_in_independent_core_model"
            and spec["execution_authority_granted"] is False and spec["kernel_checked_core_soundness"] is False,
            "mathematical specification subject or scope differs")
    _query_inventory(spec["obligations"], SPECIFICATION_OBLIGATIONS)
    plan_ref = family["exports"]["machine-plan.json"]
    plan = packet.artifact(family, "machine-plan.json")
    require(plan == {"schema": "hepta.hia.agent.block-layout.v1", "core_sha256": core.sha256,
                     "block_order": {"capped_add": ["entry", "limited", "room", "sum"]}},
            "the retained explicit block-layout plan differs")
    core_proof = _check_proof(packet, family, "core-proof.json", REQUIRED_CLAIMS[:2],
                             {"kind": "core"}, context, installation)
    require(core_proof["base_program"] == family["candidate"] and core_proof["base_core_sha256"] == core.sha256,
            "equivalence baseline is not the same exact Core")
    plan_subject = {"kind": "agent_machine_plan", "backend_profile": manifest["profiles"]["backend"],
                    "plan_profile": manifest["profiles"]["plan"], "plan": plan_ref}
    plan_proof = _check_proof(packet, family, "plan-proof.json", ("lowering_refinement",),
                              plan_subject, context, installation)
    builds, proofs = {}, {}
    for mode in ("canonical", "planned"):
        emitted = family[mode]
        build = packet.artifact(family, mode + "-build.json", emitted["build_receipt"])
        object_bytes = packet.artifact(family, mode + ".o", build["object_artifact"])
        final_bytes = packet.artifact(family, mode + ".so", emitted["native_artifact"])
        selected_plan = plan_ref if mode == "planned" else None
        selected_hash = plan_ref["sha256"] if selected_plan else None
        require(build["schema"] == "hepta.hia.agent.build.v1" and build["context"] == family["context"]
                and build["candidate"] == emitted["candidate"] == family["candidate"]
                and build["core_sha256"] == core.sha256 and build["native_artifact"] == emitted["native_artifact"]
                and build["target_profile"] == emitted["target_profile"] == context["target_profile"]
                and build["backend_profile"] == emitted["backend_profile"] == manifest["profiles"]["backend"]
                and build["installation"] == installation and build["signatures"] == abi
                and build["output_kind"] == "shared" and build["foreign_buffer_exports"] == []
                and build["machine_plan"] == (plan if mode == "planned" else None)
                and build["object_sha256"] == sha256(object_bytes).hexdigest(), "build identity differs")
        native = build["native_build"]
        require(native["core_sha256"] == core.sha256 and native["input_sha256"] == core.input_sha256
                and native["machine_plan_sha256"] == selected_hash
                and native["object_artifact"] == build["object_artifact"]
                and native["object_sha256"] == build["object_sha256"]
                and native["artifact_sha256"] == sha256(final_bytes).hexdigest()
                and native["artifact_bytes"] == len(final_bytes), "native build does not bind the original bytes")
        expected_codegen = ({"kind": "canonical", "lowering_profile": manifest["profiles"]["lowering"]}
                if mode == "canonical" else {"kind": "agent_plan", "plan_profile": manifest["profiles"]["plan"],
                    "plan": plan_ref, "verification_receipt": family["exports"]["plan-proof.json"]})
        require(build["codegen"] == expected_codegen, "build codegen and plan proof differ")
        subject = {"kind": "native_artifact", "backend_profile": build["backend_profile"],
                   "native_artifact": emitted["native_artifact"], "build_receipt": emitted["build_receipt"]}
        proof = _check_proof(packet, family, mode + "-machine-proof.json", ("lowering_refinement",),
                             subject, context, installation)
        evidence = packet.artifact(family, mode + "-machine-evidence.json", proof["checks"][0]["evidence_artifact"])
        expected_binding = {"candidate_core_sha256": core.sha256, "input_sha256": core.input_sha256,
            "native_artifact": emitted["native_artifact"], "build_receipt": emitted["build_receipt"],
            "object_artifact": build["object_artifact"], "object_sha256": build["object_sha256"],
            "final_image_sha256": emitted["native_artifact"]["sha256"], "output_kind": "shared",
            "foreign_buffer_exports": [], "entry_symbols": ["capped_add"],
            "target_profile": build["target_profile"], "backend_profile": build["backend_profile"],
            "abi_signatures": abi, "machine_plan": selected_plan, "machine_plan_sha256": selected_hash}
        require(evidence["artifact_binding"] == expected_binding, "machine proof binds different build inputs")
        _query_inventory(evidence["validation"]["obligations"], MACHINE_OBLIGATIONS)
        require(len(evidence["queries"]) == 5, "machine query artifact inventory differs")
        for query, obligation in zip(evidence["queries"], evidence["validation"]["obligations"]):
            require(query["name"] == obligation["query_file"]
                    and query["sha256"] == query["artifact"]["sha256"] == obligation["query_sha256"],
                    "machine query is not bound to its obligation")
            packet.artifact(family, mode + "-" + query["name"], query["artifact"])
        builds[mode], proofs[mode] = build, evidence
    plan_evidence = packet.reference(family, plan_proof["checks"][0]["evidence_artifact"])
    require(plan_evidence["plan"] == plan and plan_evidence["choice_checks"] == preservation_checks(plan, core)
            and plan_evidence["canonical_object_sha256"] == builds["canonical"]["object_sha256"]
            and plan_evidence["planned_object_sha256"] == builds["planned"]["object_sha256"]
            and plan_evidence["canonical_frame_bytes"] == builds["canonical"]["native_build"]["function_frames"]
            and plan_evidence["planned_frame_bytes"] == builds["planned"]["native_build"]["function_frames"]
            and plan_evidence["same_slots"] is True and plan_evidence["same_frame_sizes"] is True
            and plan_evidence["canonical_frame_bytes"] == plan_evidence["planned_frame_bytes"]
            and plan_evidence["implicit_optimizer_used"] is False,
            "plan proof evidence differs from the exact plan and original objects")
    require(family["canonical"]["native_artifact"]["sha256"] != family["planned"]["native_artifact"]["sha256"],
            "the two retained layouts are not distinct")
    planned_subject = {"kind": "native_artifact", "backend_profile": builds["planned"]["backend_profile"],
        "native_artifact": family["planned"]["native_artifact"], "build_receipt": family["planned"]["build_receipt"]}
    encoding_proof = _check_proof(packet, family, "encoding-proof.json", ("encoding_check",),
                                  planned_subject, context, installation)
    encoding_evidence = packet.reference(family, encoding_proof["checks"][0]["evidence_artifact"])
    rederived = encoding_evidence["native_build"]
    original_native = builds["planned"]["native_build"]
    # Reemission happened in a different temporary directory. Its command paths
    # are execution records, while every other native-build identity must agree.
    require(encoding_evidence["rederived_sha256"] == family["planned"]["native_artifact"]["sha256"]
            and encoding_evidence["no_llvm_or_external_assembler"] is True
            and set(rederived) == set(original_native)
            and {key: value for key, value in rederived.items() if key != "commands"}
                == {key: value for key, value in original_native.items() if key != "commands"},
            "encoding proof evidence differs from the selected native build")
    receipts = [family["exports"][name] for name in
                ("core-proof.json", "encoding-proof.json", "planned-machine-proof.json")]
    evaluation = packet.artifact(family, "evaluation.json", family["evaluation"]["evaluation_receipt"])
    require(evaluation["context"] == family["context"] and evaluation["installation"] == installation
            and evaluation["candidate_artifact"] == family["planned"]["native_artifact"]
            and evaluation["baseline_artifact"] == family["canonical"]["native_artifact"]
            and evaluation["candidate_core_sha256"] == evaluation["baseline_core_sha256"] == core.sha256
            and evaluation["build_receipt"] == family["planned"]["build_receipt"]
            and evaluation["verification_receipts"] == receipts
            and all(evaluation[key] is True for key in ("report_complete", "planned_workload_complete", "termination_confirmed"))
            and evaluation["outcome"] in {"unchanged", "improved"}, "evaluation does not bind the proved artifacts")
    workload = packet.artifact(family, "workload.json", context["workload"])
    objective = packet.artifact(family, "objective.json", context["objective"])
    vectors = witness_vectors(typ)
    require(workload == {"schema": "hepta.hia.agent.workload.v1", "cases": [
        {"function": "capped_add", "arguments": vector, "expected": {"status": "returned",
        "values": [min(vector[0] + vector[1], vector[2])]}} for vector in vectors],
        "warmup_iterations": 0, "repetitions": 1}, "frozen workload differs")
    require(objective == {"schema": "hepta.hia.agent.objective.v1", "metric": "artifact_bytes",
        "required_claims": list(REQUIRED_CLAIMS), "allow_unchanged": True, "min_improvement_ratio": 0.0},
        "frozen adoption objective differs")
    measurements = packet.artifact(family, "measurements.json", evaluation["measurements"])
    require(measurements["context"] == family["context"] and measurements["workload"] == context["workload"]
            and measurements["objective"] == context["objective"]
            and measurements["baseline_artifact"] == evaluation["baseline_artifact"]
            and measurements["candidate_artifact"] == evaluation["candidate_artifact"]
            and measurements["planned_cases"] == len(measurements["observations"]) == len(vectors) == family["native_workload_vectors"]
            and measurements["planned_workload_complete"] is True, "native measurements differ")
    before = len(packet.read(typ + "/canonical.so"))
    after = len(packet.read(typ + "/planned.so"))
    expected_outcome = "improved" if after < before else "unchanged" if after == before else "regressed"
    require(measurements["metric"] == "artifact_bytes" and measurements["baseline_value"] == str(before)
            and measurements["candidate_value"] == str(after)
            and measurements["improvement_ratio"] == (before - after) / before
            and measurements["outcome"] == evaluation["outcome"] == expected_outcome
            and all(family["evaluation"][key] == evaluation[key] for key in
                    ("baseline_artifact", "candidate_artifact", "outcome", "measurements", "full_cost_ledger",
                     "report_complete", "planned_workload_complete", "termination_confirmed")),
            "native size measurements or evaluation response differ")
    for row, vector in zip(measurements["observations"], vectors):
        require(row["arguments"] == vector, "native measurement arguments differ")
        for name in ("baseline_native", "candidate_native"):
            require(row[name]["status"] == "returned" and row[name]["mismatch"] is False
                    and row[name]["values"] == [min(vector[0] + vector[1], vector[2])],
                    "recorded native workload output differs")
    ledger = packet.artifact(family, "cost-ledger.json", evaluation["full_cost_ledger"])
    packet.artifact(family, "cost-policy.json", context["budget"]["cost_policy"])
    require(ledger["context"] == family["context"] and ledger["full_search_cost_complete"] is False
            and family["full_search_cost_complete"] is False
            and all(value["net_optimization_benefit_proved"] is False for value in (ledger, evaluation, family)),
            "incomplete costs were promoted to a complete economic claim")
    adoption = packet.artifact(family, "adoption.json", family["adoption"]["adoption_receipt"])
    rollback = packet.artifact(family, "rollback.json", family["rollback"]["rollback_receipt"])
    for record, response in ((adoption, family["adoption"]), (rollback, family["rollback"])):
        require(record["context"] == family["context"] and record["future_calls_only"] is True
                and record["in_flight_versions_retained"] is True
                and all(record[key] == response[key] for key in ("target_slot", "previous", "current", "active_artifact")),
                "adoption or rollback receipt differs from its recorded response")
    require(adoption["target_slot"] == rollback["target_slot"] == report["campaign_id"] + "/" + typ + "/slot"
            and adoption["previous"] == {"generation": "0", "epoch": "0"}
            and adoption["current"] == {"generation": "1", "epoch": "1"}
            and adoption["active_artifact"] == evaluation["candidate_artifact"]
            and adoption["retained_baseline"] == evaluation["baseline_artifact"]
            and adoption["evaluation_receipt"] == family["evaluation"]["evaluation_receipt"]
            and adoption["verification_receipts"] == receipts
            and rollback["previous"] == adoption["current"]
            and rollback["current"] == {"generation": "0", "epoch": "2"}
            and rollback["active_artifact"] == evaluation["baseline_artifact"]
            and rollback["past_effects_reversed"] is False, "adoption generation or rollback relation differs")
    # The separately reviewed adoption projection is optional in the older
    # service. When present it must agree; it never becomes reader authority.
    if "artifact_identity" in adoption:
        from hepta.hia_agent_store import digest
        proof_projection = []
        for reference in receipts:
            record = packet.reference(family, reference)
            proof_projection.append({"verification_receipt": reference, "checks": [
                {name: check[name] for name in ("claim", "status", "subject", "profile",
                    "evidence_artifact", "assumptions_artifact")} for check in record["checks"]]})
        build = builds["planned"]
        require(adoption["artifact_identity"] == {
            "schema": "hepta.hia.agent.adopted-artifact-identity.v1",
            "candidate": family["candidate"], "core_sha256": core.sha256, "input_sha256": core.input_sha256,
            "context": family["context"], "codegen": build["codegen"], "machine_plan_sha256": plan_ref["sha256"],
            "object_artifact": build["object_artifact"], "object_sha256": build["object_sha256"],
            "native_artifact": adoption["active_artifact"], "final_image_sha256": adoption["active_artifact"]["sha256"],
            "build_receipt": family["planned"]["build_receipt"], "output_kind": "shared",
            "target_profile": build["target_profile"], "backend_profile": build["backend_profile"],
            "installation": installation, "abi_signatures": abi, "abi_sha256": digest(abi),
            "proofs": proof_projection, "target_slot": adoption["target_slot"], "current": adoption["current"],
            "projection_is_execution_authority": False}, "optional adoption identity projection differs")
    owner_rows = packet.json(typ + "/owner-observations.json")
    selected_vectors = [vectors[index] for index in (0, 1, 24, 30, 62, 100, 123, 124)]
    require(len(owner_rows) == 8 and family["observed_owner_calls"] == 10, "owner-call inventory differs")
    observations = []
    for row, vector in zip(owner_rows, selected_vectors):
        require(row["arguments"] == vector, "owner-call arguments differ")
        observations.append((row["observation"], vector, adoption["active_artifact"], "1"))
    observations.extend(((family["retained_lease_after_rollback"], [1, 1, 1], adoption["active_artifact"], "1"),
                         (family["new_lease_after_rollback"], [1, 1, 1], rollback["active_artifact"], "0")))
    for observation, vector, artifact, generation in observations:
        require(observation["status"] == "returned" and observation["termination_confirmed"] is True
                and observation["values"] == [min(vector[0] + vector[1], vector[2])]
                and observation["artifact"] == artifact and observation["generation"] == generation,
                "owner result, generation or full artifact identity differs")
    expected_chain = {"core": family["candidate"], "plan": plan_ref, "plan_sha256": plan_ref["sha256"],
        "object": builds["planned"]["object_artifact"], "final_image": adoption["active_artifact"],
        "target_profile": builds["planned"]["target_profile"], "backend_profile": builds["planned"]["backend_profile"],
        "abi_signatures": abi, "context_manifest": family["exports"]["context.json"],
        "core_proof": receipts[0], "plan_proof": family["exports"]["plan-proof.json"],
        "encoding_proof": receipts[1], "machine_proof": receipts[2],
        "evaluation_receipt": family["exports"]["evaluation.json"],
        "adoption_receipt": family["exports"]["adoption.json"], "rollback_receipt": family["exports"]["rollback.json"],
        "adoption": family["adoption"], "owner_artifact": adoption["active_artifact"]}
    require(family["identity_chain"] == expected_chain, "declared identity chain differs from original evidence reconstruction")
    calls = _check_journal(packet, family, context, evaluation, adoption, rollback)
    return {"type": typ, "status": "consistent", "identity_chain": expected_chain,
            "tool_calls_checked": calls, "original_artifacts_checked": len(family["exports"]),
            "recorded_owner_calls_checked": len(observations), "abi_signatures": abi}


def saved_queries(packet, family):
    typ = family["type"]
    spec = packet.json(typ + "/specification/specification.json")
    require(spec == family["specification"] and spec["core_sha256"] == family["candidate"]["sha256"],
            "specification and selected Core differ")
    _query_inventory(spec["obligations"], SPECIFICATION_OBLIGATIONS)
    queries = [(typ + "/specification/" + q["query_file"], q) for q in spec["obligations"]]
    for mode in ("canonical", "planned"):
        proof = packet.json(typ + "/" + mode + "-machine-evidence.json")
        require(proof["artifact_binding"]["candidate_core_sha256"] == family["candidate"]["sha256"]
                and proof["validation"]["complete"] is True and proof["validation"]["ok"] is True,
                "machine proof differs")
        _query_inventory(proof["validation"]["obligations"], MACHINE_OBLIGATIONS)
        queries.extend((typ + "/" + mode + "-" + q["query_file"], q) for q in proof["validation"]["obligations"])
    require(len(queries) == 13, "per-type query inventory differs")
    for name, obligation in queries:
        require(sha256(packet.read(name)).hexdigest() == obligation["query_sha256"], "query identity differs")
    return queries


def recompute_family(packet, report, family, output):
    """Re-encode the selected original Core and ELF, then compare retained queries."""
    from hepta.hia_safe_core import validate_safe_core_artifact
    from tools.qualify_hia_scalar_adoption_chain import specification_proof

    output.mkdir()
    document = packet.artifact(family, "core.hia.json")
    fresh_spec = specification_proof(document, output / "specification")
    original_spec = family["specification"]
    for key in ("type", "specification", "core_sha256", "input_sha256", "checker_source_identity",
                "qualification_source_sha256", "solver"):
        require(fresh_spec[key] == original_spec[key], "fresh specification identity differs: " + key)
    fresh_rows = fresh_spec["obligations"][:]
    for mode in ("canonical", "planned"):
        evidence = packet.artifact(family, mode + "-machine-evidence.json")
        fresh = validate_safe_core_artifact(document, packet.artifact(family, mode + ".o"),
            packet.artifact(family, mode + ".so"), query_directory=output / mode)
        write_json(output / (mode + "-validation.json"), fresh)
        for key in ("subject", "profile", "property", "source_identity", "solver", "assumptions",
                    "unproved_obligations", "limits", "claims", "image_binding"):
            require(fresh[key] == evidence["validation"][key], "fresh machine-model identity differs: " + key)
        fresh_rows.extend(fresh["obligations"])
    retained = [q for _, q in saved_queries(packet, family)]
    require(len(fresh_rows) == len(retained) == 13, "fresh proof inventory differs")
    for fresh, original in zip(fresh_rows, retained):
        require(all(fresh[key] == original[key] for key in ("name", "expected", "result", "query_sha256")),
                "saved query does not match fresh encoding of the original artifact")
    return {"type": family["type"], "fresh_queries_checked": len(fresh_rows),
            "saved_queries_reencoded_identically": True, "producer_reemission_used": False,
            "native_image_loaded": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--expected-manifest-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--types", nargs="+", choices=TYPES, default=list(TYPES),
                        help="exact expected type inventory; default is the complete four-type matrix")
    parser.add_argument("--legacy-query-only", action="store_true",
                        help="replay historical v1 saved queries without a complete artifact-chain claim")
    args = parser.parse_args(argv)
    result = {"schema": "hepta.hia.scalar-adoption-chain-replay.v2", "status": "started",
        "replayer_sha256": sha256(Path(__file__).read_bytes()).hexdigest(), "files_verified": 0,
        "queries": [], "families": [], "recomputed": [], "complete_artifact_chain_checked": False,
        "fresh_native_execution": False, "kernel_checked_isa_proof": False,
        "execution_authority_granted": False, "recorded_execution_independently_authenticated": False,
        "scope": "saved_queries_only" if args.legacy_query_only else "original_artifact_chain_and_fresh_model_checks"}
    started = time.monotonic_ns()
    with args.output.open("x") as stream:
        try:
            import z3
            from hepta.hia_safe_core import _solver_identity
            result["replay_solver"] = _solver_identity(z3)
            packet = Packet(args.input, args.expected_manifest_sha256)
            result.update(original_manifest_sha256=packet.manifest_sha256,
                          files_verified=len(packet.files), original_bytes_verified=packet.total_bytes)
            report = packet.json("report.json")
            result["source_report_sha256"] = sha256(packet.read("report.json")).hexdigest()
            require(report["status"] == "passed" and report["source"]["worktree_status"] == "",
                    "a complete unchanged clean-source run is required")
            require(len(args.types) == len(set(args.types)) and report["types"] == args.types
                    and [row["type"] for row in report["families"]] == args.types,
                    "explicitly selected type inventory differs")
            require(report["schema"] == ("hepta.hia.scalar-adoption-chain.v1" if args.legacy_query_only
                                         else "hepta.hia.scalar-adoption-chain.v2"),
                    "v2 complete original evidence is required; historical v1 needs --legacy-query-only")
            result["source"] = report["source"]
            result["types"] = args.types
            require(all(value is False for value in report["claims"].values()),
                    "packet claims exceed this scoped qualification")
            if not args.legacy_query_only:
                fresh_output = args.output.with_name(args.output.name + ".recomputed")
                fresh_output.mkdir()
                result["recomputed_output"] = str(fresh_output)
            for family in report["families"]:
                require(family["status"] == "passed", "incomplete family")
                if not args.legacy_query_only:
                    result["families"].append(check_family(packet, report, family))
                    result["recomputed"].append(recompute_family(packet, report, family, fresh_output / family["type"]))
                for name, obligation in saved_queries(packet, family):
                    solver = z3.Solver(ctx=z3.Context())
                    solver.set(timeout=15000)
                    solver.from_string(packet.read(name).decode())
                    actual = str(solver.check())
                    result["queries"].append({"path": name, "query_sha256": obligation["query_sha256"],
                        "expected": obligation["expected"], "result": actual})
                    require(actual == obligation["expected"], "replayed query did not match its expected result")
            require(len(result["queries"]) == 13 * len(args.types), "complete query inventory differs")
            require(result["replayer_sha256"] == sha256(Path(__file__).read_bytes()).hexdigest()
                    and result["replay_solver"] == _solver_identity(z3), "replayer or solver changed during replay")
            result["complete_artifact_chain_checked"] = not args.legacy_query_only
            result["status"] = "passed_saved_queries_only" if args.legacy_query_only else "passed"
            return 0
        except BaseException as exc:
            result.update(status="failed", error_type=type(exc).__name__, error=str(exc))
            raise
        finally:
            result["elapsed_ns"] = str(time.monotonic_ns() - started)
            json.dump(result, stream, indent=2, sort_keys=True)
            stream.write("\n")
            print(json.dumps({"status": result["status"], "files": result["files_verified"],
                "queries": len(result["queries"]), "complete_artifact_chain_checked": result["complete_artifact_chain_checked"],
                "output": str(args.output)}))


if __name__ == "__main__":
    raise SystemExit(main())
