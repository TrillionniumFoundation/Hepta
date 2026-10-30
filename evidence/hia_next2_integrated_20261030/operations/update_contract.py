"""Review the new finite profiles alongside every retained canonical selector."""
from pathlib import Path
import hashlib
import json
import re
import sys
import unittest

REPO = Path(__file__).resolve().parents[1] / "hepta-integration"
sys.path.insert(0, str(REPO))
sys.dont_write_bytecode = True


def selectors(*modules):
    loader = unittest.TestLoader()
    def flatten(suite):
        for value in suite:
            if isinstance(value, unittest.TestSuite):
                yield from flatten(value)
            else:
                yield value.id()
    result = sorted(set(flatten(loader.loadTestsFromNames(modules))))
    if loader.errors or not result:
        raise ValueError("new finite matrix must resolve actual tests: " + repr(loader.errors))
    return result


def main():
    path = REPO / "docs/HIA_SAFETY_CONTRACT.json"
    contract = json.loads(path.read_bytes())
    original = {row["id"]: row for row in contract["capabilities"]}
    additions = [
        {
            "id": "independent_rust_scoped_abort_cleanup",
            "guarantee": "checked_on_every_admission",
            "scope": "Explicit raw-byte-dag-finite-heap-cleanup-v1: independent whole-module v7/v8 byte-DAG/finite-entry heap admission, exact private scalar invocation, and conservative reservation of at most 32768 cleanup actions before language execution. On a language trap or runtime budget stop, the same Rust Machine audits the complete actual inventory, explicitly ends children and call-formal loans before parent loans and owners, and retains the original stop plus bounded journal and before/after ledgers. Normal return must already be clean.",
            "exclusions": [
                "Finite-heap admission alone does not grant cleanup admission; a reservation above the caller or fixed limit refuses before execution.",
                "No external resources, chains, foreign code, callbacks, native publication or default/source/nominal authority switch.",
                "The journal reservation is not a bound on JSON reporting, process RSS, CPU, host allocation failure, panic, process death or OS resource release.",
                "An internal inventory/release inconsistency cannot qualify completed cleanup; no general unwinding, source/Core/native refinement or whole-language soundness theorem."
            ],
            "entrypoints": ["hepta.hia_rust_byte_dag.execute_rust_byte_dag", "hepta.hia_rust_byte_cleanup.validate_cleanup", "hepta.hia_routes.route_inventory"],
            "regression_selectors": selectors("tests.test_hia_rust_scoped_cleanup") + ["tests.test_hia_routes.RouteTests.test_independent_rust_profile_cannot_mint_default_or_native_admission"],
        },
        {
            "id": "finite_cpp_parent_checkpoint_reconstruction",
            "guarantee": "host_enforced_scoped_admission",
            "scope": "Existing nlohmann/json 3.11.3/3.12.0 scoped C ABI and Hepta consumer inside an immutable sealed Linux x86-64 worker. A caller owns 1..64 integers in [-1000000,1000000], with bounded lifetime requests, revision and nonce. State commits only after bound scalar correctness, ordinary lifetime ledger, complete valid response and normal child exit. Confirmed foreign failures preserve the committed checkpoint; a distinct explicit request may reconstruct it. Cleanup uncertainty poisons the owner.",
            "exclusions": [
                "A foreign SIGABRT remains a failed foreign invocation; parent reconstruction is not C++ destructor recovery or in-process memory safety.",
                "No general C++ rewrite, foreign pointer/handle transfer, arbitrary state migration, external side-effect rollback or automatic retry.",
                "Existing bounded process ownership does not prove completion of arbitrary escaped descendants or complete host/environment closure.",
                "Finite regression and audit receipts do not authorize Core admission, native publication, a new source version or general P3/P6 completion."
            ],
            "entrypoints": ["hepta.cpp_json_checkpoint.JsonCheckpoint.prepare", "hepta.cpp_json_checkpoint.JsonCheckpoint.execute", "tools.qualify_cpp_json_checkpoint.qualify"],
            "regression_selectors": selectors("tests.test_cpp_json_checkpoint") + ["tests.test_hia_routes.RouteTests.test_foreign_checkpoint_descriptor_cannot_become_core_or_rewrite_authority"],
        },
        {
            "id": "crc_parallel_bit_proposals_and_complete_cost_protocol",
            "guarantee": "reviewed_qualification_protocol",
            "scope": "Untrusted GF(2) fixed-polynomial CRC proposals for the existing repo-authored Filecheck byte kernel, including both guarded singles and a shared-body dual within the unchanged 128-operation selected-LLVM bound. All three legacy candidates remain byte-identical and the full six-image pool remains available to fixed controls. Fresh original C capture, scalar all-input/first-trap translation validation, emitted-LLVM checking and sealed native controls precede an independent frozen eight-arm study with unchanged v3 work and complete cold cost accounting.",
            "exclusions": [
                "Generated basis constants and proposal metadata are not proof or execution authority; every consumer must perform the original independent gates.",
                "Filecheck is a repository-authored research application, not a newly migrated third-party CRC library or production demand trace.",
                "Correctness, changed machine code, kernel timing and conditional break-even estimates do not establish net or whole-file performance improvement.",
                "No NDU incremental-value, universal optimum, hardware-CRC superiority, source-C or final-machine-code refinement claim."
            ],
            "entrypoints": ["hepta.hia_crc_linear.candidates", "tools.qualify_hia_crc_linear.qualify", "tools.qualify_hia_crc_linear_economics.study"],
            "regression_selectors": selectors("tests.test_hia_crc_linear", "tests.test_hia_crc_linear_qualification", "tests.test_hia_crc_linear_economics"),
        },
        {
            "id": "public_selection_first_agent_decoder",
            "guarantee": "reviewed_qualification_protocol",
            "scope": "V13 public-node-category-selection-first.v2 retains every public editable ID, selects the node before replacement in actual HTTP schema bytes, and checks the returned native GBNF for every public variant. Rust type replacements use only the existing public language type set; expressions remain untrusted. Generic whole-specification/transaction guidance and public category diagnostics are disclosed changes. Capacity-only reference rendering preserves values and never enters generation. Fresh capacity and 3/3 qualification remain mandatory before conditional main.",
            "exclusions": [
                "Schema order, public type syntax and generic prompts do not prove type/owner/resource/functional correctness or grant execution authority.",
                "No reference-selected node or task-specific answer is used in the generation contract; failed attempts and complete/unknown usage remain retained.",
                "Adaptive follow-up on prior failures; no independent holdout, public preregistration, real-model success or general Agent productivity claim follows from these regressions.",
                "Legacy/full wire serialization and older protocol identities are retained; historical runs are not reclassified as V13 results."
            ],
            "entrypoints": ["experiments.hia_agent_structured_v7_20261029.contracts_v2.response_schema", "experiments.hia_agent_toolstudy_v13_20261030.engine.ToolStudyEngine.decoder_schema", "experiments.hia_agent_toolstudy_v13_20261030.support.validate_qualification"],
            "regression_selectors": selectors("tests.test_hia_agent_toolstudy_v13"),
        },
    ]
    if set(original) & {row["id"] for row in additions}:
        raise ValueError("refuse to apply a reviewed matrix revision twice")
    contract["capabilities"].extend(additions)
    contract["authority"]["independent_execution_profiles"].append({
        "profile": "raw-byte-dag-finite-heap-cleanup-v1",
        "entrypoint": "hepta.hia_rust_byte_dag.execute_rust_byte_dag",
        "admission": "independent Rust owned verifier, finite-entry heap/action analyses and private admitted snapshot",
        "scope": "raw v7/v8 private scalar byte-DAG invocation plus bounded explicit Machine discharge after a language stop",
        "default_admission_changed": False, "python_semantic_admission_required": False,
        "native_execution_authorized": False, "external_receipts_grant_admission": False,
    })
    contract["boundaries"]["trap"] = (
        "Default VM profiles retain the stopped resource ledger and native traps abort. The explicit raw-byte-dag-finite-heap-cleanup-v1 profile separately reserves a bounded journal before execution and discharges actual invocation-owned byte loans/formals/owners after a language trap or budget stop, retaining both ledgers. This does not establish general unwinding, host panic/OOM/process-termination cleanup, or a source/native cleanup theorem.")
    contract["trusted_computing_base"].append({
        "component": "Rust scoped-abort reservation/inventory audit/discharge and the explicit foreign parent-checkpoint protocol with fixed sealed worker",
        "reason": "Separate finite implementation profiles only; logical journal preallocation is not general host resource safety, and the foreign worker, compiler, loader and existing process owner remain trusted."
    })
    for identifier, row in original.items():
        if next(v for v in contract["capabilities"] if v["id"] == identifier) != row:
            raise ValueError("prior capability changed: " + identifier)
    if any(v is not False for v in contract["unproved_claims"].values()):
        raise ValueError("universal claim was promoted")
    path.write_text(json.dumps(contract, sort_keys=True, indent=2) + "\n")
    digest = hashlib.sha256(json.dumps(contract, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()
    runner = REPO / "tools/qualify_hia_safety_contract.py"
    updated, count = re.subn(r'^REVIEWED_CONTRACT_SHA256 = "[0-9a-f]{64}"$',
                            'REVIEWED_CONTRACT_SHA256 = "' + digest + '"', runner.read_text(), flags=re.M)
    if count != 1:
        raise ValueError("reviewed matrix pin is not unique")
    runner.write_text(updated)
    print(json.dumps({"capabilities": len(contract["capabilities"]),
                      "distinct_selectors": len({s for r in contract["capabilities"] for s in r["regression_selectors"]}),
                      "contract_sha256": digest, "all_prior_capabilities_retained": True,
                      "all_universal_claims_false": True}))


if __name__ == "__main__":
    main()
