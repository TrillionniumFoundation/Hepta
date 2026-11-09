#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""One source-pinned HIA release entry, reusing the existing runtime preflight.

A release lock names source and capability identities, not deployment authority.
The default lock is reviewed repository metadata. Freeze is an explicit release
engineering operation; ordinary users describe, materialize, check or prepare it.
No command merges a branch, changes a live configuration or restarts a service.
"""
from __future__ import annotations

import argparse
import ast
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys

# The supported entry is this source file, not ``python -m``.  -B only
# disables cache writes; it does not prevent a timestamp-valid .pyc from
# replacing an imported helper. Execute the helper's actual source bytes.
_preflight_path = Path(__file__).resolve().with_name("hia_candidate_preflight.py")
_preflight_spec = importlib.util.spec_from_file_location("_hia_release_preflight", _preflight_path)
preflight = importlib.util.module_from_spec(_preflight_spec)
sys.modules[_preflight_spec.name] = preflight
exec(compile(_preflight_path.read_bytes(), str(_preflight_path), "exec"), preflight.__dict__)


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOCK = ROOT / "releases/hia-current.json"
SCHEMA = "hepta.hia.release-lock.v1"
TARGET = "x86_64-unknown-linux-gnu"
SUPPORT = "docs/HIA_SELFHOST_CORE_SUPPORT.json"
HIA_TOOLS = tuple("hia_" + name for name in (
    "describe", "read", "artifact", "context", "inspect", "candidate",
    "verify", "emit", "evaluate", "adopt", "rollback"))
BOOTSTRAP_FILES = (
    SUPPORT, "docs/HIA_SELF_HOSTING_CORE.md", "examples/hia_bootstrap/selfhost.hiaasm",
    "examples/hia_bootstrap/bytesum.hiaasm", "tools/hia_selfhost_child.py",
    "tools/qualify_hia_selfhost.py", "tools/generate_hia_selfhost.py",
    "tools/hia_selfhost_cases.py", "tools/hia_selfhost_contract.py",
    "tools/hia_selfhost_resources.py",
    "tools/hia_selfhost_bulk.py",
    "tools/hia_selfhost_loans.py",
    "tools/hia_selfhost_owned_elf.py", "tools/hia_selfhost_owned_elf_cases.py",
    "tools/hia_selfhost_owned_flow_cases.py",
    "tools/qualify_hia_selfhost_owned_elf.py",
    "tools/hia_selfhost_chain_elf.py", "tools/hia_selfhost_chain_cases.py",
    "tools/hia_selfhost_chain_flow_cases.py",
    "tools/hia_selfhost_parameter_cases.py",
    "tools/hia_selfhost_chain_allocator_child.py", "tools/hia_selfhost_chain_allocator_witness.c",
    "tools/qualify_hia_selfhost_chain_flow.py",
    "tools/qualify_hia_selfhost_chain_elf.py",
    "tools/hia_selfhost_select.py",
    "tools/hia_selfhost_tailcalls.py",
    "tools/hia_selfhost_limits.py", "tools/hia_selfhost_capacity.py",
    "tools/hia_selfhost_cfg_worklist.py",
    "tools/hia_selfhost_process_owner.py", "tests/test_hia_selfhost_process_owner.py",
    "tools/replay_hia_selfhost_upgrade.py",
    "tools/generate_hia_selfhost_contract.py", "tools/replay_hia_selfhost_cold.py",
    "tests/test_hia_selfhost.py", "tests/test_hia_selfhost_contract.py",
    "tests/test_hia_selfhost_owned_flow.py",
    "tests/test_hia_selfhost_chain.py",
    "tests/test_hia_selfhost_language_coverage.py", "docs/HIA_SELFHOST_LANGUAGE_COVERAGE.json",
)
ENTRY_FILES = ("README.md", "docs/HIA_RELEASE_ENTRY.md", "tools/hia_release.py", "tools/hia_candidate_preflight.py",
               "tools/hia_agent_native_transport.py")
CANDIDATE_FILES = (
    "tools/check_hia_safe_core.py", "tests/test_hia_safe_core_artifact.py",
    "tests/test_hia_safe_core_loader_contract.py",
    "tools/qualify_hia_native_ndu.py", "tests/test_hia_native_cohort_gate.py",
    "tests/test_hia_native_ndu.py", "tests/test_hia_native_performance_tail_gate.py",
    "tests/test_hia_native_ndu_identity.py", "tests/test_hia_prepared_gate_profile.py",
    "docs/HIA_NATIVE_COHORT_GATE_20261108.md",
    "tools/qualify_hia_safe_core_cmovne.py", "tools/hia_safe_core_cmovne_child.py",
    "tests/test_hia_safe_core_cmovne.py", "docs/HIA_SAFE_CORE_CMOVNE_20261108.md",
    "tests/test_hia_agent_native_proof_contract.py", "tests/test_hia_release_diagnostics.py",
    "tests/test_hia_agent_native_machine_validation.py",
    "tests/test_hia_agent_native_lease_snapshot.py",
    ".github/workflows/hia-sixgap-source.yml",
    ".github/workflows/hia-ndu-scalar-selection.yml",
    "tools/hia_agent_native_qualification.py",
    "tools/qualify_hia_agent_buffer_lifecycle.py", "tests/test_hia_agent_buffer_lifecycle.py",
    "tests/test_hia_agent_external_roots.py",
    "docs/HIA_AGENT_EXTERNAL_ROOT_REPORT_REPAIR_20261108.md",
    "review-evidence/hia-agent-buffer-20261108-5e6c/raw-continuation.zip",
    "tools/qualify_hia_agent_original_select_delta.py",
    "docs/HIA_AGENT_ORIGINAL_SELECT_DELTA_20261108.md",
    "docs/HIA_AGENT_EXTENSION_PROOF_PLAN_20261108.md",
    "review-evidence/hia-agent-original-select-delta-20261108-5e6c/raw-evidence.zip",
    "docs/HIA_SELFHOST_CHAIN_FLOW_QUALIFICATION.md",
    "docs/HIA_SELFHOST_CHAIN_V13_QUALIFICATION.md",
    "docs/HIA_SELFHOST_ALLOC_NODE_FIX_20261108.md",
    "docs/HIA_SELFHOST_CFG_WORKLIST_FIX_20261108.md",
    "docs/HIA_SELFHOST_COLD_PROCESS_OWNER_20261108.md",
    "docs/HIA_SELFHOST_COLD_PARALLEL_OWNER_FIX_20261108.md",
    "tools/qualify_hia_selfhost_machine_plans.py", "tests/test_hia_selfhost_machine_plans.py",
    "docs/HIA_SELFHOST_MACHINE_PLAN_HEADER_REPAIR_20261108.md",
    "tools/qualify_hia_ndu_prepared_ranker.py", "tools/replay_hia_ndu_prepared_ranker.py",
    "tests/test_hia_ndu_prepared_ranker.py", "docs/HIA_NDU_PREPARED_RANKING.md",
    "tests/test_hia_ndu_prepared_cost_intervals.py",
    "review-evidence/hia-ndu-prepared-20261108-5e6c/final-originals.tar.xz",
    "tools/qualify_hia_ndu_persistent_ranker.py", "tools/replay_hia_ndu_persistent_ranker.py",
    "tests/test_hia_ndu_persistent_ranker.py", "docs/HIA_NDU_PERSISTENT_RANKING.md",
    "tests/test_hia_ndu_persistent_cost_intervals.py",
    "review-evidence/hia-ndu-persistent-20261108-5e6c/originals.tar.xz",
    "rust/hia-ndu-bridge/src/main.rs",
    "tools/build_hia_ndu_bridge.py", "rust/hia-ndu-bridge/Cargo.toml",
    "rust/hia-ndu-bridge/Cargo.lock", "rust/hia-ndu-bridge/upstream.json",
    "tools/hia_original_reconcile.py", "tests/test_hia_original_reconcile.py",
    "tools/build_hia_safe_core.py", "tools/qualify_hia_safe_core.py",
    "tests/test_hia_safe_core.py", "docs/HIA_SAFE_CORE_MACHINE_VALIDATION.md",
    "examples/hia_safe_core/scalar_add.hia.json",
    "examples/hia_safe_core/guarded_update.hia.json",
    "examples/hia_safe_core/read_byte.hia.json",
    "tools/hia_agent_macro_policy.py", "tools/qualify_hia_macro_campaign.py",
    "docs/HIA_PRODUCT_CLOSURE_20261107.md", "docs/HIA_NDU_STRONG_CONTROL_20261107.md",
    "docs/HIA_PRODUCT_FOLLOWTHROUGH_20261107.md",
    "experiments/hia_product_closure_20261107/http-client/http_lifecycle.py",
    "experiments/hia_product_closure_20261107/http-client/test_http_lifecycle.py",
    "experiments/hia_product_closure_20261107/http-client/tools/hia_original_reconcile.py",
    "tools/hia_agent_codex_transport.py", "tools/hia_agent_fresh_session.py",
    "tests/test_hia_agent_first_use_recovery.py", "docs/HIA_AGENT_FIRST_USE.md",
    "tools/hia_repository_agent_trial.py", "tests/test_hia_repository_agent_trial.py",
    "docs/HIA_REPOSITORY_AGENT_TRIAL.md",
    "experiments/hia_repository_select_trial_20261108/public/PROMPT.txt",
    "experiments/hia_repository_select_trial_20261108/public/task.json",
    "tests/test_hia_scalar_proof_contract.py", "docs/HIA_AGENT_PROOF_RESULTS.md",
    "tools/qualify_hia_selfhost_leaf_plans.py", "tests/test_hia_machine_leaf_registers.py",
    "tools/prepare_hia_followup_tasks.py", "tools/qualify_hia_followup_tasks.py",
    "tools/qualify_hia_macro_multistep.py", "tools/hia_macro_multistep_provider.py",
    "tools/hia_macro_multistep_assessment.py", "tools/qualify_hia_cli_public_capability.py",
    "tools/hia_macro_exec_adapter.py", "tools/prepare_hia_macro_launcher.py",
    "benchmarks/hia_macro_multistep/PROTOCOL.json", "docs/HIA_AGENT_MACRO_MULTISTEP.md",
    "tests/test_hia_macro_multistep.py", "tests/test_hia_macro_exec_adapter.py",
    "tools/core_seven_shared_acceptance_plan.py",
    "tests/test_core_seven_shared_acceptance.py", "tests/test_core_seven_shared_source_closure.py",
)
RUNTIME_FILES = ("Cargo.toml", "Cargo.lock",
    "src/mcp/hia_tool_catalog.json", "src/mcp/hia_contract.rs", "src/mcp/hia_provider.rs",
    "src/mcp/server.rs", "src/mcp/hia_contract_tests.rs", "src/mcp/hia_provider_tests.rs",
    "src/mcp/hia_scoped_proof_fixture.json",
    "deploy/mcp_tool_contract.py", "deploy/stage_dc_successor.py", "deploy/hia_mcp_catalog.py",
    "deploy/contracts/hepta-hia-agent-native-v1.json")
REPOSITORIES = {"hepta": "https://github.com/TrillionniumFoundation/Hepta.git",
                "runtime": "https://github.com/TrillionniumFoundation/hepta-runtime.git"}
SOURCE_DIRECTORIES = ("hepta", "docs", "tools", "tests", "examples", "benchmarks", "formal",
                      "native", "rust", "spec", "specs", ".github", "releases",
                      "experiments/hia_agent_assembly_v4_20261030",
                      "experiments/hia_initialization_frontiers_20261103",
                      "experiments/hia_round4_20261105",
                      "experiments/hia_agent_first_use_20261107",
                      "experiments/hia_repository_select_trial_20261108",
                      "experiments/hia_release_20261107",
                      "experiments/hia_product_closure_20261107",
                      "review-evidence/hia-agent-buffer-20261108-5e6c",
                      "review-evidence/hia-agent-original-select-delta-20261108-5e6c",
                      "review-evidence/hia-ndu-prepared-20261108-5e6c",
                      "review-evidence/hia-ndu-persistent-20261108-5e6c")
MATERIALIZATION = {"hepta_sparse_directories": list(SOURCE_DIRECTORIES),
    "runtime_sparse_directories": None,
    "omitted_scope": "Historical campaigns and artifact/report archives outside this release's qualified source closure"}
# The runtime is a complete checkout, including historical evidence still read
# by its release gates. A cold filtered fetch resolves those blobs at checkout;
# its bounded download budget must not assume the much smaller Hepta closure.
CHECKOUT_TIMEOUT_SECONDS = {"hepta": 120, "runtime": 600}
QUALIFICATION = {"source_lock_only": True, "production_deployed": False,
                 "default_branch_updated": False, "agent_first_use_passed": False,
                 "native_ndu_value_passed": False,
                 "runtime_source_only_loading_enforced": False}
MCP_CONTRACT = {"hia_tools": list(HIA_TOOLS), "catalog_scope": "HIA family only",
                "whole_server_contract_required": True, "current_agent_discovery_required": True}
TARGET_ABI = {"target": TARGET, "machine": "ELF64 / AMD64 / little-endian / LP64",
    "scalar_profile": "hepta.hia.program.direct-linux-x86_64.v1",
    "borrowed_bytes_profile": "hepta.hia.program.direct-linux-x86_64-borrowed-bytes.v1",
    "calling_convention": "System V AMD64; explicit borrowed-byte wrapper",
    "primary_codegen": "hia-direct", "llvm_or_assembler_fallback": False,
    "external_linker_scope": "B0/shared-library linking and explicit ELF object qualification; the flat successor chain needs no linker"}
SELFHOST_STATIC = {"support_matrix": SUPPORT, "source": "examples/hia_bootstrap/selfhost.hiaasm",
    "loader": "tools/hia_selfhost_child.py", "seed": "Python assembler + Core checker + hia-direct + GNU ld",
    "seed_binary": "Measured per cold build in B0.receipt.json; not an unbuilt binary pin",
    "required_replay": ["B0->B1->B2->B3", "B1=B2=B3", "M2=M3", "M2!=B2"],
    "whole_language_selfhost": False}


def digest(raw):
    return sha256(raw).hexdigest()


def read_bytes(path):
    return preflight.bootstrap_read(Path(path).absolute(), 16 * 1024 * 1024)


def committed_files(root, revision, names):
    result = {}
    for name in sorted(set(names)):
        path = Path(root) / name
        raw = read_bytes(path)
        blob = preflight.git(root, "rev-parse", revision + ":" + name).strip()
        if preflight.blob_sha(raw) != blob:
            raise ValueError("release file differs from committed bytes: " + name)
        result[name] = digest(raw)
    return result


def literal_constant(path, name):
    values = []
    for node in ast.parse(read_bytes(path)).body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in node.targets):
            values.append(ast.literal_eval(node.value))
    if len(values) != 1:
        raise ValueError("one literal native profile constant required: " + name)
    return values[0]


def build_lock(hepta_root, hepta_revision, runtime_root, runtime_revision, python, release_id):
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", release_id):
        raise ValueError("release id must be a bounded plain identifier")
    identities = {"hepta": preflight.source_identity(hepta_root, hepta_revision),
                  "runtime": preflight.source_identity(runtime_root, runtime_revision)}
    preflight.configure_runtime(runtime_root, runtime_revision)
    worker = preflight.worker_inventory(hepta_root)
    if not preflight.worker_matches_commit(hepta_root, hepta_revision, worker):
        raise ValueError("actual worker inventory differs from committed source")
    pins = preflight.installed_pins(hepta_root, python)
    if pins["worker_sha256"] != digest(preflight.canonical(worker)):
        raise ValueError("worker inventory and installation manifest disagree")
    language_files = committed_files(hepta_root, hepta_revision,
                                    (*worker, *BOOTSTRAP_FILES, *ENTRY_FILES, *CANDIDATE_FILES))
    if (digest(read_bytes(Path(__file__))) != language_files["tools/hia_release.py"]
            or digest(read_bytes(Path(preflight.__file__))) != language_files["tools/hia_candidate_preflight.py"]):
        raise ValueError("executing entry/preflight differs from the selected release source")
    runtime_files = committed_files(runtime_root, runtime_revision, RUNTIME_FILES)
    if (language_files["docs/HIA_AGENT_NATIVE_TOOL_CATALOG.json"] != pins["catalog_sha256"]
            or runtime_files["src/mcp/hia_tool_catalog.json"] != pins["catalog_sha256"]):
        raise ValueError("runtime and worker catalog bytes differ")
    catalog = preflight.decode(read_bytes(Path(hepta_root) / "docs/HIA_AGENT_NATIVE_TOOL_CATALOG.json"))
    if sorted(tool["name"] for tool in catalog["tools"]) != sorted(HIA_TOOLS):
        raise ValueError("release requires the exact eleven-tool HIA family")
    matrix = preflight.decode(read_bytes(Path(hepta_root) / SUPPORT))
    if (type(matrix) is not dict or matrix.get("schema") != "hepta.hia.selfhost-core-support.v1"
            or matrix.get("target", {}).get("triple") != TARGET
            or not isinstance(matrix.get("profile"), str)
            or type(matrix.get("abi")) is not dict or type(matrix.get("limits")) is not dict):
        raise ValueError("versioned Selfhost-Core support matrix required")
    declared = matrix.get("source_identity", {}).get("files")
    if (type(declared) is not dict or not declared
            or any(language_files.get(name) != value for name, value in declared.items())
            or not (set(BOOTSTRAP_FILES) - {SUPPORT}) <= set(declared)
            or not {name for name in worker if name.startswith("hepta/")} <= set(declared)):
        raise ValueError("Selfhost-Core source/seed/loader closure differs from actual committed files")
    if (literal_constant(Path(hepta_root) / "hepta/hia_program_native.py", "TARGET") != TARGET
            or literal_constant(Path(hepta_root) / "hepta/hia_program_native.py", "PROFILE")
            != "hepta.hia.program.direct-linux-x86_64.v1"
            or literal_constant(Path(hepta_root) / "hepta/hia_native_byte_abi.py", "PROFILE")
            != "hepta.hia.program.direct-linux-x86_64-borrowed-bytes.v1"):
        raise ValueError("native source target/ABI differs from this reviewed release profile")
    versions = {"hepta": hepta_revision, "runtime": runtime_revision}
    roots = {"hepta": hepta_root, "runtime": runtime_root}
    lock = {
        "schema": SCHEMA, "release_id": release_id,
        "entrypoint": "python3 -B tools/hia_release.py",
        "materialization": dict(MATERIALIZATION),
        "sources": {name: {"repository": REPOSITORIES[name], "commit": revision,
                           "tree": preflight.git(roots[name], "rev-parse", revision + "^{tree}").strip()}
                    for name, revision in versions.items()},
        "installation": pins,
        "target_abi": dict(TARGET_ABI),
        "selfhost": {"profile": matrix["profile"], "abi": matrix["abi"], "limits": matrix["limits"],
            "support_matrix": SUPPORT, "support_matrix_sha256": language_files[SUPPORT],
            "source": "examples/hia_bootstrap/selfhost.hiaasm",
            "source_sha256": language_files["examples/hia_bootstrap/selfhost.hiaasm"],
            "loader": "tools/hia_selfhost_child.py",
            "loader_sha256": language_files["tools/hia_selfhost_child.py"], **SELFHOST_STATIC},
        "files": {"hepta": language_files, "runtime": runtime_files},
        "mcp": dict(MCP_CONTRACT),
        "qualification": dict(QUALIFICATION),
    }
    # The subprocess and inventory are not a lock against independent writers.
    # Re-observe exact bytes and cleanliness before returning a frozen record.
    if committed_files(hepta_root, hepta_revision, language_files) != language_files:
        raise ValueError("Hepta source changed during release measurement")
    if committed_files(runtime_root, runtime_revision, runtime_files) != runtime_files:
        raise ValueError("runtime source changed during release measurement")
    for name, revision in versions.items():
        if identities[name] != preflight.source_identity(roots[name], revision):
            raise ValueError("source identity changed during release measurement")
    return lock


def load_lock(path, expected=None):
    raw = read_bytes(path)
    if expected is not None and digest(raw) != expected:
        raise ValueError("release lock digest differs from supplied pin")
    lock = preflight.decode(raw)
    if type(lock) is not dict or lock.get("schema") != SCHEMA:
        raise ValueError("unsupported HIA release lock")
    if set(lock) != {"schema", "release_id", "entrypoint", "materialization", "sources", "installation", "target_abi",
                     "selfhost", "files", "mcp", "qualification"}:
        raise ValueError("release lock has missing or unknown fields")
    if (preflight.canonical(lock["qualification"]) != preflight.canonical(QUALIFICATION)
            or lock["entrypoint"] != "python3 -B tools/hia_release.py"
            or preflight.canonical(lock["target_abi"]) != preflight.canonical(TARGET_ABI)):
        raise ValueError("source lock cannot grant deployment/Agent/benefit qualification")
    if (not isinstance(lock["release_id"], str)
            or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", lock["release_id"])
            or preflight.canonical(lock["mcp"]) != preflight.canonical(MCP_CONTRACT)):
        raise ValueError("release id or eleven-tool contract is malformed")
    if preflight.canonical(lock["materialization"]) != preflight.canonical(MATERIALIZATION):
        raise ValueError("release source materialization scope is unsupported")
    if set(lock.get("sources", {})) != set(REPOSITORIES):
        raise ValueError("release must bind both repositories")
    for name, repo in REPOSITORIES.items():
        source = lock["sources"][name]
        if (type(source) is not dict or set(source) != {"repository", "commit", "tree"}
                or source["repository"] != repo
                or any(not isinstance(source[key], str) or not re.fullmatch(r"[0-9a-f]{40}", source[key])
                       for key in ("commit", "tree"))):
            raise ValueError("release source identity is malformed")
    preflight.validate_pins(lock.get("installation"))
    files = lock["files"]
    if type(files) is not dict or set(files) != set(REPOSITORIES):
        raise ValueError("both source file inventories are required")
    for name, required in (("hepta", (*BOOTSTRAP_FILES, *ENTRY_FILES, *CANDIDATE_FILES)), ("runtime", RUNTIME_FILES)):
        inventory = files[name]
        if type(inventory) is not dict or not set(required) <= set(inventory):
            raise ValueError("release file inventory is incomplete")
        for filename, value in inventory.items():
            if (type(filename) is not str or not re.fullmatch(r"[A-Za-z0-9_./-]+", filename)
                    or filename.startswith("/") or any(p in ("", ".", "..") for p in filename.split("/"))
                    or type(value) is not str or not re.fullmatch(r"[0-9a-f]{64}", value)):
                raise ValueError("release file identity is malformed")
    selfhost = lock["selfhost"]
    dynamic = {"profile", "abi", "limits", "support_matrix_sha256", "source_sha256", "loader_sha256"}
    if (type(selfhost) is not dict or set(selfhost) != set(SELFHOST_STATIC) | dynamic
            or any(preflight.canonical(selfhost.get(name)) != preflight.canonical(value)
                   for name, value in SELFHOST_STATIC.items())
            or type(selfhost["profile"]) is not str or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", selfhost["profile"])
            or type(selfhost["abi"]) is not dict or not selfhost["abi"]
            or type(selfhost["limits"]) is not dict or not selfhost["limits"]
            or any(selfhost[name + "_sha256"] != files["hepta"][selfhost[name]]
                   for name in ("support_matrix", "source", "loader"))):
        raise ValueError("selfhost support/source/loader declaration is inconsistent")
    return lock, digest(raw)


def check_lock(lock, hepta_root, runtime_root, python):
    observed = build_lock(hepta_root, lock["sources"]["hepta"]["commit"],
        runtime_root, lock["sources"]["runtime"]["commit"], python, lock["release_id"])
    if preflight.canonical(observed) != preflight.canonical(lock):
        raise ValueError("release capability/source contract differs from measured installation")
    return observed


def write_new(path, value):
    path = preflight.absolute_path(path)
    # Reuse the runtime's descriptor-relative publication policy after selection.
    parent, name = preflight.open_parent(path)
    try:
        preflight.require_trusted_publication_parent(parent)
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=parent)
        with os.fdopen(fd, "wb") as stream:
            raw = preflight.json_bytes(value)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.fsync(parent)
        return digest(raw)
    finally:
        os.close(parent)


def _source_checkout_run(command, *, repository, revision, stage, timeout, **options):
    """Keep exception types for callers, but attach only safe CLI diagnostics."""
    try:
        return subprocess.run(command, check=True, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=timeout, **options)
    except (OSError, subprocess.SubprocessError) as exc:
        if isinstance(exc, subprocess.TimeoutExpired):
            failure_kind = "timed_out"
        elif isinstance(exc, subprocess.CalledProcessError):
            failure_kind = "command_failed"
        elif isinstance(exc, OSError):
            failure_kind = "could_not_start"
        else:
            failure_kind = "subprocess_error"
        # These fields come from fixed stage/role names and the validated lock.
        # Never include command, source URL, exception text, stdout or stderr.
        diagnostic = {
            "repository": repository, "stage": stage, "pinned_commit": revision,
            "failure_kind": failure_kind, "timeout_seconds": timeout,
            "next_step": "Check Git availability, selected repository access and availability "
                         "of the pinned commit. Keep the failed destination for diagnosis; "
                         "retry with a new --directory after resolving the failure.",
        }
        if isinstance(exc, subprocess.CalledProcessError):
            diagnostic["exit_code"] = exc.returncode
        exc.source_checkout_diagnostic = diagnostic
        raise


def checkout_remote_source(source, revision, target, *, repository="source"):
    """Fetch the pinned commit without downloading unrelated branch history.

    Blob filtering is only a transport choice. Git resolves the declared source
    closure on checkout; check_lock still measures every required source byte.
    A failed exact fetch never falls back to a branch tip or a different URL.
    """
    commands = (
        ("init", ["git", "init", "--", str(target)]),
        ("remote_add", ["git", "-C", str(target), "remote", "add", "origin", str(source)]),
        ("configure_promisor", ["git", "-C", str(target), "config", "remote.origin.promisor", "true"]),
        ("configure_blob_filter", ["git", "-C", str(target), "config", "remote.origin.partialclonefilter", "blob:none"]),
        ("fetch", ["git", "-C", str(target), "fetch", "--no-tags", "--no-recurse-submodules",
                   "--filter=blob:none", "--depth=1", "origin", revision]),
    )
    for stage, command in commands:
        _source_checkout_run(command, repository=repository, revision=revision,
                             stage=stage, timeout=300,
                             env={**os.environ, "GIT_TERMINAL_PROMPT": "0"})
    fetched = _source_checkout_run(
        ["git", "--no-replace-objects", "-C", str(target), "rev-parse", "FETCH_HEAD"],
        repository=repository, revision=revision, stage="verify_fetch", timeout=30).stdout.strip()
    if fetched != revision.encode("ascii"):
        raise ValueError(f"{repository} source verify_fetch differs from the pinned release commit")


def materialize(lock, destination, repositories, python):
    """Create fresh exact-source checkouts; no dependency or service install."""
    destination = preflight.absolute_path(destination)
    if destination.exists() or destination.is_symlink():
        raise ValueError("materialization destination already exists")
    if not destination.parent.is_dir() or destination.parent.resolve() != destination.parent:
        raise ValueError("materialization parent must be an existing nonsymlink directory")
    destination.mkdir(mode=0o700)
    for name in REPOSITORIES:
        override = repositories.get(name)
        source = override or lock["sources"][name]["repository"]
        target = destination / name
        # A local cache changes transport only. Checkout identities still have
        # to match the immutable release, including actual ignored source bytes.
        if override is None:
            checkout_remote_source(source, lock["sources"][name]["commit"], target, repository=name)
        else:
            _source_checkout_run(
                ["git", "clone", "--no-checkout", "--no-hardlinks", "--", str(source), str(target)],
                repository=name, revision=lock["sources"][name]["commit"], stage="clone", timeout=300)
        if name == "hepta":
            # The repository's historical evidence blobs can be absent from a
            # valid local partial cache. Declare the complete source closure
            # explicitly rather than inheriting an unrelated checkout's sparse
            # index or treating omitted archives as deleted source.
            _source_checkout_run(
                ["git", "-C", str(target), "sparse-checkout", "set", "--cone", *SOURCE_DIRECTORIES],
                repository=name, revision=lock["sources"][name]["commit"], stage="sparse_checkout", timeout=120)
        _source_checkout_run(
            ["git", "-C", str(target), "checkout", "--detach", lock["sources"][name]["commit"]],
            repository=name, revision=lock["sources"][name]["commit"], stage="checkout",
            timeout=CHECKOUT_TIMEOUT_SECONDS[name])
    check_lock(lock, destination / "hepta", destination / "runtime", python)
    return {"hepta_root": str(destination / "hepta"), "runtime_checkout": str(destination / "runtime"),
            "status": "exact_sources_materialized", "dependencies_installed": False,
            "production_deployed": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", type=Path, default=DEFAULT_LOCK)
    parser.add_argument("--lock-sha256")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("describe", help="show the selected source, ABI and selfhost contract")
    freeze = sub.add_parser("freeze", help="release engineer: measure one clean source pair")
    freeze.add_argument("--hepta-revision", required=True)
    freeze.add_argument("--runtime-revision", required=True)
    freeze.add_argument("--release-id", required=True)
    freeze.add_argument("--output", required=True, type=Path)
    for name in ("check", "prepare", "probe"):
        sub.add_parser(name)
    for name in ("freeze", "check", "prepare", "probe"):
        command = sub.choices[name]
        command.add_argument("--hepta-root", type=Path, required=True)
        command.add_argument("--runtime-checkout", type=Path, required=True)
        command.add_argument("--worker-python", type=Path, default=Path(sys.executable))
    for name in ("prepare", "probe"):
        command = sub.choices[name]
        command.add_argument("--config", type=Path, required=True)
        command.add_argument("--output-directory", type=Path, required=True)
    probe = sub.choices["probe"]
    for name in ("candidate", "runtime-binary", "full-contract"):
        probe.add_argument("--" + name, type=Path, required=True)
        probe.add_argument("--" + name + "-sha256", required=True)
    probe.add_argument("--timeout-seconds", type=int, default=60, choices=range(1, 3601), metavar="1..3600")
    checkout = sub.add_parser("materialize", help="create cold exact-source checkouts from remote or local repositories")
    checkout.add_argument("--directory", type=Path, required=True)
    checkout.add_argument("--hepta-repository")
    checkout.add_argument("--runtime-repository")
    checkout.add_argument("--worker-python", type=Path, default=Path(sys.executable))
    args = parser.parse_args(argv)
    try:
        if args.command == "freeze":
            lock = build_lock(args.hepta_root, args.hepta_revision, args.runtime_checkout,
                              args.runtime_revision, args.worker_python, args.release_id)
            lock_hash = write_new(args.output, lock)
            result = {"status": "source_contract_frozen", "release_lock_sha256": lock_hash,
                      "production_deployed": False}
        else:
            lock, lock_hash = load_lock(args.lock, args.lock_sha256)
            if args.command == "describe":
                result = {"status": "source_contract_declared", "installed_source_checked": False,
                          "release_lock_sha256": lock_hash, "contract": lock}
            elif args.command == "materialize":
                result = materialize(lock, args.directory,
                    {"hepta": args.hepta_repository, "runtime": args.runtime_repository}, args.worker_python)
                result["release_lock_sha256"] = lock_hash
            else:
                check_lock(lock, args.hepta_root, args.runtime_checkout, args.worker_python)
                result = {"status": "source_contract_verified", "release_lock_sha256": lock_hash,
                          "production_deployed": False}
                if args.command == "prepare":
                    candidate, configuration = preflight.prepare(args.hepta_root,
                        lock["sources"]["hepta"]["commit"], lock["sources"]["runtime"]["commit"],
                        args.config, args.worker_python)
                    files = {"candidate.json": preflight.json_bytes(candidate),
                             "runtime-config.json": configuration,
                             "release-binding.json": preflight.json_bytes(result)}
                    preflight.publish(args.output_directory, files)
                    result.update(status="source_pinned", candidate_sha256=digest(files["candidate.json"]),
                                  configuration_sha256=digest(configuration))
                elif args.command == "probe":
                    candidate, metadata, config_metadata = preflight.load_candidate(
                        args.candidate, args.candidate_sha256, args.config)
                    if candidate["source_pair"] != {
                            "hepta_commit": lock["sources"]["hepta"]["commit"],
                            "runtime_commit": lock["sources"]["runtime"]["commit"],
                            "installation": lock["installation"]}:
                        raise ValueError("probe candidate differs from the selected release")
                    contract = preflight.ToolContract.load(args.full_contract, args.full_contract_sha256)
                    checks, files, binary = preflight.probe(candidate, args.config, args.runtime_binary,
                        args.runtime_binary_sha256, contract, timeout=args.timeout_seconds)
                    check_lock(lock, args.hepta_root, args.runtime_checkout, args.worker_python)
                    preflight.load_candidate(args.candidate, args.candidate_sha256, args.config)
                    result.update(status="entrypoint_observed", checks=checks,
                        evidence={"origin": "actual_configured_stdio_mcp", "runtime_binary": binary,
                                  "captures": {name: digest(raw) for name, raw in files.items()}},
                        entrypoint_observed=True, current_agent_discovery_established=False,
                        candidate_sha256=metadata["sha256"], configuration_sha256=config_metadata["sha256"],
                        full_contract_file_sha256=args.full_contract_sha256,
                        binary_build_provenance_attested=False)
                    files["release-preflight.json"] = preflight.json_bytes(result)
                    preflight.publish(args.output_directory, files)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError, RecursionError, AssertionError,
            RuntimeError, SyntaxError, subprocess.SubprocessError) as exc:
        # Do not echo subprocess argv, which may carry an administrator's private
        # repository transport. Preserve the failed stage without leaking it.
        diagnostic = getattr(exc, "source_checkout_diagnostic", None)
        if diagnostic is not None:
            message = (f"source checkout failed: {diagnostic['repository']}/"
                       f"{diagnostic['stage']} ({diagnostic['failure_kind']})")
        else:
            message = "source checkout command failed" if isinstance(exc, subprocess.SubprocessError) else str(exc)
        error = {"status": "rejected", "error": message[:4096], "production_deployed": False}
        if diagnostic is not None:
            error["source_checkout"] = diagnostic
        if isinstance(exc, preflight.IncompleteProbe):
            error["recovery"] = exc.recovery
        print(json.dumps(error, sort_keys=True), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
