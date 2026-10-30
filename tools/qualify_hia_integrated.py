#!/usr/bin/env python3
"""Qualify the merged contracts once against one frozen, committed source tree.

The full Python discovery is mandatory and executes exactly once. Its critical
module coverage is a subset of that same run, never another test denominator.
Real tool, Linux seal, separately pinned native NDU profiles, and Rust crate gates
are retained separately. Standalone historical performance/agent campaigns are
neither replayed nor promoted to measurements of this merged source revision.
Full regression still executes its existing native timing/budget controls.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import errno
from hashlib import sha1, sha256
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.qualify_hia_ndu_pipeline import _write
from tools.qualify_hia_unified import _command, cargo_test_outcome, unittest_outcome
from tools.release_check import _read_regular_evidence

SCHEMA = "hepta.hia.integrated-contract-qualification.v2"
RECURSIVE_SOURCE = "2590c0c94c5bf9a9004caeeb7b75edd6faf3eb8b"
FINITE_SOURCE = "4b6391e116949af0c7e59776baead67271856bdb"
STREAM_SOURCE = "c4a1bbed3a39beba43a6abf1a18b6f75c5725c21"
EXPECTED_GATE_NAMES = ("actual_tools_and_linux_seals", "ranking_bridge_identity",
                       "recursive_bridge_identity", "finite_bridge_identity", "stream_bridge_identity",
                       "rust_resource_crate", "full_regression", "merge_and_profile_coverage")
CRITICAL_MODULES = {
    "wire_rejection": ("test_hia_inmemory_json_key_collisions", "test_hia_inmemory_surrogate_wire",
                       "test_hia_program_tools"),
    "cpp_lexical_ownership": ("test_cpp_scoped_ownership_migration", "test_cpp_composed_migrate",
                              "test_cpp_composed_project"),
    "llvm_allocation_and_native_observables": ("test_hia_program_llvm", "test_hia_empty_owner_native",
                                               "test_hia_native_side_effects", "test_hia_native_pinning",
                                               "test_hia_native_cleanup", "test_hia_native_source_reinspect",
                                               "test_hia_v6_differential"),
    "acyclic_scalar_smt": ("test_hia_translation_validation", "test_hia_encoding_guard",
                           "test_hia_scalar_totality"),
    "compositional_barrier_smt": ("test_hia_optimization",),
    "guarded_inductive_optimization": ("test_hia_guarded_optimization",),
    "proof_profile_integration": ("test_hia_profile_integration",),
    "ranking_ndu": ("test_hia_ndu_bridge", "test_hia_ndu_optimizer", "test_hia_ndu_optimizer_budget",
                    "test_hia_ndu_optimizer_transport", "test_hia_specialization"),
    "recursive_ndu": ("test_hia_ndu", "test_hia_ndu_loop", "test_hia_economic_search",
                      "test_hia_economic_experiment", "test_hia_economic_budget"),
    "ndu_protocol_isolation": ("test_hia_ndu_bridge_isolation", "test_hia_recursive_ndu_builder"),
    "finite_native_continuation_graph": ("test_hia_ndu_graph", "test_hia_next_evaluation"),
    "exact_native_advisory_reuse": ("test_hia_ndu_cache",),
    "sealed_ndu_stream_net_value": ("test_hia_ndu_session", "test_hia_ndu_net_value"),
    "real_cpp_host_contract": ("test_cpp_upstream_host", "test_cpp_contract_capture"),
    "filecheck_research_target_and_signal_boundaries": ("test_hia_filecheck_target_profile",
                                                        "test_hia_filecheck_linker_dispatch",
                                                        "test_hia_filecheck_native_isolation"),
    "native_runtime_lifecycles": ("test_hia_multiversion", "test_hia_background_optimizer",
                                  "test_hia_adaptive", "test_hia_scalar_state",
                                  "test_hia_multiversion_totality", "test_hia_native_retirement",
                                  "test_hia_stateful", "test_hia_native_mapping_identity",
                                  "test_hia_adaptive_retirement", "test_hia_multiversion_mapping"),
    "cli_and_route_contracts": ("test_hia_optimization_cli", "test_hia_routes"),
    "finite_actions_and_instruction_grammar": ("test_hia_finite_actions", "test_hia_x86_search",
                                               "test_hia_x86_bounded_affine"),
    "rust_resource_execution": ("test_hia_rust_owned_vm", "test_hia_rust_owned_cfg",
                                "test_hia_rust_owned_memory", "test_hia_rust_migration"),
    "raw_rust_integer_admission": ("test_hia_rust_raw_integer",),
    "partial_record_states": ("test_hia_partial_record", "test_hia_partial_record_scenarios",
                              "test_hia_partial_finite_bounds"),
    "source_local_views": ("test_hia_source_local_views",),
    "source_unit_enums": ("test_hia_source_unit_enums",),
    "rust_invocation_bound_execution": ("test_hia_rust_execution_crosscheck", "test_hia_rust_transport_lifecycle",
                                        "test_hia_rust_bound_depth", "test_hia_rust_budget_v3",
                                        "test_hia_rust_api_v4", "test_hia_rust_executable_custody"),
    "reviewed_safety_protocol": ("test_hia_safety_protocol", "test_hia_integrated_inputs",
                                 "test_hia_source_head_identity", "test_hia_rust_budget_qualification",
                                 "test_hia_integrated_workflow"),
    "scalar_c_pilot_admission": ("test_c2hepta_api_path_isolation", "test_c2hepta_bounded_source",
        "test_c2hepta_bounded_capture", "test_migration_ir_identifier_guard",
        "test_migration_ir_literal_guard", "test_migration_ir_structural_budget",
        "test_migration_ir_neg_payload_guard", "test_migration_ir_parser_budget"),
    "source_partial_restore": ("test_hia_source_partial",),
    "source_scalar_export_boundaries": ("test_hia_source_exports",),
    "incremental_v8_admission": ("test_hia_incremental", "test_hia_incremental_independent",
                                 "test_hia_incremental_v8"),
    "cpp_constexpr_migration": ("test_cpp_constexpr_migration",),
    "parameter_bound_loan_returns": ("test_hia_returned_loans", "test_hia_returned_chain_loans",
                                     "test_hia_returned_loan_qualification"),
    "returned_loan_agent_interfaces": ("test_hia_returned_loan_interfaces", "test_hia_patch_impact", "test_hia_edit_batch"),
    "rust_bulk_resource_execution": ("test_hia_rust_bulk_vm",),
    "rust_v8_returned_loan_execution": ("test_hia_rust_returned_loans", "test_hia_rust_crosscheck"),
    "rust_returned_chain_execution": ("test_hia_rust_returned_chains",),
    "returned_loan_resource_budgets": ("test_hia_returned_loan_budgets",),
    "returned_loan_cross_target_execution": ("test_hia_returned_loans_cross",),
    "migration_source_invocation": ("test_c_project_semantic_flags", "test_c_project_source_arguments",
                                    "test_c_project", "test_c_project_driver_names", "test_c_cursor_control"),
    "migration_parameter_entry_effects": ("test_c_array_declarator_guard", "test_c_parameter_entry_effects"),
    "migration_original_parameter_types": ("test_c_parameter_types", "test_c_original_type_host_preflight",
                                           "test_clang_capture", "test_clang_capture_ownership",
                                           "test_darwin_capture",
                                           "test_c_process_limits"),
    "migration_contract_intake_and_ring_evidence": ("test_c_contracts", "test_c_ring_qualification_evidence"),
    "cpp_unique_owner_streaming": ("test_cpp_unique_capture", "test_cpp_unique_project"),
    "prospective_agent_choice_protocol": ("test_hia_batch_disclosed_choices",),
    "native_profile_and_lifecycle_convergence": ("test_hia_native_profile_convergence",),
    "qualification_toolchain_and_budgets": ("test_release_unit_timeout",
        "test_qualification_cargo_environment", "test_hia_unified_workflow_cli", "test_source_checkout_identity",
        "test_hia_semantic_gate_receipts"),
    "rust_native_tool_selection": ("test_linker_selection",),
    "captured_c_source_and_component_migration": ("test_c_project_source_arguments",
        "test_c_project_semantic_flags", "test_c_array_declarator_guard", "test_c_cursor_control",
        "test_c_scalar_control", "test_c_project_dependencies"),
    "nominal_parameter_field_loan_returns": ("test_hia_composite_returned_loans",),
    "shared_ndu_response_contract": ("test_hia_ndu_response", "test_hia_ndu_session"),
    "publication_interruption_ownership": ("test_hia_publication_interruptions",),
    "bounded_scalar_migration": ("test_c2hepta_api_path_isolation", "test_c2hepta_bounded_source",
        "test_migration_ir_identifier_guard", "test_migration_ir_literal_guard",
        "test_migration_ir_structural_budget", "test_migration_ir_neg_payload_guard",
        "test_migration_ir_parser_budget", "test_rustup_real_compiler_identity"),
    "selected_core_llvm_lowering": ("test_hia_scalar_lowering_check",),
    "constant_entry_payload_analysis": ("test_hia_entry_payload_bound",),
    "captured_c_project_views": ("test_hia_c_project_views", "test_hia_cursor_math", "test_hia_c_do_while",
                                 "test_hia_c_loop_jumps", "test_hia_c_loop_migration_qualification"),
    "prepared_artifact_lease_ownership": ("test_hia_artifact_session", "test_hia_artifact_narrowing"),
    "prospective_ndu_reuse_protocol": ("test_hia_ndu_activation", "test_hia_ndu_prepared_reuse",
                                       "test_hia_ndu_narrowed_controls"),
    "real_c_application_maintenance_and_pgo": ("test_hia_legacy_irpgo",),
    "bounded_agent_edits_and_reference_contract": ("test_hia_agent_primitive_into",
        "test_hia_agent_repair", "test_hia_agent_structured", "test_hia_agent_tool_references",
        "test_hia_agent_toolstudy", "test_hia_agent_toolstudy_v9", "test_hia_agent_toolstudy_v11",
        "test_hia_agent_toolstudy_v11_failures"),
    "public_catalogue_agent_decoder": ("test_hia_agent_toolstudy_v12",),
    "captured_scalar_source_snapshot": ("test_c2hepta_snapshot_capture",),
    "scalar_c_ast_capture_and_publication": ("test_c2hepta_artifact_parent_rebind",
        "test_c2hepta_ast_json_structure", "test_c2hepta_bounded_ast",
        "test_c2hepta_bounded_probes", "test_c2hepta_canonical_directory_swap",
        "test_c2hepta_frozen_source_aba", "test_c2hepta_process_group",
        "test_c2hepta_guard_convergence"),
    "guarded_native_opportunity_admission": ("test_hia_guarded_batch",),
    "finite_v8_owner_and_returned_loan_payload": ("test_hia_finite_v8_heap",),
    "captured_c_post_test_loop_semantics": ("test_c_project_do_while",),
    "finite_caller_borrowed_extents": ("test_hia_borrowed_extent_heap",),
    "bounded_scalar_loop_equivalence": ("test_hia_bounded_unroll", "test_hia_crc_kernel"),
    "captured_c_actual_native_targets": ("test_hia_c_posttest_hosts",),
    "bounded_native_execution_context": ("test_hia_finite_context", "test_clang_capture_environment",
        "test_hia_finite_context_reentrancy", "test_hia_finite_context_map_repeat"),
    "crc_static_control_cost_accounting": ("test_hia_crc_context_study",),
    "independent_rust_structural_bounds": ("test_hia_rust_static_budget",),
    "independent_rust_byte_dag_admission": ("test_hia_rust_byte_dag",),
    "independent_rust_finite_entry_heap": ("test_hia_rust_finite_heap",),
    "captured_scalar_call_first_trap_proof": ("test_hia_scalar_call_validation",),
    "real_stb_changed_body_maintenance": ("test_hia_stb_divide_update",),
    "real_stb_matched_candidate_controls": ("test_hia_stb_specialization", "test_hia_stb_ndu_protocol"),
    "captured_original_musl_postfix": ("test_c_postfix_if",),
    "bounded_oracle_reuse_and_diverse_cost_protocol": ("test_hia_finite_context_oracle_reuse",
                                                     "test_hia_crc_context_reuse_study"),
    "independent_rust_scoped_abort_cleanup": ("test_hia_rust_scoped_cleanup",),
    "finite_cpp_parent_checkpoint_reconstruction": ("test_cpp_json_checkpoint",),
    "crc_parallel_bit_proposals_and_complete_cost_protocol": ("test_hia_crc_linear",
        "test_hia_crc_linear_qualification", "test_hia_crc_linear_economics"),
    "public_selection_first_agent_decoder": ("test_hia_agent_toolstudy_v13",),
}


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _git(*arguments, root=ROOT):
    # A local refs/replace entry must not reinterpret the commit/blob whose
    # immutable identity is being qualified. This also covers source_state.
    return subprocess.check_output(["git", "--no-replace-objects", *map(str, arguments)], cwd=root)


def _digest_file(path, *, expected_blob=None, expected_mode=None):
    """Hash stable regular bytes, optionally binding them to a raw Git blob."""
    path = Path(path)
    before = path.lstat()
    _require(stat.S_ISREG(before.st_mode), "expected regular file: " + str(path))
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        _require(stat.S_ISREG(opened.st_mode), "opened object is not a regular file: " + str(path))
        _require((before.st_dev, before.st_ino, before.st_mode, before.st_size,
                  before.st_mtime_ns, before.st_ctime_ns)
                 == (opened.st_dev, opened.st_ino, opened.st_mode, opened.st_size,
                     opened.st_mtime_ns, opened.st_ctime_ns),
                 "file changed before identity read: " + str(path))
        if expected_mode is not None:
            # Git tracks the owner's executable bit, not all POSIX permissions.
            # Do not let core.fileMode=false suppress this identity boundary.
            actual_mode = "100755" if opened.st_mode & stat.S_IXUSR else "100644"
            _require(actual_mode == expected_mode, "source mode differs from raw HEAD tree: " + str(path))
        digest = sha256()
        blob_digest = (sha1(b"blob " + str(opened.st_size).encode("ascii") + b"\0")
                       if expected_blob is not None else None)
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
            if blob_digest is not None:
                blob_digest.update(chunk)
        after_fd = os.fstat(stream.fileno())
    after = path.lstat()
    signatures = {(v.st_dev, v.st_ino, v.st_mode, v.st_size, v.st_mtime_ns, v.st_ctime_ns)
                  for v in (before, opened, after_fd, after)}
    _require(len(signatures) == 1, "file changed during identity read: " + str(path))
    if blob_digest is not None:
        _require(blob_digest.hexdigest() == expected_blob,
                 "source bytes differ from raw HEAD blob: " + str(path))
    return digest.hexdigest()


def _inventory(tree):
    # The index is not a source of truth: assume-unchanged/skip-worktree can
    # hide modified or missing working bytes even from a clean `git status`.
    # One raw tree listing plus a bounded dual-hash read per file avoids loading
    # all tracked evidence blobs or forking cat-file once per source file.
    # Include directory entries: -r alone hides empty subtrees, including any
    # unsafe paths present in a deliberately constructed raw tree object.
    listing = _git("ls-tree", "-r", "-t", "--full-tree", "-z", tree)
    _require(not listing or listing.endswith(b"\0"), "incomplete raw HEAD tree inventory")
    entries = {}
    for record in listing.split(b"\0")[:-1]:
        metadata, separator, raw_name = record.partition(b"\t")
        fields = metadata.split(b" ")
        _require(separator and len(fields) == 3, "malformed raw HEAD tree member")
        mode, kind, blob = fields
        _require(((mode in {b"100644", b"100755"} and kind == b"blob")
                  or (mode == b"040000" and kind == b"tree"))
                 and re.fullmatch(rb"[0-9a-f]{40}", blob),
                 "raw HEAD tree member must be a directory or regular SHA-1 blob")
        name = raw_name.decode("utf-8")
        _require(name and all(part not in {"", ".", "..", ".git"} for part in name.split("/"))
                 and name not in entries, "unsafe or duplicate raw HEAD tree path")
        entries[name] = (mode.decode("ascii"), blob.decode("ascii"))
    return {name: _digest_file(ROOT / name, expected_mode=mode, expected_blob=blob)
            for name, (mode, blob) in sorted(entries.items()) if mode != "040000"}


def _source_state():
    head = _git("rev-parse", "HEAD").decode().strip()
    _require(re.fullmatch(r"[0-9a-f]{40}", head), "source HEAD must use full SHA-1 identity")
    tree = _git("rev-parse", head + "^{tree}").decode().strip()
    _require(re.fullmatch(r"[0-9a-f]{40}", tree), "source tree must use full SHA-1 identity")
    files = _inventory(tree)
    status = _git("status", "--porcelain", "--untracked-files=all").decode()
    _require(_git("rev-parse", "HEAD").decode().strip() == head,
             "source HEAD changed during identity read")
    return {"head": head, "tree": tree, "status": status, "files": files}


def _resolve_tool(value):
    return str(Path(shutil.which(str(value)) or str(value)).resolve(strict=True))


@contextmanager
def _environment(options, output):
    clang = _resolve_tool(options.clang)
    cargo, rustc = _resolve_tool(options.cargo), _resolve_tool(options.rustc)
    updates = {
        "CLANG": clang, "HEPTA_CLANG": clang, "CLANGXX": str(Path(clang).with_name("clang++")),
        "RUSTC": rustc, "HEPTA_NDU_BRIDGE": str(options.ranking_bridge.resolve()),
        "HEPTA_NDU_BUILD": str(options.ranking_build_receipt.resolve().parent),
        "HEPTA_NDU_UPSTREAM": str(options.ranking_upstream.resolve()),
        "HEPTA_RECURSIVE_NDU_BRIDGE": str(options.recursive_bridge.resolve()),
        "HEPTA_RECURSIVE_NDU_IDENTITY": str(options.recursive_identity.resolve()),
        "HEPTA_FINITE_NDU_BRIDGE": str(options.finite_bridge.resolve()),
        "HEPTA_FINITE_NDU_IDENTITY": str(options.finite_identity.resolve()),
        "HEPTA_NDU_STREAM_BRIDGE": str(options.stream_bridge.resolve()),
        "HEPTA_NDU_STREAM_IDENTITY": str(options.stream_identity.resolve()),
        "HEPTA_NDU_STREAM_UPSTREAM": str(options.stream_upstream.resolve()),
        # This is mandatory integrated coverage, including direct CLI use.
        # Missing tools must fail qualification, not opt this native class out.
        "HEPTA_RUN_ARTIFACT_SESSION": "1",
        "CARGO_NET_OFFLINE": "true", "PYTHONDONTWRITEBYTECODE": "1",
        "CARGO_TARGET_DIR": str(options.cargo_target_dir.resolve() if options.cargo_target_dir
                                else output / "rust-target"),
        "PATH": os.pathsep.join([str(Path(clang).parent), str(Path(cargo).parent),
                                  str(Path(rustc).parent), os.environ.get("PATH", "")]),
        "PYTHONPATH": os.pathsep.join([str(ROOT), os.environ.get("PYTHONPATH", "")]),
    }
    previous = {key: os.environ.get(key) for key in updates}
    old_cwd = Path.cwd()
    try:
        os.environ.update(updates)
        os.chdir(ROOT)
        yield updates
    finally:
        os.chdir(old_cwd)
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def _tool_gate(options, output):
    import fcntl
    import z3
    from hepta.hia_native_differential import _pin_native_artifact
    from hepta.hia_optimization import PINNED_Z3_VERSION, _solver_identity
    from hepta.c_parameter_types import original_type_reader_identity

    _require(platform.system() == "Linux" and platform.machine() in {"x86_64", "AMD64"},
             "this integrated native qualification requires the declared Linux x86-64 host")
    _require(z3.get_version_string() == PINNED_Z3_VERSION == "4.15.4", "the actual Z3 pin differs")
    selected = {
        "python": sys.executable,
        "clang": os.environ["CLANG"], "clangxx": os.environ["CLANGXX"],
        "cargo": options.cargo, "rustc": options.rustc, "gcc": "gcc", "gxx": "g++",
        "lld": os.environ.get("HEPTA_LLD", "ld.lld"),
        "llvm_readobj": os.environ.get("HEPTA_LLVM_READOBJ", "llvm-readobj"),
        "qemu_aarch64": os.environ.get("HEPTA_QEMU_AARCH64", "qemu-aarch64"),
        "qemu_riscv64": os.environ.get("HEPTA_QEMU_RISCV64", "qemu-riscv64"),
        "qemu_x86_64": os.environ.get("HEPTA_QEMU_X86_64", "qemu-x86_64"),
        "qemu_system_arm": "qemu-system-arm",
        "lean": os.environ.get("LEAN", str(ROOT.parent / "toolchains/lean-4.19.0/bin/lean")),
    }
    tools = {}
    for name, value in selected.items():
        # Keep argv[0]: ld.lld and clang++ may select a driver flavor through
        # their symlink name. Hash the resolved executable separately.
        invocation = str(Path(shutil.which(str(value)) or str(value)).absolute())
        path = _resolve_tool(invocation)
        digest = _digest_file(path)
        arguments = [invocation]
        if name == "lld" and Path(invocation).name in {"lld", "rust-lld"}:
            arguments += ["-flavor", "gnu"]
        execution = _command([*arguments, "--version"], timeout=20)
        tools[name] = {"invocation_path": invocation, "path": path,
                       "sha256": digest, "execution": execution}
        _write(output / (name + "-tool-probe.json"), tools[name])
        _require(execution["returncode"] == 0 and (execution["stdout"] + execution["stderr"]).strip(),
                 "actual tool version command failed: " + name)
        _require(_digest_file(path) == digest, "tool changed during version probe: " + name)
    payload = b"integrated native pinning probe\x00\xff"
    probe = output / "seal-probe.bin"
    probe.write_bytes(payload)
    original, _, descriptor = _pin_native_artifact(probe)
    try:
        seals = fcntl.fcntl(descriptor, getattr(fcntl, "F_GET_SEALS", 1034))
        _require(original == payload and seals & 0xF == 0xF, "actual required kernel seals absent")
        try:
            os.pwrite(descriptor, b"x", 0)
        except OSError as error:
            _require(error.errno == errno.EPERM, "unexpected sealed write error")
        else:
            raise ValueError("sealed bytes were writable")
        _require(os.pread(descriptor, len(payload) + 1, 0) == payload, "sealed readback differs")
    finally:
        os.close(descriptor)
    solver = _solver_identity(z3)
    original_type_reader = original_type_reader_identity(os.environ["CLANG"])
    _require(original_type_reader["compiler"]["path"] == tools["clang"]["path"] and
             original_type_reader["compiler"]["executable_sha256"] == tools["clang"]["sha256"],
             "original-type reader uses a different actual compiler")
    _write(output / "original-type-reader-probe.json", original_type_reader)
    return {"passed": True, "tools": tools, "solver": solver,
            "original_type_reader": original_type_reader,
            "linux_seals": {"required_bits": 15, "actual_bits": seals,
                             "actual_write_rejected_errno": errno.EPERM, "exact_readback": True},
            "scope": "actual host tools and kernel capability; individual native tests still execute their own gates"}


def _checked_map(root, expected):
    _require(type(expected) is dict and bool(expected), "a nonempty source inventory is required")
    actual = {}
    for name, digest in expected.items():
        relative = Path(name)
        _require(type(name) is str and not relative.is_absolute() and ".." not in relative.parts,
                 "source inventory has an invalid relative path")
        _require(type(digest) is str and re.fullmatch(r"[0-9a-f]{64}", digest), "invalid source digest")
        actual[name] = _digest_file(root / relative)
    _require(actual == expected, "recorded source/build inputs differ from actual files")
    return actual


def _git_inventory(checkout, commit, expected):
    observed = _git("rev-parse", commit + "^{commit}", root=checkout).decode().strip()
    _require(observed == commit, "upstream Git commit identity differs")
    # Read the selected commit's raw blobs. `git archive` can apply
    # export-subst/export-ignore and, for a partial clone, prefetch unrelated
    # blobs from the whole repository before it filters the requested paths.
    # Neither transformation nor unrelated downloads belong in this identity
    # check of the already-declared compiler inputs.
    tree = _git("ls-tree", "--full-tree", "-r", "-z", commit, "--", *sorted(expected), root=checkout)
    entries = {}
    for record in tree.split(b"\0"):
        if not record:
            continue
        metadata, encoded_path = record.split(b"\t", 1)
        mode, kind, object_id = metadata.decode("ascii").split()
        name = encoded_path.decode("utf-8")
        _require(mode in {"100644", "100755"} and kind == "blob" and name not in entries,
                 "source tree contains a duplicate or nonregular member")
        entries[name] = object_id
    _require(set(entries) == set(expected), "source tree paths differ from the declared input inventory")
    original = {name: sha256(_git("cat-file", "blob", object_id, root=checkout)).hexdigest()
                for name, object_id in entries.items()}
    _require(original == expected, "recorded source bytes differ from the exact upstream Git object")
    return observed


def _ranking_gate(options, output):
    from hepta.hia_ndu_optimizer import _bridge_identity, _native_rank

    bridge = {"binary": str(options.ranking_bridge), "build_receipt": str(options.ranking_build_receipt)}
    _, identity = _bridge_identity(bridge)
    raw, _ = _read_regular_evidence(options.ranking_build_receipt)
    _require(sha256(raw).hexdigest() == identity["build_receipt_sha256"], "ranking receipt changed during read")
    receipt = json.loads(raw)
    _checked_map(options.ranking_build_receipt.parent, receipt["build_inputs"])
    _git_inventory(options.ranking_upstream, identity["upstream_commit"], receipt["original_source_files"])
    _write(output / "ranking-build-receipt.json", receipt)
    def candidate(name, cost):
        return {"id": name, "cost_q32": cost, "uncertainty_q32": 0, "resource_q32": 0,
                "hard_violation": False, "support_sha256": sha256(name.encode()).hexdigest()}
    request = {"schema": "hepta.hia.ndu-request.v1", "objective_sha256": "11" * 32,
               "generation": 1, "resource_cap_q32": 10 << 32,
               "candidates": [candidate("abstain", 2 << 32), candidate("control", 1 << 32)]}
    response, observed = _native_rank(bridge, request, timeout_s=10)
    _require(observed == identity and response["advisory_recommendation"] == "control",
             "actual native ranking probe did not match its finite control")
    return {"passed": True, "identity": identity, "binary": str(options.ranking_bridge),
            "receipt": str(options.ranking_build_receipt), "build_inputs": receipt["build_inputs"],
            "original_source_files": receipt["original_source_files"], "request": request, "response": response,
            "scope": "one synthetic advisory protocol probe, not a program proof or performance trial"}


def _native_ndu_gate(options, output, *, profile):
    from hepta.hia_ndu import NduBridge, Q32, REQUEST_SCHEMA, candidate, event, finite_plan_request

    _require(profile in {"recursive", "finite", "stream"}, "unknown native NDU profile")
    binary = getattr(options, profile + "_bridge")
    receipt_path = getattr(options, profile + "_identity")
    upstream = getattr(options, profile + "_upstream")
    expected_source = {"recursive": RECURSIVE_SOURCE, "finite": FINITE_SOURCE,
                       "stream": STREAM_SOURCE}[profile]
    cargo = options.finite_cargo if profile == "finite" else options.cargo
    rustc = options.finite_rustc if profile == "finite" else options.rustc
    bridge = (NduBridge.for_finite_profile(binary, receipt_path)
              if profile == "finite" else NduBridge(binary, receipt_path))
    manifest = bridge.manifest
    declared_binary = manifest.get("binary")
    _require(type(declared_binary) is str and Path(declared_binary).is_absolute()
             and Path(declared_binary).resolve(strict=True) == binary.resolve(strict=True),
             "native consumer and external inventory select different executable paths")
    raw, _ = _read_regular_evidence(receipt_path)
    _require(json.loads(raw) == manifest, "recursive identity changed during read")
    receipt_digest = sha256(raw).hexdigest()
    _require(manifest["identity"]["source_commit"] == expected_source, "wrong " + profile + " upstream source pin")
    _require(manifest.get("authority") == "DENY_ALL" and manifest.get("safety_certificate") is False,
             "recursive manifest claimed authority")
    expected_tools = {"builder_sha256": _digest_file(ROOT / "tools/build_hia_recursive_ndu_bridge.py"),
                      "cargo_sha256": _digest_file(Path(_resolve_tool(cargo))),
                      "rustc_sha256": _digest_file(Path(_resolve_tool(rustc)))}
    _require(manifest["build_tools"] == expected_tools, "recursive builder/compiler bytes differ")
    _checked_map(upstream, manifest["native_sources"])
    _checked_map(upstream, manifest["bridge_sources"])
    _git_inventory(upstream, expected_source,
                   {**manifest["native_sources"], **manifest["bridge_sources"]})
    for field, digest_field in (("native_sources", "source_digest"), ("bridge_sources", "bridge_digest")):
        digest = sha256(json.dumps(manifest[field], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        _require(digest == manifest["identity"][digest_field], "recursive embedded inventory digest differs")
    _write(output / (profile + "-build-identity.json"), manifest)
    def plan(name, utility):
        digest = sha256(name.encode()).hexdigest()
        step = event(identity="integrated-probe:" + name, instant_q32=utility, preference_digest=digest)
        return candidate(candidate_id=name, verified=True, verification_digest=digest,
                         support_digest=digest, events=[step], terminal_q32=0)
    request = {"schema": REQUEST_SCHEMA, "objective_digest": "22" * 32, "snapshot_digest": "33" * 32,
               "generation": 1, "utility_unit": "normalized-net-benefit", "resource_unit": "modeled-work",
               "risk_unit": "probability", "resource_budget_q32": 10 * Q32, "risk_ceiling_q32": Q32 // 4,
               "candidates": [plan("abstain", 0), plan("control", Q32)]}
    bundle = None
    if profile == "finite":
        ms = 1_000_000
        bundle = finite_plan_request(objective_digest="11" * 32, snapshot_digest="22" * 32,
            generation=1, initial_state="base",
            states={"base": {"source_sha256": "33" * 32, "verification_sha256": "44" * 32,
                              "status": "verified"},
                    "fast": {"source_sha256": "55" * 32, "verification_sha256": "66" * 32,
                              "status": "verified"}},
            transitions=[{"id": "install-fast", "source": "base", "target": "fast",
                          "setup_ns": 20 * ms, "status": "verified",
                          "verification_sha256": "66" * 32, "support_sha256": "77" * 32}],
            batch_costs_ns={"base": [10 * ms, 200 * ms], "fast": [50 * ms, ms]},
            remaining_budget_ns=60 * ms, completion_value_ns=1000 * ms,
            decision_cost_ns=ms, observations=[])
        request = bundle["request"]
    response = bridge.evaluate(request)
    if bundle is None:
        _require(response["advisory_candidate_id"] == "control", "actual native recursive probe differs")
    else:
        selected = bundle["plans"].get(response["advisory_candidate_id"])
        _require(selected is not None and [action["id"] for action in selected["actions"]]
                 == ["hold", "install-fast"], "actual finite native continuation differs")
    session_observation = None
    if profile == "stream":
        from hepta.hia_ndu_session import NduSession

        # The full suite uses the persistent transport as a separate native
        # dependency. Bind and actually probe that process, not just its
        # compatible one-shot interface or an inherited environment variable.
        with NduSession(binary, receipt_path) as session:
            pid = session.snapshot()["pid"]
            for generation in (1, 2):
                stream_request = {**request, "generation": generation}
                _require(session.evaluate(stream_request) == bridge.evaluate(stream_request),
                         "actual stream and one-shot controls differ")
                _require(session.snapshot()["pid"] == pid, "stream unexpectedly replaced its process")
            session_observation = session.snapshot()
        _require(session.snapshot()["closed"] is True, "stream control did not close")
        session_observation["closed_after_context"] = True
    _require(_digest_file(binary) == manifest["binary_sha256"],
             "recursive binary changed during actual invocation")
    _require(_digest_file(receipt_path) == receipt_digest,
             "recursive identity changed during actual invocation")
    return {"passed": True, "profile": profile, "identity": manifest["identity"], "binary": str(binary),
            "manifest_binary_invocation": declared_binary,
            "binary_sha256": manifest["binary_sha256"], "receipt": str(receipt_path),
            "receipt_sha256": receipt_digest,
            "build_tools": {"cargo": {"path": _resolve_tool(cargo), "sha256": expected_tools["cargo_sha256"]},
                            "rustc": {"path": _resolve_tool(rustc), "sha256": expected_tools["rustc_sha256"]}},
            "native_sources": manifest["native_sources"], "bridge_sources": manifest["bridge_sources"],
            "request": request, "response": response, "finite_bundle": bundle,
            "session_observation": session_observation,
            "scope": "one synthetic advisory protocol probe; verified input flags confer no code admission authority"}


def _recursive_gate(options, output):
    return _native_ndu_gate(options, output, profile="recursive")


def _finite_gate(options, output):
    return _native_ndu_gate(options, output, profile="finite")


def _stream_gate(options, output):
    return _native_ndu_gate(options, output, profile="stream")


def _coverage(execution, outcome):
    identifiers = re.findall(r"(?m)^test\w+ \(((?:tests\.)?test_[^\s)]+)\)", execution["stderr"])
    normalized = [name.removeprefix("tests.") for name in identifiers]
    rows = {}
    for group, modules in CRITICAL_MODULES.items():
        rows[group] = {module: sorted(name for name in normalized if name.startswith(module + "."))
                       for module in modules}
    missing = [module for group in rows.values() for module, tests in group.items() if not tests]
    complete = (outcome["passed"] and len(normalized) == len(set(normalized)) == outcome["tests_run"] and not missing)
    return {"passed": complete, "subsets_of_full_regression_only": True, "groups": rows,
            "missing_modules": sorted(set(missing)), "verbose_method_records": len(normalized),
            "unique_method_records": len(set(normalized)),
            "denominator_policy": "group membership is coverage of the one full run; never add it to full tests or Rust tests"}


def _external_inventory(options, gates):
    paths = {Path(sys.executable).resolve(), options.ranking_bridge, options.ranking_build_receipt,
             options.recursive_bridge, options.recursive_identity,
             options.finite_bridge, options.finite_identity, options.stream_bridge, options.stream_identity}
    by_name = {row["name"]: row for row in gates}
    tools = by_name.get("actual_tools_and_linux_seals", {})
    for row in tools.get("tools", {}).values():
        _require(str(Path(row["invocation_path"]).resolve(strict=True)) == row["path"],
                 "tool invocation was retargeted since its actual version probe")
    paths.update(Path(row["path"]) for row in tools.get("tools", {}).values())
    original_type_reader = tools.get("original_type_reader")
    if original_type_reader:
        from hepta.c_parameter_types import original_type_reader_identity

        _require(original_type_reader_identity(os.environ["CLANG"]) == original_type_reader,
                 "original-type compiler/reader/worker identity changed since its actual load probe")
        paths.add(Path(original_type_reader["compiler"]["path"]))
        paths.update(Path(original_type_reader[name]["path"]) for name in ("reader", "worker", "python"))
    if tools.get("solver"):
        import z3
        from hepta.hia_optimization import _solver_identity

        _require(_solver_identity(z3) == tools["solver"],
                 "complete Z3 binding/library identity changed since its actual identity gate")
        paths.add(Path(tools["solver"]["library_path"]))
        paths.update(Path(z3.__file__).parent.glob("*.py"))
    ranking = by_name.get("ranking_bridge_identity", {})
    paths.update(options.ranking_build_receipt.parent / name for name in ranking.get("build_inputs", {}))
    native_profiles = [(name, by_name.get(name + "_bridge_identity", {}))
                       for name in ("recursive", "finite", "stream")]
    for name, native in native_profiles:
        upstream = getattr(options, name + "_upstream")
        if native.get("passed"):
            _require(str(Path(native["manifest_binary_invocation"]).resolve(strict=True)) == native["binary"],
                     "native consumer invocation was retargeted since its identity gate")
        for field in ("native_sources", "bridge_sources"):
            paths.update(upstream / path for path in native.get(field, {}))
        paths.update(Path(tool["path"]) for tool in native.get("build_tools", {}).values())
    actual = {str(path): _digest_file(path) for path in sorted(paths)}
    expected = {row["path"]: row["sha256"] for row in tools.get("tools", {}).values()}
    if original_type_reader:
        expected[original_type_reader["compiler"]["path"]] = original_type_reader["compiler"]["executable_sha256"]
        expected.update({original_type_reader[name]["path"]: original_type_reader[name]["sha256"]
                         for name in ("reader", "worker", "python")})
    if tools.get("solver"):
        expected[tools["solver"]["library_path"]] = tools["solver"]["library_sha256"]
    if ranking.get("passed"):
        expected[str(options.ranking_bridge)] = ranking["identity"]["binary_sha256"]
        expected[str(options.ranking_build_receipt)] = ranking["identity"]["build_receipt_sha256"]
        expected.update({str(options.ranking_build_receipt.parent / name): digest
                         for name, digest in ranking["build_inputs"].items()})
    for name, native in native_profiles:
        if native.get("passed"):
            expected[str(getattr(options, name + "_bridge"))] = native["binary_sha256"]
            expected[str(getattr(options, name + "_identity"))] = native["receipt_sha256"]
            upstream = getattr(options, name + "_upstream")
            for field in ("native_sources", "bridge_sources"):
                expected.update({str(upstream / path): digest for path, digest in native[field].items()})
            expected.update({tool["path"]: tool["sha256"] for tool in native["build_tools"].values()})
    _require(all(actual.get(name) == digest for name, digest in expected.items()),
             "external inputs changed since their actual identity gate")
    return actual


def qualify(options):
    output = options.output_directory.resolve()
    _require(not output.is_relative_to(ROOT), "retain qualification output outside the frozen source worktree")
    if options.cargo_target_dir:
        _require(not options.cargo_target_dir.resolve().is_relative_to(ROOT),
                 "retain the reusable Cargo target outside the frozen source worktree")
    _require(re.fullmatch(r"[0-9a-f]{40}", options.expected_head), "expected HEAD must be an exact full Git SHA")
    before = _source_state()
    _require(before["head"] == options.expected_head and not before["status"],
             "commit the complete integration and supply its exact clean HEAD before qualification")
    output.mkdir(parents=True, exist_ok=False)
    report = {"schema": SCHEMA, "started_utc": datetime.now(timezone.utc).isoformat(),
              "source_before": before, "gates": [], "full_regression_requested": True,
              "historical_evidence_reused_as_current": False, "standalone_performance_campaigns_replayed": False,
              "native_timing_controls_in_full_regression": True,
              "scientific_incremental_advantage_established": False, "whole_language_soundness_proved": False,
              "global_optimality_established": False, "six_stages_closed": False,
              "scope": "merged finite contracts on the actual declared host; independent historical evidence keeps its own source and denominator"}
    with _environment(options, output) as configured:
        report["configured_environment"] = configured
        report["inherited_tool_environment"] = {name: os.environ.get(name) for name in (
            "CARGO_HOME", "LD_LIBRARY_PATH", "CPLUS_INCLUDE_PATH", "CPATH", "LEAN",
            "HEPTA_LLD", "HEPTA_LLVM_READOBJ", "HEPTA_QEMU_AARCH64", "HEPTA_QEMU_RISCV64",
            "HEPTA_NDU_STREAM_BRIDGE", "HEPTA_NDU_STREAM_IDENTITY", "HEPTA_QEMU_X86_64")}
        commands = [
            ("rust_resource_crate", [str(options.cargo), "test", "--locked", "--offline", "--manifest-path",
                                     "rust/hia-core-shadow/Cargo.toml"], "cargo"),
            ("full_regression", [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"], "unittest"),
        ]
        _write(output / "frozen-plan.json", {"source_head": before["head"], "source_tree": before["tree"],
               "critical_modules": CRITICAL_MODULES, "configured_environment": configured,
               "commands": [{"name": name, "argv": argv} for name, argv, _ in commands],
               "native_identity_gates": ["actual_tools_and_linux_seals", "ranking_bridge_identity",
                                         "recursive_bridge_identity", "finite_bridge_identity", "stream_bridge_identity"],
               "historical_performance_denominators_combined": False})
        for name, function in (("actual_tools_and_linux_seals", _tool_gate),
                               ("ranking_bridge_identity", _ranking_gate),
                               ("recursive_bridge_identity", _recursive_gate),
                               ("finite_bridge_identity", _finite_gate),
                               ("stream_bridge_identity", _stream_gate)):
            print(json.dumps({"gate": name, "state": "running"}), flush=True)
            try:
                row = {"name": name, **function(options, output)}
            except Exception as error:
                row = {"name": name, "passed": False, "error": type(error).__name__ + ": " + str(error)}
            report["gates"].append(row)
            _write(output / (name + ".json"), row)
            print(json.dumps({"gate": name, "passed": row["passed"]}), flush=True)
        try:
            report["external_inventory_before"] = _external_inventory(options, report["gates"])
        except Exception as error:
            report["external_identity_error"] = type(error).__name__ + ": " + str(error)
        for name, argv, kind in commands:
            print(json.dumps({"gate": name, "state": "running"}), flush=True)
            execution = _command(argv, timeout=options.timeout)
            outcome = (cargo_test_outcome(execution["stdout"], execution["returncode"]) if kind == "cargo"
                       else unittest_outcome(execution["stderr"], execution["returncode"]))
            row = {"name": name, "execution": execution, **outcome}
            report["gates"].append(row)
            _write(output / (name + "-execution.json"), row)
            if kind == "unittest":
                coverage = {"name": "merge_and_profile_coverage", **_coverage(execution, outcome)}
                report["gates"].append(coverage)
                _write(output / "merge-and-profile-coverage.json", coverage)
            print(json.dumps({"gate": name, "passed": row["passed"], "seconds": execution["seconds"]}), flush=True)
        try:
            report["external_inventory_after"] = _external_inventory(options, report["gates"])
            report["external_inputs_unchanged"] = ("external_identity_error" not in report and
                report["external_inventory_before"] == report["external_inventory_after"])
        except Exception as error:
            report.update(external_inputs_unchanged=False, external_identity_error=type(error).__name__ + ": " + str(error))
        try:
            after = _source_state()
            report["source_after"] = after
            report["source_unchanged"] = before == after and not after["status"]
        except Exception as error:
            report.update(source_unchanged=False, source_identity_error=type(error).__name__ + ": " + str(error))
    report["ok"] = (report["source_unchanged"] and report.get("external_inputs_unchanged") is True
                    and tuple(row["name"] for row in report["gates"]) == EXPECTED_GATE_NAMES
                    and all(row["passed"] for row in report["gates"]))
    report["status"] = "bounded_integrated_contracts_passed" if report["ok"] else "integration_qualification_failed"
    report["finished_utc"] = datetime.now(timezone.utc).isoformat()
    _write(output / "qualification.json", report)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-directory", type=Path, required=True)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--clang", required=True)
    parser.add_argument("--cargo", required=True)
    parser.add_argument("--cargo-target-dir", type=Path,
                        help="optional reusable build cache outside the frozen source tree; defaults to output/rust-target")
    parser.add_argument("--rustc", required=True)
    parser.add_argument("--ranking-bridge", type=Path, required=True)
    parser.add_argument("--ranking-build-receipt", type=Path, required=True)
    parser.add_argument("--ranking-upstream", type=Path, required=True)
    parser.add_argument("--recursive-bridge", type=Path, required=True)
    parser.add_argument("--recursive-identity", type=Path, required=True)
    parser.add_argument("--recursive-upstream", type=Path, required=True)
    parser.add_argument("--finite-bridge", type=Path, required=True)
    parser.add_argument("--finite-identity", type=Path, required=True)
    parser.add_argument("--finite-upstream", type=Path, required=True)
    parser.add_argument("--stream-bridge", type=Path, required=True)
    parser.add_argument("--stream-identity", type=Path, required=True)
    parser.add_argument("--stream-upstream", type=Path, required=True)
    parser.add_argument("--finite-cargo", required=True)
    parser.add_argument("--finite-rustc", required=True)
    parser.add_argument("--timeout", type=int, default=1800, help="timeout of each actual Rust/full regression gate")
    options = parser.parse_args(argv)
    for name in ("ranking_bridge", "ranking_build_receipt", "ranking_upstream", "recursive_bridge",
                 "recursive_identity", "recursive_upstream", "finite_bridge", "finite_identity", "finite_upstream",
                 "stream_bridge", "stream_identity", "stream_upstream"):
        setattr(options, name, getattr(options, name).resolve())
    try:
        _require(1 <= options.timeout <= 3600, "gate timeout must be in 1..3600 seconds")
        result = qualify(options)
    except Exception as error:
        print(json.dumps({"ok": False, "error": type(error).__name__ + ": " + str(error)}), file=sys.stderr)
        return 1
    print(json.dumps({key: result[key] for key in ("ok", "status", "source_unchanged", "external_inputs_unchanged")}))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
