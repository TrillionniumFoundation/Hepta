"""Closed relocation-aware seven-certificate acceptance plan and finite evidence contract.

No compiler execution here. Fixed hash commitments use canonical JSON plus LF;
legacy source manifest bytes retain their original no-LF protocol.
"""
from dataclasses import replace
import json
import os
from pathlib import Path
import re
import stat
import subprocess

from tools import check_core_syntax_staged as base
from tools import core_seven_certificate_sources as seven
from tools import core_seven_parallel_relocation_sources as relocation
from tools import diagnose_core_seven_certificate as diagnostic
from tools.check_guarded_slice_lean import require

ROOT = base.ROOT
SCHEMA = 'hepta.hia.seven-relocation-acceptance.v1'
PROTOCOL = 'seven-relocation-acceptance-v1'
ADDITIONS = ('tools/check_core_seven_relocation.py', 'tools/core_seven_relocation_acceptance_plan.py',
             'tools/core_seven_relocation_acceptance_replay.py', 'tests/test_core_seven_relocation_acceptance.py',
             'docs/seven-relocation-acceptance.md', 'tools/core_seven_parallel_relocation_sources.py',
             'tests/test_core_seven_parallel_relocation_sources.py', 'docs/seven-parallel-relocation.md',
             '.github/workflows/hia-initialization-frontier-research.yml')
METADATA_RESERVE = 224589
RAW_GLOBAL = 819891
BUDGETS = dict(source=2097152, sources=8388608, module=33554432, modules=134217728,
               raw_stage=507392, metadata=262144, evidence_display=1048576,
               container=143654912, display=4096, process_ns=60000000000,
               launch_ns=540000000000, cleanup_ns=2000000000, outer_seconds=600, job_minutes=15)
SOURCE_FILES = tuple('original/' + n + '.lean' for n in seven.original.NAMES) + tuple(
    'HiaSyntaxResearch/' + n + '.lean' for n in seven.NAMES)
MODULE_FILES = tuple('HiaSyntaxResearch/' + n + '.olean' for n in seven.NAMES)
LOG_FILES = tuple(n + '.' + stream for n in seven.NAMES for stream in ('stdout', 'stderr'))
RECEIPT_FILES = tuple(n + '.' + kind + '.json' for n in seven.NAMES for kind in ('started', 'finished'))
GLOBALS = ('IDENTITY.json', 'PLAN.json', 'RUN.json', 'relocation-manifest.json')
FROZEN_FILES = frozenset(SOURCE_FILES + MODULE_FILES + LOG_FILES + RECEIPT_FILES + GLOBALS)
TERMINALS = ('RESULT.json', 'RESULT.pending.json', 'FAILURE.json')
FIXED_FILES = FROZEN_FILES | set(TERMINALS)
PHASE_CODES = {
    'preparation_invalid': ('preparation',),
    'identity_changed': ('preparation', 'prelaunch', 'verifying', 'receipt_commit', 'finalization'),
    'launch_deadline': ('prelaunch',),
    **{c: ('capturing',) for c in ('process_timeout', 'process_failed', 'output_limit', 'capture_incomplete', 'cleanup_failed')},
    **{c: ('verifying',) for c in ('inventory_invalid', 'module_invalid')},
    **{c: ('preparation', 'prelaunch', 'capturing', 'verifying', 'receipt_commit', 'finalization')
       for c in ('filesystem_invalid', 'evidence_limit')},
    'receipt_failed': ('prelaunch', 'receipt_commit'), 'finalization_failed': ('finalization',)}
SCOPE = 'Narrow Core syntax connection only; all twelve wider obligations unproved; DENY_ALL.'
digest = base.digest


def encode(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False) + '\n').encode()


def commitment(value):
    return digest(encode(value))


def same(a, b):
    return encode(a) == encode(b)


def parse(raw, *, newline=True):
    def pairs(items):
        out = {}
        for key, value in items:
            require(key not in out, 'duplicate JSON key')
            out[key] = value
        return out
    def constant(_):
        raise ValueError('nonfinite JSON')
    value = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    require(type(value) is dict and raw == (encode(value) if newline else encode(value)[:-1]), 'noncanonical JSON object')
    return value


def integer(value, low, high):
    require(type(value) is int and low <= value <= high, 'integer range/type')
    return value


def hash_value(value, length=64):
    require(type(value) is str and re.fullmatch('[0-9a-f]{%d}' % length, value), 'hash format')
    return value


def absolute(value):
    require(type(value) is str and len(value.encode()) <= 128 and re.fullmatch(r'/[A-Za-z0-9._/-]+', value)
            and all(c not in ('', '.', '..') for c in value.split('/')[1:]), 'absolute path alphabet/canonical form')
    require(str(Path(value).resolve(strict=False)) == value, 'path resolution differs')
    return value


def common(run_id):
    return dict(schema=SCHEMA, protocol=PROTOCOL, run_id=hash_value(run_id))


def flags(success=False):
    return dict(kernel_core_syntax_connection_checked=success, actual_core_bridge_proved=False,
                python_exporter_refinement_proved=False, body_prefix_refinement_proved=False,
                all_edge_transfer_proved=False,
                obligations=[dict(id=n, status='unproved') for n, _ in seven.facts.OBLIGATIONS],
                authority=dict(seven.facts.DENY))


# Frozen exact identity paths: do not hash files merely to discover their names.
SOURCE_IDENTITY_PATHS = (
    '.github/workflows/hia-core-syntax-kernel-research.yml',
    '.github/workflows/hia-guarded-slice-kernel-research.yml',
    '.github/workflows/hia-initialization-frontier-research.yml',
    'benchmarks/hia_reduction_release/affine.hepta',
    'benchmarks/hia_reduction_release/linear.hepta',
    'docs/seven-certificate-acceptance.md',
    'docs/seven-certificate-first-four-diagnostic-design.md',
    'docs/seven-certificate-source-proposal.md',
    'docs/seven-parallel-relocation.md',
    'docs/seven-relocation-acceptance.md',
    'experiments/hia_initialization_frontiers_20261103/ByteFactsResearch.lean',
    'experiments/hia_initialization_frontiers_20261103/CoreSyntaxSlice.lean',
    'experiments/hia_initialization_frontiers_20261103/GuardedUsizeSlice.lean',
    'experiments/hia_initialization_frontiers_20261103/StructuredTransport.lean',
    'formal/HiaInitializationPrefix.lean',
    'formal/proof-dependencies.txt',
    'formal/toolchain-lock.json',
    'hepta/__init__.py',
    'hepta/__main__.py',
    'hepta/agent_contract_diff.py',
    'hepta/agent_semantics.py',
    'hepta/artifact_publication.py',
    'hepta/ast.py',
    'hepta/backend.py',
    'hepta/borrowed_storage.py',
    'hepta/c_aliases.py',
    'hepta/c_allocation.py',
    'hepta/c_backend.py',
    'hepta/c_contracts.py',
    'hepta/c_definite_assignment.py',
    'hepta/c_import.py',
    'hepta/c_loop_control.py',
    'hepta/c_migrate.py',
    'hepta/c_migration_project.py',
    'hepta/c_parameter_types.py',
    'hepta/c_project.py',
    'hepta/c_project_matrix.py',
    'hepta/c_record_views.py',
    'hepta/c_resource_matrix.py',
    'hepta/c_scalar_matrix.py',
    'hepta/c_translation.py',
    'hepta/cfg.py',
    'hepta/cfg_analysis.py',
    'hepta/checker.py',
    'hepta/clang_capture.py',
    'hepta/cli.py',
    'hepta/concurrent_ir.py',
    'hepta/concurrent_lowering.py',
    'hepta/core.py',
    'hepta/cpp2hepta.py',
    'hepta/cpp_bridge.py',
    'hepta/cpp_callback_project.py',
    'hepta/cpp_class_migrate.py',
    'hepta/cpp_composed_migrate.py',
    'hepta/cpp_composed_project.py',
    'hepta/cpp_contracts.py',
    'hepta/cpp_gsl_final_action.py',
    'hepta/cpp_host_toolchain.py',
    'hepta/cpp_json_checkpoint.py',
    'hepta/cpp_owned_migrate.py',
    'hepta/cpp_project_migrate.py',
    'hepta/cpp_scoped.py',
    'hepta/cpp_unique_assignment.py',
    'hepta/cpp_unique_capture.py',
    'hepta/cpp_unique_project.py',
    'hepta/cpp_unique_reset.py',
    'hepta/darwin_capture.py',
    'hepta/debug_info.py',
    'hepta/elf_shared_abi.py',
    'hepta/executable_core.py',
    'hepta/executable_core_qualify.py',
    'hepta/executable_core_runtime.py',
    'hepta/flow_ir.py',
    'hepta/hia_adaptive.py',
    'hepta/hia_agent_assembly.py',
    'hepta/hia_artifact_session.py',
    'hepta/hia_background_optimizer.py',
    'hepta/hia_bounded_memory.py',
    'hepta/hia_bounded_unroll.py',
    'hepta/hia_bounded_wire.py',
    'hepta/hia_bundle_atomic.py',
    'hepta/hia_call_expansion.py',
    'hepta/hia_capability_flow.py',
    'hepta/hia_continuation.py',
    'hepta/hia_core.py',
    'hepta/hia_core_upgrade.py',
    'hepta/hia_crc_kernel.py',
    'hepta/hia_crc_linear.py',
    'hepta/hia_durable_queue.py',
    'hepta/hia_economic_search.py',
    'hepta/hia_edit_batch.py',
    'hepta/hia_edit_query.py',
    'hepta/hia_empty_reduction.py',
    'hepta/hia_finite_actions.py',
    'hepta/hia_finite_context.py',
    'hepta/hia_full_cost_gate.py',
    'hepta/hia_guarded_batch.py',
    'hepta/hia_guarded_optimization.py',
    'hepta/hia_heap_bound.py',
    'hepta/hia_host_region.py',
    'hepta/hia_incremental.py',
    'hepta/hia_inductive.py',
    'hepta/hia_initialization.py',
    'hepta/hia_invocation_bank.py',
    'hepta/hia_json_preflight.py',
    'hepta/hia_l1_receipt.py',
    'hepta/hia_migrate.py',
    'hepta/hia_multiversion.py',
    'hepta/hia_narrowing.py',
    'hepta/hia_native_differential.py',
    'hepta/hia_native_paired_replay.py',
    'hepta/hia_native_retirement.py',
    'hepta/hia_ndu.py',
    'hepta/hia_ndu_cache.py',
    'hepta/hia_ndu_cost.py',
    'hepta/hia_ndu_optimizer.py',
    'hepta/hia_ndu_response.py',
    'hepta/hia_ndu_session.py',
    'hepta/hia_ndu_stateful.py',
    'hepta/hia_opcodes.py',
    'hepta/hia_optimization.py',
    'hepta/hia_optimization_contract.py',
    'hepta/hia_oracle.py',
    'hepta/hia_paired_holdout.py',
    'hepta/hia_patch_impact.py',
    'hepta/hia_planning.py',
    'hepta/hia_prepared.py',
    'hepta/hia_program.py',
    'hepta/hia_program_aarch64.py',
    'hepta/hia_program_composite.py',
    'hepta/hia_program_llvm.py',
    'hepta/hia_program_runtime.py',
    'hepta/hia_program_source.py',
    'hepta/hia_program_tools.py',
    'hepta/hia_queue_commit.py',
    'hepta/hia_reduction.py',
    'hepta/hia_routes.py',
    'hepta/hia_rust_byte_cleanup.py',
    'hepta/hia_rust_byte_dag.py',
    'hepta/hia_rust_crosscheck.py',
    'hepta/hia_scalar_call_validation.py',
    'hepta/hia_scalar_lowering_check.py',
    'hepta/hia_scalar_state.py',
    'hepta/hia_scalar_totality.py',
    'hepta/hia_schema.py',
    'hepta/hia_source_bridge.py',
    'hepta/hia_specialization.py',
    'hepta/hia_stateful.py',
    'hepta/hia_static_budget.py',
    'hepta/hia_stb_specialization.py',
    'hepta/hia_swap_opt.py',
    'hepta/hia_translation_validation.py',
    'hepta/hia_x86_search.py',
    'hepta/hmir.py',
    'hepta/hsir.py',
    'hepta/lexer.py',
    'hepta/llvm_ir_profile.py',
    'hepta/llvm_owned_aarch64.py',
    'hepta/llvm_owned_backend.py',
    'hepta/llvm_owned_pipeline.py',
    'hepta/llvm_ssa_backend.py',
    'hepta/llvm_ssa_pipeline.py',
    'hepta/llvm_ssa_target.py',
    'hepta/migration_ir.py',
    'hepta/modules.py',
    'hepta/native_local_views.py',
    'hepta/native_mapping_identity.py',
    'hepta/native_resource_gate.py',
    'hepta/native_tool_identity.py',
    'hepta/object_structure.py',
    'hepta/object_symbols.py',
    'hepta/owned_aarch64_link.py',
    'hepta/owned_aarch64_runtime.py',
    'hepta/owned_drop_plan.py',
    'hepta/owned_target_layout.py',
    'hepta/packages.py',
    'hepta/parser.py',
    'hepta/pipeline.py',
    'hepta/protocol.py',
    'hepta/protocol_v3.py',
    'hepta/resource_ir.py',
    'hepta/resource_lowering.py',
    'hepta/resource_source.py',
    'hepta/runtime_concurrency.py',
    'hepta/runtime_io.py',
    'hepta/runtime_task_io.py',
    'hepta/runtime_task_tree.py',
    'hepta/scalar_host_abi.py',
    'hepta/semantic_ir.py',
    'hepta/source_map.py',
    'hepta/ssa.py',
    'hepta/ssa_reaching.py',
    'hepta/ssa_verify.py',
    'hepta/static_resource_contracts.py',
    'hepta/windows_capture.py',
    'hepta/workspace.py',
    'tests/test_core_seven_acceptance.py',
    'tests/test_core_seven_certificate_diagnostic.py',
    'tests/test_core_seven_certificate_pending_eio.py',
    'tests/test_core_seven_certificate_runner.py',
    'tests/test_core_seven_certificate_sources.py',
    'tests/test_core_seven_parallel_relocation_sources.py',
    'tests/test_core_seven_relocation_acceptance.py',
    'tools/bootstrap_verification.py',
    'tools/check_core_seven_certificate.py',
    'tools/check_core_seven_relocation.py',
    'tools/check_core_syntax_lean.py',
    'tools/check_core_syntax_partitioned.py',
    'tools/check_core_syntax_staged.py',
    'tools/check_dynamic_unsigned_step.py',
    'tools/check_guarded_slice_lean.py',
    'tools/check_initialization_frontiers.py',
    'tools/core_byte_facts_dag.py',
    'tools/core_byte_facts_diagnostic_sources.py',
    'tools/core_byte_facts_sources.py',
    'tools/core_byte_facts_verify.py',
    'tools/core_seven_acceptance_capture.py',
    'tools/core_seven_acceptance_plan.py',
    'tools/core_seven_acceptance_replay.py',
    'tools/core_seven_certificate_diagnostic_sources.py',
    'tools/core_seven_certificate_sources.py',
    'tools/core_seven_parallel_relocation_sources.py',
    'tools/core_seven_relocation_acceptance_plan.py',
    'tools/core_seven_relocation_acceptance_replay.py',
    'tools/core_syntax_declaration_diagnostic_sources.py',
    'tools/core_syntax_diagnostic_capture.py',
    'tools/core_syntax_partition_diagnostic_sources.py',
    'tools/core_syntax_partition_sources.py',
    'tools/core_syntax_stage_sources.py',
    'tools/core_syntax_structured_sources.py',
    'tools/core_syntax_structured_stages.py',
    'tools/diagnose_core_byte_facts.py',
    'tools/diagnose_core_seven_certificate.py',
    'tools/evidence_checks.py',
    'tools/experimental_deferred_guard_proposer.py',
    'tools/extract_initialization_obligations.py',
    'tools/qualify_hia_initialization_prefix.py',
    'tools/qualify_hia_selected_formal.py',
    'tools/research_deferred_guard_model.py',
)


def source_paths():
    paths = SOURCE_IDENTITY_PATHS
    require(len(paths) == 239 and commitment(paths) == 'cbb40503e9185e8a3f79f6936a60fc0f88e5e3af12cd11d4d6098d241295e8fa', 'source identity set drift requires review')
    return paths


SUPPORT_IDENTITY_PATHS = (
    'lib/lean/Init.olean',
    'lib/lean/Init/BinderNameHint.olean',
    'lib/lean/Init/BinderPredicates.olean',
    'lib/lean/Init/ByCases.olean',
    'lib/lean/Init/Classical.olean',
    'lib/lean/Init/Coe.olean',
    'lib/lean/Init/Control.olean',
    'lib/lean/Init/Control/Basic.olean',
    'lib/lean/Init/Control/EState.olean',
    'lib/lean/Init/Control/Except.olean',
    'lib/lean/Init/Control/ExceptCps.olean',
    'lib/lean/Init/Control/Id.olean',
    'lib/lean/Init/Control/Lawful.olean',
    'lib/lean/Init/Control/Lawful/Basic.olean',
    'lib/lean/Init/Control/Lawful/Instances.olean',
    'lib/lean/Init/Control/Lawful/Lemmas.olean',
    'lib/lean/Init/Control/Option.olean',
    'lib/lean/Init/Control/Reader.olean',
    'lib/lean/Init/Control/State.olean',
    'lib/lean/Init/Control/StateCps.olean',
    'lib/lean/Init/Control/StateRef.olean',
    'lib/lean/Init/Conv.olean',
    'lib/lean/Init/Core.olean',
    'lib/lean/Init/Data.olean',
    'lib/lean/Init/Data/AC.olean',
    'lib/lean/Init/Data/Array.olean',
    'lib/lean/Init/Data/Array/Attach.olean',
    'lib/lean/Init/Data/Array/Basic.olean',
    'lib/lean/Init/Data/Array/BasicAux.olean',
    'lib/lean/Init/Data/Array/BinSearch.olean',
    'lib/lean/Init/Data/Array/Bootstrap.olean',
    'lib/lean/Init/Data/Array/Count.olean',
    'lib/lean/Init/Data/Array/DecidableEq.olean',
    'lib/lean/Init/Data/Array/Erase.olean',
    'lib/lean/Init/Data/Array/Extract.olean',
    'lib/lean/Init/Data/Array/FinRange.olean',
    'lib/lean/Init/Data/Array/Find.olean',
    'lib/lean/Init/Data/Array/GetLit.olean',
    'lib/lean/Init/Data/Array/InsertIdx.olean',
    'lib/lean/Init/Data/Array/InsertionSort.olean',
    'lib/lean/Init/Data/Array/Lemmas.olean',
    'lib/lean/Init/Data/Array/Lex.olean',
    'lib/lean/Init/Data/Array/Lex/Basic.olean',
    'lib/lean/Init/Data/Array/Lex/Lemmas.olean',
    'lib/lean/Init/Data/Array/MapIdx.olean',
    'lib/lean/Init/Data/Array/Mem.olean',
    'lib/lean/Init/Data/Array/Monadic.olean',
    'lib/lean/Init/Data/Array/OfFn.olean',
    'lib/lean/Init/Data/Array/Perm.olean',
    'lib/lean/Init/Data/Array/QSort.olean',
    'lib/lean/Init/Data/Array/Range.olean',
    'lib/lean/Init/Data/Array/Set.olean',
    'lib/lean/Init/Data/Array/Subarray.olean',
    'lib/lean/Init/Data/Array/Subarray/Split.olean',
    'lib/lean/Init/Data/Array/TakeDrop.olean',
    'lib/lean/Init/Data/Array/Zip.olean',
    'lib/lean/Init/Data/BEq.olean',
    'lib/lean/Init/Data/Basic.olean',
    'lib/lean/Init/Data/BitVec.olean',
    'lib/lean/Init/Data/BitVec/Basic.olean',
    'lib/lean/Init/Data/BitVec/BasicAux.olean',
    'lib/lean/Init/Data/BitVec/Bitblast.olean',
    'lib/lean/Init/Data/BitVec/Folds.olean',
    'lib/lean/Init/Data/BitVec/Lemmas.olean',
    'lib/lean/Init/Data/Bool.olean',
    'lib/lean/Init/Data/ByteArray.olean',
    'lib/lean/Init/Data/ByteArray/Basic.olean',
    'lib/lean/Init/Data/Cast.olean',
    'lib/lean/Init/Data/Channel.olean',
    'lib/lean/Init/Data/Char.olean',
    'lib/lean/Init/Data/Char/Basic.olean',
    'lib/lean/Init/Data/Char/Lemmas.olean',
    'lib/lean/Init/Data/Fin.olean',
    'lib/lean/Init/Data/Fin/Basic.olean',
    'lib/lean/Init/Data/Fin/Bitwise.olean',
    'lib/lean/Init/Data/Fin/Fold.olean',
    'lib/lean/Init/Data/Fin/Iterate.olean',
    'lib/lean/Init/Data/Fin/Lemmas.olean',
    'lib/lean/Init/Data/Fin/Log2.olean',
    'lib/lean/Init/Data/Float.olean',
    'lib/lean/Init/Data/Float32.olean',
    'lib/lean/Init/Data/FloatArray.olean',
    'lib/lean/Init/Data/FloatArray/Basic.olean',
    'lib/lean/Init/Data/Format.olean',
    'lib/lean/Init/Data/Format/Basic.olean',
    'lib/lean/Init/Data/Format/Instances.olean',
    'lib/lean/Init/Data/Format/Macro.olean',
    'lib/lean/Init/Data/Format/Syntax.olean',
    'lib/lean/Init/Data/Function.olean',
    'lib/lean/Init/Data/Hashable.olean',
    'lib/lean/Init/Data/Int.olean',
    'lib/lean/Init/Data/Int/Basic.olean',
    'lib/lean/Init/Data/Int/Bitwise.olean',
    'lib/lean/Init/Data/Int/Bitwise/Basic.olean',
    'lib/lean/Init/Data/Int/Bitwise/Lemmas.olean',
    'lib/lean/Init/Data/Int/Cooper.olean',
    'lib/lean/Init/Data/Int/DivMod.olean',
    'lib/lean/Init/Data/Int/DivMod/Basic.olean',
    'lib/lean/Init/Data/Int/DivMod/Bootstrap.olean',
    'lib/lean/Init/Data/Int/DivMod/Lemmas.olean',
    'lib/lean/Init/Data/Int/Gcd.olean',
    'lib/lean/Init/Data/Int/Lemmas.olean',
    'lib/lean/Init/Data/Int/LemmasAux.olean',
    'lib/lean/Init/Data/Int/Linear.olean',
    'lib/lean/Init/Data/Int/OfNat.olean',
    'lib/lean/Init/Data/Int/Order.olean',
    'lib/lean/Init/Data/Int/Pow.olean',
    'lib/lean/Init/Data/List.olean',
    'lib/lean/Init/Data/List/Attach.olean',
    'lib/lean/Init/Data/List/Basic.olean',
    'lib/lean/Init/Data/List/BasicAux.olean',
    'lib/lean/Init/Data/List/Control.olean',
    'lib/lean/Init/Data/List/Count.olean',
    'lib/lean/Init/Data/List/Erase.olean',
    'lib/lean/Init/Data/List/FinRange.olean',
    'lib/lean/Init/Data/List/Find.olean',
    'lib/lean/Init/Data/List/Impl.olean',
    'lib/lean/Init/Data/List/Lemmas.olean',
    'lib/lean/Init/Data/List/Lex.olean',
    'lib/lean/Init/Data/List/MapIdx.olean',
    'lib/lean/Init/Data/List/MinMax.olean',
    'lib/lean/Init/Data/List/Monadic.olean',
    'lib/lean/Init/Data/List/Nat.olean',
    'lib/lean/Init/Data/List/Nat/BEq.olean',
    'lib/lean/Init/Data/List/Nat/Basic.olean',
    'lib/lean/Init/Data/List/Nat/Count.olean',
    'lib/lean/Init/Data/List/Nat/Erase.olean',
    'lib/lean/Init/Data/List/Nat/Find.olean',
    'lib/lean/Init/Data/List/Nat/InsertIdx.olean',
    'lib/lean/Init/Data/List/Nat/Modify.olean',
    'lib/lean/Init/Data/List/Nat/Pairwise.olean',
    'lib/lean/Init/Data/List/Nat/Perm.olean',
    'lib/lean/Init/Data/List/Nat/Range.olean',
    'lib/lean/Init/Data/List/Nat/Sublist.olean',
    'lib/lean/Init/Data/List/Nat/TakeDrop.olean',
    'lib/lean/Init/Data/List/Notation.olean',
    'lib/lean/Init/Data/List/OfFn.olean',
    'lib/lean/Init/Data/List/Pairwise.olean',
    'lib/lean/Init/Data/List/Perm.olean',
    'lib/lean/Init/Data/List/Range.olean',
    'lib/lean/Init/Data/List/Sort.olean',
    'lib/lean/Init/Data/List/Sort/Basic.olean',
    'lib/lean/Init/Data/List/Sort/Impl.olean',
    'lib/lean/Init/Data/List/Sort/Lemmas.olean',
    'lib/lean/Init/Data/List/Sublist.olean',
    'lib/lean/Init/Data/List/TakeDrop.olean',
    'lib/lean/Init/Data/List/ToArray.olean',
    'lib/lean/Init/Data/List/ToArrayImpl.olean',
    'lib/lean/Init/Data/List/Zip.olean',
    'lib/lean/Init/Data/Nat.olean',
    'lib/lean/Init/Data/Nat/Basic.olean',
    'lib/lean/Init/Data/Nat/Bitwise.olean',
    'lib/lean/Init/Data/Nat/Bitwise/Basic.olean',
    'lib/lean/Init/Data/Nat/Bitwise/Lemmas.olean',
    'lib/lean/Init/Data/Nat/Compare.olean',
    'lib/lean/Init/Data/Nat/Control.olean',
    'lib/lean/Init/Data/Nat/Div/Basic.olean',
    'lib/lean/Init/Data/Nat/Div/Lemmas.olean',
    'lib/lean/Init/Data/Nat/Dvd.olean',
    'lib/lean/Init/Data/Nat/Fold.olean',
    'lib/lean/Init/Data/Nat/Gcd.olean',
    'lib/lean/Init/Data/Nat/Lcm.olean',
    'lib/lean/Init/Data/Nat/Lemmas.olean',
    'lib/lean/Init/Data/Nat/Linear.olean',
    'lib/lean/Init/Data/Nat/Log2.olean',
    'lib/lean/Init/Data/Nat/MinMax.olean',
    'lib/lean/Init/Data/Nat/Mod.olean',
    'lib/lean/Init/Data/Nat/Power2.olean',
    'lib/lean/Init/Data/Nat/SOM.olean',
    'lib/lean/Init/Data/Nat/Simproc.olean',
    'lib/lean/Init/Data/NeZero.olean',
    'lib/lean/Init/Data/OfScientific.olean',
    'lib/lean/Init/Data/Option.olean',
    'lib/lean/Init/Data/Option/Attach.olean',
    'lib/lean/Init/Data/Option/Basic.olean',
    'lib/lean/Init/Data/Option/BasicAux.olean',
    'lib/lean/Init/Data/Option/Instances.olean',
    'lib/lean/Init/Data/Option/Lemmas.olean',
    'lib/lean/Init/Data/Option/List.olean',
    'lib/lean/Init/Data/Option/Monadic.olean',
    'lib/lean/Init/Data/Ord.olean',
    'lib/lean/Init/Data/PLift.olean',
    'lib/lean/Init/Data/Prod.olean',
    'lib/lean/Init/Data/Queue.olean',
    'lib/lean/Init/Data/RArray.olean',
    'lib/lean/Init/Data/Random.olean',
    'lib/lean/Init/Data/Range.olean',
    'lib/lean/Init/Data/Range/Basic.olean',
    'lib/lean/Init/Data/Range/Lemmas.olean',
    'lib/lean/Init/Data/Repr.olean',
    'lib/lean/Init/Data/SInt.olean',
    'lib/lean/Init/Data/SInt/Basic.olean',
    'lib/lean/Init/Data/SInt/Bitwise.olean',
    'lib/lean/Init/Data/SInt/Float.olean',
    'lib/lean/Init/Data/SInt/Float32.olean',
    'lib/lean/Init/Data/SInt/Lemmas.olean',
    'lib/lean/Init/Data/Stream.olean',
    'lib/lean/Init/Data/String.olean',
    'lib/lean/Init/Data/String/Basic.olean',
    'lib/lean/Init/Data/String/Extra.olean',
    'lib/lean/Init/Data/String/Lemmas.olean',
    'lib/lean/Init/Data/Subtype.olean',
    'lib/lean/Init/Data/Sum.olean',
    'lib/lean/Init/Data/Sum/Basic.olean',
    'lib/lean/Init/Data/Sum/Lemmas.olean',
    'lib/lean/Init/Data/ToString.olean',
    'lib/lean/Init/Data/ToString/Basic.olean',
    'lib/lean/Init/Data/ToString/Macro.olean',
    'lib/lean/Init/Data/UInt.olean',
    'lib/lean/Init/Data/UInt/Basic.olean',
    'lib/lean/Init/Data/UInt/BasicAux.olean',
    'lib/lean/Init/Data/UInt/Bitwise.olean',
    'lib/lean/Init/Data/UInt/Lemmas.olean',
    'lib/lean/Init/Data/UInt/Log2.olean',
    'lib/lean/Init/Data/ULift.olean',
    'lib/lean/Init/Data/Vector.olean',
    'lib/lean/Init/Data/Vector/Attach.olean',
    'lib/lean/Init/Data/Vector/Basic.olean',
    'lib/lean/Init/Data/Vector/Count.olean',
    'lib/lean/Init/Data/Vector/DecidableEq.olean',
    'lib/lean/Init/Data/Vector/Erase.olean',
    'lib/lean/Init/Data/Vector/Extract.olean',
    'lib/lean/Init/Data/Vector/FinRange.olean',
    'lib/lean/Init/Data/Vector/InsertIdx.olean',
    'lib/lean/Init/Data/Vector/Lemmas.olean',
    'lib/lean/Init/Data/Vector/Lex.olean',
    'lib/lean/Init/Data/Vector/MapIdx.olean',
    'lib/lean/Init/Data/Vector/Monadic.olean',
    'lib/lean/Init/Data/Vector/OfFn.olean',
    'lib/lean/Init/Data/Vector/Range.olean',
    'lib/lean/Init/Data/Vector/Zip.olean',
    'lib/lean/Init/Data/Zero.olean',
    'lib/lean/Init/Dynamic.olean',
    'lib/lean/Init/Ext.olean',
    'lib/lean/Init/GetElem.olean',
    'lib/lean/Init/Grind.olean',
    'lib/lean/Init/Grind/Cases.olean',
    'lib/lean/Init/Grind/Lemmas.olean',
    'lib/lean/Init/Grind/Norm.olean',
    'lib/lean/Init/Grind/Offset.olean',
    'lib/lean/Init/Grind/PP.olean',
    'lib/lean/Init/Grind/Propagator.olean',
    'lib/lean/Init/Grind/Tactics.olean',
    'lib/lean/Init/Grind/Util.olean',
    'lib/lean/Init/Guard.olean',
    'lib/lean/Init/Hints.olean',
    'lib/lean/Init/Internal.olean',
    'lib/lean/Init/Internal/Order.olean',
    'lib/lean/Init/Internal/Order/Basic.olean',
    'lib/lean/Init/Internal/Order/Lemmas.olean',
    'lib/lean/Init/Internal/Order/Tactic.olean',
    'lib/lean/Init/MacroTrace.olean',
    'lib/lean/Init/Meta.olean',
    'lib/lean/Init/MetaTypes.olean',
    'lib/lean/Init/Notation.olean',
    'lib/lean/Init/NotationExtra.olean',
    'lib/lean/Init/Omega.olean',
    'lib/lean/Init/Omega/Coeffs.olean',
    'lib/lean/Init/Omega/Constraint.olean',
    'lib/lean/Init/Omega/Int.olean',
    'lib/lean/Init/Omega/IntList.olean',
    'lib/lean/Init/Omega/LinearCombo.olean',
    'lib/lean/Init/Omega/Logic.olean',
    'lib/lean/Init/Prelude.olean',
    'lib/lean/Init/PropLemmas.olean',
    'lib/lean/Init/RCases.olean',
    'lib/lean/Init/ShareCommon.olean',
    'lib/lean/Init/SimpLemmas.olean',
    'lib/lean/Init/Simproc.olean',
    'lib/lean/Init/SizeOf.olean',
    'lib/lean/Init/SizeOfLemmas.olean',
    'lib/lean/Init/Syntax.olean',
    'lib/lean/Init/System.olean',
    'lib/lean/Init/System/FilePath.olean',
    'lib/lean/Init/System/IO.olean',
    'lib/lean/Init/System/IOError.olean',
    'lib/lean/Init/System/Mutex.olean',
    'lib/lean/Init/System/Platform.olean',
    'lib/lean/Init/System/Promise.olean',
    'lib/lean/Init/System/ST.olean',
    'lib/lean/Init/System/Uri.olean',
    'lib/lean/Init/Tactics.olean',
    'lib/lean/Init/TacticsExtra.olean',
    'lib/lean/Init/Task.olean',
    'lib/lean/Init/Try.olean',
    'lib/lean/Init/Util.olean',
    'lib/lean/Init/WF.olean',
    'lib/lean/Init/WFTactics.olean',
    'lib/lean/Init/While.olean',
    'lib/lean/Lean/AddDecl.olean',
    'lib/lean/Lean/Attributes.olean',
    'lib/lean/Lean/AuxRecursor.olean',
    'lib/lean/Lean/BuiltinDocAttr.olean',
    'lib/lean/Lean/Class.olean',
    'lib/lean/Lean/Compiler/BorrowedAnnotation.olean',
    'lib/lean/Lean/Compiler/ExternAttr.olean',
    'lib/lean/Lean/Compiler/IR/Basic.olean',
    'lib/lean/Lean/Compiler/IR/CompilerM.olean',
    'lib/lean/Lean/Compiler/IR/Format.olean',
    'lib/lean/Lean/Compiler/ImplementedByAttr.olean',
    'lib/lean/Lean/Compiler/InitAttr.olean',
    'lib/lean/Lean/Compiler/InlineAttrs.olean',
    'lib/lean/Lean/Compiler/NoncomputableAttr.olean',
    'lib/lean/Lean/Compiler/Old.olean',
    'lib/lean/Lean/CoreM.olean',
    'lib/lean/Lean/Data/Array.olean',
    'lib/lean/Lean/Data/AssocList.olean',
    'lib/lean/Lean/Data/DeclarationRange.olean',
    'lib/lean/Lean/Data/Format.olean',
    'lib/lean/Lean/Data/FuzzyMatching.olean',
    'lib/lean/Lean/Data/Json.olean',
    'lib/lean/Lean/Data/Json/Basic.olean',
    'lib/lean/Lean/Data/Json/Elab.olean',
    'lib/lean/Lean/Data/Json/FromToJson.olean',
    'lib/lean/Lean/Data/Json/Parser.olean',
    'lib/lean/Lean/Data/Json/Printer.olean',
    'lib/lean/Lean/Data/Json/Stream.olean',
    'lib/lean/Lean/Data/JsonRpc.olean',
    'lib/lean/Lean/Data/KVMap.olean',
    'lib/lean/Lean/Data/LBool.olean',
    'lib/lean/Lean/Data/LOption.olean',
    'lib/lean/Lean/Data/Lsp.olean',
    'lib/lean/Lean/Data/Lsp/Basic.olean',
    'lib/lean/Lean/Data/Lsp/CancelParams.olean',
    'lib/lean/Lean/Data/Lsp/Capabilities.olean',
    'lib/lean/Lean/Data/Lsp/Client.olean',
    'lib/lean/Lean/Data/Lsp/CodeActions.olean',
    'lib/lean/Lean/Data/Lsp/Communication.olean',
    'lib/lean/Lean/Data/Lsp/Diagnostics.olean',
    'lib/lean/Lean/Data/Lsp/Extra.olean',
    'lib/lean/Lean/Data/Lsp/InitShutdown.olean',
    'lib/lean/Lean/Data/Lsp/Internal.olean',
    'lib/lean/Lean/Data/Lsp/Ipc.olean',
    'lib/lean/Lean/Data/Lsp/LanguageFeatures.olean',
    'lib/lean/Lean/Data/Lsp/TextSync.olean',
    'lib/lean/Lean/Data/Lsp/Utf16.olean',
    'lib/lean/Lean/Data/Lsp/Window.olean',
    'lib/lean/Lean/Data/Lsp/Workspace.olean',
    'lib/lean/Lean/Data/Name.olean',
    'lib/lean/Lean/Data/NameMap.olean',
    'lib/lean/Lean/Data/NameTrie.olean',
    'lib/lean/Lean/Data/OpenDecl.olean',
    'lib/lean/Lean/Data/Options.olean',
    'lib/lean/Lean/Data/PersistentArray.olean',
    'lib/lean/Lean/Data/PersistentHashMap.olean',
    'lib/lean/Lean/Data/PersistentHashSet.olean',
    'lib/lean/Lean/Data/Position.olean',
    'lib/lean/Lean/Data/PrefixTree.olean',
    'lib/lean/Lean/Data/RArray.olean',
    'lib/lean/Lean/Data/RBMap.olean',
    'lib/lean/Lean/Data/RBTree.olean',
    'lib/lean/Lean/Data/SMap.olean',
    'lib/lean/Lean/Data/SSet.olean',
    'lib/lean/Lean/Data/Trie.olean',
    'lib/lean/Lean/Declaration.olean',
    'lib/lean/Lean/DeclarationRange.olean',
    'lib/lean/Lean/DocString.olean',
    'lib/lean/Lean/DocString/Add.olean',
    'lib/lean/Lean/DocString/Extension.olean',
    'lib/lean/Lean/DocString/Links.olean',
    'lib/lean/Lean/Elab/Arg.olean',
    'lib/lean/Lean/Elab/Attributes.olean',
    'lib/lean/Lean/Elab/AutoBound.olean',
    'lib/lean/Lean/Elab/AuxDef.olean',
    'lib/lean/Lean/Elab/Binders.olean',
    'lib/lean/Lean/Elab/BindersUtil.olean',
    'lib/lean/Lean/Elab/BuiltinNotation.olean',
    'lib/lean/Lean/Elab/BuiltinTerm.olean',
    'lib/lean/Lean/Elab/Command.olean',
    'lib/lean/Lean/Elab/Config.olean',
    'lib/lean/Lean/Elab/DeclModifiers.olean',
    'lib/lean/Lean/Elab/DeclNameGen.olean',
    'lib/lean/Lean/Elab/DeclUtil.olean',
    'lib/lean/Lean/Elab/DeclarationRange.olean',
    'lib/lean/Lean/Elab/DefView.olean',
    'lib/lean/Lean/Elab/Deriving/Basic.olean',
    'lib/lean/Lean/Elab/Do.olean',
    'lib/lean/Lean/Elab/ElabRules.olean',
    'lib/lean/Lean/Elab/Eval.olean',
    'lib/lean/Lean/Elab/Exception.olean',
    'lib/lean/Lean/Elab/Import.olean',
    'lib/lean/Lean/Elab/InfoTree.olean',
    'lib/lean/Lean/Elab/InfoTree/InlayHints.olean',
    'lib/lean/Lean/Elab/InfoTree/Main.olean',
    'lib/lean/Lean/Elab/InfoTree/Types.olean',
    'lib/lean/Lean/Elab/Level.olean',
    'lib/lean/Lean/Elab/MacroArgUtil.olean',
    'lib/lean/Lean/Elab/Match.olean',
    'lib/lean/Lean/Elab/MatchAltView.olean',
    'lib/lean/Lean/Elab/MutualDef.olean',
    'lib/lean/Lean/Elab/Open.olean',
    'lib/lean/Lean/Elab/PatternVar.olean',
    'lib/lean/Lean/Elab/PreDefinition/Basic.olean',
    'lib/lean/Lean/Elab/PreDefinition/Eqns.olean',
    'lib/lean/Lean/Elab/PreDefinition/FixedParams.olean',
    'lib/lean/Lean/Elab/PreDefinition/Main.olean',
    'lib/lean/Lean/Elab/PreDefinition/MkInhabitant.olean',
    'lib/lean/Lean/Elab/PreDefinition/Mutual.olean',
    'lib/lean/Lean/Elab/PreDefinition/PartialFixpoint.olean',
    'lib/lean/Lean/Elab/PreDefinition/PartialFixpoint/Eqns.olean',
    'lib/lean/Lean/Elab/PreDefinition/PartialFixpoint/Induction.olean',
    'lib/lean/Lean/Elab/PreDefinition/PartialFixpoint/Main.olean',
    'lib/lean/Lean/Elab/PreDefinition/Structural.olean',
    'lib/lean/Lean/Elab/PreDefinition/Structural/BRecOn.olean',
    'lib/lean/Lean/Elab/PreDefinition/Structural/Basic.olean',
    'lib/lean/Lean/Elab/PreDefinition/Structural/Eqns.olean',
    'lib/lean/Lean/Elab/PreDefinition/Structural/FindRecArg.olean',
    'lib/lean/Lean/Elab/PreDefinition/Structural/IndGroupInfo.olean',
    'lib/lean/Lean/Elab/PreDefinition/Structural/IndPred.olean',
    'lib/lean/Lean/Elab/PreDefinition/Structural/Main.olean',
    'lib/lean/Lean/Elab/PreDefinition/Structural/Preprocess.olean',
    'lib/lean/Lean/Elab/PreDefinition/Structural/RecArgInfo.olean',
    'lib/lean/Lean/Elab/PreDefinition/Structural/SmartUnfolding.olean',
    'lib/lean/Lean/Elab/PreDefinition/TerminationHint.olean',
    'lib/lean/Lean/Elab/PreDefinition/TerminationMeasure.olean',
    'lib/lean/Lean/Elab/PreDefinition/WF/Basic.olean',
    'lib/lean/Lean/Elab/PreDefinition/WF/Eqns.olean',
    'lib/lean/Lean/Elab/PreDefinition/WF/Fix.olean',
    'lib/lean/Lean/Elab/PreDefinition/WF/FloatRecApp.olean',
    'lib/lean/Lean/Elab/PreDefinition/WF/GuessLex.olean',
    'lib/lean/Lean/Elab/PreDefinition/WF/Main.olean',
    'lib/lean/Lean/Elab/PreDefinition/WF/PackMutual.olean',
    'lib/lean/Lean/Elab/PreDefinition/WF/Preprocess.olean',
    'lib/lean/Lean/Elab/PreDefinition/WF/Rel.olean',
    'lib/lean/Lean/Elab/PreDefinition/WF/Unfold.olean',
    'lib/lean/Lean/Elab/Quotation.olean',
    'lib/lean/Lean/Elab/Quotation/Precheck.olean',
    'lib/lean/Lean/Elab/Quotation/Util.olean',
    'lib/lean/Lean/Elab/RecAppSyntax.olean',
    'lib/lean/Lean/Elab/SetOption.olean',
    'lib/lean/Lean/Elab/Syntax.olean',
    'lib/lean/Lean/Elab/SyntheticMVars.olean',
    'lib/lean/Lean/Elab/Tactic/Basic.olean',
    'lib/lean/Lean/Elab/Tactic/BuiltinTactic.olean',
    'lib/lean/Lean/Elab/Tactic/Change.olean',
    'lib/lean/Lean/Elab/Tactic/Config.olean',
    'lib/lean/Lean/Elab/Tactic/Conv.olean',
    'lib/lean/Lean/Elab/Tactic/Conv/Basic.olean',
    'lib/lean/Lean/Elab/Tactic/Conv/Change.olean',
    'lib/lean/Lean/Elab/Tactic/Conv/Congr.olean',
    'lib/lean/Lean/Elab/Tactic/Conv/Delta.olean',
    'lib/lean/Lean/Elab/Tactic/Conv/Pattern.olean',
    'lib/lean/Lean/Elab/Tactic/Conv/Rewrite.olean',
    'lib/lean/Lean/Elab/Tactic/Conv/Simp.olean',
    'lib/lean/Lean/Elab/Tactic/Conv/Unfold.olean',
    'lib/lean/Lean/Elab/Tactic/Delta.olean',
    'lib/lean/Lean/Elab/Tactic/Doc.olean',
    'lib/lean/Lean/Elab/Tactic/ElabTerm.olean',
    'lib/lean/Lean/Elab/Tactic/FalseOrByContra.olean',
    'lib/lean/Lean/Elab/Tactic/Location.olean',
    'lib/lean/Lean/Elab/Tactic/Monotonicity.olean',
    'lib/lean/Lean/Elab/Tactic/Omega.olean',
    'lib/lean/Lean/Elab/Tactic/Omega/Core.olean',
    'lib/lean/Lean/Elab/Tactic/Omega/Frontend.olean',
    'lib/lean/Lean/Elab/Tactic/Omega/MinNatAbs.olean',
    'lib/lean/Lean/Elab/Tactic/Omega/OmegaM.olean',
    'lib/lean/Lean/Elab/Tactic/Rewrite.olean',
    'lib/lean/Lean/Elab/Tactic/Simp.olean',
    'lib/lean/Lean/Elab/Tactic/SimpTrace.olean',
    'lib/lean/Lean/Elab/Tactic/Split.olean',
    'lib/lean/Lean/Elab/Tactic/Unfold.olean',
    'lib/lean/Lean/Elab/Term.olean',
    'lib/lean/Lean/Elab/Util.olean',
    'lib/lean/Lean/Environment.olean',
    'lib/lean/Lean/Exception.olean',
    'lib/lean/Lean/Expr.olean',
    'lib/lean/Lean/HeadIndex.olean',
    'lib/lean/Lean/Hygiene.olean',
    'lib/lean/Lean/ImportingFlag.olean',
    'lib/lean/Lean/InternalExceptionId.olean',
    'lib/lean/Lean/KeyedDeclsAttribute.olean',
    'lib/lean/Lean/LabelAttribute.olean',
    'lib/lean/Lean/Language/Basic.olean',
    'lib/lean/Lean/Language/Lean/Types.olean',
    'lib/lean/Lean/Level.olean',
    'lib/lean/Lean/Linter/Basic.olean',
    'lib/lean/Lean/Linter/Deprecated.olean',
    'lib/lean/Lean/Linter/MissingDocs.olean',
    'lib/lean/Lean/Linter/UnusedVariables.olean',
    'lib/lean/Lean/Linter/Util.olean',
    'lib/lean/Lean/LoadDynlib.olean',
    'lib/lean/Lean/LocalContext.olean',
    'lib/lean/Lean/Log.olean',
    'lib/lean/Lean/Message.olean',
    'lib/lean/Lean/Meta/ACLt.olean',
    'lib/lean/Lean/Meta/AbstractMVars.olean',
    'lib/lean/Lean/Meta/AbstractNestedProofs.olean',
    'lib/lean/Lean/Meta/AppBuilder.olean',
    'lib/lean/Lean/Meta/ArgsPacker.olean',
    'lib/lean/Lean/Meta/ArgsPacker/Basic.olean',
    'lib/lean/Lean/Meta/Basic.olean',
    'lib/lean/Lean/Meta/BinderNameHint.olean',
    'lib/lean/Lean/Meta/Canonicalizer.olean',
    'lib/lean/Lean/Meta/Check.olean',
    'lib/lean/Lean/Meta/Closure.olean',
    'lib/lean/Lean/Meta/Coe.olean',
    'lib/lean/Lean/Meta/CoeAttr.olean',
    'lib/lean/Lean/Meta/CollectFVars.olean',
    'lib/lean/Lean/Meta/CollectMVars.olean',
    'lib/lean/Lean/Meta/CompletionName.olean',
    'lib/lean/Lean/Meta/CongrTheorems.olean',
    'lib/lean/Lean/Meta/Constructions/CasesOn.olean',
    'lib/lean/Lean/Meta/CtorRecognizer.olean',
    'lib/lean/Lean/Meta/DecLevel.olean',
    'lib/lean/Lean/Meta/Diagnostics.olean',
    'lib/lean/Lean/Meta/DiscrTree.olean',
    'lib/lean/Lean/Meta/DiscrTreeTypes.olean',
    'lib/lean/Lean/Meta/Eqns.olean',
    'lib/lean/Lean/Meta/Eval.olean',
    'lib/lean/Lean/Meta/ForEachExpr.olean',
    'lib/lean/Lean/Meta/FunInfo.olean',
    'lib/lean/Lean/Meta/GeneralizeTelescope.olean',
    'lib/lean/Lean/Meta/GeneralizeVars.olean',
    'lib/lean/Lean/Meta/GetUnfoldableConst.olean',
    'lib/lean/Lean/Meta/GlobalInstances.olean',
    'lib/lean/Lean/Meta/IndPredBelow.olean',
    'lib/lean/Lean/Meta/InferType.olean',
    'lib/lean/Lean/Meta/Injective.olean',
    'lib/lean/Lean/Meta/Instances.olean',
    'lib/lean/Lean/Meta/IntInstTesters.olean',
    'lib/lean/Lean/Meta/Iterator.olean',
    'lib/lean/Lean/Meta/KAbstract.olean',
    'lib/lean/Lean/Meta/KExprMap.olean',
    'lib/lean/Lean/Meta/LitValues.olean',
    'lib/lean/Lean/Meta/Match.olean',
    'lib/lean/Lean/Meta/Match/Basic.olean',
    'lib/lean/Lean/Meta/Match/CaseArraySizes.olean',
    'lib/lean/Lean/Meta/Match/CaseValues.olean',
    'lib/lean/Lean/Meta/Match/Match.olean',
    'lib/lean/Lean/Meta/Match/MatchEqs.olean',
    'lib/lean/Lean/Meta/Match/MatchEqsExt.olean',
    'lib/lean/Lean/Meta/Match/MatchPatternAttr.olean',
    'lib/lean/Lean/Meta/Match/MatcherApp/Basic.olean',
    'lib/lean/Lean/Meta/Match/MatcherApp/Transform.olean',
    'lib/lean/Lean/Meta/Match/MatcherInfo.olean',
    'lib/lean/Lean/Meta/Match/Value.olean',
    'lib/lean/Lean/Meta/MatchUtil.olean',
    'lib/lean/Lean/Meta/NatInstTesters.olean',
    'lib/lean/Lean/Meta/Offset.olean',
    'lib/lean/Lean/Meta/PPGoal.olean',
    'lib/lean/Lean/Meta/PProdN.olean',
    'lib/lean/Lean/Meta/RecursorInfo.olean',
    'lib/lean/Lean/Meta/Reduce.olean',
    'lib/lean/Lean/Meta/ReduceEval.olean',
    'lib/lean/Lean/Meta/Sorry.olean',
    'lib/lean/Lean/Meta/Structure.olean',
    'lib/lean/Lean/Meta/SynthInstance.olean',
    'lib/lean/Lean/Meta/Tactic/Acyclic.olean',
    'lib/lean/Lean/Meta/Tactic/Apply.olean',
    'lib/lean/Lean/Meta/Tactic/Assert.olean',
    'lib/lean/Lean/Meta/Tactic/Assumption.olean',
    'lib/lean/Lean/Meta/Tactic/AuxLemma.olean',
    'lib/lean/Lean/Meta/Tactic/Backtrack.olean',
    'lib/lean/Lean/Meta/Tactic/Cases.olean',
    'lib/lean/Lean/Meta/Tactic/Cleanup.olean',
    'lib/lean/Lean/Meta/Tactic/Clear.olean',
    'lib/lean/Lean/Meta/Tactic/Congr.olean',
    'lib/lean/Lean/Meta/Tactic/Constructor.olean',
    'lib/lean/Lean/Meta/Tactic/Contradiction.olean',
    'lib/lean/Lean/Meta/Tactic/Delta.olean',
    'lib/lean/Lean/Meta/Tactic/ElimInfo.olean',
    'lib/lean/Lean/Meta/Tactic/ExposeNames.olean',
    'lib/lean/Lean/Meta/Tactic/FVarSubst.olean',
    'lib/lean/Lean/Meta/Tactic/Generalize.olean',
    'lib/lean/Lean/Meta/Tactic/IndependentOf.olean',
    'lib/lean/Lean/Meta/Tactic/Induction.olean',
    'lib/lean/Lean/Meta/Tactic/Injection.olean',
    'lib/lean/Lean/Meta/Tactic/Intro.olean',
    'lib/lean/Lean/Meta/Tactic/Refl.olean',
    'lib/lean/Lean/Meta/Tactic/Rename.olean',
    'lib/lean/Lean/Meta/Tactic/Repeat.olean',
    'lib/lean/Lean/Meta/Tactic/Replace.olean',
    'lib/lean/Lean/Meta/Tactic/Revert.olean',
    'lib/lean/Lean/Meta/Tactic/Rewrite.olean',
    'lib/lean/Lean/Meta/Tactic/Simp.olean',
    'lib/lean/Lean/Meta/Tactic/Simp/Arith.olean',
    'lib/lean/Lean/Meta/Tactic/Simp/Arith/Int.olean',
    'lib/lean/Lean/Meta/Tactic/Simp/Arith/Int/Basic.olean',
    'lib/lean/Lean/Meta/Tactic/Simp/Arith/Int/Simp.olean',
    'lib/lean/Lean/Meta/Tactic/Simp/Arith/Nat.olean',
    'lib/lean/Lean/Meta/Tactic/Simp/Arith/Nat/Basic.olean',
    'lib/lean/Lean/Meta/Tactic/Simp/Arith/Nat/Simp.olean',
    'lib/lean/Lean/Meta/Tactic/Simp/Arith/Util.olean',
    'lib/lean/Lean/Meta/Tactic/Simp/Attr.olean',
    'lib/lean/Lean/Meta/Tactic/Simp/BuiltinSimprocs.olean',
    'lib/lean/Lean/Meta/Tactic/Simp/BuiltinSimprocs/Array.olean',
    'lib/lean/Lean/Meta/Tactic/Simp/BuiltinSimprocs/BitVec.olean',
    'lib/lean/Lean/Meta/Tactic/Simp/BuiltinSimprocs/Char.olean',
    'lib/lean/Lean/Meta/Tactic/Simp/BuiltinSimprocs/Core.olean',
    'lib/lean/Lean/Meta/Tactic/Simp/BuiltinSimprocs/Fin.olean',
    'lib/lean/Lean/Meta/Tactic/Simp/BuiltinSimprocs/Int.olean',
    'lib/lean/Lean/Meta/Tactic/Simp/BuiltinSimprocs/List.olean',
    'lib/lean/Lean/Meta/Tactic/Simp/BuiltinSimprocs/Nat.olean',
    'lib/lean/Lean/Meta/Tactic/Simp/BuiltinSimprocs/SInt.olean',
    'lib/lean/Lean/Meta/Tactic/Simp/BuiltinSimprocs/String.olean',
    'lib/lean/Lean/Meta/Tactic/Simp/BuiltinSimprocs/UInt.olean',
    'lib/lean/Lean/Meta/Tactic/Simp/BuiltinSimprocs/Util.olean',
    'lib/lean/Lean/Meta/Tactic/Simp/Diagnostics.olean',
    'lib/lean/Lean/Meta/Tactic/Simp/Main.olean',
    'lib/lean/Lean/Meta/Tactic/Simp/RegisterCommand.olean',
    'lib/lean/Lean/Meta/Tactic/Simp/Rewrite.olean',
    'lib/lean/Lean/Meta/Tactic/Simp/SimpAll.olean',
    'lib/lean/Lean/Meta/Tactic/Simp/SimpCongrTheorems.olean',
    'lib/lean/Lean/Meta/Tactic/Simp/SimpTheorems.olean',
    'lib/lean/Lean/Meta/Tactic/Simp/Simproc.olean',
    'lib/lean/Lean/Meta/Tactic/Simp/Types.olean',
    'lib/lean/Lean/Meta/Tactic/SolveByElim.olean',
    'lib/lean/Lean/Meta/Tactic/Split.olean',
    'lib/lean/Lean/Meta/Tactic/SplitIf.olean',
    'lib/lean/Lean/Meta/Tactic/Subst.olean',
    'lib/lean/Lean/Meta/Tactic/Symm.olean',
    'lib/lean/Lean/Meta/Tactic/TryThis.olean',
    'lib/lean/Lean/Meta/Tactic/Unfold.olean',
    'lib/lean/Lean/Meta/Tactic/UnifyEq.olean',
    'lib/lean/Lean/Meta/Tactic/Util.olean',
    'lib/lean/Lean/Meta/Transform.olean',
    'lib/lean/Lean/Meta/TransparencyMode.olean',
    'lib/lean/Lean/Meta/WHNF.olean',
    'lib/lean/Lean/MetavarContext.olean',
    'lib/lean/Lean/Modifiers.olean',
    'lib/lean/Lean/MonadEnv.olean',
    'lib/lean/Lean/Namespace.olean',
    'lib/lean/Lean/Parser/Attr.olean',
    'lib/lean/Lean/Parser/Basic.olean',
    'lib/lean/Lean/Parser/Command.olean',
    'lib/lean/Lean/Parser/Do.olean',
    'lib/lean/Lean/Parser/Extension.olean',
    'lib/lean/Lean/Parser/Extra.olean',
    'lib/lean/Lean/Parser/Level.olean',
    'lib/lean/Lean/Parser/Module.olean',
    'lib/lean/Lean/Parser/StrInterpolation.olean',
    'lib/lean/Lean/Parser/Syntax.olean',
    'lib/lean/Lean/Parser/Tactic/Doc.olean',
    'lib/lean/Lean/Parser/Term.olean',
    'lib/lean/Lean/Parser/Term/Doc.olean',
    'lib/lean/Lean/Parser/Types.olean',
    'lib/lean/Lean/ParserCompiler.olean',
    'lib/lean/Lean/ParserCompiler/Attribute.olean',
    'lib/lean/Lean/PrettyPrinter.olean',
    'lib/lean/Lean/PrettyPrinter/Basic.olean',
    'lib/lean/Lean/PrettyPrinter/Delaborator.olean',
    'lib/lean/Lean/PrettyPrinter/Delaborator/Attributes.olean',
    'lib/lean/Lean/PrettyPrinter/Delaborator/Basic.olean',
    'lib/lean/Lean/PrettyPrinter/Delaborator/Builtins.olean',
    'lib/lean/Lean/PrettyPrinter/Delaborator/FieldNotation.olean',
    'lib/lean/Lean/PrettyPrinter/Delaborator/Options.olean',
    'lib/lean/Lean/PrettyPrinter/Delaborator/SubExpr.olean',
    'lib/lean/Lean/PrettyPrinter/Delaborator/TopDownAnalyze.olean',
    'lib/lean/Lean/PrettyPrinter/Formatter.olean',
    'lib/lean/Lean/PrettyPrinter/Parenthesizer.olean',
    'lib/lean/Lean/PrivateName.olean',
    'lib/lean/Lean/ProjFns.olean',
    'lib/lean/Lean/ReducibilityAttrs.olean',
    'lib/lean/Lean/ReservedNameAction.olean',
    'lib/lean/Lean/ResolveName.olean',
    'lib/lean/Lean/ScopedEnvExtension.olean',
    'lib/lean/Lean/Server/AsyncList.olean',
    'lib/lean/Lean/Server/CodeActions.olean',
    'lib/lean/Lean/Server/CodeActions/Attr.olean',
    'lib/lean/Lean/Server/CodeActions/Basic.olean',
    'lib/lean/Lean/Server/CodeActions/Provider.olean',
    'lib/lean/Lean/Server/Completion.olean',
    'lib/lean/Lean/Server/Completion/CompletionCollectors.olean',
    'lib/lean/Lean/Server/Completion/CompletionInfoSelection.olean',
    'lib/lean/Lean/Server/Completion/CompletionItemData.olean',
    'lib/lean/Lean/Server/Completion/CompletionResolution.olean',
    'lib/lean/Lean/Server/Completion/CompletionUtils.olean',
    'lib/lean/Lean/Server/Completion/EligibleHeaderDecls.olean',
    'lib/lean/Lean/Server/Completion/SyntheticCompletion.olean',
    'lib/lean/Lean/Server/FileSource.olean',
    'lib/lean/Lean/Server/FileWorker/ExampleHover.olean',
    'lib/lean/Lean/Server/FileWorker/InlayHints.olean',
    'lib/lean/Lean/Server/FileWorker/RequestHandling.olean',
    'lib/lean/Lean/Server/FileWorker/SemanticHighlighting.olean',
    'lib/lean/Lean/Server/FileWorker/Utils.olean',
    'lib/lean/Lean/Server/GoTo.olean',
    'lib/lean/Lean/Server/InfoUtils.olean',
    'lib/lean/Lean/Server/References.olean',
    'lib/lean/Lean/Server/RequestCancellation.olean',
    'lib/lean/Lean/Server/Requests.olean',
    'lib/lean/Lean/Server/Rpc/Basic.olean',
    'lib/lean/Lean/Server/Rpc/RequestHandling.olean',
    'lib/lean/Lean/Server/ServerTask.olean',
    'lib/lean/Lean/Server/Snapshots.olean',
    'lib/lean/Lean/Server/Utils.olean',
    'lib/lean/Lean/Structure.olean',
    'lib/lean/Lean/SubExpr.olean',
    'lib/lean/Lean/Syntax.olean',
    'lib/lean/Lean/ToExpr.olean',
    'lib/lean/Lean/ToLevel.olean',
    'lib/lean/Lean/Util/CollectFVars.olean',
    'lib/lean/Lean/Util/CollectLevelMVars.olean',
    'lib/lean/Lean/Util/CollectLevelParams.olean',
    'lib/lean/Lean/Util/CollectMVars.olean',
    'lib/lean/Lean/Util/FindExpr.olean',
    'lib/lean/Lean/Util/FindLevelMVar.olean',
    'lib/lean/Lean/Util/FindMVar.olean',
    'lib/lean/Lean/Util/FoldConsts.olean',
    'lib/lean/Lean/Util/ForEachExpr.olean',
    'lib/lean/Lean/Util/ForEachExprWhere.olean',
    'lib/lean/Lean/Util/HasConstCache.olean',
    'lib/lean/Lean/Util/InstantiateLevelParams.olean',
    'lib/lean/Lean/Util/MonadBacktrack.olean',
    'lib/lean/Lean/Util/MonadCache.olean',
    'lib/lean/Lean/Util/NumApps.olean',
    'lib/lean/Lean/Util/NumObjs.olean',
    'lib/lean/Lean/Util/OccursCheck.olean',
    'lib/lean/Lean/Util/PPExt.olean',
    'lib/lean/Lean/Util/Path.olean',
    'lib/lean/Lean/Util/Paths.olean',
    'lib/lean/Lean/Util/Profile.olean',
    'lib/lean/Lean/Util/PtrSet.olean',
    'lib/lean/Lean/Util/RecDepth.olean',
    'lib/lean/Lean/Util/Recognizers.olean',
    'lib/lean/Lean/Util/ReplaceExpr.olean',
    'lib/lean/Lean/Util/ReplaceLevel.olean',
    'lib/lean/Lean/Util/SCC.olean',
    'lib/lean/Lean/Util/SafeExponentiation.olean',
    'lib/lean/Lean/Util/ShareCommon.olean',
    'lib/lean/Lean/Util/Sorry.olean',
    'lib/lean/Lean/Util/SortExprs.olean',
    'lib/lean/Lean/Util/Trace.olean',
    'lib/lean/Lean/Widget/Basic.olean',
    'lib/lean/Lean/Widget/Diff.olean',
    'lib/lean/Lean/Widget/InteractiveCode.olean',
    'lib/lean/Lean/Widget/InteractiveDiagnostic.olean',
    'lib/lean/Lean/Widget/InteractiveGoal.olean',
    'lib/lean/Lean/Widget/TaggedText.olean',
    'lib/lean/Lean/Widget/Types.olean',
    'lib/lean/Lean/Widget/UserWidget.olean',
    'lib/lean/Std/Classes/Ord.olean',
    'lib/lean/Std/Data/DHashMap/AdditionalOperations.olean',
    'lib/lean/Std/Data/DHashMap/Basic.olean',
    'lib/lean/Std/Data/DHashMap/Internal/AssocList/Basic.olean',
    'lib/lean/Std/Data/DHashMap/Internal/AssocList/Lemmas.olean',
    'lib/lean/Std/Data/DHashMap/Internal/Defs.olean',
    'lib/lean/Std/Data/DHashMap/Internal/HashesTo.olean',
    'lib/lean/Std/Data/DHashMap/Internal/Index.olean',
    'lib/lean/Std/Data/DHashMap/Internal/Model.olean',
    'lib/lean/Std/Data/DHashMap/Internal/Raw.olean',
    'lib/lean/Std/Data/DHashMap/Internal/RawLemmas.olean',
    'lib/lean/Std/Data/DHashMap/Internal/WF.olean',
    'lib/lean/Std/Data/DHashMap/Lemmas.olean',
    'lib/lean/Std/Data/DHashMap/Raw.olean',
    'lib/lean/Std/Data/DHashMap/RawDef.olean',
    'lib/lean/Std/Data/DTreeMap/AdditionalOperations.olean',
    'lib/lean/Std/Data/DTreeMap/Basic.olean',
    'lib/lean/Std/Data/DTreeMap/Internal/Balanced.olean',
    'lib/lean/Std/Data/DTreeMap/Internal/Balancing.olean',
    'lib/lean/Std/Data/DTreeMap/Internal/Cell.olean',
    'lib/lean/Std/Data/DTreeMap/Internal/Def.olean',
    'lib/lean/Std/Data/DTreeMap/Internal/Model.olean',
    'lib/lean/Std/Data/DTreeMap/Internal/Operations.olean',
    'lib/lean/Std/Data/DTreeMap/Internal/Ordered.olean',
    'lib/lean/Std/Data/DTreeMap/Internal/Queries.olean',
    'lib/lean/Std/Data/DTreeMap/Internal/WF/Defs.olean',
    'lib/lean/Std/Data/DTreeMap/Internal/WF/Lemmas.olean',
    'lib/lean/Std/Data/DTreeMap/Raw/Basic.olean',
    'lib/lean/Std/Data/HashMap.olean',
    'lib/lean/Std/Data/HashMap/AdditionalOperations.olean',
    'lib/lean/Std/Data/HashMap/Basic.olean',
    'lib/lean/Std/Data/HashMap/Lemmas.olean',
    'lib/lean/Std/Data/HashMap/Raw.olean',
    'lib/lean/Std/Data/HashSet/Basic.olean',
    'lib/lean/Std/Data/Internal/Cut.olean',
    'lib/lean/Std/Data/Internal/List/Associative.olean',
    'lib/lean/Std/Data/Internal/List/Defs.olean',
    'lib/lean/Std/Data/TreeMap.olean',
    'lib/lean/Std/Data/TreeMap/AdditionalOperations.olean',
    'lib/lean/Std/Data/TreeMap/Basic.olean',
    'lib/lean/Std/Data/TreeMap/Raw/Basic.olean',
    'lib/lean/Std/Internal/Parsec.olean',
    'lib/lean/Std/Internal/Parsec/Basic.olean',
    'lib/lean/Std/Internal/Parsec/ByteArray.olean',
    'lib/lean/Std/Internal/Parsec/String.olean',
    'lib/lean/Std/Sync/Basic.olean',
    'lib/lean/Std/Sync/Mutex.olean',
    'lib/lean/libInit_shared.so',
    'lib/lean/libleanshared.so',
    'lib/lean/libleanshared_1.so',
)

def support_paths():
    result = SUPPORT_IDENTITY_PATHS
    require(len(result) == 780 and commitment(result) == 'edcebd3d002159c741e80e9fc3c8c42fc722e54a1a1d7341c91ee31df6ea743f',
            'exact support path set drift')
    return result


def file_record(raw):
    return dict(sha256=digest(raw), bytes=len(raw))


def cap(name):
    require(name in FIXED_FILES, 'unplanned file')
    if name in SOURCE_FILES: return BUDGETS['source']
    if name in MODULE_FILES: return BUDGETS['module']
    if name in LOG_FILES: return BUDGETS['raw_stage']
    if name in ('PLAN.json', 'relocation-manifest.json'): return 32768
    if name == 'IDENTITY.json': return 144713
    if name == 'RUN.json': return 630
    return 16384


class Snapshot:
    """Stable descriptor reads, inode/ancestor and complete byte authentication."""
    def __init__(self, root):
        self.root = root
        self.files = {}
        self.directories = {}
        self.check_directories()

    def check_directories(self):
        self.root.unchanged()
        paths = [self.root.path, *self.root.path.parents]
        paths += [self.root.path / p for p in ('original', 'HiaSyntaxResearch') if os.path.lexists(self.root.path / p)]
        for path in paths:
            info = os.stat(path, follow_symlinks=False)
            key = str(path)
            value = (info.st_dev, info.st_ino)
            require(stat.S_ISDIR(info.st_mode) and (key not in self.directories or self.directories[key] == value),
                    'ancestor changed or unsafe')
            self.directories[key] = value

    def read(self, name, *, mutable=False):
        self.check_directories()
        raw = self.root.read(name, cap(name))
        info = os.stat(self.root.path / name, follow_symlinks=False)
        value = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_nlink)
        require(mutable or name not in self.files or self.files[name] == value, 'frozen inode changed')
        if not mutable: self.files[name] = value
        return raw


class External:
    """Actual pinned binary, all support bytes and exact repository source bytes."""
    def __init__(self, executable):
        self.executable = Path(absolute(str(executable)))
        absolute(str(self.executable.parent.parent))
        self.paths = {str(ROOT / n): BUDGETS['source'] for n in source_paths()}
        self.paths.update({str(self.executable.parent.parent / n): 9223372036854775807 for n in support_paths()})
        self.paths[str(self.executable)] = 9223372036854775807
        self.inodes, self.parents, self.records = {}, {}, {}
        self.check()
        pin = json.loads(self.read_source('formal/toolchain-lock.json'))['lean_binary_sha256']
        require(self.records[str(self.executable)]['sha256'] == pin, 'pinned binary required')
        self.git = diagnostic._git_baseline()

    def reject_support_shadow(self):
        prefix = self.executable.parent.parent / 'lib/lean' / base.MODULE_PREFIX
        require(not os.path.lexists(prefix) and not os.path.lexists(str(prefix) + '.olean'), 'support module-prefix shadow')

    def check(self):
        self.reject_support_shadow()
        # Streaming hashing avoids unbounded copies of support libraries.
        import hashlib
        for name, maximum in self.paths.items():
            path = Path(name)
            for parent in path.parents:
                info = os.stat(parent, follow_symlinks=False)
                key, value = str(parent), (info.st_dev, info.st_ino)
                require(stat.S_ISDIR(info.st_mode) and (key not in self.parents or self.parents[key] == value), 'external ancestor changed')
                self.parents[key] = value
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                before = os.fstat(fd)
                value = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns, s.st_nlink)
                require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= maximum,
                        'external unsafe file/size')
                h, count = hashlib.sha256(), 0
                while True:
                    chunk = os.read(fd, 65536)
                    if not chunk: break
                    count += len(chunk)
                    require(count <= maximum, 'external size grew')
                    h.update(chunk)
                require(value(before) == value(os.fstat(fd)) == value(os.stat(path, follow_symlinks=False)) and count == before.st_size,
                        'external read race')
                require(name not in self.inodes or self.inodes[name] == value(before), 'external inode changed')
                record = dict(bytes=count, sha256=h.hexdigest())
                require(name not in self.records or same(self.records[name], record), 'external bytes changed')
                self.inodes[name], self.records[name] = value(before), record
            finally: os.close(fd)
        self.reject_support_shadow()
        if hasattr(self, 'git'):
            require(same(self.git, diagnostic._git_baseline()), 'git baseline changed')

    def read_source(self, name):
        """Bounded nofollow reread of an already authenticated source file."""
        require(name in SOURCE_IDENTITY_PATHS, 'unplanned external source read')
        path = ROOT / name
        key = str(path)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            fields = lambda st: (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_nlink)
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= BUDGETS['source']
                    and fields(before) == self.inodes[key], 'external source reread identity')
            raw = bytearray()
            while len(raw) <= BUDGETS['source']:
                chunk = os.read(fd, min(65536, BUDGETS['source'] + 1 - len(raw)))
                if not chunk: break
                raw.extend(chunk)
            require(len(raw) <= BUDGETS['source'] and fields(before) == fields(os.fstat(fd)) == fields(os.stat(path, follow_symlinks=False)),
                    'external source reread race/bound')
            raw = bytes(raw)
            require(same(file_record(raw), self.records[key]), 'external source reread bytes')
            return raw
        finally:
            os.close(fd)

    def identity(self, run_id):
        return dict(**common(run_id), commit_sha=self.git['head'], tree_sha=self.git['tree'],
                    lean_binary_sha256=self.records[str(self.executable)]['sha256'],
                    sources={n: self.records[str(ROOT / n)] for n in source_paths()},
                    support={n: self.records[str(self.executable.parent.parent / n)] for n in support_paths()})


def negative_locations(prepared, proposal):
    # The relocation manifest deliberately has no negative-coordinate ledger.
    # Parse the actual candidate declarations with the original unique-line rule.
    locations = {}
    for stage in proposal.stages[9:]:
        for name in stage.rejection_names:
            require(name not in locations and name in prepared['negatives'], 'unique original negative name')
            local = prepared['negatives'][name]['certificate'].rsplit('.', 1)[1]
            lines = [i for i, line in enumerate(stage.source.splitlines(), 1)
                     if line.startswith('theorem ' + local + ' :')]
            require(len(lines) == 1, 'unique actual negative declaration')
            locations[name] = dict(module=stage.module_name, line=lines[0])
    require(len(locations) == 10 and set(locations) == set(prepared['negatives']), 'complete ten current negative coordinates')
    return locations


def prepare():
    prepared = seven.original.build_inputs()
    previous = seven.build_sources(prepared)
    # This builder invokes the unchanged relocation validator, including the
    # mandatory actual-declaration inverse and unchanged old full validators.
    proposal = relocation.build_sources(prepared, previous)
    require(type(proposal) is relocation.ParallelRelocationSources, 'distinct relocated candidate type')
    require(relocation.validate_retention(proposal) == 5593354, 'retained declarations changed')
    require(negative_locations(prepared, proposal) == previous.manifest['negative_declaration_locations'],
            'unchanged final-module negative coordinates')
    require({k: len(v['bytes']) for k, v in prepared['binding_inputs'].items()} ==
            dict(linear=14466, parallel=14466, wrong_phi=14466, literal_two=14466, wrong_condition=14585), 'full input lengths')
    return prepared, proposal


def make_plan(run_id, identity, executable, root, prepared, proposal):
    m = proposal.manifest
    locations = negative_locations(prepared, proposal)
    return dict(**common(run_id), identity_sha256=commitment(identity), original_manifest_sha256=prepared['manifest_sha256'],
        relocation_manifest_sha256=proposal.manifest_sha256,
        previous_seven_manifest_sha256=m['previous_seven_manifest_sha256'],
        stages=[dict(index=i, name=s.name, module_name=s.module_name, source_path=s.module_name.replace('.', '/') + '.lean',
                     source_sha256=s.source_sha256, source_bytes=s.source_bytes, parents=list(s.parents),
                     direct_imports=list(s.direct_imports), subject_count=len(s.expected_theorems),
                     subject_sequence_sha256=commitment(seven._qualified_prints(s.source)), rejection_names=sorted(s.rejection_names))
                for i, s in enumerate(proposal.stages)], positive_targets=sorted(prepared['expected_theorems']),
        negatives={k: dict(v, current_location=locations[k]) for k, v in prepared['negatives'].items()},
        input_bindings={k: dict(file_record(v['bytes']), root_owner=m['root_owners'][k]) for k, v in prepared['binding_inputs'].items()},
        source_file_map={'original/' + s.name + '.lean': file_record(s.source.encode()) for s in prepared['stages']},
        budgets=dict(BUDGETS), process_spec=dict(executable=absolute(str(executable)), root=absolute(str(root)),
            sysroot=absolute(str(Path(executable).parent.parent)),
            argv_template=['executable', '--root=root', '-o', 'root/module.olean', 'root/module.lean'],
            environment_keys=['LEAN_PATH', 'LEAN_SYSROOT'], unset_environment_keys=['LEAN_SRC_PATH']))


def make_run(plan):
    return dict(**common(plan['run_id']), identity_sha256=plan['identity_sha256'], plan_sha256=commitment(plan),
                original_manifest_sha256=plan['original_manifest_sha256'], relocation_manifest_sha256=plan['relocation_manifest_sha256'],
                previous_seven_manifest_sha256=plan['previous_seven_manifest_sha256'])


def reconstruct(snapshot):
    # Authenticated fixed inputs regenerate the complete original transient
    # manifest, then actual retained originals and candidates are checked in full.
    prepared = seven.original.build_inputs()
    from types import MappingProxyType
    actual_originals = []
    for stage in prepared['stages']:
        raw = snapshot.read('original/' + stage.name + '.lean')
        require(raw == stage.source.encode(), 'actual original declarations differ')
        actual_originals.append(replace(stage, source=raw.decode('utf-8')))
    actual_originals = tuple(actual_originals)
    # Reconstruct the full transient original manifest FROM those actual bytes,
    # including parsed declaration ownership and negative source coordinates.
    # Reference input streams are separately checked by the unchanged inverse.
    _, per_input = seven.original._stream(prepared['original_prepared'])
    manifest = seven.original._manifest(actual_originals, prepared['original_prepared'], per_input)
    manifest_json = seven.original.encode(manifest)
    require(manifest_json == prepared['manifest_json'], 'regenerated actual original manifest differs')
    prepared = dict(prepared, stages=actual_originals,
                    sources=MappingProxyType({s.module_name: s.source for s in actual_originals}),
                    manifest=manifest, manifest_json=manifest_json, manifest_sha256=digest(manifest_json.encode()))
    previous = seven.build_sources(prepared)
    # Derive metadata scaffolding without validating a discarded generated candidate.
    # Every actual retained candidate byte still undergoes the full validator below.
    expected = relocation._derive_stages(previous)
    stages = tuple(replace(s, source=snapshot.read(s.module_name.replace('.', '/') + '.lean').decode('utf-8')) for s in expected)
    proposal = relocation.ParallelRelocationSources(prepared['stages'], stages, snapshot.read('relocation-manifest.json').decode('utf-8'))
    relocation.validate_sources(prepared, previous, proposal)
    require(negative_locations(prepared, proposal) == previous.manifest['negative_declaration_locations'],
            'unchanged actual final-module negative coordinates')
    return prepared, proposal


def inventory(out, err, stage):
    return diagnostic._inventory(out, err, stage)


def started(plan, run, stage, accepted, remaining):
    integer(remaining, 0, BUDGETS['launch_ns'])
    return dict(**common(plan['run_id']), run_sha256=commitment(run), plan_sha256=commitment(plan),
                index=stage['index'], name=stage['name'], source_sha256=stage['source_sha256'],
                parents={p: accepted[p] for p in stage['parents']}, remaining_launch_ns=remaining)


def validate_process(p, success=False):
    booleans = ('spawned', 'timed_out', 'incomplete', 'output_truncated', 'leader_reaped', 'stdout_eof',
                'stderr_eof', 'original_group_empty', 'leader_reap_observed')
    keys = set(booleans) | {'returncode', 'elapsed_ns', 'cleanup_ns', 'leader_pid', 'original_pgid', 'leader_start_ticks',
                          'terminal_observation', 'pre_reap_group_signal', 'post_reap_group_probe'}
    require(type(p) is dict and set(p) == keys, 'process exact keys')
    require(all(type(p[k]) is bool for k in booleans), 'process booleans')
    if p['returncode'] is not None: integer(p['returncode'], -2147483648, 2147483647)
    integer(p['elapsed_ns'], 0, 600000000000); integer(p['cleanup_ns'], 0, BUDGETS['cleanup_ns'])
    for k in ('leader_pid', 'original_pgid'):
        if p[k] is not None: integer(p[k], 1, 2147483647)
    if p['leader_start_ticks'] is not None: integer(p['leader_start_ticks'], 0, 18446744073709551615)
    require(p['terminal_observation'] in ('waitid_wnowait', 'not_observed') and
            p['pre_reap_group_signal'] in ('sigkill_sent', 'sigkill_no_signalable_group', 'not_attempted', 'failed') and
            p['post_reap_group_probe'] in ('esrch', 'group_exists', 'unknown_or_permission_error', 'not_observed'), 'process enums')
    require(p['leader_reaped'] == p['leader_reap_observed'] and (p['returncode'] is not None) == p['leader_reaped'], 'reap/exit observations differ')
    require(p['post_reap_group_probe'] == 'not_observed' or p['leader_reaped'], 'probe requires reaped leader')
    require(p['original_group_empty'] == (p['post_reap_group_probe'] == 'esrch'), 'latest group probe differs')
    require(p['terminal_observation'] != 'waitid_wnowait' or p['leader_start_ticks'] is not None, 'terminal observation requires captured identity')
    require(p['cleanup_ns'] < BUDGETS['cleanup_ns'] or p['incomplete'], 'expired cleanup cannot be complete')
    if not p['spawned']:
        require(not any(p[k] for k in booleans) and p['cleanup_ns'] == 0, 'unspawned flags/cleanup')
        require(p['returncode'] is None and p['elapsed_ns'] == 0 and p['leader_pid'] is None and p['original_pgid'] is None
                and p['leader_start_ticks'] is None and not any(p[k] for k in ('leader_reaped', 'stdout_eof', 'stderr_eof', 'original_group_empty'))
                and p['terminal_observation'] == 'not_observed' and p['pre_reap_group_signal'] == 'not_attempted'
                and p['post_reap_group_probe'] == 'not_observed', 'nonlaunched observations')
    else:
        integer(p['leader_pid'], 1, 2147483647)
        require(p['original_pgid'] == p['leader_pid'], 'original process group identity')
        require(p['pre_reap_group_signal'] != 'not_attempted' and p['timed_out'] == (p['elapsed_ns'] >= BUDGETS['process_ns']), 'spawned cleanup/timeout observations')
    if p['original_group_empty']:
        require(p['leader_reaped'] and p['post_reap_group_probe'] == 'esrch', 'final empty group observation')
    if success:
        require(all(p[k] for k in ('spawned', 'leader_reaped', 'stdout_eof', 'stderr_eof', 'original_group_empty', 'leader_reap_observed'))
                and not any(p[k] for k in ('timed_out', 'incomplete', 'output_truncated')) and p['returncode'] == 0
                and p['elapsed_ns'] < BUDGETS['process_ns'] and p['cleanup_ns'] < BUDGETS['cleanup_ns']
                and p['terminal_observation'] == 'waitid_wnowait'
                and p['pre_reap_group_signal'] in ('sigkill_sent', 'sigkill_no_signalable_group')
                and p['post_reap_group_probe'] == 'esrch' and p['leader_start_ticks'] is not None, 'unsafe successful process')
    return p


def validate_failure(value):
    keys = {'schema', 'protocol', 'run_id', 'status', 'run_sha256', 'plan_sha256', 'identity_sha256',
            'failed_stage', 'phase', 'error_code', 'invocations', 'wall_ns', 'committed_receipt_sha256'} | set(flags())
    require(type(value) is dict and set(value) == keys, 'failure exact keys')
    require(all(same(value[k], v) for k, v in {**common(value['run_id']), **flags(), 'status': 'failed'}.items()), 'failure flags/header')
    code, phase, index = value['error_code'], value['phase'], value['failed_stage']
    require(type(code) is str and code in PHASE_CODES and phase in PHASE_CODES[code], 'failure code phase')
    if index is not None: integer(index, 0, 10)
    require((index is None) == (phase in ('preparation', 'finalization')), 'failure phase stage')
    integer(value['invocations'], 0, 11); integer(value['wall_ns'], 0, 600000000000)
    receipts = value['committed_receipt_sha256']
    require(type(receipts) is list and len(receipts) <= 11 and len(set(receipts)) == len(receipts), 'failure prefix shape')
    for h in receipts: hash_value(h)
    require(len(receipts) <= value['invocations'], 'failure prefix launches')
    if index is not None:
        require(len(receipts) == index and value['invocations'] in (index, index + 1), 'failure successful prefix')
        if phase == 'prelaunch': require(value['invocations'] == index, 'prelaunch invocation')
        if phase in ('capturing', 'verifying', 'receipt_commit'): require(value['invocations'] == index + 1, 'postlaunch invocation')
    if phase == 'preparation': require(value['invocations'] == 0 and not receipts, 'preparation prefix')
    for key in ('run_sha256', 'plan_sha256', 'identity_sha256'):
        if value[key] is None: require(phase == 'preparation', 'late missing binding')
        else: hash_value(value[key])
    require(value['run_sha256'] is None or value['plan_sha256'] is not None, 'run requires plan')
    require(value['plan_sha256'] is None or value['identity_sha256'] is not None, 'plan requires identity')
    return value


def budgets(files, display=b''):
    require(set(files) <= FIXED_FILES and all(type(raw) is bytes and len(raw) <= cap(n) for n, raw in files.items()), 'fixed per-file caps')
    sources = sum(len(files.get(n, b'')) for n in SOURCE_FILES)
    modules = sum(len(files.get(n, b'')) for n in MODULE_FILES)
    raw = sum(len(files.get(n, b'')) for n in LOG_FILES)
    metadata = sum(len(v) for n, v in files.items() if n not in SOURCE_FILES + MODULE_FILES + LOG_FILES)
    require(sources <= BUDGETS['sources'] and modules <= BUDGETS['modules'] and raw <= RAW_GLOBAL, 'aggregate payload caps')
    require(metadata <= METADATA_RESERVE <= BUDGETS['metadata'] and len(display) <= BUDGETS['display']
            and metadata + raw + len(display) <= BUDGETS['evidence_display']
            and sources + modules + raw + metadata <= BUDGETS['container'], 'aggregate evidence/container caps')
    for n in seven.NAMES:
        require(sum(len(files.get(n + '.' + s, b'')) for s in ('stdout', 'stderr')) <= BUDGETS['raw_stage'], 'stage raw cap')


def validate_plan_records(identity, plan, run, expected_identity, executable, root, prepared, proposal):
    require(same(identity, expected_identity), 'actual full identity differs')
    expected = make_plan(expected_identity['run_id'], expected_identity, executable, root, prepared, proposal)
    require(same(plan, expected) and same(run, make_run(expected)), 'strict complete independently regenerated plan/run')
    return expected


def validate_failed_stage(value):
    keys = {'schema', 'protocol', 'run_id', 'index', 'name', 'started_sha256', 'status',
            'process', 'logs', 'inventory', 'olean', 'error_code'}
    require(type(value) is dict and set(value) == keys, 'failed stage exact keys')
    require(all(same(value[k], v) for k, v in common(value['run_id']).items()), 'failed stage header')
    integer(value['index'], 0, 10)
    require(value['name'] == seven.NAMES[value['index']] and value['status'] == 'stage_failed'
            and value['error_code'] in PHASE_CODES and value['inventory'] is None and value['olean'] is None, 'failed stage status')
    hash_value(value['started_sha256'])
    process = validate_process(value['process'])
    logs = value['logs']
    if logs is None:
        require(not process['spawned'], 'spawned capture files required')
    else:
        require(type(logs) is dict and set(logs) == {'stdout', 'stderr'}, 'failed logs keys')
        total = 0
        for record in logs.values():
            require(type(record) is dict and set(record) == {'sha256', 'bytes'}, 'failed log record keys')
            hash_value(record['sha256']); integer(record['bytes'], 0, BUDGETS['raw_stage'])
            total += record['bytes']
        require(total <= BUDGETS['raw_stage'], 'failed raw pair bound')
        if not process['spawned']: require(total == 0, 'unspawned raw output')
    return value
