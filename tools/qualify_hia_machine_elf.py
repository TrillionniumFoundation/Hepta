"""Qualify all retained ELF callers with the explicit native object owner.

This is one component gate. It does not certify arbitrary foreign comparison
schedules, installed execution, or the complete native project.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import stat
import time
import traceback
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ''}:
    sys.path.insert(0, str(ROOT))

from tools.build_hia_machine_elf import build, current_sources, OWNED_SOURCE_FILES

MODULES = (
    'tests.test_hia_machine_x64', 'tests.test_hia_machine_plan',
    'tests.test_hia_program_native', 'tests.test_hia_safe_core_artifact',
)

# Original 608 source modules and actual ordered loader IDs from the preserved
# e77 report 0204d67d...; source changes require an explicit reviewed revision.
MODULE_SOURCE_PINS = {
    "tests/test_hia_machine_x64.py": "1ba1a51995c38ae93e5ce1a748a0b2bf3d2d6a19c0c48dfb9043c1ef639e094f",
    "tests/test_hia_machine_plan.py": "a1d090bbbb5021957ca550813afb78f061bf10412554379f5efad3ca96974af9",
    "tests/test_hia_program_native.py": "a958a2bb4c94302f73332ee133a9583b84f14eece861f51211558099446359b7",
    "tests/test_hia_safe_core_artifact.py": "f2cb87ff649d7f5af8ec809086ccd8de093bd13214410f790d5b3fef87f62f81"
}
EXPECTED_IDS = (
    "tests.test_hia_machine_x64.EncoderExecutionTests.test_all_general_registers_rex_arithmetic_shifts_conditions_and_internal_calls",
    "tests.test_hia_machine_x64.EncoderExecutionTests.test_external_allocator_relocations_resolve_with_only_ld",
    "tests.test_hia_machine_x64.EncoderExecutionTests.test_independent_elf_and_isa_tools_accept_output",
    "tests.test_hia_machine_x64.EncoderExecutionTests.test_memory_sib_displacements_lea_and_low_byte_rex",
    "tests.test_hia_machine_x64.EncoderStructuralTests.test_elf_symbol_order_and_stack_flags",
    "tests.test_hia_machine_x64.EncoderStructuralTests.test_invalid_registers_immediates_labels_and_relocations_reject",
    "tests.test_hia_machine_x64.EncoderStructuralTests.test_relocation_and_local_branches_are_deterministic",
    "tests.test_hia_machine_plan.MachinePlanExecutionTests.test_immediate_boundaries_and_live_flags_on_real_machine",
    "tests.test_hia_machine_plan.MachinePlanExecutionTests.test_independent_scratch_selection_and_layout_observations",
    "tests.test_hia_machine_plan.MachinePlanExecutionTests.test_requested_alignment_survives_elf_linking_and_loading",
    "tests.test_hia_machine_plan.MachinePlanValidationTests.test_default_plan_is_byte_identical_and_plan_changes_are_sealed",
    "tests.test_hia_machine_plan.MachinePlanValidationTests.test_each_choice_is_explicit_and_core_bound",
    "tests.test_hia_machine_plan.MachinePlanValidationTests.test_encoder_rejects_unreviewed_registers_and_choices",
    "tests.test_hia_program_native.DirectExecutionTests.test_all_integer_widths_wrapping_bits_shifts_and_signed_division",
    "tests.test_hia_program_native.DirectExecutionTests.test_allocator_observer_checks_actual_frees_and_failed_allocation",
    "tests.test_hia_program_native.DirectExecutionTests.test_bulk_operations_v2_through_v6_match_vm",
    "tests.test_hia_program_native.DirectExecutionTests.test_checked_arithmetic_comparisons_casts_and_unary",
    "tests.test_hia_program_native.DirectExecutionTests.test_checked_failures_abort_in_isolated_native_processes",
    "tests.test_hia_program_native.DirectExecutionTests.test_owned_memory_zero_initialization_and_ordinary_error_cleanup",
    "tests.test_hia_program_native.DirectExecutionTests.test_real_loops_calls_multiple_returns_and_parallel_block_moves",
    "tests.test_hia_program_native.DirectExecutionTests.test_recursive_chain_and_composite_v7_have_real_dynamic_execution",
    "tests.test_hia_program_native.DirectExecutionTests.test_scalar_c_abi_register_and_stack_arguments",
    "tests.test_hia_program_native.DirectExecutionTests.test_v8_chain_head_returned_loans_and_pop",
    "tests.test_hia_program_native.DirectExecutionTests.test_v8_parameter_loans_calls_cfg_recursion_and_aliases",
    "tests.test_hia_program_native.DirectObjectTests.test_all_versioned_agent_core_examples_are_emitted_without_llvm",
    "tests.test_hia_program_native.DirectObjectTests.test_artifact_mutation_rejected_even_with_recomputed_object_digest",
    "tests.test_hia_program_native.DirectObjectTests.test_cli_native_object_and_explicit_target_rejection",
    "tests.test_hia_program_native.DirectObjectTests.test_existing_output_is_preserved",
    "tests.test_hia_program_native.DirectObjectTests.test_foreign_target_is_explicitly_rejected",
    "tests.test_hia_program_native.DirectObjectTests.test_forged_verified_core_is_reverified_before_emission",
    "tests.test_hia_program_native.DirectObjectTests.test_object_build_in_fresh_process_prohibits_llvm_import_and_process_launch",
    "tests.test_hia_program_native.DirectObjectTests.test_object_generation_is_deterministic_and_bound_to_exact_core",
    "tests.test_hia_program_native.DirectObjectTests.test_route_inventory_names_explicit_direct_machine_selection",
    "tests.test_hia_program_native.DirectSystemLinkerTests.test_cli_native_shared_library_is_callable_with_ld",
    "tests.test_hia_program_native.DirectSystemLinkerTests.test_system_linker_alone_produces_callable_shared_library",
    "tests.test_hia_safe_core_artifact.SafeCoreArtifactTests.test_alternate_core_is_not_qualified_by_matching_producer_metadata",
    "tests.test_hia_safe_core_artifact.SafeCoreArtifactTests.test_emission_and_linking_can_be_disabled_during_consumer_validation",
    "tests.test_hia_safe_core_artifact.SafeCoreArtifactTests.test_equivalent_noncanonical_instruction_bytes_are_independently_accepted",
    "tests.test_hia_safe_core_artifact.SafeCoreArtifactTests.test_exact_supplied_bytes_and_scoped_checker_identity_are_bound",
    "tests.test_hia_safe_core_artifact.SafeCoreArtifactTests.test_final_bytes_cannot_disagree_with_the_supplied_object",
    "tests.test_hia_safe_core_artifact.SafeCoreArtifactTests.test_fresh_consumer_does_not_import_native_producers",
    "tests.test_hia_safe_core_artifact.SafeCoreArtifactTests.test_imul_carry_matches_signed_not_unsigned_truncation",
    "tests.test_hia_safe_core_artifact.SafeCoreArtifactTests.test_imul_zero_flag_is_arbitrary_after_a_known_zero_flag",
    "tests.test_hia_safe_core_artifact.SafeCoreArtifactTests.test_joint_object_and_final_arithmetic_mutation_produces_a_counterexample",
    "tests.test_hia_safe_core_artifact.SafeCoreArtifactTests.test_joint_product_to_sum_mutation_is_refuted",
    "tests.test_hia_safe_core_artifact.SafeCoreArtifactTests.test_last_identity_check_cannot_publish_a_proof_after_the_deadline",
    "tests.test_hia_safe_core_artifact.SafeCoreArtifactTests.test_pinned_input_mismatch_rejects_before_any_solver_query",
    "tests.test_hia_safe_core_artifact.SafeCoreArtifactTests.test_rejected_command_retains_original_bytes_queries_and_counterexample",
    "tests.test_hia_safe_core_artifact.SafeCoreArtifactTests.test_wrapping_multiplication_is_proved_and_executed_at_all_unsigned_widths",
    "tests.test_hia_safe_core_artifact.SafeCoreImmutableInputTests.test_imul_register_fields_and_unreviewed_encodings",
    "tests.test_hia_safe_core_artifact.SafeCoreImmutableInputTests.test_mutable_buffers_and_bytes_subclasses_are_rejected_before_parsing",
)


def flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from flatten(item)
        else:
            yield item


class ObservedResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.executed = []

    def startTest(self, test):
        self.executed.append(test.id())
        super().startTest(test)


def _bytes_pin(path):
    return sha256(Path(path).read_bytes()).hexdigest()


def _file_observation(path, maximum):
    requested = Path(path).resolve(strict=True)
    before = requested.stat()
    def identity(value):
        return (value.st_dev, value.st_ino, value.st_mode, value.st_size,
                value.st_mtime_ns, value.st_ctime_ns)
    descriptor = os.open(requested, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(descriptor, 'rb') as stream:
        opened = os.fstat(stream.fileno())
        if (not stat.S_ISREG(opened.st_mode) or not 0 < opened.st_size <= maximum
                or identity(opened) != identity(before)):
            raise ValueError('bounded ordinary ELF build file required')
        raw = stream.read(maximum + 1)
        if (len(raw) != opened.st_size or identity(os.fstat(stream.fileno())) != identity(opened)):
            raise ValueError('ELF build file changed during read')
    if identity(requested.stat()) != identity(before):
        raise ValueError('ELF build file changed after read')
    return {'path': str(requested), 'bytes': len(raw),
            'sha256': sha256(raw).hexdigest(), 'identity': list(identity(before))}, raw


def _bundle_observation(manifest):
    manifest_pin, raw = _file_observation(manifest, 16384)
    value = json.loads(raw)
    name = value['image_path']
    if type(name) is not str or not name or Path(name).name != name:
        raise ValueError('one-component ELF image filename required')
    image_pin, _ = _file_observation(Path(manifest_pin['path']).parent / name, 1 << 20)
    if image_pin['sha256'] != value['image_sha256']:
        raise ValueError('ELF image file differs from selected manifest')
    return {'manifest': manifest_pin, 'image': image_pin}, raw


def _development_sources():
    # Development scope is explicit; this map is not a cold source closure.
    from tools.hia_selfhost_contract import SOURCE_FILES
    return {name: _bytes_pin(ROOT / name)
            for name in sorted(set(SOURCE_FILES) | set(OWNED_SOURCE_FILES))}


def qualify(output, *, cold_report=None, development_manifest=None):
    output = Path(output)
    if (cold_report is None) == (development_manifest is None):
        raise ValueError('choose exactly one current cold report or development manifest')
    output.mkdir(mode=0o700)
    report = {
        'schema': 'hepta.hia.machine-elf-callers.v1', 'status': 'HOLD',
        'scope': ('MATCHING_SOURCE_COLD_BUILD' if cold_report is not None
                  else 'EXPLICIT_DEVELOPMENT_ONLY_NOT_COLD'),
        'modules': list(MODULES),
        'whole_writer_qualified': False, 'whole_native_delivery_qualified': False,
        'foreign_timsort_schedule_closed': False,
        'retained_writer_calls': [], 'loader_errors': [],
        'expected_test_ids': list(EXPECTED_IDS), 'expected_count': 51,
        'expected_module_sources': MODULE_SOURCE_PINS,
    }
    failure = None
    started = time.monotonic()
    sources = None
    before = None
    bundle_before = None
    try:
        if cold_report is not None:
            cold_report = Path(cold_report)
            cold_raw = cold_report.read_bytes()
            cold = json.loads(cold_raw)
            nested = json.loads(Path(cold['nested_report']).read_bytes())
            compiler = Path(nested['generations'][-1]['produced_image'])
            manifest = build(output / 'qualified', compiler, cold_report)
            report['cold_report_sha256'] = sha256(cold_raw).hexdigest()
            sources = current_sources
        else:
            manifest = Path(development_manifest).resolve(strict=True)
            sources = _development_sources
        before = sources()
        report['source_before'] = before
        bundle_before, manifest_raw = _bundle_observation(manifest)
        report['bundle_before'] = bundle_before
        from hepta import hia_machine_elf as public
        from hepta.hia_machine_elf_native import installed_machine_elf
        native = installed_machine_elf(str(manifest))
        if native.image_sha256 != bundle_before['image']['sha256']:
            raise ValueError('mapped native ELF image differs from observed file')
        calls_before = native.calls.copy()

        def forbidden(*unused, **ignored):
            report['retained_writer_calls'].append('write_elf_object')
            raise AssertionError('retained ELF writer entered the selected caller gate')

        module_sources = {name: _bytes_pin(ROOT / name) for name in MODULE_SOURCE_PINS}
        report['actual_module_sources'] = module_sources
        if module_sources != MODULE_SOURCE_PINS:
            raise ValueError('original 608 retained caller module bytes differ')
        loader = unittest.TestLoader()
        suite = loader.loadTestsFromNames(MODULES)
        report['loader_errors'] = list(loader.errors)
        loaded = [test.id() for test in flatten(suite)]
        report['loaded_test_ids'] = loaded
        report['tests_loaded'] = len(loaded)
        if (len(loaded) != 51 or tuple(loaded) != EXPECTED_IDS
                or len(set(loaded)) != 51 or report['loader_errors']):
            raise ValueError('exact original 51 ordered retained caller discovery required')
        with patch.dict(os.environ, {'HEPTA_HIA_MACHINE_ELF_MANIFEST': str(manifest)}), \
                patch.object(public, '_reference_write_elf_object', forbidden):
            result = unittest.TextTestRunner(verbosity=2, resultclass=ObservedResult).run(suite)
        counts = {
            'errors': len(result.errors), 'failures': len(result.failures),
            'skips': len(result.skipped), 'expected_failures': len(result.expectedFailures),
            'unexpected_successes': len(result.unexpectedSuccesses),
        }
        native_delta = dict(native.calls - calls_before)
        report.update(
            tests_run=result.testsRun, executed_test_ids=result.executed,
            anomaly_counts=counts, native_operation_counts=native_delta,
            failures=[(test.id(), trace) for test, trace in result.failures],
            errors=[(test.id(), trace) for test, trace in result.errors],
            manifest_sha256=sha256(manifest_raw).hexdigest(),
            image_sha256=native.image_sha256,
        )
        if (result.testsRun != 51 or result.executed != loaded
                or any(counts.values()) or report['retained_writer_calls']
                or not native_delta or manifest.read_bytes() != manifest_raw):
            raise ValueError('complete retained ELF caller conjunction failed')
        if cold_report is not None and cold_report.read_bytes() != cold_raw:
            raise ValueError('cold input changed during caller qualification')
        report['status'] = 'SELECTED_NATIVE_ELF_CALLERS_PASS'
    except BaseException as exc:
        failure = exc
        report['failure'] = {
            'type': type(exc).__name__, 'text': str(exc), 'traceback': traceback.format_exc(),
        }
    finally:
        try:
            if bundle_before is not None:
                bundle_after, _ = _bundle_observation(manifest)
                report['bundle_after'] = bundle_after
                if bundle_after != bundle_before:
                    raise ValueError('ELF manifest or actual executable file changed')
                report['bundle_stable'] = True
            if before is not None:
                report['source_after'] = sources()
                if report['source_after'] != before:
                    raise ValueError('retained caller source changed')
                report['source_stable'] = True
        except BaseException as exc:
            report['status'] = 'HOLD'
            report['source_failure'] = {
                'type': type(exc).__name__, 'text': str(exc), 'traceback': traceback.format_exc(),
            }
            if failure is None:
                failure = exc
        report['seconds'] = time.monotonic() - started
        if failure is not None:
            report['status'] = 'HOLD'
        with (output / 'report.json').open('x') as stream:
            json.dump(report, stream, indent=2, sort_keys=True)
            stream.write('\n')
    if failure is not None:
        raise failure
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument('--cold-report', type=Path)
    choice.add_argument('--development-manifest', type=Path)
    args = parser.parse_args()
    value = qualify(args.output, cold_report=args.cold_report,
                    development_manifest=args.development_manifest)
    print(json.dumps({'status': value['status'], 'tests_run': value['tests_run']}))


if __name__ == '__main__':
    main()
