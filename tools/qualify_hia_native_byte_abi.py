"""Qualify all retained byte ABI callers with the explicit native borrowed-byte ABI owner.

This is one component gate. It preserves the exact original 16 Byte ABI,
12 Agent buffer and one lease-snapshot methods. It does not certify installed
execution or the complete native project.
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

from tools.build_hia_native_byte_abi import build, current_sources, DEVELOPMENT_INPUT_NAMES

MODULES = ('tests.test_hia_native_byte_abi', 'tests.test_hia_agent_buffer_lifecycle', 'tests.test_hia_agent_native_lease_snapshot')
MODULE_SOURCE_PINS = {'tests/test_hia_native_byte_abi.py': 'eb9782f07e3735cb51142883b1bce2f5fb84c6ef1a7ed6c401f8d1a7b3ab0bda', 'tests/test_hia_agent_buffer_lifecycle.py': 'b3f23d740436ae90c909b65a2fbca150459fe16807cf788f17825832964302bf', 'tests/test_hia_agent_native_lease_snapshot.py': '476e49225ad1b2215f08323079f3521b5b9dbcdb33edc8b619013f426643e823'}
EXPECTED_IDS = ('tests.test_hia_native_byte_abi.ByteABIAdmissionTests.test_direct_byte_object_emission_needs_no_llvm_or_subprocess', 'tests.test_hia_native_byte_abi.ByteABIAdmissionTests.test_explicit_scalar_contract_and_public_resource_results_stay_closed', 'tests.test_hia_native_byte_abi.ByteABIAdmissionTests.test_invalid_bounds_types_unknown_and_duplicate_names_fail_closed', 'tests.test_hia_native_byte_abi.ByteABIAdmissionTests.test_manifest_and_instruction_mutations_cannot_reuse_origin', 'tests.test_hia_native_byte_abi.ByteABIAdmissionTests.test_manifest_is_explicit_and_never_broadens_default_scalar_abi', 'tests.test_hia_native_byte_abi.ByteABIAdmissionTests.test_public_loader_hook_name_is_rejected', 'tests.test_hia_native_byte_abi.ByteABINativeTests.test_disposable_invocation_owns_copies_and_preserves_costs', 'tests.test_hia_native_byte_abi.ByteABINativeTests.test_disposable_runner_contains_real_core_traps_and_infinite_loops', 'tests.test_hia_native_byte_abi.ByteABINativeTests.test_explicit_v2_machine_plan_preserves_byte_admission_and_native_output', 'tests.test_hia_native_byte_abi.ByteABINativeTests.test_extent_null_and_unsigned_address_wrap_reject_before_access', 'tests.test_hia_native_byte_abi.ByteABINativeTests.test_missing_launch_or_cleanup_evidence_never_claims_confirmed_termination', 'tests.test_hia_native_byte_abi.ByteABINativeTests.test_mixed_register_stack_argument_expansion_preserves_narrow_types', 'tests.test_hia_native_byte_abi.ByteABINativeTests.test_mutable_overlap_is_rejected_and_adjacent_ranges_are_allowed', 'tests.test_hia_native_byte_abi.ByteABINativeTests.test_ordinary_core_error_and_all_u32_status_values_remain_distinct', 'tests.test_hia_native_byte_abi.ByteABINativeTests.test_readonly_overlap_and_empty_mutable_ranges_are_allowed', 'tests.test_hia_native_byte_abi.ByteABINativeTests.test_real_source_output_buffers_and_surrounding_canaries', 'tests.test_hia_agent_buffer_lifecycle.BufferLifecycleTests.test_abort_snapshot_preserves_writes_and_detects_a_changed_prefix', 'tests.test_hia_agent_buffer_lifecycle.BufferLifecycleTests.test_adoption_consumer_bytes_survive_rollback_and_release_fences', 'tests.test_hia_agent_buffer_lifecycle.BufferLifecycleTests.test_cold_consumer_processes_preserve_lease_and_release_across_rollback', 'tests.test_hia_agent_buffer_lifecycle.BufferLifecycleTests.test_every_warmup_and_repetition_starts_with_fresh_owned_bytes', 'tests.test_hia_agent_buffer_lifecycle.BufferLifecycleTests.test_explicit_profile_exports_real_bytes_and_retains_abi_in_build', 'tests.test_hia_agent_buffer_lifecycle.BufferLifecycleTests.test_invalid_byte_shapes_and_extent_never_enter_native_execution', 'tests.test_hia_agent_buffer_lifecycle.BufferLifecycleTests.test_mixed_register_stack_scalars_and_empty_buffers_are_exact', 'tests.test_hia_agent_buffer_lifecycle.BufferLifecycleTests.test_normal_scalar_workload_does_not_opt_into_buffer_exports', 'tests.test_hia_agent_buffer_lifecycle.BufferLifecycleTests.test_refinement_stays_unsupported_and_required_proof_blocks_adoption', 'tests.test_hia_agent_buffer_lifecycle.BufferLifecycleTests.test_same_output_status_cannot_hide_changed_buffer_bytes', 'tests.test_hia_agent_buffer_lifecycle.BufferLifecycleTests.test_timeout_retains_partial_external_write_but_never_success', 'tests.test_hia_agent_buffer_lifecycle.BufferLifecycleTests.test_workload_byte_budget_and_duplicate_exports_are_rejected_at_context', 'tests.test_hia_agent_native_lease_snapshot.LeaseSnapshotTests.test_caller_mutation_during_native_call_cannot_relabel_result_or_buffers')

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
            raise ValueError('bounded ordinary byte ABI build file required')
        raw = stream.read(maximum + 1)
        if (len(raw) != opened.st_size or identity(os.fstat(stream.fileno())) != identity(opened)):
            raise ValueError('byte ABI build file changed during read')
    if identity(requested.stat()) != identity(before):
        raise ValueError('byte ABI build file changed after read')
    return {'path': str(requested), 'bytes': len(raw),
            'sha256': sha256(raw).hexdigest(), 'identity': list(identity(before))}, raw


def _bundle_observation(manifest):
    manifest_pin, raw = _file_observation(manifest, 16384)
    value = json.loads(raw)
    name = value['image_path']
    if type(name) is not str or not name or Path(name).name != name:
        raise ValueError('one-component byte ABI image filename required')
    image_pin, _ = _file_observation(Path(manifest_pin['path']).parent / name, 1 << 20)
    if image_pin['sha256'] != value['image_sha256']:
        raise ValueError('byte ABI image file differs from selected manifest')
    return {'manifest': manifest_pin, 'image': image_pin}, raw


def _development_sources():
    # Development scope is explicit; this map is not a cold source closure.
    from tools.hia_selfhost_contract import SOURCE_FILES
    return {name: _bytes_pin(ROOT / name)
            for name in sorted(set(SOURCE_FILES) | set(DEVELOPMENT_INPUT_NAMES) | set(MODULE_SOURCE_PINS))}


def qualify(output, *, cold_report=None, development_manifest=None):
    output = Path(output)
    if (cold_report is None) == (development_manifest is None):
        raise ValueError('choose exactly one current cold report or development manifest')
    output.mkdir(mode=0o700)
    report = {
        'schema': 'hepta.hia.native-byte-abi-callers.v1', 'status': 'HOLD',
        'scope': ('MATCHING_SOURCE_COLD_BUILD' if cold_report is not None
                  else 'EXPLICIT_DEVELOPMENT_ONLY_NOT_COLD'),
        'modules': list(MODULES),
        'whole_byte_abi_qualified': False, 'whole_native_delivery_qualified': False,
        'CPython_all_foreign_domains_proved': False,
        'retained_writer_calls': [], 'loader_errors': [],
        'expected_test_ids': list(EXPECTED_IDS), 'expected_count': 29,
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
        from hepta import hia_native_byte_abi as public
        from hepta.hia_native_byte_abi_selection import installed_native_byte_abi
        native = installed_native_byte_abi(str(manifest))
        if native.image_sha256 != bundle_before['image']['sha256']:
            raise ValueError('mapped native byte ABI image differs from observed file')
        from collections import Counter
        calls = Counter()
        actual_prepare = native.prepare
        def observed_prepare(name, arguments, captures=(), *, witness=None):
            calls[str(name)] += 1
            return actual_prepare(name, arguments, captures, witness=witness)

        def forbidden(*unused, **ignored):
            report['retained_writer_calls'].append('byte_abi_policy')
            raise AssertionError('retained byte ABI writer entered the selected caller gate')

        module_sources = {name: _bytes_pin(ROOT / name) for name in MODULE_SOURCE_PINS}
        report['actual_module_sources'] = module_sources
        if module_sources != MODULE_SOURCE_PINS:
            raise ValueError('original 4b retained caller module bytes differ')
        loader = unittest.TestLoader()
        suite = loader.loadTestsFromNames(MODULES)
        report['loader_errors'] = list(loader.errors)
        loaded = [test.id() for test in flatten(suite)]
        report['loaded_test_ids'] = loaded
        report['tests_loaded'] = len(loaded)
        if (len(loaded) != 29 or tuple(loaded) != EXPECTED_IDS
                or len(set(loaded)) != 29 or report['loader_errors']):
            raise ValueError('exact original 29 ordered retained caller discovery required')
        with patch.dict(os.environ, {'HEPTA_HIA_NATIVE_BYTE_ABI_MANIFEST': str(manifest)}), \
                patch.object(public, '_reference_normalize_exports', forbidden), \
                patch.object(public, '_reference_emit_wrapper', forbidden), \
                patch.object(native, 'prepare', observed_prepare):
            result = unittest.TextTestRunner(verbosity=2, resultclass=ObservedResult).run(suite)
        counts = {
            'errors': len(result.errors), 'failures': len(result.failures),
            'skips': len(result.skipped), 'expected_failures': len(result.expectedFailures),
            'unexpected_successes': len(result.unexpectedSuccesses),
        }
        native_delta = dict(calls)
        report.update(
            tests_run=result.testsRun, executed_test_ids=result.executed,
            anomaly_counts=counts, native_operation_counts=native_delta,
            failures=[(test.id(), trace) for test, trace in result.failures],
            errors=[(test.id(), trace) for test, trace in result.errors],
            manifest_sha256=sha256(manifest_raw).hexdigest(),
            image_sha256=native.image_sha256,
        )
        if (result.testsRun != 29 or result.executed != loaded
                or any(counts.values()) or report['retained_writer_calls']
                or any(native_delta.get(name, 0) <= 0 for name in ('normalize_exports', 'emit_wrapper', '_normalize', '_prologue', '_reject'))
                or manifest.read_bytes() != manifest_raw):
            raise ValueError('complete retained byte ABI caller conjunction failed')
        if cold_report is not None and cold_report.read_bytes() != cold_raw:
            raise ValueError('cold input changed during caller qualification')
        report['status'] = 'SELECTED_NATIVE_BYTE_ABI_CALLERS_PASS'
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
                    raise ValueError('byte ABI manifest or actual executable file changed')
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
