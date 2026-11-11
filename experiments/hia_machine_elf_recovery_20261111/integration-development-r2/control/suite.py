"""Run one complete frozen ELF method group with exact loaded/executed IDs."""
from pathlib import Path
import argparse
from collections import Counter
import json
import os
import sys
import time
import traceback
import unittest
from common import ROOT, SOURCE, checked_config, create, wire, require
config = checked_config(ROOT / 'control/config.json')
sys.path.insert(0, str(SOURCE))
GROUPS = {"source":["tests.test_hia_machine_elf_native.MachineElfSourceTests.test_complete_original_writer_prefix_and_reconstructed_inputs","tests.test_hia_machine_elf_native.MachineElfSourceTests.test_declared_installed_source_resource","tests.test_hia_machine_elf_native.MachineElfSourceTests.test_generated_hia_roundtrips_with_original_limits","tests.test_hia_machine_elf_native.MachineElfSourceTests.test_incomplete_cold_report_refuses_before_creating_output","tests.test_hia_machine_elf_native.MachineElfSourceTests.test_original_api_unselected_and_explicit_missing_refuses"],"native":["tests.test_hia_machine_elf_native.MachineElfNativeTests.test_backend_full_return_identity_and_mid_emit_selection","tests.test_hia_machine_elf_native.MachineElfNativeTests.test_cached_image_rebinds_installed_source_and_forged_manifest","tests.test_hia_machine_elf_native.MachineElfNativeTests.test_complete_reconstructed_55_input_denominator","tests.test_hia_machine_elf_native.MachineElfNativeTests.test_foreign_baseexception_retains_object_traceback_and_context","tests.test_hia_machine_elf_native.MachineElfNativeTests.test_malformed_ack_reaches_real_native_refusal_then_closes","tests.test_hia_machine_elf_native.MachineElfNativeTests.test_pending_step_refusal_permanently_revokes_real_effect","tests.test_hia_machine_elf_native.MachineElfNativeTests.test_pinned_owner_refuses_source_drift_before_first_identity","tests.test_hia_machine_elf_native.MachineElfNativeTests.test_post_native_entry_and_counter_baseexceptions_are_terminal","tests.test_hia_machine_elf_native.MachineElfNativeTests.test_real_installed_wheel_isolated_empty_path_without_old_writer","tests.test_hia_machine_elf_native.MachineElfNativeTests.test_repeated_observe_and_unissued_observe_are_terminal","tests.test_hia_machine_elf_native.MachineElfNativeTests.test_success_and_explicit_close_cannot_replay_effects"],"boundary":["tests.test_hia_machine_elf_native.MachineElfBoundaryTests.test_actual_64mib_code_and_final_object_boundary","tests.test_hia_machine_elf_native.MachineElfBoundaryTests.test_actual_65536_symbol_inventory_boundary","tests.test_hia_machine_elf_native.MachineElfBoundaryTests.test_actual_imported_symbol_inventory_boundary","tests.test_hia_machine_elf_native.MachineElfBoundaryTests.test_full_name_and_alignment_with_adjacent_calls"]}
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

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--group', choices=tuple(GROUPS), required=True)
    parser.add_argument('--manifest', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(mode=0o700)
    report = {'schema': 'hepta.hia.machine-elf.integration-methods.v1',
        'status': 'HOLD', 'group': args.group, 'expected_test_ids': GROUPS[args.group],
        'expected_count': len(GROUPS[args.group]), 'loaded_test_ids': [],
        'executed_test_ids': [], 'loader_errors': [], 'scope': 'DEVELOPMENT_ONLY'}
    for key in ('HEPTA_HIA_MACHINE_ELF_MANIFEST', 'HEPTA_HIA_MACHINE_ELF_COLD_REPORT',
                'HEPTA_HIA_MACHINE_ELF_DEVELOPMENT_MANIFEST'):
        os.environ.pop(key, None)
    os.environ['HEPTA_HIA_MACHINE_ELF_FIXTURE_EVIDENCE'] = str(args.output / 'fixtures')
    native = None
    calls_before = Counter()
    started = time.monotonic()
    try:
        if args.manifest is not None:
            require(args.group != 'source', 'source group does not select a development image')
            os.environ['HEPTA_HIA_MACHINE_ELF_DEVELOPMENT_MANIFEST'] = str(args.manifest)
            from hepta.hia_machine_elf_native import installed_machine_elf
            native = installed_machine_elf(str(args.manifest))
            calls_before = native.calls.copy()
        else:
            require(args.group == 'source', 'native groups require an explicit manifest')
        loader = unittest.TestLoader()
        name = 'tests.test_hia_machine_elf_native.' + {
            'source': 'MachineElfSourceTests', 'native': 'MachineElfNativeTests',
            'boundary': 'MachineElfBoundaryTests'}[args.group]
        suite = loader.loadTestsFromName(name)
        loaded = [item.id() for item in flatten(suite)]
        report.update(loaded_test_ids=loaded, loader_errors=list(loader.errors),
                      tests_loaded=len(loaded))
        require(loaded == GROUPS[args.group] and not loader.errors
                and len(set(loaded)) == len(loaded), 'exact group discovery differs')
        result = unittest.TextTestRunner(verbosity=2, resultclass=ObservedResult).run(suite)
        anomalies = {'errors': len(result.errors), 'failures': len(result.failures),
            'skips': len(result.skipped), 'expected_failures': len(result.expectedFailures),
            'unexpected_successes': len(result.unexpectedSuccesses)}
        report.update(executed_test_ids=result.executed, tests_run=result.testsRun,
            anomaly_counts=anomalies,
            errors=[(test.id(), trace) for test, trace in result.errors],
            failures=[(test.id(), trace) for test, trace in result.failures])
        require(result.executed == loaded and result.testsRun == len(GROUPS[args.group])
                and not any(anomalies.values()), 'complete method group did not pass')
        if native is not None:
            report['native_operation_counts'] = dict(native.calls - calls_before)
            require(bool(report['native_operation_counts']), 'no actual native operation observed')
            report['image_sha256'] = native.image_sha256
            report['admitted_source_sha256'] = native.admitted_source_sha256
        report['status'] = 'PASS'
    except BaseException as exc:
        report['failure'] = {'type': type(exc).__name__, 'text': str(exc),
                             'traceback': traceback.format_exc()}
    finally:
        report['seconds'] = time.monotonic() - started
        create(args.output / 'report.json', wire(report))
        print(json.dumps({'group': args.group, 'status': report['status'],
                          'tests_run': report.get('tests_run')}), flush=True)
    return 0 if report['status'] == 'PASS' else 1
if __name__ == '__main__':
    raise SystemExit(main())
