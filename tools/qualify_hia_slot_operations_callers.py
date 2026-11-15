"""Complete original Slot15 gate through the explicitly bound HIA controller.

No original method, fixture, expected value, environment-clearing test, or
deadline is changed. The decision image fixtures still build from their original
matching cold report or the explicitly supplied development compiler. Run this
entry under the existing 1800-second owned gate supervisor.
"""
from __future__ import annotations
import argparse
from collections import Counter, defaultdict
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import sys
import time
import types
import unittest

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ''):
    sys.path.insert(0, str(ROOT))
ORIGINAL_MODULE = 'tests.test_hia_slot_ledger_native'
ORIGINAL_FILE = 'tests/test_hia_slot_ledger_native.py'
ORIGINAL_SHA256 = 'cfd2224fa96ef8c6a08a5aeb44f9d7576bf7fbaa611813ee0233edac7d5dcef8'
ORIGINAL_IDS = ('tests.test_hia_slot_ledger_native.SlotLedgerNativeTests.test_actual_evaluation_policy_matches_independent_value_semantics', 'tests.test_hia_slot_ledger_native.SlotLedgerNativeTests.test_actual_fold_has_no_history_count_limit_and_uses_numeric_u64_order', 'tests.test_hia_slot_ledger_native.SlotLedgerNativeTests.test_actual_image_receipts_bind_frozen_state_and_full_descriptors', 'tests.test_hia_slot_ledger_native.SlotLedgerNativeTests.test_actual_machine_matches_every_independent_vm_result_and_state_byte', 'tests.test_hia_slot_ledger_native.SlotLedgerNativeTests.test_actual_machine_refuses_wrapped_lengths_without_partial_output', 'tests.test_hia_slot_ledger_native.SlotLedgerSourceTests.test_actual_sqlite_blob_and_short_circuit_via_independent_hia_vm', 'tests.test_hia_slot_ledger_native.SlotLedgerSourceTests.test_bad_cold_builder_refuses_before_output_or_compilation', 'tests.test_hia_slot_ledger_native.SlotLedgerSourceTests.test_evaluation_adapter_preserves_reference_errors_and_short_circuit', 'tests.test_hia_slot_ledger_native.SlotLedgerSourceTests.test_exact_generated_source_and_independent_vm_decisions', 'tests.test_hia_slot_ledger_native.SlotLedgerSourceTests.test_fixture_requires_explicit_cold_or_development_and_admits_before_output', 'tests.test_hia_slot_ledger_native.SlotLedgerSourceTests.test_independent_vm_admits_evaluation_values_and_outcomes', 'tests.test_hia_slot_ledger_native.SlotLedgerSourceTests.test_independent_vm_refuses_wrapped_lengths_and_partial_publication', 'tests.test_hia_slot_ledger_native.SlotLedgerSourceTests.test_outcome_diagnostic_cannot_override_native_decisions', 'tests.test_hia_slot_ledger_native.SlotLedgerSourceTests.test_selected_empty_or_missing_image_refuses_before_state_effect', 'tests.test_hia_slot_ledger_native.SlotLedgerSourceTests.test_unhashable_outcome_uses_interpreter_error_after_native_refusal')
OWNER_MODES = (
    '__init__', '_execute', '_call', 'snapshot', 'validate_u64', 'conditional',
    '_begin', 'admit_evaluation', 'admit_net_benefit', 'adopt', 'rollback',
    '_lease_value', 'acquire', 'lease', 'release',
)


def _json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2,
                               allow_nan=False) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument('--cold-report', type=Path)
    choice.add_argument('--development-manifest', type=Path)
    parser.add_argument('--development-compiler', type=Path)
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()
    if (args.cold_report is not None and args.development_compiler is not None
            or args.development_manifest is not None and args.development_compiler is None):
        raise ValueError('choose matching cold or both explicit development controller and compiler')
    if sha256((ROOT / ORIGINAL_FILE).read_bytes()).hexdigest() != ORIGINAL_SHA256:
        raise ValueError('complete original Slot15 test file changed')
    from tools.run_hia_unittest_gate import load_declared_suite
    from tools.hia_selfhost_contract import file_digests
    from tools.build_hia_slot_operations import INPUTS, build
    from tools.build_hia_json_preflight import admit_cold_build
    suite, planned = load_declared_suite((ORIGINAL_MODULE,))
    planned = list(planned)
    if planned != list(ORIGINAL_IDS):
        raise ValueError('complete original Slot15 ordered method identities changed')

    def pins():
        specific = (*INPUTS, ORIGINAL_FILE, 'tools/qualify_hia_slot_operations_callers.py')
        return {**file_digests(), **{name: sha256((ROOT / name).read_bytes()).hexdigest()
                                   for name in specific}}
    before = pins()
    args.evidence.mkdir(mode=0o700, parents=True, exist_ok=False)
    cold_bytes = nested_bytes = nested_path = None
    if args.cold_report is not None:
        cold_bytes = args.cold_report.read_bytes()
        outer = json.loads(cold_bytes)
        nested_path = Path(outer['nested_report']).resolve(strict=True)
        nested_bytes = nested_path.read_bytes()
        nested = json.loads(nested_bytes)
        compiler = Path(nested['generations'][-1]['produced_image']).resolve(strict=True)
        compiler_bytes = compiler.read_bytes()
        admitted = admit_cold_build(compiler_bytes, cold_bytes)
        manifest = build(args.evidence / 'controller', compiler, args.cold_report)
        scope = 'MATCHING_SOURCE_COLD_COMPLETE_ORIGINAL_SLOT15'
    else:
        compiler = args.development_compiler.resolve(strict=True)
        compiler_bytes = compiler.read_bytes()
        manifest = args.development_manifest.resolve(strict=True)
        admitted = None
        scope = 'EXPLICIT_DEVELOPMENT_COMPLETE_ORIGINAL_SLOT15_NOT_COLD'
    manifest_bytes = manifest.read_bytes()
    value = json.loads(manifest_bytes)
    image_path = manifest.parent / value['image_path']
    image_bytes = image_path.read_bytes()
    if (value['compiler_sha256'] != sha256(compiler_bytes).hexdigest()
            or value['image_sha256'] != sha256(image_bytes).hexdigest()):
        raise ValueError('controller and original decision fixture do not share the declared compiler')
    from hepta import hia_slot_operations_native as native
    from hepta.hia_slot_operations_selection import slot_operations_owner
    from hepta.hia_slot_ledger_native import NativeSlotLedgerStore
    image = native.installed_slot_operations(str(manifest))
    references = NativeSlotLedgerStore._hia_slot_reference_methods
    if tuple(references) != OWNER_MODES:
        raise ValueError('actual public Slot descriptor/reference binding differs')
    original_references = dict(references)
    saved_entry = image._entry
    original_env = dict(os.environ)
    active = ['outside-test']
    started, stopped, retained_calls = [], [], []
    entries, modes, per_test = Counter(), Counter(), defaultdict(Counter)

    class Result(unittest.TextTestResult):
        def startTest(self, test):
            active[0] = test.id()
            started.append(test.id())
            super().startTest(test)
        def stopTest(self, test):
            stopped.append(test.id())
            super().stopTest(test)
            active[0] = 'outside-test'

    def counted_entry(source, size, output, capacity, state, extent):
        code = saved_entry(source, size, output, capacity, state, extent)
        raw = ctypes.string_at(source, size)
        if len(raw) != native.REQUEST_BYTES or code != native.OUTPUT_BYTES:
            raise AssertionError('actual Slot controller ABI return changed')
        words = struct.unpack('<16Q', raw)
        if words[0] != native.REQUEST_MAGIC or not 1 <= words[5] <= 15:
            raise AssertionError('actual Slot controller request identity changed')
        entries[str(words[1])] += 1
        modes[str(words[5])] += 1
        per_test[active[0]][str(words[1])] += 1
        return code

    def forbidden(*arguments, **keywords):
        retained_calls.append(active[0])
        raise AssertionError('selected Slot controller executed a retained Python method')

    for name, method in original_references.items():
        references[name] = staticmethod(forbidden) if type(method) is staticmethod else forbidden
    image._entry = counted_entry
    started_at = time.monotonic()
    try:
        for key in ('HEPTA_HIA_SLOT_LEDGER_COLD_REPORT',
                    'HEPTA_HIA_SLOT_LEDGER_DEVELOPMENT_COMPILER',
                    'HEPTA_HIA_SLOT_OPERATIONS_MANIFEST'):
            os.environ.pop(key, None)
        if args.cold_report is not None:
            os.environ['HEPTA_HIA_SLOT_LEDGER_COLD_REPORT'] = str(args.cold_report.resolve(strict=True))
        else:
            os.environ['HEPTA_HIA_SLOT_LEDGER_DEVELOPMENT_COMPILER'] = str(compiler)
        os.environ['HEPTA_HIA_SLOT_LEDGER_EVIDENCE'] = str(args.evidence / 'original-component')
        # Explicit actual image authority survives original clear=True scopes.
        # It does not add any image/selector to an administrator bundle.
        with slot_operations_owner(str(manifest), image=image):
            with (args.evidence / 'tests.log').open('x') as stream:
                result = unittest.TextTestRunner(stream=stream, verbosity=2,
                                                resultclass=Result).run(suite)
    finally:
        image._entry = saved_entry
        references.clear()
        references.update(original_references)
        os.environ.clear()
        os.environ.update(original_env)
    elapsed = time.monotonic() - started_at
    after = pins()
    stable = (before == after and compiler.read_bytes() == compiler_bytes
              and manifest.read_bytes() == manifest_bytes and image_path.read_bytes() == image_bytes)
    if args.cold_report is not None:
        from tools.build_hia_json_preflight import current_sources
        stable = (stable and args.cold_report.read_bytes() == cold_bytes
                  and nested_path.read_bytes() == nested_bytes
                  and admit_cold_build(compiler_bytes, cold_bytes) == admitted
                  and current_sources() == admitted)
    anomalies = {name: getattr(result, name)
                 for name in ('errors', 'failures', 'skipped', 'expectedFailures', 'unexpectedSuccesses')}
    clean = result.wasSuccessful() and not any(anomalies.values())
    passed = (clean and stable and planned == started == stopped and result.testsRun == 15
              and not retained_calls and entries['0'] > 0 and entries['4'] > 0
              and sum(entries.values()) > 0 and elapsed < 1800)
    report = {
        'schema': 'hepta.hia.slot-operations-original-slot15.v1',
        'status': 'PASS' if passed else 'HOLD', 'scope': scope,
        'original_test_file_sha256': ORIGINAL_SHA256, 'planned': planned,
        'started': started, 'stopped': stopped, 'actual_tests': result.testsRun,
        'errors': [(test.id(), error) for test, error in result.errors],
        'failures': [(test.id(), error) for test, error in result.failures],
        'skipped': [(test.id(), reason) for test, reason in result.skipped],
        'expected_failures': [(test.id(), error) for test, error in result.expectedFailures],
        'unexpected_successes': [test.id() for test in result.unexpectedSuccesses],
        'wall_seconds': elapsed, 'required_outer_supervisor_seconds': 1800,
        'controller_image_sha256': image.image_sha256,
        'actual_entry_counts': dict(entries), 'actual_mode_entry_counts': dict(modes),
        'actual_entry_counts_by_test': {name: dict(counts) for name, counts in per_test.items()},
        'actual_started_frames': entries['0'], 'retained_calls': retained_calls,
        'all_original_tests_and_budgets_unmodified': True,
        'original_environment_clear_true_preserved': True,
        'old_administrator_bundles_expanded': False,
        'poison_scope': 'all fifteen retained bodies in this test process; no unobserved subprocess claim',
        'explicit_scope_uses_actual_declared_image': True,
        'source_pins_before': before, 'source_pins_after': after, 'source_and_inputs_stable': stable,
        'compiler': {'path': str(compiler), 'sha256': sha256(compiler_bytes).hexdigest()},
        'manifest': {'path': str(manifest), 'sha256': sha256(manifest_bytes).hexdigest()},
        'separate_61_112_128_130_152_gates_replaced': False,
        'whole_project_dynamic_closure_claimed': False,
    }
    _json(args.evidence / 'report.json', report)
    print(json.dumps({key: report[key] for key in ('status','scope','actual_tests','wall_seconds','actual_started_frames')}))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
