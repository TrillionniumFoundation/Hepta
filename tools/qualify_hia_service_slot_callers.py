"""Run the exact ordinary112 or separate128 complete original caller domain.

Original modules, ordered identities, work and deadlines are preserved. Existing
administrator bundles are not enlarged, and subprocess poison is not inferred
from the parent process. This gate does not replace other owner/provider gates.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from contextlib import ExitStack
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import sys
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ''):
    sys.path.insert(0, str(ROOT))
FIXTURE_NAME = 'tests/fixtures/hia_emission_original_73f1634/original-freeze.json'
FIXTURE_SHA256 = 'dec08c099ea1d262f1a3d32dc34801c816484bda6724fac60f5a8a1d5d8c4048'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument('--cold-report', type=Path)
    choice.add_argument('--development-manifest', type=Path)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--scope', choices=('ordinary112', 'separate128'), required=True)
    parser.add_argument('--companion-environment', type=Path, required=True)
    args = parser.parse_args()
    from tools.run_hia_unittest_gate import load_declared_suite
    from tools.hia_selfhost_contract import file_digests
    from tools.build_hia_service_slot import INPUTS
    from tools.qualify_hia_emission_callers import admit_original_sources
    raw = (ROOT / FIXTURE_NAME).read_bytes()
    if sha256(raw).hexdigest() != FIXTURE_SHA256:
        raise ValueError('original complete caller inventory changed')
    original = json.loads(raw)
    modules = original['ordinary_modules'] if args.scope == 'ordinary112' else original['separate_scope_modules']
    count = 112 if args.scope == 'ordinary112' else 128
    declared = original['ordinary_ordered_ids'] if args.scope == 'ordinary112' else [
        test for module in modules for test in original['callers'][module]['recorded_ids']]
    original_files = {record['path']: record['sha256'] for record in original['callers'].values()}
    count_adjustments = admit_original_sources(ROOT, original)
    if (len(modules) != (9 if args.scope == 'ordinary112' else 8) or original['ordinary_count'] != 112
            or len(original['ordinary_ordered_ids']) != 112
            or len(original['callers']) != 17
            or sum(len(row['recorded_ids']) for row in original['callers'].values()) != 240
            or original['separate_scope_count'] != 128):
        raise ValueError('the complete original caller modules differ')
    suite, planned = load_declared_suite(modules)
    planned = list(planned)
    if planned != declared:
        raise ValueError('original complete 112-method caller inventory differs')

    def source_pins():
        paths = {*INPUTS, *original_files, FIXTURE_NAME,
                 'tools/qualify_hia_service_slot_callers.py',
                 'tools/qualify_hia_emission_callers.py'}
        return {**file_digests(), **{name: sha256((ROOT / name).read_bytes()).hexdigest()
                                    for name in sorted(paths)}}

    before = source_pins()
    args.evidence.mkdir(mode=0o700, parents=True, exist_ok=False)
    if args.cold_report is not None:
        from tools.build_hia_service_slot import build
        outer = json.loads(args.cold_report.read_bytes())
        nested = json.loads(Path(outer['nested_report']).read_bytes())
        manifest = build(args.evidence / 'qualified',
            Path(nested['generations'][-1]['produced_image']), args.cold_report)
        scope = 'MATCHING_SOURCE_COLD_ORIGINAL_SERVICE_SLOT_CALLER_DOMAIN'
    else:
        manifest = args.development_manifest.resolve(strict=True)
        scope = 'EXPLICIT_DEVELOPMENT_ORIGINAL_SERVICE_SLOT_CALLER_DOMAIN'
    from hepta import hia_agent_service as api
    from hepta import hia_service_slot_native as native
    image = native.installed_service_slot(str(manifest))
    bundle = {str(path): sha256(path.read_bytes()).hexdigest()
              for path in sorted(manifest.parent.rglob('*')) if path.is_file()}
    started, stopped, reference_calls = [], [], []
    entries, frame_counts, per_test_entries = Counter(), Counter(), defaultdict(Counter)
    active = ['outside-test']

    class Result(unittest.TextTestResult):
        def startTest(self, test):
            active[0] = test.id()
            started.append(test.id())
            super().startTest(test)

        def stopTest(self, test):
            stopped.append(test.id())
            super().stopTest(test)
            active[0] = 'outside-test'

    initializer, actual_entry = native.ServiceSlotFrame.__init__, image._entry

    def counted_frame(frame, selected, *arguments, **keywords):
        if selected is not image:
            raise AssertionError('ordinary caller selected another service Slot image')
        initializer(frame, selected, *arguments, **keywords)
        frame_counts[active[0] + ':mode:' + str(frame.mode)] += 1

    def counted_entry(source, size, output, capacity, state, extent):
        magic, event = struct.unpack('<2Q', ctypes.string_at(source, 16))
        code = actual_entry(source, size, output, capacity, state, extent)
        if magic != native.REQUEST_MAGIC or code != native.OUTPUT_BYTES:
            raise AssertionError('service Slot machine return differs from declared ABI')
        entries[str(event)] += 1
        per_test_entries[active[0]][str(event)] += 1
        return code

    def forbidden(*arguments, **keywords):
        reference_calls.append(active[0])
        raise AssertionError('ordinary caller entered the retained Python service Slot body')

    begin = time.monotonic()
    with ExitStack() as stack:
        if args.companion_environment is not None:
            mapping = json.loads(args.companion_environment.read_bytes())
            if type(mapping) is not dict or any(type(k) is not str or type(v) is not str
                    or not k.startswith('HEPTA_HIA_') for k, v in mapping.items()):
                raise ValueError('companion environment must be explicit product selectors')
            if args.cold_report is not None:
                for key, value in mapping.items():
                    if 'DEVELOPMENT' in key:
                        raise ValueError('development environment cannot qualify cold callers')
                    if key.endswith('_COLD_REPORT') and Path(value).resolve() != args.cold_report.resolve():
                        raise ValueError('original companion uses a different cold report')
            stack.enter_context(patch.dict(os.environ, mapping))
        if args.scope == 'ordinary112':
            stack.enter_context(patch.dict(os.environ, {native.SELECTOR: str(manifest)}))
            stack.enter_context(patch.object(api, '_NATIVE_SERVICE_SLOT_ROLLBACK_REFERENCE', forbidden))
            stack.enter_context(patch.object(api, '_NATIVE_SERVICE_SLOT_ADOPT_REFERENCE', forbidden))
        else:
            # Keep all eight original closed administrator/absence fixtures.
            selected_environment = dict(os.environ)
            selected_environment.pop(native.SELECTOR, None)
            stack.enter_context(patch.dict(os.environ, selected_environment, clear=True))
        stack.enter_context(patch.object(native.ServiceSlotFrame, '__init__', counted_frame))
        stack.enter_context(patch.object(image, '_entry', counted_entry))
        with (args.evidence / 'tests.log').open('x') as stream:
            result = unittest.TextTestRunner(stream=stream, verbosity=2, resultclass=Result).run(suite)
    stable = source_pins() == before and all(
        sha256(Path(name).read_bytes()).hexdigest() == digest for name, digest in bundle.items())
    anomalies = ('errors', 'failures', 'skipped', 'expectedFailures', 'unexpectedSuccesses')
    clean = result.wasSuccessful() and all(not getattr(result, name) for name in anomalies)
    passed = (clean and stable and started == stopped == planned and result.testsRun == count
              and not reference_calls and (args.scope != 'ordinary112' or (sum(frame_counts.values()) > 0
              and all(entries[str(event)] > 0 for event in (0, 1, 2, 4)))))
    report = {
        'schema': 'hepta.hia.service-slot-nine-ordinary-callers.v1',
        'status': 'PASS' if passed else 'FAIL', 'scope': scope,
        'original_baseline_commit': original['base_commit'],
        'original_modules': modules, 'declared_scope': args.scope, 'declared_count': count, 'planned': planned, 'started': started, 'stopped': stopped,
        'actual_tests': result.testsRun, 'wall_seconds': time.monotonic() - begin,
        'errors': [(test.id(), error) for test, error in result.errors],
        'failures': [(test.id(), error) for test, error in result.failures],
        'skipped': [(test.id(), reason) for test, reason in result.skipped],
        'expected_failures': [(test.id(), error) for test, error in result.expectedFailures],
        'unexpected_successes': [test.id() for test in result.unexpectedSuccesses],
        'actual_service_slot_frames': sum(frame_counts.values()),
        'frames_by_original_test': dict(frame_counts),
        'actual_native_event_counts': dict(entries),
        'native_event_counts_by_original_test': dict(per_test_entries),
        'native_image_sha256': image.image_sha256,
        'reference_calls': reference_calls, 'retained_service_slot_forbidden': args.scope == 'ordinary112',
        'reference_poison_scope': 'test process; subprocesses inherit selector, not Python patches',
        'all_declared_original_modules_unfiltered': True,
        'separate128_preserves_own_selection_fixtures': args.scope == 'separate128',
        'old_fixture_image_cold_custody_not_inferred_from_new_owner_build': True, 'original_test_budgets_changed': False,
        'source_and_bundle_unchanged': stable, 'source_pins': before, 'bundle_pins': bundle,
        'original_registry_count_assertion_adjustments': count_adjustments,
        'separate_original_administrator_scope_gates': original['separate_scope_modules'],
        'other_owner_or_artifact_provider_gates_replaced_by_112': False,
        'slot_SQL_closure_inferred_from_caller_success': False,
        'resource_qualification_inferred_from_caller_success': False,
        'whole_project_dynamic_caller_closure_claimed': False,
        'whole_native_delivery_qualified': False,
    }
    (args.evidence / 'report.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps({key: report[key] for key in (
        'status', 'scope', 'actual_tests', 'wall_seconds', 'actual_service_slot_frames')}))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
