"""Run all current original service-context callers with four retained bodies poisoned.

The four complete modules include actual 3,000 ms contexts, native timeouts,
process interruptions, rollback/lease lifetimes, and malformed SQLite cleanup.
Their exact source and ordered test inventory are frozen; no skips qualify.
"""
from __future__ import annotations

import argparse
from collections import Counter
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

FIXTURE_NAME = 'tests/fixtures/service_context_callers_b569c21.json'
FIXTURE_SHA256 = '6d06a3319b6d15a64ff46f2b1991d023c0e7ecedec85d36bd9080b964a31d4bf'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument('--cold-report', type=Path)
    selection.add_argument('--development-manifest', type=Path)
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()
    from tools.run_hia_unittest_gate import load_declared_suite
    from tools.hia_selfhost_contract import file_digests
    from tools.build_hia_service_context import INPUTS
    fixture_bytes = (ROOT / FIXTURE_NAME).read_bytes()
    if sha256(fixture_bytes).hexdigest() != FIXTURE_SHA256:
        raise ValueError('frozen original context caller inventory changed')
    expected = json.loads(fixture_bytes)
    if (expected.get('schema') != 'hepta.hia.service-context-original-callers.v1'
            or len(expected['ordered_ids']) != 50
            or any(sha256((ROOT / path).read_bytes()).hexdigest() != digest
                   for path, digest in expected['source_sha256'].items())):
        raise ValueError('complete original context caller source or denominator differs')
    suite, planned = load_declared_suite(tuple(expected['modules']))
    planned = list(planned)
    if planned != expected['ordered_ids']:
        raise ValueError('ordered original context callers differ')

    def source_pins():
        return {**file_digests(ROOT),
                'tools/qualify_hia_service_context_callers.py': sha256(Path(__file__).read_bytes()).hexdigest(),
                FIXTURE_NAME: sha256((ROOT / FIXTURE_NAME).read_bytes()).hexdigest(),
                **{path: sha256((ROOT / path).read_bytes()).hexdigest() for path in INPUTS},
                **{path: sha256((ROOT / path).read_bytes()).hexdigest() for path in expected['source_sha256']}}

    before = source_pins()
    args.evidence.mkdir(mode=0o700, parents=True, exist_ok=False)
    if args.cold_report is not None:
        from tools.build_hia_service_context import build
        cold = json.loads(args.cold_report.read_bytes())
        nested = json.loads(Path(cold['nested_report']).read_bytes())
        manifest = build(args.evidence / 'qualified', Path(nested['generations'][-1]['produced_image']),
                         args.cold_report)
        scope = 'MATCHING_SOURCE_COLD_ORIGINAL_SERVICE_CONTEXT_CALLERS'
    else:
        manifest = args.development_manifest.resolve(strict=True)
        scope = 'EXPLICIT_DEVELOPMENT_COMPONENT_NOT_CURRENT_COLD'
    from hepta import hia_agent_service as owner
    from hepta.hia_service_context_native import ContextFrame, SELECTOR, installed_service_context, MATH_MAGIC
    image = installed_service_context(str(manifest))
    bundle = {str(path): sha256(path.read_bytes()).hexdigest()
              for path in sorted(manifest.parent.rglob('*')) if path.is_file()}
    started, stopped, references = [], [], []
    modes, entries, arithmetic = Counter(), Counter(), Counter()

    class Result(unittest.TextTestResult):
        def startTest(self, test):
            started.append(test.id())
            super().startTest(test)

        def stopTest(self, test):
            stopped.append(test.id())
            super().stopTest(test)

    original_frame, actual_entry = ContextFrame.__init__, image._entry

    def counted_frame(frame, selected, mode, *arguments, **keywords):
        if selected is not image:
            raise AssertionError('context caller selected another image')
        original_frame(frame, selected, mode, *arguments, **keywords)
        modes[mode] += 1

    def counted_entry(source, size, output, capacity, state, extent):
        returned = actual_entry(source, size, output, capacity, state, extent)
        magic = struct.unpack('<Q', ctypes.string_at(source, 8))[0]
        if magic == MATH_MAGIC:
            if returned != 32:
                raise AssertionError('context caller integer ABI return differs')
            operation = struct.unpack('<2Q', ctypes.string_at(source, 16))[1]
            arithmetic[str(operation)] += 1
        else:
            if returned != 80 or capacity != 80 or extent != 128 or size != 80:
                raise AssertionError('context caller native control ABI return differs')
            request = struct.unpack('<10Q', ctypes.string_at(source, size))
            entries[str(request[5]) + ':' + str(request[1])] += 1
        return returned

    def forbidden(*unused, **ignored):
        references.append(started[-1] if started else 'outside-test')
        raise AssertionError('selected service entered retained context policy')

    start = time.monotonic()
    with ExitStack() as stack:
        stack.enter_context(patch.dict(os.environ, {SELECTOR: str(manifest)}))
        for name in ('_NATIVE_SERVICE_CONTEXT_FREEZE_REFERENCE', '_NATIVE_SERVICE_CONTEXT_LOOKUP_REFERENCE',
                     '_NATIVE_SERVICE_CONTEXT_BUDGET_REFERENCE', '_NATIVE_SERVICE_CONTEXT_REMAINING_REFERENCE'):
            stack.enter_context(patch.object(owner, name, forbidden))
        for name in ('_hia_context_reference', '_context_reference', '_budget_reference', '_remaining_ms_reference'):
            stack.enter_context(patch.object(owner.HIAAgentService, name, forbidden))
        stack.enter_context(patch.object(ContextFrame, '__init__', counted_frame))
        stack.enter_context(patch.object(image, '_entry', counted_entry))
        with (args.evidence / 'tests.log').open('x') as stream:
            result = unittest.TextTestRunner(stream=stream, verbosity=2, resultclass=Result).run(suite)
    stable = source_pins() == before and all(sha256(Path(path).read_bytes()).hexdigest() == digest
                                           for path, digest in bundle.items())
    clean = result.wasSuccessful() and all(not getattr(result, name) for name in
        ('errors', 'failures', 'skipped', 'expectedFailures', 'unexpectedSuccesses'))
    passed = (started == stopped == planned and result.testsRun == len(planned) and clean and stable
              and not references and set(modes) == {1, 2, 3, 4}
              and all(entries[str(mode) + ':1'] for mode in (1, 2, 3, 4))
              and set(arithmetic) >= {'1', '2', '3', '4', '5', '6', '8'})
    report = {'status': 'PASS' if passed else 'FAIL', 'scope': scope,
        'original_modules': expected['modules'], 'planned': planned, 'started': started, 'stopped': stopped,
        'actual_tests': result.testsRun, 'wall_seconds': time.monotonic() - start,
        'errors': [(test.id(), error) for test, error in result.errors],
        'failures': [(test.id(), error) for test, error in result.failures],
        'skipped': [(test.id(), error) for test, error in result.skipped],
        'expected_failures': [(test.id(), error) for test, error in result.expectedFailures],
        'unexpected_successes': [test.id() for test in result.unexpectedSuccesses],
        'native_mode_frames': dict(modes), 'actual_machine_mode_events': dict(entries),
        'actual_integer_operations': dict(arithmetic),
        'native_image_sha256': image.image_sha256, 'reference_calls': references,
        'reference_poison_scope': 'test process; subprocesses inherit selector, not Python patches',
        'all_original_modules_unfiltered': True, 'original_test_budgets_changed': False,
        'source_and_bundle_unchanged': stable, 'source_pins': before, 'bundle_pins': bundle,
        'foreign_schema_profile_buffer_sqlite_clock_budget_effects_still_hosted': True,
        'whole_native_delivery_qualified': False}
    (args.evidence / 'report.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps({key: report[key] for key in ('status', 'scope', 'actual_tests', 'wall_seconds')}))
    if not passed:
        print((args.evidence / 'tests.log').read_text())
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
