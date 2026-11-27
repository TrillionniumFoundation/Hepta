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


_DIAGNOSTICS_CALLER = 'tests/test_hia_agent_native_tools.py'
_DIAGNOSTICS_HELPER = 'tests/hia_caller_diagnostics_admission.py'
_DIAGNOSTICS_HELPER_PIN = {'bytes': 5185, 'sha256': '9e11b98d395229bcb38f0b36094da8bffb37e694ba1ad4afdfa998a8392dd578'}
_DIAGNOSTICS_AUTHORITY = 'tests/fixtures/caller_deadline_diagnostics_v1.json'
_DIAGNOSTICS_AUTHORITY_PIN = {'bytes': 3545, 'sha256': '53aff1f370ac337d6246a0179f8b6d5c346fcc44ffd7f2187c515c95c663f97c'}


def _source_pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


_INTEGRATED_CURRENT = {
    'tests/test_hia_agent_native_tools.py': {
        'bytes': 47052, 'sha256': '64462e8735d8be3838396808dc05391e4437b2dba093fcc265468df6abb4cb70'},
    'tests/test_hia_agent_native_machine_validation.py': {
        'bytes': 23623, 'sha256': '0c03b958462d2d2b8f7304b52bf419a9832037c3db4e51fa940053176fad0cbb'},
}
_INTEGRATED_REVIEWED = {
    'tests/test_hia_agent_native_tools.py': {
        'bytes': 46518, 'sha256': 'b98c24327639363d266eb5e263c042e0a20d82a8f2e8cc08ffafb8f34f73f355'},
    'tests/test_hia_agent_native_machine_validation.py': {
        'bytes': 22171, 'sha256': 'f8e60f923d5b462c3a98f11cb00b0e5a65fb9bc1db2a17a03d55933eb944aada'},
}
_INTEGRATED_HELPER = 'tools/hia_frozen_component_sources.py'
_INTEGRATED_HELPER_PIN = {
    'bytes': 15561, 'sha256': '60a30ab07d6c58ef0523531636a3250cc9e75402bffe75a07115012efa5d0774'}
_INTEGRATED_AUTHORITY = 'tests/fixtures/hia_frozen_component_source_relations.json'
_INTEGRATED_AUTHORITY_PIN = {
    'bytes': 18122, 'sha256': 'acd25ffa7c6bea270fcb56cde74a60d7993899cb2e77173b97a814a3bcce14b9'}


def _admit_integrated_source(root, capture, name, raw):
    """Restore two exact complete caller successors as data before old admission."""
    def pin(value):
        return {'bytes': len(value), 'sha256': sha256(value).hexdigest()}

    if pin(raw) != _INTEGRATED_CURRENT.get(name):
        return raw, None
    helper, authority = capture(_INTEGRATED_HELPER), capture(_INTEGRATED_AUTHORITY)
    if pin(helper) != _INTEGRATED_HELPER_PIN or pin(authority) != _INTEGRATED_AUTHORITY_PIN:
        raise ValueError('integrated caller source history authority differs')
    from tools import hia_frozen_component_sources as history
    if Path(history.__file__).read_bytes() != helper:
        raise ValueError('integrated caller imported different source history')
    restored = history.reviewed_source(
        root, name, raw,
        take=lambda path: capture(Path(path).relative_to(root).as_posix()))
    if pin(restored) != _INTEGRATED_REVIEWED[name]:
        raise ValueError('integrated caller did not restore its complete reviewed source')
    return restored, {
        'path': name, 'physical': pin(raw), 'reviewed_predecessor': pin(restored),
        'helper': {'path': _INTEGRATED_HELPER, **pin(helper)},
        'authority': {'path': _INTEGRATED_AUTHORITY, **pin(authority)},
        'complete_source_history_only': True, 'whole_native_delivery_qualified': False,
    }


def admit_original_callers(root):
    """Retain all fifty callers and admit only the fixed diagnostic successor."""
    root, captured = Path(root), {}

    def capture(name):
        raw = (root / name).read_bytes()
        if name in captured and captured[name] != raw:
            raise ValueError('context caller source changed between captures: ' + name)
        captured[name] = raw
        return raw

    fixture_bytes = capture(FIXTURE_NAME)
    if sha256(fixture_bytes).hexdigest() != FIXTURE_SHA256:
        raise ValueError('frozen original context caller inventory changed')
    expected = json.loads(fixture_bytes)
    if (expected.get('schema') != 'hepta.hia.service-context-original-callers.v1'
            or len(expected['ordered_ids']) != 50):
        raise ValueError('complete original context caller source or denominator differs')
    diagnostics, integrated = {}, {}
    for name, digest in expected['source_sha256'].items():
        raw = capture(name)
        raw, history = _admit_integrated_source(root, capture, name, raw)
        if history is not None:
            integrated[name] = history
        if sha256(raw).hexdigest() == digest:
            continue
        if name != _DIAGNOSTICS_CALLER:
            raise ValueError('an original complete context caller module changed: ' + name)
        helper, authority = capture(_DIAGNOSTICS_HELPER), capture(_DIAGNOSTICS_AUTHORITY)
        if (_source_pin(helper) != _DIAGNOSTICS_HELPER_PIN
                or _source_pin(authority) != _DIAGNOSTICS_AUTHORITY_PIN):
            raise ValueError('context caller diagnostic authority changed')
        from tests import hia_caller_diagnostics_admission as diagnostic
        if Path(diagnostic.__file__).read_bytes() != helper:
            raise ValueError('context caller imported a different diagnostic admission')
        diagnostics[name] = diagnostic.admit(name, raw, digest, authority)
    for name, raw in captured.items():
        if (root / name).read_bytes() != raw:
            raise ValueError('context caller captured bytes changed: ' + name)
    return expected, {
        'schema': 'hepta.hia.service-context-caller-source-admission.v1',
        'authority': {'path': FIXTURE_NAME, **_source_pin(fixture_bytes)},
        'original_files': dict(expected['source_sha256']),
        'original_modules': list(expected['modules']),
        'original_ordered_ids': list(expected['ordered_ids']),
        'reviewed_diagnostic_source_adjustments': diagnostics,
        **({'reviewed_integrated_source_adjustments': integrated} if integrated else {}),
        'captured_files': {name: _source_pin(raw) for name, raw in captured.items()},
        'terminal_reread_identical': True, 'original_inventory_bytes_unchanged': True,
        'production_source_exceptions': [], 'whole_native': False,
    }


def bind_admission_to_source_capture(proof, source_digests):
    for name, expected in proof['captured_files'].items():
        if source_digests.get(name) != expected['sha256']:
            raise ValueError('context caller admission differs from source capture: ' + name)


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
    expected, source_admission = admit_original_callers(ROOT)
    suite, planned = load_declared_suite(tuple(expected['modules']))
    planned = list(planned)
    if planned != expected['ordered_ids']:
        raise ValueError('ordered original context callers differ')

    def source_pins():
        return {**file_digests(ROOT),
                'tools/qualify_hia_service_context_callers.py': sha256(Path(__file__).read_bytes()).hexdigest(),
                FIXTURE_NAME: sha256((ROOT / FIXTURE_NAME).read_bytes()).hexdigest(),
                **{path: sha256((ROOT / path).read_bytes()).hexdigest() for path in INPUTS},
                **{path: sha256((ROOT / path).read_bytes()).hexdigest() for path in expected['source_sha256']},
                **{path: sha256((ROOT / path).read_bytes()).hexdigest()
                   for path in source_admission['captured_files']}}

    before = source_pins()
    bind_admission_to_source_capture(source_admission, before)
    args.evidence.mkdir(mode=0o700, parents=True, exist_ok=False)
    if args.cold_report is not None:
        from tools.build_hia_service_context import build
        from tools.hia_cold_compiler import compiler_from_cold_report
        manifest = build(args.evidence / 'qualified', compiler_from_cold_report(args.cold_report),
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
    after = source_pins()
    bind_admission_to_source_capture(source_admission, after)
    stable = after == before and all(sha256(Path(path).read_bytes()).hexdigest() == digest
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
        'source_admission': source_admission,
        'foreign_schema_profile_buffer_sqlite_clock_budget_effects_still_hosted': True,
        'whole_native_delivery_qualified': False}
    (args.evidence / 'report.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps({key: report[key] for key in ('status', 'scope', 'actual_tests', 'wall_seconds')}))
    if not passed:
        print((args.evidence / 'tests.log').read_text())
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
