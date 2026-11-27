"""Run all current original Store callers with retained lifecycle bodies poisoned.

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

FIXTURE_NAME = 'tests/fixtures/store_lifecycle_callers_ad352ee.json'
FIXTURE_SHA256 = 'dda9b68253b30c351282417de1df488c7b213c5b19c0c2547dc95eace2622a2b'



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


def admit_original_sources(root, records):
    """Admit the exact original four modules and reviewed failure diagnostics."""
    from tests import hia_caller_diagnostics_admission as diagnostics
    root = Path(root)
    frozen = (root / FIXTURE_NAME).read_bytes()
    if sha256(frozen).hexdigest() != FIXTURE_SHA256:
        raise ValueError('frozen original Store caller inventory changed')
    original = json.loads(frozen)
    if (type(records) is not dict or records != original['source_sha256']
            or len(records) != 4):
        raise ValueError('complete original Store caller source authority differs')
    captured = {name: (root / name).read_bytes() for name in records}
    captured[FIXTURE_NAME] = frozen
    def capture(name):
        raw = (root / name).read_bytes()
        if name in captured and captured[name] != raw:
            raise ValueError('Store caller source changed between captures: ' + name)
        captured[name] = raw
        return raw

    adjustments, integrated = {}, {}
    for name, expected in records.items():
        raw = captured[name]
        raw, history = _admit_integrated_source(root, capture, name, raw)
        if history is not None:
            integrated[name] = history
        if sha256(raw).hexdigest() == expected:
            continue
        if name != diagnostics.PATH:
            raise ValueError('complete original Store caller source differs: ' + name)
        proof = captured.setdefault(diagnostics.FIXTURE,
                                    (root / diagnostics.FIXTURE).read_bytes())
        adjustments[name] = diagnostics.admit(name, raw, expected, proof)
    if any((root / name).read_bytes() != raw for name, raw in captured.items()):
        raise ValueError('original Store caller admission bytes changed')
    return {'original_source_sha256': dict(records),
            'captured_source_sha256': {name: sha256(raw).hexdigest()
                                      for name, raw in captured.items()},
            'reviewed_diagnostic_source_adjustments': adjustments,
            **({'reviewed_integrated_source_adjustments': integrated} if integrated else {}),
            'original_inventory_bytes_unchanged': True,
            'production_source_exceptions': []}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument('--cold-report', type=Path)
    selection.add_argument('--development-manifest', type=Path)
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()
    from tools.run_hia_unittest_gate import load_declared_suite
    from tools.hia_selfhost_contract import file_digests
    from tools.build_hia_store_lifecycle import INPUTS
    fixture_bytes = (ROOT / FIXTURE_NAME).read_bytes()
    if sha256(fixture_bytes).hexdigest() != FIXTURE_SHA256:
        raise ValueError('frozen original Store caller inventory changed')
    expected = json.loads(fixture_bytes)
    if (expected.get('schema') != 'hepta.hia.store-lifecycle-original-callers.v1'
            or len(expected['ordered_ids']) != 50):
        raise ValueError('complete original Store caller source or denominator differs')
    source_admission = admit_original_sources(ROOT, expected['source_sha256'])
    suite, planned = load_declared_suite(tuple(expected['modules']))
    planned = list(planned)
    if planned != expected['ordered_ids']:
        raise ValueError('ordered original Store callers differ')

    def source_pins():
        return {**file_digests(ROOT),
                'tools/qualify_hia_store_lifecycle_callers.py': sha256(Path(__file__).read_bytes()).hexdigest(),
                FIXTURE_NAME: sha256((ROOT / FIXTURE_NAME).read_bytes()).hexdigest(),
                **{path: sha256((ROOT / path).read_bytes()).hexdigest() for path in (
                    'tests/hia_caller_diagnostics_admission.py',
                    'tests/fixtures/caller_deadline_diagnostics_v1.json')},
                **{path: sha256((ROOT / path).read_bytes()).hexdigest() for path in INPUTS},
                **{path: sha256((ROOT / path).read_bytes()).hexdigest()
                   for path in source_admission['captured_source_sha256']}}

    before = source_pins()
    if any(before.get(name) != digest
           for name, digest in source_admission['captured_source_sha256'].items()):
        raise ValueError('original Store source changed between admission and qualification')
    args.evidence.mkdir(mode=0o700, parents=True, exist_ok=False)
    if args.cold_report is not None:
        from tools.build_hia_store_lifecycle import build
        from tools.hia_cold_compiler import compiler_from_cold_report
        manifest = build(args.evidence / 'qualified', compiler_from_cold_report(args.cold_report),
                         args.cold_report)
        scope = 'MATCHING_SOURCE_COLD_ORIGINAL_STORE_LIFECYCLE_CALLERS'
    else:
        manifest = args.development_manifest.resolve(strict=True)
        scope = 'EXPLICIT_DEVELOPMENT_COMPONENT_NOT_CURRENT_COLD'
    from hepta import hia_agent_store as owner
    from hepta.hia_store_lifecycle_native import LifecycleFrame, SELECTOR, installed_store_lifecycle
    image = installed_store_lifecycle(str(manifest))
    bundle = {str(path): sha256(path.read_bytes()).hexdigest()
              for path in sorted(manifest.parent.rglob('*')) if path.is_file()}
    started, stopped, references = [], [], []
    modes, entries = Counter(), Counter()

    class Result(unittest.TextTestResult):
        def startTest(self, test):
            started.append(test.id())
            super().startTest(test)

        def stopTest(self, test):
            stopped.append(test.id())
            super().stopTest(test)

    original_frame, actual_entry = LifecycleFrame.__init__, image._entry

    def counted_frame(frame, selected, mode, *arguments, **keywords):
        if selected is not image:
            raise AssertionError('Store caller selected another image')
        original_frame(frame, selected, mode, *arguments, **keywords)
        modes[mode] += 1

    def counted_entry(source, size, output, capacity, state, extent):
        returned = actual_entry(source, size, output, capacity, state, extent)
        if returned != 80 or capacity != 80 or extent != 128 or size != 80:
            raise AssertionError('Store caller native ABI return differs')
        request = struct.unpack('<10Q', ctypes.string_at(source, size))
        entries[str(request[5]) + ':' + str(request[1])] += 1
        return returned

    def forbidden(*unused, **ignored):
        references.append(started[-1] if started else 'outside-test')
        raise AssertionError('selected Store entered retained lifecycle policy')

    start = time.monotonic()
    with ExitStack() as stack:
        stack.enter_context(patch.dict(os.environ, {SELECTOR: str(manifest)}))
        for name in ('_NATIVE_STORE_INITIALIZE_REFERENCE', '_NATIVE_STORE_CLOSE_REFERENCE'):
            stack.enter_context(patch.object(owner, name, forbidden))
        for name in ('_initialize_reference', '_close_reference'):
            stack.enter_context(patch.object(owner.AgentStore, name, forbidden))
        stack.enter_context(patch.object(LifecycleFrame, '__init__', counted_frame))
        stack.enter_context(patch.object(image, '_entry', counted_entry))
        with (args.evidence / 'tests.log').open('x') as stream:
            result = unittest.TextTestRunner(stream=stream, verbosity=2, resultclass=Result).run(suite)
    stable = source_pins() == before and all(sha256(Path(path).read_bytes()).hexdigest() == digest
                                           for path, digest in bundle.items())
    clean = result.wasSuccessful() and all(not getattr(result, name) for name in
        ('errors', 'failures', 'skipped', 'expectedFailures', 'unexpectedSuccesses'))
    passed = (started == stopped == planned and result.testsRun == len(planned) and clean and stable
              and not references and set(modes) == {1, 2} and entries['1:1'] and entries['2:1'])
    report = {'status': 'PASS' if passed else 'FAIL', 'scope': scope,
        'original_modules': expected['modules'], 'planned': planned, 'started': started, 'stopped': stopped,
        'actual_tests': result.testsRun, 'wall_seconds': time.monotonic() - start,
        'errors': [(test.id(), error) for test, error in result.errors],
        'failures': [(test.id(), error) for test, error in result.failures],
        'skipped': [(test.id(), error) for test, error in result.skipped],
        'expected_failures': [(test.id(), error) for test, error in result.expectedFailures],
        'unexpected_successes': [test.id() for test in result.unexpectedSuccesses],
        'native_mode_frames': dict(modes), 'actual_machine_mode_events': dict(entries),
        'native_image_sha256': image.image_sha256, 'reference_calls': references,
        'reference_poison_scope': 'test process; subprocesses inherit selector, not Python patches',
        'all_original_modules_unfiltered': True, 'original_test_budgets_changed': False,
        'source_and_bundle_unchanged': stable, 'source_pins': before, 'bundle_pins': bundle,
        'source_admission': source_admission,
        'foreign_path_sqlite_object_and_budget_effects_still_hosted': True,
        'whole_native_delivery_qualified': False}
    (args.evidence / 'report.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps({key: report[key] for key in ('status', 'scope', 'actual_tests', 'wall_seconds')}))
    if not passed:
        print((args.evidence / 'tests.log').read_text())
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
