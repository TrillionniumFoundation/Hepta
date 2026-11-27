"""Run all 112 original ordinary callers with both file-capture controls selected.

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
    args = parser.parse_args()
    from tools.run_hia_unittest_gate import load_declared_suite
    from tools.hia_selfhost_contract import file_digests
    from tools.build_hia_store_file_capture import INPUTS
    from tools.qualify_hia_emission_callers import admit_original_sources
    raw = (ROOT / FIXTURE_NAME).read_bytes()
    if sha256(raw).hexdigest() != FIXTURE_SHA256:
        raise ValueError('original complete caller inventory changed')
    original = json.loads(raw)
    modules = original['ordinary_modules']
    original_files = {record['path']: record['sha256'] for record in original['callers'].values()}
    count_adjustments = admit_original_sources(ROOT, original)
    if (len(modules) != 9 or original['ordinary_count'] != 112
            or len(original['ordinary_ordered_ids']) != 112
            or len(original['callers']) != 17
            or sum(len(row['recorded_ids']) for row in original['callers'].values()) != 240
            or original['separate_scope_count'] != 128):
        raise ValueError('the complete original caller modules differ')
    suite, planned = load_declared_suite(modules)
    planned = list(planned)
    if planned != original['ordinary_ordered_ids']:
        raise ValueError('original complete 112-method caller inventory differs')

    def source_pins():
        paths = {*INPUTS, *original_files, FIXTURE_NAME,
                 'tools/qualify_hia_store_file_capture_callers.py',
                 'tools/qualify_hia_emission_callers.py'}
        return {**file_digests(), **{name: sha256((ROOT / name).read_bytes()).hexdigest()
                                    for name in sorted(paths)}}

    before = source_pins()
    args.evidence.mkdir(mode=0o700, parents=True, exist_ok=False)
    if args.cold_report is not None:
        from tools.build_hia_store_file_capture import build
        from tools.hia_cold_compiler import compiler_from_cold_report
        manifest = build(args.evidence / 'qualified',
            compiler_from_cold_report(args.cold_report), args.cold_report)
        scope = 'MATCHING_SOURCE_COLD_NINE_ORDINARY_STORE_FILE_CAPTURE_CALLER_MODULES'
    else:
        manifest = args.development_manifest.resolve(strict=True)
        scope = 'EXPLICIT_DEVELOPMENT_NINE_ORDINARY_STORE_FILE_CAPTURE_CALLER_MODULES'
    from hepta import hia_agent_store as api
    from hepta import hia_store_file_capture_native as native
    image = native.installed_store_file_capture(str(manifest))
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

    initializer, actual_entry = native.StoreFileCaptureFrame.__init__, image._entry

    def counted_frame(frame, selected, *arguments, **keywords):
        if selected is not image:
            raise AssertionError('ordinary caller selected another file-capture image')
        initializer(frame, selected, *arguments, **keywords)
        frame_counts[active[0]] += 1

    def counted_entry(source, size, output, capacity, state, extent):
        magic, event = struct.unpack('<2Q', ctypes.string_at(source, 16))
        code = actual_entry(source, size, output, capacity, state, extent)
        if magic != native.REQUEST_MAGIC or code != native.OUTPUT_BYTES:
            raise AssertionError('file-capture machine return differs from declared ABI')
        entries[str(event)] += 1
        per_test_entries[active[0]][str(event)] += 1
        return code

    def forbidden(*arguments, **keywords):
        reference_calls.append(active[0])
        raise AssertionError('ordinary caller entered a retained complete Python file-capture body')

    begin = time.monotonic()
    with ExitStack() as stack:
        stack.enter_context(patch.dict(os.environ, {native.SELECTOR: str(manifest)}))
        stack.enter_context(patch.object(api, '_STABLE_READ_REFERENCE', forbidden))
        stack.enter_context(patch.object(api, '_CAPTURE_PATH_REFERENCE', forbidden))
        stack.enter_context(patch.object(native.StoreFileCaptureFrame, '__init__', counted_frame))
        stack.enter_context(patch.object(image, '_entry', counted_entry))
        with (args.evidence / 'tests.log').open('x') as stream:
            result = unittest.TextTestRunner(stream=stream, verbosity=2, resultclass=Result).run(suite)
    stable = source_pins() == before and all(
        sha256(Path(name).read_bytes()).hexdigest() == digest for name, digest in bundle.items())
    anomalies = ('errors', 'failures', 'skipped', 'expectedFailures', 'unexpectedSuccesses')
    clean = result.wasSuccessful() and all(not getattr(result, name) for name in anomalies)
    passed = (clean and stable and started == stopped == planned and result.testsRun == 112
              and not reference_calls and sum(frame_counts.values()) > 0
              and all(entries[str(event)] > 0 for event in (0, 1, 2)))
    report = {
        'schema': 'hepta.hia.store-file-capture-nine-ordinary-callers.v1',
        'status': 'PASS' if passed else 'FAIL', 'scope': scope,
        'original_baseline_commit': original['base_commit'],
        'original_modules': modules, 'planned': planned, 'started': started, 'stopped': stopped,
        'actual_tests': result.testsRun, 'wall_seconds': time.monotonic() - begin,
        'errors': [(test.id(), error) for test, error in result.errors],
        'failures': [(test.id(), error) for test, error in result.failures],
        'skipped': [(test.id(), reason) for test, reason in result.skipped],
        'expected_failures': [(test.id(), error) for test, error in result.expectedFailures],
        'unexpected_successes': [test.id() for test in result.unexpectedSuccesses],
        'actual_file_capture_frames': sum(frame_counts.values()),
        'frames_by_original_test': dict(frame_counts),
        'actual_native_event_counts': dict(entries),
        'native_event_counts_by_original_test': dict(per_test_entries),
        'native_image_sha256': image.image_sha256,
        'reference_calls': reference_calls, 'retained_stable_and_capture_forbidden': True,
        'reference_poison_scope': 'test process; subprocesses inherit selector, not Python patches',
        'all_nine_ordinary_modules_unfiltered': True, 'original_test_budgets_changed': False,
        'source_and_bundle_unchanged': stable, 'source_pins': before, 'bundle_pins': bundle,
        'original_registry_count_assertion_adjustments': count_adjustments,
        'separate_original_administrator_scope_gates': original['separate_scope_modules'],
        'other_owner_or_artifact_provider_gates_replaced_by_112': False,
        'complete_stable_read_and_capture_path_control_selected': True,
        'opaque_Path_stream_and_OS_effects_hosted': True,
        'raw_descriptor_primitive_substituted_by_caller_gate': False,
        'resource_qualification_inferred_from_caller_success': False,
        'whole_project_dynamic_caller_closure_claimed': False,
        'whole_native_delivery_qualified': False,
    }
    (args.evidence / 'report.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps({key: report[key] for key in (
        'status', 'scope', 'actual_tests', 'wall_seconds', 'actual_file_capture_frames')}))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
