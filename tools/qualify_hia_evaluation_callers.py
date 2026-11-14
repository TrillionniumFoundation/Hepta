"""Run every original ordinary evaluation caller with the retained body forbidden.

The five original explicit administrator-bundle modules retain their separate
gates. Their original inputs are not changed to acquire this new helper.
This command cannot establish whole-project dynamic-caller closure.
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
FIXTURE_NAME = 'tests/fixtures/evaluation_callers_19065.json'
FIXTURE_SHA256 = '256e6c83a79fc2f237b4c12dd4bc2ae00d61bee03332b6adc794086b7e081395'


def admit_original_sources(root, records):
    """Allow only the registry's exact added-owner count in one old assertion."""
    from hepta.hia_native_helpers import HELPERS
    count = len(HELPERS)
    if count < 35:
        raise ValueError('the original native helper registry lost an owner')
    original_line = b'        self.assertEqual(len(HELPERS), 35)\n'
    current_line = ('        self.assertEqual(len(HELPERS), ' + str(count) + ')\n').encode()
    adjustments = []
    for name, digest in records.items():
        raw = (root / name).read_bytes()
        actual = sha256(raw).hexdigest()
        if actual == digest:
            continue
        if (name != 'tests/test_hia_worker_native_helpers.py'
                or raw.count(current_line) != 1
                or sha256(raw.replace(current_line, original_line, 1)).hexdigest() != digest):
            raise ValueError('original caller source differs: ' + name)
        adjustments.append({'path': name, 'original_sha256': digest, 'current_sha256': actual,
            'original_helper_count': 35, 'current_helper_count': count,
            'sole_permitted_change': 'one exact registry-count assertion decimal literal',
            'all_other_source_bytes_unchanged': True})
    return adjustments


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument('--cold-report', type=Path)
    choice.add_argument('--development-manifest', type=Path)
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()
    from tools.run_hia_unittest_gate import load_declared_suite
    from tools.hia_selfhost_contract import file_digests
    from tools.build_hia_evaluation import INPUTS
    raw = (ROOT / FIXTURE_NAME).read_bytes()
    if sha256(raw).hexdigest() != FIXTURE_SHA256:
        raise ValueError('original evaluation caller inventory changed')
    original = json.loads(raw)
    modules = original['ordinary_modules']
    original_files = {record['path']: record['sha256'] for record in original['modules'].values()}
    count_adjustments = admit_original_sources(ROOT, original_files)
    if (len(modules) != 7 or original['ordinary_count'] != 81
            or len(original['ordinary_ordered_ids']) != 81
            or len(original['modules']) != 12 or original['all_original_tests'] != 183):
        raise ValueError('the complete original evaluation modules differ')
    suite, planned = load_declared_suite(modules)
    planned = list(planned)
    if planned != original['ordinary_ordered_ids']:
        raise ValueError('original complete 81-method caller inventory differs')
    def source_pins():
        paths = {*INPUTS, *original_files, FIXTURE_NAME,
                 'tools/qualify_hia_evaluation_callers.py'}
        return {**file_digests(), **{name: sha256((ROOT / name).read_bytes()).hexdigest()
                                    for name in sorted(paths)}}
    before = source_pins()
    args.evidence.mkdir(mode=0o700, parents=True, exist_ok=False)
    if args.cold_report is not None:
        from tools.build_hia_evaluation import build
        cold = json.loads(args.cold_report.read_bytes())
        nested = json.loads(Path(cold['nested_report']).read_bytes())
        manifest = build(args.evidence / 'qualified',
                         Path(nested['generations'][-1]['produced_image']), args.cold_report)
        scope = 'MATCHING_SOURCE_COLD_SEVEN_ORDINARY_EVALUATION_CALLER_MODULES'
    else:
        manifest = args.development_manifest.resolve(strict=True)
        scope = 'EXPLICIT_DEVELOPMENT_SEVEN_ORDINARY_EVALUATION_CALLER_MODULES'
    from hepta.hia_agent_service import HIAAgentService
    from hepta.hia_evaluation_native import (EvaluationFrame, SELECTOR, REQUEST_MAGIC,
        MATH_MAGIC, OUTPUT_BYTES, installed_evaluation)
    image = installed_evaluation(str(manifest))
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

    initializer, actual_entry = EvaluationFrame.__init__, image._entry

    def counted_frame(frame, selected, *arguments, **keywords):
        if selected is not image:
            raise AssertionError('ordinary caller selected another evaluation image')
        initializer(frame, selected, *arguments, **keywords)
        frame_counts[active[0]] += 1

    def counted_entry(source, size, output, capacity, state, extent):
        magic, event = struct.unpack('<2Q', ctypes.string_at(source, 16))
        code = actual_entry(source, size, output, capacity, state, extent)
        if magic == REQUEST_MAGIC and code == OUTPUT_BYTES:
            key = 'continuation:' + str(event)
        elif magic == MATH_MAGIC and code == 32:
            key = 'integer:' + str(event)
        else:
            raise AssertionError('evaluation machine return differs from its declared ABI')
        entries[key] += 1
        per_test_entries[active[0]][key] += 1
        return code

    def forbidden(*arguments, **keywords):
        reference_calls.append(active[0])
        raise AssertionError('ordinary caller entered the retained Python evaluation body')

    begin = time.monotonic()
    with ExitStack() as stack:
        stack.enter_context(patch.dict(os.environ, {SELECTOR: str(manifest)}))
        stack.enter_context(patch.object(HIAAgentService, '_hia_evaluate_reference', forbidden))
        stack.enter_context(patch.object(EvaluationFrame, '__init__', counted_frame))
        stack.enter_context(patch.object(image, '_entry', counted_entry))
        with (args.evidence / 'tests.log').open('x') as stream:
            result = unittest.TextTestRunner(stream=stream, verbosity=2, resultclass=Result).run(suite)
    stable = source_pins() == before and all(
        sha256(Path(name).read_bytes()).hexdigest() == digest for name, digest in bundle.items())
    anomalies = ('errors', 'failures', 'skipped', 'expectedFailures', 'unexpectedSuccesses')
    clean = result.wasSuccessful() and all(not getattr(result, name) for name in anomalies)
    passed = (clean and stable and started == stopped == planned and result.testsRun == 81
              and not reference_calls and sum(frame_counts.values()) > 0
              and entries['continuation:0'] > 0 and entries['continuation:1'] > 0
              and entries['continuation:2'] > 0 and any(key.startswith('integer:') for key in entries))
    report = {
        'schema': 'hepta.hia.evaluation-seven-ordinary-callers.v1',
        'status': 'PASS' if passed else 'FAIL', 'scope': scope,
        'original_baseline_commit': original['base_commit'],
        'original_modules': modules, 'planned': planned, 'started': started, 'stopped': stopped,
        'actual_tests': result.testsRun, 'wall_seconds': time.monotonic() - begin,
        'errors': [(test.id(), error) for test, error in result.errors],
        'failures': [(test.id(), error) for test, error in result.failures],
        'skipped': [(test.id(), reason) for test, reason in result.skipped],
        'expected_failures': [(test.id(), error) for test, error in result.expectedFailures],
        'unexpected_successes': [test.id() for test in result.unexpectedSuccesses],
        'actual_evaluation_frames': sum(frame_counts.values()),
        'frames_by_original_test': dict(frame_counts),
        'actual_native_event_counts': dict(entries),
        'native_event_counts_by_original_test': dict(per_test_entries),
        'native_image_sha256': image.image_sha256,
        'reference_calls': reference_calls, 'retained_evaluation_body_forbidden': True,
        'reference_poison_scope': 'test process; subprocesses inherit selector, not Python patches',
        'all_seven_ordinary_modules_unfiltered': True, 'original_test_budgets_changed': False,
        'source_and_bundle_unchanged': stable, 'source_pins': before, 'bundle_pins': bundle,
        'original_registry_count_assertion_adjustments': count_adjustments,
        'separate_original_administrator_scope_gates': original['explicit_scope_modules'],
        'whole_project_dynamic_caller_closure_claimed': False,
        'whole_native_delivery_qualified': False,
    }
    (args.evidence / 'report.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps({key: report[key] for key in ('status', 'scope', 'actual_tests', 'wall_seconds',
                                                 'actual_evaluation_frames')}))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
