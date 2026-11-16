"""Run the unchanged complete native-publication profile with HIA decisions.

The original controls retain actual Clang, Rust, Z3, sealed loading and their
original time budgets. Synthetic sample values only exercise policy branches;
they do not establish a performance advantage.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ''}:
    sys.path.insert(0, str(ROOT))

from tools.run_hia_unittest_gate import load_declared_suite

ORIGINAL_MODULES = ('tests.test_hia_native_profile_convergence',)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument('--cold-report', type=Path)
    selection.add_argument('--development-manifest', type=Path)
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()
    from tools.hia_selfhost_contract import file_digests
    before = file_digests(ROOT)
    suite, planned = load_declared_suite(ORIGINAL_MODULES)
    planned = list(planned)
    args.evidence.mkdir(mode=0o700, parents=True, exist_ok=False)
    if args.cold_report:
        from tools.build_hia_publication_measurement import build
        cold = json.loads(args.cold_report.read_bytes())
        nested = json.loads(Path(cold['nested_report']).read_bytes())
        manifest = build(args.evidence / 'qualified',
                         Path(nested['generations'][-1]['produced_image']), args.cold_report)
        scope = 'MATCHING_SOURCE_COLD_ORIGINAL_PUBLICATION_CALLERS'
    else:
        manifest = args.development_manifest.resolve(strict=True)
        scope = 'EXPLICIT_DEVELOPMENT_COMPONENT_NOT_CURRENT_COLD'
    from hepta import hia_multiversion as owner
    from hepta.hia_publication_measurement_native import (NativePublicationMeasurement,
        SELECTOR, installed_publication_measurement)
    image = installed_publication_measurement(str(manifest))
    bundle = {str(path): sha256(path.read_bytes()).hexdigest()
              for path in sorted(manifest.parent.rglob('*')) if path.is_file()}
    started, stopped, entries = [], [], []
    context = threading.local()
    class Result(unittest.TextTestResult):
        def startTest(self, test):
            started.append(test.id())
            super().startTest(test)
        def stopTest(self, test):
            stopped.append(test.id())
            super().stopTest(test)
    assess = NativePublicationMeasurement.assess
    publish = owner.ScalarMultiversionRuntime.publish_if_current
    def observed_publish(runtime, *arguments, **keywords):
        previous = getattr(context, 'runtime', None)
        context.runtime = runtime
        try:
            return publish(runtime, *arguments, **keywords)
        finally:
            context.runtime = previous
    def observed_assess(selected, *arguments, **keywords):
        result = assess(selected, *arguments, **keywords)
        runtime = getattr(context, 'runtime', None)
        entries.append({'image_sha256': selected.image_sha256,
                        'native_source_sha256': selected.admitted_source_sha256,
                        'inside_actual_publish_if_current': runtime is not None,
                        'runtime_lock_owned_by_current_thread': bool(runtime is not None and runtime._lock._is_owned()),
                        'eligible': result['eligible'], 'reasons': result['reasons'],
                        'measurement_sha256': result['measurement_sha256']})
        return result
    start = time.monotonic()
    with ExitStack() as stack:
        stack.enter_context(patch.dict(os.environ, {SELECTOR: str(manifest)}))
        stack.enter_context(patch.object(owner, '_reference_assess_measurement',
            side_effect=AssertionError('retained publication measurement policy entered')))
        stack.enter_context(patch.object(owner, 'median', side_effect=AssertionError('host median entered')))
        stack.enter_context(patch.object(NativePublicationMeasurement, 'assess', observed_assess))
        stack.enter_context(patch.object(owner.ScalarMultiversionRuntime, 'publish_if_current', observed_publish))
        with (args.evidence / 'tests.log').open('x') as stream:
            result = unittest.TextTestRunner(stream=stream, verbosity=2, resultclass=Result).run(suite)
    stable = (file_digests(ROOT) == before and all(sha256(Path(path).read_bytes()).hexdigest() == digest
                                                for path, digest in bundle.items()))
    entered = bool(entries) and all(row['image_sha256'] == image.image_sha256 for row in entries)
    preselection = any(row['inside_actual_publish_if_current'] and row['eligible']
                      and not row['runtime_lock_owned_by_current_thread'] for row in entries)
    commit_gate = any(row['inside_actual_publish_if_current'] and row['eligible']
                     and row['runtime_lock_owned_by_current_thread'] for row in entries)
    refusal = any(not row['eligible'] for row in entries)
    clean = result.wasSuccessful() and all(not getattr(result, name) for name in
        ('errors', 'failures', 'skipped', 'expectedFailures', 'unexpectedSuccesses'))
    passed = (started == stopped == planned and result.testsRun == len(planned)
              and clean and stable and entered and preselection and commit_gate and refusal)
    report = {'status': 'PASS' if passed else 'FAIL', 'scope': scope,
        'original_modules': ORIGINAL_MODULES, 'planned': planned, 'started': started, 'stopped': stopped,
        'actual_tests': result.testsRun, 'wall_seconds': time.monotonic() - start,
        'errors': [(test.id(), error) for test, error in result.errors],
        'failures': [(test.id(), error) for test, error in result.failures],
        'skipped': [(test.id(), error) for test, error in result.skipped],
        'expected_failures': [(test.id(), error) for test, error in result.expectedFailures],
        'unexpected_successes': [test.id() for test in result.unexpectedSuccesses],
        'actual_native_entries': entries, 'observed_preselection_policy': preselection,
        'observed_policy_under_actual_commit_lock': commit_gate, 'observed_policy_refusal': refusal,
        'all_original_modules_unfiltered': True, 'retained_policy_and_host_median_forbidden': True,
        'source_and_bundle_unchanged': stable, 'source_pins': before, 'bundle_pins': bundle,
        'host_locks_effects_proofs_loader_retained': True, 'whole_native_delivery_qualified': False}
    (args.evidence / 'report.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps({key: report[key] for key in ('status', 'scope', 'actual_tests', 'wall_seconds')}))
    if not passed:
        print((args.evidence / 'tests.log').read_text())
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
