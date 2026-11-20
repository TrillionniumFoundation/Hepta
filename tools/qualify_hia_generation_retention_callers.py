"""Run complete unchanged lifecycle callers with retained HIA lease state.

Original Clang, Z3, Rust where required, actual sealed loading, time budgets,
max-live admission and resource-release controls remain mandatory. No test
class, skip or expected failure is silently removed from this qualification.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ''}:
    sys.path.insert(0, str(ROOT))

from tools.run_hia_unittest_gate import load_declared_suite

ORIGINAL_MODULES = ('tests.test_hia_multiversion', 'tests.test_hia_native_retirement',
                    'tests.test_hia_publication_interruptions', 'tests.test_hia_scalar_state',
                    'tests.test_hia_background_optimizer', 'tests.test_hia_native_profile_convergence')


def observe_companion_policies(stack, bundle, compiler_sha256):
    """Bind the three prior cold components and observe their real returns."""
    from hepta import hia_multiversion as public
    from hepta import native_mapping_identity as mapping_public
    from hepta import hia_scalar_profile_native as scalar
    from hepta import hia_publication_measurement_native as measurement
    from hepta import native_mapping_native as mapping
    specifications = (
        ('scalar_profile', scalar.SELECTOR, scalar.installed_scalar_profile,
         scalar.NativeScalarProfile, 'decision'),
        ('publication_measurement', measurement.SELECTOR, measurement.installed_publication_measurement,
         measurement.NativePublicationMeasurement, 'observe'),
        ('native_mapping', mapping.SELECTOR, mapping.installed_native_mapping,
         mapping.NativeMappingImage, 'matches'))
    reports = {}
    for name, selector, install, factory, method in specifications:
        if not os.environ.get(selector):
            raise ValueError('combined original caller gate requires explicit ' + selector)
        path = Path(os.environ[selector]).resolve(strict=True)
        selected = install(str(path))
        manifest = json.loads(path.read_bytes())
        if manifest['compiler_sha256'] != compiler_sha256:
            raise ValueError('combined original caller components do not bind the same compiler')
        bundle.update({str(item): sha256(item.read_bytes()).hexdigest()
                       for item in sorted(path.parent.rglob('*')) if item.is_file()})
        report = {'selector': selector, 'manifest': str(path),
                  'image_sha256': selected.image_sha256,
                  'source_sha256': selected.admitted_source_sha256,
                  'compiler_sha256': manifest['compiler_sha256'],
                  'actual_native_returns': 0, 'observed_images': {}, 'status_counts': {}}
        reports[name] = report
        original = getattr(factory, method)
        def observer(original, report, name):
            def call(image, *arguments, **keywords):
                result = original(image, *arguments, **keywords)
                report['actual_native_returns'] += 1
                images = report['observed_images']
                images[image.image_sha256] = images.get(image.image_sha256, 0) + 1
                code = result[0] if name == 'scalar_profile' else result[1] if name == 'publication_measurement' else 'accepted'
                counts = report['status_counts']
                counts[str(code)] = counts.get(str(code), 0) + 1
                return result
            return call
        stack.enter_context(patch.object(factory, method, observer(original, report, name)))
    for module, name in ((public, '_reference_scalar_profile'),
                         (public, '_reference_assess_measurement'),
                         (mapping_public, '_reference_mapping_matches')):
        stack.enter_context(patch.object(module, name,
            side_effect=AssertionError('combined native caller gate entered hosted policy: ' + name)))
    stack.enter_context(patch.object(public, 'median',
        side_effect=AssertionError('combined native caller gate entered hosted measurement median')))
    return reports


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument('--cold-report', type=Path)
    choice.add_argument('--development-manifest', type=Path)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--require-companion-policies', action='store_true',
                        help='require selected scalar-profile, publication-measurement and mapping images')
    args = parser.parse_args()
    from tools.hia_selfhost_contract import file_digests
    from tools.build_hia_generation_retention import INPUTS, build
    extra = (*INPUTS, 'tests/test_hia_generation_retention_native.py',
             'tools/qualify_hia_generation_retention_callers.py',
             *(name.replace('.', '/') + '.py' for name in ORIGINAL_MODULES))
    def sources():
        return {**file_digests(ROOT), **{name: sha256((ROOT / name).read_bytes()).hexdigest()
                                        for name in extra}}
    before = sources()
    suite, planned = load_declared_suite(ORIGINAL_MODULES)
    planned = list(planned)
    args.evidence.mkdir(mode=0o700, parents=True, exist_ok=False)
    if args.cold_report:
        cold = json.loads(args.cold_report.read_bytes())
        nested = json.loads(Path(cold['nested_report']).read_bytes())
        manifest = build(args.evidence / 'qualified',
                         Path(nested['generations'][-1]['produced_image']), args.cold_report)
        scope = 'MATCHING_SOURCE_COLD_ORIGINAL_GENERATION_CALLERS'
    else:
        manifest = args.development_manifest.resolve(strict=True)
        scope = 'EXPLICIT_DEVELOPMENT_COMPONENT_NOT_CURRENT_COLD'
    from hepta import hia_multiversion as public
    from hepta.hia_generation_retention_native import (GenerationRetention, SELECTOR,
                                                       installed_generation_retention)
    image = installed_generation_retention(str(manifest))
    bundle = {str(path): sha256(path.read_bytes()).hexdigest()
              for path in sorted(manifest.parent.rglob('*')) if path.is_file()}
    started, stopped, samples = [], [], []
    counts = {event: 0 for event in range(7)}
    mutation_without_runtime_lock = []
    identities = set()
    companions = {}

    class Result(unittest.TextTestResult):
        def startTest(self, test):
            started.append(test.id())
            super().startTest(test)
        def stopTest(self, test):
            stopped.append(test.id())
            super().stopTest(test)

    invoke = GenerationRetention._invoke
    generation_get = public._Generation.__getattribute__
    lease_get = public.GenerationLease.__getattribute__

    def forbid_reference_generation(state, name):
        if name in ('_reference_leases', '_reference_retired'):
            if generation_get(state, '_retention') is not None:
                raise AssertionError('hosted generation policy state read')
        return generation_get(state, name)

    def forbid_reference_lease(lease, name):
        if name == '_reference_closed' and lease_get(lease, '_native_cell') is not None:
            raise AssertionError('hosted lease closure state read')
        return lease_get(lease, name)

    def observed_invoke(state, event, *arguments, **keywords):
        result = invoke(state, event, *arguments, **keywords)
        counts[event] += 1
        identities.add(state.image.image_sha256)
        locked = state._runtime._lock._is_owned()
        if event in (1, 2, 3, 4) and not locked:
            mutation_without_runtime_lock.append(event)
        if len(samples) < 64:
            generation = state._generation
            samples.append({'event': event, 'returned': result,
                            'generation': None if generation is None else generation.info.generation,
                            'runtime_lock_owned_by_current_thread': locked,
                            'image_sha256': state.image.image_sha256})
        return result

    start = time.monotonic()
    with ExitStack() as stack:
        stack.enter_context(patch.dict(os.environ, {SELECTOR: str(manifest)}))
        if args.require_companion_policies:
            companions = observe_companion_policies(stack, bundle,
                json.loads(manifest.read_bytes())['compiler_sha256'])
        stack.enter_context(patch.object(public._Generation, '__getattribute__', forbid_reference_generation))
        stack.enter_context(patch.object(public.GenerationLease, '__getattribute__', forbid_reference_lease))
        stack.enter_context(patch.object(GenerationRetention, '_invoke', observed_invoke))
        with (args.evidence / 'tests.log').open('x') as stream:
            result = unittest.TextTestRunner(stream=stream, verbosity=2, resultclass=Result).run(suite)
    stable = (sources() == before and all(sha256(Path(path).read_bytes()).hexdigest() == digest
                                          for path, digest in bundle.items()))
    clean = result.wasSuccessful() and all(not getattr(result, name) for name in
        ('errors', 'failures', 'skipped', 'expectedFailures', 'unexpectedSuccesses'))
    native = (all(counts[event] > 0 for event in range(7))
              and identities == {image.image_sha256} and not mutation_without_runtime_lock)
    combined = (not args.require_companion_policies or (len(companions) == 3 and all(
        row['actual_native_returns'] > 0 and set(row['observed_images']) == {row['image_sha256']}
        for row in companions.values())))
    passed = (started == stopped == planned and result.testsRun == len(planned)
              and clean and stable and native and combined)
    report = {'status': 'PASS' if passed else 'FAIL', 'scope': scope,
        'original_modules': ORIGINAL_MODULES, 'planned': planned, 'started': started, 'stopped': stopped,
        'actual_tests': result.testsRun, 'wall_seconds': time.monotonic() - start,
        'errors': [(test.id(), error) for test, error in result.errors],
        'failures': [(test.id(), error) for test, error in result.failures],
        'skipped': [(test.id(), error) for test, error in result.skipped],
        'expected_failures': [(test.id(), error) for test, error in result.expectedFailures],
        'unexpected_successes': [test.id() for test in result.unexpectedSuccesses],
        'native_event_counts': counts, 'native_observation_samples': samples,
        'native_image_sha256': image.image_sha256,
        'native_source_sha256': image.admitted_source_sha256,
        'mutation_without_original_runtime_lock': mutation_without_runtime_lock,
        'required_companion_policies': args.require_companion_policies,
        'companion_policy_observations': companions,
        'companion_reference_policies_forbidden': args.require_companion_policies,
        'all_original_modules_unfiltered': True, 'hosted_reference_state_reads_forbidden': True,
        'source_and_bundle_unchanged': stable, 'source_pins': before, 'bundle_pins': bundle,
        'host_locks_selection_epochs_effects_proofs_loader_retained': True,
        'arbitrary_python_async_unwind_proved': False, 'whole_native_delivery_qualified': False}
    (args.evidence / 'report.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps({key: report[key] for key in ('status', 'scope', 'actual_tests', 'wall_seconds')}))
    if not passed:
        print((args.evidence / 'tests.log').read_text())
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
