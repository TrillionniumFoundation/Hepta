"""Run all 63 original artifact tests plus the three complete additional modules.

Original fixtures, method bodies, assertions and deadlines remain unchanged.
Reference16 retains its original unselected policy. NDU19 and assembly18 use
explicit generic publication; all NativeTools32 use the original supported
Store selector, preserving the original sealed-child guard without exceptions.
Missing original prerequisites and skips fail this gate. This command does not
claim whole-project dynamic caller or installed-worker closure.
"""
from __future__ import annotations
import argparse
from collections import Counter, defaultdict
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
if __package__ in (None, ''):
    sys.path.insert(0, str(ROOT))
FIXTURE = 'tests/fixtures/hia_artifact_delivery_callers_5bf69586.json'
FIXTURE_SHA256 = '90c692ff69571913150d577761520f9b63d1a50fabd3d9c3a0ccf7baeb8f2754'
COLD_ENV = 'HEPTA_HIA_ARTIFACT_PUBLICATION_COLD_REPORT'
PUBLIC_SELECTOR = 'HEPTA_HIA_ARTIFACT_PUBLICATION_MANIFEST'
STORE_SELECTOR = 'HEPTA_HIA_AGENT_ARTIFACT_STORE_MANIFEST'
OPERATIONS = ('publish', 'verify', 'withdraw', 'store-put', 'store-get', 'store-hash')


def admit_inventory():
    raw = (ROOT / FIXTURE).read_bytes()
    if sha256(raw).hexdigest() != FIXTURE_SHA256:
        raise ValueError('complete original artifact caller inventory changed')
    value = json.loads(raw)
    if ((value['direct_count'], value['additional_count'], value['total_count']) != (63, 69, 132)
            or len(value['modules']) != 7 or len(value['ordered_ids']) != 132):
        raise ValueError('original complete seven-module 132-method scope changed')
    direct_raw = (ROOT / value['direct_original_fixture']).read_bytes()
    if sha256(direct_raw).hexdigest() != value['direct_original_fixture_sha256']:
        raise ValueError('independent original four-module artifact fixture changed')
    if json.loads(direct_raw)['declared_original_test_ids'] != value['direct_ordered_ids']:
        raise ValueError('independent original complete 63 IDs differ')
    for record in value['modules']:
        current = (ROOT / record['path']).read_bytes()
        if len(current) != record['bytes'] or sha256(current).hexdigest() != record['sha256']:
            raise ValueError('original caller source bytes changed: ' + record['path'])
    additional = value['additional_groups']
    if ([group['count'] for group in additional] != [37, 32]
            or [group['selector'] for group in additional] != [PUBLIC_SELECTOR, STORE_SELECTOR]
            or sum((group['ordered_ids'] for group in additional), []) != value['additional_ordered_ids']
            or value['direct_ordered_ids'] + value['additional_ordered_ids'] != value['ordered_ids']):
        raise ValueError('original complete module grouping or ordering changed')
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--cold-report', type=Path)
    mode.add_argument('--development-manifest', type=Path)
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()
    from tools.run_hia_unittest_gate import load_declared_suite
    from tools.hia_selfhost_contract import file_digests
    original = admit_inventory()
    for selector in (PUBLIC_SELECTOR, STORE_SELECTOR):
        if selector in os.environ:
            raise ValueError('the original artifact caller gate owns selector presence: ' + selector)
    cold_path = None if args.cold_report is None else args.cold_report.resolve(strict=True)
    if COLD_ENV in os.environ:
        if not os.environ[COLD_ENV] or cold_path is None or Path(os.environ[COLD_ENV]).resolve(strict=True) != cold_path:
            raise ValueError('original fixture cold selection differs from explicit gate mode')
    evidence = args.evidence.resolve()
    if evidence == ROOT or ROOT in evidence.parents:
        raise ValueError('caller evidence must be outside the original source tree')
    evidence.mkdir(mode=0o700, parents=True, exist_ok=False)
    declared_groups = [{'name': 'original-direct-63', 'modules': original['direct_modules'],
                        'ordered_ids': original['direct_ordered_ids'], 'count': 63, 'selector': None},
                       *original['additional_groups']]
    suites = []
    for group in declared_groups:
        suite, ids = load_declared_suite(group['modules'])
        if list(ids) != group['ordered_ids'] or suite.countTestCases() != group['count']:
            raise ValueError('real complete unittest discovery differs: ' + group['name'])
        suites.append(suite)

    def source_pins():
        extras = [FIXTURE, original['direct_original_fixture'],
                  'tools/qualify_hia_artifact_delivery_callers.py',
                  *(r['path'] for r in original['modules'])]
        return {**file_digests(), **{name: sha256((ROOT / name).read_bytes()).hexdigest() for name in extras}}

    before = source_pins()
    cold_pin = compiler_pin = None
    if cold_path is not None:
        cold_raw = cold_path.read_bytes()
        cold = json.loads(cold_raw)
        nested_path = Path(cold['nested_report'])
        nested_raw = nested_path.read_bytes()
        nested = json.loads(nested_raw)
        compiler = Path(nested['generations'][-1]['produced_image'])
        compiler_pin = {'path': str(compiler), 'sha256': sha256(compiler.read_bytes()).hexdigest()}
        cold_pin = {'path': str(cold_path), 'sha256': sha256(cold_raw).hexdigest(),
                    'nested_path': str(nested_path), 'nested_sha256': sha256(nested_raw).hexdigest()}
        from tools.build_hia_artifact_publication import build
        executable = build(evidence / 'additional-selected-build', compiler, cold_path)
        manifest = executable.parent / 'build.json'
        scope = 'MATCHING_SOURCE_COLD_ORIGINAL_ARTIFACT_63_PLUS_ADDITIONAL_69'
    else:
        manifest = args.development_manifest.resolve(strict=True)
        executable = manifest.parent / 'hia-artifact'
        scope = 'EXPLICIT_DEVELOPMENT_ORIGINAL_ARTIFACT_63_PLUS_ADDITIONAL_69'
    from hepta import artifact_publication as publication
    from hepta import artifact_publication_native as native
    from hepta.hia_artifact_delivery import ArtifactInvocation
    from hepta.hia_artifact_delivery_protocol import public_executable
    admitted = native._validated_code(str(manifest))
    if public_executable(admitted) != executable.read_bytes():
        raise ValueError('additional application differs from fixed admitted public/private code')
    application = {str(path): sha256(path.read_bytes()).hexdigest() for path in (manifest, executable)}
    public_codes = {publication.publish_verified.__code__, publication.verify_published.__code__}
    original_read = publication._read_exact
    handoff, returned, confirmed = ArtifactInvocation.handoff, ArtifactInvocation.returned, ArtifactInvocation.confirmed
    active, current_group = ['outside-test'], ['outside-group']
    started, stopped, reference_calls = [], [], []
    counts, per_test = Counter(), defaultdict(Counter)
    acknowledgements = []

    def guarded_read(*arguments, **keywords):
        # Direct original selected public read only; no frame walking,
        # global tracing, or reference16 ban. Withdrawal keeps old controls.
        caller = sys._getframe(1)
        selected = caller.f_locals.get('selected')
        if caller.f_code in public_codes and type(selected) is str and len(selected) != 0:
            reference_calls.append({'test': active[0], 'group': current_group[0], 'provider': '_read_exact'})
            raise AssertionError('REFERENCE_PUBLICATION: selected public read entered retained policy')
        return original_read(*arguments, **keywords)

    def observed_handoff(invocation, environment):
        value = handoff(invocation, environment)
        key = 'handoff:' + invocation.operation
        counts[key] += 1
        per_test[active[0]][key] += 1
        return value

    def observed_return(invocation, process):
        receipt = returned(invocation, process)
        key = 'acknowledged:' + invocation.operation
        counts[key] += 1
        per_test[active[0]][key] += 1
        acknowledgements.append({'test': active[0], 'group': current_group[0],
            'operation': invocation.operation, 'returncode': process.returncode,
            'stdout_bytes': len(process.stdout), 'stdout_sha256': sha256(process.stdout).hexdigest(),
            'stderr_bytes': len(process.stderr), 'stderr_hex': process.stderr.hex(),
            'nonce_hex': invocation.nonce.hex(), 'outcome': receipt.outcome,
            'acknowledged_operation': receipt.operation, 'input_bytes': receipt.input_bytes})
        return receipt

    def observed_confirmed(invocation):
        value = confirmed(invocation)
        key = 'public-receipt:' + invocation.operation
        counts[key] += 1
        per_test[active[0]][key] += 1
        return value

    class Result(unittest.TextTestResult):
        def startTest(self, test):
            active[0] = test.id()
            started.append(test.id())
            super().startTest(test)

        def stopTest(self, test):
            stopped.append(test.id())
            super().stopTest(test)
            active[0] = 'outside-test'

    def run_group(group, suite):
        current_group[0] = group['name']
        begin = time.monotonic()
        with (evidence / (group['name'] + '-tests.log')).open('x') as log:
            result = unittest.TextTestRunner(stream=log, verbosity=2, resultclass=Result).run(suite)
        value = {'name': group['name'], 'modules': group['modules'], 'planned': group['ordered_ids'],
            'selector': group['selector'], 'actual_tests': result.testsRun,
            'wall_seconds': time.monotonic() - begin,
            'errors': [(test.id(), error) for test, error in result.errors],
            'failures': [(test.id(), error) for test, error in result.failures],
            'skipped': [(test.id(), reason) for test, reason in result.skipped],
            'expected_failures': [(test.id(), error) for test, error in result.expectedFailures],
            'unexpected_successes': [test.id() for test in result.unexpectedSuccesses],
            'was_successful': result.wasSuccessful()}
        current_group[0] = 'outside-group'
        return value

    begin = time.monotonic()
    groups = []
    with ExitStack() as stack:
        if cold_path is not None:
            stack.enter_context(patch.dict(os.environ, {COLD_ENV: str(cold_path)}))
        stack.enter_context(patch.object(publication, '_read_exact', guarded_read))
        stack.enter_context(patch.object(ArtifactInvocation, 'handoff', observed_handoff))
        stack.enter_context(patch.object(ArtifactInvocation, 'returned', observed_return))
        stack.enter_context(patch.object(ArtifactInvocation, 'confirmed', observed_confirmed))
        for group, suite in zip(declared_groups, suites):
            # Complete class/module teardown finishes before changing selection.
            # No original test has a per-method exception or filter.
            with ExitStack() as selected:
                if group['selector'] is not None:
                    selected.enter_context(patch.dict(os.environ, {group['selector']: str(manifest)}))
                groups.append(run_group(group, suite))
    after = source_pins()
    stable = after == before and all(sha256(Path(name).read_bytes()).hexdigest() == digest
                                    for name, digest in application.items())
    if cold_pin is not None:
        stable = stable and sha256(cold_path.read_bytes()).hexdigest() == cold_pin['sha256']
        stable = stable and sha256(Path(cold_pin['nested_path']).read_bytes()).hexdigest() == cold_pin['nested_sha256']
        stable = stable and sha256(Path(compiler_pin['path']).read_bytes()).hexdigest() == compiler_pin['sha256']
    anomaly_keys = ('errors', 'failures', 'skipped', 'expected_failures', 'unexpected_successes')
    clean = all(g['was_successful'] and g['actual_tests'] == len(g['planned'])
                and all(not g[key] for key in anomaly_keys) for g in groups)
    passed = (clean and stable and started == stopped == original['ordered_ids']
              and not reference_calls
              and all(counts['acknowledged:' + operation] > 0 for operation in OPERATIONS)
              and all(counts['public-receipt:' + operation] > 0 for operation in OPERATIONS))
    report = {'schema': 'hepta.hia.artifact-delivery-original-callers.v1',
        'status': 'PASS' if passed else 'FAIL', 'scope': scope,
        'original_baseline_commit': original['base_commit'],
        'original_fixture_baseline_commit': original['direct_original_fixture_base'],
        'modules': [r['module'] for r in original['modules']],
        'planned': original['ordered_ids'], 'started': started, 'stopped': stopped,
        'actual_tests': sum(g['actual_tests'] for g in groups), 'groups': groups,
        'wall_seconds': time.monotonic() - begin,
        'source_before': before, 'source_after': after,
        'source_and_application_unchanged': stable,
        'additional_manifest': str(manifest), 'additional_application_pins': application,
        'additional_fixed_private_sha256': sha256(admitted).hexdigest(),
        'cold_report': cold_pin, 'compiler': compiler_pin,
        'provider_observations': dict(counts),
        'provider_observations_by_test': {key: dict(value) for key, value in per_test.items()},
        'acknowledgements': acknowledgements, 'reference_calls': reference_calls,
        'poison_scope': 'Only direct _read_exact calls in original public code with captured nonempty selection. No global reference16 ban. Withdrawal retains the original sealed-descriptor/operation assertions.',
        'observation_scope': 'Parent-process provider handoff and validated ACK/public receipt calls. No claim that Python wrappers instrument subprocess interiors.',
        'original_fixture_build_inputs_modified': False,
        'original_fixture_temporary_builds_claimed_retained': False,
        'whole_module_selectors': {'original-direct-63': 'original fixtures only',
                                  'additional-generic-37': PUBLIC_SELECTOR,
                                  'additional-store-32': STORE_SELECTOR},
        'all_seven_modules_unfiltered': True,
        'original_test_limits_deadlines_assertions_changed': False,
        'new_aggregate_wall_limit_added': False,
        'whole_project_dynamic_caller_closure_claimed': False,
        'installed_worker_qualified_by_this_gate': False,
        'whole_native_delivery_qualified': False}
    (evidence / 'report.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    print(json.dumps({key: report[key] for key in ('status', 'scope', 'actual_tests', 'wall_seconds')}))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
