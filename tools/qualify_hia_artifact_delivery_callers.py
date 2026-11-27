"""Run all 132 original artifact callers and two exact current successor tests.

Original fixtures, method identities and deadlines remain unchanged. The fixed
current six-result discovery assertion is admitted by its complete source
inverse and reported explicitly; it changes no runtime budget.
Reference16 retains its original unselected policy. NDU19 and assembly18 retain
explicit generic publication; the two pinned assembly successors also run; all NativeTools32 use the original supported
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


_DIAGNOSTICS_CALLER = 'tests/test_hia_agent_native_tools.py'
_DIAGNOSTICS_HELPER = 'tests/hia_caller_diagnostics_admission.py'
_DIAGNOSTICS_HELPER_PIN = {'bytes': 5185, 'sha256': '9e11b98d395229bcb38f0b36094da8bffb37e694ba1ad4afdfa998a8392dd578'}
_DIAGNOSTICS_AUTHORITY = 'tests/fixtures/caller_deadline_diagnostics_v1.json'
_DIAGNOSTICS_AUTHORITY_PIN = {'bytes': 3545, 'sha256': '53aff1f370ac337d6246a0179f8b6d5c346fcc44ffd7f2187c515c95c663f97c'}


def _source_pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def _admit_diagnostic_source(capture, name, raw, original_digest):
    if name != _DIAGNOSTICS_CALLER:
        raise ValueError('an original complete caller module changed: ' + name)
    helper, authority = capture(_DIAGNOSTICS_HELPER), capture(_DIAGNOSTICS_AUTHORITY)
    if (_source_pin(helper) != _DIAGNOSTICS_HELPER_PIN
            or _source_pin(authority) != _DIAGNOSTICS_AUTHORITY_PIN):
        raise ValueError('caller diagnostic source authority changed')
    from tests import hia_caller_diagnostics_admission as diagnostic
    if Path(diagnostic.__file__).read_bytes() != helper:
        raise ValueError('caller imported a different diagnostic admission')
    return diagnostic.admit(name, raw, original_digest, authority)


def bind_admission_to_source_capture(proof, source_digests):
    for name, expected in proof['captured_files'].items():
        if source_digests.get(name) != expected['sha256']:
            raise ValueError('caller admission differs from actual source capture: ' + name)


_HISTORY_HELPER = 'tools/hia_artifact_caller_source_history.py'
_HISTORY_HELPER_PIN = {'bytes': 10362, 'sha256': 'd2e9e9ee425e8be44023ca169c5d3a887a3bcbb0b7bab28e91b6f4642bc3fe1e'}
_HISTORY_CURRENT = {
    'tests/test_hia_agent_assembly.py': {
        'bytes': 15006, 'sha256': '367ba5cf0280d2a0cca2f42d20387d81982b5b2b45f439d3898fb51905eff339'},
    'tests/test_hia_artifact_publication_native.py': {
        'bytes': 19607, 'sha256': 'de92f2dc85c187fb0834de801899801c6cb1c36ab03909dab07554bcf15ee0dc'},
    'tests/test_hia_agent_native_tools.py': {
        'bytes': 47052, 'sha256': '64462e8735d8be3838396808dc05391e4437b2dba093fcc265468df6abb4cb70'},
}
_HISTORY_NATIVE_SIX = {
    'bytes': 47052, 'sha256': '9af14ac9dc15cafcd60be2c4e8690fafa778b41bc66c73379e9490ac67376fc2'}


def _history_current(name, actual):
    return (actual == _HISTORY_CURRENT.get(name)
            or (name == _DIAGNOSTICS_CALLER and actual == _HISTORY_NATIVE_SIX))


_ASSEMBLY_PATH = 'tests/test_hia_agent_assembly.py'
_ASSEMBLY_ADDED_IDS = (
    'tests.test_hia_agent_assembly.HIAAgentAssemblyTests.test_package_renderer_keeps_independent_roundtrip_and_profile_errors',
    'tests.test_hia_agent_assembly.HIAAgentAssemblyTests.test_package_syntax_document_still_requires_whole_core_admission',
)


def _admit_reviewed_source(root, capture, name, raw):
    if not _history_current(name, _source_pin(raw)):
        return raw, None
    helper = capture(_HISTORY_HELPER)
    if _source_pin(helper) != _HISTORY_HELPER_PIN:
        raise ValueError('artifact caller complete source-history helper differs')
    from tools import hia_artifact_caller_source_history as history
    if Path(history.__file__).read_bytes() != helper:
        raise ValueError('artifact caller imported different source history')
    restored, proof = history.reviewed(
        root, name, raw,
        take=lambda path: capture(Path(path).relative_to(root).as_posix()))
    if proof is None or proof['path'] != name or proof['physical'] != _source_pin(raw):
        raise ValueError('artifact caller source history lost physical input identity')
    return restored, proof


def declared_execution_groups(original, admission):
    """Keep all original identities and append only the two pinned actual methods."""
    groups = [{'name': 'original-direct-63', 'modules': original['direct_modules'],
               'ordered_ids': original['direct_ordered_ids'], 'count': 63, 'selector': None},
              *original['additional_groups']]
    groups = json.loads(json.dumps(groups))
    original_ids = original['ordered_ids']
    if (len(original_ids) != 132 or len(set(original_ids)) != 132
            or sum((group['ordered_ids'] for group in groups), []) != original_ids
            or admission['original_ordered_ids'] != original_ids):
        raise ValueError('artifact original complete execution groups differ')
    histories = admission.get('reviewed_integrated_source_adjustments', {})
    if type(histories) is not dict or not set(histories) <= set(_HISTORY_CURRENT):
        raise ValueError('artifact execution source-history members differ')
    captured = admission['captured_files']
    for name, proof in histories.items():
        expected_added = list(_ASSEMBLY_ADDED_IDS) if name == _ASSEMBLY_PATH else []
        if (proof['path'] != name or not _history_current(name, proof['physical'])
                or captured.get(name) != proof['physical']
                or captured.get(_HISTORY_HELPER) != _HISTORY_HELPER_PIN
                or proof['added_ordered_ids'] != expected_added
                or proof['complete_original_inverse_verified'] is not True
                or proof['complete_current_forward_replay_verified'] is not True
                or proof['terminal_reread_identical'] is not True
                or proof['whole_native_delivery_qualified'] is not False):
            raise ValueError('artifact execution history is not bound to exact captured source')
        if name == _DIAGNOSTICS_CALLER:
            has_six = proof['physical'] == _HISTORY_NATIVE_SIX
            assertion = proof.get('native_result_assertion_successor')
            if has_six != (assertion is not None):
                raise ValueError('artifact native-result assertion history is missing or spurious')
            if has_six:
                expected_assertion = {
                    'path': name, 'physical': _HISTORY_NATIVE_SIX,
                    'predecessor': _HISTORY_CURRENT[name],
                    'helper': {'path': 'tools/hia_native_result_caller_history.py',
                        'bytes': 2868, 'sha256': 'e1e1edfcaeaf0f80f7b2b51604afff87908d45419f1aef87fbf8408589cc4248'},
                    'authority': {'path': 'tests/fixtures/hia_native_result_caller_history_v1.json',
                        'bytes': 1087, 'sha256': 'dccd8c04824fdaa3ac7cf638fd487622a8ecfd198236cf0108ef8dc2edb10130'},
                    'definition': 'ArtifactContractTests.test_discovery_is_readable_and_source_bound',
                    'assertion': 'support["limits"]["function_results"]',
                    'previous_expected': 3, 'current_expected': 6, 'exact_byte_splices': 1,
                    'complete_original_inverse_verified': True,
                    'complete_current_forward_replay_verified': True,
                    'original_deadlines_changed': False, 'original_runtime_budgets_changed': False,
                }
                if (assertion != expected_assertion
                        or any(type(assertion[key]) is not int
                               for key in ('previous_expected', 'current_expected', 'exact_byte_splices'))
                        or any(type(assertion[key]) is not bool
                               for key in ('complete_original_inverse_verified',
                                           'complete_current_forward_replay_verified',
                                           'original_deadlines_changed', 'original_runtime_budgets_changed'))
                        or captured.get(assertion['helper']['path']) != {
                            key: assertion['helper'][key] for key in ('bytes', 'sha256')}
                        or captured.get(assertion['authority']['path']) != {
                            key: assertion['authority'][key] for key in ('bytes', 'sha256')}):
                    raise ValueError('artifact native-result assertion history differs')
    for name in _HISTORY_CURRENT:
        if _history_current(name, captured.get(name)) != (name in histories):
            raise ValueError('artifact exact current source cannot omit its history')
    assembly_current = captured.get(_ASSEMBLY_PATH) == _HISTORY_CURRENT[_ASSEMBLY_PATH]
    if assembly_current != (_ASSEMBLY_PATH in histories):
        raise ValueError('artifact current assembly cannot omit its successor identities')
    added = list(_ASSEMBLY_ADDED_IDS) if assembly_current else []
    if added:
        records = {row['module']: row for row in original['modules']}
        for group in groups:
            old_ids = group['ordered_ids']
            expanded = []
            for module in group['modules']:
                ids = list(records[module]['ordered_ids'])
                if records[module]['path'] == _ASSEMBLY_PATH:
                    if set(ids) & set(added):
                        raise ValueError('artifact successor reuses an original identity')
                    ids = sorted([*ids, *added])
                expanded.extend(ids)
            if [name for name in expanded if name in set(old_ids)] != old_ids:
                raise ValueError('artifact successor displaced original ordered identities')
            group['original_ordered_ids'] = old_ids
            group['successor_added_ordered_ids'] = [name for name in expanded if name in added]
            group['ordered_ids'], group['count'] = expanded, len(expanded)
    planned = sum((group['ordered_ids'] for group in groups), [])
    if (len(planned) != 132 + len(added) or len(set(planned)) != len(planned)
            or [name for name in planned if name in set(original_ids)] != original_ids
            or [name for name in planned if name not in set(original_ids)] != added):
        raise ValueError('artifact complete original and successor execution table differs')
    return groups, planned, added


def admit_inventory(root=None, *, with_source_admission=False):
    # The original no-argument API still returns the unchanged complete fixture.
    root, captured = Path(ROOT if root is None else root), {}

    def capture(name):
        raw = (root / name).read_bytes()
        if name in captured and captured[name] != raw:
            raise ValueError('artifact caller source changed between captures: ' + name)
        captured[name] = raw
        return raw

    raw = capture(FIXTURE)
    if sha256(raw).hexdigest() != FIXTURE_SHA256:
        raise ValueError('complete original artifact caller inventory changed')
    value = json.loads(raw)
    if ((value['direct_count'], value['additional_count'], value['total_count']) != (63, 69, 132)
            or len(value['modules']) != 7 or len(value['ordered_ids']) != 132):
        raise ValueError('original complete seven-module 132-method scope changed')
    direct_raw = capture(value['direct_original_fixture'])
    if sha256(direct_raw).hexdigest() != value['direct_original_fixture_sha256']:
        raise ValueError('independent original four-module artifact fixture changed')
    if json.loads(direct_raw)['declared_original_test_ids'] != value['direct_ordered_ids']:
        raise ValueError('independent original complete 63 IDs differ')
    diagnostics, histories = {}, {}
    for record in value['modules']:
        current = capture(record['path'])
        current, history = _admit_reviewed_source(root, capture, record['path'], current)
        if history is not None:
            histories[record['path']] = history
        if len(current) != record['bytes'] or sha256(current).hexdigest() != record['sha256']:
            relation = _admit_diagnostic_source(capture, record['path'], current, record['sha256'])
            if relation['original']['bytes'] != record['bytes']:
                raise ValueError('original caller source extent changed: ' + record['path'])
            diagnostics[record['path']] = relation
    additional = value['additional_groups']
    if ([group['count'] for group in additional] != [37, 32]
            or [group['selector'] for group in additional] != [PUBLIC_SELECTOR, STORE_SELECTOR]
            or sum((group['ordered_ids'] for group in additional), []) != value['additional_ordered_ids']
            or value['direct_ordered_ids'] + value['additional_ordered_ids'] != value['ordered_ids']):
        raise ValueError('original complete module grouping or ordering changed')
    for name, data in captured.items():
        if (root / name).read_bytes() != data:
            raise ValueError('artifact caller captured bytes changed: ' + name)
    proof = {
        'schema': 'hepta.hia.artifact-delivery-caller-source-admission.v1',
        'authority': {'path': FIXTURE, **_source_pin(raw)},
        'original_files': {record['path']: record['sha256'] for record in value['modules']},
        'original_modules': [record['module'] for record in value['modules']],
        'original_ordered_ids': list(value['ordered_ids']),
        'original_direct_ordered_ids': list(value['direct_ordered_ids']),
        'original_additional_ordered_ids': list(value['additional_ordered_ids']),
        'reviewed_diagnostic_source_adjustments': diagnostics,
        **({'reviewed_integrated_source_adjustments': histories} if histories else {}),
        'captured_files': {name: _source_pin(data) for name, data in captured.items()},
        'terminal_reread_identical': True, 'original_inventory_bytes_unchanged': True,
        'production_source_exceptions': [], 'whole_native': False,
    }
    return (value, proof) if with_source_admission else value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--cold-report', type=Path)
    mode.add_argument('--development-manifest', type=Path)
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()
    from tools.run_hia_unittest_gate import load_declared_suite
    from tools.hia_selfhost_contract import file_digests
    original, source_admission = admit_inventory(ROOT, with_source_admission=True)
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
    declared_groups, planned, added_ids = declared_execution_groups(original, source_admission)
    suites = []
    for group in declared_groups:
        suite, ids = load_declared_suite(group['modules'])
        if list(ids) != group['ordered_ids'] or suite.countTestCases() != group['count']:
            raise ValueError('real complete unittest discovery differs: ' + group['name'])
        suites.append(suite)

    def source_pins():
        extras = [FIXTURE, original['direct_original_fixture'],
                  'tools/qualify_hia_artifact_delivery_callers.py',
                  *(r['path'] for r in original['modules']),
                  *source_admission['captured_files']]
        return {**file_digests(), **{name: sha256((ROOT / name).read_bytes()).hexdigest() for name in extras}}

    before = source_pins()
    bind_admission_to_source_capture(source_admission, before)

    cold_pin = compiler_pin = None
    native_cold_mode, cold_inputs, native_sources = False, {}, None

    def take_cold(path):
        path = Path(path)
        raw = path.read_bytes()
        if path in cold_inputs and cold_inputs[path] != raw:
            raise ValueError('artifact caller cold input changed: ' + str(path))
        cold_inputs[path] = raw
        return raw

    if cold_path is not None:
        cold_raw = take_cold(cold_path)
        cold = json.loads(cold_raw)
        from tools.hia_native_cold_admission import SCHEMA as NATIVE_COLD_SCHEMA
        native_cold_mode = cold.get('schema') == NATIVE_COLD_SCHEMA
        if native_cold_mode:
            from tools.hia_component_cold_readback import native_cold_compiler
            compiler, compiler_bytes, native_sources = native_cold_compiler(
                ROOT, cold_path, read=take_cold)
            cold_pin = {'path': str(cold_path), 'sha256': sha256(cold_raw).hexdigest(),
                        'source_domain': 'NATIVE_CORE_AUTHORITY',
                        'captured_files': {str(path): _source_pin(raw)
                                           for path, raw in cold_inputs.items()}}
            compiler_pin = {'path': str(compiler), 'sha256': sha256(compiler_bytes).hexdigest()}
        else:
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
        scope = ('MATCHING_SOURCE_COLD_ORIGINAL_ARTIFACT_132_PLUS_REVIEWED_SUCCESSOR_2'
                 if added_ids else 'MATCHING_SOURCE_COLD_ORIGINAL_ARTIFACT_63_PLUS_ADDITIONAL_69')
    else:
        manifest = args.development_manifest.resolve(strict=True)
        executable = manifest.parent / 'hia-artifact'
        scope = ('EXPLICIT_DEVELOPMENT_ORIGINAL_ARTIFACT_132_PLUS_REVIEWED_SUCCESSOR_2'
                 if added_ids else 'EXPLICIT_DEVELOPMENT_ORIGINAL_ARTIFACT_63_PLUS_ADDITIONAL_69')
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
    bind_admission_to_source_capture(source_admission, after)
    stable = after == before and all(sha256(Path(name).read_bytes()).hexdigest() == digest
                                    for name, digest in application.items())
    if cold_pin is not None:
        stable = stable and sha256(cold_path.read_bytes()).hexdigest() == cold_pin['sha256']
        if native_cold_mode:
            final_compiler, final_bytes, final_sources = native_cold_compiler(
                ROOT, cold_path, read=take_cold)
            stable = (stable and str(final_compiler) == compiler_pin['path']
                      and sha256(final_bytes).hexdigest() == compiler_pin['sha256']
                      and final_sources == native_sources
                      and all(path.read_bytes() == raw for path, raw in cold_inputs.items()))
        else:
            stable = stable and sha256(Path(cold_pin['nested_path']).read_bytes()).hexdigest() == cold_pin['nested_sha256']
        stable = stable and sha256(Path(compiler_pin['path']).read_bytes()).hexdigest() == compiler_pin['sha256']
    anomaly_keys = ('errors', 'failures', 'skipped', 'expected_failures', 'unexpected_successes')
    clean = all(g['was_successful'] and g['actual_tests'] == len(g['planned'])
                and all(not g[key] for key in anomaly_keys) for g in groups)
    passed = (clean and stable and started == stopped == planned
              and not reference_calls
              and all(counts['acknowledged:' + operation] > 0 for operation in OPERATIONS)
              and all(counts['public-receipt:' + operation] > 0 for operation in OPERATIONS))
    assertion_successors = [
        proof['native_result_assertion_successor']
        for proof in source_admission.get('reviewed_integrated_source_adjustments', {}).values()
        if 'native_result_assertion_successor' in proof]
    report = {'schema': ('hepta.hia.artifact-delivery-original-callers.v2'
                         if added_ids or native_cold_mode else 'hepta.hia.artifact-delivery-original-callers.v1'),
        'status': 'PASS' if passed else 'FAIL', 'scope': scope,
        'original_baseline_commit': original['base_commit'],
        'original_fixture_baseline_commit': original['direct_original_fixture_base'],
        'modules': [r['module'] for r in original['modules']],
        'planned': planned, 'started': started, 'stopped': stopped,
        'original_planned': list(original['ordered_ids']),
        'original_count': 132, 'reviewed_successor_added_ids': added_ids,
        'reviewed_successor_added_count': len(added_ids),
        'all_original_methods_executed_in_order':
            [name for name in started if name in set(original['ordered_ids'])] == original['ordered_ids'],
        'all_reviewed_successor_methods_executed':
            [name for name in started if name in set(added_ids)] == added_ids,
        'actual_tests': sum(g['actual_tests'] for g in groups), 'groups': groups,
        'wall_seconds': time.monotonic() - begin,
        'source_before': before, 'source_after': after,
        'caller_source_admission': source_admission,
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
        'original_test_limits_deadlines_assertions_changed': bool(assertion_successors),
        'original_test_deadlines_changed': False,
        'original_test_runtime_budgets_changed': False,
        'reviewed_native_result_assertion_successors': assertion_successors,
        'new_aggregate_wall_limit_added': False,
        'whole_project_dynamic_caller_closure_claimed': False,
        'installed_worker_qualified_by_this_gate': False,
        'whole_native_delivery_qualified': False}
    (evidence / 'report.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    print(json.dumps({key: report[key] for key in ('status', 'scope', 'actual_tests', 'wall_seconds')}))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
