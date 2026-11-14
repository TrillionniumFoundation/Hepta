"""Strict current-cold qualification of the optional five-image CLI route.

The original 43 test bytes and ordered IDs are retained.  Their production
fixture builder is explicitly bound to the new five-image producer; every such
call is recorded and independently re-admitted.  No development selection can
enter this driver, and test reports do not grant cold authority.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import time
import traceback
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ''):
    sys.path.insert(0, str(ROOT))

from tools.hia_cli_discovery_bundle_custody import (
    BUNDLE_SCHEMA, CAPACITY, LABELS, SCHEMAS, SOURCES, admit_cold, admit_compilation,
    binding, check_bindings, encoded, guard_authority, owner_sources, publish,
    read_json, require, retained_inputs,
)

COLD_FIXTURE = 'HEPTA_HIA_CLI_DISCOVERY_BUNDLE_COLD_FIXTURE'
DEVELOPMENT = 'HEPTA_HIA_CLI_DISCOVERY_BUNDLE_DEVELOPMENT_MANIFEST'
EVIDENCE = 'HEPTA_HIA_CLI_DISCOVERY_BUNDLE_EVIDENCE'
OLD_COLD = 'HEPTA_HIA_CLI_COLD_REPORT'
OLD_DEVELOPMENT = 'HEPTA_HIA_CLI_DEVELOPMENT_MANIFEST'
OLD_EVIDENCE = 'HEPTA_HIA_CLI_FIXTURE_EVIDENCE'
FIXTURE_SCHEMA = 'hepta.hia.cli-discovery-bundle-cold-fixture.v1'
FIXTURE_STATUS = 'MATCHING_SOURCE_COLD_FIXTURE_BUILT'
CLASS = 'tests.test_hia_cli_discovery_routing_native.CliDiscoveryRoutingNativeTests'
NATIVE_METHODS = (
    'test_01_original_21_discovery_and_foreign_observations',
    'test_02_original_12_evaluation_order_and_retirement_observations',
    'test_03_original_three_admission_side_effect_controls',
    'test_04_original_four_foreign_error_lifetime_observations',
    'test_05_original_28_parser_contexts_and_complete_graphs',
    'test_06_original_three_routing_lost_ack_and_complete_vm_frames',
    'test_07_original_eight_parser_protocol_lifetime_and_complete_vm_frames',
    'test_08_actual_routing_step_reentry_is_rejected_before_second_native_entry',
    'test_09_inplace_metadata_mutation_retains_actual_foreign_semantics',
)
NATIVE_IDS = tuple(CLASS + '.' + name for name in NATIVE_METHODS)
ANOMALIES = ('failures', 'errors', 'skipped', 'expected_failures', 'unexpected_successes')
SECONDS = 180
CLEANUP_SECONDS = 3


def groups():
    return {'original_cli': tuple(retained_inputs()['original_ids']), 'routing': NATIVE_IDS}


def inspect_build(directory, authority):
    from tools.build_hia_cli_discovery_bundle import BUILD_SCHEMA, COLD_SCOPE, DEVELOPMENT_SCOPE
    directory = Path(directory).absolute()
    report_path, manifest_path = directory / 'build.json', directory / 'manifest.json'
    report, bundle = read_json(report_path.read_bytes()), read_json(manifest_path.read_bytes())
    expected_keys = {'schema', *[name + suffix for name in SOURCES
                                for suffix in ('_manifest', '_manifest_sha256')]}
    require(type(bundle) is dict and set(bundle) == expected_keys and bundle['schema'] == BUNDLE_SCHEMA,
            'complete five-image CLI manifest required')
    require(type(report) is dict and report.get('schema') == BUILD_SCHEMA
            and report.get('status') == 'NATIVE_CANDIDATE_BUILT'
            and report.get('scope') == (COLD_SCOPE if authority is not None else DEVELOPMENT_SCOPE)
            and report.get('matching_cold') is (authority is not None)
            and report.get('authority') == authority and report.get('bundle') == bundle
            and report.get('owner_sources_before') == owner_sources() == report.get('owner_sources_after')
            and type(report.get('compile_seconds')) is int and report['compile_seconds'] == 20
            and type(report.get('capacity')) is int and report['capacity'] == CAPACITY
            and report.get('ordinary_cli_activated') is False and report.get('whole_cli_native') is False
            and report.get('whole_native_delivery_qualified') is False
            and type(report.get('components')) is dict and set(report['components']) == set(SOURCES),
            'stale, incomplete or differently scoped CLI bundle build')
    compiler = Path(report['input_bindings'][0]['path'])
    if authority is not None:
        require(str(compiler) == authority['compiler']
                and report['compiler_sha256'] == authority['compiler_sha256'], 'current cold B3 differs')
        guard_authority(authority)
    require(sha256(compiler.read_bytes()).hexdigest() == report['compiler_sha256'], 'compiler bytes changed')
    all_bindings = [binding(report_path), binding(manifest_path)]
    components = {}
    for name, source_name in SOURCES.items():
        folder = directory / name
        target = folder / 'manifest.json'
        source = (ROOT / source_name).read_bytes()
        manifest = read_json(target.read_bytes())
        require(bundle[name + '_manifest'] == name + '/manifest.json'
                and bundle[name + '_manifest_sha256'] == sha256(target.read_bytes()).hexdigest()
                and type(manifest) is dict and set(manifest) == {
                    'schema', 'source_sha256', 'image_path', 'image_sha256', 'compiler_sha256'}
                and manifest['schema'] == SCHEMAS[name]
                and manifest['source_sha256'] == sha256(source).hexdigest()
                and manifest['image_path'] == LABELS[name] + '.image.bin'
                and manifest['compiler_sha256'] == report['compiler_sha256'],
                'CLI component manifest differs: ' + name)
        image = folder / manifest['image_path']
        require(sha256(image.read_bytes()).hexdigest() == manifest['image_sha256'], 'CLI component image changed')
        actual, observed = admit_compilation(folder, LABELS[name], compiler, source, image)
        require(report['components'][name] == {'manifest': manifest,
                'actual_compile_receipt': actual, 'observation_bindings': observed},
                'CLI component build does not match actual child observations')
        all_bindings.extend((*observed, binding(target), binding(ROOT / source_name)))
        components[name] = manifest
    check_bindings(report['input_bindings'])
    all_bindings = list({row['path']: row for row in all_bindings}.values())
    check_bindings(all_bindings)
    return {'manifest': str(manifest_path), 'build_report': str(report_path),
            'compiler': str(compiler), 'components': components, 'input_bindings': all_bindings}


def prepare_fixture(output, cold_report):
    from tools.build_hia_cli_discovery_bundle import build
    authority = admit_cold(cold_report)
    output = Path(output).absolute()
    require(not output.exists() and not output.is_symlink(), 'exclusive CLI fixture output required')
    output.mkdir(mode=0o700)
    build(output / 'build', authority['compiler'], authority['cold_report'])
    built = inspect_build(output / 'build', authority)
    guard_authority(authority)
    fixture = {'schema': FIXTURE_SCHEMA, 'status': FIXTURE_STATUS, 'authority': authority,
               'build': built, 'owner_sources': owner_sources(), 'matching_cold': True,
               'scope': 'MATCHING_CURRENT_SOURCE_COLD_CLI_DISCOVERY_BUNDLE',
               'ordinary_cli_activated': False, 'whole_cli_native': False,
               'whole_native_delivery_qualified': False}
    path = output / 'FIXTURE.json'
    publish(path, fixture)
    admit_fixture(path)
    return path


def admit_fixture(path):
    path = Path(path).resolve(strict=True)
    raw = path.read_bytes()
    value = read_json(raw)
    require(type(value) is dict and set(value) == {'schema', 'status', 'authority', 'build', 'owner_sources',
            'matching_cold', 'scope', 'ordinary_cli_activated', 'whole_cli_native', 'whole_native_delivery_qualified'}
            and value['schema'] == FIXTURE_SCHEMA and value['status'] == FIXTURE_STATUS
            and value['scope'] == 'MATCHING_CURRENT_SOURCE_COLD_CLI_DISCOVERY_BUNDLE'
            and value['matching_cold'] is True and value['ordinary_cli_activated'] is False
            and value['whole_cli_native'] is False and value['whole_native_delivery_qualified'] is False
            and type(value['authority']) is dict and type(value['build']) is dict,
            'strict current-cold CLI bundle fixture required')
    authority = admit_cold(value['authority']['cold_report'])
    require(authority == value['authority'] and value['owner_sources'] == owner_sources(),
            'CLI bundle fixture authority or owner sources changed')
    require(inspect_build(Path(value['build']['build_report']).parent, authority) == value['build'],
            'CLI bundle fixture differs from actual build')
    check_bindings(value['build']['input_bindings'])
    require(path.read_bytes() == raw, 'CLI fixture changed while being admitted')
    return value


def _flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from _flatten(item)
        else:
            yield item


def admit_result(report, group, request_sha):
    expected = list(groups()[group])
    require(type(report) is dict and report.get('schema') == 'hepta.hia.cli-discovery-bundle-test-observations.v1'
            and report.get('scope') == 'OBSERVATIONS_ONLY_NOT_COLD_AUTHORITY' and report.get('status') == 'PASS'
            and report.get('group') == group and report.get('request_sha256') == request_sha
            and report.get('loaded_ids') == expected == report.get('started_ids') == report.get('stopped_ids')
            and type(report.get('loaded')) is int and report['loaded'] == len(expected)
            and type(report.get('tests_run')) is int and report['tests_run'] == len(expected)
            and all(type(report.get(key)) is list and report[key] == [] for key in ANOMALIES)
            and report.get('source_and_inputs_unchanged') is True,
            'failed, incomplete or differently selected CLI bundle observations')
    if group == 'original_cli':
        calls = report.get('fixture_provider_calls')
        require(type(calls) is list and len(calls) == 3
                and sum(row.get('status') == 'BUILT_AND_READ_BACK' for row in calls) == 2
                and sum(row.get('status') == 'REJECTED_BEFORE_BUILD' for row in calls) == 1,
                'original CLI fixture provider calls were not completely observed')


def _child(request_path):
    raw = Path(request_path).read_bytes()
    request = read_json(raw)
    require(type(request) is dict and set(request) == {'schema', 'group', 'fixture', 'fixture_binding',
            'source_manifest', 'controls_evidence', 'output'}
            and request['schema'] == 'hepta.hia.cli-discovery-bundle-test-request.v1'
            and request['group'] in groups(), 'invalid CLI bundle observation request')
    require(DEVELOPMENT not in os.environ and OLD_DEVELOPMENT not in os.environ
            and os.environ.get(COLD_FIXTURE) == request['fixture']
            and os.environ.get(EVIDENCE) == request['controls_evidence'], 'mixed CLI bundle fixture selection')
    require(binding(request['fixture']) == request['fixture_binding'], 'CLI fixture changed')
    fixture = admit_fixture(request['fixture'])
    authority = fixture['authority']
    require(authority['source_manifest'] == request['source_manifest'], 'CLI child cold source map differs')
    expected = groups()[request['group']]
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromNames(expected)
    ids = [test.id() for test in _flatten(suite)]
    require(tuple(ids) == expected and not loader.errors, 'exact CLI bundle test discovery failed')
    report = {'schema': 'hepta.hia.cli-discovery-bundle-test-observations.v1',
              'scope': 'OBSERVATIONS_ONLY_NOT_COLD_AUTHORITY', 'status': 'FAIL',
              'group': request['group'], 'request_sha256': sha256(raw).hexdigest(),
              'loaded_ids': ids, 'loaded': suite.countTestCases(), 'started_ids': [], 'stopped_ids': [],
              'fixture_provider_calls': []}
    class Result(unittest.TextTestResult):
        def startTest(self, test):
            report['started_ids'].append(test.id()); super().startTest(test)
        def stopTest(self, test):
            report['stopped_ids'].append(test.id()); super().stopTest(test)
    def fixture_provider(output, compiler, cold_report):
        from tools.build_hia_cli_discovery_bundle import build
        row = {'output': str(output), 'compiler': str(compiler), 'cold_report': str(cold_report),
               'provider': 'tools.build_hia_cli_discovery_bundle.build', 'status': 'REJECTED_BEFORE_BUILD'}
        report['fixture_provider_calls'].append(row)
        actual = admit_cold(cold_report)
        require(actual == authority and Path(compiler).resolve(strict=True) == Path(authority['compiler']),
                'original CLI fixture requested a different cold authority')
        manifest = build(output, compiler, cold_report)
        row['build'] = inspect_build(Path(manifest).parent, authority)
        row['status'] = 'BUILT_AND_READ_BACK'
        return manifest
    try:
        if request['group'] == 'original_cli':
            require(os.environ.get(OLD_COLD) == authority['cold_report']
                    and os.environ.get(OLD_EVIDENCE) == request['controls_evidence'],
                    'original CLI tests must use their unchanged cold branch')
            from tools import build_hia_cli_native as old_builder
            with patch.object(old_builder, 'build', fixture_provider):
                result = unittest.TextTestRunner(stream=sys.stderr, verbosity=2, resultclass=Result).run(suite)
        else:
            result = unittest.TextTestRunner(stream=sys.stderr, verbosity=2, resultclass=Result).run(suite)
        report.update(tests_run=result.testsRun,
            failures=[(t.id(), text) for t, text in result.failures],
            errors=[(t.id(), text) for t, text in result.errors],
            skipped=[(t.id(), reason) for t, reason in result.skipped],
            expected_failures=[(t.id(), text) for t, text in result.expectedFailures],
            unexpected_successes=[t.id() for t in result.unexpectedSuccesses])
        admit_fixture(request['fixture'])
        for row in report['fixture_provider_calls']:
            if row['status'] == 'BUILT_AND_READ_BACK':
                require(inspect_build(Path(row['build']['build_report']).parent, authority) == row['build'],
                        'original CLI fixture output changed after tests')
        report.update(source_and_inputs_unchanged=True, status='PASS')
        admit_result(report, request['group'], sha256(raw).hexdigest())
    except BaseException:
        report.update(status='FAIL', traceback=traceback.format_exc())
    finally:
        publish(request['output'], report)
    return 0 if report['status'] == 'PASS' else 1


def _owned(command, output, environment):
    from tools.hia_selfhost_process_owner import run_owned
    output = Path(output); output.mkdir(mode=0o700)
    return run_owned(command, cwd=ROOT, env=environment,
        stdout_path=output/'stdout.raw', stderr_path=output/'stderr.raw',
        receipt_path=output/'OWNER.json', qualification_seconds=SECONDS, cleanup_seconds=CLEANUP_SECONDS)


def _owner_pass(owner):
    return (type(owner) is dict and owner.get('status') == 'OWNED_PROCESS_COMPLETED'
        and type(owner.get('returncode')) is int and owner['returncode'] == 0
        and type(owner.get('qualification_seconds')) is int and owner['qualification_seconds'] == SECONDS
        and type(owner.get('cleanup_seconds')) is int and owner['cleanup_seconds'] == CLEANUP_SECONDS
        and owner.get('timed_out') is False and owner.get('exit_observed_before_deadline') is True
        and owner.get('cleanup', {}).get('complete') is True and owner.get('cleanup', {}).get('observed_echild') is True)


def qualify(output, cold_report):
    authority = admit_cold(cold_report)
    output = Path(output).absolute()
    require(not output.exists() and not output.is_symlink(), 'exclusive CLI qualification directory required')
    output.mkdir(mode=0o700)
    environment = {k:v for k,v in os.environ.items() if not k.startswith('HEPTA_') and k != 'PYTHONPATH'}
    environment['PYTHONDONTWRITEBYTECODE'] = '1'
    selected = groups()
    report = {'schema': 'hepta.hia.cli-discovery-bundle-qualification.v1', 'status': 'FAIL',
              'scope': 'MATCHING_CURRENT_SOURCE_COLD_CLI_DISCOVERY_BUNDLE', 'qualification_complete': False,
              'authority': authority, 'source_before': authority['source_manifest'],
              'expected_ids': [item for ids in selected.values() for item in ids],
              'original_cli_count': 43, 'new_native_methods': len(NATIVE_IDS), 'groups': [],
              'compile_seconds': 20, 'capacity': CAPACITY, 'vm_steps': 10000000,
              'vm_heap_bytes': 8 << 20, 'vm_call_depth': 128,
              'group_seconds': SECONDS, 'cleanup_seconds': CLEANUP_SECONDS,
              'ordinary_cli_activated': False, 'whole_cli_native': False, 'whole_native_delivery_qualified': False}
    start = time.monotonic_ns(); fixture_path = output/'fixture/FIXTURE.json'
    try:
        report['preparation_owner'] = _owned([sys.executable, '-I', '-B', str(Path(__file__).resolve()),
            '--_prepare', str(output/'fixture'), '--cold-report', authority['cold_report']], output/'prepare', environment)
        require(_owner_pass(report['preparation_owner']), 'CLI cold fixture preparation failed')
        admit_fixture(fixture_path)
        all_passed = True
        for group in selected:
            guard_authority(authority)
            folder = output/group; folder.mkdir(mode=0o700)
            controls = folder/'controls'; controls.mkdir(mode=0o700)
            request = {'schema': 'hepta.hia.cli-discovery-bundle-test-request.v1', 'group': group,
                'fixture': str(fixture_path), 'fixture_binding': binding(fixture_path),
                'source_manifest': authority['source_manifest'], 'controls_evidence': str(controls),
                'output': str(folder/'REPORT.json')}
            request_path = folder/'REQUEST.json'; publish(request_path, request)
            env = {**environment, COLD_FIXTURE:str(fixture_path), EVIDENCE:str(controls)}
            if group == 'original_cli':
                env.update({OLD_COLD:authority['cold_report'], OLD_EVIDENCE:str(controls)})
            item = {'group':group, 'status':'FAIL'}
            try:
                item['owner'] = _owned([sys.executable, '-I', '-B', str(Path(__file__).resolve()),
                    '--_child', str(request_path)], folder/'command', env)
                item['observations'] = read_json((folder/'REPORT.json').read_bytes())
                admit_result(item['observations'], group, sha256(request_path.read_bytes()).hexdigest())
                require(_owner_pass(item['owner']), 'CLI observation owner did not complete under original limits')
                item['status'] = 'PASS'
            except BaseException:
                item['traceback'] = traceback.format_exc(); all_passed = False
            report['groups'].append(item)
        require(all_passed and len(report['groups']) == len(selected), 'complete CLI conjunction failed')
        report.update(status='MATCHING_CURRENT_SOURCE_COLD_CLI_DISCOVERY_BUNDLE_PASS', qualification_complete=True)
    except BaseException:
        report['traceback'] = traceback.format_exc()
    finally:
        try:
            guard_authority(authority)
            if fixture_path.exists(): admit_fixture(fixture_path)
            from tools.build_hia_json_preflight import current_sources
            report.update(source_after=current_sources(), source_and_inputs_unchanged=True)
        except BaseException:
            report.update(status='FAIL', qualification_complete=False, source_and_inputs_unchanged=False,
                          final_guard_error=traceback.format_exc())
        report['wall_ns'] = time.monotonic_ns()-start
        publish(output/'REPORT.json', report)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cold-report', type=Path); parser.add_argument('--evidence', type=Path)
    parser.add_argument('--_prepare', type=Path); parser.add_argument('--_child', type=Path)
    args = parser.parse_args(argv)
    if args._child is not None:
        require(args.cold_report is None and args.evidence is None and args._prepare is None, 'child options are separate')
        return _child(args._child)
    if args._prepare is not None:
        require(args.cold_report is not None and args.evidence is None, 'real current cold is required')
        print(prepare_fixture(args._prepare, args.cold_report)); return 0
    require(args.cold_report is not None and args.evidence is not None, '--cold-report and --evidence required')
    value = qualify(args.evidence, args.cold_report)
    print(json.dumps({k:value[k] for k in ('status', 'scope', 'qualification_complete')}))
    return 0 if value['qualification_complete'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
