"""Strict matching-current-source qualification of the discovery JSON owner.

This hosted driver has no development option. The original 61 machine cases,
six independent full-buffer VM cases and their limits remain separate named
observations. Only a real current cold B3 can prepare this fixture.
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

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ''}:
    sys.path.insert(0, str(ROOT))

from tools.hia_cli_discovery_custody import (
    admit_cold, admit_compilation, binding, check_bindings, encoded, guard_authority,
    owner_sources, publish, read_json, require,
)

COLD_FIXTURE = 'HEPTA_HIA_CLI_DISCOVERY_JSON_COLD_FIXTURE'
EVIDENCE = 'HEPTA_HIA_CLI_DISCOVERY_JSON_EVIDENCE'
DEVELOPMENT = 'HEPTA_HIA_CLI_DISCOVERY_JSON_DEVELOPMENT_MANIFEST'
FIXTURE_SCHEMA = 'hepta.hia.cli-discovery-json-cold-fixture.v1'
FIXTURE_STATUS = 'MATCHING_SOURCE_COLD_FIXTURE_BUILT'
MODULE = 'tests.test_hia_cli_discovery_json'
CLASS = MODULE + '.CliDiscoveryJsonNativeTests'
GROUPS = {
    'native': (CLASS + '.test_01_all_original_61_native_observations',),
    'vm': (CLASS + '.test_02_all_original_six_vm_full_buffers',),
    'runtime': (CLASS + '.test_03_public_byte_api_does_not_call_python_semantic_owners',),
    'installed': (CLASS + '.test_04_real_portable_wheel_resource_and_fresh_binding',),
}
EXPECTED_IDS = tuple(item for values in GROUPS.values() for item in values)
ANOMALIES = ('failures', 'errors', 'skipped', 'expected_failures', 'unexpected_successes')
SECONDS = 180
CLEANUP_SECONDS = 3


def _built(directory, authority):
    from tools.build_hia_cli_discovery_json import COLD_SCOPE, LABEL
    from hepta.hia_cli_discovery_json_native import SOURCE_NAME, SCHEMA
    directory = Path(directory)
    report_path, manifest_path = directory / 'build.json', directory / 'manifest.json'
    report, manifest = read_json(report_path.read_bytes()), read_json(manifest_path.read_bytes())
    source = (ROOT / SOURCE_NAME).read_bytes()
    require(type(report) is dict and report.get('schema') == 'hepta.hia.cli-discovery-json-build.v1'
            and report.get('status') == 'NATIVE_CANDIDATE_BUILT' and report.get('scope') == COLD_SCOPE
            and report.get('matching_cold') is True and report.get('authority') == authority
            and report.get('owner_sources_before') == owner_sources() == report.get('owner_sources_after')
            and type(report.get('compile_seconds')) is int and report['compile_seconds'] == 20
            and type(report.get('capacity')) is int and report['capacity'] == 1048576,
            'development or stale discovery build cannot prepare a cold fixture')
    require(type(manifest) is dict and set(manifest) == {'schema', 'source_sha256', 'image_path',
            'image_sha256', 'compiler_sha256'} and manifest['schema'] == SCHEMA
            and manifest['image_path'] == LABEL + '.image.bin'
            and manifest['source_sha256'] == sha256(source).hexdigest()
            and manifest['compiler_sha256'] == authority['compiler_sha256']
            and report.get('manifest') == manifest, 'discovery manifest binding differs')
    image = directory / manifest['image_path']
    require(sha256(image.read_bytes()).hexdigest() == manifest['image_sha256'], 'discovery image changed')
    actual, observations = admit_compilation(directory, LABEL, authority['compiler'], source, image)
    require(report.get('native_compile_receipt') == actual, 'discovery build receipt differs from actual child')
    check_bindings(report['input_bindings'])
    return {'manifest': str(manifest_path.absolute()), 'build_report': str(report_path.absolute()),
            'image': str(image.absolute()), 'image_sha256': manifest['image_sha256'],
            'source_sha256': manifest['source_sha256'],
            'input_bindings': list({row['path']: row for row in observations + [
                binding(manifest_path), binding(report_path), binding(ROOT / SOURCE_NAME)]}.values())}


def prepare_fixture(output, cold_report):
    from tools.build_hia_cli_discovery_json import build
    authority = admit_cold(cold_report)
    output = Path(output).absolute()
    require(not output.exists() and not output.is_symlink(), 'exclusive discovery fixture directory required')
    output.mkdir(mode=0o700)
    build(output / 'build', Path(authority['compiler']), Path(authority['cold_report']))
    built = _built(output / 'build', authority)
    guard_authority(authority)
    fixture = {'schema': FIXTURE_SCHEMA, 'status': FIXTURE_STATUS, 'authority': authority,
               'build': built, 'owner_sources': owner_sources(), 'matching_cold': True,
               'scope': 'MATCHING_SOURCE_COLD_CLI_DISCOVERY_JSON',
               'ordinary_cli_activated': False, 'whole_cli_native': False,
               'whole_native_delivery_qualified': False}
    path = output / 'FIXTURE.json'
    publish(path, fixture)
    admit_fixture(path)
    return path


def admit_fixture(path):
    """Fresh actual cold + build inputs, before each independent observation."""
    path = Path(path).resolve(strict=True)
    raw = path.read_bytes()
    value = read_json(raw)
    require(type(value) is dict and set(value) == {'schema', 'status', 'authority', 'build', 'owner_sources',
                'matching_cold', 'scope', 'ordinary_cli_activated', 'whole_cli_native',
                'whole_native_delivery_qualified'}
            and value['schema'] == FIXTURE_SCHEMA and value['status'] == FIXTURE_STATUS
            and value['matching_cold'] is True
            and value['scope'] == 'MATCHING_SOURCE_COLD_CLI_DISCOVERY_JSON'
            and value['ordinary_cli_activated'] is False and value['whole_cli_native'] is False
            and value['whole_native_delivery_qualified'] is False,
            'strict discovery cold fixture required')
    require(type(value['authority']) is dict and type(value['build']) is dict,
            'discovery cold authority and build required')
    authority = admit_cold(value['authority']['cold_report'])
    require(authority == value['authority'], 'discovery cold authority changed')
    require(value['owner_sources'] == owner_sources(), 'discovery fixture owner inputs changed')
    build_path = Path(value['build']['build_report'])
    require(_built(build_path.parent, authority) == value['build'], 'discovery fixture build identity differs')
    check_bindings(value['build']['input_bindings'])
    require(path.read_bytes() == raw, 'discovery fixture changed during admission')
    return value


def _flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from _flatten(item)
        else:
            yield item


def admit_result(report, group, request_sha):
    expected = list(GROUPS[group])
    require(type(report) is dict and report.get('schema') == 'hepta.hia.cli-discovery-json-test-observations.v1'
            and report.get('scope') == 'OBSERVATIONS_ONLY_NOT_COLD_AUTHORITY'
            and report.get('status') == 'PASS' and report.get('group') == group
            and report.get('request_sha256') == request_sha,
            'discovery child observation identity differs')
    require(report.get('loaded_ids') == expected == report.get('started_ids') == report.get('stopped_ids')
            and type(report.get('loaded')) is int and report['loaded'] == len(expected)
            and type(report.get('tests_run')) is int and report['tests_run'] == len(expected)
            and all(type(report.get(key)) is list and report[key] == [] for key in ANOMALIES)
            and report.get('source_and_inputs_unchanged') is True,
            'incomplete, skipped, or failed discovery child controls')


def _child(request_path):
    request_path = Path(request_path).resolve(strict=True)
    raw = request_path.read_bytes()
    request = read_json(raw)
    require(type(request) is dict and set(request) == {'schema', 'group', 'fixture', 'fixture_binding',
            'source_manifest', 'output', 'controls_evidence'}
            and request['schema'] == 'hepta.hia.cli-discovery-json-test-request.v1'
            and request['group'] in GROUPS, 'invalid discovery test request')
    require(DEVELOPMENT not in os.environ and os.environ.get(COLD_FIXTURE) == request['fixture']
            and os.environ.get(EVIDENCE) == request['controls_evidence'], 'mixed discovery fixture selection')
    require(binding(request['fixture']) == request['fixture_binding'], 'discovery fixture changed')
    fixture = admit_fixture(request['fixture'])
    require(fixture['authority']['source_manifest'] == request['source_manifest'], 'child cold source map differs')
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromNames(GROUPS[request['group']])
    ids = [test.id() for test in _flatten(suite)]
    require(ids == list(GROUPS[request['group']]) and not loader.errors, 'exact discovery test discovery failed')
    report = {'schema': 'hepta.hia.cli-discovery-json-test-observations.v1',
              'scope': 'OBSERVATIONS_ONLY_NOT_COLD_AUTHORITY', 'status': 'FAIL',
              'group': request['group'], 'request_sha256': sha256(raw).hexdigest(),
              'loaded_ids': ids, 'loaded': suite.countTestCases(), 'started_ids': [], 'stopped_ids': []}
    class Result(unittest.TextTestResult):
        def startTest(self, test):
            report['started_ids'].append(test.id())
            super().startTest(test)
        def stopTest(self, test):
            report['stopped_ids'].append(test.id())
            super().stopTest(test)
    try:
        result = unittest.TextTestRunner(stream=sys.stderr, verbosity=2, resultclass=Result).run(suite)
        report.update(tests_run=result.testsRun,
            failures=[(test.id(), text) for test, text in result.failures],
            errors=[(test.id(), text) for test, text in result.errors],
            skipped=[(test.id(), reason) for test, reason in result.skipped],
            expected_failures=[(test.id(), text) for test, text in result.expectedFailures],
            unexpected_successes=[test.id() for test in result.unexpectedSuccesses])
        admit_fixture(request['fixture'])
        report['source_and_inputs_unchanged'] = True
        report['status'] = 'PASS'
        admit_result(report, request['group'], sha256(raw).hexdigest())
    except BaseException:
        report.update(status='FAIL', traceback=traceback.format_exc())
    finally:
        publish(request['output'], report)
    return 0 if report['status'] == 'PASS' else 1


def _owned(command, output, environment):
    from tools.hia_selfhost_process_owner import run_owned
    output = Path(output)
    output.mkdir(mode=0o700)
    result = run_owned(command, cwd=ROOT, env=environment,
        stdout_path=output / 'stdout.raw', stderr_path=output / 'stderr.raw',
        receipt_path=output / 'OWNER.json', qualification_seconds=SECONDS,
        cleanup_seconds=CLEANUP_SECONDS)
    return result


def _owner_pass(owner):
    return (type(owner) is dict and owner.get('status') == 'OWNED_PROCESS_COMPLETED'
            and type(owner.get('returncode')) is int and owner['returncode'] == 0
            and type(owner.get('qualification_seconds')) is int and owner['qualification_seconds'] == SECONDS
            and type(owner.get('cleanup_seconds')) is int and owner['cleanup_seconds'] == CLEANUP_SECONDS
            and owner.get('timed_out') is False and owner.get('exit_observed_before_deadline') is True
            and owner.get('cleanup', {}).get('complete') is True
            and owner.get('cleanup', {}).get('observed_echild') is True)


def qualify(output, cold_report):
    authority = admit_cold(cold_report)
    output = Path(output).absolute()
    require(not output.exists() and not output.is_symlink(), 'exclusive discovery qualification output required')
    environment = {key: value for key, value in os.environ.items() if not key.startswith('HEPTA_')}
    environment['PYTHONDONTWRITEBYTECODE'] = '1'
    output.mkdir(mode=0o700)
    report = {'schema': 'hepta.hia.cli-discovery-json-qualification.v1', 'status': 'FAIL',
              'scope': 'MATCHING_SOURCE_COLD_CLI_DISCOVERY_JSON', 'qualification_complete': False,
              'authority': authority, 'source_before': authority['source_manifest'],
              'expected_ids': list(EXPECTED_IDS), 'expected_count': 4, 'groups': [],
              'machine_cases': 61, 'vm_cases': 6, 'vm_steps': 10000000,
              'vm_heap_bytes': 8 << 20, 'vm_call_depth': 128, 'compile_seconds': 20,
              'buffer_capacity': 1048576, 'group_seconds': SECONDS, 'cleanup_seconds': CLEANUP_SECONDS,
              'ordinary_cli_activated': False, 'whole_cli_native': False,
              'whole_native_delivery_qualified': False}
    start = time.monotonic_ns()
    fixture_path = output / 'fixture' / 'FIXTURE.json'
    try:
        command = [sys.executable, '-I', '-B', str(Path(__file__).resolve()), '--_prepare',
                   str(output / 'fixture'), '--cold-report', authority['cold_report']]
        prepared = _owned(command, output / 'prepare', environment)
        report['preparation_owner'] = prepared
        require(_owner_pass(prepared), 'strict discovery cold fixture preparation failed')
        fixture = admit_fixture(fixture_path)
        controls = output / 'controls'
        controls.mkdir(mode=0o700)
        all_passed = True
        for group in GROUPS:
            guard_authority(authority)
            folder = output / group
            folder.mkdir(mode=0o700)
            request = {'schema': 'hepta.hia.cli-discovery-json-test-request.v1', 'group': group,
                       'fixture': str(fixture_path), 'fixture_binding': binding(fixture_path),
                       'source_manifest': authority['source_manifest'],
                       'controls_evidence': str(controls), 'output': str(folder / 'REPORT.json')}
            request_path = folder / 'REQUEST.json'
            publish(request_path, request)
            env = {**environment, COLD_FIXTURE: str(fixture_path), EVIDENCE: str(controls)}
            item = {'group': group, 'status': 'FAIL'}
            try:
                item['owner'] = _owned([sys.executable, '-I', '-B', str(Path(__file__).resolve()),
                                       '--_child', str(request_path)], folder / 'command', env)
                child = read_json((folder / 'REPORT.json').read_bytes())
                item['observations'] = child
                admit_result(child, group, sha256(request_path.read_bytes()).hexdigest())
                require(_owner_pass(item['owner']), 'discovery child did not complete under the original owner limit')
                item['status'] = 'PASS'
            except BaseException:
                item['traceback'] = traceback.format_exc()
                all_passed = False
            report['groups'].append(item)
        require(all_passed and len(report['groups']) == 4, 'complete discovery conjunction failed')
        report.update(status='MATCHING_SOURCE_COLD_CLI_DISCOVERY_JSON_PASS', qualification_complete=True)
    except BaseException:
        report['traceback'] = traceback.format_exc()
    finally:
        try:
            guard_authority(authority)
            if fixture_path.exists():
                admit_fixture(fixture_path)
            from tools.build_hia_json_preflight import current_sources
            report.update(source_after=current_sources(), source_and_inputs_unchanged=True)
        except BaseException:
            report.update(status='FAIL', qualification_complete=False, source_and_inputs_unchanged=False,
                          final_guard_error=traceback.format_exc())
        report['wall_ns'] = time.monotonic_ns() - start
        publish(output / 'REPORT.json', report)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cold-report', type=Path)
    parser.add_argument('--evidence', type=Path)
    parser.add_argument('--_prepare', type=Path)
    parser.add_argument('--_child', type=Path)
    args = parser.parse_args(argv)
    if args._child is not None:
        require(args.cold_report is None and args.evidence is None and args._prepare is None,
                'child arguments must remain separate')
        return _child(args._child)
    if args._prepare is not None:
        require(args.cold_report is not None and args.evidence is None, 'real cold fixture preparation required')
        print(prepare_fixture(args._prepare, args.cold_report))
        return 0
    require(args.cold_report is not None and args.evidence is not None, '--cold-report and --evidence required')
    result = qualify(args.evidence, args.cold_report)
    print(json.dumps({key: result[key] for key in ('status', 'qualification_complete', 'scope')}))
    return 0 if result['qualification_complete'] is True else 1


if __name__ == '__main__':
    raise SystemExit(main())
