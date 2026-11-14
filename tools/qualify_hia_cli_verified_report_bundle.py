"""Strict cold fixture and original43 + report140 observation qualification.

The actual current-source cold report, all B1/B2/B3 bytes, six real compile
observations and complete retained caller outcomes remain separate authority
checks. A development manifest never enters this production driver.
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

from tools.hia_cli_verified_report_custody import (
    BUNDLE_SCHEMA, CAPACITY, LABEL, SCHEMA, SOURCE, admit_cold, admit_compilation,
    binding, check_bindings, guard_authority, owner_sources, publish, read_json,
    require, retained_inputs,
)

COLD_FIXTURE = 'HEPTA_HIA_CLI_VERIFIED_REPORT_COLD_FIXTURE'
DEVELOPMENT = 'HEPTA_HIA_CLI_VERIFIED_REPORT_DEVELOPMENT_MANIFEST'
EVIDENCE = 'HEPTA_HIA_CLI_VERIFIED_REPORT_EVIDENCE'
OLD_COLD = 'HEPTA_HIA_CLI_COLD_REPORT'
OLD_DEVELOPMENT = 'HEPTA_HIA_CLI_DEVELOPMENT_MANIFEST'
OLD_EVIDENCE = 'HEPTA_HIA_CLI_FIXTURE_EVIDENCE'
FIXTURE_SCHEMA = 'hepta.hia.cli-verified-report-cold-fixture.v1'
FIXTURE_STATUS = 'MATCHING_SOURCE_COLD_FIXTURE_BUILT'
SCOPE = 'MATCHING_CURRENT_SOURCE_COLD_CLI_VERIFIED_REPORT_BUNDLE'
NATIVE_IDS = (
    'tests.test_hia_cli_verified_report_native.CliVerifiedReportNativeTests.test_original_140_report_and_cli_observations',
    'tests.test_hia_cli_verified_report_native.CliVerifiedReportNativeTests.test_report_warm_mapping_and_strict_image_readback_remain_distinct',
)
ANOMALIES = ('failures', 'errors', 'skipped', 'expected_failures', 'unexpected_successes')
SECONDS, CLEANUP_SECONDS = 180, 3


def groups():
    return {'original_cli': tuple(retained_inputs()['original_cli_ids']), 'report': NATIVE_IDS}


def inspect_build(directory, authority):
    from hepta.hia_cli_verified_report_native import _resource_binding
    from tools.build_hia_cli_verified_report_bundle import BUILD_SCHEMA, COLD_SCOPE, DEVELOPMENT_SCOPE
    from tools.qualify_hia_cli_discovery_bundle import inspect_build as inspect_companion
    from tools.hia_cli_discovery_bundle_custody import SOURCES as ORIGINAL_SOURCES
    directory = Path(directory).absolute()
    report_path = directory / 'verified-report-build.json'
    manifest_path = directory / 'verified-report-bundle.json'
    report = read_json(report_path.read_bytes())
    bundle = read_json(manifest_path.read_bytes())
    keys = {'schema', 'verified_report_manifest', 'verified_report_manifest_sha256',
            *[name + suffix for name in ORIGINAL_SOURCES
              for suffix in ('_manifest', '_manifest_sha256')]}
    require(type(bundle) is dict and set(bundle) == keys and bundle['schema'] == BUNDLE_SCHEMA,
            'complete flat six-image report bundle required')
    require(type(report) is dict and report.get('schema') == BUILD_SCHEMA
            and report.get('status') == 'NATIVE_CANDIDATE_BUILT'
            and report.get('scope') == (COLD_SCOPE if authority is not None else DEVELOPMENT_SCOPE)
            and report.get('matching_cold') is (authority is not None)
            and report.get('authority') == authority and report.get('bundle') == bundle
            and report.get('owner_sources_before') == owner_sources() == report.get('owner_sources_after')
            and type(report.get('compile_seconds')) is int and report['compile_seconds'] == 20
            and type(report.get('capacity')) is int and report['capacity'] == CAPACITY
            and report.get('ordinary_cli_activated') is False
            and report.get('whole_cli_native') is False and report.get('whole_verify_native') is False
            and report.get('whole_native_delivery_qualified') is False,
            'stale, incomplete or differently scoped report build')
    companion = inspect_companion(directory, authority)
    require(report.get('companion') == companion, 'report companion does not match its actual original build')
    original = read_json((directory / 'manifest.json').read_bytes())
    projection = {key: value for key, value in bundle.items()
                  if key not in ('verified_report_manifest', 'verified_report_manifest_sha256')}
    projection['schema'] = original['schema']
    require(projection == original, 'six-image envelope changed an original companion field')
    compiler = Path(companion['compiler'])
    require(sha256(compiler.read_bytes()).hexdigest() == report.get('compiler_sha256'), 'report compiler changed')
    if authority is not None:
        require(str(compiler) == authority['compiler']
                and report['compiler_sha256'] == authority['compiler_sha256'], 'report compiler is not current cold B3')
        guard_authority(authority)
    from hepta.hia_optional_profiles import fresh_profile_capture
    _, source_captures = fresh_profile_capture(BUNDLE_SCHEMA)
    source = source_captures[SOURCE]
    folder = directory / 'verified_report'
    target = folder / 'manifest.json'
    manifest = read_json(target.read_bytes())
    require(bundle['verified_report_manifest'] == 'verified_report/manifest.json'
            and bundle['verified_report_manifest_sha256'] == sha256(target.read_bytes()).hexdigest()
            and type(manifest) is dict and set(manifest) == {
                'schema', 'source_sha256', 'image_path', 'image_sha256', 'compiler_sha256', 'profile_resources'}
            and manifest['schema'] == SCHEMA and manifest['source_sha256'] == sha256(source).hexdigest()
            and manifest['image_path'] == LABEL + '.image.bin'
            and manifest['compiler_sha256'] == report['compiler_sha256'],
            'report component manifest differs')
    resource_root, resource_identity, captured_raw = _resource_binding(folder, manifest['profile_resources'])
    captured_source = resource_root / SOURCE
    require(captured_raw == source
            and manifest['profile_resources']['source_root'] == 'profile-resources'
            and manifest['profile_resources']['source_relative'] == SOURCE,
            'captured report source is not the actual cold-bound compile input')
    image = folder / manifest['image_path']
    require(sha256(image.read_bytes()).hexdigest() == manifest['image_sha256'], 'report component image changed')
    actual, observations = admit_compilation(folder, LABEL, compiler, source, image)
    require(report.get('report_component') == {'manifest': manifest,
            'actual_compile_receipt': actual, 'observation_bindings': observations},
            'report build differs from actual child observation')
    check_bindings(report['input_bindings'])
    bindings = [binding(report_path), binding(manifest_path), *companion['input_bindings'],
                *observations, binding(target), binding(ROOT / SOURCE), binding(captured_source)]
    bindings = list({row['path']: row for row in bindings}.values())
    check_bindings(bindings)
    return {'manifest': str(manifest_path), 'build_report': str(report_path), 'compiler': str(compiler),
            'companion': companion, 'report_component': manifest, 'input_bindings': bindings}


def prepare_fixture(output, cold_report):
    from tools.build_hia_cli_verified_report_bundle import build
    authority = admit_cold(cold_report)
    output = Path(output).absolute()
    require(not output.exists() and not output.is_symlink(), 'exclusive report fixture output required')
    output.mkdir(mode=0o700)
    build(output / 'build', authority['compiler'], authority['cold_report'])
    built = inspect_build(output / 'build', authority)
    guard_authority(authority)
    value = {'schema': FIXTURE_SCHEMA, 'status': FIXTURE_STATUS, 'scope': SCOPE,
             'authority': authority, 'build': built, 'owner_sources': owner_sources(),
             'matching_cold': True, 'ordinary_cli_activated': False, 'whole_cli_native': False,
             'whole_verify_native': False, 'whole_native_delivery_qualified': False}
    path = output / 'FIXTURE.json'
    publish(path, value)
    admit_fixture(path)
    return path


def admit_fixture(path):
    path = Path(path).resolve(strict=True)
    raw = path.read_bytes()
    value = read_json(raw)
    require(type(value) is dict and set(value) == {'schema', 'status', 'scope', 'authority', 'build',
            'owner_sources', 'matching_cold', 'ordinary_cli_activated', 'whole_cli_native',
            'whole_verify_native', 'whole_native_delivery_qualified'}
            and value['schema'] == FIXTURE_SCHEMA and value['status'] == FIXTURE_STATUS
            and value['scope'] == SCOPE and value['matching_cold'] is True
            and value['ordinary_cli_activated'] is False and value['whole_cli_native'] is False
            and value['whole_verify_native'] is False and value['whole_native_delivery_qualified'] is False
            and type(value['authority']) is dict and type(value['build']) is dict,
            'strict current-source cold report fixture required')
    authority = admit_cold(value['authority']['cold_report'])
    require(authority == value['authority'] and value['owner_sources'] == owner_sources(),
            'report fixture authority or owner sources changed')
    require(inspect_build(Path(value['build']['build_report']).parent, authority) == value['build'],
            'report fixture does not bind its actual six-image build')
    check_bindings(value['build']['input_bindings'])
    require(path.read_bytes() == raw, 'report fixture changed during admission')
    return value


def _flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from _flatten(item)
        else:
            yield item


def admit_result(value, group, request_sha):
    expected = list(groups()[group])
    require(type(value) is dict and value.get('schema') == 'hepta.hia.cli-verified-report-test-observations.v1'
            and value.get('scope') == 'OBSERVATIONS_ONLY_NOT_COLD_AUTHORITY' and value.get('status') == 'PASS'
            and value.get('group') == group and value.get('request_sha256') == request_sha
            and value.get('loaded_ids') == expected == value.get('started_ids') == value.get('stopped_ids')
            and type(value.get('loaded')) is int and value['loaded'] == len(expected)
            and type(value.get('tests_run')) is int and value['tests_run'] == len(expected)
            and all(type(value.get(key)) is list and value[key] == [] for key in ANOMALIES)
            and value.get('source_and_inputs_unchanged') is True,
            'incomplete, failed or differently selected report observations')
    if group == 'original_cli':
        calls = value.get('fixture_provider_calls')
        require(type(calls) is list and len(calls) == 3
                and sum(row.get('status') == 'BUILT_AND_READ_BACK' for row in calls) == 2
                and sum(row.get('status') == 'REJECTED_BEFORE_BUILD' for row in calls) == 1,
                'original43 fixture provider observations are incomplete')


def _child(request_path):
    raw = Path(request_path).read_bytes()
    request = read_json(raw)
    require(type(request) is dict and set(request) == {'schema', 'group', 'fixture', 'fixture_binding',
            'source_manifest', 'controls_evidence', 'output'}
            and request['schema'] == 'hepta.hia.cli-verified-report-test-request.v1'
            and request['group'] in groups(), 'invalid report observation request')
    require(DEVELOPMENT not in os.environ and OLD_DEVELOPMENT not in os.environ
            and os.environ.get(COLD_FIXTURE) == request['fixture']
            and os.environ.get(EVIDENCE) == request['controls_evidence'], 'mixed report fixture selection')
    require(binding(request['fixture']) == request['fixture_binding'], 'report fixture changed')
    fixture = admit_fixture(request['fixture'])
    authority = fixture['authority']
    require(authority['source_manifest'] == request['source_manifest'], 'report child source map differs')
    expected = groups()[request['group']]
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromNames(expected)
    ids = [test.id() for test in _flatten(suite)]
    require(tuple(ids) == expected and not loader.errors, 'exact original/report test discovery failed')
    value = {'schema': 'hepta.hia.cli-verified-report-test-observations.v1',
             'scope': 'OBSERVATIONS_ONLY_NOT_COLD_AUTHORITY', 'status': 'FAIL',
             'group': request['group'], 'request_sha256': sha256(raw).hexdigest(),
             'loaded_ids': ids, 'loaded': suite.countTestCases(), 'started_ids': [], 'stopped_ids': [],
             'fixture_provider_calls': []}

    class Result(unittest.TextTestResult):
        def startTest(self, test):
            value['started_ids'].append(test.id()); super().startTest(test)
        def stopTest(self, test):
            value['stopped_ids'].append(test.id()); super().stopTest(test)

    def fixture_provider(output, compiler, cold_report):
        from tools.build_hia_cli_verified_report_bundle import build
        row = {'output': str(output), 'compiler': str(compiler), 'cold_report': str(cold_report),
               'provider': 'tools.build_hia_cli_verified_report_bundle.build', 'status': 'REJECTED_BEFORE_BUILD'}
        value['fixture_provider_calls'].append(row)
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
                    'original43 must use their unchanged cold fixture branch')
            from tools import build_hia_cli_native as original_builder
            with patch.object(original_builder, 'build', fixture_provider):
                result = unittest.TextTestRunner(stream=sys.stderr, verbosity=2, resultclass=Result).run(suite)
        else:
            result = unittest.TextTestRunner(stream=sys.stderr, verbosity=2, resultclass=Result).run(suite)
        value.update(tests_run=result.testsRun,
            failures=[(test.id(), text) for test, text in result.failures],
            errors=[(test.id(), text) for test, text in result.errors],
            skipped=[(test.id(), text) for test, text in result.skipped],
            expected_failures=[(test.id(), text) for test, text in result.expectedFailures],
            unexpected_successes=[test.id() for test in result.unexpectedSuccesses])
        admit_fixture(request['fixture'])
        for row in value['fixture_provider_calls']:
            if row['status'] == 'BUILT_AND_READ_BACK':
                require(inspect_build(Path(row['build']['build_report']).parent, authority) == row['build'],
                        'original43 actual build changed after tests')
        value.update(source_and_inputs_unchanged=True, status='PASS')
        admit_result(value, request['group'], sha256(raw).hexdigest())
    except BaseException:
        value.update(status='FAIL', traceback=traceback.format_exc())
    finally:
        publish(request['output'], value)
    return 0 if value['status'] == 'PASS' else 1


def _owned(command, output, environment):
    from tools.hia_selfhost_process_owner import run_owned
    output = Path(output); output.mkdir(mode=0o700)
    return run_owned(command, cwd=ROOT, env=environment,
        stdout_path=output / 'stdout.raw', stderr_path=output / 'stderr.raw',
        receipt_path=output / 'OWNER.json', qualification_seconds=SECONDS, cleanup_seconds=CLEANUP_SECONDS)


def _owner_pass(owner):
    return (type(owner) is dict and owner.get('status') == 'OWNED_PROCESS_COMPLETED'
        and type(owner.get('returncode')) is int and owner['returncode'] == 0
        and type(owner.get('qualification_seconds')) is int and owner['qualification_seconds'] == SECONDS
        and type(owner.get('cleanup_seconds')) is int and owner['cleanup_seconds'] == CLEANUP_SECONDS
        and owner.get('timed_out') is False and owner.get('exit_observed_before_deadline') is True
        and owner.get('cleanup', {}).get('complete') is True and owner['cleanup'].get('observed_echild') is True)


def qualify(output, cold_report):
    authority = admit_cold(cold_report)
    output = Path(output).absolute()
    require(not output.exists() and not output.is_symlink(), 'exclusive report qualification output required')
    output.mkdir(mode=0o700)
    environment = {key: val for key, val in os.environ.items() if not key.startswith('HEPTA_') and key != 'PYTHONPATH'}
    environment['PYTHONDONTWRITEBYTECODE'] = '1'
    selected = groups()
    value = {'schema': 'hepta.hia.cli-verified-report-qualification.v1', 'status': 'FAIL',
             'scope': SCOPE, 'qualification_complete': False, 'authority': authority,
             'source_before': authority['source_manifest'], 'expected_ids': [item for ids in selected.values() for item in ids],
             'original_cli_count': 43, 'report_test_methods': len(NATIVE_IDS), 'retained_report_cases': 140,
             'groups': [], 'compile_seconds': 20, 'capacity': CAPACITY, 'vm_steps': 10000000,
             'group_seconds': SECONDS, 'cleanup_seconds': CLEANUP_SECONDS,
             'ordinary_cli_activated': False, 'whole_cli_native': False, 'whole_verify_native': False,
             'whole_native_delivery_qualified': False}
    start = time.monotonic_ns(); fixture_path = output / 'fixture/FIXTURE.json'
    try:
        value['preparation_owner'] = _owned([sys.executable, '-I', '-B', str(Path(__file__).resolve()),
            '--_prepare', str(output / 'fixture'), '--cold-report', authority['cold_report']], output / 'prepare', environment)
        require(_owner_pass(value['preparation_owner']), 'report current-cold fixture preparation failed')
        admit_fixture(fixture_path)
        all_passed = True
        for group in selected:
            guard_authority(authority)
            folder = output / group; folder.mkdir(mode=0o700)
            controls = folder / 'controls'; controls.mkdir(mode=0o700)
            request = {'schema': 'hepta.hia.cli-verified-report-test-request.v1', 'group': group,
                       'fixture': str(fixture_path), 'fixture_binding': binding(fixture_path),
                       'source_manifest': authority['source_manifest'], 'controls_evidence': str(controls),
                       'output': str(folder / 'REPORT.json')}
            request_path = folder / 'REQUEST.json'; publish(request_path, request)
            env = {**environment, COLD_FIXTURE: str(fixture_path), EVIDENCE: str(controls)}
            if group == 'original_cli':
                env.update({OLD_COLD: authority['cold_report'], OLD_EVIDENCE: str(controls)})
            item = {'group': group, 'status': 'FAIL'}
            try:
                item['owner'] = _owned([sys.executable, '-B', str(Path(__file__).resolve()),
                    '--_child', str(request_path)], folder / 'command', env)
                item['observations'] = read_json((folder / 'REPORT.json').read_bytes())
                admit_result(item['observations'], group, sha256(request_path.read_bytes()).hexdigest())
                require(_owner_pass(item['owner']), 'report observations did not complete under original limits')
                item['status'] = 'PASS'
            except BaseException:
                item['traceback'] = traceback.format_exc(); all_passed = False
            value['groups'].append(item)
            owner = item.get('owner')
            require(type(owner) is dict and type(owner.get('cleanup')) is dict
                    and owner['cleanup'].get('complete') is True
                    and owner['cleanup'].get('observed_echild') is True,
                    'report cleanup is unconfirmed; later groups must not start')
        require(all_passed and len(value['groups']) == len(selected), 'complete report/original43 conjunction failed')
        value.update(status='MATCHING_CURRENT_SOURCE_COLD_CLI_VERIFIED_REPORT_PASS', qualification_complete=True)
    except BaseException:
        value['traceback'] = traceback.format_exc()
    finally:
        try:
            guard_authority(authority)
            if fixture_path.exists():
                admit_fixture(fixture_path)
            from tools.build_hia_json_preflight import current_sources
            value.update(source_after=current_sources(), source_and_inputs_unchanged=True)
        except BaseException:
            value.update(status='FAIL', qualification_complete=False, source_and_inputs_unchanged=False,
                         final_guard_error=traceback.format_exc())
        value['wall_ns'] = time.monotonic_ns() - start
        publish(output / 'REPORT.json', value)
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cold-report', type=Path); parser.add_argument('--evidence', type=Path)
    parser.add_argument('--_prepare', type=Path); parser.add_argument('--_child', type=Path)
    args = parser.parse_args(argv)
    if args._child is not None:
        require(args.cold_report is None and args.evidence is None and args._prepare is None, 'child options are separate')
        return _child(args._child)
    if args._prepare is not None:
        require(args.cold_report is not None and args.evidence is None, 'real current cold required')
        print(prepare_fixture(args._prepare, args.cold_report)); return 0
    require(args.cold_report is not None and args.evidence is not None, '--cold-report and --evidence required')
    result = qualify(args.evidence, args.cold_report)
    print(json.dumps({key: result[key] for key in ('status', 'scope', 'qualification_complete')}))
    return 0 if result['qualification_complete'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
