"""Qualify the explicit bounded roundtrip profile from matching-current cold.

Four permanent groups preserve the original130 kernel controls, pipeline7
(six actual pure-HIA whole-buffer observations), two last-byte faults, and one
new real packaging/install group. The separate semantic checker6 VM result
remains5PASS/1fuelFAIL. Neither default nor whole-language authority is granted.
Every group keeps the original180+3 owner; every compile20s/1MiB; every VM10M.
"""
from pathlib import Path
import argparse
import os
import platform
import sys
import time
import traceback
import unittest

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ''):
    sys.path.insert(0, str(ROOT))

from tools.hia_linux_file_roundtrip_cold import (
    PROFILE, CAPACITY, RETAINED, profile_capture, captured_source_binding, admit_cold, guard_authority, re_admit_authority,
    capture_runtime_context, guard_runtime_context, runtime_child_environment,
    retained, pin, publish, decode, wire, digest, require, check_bindings, owner_pass, capture,
    KNOWN_SEPARATE_SEMANTIC_SUITE,
)
from tests.hia_linux_file_roundtrip_ids import GROUP_ORDER, GROUP_COUNTS, GROUP_CLASSES, EXPECTED_IDS

COLD_FIXTURE_ENV = 'HEPTA_HIA_ROUNDTRIP_COLD_FIXTURE'
EVIDENCE_ENV = 'HEPTA_HIA_ROUNDTRIP_COLD_EVIDENCE'
FIXTURE_SCHEMA = 'hepta.hia.linux-file-roundtrip-current-cold-fixture.v1'
FIXTURE_STATUS = 'ACTUAL_CURRENT_COLD_ROUNDTRIP_INPUTS_PREPARED_NOT_QUALIFIED'
REQUEST_SCHEMA = 'hepta.hia.roundtrip-cold-request.v1'
RESULT_SCHEMA = 'hepta.hia.roundtrip-cold-observations.v1'
SCOPE = 'EXPLICIT_BOUNDED_ROUNDTRIP_130_KERNEL_7_PIPELINE_2_FAULTS_PORTABLE'
GROUP_SECONDS = 180
CLEANUP_SECONDS = 3
LIMITS = {'group_seconds': 180, 'cleanup_seconds': 3, 'compile_seconds': 20,
          'compile_output_bytes': CAPACITY, 'compile_workspace_bytes': CAPACITY,
          'aggregate_ELF_bytes': CAPACITY, 'VM_steps': 10000000,
          'kernel_wall_seconds': 20, 'kernel_cleanup_seconds': 3}
ANOMALIES = ('failures', 'errors', 'skipped', 'expected_failures', 'unexpected_successes', 'subtest_failures')


def retain_authority_inputs(folder, authority):
    """Keep complete source bytes and cold originals, including partial failure."""
    folder = Path(folder); folder.mkdir(mode=0o700)
    report = {'schema': 'hepta.hia.roundtrip-current-input-capture.v1', 'status': 'FAIL',
              'sources': [], 'cold_inputs': []}
    try:
        guard_authority(authority)
        _, captured_sources = profile_capture()
        for name, expected in sorted(authority['source_manifest'].items()):
            relative = Path(name)
            require(not relative.is_absolute() and '..' not in relative.parts
                    and relative.as_posix() == name, 'closed source capture path required')
            target = folder / 'source' / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            raw = captured_sources[name] if name in captured_sources else (ROOT / relative).read_bytes()
            require(digest(raw) == expected, 'current source changed while capturing: ' + name)
            capture(target, raw)
            binding = captured_source_binding(ROOT / relative, raw) if name in captured_sources else pin(ROOT / relative)
            report['sources'].append({'name': name, 'original': binding, 'capture': pin(target),
                'source_content_read': 'safe-profile-capture' if name in captured_sources else 'original-cold-protocol',
                'original_mode_observation': 'post-capture-lstat' if name in captured_sources else 'original-pin'})
        cold = folder / 'cold'; cold.mkdir(mode=0o700)
        for index, binding in enumerate(authority['input_bindings']):
            check_bindings([binding])
            target = cold / (f'{index:03d}-' + Path(binding['path']).name)
            capture(target, Path(binding['path']).read_bytes())
            report['cold_inputs'].append({'original': binding, 'capture': pin(target)})
        guard_authority(authority)
        report['status'] = 'COMPLETE_BYTES_RETAINED_NO_ADDITIONAL_AUTHORITY'
    except BaseException:
        report['traceback'] = traceback.format_exc(); raise
    finally:
        publish(folder / 'CAPTURE.json', report)
    return pin(folder / 'CAPTURE.json')


def prepare_fixture(output, cold_report):
    from tools.build_hia_linux_file_roundtrip_cold import build_toolchain, build_program, build_observer
    output = Path(output).absolute(); output.mkdir(mode=0o700, parents=False, exist_ok=False)
    report = {'schema': FIXTURE_SCHEMA, 'status': 'FAIL', 'scope': SCOPE, 'profile': PROFILE,
        'matching_cold': False, 'qualification_complete': False, 'whole_native': False,
        'default_activated': False, 'full_checker_vm_qualification': False, 'limits': LIMITS,
        'known_separate_semantic_suite': KNOWN_SEPARATE_SEMANTIC_SUITE}
    try:
        authority = admit_cold(cold_report)
        originals = retained()
        report['authority'] = authority
        chain = build_toolchain(output / 'toolchain', cold_report)
        program = build_program(output / 'production', chain)
        observer = build_observer(output / 'observer', program)
        guard_authority(authority)
        report.update(status=FIXTURE_STATUS, matching_cold=True, toolchain=pin(chain),
            production=pin(program), observer=pin(observer), retained_fixture=pin(ROOT / RETAINED),
            known_separate_semantic_suite=originals['known_separate_semantic_suite'])
    except BaseException:
        report.update(status='FAIL', matching_cold=False, traceback=traceback.format_exc()); raise
    finally:
        publish(output / 'FIXTURE.json', report)
    admit_fixture(output / 'FIXTURE.json')
    return output / 'FIXTURE.json'


def fixture_shape(report):
    require(type(report) is dict and report.get('schema') == FIXTURE_SCHEMA
            and report.get('status') == FIXTURE_STATUS and report.get('scope') == SCOPE
            and report.get('profile') == PROFILE and report.get('matching_cold') is True
            and report.get('qualification_complete') is False and report.get('whole_native') is False
            and report.get('default_activated') is False and report.get('full_checker_vm_qualification') is False
            and report.get('limits') == LIMITS and all(type(v) is int for v in report['limits'].values()),
            'actual current-cold roundtrip preparation required; development is not authority')


def admit_fixture(path):
    from tools.build_hia_linux_file_roundtrip_cold import admit_toolchain, admit_program, admit_observer
    path = Path(path).resolve(strict=True); raw = path.read_bytes(); report = decode(raw)
    fixture_shape(report)
    authority = re_admit_authority(report.get('authority'))
    bindings = [report[name] for name in ('toolchain', 'production', 'observer', 'retained_fixture')]
    check_bindings(bindings)
    require(report['retained_fixture'] == pin(ROOT / RETAINED), 'fixed complete original fixture differs')
    originals = retained()
    require(report['known_separate_semantic_suite'] == originals['known_separate_semantic_suite'],
            'known separate checker fuel failure cannot be omitted or reclassified')
    chain = admit_toolchain(report['toolchain']['path'], authority=authority)
    program = admit_program(report['production']['path'], authority=authority)
    observer = admit_observer(report['observer']['path'], authority=authority)
    require(program['toolchain'] == report['toolchain'] and observer['production'] == report['production']
            and program['authority'] == observer['authority'] == chain['authority'] == authority,
            'fixture actual compiler/production/observer lineage differs')
    guard_authority(authority)
    require(path.read_bytes() == raw, 'fixture changed during actual admission')
    return report


def load_fixture(environment=None):
    env = os.environ if environment is None else environment
    require(type(env.get(COLD_FIXTURE_ENV)) is str and env[COLD_FIXTURE_ENV]
            and type(env.get(EVIDENCE_ENV)) is str and env[EVIDENCE_ENV],
            'explicit cold fixture and retained evidence paths required')
    path = Path(env[COLD_FIXTURE_ENV]).resolve(strict=True)
    observations = Path(env[EVIDENCE_ENV]).absolute()
    return path, admit_fixture(path), observations


def flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from flatten(item)
        else:
            yield item


def load_suite(group):
    require(group in GROUP_ORDER, 'unknown complete roundtrip group')
    selector = 'tests.test_hia_linux_file_roundtrip_cold.' + GROUP_CLASSES[group]
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromName(selector)
    ids = [item.id() for item in flatten(suite)]
    require(not loader.errors and tuple(ids) == EXPECTED_IDS[group]
            and len(ids) == GROUP_COUNTS[group], 'complete ordered permanent roundtrip IDs differ')
    return suite, ids


def admit_child_report(report, request_sha, group):
    require(type(report) is dict and report.get('schema') == RESULT_SCHEMA
            and report.get('scope') == 'OBSERVATIONS_ONLY_NO_COLD_AUTHORITY'
            and report.get('status') == 'PASS' and report.get('group') == group
            and report.get('request_sha256') == request_sha
            and report.get('source_and_inputs_unchanged') is True
            and type(report.get('tests_run')) is int and report['tests_run'] == GROUP_COUNTS[group],
            'complete actual roundtrip group terminal required')
    for name in ('loaded_ids', 'started_ids', 'stopped_ids'):
        require(type(report.get(name)) is list and tuple(report[name]) == EXPECTED_IDS[group],
                'missing/reordered roundtrip method: ' + name)
    anomalies = report.get('anomalies')
    require(type(anomalies) is dict and set(anomalies) == set(ANOMALIES)
            and all(type(value) is list and value == [] for value in anomalies.values()),
            'skips, subtest failures or other anomalies cannot qualify')


def cleanup_observed(owner):
    return (type(owner) is dict and type(owner.get('cleanup')) is dict
            and owner['cleanup'].get('complete') is True
            and owner['cleanup'].get('observed_echild') is True)


def verify_actual_observations(group, directory, fixture):
    from tests.hia_linux_file_roundtrip_cases import context
    from tools import hia_linux_file_roundtrip_readback as readback
    ctx = context(fixture)
    ctx['production_path'] = fixture['production']['path']
    if group == 'kernel':
        return readback.kernel(ctx, directory)
    if group == 'pipeline':
        return readback.pipeline(ctx, directory)
    if group == 'tail_faults':
        return readback.tail_faults(ctx, directory)
    require(group == 'portable', 'unknown roundtrip observation group')
    from tests.hia_linux_file_roundtrip_portable import verify
    return [verify(ctx, directory)]


def _child(request_path):
    raw = Path(request_path).read_bytes(); request = decode(raw)
    require(type(request) is dict and set(request) == {'schema', 'group', 'fixture', 'fixture_binding',
            'source_manifest', 'output'} and request['schema'] == REQUEST_SCHEMA
            and request['group'] in GROUP_ORDER, 'complete owned roundtrip request required')
    group = request['group']; output = Path(request['output']); output.mkdir(mode=0o700)
    report = {'schema': RESULT_SCHEMA, 'scope': 'OBSERVATIONS_ONLY_NO_COLD_AUTHORITY',
        'status': 'FAIL', 'group': group, 'request_sha256': digest(raw), 'python': sys.version,
        'loaded_ids': [], 'started_ids': [], 'stopped_ids': [], 'tests_run': 0,
        'anomalies': {name: [] for name in ANOMALIES}}
    fixture = None
    try:
        require(sys.flags.optimize == 0, 'original assertions require unoptimized Python')
        selected, fixture, observations = load_fixture()
        require(str(selected) == request['fixture'] and pin(selected) == request['fixture_binding']
                and observations == output / 'observations'
                and fixture['authority']['source_manifest'] == request['source_manifest'],
                'child source/current-cold inputs differ')
        observations.mkdir(mode=0o700)
        suite, ids = load_suite(group); report['loaded_ids'] = ids
        publish(output / 'DISCOVERY.json', {'group': group, 'loaded_ids': ids})
        with (output / 'EVENTS.jsonl').open('x') as events:
            class Result(unittest.TextTestResult):
                def startTest(self, test):
                    report['started_ids'].append(test.id())
                    events.write(wire({'event': 'start', 'id': test.id()}).decode().replace('\n', '') + '\n')
                    events.flush(); super().startTest(test)
                def stopTest(self, test):
                    report['stopped_ids'].append(test.id())
                    events.write(wire({'event': 'stop', 'id': test.id()}).decode().replace('\n', '') + '\n')
                    events.flush(); super().stopTest(test)
                def addSubTest(self, test, subtest, err):
                    if err is not None:
                        report['anomalies']['subtest_failures'].append((subtest.id(), ''.join(traceback.format_exception(*err))))
                    super().addSubTest(test, subtest, err)
            result = unittest.TextTestRunner(verbosity=2, resultclass=Result).run(suite)
        report['tests_run'] = result.testsRun
        report['anomalies'].update(
            failures=[(test.id(), trace) for test, trace in result.failures],
            errors=[(test.id(), trace) for test, trace in result.errors],
            skipped=[(test.id(), why) for test, why in result.skipped],
            expected_failures=[(test.id(), trace) for test, trace in result.expectedFailures],
            unexpected_successes=[test.id() for test in result.unexpectedSuccesses])
        if report['started_ids'] == report['stopped_ids'] == ids and result.testsRun == GROUP_COUNTS[group] and not any(report['anomalies'].values()):
            report['actual'] = verify_actual_observations(group, observations, fixture)
            report['status'] = 'PASS'
    except BaseException:
        report.update(status='FAIL', traceback=traceback.format_exc())
    finally:
        try:
            require(fixture is not None, 'child never admitted an actual cold fixture')
            guard_authority(fixture['authority'])
            require(admit_fixture(request['fixture']) == fixture
                    and pin(request['fixture']) == request['fixture_binding']
                    and Path(request_path).read_bytes() == raw, 'child inputs changed')
            report['source_and_inputs_unchanged'] = True
        except BaseException:
            report.update(status='FAIL', source_and_inputs_unchanged=False, final_guard_error=traceback.format_exc())
        publish(output / 'RESULT.json', report)
    return 0 if report['status'] == 'PASS' else 1


def _prepare(output, cold_report):
    report = {'schema': 'hepta.hia.roundtrip-preparation-terminal.v1', 'status': 'FAIL'}
    try:
        fixture = prepare_fixture(Path(output) / 'fixture', cold_report)
        report.update(status='PASS', fixture=str(fixture), fixture_binding=pin(fixture))
    except BaseException:
        report['traceback'] = traceback.format_exc()
    publish(Path(output) / 'PREPARE.json', report)
    return 0 if report['status'] == 'PASS' else 1


def _read_owner_return(path, returned):
    """Reconstruct run_owned's complete returned view of its real receipt.

    The supervisor exit is the observation returned by the just-completed
    run_owned call. This helper never manufactures a process or qualification.
    """
    raw = Path(path).read_bytes()
    receipt = decode(raw)
    require(type(receipt) is dict and type(returned) is dict
            and 'supervisor_returncode' not in receipt and 'receipt_sha256' not in receipt
            and type(returned.get('supervisor_returncode')) is int,
            'complete actual owner receipt and observed supervisor exit required')
    expected = {**receipt, 'supervisor_returncode': returned['supervisor_returncode'],
                'receipt_sha256': digest(raw)}
    if returned['supervisor_returncode'] != 0 and receipt.get('status') == 'OWNED_PROCESS_COMPLETED':
        expected['status'] = 'OWNER_EXIT_MISMATCH_HOLD'
    require(wire(returned) == wire(expected), 'complete raw/returned owner receipt binding differs')
    return returned


def _owner(command, environment, folder, *, runtime_context):
    from tools.hia_selfhost_process_owner import run_owned
    folder.mkdir(mode=0o700)
    guard_runtime_context(runtime_context)
    request = {'command': command, 'cwd': str(ROOT), 'environment': environment,
               'qualification_seconds': GROUP_SECONDS, 'cleanup_seconds': CLEANUP_SECONDS,
               'runtime_launch_context': runtime_context}
    publish(folder / 'REQUEST.json', request)
    owner = run_owned(command, cwd=ROOT, env=environment, supervisor_env=environment,
        stdout_path=folder / 'stdout.log', stderr_path=folder / 'stderr.log',
        receipt_path=folder / 'OWNER.json', qualification_seconds=GROUP_SECONDS, cleanup_seconds=CLEANUP_SECONDS)
    publish(folder / 'RETURNED-OWNER.json', owner)
    _read_owner_return(folder / 'OWNER.json', owner)
    runtime_result = {'status': 'FAIL', 'before': runtime_context}
    try:
        runtime_result.update(status='PASS', after=guard_runtime_context(runtime_context))
    except BaseException:
        runtime_result['traceback'] = traceback.format_exc(); raise
    finally:
        publish(folder / 'RUNTIME-READBACK.json', runtime_result)
    return owner


def qualify(cold_report, evidence):
    folder = Path(evidence).absolute(); folder.mkdir(mode=0o700, parents=False, exist_ok=False)
    report = {'schema': 'hepta.hia.roundtrip-cold-qualification.v1', 'status': 'FAIL',
        'scope': SCOPE, 'profile': PROFILE, 'matching_cold': False, 'qualification_complete': False,
        'whole_native': False, 'default_activated': False, 'full_checker_vm_qualification': False,
        'known_separate_semantic_suite': KNOWN_SEPARATE_SEMANTIC_SUITE,
        'expected_ids': EXPECTED_IDS, 'expected_counts': GROUP_COUNTS, 'group_order': GROUP_ORDER,
        'limits': LIMITS, 'python': sys.version, 'groups': {}}
    authority = fixture = selected = runtime_context = None
    started = time.monotonic_ns()
    environment = {'PATH': os.environ.get('PATH', ''), 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
                   'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONHASHSEED': '0'}
    try:
        require(all(name not in os.environ for name in (COLD_FIXTURE_ENV, EVIDENCE_ENV)),
                'standalone qualifier refuses ambient fixture/evidence override')
        require(sys.flags.optimize == 0 and sys.platform == 'linux'
                and platform.machine().lower() in ('x86_64', 'amd64'),
                'unoptimized Python and actual Linux x86-64 required; no skip fallback')
        runtime_context = capture_runtime_context()
        environment = runtime_child_environment(environment, runtime_context)
        report['runtime_launch_context'] = runtime_context
        report['cold_input'] = pin(cold_report)
        authority = admit_cold(cold_report); report['authority'] = authority
        report['source_before'] = authority['source_manifest']
        report['complete_current_inputs'] = retain_authority_inputs(folder / 'current-inputs', authority)
        report['known_separate_semantic_suite'] = retained()['known_separate_semantic_suite']
        command = [sys.executable, '-I', '-B', str(Path(__file__).resolve()), '--prepare-output', str(folder),
                   '--cold-report', authority['cold_report']]
        report['prepare_owner'] = _owner(command, environment, folder / 'prepare-command', runtime_context=runtime_context)
        preparation = decode((folder / 'PREPARE.json').read_bytes()); report['preparation'] = preparation
        require(owner_pass(report['prepare_owner']) and preparation.get('status') == 'PASS',
                'actual cold preparation failed its original owner')
        selected = Path(preparation['fixture'])
        require(pin(selected) == preparation['fixture_binding'], 'prepared fixture changed')
        fixture = admit_fixture(selected)
        for group in GROUP_ORDER:
            result = {'group': group, 'status': 'FAIL'}
            try:
                guard_authority(authority)
                request = {'schema': REQUEST_SCHEMA, 'group': group, 'fixture': str(selected),
                    'fixture_binding': pin(selected), 'source_manifest': authority['source_manifest'],
                    'output': str(folder / group)}
                request_path = folder / (group + '-REQUEST.json'); publish(request_path, request)
                raw = request_path.read_bytes()
                child_env = {**environment, COLD_FIXTURE_ENV: str(selected),
                             EVIDENCE_ENV: str(folder / group / 'observations')}
                command = [sys.executable, '-I', '-B', str(Path(__file__).resolve()), '--child-request', str(request_path)]
                result['owner'] = _owner(command, child_env, folder / (group + '-command'), runtime_context=runtime_context)
                child = decode((folder / group / 'RESULT.json').read_bytes()); result['observations'] = child
                require(owner_pass(result['owner']), 'original group deadline/exit/cleanup failed')
                admit_child_report(child, digest(raw), group)
                events = [decode(line) for line in (folder / group / 'EVENTS.jsonl').read_bytes().splitlines()]
                require(events == [event for identity in EXPECTED_IDS[group]
                    for event in ({'event': 'start', 'id': identity}, {'event': 'stop', 'id': identity})],
                    'complete actual start/stop event order differs')
                result['actual'] = verify_actual_observations(group, folder / group / 'observations', fixture)
                require(result['actual'] == child['actual'] and request_path.read_bytes() == raw
                        and pin(selected) == request['fixture_binding'], 'independent raw readback/input identity differs')
                result['status'] = 'PASS'
            except BaseException:
                result.update(status='FAIL', traceback=traceback.format_exc())
            report['groups'][group] = result
            require(cleanup_observed(result.get('owner')),
                    'prior process cleanup is unknown or incomplete; later groups cannot start')
            # Ordinary observation failure keeps subsequent fixed groups. Source
            # drift is a refusal, never permission for continued execution.
            guard_authority(authority)
        require(tuple(report['groups']) == GROUP_ORDER and all(report['groups'][g]['status'] == 'PASS' for g in GROUP_ORDER),
                'one or more complete bounded groups failed')
        require(admit_fixture(selected) == fixture, 'final current-cold fixture differs')
        report.update(status='MATCHING_CURRENT_COLD_BOUNDED_ROUNDTRIP_PASS', matching_cold=True,
                      qualification_complete=True, tests_run=140)
    except BaseException:
        report.update(status='FAIL', matching_cold=False, qualification_complete=False, traceback=traceback.format_exc())
    finally:
        try:
            require(authority is not None, 'no actual matching-current-cold authority admitted')
            guard_authority(authority)
            if fixture is not None:
                require(admit_fixture(selected) == fixture, 'final fixture/source changed')
            report.update(source_and_inputs_unchanged=True, source_after=authority['source_manifest'])
        except BaseException:
            report.update(status='FAIL', matching_cold=False, qualification_complete=False,
                          source_and_inputs_unchanged=False, final_guard_error=traceback.format_exc())
        try:
            require(runtime_context is not None, 'no actual runtime launch context captured')
            report['runtime_after'] = guard_runtime_context(runtime_context)
            report['runtime_unchanged'] = True
        except BaseException:
            report.update(status='FAIL', matching_cold=False, qualification_complete=False,
                runtime_unchanged=False, runtime_final_guard_error=traceback.format_exc())
        report['wall_ns'] = time.monotonic_ns() - started
        publish(folder / 'QUALIFICATION.json', report)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cold-report', type=Path)
    parser.add_argument('--evidence', type=Path)
    parser.add_argument('--prepare-output', type=Path)
    parser.add_argument('--child-request', type=Path)
    args = parser.parse_args(argv)
    if args.child_request is not None:
        require(args.cold_report is None and args.evidence is None and args.prepare_output is None,
                'child request cannot mix cold inputs')
        return _child(args.child_request)
    if args.prepare_output is not None:
        require(args.cold_report is not None and args.evidence is None, 'explicit cold prepare required')
        return _prepare(args.prepare_output, args.cold_report)
    require(args.cold_report is not None and args.evidence is not None, '--cold-report and --evidence required')
    report = qualify(args.cold_report, args.evidence)
    print(wire({key: report[key] for key in ('status', 'scope', 'matching_cold', 'qualification_complete',
        'whole_native', 'full_checker_vm_qualification')}).decode(), end='')
    return 0 if report['status'] == 'MATCHING_CURRENT_COLD_BOUNDED_ROUNDTRIP_PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
