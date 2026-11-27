"""Exclusive, fail-stopping executor. No default action and no cold authority.

This file is AUTHORING only until an exact bound plan has been reviewed and
the one execution is authorized. The original test methods are not projected.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import time
import traceback
import unittest

HERE = Path(__file__).absolute().parent
SCHEMA = 'hepta.hia.inspect-cli-witness.execution.v1'
CAPACITY = 1048576
SECONDS = 180
CLEANUP = 3
MINIMUM_FREE = 1 << 30
KIT = Path('/workspace/scratch/dda74a4fae35/v119-inspect-policy-execution-r1')
sys.path[:0] = [str(HERE), str(KIT)]
from inspect_exec_support import (B3, compiler_bytes, complete_receipt, encoded,
    json_bytes, pin, publish, read_regular, require, snapshot, tree_digest)


def fixed(row):
    path = Path(row['path'])
    raw = read_regular(path, maximum=max(CAPACITY, row['pin']['bytes']), expected=row['pin'])
    require(stat.S_IMODE(path.lstat().st_mode) == row['posix_mode'], 'full POSIX mode differs')
    return raw


def controls(plan):
    for row in plan['controls'].values():
        fixed(row)
    for row in plan['retained_authorities'].values():
        fixed(row)
    require(compiler_bytes() == fixed(plan['compiler']), 'ordinary fixed B3 identity differs')


def source_guard(plan):
    expected = json_bytes(fixed(plan['source_manifest']))
    source = Path(plan['source'])
    actual = snapshot(source)
    require(actual == expected and len(actual) == 3191
            and tree_digest(actual) == plan['source_tree'], 'complete 3191-path view differs')
    modes = json_bytes(fixed(plan['source_modes']))
    require(set(modes) == set(actual) and all(
        stat.S_IMODE((source / name).lstat().st_mode) == mode for name, mode in modes.items()),
        'complete source POSIX modes differ')
    for name, row in plan['adapter_files'].items():
        require(actual[name] == row, 'three-file adapter implementation closure differs')
    return {'tree': tree_digest(actual), 'count': len(actual), 'modes': modes}


def admit_tests(value, ids):
    require(value['status'] == 'PASS' and value['loaded_ids'] == ids
            and value['declared_ids'] == ids and value['started_ids'] == ids
            and value['stopped_ids'] == ids and value['tests_run'] == len(ids)
            and all(not value.get(key) for key in ('failures', 'errors', 'skipped',
                'expected_failures', 'unexpected_successes', 'loader_errors')),
            'exact original/new test inventory or outcome differs')


def run_tests(ids, directory):
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromNames(ids)
    def flatten(item):
        if isinstance(item, unittest.TestSuite):
            for child in item:
                yield from flatten(child)
        else:
            yield item
    loaded = [test.id() for test in flatten(suite)]
    report = {'status': 'FAIL', 'declared_ids': ids, 'loaded_ids': loaded,
        'loader_errors': loader.errors, 'started_ids': [], 'stopped_ids': [], 'events': [],
        'subtests': []}
    class Result(unittest.TextTestResult):
        def startTest(self, test):
            report['started_ids'].append(test.id())
            report['events'].append(['start', test.id()])
            super().startTest(test)
        def stopTest(self, test):
            report['stopped_ids'].append(test.id())
            report['events'].append(['stop', test.id()])
            super().stopTest(test)
        def addSubTest(self, test, subtest, error):
            report['subtests'].append({'parent': test.id(), 'id': subtest.id(),
                'parameters': repr(dict(subtest.params)), 'success': error is None,
                'error': None if error is None else ''.join(traceback.format_exception(*error))})
            super().addSubTest(test, subtest, error)
    try:
        require(loaded == ids and not loader.errors, 'test discovery must be exact before running')
        new_only = bool(ids) and all(name.startswith('test_inspect_cli_witness_controls.') for name in ids)
        report['failfast_new_controls_only'] = new_only
        result = unittest.TextTestRunner(stream=sys.stderr, verbosity=2, resultclass=Result,
                                         failfast=new_only).run(suite)
        report.update(tests_run=result.testsRun,
            failures=[(test.id(), text) for test, text in result.failures],
            errors=[(test.id(), text) for test, text in result.errors],
            skipped=[(test.id(), text) for test, text in result.skipped],
            expected_failures=[(test.id(), text) for test, text in result.expectedFailures],
            unexpected_successes=[test.id() for test in result.unexpectedSuccesses])
        report['status'] = 'PASS' if result.wasSuccessful() else 'FAIL'
        admit_tests(report, ids)
    except BaseException:
        report['status'] = 'FAIL'
        report['executor_error'] = traceback.format_exc()
        raise
    finally:
        publish(directory / 'TESTS.json', report)
    return report


def build_inspect(plan, directory):
    from tools.qualify_hia_selfhost import compile_stage
    from tools.hia_cli_discovery_custody import admit_compilation
    from hepta.hia_inspect_program_native import SCHEMA, SOURCE_NAME, IMAGE_NAME, _capture_host_sources
    source = (Path(plan['source']) / 'examples/hia_bootstrap/inspect_program.hepta').read_bytes()
    hosts = _capture_host_sources()
    output = directory / 'inspect'; output.mkdir(mode=0o700)
    (output / SOURCE_NAME).write_bytes(source)
    image, returned = compile_stage(output, 'inspect-program', Path(B3['path']), source)
    receipt, observations = admit_compilation(output, 'inspect-program', Path(B3['path']), source, image)
    require(returned == receipt and Path(image) == output / IMAGE_NAME
            and _capture_host_sources() == hosts, 'actual original compile/host capture differs')
    image_raw = Path(image).read_bytes()
    require(0 < len(image_raw) <= CAPACITY, 'actual inspect image exceeds original limit')
    manifest = {'schema': SCHEMA, 'source_path': SOURCE_NAME,
        'source_sha256': hashlib.sha256(source).hexdigest(), 'image_path': IMAGE_NAME,
        'image_sha256': hashlib.sha256(image_raw).hexdigest(), 'compiler_sha256': B3['sha256'],
        'host_sources': hosts}
    publish(output / 'manifest.json', manifest)
    report = {'manifest': str(output / 'manifest.json'), 'source': pin(source),
        'image': pin(image_raw), 'receipt': receipt, 'observations': observations,
        'default_compile_receipt_is_not_a_full_workspace_observation': True,
        'matching_current_cold': False}
    publish(directory / 'BUILD.json', report)
    return report


def build_report(plan, directory):
    from tools.build_hia_cli_verified_report_bundle import build_development
    manifest = build_development(directory / 'six-image-bundle', Path(B3['path']))
    raw = Path(manifest).read_bytes()
    value = json_bytes(raw)
    components = ('control', 'format', 'discovery', 'routing', 'parser_context', 'verified_report')
    children = {}
    for name in components:
        path = Path(manifest).parent / value[name + '_manifest']
        child_raw = path.read_bytes()
        require(hashlib.sha256(child_raw).hexdigest() == value[name + '_manifest_sha256'],
                'real companion manifest changed')
        child = json_bytes(child_raw)
        image = path.parent / child['image_path']
        image_raw = image.read_bytes()
        require(0 < len(image_raw) <= CAPACITY and child['compiler_sha256'] == B3['sha256']
                and hashlib.sha256(image_raw).hexdigest() == child['image_sha256'],
                'real companion image/compiler differs')
        children[name] = {'manifest': str(path), 'manifest_pin': pin(child_raw),
                          'image': str(image), 'image_pin': pin(image_raw)}
    # The real loader, including the fixed optional-profile host pins, is used
    # by each test child. No invented cold record is created for this build.
    report = {'manifest': str(manifest), 'manifest_pin': pin(raw), 'children': children,
              'compiler': B3, 'six_real_compilations': True, 'matching_current_cold': False}
    publish(directory / 'BUILD.json', report)
    return report


@contextmanager
def retained_selection(context):
    """Parent-process fixture; real original loader remains before selection.

    Nested wheel/interpreter tests stay byte-exact and use their own original
    six-image path. They are NOT represented as private-op10 child coverage.
    """
    import inspect_cli_control_support as support
    support.configure(context)
    actual = support.ActualComponents(Path(context['controls_output']))
    from hepta import hia_cli_verified_report_native as module
    original = module.installed_bundle
    selections = []
    def select(path, raw, bundle, *, strict=False):
        base = original(path, raw, bundle, strict=strict)
        chosen = actual.adapter.select_inspect_report_cli(base, actual.record)
        selections.append({'path': str(path), 'private_selected': type(chosen) is actual.adapter.NativeInspectReportCli})
        return chosen
    module.installed_bundle = select
    try:
        yield actual
    finally:
        module.installed_bundle = original
        publish(actual.directory / 'RETAINED-SELECTIONS.json', {
            'selections': selections, 'same_process_only': True,
            'nested_original_child_claimed_as_new_inspect': False})
        actual.close()


def child(request_path, request_sha256):
    raw = read_regular(Path(request_path), maximum=8 << 20)
    require(hashlib.sha256(raw).hexdigest() == request_sha256, 'request raw differs')
    request = json_bytes(raw)
    plan = json_bytes(fixed(request['plan']))
    require(plan['schema'] == SCHEMA and plan['state'] == 'BOUND_AWAITING_EXPLICIT_EXECUTION',
            'authoring template cannot launch')
    controls(plan)
    before = source_guard(plan)
    source = Path(plan['source'])
    sys.path.insert(0, str(source))
    from tools.hia_linux_file_roundtrip_cold import guard_runtime_context
    guard_runtime_context(request['runtime'])
    require(sys.version_info[:3] == (3, 14, 4), 'actual fixed runtime required')
    label = request['group']
    require(label in plan['groups'] and request['ids'] == plan['groups'][label]['ids'], 'group differs')
    directory = Path(request['directory'])
    result = {'schema': SCHEMA + '.child', 'status': 'FAIL', 'request_pin': pin(raw),
              'group': label, 'source_before': before, 'cold': False, 'whole': False}
    try:
        if label == 'build-report-six':
            result['build'] = build_report(plan, directory)
        elif label == 'build-inspect':
            result['build'] = build_inspect(plan, directory)
        elif label in ('source10', 'source8'):
            result['tests'] = run_tests(request['ids'], directory)
            require(len(result['tests']['subtests']) == plan['groups'][label]['subtests'],
                    'original Source subtest count differs')
        else:
            context = {'source': str(source), 'adapter_files': plan['adapter_files'],
                'report_manifest': request['report_manifest'], 'inspect_manifest': request['inspect_manifest'],
                'controls_output': str(directory / 'controls')}
            if label in ('retained3', 'original-cli43'):
                require(os.environ.get('HEPTA_HIA_CLI_DEVELOPMENT_MANIFEST') == request['report_manifest']
                        and 'HEPTA_HIA_CLI_COLD_REPORT' not in os.environ
                        and 'HEPTA_HIA_CLI_MANIFEST' not in os.environ, 'mixed retained fixture authority')
                with retained_selection(context):
                    result['tests'] = run_tests(request['ids'], directory)
            else:
                import inspect_cli_control_support as support
                support.configure(context)
                result['tests'] = run_tests(request['ids'], directory)
        guard_runtime_context(request['runtime'])
        controls(plan)
        require(source_guard(plan) == before, 'actual whole source changed')
        result['status'] = 'PASS'
    except BaseException:
        result['traceback'] = traceback.format_exc()
    finally:
        try:
            result['source_after'] = source_guard(plan)
            result['source_unchanged'] = result['source_after'] == before
            require(result['source_unchanged'], 'terminal source differs')
            controls(plan)
            guard_runtime_context(request['runtime'])
        except BaseException:
            result['guard_error'] = traceback.format_exc(); result['status'] = 'FAIL'
        publish(directory / 'RESULT.json', result)
    return 0 if result['status'] == 'PASS' else 1


def bound_file(path):
    path = Path(path).absolute()
    raw = read_regular(path, maximum=max(CAPACITY, path.lstat().st_size))
    return {'path': str(path), 'pin': pin(raw, mode='100755' if path.stat().st_mode & 0o111 else '100644'),
            'posix_mode': stat.S_IMODE(path.lstat().st_mode)}


def artifact_inventory(directory):
    result = []
    for path in sorted(Path(directory).rglob('*')):
        require(not path.is_symlink(), 'stage artifact symlink refused')
        if path.is_dir():
            continue
        result.append(bound_file(path))
    return result


def execute(plan_path, plan_sha256):
    raw = read_regular(Path(plan_path).absolute(), maximum=16 << 20)
    require(hashlib.sha256(raw).hexdigest() == plan_sha256, 'bound plan raw differs')
    plan = json_bytes(raw)
    require(plan['schema'] == SCHEMA and plan['state'] == 'BOUND_AWAITING_EXPLICIT_EXECUTION'
            and plan['limits'] == {'owner_seconds': 180, 'cleanup_seconds': 3,
                'compile_seconds': 20, 'image_bytes': 1048576, 'vm_steps': 10000000,
                'storage_free_bytes': MINIMUM_FREE}, 'no authoring template/default/widened budget')
    require(set(plan['groups']) == set(plan['group_order'])
            and len(plan['group_order']) == len(set(plan['group_order'])), 'fixed group sequence differs')
    controls(plan)
    source_guard(plan)
    for row in plan['predecessor_evidence']:
        fixed(row)
    attempt = Path(plan['attempt'])
    require(attempt.is_absolute() and not attempt.exists() and attempt.parent.is_dir(),
            'one absent exclusive attempt required')
    require(os.statvfs(attempt.parent).f_bavail * os.statvfs(attempt.parent).f_frsize >= MINIMUM_FREE,
            'original 1GiB entry floor not met')
    attempt.mkdir(mode=0o700)
    (attempt / 'tmp').mkdir(mode=0o700)
    publish(attempt / 'PLAN-USED.json', plan)
    sys.path.insert(0, plan['source'])
    from tools.hia_linux_file_roundtrip_cold import guard_runtime_context, runtime_child_environment
    from tools.hia_selfhost_process_owner import run_owned
    runtime = plan['runtime']
    result = {'schema': SCHEMA + '.result', 'status': 'FAIL', 'plan_pin': pin(raw),
        'stages': [], 'owner_launch_attempts': 0, 'started_ns': time.monotonic_ns(),
        'scope': 'explicit preissued definition domain with real HIA op10; development only',
        'cold': False, 'default_activated': False, 'whole': False}
    report_manifest = inspect_manifest = None
    builds = []
    try:
        guard_runtime_context(runtime)
        require(runtime['version'] == [3, 14, 4], 'actual reviewed runtime differs')
        environment = runtime_child_environment({
            'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': str(attempt),
            'TMPDIR': str(attempt / 'tmp'), 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
            'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONHASHSEED': '0'}, runtime)
        publish(attempt / 'RUNTIME.json', runtime)
        for index, label in enumerate(plan['group_order']):
            controls(plan); source_guard(plan); guard_runtime_context(runtime)
            require(Path(plan_path).read_bytes() == raw, 'plan changed before next group')
            free = os.statvfs(attempt).f_bavail * os.statvfs(attempt).f_frsize
            require(free >= MINIMUM_FREE, 'original per-stage 1GiB floor not met; stop')
            for item in builds:
                fixed(item)
            directory = attempt / ('%02d-' % (index + 1) + label)
            directory.mkdir(mode=0o700)
            request = {'schema': SCHEMA + '.request', 'plan': bound_file(plan_path),
                'group': label, 'ids': plan['groups'][label]['ids'], 'runtime': runtime,
                'directory': str(directory), 'report_manifest': report_manifest,
                'inspect_manifest': inspect_manifest}
            if label not in ('source10', 'source8', 'build-report-six', 'build-inspect'):
                require(report_manifest is not None and inspect_manifest is not None,
                        'both actual builds must finish before any new/retained machine group')
            request_path = directory / 'REQUEST.json'; publish(request_path, request)
            flags = ['-B'] if label == 'original-cli43' else ['-I', '-B']
            command = [runtime['launch_executable'], *flags, str(HERE / Path(__file__).name),
                       '--child', str(request_path), '--request-sha256', pin(encoded(request))['sha256']]
            env = dict(environment)
            if label in ('retained3', 'original-cli43'):
                env.update(HEPTA_HIA_CLI_DEVELOPMENT_MANIFEST=report_manifest,
                           HEPTA_HIA_CLI_FIXTURE_EVIDENCE=str(directory / 'retained-fixtures'))
            publish(directory / 'COMMAND.json', {'command': command, 'cwd': plan['source'],
                'environment': env, 'supervisor_environment': env,
                'qualification_seconds': SECONDS, 'cleanup_seconds': CLEANUP,
                'free_bytes_before': free})
            row = {'label': label, 'status': 'FAIL', 'started_ns': time.monotonic_ns(),
                   'directory': str(directory), 'owner_returned': None}
            result['stages'].append(row)
            try:
                result['owner_launch_attempts'] += 1
                returned = run_owned(command, cwd=plan['source'], env=env, supervisor_env=env,
                    stdout_path=directory / 'stdout.raw', stderr_path=directory / 'stderr.raw',
                    receipt_path=directory / 'OWNER.json', qualification_seconds=SECONDS, cleanup_seconds=CLEANUP)
                row['owner_returned'] = returned
                publish(directory / 'OWNER-RETURNED.json', returned)
                complete_receipt(returned, directory / 'OWNER.json')
                actual = json_bytes((directory / 'RESULT.json').read_bytes())
                require(actual['status'] == 'PASS' and actual['source_unchanged'] is True
                        and actual['request_pin'] == pin(encoded(request)), 'actual child failed or differs')
                if label.startswith('build-'):
                    manifest = actual['build']['manifest']
                    require(Path(manifest).is_relative_to(directory), 'actual manifest left this build')
                    if label == 'build-report-six':
                        report_manifest = manifest
                    else:
                        inspect_manifest = manifest
                        require(actual['build']['image'] == plan['predecessor_inspect_image']['pin'],
                                'same HIA source/B3 failed exact actual R3 image comparison')
                    builds.extend(artifact_inventory(directory))
                else:
                    admit_tests(actual['tests'], request['ids'])
                    require(json_bytes((directory / 'TESTS.json').read_bytes()) == actual['tests'],
                            'actual test report/raw differs')
                row['status'] = 'PASS'
            except BaseException:
                row['error'] = traceback.format_exc()
                result['halted_after_first_failure'] = True
                raise
            finally:
                row['finished_ns'] = time.monotonic_ns()
                try:
                    row['source_after'] = source_guard(plan)
                    controls(plan); guard_runtime_context(runtime)
                except BaseException:
                    row['guard_error'] = traceback.format_exc(); row['status'] = 'FAIL'
                publish(directory / 'STAGE.json', row)
            require(row['status'] == 'PASS', 'post-owner source/runtime guard failed; no later stage')
        for item in builds:
            fixed(item)
        controls(plan); source_guard(plan); guard_runtime_context(runtime)
        result['status'] = 'DEVELOPMENT_OP10_CONTROLS_PASS'
    except BaseException:
        result['error'] = traceback.format_exc()
        result['halted_after_first_failure'] = True
    finally:
        result['finished_ns'] = time.monotonic_ns()
        try:
            result['source_after'] = source_guard(plan)
            controls(plan); guard_runtime_context(runtime)
        except BaseException:
            result['final_guard_error'] = traceback.format_exc(); result['status'] = 'FAIL'
        publish(attempt / 'OUTER.json', result)
    return 0 if result['status'] == 'DEVELOPMENT_OP10_CONTROLS_PASS' else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', type=Path)
    parser.add_argument('--plan-sha256')
    parser.add_argument('--child', type=Path)
    parser.add_argument('--request-sha256')
    args = parser.parse_args(argv)
    if args.child is not None:
        require(args.execute is None and args.plan_sha256 is None and args.request_sha256,
                'one exact child mode required')
        return child(args.child.absolute(), args.request_sha256)
    require(args.execute is not None and args.plan_sha256 and args.request_sha256 is None,
            'explicit bound plan and hash required; authoring is not authorization')
    return execute(args.execute.absolute(), args.plan_sha256)


if __name__ == '__main__':
    raise SystemExit(main())
