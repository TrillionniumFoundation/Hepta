"""Run only the original3/CLI43 groups after a separate real build admission.

The original failed build remains immutable; all build entry points reject.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import stat
import sys
import time
import traceback

HERE = Path(__file__).absolute().parent
ROOT = Path('/workspace/scratch/dda74a4fae35')
FIRST = ROOT / 'v119-inspect-retained-regressions-r1'
RECOVERY = ROOT / 'v119-inspect-retained-recovery-r1'
PRIOR = ROOT / 'v119-inspect-source10-r1'
GEN = ROOT / 'v119-inspect-generation-only-r1'
KIT = ROOT / 'v119-inspect-policy-execution-r1'
BASE = ROOT / 'v120-union-r20/source'
SOURCE = GEN / 'attempt-r1/source'
TREE = '7df49dd24bbba4ba3210168e639d6ea35a76a475'
SCHEMA = 'hepta.hia.inspect-retained-regression-stages.v2'
SECONDS, CLEANUP, MIB = 180, 3, 1048576
_ATTEMPT = None


def require(value, message):
    if not value:
        raise AssertionError(message)


def pin(raw):
    return {'bytes': len(raw), 'mode': '100644', 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def bootstrap(plan_path, plan_sha256):
    raw = Path(plan_path).read_bytes()
    require(hashlib.sha256(raw).hexdigest() == plan_sha256, 'reviewed stage plan differs')
    plan = json.loads(raw)
    require(plan['schema'] == SCHEMA + '.plan' and plan['status'] == 'AUTHORED_NOT_EXECUTED'
            and plan['source'] == {'path': str(SOURCE), 'tree': TREE, 'files': 3187}
            and plan['limits'] == {'qualification_seconds': SECONDS, 'cleanup_seconds': CLEANUP,
                                   'compile_seconds': 20, 'capacity': MIB}
            and pin(Path(__file__).read_bytes()) == plan['runner'], 'fixed stage contract differs')
    require(pin((HERE / 'CONTRACT.md').read_bytes()) == plan['contract'], 'stage contract changed')
    require(pin((FIRST / 'run_retained_regressions.py').read_bytes()) == plan['original_runner']
            and pin((RECOVERY / 'admit_existing_cli_build.py').read_bytes()) == plan['admission_runner']
            and pin((RECOVERY / 'ADMISSION-PLAN.json').read_bytes()) == plan['admission_plan']['pin'],
            'separate original/recovery authority changed')
    require(pin((PRIOR / 'run_source10_only_r2.py').read_bytes()) == plan['prior_runner'], 'prior runner changed')
    sys.path.insert(0, str(PRIOR))
    import run_source10_only_r2 as prior
    require(Path(prior.__file__).absolute() == PRIOR / 'run_source10_only_r2.py', 'wrong prior guard')
    old_plan, guard, support, captures = prior.bootstrap(PRIOR / 'SOURCE10-PLAN-R2.json', plan['prior_plan_sha256'])
    for name, row in plan['prior_results'].items():
        value, metadata = guard.read_exact(Path(row['path']), maximum=max(row['pin']['bytes'], MIB), expected=row['pin'])
        require(metadata['mode'] == row['posix_mode'], 'prior result mode changed')
        if name == 'result':
            result = json.loads(value)
            require(result['status'] == 'SOURCE10_ONLY_PASS' and result['owner_launch_attempts'] == 1
                    and result['source_tree'] == TREE and result['complete_source_guard_pass'] is True,
                    'completed exact Source10 prerequisite missing')
    spec = json.loads((KIT / 'EXECUTION-SPEC.json').read_bytes())
    require(plan['groups'] == {name: spec['groups'][name] for name in ('original3', 'original-cli43')}
            and len(plan['groups']['original3']) == 3 and len(plan['groups']['original-cli43']) == 43,
            'original groups and exact ordered IDs differ')
    require(plan['ordered_group_names'] == ['original3', 'original-cli43'], 'original group order differs')
    require(plan['overlap_ids'] == sorted(set(plan['groups']['original3']) & set(plan['groups']['original-cli43']))
            and len(plan['overlap_ids']) == 1, 'original shared method projection differs')
    sys.path.insert(0, str(KIT))
    import run_inspect_development as frozen
    require(Path(frozen.__file__).absolute() == KIT / 'run_inspect_development.py', 'wrong frozen executor')
    return plan, prior, old_plan, guard, support, captures, frozen


def full_guard(output, label, context):
    plan, prior, old_plan, guard, support, captures, frozen = context
    return prior.full_guard(output, label, old_plan, guard, support, captures)


def write_fence(protected_inodes, additional_roots=()):
    """Process-local cooperative write guard; original owned subprocesses remain allowed.

    The original CLI tests create wheel fixtures and subprocesses. Their calls
    are not replaced. Independent complete byte/stat guards remain required.
    This Python hook is not a hostile-code sandbox or an inherited OS policy.
    """
    roots = (BASE, SOURCE, KIT, GEN, PRIOR, FIRST, RECOVERY, *additional_roots)
    exact = (Path(__file__).absolute(), HERE / 'PLAN.json', HERE / 'CONTRACT.md')
    def check(path, directory_fd=None):
        if type(path) is int:
            current = os.fstat(path)
            require((current.st_dev, current.st_ino) not in protected_inodes, 'protected descriptor mutation')
            return
        require(type(path) in (str, bytes), 'exact filesystem argument required')
        named = Path(os.fsdecode(path))
        if named.is_absolute() or directory_fd in (None, -1, -100):
            value = Path(os.path.abspath(named))
        else:
            require(type(directory_fd) is int, 'exact directory descriptor required')
            held = os.fstat(directory_fd)
            require(stat.S_ISDIR(held.st_mode), 'directory descriptor is not a directory')
            name = os.readlink('/proc/self/fd/' + str(directory_fd))
            require(name.startswith('/') and not name.endswith(' (deleted)'), 'unavailable held directory')
            directory = Path(name)
            current = directory.stat()
            require((current.st_dev, current.st_ino) == (held.st_dev, held.st_ino), 'named/held directory differs')
            value = Path(os.path.abspath(directory / named))
        resolved = value.resolve(strict=False)
        require(value not in exact and resolved not in exact
                and not any(value.is_relative_to(root) or resolved.is_relative_to(root) for root in roots),
                'protected source/evidence mutation')
        try:
            current = value.stat()
        except FileNotFoundError:
            return
        require((current.st_dev, current.st_ino) not in protected_inodes, 'protected inode alias mutation')
    def audit(event, args):
        if event == 'open':
            path, mode, flags = args
            if (type(flags) is int and flags & (os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND)) or (
                    type(mode) is str and any(c in mode for c in 'wax+')):
                check(path)
        elif event in ('os.remove', 'os.rmdir'):
            check(args[0], args[1])
        elif event in ('os.mkdir', 'os.chmod'):
            check(args[0], args[2])
        elif event in ('os.chown', 'os.utime'):
            check(args[0], args[3])
        elif event == 'os.truncate':
            check(args[0])
        elif event in ('os.rename', 'os.link'):
            check(args[0], args[2]); check(args[1], args[3])
        elif event == 'os.symlink':
            check(args[1], args[2])
    sys.addaudithook(audit)


def bind_cli_build(path, expected_sha, context):
    """Consume the separate actual read-only admission; never upgrade old FAIL."""
    plan, prior, old_plan, guard, support, captures, frozen = context
    require(path is not None and type(expected_sha) is str and len(expected_sha) == 64,
            'explicit actual read-only admission result binding required')
    sys.path.insert(0, str(RECOVERY))
    import admit_existing_cli_build as admission
    require(Path(admission.__file__).absolute() == RECOVERY / 'admit_existing_cli_build.py',
            'wrong separate admission consumer')
    loaded = admission.bootstrap(plan['admission_plan']['path'], plan['admission_plan']['pin']['sha256'])
    require(loaded[0]['source'] == plan['source'], 'recovery and retained sources differ')
    return admission.verified_result(path, expected_sha, loaded)


def run_frozen_child(inner_path, inner_sha, subtest_path, support, frozen):
    import unittest
    original = unittest.TextTestResult
    rows = []
    class Result(original):
        def addSubTest(self, test, subtest, error):
            # Do not inspect/repr arbitrary original subtest provider values.
            rows.append({'ordinal': len(rows)+1, 'method_id': test.id(), 'success': error is None})
            return super().addSubTest(test, subtest, error)
    unittest.TextTestResult = Result
    try:
        return frozen.child(inner_path, inner_sha)
    finally:
        unittest.TextTestResult = original
        support.publish(subtest_path, {'schema': SCHEMA + '.subtests', 'observations': rows,
            'foreign_parameter_protocols_not_probed': True, 'original_TextTestResult_restored': True})


def child(request_path, request_sha256):
    raw = Path(request_path).read_bytes()
    require(hashlib.sha256(raw).hexdigest() == request_sha256, 'wrapper request changed')
    request = json.loads(raw)
    require(request['schema'] == SCHEMA + '.request', 'unknown wrapper request')
    require(request['stage'] in ('original3', 'original-cli43'), 'R2 child forbids all build stages')
    context = bootstrap(request['plan'], request['plan_sha256'])
    plan, prior, old_plan, guard, support, captures, frozen = context
    directory = Path(request_path).parent
    output = directory / 'wrapper'
    output.mkdir(mode=0o700); (output / 'maps').mkdir(mode=0o700)
    result = {'schema': SCHEMA + '.child', 'status': 'FAIL', 'request_pin': pin(raw),
              'matching_current_cold': False, 'whole_cli_native': False}
    binding = None
    try:
        full_guard(output, 'before', context)
        sys.path.insert(0, str(SOURCE))
        from tools.hia_linux_file_roundtrip_cold import guard_runtime_context
        guard_runtime_context(request['runtime_context'])
        inner_path = directory / 'FROZEN-REQUEST.json'
        inner_raw = inner_path.read_bytes()
        require(pin(inner_raw) == request['inner_request_pin'], 'frozen child request changed')
        inner = support.json_bytes(inner_raw)
        require(inner['source'] == str(SOURCE) and inner['runtime_context'] == request['runtime_context'],
                'fixed child source/runtime differs')
        if request['stage'] == 'build-cli':
            require(inner['kind'] == 'build-cli' and inner['group'] == 'build-cli'
                    and inner['ids'] == [] and request['build_result'] is None, 'invalid build stage')
        else:
            require(request['stage'] in plan['ordered_group_names'] and inner['kind'] == 'tests'
                    and inner['group'] == request['stage'] and inner['ids'] == plan['groups'][request['stage']],
                    'original group or exact IDs changed')
            binding = bind_cli_build(request['build_result'], request['build_result_sha256'], context)
            require(inner['cli_manifest'] == binding['manifest'], 'original group CLI fixture differs')
        protected = {(row['device'], row['inode']) for key in ('base_final', 'source_final')
                     for row in captures[key]['stat'].values()}
        if binding:
            protected.update((row['device'], row['inode']) for row in binding['capture']['stat'].values())
        write_fence(protected, () if binding is None else (Path(binding['output']),))
        code = run_frozen_child(inner_path, pin(inner_raw)['sha256'], output / 'SUBTESTS.json', support, frozen)
        require(code == 0, 'original frozen child/group failed')
        if binding:
            require(bind_cli_build(request['build_result'], request['build_result_sha256'], context) == binding,
                    'actual CLI build changed during original group')
        guard_runtime_context(request['runtime_context'])
        result.update(status='PASS', original_child_returncode=code)
    except BaseException:
        result['traceback'] = traceback.format_exc()
    finally:
        try:
            full_guard(output, 'after', context)
            result['all_source_bytes_modes_stats_unchanged'] = True
        except BaseException:
            result['source_guard_error'] = traceback.format_exc(); result['status'] = 'FAIL'
        support.publish(output / 'RESULT.json', result)
    return 0 if result['status'] == 'PASS' else 1


def execute(plan_path, plan_sha256, kind, attempt, build_result=None, build_result_sha256=None):
    global _ATTEMPT
    require(kind == 'retained-groups', 'R2 forbids all new build entry points')
    context = bootstrap(plan_path, plan_sha256)
    plan, prior, old_plan, guard, support, captures, frozen = context
    attempt = Path(attempt).absolute()
    expected = HERE / ('build-cli-attempt-r1' if kind == 'build-cli' else 'retained-groups-attempt-r1')
    require(attempt == expected and not attempt.exists(), 'new fixed stage attempt required')
    require(guard.storage(HERE)['available_bytes'] >= plan['minimum_free_bytes'][kind],
            'insufficient independent stage evidence/fixture storage')
    binding = None
    if kind == 'build-cli':
        require(build_result is None and build_result_sha256 is None, 'build stage cannot inherit another build')
    else:
        require(build_result is not None and build_result_sha256 is not None, 'actual build result required')
    attempt.mkdir(mode=0o700); _ATTEMPT = attempt
    (attempt / 'maps').mkdir(mode=0o700); (attempt / 'tmp').mkdir(mode=0o700)
    support.publish(attempt / 'PLAN-USED.json', plan)
    report = {'schema': SCHEMA + '.result', 'status': 'FAIL', 'scope': kind,
        'plan_pin': pin(Path(plan_path).read_bytes()), 'stages': [], 'owner_launch_attempts': 0,
        'group_counts': {}, 'source_tree': TREE, 'source_files': 3187,
        'matching_current_cold': False, 'whole_cli_native': False,
        'inspect_owner_executed': False, 'inspect_Native17_executed': False,
        'inspect_VM12_executed': False, 'started_ns': time.monotonic_ns()}
    try:
        full_guard(attempt, 'before', context)
        if kind == 'retained-groups':
            binding = bind_cli_build(build_result, build_result_sha256, context)
        sys.path.insert(0, str(SOURCE))
        from tools.hia_selfhost_process_owner import run_owned
        from tools.hia_linux_file_roundtrip_cold import (
            capture_runtime_context, guard_runtime_context, runtime_child_environment)
        runtime = capture_runtime_context()
        require(runtime == captures['generation_runtime'], 'fixed actual runtime changed')
        support.publish(attempt / 'RUNTIME.json', runtime)
        environment = runtime_child_environment({'PATH': '/usr/local/bin:/usr/bin:/bin',
            'HOME': str(attempt), 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
            'PYTHONDONTWRITEBYTECODE': '1', 'TMPDIR': str(attempt / 'tmp')}, runtime)
        groups = ['build-cli'] if kind == 'build-cli' else plan['ordered_group_names']
        for ordinal, group in enumerate(groups):
            directory = attempt / ('%02d-%s' % (ordinal, group))
            directory.mkdir(mode=0o700); (directory / 'maps').mkdir(mode=0o700)
            full_guard(directory, 'before', context)
            guard_runtime_context(runtime); support.check_kit()
            env = dict(environment)
            inner = {'schema': frozen.REQUEST_SCHEMA, 'kind': 'build-cli' if kind == 'build-cli' else 'tests',
                'source': str(SOURCE), 'source_map': plan['source_map']['path'],
                'source_map_pin': plan['source_map']['pin'], 'kit_index_pin': plan['kit_index_pin'],
                'runtime_context': runtime, 'output': str(directory / 'FROZEN-RESULT.json'),
                'group': group, 'ids': [] if kind == 'build-cli' else plan['groups'][group]}
            if kind == 'build-cli':
                inner['build_output'] = str(attempt / 'retained-cli-build')
            else:
                binding = bind_cli_build(build_result, build_result_sha256, context)
                inner['cli_manifest'] = binding['manifest']
                inner['controls_output'] = str(directory / 'controls')
                env.update(HEPTA_HIA_CLI_DEVELOPMENT_MANIFEST=binding['manifest'],
                           HEPTA_HIA_CLI_FIXTURE_EVIDENCE=str(directory / 'retained-fixtures'))
            inner_path = directory / 'FROZEN-REQUEST.json'; support.publish(inner_path, inner)
            request = {'schema': SCHEMA + '.request', 'stage': group,
                'plan': str(Path(plan_path).absolute()), 'plan_sha256': plan_sha256,
                'runtime_context': runtime, 'inner_request_pin': pin(inner_path.read_bytes()),
                'build_result': None if binding is None else binding['result'],
                'build_result_sha256': None if binding is None else binding['result_pin']['sha256']}
            request_path = directory / 'REQUEST.json'; support.publish(request_path, request)
            command = [sys.executable, '-I', '-B', str(Path(__file__).absolute()),
                       '--child', str(request_path), '--request-sha256', pin(request_path.read_bytes())['sha256']]
            support.publish(directory / 'COMMAND.json', {'argv': command, 'cwd': str(SOURCE),
                'environment': env, 'supervisor_environment': env,
                'qualification_seconds': SECONDS, 'cleanup_seconds': CLEANUP})
            row = {'group': group, 'status': 'FAIL', 'started_ns': time.monotonic_ns()}
            report['stages'].append(row)
            returned = None
            try:
                report['owner_launch_attempts'] += 1
                returned = run_owned(command, cwd=SOURCE, env=env, supervisor_env=env,
                    stdout_path=directory / 'stdout.raw', stderr_path=directory / 'stderr.raw',
                    receipt_path=directory / 'OWNER.json', qualification_seconds=SECONDS,
                    cleanup_seconds=CLEANUP)
                support.publish(directory / 'OWNER-RETURNED.json', returned)
                support.complete_receipt(returned, directory / 'OWNER.json')
                wrapper = support.json_bytes((directory / 'wrapper/RESULT.json').read_bytes())
                require(wrapper['status'] == 'PASS' and wrapper['request_pin'] == pin(request_path.read_bytes())
                        and wrapper['all_source_bytes_modes_stats_unchanged'] is True, 'wrapper did not complete')
                value = support.json_bytes((directory / 'FROZEN-RESULT.json').read_bytes())
                require(value['status'] == 'PASS' and value['request_pin'] == pin(inner_path.read_bytes())
                        and value['source_unchanged'] is True and value['compiler_unchanged'] is True,
                        'actual original child result differs')
                if kind == 'retained-groups':
                    tests = support.json_bytes((directory / 'TESTS.json').read_bytes())
                    ids = plan['groups'][group]
                    require(tests == value['tests'] and tests['status'] == 'PASS'
                            and tests['declared_ids'] == tests['loaded_ids'] == tests['started_ids'] == tests['stopped_ids'] == ids
                            and tests['tests_run'] == len(ids)
                            and tests['events'] == [e for name in ids for e in (['start', name], ['stop', name])]
                            and not any(tests[k] for k in ('loader_errors','failures','errors','skipped','expected_failures','unexpected_successes')),
                            'original complete test observation differs')
                    subtests = support.json_bytes((directory / 'wrapper/SUBTESTS.json').read_bytes())
                    require(all(x['success'] for x in subtests['observations']), 'original subtest failure')
                    report['group_counts'][group] = {'tests_run': len(ids), 'events': len(ids)*2,
                        'subtests': len(subtests['observations']), 'exact_ids': ids, 'status': 'PASS'}
                    require(bind_cli_build(build_result, build_result_sha256, context) == binding,
                            'CLI build changed after original group')
                guard_runtime_context(runtime); support.check_kit()
                row['status'] = 'PASS'
            except BaseException:
                row['traceback'] = traceback.format_exc()
                raise
            finally:
                row['owner_returned'] = returned; row['finished_ns'] = time.monotonic_ns()
                try:
                    full_guard(directory, 'after', context)
                    row['source_guard_pass'] = True
                except BaseException:
                    row['source_guard_error'] = traceback.format_exc(); row['status'] = 'FAIL'
                    raise
                finally:
                    support.publish(directory / 'STAGE.json', row)
        if kind == 'build-cli':
            build = attempt / 'retained-cli-build'
            file_map = support.snapshot(build)
            captured = guard.capture(build, file_map)
            guard.assert_capture(captured, file_map)
            report['build_capture'] = guard.cas(attempt, captured)
            report['status'] = 'BUILD_CLI_ONLY_PASS'
        else:
            report.update(status='RETAINED_GROUPS_PASS', methods_executed=46,
                          distinct_method_ids=45, overlap_ids=plan['overlap_ids'])
    except BaseException:
        report['traceback'] = traceback.format_exc(); report['halted_after_first_failed_stage'] = True
        report['status'] = 'FAIL'
    finally:
        try:
            full_guard(attempt, 'after', context)
            report['complete_source_guard_pass'] = True
        except BaseException:
            report['source_guard_error'] = traceback.format_exc(); report['status'] = 'FAIL'
        report['finished_ns'] = time.monotonic_ns()
        support.publish(attempt / 'RESULT.json', report)
    return 0 if report['status'] in ('BUILD_CLI_ONLY_PASS', 'RETAINED_GROUPS_PASS') else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute-stage', choices=('retained-groups',))
    parser.add_argument('--plan', type=Path); parser.add_argument('--plan-sha256')
    parser.add_argument('--attempt', type=Path); parser.add_argument('--build-result', type=Path)
    parser.add_argument('--build-result-sha256'); parser.add_argument('--child', type=Path)
    parser.add_argument('--request-sha256')
    args = parser.parse_args(argv)
    if args.child is not None:
        require(args.execute_stage is None and args.plan is None and args.plan_sha256 is None
                and args.attempt is None and args.build_result is None and args.build_result_sha256 is None
                and args.request_sha256 is not None, 'mixed child/parent invocation')
        return child(args.child, args.request_sha256)
    require(args.execute_stage and args.plan and args.plan_sha256 and args.attempt
            and args.request_sha256 is None, 'explicit reviewed stage required')
    try:
        return execute(args.plan, args.plan_sha256, args.execute_stage, args.attempt,
                       args.build_result, args.build_result_sha256)
    except BaseException:
        error = traceback.format_exc(); sys.stderr.write(error)
        if _ATTEMPT is not None and not (_ATTEMPT / 'RESULT.json').exists():
            with (_ATTEMPT / 'ENTRY-FAILURE.json').open('x') as stream:
                json.dump({'status': 'FAIL', 'traceback': error, 'matching_current_cold': False}, stream)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
