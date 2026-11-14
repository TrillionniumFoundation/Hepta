"""One explicitly bound op13 child under the unchanged 180+3 supervisor.

This file neither binds nor launches an owner. An authoring plan is rejected;
the caller must supply a new complete actual source/runtime/input binding.
No generator, compiler, Native owner or test runs when this module is read.
"""
from __future__ import annotations

import argparse
from hashlib import sha1, sha256
import json
import os
from pathlib import Path
import stat
import sys
import traceback
import unittest

SCHEMA = 'hepta.hia.patch-cli.bound-child.v3'
FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_nlink')
LIMITS = {'owner_seconds': 180, 'cleanup_seconds': 3, 'compile_seconds': 20,
          'native_capacity': 1048576, 'vm_steps': 10000000,
          'vm_heap': 8388608, 'vm_call_depth': 128}


def require(value, message):
    if not value:
        raise AssertionError(message)


def pin(raw, mode='100644'):
    return {'bytes': len(raw), 'mode': mode, 'sha256': sha256(raw).hexdigest(),
            'git_blob': sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def seven(info):
    return {key: getattr(info, key) for key in FIELDS}


def pairs(items):
    out = {}
    for key, value in items:
        require(type(key) is str and key not in out, 'duplicate/nonstring JSON key')
        out[key] = value
    return out


def decode(raw):
    return json.loads(raw, object_pairs_hook=pairs)


def fixed(row):
    require(type(row) is dict and set(row) == {'path', 'pin', 'stat'}, 'complete actual binding required')
    path = Path(row['path'])
    require(path.is_absolute() and '..' not in path.parts and set(row['stat']) == set(FIELDS),
            'absolute path and complete new stat required')
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and seven(before) == row['stat'] == seven(path.lstat())
                and before.st_size == row['pin']['bytes'], 'held/named input identity differs')
        pieces, remaining = [], before.st_size + 1
        while remaining:
            part = os.read(fd, min(1048576, remaining))
            if not part:
                break
            pieces.append(part)
            remaining -= len(part)
        raw = b''.join(pieces)
        require(seven(os.fstat(fd)) == row['stat'] == seven(path.lstat())
                and pin(raw, row['pin']['mode']) == row['pin'], 'actual input changed during full read')
        return raw
    finally:
        os.close(fd)


def metadata(root):
    """Complete fresh path/regular-mode/seven-stat inventory; no omissions."""
    rows = {'.': seven(root.lstat())}
    require(stat.S_ISDIR(rows['.']['st_mode']), 'source root is not an actual directory')
    def walk(directory, prefix):
        for item in sorted(os.scandir(directory), key=lambda value: value.name):
            info = item.stat(follow_symlinks=False)
            name = prefix + item.name
            require(stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode), 'unknown source member type')
            rows[name] = seven(info)
            if stat.S_ISDIR(info.st_mode):
                walk(Path(item.path), name + '/')
            else:
                require(info.st_nlink == 1, 'source must be an independently bound byte copy')
    walk(root, '')
    return rows


def source_guard(request, observer):
    expected = decode(fixed(request['source_map']))
    state = decode(fixed(request['source_state']))
    root = Path(request['source'])
    require(root.is_absolute() and '..' not in root.parts and len(expected) == 3210,
            'complete 3210 source scope required')
    before = metadata(root)
    require(before == state, 'actual complete source identity differs before read')
    # Reuse the exact original reader. It reads every regular source file;
    # this call never replaces contents by a cached digest or receipt.
    actual = observer.snapshot(root)
    require(actual == expected and metadata(root) == before,
            'source bytes/modes/pathset/seven stats changed')
    return {'files': len(actual), 'source_map': request['source_map']['pin'],
            'source_state': request['source_state']['pin'], 'all_bytes_read': True}


def controls_guard(request):
    require(type(request['controls']) is dict and request['controls'], 'actual control bindings required')
    for key in sorted(request['controls']):
        fixed(request['controls'][key])
    require(Path(request['controls']['run_control_child.py']['path']) == Path(__file__).absolute(),
            'bound child identity differs')


def publish(path, value):
    raw = (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
    require(Path(path).read_bytes() == raw, 'evidence readback differs')


def flatten(suite):
    if isinstance(suite, unittest.TestSuite):
        for item in suite:
            yield from flatten(item)
    else:
        yield suite


def run_tests(ids, report_path):
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromNames(ids)
    report = {'status': 'FAIL', 'declared_ids': ids, 'loaded_ids': [test.id() for test in flatten(suite)],
              'loader_errors': list(loader.errors), 'events': [], 'subtests': []}
    class Result(unittest.TextTestResult):
        def startTest(self, test):
            report['events'].append(['start', test.id()])
            super().startTest(test)
        def stopTest(self, test):
            report['events'].append(['stop', test.id()])
            super().stopTest(test)
        def addSubTest(self, test, subtest, err):
            report['subtests'].append({'parent': test.id(), 'id': subtest.id(),
                                      'status': 'PASS' if err is None else 'FAIL'})
            super().addSubTest(test, subtest, err)
    try:
        require(not loader.errors and report['loaded_ids'] == ids and suite.countTestCases() == len(ids),
                'exact loaded IDs differ')
        actual = unittest.TextTestRunner(stream=sys.stderr, verbosity=2, resultclass=Result).run(suite)
        report.update(tests_run=actual.testsRun,
            failures=[(test.id(), text) for test, text in actual.failures],
            errors=[(test.id(), text) for test, text in actual.errors],
            skipped=[(test.id(), text) for test, text in actual.skipped],
            expected_failures=[(test.id(), text) for test, text in actual.expectedFailures],
            unexpected_successes=[test.id() for test in actual.unexpectedSuccesses])
        require(actual.testsRun == len(ids) and report['events'] ==
                [event for name in ids for event in (['start', name], ['stop', name])]
                and not any(report[key] for key in ('failures', 'errors', 'skipped',
                    'expected_failures', 'unexpected_successes'))
                and all(row['status'] == 'PASS' for row in report['subtests']),
                'test failure/error/skip/missing event')
        report['status'] = 'PASS'
    except BaseException:
        report['traceback'] = traceback.format_exc()
        raise
    finally:
        publish(report_path, report)
    return report


def child(request_path, request_sha256):
    path = Path(request_path).absolute()
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= 8 << 20, 'bounded owned request required')
    raw = path.read_bytes()
    require(seven(path.lstat()) == seven(info) and sha256(raw).hexdigest() == request_sha256,
            'request bytes changed')
    request = decode(raw)
    require(request['schema'] == SCHEMA and request['state'] == 'BOUND_AWAITING_ROOT_AUTHORIZATION'
            and request['limits'] == LIMITS, 'unbound template or changed original budgets')
    directory = Path(request['directory'])
    require(directory.is_absolute() and stat.S_ISDIR(directory.lstat().st_mode)
            and stat.S_IMODE(directory.lstat().st_mode) == 0o700, 'exclusive owned evidence root required')
    result = {'schema': SCHEMA + '.result', 'status': 'FAIL', 'request_pin': pin(raw),
              'phase': request['phase'], 'current_cold': False, 'default': False, 'whole': False}
    observer = guard_runtime = None
    try:
        controls_guard(request)
        observer_row = request['controls']['inspect_exec_support.py']
        require(observer_row['pin']['git_blob'] == 'f6d59fd0caef181064c5b77adca2b7e9216ac332',
                'original FrameJournal support differs')
        sys.path.insert(0, str(Path(observer_row['path']).parent))
        import inspect_exec_support
        observer = inspect_exec_support
        require(Path(observer.__file__).absolute() == Path(observer_row['path']), 'wrong observer module loaded')
        result['source_before'] = source_guard(request, observer)
        require(sys.implementation.name == 'cpython' and sys.version_info[:3] == (3, 14, 4)
                and sys.flags.dont_write_bytecode and sys.flags.isolated, 'actual 3.14.4 -I -B required')
        sys.path[:0] = [request['source'], str(Path(request['controls']['inspect_cli_control_support.py']['path']).parent)]
        from tools.hia_linux_file_roundtrip_cold import guard_runtime_context
        guard_runtime = guard_runtime_context
        guard_runtime(request['runtime'])
        matrix = decode(fixed(request['controls']['CONTROL-MATRIX.json']))
        groups = {'source8': matrix['source_ids']}
        groups.update((row['group'], [row['id']]) for row in matrix['native_groups'])
        require(request['group'] in groups and request['ids'] == groups[request['group']],
                'exact group/ID selection differs')
        phase = 'source' if request['group'] == 'source8' else 'native'
        cfg = request['context']
        require(request['phase'] == cfg['phase'] == phase and cfg['source'] == request['source']
                and cfg['controls_output'] == str(directory / 'controls'), 'bound context differs')
        if phase == 'native':
            group = next(row for row in matrix['native_groups'] if row['group'] == request['group'])
            require(cfg['signature_native'] is group['signature_native'], 'signature choice differs')
            require(set(request['native_inputs']) == {'control', 'format', 'discovery', 'routing',
                'parser_context', 'verified_report', 'inspect', 'patch'}, 'eight actual component bindings required')
            for row in request['native_inputs'].values():
                for key in ('manifest', 'source', 'image'):
                    fixed(row[key])
            fixed(request['report_bundle'])
            require(cfg['report_manifest'] == request['report_bundle']['path']
                    and cfg['inspect_manifest'] == request['native_inputs']['inspect']['manifest']['path']
                    and cfg['patch_manifest'] == request['native_inputs']['patch']['manifest']['path'],
                    'actual manifests differ from the context')
        else:
            require(not any(key in request for key in ('native_inputs', 'report_bundle')),
                    'Source-only request cannot open Native path')
        from tests import hia_patch_cli_support
        hia_patch_cli_support.configure(cfg)
        result['tests'] = run_tests(request['ids'], directory / 'TESTS.json')
        result['status'] = 'PASS'
    except BaseException:
        result['traceback'] = traceback.format_exc()
    finally:
        errors = []
        for name in ('source', 'controls', 'runtime', 'native-inputs'):
            try:
                if name == 'source':
                    require(observer is not None, 'source reader never established')
                    result['source_after'] = source_guard(request, observer)
                    require(result['source_after'] == result.get('source_before'), 'terminal source differs')
                elif name == 'controls':
                    controls_guard(request)
                elif name == 'runtime':
                    require(guard_runtime is not None, 'runtime guard never established')
                    guard_runtime(request['runtime'])
                elif request['phase'] == 'native':
                    for row in request['native_inputs'].values():
                        for key in ('manifest', 'source', 'image'):
                            fixed(row[key])
                    fixed(request['report_bundle'])
            except BaseException:
                errors.append({'guard': name, 'traceback': traceback.format_exc()})
        if errors:
            result.update(status='FAIL', terminal_guard_errors=errors)
        try:
            publish(directory / 'RESULT.json', result)
        except BaseException:
            result.update(status='FAIL', publication_error=traceback.format_exc())
            try:
                sys.stderr.write(json.dumps(result, sort_keys=True) + '\n')
                sys.stderr.flush()
            except BaseException:
                pass
    return 0 if result['status'] == 'PASS' else 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--request', required=True)
    parser.add_argument('--request-sha256', required=True)
    args = parser.parse_args()
    return child(args.request, args.request_sha256)


if __name__ == '__main__':
    raise SystemExit(main())
