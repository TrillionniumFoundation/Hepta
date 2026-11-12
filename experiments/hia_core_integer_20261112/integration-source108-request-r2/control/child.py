"""Source/VM controls with four exact negative Python commands and all other entry poisons."""
from __future__ import annotations
from contextlib import ExitStack
import ctypes
from hashlib import sha256
import importlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import stat
import tempfile
import time
import traceback
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import HERE, identity, pin, require, request, runtime, save


def flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from flatten(item)
        else:
            yield item


# These are the four existing negative-admission commands in one unchanged
# source method. They are not a general subprocess or native-entry allowance.
NEGATIVE_PROCESS_POLICY = {
    'schema': 'hepta.source83-four-negative-python-permissions.v1',
    'target_test_id': 'tests.test_hia_store_page_gates.StorePageCIGateTests.'
                      'test_real_command_rejects_bad_cold_and_development_before_creating_evidence',
    'script': 'tools/qualify_hia_store_page_ci.py',
    'binding_sources': [
        'tests/test_hia_store_page_gates.py',
        'tools/qualify_hia_store_page_ci.py',
        'tools/hia_store_page_gates.py',
        'tools/build_hia_json_preflight.py'],
    'cases': [
        {'owner': 'authority', 'development': False},
        {'owner': 'authority', 'development': True},
        {'owner': 'page', 'development': False},
        {'owner': 'page', 'development': True}],
    'prefixes': {'authority': 'HEPTA_HIA_AGENT_STORE_AUTHORITY',
                 'page': 'HEPTA_HIA_ARTIFACT_PAGE'},
    'python_flags': ['-I', '-S', '-B'],
    'environment': {'PATH': '', 'LANG': 'C', 'LC_ALL': 'C'},
    'development_value': '/old/development',
    'input_bytes_utf8': '{}',
    'timeout_seconds': 10,
    'expected_processes': 4,
    'all_other_subprocess_entries_forbidden': True,
    'native_and_compiler_entries_forbidden': True,
    'zero_process_scope_claimed': False,
}


class NegativeAdmissions:
    """Validate before delegating to the original run/Popen implementations.

    No child result, exception, communicate call or context-manager exit is
    mocked. The exact original run() owns its original ten-second timeout and
    its original Popen cleanup. A consumed permission is never retried.
    """
    def __init__(self, policy, source, output, current_test, forbidden):
        require(policy['source_child_process_policy'] == NEGATIVE_PROCESS_POLICY,
                'frozen four-command process policy differs')
        self.policy, self.source, self.output = policy, source, output
        self.current_test, self.forbidden = current_test, forbidden
        self.original_run, self.original_popen = subprocess.run, subprocess.Popen
        self.completed_type = subprocess.CompletedProcess
        self.rows, self.refusals = [], []
        self.pending = None

    def check(self, condition, message):
        if not condition:
            self.refusals.append(message)
            self.forbidden()

    def sources(self):
        expected = {row['relative_path']: row for row in self.policy['source_files']}
        rows = []
        for name in NEGATIVE_PROCESS_POLICY['binding_sources']:
            observed = pin(self.source / name)
            self.check(all(observed[key] == expected[name][key]
                           for key in ('size', 'sha256', 'git_blob_sha1', 'mode')),
                       'negative-command frozen source changed: ' + name)
            self.check(observed['uid'] == os.geteuid() and observed['nlink'] == 1
                       and observed['mode'] & 0o022 == 0
                       and str((self.source / name).resolve(strict=True)) == observed['path'],
                       'negative-command source ownership/alias differs')
            rows.append(observed)
        return rows

    @staticmethod
    def directory_identity(value):
        return {'device': value.st_dev, 'inode': value.st_ino,
                'mode': stat.S_IMODE(value.st_mode), 'uid': value.st_uid,
                'gid': value.st_gid, 'nlink': value.st_nlink,
                'size': value.st_size, 'mtime_ns': value.st_mtime_ns,
                'ctime_ns': value.st_ctime_ns}

    def temporary(self, cwd, descriptor):
        named, held = cwd.lstat(), os.fstat(descriptor)
        self.check(stat.S_ISDIR(named.st_mode) and identity(named) == identity(held)
                   and named.st_uid == os.geteuid() and stat.S_IMODE(named.st_mode) == 0o700
                   and cwd == cwd.resolve(strict=True)
                   and cwd.parent == Path(tempfile.gettempdir()).resolve(strict=True),
                   'negative-command current private temporary directory differs')
        self.check(os.listdir(descriptor) == ['cold.json'],
                   'negative command must have only its original cold.json input')
        return self.directory_identity(held)

    def cold(self, cwd, directory_fd, descriptor):
        named = os.stat('cold.json', dir_fd=directory_fd, follow_symlinks=False)
        held = os.fstat(descriptor)
        self.check(stat.S_ISREG(named.st_mode) and identity(named) == identity(held)
                   and named.st_uid == os.geteuid() and named.st_nlink == 1
                   and stat.S_IMODE(named.st_mode) & 0o022 == 0 and named.st_size == 2,
                   'negative-command input is not the original owned regular two-byte file')
        os.lseek(descriptor, 0, os.SEEK_SET)
        raw = os.read(descriptor, 3)
        self.check(raw == b'{}' and identity(held) == identity(os.fstat(descriptor))
                   == identity(os.stat('cold.json', dir_fd=directory_fd, follow_symlinks=False)),
                   'negative-command input changed or is not the original {} bytes')
        result = pin(cwd / 'cold.json')
        self.check(result['size'] == 2 and result['sha256'] == sha256(raw).hexdigest(),
                   'negative-command original input pin differs')
        return result

    def expected_command(self, cwd, case):
        return [sys.executable, '-I', '-S', '-B',
                str(self.source / NEGATIVE_PROCESS_POLICY['script']), 'component',
                '--owner', case['owner'], '--cold-report', str(cwd / 'cold.json'),
                '--output', str(cwd / 'report.json'), '--evidence-dir', str(cwd / 'evidence')]

    def expected_environment(self, case):
        result = dict(NEGATIVE_PROCESS_POLICY['environment'])
        if case['development']:
            result[NEGATIVE_PROCESS_POLICY['prefixes'][case['owner']]
                   + '_DEVELOPMENT_MANIFEST'] = '/old/development'
        return result

    def write_bytes(self, path, raw):
        with path.open('xb') as stream:
            stream.write(raw)
        return pin(path)

    def popen(self, *arguments, **keywords):
        permit = self.pending
        self.check(permit is not None and self.current_test() == NEGATIVE_PROCESS_POLICY['target_test_id'],
                   'Popen outside the active frozen negative-command permission')
        self.check(not permit['consumed'] and len(arguments) == 1
                   and arguments[0] is permit['command_object']
                   and arguments[0] == permit['row']['command']
                   and set(keywords) == {'cwd', 'env', 'stdout', 'stderr'}
                   and keywords['cwd'] is permit['cwd_object']
                   and keywords['env'] is permit['environment_object']
                   and dict(keywords['env']) == permit['row']['environment']
                   and type(keywords['stdout']) is int and keywords['stdout'] == subprocess.PIPE
                   and type(keywords['stderr']) is int and keywords['stderr'] == subprocess.PIPE,
                   'original run-to-Popen call changed or permission was reused')
        permit['consumed'] = True
        permit['row']['popen_permission_consumed'] = True
        process = self.original_popen(*arguments, **keywords)
        permit['process'] = process
        permit['row'].update(process_started=True, pid=process.pid)
        return process

    def run(self, *arguments, **keywords):
        self.check(self.pending is None
                   and self.current_test() == NEGATIVE_PROCESS_POLICY['target_test_id']
                   and len(self.rows) < 4, 'run outside the frozen method or command denominator')
        self.check(len(arguments) == 1 and type(arguments[0]) is list
                   and all(type(value) is str for value in arguments[0])
                   and set(keywords) == {'cwd', 'env', 'capture_output', 'timeout'}
                   and type(keywords['cwd']) is type(Path())
                   and type(keywords['env']) is dict
                   and all(type(k) is str and type(v) is str for k, v in keywords['env'].items())
                   and keywords['capture_output'] is True
                   and type(keywords['timeout']) is int and keywords['timeout'] == 10,
                   'original run arguments/environment/ten-second timeout differ')
        case = NEGATIVE_PROCESS_POLICY['cases'][len(self.rows)]
        cwd = keywords['cwd']
        self.check(cwd.is_absolute() and arguments[0] == self.expected_command(cwd, case)
                   and keywords['env'] == self.expected_environment(case),
                   'frozen ordered negative command or environment differs')
        runtime_before = runtime(self.policy['runtime'])
        self.check(str(Path(sys.executable).resolve(strict=True)) == runtime_before['path'],
                   'negative command interpreter binding differs')
        sources_before = self.sources()
        directory_fd = os.open(cwd, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        cold_fd = None
        row = None
        permit = None
        original_exception = None
        try:
            directory_before = self.temporary(cwd, directory_fd)
            cold_fd = os.open('cold.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                              dir_fd=directory_fd)
            cold_before = self.cold(cwd, directory_fd, cold_fd)
            number = len(self.rows) + 1
            stem = self.output / ('negative-admission-' + str(number))
            row = {'schema': 'hepta.source83-negative-admission-process.v1',
                   'index': number, 'case': dict(case), 'test_id': self.current_test(),
                   'status': 'HOLD', 'command': list(arguments[0]), 'cwd': str(cwd),
                   'environment': dict(keywords['env']), 'timeout_seconds': 10,
                   'runtime_before': runtime_before, 'binding_sources_before': sources_before,
                   'temporary_parent': str(cwd.parent),
                   'directory_before': directory_before, 'cold_before': cold_before,
                   'input_original': self.write_bytes(stem.with_suffix('.input.bin'), b'{}'),
                   'popen_permission_consumed': False, 'process_started': False,
                   'original_run_called': False, 'original_run_returned': False,
                   'original_process_context_closed': False,
                   'started_monotonic_ns': time.monotonic_ns()}
            self.rows.append(row)
            save(stem.with_suffix('.request.json'), {
                key: row[key] for key in ('schema', 'index', 'case', 'test_id', 'command', 'cwd',
                                         'environment', 'timeout_seconds', 'runtime_before',
                                         'binding_sources_before', 'temporary_parent', 'directory_before', 'cold_before',
                                         'input_original', 'started_monotonic_ns')})
            row['request_original'] = pin(stem.with_suffix('.request.json'))
            permit = {'row': row, 'consumed': False, 'process': None,
                      'command_object': arguments[0], 'environment_object': keywords['env'],
                      'cwd_object': cwd}
            self.pending = permit
            # This is the unchanged standard-library implementation; it calls
            # the exact original Popen instance's communicate/__exit__ itself.
            row['original_run_called'] = True
            observed = self.original_run(*arguments, **keywords)
            row['original_run_returned'] = True
            self.check(type(observed) is self.completed_type
                       and observed.args == row['command']
                       and type(observed.returncode) is int
                       and type(observed.stdout) is bytes and type(observed.stderr) is bytes,
                       'original CompletedProcess value differs')
            row.update(returncode=observed.returncode,
                       stdout=self.write_bytes(stem.with_suffix('.stdout.bin'), observed.stdout),
                       stderr=self.write_bytes(stem.with_suffix('.stderr.bin'), observed.stderr))
            process = permit['process']
            row['original_process_context_closed'] = (
                process is not None and type(process.returncode) is int
                and process.returncode == observed.returncode
                and process.stdout is not None and process.stdout.closed
                and process.stderr is not None and process.stderr.closed)
            row['directory_after'] = self.temporary(cwd, directory_fd)
            row['cold_after'] = self.cold(cwd, directory_fd, cold_fd)
            row['runtime_after'] = runtime(self.policy['runtime'])
            row['binding_sources_after'] = self.sources()
            row['output_absent'] = not os.path.lexists(cwd / 'report.json')
            row['evidence_absent'] = not os.path.lexists(cwd / 'evidence')
            needle = b'development selection' if case['development'] else b'nested_report'
            self.check(row['popen_permission_consumed'] and row['process_started']
                       and row['original_process_context_closed'] and observed.returncode != 0
                       and needle in observed.stderr
                       and row['directory_after'] == directory_before
                       and row['cold_after'] == cold_before
                       and row['runtime_after'] == runtime_before
                       and row['binding_sources_after'] == sources_before
                       and row['output_absent'] and row['evidence_absent'],
                       'actual negative admission did not preserve the original refusal contract')
            row['status'] = 'NEGATIVE_ADMISSION_RETURNED_AND_CLOSED'
            return observed
        except BaseException as error:
            original_exception = error
            if row is not None:
                row['status'] = 'HOLD'
                row['error'] = traceback.format_exc()
                row['exception_type'] = type(error).__module__ + '.' + type(error).__qualname__
                if isinstance(error, subprocess.TimeoutExpired):
                    for label, raw in (('stdout', error.stdout), ('stderr', error.stderr)):
                        if type(raw) is bytes:
                            try:
                                row[label + '_partial'] = self.write_bytes(
                                    stem.with_suffix('.' + label + '.partial.bin'), raw)
                            except BaseException:
                                row.setdefault('preservation_errors', []).append(traceback.format_exc())
            raise
        finally:
            self.pending = None
            cleanup_error = None
            try:
                if row is not None:
                    process = None if permit is None else permit['process']
                    if process is not None:
                        row['returncode_after_original_run'] = process.returncode
                        row['original_process_context_closed'] = (
                            type(process.returncode) is int
                            and process.stdout is not None and process.stdout.closed
                            and process.stderr is not None and process.stderr.closed)
                    row['ended_monotonic_ns'] = time.monotonic_ns()
                    save(stem.with_suffix('.receipt.json'), dict(row))
                    row['receipt_original'] = pin(stem.with_suffix('.receipt.json'))
            except BaseException as error:
                cleanup_error = error
                if row is not None:
                    row['status'] = 'HOLD'
                    row.setdefault('preservation_errors', []).append(traceback.format_exc())
            for descriptor in (cold_fd, directory_fd):
                if descriptor is not None:
                    try:
                        os.close(descriptor)
                    except BaseException as error:
                        if cleanup_error is None:
                            cleanup_error = error
                        if row is not None:
                            row['status'] = 'HOLD'
                            row.setdefault('preservation_errors', []).append(traceback.format_exc())
            # An observation or close error must never replace the exception
            # raised by the original run(), including its TimeoutExpired.
            if original_exception is None and cleanup_error is not None:
                raise cleanup_error

    def complete(self):
        require(self.pending is None and not self.refusals and len(self.rows) == 4
                and [row['case'] for row in self.rows] == NEGATIVE_PROCESS_POLICY['cases']
                and all(row['status'] == 'NEGATIVE_ADMISSION_RETURNED_AND_CLOSED'
                        and row.get('error') is None and not row.get('preservation_errors')
                        and row['popen_permission_consumed'] and row['process_started']
                        and row['original_run_returned'] and row['original_process_context_closed']
                        and type(row['returncode']) is int and row['returncode'] != 0
                        for row in self.rows),
                'the four original negative-admission processes did not all close normally')



def main():
    policy = request()
    runtime(policy['runtime'])
    source = Path(policy['source_root'])
    sys.path.insert(0, str(source))
    operation = sys.argv[1]
    output = Path(policy['evidence_root']) / 'evidence'
    attempted = []
    def forbidden(*args, **kwargs):
        attempted.append('native/compiler/subprocess-attempt')
        raise AssertionError('source-only operation attempted native/compiler/subprocess execution')
    current_test = {'id': None}
    admission = NegativeAdmissions(policy, source, output, lambda: current_test['id'], forbidden)
    result_code = 1
    report = {'schema': 'hepta.hia.core-integer-integration-source-child.v1', 'status': 'HOLD',
        'native_or_compiler_or_process_attempts': attempted, 'forbidden_attempts': attempted,
        'source_child_process_policy': NEGATIVE_PROCESS_POLICY,
        'allowed_negative_process_records': admission.rows,
        'negative_permission_refusals': admission.refusals,
        'allowed_negative_processes': 0, 'zero_process_scope_claimed': False,
        'native_executed': False,
        'complete116_executed': False, 'complete18_executed': False, 'cold_executed': False,
        'operation': operation, 'expected_ids': policy['expected_ids'] if operation == 'tests' else [],
        'loaded_ids': [], 'executed_ids': [], 'runtime': sys.version,
        'runtime_identity': runtime(policy['runtime'])}
    at = time.monotonic()
    try:
        with ExitStack() as stack:
            stack.enter_context(patch.object(subprocess, 'Popen', admission.popen))
            stack.enter_context(patch.object(subprocess, 'run', admission.run))
            from hepta import hia_json_preflight_native as images
            stack.enter_context(patch.object(images.NativeHiaJsonImage, '__init__', forbidden))
            from tools import qualify_hia_selfhost as compiler
            stack.enter_context(patch.object(compiler, 'compile_stage', forbidden))
            stack.enter_context(patch.object(compiler, 'build_seed', forbidden))
            if operation == 'module':
                module = sys.argv[2]
                require(module in ['tools.generate_hia_' + name for name in policy['generator_names']], 'module allowlist')
                sys.argv = [module]
                try:
                    runpy.run_module(module, run_name='__main__')
                except SystemExit as exit_value:
                    if exit_value.code not in (None, 0):
                        raise
            elif operation == 'script':
                name, arguments = sys.argv[2], sys.argv[3:]
                require([name, arguments] in policy['derivations'], 'derivation allowlist')
                sys.argv = [str(source / name), *arguments]
                try:
                    runpy.run_path(str(source / name), run_name='__main__')
                except SystemExit as exit_value:
                    if exit_value.code not in (None, 0):
                        raise
            elif operation == 'tests':
                os.environ['HEPTA_COMPARE_BASE_ROOT'] = str(source)
                os.environ['HEPTA_COMPARE_CONTROL_EVIDENCE'] = str(output / 'numeric-source-fixture')
                os.environ['HEPTA_INTEGER_DRAFT_ROOT'] = str(source / 'tests/fixtures/hia_core_integer')
                os.environ['HEPTA_INTEGER_SOURCE_EVIDENCE'] = str(output / 'integer-source-fixture')
                loader = unittest.TestLoader()
                # Import-time CPython function-pointer type declarations remain
                # mechanical host declarations. No image may be instantiated.
                suite = loader.loadTestsFromNames(policy['test_classes'])
                report['loaded_ids'] = [test.id() for test in flatten(suite)]
                report['loader_errors'] = list(loader.errors)
                require(report['loaded_ids'] == policy['expected_ids'] and not loader.errors,
                        'full frozen source method inventory differs')
                for name in ('CDLL', 'PyDLL', 'CFUNCTYPE', 'PYFUNCTYPE'):
                    stack.enter_context(patch.object(ctypes, name, forbidden))
                executed = report['executed_ids']
                class Result(unittest.TextTestResult):
                    def startTest(self, test):
                        require(current_test['id'] is None, 'overlapping source-test lifecycle')
                        current_test['id'] = test.id()
                        executed.append(test.id())
                        super().startTest(test)
                    def stopTest(self, test):
                        try:
                            super().stopTest(test)
                        finally:
                            current_test['id'] = None
                with (output / 'source-unittest.log').open('x') as stream:
                    result = unittest.TextTestRunner(stream=stream, verbosity=2, resultclass=Result).run(suite)
                report['tests_run'] = result.testsRun
                for name in ('errors', 'failures', 'skipped', 'expectedFailures', 'unexpectedSuccesses'):
                    report[name] = [(item[0].id(), item[1]) if isinstance(item, tuple) else item.id()
                                    for item in getattr(result, name)]
                require(result.wasSuccessful() and executed == policy['expected_ids']
                        and result.testsRun == len(executed)
                        and not any(report[name] for name in ('loader_errors', 'errors', 'failures',
                            'skipped', 'expectedFailures', 'unexpectedSuccesses')),
                        'one or more complete frozen source controls failed')
                admission.complete()
            else:
                raise ValueError('unknown source-only child operation')
        require(not attempted, 'preserved native/compiler/process poison was triggered')
        report['status'] = 'SOURCE_CHILD_PASS'
        result_code = 0
    except BaseException:
        report['status'] = 'HOLD'
        report['error'] = traceback.format_exc()
    finally:
        report['allowed_negative_processes'] = sum(row['process_started'] is True for row in admission.rows)
        report['forbidden_attempt_count'] = len(attempted)
        report['seconds'] = time.monotonic() - at
        if operation == 'tests':
            save(output / 'source-tests.json', report)
        else:
            save(Path(os.environ['HEPTA_COMPARE_SOURCE_CHILD_REPORT']), report)
    print(json.dumps({key: report.get(key) for key in ('operation', 'status', 'seconds', 'error')}, sort_keys=True))
    return result_code


if __name__ == '__main__':
    raise SystemExit(main())
