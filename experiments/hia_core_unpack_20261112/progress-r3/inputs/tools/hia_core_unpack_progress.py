"""Bounded observations around the UNPACK qualifier's unchanged unittest run.

This module never invokes a product primitive or counts a progress transition
as a method PASS. The complete original report and the original owner deadline
remain mandatory. Only the explicit UNPACK wrapper installs these hooks.
"""
from __future__ import annotations

from contextlib import contextmanager, ExitStack
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import sys
import threading
import time
import unittest
import unittest.suite
from unittest.mock import patch

SCHEMA = 'hepta.hia.core-unpack-qualification-progress.v1'
RECEIPT_SCHEMA = 'hepta.hia.core-unpack-qualification-progress-receipt.v1'
SUMMARY_SCHEMA = 'hepta.hia.core-unpack-qualification-progress-binding.v1'
LOG_NAME, RECEIPT_NAME = 'progress.jsonl', 'progress.receipt.json'
MAX_BYTES, MAX_EVENT_BYTES, MAX_EVENTS, MAX_RECEIPT_BYTES = 524288, 1024, 1024, 131072
# The whole official file is byte-identical in CPython 3.12.14 and 3.14.4.
SUITE_SOURCE_SHA256 = 'ed2da92bc9f97c53403ee2d3d12cc53b16a96e85d596ebc887b5a93458f3f6bc'
RUNTIMES = ((3, 12, 14), (3, 14, 4))
FIELDS = {'sequence', 'event', 'group', 'subject', 'monotonic_ns', 'native_returns', 'detail'}
FIXTURES = {'class_setup', 'class_teardown', 'module_fixture', 'module_teardown'}
OUTCOMES = {'normal_return', 'fixture_error', 'base_exception'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def wire(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n').encode('ascii')


def digest(value):
    return sha256(wire(value)).hexdigest()


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, 'duplicate progress JSON key')
        result[key] = value
    return result


def parsed(raw):
    return json.loads(raw, object_pairs_hook=pairs)


def identity(info):
    return {key: getattr(info, 'st_' + key) for key in
            ('dev', 'ino', 'mode', 'uid', 'gid', 'nlink', 'size', 'mtime_ns', 'ctime_ns')}


def directory_identity(info):
    return tuple(getattr(info, 'st_' + key) for key in ('dev', 'ino', 'mode', 'uid', 'gid'))


def stable_chain(chain):
    for parent, name, child, before in chain[1:]:
        require(directory_identity(os.fstat(child)) == before == directory_identity(
            os.stat(name, dir_fd=parent, follow_symlinks=False)), 'progress directory chain changed')


def open_parent(path):
    path = Path(path).absolute()
    require(path.parts[0] == '/' and all(part not in ('.', '..') for part in path.parts[1:]),
            'fixed absolute progress path required')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open('/', flags)
    chain = [(None, None, fd, directory_identity(os.fstat(fd)))]
    try:
        for name in path.parts[1:-1]:
            child = os.open(name, flags, dir_fd=fd)
            chain.append((fd, name, child, directory_identity(os.fstat(child))))
            fd = child
        stable_chain(chain)
        return path, chain
    except BaseException:
        for _, _, held, _ in reversed(chain):
            os.close(held)
        raise


def close_chain(chain):
    for _, _, fd, _ in reversed(chain):
        os.close(fd)


def regular(info, owned):
    require(stat.S_ISREG(info.st_mode) and (not owned or
            (info.st_uid == os.geteuid() and info.st_nlink == 1)), 'progress leaf must be a fixed ordinary file')


def read_file(path, maximum=None, *, owned=False, contents=True):
    path, chain = open_parent(path)
    fd = None
    try:
        parent = chain[-1][2]
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
        before = os.fstat(fd)
        regular(before, owned)
        require(maximum is None or before.st_size <= maximum, 'progress file exceeds its fixed bound')
        result, hashed, total = [], sha256(), 0
        while total < before.st_size:
            part = os.read(fd, min(65536, before.st_size - total))
            require(bool(part), 'progress file truncated during reading')
            total += len(part)
            hashed.update(part)
            if contents:
                result.append(part)
        require(os.read(fd, 1) == b'', 'progress file grew during reading')
        require(identity(before) == identity(os.fstat(fd)) == identity(
            os.stat(path.name, dir_fd=parent, follow_symlinks=False)), 'progress leaf identity changed')
        stable_chain(chain)
        return b''.join(result), {'path': str(path), 'size': total, 'sha256': hashed.hexdigest(),
                                  'identity': identity(before)}
    finally:
        if fd is not None:
            os.close(fd)
        close_chain(chain)


def plain_pin(value):
    return {key: value[key] for key in ('path', 'size', 'sha256')}


def create_file(path, raw, maximum):
    require(type(raw) is bytes and len(raw) <= maximum, 'bounded progress receipt bytes required')
    path, chain = open_parent(path)
    fd = None
    try:
        parent = chain[-1][2]
        fd = os.open(path.name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=parent)
        regular(os.fstat(fd), True)
        require(os.write(fd, raw) == len(raw), 'short progress receipt write')
        os.fsync(fd)
        os.fchmod(fd, 0o400)
        before = os.fstat(fd)
        os.lseek(fd, 0, os.SEEK_SET)
        actual = bytearray()
        while len(actual) < len(raw):
            part = os.read(fd, len(raw) - len(actual))
            require(bool(part), 'short progress receipt readback')
            actual.extend(part)
        require(bytes(actual) == raw and os.read(fd, 1) == b'', 'progress receipt readback differs')
        require(identity(before) == identity(os.fstat(fd)) == identity(
            os.stat(path.name, dir_fd=parent, follow_symlinks=False)), 'progress receipt leaf changed')
        stable_chain(chain)
    finally:
        if fd is not None:
            os.close(fd)
        close_chain(chain)
    return read_file(path, maximum, owned=True)[1]


def specifications(groups):
    require(type(groups) in (list, tuple) and groups, 'progress groups are required')
    result, all_ids, labels, module_sets = [], set(), set(), set()
    for group in groups:
        require(type(group) is dict, 'progress group must be a dictionary')
        label, modules, ids = (group.get(key) for key in ('label', 'modules', 'ids'))
        require(type(label) is str and 0 < len(label) <= 64 and label not in labels,
                'progress group label differs')
        require(type(modules) in (list, tuple) and modules and all(
            type(name) is str and 0 < len(name) <= 256 for name in modules), 'progress module names differ')
        require(tuple(modules) not in module_sets and len(set(modules)) == len(modules),
                'duplicate progress module inventory')
        require(type(ids) in (list, tuple) and ids and all(type(name) is str and 0 < len(name) <= 384
            for name in ids) and len(set(ids)) == len(ids) and not all_ids.intersection(ids),
            'progress frozen test IDs differ')
        labels.add(label); module_sets.add(tuple(modules)); all_ids.update(ids)
        result.append({'label': label, 'modules': list(modules), 'ids': list(ids)})
    return result


def runtime_source():
    require(sys.implementation.name == 'cpython' and tuple(sys.version_info[:3]) in RUNTIMES,
            'progress hooks require a specifically admitted CPython runtime')
    _, value = read_file(Path(unittest.suite.__file__), 65536)
    require(value['sha256'] == SUITE_SOURCE_SHA256, 'actual unittest TestSuite source differs')
    return {'implementation': 'CPython', 'version': list(sys.version_info[:3]), 'suite_source': value}


def source_pin():
    return read_file(Path(__file__), 262144, contents=False)[1]


def checked_suite(suite, suite_type):
    ids, count, tests, suites = [], 0, {}, []
    def visit(item):
        nonlocal count
        if isinstance(item, unittest.TestCase):
            name = item.id()
            ids.append(name)
            tests[id(item)] = name
        else:
            require(type(item) is suite_type, 'an inner suite is not covered by progress hooks')
            count += 1
            suites.append(item)
            for child in item:
                visit(child)
    visit(suite)
    return ids, count, tests, suites


def class_name(value):
    return value.__module__ + '.' + value.__qualname__


def anomaly_count(result):
    return sum(len(getattr(result, key)) for key in
               ('errors', 'failures', 'skipped', 'expectedFailures', 'unexpectedSuccesses'))


class ProgressRecorder:
    def __init__(self, directory, groups, native_returns):
        self.directory = Path(directory).absolute()
        self.groups = specifications(groups)
        self.native_returns = native_returns
        self.source_before, self.runtime_before = source_pin(), runtime_source()
        self.pid, self.thread = os.getpid(), threading.get_ident()
        self.count = self.size = 0
        self.hashed = sha256()
        self.current_group = ''
        self.loaded = []
        self.tests = {}
        self.errors = []
        self.broken = self.finished = self.active = False
        self.path, self.chain = open_parent(self.directory / LOG_NAME)
        self.fd = None
        try:
            self.fd = os.open(self.path.name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                              0o600, dir_fd=self.chain[-1][2])
            regular(os.fstat(self.fd), True)
            self.event('operation_begin', detail={'specifications_sha256': digest(self.groups)})
        except BaseException:
            if self.fd is not None:
                os.close(self.fd)
            close_chain(self.chain)
            raise

    def here(self):
        # Once a secondary log failure has been retained, continue only the
        # original unittest work. finish() records HOLD without another write
        # replacing the already caught original fixture error.
        return (self.active and not self.broken and os.getpid() == self.pid
                and threading.get_ident() == self.thread)

    def event(self, event, subject='', detail=None):
        require(not self.broken and not self.finished, 'progress writer is not active')
        try:
            steps = self.native_returns()
            require(type(steps) is int and steps >= 0, 'progress native-return summary differs')
            row = {'sequence': self.count, 'event': event, 'group': self.current_group,
                   'subject': subject, 'monotonic_ns': time.monotonic_ns(),
                   'native_returns': steps, 'detail': {} if detail is None else detail}
            raw = wire(row)
            require(len(raw) <= MAX_EVENT_BYTES and self.size + len(raw) <= MAX_BYTES
                    and self.count < MAX_EVENTS, 'progress event inventory exceeds its fixed bound')
            require(os.write(self.fd, raw) == len(raw), 'short progress event write')
            self.hashed.update(raw); self.size += len(raw); self.count += 1
        except BaseException as error:
            self.broken = True
            self.errors.append(type(error).__module__ + '.' + type(error).__qualname__)
            raise

    def secondary_event(self, *args, **kwargs):
        # Called only while preserving an already active original exception.
        # The original bare raise has priority over a diagnostic failure.
        try:
            self.event(*args, **kwargs)
        except BaseException:
            pass

    def fixture(self, kind, subject, result, call, failed):
        self.event('fixture_begin', subject, {'kind': kind})
        before = anomaly_count(result)
        try:
            value = call()
        except BaseException as error:
            self.secondary_event('fixture_end', subject, {'kind': kind, 'outcome': 'base_exception',
                'exception_type': type(error).__module__ + '.' + type(error).__qualname__})
            raise
        fixture_failed = failed() or anomaly_count(result) != before
        # A caught unittest fixture error is already present in result. Preserve
        # that original result if recording its outcome also fails.
        emit = self.secondary_event if fixture_failed else self.event
        emit('fixture_end', subject, {'kind': kind,
            'outcome': 'fixture_error' if fixture_failed else 'normal_return', 'exception_type': None})
        return value

    @contextmanager
    def observe(self):
        require(not self.active and not self.finished, 'progress observation cannot be nested')
        owner = self
        base_suite, base_loader = unittest.TestSuite, unittest.TestLoader
        base_start, base_stop = unittest.TestResult.startTest, unittest.TestResult.stopTest
        class TracedSuite(base_suite):
            def run(self, result, debug=False):
                group = getattr(self, '_unpack_progress_group', None)
                if not owner.here() or group is None:
                    return super().run(result, debug)
                require(not owner.current_group, 'progress group runs cannot be nested')
                owner.current_group = group['label']
                try:
                    owner.event('group_begin', detail={'loaded_count': len(group['ids']),
                        'loaded_ids_sha256': digest(group['ids']), 'nested_suite_count': self._unpack_suite_count})
                    value = super().run(result, debug)
                except BaseException as error:
                    owner.secondary_event('group_end', detail={'outcome': 'base_exception',
                        'exception_type': type(error).__module__ + '.' + type(error).__qualname__})
                    raise
                else:
                    emit = owner.secondary_event if anomaly_count(result) else owner.event
                    emit('group_end', detail={'outcome': 'normal_return', 'exception_type': None})
                    return value
                finally:
                    owner.tests.clear()
                    owner.current_group = ''

            def _handleClassSetUp(self, test, result):
                current = test.__class__
                call = lambda: super(TracedSuite, self)._handleClassSetUp(test, result)
                if (not owner.here() or not getattr(self, '_unpack_progress_selected', False)
                        or not owner.current_group
                        or current == getattr(result, '_previousTestClass', None)
                        or result._moduleSetUpFailed or getattr(current, '__unittest_skip__', False)):
                    return call()
                return owner.fixture('class_setup', class_name(current), result, call,
                    lambda: bool(getattr(current, '_classSetupFailed', False)))

            def _tearDownPreviousClass(self, test, result):
                previous = getattr(result, '_previousTestClass', None)
                call = lambda: super(TracedSuite, self)._tearDownPreviousClass(test, result)
                if (not owner.here() or not getattr(self, '_unpack_progress_selected', False)
                        or not owner.current_group or previous is None
                        or previous == test.__class__ or getattr(previous, '_classSetupFailed', False)
                        or getattr(result, '_moduleSetUpFailed', False)
                        or getattr(previous, '__unittest_skip__', False)):
                    return call()
                return owner.fixture('class_teardown', class_name(previous), result, call, lambda: False)

            def _handleModuleFixture(self, test, result):
                current = test.__class__.__module__
                call = lambda: super(TracedSuite, self)._handleModuleFixture(test, result)
                if (not owner.here() or not getattr(self, '_unpack_progress_selected', False)
                        or not owner.current_group or current == self._get_previous_module(result)):
                    return call()
                return owner.fixture('module_fixture', current, result, call,
                    lambda: bool(getattr(result, '_moduleSetUpFailed', False)))

            def _handleModuleTearDown(self, result):
                previous = self._get_previous_module(result)
                call = lambda: super(TracedSuite, self)._handleModuleTearDown(result)
                if (not owner.here() or not getattr(self, '_unpack_progress_selected', False)
                        or not owner.current_group or previous is None
                        or getattr(result, '_moduleSetUpFailed', False)):
                    return call()
                return owner.fixture('module_teardown', previous, result, call, lambda: False)

        class TracedLoader(base_loader):
            suiteClass = TracedSuite
            def loadTestsFromNames(self, names, module=None):
                suite = super().loadTestsFromNames(names, module)
                matched = [group for group in owner.groups if list(names) == group['modules']]
                if owner.here() and not owner.current_group and matched:
                    group = matched[0]
                    require(owner.loaded == [item['label'] for item in owner.groups[:len(owner.loaded)]]
                            and len(owner.loaded) < len(owner.groups)
                            and group == owner.groups[len(owner.loaded)], 'progress loader group order differs')
                    ids, count, tests, suites = checked_suite(suite, TracedSuite)
                    require(ids == group['ids'], 'progress loader IDs differ from the unchanged originals')
                    for selected in suites:
                        selected._unpack_progress_selected = True
                    owner.tests.update(tests)
                    owner.loaded.append(group['label'])
                    suite._unpack_progress_group = group
                    suite._unpack_suite_count = count
                return suite

        def start(result, test):
            name = owner.tests.get(id(test))
            if owner.here() and owner.current_group and name is not None:
                owner.event('test_start', name)
            return base_start(result, test)

        def stop(result, test):
            name = owner.tests.pop(id(test), None)
            active_exception = sys.exc_info()[0] is not None
            try:
                value = base_stop(result, test)
            except BaseException as error:
                if owner.here() and owner.current_group and name is not None:
                    owner.secondary_event('test_stop', name, {'callback': 'stopTest',
                        'exception_type': type(error).__module__ + '.' + type(error).__qualname__})
                raise
            if owner.here() and owner.current_group and name is not None:
                function = owner.secondary_event if active_exception or anomaly_count(result) else owner.event
                function('test_stop', name, {'callback': 'stopTest', 'exception_type': None})
            return value

        self.active = True
        try:
            with ExitStack() as stack:
                stack.enter_context(patch.object(unittest, 'TestLoader', TracedLoader))
                stack.enter_context(patch.object(unittest.TestResult, 'startTest', start))
                stack.enter_context(patch.object(unittest.TestResult, 'stopTest', stop))
                yield self
        finally:
            self.active = False

    def finish(self, *, complete, original_report=None):
        require(type(complete) is bool and not self.finished and not self.active,
                'progress finish requires a closed observation scope')
        error = None
        try:
            if not self.broken:
                self.event('operation_end', detail={'complete': complete,
                    'original_report_sha256': None if original_report is None else original_report['sha256']})
        except BaseException as caught:
            error = type(caught).__module__ + '.' + type(caught).__qualname__
        try:
            os.fsync(self.fd)
            os.fchmod(self.fd, 0o400)
            stable_chain(self.chain)
        finally:
            self.finished = True
            os.close(self.fd)
            close_chain(self.chain)
        raw, log_pin = read_file(self.path, MAX_BYTES, owned=True)
        source_after, runtime_after = source_pin(), runtime_source()
        receipt = {'schema': RECEIPT_SCHEMA, 'status': 'HOLD', 'complete': False,
            'specifications': self.groups, 'progress': log_pin, 'original_report': original_report,
            'source_before': self.source_before, 'source_after': source_after,
            'runtime_before': self.runtime_before, 'runtime_after': runtime_after,
            'writer_event_count': self.count, 'writer_bytes': self.size,
            'writer_sha256': self.hashed.hexdigest(), 'logging_errors': list(self.errors),
            'error': error, 'semantic': None, 'method_pass_claimed_by_progress': False}
        try:
            require(not self.broken and not self.errors and error is None, 'progress logging failed')
            require(len(raw) == self.size and sha256(raw).hexdigest() == self.hashed.hexdigest(),
                    'complete progress bytes differ from writes')
            require(self.source_before == source_after and self.runtime_before == runtime_after,
                    'progress implementation/runtime changed')
            receipt['semantic'] = validate_events(raw, self.groups, complete, original_report)
            receipt['complete'] = complete
            receipt['status'] = 'COMPLETE' if complete else 'HOLD'
        except BaseException as caught:
            receipt['error'] = type(caught).__module__ + '.' + type(caught).__qualname__
        receipt_pin = create_file(self.directory / RECEIPT_NAME, wire(receipt), MAX_RECEIPT_BYTES)
        return {'schema': SUMMARY_SCHEMA, 'complete': receipt['complete'], 'status': receipt['status'],
                'progress': log_pin, 'receipt': receipt_pin,
                'native_step_returns': None if receipt['semantic'] is None
                    else receipt['semantic']['final_native_returns']}


def validate_events(raw, groups, require_complete, original_report):
    groups = specifications(groups)
    require(type(require_complete) is bool, 'progress completeness must be explicit')
    require(type(raw) is bytes and 0 < len(raw) <= MAX_BYTES and raw.endswith(b'\n'),
            'complete bounded progress bytes required')
    lines = raw.splitlines(keepends=True)
    require(len(lines) <= MAX_EVENTS and all(len(row) <= MAX_EVENT_BYTES for row in lines),
            'progress event extent differs')
    rows = [parsed(row) for row in lines]
    current, index, fixtures, running_test = None, 0, [], None
    started, stopped, previous_time, previous_native, bad = [], [], -1, -1, False
    begun = ended = False
    for number, row in enumerate(rows):
        require(type(row) is dict and set(row) == FIELDS and type(row['sequence']) is int
                and row['sequence'] == number and type(row['monotonic_ns']) is int
                and row['monotonic_ns'] >= 0 and row['monotonic_ns'] >= previous_time
                and type(row['native_returns']) is int and row['native_returns'] >= 0
                and row['native_returns'] >= previous_native and type(row['detail']) is dict
                and type(row['event']) is str
                and type(row['group']) is str and type(row['subject']) is str,
                'progress event shape, order or counters differ')
        previous_time, previous_native = row['monotonic_ns'], row['native_returns']
        event, detail = row['event'], row['detail']
        require(not ended, 'events follow complete progress end')
        if event == 'operation_begin':
            require(number == 0 and not begun and row['group'] == row['subject'] == ''
                    and detail == {'specifications_sha256': digest(groups)}, 'progress begin differs')
            begun = True
        elif event == 'group_begin':
            require(begun and current is None and index < len(groups) and not fixtures and running_test is None,
                    'progress group begin is out of order')
            current = groups[index]
            require(row['group'] == current['label'] and row['subject'] == ''
                    and set(detail) == {'loaded_count', 'loaded_ids_sha256', 'nested_suite_count'}
                    and type(detail['loaded_count']) is int and detail['loaded_count'] == len(current['ids'])
                    and detail['loaded_ids_sha256'] == digest(current['ids'])
                    and type(detail['nested_suite_count']) is int and detail['nested_suite_count'] > 0,
                    'progress loaded suite inventory differs')
            started, stopped = [], []
        elif event == 'fixture_begin':
            require(current is not None and row['group'] == current['label'] and row['subject']
                    and set(detail) == {'kind'} and detail['kind'] in FIXTURES and running_test is None,
                    'fixture begin differs')
            fixtures.append((detail['kind'], row['subject']))
        elif event == 'fixture_end':
            require(current is not None and row['group'] == current['label'] and fixtures
                    and set(detail) == {'kind', 'outcome', 'exception_type'}
                    and fixtures.pop() == (detail['kind'], row['subject']) and detail['outcome'] in OUTCOMES
                    and ((detail['outcome'] == 'base_exception' and type(detail['exception_type']) is str)
                         or (detail['outcome'] != 'base_exception' and detail['exception_type'] is None)),
                    'fixture end does not match its actual begin/outcome')
            bad |= detail['outcome'] != 'normal_return'
        elif event == 'test_start':
            require(current is not None and row['group'] == current['label'] and not fixtures
                    and running_test is None and detail == {} and row['subject'] in current['ids']
                    and (not started or current['ids'].index(row['subject']) > current['ids'].index(started[-1])),
                    'test start differs from original order')
            running_test = row['subject']; started.append(running_test)
        elif event == 'test_stop':
            require(current is not None and row['group'] == current['label'] and not fixtures
                    and running_test == row['subject'] and set(detail) == {'callback', 'exception_type'}
                    and detail['callback'] == 'stopTest' and (detail['exception_type'] is None
                         or type(detail['exception_type']) is str), 'test stop lacks its matching original start')
            stopped.append(running_test); running_test = None
            bad |= detail['exception_type'] is not None
        elif event == 'group_end':
            require(current is not None and row['group'] == current['label'] and row['subject'] == ''
                    and not fixtures and running_test is None
                    and set(detail) == {'outcome', 'exception_type'}
                    and detail['outcome'] in ('normal_return', 'base_exception')
                    and ((detail['outcome'] == 'normal_return' and detail['exception_type'] is None)
                         or (detail['outcome'] == 'base_exception' and type(detail['exception_type']) is str)),
                    'group end differs')
            if require_complete:
                require(started == current['ids'] == stopped and detail['outcome'] == 'normal_return',
                        'progress cannot replace complete original test callbacks')
            bad |= detail['outcome'] != 'normal_return'
            current = None; index += 1
        elif event == 'operation_end':
            require(begun and number == len(rows) - 1 and current is None and not fixtures
                    and running_test is None and row['group'] == row['subject'] == ''
                    and set(detail) == {'complete', 'original_report_sha256'}
                    and type(detail['complete']) is bool and detail['complete'] is require_complete
                    and detail['original_report_sha256'] == (None if original_report is None
                                                           else original_report['sha256']),
                    'complete progress end or original-report binding differs')
            if require_complete:
                require(index == len(groups) and not bad and original_report is not None,
                        'progress fixture/group completion is missing or failed')
            ended = True
        else:
            raise ValueError('unknown progress event')
    require(begun and ended, 'progress is truncated before a complete end')
    return {'event_count': len(rows), 'group_count': index,
            'test_start_count': sum(row['event'] == 'test_start' for row in rows),
            'test_stop_count': sum(row['event'] == 'test_stop' for row in rows),
            'fixture_error_or_exception_seen': bad, 'final_native_returns': previous_native,
            'method_pass_claimed_by_progress': False}


def inspect_progress(directory, groups, original_report):
    """Actual file reader used by new UNPACK gates, never by the old thirty."""
    directory = Path(directory).absolute()
    raw_receipt, receipt_pin = read_file(directory / RECEIPT_NAME, MAX_RECEIPT_BYTES, owned=True)
    receipt = parsed(raw_receipt)
    raw, log_pin = read_file(directory / LOG_NAME, MAX_BYTES, owned=True)
    expected_groups = specifications(groups)
    require(type(receipt) is dict and receipt.get('schema') == RECEIPT_SCHEMA
            and receipt.get('status') == 'COMPLETE' and receipt.get('complete') is True
            and receipt.get('logging_errors') == [] and receipt.get('error') is None
            and receipt.get('method_pass_claimed_by_progress') is False,
            'progress HOLD or missing completion cannot qualify')
    _, actual_original = read_file(directory / 'core-callers/report.json', contents=False)
    require(plain_pin(actual_original) == original_report == receipt.get('original_report'),
            'progress is bound to another original complete report')
    actual_source, actual_runtime = source_pin(), runtime_source()
    require(receipt.get('specifications') == expected_groups and receipt.get('progress') == log_pin
            and receipt.get('source_before') == actual_source == receipt.get('source_after')
            and receipt.get('runtime_before') == actual_runtime == receipt.get('runtime_after')
            and type(receipt.get('writer_bytes')) is int and receipt['writer_bytes'] == len(raw)
            and receipt.get('writer_sha256') == sha256(raw).hexdigest(),
            'progress bytes, runtime or implementation identity differs')
    semantic = validate_events(raw, expected_groups, True, original_report)
    require(type(receipt.get('writer_event_count')) is int
            and receipt['writer_event_count'] == semantic['event_count']
            and receipt.get('semantic') == semantic, 'progress complete semantic receipt differs')
    return {'schema': SUMMARY_SCHEMA, 'complete': True, 'status': 'COMPLETE',
            'progress': log_pin, 'receipt': receipt_pin,
            'native_step_returns': semantic['final_native_returns']}
