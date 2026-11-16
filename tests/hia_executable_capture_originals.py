"""Independent original-only inputs and OS-ABI model for executable capture.

Only the immutable original class, _reject and whole _sealed_executable bodies
are compiled. The model does not reproduce the capture policy: it implements
the seven operating-system primitives and their CPython audit/signal ABI.
Original streams must be frozen twice before a candidate factory is invoked.
No expected candidate output, syscall transcript, cleanup decision or fd is
generated from the candidate's HIA policy.
"""
from __future__ import annotations
import ast
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import traceback
import types

ROOT = Path(__file__).resolve().parents[1]
ORIGINAL = ROOT / 'tests/fixtures/executable_capture_r19_original.py.txt'
CASES = ROOT / 'tests/fixtures/executable_capture_cases.json'
ORIGINAL_SHA = '18e881fdd56e1d8a8f391b2e16060cd29420805cab33970873d018a65e26dddf'
BODY_SHA = '410e94cded049e8b41176ce8deea3e34573053de9fd7c4219d2f2ebffde72754'
NAMES = ('MEMFD', 'WRITE', 'CHMOD', 'ADD_SEALS', 'GET_SEALS', 'PREAD', 'CLOSE')
MASK = (1 << 64) - 1


class OuterActiveError(Exception):
    pass


def _make_fault(name):
    cls = {
        'OSError': OSError, 'ValueError': ValueError, 'AttributeError': AttributeError,
        'MemoryError': MemoryError, 'RuntimeError': RuntimeError,
        'KeyboardInterrupt': KeyboardInterrupt, 'SystemExit': SystemExit,
        'GeneratorExit': GeneratorExit, 'StopIteration': StopIteration,
    }[name]
    return cls('frozen-audit-or-signal-fault')


def _error(error, world, seen=()):
    if error is None:
        return None
    if any(previous is error for previous in seen):
        return {'cycle': True}
    return {
        'module': type(error).__module__, 'type': type(error).__qualname__,
        'args': list(error.args), 'is_injected': error is world.fault,
        'is_outer': error is world.outer, 'errno': getattr(error, 'errno', None),
        'filename': getattr(error, 'filename', None), 'filename2': getattr(error, 'filename2', None),
        'text': str(error),
        'name': getattr(error, 'name', None), 'obj_is_none': getattr(error, 'obj', None) is None,
        'code': getattr(error, 'code', None), 'capture': getattr(error, 'capture', None),
        'suppress_context': error.__suppress_context__,
        'cause': _error(error.__cause__, world, seen + (error,)),
        'context': _error(error.__context__, world, seen + (error,)),
    }


class World:
    """Finite OS values; arbitrary Python os-provider monkeypatches are outside it."""
    def __init__(self, case):
        self.case = case
        self.trace = []
        self.counts = {}
        self.contents = bytearray()
        self.closed = False
        self.mode = 0
        self.seals = case.get('seals', 15)
        self.kernel_fault_count = self.callback_fault_count = 0
        fault = case.get('callback_fault')
        self.fault = None if fault is None else _make_fault(fault['family'])
        self.outer = OuterActiveError('frozen-outer-exception')

    def event(self, name, args):
        count = self.counts.get(name, 0) + 1
        self.counts[name] = count
        active = sys.exception()
        self.trace.append({
            'event': name, 'occurrence': count, 'args': args,
            'active': _error(active, self),
        })
        return count

    def callback(self, point, args):
        count = self.event(point, args)
        fault = self.case.get('callback_fault')
        if fault is not None and fault['point'] == point and fault['occurrence'] == count:
            self.callback_fault_count += 1
            raise self.fault

    def audit(self, name, *args):
        if name == 'os.chmod':
            if args != (73, 0o500, -1):
                raise AssertionError('unexpected original chmod audit operands')
            point = 'AUDIT_CHMOD'
        elif name == 'fcntl.fcntl' and args == (73, 1033, 15):
            point = 'AUDIT_ADD_SEALS'
        elif name == 'fcntl.fcntl' and args == (73, 1034, None):
            point = 'AUDIT_GET_SEALS'
        else:
            raise AssertionError('unexpected original audit event')
        self.callback(point, [name, *args])

    def signals(self):
        self.callback('CHECK_SIGNALS', [])
        return 0

    def kernel(self, operation, fd=-1, *, payload=b'', count=0, arg=0):
        name = NAMES[operation - 1]
        if operation == 1:
            args = ['hia-selfhost-compiler', arg]
        elif operation == 2:
            args = [fd, payload.hex()]
        elif operation == 3:
            args = [fd, arg]
        elif operation == 4:
            args = [fd, 1033, arg]
        elif operation == 5:
            args = [fd, 1034]
        elif operation == 6:
            args = [fd, count, 0]
        else:
            args = [fd]
        occurrence = self.event(name, args)
        fault = self.case.get('kernel_fault')
        if fault is not None and fault['operation'] == name and fault['occurrence'] == occurrence:
            self.kernel_fault_count += 1
            return -fault['errno'], b''
        if operation == 1:
            return 73, b''
        if fd != 73 or self.closed:
            return -9, b''
        if operation == 2:
            counts = self.case.get('write_counts', [])
            amount = counts[occurrence - 1] if occurrence <= len(counts) else len(payload)
            if not 0 <= amount <= len(payload):
                raise AssertionError('invalid frozen short-write input')
            self.contents.extend(payload[:amount])
            return amount, b''
        if operation == 3:
            self.mode = arg
            return 0, b''
        if operation == 4:
            return 0, b''
        if operation == 5:
            return self.seals, b''
        if operation == 6:
            raw = (bytes.fromhex(self.case['pread_hex']) if 'pread_hex' in self.case
                   else bytes(self.contents))
            raw = raw[:count]
            return len(raw), raw
        self.closed = True
        return 0, b''

    @staticmethod
    def raise_errno(number):
        raise OSError(number, os.strerror(number))

    def syscall(self, operation, fd=-1, **kw):
        while True:
            result, payload = self.kernel(operation, fd, **kw)
            if result >= 0:
                return payload if operation == 6 else result
            if result == -4 and operation in (2, 3, 4, 5, 6):
                self.signals()
                continue
            self.raise_errno(-result)

    def memfd_create(self, name, flags):
        if (name, flags) != ('hia-selfhost-compiler', 3):
            raise AssertionError('original memfd arguments changed')
        return self.syscall(1, arg=flags)

    def write(self, fd, raw):
        return self.syscall(2, fd, payload=raw)

    def fchmod(self, fd, mode):
        self.audit('os.chmod', fd, mode, -1)
        return self.syscall(3, fd, arg=mode)

    def fcntl(self, fd, command, *extra):
        if command == 1033:
            if extra != (15,):
                raise AssertionError('original add-seals arguments changed')
            self.audit('fcntl.fcntl', fd, command, extra[0])
            return self.syscall(4, fd, arg=extra[0])
        if command != 1034 or extra:
            raise AssertionError('original get-seals arguments changed')
        self.audit('fcntl.fcntl', fd, command, None)
        return self.syscall(5, fd)

    def pread(self, fd, count, offset):
        if offset != 0:
            raise AssertionError('original pread offset changed')
        return self.syscall(6, fd, count=count)

    def close(self, fd):
        self.syscall(7, fd)

    def verify_faults(self):
        expected_kernel = 1 if 'kernel_fault' in self.case else 0
        expected_callback = 1 if 'callback_fault' in self.case else 0
        if (self.kernel_fault_count, self.callback_fault_count) != (expected_kernel, expected_callback):
            raise AssertionError('a declared original primitive/callback fault was not observed')


def inputs():
    raw = CASES.read_bytes()
    value = json.loads(raw)
    if (value['original_source_sha256'] != ORIGINAL_SHA
            or value['original_body_sha256'] != BODY_SHA
            or value['case_count'] != 109 or value['invocation_count'] != 218
            or value['outer_states'] != [False, True]):
        raise ValueError('original executable-capture input identity differs')
    ordered = [case['id'] + '.outer' + str(int(outer))
               for case in value['cases'] for outer in value['outer_states']]
    if ordered != value['ordered_ids'] or len(set(ordered)) != 218:
        raise ValueError('original executable-capture complete input order differs')
    return raw, value


def original(world):
    raw = ORIGINAL.read_bytes()
    if sha256(raw).hexdigest() != ORIGINAL_SHA:
        raise ValueError('original full selfhost source differs')
    text = raw.decode()
    tree = ast.parse(text)
    names = ('SelfhostBuildRejected', '_reject', '_sealed_executable')
    definitions = {node.name: node for node in tree.body
                   if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in names}
    if tuple(name for name in names if name in definitions) != names:
        raise ValueError('original executable-capture definition is missing')
    node = definitions['_sealed_executable']
    body = ''.join(text.splitlines(keepends=True)[node.lineno - 1:node.end_lineno])
    if sha256(body.encode()).hexdigest() != BODY_SHA:
        raise ValueError('original executable-capture body differs')
    namespace = {
        '__name__': 'hepta.hia_program_selfhost',
        'os': types.SimpleNamespace(memfd_create=world.memfd_create, write=world.write,
                                  fchmod=world.fchmod, pread=world.pread, close=world.close,
                                  MFD_CLOEXEC=1, MFD_ALLOW_SEALING=2),
        'fcntl': types.SimpleNamespace(fcntl=world.fcntl),
        'F_ADD_SEALS': 1033, 'F_GET_SEALS': 1034, 'REQUIRED_SEALS': 15,
    }
    module = ast.Module(body=[definitions[name] for name in names], type_ignores=[])
    exec(compile(module, str(ORIGINAL), 'exec'), namespace)
    return namespace['_sealed_executable']


def observe(case, outer, factory):
    world = World(case)
    function = factory(world)
    def consume():
        try:
            value = function(bytes.fromhex(case['raw_hex']))
        except BaseException as error:
            return {'returned': None, 'error': _error(error, world)}, ''.join(
                traceback.format_exception(type(error), error, error.__traceback__))
        return {'returned': list(value), 'error': None}, ''
    if outer:
        try:
            raise world.outer
        except OuterActiveError:
            outcome, stack = consume()
    else:
        outcome, stack = consume()
    world.verify_faults()
    result = {
        'id': case['id'] + '.outer' + str(int(outer)), 'outcome': outcome,
        'trace': world.trace, 'contents_hex': bytes(world.contents).hex(),
        'mode': world.mode, 'seals': world.seals, 'closed': world.closed,
        'faults': {'kernel': world.kernel_fault_count, 'callback': world.callback_fault_count},
    }
    return result, stack


def write_stream(directory, factory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=False)
    input_raw, table = inputs()
    source_raw = ORIGINAL.read_bytes()
    planned = table['ordered_ids']
    started, stopped = [], []
    digest = sha256()
    with (directory / 'observations.jsonl').open('xb') as output, (
            directory / 'raw-tracebacks.jsonl').open('xb') as stacks:
        for case in table['cases']:
            for outer in table['outer_states']:
                case_id = case['id'] + '.outer' + str(int(outer))
                started.append(case_id)
                row, stack = observe(case, outer, factory)
                encoded = (json.dumps(row, sort_keys=True, separators=(',', ':')) + '\n').encode()
                output.write(encoded)
                output.flush()
                digest.update(encoded)
                stacks.write((json.dumps({'id': case_id, 'traceback': stack},
                                         sort_keys=True) + '\n').encode())
                stacks.flush()
                stopped.append(case_id)
    if CASES.read_bytes() != input_raw or ORIGINAL.read_bytes() != source_raw:
        raise ValueError('original executable-capture inputs drifted')
    report = {
        'schema': 'hepta.executable-capture.observations.v1',
        'planned': planned, 'started': started, 'stopped': stopped,
        'observation_sha256': digest.hexdigest(),
        'observation_bytes': (directory / 'observations.jsonl').stat().st_size,
        'input_sha256': sha256(input_raw).hexdigest(),
        'original_source_sha256': sha256(source_raw).hexdigest(),
        'whole_native_delivery_qualified': False, 'all_input_equivalence_proved': False,
    }
    (directory / 'report.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    return report


def freeze_originals(directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=False)
    first = write_stream(directory / 'first', original)
    second = write_stream(directory / 'second', original)
    one = (directory / 'first/observations.jsonl').read_bytes()
    two = (directory / 'second/observations.jsonl').read_bytes()
    if first != second or one != two:
        raise AssertionError('two complete independent original observations differ')
    frozen = {
        'schema': 'hepta.executable-capture.originals-frozen.v1',
        'original_report': first, 'expected_sha256': sha256(one).hexdigest(),
        'expected_bytes': len(one),
        'originals': ['first/observations.jsonl', 'second/observations.jsonl'],
    }
    target = directory / 'expectations-frozen.json'
    encoded = (json.dumps(frozen, sort_keys=True, indent=2) + '\n').encode()
    target.write_bytes(encoded)
    return {'authority': frozen, 'authority_sha256': sha256(encoded).hexdigest(),
            'authority_bytes': len(encoded)}


def compare_frozen(directory, expected, candidate):
    directory, candidate = Path(directory), Path(candidate)
    authority_path = directory / 'expectations-frozen.json'
    authority_raw = authority_path.read_bytes()
    if (sha256(authority_raw).hexdigest() != expected['authority_sha256']
            or len(authority_raw) != expected['authority_bytes']
            or json.loads(authority_raw) != expected['authority']):
        raise ValueError('the pre-candidate original authority changed')
    bound = expected['authority']
    original_path = directory / 'first/observations.jsonl'
    second_path = directory / 'second/observations.jsonl'
    actual_path = candidate / 'observations.jsonl'
    report_path = candidate / 'report.json'
    report_raw = report_path.read_bytes()
    actual_report = json.loads(report_raw)
    before = (original_path.read_bytes(), actual_path.read_bytes())
    second = second_path.read_bytes()
    if (second != before[0]
            or actual_report['planned'] != bound['original_report']['planned']
            or actual_report['started'] != actual_report['planned']
            or actual_report['stopped'] != actual_report['planned']
            or actual_report['input_sha256'] != bound['original_report']['input_sha256']
            or actual_report['original_source_sha256'] != ORIGINAL_SHA
            or sha256(before[1]).hexdigest() != actual_report['observation_sha256']
            or len(before[1]) != actual_report['observation_bytes']
            or sha256(before[0]).hexdigest() != bound['expected_sha256']
            or len(before[0]) != bound['expected_bytes']):
        raise ValueError('the actually consumed original stream differs from its prior pin')
    rows, actual = before[0].splitlines(), before[1].splitlines()
    differences = []
    if len(rows) != 218 or len(actual) != 218:
        raise AssertionError('capture comparison requires the full 218 ordered records')
    for original_raw, candidate_raw in zip(rows, actual, strict=True):
        old, new = json.loads(original_raw), json.loads(candidate_raw)
        if old['id'] != new['id']:
            raise AssertionError('capture comparison input order differs')
        if original_raw != candidate_raw:
            differences.append({'id': old['id'], 'original': old, 'candidate': new})
    if ((original_path.read_bytes(), actual_path.read_bytes()) != before
            or second_path.read_bytes() != second
            or authority_path.read_bytes() != authority_raw
            or report_path.read_bytes() != report_raw):
        raise ValueError('capture comparison consumed raw changed during readback')
    report = {'complete_ordered_records': 218, 'differences': differences,
              'original_sha256': sha256(before[0]).hexdigest(),
              'candidate_sha256': sha256(before[1]).hexdigest(),
              'whole_native_delivery_qualified': False, 'all_input_equivalence_proved': False}
    (candidate / 'comparison.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    return report
