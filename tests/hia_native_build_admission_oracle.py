"""Independent observations of the complete, byte-frozen aac7550 methods.

This module never reads the candidate state graph.  Providers and opaque Python
protocol objects are shared input fixtures, not a second admission algorithm.
"""
from contextlib import ExitStack
from hashlib import sha256 as original_sha256
from pathlib import Path
from unittest.mock import patch
import copy
import hashlib
import itertools
import json
import textwrap
import time


HERE = Path(__file__).resolve().parent
FROZEN_FILES = {'_signatures': 'hia_native_build_signatures_aac7550.py.txt', '_native': 'hia_native_build_native_aac7550.py.txt', '_build_inputs': 'hia_native_build_inputs_aac7550.py.txt', '_build_receipt': 'hia_native_build_receipt_aac7550.py.txt', '_behavior_equivalence': 'hia_native_build_behavior_equivalence_aac7550.py.txt'}
METHOD_SHA256 = {
    '_signatures': 'a37a0418e32f559efcd7261de2ba542e0de281ecb2b7e13059c1995cbff4853b',
    '_native': '4b4f84e3b4fe3bf3ac83224e377e3ad3cd4637dab1714a740fbe7c8671d61ddd',
    '_build_inputs': '1d78f665c3408a729db6223e62d886375e8a2d016b6e72cbfed198b051acfc4a',
    '_build_receipt': '8a3d1c1e0e19091fffa35e40e57621dec31ffd586abdf8ac1c9b7376fc1865ac',
}


def snapshot(value, seen=None):
    """Inspect fixture storage without invoking its instrumented protocols."""
    kind = type(value)
    if value is None or kind in (str, bool):
        return value
    if kind is float:
        return value if value == value and value not in (float('inf'), -float('inf')) else {'float_hex': value.hex()}
    if kind is int:
        return value if value.bit_length() <= 8192 else {'integer_hex': hex(value)}
    if kind in (bytes, bytearray):
        return {'type': kind.__name__, 'hex': value.hex()}
    if kind is memoryview:
        return {'type': 'memoryview', 'hex': value.tobytes().hex()}
    if isinstance(value, (dict, list, tuple)):
        seen = set() if seen is None else seen
        if id(value) in seen:
            return {'cycle': getattr(value, 'label', kind.__name__)}
        seen = seen | {id(value)}
        if isinstance(value, dict):
            return {'mapping': [[snapshot(k, seen), snapshot(v, seen)] for k, v in dict.items(value)]}
        items = list.__iter__(value) if isinstance(value, list) else tuple.__iter__(value)
        return {'sequence': kind.__name__, 'items': [snapshot(v, seen) for v in items]}
    return {'opaque': kind.__name__, 'label': getattr(value, 'label', kind.__name__)}


ERRORS = {kind.__name__: kind for kind in (
    ValueError, TypeError, KeyError, RuntimeError, OSError, OverflowError,
    RecursionError, StopIteration, KeyboardInterrupt, SystemExit, AttributeError)}


class Trace:
    def __init__(self, fault=None):
        self.events = []
        self.fault = fault
        self.matches = 0

    def emit(self, event, *arguments):
        encoded = [snapshot(value) for value in arguments]
        self.events.append({'event': event, 'arguments': encoded})
        fault = self.fault
        if fault and event == fault['event'] and (
                'argument0' not in fault or encoded and encoded[0] == fault['argument0']):
            self.matches += 1
            if self.matches == fault.get('occurrence', 1):
                raise ERRORS[fault['exception']](*fault.get('args', ['opaque-provider-fault']))


class ObservedDict(dict):
    def __init__(self, trace, label, values=()):
        super().__init__(values)
        self.trace, self.label = trace, label
        self.items_override = None

    def __getitem__(self, key):
        self.trace.emit(self.label + '.getitem', key)
        return dict.__getitem__(self, key)

    def get(self, key, default=None):
        self.trace.emit(self.label + '.get', key, default)
        return dict.get(self, key, default)

    def items(self):
        self.trace.emit(self.label + '.items')
        return dict.items(self) if self.items_override is None else self.items_override

    def __iter__(self):
        self.trace.emit(self.label + '.iter')
        return dict.__iter__(self)

    def __eq__(self, other):
        self.trace.emit(self.label + '.eq', other)
        return dict.__eq__(self, other)

    def __ne__(self, other):
        self.trace.emit(self.label + '.ne', other)
        return dict.__ne__(self, other)


class ObservedIterator:
    def __init__(self, trace, label, values, *, hint=None):
        self.trace, self.label, self.values = trace, label, list(values)
        self.index, self.hint = 0, hint

    def __iter__(self):
        self.trace.emit(self.label + '.iter')
        return self

    def __next__(self):
        self.trace.emit(self.label + '.next', self.index)
        if self.index == len(self.values):
            raise StopIteration
        value = self.values[self.index]
        self.index += 1
        return value

    def __length_hint__(self):
        self.trace.emit(self.label + '.length_hint')
        return len(self.values) - self.index if self.hint is None else self.hint


class ObservedIterable:
    def __init__(self, trace, label, values, *, length=None):
        self.trace, self.label, self.values, self.length = trace, label, list(values), length

    def __iter__(self):
        self.trace.emit(self.label + '.iter')
        return ObservedIterator(self.trace, self.label + '.iterator', self.values)

    def __len__(self):
        self.trace.emit(self.label + '.len')
        return len(self.values) if self.length is None else self.length


class Truth:
    def __init__(self, trace, label, value):
        self.trace, self.label, self.value = trace, label, value

    def __bool__(self):
        self.trace.emit(self.label + '.bool')
        return self.value


class Compared:
    def __init__(self, trace, label, value, *, equal=None, unequal=None):
        self.trace, self.label, self.value = trace, label, value
        self.equal, self.unequal = equal, unequal

    def __eq__(self, other):
        self.trace.emit(self.label + '.eq', other)
        return self.value == other if self.equal is None else self.equal

    def __ne__(self, other):
        self.trace.emit(self.label + '.ne', other)
        return self.value != other if self.unequal is None else self.unequal

    def __hash__(self):
        self.trace.emit(self.label + '.hash')
        return hash(self.value)


class Program:
    def __init__(self, fixture, label, document, scalar_names, canonical=b'original-core'):
        self.fixture, self.label, self.document = fixture, label, document
        self.scalar_names, self.canonical = scalar_names, canonical
        self.core_digest, self.input_digest = 'c' * 64, 'i' * 64

    def as_dict(self):
        self.fixture.trace.emit(self.label + '.as_dict')
        return self.document

    @property
    def scalar_entrypoints(self):
        self.fixture.trace.emit(self.label + '.scalar_entrypoints')
        return self.scalar_names

    @property
    def sha256(self):
        self.fixture.trace.emit(self.label + '.sha256')
        return self.core_digest

    @property
    def input_sha256(self):
        self.fixture.trace.emit(self.label + '.input_sha256')
        return self.input_digest

    @property
    def canonical_bytes(self):
        self.fixture.trace.emit(self.label + '.canonical_bytes')
        return self.canonical


class Store:
    def __init__(self, fixture):
        self.fixture = fixture

    def get(self, reference, *, kind):
        f = self.fixture
        f.trace.emit('store.get:' + kind, reference)
        if kind in f.store_results:
            return f.store_results[kind]
        return (f.native_bytes, f.metadata) if kind == 'native' else (f.object_bytes, f.object_metadata)

    def get_json(self, reference, *, kind):
        f = self.fixture
        f.trace.emit('store.get_json:' + kind, reference)
        if kind in f.store_results:
            return f.store_results[kind]
        return f.record, f.record_metadata


class Service:
    def __init__(self, fixture):
        self.fixture, self.store = fixture, Store(fixture)

    @property
    def identities(self):
        self.fixture.trace.emit('service.identities')
        return self.fixture.installation

    @property
    def profiles(self):
        self.fixture.trace.emit('service.profiles')
        return self.fixture.profiles

    def _program(self, reference):
        self.fixture.trace.emit('service._program', reference)
        return self.fixture.program

    def _context(self, reference):
        self.fixture.trace.emit('service._context', reference)
        return self.fixture.context


class Fixture:
    def __init__(self, case):
        self.case, self.trace = case, Trace()
        self.widths = {name: bits for prefix in ('i', 'u') for bits in (8, 16, 32, 64)
                       for name in (prefix + str(bits),)}
        self.widths.update(isize=64, usize=64)
        self.buffer_profile = 'hepta.hia.agent.borrowed-byte-snapshots.v1'
        self.functions = [self.function('f')]
        self.document = ObservedDict(self.trace, 'document', {'functions': self.functions})
        self.program = Program(self, 'program', self.document, ['f'])
        self.exports, self.normalized_exports = (), []
        self.installation = {'backend_sha256': 'b' * 64, 'agent_sha256': 'a' * 64}
        self.profiles = ObservedDict(self.trace, 'profiles', {'target': {'id': 'target'}, 'backend': {'id': 'backend'}})
        self.context_ref = {'id': 'context'}
        self.context_argument = self.context_ref
        self.candidate_ref = {'id': 'candidate'}
        self.context = ObservedDict(self.trace, 'context', {'foreign_buffer_exports': []})
        self.native_bytes, self.object_bytes = b'actual-final-bytes', b'actual-object-bytes'
        self.artifact_ref = {'id': 'native-artifact', 'sha256': original_sha256(self.native_bytes).hexdigest()}
        self.object_ref = {'id': 'build-object', 'sha256': original_sha256(self.object_bytes).hexdigest()}
        self.build_ref = {'id': 'build-receipt'}
        self.metadata = ObservedDict(self.trace, 'metadata', {
            'installation': self.installation, 'context': self.context_ref, 'candidate': self.candidate_ref,
            'core_sha256': self.program.core_digest,
            'signatures': {'f': {'params': ['u32', 'bool'], 'returns': ['u64']}},
            'foreign_buffer_exports': [], 'output_kind': 'shared'})
        self.built = {'object_artifact': self.object_ref,
                      'object_sha256': self.object_ref['sha256'], 'core_sha256': self.program.core_digest,
                      'input_sha256': self.program.input_digest, 'implementation_sha256': self.installation['backend_sha256'],
                      'kind': 'shared', 'foreign_buffer_exports': [], 'artifact_sha256': self.artifact_ref['sha256'],
                      'machine_plan_sha256': 'p' * 64}
        self.record = ObservedDict(self.trace, 'record', self.metadata)
        dict.update(self.record, {'native_artifact': self.artifact_ref,
                                 'target_profile': dict.__getitem__(self.profiles, 'target'),
                                 'backend_profile': dict.__getitem__(self.profiles, 'backend'),
                                 'native_build': self.built, 'object_artifact': self.object_ref,
                                 'object_sha256': self.object_ref['sha256']})
        self.record_metadata = {'provider': 'build-receipt-metadata'}
        self.store_results = {}
        self.object_metadata = ObservedDict(self.trace, 'object_metadata', {
            'schema': 'hepta.hia.agent.build-object.v1', 'core_sha256': self.program.core_digest,
            'machine_plan_sha256': self.built['machine_plan_sha256'], 'installation': self.installation})
        self.service = Service(self)
        self.original, self.revised = self.program, None
        self.timeout_ms = 1000
        self.namespace = self.make_namespace()
        self.arrange(case)
        self.trace.events.clear()
        self.trace.fault = copy.deepcopy(case.get('fault'))

    def function(self, name, params=('u32', 'bool'), returns=('u64',)):
        return ObservedDict(self.trace, 'function:' + str(name), {
            'name': name, 'params': [ObservedDict(self.trace, 'parameter:' + str(name) + ':' + str(i), {'type': typ})
                                    for i, typ in enumerate(params)],
            'returns': list(returns), 'effects': [], 'entry': 'entry',
            'blocks': [{'id': 'entry', 'ops': [], 'term': {'op': 'return', 'values': []}}]})

    def make_namespace(self):
        from hepta.hia_agent_store import AgentRejected
        namespace = {'__package__': 'hepta', '__name__': 'hepta.hia_agent_service',
                     'sha256': self.hash, 'reject': self.reject,
                     'itertools': itertools, 'time': time, 'AgentRejected': AgentRejected,
                     '_vm_observation': self.forbidden,
                     'wire': lambda value: json.dumps(value, sort_keys=True).encode()}
        for name in (*METHOD_SHA256, '_behavior_equivalence'):
            path = HERE / 'fixtures' / FROZEN_FILES[name]
            raw = path.read_bytes()
            expected = METHOD_SHA256.get(name, '939d69a36845690b7a8ecc4401f38634ce7d04d7d79e615bace6894f71939e40')
            if original_sha256(raw).hexdigest() != expected:
                raise AssertionError('frozen complete original body changed: ' + name)
            exec(compile(textwrap.dedent(raw.decode()), str(path), 'exec'), namespace)
        return namespace

    def forbidden(self, *args, **kwargs):
        raise AssertionError('unexpected retained policy body, reference VM or solver')

    def reject(self, code, message, phase='admission', **kwargs):
        from hepta.hia_agent_store import AgentRejected
        self.trace.emit('reject', code, message, phase, kwargs)
        raise AgentRejected(code, message, phase, **kwargs)

    def hash(self, data=b''):
        self.trace.emit('sha256', data)
        hashed = original_sha256(data)
        fixture = self

        class Digest:
            def hexdigest(self):
                fixture.trace.emit('sha256.hexdigest')
                return hashed.hexdigest()

            def update(self, value):
                fixture.trace.emit('sha256.update', value)
                return hashed.update(value)
        return Digest()

    def normalize(self, exports, program):
        self.trace.emit('normalize_exports', exports, program)
        return self.normalized_exports

    def verify_optimization(self, original, revised, policy):
        self.trace.emit('verify_optimization', original, revised, policy)
        return {'status': 'unknown', 'opaque_provider_result': True}

    def providers(self):
        from hepta import hia_program_native, hia_native_byte_abi, hia_agent_buffers, hia_optimization
        stack = ExitStack()
        for module, name, value in (
                (hia_program_native, 'WIDTHS', self.widths),
                (hia_native_byte_abi, 'normalize_exports', self.normalize),
                (hia_agent_buffers, 'PROFILE', self.buffer_profile),
                (hia_optimization, 'verify_optimization', self.verify_optimization)):
            stack.enter_context(patch.object(module, name, value))
        return stack

    def arguments(self):
        mode = self.case.get('mode', 1)
        if mode == 1:
            return self.program, self.exports
        if mode == 2:
            return self.artifact_ref, self.context_argument
        return self.build_ref, self.context_ref, self.artifact_ref

    def set_exports(self, pairs):
        self.exports = pairs
        self.normalized_exports = [tuple(pair) for pair in pairs]
        foreign = [list(pair) for pair in pairs]
        self.context['foreign_buffer_exports'] = foreign
        self.metadata['foreign_buffer_exports'] = foreign
        self.record['foreign_buffer_exports'] = foreign
        self.built['foreign_buffer_exports'] = foreign
        signatures = {'f': {'params': ['u32', 'bool'], 'returns': ['u64']}}
        for name, extent in pairs:
            if name == 'f':
                signatures[name].update(abi=self.buffer_profile, max_buffer_bytes=extent)
        self.metadata['signatures'] = signatures
        self.record['signatures'] = signatures

    def arrange(self, case):
        if __package__:
            from .hia_native_build_admission_scenarios import arrange
        else:
            from hia_native_build_admission_scenarios import arrange
        arrange(self, case)

    def aliases(self, value):
        mode = self.case.get('mode', 1)
        if mode == 2 and type(value) is tuple and len(value) == 3:
            return {'data': value[0] is self.native_bytes, 'metadata': value[1] is self.metadata,
                    'program': value[2] is self.program}
        if mode == 3 and type(value) is tuple and len(value) == 4:
            return {'record': value[0] is self.record, 'data': value[1] is self.native_bytes,
                    'object_bytes': value[2] is self.object_bytes, 'program': value[3] is self.program}
        if mode == 4:
            return {'record': value is self.record}
        if mode == 1 and type(value) is dict:
            result = {}
            for index, fn in enumerate(self.functions):
                if not isinstance(fn, dict) or 'name' not in fn or 'returns' not in fn:
                    continue
                name = dict.__getitem__(fn, 'name')
                try:
                    returned = dict.get(value, name)
                except TypeError:
                    continue
                if type(returned) is dict:
                    result[str(index)] = returned.get('returns') is dict.__getitem__(fn, 'returns')
            return result
        return {}


def exception_record(error):
    row = {'type': type(error).__module__ + '.' + type(error).__qualname__, 'args': snapshot(error.args)}
    for name in ('code', 'phase', 'retry_action', 'details_artifact'):
        if hasattr(error, name):
            row[name] = snapshot(getattr(error, name))
    if error.__cause__ is not None:
        row['cause'] = exception_record(error.__cause__)
    row['suppress_context'] = error.__suppress_context__
    return row


def observe_case(case, owner=None):
    """owner(mode, service, arguments, namespace) may execute the candidate frame."""
    fixture = Fixture(case)
    ns, service, mode = fixture.namespace, fixture.service, case.get('mode', 1)
    for name in ('_native', '_build_inputs', '_build_receipt'):
        setattr(service, name, ns[name].__get__(service) if owner is None else fixture.forbidden)
    if owner is not None:
        ns['_signatures'] = (lambda program, exports=(): owner(1, None, (program, exports), ns)
                             if case.get('route') == 'behavior' else fixture.forbidden(program, exports))
    with fixture.providers():
        try:
            if case.get('route') == 'behavior':
                value = ns['_behavior_equivalence'](service, fixture.original, fixture.revised, fixture.timeout_ms)
            elif owner is None:
                method = {1: '_signatures', 2: '_native', 3: '_build_inputs', 4: '_build_receipt'}[mode]
                value = ns[method](*fixture.arguments()) if mode == 1 else ns[method](service, *fixture.arguments())
            else:
                value = owner(mode, None if mode == 1 else service, fixture.arguments(), ns)
            result = {'returned': snapshot(value), 'aliases': fixture.aliases(value)}
        except BaseException as error:
            result = {'exception': exception_record(error)}
    return {'name': case['name'], 'mode': mode, 'route': case.get('route', 'owner'),
            'outcome': result, 'trace': fixture.trace.events}
