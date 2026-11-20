"""Two frozen originals executed only against deterministic fake providers.

No product import, HIA native image, Core VM, filesystem effect, compiler or
child process is used. Candidate code must not change this frozen oracle.
"""
from __future__ import annotations
import builtins
from contextlib import contextmanager
from hashlib import sha256 as real_sha256
import json
from pathlib import Path as RealPath
import sys
import textwrap
import types

ROOT = RealPath(__file__).resolve().parent
FREEZE = json.loads((ROOT / 'original-freeze.json').read_text())
BASE_COMMIT = FREEZE['base_commit']
OBJECT = b'FAKE-IMMUTABLE-OBJECT\x00\xff'
SHARED = b'FAKE-IMMUTABLE-SHARED\x00\xfe'
CORE, INPUT, MACHINE_PLAN = 'c' * 64, 'd' * 64, 'e' * 64


class AgentRejected(ValueError):
    pass


class InjectedError(ValueError):
    pass


class InjectedBase(BaseException):
    pass


ERROR_TYPES = {
    'InjectedError': InjectedError, 'ValueError': ValueError, 'TypeError': TypeError,
    'OSError': OSError, 'OverflowError': OverflowError, 'RecursionError': RecursionError,
    'RuntimeError': RuntimeError, 'StopIteration': StopIteration,
    'KeyboardInterrupt': KeyboardInterrupt, 'SystemExit': SystemExit,
    'InjectedBase': InjectedBase,
}


def canonical(value):
    """Snapshot without calling fake objects' overloaded protocols."""
    if isinstance(value, Number):
        return {'object': object.__getattribute__(value, '_label'),
                'value': canonical(object.__getattribute__(value, 'value'))}
    if isinstance(value, OracleObject):
        return {'object': object.__getattribute__(value, '_label')}
    if isinstance(value, BaseException):
        return {'exception': type(value).__name__, 'args': canonical(value.args)}
    if isinstance(value, type) and issubclass(value, BaseException):
        return {'exception_type': value.__name__}
    if value is None or type(value) in (bool, int, str):
        return value
    if isinstance(value, bytes):
        return {'bytes': bytes.hex(value), 'type': type(value).__name__}
    if isinstance(value, bytearray):
        return {'bytearray': bytes(value).hex()}
    if type(value) is float:
        return {'float': value.hex()}
    if isinstance(value, dict):
        return {str(k): canonical(v) for k, v in dict.items(value)}
    if isinstance(value, list):
        return [canonical(v) for v in list.__iter__(value)]
    if isinstance(value, tuple):
        return {'tuple': [canonical(v) for v in tuple.__iter__(value)]}
    if isinstance(value, types.TracebackType):
        return {'traceback': True}
    if isinstance(value, types.SimpleNamespace):
        return {'provider_namespace': sorted(vars(value))}
    if callable(value):
        return {'callable': getattr(value, '__name__', type(value).__name__)}
    raise AssertionError('oracle cannot observe ' + type(value).__name__)


def exception_record(error, seen=None):
    seen = set() if seen is None else seen
    if error is None:
        return None
    if id(error) in seen:
        return {'cycle': type(error).__name__}
    seen.add(id(error))
    return {'type': type(error).__name__, 'args': canonical(error.args),
            'cause': exception_record(error.__cause__, seen),
            'context': exception_record(error.__context__, seen),
            'suppress_context': error.__suppress_context__}


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


class OracleObject:
    def __init__(self, fixture, label):
        self._fixture, self._label = fixture, label


class Trace:
    def __init__(self, fixture):
        self.fixture, self.events, self.counts = fixture, [], {}
        self.raised_objects = []

    def error(self, spec, label):
        if isinstance(spec, str):
            return ERROR_TYPES[spec](label)
        return ERROR_TYPES[spec.get('type', 'InjectedError')](*spec.get('args', [label]))

    def invoke(self, operation, arguments, callback):
        index = self.counts.get(operation, 0) + 1
        self.counts[operation] = index
        self.events.append({'event': 'call', 'operation': operation, 'index': index,
                            'arguments': canonical(arguments), 'active_exception': canonical(sys.exception())})
        faults = self.fixture.case.get('faults', [])
        if 'fault' in self.fixture.case:
            faults = [self.fixture.case['fault'], *faults]
        match = next((f for f in faults if f['operation'] == operation and f.get('index', 1) == index), None)
        try:
            if match and match.get('when', 'before') == 'before':
                raise self.error(match, operation + ':before')
            value = callback()
            if match and match.get('when', 'before') == 'after':
                raise self.error(match, operation + ':after')
        except BaseException as error:
            self.raised_objects.append((operation, index, error))
            self.events.append({'event': 'raise', 'operation': operation, 'index': index,
                                'error': canonical(error)})
            raise
        self.events.append({'event': 'return', 'operation': operation, 'index': index,
                            'value': canonical(value)})
        return value


class Truth(OracleObject):
    def __init__(self, fixture, label, values):
        super().__init__(fixture, label)
        self.values, self.index = values, 0

    def __bool__(self):
        def value():
            answer = self.values[min(self.index, len(self.values) - 1)]
            self.index += 1
            if isinstance(answer, str):
                raise ERROR_TYPES[answer](self._label)
            return answer
        return self._fixture.trace.invoke(self._label + '.__bool__', (), value)


class Comparable(OracleObject):
    def __init__(self, fixture, label, spec):
        super().__init__(fixture, label)
        self.spec, self.index = spec, 0

    def _compare(self, op, other):
        def value():
            choices = self.spec.get('sequence', [self.spec])
            spec = choices[min(self.index, len(choices) - 1)]
            self.index += 1
            if 'raise' in spec:
                raise ERROR_TYPES[spec['raise']](self._label)
            if 'truth' in spec:
                return Truth(self._fixture, self._label + '.' + op + '.result', spec['truth'])
            return spec.get('value', True)
        return self._fixture.trace.invoke(self._label + '.' + op, (other,), value)

    def __eq__(self, other): return self._compare('__eq__', other)
    def __ne__(self, other): return self._compare('__ne__', other)


def scalar(value):
    return value.value if isinstance(value, Number) else value


class Number(OracleObject):
    def __init__(self, fixture, label, value):
        super().__init__(fixture, label)
        self.value = value

    def _binary(self, op, other, callback, numeric=False):
        def value():
            result = callback(self.value, scalar(other))
            return Number(self._fixture, self._label + '.' + op, result) if numeric else result
        return self._fixture.trace.invoke(self._label + '.' + op, (other,), value)

    def __le__(self, other): return self._binary('__le__', other, lambda a, b: a <= b)
    def __lt__(self, other): return self._binary('__lt__', other, lambda a, b: a < b)
    def __gt__(self, other): return self._binary('__gt__', other, lambda a, b: a > b)
    def __truediv__(self, other): return self._binary('__truediv__', other, lambda a, b: a / b, True)
    def __add__(self, other): return self._binary('__add__', other, lambda a, b: a + b, True)
    def __radd__(self, other): return self._binary('__radd__', other, lambda a, b: b + a, True)
    def __sub__(self, other): return self._binary('__sub__', other, lambda a, b: a - b, True)
    def __rsub__(self, other): return self._binary('__rsub__', other, lambda a, b: b - a, True)


class Mapping(dict):
    def __init__(self, fixture, label, values):
        dict.__init__(self, values)
        self.fixture, self.label = fixture, label

    def __getitem__(self, key):
        def value():
            answer = dict.__getitem__(self, key)
            self.fixture.mutate(self.label + '.__getitem__', key)
            return answer
        return self.fixture.trace.invoke(self.label + '.__getitem__', (key,), value)

    def get(self, key, *default):
        return self.fixture.trace.invoke(self.label + '.get', (key, *default),
                                         lambda: dict.get(self, key, *default))

    def pop(self, key, *default):
        return self.fixture.trace.invoke(self.label + '.pop', (key, *default),
                                         lambda: dict.pop(self, key, *default))

    def __setitem__(self, key, value):
        return self.fixture.trace.invoke(self.label + '.__setitem__', (key, value),
                                         lambda: dict.__setitem__(self, key, value))


class Sequence(OracleObject):
    def __init__(self, fixture, label, values):
        super().__init__(fixture, label)
        self.values, self.iterations = values, 0

    def __iter__(self):
        def value():
            self.iterations += 1
            return Iterator(self._fixture, self._label + '.iterator.' + str(self.iterations), self.values)
        return self._fixture.trace.invoke(self._label + '.__iter__', (), value)


class Iterator(OracleObject):
    def __init__(self, fixture, label, values):
        super().__init__(fixture, label)
        self.values, self.index = values, 0

    def __iter__(self):
        return self._fixture.trace.invoke(self._label + '.__iter__', (), lambda: self)

    def __next__(self):
        def value():
            if self.index == len(self.values):
                raise StopIteration
            answer = self.values[self.index]
            self.index += 1
            return answer
        return self._fixture.trace.invoke(self._label + '.__next__', (), value)


class Program(OracleObject):
    @property
    def sha256(self):
        def value():
            self._fixture.mutate('program.sha256', None)
            return CORE
        return self._fixture.trace.invoke('program.sha256', (), value)


class Bytes(bytes):
    pass


class Image(OracleObject):
    @property
    def object_bytes(self):
        variants = {'bytes': OBJECT, 'subclass': Bytes(OBJECT), 'bytearray': bytearray(OBJECT), 'none': None}
        return self._fixture.trace.invoke('image.object_bytes', (),
            lambda: variants[self._fixture.case.get('object_bytes', 'bytes')])


class Digest(OracleObject):
    def __init__(self, fixture, label, data):
        super().__init__(fixture, label)
        self.data = data

    def hexdigest(self):
        def value():
            self._fixture.mutate(self._label + '.hexdigest', None)
            return real_sha256(self.data).hexdigest()
        return self._fixture.trace.invoke(self._label + '.hexdigest', (), value)


class VirtualPath(OracleObject):
    def __init__(self, fixture, value):
        super().__init__(fixture, 'path:' + value)
        self.value = value

    def __truediv__(self, name):
        return self._fixture.trace.invoke('Path.join', (self, name),
            lambda: VirtualPath(self._fixture, self.value + '/' + name))

    def read_bytes(self):
        return self._fixture.trace.invoke('Path.read_bytes', (self,), lambda: self._fixture.final_bytes)


class TempSpecial:
    def __init__(self, name):
        self.name = name

    def __get__(self, manager, owner):
        if manager is None:
            raise AssertionError('original with must bind descriptor to actual manager')
        return manager._fixture.trace.invoke('temp.lookup_' + self.name, (manager, owner.__name__),
            lambda: getattr(manager, self.name))


class Temporary(OracleObject):
    __enter__ = TempSpecial('enter')
    __exit__ = TempSpecial('exit')

    def __init__(self, fixture, index):
        super().__init__(fixture, 'temporary.' + str(index))
        self.entered, self.exited, self.exit_calls = False, False, 0
        if fixture.case.get('instance_special_shadows'):
            self.__enter__ = self.forbidden_instance_special
            self.__exit__ = self.forbidden_instance_special

    def forbidden_instance_special(self, *args):
        raise AssertionError('with consulted instance special method shadow')

    def enter(self):
        def value():
            self.entered = True
            return 'VIRTUAL-TEMP'
        return self._fixture.trace.invoke('temp.enter', (self,), value)

    def exit(self, exc_type, error, traceback):
        active = sys.exception()
        observed = {'type': exc_type, 'error': error, 'traceback': traceback is not None,
                    'traceback_is_error_traceback': traceback is not None and error is not None and traceback is error.__traceback__,
                    'active_exception': active, 'active_is_error': active is error,
                    'active_is_outer': active is self._fixture.outer_error}
        def value():
            self.exit_calls += 1
            self.exited = True
            if self._fixture.case.get('exit_bare_raise'):
                raise
            answer = self._fixture.case.get('exit_result', False)
            if isinstance(answer, list):
                return Truth(self._fixture, 'temp.exit.result', answer)
            return answer
        return self._fixture.trace.invoke('temp.exit', observed, value)


class TimeModule(OracleObject):
    @property
    def monotonic(self):
        variant = self._fixture.clock_variant
        def call():
            def value():
                index = self._fixture.clock_calls
                self._fixture.clock_calls += 1
                answer = self._fixture.clock_values[min(index, len(self._fixture.clock_values) - 1)]
                if variant == 'replacement':
                    answer = 200.5
                self._fixture.mutate('time.monotonic.call.' + variant, None)
                return answer
            return self._fixture.trace.invoke('time.monotonic.call.' + variant, (), value)
        return self._fixture.trace.invoke('time.monotonic.lookup', (), lambda: call)


class TempModule(OracleObject):
    @property
    def TemporaryDirectory(self):
        def construct(*args, **kwargs):
            def value():
                manager = Temporary(self._fixture, len(self._fixture.temporaries))
                self._fixture.temporaries.append(manager)
                return manager
            return self._fixture.trace.invoke('temp.construct', (args, kwargs), value)
        return self._fixture.trace.invoke('temp.constructor.lookup', (), lambda: construct)


class NativeModule(OracleObject):
    @property
    def emit_program_machine(self):
        return self._fixture.trace.invoke('native.emit.lookup', (), lambda: self._fixture.emit_program_machine)

    @property
    def compile_program_machine(self):
        variant = self._fixture.native_compile_variant
        def compile_provider(*args, **kwargs):
            return self._fixture.compile_program_machine(variant, *args, **kwargs)
        return self._fixture.trace.invoke('native.compile.lookup', (), lambda: compile_provider)


class Store(OracleObject):
    @property
    def root(self):
        return self._fixture.trace.invoke('store.root', (), lambda: 'VIRTUAL-ROOT')

    @property
    def get_json(self):
        def call(reference):
            return self._fixture.trace.invoke('store.get_json.call', (reference,),
                lambda: (self._fixture.plan, {'uninterpreted_metadata': 'retained'}))
        return self._fixture.trace.invoke('store.get_json.lookup', (), lambda: call)

    @property
    def put(self):
        variant = self._fixture.store_put_variant
        def call(data, kind, metadata):
            def value():
                artifact = {'kind': kind, 'sha256': real_sha256(data).hexdigest(),
                            'variant': variant, 'publication': len(self._fixture.store_effects)}
                self._fixture.store_effects.append({'operation': 'put', 'data': canonical(data),
                    'kind': kind, 'metadata': canonical(metadata), 'artifact': artifact})
                return artifact
            return self._fixture.trace.invoke('store.put.call.' + variant, (data, kind, metadata), value)
        return self._fixture.trace.invoke('store.put.lookup', (), lambda: call)

    @property
    def json(self):
        def call(data, kind):
            def value():
                artifact = {'kind': kind, 'sha256': real_sha256(encoded(canonical(data))).hexdigest(),
                            'publication': len(self._fixture.store_effects)}
                self._fixture.store_effects.append({'operation': 'json', 'data': canonical(data),
                    'kind': kind, 'artifact': artifact})
                return artifact
            return self._fixture.trace.invoke('store.json.call', (data, kind), value)
        return self._fixture.trace.invoke('store.json.lookup', (), lambda: call)


class Service(OracleObject):
    _LOOKUPS = frozenset(('_profile', '_context', '_program', '_verification', '_remaining_ms'))

    def __getattribute__(self, name):
        if name in Service._LOOKUPS:
            fixture = object.__getattribute__(self, '_fixture')
            return fixture.trace.invoke('service.' + name + '.lookup', (),
                                        lambda: object.__getattribute__(self, name))
        return object.__getattribute__(self, name)

    @property
    def store(self):
        return self._fixture.trace.invoke('service.store', (), lambda: self._fixture.store)

    @property
    def identities(self):
        return self._fixture.trace.invoke('service.identities', (),
            lambda: {'backend': 'fake-fixed-backend', 'installation': INPUT})

    def _profile(self, reference, kind):
        return self._fixture.trace.invoke('service._profile.call', (reference, kind), lambda: None)

    def _context(self, reference):
        return self._fixture.trace.invoke('service._context.call', (reference,), lambda: self._fixture.context)

    def _program(self, reference):
        return self._fixture.trace.invoke('service._program.call', (reference,), lambda: self._fixture.program)

    def _verification(self, reference, context, candidate):
        def value():
            if self._fixture.case.get('verification_replaces_compile'):
                self._fixture.compile_variant = 'replacement'
            return self._fixture.receipt
        return self._fixture.trace.invoke('service._verification.call', (reference, context, candidate), value)

    def _remaining_ms(self, context):
        def value():
            if self._fixture.case.get('remaining_replaces_compile'):
                self._fixture.compile_variant = 'replacement'
            return self._fixture.timeout
        return self._fixture.trace.invoke('service._remaining_ms.call', (context,), value)

    @property
    def _compile(self):
        variant = self._fixture.compile_variant
        def call(*args, **kwargs):
            def value():
                if variant == 'original':
                    return self._fixture.compile_delegate(self, *args, **kwargs)
                data = self._fixture.final_bytes + (b'REPLACED' if variant == 'replacement' else b'')
                return data, self._fixture.build_result(include_artifact=True, variant=variant)
            return self._fixture.trace.invoke('service._compile.call.' + variant, (args, kwargs), value)
        return self._fixture.trace.invoke('service._compile.lookup', (), lambda: call)


def number_spec(value):
    if isinstance(value, str):
        return {'nan': float('nan'), 'inf': float('inf'), '-inf': -float('inf'),
                '-zero': -0.0, 'wide': 1 << 4096}[value]
    return value


class Fixture:
    def __init__(self, case):
        self.case, self.trace = case, Trace(self)
        self.store_effects, self.temporaries, self.clock_calls = [], [], 0
        self.outer_error = None
        self.compile_variant = case.get('compile_route', 'stub')
        self.native_compile_variant = self.store_put_variant = self.clock_variant = 'original'
        self.kind = case.get('kind', 'shared')
        if isinstance(self.kind, dict):
            self.kind = Comparable(self, 'kind', self.kind)
        self.timeout = number_spec(case.get('timeout', 2500))
        self.clock_values = [number_spec(v) for v in case.get('clock', [100.0, 100.25])]
        if case.get('number_protocol'):
            self.timeout = Number(self, 'number.timeout', self.timeout)
            self.clock_values = [Number(self, 'number.clock.' + str(i), v) for i, v in enumerate(self.clock_values)]
        self.final_bytes = OBJECT if case.get('kind') == 'object' else SHARED
        if case.get('output_bytes_changed'):
            self.final_bytes += b'CHANGED'
        self.program, self.image = Program(self, 'program'), Image(self, 'image')
        self.store, self.service = Store(self, 'store'), Service(self, 'service')
        self.plan = Mapping(self, 'plan', {'schema': 'fake-plan', 'core_sha256': CORE})
        self.context = Mapping(self, 'context', {'target_profile': {'sha256': 'target'}})
        exports = case.get('exports', [])
        if case.get('export_iterables'):
            exports = Sequence(self, 'exports', [Sequence(self, 'export.' + str(i), pair) if isinstance(pair, list)
                                               else pair for i, pair in enumerate(exports)])
        if not case.get('exports_missing'):
            dict.__setitem__(self.context, 'foreign_buffer_exports', exports)
        if case.get('target_missing'):
            dict.pop(self.context, 'target_profile')
        self.codegen = Mapping(self, 'codegen',
            {'kind': 'agent_plan', 'plan_profile': {'sha256': 'plan-profile'},
             'plan': {'sha256': 'plan'}, 'verification_receipt': {'sha256': 'plan-receipt'}}
            if case.get('plan') else {'kind': 'canonical', 'lowering_profile': {'sha256': 'lowering'}})
        if 'codegen_kind_compare' in case:
            dict.__setitem__(self.codegen, 'kind', Comparable(self, 'codegen.kind', case['codegen_kind_compare']))
        verification_receipts = case.get('receipts', [])
        if case.get('receipt_iterable'):
            verification_receipts = Sequence(self, 'verification_receipts', verification_receipts)
        self.args = Mapping(self, 'arguments', {'backend_profile': {'sha256': 'backend'},
            'context': {'sha256': 'context'}, 'candidate': {'sha256': 'candidate'},
            'verification_receipts': verification_receipts, 'codegen': self.codegen, 'output_kind': self.kind})
        for key in case.get('arguments_missing', []):
            dict.pop(self.args, key)
        subject = {'kind': 'agent_machine_plan', 'backend_profile': {'sha256': 'backend'},
                   'plan_profile': {'sha256': 'plan-profile'}, 'plan': {'sha256': 'plan'}}
        if not case.get('subject_matches', True):
            subject['kind'] = 'wrong-subject'
        if 'subject_compare' in case:
            subject = Comparable(self, 'receipt.subject', case['subject_compare'])
        checks = []
        for i, source in enumerate(case.get('checks', [{'claim': 'lowering_refinement', 'status': 'proved'}])):
            values = {key: Comparable(self, 'check.' + str(i) + '.' + key, value) if isinstance(value, dict)
                      else value for key, value in source.items()}
            checks.append(Mapping(self, 'check.' + str(i), values))
        self.receipt = Mapping(self, 'receipt', {'subject': subject,
            'checks': Sequence(self, 'checks', checks) if case.get('checks_iterable', True) else checks})
        for key in case.get('receipt_missing', []):
            dict.pop(self.receipt, key)
        self.native_module = NativeModule(self, 'native_module')
        self.namespace = {'__builtins__': builtins.__dict__, '__name__': 'hepta.hia_emission_frozen_original',
            '__package__': 'hepta', 'time': TimeModule(self, 'time'), 'tempfile': TempModule(self, 'tempfile'),
            'Path': self.path, 'sha256': self.hash_original, 'reject': self.reject, 'validate': self.validate,
            'PLAN_SCHEMA': {'schema': 'fake-machine-plan-schema'}, '_signatures': self.signatures}
        for name in ('compile', 'emit'):
            source = (ROOT / ('hia_emission_' + name + '_73f1634.py.txt')).read_text()
            exec(compile(textwrap.dedent(source), 'frozen-original-73f1634-' + name + '.py', 'exec',
                         dont_inherit=True), self.namespace)
        self.original_compile = self.namespace['_compile']
        self.original_emit = self.namespace['_hia_emit']
        self.compile_delegate = self.original_compile

    def mutate(self, operation, key):
        if operation == 'arguments.__getitem__' and key == 'output_kind' and self.case.get('kind_replaces_compile'):
            self.compile_variant = 'replacement'
        for mutation in self.case.get('mutations', []):
            if mutation['operation'] != operation:
                continue
            if self.trace.counts.get(operation, 0) != mutation.get('index', 1):
                continue
            if 'key' in mutation and mutation['key'] != key:
                continue
            name = mutation['replace']
            if name == 'native_compile': self.native_compile_variant = 'replacement'
            elif name == 'store_put': self.store_put_variant = 'replacement'
            elif name == 'clock': self.clock_variant = 'replacement'
            elif name == 'sha256': self.namespace['sha256'] = self.hash_replacement
            else: raise AssertionError('unknown oracle mutation ' + name)

    def build_result(self, include_artifact=False, variant='original'):
        data = self.final_bytes + (b'REPLACED' if variant == 'replacement' else b'')
        values = {'output': 'VIRTUAL-OUTPUT', 'object_sha256': real_sha256(OBJECT).hexdigest(),
                  'core_sha256': CORE, 'artifact_sha256': real_sha256(data).hexdigest(),
                  'machine_plan_sha256': MACHINE_PLAN, 'opaque_retained': 'original'}
        values.update(self.case.get('build_updates', {}))
        for key in self.case.get('build_missing', []):
            values.pop(key, None)
        for key, spec in self.case.get('build_comparisons', {}).items():
            values[key] = Comparable(self, 'build.' + key, spec)
        if include_artifact:
            values['object_artifact'] = {'kind': 'build-object', 'sha256': real_sha256(OBJECT).hexdigest()}
        return Mapping(self, 'build', values)

    def emit_program_machine(self, *args, **kwargs):
        def value():
            self.mutate('native.emit.call', None)
            return self.image
        return self.trace.invoke('native.emit.call', (args, kwargs), value)

    def compile_program_machine(self, variant, *args, **kwargs):
        def value():
            kwargs['command_log'].append(['compiler-provider-' + variant, kwargs['kind']])
            return self.build_result(variant=variant)
        return self.trace.invoke('native.compile.call.' + variant, (args, kwargs), value)

    def path(self, directory):
        return self.trace.invoke('Path.construct', (directory,), lambda: VirtualPath(self, directory))

    def hash_original(self, data):
        return self.trace.invoke('sha256.original', (data,), lambda: Digest(self, 'hash.original', data))

    def hash_replacement(self, data):
        return self.trace.invoke('sha256.replacement', (data,), lambda: Digest(self, 'hash.replacement', data))

    def reject(self, code, message, field):
        def value():
            raise AgentRejected(code, message, field)
        return self.trace.invoke('reject', (code, message, field), value)

    def validate(self, value, schema, field):
        return self.trace.invoke('validate', (value, schema, field), lambda: None)

    def signatures(self, program, exports):
        return self.trace.invoke('_signatures', (program, exports),
            lambda: [{'name': 'entry', 'return_type': 'i64', 'args': [], 'exports': canonical(exports)}])

    def arguments(self):
        if self.case['mode'] == 1:
            return (self.program, self.kind, self.plan if self.case.get('plan') else None,
                    self.timeout, tuple(tuple(pair) for pair in self.case.get('exports', [])))
        return (self.args,)

    @contextmanager
    def providers(self):
        original_import = builtins.__import__
        def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
            if name in ('hia_program_native', 'hepta.hia_program_native'):
                return self.trace.invoke('import.hia_program_native', (name, tuple(fromlist), level),
                                         lambda: self.native_module)
            return original_import(name, globals, locals, fromlist, level)
        builtins.__import__ = fake_import
        try:
            yield self
        finally:
            builtins.__import__ = original_import

    def original(self):
        if self.case['mode'] == 1:
            program, kind, plan, timeout, exports = self.arguments()
            return self.original_compile(self.service, program, kind, plan, timeout,
                                         foreign_buffer_exports=exports)
        return self.original_emit(self.service, self.args)

    def observe(self, operation):
        def run():
            try:
                value = operation()
                return {'kind': 'returned', 'value': canonical(value)}
            except BaseException as error:
                return {'kind': 'raised', 'error': exception_record(error),
                        'is_outer_exception': error is self.outer_error,
                        'same_provider_error': [[op, index] for op, index, value in self.trace.raised_objects
                                                if value is error],
                        'cause_is_provider_error': [[op, index] for op, index, value in self.trace.raised_objects
                                                    if value is error.__cause__]}
        if self.case.get('outer_exception'):
            try:
                raise InjectedError('preexisting outer exception')
            except InjectedError as error:
                self.outer_error = error
                outcome = run()
        else:
            outcome = run()
        return {'name': self.case['name'], 'mode': self.case['mode'], 'outcome': outcome,
                'trace': self.trace.events, 'store_effects': self.store_effects,
                'temporaries': [{'entered': x.entered, 'exited': x.exited, 'exit_calls': x.exit_calls}
                                for x in self.temporaries], 'clock_calls': self.clock_calls,
                'compile_variant_after': self.compile_variant,
                'native_compile_variant_after': self.native_compile_variant,
                'store_put_variant_after': self.store_put_variant, 'clock_variant_after': self.clock_variant}


def observe_case(case):
    fixture = Fixture(case)
    with fixture.providers():
        return fixture.observe(fixture.original)


def cases():
    return json.loads((ROOT / 'cases.json').read_text())['cases']
