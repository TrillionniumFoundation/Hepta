"""Independent complete-original inspect/candidate observations; no policy mirror.

Expected outcomes come only from the byte-frozen two original methods. Fakes
implement individual object/provider protocols, not handler control decisions.
This module does not import the product. Fixture objects are fresh per case;
the ordinary service/arguments are held by the consumer through body return.
No SQL, filesystem provider, compiler, VM or native image is invoked here.
"""
from __future__ import annotations

import builtins
from contextlib import contextmanager
from hashlib import sha256
import json
from pathlib import Path
import sys
import textwrap
import traceback
import types
import weakref

DIRECTORY = Path(__file__).parent / 'fixtures/hia_service_inspection_original_bc011'
ORIGINALS = {
    1: ('inspect.bc011.py.txt', '0b94fc6cf910593c8993fc06de4fcfe6b6318f7b974028b4cfdc70033ec6b267'),
    2: ('candidate.bc011.py.txt', 'd50fa77b3dbad0c8cca486b0936ca5b65be3f606fff371b29f35d38154993b42'),
}
# The filename/digest pair above is checked before compile; a static reviewer
# must compare each literal with source-identity.json, not with current product.
MISSING = object()
FAULT_TYPES = {
    'ValueError': ValueError, 'TypeError': TypeError, 'OSError': OSError,
    'RuntimeError': RuntimeError, 'MemoryError': MemoryError,
    'KeyboardInterrupt': KeyboardInterrupt, 'SystemExit': SystemExit,
    'StopIteration': StopIteration, 'AttributeError': AttributeError,
}


class Rejected(ValueError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode()


def snapshot(value):
    kind = type(value)
    if value is None:
        return {'none': True}
    if kind is bool:
        return {'bool': value}
    if kind is int:
        return {'int': str(value)}
    if kind is float:
        return {'float': value.hex()}
    if kind is str:
        return {'str': value}
    if kind is bytes:
        return {'bytes_hex': value.hex()}
    if kind is bytearray:
        return {'bytearray_hex': value.hex()}
    if isinstance(value, Observed):
        return {'object': type(value).__name__,
                'token': object.__getattribute__(value, '_token')}
    if isinstance(value, Text):
        return {'text': str.__str__(value),
                'token': object.__getattribute__(value, '_token')}
    if kind in (tuple, list):
        return {kind.__name__: [snapshot(item) for item in value]}
    if kind is dict:
        return {'dict': [[snapshot(key), snapshot(item)] for key, item in value.items()]}
    if kind is types.GeneratorType:
        return {'generator': value.gi_code.co_name}
    if kind in (types.MethodType, types.FunctionType, types.BuiltinFunctionType):
        return {'callable': getattr(value, '__name__', kind.__name__)}
    return {'opaque_type': kind.__name__}


def error_snapshot(error, fault):
    if error is None:
        return None
    return {'class': type(error).__name__, 'args': snapshot(error.args),
            'injected_identity': error is fault,
            'name': snapshot(getattr(error, 'name', None)),
            'obj': snapshot(getattr(error, 'obj', None)),
            'cause_class': None if error.__cause__ is None else type(error.__cause__).__name__,
            'cause_is_injected': error.__cause__ is fault if fault is not None else False,
            'context_class': None if error.__context__ is None else type(error.__context__).__name__,
            'context_is_injected': error.__context__ is fault if fault is not None else False,
            'suppress_context': error.__suppress_context__}


class World:
    def __init__(self, case):
        self.case = case
        self.events, self.weak_objects, self.escaped = [], [], []
        self.serial, self.occurrences = {}, {}
        self.fault = None
        self.fault_hits = 0
        spec = case.get('fault')
        if spec is not None:
            self.fault = FAULT_TYPES[spec['kind']]('injected:' + spec['operation'])
        self.namespace = None

    def token(self, name):
        self.serial[name] = self.serial.get(name, 0) + 1
        return name + '.' + str(self.serial[name])

    def register(self, value):
        self.weak_objects.append(weakref.ref(value))

    def record(self, operation, at, occurrence, value=MISSING):
        row = {'operation': operation, 'at': at, 'occurrence': occurrence}
        if value is not MISSING:
            row['value'] = snapshot(value)
        self.events.append(row)

    def inject(self, operation, at, occurrence):
        spec = self.case.get('fault')
        if (spec is not None and spec['operation'] == operation
                and spec['at'] == at and spec['occurrence'] == occurrence):
            self.fault_hits += 1
            raise self.fault

    def edge(self, operation, callback):
        index = self.occurrences.get(operation, 0) + 1
        self.occurrences[operation] = index
        self.record(operation, 'before', index)
        self.inject(operation, 'before', index)
        value = callback()
        self.record(operation, 'after', index, value)
        self.inject(operation, 'after', index)
        return value

    def provider(self, name, callback):
        def call(*args, **kwargs):
            self.events.append({'operation': name + '.arguments',
                'args': snapshot(args), 'kwargs': snapshot(kwargs)})
            value = self.edge(name, lambda: callback(*args, **kwargs))
            rebind = self.case.get('rebind_after_provider')
            if rebind and rebind['provider'] == name:
                global_name = rebind['global']
                self.namespace[global_name] = self.provider('global.rebound.' + global_name,
                    lambda *a, **k: rebind['result'])
            return value
        return call

    def reject(self, code, detail):
        def run():
            if self.case.get('reject_returns'):
                return None
            raise Rejected(code, detail)
        return self.edge('reject:' + code, run)

    def scalar(self, value, name):
        if self.case.get('tracked_text'):
            return Text(self, name, value)
        return value

    def program(self, name='program'):
        return Program(self, name)

    def diagnostics(self):
        return Map(self, 'diagnostics', {'schema': 'diagnostics.v1', 'whole_program_checked': True})

    def image(self):
        return Image(self, 'image')

    def functions(self):
        rows = self.case.get('functions', [
            {'name': 'f0', 'blocks': [{'id': 'b0'}, {'id': 'b1'}]},
            {'name': 'f1', 'blocks': [{'id': 'b0'}]},
        ])
        nodes = []
        for index, row in enumerate(rows):
            blocks = [Map(self, 'block', {'id': block['id'], 'body': 'body'})
                      for block in row.get('blocks', [])]
            node = Map(self, 'function', {'name': row['name'],
                'blocks': Iterable(self, 'blocks', blocks)})
            nodes.append(node)
        return Iterable(self, 'functions', nodes)

    def all_foreign(self, iterable):
        policy = self.case.get('all', 'consume')
        def run():
            if policy == 'retain-true':
                self.escaped.append(iterable)
                return Truth(self, 'all-result', True)
            if policy == 'retain-false':
                self.escaped.append(iterable)
                return Truth(self, 'all-result', False)
            if policy == 'first':
                return next(iterable)
            if policy == 'twice':
                first = tuple(iterable)
                second = tuple(iterable)
                return bool(first) and not second
            return builtins.all(iterable)
        return self.edge('global.all', run)


class Observed:
    _observed_names = frozenset()
    def __init__(self, world, name):
        self._world, self._token = world, world.token(name)
        world.register(self)

    def __getattribute__(self, name):
        names = object.__getattribute__(self, '_observed_names')
        if name in names:
            world = object.__getattribute__(self, '_world')
            token = object.__getattribute__(self, '_token')
            return world.edge(token + '.' + name + '.lookup',
                              lambda: object.__getattribute__(self, name))
        return object.__getattribute__(self, name)

    def __del__(self):
        try:
            world = object.__getattribute__(self, '_world')
            token = object.__getattribute__(self, '_token')
            world.events.append({'operation': token + '.release'})
        except BaseException:
            # Only a partially initialized fake can reach this path.
            pass


class Truth(Observed):
    def __init__(self, world, name, value):
        super().__init__(world, name)
        self._value = value
    def __bool__(self):
        return self._world.edge(self._token + '.bool', lambda: self._value)


class Text(str):
    def __new__(cls, world, name, value):
        result = str.__new__(cls, value)
        result._world, result._token = world, world.token(name)
        return result
    def __eq__(self, other):
        return self._world.edge(self._token + '.eq',
            lambda: Truth(self._world, 'comparison', str.__eq__(self, other)))
    def __ne__(self, other):
        return self._world.edge(self._token + '.ne',
            lambda: Truth(self._world, 'comparison', str.__ne__(self, other)))
    __hash__ = str.__hash__


class Map(Observed):
    _observed_names = frozenset({'get'})
    def __init__(self, world, name, values):
        super().__init__(world, name)
        self._values = values
    def __getitem__(self, key):
        return self._world.edge(self._token + '.getitem:' + str(key),
                                lambda: self._values[key])
    def __contains__(self, key):
        return self._world.edge(self._token + '.contains:' + str(key),
                                lambda: key in self._values)
    def get(self, key, default=None):
        return self._world.edge(self._token + '.get:' + str(key),
                                lambda: self._values.get(key, default))


class Iterable(Observed):
    def __init__(self, world, name, items):
        super().__init__(world, name)
        self._items, self._index, self._iterations = items, 0, 0
    def __iter__(self):
        def make():
            self._iterations += 1
            if self._world.case.get('one_shot_iterables'):
                return self
            return Iterator(self._world, self._token + '.iterator', self._items)
        return self._world.edge(self._token + '.iter', make)
    def __next__(self):
        def run():
            if self._index == len(self._items):
                raise StopIteration
            value = self._items[self._index]
            self._index += 1
            return value
        return self._world.edge(self._token + '.next', run)


class Iterator(Iterable):
    def __iter__(self):
        def run():
            if self._world.case.get('replacement_iterator') and not self._iterations:
                self._iterations += 1
                return Iterator(self._world, self._token + '.replacement', self._items)
            self._iterations += 1
            return self
        return self._world.edge(self._token + '.iter', run)


class Program(Observed):
    _observed_names = frozenset({'sha256', 'input_sha256', 'canonical_bytes', 'as_dict'})
    @property
    def sha256(self):
        return 'c' * 64
    @property
    def input_sha256(self):
        return 'd' * 64
    @property
    def canonical_bytes(self):
        return b'canonical-program'
    def as_dict(self):
        return self._world.edge(self._token + '.as_dict',
            lambda: Map(self._world, 'document', {'functions': self._world.functions()}))


class Image(Observed):
    _observed_names = frozenset({'text_bytes', 'sha256', 'function_frames', 'object_bytes'})
    @property
    def text_bytes(self):
        return b'text'
    @property
    def sha256(self):
        return 'e' * 64
    @property
    def function_frames(self):
        return [('f0', 16), ('f1', 32)]
    @property
    def object_bytes(self):
        return b'object-image'


class Digest(Observed):
    _observed_names = frozenset({'hexdigest'})
    def hexdigest(self):
        return self._world.edge(self._token + '.hexdigest', lambda: 'f' * 64)


class Store(Observed):
    _observed_names = frozenset({'get', 'get_json', 'put', 'json'})
    def get(self, reference):
        def result():
            if reference == 'patch':
                value = self._world.case.get('patch_bytes', 'patch')
            elif reference == 'base':
                value = 'base-core'
            else:
                value = self._world.case.get('source_bytes', 'assembly')
            return value.encode(), Map(self._world, 'metadata', {'kind': 'artifact'})
        return self._world.edge(self._token + '.get:' + str(reference), result)
    def get_json(self, reference):
        return self._world.edge(self._token + '.get_json:' + str(reference),
            lambda: (Map(self._world, 'patch', {'schema': self._world.scalar(
                self._world.case.get('patch_schema', 'patch.v1'), 'patch-schema')}),
                Map(self._world, 'metadata', {})))
    def put(self, data, kind, metadata=None):
        self._world.events.append({'operation': self._token + '.put.arguments',
            'data': snapshot(data), 'kind': snapshot(kind), 'metadata': snapshot(metadata)})
        return self._world.edge(self._token + '.put:' + kind,
            lambda: Map(self._world, 'stored-' + kind, {'kind': kind}))
    def json(self, data, kind):
        self._world.events.append({'operation': self._token + '.json.arguments',
            'data': snapshot(data), 'kind': snapshot(kind)})
        return self._world.edge(self._token + '.json:' + kind,
            lambda: Map(self._world, 'stored-' + kind, {'kind': kind}))


class Service(Observed):
    _observed_names = frozenset({'_program', '_context', 'store', 'profiles'})
    def __init__(self, world):
        super().__init__(world, 'service')
        self._stable_store = Store(world, 'store') if world.case.get('store_policy', 'stable') == 'stable' else None
    @property
    def store(self):
        if self._stable_store is not None:
            return self._stable_store
        return Store(self._world, 'store')
    @property
    def profiles(self):
        return Map(self._world, 'profiles', {'lowering': 'lowering.v1'})
    def _program(self, reference):
        return self._world.edge('service._program', lambda: self._world.program())
    def _context(self, reference):
        return self._world.edge('service._context', lambda: Map(self._world, 'context',
            {'foreign_buffer_exports': self._world.case.get('exports', [['f0', 2]])}))


class Environment:
    def __init__(self, world):
        self.world = world
    def get(self, name):
        return self.world.edge('environment.get:' + name,
            lambda: self.world.case.get('native_patch_selector'))


class Fixture:
    def __init__(self, case):
        self.case, self.world = case, World(case)
        w = self.world
        self.service = Service(w)
        if case['mode'] == 1:
            selector = Map(w, 'selector', dict(case.get('selector', {})))
            values = {'program': 'program', 'view': w.scalar(case.get('view', 'summary'), 'view'),
                      'context': 'context', 'selector': selector}
            if case.get('cursor'):
                values['cursor'] = 'cursor'
            if case.get('selector_absent'):
                del values['selector']
        else:
            values = {'context': 'context', 'change': Map(w, 'change', {
                'kind': w.scalar(case.get('kind', 'import'), 'kind'),
                'source': 'source', 'format': w.scalar(case.get('format', 'hia-asm.v1'), 'format'),
                'base_program': 'base', 'patch': 'patch', 'patch_schema': 'patch.v1'})}
        self.arguments = Map(w, 'arguments', values)
        self.namespace = {'__name__': 'hepta.hia_agent_service', '__package__': 'hepta',
            '__builtins__': vars(builtins), 'reject': w.reject,
            'sha256': w.provider('sha256', lambda value: Digest(w, 'digest')),
            'os': types.SimpleNamespace(environ=Environment(w)),
            'verify_program': w.provider('verify_program', lambda value: w.program('verified')),
            'decode_json': w.provider('decode_json', lambda value: Map(w, 'decoded', {}))}
        if case.get('all') is not None:
            self.namespace['all'] = w.all_foreign
        for name in case.get('tracked_globals', []):
            self.namespace[name] = w.provider('global.' + name, getattr(builtins, name))
        for key in case.get('remove_arguments', []):
            self.arguments._values.pop(key, None)
        for key in case.get('missing_globals', []):
            self.namespace.pop(key, None)
        self.world.namespace = self.namespace
        self.modules = {
            'hia_program_tools': {
                'inspect_program': w.provider('inspect_program', lambda program: Map(w, 'summary', {})),
                'apply_program_patch': w.provider('apply_program_patch',
                    lambda program, patch: (w.program('patched'), w.diagnostics()))},
            'hia_edit_query': {'prepare_edit': w.provider('prepare_edit',
                lambda program, **kwargs: Map(w, 'prepared', {'query': 'q'}))},
            'hia_program_native': {'emit_program_machine': w.provider('emit_program_machine',
                lambda program, **kwargs: w.image())},
            'hia_agent_assembly': {'assemble_program': w.provider('assemble_program',
                lambda data: w.program('assembled'))},
            'hia_agent_candidate_native': {'apply_candidate_patch': w.provider('apply_candidate_patch',
                lambda *args: (None if case.get('native_patch_returns_none') else
                    (b'native-core', b'native-diagnostics')))},
            'hia_agent_service': {},
        }

    @contextmanager
    def providers(self):
        previous = {}
        package = types.ModuleType('hepta')
        package.__path__ = []
        replacements = {'hepta': package}
        for name, values in self.modules.items():
            full = 'hepta.' + name
            module = types.ModuleType(full)
            module.__dict__.update(values)
            replacements[full] = module
        try:
            for name, module in replacements.items():
                previous[name] = sys.modules.get(name, MISSING)
                sys.modules[name] = module
            yield
        finally:
            for name in reversed(tuple(replacements)):
                if previous[name] is MISSING:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = previous[name]

    def original(self):
        name, wanted = ORIGINALS[self.case['mode']]
        raw = (DIRECTORY / name).read_bytes()
        if sha256(raw).hexdigest() != wanted:
            raise ValueError('complete original handler identity differs')
        namespace = dict(self.namespace)
        exec(compile('class Original:\n' + raw.decode(), '<frozen-' + name + '>', 'exec'), namespace)
        method = getattr(namespace['Original'],
                         '_hia_inspect' if self.case['mode'] == 1 else '_hia_candidate')
        # Provider rebinding acts on the actual captured namespace, not a copy.
        self.namespace = self.world.namespace = namespace
        return method


def observe_case(case, owner=None):
    """owner(mode, service, arguments, namespace, original_code) is optional.

No invocation happens at import. owner=None executes only the pinned original;
a future candidate comparison must explicitly supply a separately admitted
owner and preserve this same fixture, raw observations and runtime identity.
    """
    fixture = Fixture(case)
    world = fixture.world
    method = fixture.original()
    result = error = None
    raw_traceback = None
    outer = RuntimeError('outer-active-exception') if case.get('outer') else None
    def invoke():
        if owner is None:
            return method(fixture.service, fixture.arguments)
        return owner(case['mode'], fixture.service, fixture.arguments,
                     fixture.namespace, method.__code__)
    with fixture.providers():
        try:
            if outer is not None:
                try:
                    raise outer
                except RuntimeError:
                    result = invoke()
            else:
                result = invoke()
        except BaseException as caught:
            error = caught
            raw_traceback = ''.join(traceback.format_exception(type(error), error, error.__traceback__))
    body_end = len(world.events)
    result_view, error_view = snapshot(result), error_snapshot(error, world.fault)
    if error_view is not None:
        error_view['context_is_outer'] = error.__context__ is outer
    owner_live = sorted(object.__getattribute__(item, '_token')
                        for ref in world.weak_objects if (item := ref()) is not None)
    item = None
    world.events.append({'operation': 'observer.consumer_release.begin'})
    if error is not None:
        traceback.clear_frames(error.__traceback__)
        error.__traceback__ = None
    if world.fault is not None:
        traceback.clear_frames(world.fault.__traceback__)
        world.fault.__traceback__ = None
    result = error = outer = None
    world.escaped.clear()
    consumer_end = len(world.events)
    observation = {'case_id': case['id'], 'mode': case['mode'],
        'result': result_view, 'error': error_view, 'trace': world.events,
        'body_trace_end': body_end, 'consumer_release_trace_end': consumer_end,
        'objects_live_at_body_return': owner_live, 'fault_hits': world.fault_hits,
        'fault_required': case.get('fault') is not None,
        'fresh_original_function_code': True,
        'fixture_keeps_service_and_arguments_through_consumer': True,
        'actual_SQL_or_filesystem_or_compiler_provider_called': False}
    return observation, raw_traceback
