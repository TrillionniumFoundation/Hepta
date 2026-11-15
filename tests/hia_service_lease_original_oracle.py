"""Independent original-only observations for the four frozen service lease bodies.

This module does not import any product owner. A candidate factory is supplied
only by a separate child after its own input admission. Events and weakrefs do
not retain temporary receivers/callables/results. Explicit GC is an input
observation, never a cleanup or normalization operation.
"""
from __future__ import annotations
import ast
import builtins
import gc
import hashlib
import json
from pathlib import Path
import sys
import types
import weakref

FIXTURE = Path(__file__).with_name('fixtures') / 'hia_service_lease_original_r3'
METHODS = {1: 'acquire_slot', 2: '_lease', 3: 'invoke_lease', 4: 'release_slot'}
EXPECTED_ORIGINALS = {
    'acquire_slot': 'f6ffec9de3bbadb39a207bed2ff865cc3f528d7191a305150040487a4e98f620',
    '_lease': '83f904f65495c4008cd23a9c4338d4e7aea7b8a5c7f81623f9c58144d696d0a2',
    'invoke_lease': 'f0ac06c94df677a31d88bb6eea22e19039faba5b331e1a2ea030e0161e638c4b',
    'release_slot': '28d3c4088f25b507e80ff6bdf7f0fb6728ac8e7a8ca87dd3e96b2a24f6830c56',
}
_CODES = {}
for _name, _digest in EXPECTED_ORIGINALS.items():
    _raw = (FIXTURE / (_name + '.py.txt')).read_bytes()
    if hashlib.sha256(_raw).hexdigest() != _digest:
        raise RuntimeError('original lease method bytes differ: ' + _name)
    _text = '\n'.join(line[4:] if line.startswith('    ') else line
                      for line in _raw.decode().splitlines()) + '\n'
    _scope = {}
    exec(compile(_text, str(FIXTURE / (_name + '.py.txt')), 'exec'), _scope)
    _CODES[_name] = _scope[_name].__code__
del _name, _digest, _raw, _text, _scope


def canonical(value):
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':')) + '\n').encode()


def original_factory(mode, namespace):
    return types.FunctionType(_CODES[METHODS[mode]], namespace)


def _primitive(value):
    if type(value) in (type(None), bool, int, float, str):
        return value
    if type(value) is bytes:
        return {'bytes': value.hex()}
    if isinstance(value, Token):
        return {'token': value.tag}
    if isinstance(value, dict):
        return {str(k): _primitive(v) for k, v in dict.items(value)}
    if isinstance(value, (tuple, list)):
        return [_primitive(v) for v in value]
    if isinstance(value, Provider):
        return {'provider': value.kind}
    return {'type': type(value).__module__ + '.' + type(value).__qualname__}


def _error(error, world, depth=0):
    if error is None:
        return None
    if depth > 8:
        return {'cycle_or_depth': True}
    result = {'type': type(error).__module__ + '.' + type(error).__qualname__,
              'args': _primitive(error.args),
              'name': _primitive(getattr(error, 'name', None)),
              'obj': world.tag(getattr(error, 'obj', None)),
              'suppress_context': error.__suppress_context__,
              'is_requested_fault': error is world.fault_error}
    result['cause'] = _error(error.__cause__, world, depth + 1)
    result['context'] = _error(error.__context__, world, depth + 1)
    return result


class OracleFixtureError(RuntimeError):
    pass


class Namespace:
    __slots__ = ('value', '__weakref__')
    def __init__(self, value):
        self.value = value


class World:
    def __init__(self, case):
        self.case = case
        self.events = []
        self.counts = {}
        self.refs = {}
        self.labels = {}
        self.fault_hits = 0
        self.fault_error = None
        self.namespace = None
        self.next_serial = {}

    def active(self):
        error = sys.exception()
        if error is None:
            return None
        return 'fault' if error is self.fault_error else ('outer' if isinstance(error, KeyError)
                                                        and error.args == ('outer',) else type(error).__name__)

    def tag(self, value):
        if value is None:
            return None
        return self.labels.get(id(value), _primitive(value))

    def watch(self, value, label):
        count = self.next_serial.get(label, 0) + 1
        self.next_serial[label] = count
        name = label + '#' + str(count)
        self.refs[name] = weakref.ref(value)
        self.labels[id(value)] = name
        return value

    def event(self, name, *values):
        count = self.counts.get(name, 0) + 1
        self.counts[name] = count
        self.events.append({'event': name, 'n': count, 'args': _primitive(values), 'active': self.active()})
        fault = self.case.get('fault')
        if fault and fault['event'] == name and fault.get('occurrence', 1) == count:
            self.fault_hits += 1
            family = fault.get('family', 'RuntimeError')
            error_type = getattr(builtins, family)
            self.fault_error = error_type('injected:' + name)
            raise self.fault_error

    def deleted(self, name):
        self.events.append({'event': name + '.delete', 'active': self.active()})

    def global_type(self, value):
        self.event('global.type.call', value)
        if self.case.get('mutate_snapshot_callees') and self.counts['global.type.call'] == 2:
            namespace = self.namespace()
            namespace.value['wire'] = self.forbidden_wire
            namespace.value['decode_data'] = self.forbidden_decode
        return type(value)

    def global_list(self, value):
        self.event('global.list.call', value)
        return list(value)

    def wire(self, value):
        self.event('global.wire.call', value)
        return json.dumps(_primitive(value), ensure_ascii=True).encode()

    def decode(self, value):
        self.event('global.decode.call', value)
        return json.loads(value)

    def forbidden_wire(self, value):
        self.event('forbidden.wire.call')
        raise OracleFixtureError('original captured wire callee was lost')

    def forbidden_decode(self, value):
        self.event('forbidden.decode.call')
        raise OracleFixtureError('original captured decoder callee was lost')

    def uint64(self, value, label):
        self.event('global.uint64.call', value, label)
        return value

    def reject(self, *args):
        self.event('global.reject.call', *args)
        if not self.case.get('reject_returns'):
            raise ValueError(*args)

    def import_module(self, name, globals=None, locals=None, fromlist=(), level=0):
        self.event('import.' + name, list(fromlist), level)
        if (name, tuple(fromlist), level) not in (
                ('hia_agent_runner', ('run_native_batch',), 1),
                ('hia_agent_buffers', ('validate_arguments',), 1)):
            raise OracleFixtureError('unexpected original import')
        return Imported(self, name)


class Token:
    __slots__ = ('world', 'tag', 'truth', '__weakref__')
    def __init__(self, world, tag, truth=True):
        self.world, self.tag, self.truth = world, tag, truth
        world.watch(self, tag)
    def __bool__(self):
        self.world.event(self.tag + '.bool')
        if self.tag == 'exit-result' and self.world.case.get('exit_truth_error'):
            raise LookupError('exit truth failed')
        return self.truth
    def __del__(self):
        self.world.deleted(self.tag)


class Map(dict):
    def __init__(self, world, tag, value):
        dict.__init__(self, value)
        self.world, self.tag = world, tag
        world.watch(self, tag)
    def __getitem__(self, key):
        self.world.event(self.tag + '.getitem', key)
        return dict.__getitem__(self, key)
    def get(self, key, default=None):
        self.world.event(self.tag + '.get', key, default)
        return dict.get(self, key, default)
    def pop(self, key, *default):
        self.world.event(self.tag + '.pop', key, *default)
        return dict.pop(self, key, *default)
    def keys(self):
        self.world.event(self.tag + '.keys')
        return dict.keys(self)
    def __iter__(self):
        self.world.event(self.tag + '.iter')
        return dict.__iter__(self)
    def __del__(self):
        self.world.deleted(self.tag)


class Imported:
    __slots__ = ('world', 'name')
    def __init__(self, world, name):
        self.world, self.name = world, name
    def __getattribute__(self, name):
        if name in ('run_native_batch', 'validate_arguments'):
            world = object.__getattribute__(self, 'world')
            world.event('imported.' + name + '.get')
            return Provider(world, name)
        return object.__getattribute__(self, name)


class Special:
    __slots__ = ('kind',)
    def __init__(self, kind):
        self.kind = kind
    def __get__(self, instance, owner):
        world = instance.world
        world.event('manager.' + self.kind + '.lookup')
        return Provider(world, self.kind)


class Manager:
    __slots__ = ('world', '__weakref__')
    __enter__ = Special('enter')
    __exit__ = Special('exit')
    def __init__(self, world):
        self.world = world
        world.watch(self, 'manager')
    def __del__(self):
        self.world.deleted('manager')


class MissingEnter:
    __slots__ = ('world', '__weakref__')
    __exit__ = Special('exit')
    def __init__(self, world):
        self.world = world
        world.watch(self, 'manager')
    def __del__(self):
        self.world.deleted('manager')


class MissingExit:
    __slots__ = ('world', '__weakref__')
    __enter__ = Special('enter')
    def __init__(self, world):
        self.world = world
        world.watch(self, 'manager')
    def __del__(self):
        self.world.deleted('manager')


class Store:
    __slots__ = ('world', '__weakref__')
    def __init__(self, world):
        self.world = world
        world.watch(self, 'store')
    def __getattribute__(self, name):
        if name in ('transaction', 'put'):
            world = object.__getattribute__(self, 'world')
            world.event('store.' + name + '.get')
            return Provider(world, name)
        return object.__getattribute__(self, name)
    def __del__(self):
        self.world.deleted('store')


class Ledger:
    __slots__ = ('world', '__weakref__')
    def __init__(self, world):
        self.world = world
        world.watch(self, 'ledger')
    def __getattribute__(self, name):
        if name in ('acquire', 'lease', 'release'):
            world = object.__getattribute__(self, 'world')
            world.event('ledger.' + name + '.get')
            return Provider(world, 'ledger.' + name)
        return object.__getattribute__(self, name)
    def __del__(self):
        self.world.deleted('ledger')


class Subject:
    __slots__ = ('world', '_values', '__weakref__')
    def __init__(self, world):
        self.world = world
        self._values = {}
        if not world.case.get('temporary_store'):
            self._values['store'] = Store(world)
        if world.case.get('ledger', True):
            self._values['ledger'] = Ledger(world)
        world.watch(self, 'service')
    def __getattribute__(self, name):
        if name in ('store', '_slot_ledger', '_slot_snapshot', '_native', '_context', '_lease',
                    '_reference_slot_acquire', '_reference_slot_lease', '_reference_slot_release'):
            world = object.__getattribute__(self, 'world')
            world.event('service.' + name + '.get')
            values = object.__getattribute__(self, '_values')
            if name == 'store':
                return Store(world) if world.case.get('temporary_store') else values['store']
            if name == '_slot_ledger':
                if world.case.get('ledger_disappears') and world.counts['service._slot_ledger.get'] == 2:
                    return None
                return values.get('ledger')
            return Provider(world, name)
        return object.__getattribute__(self, name)
    def __del__(self):
        self.world.deleted('service')


def _lease_value(world):
    return Map(world, 'retained-lease', {'id': 'lease-0', 'slot': 'slot-0',
        'generation': 7, 'artifact': {'id': 'artifact-0'}})


class Provider:
    __slots__ = ('world', 'kind', '__weakref__')
    def __init__(self, world, kind):
        self.world, self.kind = world, kind
        world.watch(self, 'callable.' + kind)
    def __del__(self):
        self.world.deleted('callable.' + self.kind)
    def __call__(self, *args, **kwargs):
        w, kind = self.world, self.kind
        w.event(kind + '.call', args, kwargs)
        if kind == 'transaction':
            cls = {'missing_enter': MissingEnter, 'missing_exit': MissingExit}.get(w.case.get('manager'), Manager)
            return cls(w)
        if kind == 'enter':
            return Token(w, 'enter-result')
        if kind == 'exit':
            if w.case.get('exit_raise'):
                raise LookupError('exit failed')
            if w.case.get('exit_reraise'):
                raise
            return Token(w, 'exit-result', bool(w.case.get('suppress', False)))
        if kind in ('ledger.acquire', '_reference_slot_acquire'):
            if kind == 'ledger.acquire' and w.case.get('ledger_callback'):
                args[2]({'id': 'artifact-0'})
            return _lease_value(w)
        if kind in ('ledger.lease', '_reference_slot_lease', '_lease'):
            return _lease_value(w)
        if kind in ('ledger.release', '_reference_slot_release'):
            return Map(w, 'released', {'released': True, 'generation': 7, 'artifact_retained': True})
        if kind == '_slot_snapshot':
            return {'active_artifact': {'id': 'artifact-0'}}
        if kind == '_native':
            signature = None if w.case.get('missing_signature') else Map(w, 'signature', {'abi': w.case.get('abi', True)})
            signatures = Map(w, 'signatures', {'f': signature})
            metadata = Map(w, 'metadata', {'output_kind': w.case.get('output_kind', 'shared'),
                'signatures': signatures, 'context': {'id': 'context-0'}})
            return Token(w, 'data'), metadata, Token(w, 'program')
        if kind == 'validate_arguments':
            return Token(w, 'validate-result')
        if kind == '_context':
            return Map(w, 'context', {'budget': Map(w, 'budget', {'max_native_wall_ms': 123,
                                                               'max_memory_bytes': 456})})
        if kind == 'run_native_batch':
            captured = [Map(w, 'captured-' + str(i), {'data': Token(w, 'buffer-data-' + str(i)),
                         'argument': i, 'label': 'buffer-' + str(i)}) for i in range(w.case.get('buffers', 0))]
            observation = Map(w, 'observation', {'status': w.case.get('observation_status', 'returned'),
                                                'values': [4, 9]})
            return Map(w, 'result', {'status': w.case.get('status', 'returned'),
                'report': Map(w, 'report', {'observations': [observation]}),
                'captured_buffers': captured, 'termination_confirmed': w.case.get('terminated', True)})
        if kind == 'put':
            return Token(w, 'issued-reference')
        raise OracleFixtureError('unknown fake provider: ' + kind)


def _call(mode, call, world, retained):
    try:
        if mode == 1:
            result = call.pop('function')(call.pop('self'), call.pop('target_slot'))
        elif mode == 2 or mode == 4:
            result = call.pop('function')(call.pop('self'), call.pop('lease'))
        else:
            result = call.pop('function')(call.pop('self'), call.pop('lease'),
                                         call.pop('name'), call.pop('arguments'))
        value = _primitive(result)
        del result
        return {'kind': 'returned', 'value': value}
    except BaseException as error:
        value = _error(error, world)
        if world.case.get('retain_traceback'):
            retained.append(error)
        return {'kind': 'raised', 'error': value}


def observe(case, factory=original_factory):
    world = World(case)
    builtins_map = dict(vars(builtins))
    builtins_map['__import__'] = world.import_module
    namespace = Namespace({'__name__': 'hepta.hia_agent_service', '__package__': 'hepta',
        '__builtins__': builtins_map, 'type': world.global_type, 'str': str, 'tuple': tuple,
        'list': world.global_list, 'wire': world.wire, 'decode_data': world.decode,
        'reject': world.reject, 'uint64': world.uint64})
    world.namespace = weakref.ref(namespace)
    mode = case['mode']
    call = {'function': factory(mode, namespace.value), 'self': Subject(world)}
    if mode == 1:
        call['target_slot'] = 'slot-0'
    else:
        call['lease'] = Map(world, 'caller-lease', {'id': 'lease-0', 'slot': 'slot-0',
                                                  'generation': 7, 'artifact': {'id': 'artifact-0'}})
    if mode == 3:
        call['name'] = 17 if case.get('non_string_function') else 'f'
        items = [1, {'kind': 'buffer', 'bytes': [1, 2, 3]}]
        call['arguments'] = tuple(items) if case.get('tuple_arguments', True) else items
        del items
    retained = []
    if case.get('outer'):
        try:
            raise KeyError('outer')
        except KeyError:
            outcome = _call(mode, call, world, retained)
            world.event('observer.after-call')
            world.event('observer.before-retained-release')
            retained.clear()
            world.fault_error = None
            world.event('observer.after-retained-release')
    else:
        outcome = _call(mode, call, world, retained)
        world.event('observer.after-call')
        world.event('observer.before-retained-release')
        retained.clear()
        world.fault_error = None
        world.event('observer.after-retained-release')
    expected_hits = 1 if case.get('fault') else 0
    if world.fault_hits != expected_hits:
        raise OracleFixtureError('fault did not reach its single declared event: ' + case['id'])
    collected = None
    before = {name: ref() is not None for name, ref in sorted(world.refs.items())}
    if case.get('explicit_gc'):
        world.event('observer.gc.before')
        collected = gc.collect()
        world.event('observer.gc.after', collected)
    after = {name: ref() is not None for name, ref in sorted(world.refs.items())}
    record = {'id': case['id'], 'mode': mode, 'outcome': outcome,
              'events': world.events, 'fault_hits': world.fault_hits,
              'alive_before_explicit_gc': before, 'alive_after_explicit_gc': after,
              'explicit_gc_collected': collected}
    # Seal primitive bytes now. No later finalizer can rewrite this observation.
    return json.loads(canonical(record))


def cases():
    path = FIXTURE / 'cases.json'
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != '3069ee6e015e2c9bdb0d66fac5bf53ce393a192df69bc9ce28068460edf62f47':
        raise OracleFixtureError('frozen lease input manifest bytes differ')
    value = json.loads(raw)
    if type(value) is not list or len({case['id'] for case in value}) != len(value):
        raise OracleFixtureError('case manifest is not a unique complete list')
    return value
