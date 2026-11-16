"""Independent exact-body oracle. Importing this file runs no original.

Only the four frozen original definitions are compiled for the original lane.
No product module, HIA graph, expected-value generator or real filesystem
provider is imported here. The observer owns injected/outer exception identity;
natural errors retain every serialized field and their raw traceback separately.
"""
from __future__ import annotations
import ast
import gc
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import sys
import traceback
import weakref

HERE = Path(__file__).resolve().parent
ORIGINALS = HERE / 'fixtures/hia_store_file_capture_original_65630'
PINNED = {
    'AgentRejected': '30dc9ad1340152ba28445b2138a354eeaf1f0f6edafb94573c45914665acf21b',
    'reject': '5bc1a0a02aa8057d238a45db3b612d8efd573ecb02be4a017927a19bacca02a6',
    'stable_read': '56f8419c2343b5f6339fde0b42f92866e1c9d60b1cbe32bd24c54cda9ee40dfa',
    'capture_path': '67f6ce67d4ba5cb8619be15a5aeeb6dbbf4214c2c04a5300411b8e6ad0a1cdea',
}
ERRORS = {x.__name__: x for x in (OSError, ValueError, AttributeError, RuntimeError,
          KeyboardInterrupt, SystemExit, MemoryError, StopIteration, GeneratorExit)}
_CODE = None

def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':')).encode()

def original_namespace():
    global _CODE
    pieces = []
    for name, digest in PINNED.items():
        raw = (ORIGINALS / (name + '.py.txt')).read_bytes()
        if sha256(raw).hexdigest() != digest:
            raise ValueError('original source changed: ' + name)
        pieces.append(raw)
    raw = b'\n'.join(pieces)
    if _CODE is None:
        _CODE = compile(raw, str(ORIGINALS / 'exact-originals.py'), 'exec')
    namespace = {'__builtins__': __builtins__, '__name__': 'hepta.hia_agent_store'}
    exec(_CODE, namespace)
    return namespace

def role(value):
    if value is None or type(value) in (bool, int, str):
        return value
    if type(value) is bytes:
        return {'bytes': value.hex()}
    if isinstance(value, Token):
        return object.__getattribute__(value, 'token')
    if type(value) in (list, tuple):
        return [role(x) for x in value]
    return {'type': type(value).__module__ + '.' + type(value).__qualname__}

def error_fields(error, world, seen=None):
    if error is None:
        return None
    if seen is None:
        seen = set()
    if id(error) in seen:
        return {'cycle_to_live_exception': True}
    seen.add(id(error))
    value = {'type': type(error).__module__ + '.' + type(error).__qualname__,
             'args': role(error.args), 'text': str(error),
             'same_injected': error is world.fault, 'same_outer': error is world.outer,
             'suppress_context': error.__suppress_context__,
             'name': role(getattr(error, 'name', None)),
             'obj': role(getattr(error, 'obj', None)),
             'code': role(getattr(error, 'code', None)),
             'phase': role(getattr(error, 'phase', None)),
             'retry_action': role(getattr(error, 'retry_action', None))}
    value['cause'] = error_fields(error.__cause__, world, seen)
    value['context'] = error_fields(error.__context__, world, seen)
    return value

class Token:
    def __init__(self, world, kind):
        self.world = weakref.ref(world)
        self.token = world.new_token(kind, self)
    def __del__(self):
        world = self.world()
        if world is not None:
            world.record('delete', self.token)

class Limit(Token):
    def __init__(self, world):
        super().__init__(world, 'limit')
        self.value = world.case.get('limit', 4)
    def __lt__(self, other):
        world = self.world()
        world.hit('limit.compare.before')
        result = Truth(world, other > self.value)
        world.hit('limit.compare.after')
        return result
    def __add__(self, other):
        world = self.world()
        world.hit('limit.add.before')
        result = self.value + other
        world.hit('limit.add.after')
        return result

class Truth(Token):
    def __init__(self, world, value, *, fail=False):
        super().__init__(world, 'truth')
        self.value, self.fail = value, fail
    def __bool__(self):
        world = self.world()
        world.hit('truth.before')
        if self.fail:
            raise ValueError('exit truth refused')
        world.hit('truth.after')
        return self.value

class Data(Token):
    def __len__(self):
        world = self.world()
        world.hit('data.len.before')
        value = world.case.get('data_length', world.case.get('size', 4))
        world.hit('data.len.after')
        return value

class Stat(Token):
    FIELDS = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_mode')
    def __init__(self, world, when):
        super().__init__(world, 'stat.' + when)
        self.when = when
    def __getattribute__(self, name):
        if name not in Stat.FIELDS:
            return object.__getattribute__(self, name)
        world = object.__getattribute__(self, 'world')()
        when = object.__getattribute__(self, 'when')
        world.hit('stat.' + when + '.' + name + '.before')
        values = {'st_dev': 1, 'st_ino': 7, 'st_size': world.case.get('size', 4),
                  'st_mtime_ns': 123456789, 'st_ctime_ns': 123456799,
                  'st_mode': stat.S_IFREG if world.case.get('regular', True) else stat.S_IFIFO}
        value = values[name]
        if when == 'after' and world.case.get('changed') == name:
            value += 1
        world.hit('stat.' + when + '.' + name + '.after')
        return value

class Stream(Token):
    def __init__(self, world, fd):
        super().__init__(world, 'stream')
        self.fd = fd
    def fileno(self):
        world = self.world()
        world.hit('stream.fileno.before')
        value = self.fd
        world.hit('stream.fileno.after')
        return value
    def read(self, count):
        world = self.world()
        world.hit('stream.read.before', count)
        value = Data(world, 'data')
        world.hit('stream.read.after')
        return value

class Special:
    def __init__(self, name):
        self.name = name
    def __get__(self, manager, owner):
        world = manager.world()
        world.hit('special.' + self.name + '.lookup.before')
        value = Binding(world, manager, self.name)
        world.hit('special.' + self.name + '.lookup.after')
        return value

class Binding(Token):
    def __init__(self, world, manager, name):
        super().__init__(world, 'binding.' + name)
        self.manager = None if world.case.get('manager') == 'detached' else manager
        self.fd, self.name = manager.fd, name
    def __call__(self, *args):
        world = self.world()
        world.hit('special.' + self.name + '.call.before', role(args))
        if self.name == 'enter':
            value = Stream(world, self.fd)
        else:
            world.closed_streams.append(self.fd)
            world.record('stream.closed', self.fd)
            value = Truth(world, world.case.get('manager') == 'suppress',
                          fail=world.case.get('manager') == 'truth_raises')
        world.hit('special.' + self.name + '.call.after')
        return value

class Manager(Token):
    __enter__, __exit__ = Special('enter'), Special('exit')
    def __init__(self, world, fd):
        super().__init__(world, 'manager')
        self.fd = fd

class MissingEnter(Token):
    __exit__ = Special('exit')
    def __init__(self, world, fd):
        super().__init__(world, 'manager')
        self.fd = fd

class MissingExit(Token):
    __enter__ = Special('enter')
    def __init__(self, world, fd):
        super().__init__(world, 'manager')
        self.fd = fd

class MissingBoth(Token):
    def __init__(self, world, fd):
        super().__init__(world, 'manager')
        self.fd = fd

class Root(Token):
    def __init__(self, world, value):
        super().__init__(world, 'root')
        self.value = value

class Roots(Token):
    def __iter__(self):
        world = self.world()
        world.hit('roots.iter.before')
        value = RootIterator(world)
        world.hit('roots.iter.after')
        return value

class RootIterator(Token):
    def __init__(self, world):
        super().__init__(world, 'roots.iterator')
        self.index = 0
    def __iter__(self):
        return self
    def __next__(self):
        world = self.world()
        world.hit('roots.next.before')
        values = world.case.get('roots', ['/allowed'])
        if self.index == len(values):
            raise StopIteration
        value = Root(world, values[self.index])
        self.index += 1
        world.hit('roots.next.after')
        return value

class Relative(Token):
    def __init__(self, world, parts):
        super().__init__(world, 'relative')
        self._parts, self.reads = parts, 0
    @property
    def parts(self):
        world = self.world()
        world.hit('relative.parts.before')
        self.reads += 1
        value = tuple(world.case.get('second_parts', self._parts) if self.reads > 1 else self._parts)
        world.hit('relative.parts.after')
        return value

class Lexical(Token):
    def __init__(self, world, value):
        super().__init__(world, 'path')
        self.value = value
    @property
    def parts(self):
        world = self.world()
        world.hit('path.parts.before')
        # Keep explicit dot components for this fake Path protocol. The real
        # pathlib normalization is separately exercised by the real OS gate.
        value = ('/',) + tuple(x for x in self.value.split('/') if x)
        world.hit('path.parts.after')
        return value
    def relative_to(self, root):
        world = self.world()
        world.hit('path.relative.before', role(root))
        prefix = root.value
        if self.value != prefix and not self.value.startswith(prefix.rstrip('/') + '/'):
            raise ValueError('not below this root')
        parts = world.case.get('relative_parts',
                    [x for x in self.value[len(prefix):].split('/') if x])
        value = Relative(world, parts)
        world.hit('path.relative.after')
        return value

class PathFacade:
    def __init__(self, world):
        self.world = weakref.ref(world)
    def __call__(self, path):
        world = self.world()
        world.hit('Path.call.before', role(path))
        value = Lexical(world, path)
        world.hit('Path.call.after')
        return value

class PathOS:
    def __init__(self, world):
        self.world = weakref.ref(world)
    def isabs(self, path):
        world = self.world()
        world.hit('os.path.isabs.before', role(path))
        value = path.startswith('/')
        world.hit('os.path.isabs.after')
        return value

class OS:
    O_RDONLY, O_CLOEXEC, O_NOFOLLOW, O_NONBLOCK, O_DIRECTORY = 0, 0x80000, 0x20000, 0x800, 0x10000
    WATCHED = frozenset(('open', 'fdopen', 'fstat', 'close', 'path',
                         'O_RDONLY', 'O_CLOEXEC', 'O_NOFOLLOW', 'O_NONBLOCK', 'O_DIRECTORY'))
    def __init__(self, world):
        self.world = weakref.ref(world)
        self.path = PathOS(world)
    def __getattribute__(self, name):
        if name not in OS.WATCHED:
            return object.__getattribute__(self, name)
        world = object.__getattribute__(self, 'world')()
        world.hit('os.lookup.' + name + '.before')
        value = object.__getattribute__(self, name)
        world.hit('os.lookup.' + name + '.after')
        return value
    def open(self, path, flags, *, dir_fd=None):
        world = self.world()
        world.hit('os.open.before', [role(path), flags, dir_fd])
        world.next_fd += 1
        value = world.next_fd
        world.opened.append([value, role(path), flags, dir_fd])
        world.hit('os.open.after', value)
        return value
    def fdopen(self, fd, mode):
        world = self.world()
        world.hit('os.fdopen.before', [fd, mode])
        cls = {'missing_enter': MissingEnter, 'missing_exit': MissingExit,
               'missing_both': MissingBoth}.get(world.case.get('manager'), Manager)
        value = cls(world, fd)
        world.hit('os.fdopen.after')
        return value
    def fstat(self, fd):
        world = self.world()
        world.hit('os.fstat.before', fd)
        world.stat_calls += 1
        value = Stat(world, 'before' if world.stat_calls % 2 else 'after')
        world.hit('os.fstat.after')
        return value
    def close(self, fd):
        world = self.world()
        world.hit('os.close.before', fd)
        world.closed.append(fd)
        world.hit('os.close.after', fd)

class World:
    def __init__(self, case):
        self.case = case
        self.phase, self.events, self.hits = 'call', [], []
        self.tokens, self.sequence = {}, 0
        self.opened, self.closed, self.closed_streams = [], [], []
        self.next_fd, self.stat_calls = 100, 0
        self.outer = RuntimeError('declared outer')
        family = case.get('fault', {}).get('family', 'OSError')
        self.fault = ERRORS[family]('frozen fault')
        self.fired = False
        # A post-error target retains the original basis OSError as a distinct
        # prerequisite. The target family's exception must still fire later.
        self.prerequisite = (OSError('frozen fault')
                             if case.get('fault') and case.get('base_fault') else None)
        self.prerequisite_fired = False
        self.prerequisite_hit = None
    def active(self):
        # No persistent id-to-label table; only known live anchors use identity.
        if sys.exception() is None:
            return None
        if sys.exception() is self.fault:
            return 'injected'
        if sys.exception() is self.prerequisite:
            return 'prerequisite'
        if sys.exception() is self.outer:
            return 'outer'
        return type(sys.exception()).__module__ + '.' + type(sys.exception()).__qualname__
    def record(self, name, value=None):
        self.events.append([name, role(value), self.phase, self.active()])
    def new_token(self, name, value):
        self.sequence += 1
        token = name + '#' + str(self.sequence)
        self.tokens[token] = weakref.ref(value)
        self.record('create', token)
        return token
    def hit(self, label, value=None):
        index = len(self.hits)
        self.hits.append({'index': index, 'label': label})
        self.record(label, value)
        fault = self.case.get('fault')
        fire = bool(fault is not None and index == fault['index'])
        if fire and label != fault['label']:
            raise AssertionError('declared original fault cutpoint differs')
        if not self.fired and fire:
            self.fired = True
            raise self.fault
        if label == self.case.get('base_fault'):
            if self.prerequisite is not None:
                if not self.prerequisite_fired:
                    self.prerequisite_fired = True
                    self.prerequisite_hit = index
                    raise self.prerequisite
            elif not self.fired:
                self.fired = True
                raise self.fault
    def alive(self):
        return [key for key, value in self.tokens.items() if value() is not None]
    def install(self, namespace):
        namespace.update(os=OS(self), stat=stat, Path=PathFacade(self))
        matching = self.case.get('matching')
        namespace['OSError'] = ((OSError, ValueError) if matching == 'tuple' else 7 if matching == 'invalid'
                                else (OSError, 7) if matching == 'invalid_tuple' else OSError)
        if self.case.get('reject_returns'):
            namespace['reject'] = self.reject_returns
        if self.case.get('read_override'):
            namespace['stable_read'] = self.read_override
    def reject_returns(self, *args, **kwargs):
        self.hit('reject.override.before', role(args))
        self.hit('reject.override.after')
    def read_override(self, path, limit, *, dir_fd=None):
        self.hit('stable.override.before', [role(path), role(limit), dir_fd])
        value = None if self.case['read_override'] == 'none' else Data(self, 'override.data')
        self.hit('stable.override.after')
        return value
    def arguments(self):
        path = self.case.get('path', '/allowed/payload')
        if self.case.get('path_kind') == 'object':
            path = Token(self, 'input.path')
        limit = Limit(self) if self.case.get('opaque_limit') else self.case.get('limit', 4)
        if self.case['mode'] == 'stable':
            return {'path': path, 'limit': limit, 'dir_fd': self.case.get('dir_fd')}
        return {'path': path, 'roots': Roots(self, 'roots'), 'limit': limit}

def observe(case, *, factory=None):
    world = World(case)
    namespace = original_namespace()
    world.install(namespace)
    provider = namespace['stable_read' if case['mode'] == 'stable' else 'capture_path']
    if factory is not None:
        provider = factory(namespace, case['mode'])
    arguments = world.arguments()
    retained, raw_tracebacks = [], []
    outcome = None
    value = None
    def invoke():
        nonlocal value, outcome
        try:
            if case['mode'] == 'stable':
                value = provider(arguments.pop('path'), arguments.pop('limit'),
                                 dir_fd=arguments.pop('dir_fd'))
            else:
                value = provider(arguments.pop('path'), arguments.pop('roots'),
                                 arguments.pop('limit'))
        except BaseException as error:
            outcome = {'error': error_fields(error, world)}
            raw_tracebacks.append(traceback.format_exception(type(error), error, error.__traceback__))
            if case.get('retain_traceback'):
                retained.append(error)
        else:
            outcome = {'return': role(value)}
    if case.get('outer'):
        try:
            raise world.outer
        except BaseException:
            invoke()
    else:
        invoke()
    at_return = json.loads(canonical({'events': world.events, 'alive': world.alive(),
                                      'outcome': outcome}))
    world.phase = 'consumer-release'
    value = None
    provider = None
    arguments = None
    namespace = None
    retained.clear()
    if case.get('explicit_gc'):
        collected = gc.collect()
    else:
        collected = None
    result = json.loads(canonical({'id': case['id'], 'outcome': outcome,
              'at_return': at_return, 'events': world.events, 'hits': world.hits,
              'opened': world.opened, 'closed': world.closed,
              'closed_streams': world.closed_streams, 'alive': world.alive(),
              'injected_fault_fired': world.fired, 'explicit_gc_collected': collected}))
    if case.get('fault') and not world.fired:
        raise AssertionError('frozen fault was never reached')
    if world.prerequisite is not None:
        if not world.prerequisite_fired:
            raise AssertionError('original basis prerequisite was never reached')
        if world.prerequisite_hit >= case['fault']['index']:
            raise AssertionError('original basis prerequisite did not precede target')
        result['prerequisite_fault'] = {
            'family': type(world.prerequisite).__name__,
            'label': case['base_fault'], 'index': world.prerequisite_hit,
            'fired': world.prerequisite_fired}
    return result, raw_tracebacks
