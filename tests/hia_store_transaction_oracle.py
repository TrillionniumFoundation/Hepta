"""Independent frozen-original transaction observer; no product imports.

Declared and observed exceptions are retained until a case ends to give stable
identity labels. This observer does not claim exception-destructor coverage.
Temporary enter/exit/SQL results and captured special callables are not directly
retained. Each returned record is a canonical detached snapshot after the
explicit generator cleanup. Declared explicit_gc cases separately observe the
subsequent cyclic-GC stage; no case claims every possible finalization history.
"""
from __future__ import annotations
import builtins
import contextlib
import contextvars
import gc
import hashlib
import inspect
import json
import os
from pathlib import Path
import sys
import textwrap
import threading
import types
import warnings
import weakref

BASE = builtins.BaseException
HERE = Path(__file__).resolve().parent
FIXTURE = HERE / 'fixtures' / 'hia_store_transaction_original_c019'
ORIGINAL_SHA256 = '23d89d8ae63bf196203cbd53a5cc8970083470a77fdd16625eb96d618e0a5587'
ORIGINAL_CODE = None
CURRENT = contextvars.ContextVar('independent_transaction_oracle_context', default='base')
ERROR_TYPES = {name: getattr(builtins, name) for name in (
    'ValueError', 'RuntimeError', 'TypeError', 'AttributeError', 'KeyError',
    'OSError', 'KeyboardInterrupt', 'SystemExit', 'GeneratorExit',
    'StopIteration', 'StopAsyncIteration')}


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True,
                      separators=(',', ':'), allow_nan=False).encode()


def original_factory(store, namespace):
    global ORIGINAL_CODE
    raw = (FIXTURE / 'transaction.c019.py.txt').read_bytes()
    if hashlib.sha256(raw).hexdigest() != ORIGINAL_SHA256:
        raise AssertionError('frozen decorated original transaction changed')
    namespace.setdefault('contextmanager', contextlib.contextmanager)
    if ORIGINAL_CODE is None:
        ORIGINAL_CODE = compile(textwrap.dedent(raw.decode()), '<frozen-c019-AgentStore.transaction>', 'exec')
    exec(ORIGINAL_CODE, namespace)
    return namespace['transaction'](store)


class Token:
    def __init__(self, fixture, label, truth=None, action=None):
        self.fixture, self.label, self.truth, self.action = fixture, label, truth, action

    def __bool__(self):
        self.fixture.hit(self.label + '.bool')
        return self.truth

    def __del__(self):
        f = self.fixture
        f.hit(self.label + '.delete')
        if self.action:
            f.mutate(self.action)


class CapturedSpecial:
    def __init__(self, owner, method):
        self.owner, self.method = owner, method

    def __call__(self, *args):
        return self.owner.invoke(self.method, *args)

    def __del__(self):
        if self.owner.fixture.case.get('release_bindings'):
            self.owner.fixture.hit(self.owner.label + '.' + self.method + '.binding.delete')


class Special:
    def __init__(self, method):
        self.method = method

    def __get__(self, owner, cls=None):
        if owner is None:
            return self
        f = owner.fixture
        f.hit(owner.label + '.' + self.method + '.lookup')
        if f.case.get('noncallable_special') == self.method:
            return 17
        return CapturedSpecial(owner, self.method)


class FakeLock:
    __enter__ = Special('enter')
    __exit__ = Special('exit')

    def __init__(self, fixture, label='lock0', ephemeral=False):
        self.fixture, self.label, self.ephemeral = fixture, label, ephemeral
        self.held = False

    def invoke(self, method, *args):
        f = self.fixture
        if method == 'enter':
            f.hit(self.label + '.enter.call')
            self.held = True
            if f.case.get('enter_token'):
                return Token(f, self.label + '.enter.result', action=f.case.get('enter_delete_action'))
            return f.case.get('enter_value')
        typ, error, tb = args
        f.hit(self.label + '.exit.call', exception=f.error(error),
              type_matches=typ is (type(error) if error is not None else None),
              traceback_is_exception_traceback=tb is (error.__traceback__ if error is not None else None))
        self.held = False
        policy = f.case.get('exit', False)
        if isinstance(policy, str) and policy.startswith('token_'):
            truth = {'token_true': True, 'token_false': False, 'token_bad': 1}[policy]
            return Token(f, self.label + '.exit.result', truth, f.case.get('exit_delete_action'))
        return policy

    def __del__(self):
        if self.ephemeral:
            self.fixture.hit(self.label + '.manager.delete')


class MissingEnter:
    __exit__ = Special('exit')
    invoke = FakeLock.invoke
    def __init__(self, fixture):
        self.fixture, self.label, self.held = fixture, 'lock0', False


class MissingExit:
    __enter__ = Special('enter')
    invoke = FakeLock.invoke
    def __init__(self, fixture):
        self.fixture, self.label, self.held = fixture, 'lock0', False


class DB:
    def __init__(self, fixture, label):
        self.fixture, self.label = fixture, label

    def __getattribute__(self, name):
        if name == 'execute':
            f = object.__getattribute__(self, 'fixture')
            label = object.__getattribute__(self, 'label')
            f.hit(label + '.execute.lookup')
            if f.case.get('noncallable_execute'):
                return 19
        return object.__getattribute__(self, name)

    def execute(self, sql):
        f = self.fixture
        f.hit(self.label + '.execute.call', sql=sql)
        f.commands.append([self.label, sql])
        f.hit(self.label + '.execute.after', sql=sql)
        if f.case.get('sql_return_token'):
            return Token(f, self.label + '.' + sql + '.result', action=f.case.get('sql_delete_actions', {}).get(sql))
        return f.case.get('sql_return_value')


class Store:
    def __init__(self, fixture):
        self.fixture = fixture

    def __getattribute__(self, name):
        if name in ('lock', 'db'):
            f = object.__getattribute__(self, 'fixture')
            f.hit('store.' + name + '.get')
            if name == 'db':
                return f.db
            if f.case.get('ephemeral_lock'):
                return FakeLock(f, 'lock0', True)
            return f.lock
        return object.__getattribute__(self, name)


class Fixture:
    def __init__(self, case):
        self.case = case
        self.trace, self.commands, self.outcomes, self.unraisables = [], [], [], []
        self.counts, self.exception_labels, self.exception_refs = {}, {}, []
        self.errors = {name: cls(name + '-original') for name, cls in ERROR_TYPES.items()}
        self.errors['body'] = ValueError('body-original')
        self.errors['outer'] = KeyError('outer-original')
        for name, error in self.errors.items():
            self.exception_labels[id(error)] = name
            self.exception_refs.append(error)
        self.namespace = {'contextmanager': contextlib.contextmanager, '__name__': 'frozen_transaction'}
        self.db0, self.db1 = DB(self, 'db0'), DB(self, 'db1')
        self.db = self.db0
        lock_kind = case.get('lock_kind', 'fake')
        self.lock = {'fake': lambda: FakeLock(self), 'none': lambda: None,
                     'missing_enter': lambda: MissingEnter(self), 'missing_exit': lambda: MissingExit(self),
                     'rlock': threading.RLock}[lock_kind]()
        self.store, self.cm = Store(self), None
        self.actor = 'main'
        self.role = threading.local()
        self.callbacks_seen = set()
        self.block_entered = threading.Event()
        self.block_release = threading.Event()
        self.reentering = False
        self.supplied_tb = None
        if case.get('matcher'):
            self.set_matcher(case['matcher'])

    def value(self, value):
        if value is None or type(value) in (bool, int, str, float):
            return value
        if isinstance(value, BASE):
            return {'exception': self.label(value)}
        if value is self.store:
            return {'identity': 'store'}
        if value is self.db0:
            return {'identity': 'db0'}
        if value is self.db1:
            return {'identity': 'db1'}
        if isinstance(value, (list, tuple)):
            return [self.value(x) for x in value]
        if isinstance(value, dict):
            return {str(k): self.value(v) for k, v in value.items()}
        if isinstance(value, Token):
            return {'token': value.label}
        return {'type': type(value).__name__}

    def label(self, error):
        if error is None:
            return None
        key = id(error)
        if key not in self.exception_labels:
            label = 'generated-' + str(len(self.exception_refs))
            self.exception_labels[key] = label
            self.exception_refs.append(error)
        return self.exception_labels[key]

    def error(self, error, seen=None):
        if error is None:
            return None
        seen = set() if seen is None else seen
        label = self.label(error)
        if id(error) in seen:
            return {'ref': label}
        seen.add(id(error))
        result = {'identity': label, 'type': type(error).__name__, 'args': self.value(error.args),
                  'cause': self.error(error.__cause__, seen), 'context': self.error(error.__context__, seen),
                  'suppress_context': error.__suppress_context__}
        if isinstance(error, AttributeError):
            result.update(name=error.name, obj=self.value(error.obj))
        return result

    def state(self):
        gen = getattr(self.cm, 'gen', None)
        if not isinstance(gen, types.GeneratorType):
            return {'real_generator': False}
        return {'real_generator': True, 'state': inspect.getgeneratorstate(gen),
                'running': gen.gi_running, 'frame_present': gen.gi_frame is not None}

    def hit(self, event, **details):
        occurrence = self.counts.get(event, 0) + 1
        self.counts[event] = occurrence
        self.trace.append({'event': event, 'occurrence': occurrence,
                           'actor': getattr(self.role, 'name', 'main'), 'context': CURRENT.get(),
                           'active_exception': self.label(sys.exception()), **details})
        if self.case.get('block_event') == event and not self.block_entered.is_set():
            self.block_entered.set()
            if not self.block_release.wait(5):
                raise AssertionError('oracle synchronization failed')
        for index, callback in enumerate(self.case.get('callbacks', [])):
            if event == callback['event'] and occurrence == callback.get('occurrence', 1):
                if index in self.callbacks_seen:
                    continue
                self.callbacks_seen.add(index)
                self.mutate(callback['action'])
        for fault in self.case.get('faults', []):
            if event == fault['event'] and occurrence == fault.get('occurrence', 1):
                raise self.errors[fault['error']]

    def set_matcher(self, name):
        if name == 'builtin':
            self.namespace['BaseException'] = BASE
        elif name == 'fallback':
            self.namespace.pop('BaseException', None)
        elif name == 'Exception':
            self.namespace['BaseException'] = Exception
        elif name == 'ValueError':
            self.namespace['BaseException'] = ValueError
        elif name == 'KeyError':
            self.namespace['BaseException'] = KeyError
        elif name == 'tuple':
            self.namespace['BaseException'] = (ValueError, GeneratorExit)
        elif name == 'empty_tuple':
            self.namespace['BaseException'] = ()
        elif name == 'invalid':
            self.namespace['BaseException'] = 7
        elif name == 'mixed_tuple':
            self.namespace['BaseException'] = (ValueError, 7)
        else:
            raise AssertionError(name)

    def mutate(self, action):
        self.trace.append({'event': 'observer.mutate', 'action': action,
                           'actor': getattr(self.role, 'name', 'main'), 'context': CURRENT.get(),
                           'active_exception': self.label(sys.exception())})
        if action == 'db1':
            self.db = self.db1
        elif action == 'db_none':
            self.db = None
        elif action == 'lock1':
            self.lock = FakeLock(self, 'lock1')
        elif action.startswith('matcher:'):
            self.set_matcher(action.split(':', 1)[1])
        elif action.startswith('reenter:'):
            if self.reentering:
                raise AssertionError('oracle recursive callback')
            self.reentering = True
            try:
                self.perform({'op': action.split(':', 1)[1]}, nested=True)
            finally:
                self.reentering = False
        else:
            raise AssertionError(action)

    def operation(self, action):
        op = action['op']
        if op == 'enter':
            return self.cm.__enter__()
        if op == 'exit':
            name = action.get('error')
            error = self.errors[name] if name else None
            return self.cm.__exit__(type(error) if error is not None else None, error,
                                    error.__traceback__ if error is not None else None)
        if op == 'exit_none_value':
            return self.cm.__exit__(ERROR_TYPES[action['type']], None, None)
        if op == 'next':
            return next(self.cm.gen)
        if op == 'send':
            return self.cm.gen.send(action.get('value'))
        if op == 'throw':
            style = action.get('style', 'instance')
            error = self.errors[action.get('error', 'body')]
            if style == 'instance':
                return self.cm.gen.throw(error)
            if style == 'class':
                return self.cm.gen.throw(type(error))
            if style == 'two':
                return self.cm.gen.throw(type(error), error)
            if style == 'three':
                return self.cm.gen.throw(type(error), error, error.__traceback__)
            if style == 'invalid':
                return self.cm.gen.throw(17)
            if style == 'bad_traceback':
                return self.cm.gen.throw(type(error), error, 17)
            if style == 'bad_value':
                return self.cm.gen.throw(error, 'another')
            raise AssertionError(style)
        if op == 'close':
            return self.cm.gen.close()
        if op == 'with':
            with self.cm as value:
                self.hit('observer.body', value=self.value(value))
                for mutation in action.get('mutations', []):
                    self.mutate(mutation)
                if action.get('error'):
                    raise self.errors[action['error']]
            return None
        if op == 'mutate':
            self.mutate(action['action'])
            return None
        if op == 'inspect':
            return self.state()
        raise AssertionError(op)

    def perform(self, action, nested=False):
        active = sys.exception()
        before = self.state()
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            try:
                value = self.operation(action)
                outcome = {'kind': 'return', 'value': self.value(value)}
                del value
            except BASE as error:
                outcome = {'kind': 'raise', 'error': self.error(error)}
        row = {'action': action, 'nested': nested, 'actor': getattr(self.role, 'name', 'main'),
               'context': CURRENT.get(), 'before': before, 'after': self.state(),
               'outcome': outcome, 'caller_active_exception_restored': sys.exception() is active,
               'warnings': [{'category': item.category.__name__, 'message': str(item.message)} for item in caught]}
        self.outcomes.append(row)
        return row

    def threaded(self, action):
        result, failure = [], []
        def child():
            self.role.name = 'worker'
            try:
                result.append(self.perform(action))
            except BASE as error:
                failure.append(self.error(error))
        t = threading.Thread(target=child, name='transaction-original-observer')
        t.start(); t.join(5)
        if t.is_alive():
            raise AssertionError('oracle worker failed to finish')
        if failure:
            raise AssertionError(failure)
        return result[0]

    def forked(self, action):
        if not hasattr(os, 'fork'):
            return {'unsupported': 'os.fork unavailable; no behavior qualified'}
        readfd, writefd = os.pipe()
        child = os.fork()
        if child == 0:
            os.close(readfd)
            try:
                self.role.name = 'fork-child'
                prefix = len(self.trace)
                result = self.perform(action)
                data = canonical({'result': result, 'trace_after_fork': self.trace[prefix:],
                                  'commands': self.commands, 'state': self.state()})
                while data:
                    data = data[os.write(writefd, data):]
                os.close(writefd)
                os._exit(0)
            except BASE:
                os._exit(92)
        os.close(writefd)
        chunks = []
        while True:
            part = os.read(readfd, 65536)
            if not part:
                break
            chunks.append(part)
        os.close(readfd)
        _, status = os.waitpid(child, 0)
        if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
            raise AssertionError('oracle fork failed: '+str(status))
        return json.loads(b''.join(chunks))

    def concurrent(self):
        errors = []
        def blocked():
            self.role.name = 'worker'
            try:
                self.perform({'op': 'enter'})
            except BASE as error:
                errors.append(self.error(error))
        t = threading.Thread(target=blocked, name='transaction-original-blocked')
        t.start()
        if not self.block_entered.wait(5):
            self.block_release.set();t.join(5)
            raise AssertionError('original worker did not reach controlled block')
        during = self.state()
        self.perform({'op': 'send', 'value': None})
        self.perform({'op': 'throw', 'error': 'body'})
        self.perform({'op': 'close'})
        self.block_release.set();t.join(5)
        if t.is_alive() or errors:
            raise AssertionError('oracle blocked worker failed')
        return during


def _observe(case, factory=None):
    f = Fixture(case)
    previous_hook = sys.unraisablehook
    def hook(record):
        f.unraisables.append({'error': f.error(record.exc_value),
                              'message': record.err_msg,
                              'object_type': type(record.object).__name__})
    sys.unraisablehook = hook
    special = {}
    try:
        f.cm = (factory or original_factory)(f.store, f.namespace)
        f.trace.append({'event': 'observer.factory_return', 'state': f.state(),
                        'real_contextmanager': type(f.cm) is contextlib._GeneratorContextManager,
                        'effects_before_first_advance': dict(f.counts)})
        def actions():
            for action in case.get('actions', []):
                if action.get('thread'):
                    f.threaded({k:v for k,v in action.items() if k!='thread'})
                elif action.get('context'):
                    name=action['context'];ctx=contextvars.Context()
                    def in_context():
                        CURRENT.set(name);f.perform({k:v for k,v in action.items() if k!='context'})
                    ctx.run(in_context)
                elif action['op']=='fork':
                    special.setdefault('forks', []).append(f.forked(action['action']))
                elif action['op']=='concurrent':
                    special['gi_running_during_block'] = f.concurrent()
                else:
                    f.perform(action)
        if case.get('outer_exception'):
            try:
                raise f.errors['outer']
            except BASE:
                actions()
        else:
            actions()
        before_cleanup=f.state()
        if f.cm.gen.gi_frame is not None:
            f.perform({'op':'close','observer_cleanup':True})
        record = {'id':case['id'],'trace':f.trace,'outcomes':f.outcomes,'commands':f.commands,
                  'before_observer_cleanup':before_cleanup,'final_state':f.state(),
                  'unraisables':f.unraisables,'special':special}
        # Freeze events at the declared endpoint. Later cyclic finalization
        # must not rewrite an observation already delivered to the caller.
        return json.loads(canonical(record))
    finally:
        f.block_release.set()
        sys.unraisablehook=previous_hook


def observe(case, factory=None):
    if not case.get('explicit_gc'):
        return _observe(case, factory)
    # A separate, bounded stage observes real cyclic finalization. Keeping
    # only primitive event lists and a weak reference does not keep the case
    # fixture or its traceback cycles alive after _observe returns.
    gc.collect()
    captured = {}
    def tracked_factory(store, namespace):
        f = store.fixture
        captured['fixture'] = weakref.ref(f)
        captured['trace'] = f.trace
        return (factory or original_factory)(store, namespace)
    record = _observe(case, tracked_factory)
    prefix = len(record['trace'])
    was_enabled = gc.isenabled()
    gc.disable()
    unraisables = []
    previous_hook = sys.unraisablehook
    def hook(event):
        unraisables.append({'type': type(event.exc_value).__name__,
                            'args': list(event.exc_value.args),
                            'message': event.err_msg,
                            'object_type': type(event.object).__name__})
    try:
        before = captured['fixture']() is not None
        sys.unraisablehook = hook
        gc.collect()
        stage = {'fixture_alive_before': before,
                 'fixture_alive_after': captured['fixture']() is not None,
                 'trace_after_observation': captured['trace'][prefix:],
                 'unraisables': unraisables,
                 'explicit_collect_calls': 1,
                 'observer_active_exception_none': sys.exception() is None}
        record['explicit_gc_stage'] = json.loads(canonical(stage))
    finally:
        sys.unraisablehook = previous_hook
        if was_enabled:
            gc.enable()
    return record
