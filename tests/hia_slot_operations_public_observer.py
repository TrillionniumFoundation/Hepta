"""Additional public binding and retained-provider-traceback original controls.

These are independent new inputs. The immutable original248 and derived7574,
their observers and expectations remain unchanged.
"""
from __future__ import annotations
import argparse
import builtins
from pathlib import Path
import os
import sys
import traceback
import types
if __package__ in (None, ''):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tests.hia_slot_operations_qualification_support import (
    NAMES, canonical, admit_originals, admit_cases, admit_product, write_json)
from tests import hia_slot_operations_observer as driver

_HELD_TYPES = []

# STATIC PROPOSAL ONLY. No observer, original method, or candidate has run.
# This code is private to the complete handled-traceback observer below.
# A borrowed token is valid only inside the exact, pinned except-alias scope.
import weakref
from _thread import get_ident as _identity_thread_id


class _BorrowedErrorIdentity:
    __slots__ = ("nonce", "address", "label", "pid", "thread", "active")

    def __init__(self, nonce, address, label, pid, thread):
        self.nonce, self.address, self.label = nonce, address, label
        self.pid, self.thread, self.active = pid, thread, True


class _LifetimeErrorIdentities:
    __slots__ = ("_failure_type", "_weak", "_serial", "_borrows", "_nonce", "_failed")

    def __init__(self, failure_type):
        self._failure_type = failure_type
        self._weak = {}
        self._serial = 0
        self._borrows = []
        self._nonce = object()
        self._failed = False

    def _fail(self, message):
        # Set a sticky primitive before raising: sys.unraisablehook can itself
        # fail, and the outer observer must still reject the attempted record.
        self._failed = True
        raise self._failure_type(message)

    def _label(self, preferred):
        serial = self._serial + 1
        label = preferred or "error#" + str(serial)
        self._serial = serial
        return label

    def name(self, error, preferred=None):
        try:
            if self._failed:
                self._fail("exception identity observation already failed")
            address = id(error)
            for borrowed in reversed(self._borrows):
                if borrowed.address == address:
                    if (not borrowed.active or borrowed.nonce is not self._nonce
                            or borrowed.pid != os.getpid()
                            or borrowed.thread != _identity_thread_id()):
                        self._fail("exception identity borrow is not current")
                    # The pinned except alias still owns this exact object.
                    # The integer is an index within that proven-live interval,
                    # never authority for an arbitrary earlier exception.
                    return borrowed.label
            previous = self._weak.get(address)
            if previous is not None and previous[0]() is error:
                return previous[1]
            try:
                reference = weakref.ref(error)  # no callback/hash/equality
            except TypeError:
                self._fail("unborrowed exception is not weak-referenceable")
            label = self._label(preferred)
            self._weak[address] = (reference, label)
            return label
        except BaseException:
            self._failed = True
            raise

    def borrow_current(self, error, preferred=None):
        """Only the pinned caller's still-live except alias permits this call."""
        try:
            if self._failed or sys.exception() is not error:
                self._fail("exception identity borrow lacks the current exception")
            address = id(error)
            if any(value.address == address for value in self._borrows):
                self._fail("duplicate exception identity borrow")
            previous = self._weak.get(address)
            label = (previous[1] if previous is not None and previous[0]() is error
                     else self._label(preferred))
            token = _BorrowedErrorIdentity(
                self._nonce, address, label, os.getpid(), _identity_thread_id())
            self._borrows.append(token)
            return token
        except BaseException:
            self._failed = True
            raise

    def release_borrow(self, token):
        try:
            if (not self._borrows or self._borrows[-1] is not token
                    or token.nonce is not self._nonce or not token.active
                    or token.pid != os.getpid()
                    or token.thread != _identity_thread_id()):
                self._fail("exception identity borrow exit is not current")
            token.active = False
            self._borrows.pop()
        except BaseException:
            self._failed = True
            raise

    def check_complete(self):
        if self._failed or self._borrows:
            self._fail("exception identity observation is incomplete")


class _HandledIdentityController:
    """Retains registries, never World instances, exceptions, or tracebacks."""

    def __init__(self, namespace):
        original_world = namespace["World"]
        failure_type = namespace["OracleFixtureError"]
        registries = []

        class LifetimeWorld(original_world):
            def __init__(self, case):
                original_world.__init__(self, case)
                identity = _LifetimeErrorIdentities(failure_type)
                self._observer_error_identity = identity
                registries.append(identity)

            def name_error(self, error, preferred=None):
                return self._observer_error_identity.name(error, preferred)

        self._registries = registries
        namespace["World"] = LifetimeWorld

    def check_complete(self):
        for identity in self._registries:
            identity.check_complete()


class FalseOperand:
    def __init__(self, world):
        self.world = world
        world.register(self, 'false-and-operand')

    def __bool__(self):
        self.world.event('namespace.false-operand.bool')
        return False

    def __int__(self):
        self.world.event('namespace.false-operand.int')
        return 0


class GlobalCall:
    def __init__(self, world, name, false_lhs=False, raises=None):
        self.world, self.name, self.false_lhs, self.raises = world, name, false_lhs, raises

    def __call__(self, *arguments, **keywords):
        self.world.event('namespace.' + self.name, arguments=arguments, keywords=keywords)
        if self.raises is not None:
            raise getattr(builtins, self.raises)('declared global protocol error')
        if self.name == 'isinstance' and self.false_lhs:
            return FalseOperand(self.world)
        return getattr(builtins, self.name)(*arguments, **keywords)


class HandledProviderError(RuntimeError):
    pass


def captured_db_getter(store):
    world = object.__getattribute__(store, '_world')
    try:
        raise HandledProviderError('declared provider-handled exception')
    except HandledProviderError as error:
        world.event('provider.handled-error', inject=False)
        if world.case['retain_provider_traceback']:
            world.provider_tracebacks.append(error.__traceback__)
    world.event('store.lookup.db')
    return object.__getattribute__(store, '_db')


def invoke(cls, subject, name, args, kwargs, route):
    if route == 'class':
        if name == '_lease_value':
            return cls._lease_value(*args, **kwargs)
        return getattr(cls, name)(subject, *args, **kwargs)
    return getattr(subject, name)(*args, **kwargs)


def subclass(source_class):
    class DeclaredSubclass(source_class):
        def _call(self, opcode, fields=(), *, labels=(), state=None, **values):
            self._world.event('subclass.override._call', opcode=opcode, fields=fields,
                              labels=labels, state=state, values=values)
            return self._world.receipt(opcode)
    _HELD_TYPES.append(DeclaredSubclass)
    return DeclaredSubclass


def specifications(originals, group):
    bases = {}
    for case in originals:
        if case['id'].startswith('base.') and case['outer_exception'] is False:
            bases.setdefault(case['method'], case)
    if set(bases) != set(NAMES):
        raise AssertionError('immutable original bases omit a public method')
    result = []
    if group == 'public':
        for name in NAMES:
            for route in ('instance', 'class'):
                result.append({'id': 'public.' + route + '.' + name, 'base': bases[name],
                               'route': route, 'kind': 'ordinary'})
            for invalid in ('missing', 'duplicate', 'excess'):
                result.append({'id': 'binding.' + invalid + '.' + name, 'base': bases[name],
                               'route': 'class', 'kind': invalid})
        for kind in ('global-false-and', 'global-true-and', 'global-isinstance-StopIteration', 'global-int-MemoryError'):
            result.append({'id': kind, 'base': bases['conditional'],
                           'route': 'class', 'kind': kind})
        result.append({'id': 'global-lease-int-type-str', 'base': bases['lease'],
                       'route': 'class', 'kind': 'global-lease'})
        for route in ('instance', 'class'):
            for kind in ('instance-override', 'subclass-override'):
                result.append({'id': kind + '.' + route, 'base': bases['validate_u64'],
                               'route': route, 'kind': kind})
        return result
    templates = {case['template']: case for case in originals
                 if case['id'].startswith('base.') and case['outer_exception'] is False}
    for template in ('snapshot-present', 'adopt-active', 'lease-check'):
        for retain in (False, True):
            for outer in (False, True):
                result.append({'id': 'handled-tb.' + template + '.retain' + str(int(retain))
                               + '.outer' + str(int(outer)), 'base': templates[template],
                               'kind': 'handled-traceback', 'retain': retain,
                               'outer': outer, 'route': 'instance'})
    return result


def observe(namespace, spec, backend):
    case = namespace['copy_json'](spec['base'])
    case.update(id=spec['id'], fault=None, outer_exception=spec.get('outer', False),
                retain_provider_traceback=spec.get('retain', False))
    case['settings']['collect'] = False
    world = namespace['World'](case)
    world.provider_tracebacks = []
    namespace['ACTIVE'] = world
    cls, original_methods = namespace['ORIGINAL'], namespace['ORIGINAL_METHODS']
    old_property = namespace['Store'].db
    if spec['kind'] == 'handled-traceback':
        namespace['Store'].db = property(captured_db_getter)
    ns = cls.__init__.__globals__ if backend is None else vars(backend['ledger'])
    namespaces = [ns] if backend is None else [ns, backend['original_namespace']]
    changed = []
    try:
        if spec['kind'].startswith('global-'):
            names = ('type', 'str', 'int') if spec['kind'] == 'global-lease' else ('isinstance', 'set', 'int')
            for name in names:
                raised = ('StopIteration' if spec['kind'] == 'global-isinstance-StopIteration' and name == 'isinstance'
                          else 'MemoryError' if spec['kind'] == 'global-int-MemoryError' and name == 'int' else None)
                replacement = GlobalCall(world, name, spec['kind'] == 'global-false-and', raised)
                for target in namespaces:
                    changed.append((target, name, name in target, target.get(name)))
                    target[name] = replacement
        if spec['kind'] == 'subclass-override':
            cls = subclass(cls)
            subject = object.__new__(cls)
            subject._world = world
            world.register(subject, 'subject')
        else:
            subject = namespace['Subject'](world)
        world.subject_ref = namespace['weakref'].ref(subject)
        cls.__init__(subject, world.new_store(), namespace['Image'](world))
        if spec['kind'] == 'instance-override':
            object.__getattribute__(subject, '_values')['_call'] = namespace['Override'](world, '_call')
        args, kwargs = world.arguments(subject)
        if spec['kind'] == 'missing':
            args, kwargs = (), {}
        elif spec['kind'] == 'excess':
            args, kwargs = tuple(range(32)), {}
        elif spec['kind'] == 'duplicate':
            original = (original_methods if backend is None else backend['references'][1])[case['method']]
            if type(original) is staticmethod:
                first = original.__func__.__code__.co_varnames[0]
            else:
                first = original.__code__.co_varnames[1]
            kwargs = dict(kwargs)
            kwargs[first] = args[0]
        world.phase, result = 'invoke', None
        before_entries = None if backend is None else backend['entry'].entries
        try:
            if case['outer_exception']:
                try:
                    raise KeyError('declared outer exception')
                except KeyError as outer:
                    if spec['kind'] == 'handled-traceback':
                        outer_identity = world._observer_error_identity.borrow_current(outer, 'outer')
                        try:
                            result = invoke(cls, subject, case['method'], args, kwargs, spec['route'])
                        finally:
                            world._observer_error_identity.release_borrow(outer_identity)
                    else:
                        world.name_error(outer, 'outer')
                        result = invoke(cls, subject, case['method'], args, kwargs, spec['route'])
            else:
                result = invoke(cls, subject, case['method'], args, kwargs, spec['route'])
        except namespace['OracleFixtureError']:
            raise
        except BaseException as error:
            outcome = {'kind': 'raised', 'error': world.error(error)}
            raw = ''.join(traceback.format_exception(error))
        else:
            outcome, raw = {'kind': 'returned', 'value': world.value(result)}, None
        if spec['kind'] in ('missing', 'duplicate', 'excess'):
            if outcome['kind'] != 'raised' or outcome['error']['type'] != 'builtins.TypeError':
                raise AssertionError('declared argument binding input did not reject')
            if backend is not None and backend['entry'].entries != before_entries:
                raise AssertionError('native control preceded original signature binding')
        world.phase = 'consumer-release'
        world.event('observer.consumer_release.begin', inject=False)
        subject = args = kwargs = result = None
        world.event('observer.consumer_release.end', inject=False)
        at_return = namespace['copy_json']({'events': world.events, 'alive': world.alive()})
        world.phase = 'handled-provider-traceback-release'
        world.event('observer.provider_traceback_release.begin',
                    count=len(world.provider_tracebacks), inject=False)
        world.provider_tracebacks.clear()
        world.event('observer.provider_traceback_release.end', inject=False)
        record = namespace['copy_json']({'id': spec['id'], 'base_id': spec['base']['id'],
            'route': spec['route'], 'kind': spec['kind'], 'outcome': outcome,
            'events': world.events, 'at_consumer_return': at_return,
            'alive_after_explicit_tb_release': world.alive(),
            'fake_sql_effects': world.effects, 'complete_request_packets': world.requests,
            'explicit_gc_performed': False, 'unraisable': world.unraisable})
        if spec['kind'] == 'handled-traceback':
            world._observer_error_identity.check_complete()
        if world.unraisable:
            raise AssertionError('supplemental observer unraisable')
        driver._SETUP.append(world)
        return record, raw
    finally:
        namespace['Store'].db = old_property
        for target, name, present, value in reversed(changed):
            if present:
                target[name] = value
            else:
                target.pop(name, None)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('root', 'oracle-root', 'derived-inputs', 'product-freeze', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--product-freeze-sha256', required=True)
    parser.add_argument('--backend', choices=('original', 'unselected', 'vm', 'native'), required=True)
    parser.add_argument('--group', choices=('public', 'handled-traceback'), required=True)
    parser.add_argument('--manifest', type=Path)
    options = parser.parse_args()
    root, oracle_root, output = options.root.resolve(), options.oracle_root.resolve(), options.output.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    before = admit_originals(oracle_root)
    product = admit_product(root, options.product_freeze, options.product_freeze_sha256)
    bases, unused = admit_cases(oracle_root, options.derived_inputs, 'original248')
    namespace = driver.load_observer(oracle_root)
    backend = driver.prepare_backend(root, options.backend, options.manifest)
    namespace['install_audit'](oracle_root, output)
    namespace['load_originals'](oracle_root)
    specs = specifications(bases, options.group)
    fixture = root / 'tests/fixtures/hia_slot_operations_qualification' / (options.group + '-inputs.json')
    import json
    if canonical(json.loads(fixture.read_bytes())['cases']) != canonical(specs):
        raise AssertionError('independent supplemental complete input manifest differs')
    identity_controller = (_HandledIdentityController(namespace)
                           if options.group == 'handled-traceback' else None)
    if backend is not None:
        driver.bind_actual_public(namespace, backend)
    planned = [spec['id'] for spec in specs]
    write_json(output / 'planned.json', {'ordered_ids': planned, 'inputs': specs})
    started, stopped, failures = [], [], []
    prior = sys.unraisablehook
    def unraisable(value):
        active = namespace['ACTIVE']
        if active is not None:
            active.unraisable.append({'error': active.error(value.exc_value),
                'object': active.value(value.object), 'message': value.err_msg})
    sys.unraisablehook = unraisable
    try:
        with (output / 'observations.jsonl').open('xb') as observed, (
                output / 'raw-exceptions.jsonl').open('xb') as errors:
            for spec in specs:
                started.append(spec['id'])
                record, raw = observe(namespace, spec, backend)
                observed.write(canonical(record) + b'\n')
                observed.flush()
                errors.write(canonical({'id': spec['id'], 'traceback': raw}) + b'\n')
                errors.flush()
                stopped.append(spec['id'])
    except BaseException as error:
        failures.append({'type': type(error).__module__ + '.' + type(error).__qualname__,
                         'message': str(error), 'traceback': traceback.format_exc()})
    finally:
        sys.unraisablehook = prior
        driver.unbind_actual_public(backend)
    after = admit_originals(oracle_root)
    product_after = admit_product(root, options.product_freeze, options.product_freeze_sha256)
    if identity_controller is not None:
        try:
            identity_controller.check_complete()
        except BaseException as error:
            failures.append({'type': type(error).__module__ + '.' + type(error).__qualname__,
                             'message': str(error), 'traceback': traceback.format_exc()})
    counts = None if backend is None else {
        'returned_entries': backend['entry'].entries, 'events': dict(backend['entry'].events),
        'modes': dict(backend['entry'].modes), 'retained_calls': backend['retained_calls']}
    good = planned == started == stopped and not failures and before == after and product == product_after
    if backend is not None:
        good = good and counts['retained_calls'] == []
        good = good and (counts['returned_entries'] == 0 if backend.get('unselected', False)
                         else counts['returned_entries'] > 0)
    write_json(output / 'report.json', {'schema': 'hepta.slot-operations.public-supplement.v1',
        'status': 'RECORDED' if good else 'HOLD', 'group': options.group,
        'planned': planned, 'started': started, 'stopped': stopped, 'failures': failures,
        'backend': options.backend, 'counts': counts, 'pid': os.getpid(), 'ppid': os.getppid(),
        'pgid': os.getpgrp(), 'runtime': sys.version, 'source_before': before, 'source_after': after,
        'product_before': product, 'product_after': product_after,
        'original_248_and_7574_modified': False, 'no_gc_normalization': True,
        'scope': 'new finite public and explicitly retained provider traceback controls',
        'actual_SQL': 0})
    return 0 if good else 1


if __name__ == '__main__':
    raise SystemExit(main())
