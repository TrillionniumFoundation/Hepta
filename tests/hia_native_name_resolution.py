"""Independent native name/import differential controls; no runtime policy."""
from __future__ import annotations
from types import SimpleNamespace
import builtins
import gc
import sys


class MarkerError(Exception):
    pass


def error_record(error):
    result = {'type': type(error).__module__ + '.' + type(error).__qualname__,
              'args': list(error.args), 'name': getattr(error, 'name', None),
              'path': getattr(error, 'path', None),
              'suppress_context': error.__suppress_context__}
    context = error.__context__
    result['context'] = None if context is None else {
        'type': type(context).__module__ + '.' + type(context).__qualname__,
        'args': list(context.args)}
    return result


def observed(call, events):
    try:
        value = call()
        return {'result': 'value', 'value': value, 'events': list(events)}
    except BaseException as error:
        return {'result': 'error', 'error': error_record(error), 'events': list(events)}


class Recorder:
    def __init__(self, events):
        self.events = events
        self.data = bytearray()
    def __getattr__(self, name):
        def call(*args, **kwargs):
            self.events.append([name, list(args), kwargs])
        return call


def replacement(kind, name, original, events):
    if kind == 'original':
        return original
    if kind == 'none':
        return None
    if kind == 'object':
        return object()
    if kind == 'function':
        def foreign(*args, **kwargs):
            events.append(['foreign', name])
            raise MarkerError(name)
        return foreign
    class Foreign:
        def __getattribute__(self, field):
            if field in ('__module__', '__qualname__', '__name__'):
                raise MarkerError('metadata-read:' + field)
            return object.__getattribute__(self, field)
        def __call__(self, *args, **kwargs):
            events.append(['foreign', name])
            raise MarkerError(name)
    return Foreign()


def core_case(name, events):
    code = Recorder(events)
    target = SimpleNamespace(c=code, types={'a': 'u8'}, value_registers={'a': 'rax'},
        slots={'a': -8}, frame=0, saved_registers={})
    target.load = lambda *args, **kwargs: events.append(['load', list(args), kwargs])
    target.store = lambda *args, **kwargs: events.append(['store', list(args), kwargs])
    target.compare_imm = lambda *args: events.append(['compare_imm', list(args)])
    target.fail_if = lambda *args: events.append(['fail_if', list(args)])
    if name == '_words': return 'copy', (target, 'a', 'b')
    if name == '_reject': return 'load', (target, 'a', 'rax', 1)
    if name == '_bounds': return 'range_check', (target, 'rax', 'u8', 'u64')
    if name == '_normalize': return 'narrow_result', (target, 'u8', False)
    # Stop immediately after the prologue's observable effects. Both original
    # and HIA then perform the same missing fn attribute read.
    return 'render', (target,)


def byte_case(name, events):
    if name == '_reject':
        return 'normalize_exports', ([], None)
    code = Recorder(events)
    counter = [0]
    def label(value):
        counter[0] += 1
        return value + str(counter[0])
    emitter = SimpleNamespace(c=code, label=label, function_symbol=lambda name: name,
                              symbols=[], exports=[])
    return 'emit_wrapper', (emitter, {'name': 'f', 'params': [{'name': 'n', 'type': 'u8'}]}, 8)


def assert_helper_rebindings(test, family, new_owner):
    from hepta import hia_program_native as backend, hia_native_byte_abi as byte_api
    names = ('_reject', '_words', '_bounds', '_normalize', '_prologue') if family == 'core' else ('_reject', '_normalize', '_prologue')
    rows = []
    for name in names:
        original = vars(backend)[name]
        for timing in ('before-admission', 'after-admission'):
            for kind in ('original', 'function', 'none', 'object', 'deleted', 'metadata-error'):
                with test.subTest(family=family, helper=name, timing=timing, replacement=kind):
                    sides = []
                    for native in (False, True):
                        events = []
                        vars(backend)[name] = original
                        image = new_owner() if native and timing == 'after-admission' else None
                        if kind == 'deleted':
                            del vars(backend)[name]
                        else:
                            vars(backend)[name] = replacement(kind, name, original, events)
                        try:
                            if native and timing == 'before-admission':
                                image = new_owner()
                            method, arguments = (core_case if family == 'core' else byte_case)(name, events)
                            if native:
                                key = '_Function.' + method if family == 'core' else method
                                call = lambda: image.finish(image.prepare(key, arguments))
                            elif family == 'core':
                                call = lambda: getattr(backend._Function, method)(*arguments)
                            else:
                                call = lambda: getattr(byte_api, '_reference_' + method)(*arguments)
                            sides.append(observed(call, events))
                            if native:
                                test.assertGreater(image.entries, 0)
                        finally:
                            vars(backend)[name] = original
                            image = None
                    rows.append({'helper': name, 'timing': timing, 'case': kind,
                                 'reference': sides[0], 'native': sides[1]})
                    test.assertEqual(sides[0], sides[1])
    return rows


def assert_missing_global_port(test, frame_type):
    namespace = {'__builtins__': vars(builtins)}
    exec('def missing():\n    return HIA_MISSING_GLOBAL_80\n', namespace)
    frame = SimpleNamespace(image=SimpleNamespace(namespace=namespace, backend_namespace=namespace, _helpers={}), mode=1)
    for outer in (False, True):
        def call(native):
            action = (lambda: frame_type._global(frame, 'HIA_MISSING_GLOBAL_80')) if native else namespace['missing']
            if not outer:
                return observed(action, [])
            try:
                raise MarkerError('active-outer')
            except MarkerError:
                return observed(action, [])
        with test.subTest(active_outer=outer):
            test.assertEqual(call(False), call(True))


def assert_byte_import_groups(test, new_owner):
    from hepta import hia_native_byte_abi as api, hia_program_native as backend
    rows = []
    for proxy in (False, True):
        sides = []
        for native in (False, True):
            image = new_owner() if native else None
            events = []
            original_import = builtins.__import__
            class ModuleProxy:
                def __getattr__(self, name):
                    events.append(['import-from', name])
                    return getattr(backend, name)
                def __del__(self):
                    events.append(['module-released'])
            def hooked(name, globals=None, locals=None, fromlist=(), level=0):
                if level == 1 and name in ('hia_program', 'hia_program_native'):
                    events.append(['import-name', name, list(fromlist), globals is vars(api), level])
                    if proxy and name == 'hia_program_native':
                        return ModuleProxy()
                return original_import(name, globals, locals, fromlist, level)
            try:
                builtins.__import__ = hooked
                call = (lambda: image.normalize_exports((), None)) if native else (lambda: api._reference_normalize_exports((), None))
                sides.append(observed(call, events))
            finally:
                builtins.__import__ = original_import
                image = None
        rows.append({'proxy': proxy, 'reference': sides[0], 'native': sides[1]})
        with test.subTest(proxy=proxy):
            test.assertEqual(sides[0], sides[1])
    return rows


def assert_import_error_retirement(test, family, new_owner):
    from hepta import hia_native_byte_abi as api, hia_program_native as backend, hia_program
    provider = backend if family == 'byte' else hia_program
    module_name = 'hia_program_native' if family == 'byte' else 'hia_program'
    missing_names = (None, 'IMPORTS', '_LOADER_HOOKS', '_reject') if family == 'byte' else (None, 'VerifiedProgram', 'verify_program')
    rows = []
    for missing in missing_names:
        for outer in (False, True):
            sides = []
            for native in (False, True):
                gc.collect()
                events = []
                image = new_owner() if native else None
                class ModuleProxy:
                    __name__ = 'hepta.v80_virtual_import_provider'
                    __file__ = '/virtual/v80-import-provider.py'
                    def __getattr__(self, name):
                        events.append(['field', name])
                        if name == missing:
                            raise AttributeError(name)
                        return getattr(provider, name)
                    def __del__(self):
                        active = sys.exception()
                        events.append(['release', None if active is None else type(active).__name__])
                old_import = builtins.__import__
                def hooked(name, globals=None, locals=None, fromlist=(), level=0):
                    if name == module_name and level == 1:
                        events.append(['import', list(fromlist)])
                        return ModuleProxy()
                    return old_import(name, globals, locals, fromlist, level)
                held = []
                result = None
                def run():
                    nonlocal result
                    try:
                        if family == 'byte':
                            value = image.normalize_exports((), None) if native else api._reference_normalize_exports((), None)
                        else:
                            value = image.finish(image.prepare('emit_program_machine', (None, backend.TARGET, None, ()))) if native else backend._reference_emit_program_machine(None)
                        result = {'kind': 'value', 'value': value}
                    except BaseException as error:
                        held.append(error)
                        result = {'kind': 'error', 'error': error_record(error)}
                try:
                    builtins.__import__ = hooked
                    if outer:
                        try:
                            raise RuntimeError('outer')
                        except RuntimeError:
                            run()
                    else:
                        run()
                finally:
                    builtins.__import__ = old_import
                at_return = list(events)
                held.clear()
                gc.collect()
                sides.append({'result': result, 'while_error_held': at_return,
                              'after_error_release': list(events)})
                if native:
                    test.assertGreater(image.entries, 0)
                image = None
            rows.append({'missing': missing, 'outer': outer, 'reference': sides[0], 'native': sides[1]})
            with test.subTest(family=family, missing=missing, outer=outer):
                test.assertEqual(sides[0], sides[1])
    return rows
