"""Original constructor boundary and HIA options policy comparisons.

The original unmodified __init__ is stopped by the first Path call. The scalar
runtime type fixture is accepted only to reach this component's owned boundary.
An author run is explicitly a development check, never native qualification.
"""
from __future__ import annotations
import argparse
import ast
import ctypes as C
import hashlib
import importlib
import json
import math
import os
from pathlib import Path
import platform
import random
import struct
import sys
from tools.qualify_hia_result_value_dict_iterator import AuthorEngine, NativeEngine, StringAlias, Values, ZERO, put, word

ROOT = Path(__file__).resolve().parents[1]
SOURCE_SHA = 'd5a3c81eb0d7907fe872565b6ca6605708f8a6f13fd5a8d55788a9a13a095f7b'


def request(caps=(), op=0):
    result = bytearray(128)
    result[:8] = b'HIABOPQ1'
    put(result, 8, op)
    for i, cap in enumerate(caps):
        struct.pack_into('<3Q', result, 24 + i * 24, *cap)
    return bytes(result)


class BoundaryReached(BaseException):
    pass


def original_constructor():
    path = ROOT / 'hepta/hia_background_optimizer.py'
    source = path.read_bytes()
    assert hashlib.sha256(source).hexdigest() == SOURCE_SHA
    parsed = ast.parse(source)
    error = next(n for n in parsed.body if isinstance(n, ast.ClassDef) and n.name == 'BackgroundOptimizationRejected')
    reject = next(n for n in parsed.body if isinstance(n, ast.FunctionDef) and n.name == '_reject')
    owner = next(n for n in parsed.body if isinstance(n, ast.ClassDef) and n.name == 'BackgroundOptimizer')
    ctor = next(n for n in owner.body if isinstance(n, ast.FunctionDef) and n.name == '__init__')
    fixture_type = type('ScalarMultiversionRuntime', (), {})

    def stop_path(value):
        raise BoundaryReached()

    namespace = {'ScalarMultiversionRuntime': fixture_type, 'Path': stop_path}
    exec(compile(ast.Module(body=[error, reject, ctor], type_ignores=[]), str(path), 'exec'), namespace)

    def observe(kwargs):
        values = {'function': 'f', 'bridge': {'binary': 'b', 'build_receipt': 'r'}, **kwargs}
        try:
            namespace['__init__'](object(), fixture_type(), None, **values)
        except BoundaryReached:
            b = values.get('bridge_timeout_s', 10.0)
            return ('ok', values.get('max_pending', 8), values.get('timeout_ms', 2000),
                    int(b) if type(b) is int else struct.unpack('<Q', struct.pack('<d', b))[0], int(type(b) is int))
        except namespace['BackgroundOptimizationRejected'] as exc:
            return ('error', type(exc).__name__, str(exc))
        raise AssertionError('original constructor passed the configured boundary')
    return observe


class Policy:
    def __init__(self, values, image=None):
        self.values = values
        self.module = importlib.import_module('tools.generate_hia_background_optimizer_constructor_options')
        self.calls = 0
        if image is None:
            self.image = None
            self.context = bytearray(2048)
            self.namespace = dict(length=len, byte=lambda b, at: b[at], word_load=word, store=AuthorEngine.store)
            exec(compile('from __future__ import annotations\n' + self.module.source_program(),
                         '<exact-HIA-constructor-options-author>', 'exec'), self.namespace)
            entry, context = 1, 2
        else:
            from tools.qualify_hia_multiversion_components import Image
            self.image = Image(image)
            self.context = C.create_string_buffer(2048)
            entry = values.engine.image.address
            context = C.addressof(values.engine.context)
        for at, number in ((0, int.from_bytes(b'HIABOPC1', 'little')), (8, entry), (16, context),
                           (24, 256), (32, os.getpid())):
            put(self.context, at, number)

    def call(self, raw):
        self.calls += 1
        if self.image is not None:
            out = C.create_string_buffer(32768)
            rc = self.image(raw, out, self.context) & 0xffffffff
            return rc, out.raw
        out = bytearray(32768)
        for _ in range(120):
            action = self.namespace['options'](raw, out, self.context)
            if action == 0 or action == 4294967293:
                return action, bytes(out)
            if action == 10:
                continue
            if action == 1:
                assert word(out, 0) == 39 and word(out, 8) == 0
                put(out, self.module.C['FEEDBACK'], os.getpid())
                continue
            if action == 9:
                assert (word(out, 0), word(out, 8), word(out, 48), word(out, 56)) == (1, 51, 2, 256)
                begin, count, target, extent = (word(out, at) for at in (16, 24, 32, 40))
                rc, actual = self.values.engine.call(bytes(out[begin:begin + count]), on=extent)
                out[target:target + extent] = actual
                put(out, self.module.C['FEEDBACK'], rc)
                continue
            raise AssertionError(('unexpected policy author action', action))
        raise AssertionError('constructor policy continuation did not terminate')


def actual_value(values, obj):
    if type(obj) is dict:
        result = values.keep(values.raw(4))
        for k, v in obj.items():
            key, value = actual_value(values, k), actual_value(values, v)
            values.raw(10, a=result, b=key, c=value)
            values.drop(key)
            values.drop(value)
        return result
    if type(obj) is list:
        result = values.keep(values.raw(3))
        for v in obj:
            value = actual_value(values, v)
            values.raw(16, a=result, b=value)
            values.drop(value)
        return result
    return values.scalar(obj)


def cases():
    yield 'defaults', {}
    for x in range(-2, 11):
        yield 'max-pending-' + str(x), {'max_pending': x}
    for x in range(5002):
        yield 'timeout-' + str(x), {'timeout_ms': x}
    for x in range(-2, 63):
        yield 'bridge-integer-' + str(x), {'bridge_timeout_s': x}
    floats = [-math.inf, -60.0, -1.0, -0.0, 0.0, math.nextafter(0.0, 1.0), 0.1,
              1.0, 10.0, math.nextafter(60.0, 0.0), 60.0, math.nextafter(60.0, math.inf), math.inf, math.nan]
    rng = random.Random(78415)
    floats.extend(struct.unpack('<d', struct.pack('<Q', rng.getrandbits(64)))[0] for _ in range(128))
    for i, x in enumerate(floats):
        yield 'bridge-binary64-' + str(i), {'bridge_timeout_s': x}
    for name in ('max_pending', 'timeout_ms', 'bridge_timeout_s'):
        for i, x in enumerate((None, False, True, '', '1', b'1', [], {}, 1.0, StringAlias('1'))):
            yield name + '-exact-type-' + str(i), {name: x}
        for label, x in (('huge-positive', 10 ** 100000), ('huge-negative', -(10 ** 100000))):
            yield name + '-' + label, {name: x}
    for i, bridge in enumerate((None, False, '', [], {}, {'binary': 'b'}, {'build_receipt': 'r'},
                                {'binary': 'b', 'build_receipt': 'r', 'extra': 'x'},
                                {'binary': 'b', 'wrong': 'r'}, {b'binary': 'b', 'build_receipt': 'r'},
                                {StringAlias('binary'): 'b', 'build_receipt': 'r'},
                                {'build_receipt': 'r', 'binary': 'b'},
                                {'binary': None, 'build_receipt': []})):
        yield 'bridge-keys-' + str(i), {'bridge': bridge}
    for max_pending in (False, 0, 1, 8, 9):
        for timeout_ms in (False, 0, 1, 5000, 5001):
            for bridge_timeout_s in (False, 0, 1, 60, 61):
                yield 'priority-' + '-'.join(map(str, (max_pending, timeout_ms, bridge_timeout_s))), {
                    'max_pending': max_pending, 'timeout_ms': timeout_ms, 'bridge_timeout_s': bridge_timeout_s, 'bridge': {}}


def observe_reply(out):
    assert out[:8] == b'HIABOPR1'
    status = word(out, 8)
    if status == 0:
        assert word(out, 16) == 1
        return ('ok', *(word(out, at) for at in (24, 32, 40, 48)))
    assert status == 1, out[:192].hex()
    raw = out[192:192 + word(out, 128)]
    error = json.loads(raw)
    assert set(error) == {'class', 'message'}, error
    return ('error', error['class'], error['message'])


def cleanup_author_matrix():
    module = importlib.import_module('tools.generate_hia_background_optimizer_constructor_options')
    n = dict(length=len, byte=lambda b, at: b[at], word_load=word, store=AuthorEngine.store)
    exec(compile('from __future__ import annotations\n' + module.source_program(), '<exact-options-author>', 'exec'), n)
    c = module.C
    rows = []
    for status in (0, 1, 6, 11, 999):
        for known in (0, 1):
            for consumed in (0, 1):
                for pending in (0, 1):
                    out, work = bytearray(32768), bytearray(2048)
                    put(out, c['PHASE'], 101)
                    struct.pack_into('<3Q', out, c['REFS'], 123, 456, 789)
                    for off, value in ((0, c['VR2']), (8, status), (80, pending), (88, known), (96, consumed)):
                        put(out, c['RP'] + off, value)
                    n['options'](request(), out, work)
                    valid = (known == 1 and status in (0, 1, 6, 11)
                             and (consumed == 0 or status in (0, 11))
                             and (status != 1 or pending == 0)
                             and (status != 0 or consumed == 1 and pending == 0))
                    expected_clear = valid and consumed == 1
                    assert (word(out, c['REFS']) == 0) == expected_clear, (status, known, consumed, pending)
                    success = status == 0 and known == consumed == 1 and pending == 0
                    if success:
                        assert word(out, c['PHASE']) == 100 and word(out, c['CLEAN']) == 1
                    else:
                        expected_quarantine = 1 if valid and (consumed == 0 or pending == 1) else 2
                        assert word(work, 40) == expected_quarantine, (status, known, consumed, pending)
                    rows.append({'name': 'author-op29-reply-matrix', 'status': status, 'known': known,
                                 'consumed': consumed, 'pending': pending, 'passed': True})
    for at in tuple(range(16, 80, 8)) + tuple(range(104, 128, 8)) + (80, 88, 96):
        out, work = bytearray(32768), bytearray(2048)
        put(out, c['PHASE'], 101)
        struct.pack_into('<3Q', out, c['REFS'], 123, 456, 789)
        put(out, c['RP'], c['VR2'])
        put(out, c['RP'] + 88, 1)
        put(out, c['RP'] + 96, 1)
        put(out, c['RP'] + at, 2)
        n['options'](request(), out, work)
        assert word(work, 40) == 2 and word(out, c['REFS']) == 123
        rows.append({'name': 'author-op29-malformed-reply-retains-custody', 'offset': at, 'passed': True})
    for status in (0, 6, 11):
        for pending in (0, 1):
            out, work = bytearray(32768), bytearray(2048)
            put(out, c['PHASE'], 102)
            put(out, c['PENDING'], 1)
            for off, value in ((0, c['VR2']), (8, status), (80, pending), (88, 1)):
                put(out, c['RP'] + off, value)
            n['options'](request(), out, work)
            assert (word(out, c['PENDING']) == 0) == (status == 0 and pending == 0)
            rows.append({'name': 'author-op31-only-confirmed-success-clears-pending', 'status': status, 'pending': pending, 'passed': True})
    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--author', action='store_true')
    parser.add_argument('--options-image', type=Path)
    parser.add_argument('--value-image', type=Path)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    assert args.author != bool(args.options_image or args.value_image)
    assert args.author or args.options_image and args.value_image
    original = original_constructor()
    values = Values(AuthorEngine() if args.author else NativeEngine(args.value_image))
    policy = Policy(values, args.options_image)
    rows = []
    old_limit = sys.get_int_max_str_digits()
    sys.set_int_max_str_digits(0)
    try:
        bridge = actual_value(values, {'binary': 'b', 'build_receipt': 'r'})
        for name, kwargs in cases():
            caps = [actual_value(values, kwargs[key]) if key in kwargs else ZERO
                    for key in ('max_pending', 'timeout_ms', 'bridge_timeout_s')]
            last = actual_value(values, kwargs['bridge']) if 'bridge' in kwargs else bridge
            rc, out = policy.call(request([*caps, last]))
            assert rc == 0, (name, rc)
            got, wanted = observe_reply(out), original(kwargs)
            assert got == wanted, (name, got, wanted)
            assert word(policy.context, 40) == 0
            for cap in caps:
                if cap != ZERO:
                    values.drop(cap)
            if last != bridge:
                values.drop(last)
            rows.append({'name': name, 'passed': True})
        rc, out = policy.call(request(op=1))
        assert rc == 0 and word(out, 8) == word(out, 16) == 0
        rows.append({'name': 'empty-cleanup-only', 'passed': True})
        if args.author:
            rows.extend(cleanup_author_matrix())
    finally:
        values.finish()
        sys.set_int_max_str_digits(old_limit)
    source_paths = ('tools/generate_hia_background_optimizer_constructor_options.py',
                    'examples/hia_bootstrap/background_optimizer_constructor_options.hepta')
    report = {'schema': 'hepta.hia.background-constructor-options.original-qualification.v1',
              'scope': 'development-author-transitions-only' if args.author else 'actual-native-image',
              'native_image_executed': not args.author, 'whole_native_runtime_qualified': False,
              'oracle': platform.python_implementation() + ' ' + platform.python_version(),
              'original_source_sha256': SOURCE_SHA, 'passed': len(rows), 'failed': 0,
              'value_calls': values.engine.calls, 'policy_calls': policy.calls,
              'cases': rows,
              'sources': {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in source_paths}}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: report[k] for k in ('scope', 'oracle', 'passed', 'policy_calls', 'native_image_executed')}), flush=True)


if __name__ == '__main__':
    main()
