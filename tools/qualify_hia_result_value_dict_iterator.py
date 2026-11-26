"""Original dict comparisons for the live HIA iterator.

--image executes the supplied native value image. --author executes the exact
development author functions in Python; that mode is never native qualification.
The original oracle is the running CPython dictionary, not a mutation model.
"""
from __future__ import annotations

import argparse
import ctypes as C
import hashlib
import importlib
import json
import os
from pathlib import Path
import platform
import random
import struct

MASK = (1 << 64) - 1
ZERO = (0, 0, 0)


def word(data, at):
    return struct.unpack_from('<Q', data, at)[0]


def put(data, at, value):
    struct.pack_into('<Q', data, at, value & MASK)


def wire(op, a=ZERO, b=ZERO, c=ZERO, arg0=0, arg1=0, tail=b''):
    data = bytearray(128 + len(tail))
    data[:8] = b'HIABVQ02' if 25 <= op <= 31 else b'HIABVQ01'
    for at, value in ((8, op), (96, len(tail)), (104, arg0), (112, arg1)):
        put(data, at, value)
    for at, cap in ((24, a), (48, b), (72, c)):
        struct.pack_into('<3Q', data, at, *cap)
    data[128:] = tail
    return bytes(data)


class NativeEngine:
    scope = 'actual-native-image'

    def __init__(self, path):
        from tools.qualify_hia_multiversion_components import Image
        self.image = Image(path)
        self.context = C.create_string_buffer(256)
        self.calls = 0
        rc, out = self.call(wire(0, arg0=4300))
        assert rc == 0 and word(out, 8) == 0, (rc, out[:128].hex())

    def call(self, request, on=16384):
        out = C.create_string_buffer(on)
        rc = self.image(request, out, self.context) & 0xffffffff
        self.calls += 1
        return rc, out.raw

    def finish(self):
        rc, out = self.call(wire(30))
        assert rc == 0 and out[:8] == b'HIABVR02'
        assert (word(out, 8), word(out, 80), word(out, 88), word(out, 96)) == (0, 0, 1, 1)


class AuthorEngine:
    scope = 'development-author-transitions-only'

    def __init__(self, unused=None):
        common = importlib.import_module('tools.generate_hia_result_value_common')
        core = importlib.import_module('tools.generate_hia_result_value_core')
        iterator = importlib.import_module('tools.generate_hia_result_value_dict_iterator')
        owner = importlib.import_module('tools.generate_hia_result_value_owner')
        self.ns = dict(common.C)
        self.ns.update(length=len, byte=lambda b, i: b[i], store=self.store)
        exact = core.SOURCE + '\n' + iterator.SOURCE + '\n' + owner.SOURCE + '\n' + common.SOURCE
        exec(compile('from __future__ import annotations\n' + exact,
                     '<exact-HIA-development-authors>', 'exec'), self.ns)
        self.w = bytearray(65536)
        self.calls = 0
        self.growth_failures = 0
        self.allocation_fault = None
        self.allocation_attempts = 0
        self.real_allocate = self.ns['allocate']
        self.ns['allocate'] = self.allocate
        out = bytearray(16384)
        put(out, common.C['G_PHASE'], 90)
        put(out, common.C['G_TAG0'], 18446744073709551557)
        put(out, common.C['G_INPUT'], 4300)
        assert self.ns['result_value_core'](b'', out, self.w) == 0

    @staticmethod
    def store(data, at, value):
        data[at] = value & 255

    def allocate(self, arena, count):
        self.allocation_attempts += 1
        if self.allocation_fault is not None and self.allocation_attempts >= self.allocation_fault:
            put(arena, 16, max(word(arena, 16), count + 32))
            return 0
        return self.real_allocate(arena, count)

    def call(self, request, on=16384):
        self.calls += 1
        out = bytearray(on)
        op = word(request, 8)
        n = self.ns
        if op in (29, 30, 31):
            put(out, n['P_DROP_KNOWN'], 1)
        entry = n['result_value_dict_iterator'] if op in (27, 28) else n['result_value_core']
        for _ in range(80):
            action = entry(request, out, self.w)
            if action == 0:
                n['finish'](request, out, word(out, n['P_ERROR']))
                return 0, bytes(out)
            if action == 10:
                continue
            if action == 1:
                if self.allocation_fault is not None:
                    self.growth_failures += 1
                    put(out, n['G_ALLOC_FAILED'], 1)
                    continue
                old = len(self.w)
                wanted = word(out, n['G_WANT'])
                assert wanted > old and wanted & (wanted - 1) == 0
                self.w.extend(bytes(wanted - old))
                n['arena_extend'](self.w, old)
                put(out, n['G_ALLOC_FAILED'], 0)
                continue
            if action == 5:
                at = word(out, n['G_RANDOM']) + word(out, n['G_RUSED'])
                count = word(out, n['G_RN']) - word(out, n['G_RUSED'])
                self.w[at:at + count] = os.urandom(count)
                put(out, n['G_FEEDBACK'], count)
                continue
            if action == 4 and word(out, n['P_ROLE']) == 5:
                # Development-only external formatter dependency. Native mode
                # calls the real captured HIA formatter through its image.
                value = struct.unpack_from('<d', out, 1408)[0]
                lexical = repr(value).encode('ascii')
                assert len(lexical) <= 32
                out[1440:1440 + len(lexical)] = lexical
                put(out, n['G_FEEDBACK'], len(lexical))
                continue
            raise AssertionError(('unexpected development author action', op, action))
        raise AssertionError(('unbounded development author continuation', op, word(out, n['G_PHASE'])))

    def finish(self):
        assert word(self.w, 88) == 0, ('remaining real capability nodes', word(self.w, 88))
        self.ns['collect'](self.w)
        assert word(self.w, 104) == 3, ('remaining non-singleton graph objects', word(self.w, 104))


class StringAlias(str):
    pass


class Values:
    def __init__(self, engine):
        self.engine = engine
        self.held = set()

    def raw(self, op, *, want=0, on=16384, **kw):
        rc, out = self.engine.call(wire(op, **kw), on=on)
        assert rc == 0 and out[:8] == (b'HIABVR02' if op in (29, 30, 31) else b'HIABVR01'), (op, rc, out[:128].hex())
        assert word(out, 8) == want, (op, word(out, 8), want)
        return out

    def keep(self, out, at=24):
        cap = struct.unpack_from('<3Q', out, at)
        assert cap[0] and cap not in self.held
        self.held.add(cap)
        return cap

    def drop(self, cap):
        assert cap in self.held, cap
        out = self.raw(29, a=cap)
        assert (word(out, 80), word(out, 88), word(out, 96)) == (0, 1, 1)
        self.held.remove(cap)

    def scalar(self, value):
        if type(value) is StringAlias:
            env = self.scalar(None)
            base = self.scalar(str(value))
            name = self.scalar('StringAlias')
            result = self.keep(self.raw(25, a=env, b=base, c=name, arg0=4))
            for cap in (env, base, name):
                self.drop(cap)
            return result
        if value is None:
            kind, tail, arg1 = 0, b'', 0
        elif type(value) is bool:
            kind, tail, arg1 = 1, b'', int(value)
        elif type(value) is int:
            kind, tail, arg1 = 2, str(value).encode(), 0
        elif type(value) is float:
            kind, tail, arg1 = 3, struct.pack('<d', value), 0
        elif type(value) is str:
            kind, tail, arg1 = 4, value.encode('utf-8', 'surrogatepass'), 0
        elif type(value) is bytes:
            kind, tail, arg1 = 7, value, 0
        else:
            raise TypeError(type(value))
        return self.keep(self.raw(2, arg0=kind, arg1=arg1, tail=tail))

    def python(self, cap):
        out = self.raw(7, a=cap)
        kind, count = word(out, 16), word(out, 72)
        if kind == 0:
            return None
        if kind == 8:
            info = self.raw(26, a=cap)
            children = [self.keep(info, 8224 + i * 24) for i in range(3)]
            assert word(info, 8200) == 4
            result = StringAlias(self.python(children[1]))
            for child in children:
                self.drop(child)
            return result
        data = self.raw(19, a=cap, arg1=count, on=max(16384, 8192 + count))[8192:8192 + count]
        if kind == 1:
            return bool(data[0])
        if kind == 2:
            return int(data)
        if kind == 4:
            return data.decode('utf-8', 'surrogatepass')
        if kind == 7:
            return data
        raise AssertionError(('unexpected scalar kind', kind))

    def dictionary(self, items):
        cap = self.keep(self.raw(4))
        for key, value in items:
            self.set(cap, key, value)
        return cap

    def set(self, dictionary, key, value):
        k, v = self.scalar(key), self.scalar(value)
        self.raw(10, a=dictionary, b=k, c=v)
        self.drop(k)
        self.drop(v)

    def delete(self, dictionary, key):
        k = self.scalar(key)
        self.raw(11, a=dictionary, b=k)
        self.drop(k)

    def iterator(self, dictionary, mode):
        return self.keep(self.raw(27, a=dictionary, arg0=mode))

    def next_caps(self, iterator, mode, *, on=16384):
        rc, out = self.engine.call(wire(28, a=iterator), on=on)
        assert rc == 0 and out[:8] == b'HIABVR01', (rc, out[:128].hex())
        status = word(out, 8)
        if status in (14, 15):
            return ('error', 'dictionary changed size during iteration' if status == 14 else 'dictionary keys changed during iteration')
        if status == 13:
            assert word(out, 72) == 8256
            return ('short', 8256)
        assert status == 0, (status, out[:128].hex())
        rows = word(out, 64)
        assert rows in (0, 1), rows
        if rows == 0:
            return ('end',)
        assert word(out, 72) == 8256
        key = self.keep(out, 8208) if mode != 2 else None
        value = self.keep(out, 8232) if mode != 0 else None
        return ('row', key, value)

    def next(self, iterator, mode):
        result = self.next_caps(iterator, mode)
        if result[0] != 'row':
            return result
        _, key, value = result
        pykey = self.python(key) if key is not None else None
        pyvalue = self.python(value) if value is not None else None
        for cap in (key, value):
            if cap is not None:
                self.drop(cap)
        return ('value', pykey if mode == 0 else (pykey, pyvalue) if mode == 1 else pyvalue)

    def finish(self):
        while self.held:
            self.drop(next(iter(self.held)))
        self.engine.finish()


def oracle_next(iterator):
    try:
        return ('value', next(iterator))
    except StopIteration:
        return ('end',)
    except RuntimeError as exc:
        return ('error', str(exc))


def run_case(factory, name, items, actions, mode):
    values = Values(factory())
    actual = values.dictionary(items)
    expected = dict(items)
    native_iter = values.iterator(actual, mode)
    original_iter = iter(expected if mode == 0 else expected.items() if mode == 1 else expected.values())
    compared = 0
    try:
        for action in actions:
            if action == 'next':
                got, want = values.next(native_iter, mode), oracle_next(original_iter)
                assert got == want, (name, mode, compared, got, want)
                compared += 1
            elif action[0] == 'set':
                _, key, value = action
                values.set(actual, key, value)
                expected[key] = value
            elif action[0] == 'del':
                values.delete(actual, action[1])
                del expected[action[1]]
            else:
                raise AssertionError(action)
        for _ in range(len(expected) + 3):
            got, want = values.next(native_iter, mode), oracle_next(original_iter)
            assert got == want, (name, mode, 'drain', compared, got, want)
            compared += 1
        return {'name': name, 'mode': mode, 'compared_next': compared, 'calls': values.engine.calls, 'passed': True}
    finally:
        values.finish()


def mutation_cases():
    for count in (0, 1, 2, 4, 5, 6, 10, 21, 22, 42):
        yield 'ordinary-' + str(count), [(str(i), i) for i in range(count)], []
    yield 'replace-future-value', [('a', 1), ('b', 2)], ['next', ('set', 'b', 20), 'next']
    yield 'sticky-delete-size-error', [('a', 1), ('b', 2)], ['next', ('del', 'b'), 'next', ('set', 'b', 2), 'next']
    yield 'sticky-insert-size-error', [('a', 1), ('b', 2)], ['next', ('set', 'c', 3), 'next', ('del', 'c'), 'next']
    yield 'same-size-consumed-key-replaced', [('a', 1), ('b', 2)], ['next', ('del', 'a'), ('set', 'c', 3)]
    yield 'same-size-unseen-key-replaced', [('a', 1), ('b', 2)], ['next', ('del', 'b'), ('set', 'c', 3)]
    yield 'resize-before-first-next', [(str(i), i) for i in range(5)], [('del', '0'), ('set', 'x', 99)]
    yield 'compact-after-two-yields', [(str(i), i) for i in range(5)], ['next', 'next', ('del', '0'), ('set', 'x', 99)]
    yield 'general-conversion-equal-key', [(str(i), i) for i in range(5)], ['next', ('del', '0'), ('set', 'x', 99), ('set', StringAlias('4'), 44)]
    yield 'general-conversion-after-delete', [(str(i), i) for i in range(5)], ['next', ('del', '0'), ('set', StringAlias('4'), 44), ('set', 'x', 99)]
    yield 'nonstring-key-conversion', [(str(i), i) for i in range(5)], ['next', ('del', '0'), ('set', 0, 99)]
    yield 'mutation-after-exhaustion', [('a', 1)], ['next', 'next', ('set', 'b', 2), 'next']
    for seed in range(32):
        randomizer = random.Random(seed)
        count = randomizer.randrange(1, 24)
        initial = [(str(i), i) for i in range(count)]
        model = dict(initial)
        actions = []
        for i in range(24):
            choice = randomizer.randrange(5)
            if choice < 2 or not model:
                actions.append('next')
            elif choice == 2:
                key = randomizer.choice(list(model))
                actions.append(('set', key, i * 31))
                model[key] = i * 31
            elif choice == 3:
                key = randomizer.choice(list(model))
                actions.append(('del', key))
                del model[key]
                replacement = 'new-' + str(i)
                actions.append(('set', replacement, i))
                model[replacement] = i
            else:
                key = StringAlias(randomizer.choice(list(model)))
                actions.append(('set', key, -i))
                model[key] = -i
        yield 'random-mutations-' + str(seed), initial, actions


def ownership_cases(factory):
    rows = []
    for mode in range(3):
        v = Values(factory())
        d = v.dictionary([('a', 17), ('b', 29)])
        i = v.iterator(d, mode)
        assert v.next_caps(i, mode, on=8192) == ('short', 8256)
        v.drop(d)
        row = v.next_caps(i, mode)
        assert row[0] == 'row'
        v.drop(i)
        if row[1] is not None:
            assert v.python(row[1]) == 'a'
        if row[2] is not None:
            assert v.python(row[2]) == 17
        v.finish()
        rows.append({'name': 'short-output-does-not-advance-and-owned-results-outlive-parents', 'mode': mode, 'passed': True})
    v = Values(factory())
    d = v.dictionary([('a', 1)])
    i = v.iterator(d, 1)
    key = v.scalar('iterator-cycle')
    v.raw(10, a=d, b=key, c=i)
    v.drop(key)
    v.drop(d)
    v.drop(i)
    v.finish()
    rows.append({'name': 'unreachable-dictionary-iterator-cycle-collected', 'passed': True})
    v = Values(factory())
    d = v.dictionary([('a', 1)])
    i, other = v.iterator(d, 0), v.iterator(d, 0)
    table = v.dictionary([])
    value = v.scalar(33)
    v.raw(10, a=table, b=i, c=value)
    alias = v.keep(v.raw(5, a=i))
    result = v.keep(v.raw(9, a=table, b=alias))
    assert v.python(result) == 33
    v.raw(9, a=table, b=other, want=3)
    v.finish()
    rows.append({'name': 'iterator-identity-hash-and-retained-key-identity', 'passed': True})
    return rows


def author_allocation_cases():
    rows = []
    for operation, failures in ((27, range(1, 5)), (28, range(1, 4))):
        for failure in failures:
            engine = AuthorEngine()
            v = Values(engine)
            d = v.dictionary([('a', 1), ('b', 2)])
            iterator = v.iterator(d, 1) if operation == 28 else None
            before_caps = word(engine.w, 88)
            before_objects = word(engine.w, 104)
            engine.allocation_attempts = 0
            engine.allocation_fault = failure
            out = v.raw(operation, a=d if operation == 27 else iterator, arg0=1 if operation == 27 else 0, want=5)
            assert word(engine.w, 88) == before_caps
            assert word(engine.w, 104) == before_objects
            assert engine.growth_failures == 2, engine.growth_failures
            engine.allocation_fault = None
            if operation == 28:
                assert v.next(iterator, 1) == ('value', ('a', 1))
            else:
                iterator = v.iterator(d, 1)
                assert v.next(iterator, 1) == ('value', ('a', 1))
            v.finish()
            rows.append({'name': 'author-persistent-allocation-refusal', 'operation': operation, 'allocation': failure, 'passed': True})
    engine = AuthorEngine()
    v = Values(engine)
    d = v.dictionary([('a', 1)])
    key, value = v.scalar(StringAlias('new')), v.scalar(2)
    engine.allocation_attempts = 0
    engine.allocation_fault = 1
    v.raw(10, a=d, b=key, c=value, want=5)
    assert engine.growth_failures == 2
    engine.allocation_fault = None
    v.raw(9, a=d, b=key, want=3)
    original_key=v.scalar('a')
    result=v.keep(v.raw(9,a=d,b=original_key))
    assert v.python(result)==1
    v.drop(original_key)
    v.raw(10, a=d, b=key, c=value)
    result = v.keep(v.raw(9, a=d, b=key))
    assert v.python(result) == 2
    v.finish()
    rows.append({'name': 'author-dictionary-conversion-persistent-growth-refusal-preserves-value', 'passed': True})
    return rows


def main():
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--image', type=Path)
    mode.add_argument('--author', action='store_true')
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    factory = AuthorEngine if args.author else lambda: NativeEngine(args.image)
    rows = [run_case(factory, name, items, actions, mode)
            for name, items, actions in mutation_cases() for mode in range(3)]
    rows.extend(ownership_cases(factory))
    if args.author:
        rows.extend(author_allocation_cases())
    root = Path(__file__).resolve().parents[1]
    sources = {}
    for role in ('common', 'core', 'owner', 'dict_iterator'):
        source = root / 'tools' / ('generate_hia_result_value_' + role + '.py')
        raw = source.read_bytes()
        sources[str(source.relative_to(root))] = {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
    report = {
        'schema': 'hepta.hia.result-value-live-dict-iterator.qualification.v1',
        'scope': AuthorEngine.scope if args.author else NativeEngine.scope,
        'native_image_executed': not args.author,
        'whole_native_runtime_qualified': False,
        'oracle': platform.python_implementation() + ' ' + platform.python_version(),
        'native_image': None if args.author else {'path': str(args.image), 'sha256': hashlib.sha256(args.image.read_bytes()).hexdigest()},
        'sources': sources,
        'cases': rows,
        'passed': len(rows),
        'compared_next': sum(row.get('compared_next', 0) for row in rows),
        'failed': 0,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: report[k] for k in ('scope', 'oracle', 'passed', 'compared_next', 'native_image_executed')}), flush=True)


if __name__ == '__main__':
    main()
