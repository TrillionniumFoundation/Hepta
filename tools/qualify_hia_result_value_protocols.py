"""Actual native equality/hash/key semantics against the original Python objects."""
from pathlib import Path
import argparse
import ctypes as C
import dataclasses
import hashlib
import json
import math
import platform
import queue
import random
import struct
import threading

from hepta.hia_multiversion import ScalarABI, GenerationInfo
from hepta.hia_program import VerifiedProgram
from tools.qualify_hia_result_value_verified_program import Values as PriorValues
from tools.qualify_hia_result_value_resources import NativeEngine, frame, word, ZERO


class Values(PriorValues):
    def raw(self, op, *, want=0, on=16384, **kw):
        if op not in (62, 63):
            return super().raw(op, want=want, on=on, **kw)
        wire = bytearray(frame(op, **kw))
        wire[:8] = b'HIABVQ05'
        rc, out = self.engine.call(bytes(wire), on=on)
        assert rc == 0 and out[:8] == b'HIABVR01', (op, rc, out[:128].hex())
        assert word(out, 8) == want, (op, word(out, 8), want, out[:128].hex())
        return out

    def equal(self, a, b):
        out = self.raw(62, a=a, b=b)
        assert word(out, 16) == 1 and word(out, 48) in (0, 1)
        return bool(word(out, 48))

    def hash(self, a):
        out = self.raw(63, a=a)
        assert word(out, 16) == 2 and out[24:48] == bytes(24)
        value = word(out, 48)
        return value if value < 1 << 63 else value - (1 << 64)

    def get(self, container, key):
        return self.keep(self.raw(9, a=container, b=key))


def make(v, value):
    if type(value) in (ScalarABI, GenerationInfo, VerifiedProgram):
        fields = [make(v, getattr(value, f.name)) for f in dataclasses.fields(value)]
        if type(value) is ScalarABI:
            cap = v.keep(v.raw(41, a=fields[0], b=fields[1], c=fields[2]))
        elif type(value) is GenerationInfo:
            packed = v.tuple(fields)
            cap = v.keep(v.raw(42, a=packed))
            v.drop(packed)
        else:
            cap = v.program(*fields)
        for field in fields:
            v.drop(field)
        return cap
    if type(value) in (tuple, list):
        fields = [make(v, x) for x in value]
        cap = v.tuple(fields) if type(value) is tuple else v.lst(fields)
        for field in fields:
            v.drop(field)
        return cap
    if type(value) is dict:
        cap = v.keep(v.raw(4))
        for key, item in value.items():
            k, child = make(v, key), make(v, item)
            v.raw(10, a=cap, b=k, c=child)
            v.drop(k)
            v.drop(child)
        return cap
    return v.scalar(value)


def clear(v):
    for cap in list(v.held):
        v.drop(cap)
    assert word(v.raw(47), 48) == 0


def record_fields(v, cap, n):
    fields = [v.field(cap, i) for i in range(n)]
    result = v.tuple(fields)
    for field in fields:
        v.drop(field)
    return result


def deny_growth():
    class Filter(C.Structure):
        _fields_ = [('code', C.c_ushort), ('jt', C.c_ubyte),
                    ('jf', C.c_ubyte), ('k', C.c_uint)]
    class Program(C.Structure):
        _fields_ = [('length', C.c_ushort), ('filters', C.POINTER(Filter))]
    instructions = (Filter * 4)(
        Filter(0x20, 0, 0, 0), Filter(0x15, 0, 1, 25),
        Filter(0x06, 0, 0, 0x00050000 | 12), Filter(0x06, 0, 0, 0x7fff0000))
    program = Program(len(instructions), instructions)
    libc = C.CDLL(None, use_errno=True)
    assert libc.prctl(38, 1, 0, 0, 0) == 0, C.get_errno()
    assert libc.prctl(22, 2, C.byref(program), 0, 0) == 0, C.get_errno()


def allocation_failure(v):
    left = make(v, (1,))
    right = make(v, (1,))
    for _ in range(64):
        a, b = v.tuple([left]), v.tuple([right])
        v.drop(left)
        v.drop(right)
        left, right = a, b
    table = make(v, {'unchanged': 7})
    value = v.scalar(9)
    initial_caps = word(v.raw(47), 48)
    result = queue.Queue()
    def worker():
        tokens = []
        try:
            deny_growth()
            extent = word(v.engine.context.raw, 40)
            for _ in range(65536):
                rc, out = v.engine.call(frame(21))
                assert rc == 0 and out[:8] == b'HIABVR01'
                if word(out, 8):
                    assert word(out, 8) == 5 and out[24:48] == bytes(24)
                    break
                tokens.append(struct.unpack_from('<3Q', out, 24))
            else:
                raise AssertionError('native arena did not reach refused kernel mremap')
            assert len(tokens) >= 8
            for _ in range(4):
                raw = v.raw(30, a=tokens.pop())
                assert (word(raw, 88), word(raw, 96)) == (1, 1)
            count = word(v.raw(47), 48)
            v.raw(63, a=left, want=5)
            v.raw(62, a=left, b=right, want=5)
            v.raw(10, a=table, b=left, c=value, want=5)
            assert word(v.raw(47), 48) == count
            assert word(v.engine.context.raw, 40) == extent
            result.put((tokens, dict(kernel_mremap_errno=12, retained_context_tokens=len(tokens),
                                    hash_and_equality_and_dict_insert_refused=True,
                                    no_cap_leak_or_table_mutation=True)))
        except BaseException as error:
            result.put((tokens, error))
    thread = threading.Thread(target=worker)
    thread.start()
    thread.join(120)
    assert not thread.is_alive()
    tokens, result = result.get_nowait()
    for cap in tokens:
        out = v.raw(30, a=cap)
        assert (word(out, 88), word(out, 96)) == (1, 1)
    if isinstance(result, BaseException):
        raise result
    assert word(v.raw(47), 48) == initial_caps
    assert v.python_value(table) == {'unchanged': 7}
    assert v.equal(left, right) and v.hash(left) == v.hash(right)
    v.raw(10, a=table, b=left, c=value)
    retrieved = v.get(table, right)
    assert v.python(retrieved) == 9
    v.drop(retrieved)
    clear(v)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    assert platform.python_version() == '3.14.4' and platform.machine() == 'x86_64'
    args.output.mkdir(parents=True, exist_ok=False)
    v = Values(NativeEngine(args.image))
    rows = []
    def add(case, **details):
        rows.append(dict(case=case, **details))
        (args.output / 'progress.json').write_text(json.dumps(rows, indent=2) + '\n')
        print('PROTOCOL_CASE', case, flush=True)

    numbers = [None, False, True, 0, 1, -1, 2**61-1, -(2**61-1), 2**61,
               2**64-1, -(2**300), 10**300+7, 0.0, -0.0, 1.0, -1.0,
               0.25, -2.5, float(2**61), float('inf'), -float('inf'),
               float.fromhex('0x0.0000000000001p-1022'),
               float.fromhex('0x1.fffffffffffffp+1023')]
    caps = [make(v, x) for x in numbers]
    comparisons = 0
    for i, a in enumerate(numbers):
        assert v.hash(caps[i]) == hash(a), (a, v.hash(caps[i]), hash(a))
        for j, b in enumerate(numbers):
            assert v.equal(caps[i], caps[j]) == (a == b), (a, b)
            if a == b:
                assert v.hash(caps[i]) == v.hash(caps[j])
            comparisons += 1
    randomizer = random.Random(620130)
    for _ in range(256):
        number = struct.unpack('<d', struct.pack('<Q', randomizer.getrandbits(64)))[0]
        cap = v.scalar(number)
        if math.isnan(number):
            assert not v.equal(cap, cap) and v.hash(cap) == v.hash(cap)
        else:
            assert v.hash(cap) == hash(number), (number, v.hash(cap), hash(number))
        v.drop(cap)
    clear(v)
    add('numeric-cross-kind-equality-and-real-python-hash', comparisons=comparisons,
        additional_binary64_patterns=256)

    structures = [
        (), (1,), (True, 2.5, None), ((1, 2), (3, (4,))), ('x', b'x', '\ud800'),
        [], [1, {'a': (2, 3)}], {'a': [1, 2], 'b': (3,)},
        ScalarABI('f', ('i64',), 'i64'), ScalarABI(1, (True,), None),
        VerifiedProgram(b'{}'), VerifiedProgram(1, (True, None)),
        GenerationInfo(1, 'p', 'i', 'a', 5, (ScalarABI('f', (), 'i64'),), 2, 3, True)]
    for original in structures:
        a, b = make(v, original), make(v, original)
        assert v.equal(a, b) and v.equal(a, a)
        try:
            expected = hash(original)
        except TypeError:
            v.raw(63, a=a, want=2)
        else:
            assert v.hash(a) == v.hash(b)
            if isinstance(original, (ScalarABI, GenerationInfo, VerifiedProgram)):
                fields = record_fields(v, a, len(dataclasses.fields(original)))
                assert v.hash(a) == v.hash(fields)
                v.drop(fields)
            if original in ((), (1,), (True, 2.5, None), ((1, 2), (3, (4,)))) or original == ScalarABI(1, (True,), None) or original == VerifiedProgram(1, (True, None)):
                assert v.hash(a) == expected
        v.drop(a)
        v.drop(b)
    for a, b in [((1,), [1]), ((), []), ((1,), (2,)),
                 (ScalarABI('f', (), 'i64'), ('f', (), 'i64')),
                 ({'a': 1, 'b': 2}, {'b': 2, 'a': 1}),
                 ({'a': 1}, {'a': 2}), ([{'x': [1]}], [{'x': [2]}])]:
        left, right = make(v, a), make(v, b)
        assert v.equal(left, right) == (a == b), (a, b)
        v.drop(left)
        v.drop(right)
    clear(v)
    add('tuple-list-dict-and-real-dataclass-equality-and-hash', structures=len(structures))

    table = make(v, {})
    originals = [(1, 2), (True, 2.0), ((1,), ('x', b'y')),
                 ScalarABI('f', ('i64',), 'i64'),
                 VerifiedProgram(b'{}'), VerifiedProgram(4, (1, 2))]
    oracle = {}
    for index, original in enumerate(originals):
        key, value = make(v, original), v.scalar(index)
        v.raw(10, a=table, b=key, c=value)
        oracle[original] = index
        assert word(v.raw(17, a=table), 48) == len(oracle)
        v.drop(key)
        v.drop(value)
    for original, expected in oracle.items():
        key = make(v, original)
        result = v.get(table, key)
        assert v.python(result) == expected
        v.drop(result)
        v.raw(11, a=table, b=key)
        v.raw(9, a=table, b=key, want=3)
        v.drop(key)
    assert word(v.raw(17, a=table), 48) == 0
    clear(v)
    add('actual-tuple-and-dataclass-dict-key-replace-lookup-delete',
        original_insertions=len(originals), unique_keys=len(oracle))

    same_nan = float('nan')
    other_nan = float('nan')
    n, m = v.scalar(same_nan), v.scalar(other_nan)
    assert not v.equal(n, n) and not v.equal(n, m)
    ta, tb, tc = v.tuple([n]), v.tuple([n]), v.tuple([m])
    la, lb = v.lst([n]), v.lst([n])
    none = v.scalar(None)
    ra, rb = v.program(n), v.program(n)
    assert v.equal(ta, tb) == ((same_nan,) == (same_nan,))
    assert not v.equal(ta, tc)
    assert v.equal(la, lb) == ([same_nan] == [same_nan])
    assert v.equal(ra, ra) and not v.equal(ra, rb)
    assert VerifiedProgram(same_nan) != VerifiedProgram(same_nan)
    assert v.hash(ra) == v.hash(rb)
    table = make(v, {})
    marker = v.scalar(31)
    v.raw(10, a=table, b=ta, c=marker)
    got = v.get(table, tb)
    assert v.python(got) == 31
    v.drop(got)
    v.raw(9, a=table, b=tc, want=3)
    v.raw(10, a=table, b=ra, c=marker)
    got = v.get(table, ra)
    assert v.python(got) == 31
    v.drop(got)
    v.raw(9, a=table, b=rb, want=3)
    clear(v)
    add('nan-identity-differs-between-tuple-and-python314-dataclass-fields')

    base = v.builtin(36)
    cls = v.cls('ProgramSubclass', [base])
    cls2 = v.cls('ProgramSubclass', [base])
    leftfield = v.scalar(1)
    rightfield = v.scalar(1.0)
    exact = v.program(leftfield)
    sub = v.program(leftfield, cls=cls)
    equal_sub = v.program(rightfield, cls=cls)
    other_sub = v.program(leftfield, cls=cls2)
    assert not v.equal(exact, sub) and v.equal(sub, equal_sub) and not v.equal(sub, other_sub)
    assert v.hash(exact) == v.hash(sub) == v.hash(equal_sub) == v.hash(other_sub)
    tupleclass = v.cls('TupleSubclass', [v.builtin(28)])
    tuplebase = make(v, (1, 2))
    inherited = v.inherited(tupleclass, tuplebase)
    compare = make(v, (1.0, 2.0))
    assert v.equal(inherited, compare) and v.hash(inherited) == v.hash(compare)
    table = make(v, {})
    v.raw(10, a=table, b=inherited, c=sub)
    got = v.get(table, compare)
    assert v.same(got, sub)
    v.drop(got)
    clear(v)
    add('exact-dataclass-class-identity-and-real-tuple-subclass-keys')

    mutable = [1, {'x': 2}]
    for original in ((mutable,), ScalarABI('f', mutable, 'i64'),
                     VerifiedProgram(mutable), VerifiedProgram({'x': 1})):
        a, b = make(v, original), make(v, original)
        assert v.equal(a, b)
        v.raw(63, a=a, want=2)
        table, item = make(v, {'prior': 7}), v.scalar(8)
        v.raw(10, a=table, b=a, c=item, want=2)
        assert v.python_value(table) == {'prior': 7}
        clear(v)
    add('unhashable-fields-preserve-table-and-original-error')

    a, b = v.lst([]), v.lst([])
    v.raw(16, a=a, b=a)
    v.raw(16, a=b, b=b)
    assert v.equal(a, a)
    v.raw(62, a=a, b=b, want=23)
    left, right = [], []
    left.append(left)
    right.append(right)
    try:
        left == right
    except RecursionError:
        pass
    else:
        raise AssertionError('original recursive comparison did not fail')
    clear(v)
    add('cyclic-comparison-reports-recursion-without-losing-graph-custody')

    a, b = make(v, (1,)), make(v, (1.0,))
    original_a, original_b = (1,), (1.0,)
    for _ in range(256):
        na, nb = v.tuple([a]), v.tuple([b])
        v.drop(a)
        v.drop(b)
        a, b = na, nb
        original_a, original_b = (original_a,), (original_b,)
    assert v.equal(a, b) == (original_a == original_b)
    assert v.hash(a) == v.hash(b) == hash(original_a)
    for _ in range(8):
        assert v.equal(a, b) and v.hash(a) == hash(original_a)
    clear(v)
    add('deep-immutable-graph-uses-native-work-stack', depth=257)

    add('real-kernel-allocation-failure', **allocation_failure(v))

    a, b = v.scalar(1), v.scalar(2)
    count = word(v.raw(47), 48)
    v.raw(62, a=(1, 1, 1), b=b, want=1)
    v.raw(62, a=a, b=(1, 1, 1), want=1)
    v.raw(63, a=(1, 1, 1), want=1)
    assert word(v.raw(47), 48) == count
    before = v.engine.context.raw
    malformed = []
    for op in (62, 63):
        valid = bytearray(frame(op))
        valid[:8] = b'HIABVQ05'
        for magic in (b'HIABVQ01', b'HIABVQ02', b'HIABVQ03', b'HIABVQ04'):
            wire = bytearray(valid)
            wire[:8] = magic
            malformed.append(bytes(wire))
        for at in (16, 72, 80, 88, 96, 104, 112, 120):
            wire = bytearray(valid)
            struct.pack_into('<Q', wire, at, 1)
            malformed.append(bytes(wire))
        if op == 63:
            for at in (48, 56, 64):
                wire = bytearray(valid)
                struct.pack_into('<Q', wire, at, 1)
                malformed.append(bytes(wire))
        malformed += [bytes(valid[:-1]), bytes(valid) + b'\0']
    for wire in malformed:
        rc, _ = v.engine.call(wire)
        assert rc == 0xfffffffd and v.engine.context.raw == before
    clear(v)
    add('private-cap-and-protocol-wire-guards', controls=len(malformed), invalid_caps=3)
    v.finish()
    report = dict(schema='hia.native-value-protocols.qualification.v1',
                  passed=True, actual_native_image=True, oracle=platform.python_version(),
                  image_sha256=hashlib.sha256(args.image.read_bytes()).hexdigest(),
                  groups=rows, tuple_record_default_equality_hash_qualified=True,
                  actual_dict_tuple_record_keys_qualified=True,
                  python314_dataclass_nan_identity_qualified=True,
                  native_custom_method_dispatch_qualified=False,
                  whole_public_runtime_qualified=False)
    (args.output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(dict(passed=True, groups=len(rows))), flush=True)


if __name__ == '__main__':
    main()
