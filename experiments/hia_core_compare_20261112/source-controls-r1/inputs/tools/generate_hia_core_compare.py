"""Author exact numeric comparison control, independent of Python comparison.

The HIA owner classifies IEEE-754 values, orders signed arbitrary-size integer
magnitudes through fixed limb windows, aligns mixed finite dyadic numbers and
chooses the six predicates. Python only transports exact builtin values.
"""
from __future__ import annotations

import ast
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

MAGIC = int.from_bytes(b'HIACMP01', 'little')
SOURCE = r'''
def compare(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) != 256 or length(o) != 128 or length(w) != 512:
        return refuse(w)
    if read(s, 0) != COMPARE_MAGIC:
        return refuse(w)
    if get(w, 0) == 0:
        at = 0
        while at < 512:
            if get(w, at) != 0:
                return refuse(w)
            at = at + 8
        if read(s, 8) != 0 or read(s, 16) != 0:
            return refuse(w)
        operation = read(s, 24)
        if operation < 1 or operation > 6:
            return refuse(w)
        at = 80
        while at < 256:
            if read(s, at) != 0:
                return refuse(w)
            at = at + 8
        side = 0
        while side < 2:
            record = 32 + side * 24
            kind = read(s, record)
            size = read(s, record + 8)
            scalar = read(s, record + 16)
            if kind < 1 or kind > 3:
                return refuse(w)
            if kind == 1:
                if size != 0 or scalar > 1:
                    return refuse(w)
            elif kind == 2:
                top = scalar & 63
                if scalar > 127 or top > 32:
                    return refuse(w)
                if size == 0:
                    if scalar != 0:
                        return refuse(w)
                elif top == 0:
                    return refuse(w)
            elif size != 0:
                return refuse(w)
            put(w, record, kind)
            put(w, record + 8, size)
            put(w, record + 16, scalar)
            side = side + 1
        put(w, 0, COMPARE_MAGIC)
        put(w, 24, operation)
        if classification(w, 32) == 2 or classification(w, 56) == 2:
            return complete(o, w, 3)
        left_sign = number_sign(w, 32)
        right_sign = number_sign(w, 56)
        if left_sign != right_sign:
            return complete(o, w, choose(left_sign == 1, 0, 2))
        put(w, 80, left_sign)
        left_class = classification(w, 32)
        right_class = classification(w, 56)
        if left_class != 0 or right_class != 0:
            return finish_magnitude(o, w, scalar_relation(left_class, right_class))
        left_kind = get(w, 32)
        right_kind = get(w, 56)
        if left_kind == 3 and right_kind == 3:
            left = get(w, 48) & 9223372036854775807
            right = get(w, 72) & 9223372036854775807
            return finish_magnitude(o, w, scalar_relation(left, right))
        if left_kind != 3 and right_kind != 3:
            left_words = integer_words(w, 32)
            right_words = integer_words(w, 56)
            if left_words != right_words:
                return finish_magnitude(o, w, scalar_relation(left_words, right_words))
            left_top = integer_width(w, 32)
            right_top = integer_width(w, 56)
            if left_top != right_top:
                return finish_magnitude(o, w, scalar_relation(left_top, right_top))
            if left_words == 0:
                return complete(o, w, 1)
            # A limb count, rather than a potentially overflowing total bit
            # count, spans every physically addressable Python integer.
            put(w, 96, left_words)
            put(w, 8, 10)
        else:
            integer_record = choose(left_kind == 3, 56, 32)
            integer_size = integer_words(w, integer_record)
            if integer_size > 32:
                return finish_magnitude(o, w, choose(left_kind == 3, 0, 2))
            left_top = number_top(w, 32)
            right_top = number_top(w, 56)
            if left_top != right_top:
                return finish_magnitude(o, w, scalar_relation(left_top, right_top))
            if left_top == 0:
                return complete(o, w, 1)
            put(w, 136, left_top)
            put(w, 8, 30)
    else:
        if get(w, 0) != COMPARE_MAGIC or get(w, 8) == 99:
            return refuse(w)
        phase = get(w, 8)
        if phase != 11 and phase != 13 and phase != 31:
            return refuse(w)
        if read(s, 8) != 1 or read(s, 16) != get(w, 16):
            return refuse(w)
        if read(s, 24) != get(w, 120) or read(s, 32) != get(w, 104) or read(s, 40) != get(w, 112):
            return refuse(w)
        at = 48
        while at < 128:
            if read(s, at) != 0:
                return refuse(w)
            at = at + 8
        count = get(w, 112)
        at = 128 + count * 4
        while at < 256:
            if byte(s, at) != 0:
                return refuse(w)
            at = at + 1
        side = get(w, 120)
        index = 0
        while index < count:
            put32(w, 256 + side * 128 + index * 4, read32(s, 128 + index * 4))
            index = index + 1
        words = get(w, 40 + side * 24)
        if get(w, 104) + count == words:
            top_word = get32(w, 256 + side * 128 + (count - 1) * 4)
            expected = get(w, 48 + side * 24) & 63
            if bit_length(top_word) != expected:
                return refuse(w)
        if phase == 11:
            put(w, 8, 12)
        elif phase == 13:
            put(w, 8, 14)
        else:
            put(w, 8, 32)
    while True:
        phase = get(w, 8)
        if phase == 10:
            remaining = get(w, 96)
            count = choose(remaining < 32, remaining, 32)
            start = remaining - count
            put(w, 104, start)
            put(w, 112, count)
            if get(w, 32) == 2:
                return request(o, w, 0, start, count, 11)
            fill_boolean(w, 256, start, count, get(w, 48))
            put(w, 8, 12)
        elif phase == 12:
            if get(w, 56) == 2:
                return request(o, w, 1, get(w, 104), get(w, 112), 13)
            fill_boolean(w, 384, get(w, 104), get(w, 112), get(w, 72))
            put(w, 8, 14)
        elif phase == 14:
            index = get(w, 112)
            while index > 0:
                index = index - 1
                left = get32(w, 256 + index * 4)
                right = get32(w, 384 + index * 4)
                if left != right:
                    return finish_magnitude(o, w, scalar_relation(left, right))
            remaining = get(w, 104)
            if remaining == 0:
                return complete(o, w, 1)
            put(w, 96, remaining)
            put(w, 8, 10)
        elif phase == 30:
            side = choose(get(w, 32) == 2, 0, 1)
            record = 32 + side * 24
            words = get(w, record + 8)
            if get(w, record) == 2 and words != 0:
                return request(o, w, side, 0, words, 31)
            put(w, 8, 32)
        elif phase == 32:
            left_low = number_shift(w, 32) >> 5
            right_low = number_shift(w, 56) >> 5
            low = choose(left_low < right_low, left_low, right_low)
            index = (get(w, 136) + 31) >> 5
            while index > low:
                index = index - 1
                left = scaled_word(w, 32, 256, index)
                right = scaled_word(w, 56, 384, index)
                if left != right:
                    return finish_magnitude(o, w, scalar_relation(left, right))
            return complete(o, w, 1)
        else:
            return refuse(w)
    return refuse(w)

def classification(w:mutbuf, record:u64) -> u64:
    if get(w, record) != 3:
        return 0
    bits = get(w, record + 16)
    if ((bits >> 52) & 2047) != 2047:
        return 0
    return choose((bits & 4503599627370495) == 0, 1, 2)

def integer_words(w:mutbuf, record:u64) -> u64:
    if get(w, record) == 1:
        return get(w, record + 16)
    return get(w, record + 8)

def integer_width(w:mutbuf, record:u64) -> u64:
    if get(w, record) == 1:
        return get(w, record + 16)
    return get(w, record + 16) & 63

def number_sign(w:mutbuf, record:u64) -> u64:
    kind = get(w, record)
    if kind == 1:
        return 0
    if kind == 2:
        return get(w, record + 16) >> 6
    bits = get(w, record + 16)
    if bits & 9223372036854775807 == 0:
        return 0
    return bits >> 63

def number_top(w:mutbuf, record:u64) -> u64:
    if get(w, record) != 3:
        words = integer_words(w, record)
        if words == 0:
            return 0
        # Called only after the mixed comparison admitted at most 32 limbs.
        return (words - 1) * 32 + integer_width(w, record) + 1074
    bits = get(w, record + 16)
    exponent = (bits >> 52) & 2047
    if exponent != 0:
        return exponent + 52
    return bit_length(bits & 4503599627370495)

def number_shift(w:mutbuf, record:u64) -> u64:
    if get(w, record) != 3:
        return 1074
    exponent = (get(w, record + 16) >> 52) & 2047
    return choose(exponent == 0, 0, exponent - 1)

def magnitude_word(w:mutbuf, record:u64, base:u64, index:u64) -> u64:
    kind = get(w, record)
    if kind == 1:
        return choose(index == 0, get(w, record + 16), 0)
    if kind == 2:
        words = get(w, record + 8)
        if index >= words:
            return 0
        return get32(w, base + index * 4)
    bits = get(w, record + 16)
    mantissa = bits & 4503599627370495
    if ((bits >> 52) & 2047) != 0:
        mantissa = mantissa | 4503599627370496
    if index == 0:
        return mantissa & 4294967295
    if index == 1:
        return mantissa >> 32
    return 0

def scaled_word(w:mutbuf, record:u64, base:u64, index:u64) -> u64:
    shift = number_shift(w, record)
    whole = shift >> 5
    if index < whole:
        return 0
    source = index - whole
    part = shift & 31
    value = (magnitude_word(w, record, base, source) << part) & 4294967295
    if part != 0 and source != 0:
        value = value | (magnitude_word(w, record, base, source - 1) >> (32 - part))
    return value

def bit_length(value:u64) -> u64:
    count = 0
    while value != 0:
        value = value >> 1
        count = count + 1
    return count

def scalar_relation(left:u64, right:u64) -> u64:
    if left < right:
        return 0
    if left > right:
        return 2
    return 1

def predicate(operation:u64, relation:u64) -> u64:
    if operation == 1:
        return choose(relation == 1, 1, 0)
    if operation == 2:
        return choose(relation != 1, 1, 0)
    if operation == 3:
        return choose(relation == 0, 1, 0)
    if operation == 4:
        return choose(relation < 2, 1, 0)
    if operation == 5:
        return choose(relation == 2, 1, 0)
    return choose(relation == 1 or relation == 2, 1, 0)

def finish_magnitude(o:mutbuf, w:mutbuf, relation:u64) -> u32:
    result = relation
    if get(w, 80) == 1 and relation != 1:
        result = 2 - relation
    return complete(o, w, result)

def complete(o:mutbuf, w:mutbuf, relation:u64) -> u32:
    put(w, 8, 99)
    at = 0
    while at < 128:
        put(o, at, 0)
        at = at + 8
    put(o, 0, COMPARE_MAGIC)
    put(o, 8, get(w, 16))
    put(o, 16, relation)
    flag = predicate(get(w, 24), relation)
    put(o, 24, flag)
    return 0

def request(o:mutbuf, w:mutbuf, side:u64, start:u64, count:u64, phase:u64) -> u32:
    if side > 1 or count == 0 or count > 32 or get(w, 16) == 18446744073709551615:
        return refuse(w)
    record = 32 + side * 24
    words = get(w, record + 8)
    if get(w, record) != 2 or start >= words or count > words - start:
        return refuse(w)
    seq = get(w, 16) + 1
    put(w, 16, seq)
    put(w, 8, phase)
    put(w, 104, start)
    put(w, 112, count)
    put(w, 120, side)
    at = 0
    while at < 128:
        put(o, at, 0)
        at = at + 8
    put(o, 0, COMPARE_MAGIC)
    put(o, 8, seq)
    put(o, 16, 1)
    put(o, 24, side)
    put(o, 32, start)
    put(o, 40, count)
    return 1

def fill_boolean(w:mutbuf, base:u64, start:u64, count:u64, scalar:u64) -> u64:
    index = 0
    while index < count:
        value = choose(start == 0 and index == 0, scalar, 0)
        put32(w, base + index * 4, value)
        index = index + 1
    return 0

def refuse(w:mutbuf) -> u32:
    if length(w) == 512:
        put(w, 8, 99)
    return 4294967293

WORD_HELPERS
'''


def source():
    helpers = []
    for name, buffer_type, width in (
            ('read', 'readbuf', 8), ('get', 'mutbuf', 8),
            ('read32', 'readbuf', 4), ('get32', 'mutbuf', 4)):
        helpers.extend([f'def {name}(w:{buffer_type}, index:u64) -> u64:', '    value = 0'])
        for i in range(width):
            helpers.append(f'    value = value | (byte(w, index + {i}) << {i * 8})')
        helpers.append('    return value')
    for name, width in (('put', 8), ('put32', 4)):
        helpers.append(f'def {name}(w:mutbuf, index:u64, value:u64) -> u64:')
        for i in range(width):
            helpers.append(f'    store(w, index + {i}, value >> {i * 8})')
        helpers.append('    return value')
    return SOURCE.replace('COMPARE_MAGIC', str(MAGIC)).replace('WORD_HELPERS', '\n'.join(helpers))


def document():
    nodes = ast.parse(source()).body
    names = {node.name: 'f' + str(i) for i, node in enumerate(nodes)}
    signatures = {node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id)
                  for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = Builder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(p) for p in builder.params],
            'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
            'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8',
                                  'module': 'core_compare', 'functions': functions})


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    with args.output.open('x') as stream:
        stream.write(render_assembly(document()))
    print(args.output.name, args.output.stat().st_size)


if __name__ == '__main__':
    main()
