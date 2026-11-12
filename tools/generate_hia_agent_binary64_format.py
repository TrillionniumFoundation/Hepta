"""Author shortest round-trip binary64 JSON printing with integer intervals.

The integer digit-generation algorithm keeps exact asymmetric rounding margins,
including subnormals and powers of two. It neither calls a host floating printer
nor searches a smaller numeric domain. Foreign float-bit transport is separate.
"""
import ast
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
from tools.generate_hia_agent_binary64 import source_program as decimal_source

FORMAT = r'''
def render_binary64(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) != 8:
        return 4294967295
    if length(w) < 8192:
        return 4294967293
    original = read64(s, 0)
    magnitude = original & 9223372036854775807
    negative = (original >> 63) != 0
    exponent = (magnitude >> 52) & 2047
    mantissa = magnitude & 4503599627370495
    if exponent == 2047:
        return 4294967295
    cursor = 0
    if negative:
        cursor = emit(w, cursor, 45)
    if magnitude == 0:
        cursor = emit(w, cursor, 48)
        cursor = emit(w, cursor, 46)
        cursor = emit(w, cursor, 48)
    else:
        if exponent != 0:
            mantissa = mantissa | 4503599627370496
        # N/D is the exact positive float; L/D and H/D are its lower and
        # upper half-ULPs. The lower margin halves only at normal powers of
        # two above the normal/subnormal transition. All use a common4 scale.
        set64(w, 0, mantissa << 2)
        set64(w, 1040, 4)
        set64(w, 2080, 2)
        set64(w, 3120, 2)
        if exponent > 1 and mantissa == 4503599627370496:
            set64(w, 2080, 1)
        if exponent == 0:
            shift(w, 1040, 1074)
            binary = 3021 + bits(w, 0) - 2
        else:
            binary = exponent + 3073
            if exponent >= 1075:
                shift(w, 0, exponent - 1075)
                shift(w, 2080, exponent - 1075)
                shift(w, 3120, exponent - 1075)
            else:
                shift(w, 1040, 1075 - exponent)
        # A fixed integer log10(2) approximation is corrected by exact
        # integer comparisons, never by host logarithms or FP operations.
        order = 815 + ((binary * 1233) >> 12)
        if order_relation(w, order) == 1:
            order = order - 1
        if order_relation(w, order + 1) != 1:
            order = order + 1
        if order >= 2048:
            count = order - 2048
            i = 0
            while i < count:
                if multiply(w, 1040, 10, 0) != 0:
                    return 4294967293
                i = i + 1
        else:
            count = 2048 - order
            i = 0
            while i < count:
                if multiply(w, 0, 10, 0) != 0 or multiply(w, 2080, 10, 0) != 0 or multiply(w, 3120, 10, 0) != 0:
                    return 4294967293
                i = i + 1
        inclusive = (mantissa & 1) == 0
        digits = 0
        done = False
        round_up = False
        while digits < 17 and done == False:
            value = 0
            while compare_big(w, 0, 1040) != 1:
                subtract(w, 0, 1040)
                value = value + 1
            if value > 9:
                return 4294967293
            store(w, 6200 + digits, value + 48)
            digits = digits + 1
            relation = compare_big(w, 0, 2080)
            low = relation == 1 or (relation == 0 and inclusive)
            copy_big(w, 0, 4160)
            if add_big(w, 4160, 3120) != 0:
                return 4294967293
            relation = compare_big(w, 4160, 1040)
            high = relation == 2 or (relation == 0 and inclusive)
            if low or high:
                done = True
                if low and high:
                    multiply(w, 0, 2, 0)
                    relation = compare_big(w, 0, 1040)
                    round_up = relation == 2 or (relation == 0 and (value & 1) != 0)
                else:
                    round_up = high
            else:
                if multiply(w, 0, 10, 0) != 0 or multiply(w, 2080, 10, 0) != 0 or multiply(w, 3120, 10, 0) != 0:
                    return 4294967293
        if done == False:
            return 4294967293
        if round_up:
            at = digits
            carry = True
            while at > 0 and carry:
                at = at - 1
                value = byte(w, 6200 + at)
                if value == 57:
                    store(w, 6200 + at, 48)
                else:
                    store(w, 6200 + at, value + 1)
                    carry = False
            if carry:
                store(w, 6200, 49)
                digits = 1
                order = order + 1
        while digits > 1 and byte(w, 6200 + digits - 1) == 48:
            digits = digits - 1
        if order < 2044 or order >= 2064:
            cursor = emit(w, cursor, byte(w, 6200))
            if digits > 1:
                cursor = emit(w, cursor, 46)
                i = 1
                while i < digits:
                    cursor = emit(w, cursor, byte(w, 6200 + i))
                    i = i + 1
            cursor = emit(w, cursor, 101)
            if order < 2048:
                cursor = emit(w, cursor, 45)
                power = 2048 - order
            else:
                cursor = emit(w, cursor, 43)
                power = order - 2048
            # Binary64 decimal exponents need at most3 digits; CPython JSON
            # spells a scientific exponent with an explicit sign and >=2.
            hundreds = 0
            while power >= 100:
                hundreds = hundreds + 1
                power = power - 100
            if hundreds != 0:
                cursor = emit(w, cursor, hundreds + 48)
            tens = 0
            while power >= 10:
                tens = tens + 1
                power = power - 10
            cursor = emit(w, cursor, tens + 48)
            cursor = emit(w, cursor, power + 48)
        elif order >= 2048:
            integer_digits = order - 2048 + 1
            i = 0
            while i < integer_digits:
                value = 48
                if i < digits:
                    value = byte(w, 6200 + i)
                cursor = emit(w, cursor, value)
                i = i + 1
            cursor = emit(w, cursor, 46)
            if digits <= integer_digits:
                cursor = emit(w, cursor, 48)
            else:
                while i < digits:
                    cursor = emit(w, cursor, byte(w, 6200 + i))
                    i = i + 1
        else:
            cursor = emit(w, cursor, 48)
            cursor = emit(w, cursor, 46)
            i = order + 1
            while i < 2048:
                cursor = emit(w, cursor, 48)
                i = i + 1
            i = 0
            while i < digits:
                cursor = emit(w, cursor, byte(w, 6200 + i))
                i = i + 1
    if length(o) < cursor:
        return 4294967294
    i = 0
    while i < cursor:
        store(o, i, byte(w, 6144 + i))
        i = i + 1
    return cursor

def set64(w:mutbuf, at:u64, value:u64) -> u64:
    put(w, at, 2)
    put(w, at + 8, value & 4294967295)
    put(w, at + 16, value >> 32)
    normalize(w, at)
    return 0

def order_relation(w:mutbuf, power:u64) -> u64:
    if power >= 2048:
        copy_big(w, 1040, 4160)
        count = power - 2048
    else:
        copy_big(w, 0, 4160)
        count = 2048 - power
    i = 0
    while i < count:
        multiply(w, 4160, 10, 0)
        i = i + 1
    if power >= 2048:
        return compare_big(w, 0, 4160)
    return compare_big(w, 4160, 1040)

def add_big(w:mutbuf, left:u64, right:u64) -> u64:
    a = get(w, left)
    b = get(w, right)
    count = choose(a >= b, a, b)
    carry = 0
    i = 0
    while i < count:
        x = 0
        y = 0
        if i < a:
            x = get(w, left + 8 + i * 8)
        if i < b:
            y = get(w, right + 8 + i * 8)
        value = x + y + carry
        put(w, left + 8 + i * 8, value & 4294967295)
        carry = value >> 32
        i = i + 1
    if carry != 0:
        if count >= 128:
            return 1
        put(w, left + 8 + count * 8, carry)
        count = count + 1
    put(w, left, count)
    return 0

def emit(w:mutbuf, index:u64, value:u64) -> u64:
    store(w, 6144 + index, value)
    return index + 1

def read64(s:readbuf, at:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(s, at + i) << (i * 8))
        i = i + 1
    return value
'''


def source_program():
    source = decimal_source()
    names = {'multiply', 'bits', 'copy_big', 'normalize', 'shift', 'compare_big', 'subtract', 'get', 'put'}
    helpers = [ast.get_source_segment(source, n) for n in ast.parse(source).body if n.name in names]
    assert len(helpers) == len(names)
    return FORMAT.strip() + '\n\n' + '\n\n'.join(helpers) + '\n'


def document():
    nodes = ast.parse(source_program()).body
    names = {n.name: 'f' + str(i) for i, n in enumerate(nodes)}
    signatures = {n.name: ([a.annotation.id for a in n.args.args], n.returns.id) for n in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        b = Builder(node, names, signatures, total)
        b.statements(node.body)
        functions.append({'name': names[node.name], 'params': [b.param(v) for v in b.params],
                          'returns': [b.returns], 'effects': ['read', 'write', 'trap'],
                          'entry': 'b0', 'blocks': b.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8', 'module': 'agent_binary64_format', 'functions': functions})


if __name__ == '__main__':
    target = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap/agent_binary64_format.hepta'
    target.write_text(render_assembly(document()))
    print(target.name, target.stat().st_size)
