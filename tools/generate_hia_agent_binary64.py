"""Author exact decimal-to-binary64 rounding using only HIA integer operations.

No C/Python floating conversion is called by the generated program. Retain 800
significant decimal digits plus a sticky bit: every binary64 rounding boundary
has at most 768 significant decimal digits (odd coefficient <2**54 times a power
of five <=5**1075), so discarded digits can only disambiguate an exact boundary.
This algorithm does not implement shortest printing or native persistence.
"""
import ast
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

SOURCE = r'''
def convert(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    n = length(s)
    if n == 0 or n > 8388608:
        return 4294967295
    if length(o) < 8 or length(w) < 4096:
        return 4294967293
    small(w, 0, 0)
    small(w, 1040, 1)
    put(w, 3120, 0)
    put(w, 3128, 0)
    put(w, 3136, 0)
    index = 0
    sign = 0
    if byte(s, 0) == 45:
        sign = 9223372036854775808
        index = 1
    if index >= n:
        return 4294967295
    ch = byte(s, index)
    if ch == 48:
        index = index + 1
    else:
        if ch < 49 or ch > 57:
            return 4294967295
        going = True
        while going and index < n:
            ch = byte(s, index)
            if ch >= 48 and ch <= 57:
                if digit(w, ch - 48) != 0:
                    return 4294967293
                index = index + 1
            else:
                going = False
    fraction = 0
    if index < n and byte(s, index) == 46:
        index = index + 1
        begin = index
        going = True
        while going and index < n:
            ch = byte(s, index)
            if ch >= 48 and ch <= 57:
                if digit(w, ch - 48) != 0:
                    return 4294967293
                fraction = fraction + 1
                index = index + 1
            else:
                going = False
        if index == begin:
            return 4294967295
    exponent = 0
    negative_exponent = False
    if index < n and (byte(s, index) == 69 or byte(s, index) == 101):
        index = index + 1
        if index < n and (byte(s, index) == 43 or byte(s, index) == 45):
            negative_exponent = byte(s, index) == 45
            index = index + 1
        begin = index
        going = True
        while going and index < n:
            ch = byte(s, index)
            if ch >= 48 and ch <= 57:
                if exponent < 33554432:
                    exponent = exponent * 10 + ch - 48
                    if exponent > 33554432:
                        exponent = 33554432
                index = index + 1
            else:
                going = False
        if index == begin:
            return 4294967295
    if index != n:
        return 4294967295
    significant = get(w, 3120)
    if significant == 0:
        put(o, 0, sign)
        return 8
    order = 67108864 + significant - fraction - 1
    if negative_exponent:
        order = order - exponent
    else:
        order = order + exponent
    if order > 67109172:
        return 4294967292
    if order < 67108540:
        put(o, 0, sign)
        return 8
    power = order + 1 - get(w, 3128)
    if power >= 67108864:
        count = power - 67108864
        base = 0
    else:
        count = 67108864 - power
        base = 1040
    i = 0
    while i < count:
        if multiply(w, base, 10, 0) != 0:
            return 4294967293
        i = i + 1
    # Exponents have a positive bias; no signed arithmetic or host log is used.
    binary = 4096 + bits(w, 0) - bits(w, 1040)
    if binary >= 4096:
        copy_big(w, 1040, 2080)
        if shift(w, 2080, binary - 4096) != 0:
            return 4294967293
        relation = compare_big(w, 0, 2080)
    else:
        copy_big(w, 0, 2080)
        if shift(w, 2080, 4096 - binary) != 0:
            return 4294967293
        relation = compare_big(w, 2080, 1040)
    if relation == 1:
        binary = binary - 1
    if binary > 5119:
        return 4294967292
    normal = binary >= 3074
    if normal:
        scale = 12340 - binary
    else:
        scale = 9266
    if scale >= 8192:
        if shift(w, 0, scale - 8192) != 0:
            return 4294967293
    else:
        if shift(w, 1040, 8192 - scale) != 0:
            return 4294967293
    numerator_bits = bits(w, 0)
    denominator_bits = bits(w, 1040)
    quotient = 0
    if numerator_bits >= denominator_bits:
        step = numerator_bits - denominator_bits + 1
        if step > 54:
            return 4294967293
        while step > 0:
            step = step - 1
            copy_big(w, 1040, 2080)
            if shift(w, 2080, step) != 0:
                return 4294967293
            if compare_big(w, 0, 2080) != 1:
                subtract(w, 0, 2080)
                quotient = quotient | (1 << step)
    if shift(w, 0, 1) != 0:
        return 4294967293
    relation = compare_big(w, 0, 1040)
    if relation == 2 or (relation == 0 and ((quotient & 1) != 0 or get(w, 3136) != 0)):
        quotient = quotient + 1
    if normal:
        if quotient == 9007199254740992:
            quotient = quotient >> 1
            binary = binary + 1
        if binary > 5119:
            return 4294967292
        result = ((binary - 3073) << 52) | (quotient - 4503599627370496)
    else:
        result = quotient
    put(o, 0, result | sign)
    return 8

def digit(w:mutbuf, value:u64) -> u64:
    count = get(w, 3120)
    if count == 0 and value == 0:
        return 0
    put(w, 3120, count + 1)
    kept = get(w, 3128)
    if kept < 800:
        put(w, 3128, kept + 1)
        return multiply(w, 0, 10, value)
    if value != 0:
        put(w, 3136, 1)
    return 0

def small(w:mutbuf, at:u64, value:u64) -> u64:
    put(w, at, 1)
    put(w, at + 8, value)
    return 0

def multiply(w:mutbuf, at:u64, factor:u64, carry:u64) -> u64:
    count = get(w, at)
    i = 0
    while i < count:
        value = get(w, at + 8 + i * 8) * factor + carry
        put(w, at + 8 + i * 8, value & 4294967295)
        carry = value >> 32
        i = i + 1
    if carry != 0:
        if count >= 128:
            return 1
        put(w, at + 8 + count * 8, carry)
        put(w, at, count + 1)
    return 0

def bits(w:mutbuf, at:u64) -> u64:
    count = get(w, at)
    value = get(w, at + count * 8)
    result = (count - 1) * 32
    while value != 0:
        result = result + 1
        value = value >> 1
    return result

def copy_big(w:mutbuf, source:u64, target:u64) -> u64:
    count = get(w, source)
    i = 0
    while i <= count:
        put(w, target + i * 8, get(w, source + i * 8))
        i = i + 1
    return 0

def normalize(w:mutbuf, at:u64) -> u64:
    count = get(w, at)
    while count > 1 and get(w, at + count * 8) == 0:
        count = count - 1
    put(w, at, count)
    return 0

def shift(w:mutbuf, at:u64, amount:u64) -> u64:
    words = amount >> 5
    rest = amount & 31
    count = get(w, at)
    total = count + words
    if rest != 0:
        total = total + 1
    if total > 128:
        return 1
    i = total
    while i > 0:
        i = i - 1
        value = 0
        if i >= words:
            index = i - words
            if index < count:
                value = (get(w, at + 8 + index * 8) << rest) & 4294967295
            if rest != 0 and index > 0 and index - 1 < count:
                value = value | (get(w, at + index * 8) >> (32 - rest))
        put(w, at + 8 + i * 8, value)
    put(w, at, total)
    normalize(w, at)
    return 0

def compare_big(w:mutbuf, left:u64, right:u64) -> u64:
    a = get(w, left)
    b = get(w, right)
    if a < b:
        return 1
    if a > b:
        return 2
    i = a
    while i > 0:
        x = get(w, left + i * 8)
        y = get(w, right + i * 8)
        if x < y:
            return 1
        if x > y:
            return 2
        i = i - 1
    return 0

def subtract(w:mutbuf, left:u64, right:u64) -> u64:
    a = get(w, left)
    b = get(w, right)
    borrow = 0
    i = 0
    while i < a:
        y = 0
        if i < b:
            y = get(w, right + 8 + i * 8)
        value = 4294967296 + get(w, left + 8 + i * 8) - y - borrow
        put(w, left + 8 + i * 8, value & 4294967295)
        borrow = choose(value < 4294967296, 1, 0)
        i = i + 1
    normalize(w, left)
    return 0

def get(w:mutbuf, at:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(w, at + i) << (i * 8))
        i = i + 1
    return value

def put(w:mutbuf, at:u64, value:u64) -> u64:
    i = 0
    while i < 8:
        store(w, at + i, value & 255)
        value = value >> 8
        i = i + 1
    return 0
'''


def source_program():
    return SOURCE


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
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8', 'module': 'agent_binary64', 'functions': functions})


if __name__ == '__main__':
    target = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap/agent_binary64.hepta'
    target.write_text(render_assembly(document()))
    print(target.name, target.stat().st_size)
