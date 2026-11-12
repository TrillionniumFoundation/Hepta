"""HIA policy and representation continuation for raw CLI JSON scalars.

This is an additional experimental subcontroller, not default admission.
The separately retained text image owns escaping and finite number rendering.
This controller owns representation conversion, early and late integer-limit
branches, and the original dynamic _pylong extension sequence.  The latter is
an explicit existing foreign call, not a claim that its Python body is native.
Allocation, pending-call and complete graph/3.12 generator qualification are
still separate obligations.  No input-size or decimal-digit policy is added.
"""
from __future__ import annotations

import ast
from pathlib import Path

SYMBOLS = {
    'MAGIC': int.from_bytes(b'HCLISCL1', 'little'),
    'TEXT_MAGIC': int.from_bytes(b'HCLIJTX1', 'little'),
    'ABI': 4294967293, 'MAX_SIZE': 9223372036854775807,
    'PHASE': 8, 'SEQUENCE': 16, 'PENDING': 24,
    'REPLY_SEQUENCE': 32, 'REPLY_OPERATION': 40, 'RAISED': 48,
    'ABORT': 56, 'OPERATION': 64, 'ARGUMENTS': 72,
    'FINAL': 112, 'OBJECT': 120, 'KIND': 128, 'QUOTED': 136,
    'COUNT': 144, 'WIDTH': 152, 'SHIFT': 160, 'SIGN': 168,
    'PACKET_BYTES': 176, 'MEASURED': 184, 'LIMIT': 192,
    'VALUE_ERROR': 200, 'TYPE_ERROR': 208,
    'MODULE': 216, 'STRING': 224, 'CHECK_CELL': 232,
    'ANSWER': 256, 'SLOT': 320,
    'MODULE_NAME': 512, 'METHOD_NAME': 544, 'BAD_RESULT': 608,
}
LITERALS = {
    'MODULE_NAME': b'_pylong\0',
    'METHOD_NAME': b'int_to_decimal_string\0',
    'BAD_RESULT': b'_pylong.int_to_decimal_string did not return a str\0',
}

SOURCE = r'''
def cli_json_scalar(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) != 1024 or get(w, 0) != MAGIC or get(w, FINAL) != 0:
        return ABI
    if get(w, ABORT) != 0:
        put(w, ABORT, 0)
        put(w, PENDING, 0)
        put(w, PHASE, 900)
    elif get(w, PENDING) != 0:
        if get(w, REPLY_SEQUENCE) != get(w, SEQUENCE) or get(w, REPLY_OPERATION) != get(w, OPERATION):
            return ABI
        put(w, PENDING, 0)
    elif get(w, PHASE) != 0:
        return ABI
    if get(w, PHASE) == 0:
        if get(w, OBJECT) == 0 or get(w, KIND) > 3 or get(w, QUOTED) != choose(get(w, KIND) == 0, 1, 0):
            return ABI
        if get(w, SLOT) != 0 or get(w, RAISED) != 0:
            return ABI
        literals(w)
        put(w, CHECK_CELL, 0)
        put(w, PHASE, 1)
    while True:
        phase = get(w, PHASE)
        if phase < 100:
            status = observe_scalar(w, phase)
        elif phase < 200:
            status = integer_policy(w, phase)
        elif phase < 300:
            status = dynamic_decimal(w, phase)
        elif phase < 500:
            status = materialize(s, o, w, phase)
        else:
            status = unwind(w, phase)
        if status != 4:
            return status
    return ABI

def observe_scalar(w:mutbuf, phase:u64) -> u64:
    if phase == 1:
        return request(w, 46, get(w, CHECK_CELL), 0, 0, 0, 0, 2)
    if phase == 2:
        if answer(w, 0) != 0:
            return ABI
        cell = get(w, CHECK_CELL) + 1
        put(w, CHECK_CELL, cell)
        if cell < 8:
            put(w, PHASE, 1)
            return 4
        return request(w, 17, 0, 0, 0, 0, 0, 3)
    if phase == 3:
        put(w, VALUE_ERROR, answer(w, 4))
        put(w, TYPE_ERROR, answer(w, 5))
        kind = get(w, KIND)
        if kind == 0:
            return request(w, 38, get(w, OBJECT), 0, 0, 0, 0, 10)
        if kind == 1:
            return request(w, 69, get(w, OBJECT), 0, 0, 0, 0, 20)
        if kind == 2:
            return request(w, 39, get(w, OBJECT), 0, 0, 0, 0, 30)
        return request(w, 55, get(w, OBJECT), 0, 0, 0, 0, 40)
    if phase == 10:
        if get(w, RAISED) != 0:
            return failed(w)
        count = answer(w, 0)
        width = answer(w, 1)
        if width != 1 and width != 2 and width != 4:
            return ABI
        if count > (MAX_SIZE - 64) >> 2:
            return request(w, 20, 0, 0, 0, 0, 0, 900)
        put(w, COUNT, count)
        put(w, WIDTH, width)
        put(w, PACKET_BYTES, 64 + count * 4)
        return request(w, 210, get(w, PACKET_BYTES), 0, 0, 0, 0, 400)
    if phase == 20:
        if get(w, RAISED) != 0:
            return failed(w)
        count = answer(w, 0)
        sign = answer(w, 1)
        shift = answer(w, 2)
        width = answer(w, 4)
        if (shift != 15 or width != 2) and (shift != 30 or width != 4):
            return ABI
        if sign > 2 or (count == 0 and sign != 1) or (count != 0 and sign == 1):
            return ABI
        put(w, COUNT, count)
        put(w, SIGN, sign)
        put(w, SHIFT, shift)
        put(w, WIDTH, width)
        # Original threshold test precedes scratch allocation and _pylong.
        # C integer division: 6400/45+2 == 144; 6400/90+2 == 73.
        # The shift/width pair was validated above, before this choice.
        if count >= choose(shift == 15, 144, 73):
            return request(w, 70, 0, 0, 0, 0, 0, 100)
        put(w, PHASE, 110)
        return 4
    if phase == 30:
        if get(w, RAISED) != 0:
            return failed(w)
        put(w, COUNT, answer(w, 0))
        put(w, PACKET_BYTES, 72)
        return request(w, 210, 72, 0, 0, 0, 0, 400)
    if phase == 40:
        if get(w, RAISED) != 0:
            return failed(w)
        bits = answer(w, 0)
        if (bits & 448) == 0:
            return ABI
        put(w, COUNT, choose((bits & 64) != 0, 0, choose((bits & 256) != 0, 1, 2)))
        put(w, PACKET_BYTES, 64)
        return request(w, 210, 64, 0, 0, 0, 0, 400)
    return ABI

def integer_policy(w:mutbuf, phase:u64) -> u64:
    if phase == 100:
        limit = answer(w, 0)
        if limit > 2147483647 or answer(w, 1) != 640 or answer(w, 2) != get(w, SHIFT) or answer(w, 3) != 1:
            return ABI
        put(w, LIMIT, limit)
        if limit > 0:
            count = get(w, COUNT)
            # A valid phase 100 follows the >=73 or >=144 threshold.
            # Guard subtraction explicitly so u64 never wraps below 11.
            if count >= 11:
                divisor = choose(get(w, SHIFT) == 15, 45, 90)
                if divide_small(limit, divisor) <= divide_small(count - 11, 10):
                    return request(w, 73, limit, 0, 0, 0, 0, 900)
        put(w, PHASE, 110)
        return 4
    if phase == 110:
        if get(w, COUNT) > 1000:
            put(w, PHASE, 200)
            return 4
        # This branch retains the original <=1000-digit conversion domain;
        # larger values follow the actual dynamic extension below, not a
        # fabricated admission rejection or a Python formatting fallback.
        words = (get(w, COUNT) * get(w, SHIFT) + 31) >> 5
        put(w, PACKET_BYTES, 64 + words * 4)
        return request(w, 210, get(w, PACKET_BYTES), 0, 0, 0, 0, 400)
    if phase == 120:
        limit = answer(w, 0)
        if limit > 2147483647 or answer(w, 1) != 640 or answer(w, 2) != get(w, SHIFT) or answer(w, 3) != 1:
            return ABI
        if limit > 0 and get(w, MEASURED) - choose(get(w, SIGN) == 2, 1, 0) > limit:
            return request(w, 73, limit, 0, 0, 0, 0, 900)
        put(w, PHASE, 430)
        return 4
    return ABI

def dynamic_decimal(w:mutbuf, phase:u64) -> u64:
    if phase == 200:
        return request(w, 71, MODULE_NAME, 0, 0, 0, 0, 201)
    if phase == 201:
        if get(w, SLOT) == 0:
            return failed(w)
        return request(w, 44, 0, 0, 0, 0, 0, 202)
    if phase == 202:
        put(w, MODULE, answer(w, 0))
        return request(w, 72, get(w, MODULE), METHOD_NAME, get(w, OBJECT), 0, 0, 203)
    if phase == 203:
        if get(w, SLOT) == 0:
            return failed(w)
        return request(w, 44, 1, 0, 0, 0, 0, 204)
    if phase == 204:
        put(w, STRING, answer(w, 0))
        return request(w, 55, get(w, STRING), 0, 0, 0, 0, 205)
    if phase == 205:
        if (answer(w, 0) & 1) == 0:
            return request(w, 10, get(w, TYPE_ERROR), BAD_RESULT, 51, 0, 0, 900)
        # Original writer=NULL branch acquires the returned s before dropping
        # mod and then s.  This preserves an arbitrary returned str subtype.
        return request(w, 74, 1, 0, 0, 0, 0, 206)
    if phase == 206:
        return request(w, 45, 0, 0, 0, 0, 0, 207)
    if phase == 207:
        return request(w, 45, 1, 0, 0, 0, 0, 440)
    return ABI

def materialize(s:readbuf, o:mutbuf, w:mutbuf, phase:u64) -> u64:
    if phase == 400:
        if get(w, RAISED) != 0:
            return failed(w)
        if length(o) < get(w, PACKET_BYTES):
            return ABI
        status = packet(s, o, w)
        if status != 0:
            return status
        return request(w, 211, get(w, PACKET_BYTES), 0, 0, 0, 0, 420)
    if phase == 420:
        if get(w, RAISED) != 0:
            return failed(w)
        if answer(w, 0) != answer(w, 1):
            return ABI
        if answer(w, 0) == 4:
            return request(w, choose(get(w, KIND) == 0, 76, 20), 0, 0, 0, 0, 0, 900)
        if answer(w, 0) != 0 or answer(w, 2) > MAX_SIZE >> 2:
            return ABI
        put(w, MEASURED, answer(w, 2))
        # CPython tests strlen including the sign against the threshold, then
        # compares only decimal digits against a freshly read current limit.
        if get(w, KIND) == 1 and answer(w, 2) > 640:
            return request(w, 70, 0, 0, 0, 0, 0, 120)
        put(w, PHASE, 430)
        return 4
    if phase == 430:
        put(o, 16, 1)
        return request(w, 212, get(w, PACKET_BYTES), get(w, MEASURED), 0, 0, 0, 431)
    if phase == 431:
        if get(w, RAISED) != 0:
            return failed(w)
        if answer(w, 0) != 0 or answer(w, 1) != 0 or answer(w, 2) != get(w, MEASURED):
            return ABI
        operation = choose(get(w, KIND) == 1 or get(w, KIND) == 2, 75, 68)
        return request(w, operation, 0, get(w, MEASURED), 0, 0, 0, 440)
    if phase == 440:
        if get(w, RAISED) != 0:
            return failed(w)
        if get(w, SLOT) == 0:
            return ABI
        put(w, FINAL, 1)
        return 0
    return ABI

def packet(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    index = 0
    while index < 64:
        store(o, index, 0)
        index = index + 1
    put(o, 0, TEXT_MAGIC)
    kind = get(w, KIND)
    put(o, 8, kind)
    if kind == 0:
        count = get(w, COUNT)
        width = get(w, WIDTH)
        if width != 1 and width != 2 and width != 4:
            return ABI
        width_shift = choose(width == 1, 0, choose(width == 2, 1, 2))
        # Check the quotient before multiplication, keeping the original
        # exact-byte-count test and preventing count*width overflow.
        if count > length(s) >> width_shift or length(s) != count * width:
            return ABI
        put(o, 32, count)
        index = 0
        while index < count:
            value = storage_word(s, index * width, width)
            if value > 1114111:
                return ABI
            put32(o, 64 + index * 4, value)
            index = index + 1
        return 0
    if kind == 1:
        return long_packet(s, o, w)
    if kind == 2:
        put(o, 32, 1)
        put(o, 64, get(w, COUNT))
        return 0
    put(o, 40, get(w, COUNT))
    return 0

def long_packet(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    count = get(w, COUNT)
    width = get(w, WIDTH)
    shift = get(w, SHIFT)
    if count > 1000 or length(s) != count * width:
        return ABI
    index = 0
    words = 0
    bits = 0
    carry = 0
    while index < count:
        digit = storage_word(s, index * width, width)
        if digit >= 1 << shift or (index + 1 == count and digit == 0):
            return ABI
        carry = carry | (digit << bits)
        bits = bits + shift
        if bits >= 32:
            put32(o, 64 + words * 4, carry & 4294967295)
            words = words + 1
            carry = carry >> 32
            bits = bits - 32
        index = index + 1
    if carry != 0:
        put32(o, 64 + words * 4, carry)
        words = words + 1
    put(o, 32, words)
    put(o, 40, choose(get(w, SIGN) == 2, 1, 0))
    put(w, PACKET_BYTES, 64 + words * 4)
    return 0

def unwind(w:mutbuf, phase:u64) -> u64:
    if phase == 900:
        if get(w, SLOT) != 0:
            return request(w, 6, 0, 0, 0, 0, 0, 901)
        put(w, PHASE, 901)
        return 4
    if phase == 901:
        return request(w, 46, 0, 0, 0, 0, 0, 902)
    if phase == 902:
        if answer(w, 0) != 0:
            return request(w, 45, 0, 0, 0, 0, 0, 903)
        put(w, PHASE, 903)
        return 4
    if phase == 903:
        return request(w, 46, 1, 0, 0, 0, 0, 904)
    if phase == 904:
        if answer(w, 0) != 0:
            return request(w, 45, 1, 0, 0, 0, 0, 905)
        put(w, PHASE, 905)
        return 4
    if phase == 905:
        if get(w, SLOT) != 0 or get(w, RAISED) == 0:
            return ABI
        put(w, FINAL, 2)
        return 1
    return ABI

def failed(w:mutbuf) -> u64:
    put(w, PHASE, 900)
    return 4

def request(w:mutbuf, operation:u64, a:u64, b:u64, c:u64, d:u64, e:u64, following:u64) -> u64:
    sequence = get(w, SEQUENCE)
    if sequence == 18446744073709551615:
        return ABI
    put(w, SEQUENCE, sequence + 1)
    put(w, PENDING, 1)
    put(w, OPERATION, operation)
    put(w, ARGUMENTS, a)
    put(w, ARGUMENTS + 8, b)
    put(w, ARGUMENTS + 16, c)
    put(w, ARGUMENTS + 24, d)
    put(w, ARGUMENTS + 32, e)
    put(w, PHASE, following)
    return 2

def answer(w:mutbuf, index:u64) -> u64:
    return get(w, ANSWER + index * 8)

def divide_small(value:u64, divisor:u64) -> u64:
    # All callers use 10, 45, or 90.  Before each step remainder<divisor;
    # afterward it is below 2*divisor<=180, so no u64 shift can overflow.
    # Quotient appends exactly one bit in each of the 64 iterations.
    quotient = 0
    remainder = 0
    remaining = 64
    while remaining != 0:
        remaining = remaining - 1
        remainder = (remainder << 1) | ((value >> remaining) & 1)
        quotient = quotient << 1
        if remainder >= divisor:
            remainder = remainder - divisor
            quotient = quotient | 1
    return quotient

def storage_word(s:readbuf, at:u64, width:u64) -> u64:
    value = 0
    index = 0
    while index < width:
        value = value | (byte(s, at + index) << (index * 8))
        index = index + 1
    return value

def get(w:mutbuf, at:u64) -> u64:
    value = 0
    index = 0
    while index < 8:
        value = value | (byte(w, at + index) << (index * 8))
        index = index + 1
    return value

def put(w:mutbuf, at:u64, value:u64) -> u64:
    index = 0
    while index < 8:
        store(w, at + index, (value >> (index * 8)) & 255)
        index = index + 1
    return 0

def put32(w:mutbuf, at:u64, value:u64) -> u64:
    index = 0
    while index < 4:
        store(w, at + index, (value >> (index * 8)) & 255)
        index = index + 1
    return 0
'''


def source_program():
    class Constants(ast.NodeTransformer):
        def visit_Name(self, node):
            if node.id in SYMBOLS:
                return ast.copy_location(ast.Constant(SYMBOLS[node.id]), node)
            return node

    literal_body = []
    for name, raw in LITERALS.items():
        for index, value in enumerate(raw):
            literal_body.append(f'    store(w, {SYMBOLS[name] + index}, {value})')
    literal_body.append('    return 0')
    literal_source = '\ndef literals(w:mutbuf) -> u64:\n' + '\n'.join(literal_body) + '\n'
    return ast.unparse(ast.fix_missing_locations(
        Constants().visit(ast.parse(SOURCE + literal_source)))) + '\n'


def document():
    from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

    nodes = ast.parse(source_program()).body
    if any(not isinstance(node, ast.FunctionDef) for node in nodes):
        raise ValueError('only scalar function definitions may enter HIA')
    names = {node.name: 'f' + str(index) for index, node in enumerate(nodes)}
    if len(names) != len(nodes):
        raise ValueError('duplicate scalar authoring function')
    signatures = {node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id) for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = Builder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(value) for value in builder.params],
                          'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
                          'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8',
                                  'module': 'cli_json_scalar', 'functions': functions})


if __name__ == '__main__':
    import argparse
    from hepta.hia_agent_assembly import render_assembly

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    with args.output.open('x') as stream:
        stream.write(render_assembly(document()))
