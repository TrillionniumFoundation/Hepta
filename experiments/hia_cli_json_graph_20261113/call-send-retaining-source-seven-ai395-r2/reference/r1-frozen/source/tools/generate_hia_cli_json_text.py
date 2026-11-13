"""Static candidate for CLI JSON scalar text, separate from graph observation.

The HIA source below works in UTF-32 code points, including isolated surrogates.
It has no 8 MiB, node-count or nesting policy. The existing complete finite
binary64 algorithm is composed verbatim through format_program(); NaN and
infinities are selected here from their original IEEE representation.

This file does not select or replace cli.output_json. It is an unexecuted
candidate component of the versioned graph continuation described alongside
it. CPython graph traversal, sort schedule, reference lifetime and exception
notes are separate obligations; producing this component is not their proof.
"""
from __future__ import annotations

import ast
from pathlib import Path


SOURCE_PATH = 'examples/hia_bootstrap/cli_json_text.hiaasm'
SYMBOLS = {
    'TEXT_MAGIC': int.from_bytes(b'HCLIJTX1', 'little'),
    'NULL_WORD': int.from_bytes(b'null', 'little'),
    'FALSE_WORD': int.from_bytes(b'false', 'little'),
    'TRUE_WORD': int.from_bytes(b'true', 'little'),
    'NAN_WORD': int.from_bytes(b'NaN', 'little'),
    'INF_WORD': int.from_bytes(b'Infinity', 'little'),
}

# Input is a mechanical, immutable observation record, not pre-encoded JSON.
# 8 words: magic, kind, mode, reserved, count, sign/constant, digit_limit, zero.
# kind: 0 = Unicode code points; 1 = magnitude uint32 limbs; 2 = IEEE64;
#       3 = None/False/True identity. mode: 0 measure; 1 emit UTF-32LE.
# Integer workspace: 256 + count*4 + (count*10+1) + 8192 bytes.
# Other workspace: at least 256 + 8192 bytes. The final 8192 bytes are the
# unchanged finite binary64 formatter's scratch. All input counts are uint64.
# Result words: magic, status, successful code-point count, diagnostic count.
# No caller may consume output/count following a nonzero actual native status.
SOURCE = r'''
def cli_json_text(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < 8448:
        return 1
    put(w, 0, TEXT_MAGIC)
    put(w, 8, 1)
    put(w, 16, 0)
    put(w, 24, 0)
    if length(s) < 64 or read(s, 0) != TEXT_MAGIC:
        return finish(w, 1, 0, 0)
    kind = read(s, 8)
    mode = read(s, 16)
    if kind > 3 or mode > 1 or read(s, 24) != 0 or read(s, 56) != 0:
        return finish(w, 1, 0, 0)
    if kind == 0:
        return string_text(s, o, w, mode)
    if kind == 1:
        return integer_text(s, o, w, mode)
    if kind == 2:
        return float_text(s, o, w, mode)
    if length(s) != 64 or read(s, 32) != 0 or read(s, 40) > 2 or read(s, 48) != 0:
        return finish(w, 1, 0, 0)
    return constant_text(o, w, mode, read(s, 40))

def finish(w:mutbuf, status:u32, count:u64, detail:u64) -> u32:
    put(w, 8, widen(status))
    put(w, 16, choose(widen(status) == 0, count, 0))
    put(w, 24, detail)
    return status

def string_text(s:readbuf, o:mutbuf, w:mutbuf, mode:u64) -> u32:
    size = read(s, 32)
    if read(s, 40) != 0 or read(s, 48) != 0:
        return finish(w, 1, 0, 0)
    if ((length(s) - 64) & 3) != 0 or size != (length(s) - 64) >> 2:
        return finish(w, 1, 0, 0)
    required = 2
    index = 0
    while index < size:
        character = read32(s, 64 + index * 4)
        if character > 1114111:
            return finish(w, 1, 0, index)
        width = escape_width(character)
        if required > 9223372036854775807 - width:
            return finish(w, 4, 0, 0)
        required = required + width
        index = index + 1
    if mode == 0:
        return finish(w, 0, required, 0)
    if required > length(o) >> 2:
        return finish(w, 2, 0, required)
    point(o, 0, 34)
    cursor = 1
    index = 0
    while index < size:
        character = read32(s, 64 + index * 4)
        cursor = escape_point(o, cursor, character)
        index = index + 1
    point(o, cursor, 34)
    return finish(w, 0, cursor + 1, 0)

def escape_width(character:u64) -> u64:
    if character == 34 or character == 92 or character == 8 or character == 9 or character == 10 or character == 12 or character == 13:
        return 2
    return choose(character < 32, 6, 1)

def escape_point(o:mutbuf, cursor:u64, character:u64) -> u64:
    if character == 34 or character == 92:
        point(o, cursor, 92)
        point(o, cursor + 1, character)
        return cursor + 2
    if character == 8 or character == 9 or character == 10 or character == 12 or character == 13:
        point(o, cursor, 92)
        escape = choose(character == 8, 98, choose(character == 9, 116, choose(character == 10, 110, choose(character == 12, 102, 114))))
        point(o, cursor + 1, escape)
        return cursor + 2
    if character < 32:
        point(o, cursor, 92)
        point(o, cursor + 1, 117)
        point(o, cursor + 2, 48)
        point(o, cursor + 3, 48)
        high = character >> 4
        low = character & 15
        point(o, cursor + 4, high + choose(high < 10, 48, 87))
        point(o, cursor + 5, low + choose(low < 10, 48, 87))
        return cursor + 6
    # This is text, not UTF-8 admission: surrogate code points stay literal.
    point(o, cursor, character)
    return cursor + 1

def integer_text(s:readbuf, o:mutbuf, w:mutbuf, mode:u64) -> u32:
    words = read(s, 32)
    negative = read(s, 40)
    limit = read(s, 48)
    if negative > 1 or limit > 2147483647 or ((length(s) - 64) & 3) != 0:
        return finish(w, 1, 0, 0)
    if words != (length(s) - 64) >> 2:
        return finish(w, 1, 0, 0)
    if words == 0:
        if negative != 0:
            return finish(w, 1, 0, 0)
    elif read32(s, 64 + (words - 1) * 4) == 0:
        return finish(w, 1, 0, 0)
    # This is address arithmetic, not a new integer digit or input budget.
    if words > 658812288346769097:
        return finish(w, 4, 0, 0)
    limb_base = 256
    digit_base = limb_base + words * 4
    digit_capacity = words * 10 + 1
    if length(w) < digit_base + digit_capacity + 8192:
        return finish(w, 1, 0, 0)
    index = 0
    while index < words:
        put32(w, limb_base + index * 4, read32(s, 64 + index * 4))
        index = index + 1
    count = 0
    while words > 0:
        carry = 0
        index = words
        while index > 0:
            index = index - 1
            value = get32(w, limb_base + index * 4)
            quotient = 0
            bit = 32
            while bit > 0:
                bit = bit - 1
                carry = (carry << 1) | ((value >> bit) & 1)
                if carry >= 1000000000:
                    carry = carry - 1000000000
                    quotient = quotient | (1 << bit)
            put32(w, limb_base + index * 4, quotient)
        while words > 0 and get32(w, limb_base + (words - 1) * 4) == 0:
            words = words - 1
        digits = 0
        while digits < 9 and (words != 0 or carry != 0 or digits == 0):
            quotient = (carry * 3435973837) >> 35
            if count >= digit_capacity:
                return finish(w, 1, 0, 0)
            store(w, digit_base + count, carry - quotient * 10 + 48)
            carry = quotient
            count = count + 1
            digits = digits + 1
    if count == 0:
        store(w, digit_base, 48)
        count = 1
    if limit != 0 and count > limit:
        return finish(w, 3, 0, count)
    required = count + negative
    if mode == 0:
        return finish(w, 0, required, 0)
    if required > length(o) >> 2:
        return finish(w, 2, 0, required)
    if negative != 0:
        point(o, 0, 45)
    index = 0
    while index < count:
        point(o, negative + index, byte(w, digit_base + count - 1 - index))
        index = index + 1
    return finish(w, 0, required, 0)

def float_text(s:readbuf, o:mutbuf, w:mutbuf, mode:u64) -> u32:
    if length(s) != 72 or read(s, 32) != 1 or read(s, 40) != 0 or read(s, 48) != 0:
        return finish(w, 1, 0, 0)
    bits = read(s, 64)
    magnitude = bits & 9223372036854775807
    if (magnitude >> 52) == 2047:
        if (magnitude & 4503599627370495) != 0:
            return constant_text(o, w, mode, 3)
        return constant_text(o, w, mode, choose((bits >> 63) != 0, 5, 4))
    put(w, length(w) - 192, bits)
    count = widen(format_render_binary64(w))
    if count == 0 or count > 32:
        return finish(w, 5, 0, count)
    if mode == 0:
        return finish(w, 0, count, 0)
    if count > length(o) >> 2:
        return finish(w, 2, 0, count)
    index = 0
    while index < count:
        point(o, index, byte(w, length(w) - 2048 + index))
        index = index + 1
    return finish(w, 0, count, 0)

def constant_text(o:mutbuf, w:mutbuf, mode:u64, kind:u64) -> u32:
    count = choose(kind == 1, 5, choose(kind == 3, 3, choose(kind == 4, 8, choose(kind == 5, 9, 4))))
    if kind > 5:
        return finish(w, 1, 0, 0)
    if mode == 0:
        return finish(w, 0, count, 0)
    if count > length(o) >> 2:
        return finish(w, 2, 0, count)
    index = 0
    while index < count:
        point(o, index, constant_point(kind, index))
        index = index + 1
    return finish(w, 0, count, 0)

def constant_point(kind:u64, index:u64) -> u64:
    if kind == 5 and index == 0:
        return 45
    shift = index
    if kind == 5:
        shift = index - 1
    word = NULL_WORD
    if kind == 1:
        word = FALSE_WORD
    elif kind == 2:
        word = TRUE_WORD
    elif kind == 3:
        word = NAN_WORD
    elif kind == 4 or kind == 5:
        word = INF_WORD
    return (word >> (shift * 8)) & 255

def point(o:mutbuf, at:u64, value:u64) -> u64:
    index = 0
    while index < 4:
        store(o, at * 4 + index, (value >> (index * 8)) & 255)
        index = index + 1
    return 0

def read(s:readbuf, at:u64) -> u64:
    value = 0
    index = 0
    while index < 8:
        value = value | (byte(s, at + index) << (index * 8))
        index = index + 1
    return value

def read32(s:readbuf, at:u64) -> u64:
    value = 0
    index = 0
    while index < 4:
        value = value | (byte(s, at + index) << (index * 8))
        index = index + 1
    return value

def get32(w:mutbuf, at:u64) -> u64:
    value = 0
    index = 0
    while index < 4:
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

def widen(value:u32) -> u64:
    return value
'''


def source_program():
    from tools.generate_hia_worker_request import format_program

    class Constants(ast.NodeTransformer):
        def visit_Name(self, node):
            if node.id in SYMBOLS:
                return ast.copy_location(ast.Constant(SYMBOLS[node.id]), node)
            return node

    literal = ast.unparse(ast.fix_missing_locations(Constants().visit(ast.parse(SOURCE))))
    return literal + '\n' + format_program()


def document():
    from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

    nodes = ast.parse(source_program()).body
    if not nodes or any(not isinstance(node, ast.FunctionDef) for node in nodes):
        raise ValueError('only function definitions may enter CLI JSON text authoring')
    names = {node.name: 'f' + str(index) for index, node in enumerate(nodes)}
    if len(names) != len(nodes):
        raise ValueError('duplicate CLI JSON text authoring symbol')
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
                                  'module': 'cli_json_text', 'functions': functions})


if __name__ == '__main__':
    import argparse
    from hepta.hia_agent_assembly import render_assembly

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    with args.output.open('x') as stream:
        stream.write(render_assembly(document()))
