"""Author the iterative HIA source-type grammar (candidate, not a whole parser).

Python is an authoring language only: the checked-in HIA program performs all
syntax decisions, path/generic/reference/array recognition and depth accounting.
Its flat result is materialized separately, never reparsed by a host grammar.
"""
from __future__ import annotations
import ast
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from hepta.hia_source_lexer_native import KEYWORD_ORDER, PAIR_ORDER
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

SOURCE = r'''
def entry(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < 9472 or length(s) < 48 or length(s) > 1048576:
        return 4294967293
    count = read_word(s, 8)
    payload = read_word(s, 32)
    if read_word(s, 0) != 3549479791681612104 or count == 0 or count > 4096 or read_word(s, 16) >= count or read_word(s, 24) > 96:
        return 4294967293
    if payload != 48 + count * 56 or payload > length(s) or read_word(s, 40) != length(s) - payload:
        return 4294967293
    i = 0
    last = 0
    while i < count:
        row = 48 + i * 56
        kind = read_word(s, row)
        if valid_kind(kind) == 0 or read_word(s, row + 8) < last or read_word(s, row + 16) < read_word(s, row + 8) or read_word(s, row + 24) == 0 or read_word(s, row + 32) == 0:
            return 4294967293
        if read_word(s, row + 40) > read_word(s, row + 48) or read_word(s, row + 48) > length(s) - payload:
            return 4294967293
        if (kind == 0 and i + 1 != count) or (i + 1 == count and kind != 0):
            return 4294967293
        last = read_word(s, row + 16)
        i = i + 1
    initialize(s, w, 0)
    run(s, o, w)
    nodes = get(w, 24)
    splits = get(w, 32)
    size = 80 + nodes * 64 + splits * 16
    if length(o) < size:
        return 4294967294
    initialize(s, w, 1)
    put(w, 56, nodes)
    run(s, o, w)
    put(o, 0, get(w, 24))
    put(o, 8, get(w, 32))
    put(o, 16, get(w, 0))
    put(o, 24, get(w, 8))
    put(o, 32, get(w, 72))
    put(o, 40, get(w, 40))
    put(o, 48, get(w, 96))
    put(o, 56, get(w, 104))
    put(o, 64, get(w, 112))
    put(o, 72, get(w, 120))
    return size

def initialize(s:readbuf, w:mutbuf, phase:u64) -> u64:
    i = 0
    while i < 128:
        put(w, i, 0)
        i = i + 8
    put(w, 0, read_word(s, 16))
    put(w, 48, phase)
    return 0

def valid_kind(k:u64) -> u64:
    if k <= 5 or (k >= 128 and k < 157) or (k >= 512 and k < 524):
        return 1
    if k >= 256 and k < 384:
        return 1
    return 0

def kind(s:readbuf, w:mutbuf) -> u64:
    if get(w, 8) != 0:
        return get(w, 8)
    return read_word(s, 48 + get(w, 0) * 56)

def advance(s:readbuf, w:mutbuf) -> u64:
    if kind(s, w) != 0:
        put(w, 0, get(w, 0) + 1)
        put(w, 8, 0)
    return 0

def fail(w:mutbuf, error:u64, expected:u64) -> u64:
    if get(w, 40) == 0:
        put(w, 40, error)
        put(w, 96, get(w, 0))
        put(w, 104, get(w, 8))
        put(w, 112, expected)
    return 0

def expect(s:readbuf, w:mutbuf, wanted:u64, error:u64) -> u64:
    if kind(s, w) != wanted:
        fail(w, error, wanted)
        return 0
    advance(s, w)
    return 1

def frame(w:mutbuf) -> u64:
    return 256 + (get(w, 16) - 1) * 96

def field(o:mutbuf, w:mutbuf, node:u64, index:u64, value:u64) -> u64:
    if get(w, 48) == 1:
        put(o, 80 + (node - 1) * 64 + index * 8, value)
    return 0

def node(o:mutbuf, w:mutbuf, tag:u64, token:u64) -> u64:
    n = get(w, 24) + 1
    put(w, 24, n)
    i = 0
    while i < 8:
        field(o, w, n, i, 0)
        i = i + 1
    field(o, w, n, 0, tag)
    field(o, w, n, 1, token)
    return n

def add_lifetime(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    f = frame(w)
    life = node(o, w, 8, get(w, 0))
    if get(w, f + 32) == 0:
        field(o, w, get(w, f), 4, life)
    else:
        field(o, w, get(w, f + 32), 6, life)
    put(w, f + 32, life)
    advance(s, w)
    return 0

def special(s:readbuf, token:u64) -> u64:
    row = 48 + token * 56
    at = read_word(s, 32) + read_word(s, row + 40)
    n = read_word(s, row + 48) - read_word(s, row + 40)
    if n == 6:
        if peek(s, at) == 66 and peek(s, at+1) == 117 and peek(s, at+2) == 102 and peek(s, at+3) == 102 and peek(s, at+4) == 101 and peek(s, at+5) == 114:
            return 1
        if peek(s, at) == 83 and peek(s, at+1) == 101 and peek(s, at+2) == 110 and peek(s, at+3) == 100 and peek(s, at+4) == 101 and peek(s, at+5) == 114:
            return 3
    if n == 4:
        if peek(s, at) == 84 and peek(s, at+1) == 97 and peek(s, at+2) == 115 and peek(s, at+3) == 107:
            return 2
    return 0

def close(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    k = kind(s, w)
    if k == K_SHR or k == K_GE:
        if get(w, 48) == 1:
            at = 80 + get(w, 56) * 64 + get(w, 32) * 16
            put(o, at, get(w, 0))
            put(o, at + 8, k)
        put(w, 32, get(w, 32) + 1)
        second = 318
        if k == K_GE:
            second = 317
        put(w, 8, second)
        return 1
    return expect(s, w, 318, 5)

def run(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    while get(w, 80) != 4 and get(w, 40) == 0:
        mode = get(w, 80)
        if mode == 0:
            begin(s, o, w)
        else:
            if mode == 1:
                deliver(s, o, w)
            else:
                if mode == 2:
                    if kind(s, w) == 2:
                        add_lifetime(s, o, w)
                        put(w, 80, 3)
                    else:
                        put(w, 80, 0)
                else:
                    if kind(s, w) == 300:
                        advance(s, w)
                        put(w, 80, 2)
                    else:
                        if close(s, o, w) == 1:
                            put(w, 80, 1)
    return 0

def begin(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if read_word(s, 24) + get(w, 16) + 1 > 96:
        return fail(w, 7, 0)
    put(w, 16, get(w, 16) + 1)
    f = frame(w)
    i = 0
    while i < 96:
        put(w, f + i, 0)
        i = i + 8
    k = kind(s, w)
    tag = 0
    if k == K_READ:
        tag = 5
    if k == K_MUT:
        tag = 6
    if k == 347:
        tag = 1
    if k == K_RAW:
        tag = 3
    n = node(o, w, tag, get(w, 0))
    put(w, f, n)
    put(w, f + 8, tag)
    if tag == 5 or tag == 6:
        advance(s, w)
        if kind(s, w) != 2:
            return fail(w, 3, 2)
        add_lifetime(s, o, w)
        return 0
    if tag == 1:
        advance(s, w)
        return 0
    if tag == 3:
        advance(s, w)
        k = kind(s, w)
        if k != K_CONST and k != K_MUT:
            return fail(w, 4, 0)
        if k == K_MUT:
            put(w, f + 8, 4)
            field(o, w, n, 0, 4)
        advance(s, w)
        return 0
    if kind(s, w) != 1:
        return fail(w, 1, 1)
    put(w, f + 56, get(w, 0))
    put(w, f + 64, special(s, get(w, 0)))
    part = node(o, w, 7, get(w, 0))
    field(o, w, n, 2, part)
    put(w, f + 40, part)
    advance(s, w)
    while kind(s, w) == K_PATH and get(w, 40) == 0:
        advance(s, w)
        if kind(s, w) != 1:
            return fail(w, 2, 1)
        part = node(o, w, 7, get(w, 0))
        field(o, w, get(w, f + 40), 6, part)
        put(w, f + 40, part)
        put(w, f + 64, 0)
        advance(s, w)
    if kind(s, w) == 316:
        advance(s, w)
        put(w, 80, 2)
    else:
        put(w, 80, 1)
    return 0

def deliver(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    f = frame(w)
    if get(w, f + 64) != 0 and get(w, f + 24) != 1:
        put(w, 120, get(w, f + 56))
        return fail(w, 8, get(w, f + 64))
    child = get(w, f)
    put(w, 16, get(w, 16) - 1)
    if get(w, 16) == 0:
        put(w, 72, child)
        put(w, 80, 4)
        return 0
    f = frame(w)
    parent = get(w, f)
    tag = get(w, f + 8)
    if tag == 0:
        if get(w, f + 16) == 0:
            field(o, w, parent, 3, child)
        else:
            field(o, w, get(w, f + 16), 6, child)
        put(w, f + 16, child)
        put(w, f + 24, get(w, f + 24) + 1)
        put(w, 80, 3)
    else:
        field(o, w, parent, 5, child)
        if tag == 1:
            if kind(s, w) == 315:
                advance(s, w)
                if kind(s, w) != 3:
                    return fail(w, 6, 3)
                field(o, w, parent, 0, 2)
                field(o, w, parent, 1, get(w, 0))
                advance(s, w)
            expect(s, w, 349, 9)
        put(w, 80, 1)
    return 0

def read_word(s:readbuf, at:u64) -> u64:
    value = 0
    value = value | (byte(s, at + 0) << 0)
    value = value | (byte(s, at + 1) << 8)
    value = value | (byte(s, at + 2) << 16)
    value = value | (byte(s, at + 3) << 24)
    value = value | (byte(s, at + 4) << 32)
    value = value | (byte(s, at + 5) << 40)
    value = value | (byte(s, at + 6) << 48)
    value = value | (byte(s, at + 7) << 56)
    return value

def get(w:mutbuf, at:u64) -> u64:
    value = 0
    value = value | (byte(w, at + 0) << 0)
    value = value | (byte(w, at + 1) << 8)
    value = value | (byte(w, at + 2) << 16)
    value = value | (byte(w, at + 3) << 24)
    value = value | (byte(w, at + 4) << 32)
    value = value | (byte(w, at + 5) << 40)
    value = value | (byte(w, at + 6) << 48)
    value = value | (byte(w, at + 7) << 56)
    return value

def peek(s:readbuf, at:u64) -> u64:
    if at >= length(s):
        return 0
    return byte(s, at)

def put(o:mutbuf, at:u64, value:u64) -> u64:
    store(o, at + 0, (value >> 0) & 255)
    store(o, at + 1, (value >> 8) & 255)
    store(o, at + 2, (value >> 16) & 255)
    store(o, at + 3, (value >> 24) & 255)
    store(o, at + 4, (value >> 32) & 255)
    store(o, at + 5, (value >> 40) & 255)
    store(o, at + 6, (value >> 48) & 255)
    store(o, at + 7, (value >> 56) & 255)
    return 0
'''


def source_program():
    text = SOURCE
    for name, word in {'READ':'read', 'MUT':'mut', 'RAW':'raw', 'CONST':'const'}.items():
        text = text.replace('K_'+name, str(128 + KEYWORD_ORDER.index(word)))
    for name, word in {'SHR':'>>', 'GE':'>=', 'PATH':'::'}.items():
        text = text.replace('K_'+name, str(512 + PAIR_ORDER.index(word)))
    return text


def document():
    nodes = ast.parse(source_program()).body
    names = {node.name: 'f'+str(i) for i, node in enumerate(nodes)}
    signatures = {node.name: ([a.annotation.id for a in node.args.args], node.returns.id) for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = Builder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(v) for v in builder.params],
            'returns': [builder.returns], 'effects': ['read','write','trap'], 'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema':'hepta.hia.program.v8', 'module':'source_type_parser', 'functions':functions})


def main():
    path = Path(__file__).resolve().parents[1]/'examples/hia_bootstrap/source_type_parser.hiaasm'
    path.write_text(render_assembly(document()))
    print(path.name, path.stat().st_size)


if __name__ == '__main__':
    main()
