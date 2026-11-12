"""Author a HIA JSON wire-to-canonical-wire library, including key sorting.

This consumes the HIA value-arena decoder. It does not use a host JSON encoder
at execution time, or turn the still-Python semantic checker into HIA.
"""
from __future__ import annotations
import ast
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_json_decode import source_program as decoder_source
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

SOURCE = r'''
def canonical_json(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < 128 or length(o) < 128 or length(o) < length(s):
        return 4294967293
    maximum = get(w, 48)
    maximum_depth = get(w, 56)
    put(o, 48, maximum)
    put(o, 56, maximum_depth)
    result = widen(decode_json(s, w, o))
    if result >= 4294967292:
        return result
    # The decoded arena lives in w. Its reserved header word is now a cursor;
    # no foreign object or buffer alias is involved in serialization.
    put(w, 56, 0)
    node = 0
    going = True
    while going:
        record = 64 + node * 56
        kind = get(w, record)
        parent = get(w, record + 8)
        if parent != 18446744073709551615:
            if get(w, 64 + parent * 56) == 6:
                append_string(o, w, get(w, record + 40), get(w, record + 48))
                append_byte(o, w, 58)
        complete = True
        if kind == 5 or kind == 6:
            if kind == 6:
                sort_object(w, node)
            append_byte(o, w, choose(kind == 5, 91, 123))
            if get(w, record + 32) == 0:
                append_byte(o, w, choose(kind == 5, 93, 125))
            else:
                node = get(w, record + 24)
                complete = False
        else:
            start = get(w, record + 24)
            size = get(w, record + 32)
            if kind == 4:
                append_string(o, w, start, size)
            else:
                if kind == 3 and size == 2 and byte(s, start) == 45 and byte(s, start + 1) == 48:
                    append_byte(o, w, 48)
                else:
                    i = 0
                    while i < size:
                        append_byte(o, w, byte(s, start + i))
                        i = i + 1
        if complete:
            moving = True
            while moving:
                record = 64 + node * 56
                sibling = get(w, record + 16)
                if sibling != 18446744073709551615:
                    append_byte(o, w, 44)
                    node = sibling
                    moving = False
                else:
                    parent = get(w, record + 8)
                    if parent == 18446744073709551615:
                        going = False
                        moving = False
                    else:
                        node = parent
                        append_byte(o, w, choose(get(w, 64 + node * 56) == 5, 93, 125))
    return get(w, 56)

def append_byte(o:mutbuf, w:mutbuf, value:u64) -> u64:
    index = get(w, 56)
    store(o, index, value)
    put(w, 56, index + 1)
    return 0

def hex_digit(value:u64) -> u64:
    return choose(value < 10, value + 48, value + 87)

def append_string(o:mutbuf, w:mutbuf, start:u64, size:u64) -> u64:
    append_byte(o, w, 34)
    i = 0
    while i < size:
        value = byte(w, start + i)
        if value < 32:
            append_byte(o, w, 92)
            escape = 0
            if value == 8:
                escape = 98
            if value == 9:
                escape = 116
            if value == 10:
                escape = 110
            if value == 12:
                escape = 102
            if value == 13:
                escape = 114
            if escape != 0:
                append_byte(o, w, escape)
            else:
                append_byte(o, w, 117)
                append_byte(o, w, 48)
                append_byte(o, w, 48)
                append_byte(o, w, hex_digit(value >> 4))
                append_byte(o, w, hex_digit(value & 15))
        else:
            if value == 34 or value == 92:
                append_byte(o, w, 92)
            append_byte(o, w, value)
        i = i + 1
    append_byte(o, w, 34)
    return 0

def next_node(w:mutbuf, node:u64) -> u64:
    return get(w, 64 + node * 56 + 16)

def key_less(w:mutbuf, a:u64, b:u64) -> u64:
    ra = 64 + a * 56
    rb = 64 + b * 56
    aa = get(w, ra + 40)
    bb = get(w, rb + 40)
    na = get(w, ra + 48)
    nb = get(w, rb + 48)
    i = 0
    while i < na and i < nb:
        x = byte(w, aa + i)
        y = byte(w, bb + i)
        if x < y:
            return 1
        if x > y:
            return 0
        i = i + 1
    return choose(na <= nb, 1, 0)

def sort_object(w:mutbuf, node:u64) -> u64:
    record = 64 + node * 56
    size = get(w, record + 32)
    head = get(w, record + 24)
    width = 1
    while width < size:
        p = head
        head = 18446744073709551615
        tail = 18446744073709551615
        while p != 18446744073709551615:
            q = p
            left = 0
            while left < width and q != 18446744073709551615:
                q = next_node(w, q)
                left = left + 1
            right = width
            element = 0
            while left > 0 or (right > 0 and q != 18446744073709551615):
                take_left = False
                if left > 0:
                    if right == 0 or q == 18446744073709551615:
                        take_left = True
                    else:
                        if key_less(w, p, q) == 1:
                            take_left = True
                if take_left:
                    element = p
                    p = next_node(w, p)
                    left = left - 1
                else:
                    element = q
                    q = next_node(w, q)
                    right = right - 1
                if tail == 18446744073709551615:
                    head = element
                else:
                    put(w, 64 + tail * 56 + 16, element)
                tail = element
            p = q
        put(w, 64 + tail * 56 + 16, 18446744073709551615)
        width = width * 2
    put(w, record + 24, head)
    return 0
'''


def document():
    nodes = ast.parse(SOURCE + decoder_source()).body
    names = {node.name: 'f' + str(i) for i, node in enumerate(nodes)}
    signatures = {node.name: ([a.annotation.id for a in node.args.args], node.returns.id) for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = Builder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(v) for v in builder.params],
                          'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
                          'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8', 'module': 'json_canonical', 'functions': functions})


def main():
    path = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap/json_canonical.hepta'
    path.write_text(render_assembly(document()))
    print(path.name, path.stat().st_size)


if __name__ == '__main__':
    main()
