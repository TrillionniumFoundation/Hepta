"""Author a lossless HIA JSON arena decoder; no host JSON parser in the image.

The native arena records hierarchy, tags, decoded UTF-8 strings/keys and exact
integer lexemes. Materializing foreign Python objects remains a separate bridge.
"""
from __future__ import annotations
import ast
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_json_preflight import SOURCE as PREFLIGHT_SOURCE
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

DECODER_SOURCE = r'''
def decode_json(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) > 8388608 or length(w) < 128 or length(o) < 128:
        return 4294967293
    maximum = get(w, 48)
    maximum_depth = get(w, 56)
    if maximum < 1 or maximum > 1048576 or maximum_depth > 128:
        return 4294967293
    if length(w) < 128 + (maximum_depth + 1) * 48:
        return 4294967293
    put(o, 48, maximum)
    put(o, 56, maximum_depth)
    result = widen(preflight(s, w, o))
    if result == 1:
        return 4294967295
    if result == 2:
        return 4294967294
    if result == 4:
        return 4294967292
    if result != 0:
        return 4294967293
    count = get(o, 64)
    base = 64 + count * 56
    if length(o) < base + length(s):
        return 4294967293
    # Phase one used o as a small state stack and w as key slots. Phase two
    # reuses w for a private container stack; no value graph was built earlier.
    put(w, 0, 0)
    put(w, 64, 0)
    put(w, 72, base)
    put(w, 96, 0)
    going = True
    while going:
        index = whitespace(s, get(w, 0))
        put(w, 0, index)
        if index == length(s):
            going = False
        else:
            ch = byte(s, index)
            if ch == 44 or ch == 58:
                put(w, 0, index + 1)
            else:
                if ch == 93 or ch == 125:
                    put(w, 96, get(w, 96) - 1)
                    put(w, 0, index + 1)
                else:
                    if ch == 91 or ch == 123:
                        kind = choose(ch == 91, 5, 6)
                        node = new_node(o, w, kind, 18446744073709551615, 0)
                        depth = get(w, 96)
                        frame = 128 + depth * 48
                        put(w, frame, node)
                        put(w, frame + 8, kind)
                        put(w, frame + 16, 18446744073709551615)
                        put(w, frame + 24, 0)
                        put(w, frame + 32, 0)
                        put(w, frame + 40, 0)
                        put(w, 96, depth + 1)
                        put(w, 0, index + 1)
                    else:
                        if ch == 34:
                            decode_string(s, o, w)
                            depth = get(w, 96)
                            key = False
                            frame = 128
                            if depth > 0:
                                frame = 128 + (depth - 1) * 48
                                if get(w, frame + 8) == 6 and get(w, frame + 40) == 0:
                                    key = True
                            if key:
                                put(w, frame + 24, get(w, 80))
                                put(w, frame + 32, get(w, 88))
                                put(w, frame + 40, 1)
                            else:
                                new_node(o, w, 4, get(w, 80), get(w, 88))
                        else:
                            end = atom(s, index)
                            kind = 3
                            if ch == 110:
                                kind = 0
                            if ch == 102:
                                kind = 1
                            if ch == 116:
                                kind = 2
                            new_node(o, w, kind, index, end - index)
                            put(w, 0, end)
    if get(w, 64) != count or get(w, 96) != 0:
        return 4294967293
    put(o, 0, 5208772604367785521)
    put(o, 8, count)
    put(o, 16, base)
    put(o, 24, get(w, 72))
    put(o, 32, get(w, 72))
    put(o, 40, length(s))
    put(o, 48, 1)
    put(o, 56, 0)
    return get(w, 72)

def widen(value:u64) -> u64:
    return value

def new_node(o:mutbuf, w:mutbuf, kind:u64, start:u64, size:u64) -> u64:
    node = get(w, 64)
    record = 64 + node * 56
    put(w, 64, node + 1)
    put(o, record, kind)
    put(o, record + 8, 18446744073709551615)
    put(o, record + 16, 18446744073709551615)
    put(o, record + 24, start)
    put(o, record + 32, size)
    put(o, record + 40, 0)
    put(o, record + 48, 0)
    depth = get(w, 96)
    if depth > 0:
        frame = 128 + (depth - 1) * 48
        parent = get(w, frame)
        put(o, record + 8, parent)
        parent_record = 64 + parent * 56
        previous = get(w, frame + 16)
        if previous == 18446744073709551615:
            put(o, parent_record + 24, node)
        else:
            put(o, 64 + previous * 56 + 16, node)
        put(w, frame + 16, node)
        put(o, parent_record + 32, get(o, parent_record + 32) + 1)
        if get(w, frame + 8) == 6:
            put(o, record + 40, get(w, frame + 24))
            put(o, record + 48, get(w, frame + 32))
            put(w, frame + 40, 0)
    return node

def decode_string(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    index = get(w, 0) + 1
    start = get(w, 72)
    going = True
    while going:
        unit = decoded(s, index)
        cp = unit & 4294967295
        index = unit >> 32
        if cp == 1114112:
            going = False
        else:
            write_scalar(o, w, cp)
    put(w, 0, index)
    put(w, 80, start)
    put(w, 88, get(w, 72) - start)
    return 0

def write_scalar(o:mutbuf, w:mutbuf, cp:u64) -> u64:
    index = get(w, 72)
    if cp < 128:
        store(o, index, cp)
        index = index + 1
    else:
        if cp < 2048:
            store(o, index, 192 | (cp >> 6))
            store(o, index + 1, 128 | (cp & 63))
            index = index + 2
        else:
            if cp < 65536:
                store(o, index, 224 | (cp >> 12))
                store(o, index + 1, 128 | ((cp >> 6) & 63))
                store(o, index + 2, 128 | (cp & 63))
                index = index + 3
            else:
                store(o, index, 240 | (cp >> 18))
                store(o, index + 1, 128 | ((cp >> 12) & 63))
                store(o, index + 2, 128 | ((cp >> 6) & 63))
                store(o, index + 3, 128 | (cp & 63))
                index = index + 4
    put(w, 72, index)
    return 0
'''


def source_program():
    # Preserve the already qualified preflight algorithm exactly; only export
    # its observed node count to private state for this separate arena profile.
    old = '            if index == length(s):\n                return 0'
    new = '            if index == length(s):\n                put(w, 64, nodes)\n                return 0'
    if PREFLIGHT_SOURCE.count(old) != 1:
        raise ValueError('preflight node-count export point changed')
    return DECODER_SOURCE + PREFLIGHT_SOURCE.replace(old, new)


def document():
    nodes = ast.parse(source_program()).body
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
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8', 'module': 'json_decode', 'functions': functions})


def main():
    path = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap/json_decode.hepta'
    path.write_text(render_assembly(document()))
    print(path.name, path.stat().st_size)


if __name__ == '__main__':
    main()
