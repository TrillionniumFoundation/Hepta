"""Author Agent snapshot admission/materialization as explicit HIA Core.

The Python AST is an authoring notation only, not an admitted runtime input.
Native HIA checks field inventory, value tags, canonical lowercase hex, extents
and fill range before writing any result. It neither opens files nor grants
buffer ownership or invocation authority.
"""
from __future__ import annotations
import ast
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

BODY = r'''
def snapshot(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < 64:
        return 4294967293
    status = parse(s, w)
    if status != 0:
        return status
    size = getw(w, 32)
    if getw(w, 0) == 2:
        if getw(w, 24) != 1 or getw(w, 16) > 2097152 or (getw(w, 16) & 1) != 0:
            return 1
        i = 0
        while i < getw(w, 16):
            if nibble(byte(s, getw(w, 8) + i)) > 15:
                return 1
            i = i + 1
        size = getw(w, 16) >> 1
    elif getw(w, 0) == 12:
        if getw(w, 40) != 2 or getw(w, 56) != 2 or size > 1048576 or getw(w, 48) > 255:
            return 2
    else:
        return 3
    required = 8
    if get(s, 8) == 1:
        required = required + size
    if length(o) < required:
        return 5
    put(o, 0, size)
    if get(s, 8) == 1:
        i = 0
        while i < size:
            value = getw(w, 48)
            if getw(w, 0) == 2:
                value = (nibble(byte(s, getw(w, 8) + i * 2)) << 4) | nibble(byte(s, getw(w, 8) + i * 2 + 1))
            store(o, i + 8, value)
            i = i + 1
    return 0

def parse(s:readbuf, w:mutbuf) -> u64:
    if length(s) < 32:
        return 4294967293
    if get(s, 0) != 1 or get(s, 8) > 1:
        return 4294967293
    if get(s, 16) != 1:
        return 4
    if get(s, 24) < 1 or get(s, 24) > 2:
        return 3
    i = 0
    while i < 64:
        store(w, i, 0)
        i = i + 1
    pos = 32
    i = 0
    while i < get(s, 24):
        if pos > length(s) or length(s) - pos < 32:
            return 4294967293
        key = get(s, pos)
        tag = get(s, pos + 8)
        extent = get(s, pos + 16)
        number = get(s, pos + 24)
        pos = pos + 32
        if key < 1 or key > 3:
            return 3
        if (getw(w, 0) & (1 << key)) != 0:
            return 3
        put(w, 0, getw(w, 0) | (1 << key))
        if extent > length(s) - pos:
            return 4294967293
        if tag != 1 and extent != 0:
            return 4294967293
        if key == 1:
            put(w, 8, pos)
            put(w, 16, extent)
            put(w, 24, tag)
        if key == 2:
            put(w, 32, number)
            put(w, 40, tag)
        if key == 3:
            put(w, 48, number)
            put(w, 56, tag)
        pos = pos + extent
        i = i + 1
    if pos != length(s):
        return 4294967293
    return 0

def nibble(value:u64) -> u64:
    if value >= 48 and value <= 57:
        return value - 48
    if value >= 97 and value <= 102:
        return value - 87
    return 256

def get(s:readbuf, index:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(s, index + i) << (i * 8))
        i = i + 1
    return value

def getw(s:mutbuf, index:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(s, index + i) << (i * 8))
        i = i + 1
    return value

def put(o:mutbuf, index:u64, value:u64) -> u64:
    i = 0
    while i < 8:
        store(o, index + i, value & 255)
        value = value >> 8
        i = i + 1
    return 0
'''


def document():
    nodes = ast.parse(BODY).body
    names = {node.name: 'f' + str(i) for i, node in enumerate(nodes)}
    signatures = {node.name: ([a.annotation.id for a in node.args.args], node.returns.id) for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = Builder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(v) for v in builder.params],
            'returns': [builder.returns], 'effects': ['read', 'write', 'trap'], 'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8', 'module': 'agent_snapshot', 'functions': functions})


def main():
    path = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap/agent_snapshot.hiaasm'
    path.write_text(render_assembly(document()))
    print(path.name, path.stat().st_size)


if __name__ == '__main__':
    main()
