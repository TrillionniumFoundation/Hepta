"""HIA-only JSON snapshot decoding and materialization; no object transport."""
from __future__ import annotations
import ast
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_json_decode import source_program as decoder_source
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

ADAPTER = r'''
def snapshot_json(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < 6320:
        return 4294967294
    put(w, 48, 1048576)
    put(w, 56, 128)
    status = widen(decode_json(s, o, w))
    if status == 4294967294 or status == 4294967293:
        return 4294967294
    if status == 4294967295 or status == 4294967292:
        return 4294967295
    if status < 120 or status > length(o):
        return 4294967294
    if get(o, 64) != 6 or get(o, 96) < 1 or get(o, 96) > 2:
        return 4294967295
    put(w, 0, 0)
    put(w, 8, 0)
    put(w, 16, 0)
    put(w, 32, 0)
    put(w, 48, 0)
    child = get(o, 88)
    i = 0
    while i < get(o, 96):
        if child >= get(o, 8):
            return 4294967295
        record = 64 + child * 56
        key = descriptor_key(o, get(o, record + 40), get(o, record + 48))
        if key == 0 or (get(w, 0) & (1 << key)) != 0:
            return 4294967295
        put(w, 0, get(w, 0) | (1 << key))
        if key == 1:
            if get(o, record) != 4:
                return 4294967295
            put(w, 8, get(o, record + 24))
            put(w, 16, get(o, record + 32))
        else:
            if get(o, record) != 3:
                return 4294967295
            number = bounded_integer(s, get(o, record + 24), get(o, record + 32))
            if number > 1048576:
                return 4294967295
            if key == 2:
                put(w, 32, number)
            else:
                put(w, 48, number)
        child = get(o, record + 16)
        i = i + 1
    size = get(w, 32)
    if get(w, 0) == 2:
        if get(w, 16) > 2097152 or (get(w, 16) & 1) != 0:
            return 4294967295
        i = 0
        while i < get(w, 16):
            if snapshot_nibble(byte(o, get(w, 8) + i)) > 15:
                return 4294967295
            i = i + 1
        size = get(w, 16) >> 1
    elif get(w, 0) == 12:
        if size > 1048576 or get(w, 48) > 255:
            return 4294967295
    else:
        return 4294967295
    if length(o) < size:
        return 4294967294
    i = 0
    while i < size:
        value = get(w, 48)
        if get(w, 0) == 2:
            value = (snapshot_nibble(byte(o, get(w, 8) + i * 2)) << 4) | snapshot_nibble(byte(o, get(w, 8) + i * 2 + 1))
        store(o, i, value)
        i = i + 1
    return size

def bounded_integer(s:readbuf, start:u64, size:u64) -> u64:
    if size == 0 or start > length(s) or size > length(s) - start:
        return 1048577
    if byte(s, start) == 45:
        if size == 2 and byte(s, start + 1) == 48:
            return 0
        return 1048577
    value = 0
    i = 0
    while i < size:
        ch = byte(s, start + i)
        if ch < 48 or ch > 57:
            return 1048577
        value = value * 10 + ch - 48
        if value > 1048576:
            return 1048577
        i = i + 1
    return value

def snapshot_nibble(value:u64) -> u64:
    if value >= 48 and value <= 57:
        return value - 48
    if value >= 97 and value <= 102:
        return value - 87
    return 256
'''


def source_program():
    key = '\ndef descriptor_key(o:mutbuf, start:u64, size:u64) -> u64:\n'
    key += '    if start > length(o) or size > length(o) - start:\n        return 0\n'
    for number, word in enumerate(('bytes_hex', 'byte_length', 'fill_byte'), 1):
        tests = [f'size == {len(word)}'] + [f'byte(o, start + {i}) == {v}' for i, v in enumerate(word.encode())]
        key += '    if ' + ' and '.join(tests) + f':\n        return {number}\n'
    key += '    return 0\n'
    return ADAPTER + key + decoder_source()


def document():
    nodes = ast.parse(source_program()).body
    assert len({n.name for n in nodes}) == len(nodes)
    names = {n.name: 'f' + str(i) for i, n in enumerate(nodes)}
    signatures = {n.name: ([a.annotation.id for a in n.args.args], n.returns.id) for n in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = Builder(node, names, signatures, total); builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(p) for p in builder.params],
            'returns': [builder.returns], 'effects': ['read', 'write', 'trap'], 'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8', 'module': 'agent_snapshot_json', 'functions': functions})


def main():
    path = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap/agent_snapshot_json.hiaasm'
    path.write_text(render_assembly(document())); print(path.name, path.stat().st_size)


if __name__ == '__main__':
    main()
