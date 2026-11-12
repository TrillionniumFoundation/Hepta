"""Author incremental SHA-256 state transitions in HIA, without a foreign hash."""
from __future__ import annotations
import ast
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
from tools.generate_hia_sha256 import INITIAL, ROUND, BODY, HELPERS

# Bytes 0..1087 retain the one-shot schedule/chaining layout. The state then
# holds total length, partial-block size, phase, 64 pending bytes and an ABI tag.
STATE_BYTES = 1184
MAX_CHUNK = 8 << 20
MAX_TOTAL = (1 << 61) - 1
MAGIC = 0x3153484132353648


# A stream may cover the full Agent 64 MiB quota. Keep the original one-shot
# authoring constants and algebra unchanged; only this stream uses these
# straight-line, checked u8 accesses. The order, full u64 width and layout are
# identical to the retained byte loops. No native-width memory primitive or
# foreign hash is introduced.
STREAM_WORD_HELPERS = r'''
def get(w:mutbuf, index:u64) -> u64:
    value = byte(w, index)
    value = value | (byte(w, index + 1) << 8)
    value = value | (byte(w, index + 2) << 16)
    value = value | (byte(w, index + 3) << 24)
    value = value | (byte(w, index + 4) << 32)
    value = value | (byte(w, index + 5) << 40)
    value = value | (byte(w, index + 6) << 48)
    value = value | (byte(w, index + 7) << 56)
    return value

def put(w:mutbuf, index:u64, value:u64) -> u64:
    store(w, index, value & 255)
    store(w, index + 1, (value >> 8) & 255)
    store(w, index + 2, (value >> 16) & 255)
    store(w, index + 3, (value >> 24) & 255)
    store(w, index + 4, (value >> 32) & 255)
    store(w, index + 5, (value >> 40) & 255)
    store(w, index + 6, (value >> 48) & 255)
    store(w, index + 7, (value >> 56) & 255)
    return 0
'''


def source_program():
    source = '''def stream(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 1 or length(s) > 8388609 or length(o) < 32 or length(w) < 1184:
        return 4294967293
    op = byte(s, 0)
    if op == 0:
        if length(s) != 1:
            return 4294967293
'''
    for i, value in enumerate(ROUND):
        source += f'        put(w, {i * 8}, {value})\n'
    for i, value in enumerate(INITIAL):
        source += f'        put(w, {1024 + i * 8}, {value})\n'
    source += f'''        put(w, 1088, 0)
        put(w, 1096, 0)
        put(w, 1104, 1)
        put(w, 1176, {MAGIC})
        return 0
    if op != 1 and op != 2:
        return 4294967293
    if get(w, 1176) != {MAGIC} or get(w, 1104) != 1:
        return 4294967293
    total = get(w, 1088)
    used = get(w, 1096)
    if total > 2305843009213693951 or used != (total & 63):
        return 4294967293
    if op == 1:
        count = length(s) - 1
        if count > 2305843009213693951 - total:
            return 4294967293
        i = 1
        while i < length(s):
            store(w, 1112 + used, byte(s, i))
            used = used + 1
            if used == 64:
                compress(w)
                used = 0
            i = i + 1
        put(w, 1088, total + count)
        put(w, 1096, used)
        return 0
    if length(s) != 1:
        return 4294967293
    store(w, 1112 + used, 128)
    used = used + 1
    while used != 56:
        if used == 64:
            compress(w)
            used = 0
        else:
            store(w, 1112 + used, 0)
            used = used + 1
    bits = total << 3
    i = 0
    while i < 8:
        store(w, 1168 + i, (bits >> ((7 - i) * 8)) & 255)
        i = i + 1
    compress(w)
    put(w, 1104, 2)
    i = 0
    while i < 8:
        value = get(w, 1024 + i * 8)
        j = 0
        while j < 4:
            store(o, i * 4 + j, (value >> ((3 - j) * 8)) & 255)
            j = j + 1
        i = i + 1
    return 32

def compress(w:mutbuf) -> u64:
    i = 0
    while i < 16:
        value = 0
        j = 0
        while j < 4:
            value = (value << 8) | byte(w, 1112 + i * 4 + j)
            j = j + 1
        put(w, 512 + i * 8, value)
        i = i + 1
'''
    # Reuse exactly the independently qualified SHA schedule and round algebra;
    # only message delivery/padding and persistent state differ from one-shot.
    compression = BODY[BODY.index('        while i < 64:'):]
    source += ''.join(line[4:] + '\n' for line in compression.splitlines())
    for i, name in enumerate('abcdefgh'):
        source += f'    put(w, {1024 + i * 8}, (get(w, {1024 + i * 8}) + {name}) & 4294967295)\n'
    source += '    return 0\n'
    return (source + HELPERS[HELPERS.index('\ndef rotate'):HELPERS.index('\ndef get')]
            + STREAM_WORD_HELPERS)


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
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8', 'module': 'sha256_stream', 'functions': functions})


def main():
    path = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap/sha256_stream.hiaasm'
    path.write_text(render_assembly(document()))
    print(path.name, path.stat().st_size)


if __name__ == '__main__':
    main()
