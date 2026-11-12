"""Author the full Core edge capability-renaming policy in HIA.

The host transports opaque string identities; this program implements every
injectivity/liveness/closure decision and every graph-field renaming. This is
not the full Core verifier or an all-input refinement proof.
"""
import ast
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
MAGIC = int.from_bytes(b'HIACAP01', 'little')
RESULT = int.from_bytes(b'HIACAR01', 'little')
NONE = (1 << 64) - 1

def source_program():
    return SOURCE.replace('RESULT', str(RESULT)).replace('MAGIC', str(MAGIC)).replace('NONE', str(NONE))

SOURCE = r'''
def rename(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 64 or uint(s, 0) != MAGIC:
        return 4294967295
    n = uint(s, 8)
    m = uint(s, 16)
    ns = uint(s, 24)
    if n > 262144 or m > 262144 or ns > 2097152:
        return 4294967295
    if length(s) != 64 + n * 48 + m * 16:
        return 4294967295
    if uint(s, 32) != 0 or uint(s, 40) != 0 or uint(s, 48) != 0 or uint(s, 56) != 0:
        return 4294967295
    size = 64 + m * 48
    if length(o) < size or length(w) < size + ns * 24:
        return 4294967294
    # Three private symbol-indexed tables: capabilities, sources, targets.
    i = 0
    while i < ns * 24:
        store(w, size + i, 255)
        i = i + 1
    i = 0
    while i < n:
        at = 64 + i * 48
        name = uint(s, at)
        typ = uint(s, at + 8)
        root = uint(s, at + 16)
        parent = uint(s, at + 24)
        origin = uint(s, at + 40)
        if name >= ns or typ >= ns or root >= ns or uint(s, at + 32) > 1:
            return 4294967295
        if parent != NONE and parent >= ns:
            return 4294967295
        if origin != NONE and origin >= ns:
            return 4294967295
        if get(w, size + name * 8) != NONE:
            return 4294967295
        put(w, size + name * 8, i)
        i = i + 1
    i = 0
    while i < m:
        at = 64 + n * 48 + i * 16
        source = uint(s, at)
        target = uint(s, at + 8)
        if source >= ns or target >= ns:
            return 4294967295
        if get(w, size + ns * 8 + source * 8) != NONE:
            return 4294967295
        put(w, size + ns * 8 + source * 8, i)
        if get(w, size + ns * 16 + target * 8) != NONE:
            return 4294967293
        put(w, size + ns * 16 + target * 8, i)
        i = i + 1
    # Error precedence matches the production, independently specified policy:
    # injectivity, absent capability, local loss, then root/parent closure.
    i = 0
    while i < m:
        source = uint(s, 64 + n * 48 + i * 16)
        if get(w, size + source * 8) == NONE:
            return 4294967292
        i = i + 1
    i = 0
    while i < n:
        at = 64 + i * 48
        if uint(s, at + 32) == 0:
            if get(w, size + ns * 8 + uint(s, at) * 8) == NONE:
                return 4294967291
        i = i + 1
    i = 0
    while i < m:
        edge = 64 + n * 48 + i * 16
        source = uint(s, edge)
        cap = 64 + get(w, size + source * 8) * 48
        root = uint(s, cap + 16)
        parent = uint(s, cap + 24)
        rr = get(w, size + ns * 8 + root * 8)
        if rr == NONE:
            return 4294967290
        pp = NONE
        if parent != NONE:
            pp = get(w, size + ns * 8 + parent * 8)
            if pp == NONE:
                return 4294967290
            pp = uint(s, 64 + n * 48 + pp * 16 + 8)
        result = 64 + i * 48
        put(w, result, uint(s, edge + 8))
        put(w, result + 8, uint(s, cap + 8))
        put(w, result + 16, uint(s, 64 + n * 48 + rr * 16 + 8))
        put(w, result + 24, pp)
        put(w, result + 32, uint(s, cap + 32))
        put(w, result + 40, uint(s, cap + 40))
        i = i + 1
    put(w, 0, RESULT)
    put(w, 8, m)
    put(w, 16, ns)
    i = 24
    while i < 64:
        put(w, i, 0)
        i = i + 8
    # No output write precedes complete graph admission, even on late failure.
    i = 0
    while i < size:
        store(o, i, byte(w, i))
        i = i + 1
    return size

def uint(s:readbuf, at:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(s, at + i) << (i * 8))
        i = i + 1
    return value

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
                          'returns': [b.returns], 'effects': ['read', 'write', 'trap'], 'entry': 'b0', 'blocks': b.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8', 'module': 'capability_renaming', 'functions': functions})

if __name__ == '__main__':
    path = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap/capability_renaming.hepta'
    path.write_text(render_assembly(document()))
    print(path.name, path.stat().st_size)
