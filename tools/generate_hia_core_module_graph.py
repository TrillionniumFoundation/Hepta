"""Author Core module/name resolution in HIA, independent of high-level Hepta."""
import ast
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

MAGIC = int.from_bytes(b'HIAMOD01', 'little')
RESULT = int.from_bytes(b'HIAMOR01', 'little')
NONE = (1 << 64) - 1

def source_program():
    return r'''
def resolve(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if valid(s) == 0:
        return 4294967295
    nm = uint(s, 8)
    nf = uint(s, 16)
    ni = uint(s, 24)
    nc = uint(s, 32)
    nx = uint(s, 40)
    size = 64 + 8 * (nm + ni + nc + nx)
    if length(o) < size or length(w) < size + 8 * (nf + nm):
        return 4294967294
    i = 0
    while i < size + 8 * (nf + nm):
        store(w, i, 0)
        i = i + 1
    # Validate declarations before using names to resolve anything.
    status = declarations(s)
    if status != 0:
        return status
    entry = find_module(s, uint(s, 56), uint(s, 64))
    if entry == NONE:
        return 4294967288
    # Exports are separate facts: the host never computes visibility flags.
    i = 0
    while i < uint(s, 40):
        target = find_function(s, row(s, 4, i, 0), row(s, 4, i, 1), row(s, 4, i, 2))
        if target == NONE:
            return 4294967287
        if get(w, size + target * 8) != 0:
            return 4294967286
        put(w, size + target * 8, 1)
        exported = NONE
        if row(s, 4, i, 0) == entry:
            exported = target
        put(w, 64 + (nm + ni + nc) * 8 + i * 8, exported)
        i = i + 1
    i = 0
    while i < ni:
        status = resolve_import(s, w, i, size)
        if status != 0:
            return status
        i = i + 1
    i = 0
    while i < nc:
        caller = row(s, 3, i, 0)
        origin = row(s, 1, caller, 0)
        target = find_function(s, origin, row(s, 3, i, 1), row(s, 3, i, 2))
        if target == NONE:
            j = 0
            while j < ni:
                if row(s, 2, j, 0) == origin:
                    if equal(s, row(s, 2, j, 1), row(s, 2, j, 2), row(s, 3, i, 1), row(s, 3, i, 2)) != 0:
                        target = get(w, 64 + nm * 8 + j * 8)
                j = j + 1
        if target == NONE:
            return 4294967282
        put(w, 64 + (nm + ni) * 8 + i * 8, target)
        i = i + 1
    # Stable dependency-first order. Check every declared module, including
    # unused modules and unused imports, rather than pruning a failed witness.
    done = 0
    while done < nm:
        chosen = NONE
        b = 0
        while b < nm and chosen == NONE:
            if get(w, size + nf * 8 + b * 8) == 0:
                chosen = b
            b = b + 1
        if chosen == NONE:
            return 4294967281
        put(w, size + nf * 8 + chosen * 8, NONE)
        put(w, 64 + done * 8, chosen)
        i = 0
        while i < ni:
            target = get(w, 64 + nm * 8 + i * 8)
            if row(s, 1, target, 0) == chosen:
                origin = row(s, 2, i, 0)
                degree = get(w, size + nf * 8 + origin * 8)
                if degree == 0 or degree == NONE:
                    return 4294967295
                put(w, size + nf * 8 + origin * 8, degree - 1)
            i = i + 1
        done = done + 1
    # No public output byte changes before all names, privacy and cycles pass.
    put(w, 0, RESULT)
    put(w, 8, nm)
    put(w, 16, nf)
    put(w, 24, ni)
    put(w, 32, nc)
    put(w, 40, nx)
    put(w, 48, entry)
    i = 0
    while i < size:
        store(o, i, byte(w, i))
        i = i + 1
    return size

def valid(s:readbuf) -> u64:
    if length(s) < 80 or length(s) > 8388608 or uint(s, 0) != MAGIC or uint(s, 72) != 0:
        return 0
    nm = uint(s, 8)
    nf = uint(s, 16)
    if nm == 0 or nm > 1024 or nf == 0 or nf > 1024:
        return 0
    if uint(s, 24) > 4096 or uint(s, 32) > 16384 or uint(s, 40) > 1024 or uint(s, 48) > 8388608:
        return 0
    if strings(s) + uint(s, 48) != length(s) or name(s, uint(s, 56), uint(s, 64)) == 0:
        return 0
    i = 0
    end = 0
    while i < nm:
        if name(s, row(s, 0, i, 0), row(s, 0, i, 1)) == 0:
            return 0
        if row(s, 0, i, 2) != end or row(s, 0, i, 3) > nf - end:
            return 0
        stop = end + row(s, 0, i, 3)
        while end < stop:
            if row(s, 1, end, 0) != i or row(s, 1, end, 3) != 0:
                return 0
            if name(s, row(s, 1, end, 1), row(s, 1, end, 2)) == 0:
                return 0
            end = end + 1
        i = i + 1
    if end != nf:
        return 0
    i = 0
    while i < uint(s, 24):
        if row(s, 2, i, 0) >= nm:
            return 0
        j = 1
        while j < 7:
            if name(s, row(s, 2, i, j), row(s, 2, i, j + 1)) == 0:
                return 0
            j = j + 2
        i = i + 1
    i = 0
    while i < uint(s, 32):
        if row(s, 3, i, 0) >= nf or name(s, row(s, 3, i, 1), row(s, 3, i, 2)) == 0:
            return 0
        i = i + 1
    i = 0
    while i < uint(s, 40):
        if row(s, 4, i, 0) >= nm or name(s, row(s, 4, i, 1), row(s, 4, i, 2)) == 0:
            return 0
        i = i + 1
    return 1

def declarations(s:readbuf) -> u64:
    i = 0
    while i < uint(s, 8):
        j = 0
        while j < i:
            if equal(s, row(s, 0, i, 0), row(s, 0, i, 1), row(s, 0, j, 0), row(s, 0, j, 1)) != 0:
                return 4294967293
            j = j + 1
        i = i + 1
    i = 0
    while i < uint(s, 16):
        origin = row(s, 1, i, 0)
        j = row(s, 0, origin, 2)
        while j < i:
            if equal(s, row(s, 1, i, 1), row(s, 1, i, 2), row(s, 1, j, 1), row(s, 1, j, 2)) != 0:
                return 4294967292
            j = j + 1
        i = i + 1
    return 0

def resolve_import(s:readbuf, w:mutbuf, i:u64, size:u64) -> u64:
    origin = row(s, 2, i, 0)
    if find_function(s, origin, row(s, 2, i, 1), row(s, 2, i, 2)) != NONE:
        return 4294967291
    j = 0
    while j < i:
        if row(s, 2, j, 0) == origin:
            if equal(s, row(s, 2, i, 1), row(s, 2, i, 2), row(s, 2, j, 1), row(s, 2, j, 2)) != 0:
                return 4294967291
        j = j + 1
    target_module = find_module(s, row(s, 2, i, 3), row(s, 2, i, 4))
    if target_module == NONE:
        return 4294967290
    target = find_function(s, target_module, row(s, 2, i, 5), row(s, 2, i, 6))
    if target == NONE:
        return 4294967289
    if get(w, size + target * 8) == 0:
        return 4294967285
    put(w, 64 + uint(s, 8) * 8 + i * 8, target)
    degree = size + uint(s, 16) * 8 + origin * 8
    put(w, degree, get(w, degree) + 1)
    return 0

def find_module(s:readbuf, start:u64, count:u64) -> u64:
    i = 0
    while i < uint(s, 8):
        if equal(s, start, count, row(s, 0, i, 0), row(s, 0, i, 1)) != 0:
            return i
        i = i + 1
    return NONE

def find_function(s:readbuf, origin:u64, start:u64, count:u64) -> u64:
    i = row(s, 0, origin, 2)
    end = i + row(s, 0, origin, 3)
    while i < end:
        if equal(s, start, count, row(s, 1, i, 1), row(s, 1, i, 2)) != 0:
            return i
        i = i + 1
    return NONE

def name(s:readbuf, at:u64, n:u64) -> u64:
    if n == 0 or n > 128 or at > uint(s, 48) or n > uint(s, 48) - at:
        return 0
    start = strings(s) + at
    i = 0
    while i < n:
        c = byte(s, start + i)
        if c != 95 and (c < 65 or c > 90) and (c < 97 or c > 122):
            if i == 0 or c < 48 or c > 57:
                return 0
        i = i + 1
    if n >= 6:
        if byte(s, start) == 95 and byte(s, start + 1) == 95 and byte(s, start + 2) == 104:
            if byte(s, start + 3) == 105 and byte(s, start + 4) == 97 and byte(s, start + 5) == 95:
                return 0
    return 1

def equal(s:readbuf, a:u64, n:u64, b:u64, m:u64) -> u64:
    if n != m:
        return 0
    start = strings(s)
    i = 0
    while i < n:
        if byte(s, start + a + i) != byte(s, start + b + i):
            return 0
        i = i + 1
    return 1

def strings(s:readbuf) -> u64:
    return 80 + uint(s, 8) * 32 + uint(s, 16) * 32 + uint(s, 24) * 56 + uint(s, 32) * 24 + uint(s, 40) * 24

def row(s:readbuf, kind:u64, i:u64, field:u64) -> u64:
    base = 80
    stride = 32
    if kind >= 1:
        base = base + uint(s, 8) * 32
    if kind >= 2:
        base = base + uint(s, 16) * 32
        stride = 56
    if kind >= 3:
        base = base + uint(s, 24) * 56
        stride = 24
    if kind >= 4:
        base = base + uint(s, 32) * 24
    return uint(s, base + i * stride + field * 8)

def uint(s:readbuf, at:u64) -> u64:
    x = 0
    i = 0
    while i < 8:
        x = x | (byte(s, at + i) << (i * 8))
        i = i + 1
    return x

def get(w:mutbuf, at:u64) -> u64:
    x = 0
    i = 0
    while i < 8:
        x = x | (byte(w, at + i) << (i * 8))
        i = i + 1
    return x

def put(w:mutbuf, at:u64, x:u64) -> u64:
    i = 0
    while i < 8:
        store(w, at + i, x & 255)
        x = x >> 8
        i = i + 1
    return 0
'''.replace('RESULT', str(RESULT)).replace('MAGIC', str(MAGIC)).replace('NONE', str(NONE))

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
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8', 'module': 'core_module_graph', 'functions': functions})

if __name__ == '__main__':
    path = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap/core_module_graph.hiaasm'
    path.write_text(render_assembly(document()))
    print(path.name, path.stat().st_size)
