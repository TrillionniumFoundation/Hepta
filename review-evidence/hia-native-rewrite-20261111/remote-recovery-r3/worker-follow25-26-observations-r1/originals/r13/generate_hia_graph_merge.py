"""Join two independently issued immutable GraphLeases without host traversal.

The new root is [selected left root, selected right root]. All original nodes,
edges, scalars, cycles and aliases within each input are preserved. Distinct
leases do not confer a cross-lease object-identity relationship. This is a
private mechanical graph owner, not JSON admission or public object capture.
"""
from __future__ import annotations
import ast
from hashlib import sha256
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import compact_authoring_cfg, total_scalar_functions
from tools import hia_agent_edit_source_views as shared

CONSTANTS = {'COMMAND': int.from_bytes(b'HIAGMC01', 'little'),
             'STATE': int.from_bytes(b'HIAGMW01', 'little'),
             'EVENT': int.from_bytes(b'HIAGME01', 'little'),
             'GRAPH': int.from_bytes(b'HIAGRF01', 'little'),
             'BAD': 0xfffffffd, 'MAX': (1 << 64) - 1}
SOURCE = r'''
def graph_merge(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    if length(w) < 512:
        return BAD
    if get(w, 8) == 3:
        return BAD
    if get(w, 8) == 2:
        return refuse(w, 1)
    if length(s) < 256 or word(s, 0) != COMMAND or word(s, 16) == 0 or word(s, 24) == 0:
        return refuse(w, 2)
    i = 56
    while i < 128:
        if word(s, i) != 0:
            return refuse(w, 3)
        i = i + 8
    if graph_shape(s, 128, length(s) - 128) == 0 or graph_shape(r, 0, length(r)) == 0:
        return refuse(w, 4)
    if word(s, 40) == 0 or word(s, 40) > word(s, 144) or word(s, 48) == 0 or word(s, 48) > word(r, 16):
        return refuse(w, 5)
    if get(w, 8) == 0:
        if word(s, 8) != 1 or word(s, 32) != 0:
            return refuse(w, 6)
        i = 0
        while i < 512:
            if byte(w, i) != 0:
                return refuse(w, 7)
            i = i + 1
        put(w, 0, STATE)
        put(w, 8, 1)
        put(w, 16, word(s, 16))
        put(w, 24, word(s, 24))
        put(w, 40, length(s))
        put(w, 48, length(r))
        put(w, 56, word(s, 40))
        put(w, 64, word(s, 48))
        copy_bytes(w, s, 384, 128, 64)
        copy_bytes(w, r, 448, 0, 64)
        if plan(s, r, w) == 0:
            return refuse(w, 8)
    else:
        if get(w, 0) != STATE or get(w, 8) != 1 or word(s, 8) != 2:
            return refuse(w, 9)
        if word(s, 16) != get(w, 16) or word(s, 24) != get(w, 24) or word(s, 32) != get(w, 32):
            return refuse(w, 10)
        if length(s) != get(w, 40) or length(r) != get(w, 48):
            return refuse(w, 11)
        if word(s, 40) != get(w, 56) or word(s, 48) != get(w, 64):
            return refuse(w, 12)
        i = 0
        while i < 64:
            if byte(s, 128 + i) != byte(w, 384 + i) or byte(r, i) != byte(w, 448 + i):
                return refuse(w, 13)
            i = i + 1
    if get(w, 152) > length(w):
        return event(w, 1)
    fill_range(w, 512, get(w, 144), 0)
    put(w, 512, GRAPH)
    put(w, 520, get(w, 16))
    put(w, 528, get(w, 120))
    put(w, 536, 1)
    put(w, 544, get(w, 128))
    put(w, 552, get(w, 136))
    put(w, 560, get(w, 144))
    put(w, 576, 5)
    put(w, 608, 2)
    put(w, 616, 1)
    edgebase = 576 + get(w, 120) * 64
    put(w, edgebase, get(w, 56) + 1)
    put(w, edgebase + 8, get(w, 64) + get(w, 72) + 1)
    if clone_graph(s, w, 128, 1, 2, 0) == 0:
        return refuse(w, 14)
    if clone_graph(r, w, 0, get(w, 72) + 1, get(w, 88) + 2, get(w, 104)) == 0:
        return refuse(w, 15)
    put(w, 8, 2)
    return event(w, 0)

def graph_shape(s:readbuf, base:u64, size:u64) -> u64:
    if base > length(s) or size < 128 or size > length(s) - base:
        return 0
    if word(s, base) != GRAPH or word(s, base + 8) == 0 or word(s, base + 56) != 0:
        return 0
    nodes = word(s, base + 16)
    edges = word(s, base + 32)
    if nodes == 0 or nodes > (size - 64) >> 6:
        return 0
    edgebase = 64 + nodes * 64
    if edges > (size - edgebase) >> 3:
        return 0
    scalarbase = edgebase + edges * 8
    if word(s, base + 40) != size - scalarbase or word(s, base + 48) != size:
        return 0
    if word(s, base + 24) == 0 or word(s, base + 24) > nodes:
        return 0
    return 1

def plan(s:readbuf, r:readbuf, w:mutbuf) -> u64:
    put(w, 72, word(s, 144))
    put(w, 80, word(r, 16))
    put(w, 88, word(s, 160))
    put(w, 96, word(r, 32))
    put(w, 104, word(s, 168))
    put(w, 112, word(r, 40))
    if get(w, 72) >= MAX - get(w, 80) or get(w, 88) > MAX - 2 - get(w, 96):
        return 0
    nodes = get(w, 72) + get(w, 80) + 1
    edges = get(w, 88) + get(w, 96) + 2
    if nodes > (MAX - 64) >> 6:
        return 0
    base = 64 + nodes * 64
    if edges > (MAX - base) >> 3:
        return 0
    base = base + edges * 8
    if get(w, 104) > MAX - get(w, 112):
        return 0
    scalars = get(w, 104) + get(w, 112)
    if scalars > MAX - base or base + scalars > MAX - 512:
        return 0
    put(w, 120, nodes)
    put(w, 128, edges)
    put(w, 136, scalars)
    put(w, 144, base + scalars)
    put(w, 152, 512 + base + scalars)
    return 1

def clone_graph(s:readbuf, w:mutbuf, source:u64, node_delta:u64, edge_delta:u64, scalar_delta:u64) -> u64:
    n = word(s, source + 16)
    e = word(s, source + 32)
    sb = 64 + n * 64 + e * 8
    target_edges = 64 + get(w, 120) * 64
    target_scalars = target_edges + get(w, 128) * 8
    i = 0
    while i < n:
        at = source + 64 + i * 64
        target = 576 + (i + node_delta) * 64
        kind = word(s, at)
        if kind > 9 or word(s, at + 56) != 0:
            return 0
        copy_bytes(w, s, target, at, 64)
        if kind == 5 or kind == 6 or kind == 7:
            if clone_container(s, w, at, target, e, edge_delta, i + node_delta + 1) == 0:
                return 0
        else:
            if clone_scalar(s, w, at, target, sb, source + sb, target_scalars + scalar_delta, kind) == 0:
                return 0
        i = i + 1
    i = 0
    while i < e:
        value = word(s, source + 64 + n * 64 + i * 8)
        if value == 0 or value > n:
            return 0
        put(w, 512 + target_edges + (i + edge_delta) * 8, value + node_delta)
        i = i + 1
    copy_bytes(w, s, 512 + target_scalars + scalar_delta, source + sb, word(s, source + 40))
    return 1

def clone_container(s:readbuf, w:mutbuf, at:u64, target:u64, edges:u64, delta:u64, identity:u64) -> u64:
    if word(s, at + 8) != 0 or word(s, at + 16) != 0 or word(s, at + 40) == 0 or word(s, at + 48) != 0:
        return 0
    first = word(s, at + 24)
    count_ = word(s, at + 32)
    if word(s, at) == 6:
        if count_ > MAX >> 1:
            return 0
        count_ = count_ * 2
    if first > edges or count_ > edges - first:
        return 0
    put(w, target + 24, first + delta)
    put(w, target + 40, identity)
    return 1

def clone_scalar(s:readbuf, w:mutbuf, at:u64, target:u64, relative_base:u64, absolute_base:u64, target_base:u64, kind:u64) -> u64:
    if word(s, at + 24) != 0 or word(s, at + 32) != 0 or word(s, at + 40) != 0:
        return 0
    begin = word(s, at + 8)
    size = word(s, at + 16)
    aux = word(s, at + 48)
    if kind == 0 or kind == 1 or kind == 8:
        if begin != 0 or size != 0:
            return 0
        if kind == 1:
            if aux > 1:
                return 0
        elif aux != 0:
            return 0
        return 1
    if begin < relative_base:
        return 0
    relative = begin - relative_base
    if absolute_base > length(s) or relative > length(s) - absolute_base or size > length(s) - absolute_base - relative:
        return 0
    if kind == 2:
        if aux > 1 or (size == 0 and aux != 0):
            return 0
        if size != 0 and byte(s, absolute_base + relative + size - 1) == 0:
            return 0
    elif kind == 3:
        if size != 8 or aux != 0:
            return 0
    elif kind == 9:
        if aux != 0:
            return 0
    put(w, target + 8, target_base + relative)
    return 1

def event(w:mutbuf, action:u64) -> u32:
    if get(w, 32) == MAX:
        put(w, 8, 3)
        return BAD
    put(w, 32, get(w, 32) + 1)
    put(w, 256, EVENT)
    put(w, 264, action)
    put(w, 272, get(w, 16))
    put(w, 280, get(w, 24))
    put(w, 288, get(w, 32))
    put(w, 296, get(w, 152))
    put(w, 304, 512)
    put(w, 312, get(w, 144))
    put(w, 320, get(w, 192))
    put(w, 328, get(w, 120))
    put(w, 336, get(w, 128))
    put(w, 344, get(w, 136))
    put(w, 352, get(w, 56) + 1)
    put(w, 360, get(w, 64) + get(w, 72) + 1)
    put(w, 368, 0)
    put(w, 376, 0)
    return 384

def refuse(w:mutbuf, reason:u64) -> u32:
    put(w, 8, 3)
    put(w, 192, reason)
    event(w, 3)
    return BAD
'''

def source_program():
    assert sha256(Path(shared.__file__).read_bytes()).hexdigest() == '555472263213f15deb239fcf3bf8e5b273a28caf3a67bb29ffd037f171d7ae5c'
    class Expand(ast.NodeTransformer):
        def visit_Name(self, node):
            return ast.copy_location(ast.Constant(CONSTANTS[node.id]), node) if node.id in CONSTANTS else node
    own = Expand().visit(ast.parse(SOURCE)).body
    helpers = {node.name: node for node in ast.parse(shared.source_program()).body}
    tree = ast.Module(body=own + [helpers[key] for key in ('word', 'get', 'put')], type_ignores=[])
    return ast.unparse(ast.fix_missing_locations(tree)) + '\n'

def document():
    nodes = ast.parse(source_program()).body
    names = {node.name: 'f' + str(i + 1) for i, node in enumerate(nodes)}
    signatures = {node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id) for node in nodes}
    total = total_scalar_functions(nodes)
    params = [{'name': 'v0', 'type': 'readbuf'}, {'name': 'v1', 'type': 'mutbuf'}, {'name': 'v2', 'type': 'mutbuf'}]
    functions = [{'name': 'f0', 'params': params, 'returns': ['u32'], 'effects': ['read', 'write', 'trap'],
        'entry': 'b0', 'blocks': [{'id': 'b0', 'params': params, 'ops': [
            {'op': 'borrow.read', 'args': ['v1'], 'out': [{'name': 'v3', 'type': 'readbuf'}], 'attrs': {}},
            {'op': 'call', 'args': ['v0', 'v3', 'v2'], 'out': [{'name': 'v4', 'type': 'u32'}], 'attrs': {'function': names['graph_merge']}},
            {'op': 'loan.end', 'args': ['v3'], 'out': [], 'attrs': {}}], 'term': {'op': 'ret', 'values': ['v4']}}]}]
    for node in nodes:
        builder = shared.CopyBuilder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(v) for v in builder.params],
                          'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
                          'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8', 'module': 'graph_merge', 'functions': functions})

if __name__ == '__main__':
    doc = document()
    path = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap/graph_merge.hiaasm'
    path.write_text(render_assembly(doc))
    print(path.name, path.stat().st_size, len(doc['functions']), sum(len(f['blocks']) for f in doc['functions']),
          max(len(f['blocks']) for f in doc['functions']), sum(len(b['ops']) for f in doc['functions'] for b in f['blocks']))
