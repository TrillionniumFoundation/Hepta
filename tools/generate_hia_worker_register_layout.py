"""Author sealed JSON ingress for HIA's checked register-coordinate packet."""
from __future__ import annotations

import ast
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_json_decode import source_program as json_decoder
from tools.generate_hia_machine_plan import source_program as machine_plan
from tools.generate_hia_worker_block_layout import INPUT_BYTES, MAX_NODES, PREFLIGHT_BYTES

SOURCE = Path('examples/hia_bootstrap/worker_register_layout.hepta')
WORKSPACE_BYTES = 128 << 20
INVALID = 0xfffffffd
NONE = (1 << 64) - 1

POLICY = r'''
def register_layout(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 8 or length(s) > INPUT_MAX or length(o) < PREFLIGHT or length(w) < WORKSPACE:
        return INVALID
    put(o, 48, NODES)
    put(o, 56, 128)
    arena = widen(decode_json(s, w, o))
    if arena >= 4294967292 or get(w, 64) != 5 or get(w, 96) != 3:
        return INVALID
    packet = align8(arena)
    end = typed_tree(s, w, packet)
    if end == INVALID:
        return INVALID
    return bound_register_packet(o, w, packet, align8(end))

# Walk the already decoded tree without a separate stack. Open container
# output offsets replace their no-longer-used original source spans.
def typed_tree(s:readbuf, w:mutbuf, cursor:u64) -> u64:
    node = 64
    while True:
        parent = get(w, node + 8)
        if parent != NONE:
            owner = 64 + parent * 72
            if get(w, owner) == 6:
                cursor = typed_string(w, get(w, node + 40), get(w, node + 48), cursor)
                if cursor == INVALID:
                    return INVALID
        kind = get(w, node)
        if kind == 5 or kind == 6:
            if length(w) - cursor < 24:
                return INVALID
            put(w, cursor, kind)
            count = get(w, node + 32)
            put(w, cursor + 8, 8)
            put(w, cursor + 16, count)
            if count != 0:
                put(w, node + 56, cursor)
                cursor = cursor + 24
                node = 64 + get(w, node + 24) * 72
            else:
                cursor = cursor + 24
                closed = close_through(w, node, cursor)
                if closed == NONE:
                    return cursor
                node = closed
        else:
            cursor = typed_leaf(s, w, node, cursor, kind)
            if cursor == INVALID:
                return INVALID
            closed = close_through(w, node, cursor)
            if closed == NONE:
                return cursor
            node = closed
    return INVALID

def close_through(w:mutbuf, node:u64, cursor:u64) -> u64:
    while True:
        sibling = get(w, node + 16)
        if sibling != NONE:
            return 64 + sibling * 72
        parent = get(w, node + 8)
        if parent == NONE:
            return NONE
        node = 64 + parent * 72
        start = get(w, node + 56)
        put(w, start + 8, cursor - start - 16)
    return NONE

def typed_leaf(s:readbuf, w:mutbuf, node:u64, cursor:u64, kind:u64) -> u64:
    at = get(w, node + 24)
    size = get(w, node + 32)
    if kind == 4:
        return typed_string(w, at, size, cursor)
    if kind == 3:
        return typed_number(s, w, at, size, cursor)
    extent = choose(kind == 0, 16, 17)
    if extent > length(w) - cursor:
        return INVALID
    put(w, cursor, choose(kind == 0, 0, 1))
    put(w, cursor + 8, extent - 16)
    if kind != 0:
        store(w, cursor + 16, kind - 1)
    return cursor + extent

def typed_string(w:mutbuf, at:u64, size:u64, cursor:u64) -> u64:
    if 16 + size > length(w) - cursor:
        return INVALID
    put(w, cursor, 4)
    put(w, cursor + 8, size)
    index = 0
    while index < size:
        store(w, cursor + 16 + index, byte(w, at + index))
        index = index + 1
    return cursor + 16 + size

def typed_number(s:readbuf, w:mutbuf, at:u64, size:u64, cursor:u64) -> u64:
    if size == 2 and byte(s, at) == 45 and byte(s, at + 1) == 48:
        at = at + 1
        size = 1
    if 16 + size > length(w) - cursor:
        return INVALID
    kind = 2
    index = 0
    while index < size:
        value = byte(s, at + index)
        if value == 46 or value == 69 or value == 101:
            kind = 3
        store(w, cursor + 16 + index, value)
        index = index + 1
    put(w, cursor, kind)
    put(w, cursor + 8, size)
    return cursor + 16 + size
'''


def program():
    constants = dict(INPUT_MAX=INPUT_BYTES, NODES=MAX_NODES, PREFLIGHT=PREFLIGHT_BYTES,
                     WORKSPACE=WORKSPACE_BYTES, INVALID=INVALID, NONE=NONE)

    class Constants(ast.NodeTransformer):
        def visit_Name(self, node):
            if node.id in constants:
                return ast.copy_location(ast.Constant(constants[node.id]), node)
            return node

    raw_decoder = json_decoder(wire_spans=True)
    guard = 'if length(s) > 8388608 or length(w) < 128'
    if raw_decoder.count(guard) != 2:
        raise ValueError('JSON decoder admission sites differ')
    raw_decoder = raw_decoder.replace(guard, guard.replace('8388608', str(INPUT_BYTES)))
    reader = Constants().visit(ast.parse(POLICY))
    machinery = ast.parse(machine_plan()).body
    decoder = ast.parse(raw_decoder).body
    nodes = {node.name: node for node in (*decoder, *machinery, *reader.body)}
    # Keep only the exact shared decisions required by the standalone role.
    selected = {}
    pending = ['register_layout']
    while pending:
        name = pending.pop()
        if name in selected:
            continue
        node = selected[name] = nodes[name]
        pending.extend(callee.func.id for callee in ast.walk(node)
                       if isinstance(callee, ast.Call) and isinstance(callee.func, ast.Name)
                       and callee.func.id in nodes and callee.func.id not in selected)
    reachable = [reader.body[0], *(node for name, node in nodes.items()
                                 if name in selected and name != 'register_layout')]
    return ast.unparse(ast.fix_missing_locations(ast.Module(body=reachable, type_ignores=[])))


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)), encoding='utf-8')
