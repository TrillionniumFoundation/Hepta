"""Author a finite HIA Cell continuation; Python is authoring, not its runtime."""
from __future__ import annotations
import ast
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

SOURCE_PATH = "examples/hia_cell_bridge/continuation.hepta"
SYMBOLS = {
    "REQUEST_MAGIC": int.from_bytes(b"HCLREQ01", "little"),
    "RESPONSE_MAGIC": int.from_bytes(b"HCLRES01", "little"),
    "STATE_MAGIC": int.from_bytes(b"HCLSTA01", "little"),
    "HEADER": 256, "MAX_PAYLOAD": 65536,
}

# Digests are runtime observations. Native HIA binds them but cannot itself
# authenticate their preimages. Every rejection precedes all state/output writes.
SOURCE = r'''
def cell_bridge_step(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < HEADER or length(s) > HEADER + MAX_PAYLOAD:
        return 1
    if length(w) != HEADER:
        return 2
    payload = read64(s, 160)
    if payload != length(s) - HEADER:
        return 3
    if length(o) < HEADER + payload:
        return 4
    if read64(s, 0) != REQUEST_MAGIC or read64(s, 8) != 1:
        return 5
    if read64(s, 184) != 0 or zero_input(s, 224, 32) != 1:
        return 5
    if read64(s, 24) == 0:
        return 6
    if zero_input(s, 32, 32) == 1 or zero_input(s, 64, 32) == 1:
        return 6
    if zero_input(s, 96, 32) == 1 or zero_input(s, 128, 32) == 1:
        return 6
    limit = read64(s, 176)
    if limit == 0 or limit > MAX_PAYLOAD:
        return 7
    event = read64(s, 16)
    if event == 1:
        return begin(s, o, w)
    if event < 2 or event > 4:
        return 8
    if valid_pending(w) != 1:
        return 9
    if read64(s, 24) != get(w, 24) or limit != get(w, 168):
        return 10
    index = 32
    while index < 160:
        if byte(s, index) != byte(w, index):
            return 10
        index = index + 1
    if event == 2:
        return result(s, o, w)
    if payload != 0 or read64(s, 168) != 0 or zero_input(s, 192, 32) != 1:
        return 11
    if event == 3:
        put(w, 16, 5)
        respond(s, o, 5, 5)
        return 0
    if get(w, 184) != 0:
        return 12
    put(w, 16, 6)
    put(w, 184, 1)
    respond(s, o, 6, 6)
    return 0

def begin(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if zero_state(w, 0, HEADER) != 1:
        return 9
    if read64(s, 168) != 0:
        return 11
    index = 0
    while index < 32:
        if byte(s, 128 + index) != byte(s, 192 + index):
            return 11
        index = index + 1
    put(w, 0, STATE_MAGIC)
    put(w, 8, 1)
    put(w, 16, 1)
    copy_input(s, w, 24, 24, 136)
    put(w, 160, read64(s, 160))
    put(w, 168, read64(s, 176))
    respond(s, o, 1, 1)
    return 0

def valid_pending(w:mutbuf) -> u64:
    if get(w, 0) != STATE_MAGIC or get(w, 8) != 1:
        return 0
    phase = get(w, 16)
    if phase != 1 and phase != 5 and phase != 6:
        return 0
    if get(w, 24) == 0 or get(w, 160) > MAX_PAYLOAD:
        return 0
    if get(w, 168) == 0 or get(w, 168) > MAX_PAYLOAD:
        return 0
    if get(w, 176) != 0 or get(w, 184) > 1:
        return 0
    if phase == 1 and get(w, 184) != 0:
        return 0
    if phase == 6 and get(w, 184) != 1:
        return 0
    if zero_state(w, 192, 64) != 1:
        return 0
    return 1

def result(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    status = read64(s, 168)
    payload = read64(s, 160)
    if status < 1 or status > 4 or payload > get(w, 168):
        return 11
    if status == 4:
        if payload != 0 or zero_input(s, 192, 32) != 1:
            return 11
        put(w, 16, 5)
        respond(s, o, 5, 5)
        return 0
    if zero_input(s, 192, 32) == 1:
        return 11
    phase = status + 1
    put(w, 16, phase)
    put(w, 176, payload)
    copy_input(s, w, 192, 192, 32)
    respond(s, o, phase, phase)
    return 0

def respond(s:readbuf, o:mutbuf, action:u64, phase:u64) -> u64:
    copy_input(s, o, 0, 0, length(s))
    put(o, 0, RESPONSE_MAGIC)
    put(o, 16, action)
    put(o, 168, phase)
    return 0

def copy_input(s:readbuf, w:mutbuf, source:u64, target:u64, count:u64) -> u64:
    index = 0
    while index < count:
        store(w, target + index, byte(s, source + index))
        index = index + 1
    return 0

def zero_input(s:readbuf, at:u64, count:u64) -> u64:
    index = 0
    while index < count:
        if byte(s, at + index) != 0:
            return 0
        index = index + 1
    return 1

def zero_state(w:mutbuf, at:u64, count:u64) -> u64:
    index = 0
    while index < count:
        if byte(w, at + index) != 0:
            return 0
        index = index + 1
    return 1

def read64(s:readbuf, at:u64) -> u64:
    value = 0
    index = 0
    while index < 8:
        value = value | (byte(s, at + index) << (index * 8))
        index = index + 1
    return value

def get(w:mutbuf, at:u64) -> u64:
    value = 0
    index = 0
    while index < 8:
        value = value | (byte(w, at + index) << (index * 8))
        index = index + 1
    return value

def put(w:mutbuf, at:u64, value:u64) -> u64:
    index = 0
    while index < 8:
        store(w, at + index, (value >> (index * 8)) & 255)
        index = index + 1
    return 0
'''


def document():
    class Replace(ast.NodeTransformer):
        def visit_Name(self, node):
            return ast.copy_location(ast.Constant(SYMBOLS[node.id]), node) if node.id in SYMBOLS else node
    tree = ast.fix_missing_locations(Replace().visit(ast.parse(SOURCE)))
    nodes = tree.body
    names = {node.name: node.name for node in nodes}
    signatures = {node.name: ([a.annotation.id for a in node.args.args], node.returns.id) for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = Builder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({"name": names[node.name], "params": [builder.param(v) for v in builder.params],
                          "returns": [builder.returns], "effects": ["read", "write", "trap"],
                          "entry": "b0", "blocks": builder.blocks})
    return compact_authoring_cfg({"schema": "hepta.hia.program.v8", "module": "cell_bridge_continuation",
                                  "functions": functions})


if __name__ == "__main__":
    target = Path(__file__).resolve().parents[1] / SOURCE_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_assembly(document()), encoding="utf-8")
    print(target, target.stat().st_size)
