"""Author the complete bounded-memory API decisions and writes in HIA."""
from __future__ import annotations

import ast
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ''}:
    sys.path.insert(0, str(ROOT))

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

REQUEST_MAGIC = int.from_bytes(b'HIABMEM1', 'little')
SOURCE = r'''
def bounded_memory(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) != 80 or length(w) != 0:
        return 3
    if word(s, 0) != @REQUEST_MAGIC@ or word(s, 24) != 0:
        return 3
    operation = word(s, 8)
    if operation != 1 and operation != 2:
        return 3
    if word(s, 16) != 1 or word(s, 32) != 1 or word(s, 48) != 1:
        return 1
    offset = word(s, 40)
    count = word(s, 56)
    extent = length(o)
    if offset > extent:
        return 1
    if count > extent - offset:
        return 1
    last = word(s, 72)
    if operation == 1:
        if word(s, 64) != 1 or last > 255:
            return 2
        if count != 0:
            fill_range(o, offset, count, last)
    else:
        if word(s, 64) != 1:
            return 1
        if last > extent:
            return 1
        if count > extent - last:
            return 1
        if count != 0 and offset != last:
            move_within(o, offset, last, count)
    return 0

def word(s:readbuf, at:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(s, at + i) << (i * 8))
        i = i + 1
    return value
'''


class MemoryBuilder(Builder):
    def expr(self, value):
        if isinstance(value, ast.Call) and isinstance(value.func, ast.Name) and value.func.id == 'move_within':
            args = [self.expr(arg) for arg in value.args]
            return self.op('buffer.move_within', [args[0], *[self.cast(arg, 'usize') for arg in args[1:]]])
        return super().expr(value)


def document():
    nodes = ast.parse(SOURCE.replace('@REQUEST_MAGIC@', str(REQUEST_MAGIC))).body
    names = {node.name: 'f' + str(i) for i, node in enumerate(nodes)}
    signatures = {node.name: ([a.annotation.id for a in node.args.args], node.returns.id)
                  for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = MemoryBuilder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name],
            'params': [builder.param(value) for value in builder.params],
            'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
            'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8',
        'module': 'bounded_memory', 'functions': functions})


if __name__ == '__main__':
    path = ROOT / 'examples/hia_bootstrap/bounded_memory.hepta'
    path.write_text(render_assembly(document()))
    print(path.name, path.stat().st_size)
