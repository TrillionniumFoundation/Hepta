"""Author current context creation, lookup and deadline control in HIA.

The public contract is the actual Agent JSON surface with the fixed buffer,
schema, profile, SQLite, clock and execution-budget providers. This is not a
new promise about arbitrary replacements of private Python implementation
functions. Exact signed arithmetic and all policy branches/iterations belong
to the image; object representation and physical effects remain named ports.
"""
from __future__ import annotations
import ast
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ''):
    sys.path.insert(0, str(ROOT))

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
from tools.generate_hia_store_lifecycle import source_program as lifecycle_protocol
from tools.hia_service_context_arithmetic import source as arithmetic_source, REQUEST_MAGIC as MATH_MAGIC

REQUEST_MAGIC = int.from_bytes(b'HCTXREQ1', 'little')
RESULT_MAGIC = int.from_bytes(b'HCTXRSP1', 'little')
STATE_MAGIC = int.from_bytes(b'HCTXSTA1', 'little')
SOURCE_NAME = 'examples/hia_bootstrap/service_context.hepta'

POLICY = r'''
def context_entry(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) >= 8:
        if read_word(s, 0) == @MATH_MAGIC@:
            return context_math(s, o, w)
    if length(s) != 80 or length(o) < 80 or length(w) != 128:
        return 4294967293
    if read_word(s, 0) != @REQUEST_MAGIC@ or read_word(s, 64) != 0 or read_word(s, 72) != 0:
        return 4294967293
    event = read_word(s, 8)
    if event == 0:
        return initialize(s, o, w)
    if valid_state(w) == 0:
        return 4294967293
    if read_word(s, 40) != get(w, 2) or read_word(s, 48) != get(w, 6) or read_word(s, 56) != get(w, 7):
        return refuse(o, w)
    if read_word(s, 16) != get(w, 4) or read_word(s, 24) != get(w, 3):
        return refuse(o, w)
    if event == 1:
        if get(w, 5) != 1 or read_word(s, 32) != 0:
            return refuse(o, w)
        set(w, 5, 2)
        seal(w)
        return answer(o, w, 0)
    if event == 2:
        if get(w, 5) != 2:
            return refuse(o, w)
        observed = read_word(s, 32)
        if is_predicate(get(w, 3)) == 1:
            if observed > 1:
                return refuse(o, w)
        else:
            if observed != 0:
                return refuse(o, w)
        return succeeded(o, w, observed)
    if event == 3:
        if get(w, 5) != 2 or read_word(s, 32) != 0:
            return refuse(o, w)
        set(w, 9, 1)
        return advance(o, w, 0, 5)
    return refuse(o, w)

def initialize(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    mode = read_word(s, 40)
    if mode < 1 or mode > 4 or read_word(s, 16) != 0 or read_word(s, 24) != 0 or read_word(s, 32) != 0:
        return 4294967293
    if read_word(s, 48) == 0 and read_word(s, 56) == 0:
        return 4294967293
    i = 0
    while i < 128:
        if byte(w, i) != 0:
            return 4294967293
        i = i + 1
    set(w, 0, @STATE_MAGIC@)
    set(w, 1, 1)
    set(w, 2, mode)
    set(w, 3, 1 + (mode - 1) * 100)
    set(w, 4, 1)
    set(w, 5, 1)
    set(w, 6, read_word(s, 48))
    set(w, 7, read_word(s, 56))
    seal(w)
    return answer(o, w, 0)

def succeeded(o:mutbuf, w:mutbuf, observed:u64) -> u32:
    port = get(w, 3)
    next_port = port + 1
    if port == 10:
        if observed == 0:
            next_port = 16
    elif port == 12:
        if observed == 0:
            next_port = 10
    elif port == 13:
        if observed == 0:
            next_port = 12
    elif port == 15:
        next_port = 12
    elif port == 17:
        if observed == 1:
            next_port = 90
    elif port == 20:
        if get(w, 8) < 3:
            set(w, 8, get(w, 8) + 1)
            next_port = 20
        else:
            set(w, 8, 0)
    elif port == 23 or port == 24:
        if observed == 0:
            next_port = 91
    elif port == 25:
        if observed == 1:
            next_port = 92
    elif port == 27:
        if observed == 0:
            next_port = 29
    elif port == 29:
        if get(w, 8) == 0:
            set(w, 8, 1)
            next_port = 26
        else:
            set(w, 8, 0)
    elif port == 31:
        if observed == 0:
            next_port = 33
    elif port == 32:
        if observed == 1:
            next_port = 94
    elif port == 33:
        if observed == 0:
            next_port = 37
    elif port == 35:
        if observed == 0:
            next_port = 37
    elif port == 36:
        next_port = 35
        if observed == 1:
            next_port = 95
    elif port == 38:
        if observed == 0:
            next_port = 40
    elif port == 46 or port == 111 or port == 209 or port == 309:
        return advance(o, w, 0, 4)
    elif port == 90:
        next_port = 18
    elif port == 91:
        next_port = 25
    elif port == 92:
        next_port = 26
    elif port == 94:
        next_port = 33
    elif port == 95:
        next_port = 37
    elif port == 103 or port == 104:
        if observed == 1:
            next_port = 190
    elif port == 106 or port == 107:
        if observed == 1:
            next_port = 191
    elif port == 109:
        if get(w, 8) == 0:
            set(w, 8, 1)
            next_port = 108
    elif port == 190:
        next_port = 105
    elif port == 191:
        next_port = 108
    elif port == 207:
        if observed == 1:
            next_port = 290
    elif port == 208:
        if observed == 0:
            return advance(o, w, 0, 4)
    elif port == 290:
        next_port = 208
    return advance(o, w, next_port, 1)

def is_predicate(port:u64) -> u64:
    if port == 10 or port == 12 or port == 13 or port == 17 or port == 23 or port == 24 or port == 25:
        return 1
    if port == 27 or port == 31 or port == 32 or port == 33 or port == 35 or port == 36 or port == 38:
        return 1
    if port == 103 or port == 104 or port == 106 or port == 107 or port == 207 or port == 208:
        return 1
    return 0

def valid_state(w:mutbuf) -> u64:
    mode = get(w, 2)
    if get(w, 0) != @STATE_MAGIC@ or get(w, 1) != 1 or mode < 1 or mode > 4:
        return 0
    if get(w, 4) == 0 or get(w, 5) == 0 or get(w, 5) > 6 or get(w, 5) == 3:
        return 0
    if get(w, 8) > 3 or get(w, 9) > 1 or get(w, 11) != 0 or get(w, 12) != 0 or get(w, 13) != 0 or get(w, 14) != 0 or get(w, 15) != 0:
        return 0
    if checksum(w) != get(w, 10):
        return 0
    port = get(w, 3)
    if get(w, 5) == 1 or get(w, 5) == 2:
        if mode == 1:
            if (port >= 1 and port <= 46) or port == 90 or port == 91 or port == 92 or port == 94 or port == 95:
                return 1
        elif mode == 2:
            if (port >= 101 and port <= 111) or port == 190 or port == 191:
                return 1
        elif mode == 3:
            if (port >= 201 and port <= 209) or port == 290:
                return 1
        else:
            if port >= 301 and port <= 309:
                return 1
        return 0
    if port != 0:
        return 0
    return 1

def advance(o:mutbuf, w:mutbuf, port:u64, phase:u64) -> u32:
    if get(w, 4) == 18446744073709551615:
        return refuse(o, w)
    set(w, 3, port)
    set(w, 4, get(w, 4) + 1)
    set(w, 5, phase)
    seal(w)
    return answer(o, w, 0)

def put_word(o:mutbuf, at:u64, value:u64) -> u64:
    i = 0
    while i < 8:
        store(o, at + i, value >> (i * 8))
        i = i + 1
    return 0
'''


def source_program():
    # Reuse only the already qualified transport envelope helpers. Neither
    # lifecycle policy nor its modes/branches become context policy inputs.
    wanted = {'refuse', 'answer', 'checksum', 'seal', 'read_word', 'get', 'set'}
    helpers = [node for node in ast.parse(lifecycle_protocol()).body
               if isinstance(node, ast.FunctionDef) and node.name in wanted]
    from tools.generate_hia_store_lifecycle import RESULT_MAGIC as PREVIOUS_RESULT
    text = POLICY + '\n' + '\n\n'.join(ast.unparse(node) for node in helpers)
    text = text.replace(str(PREVIOUS_RESULT), str(RESULT_MAGIC))
    text += '\n' + arithmetic_source()
    for name in ('REQUEST_MAGIC', 'RESULT_MAGIC', 'STATE_MAGIC', 'MATH_MAGIC'):
        text = text.replace('@' + name + '@', str(globals()[name]))
    return text


class ContextBuilder(Builder):
    def expr(self, node):
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.FloorDiv, ast.Mod)):
            left, right = self.expr(node.left), self.expr(node.right)
            return self.op('int.div.checked' if isinstance(node.op, ast.FloorDiv) else 'int.rem.checked',
                           [left, right], left[1])
        return super().expr(node)


def document():
    nodes = ast.parse(source_program()).body
    names = {node.name: 'f' + str(i) for i, node in enumerate(nodes)}
    signatures = {node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id)
                  for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = ContextBuilder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(v) for v in builder.params],
            'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
            'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8',
                                  'module': 'service_context', 'functions': functions})


if __name__ == '__main__':
    path = ROOT / SOURCE_NAME
    path.write_text(render_assembly(document()))
    print(path.name, path.stat().st_size)
