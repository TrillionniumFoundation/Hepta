"""Author the complete task-helper cache controller in ordinary HIA.

HIA owns lookup, continuation order, generator-result commits and publication.
All keys are identities already issued by the native type owner. Complete
helper objects stay in the generic external-value pool.
"""
from __future__ import annotations

import ast
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_core_json_frontend import packed
from tools.generate_hia_enum_match import BODY as MATCH_BODY
from tools.generate_hia_instruction_policy import SOURCE as TRANSPORT_SOURCE
from tools.generate_hia_task_helpers import BODY as HELPER_BODY
from tools.hia_native_value_graph import BODY as GRAPH_BODY, EXTERNAL_BODY
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

MAGIC = int.from_bytes(b'HIATHC01', 'little')
INPUT_BYTES = 1 << 20
OUTPUT_BYTES = 4096
WORKSPACE_BYTES = 2 << 20
CONSTANTS = {'MAGIC': MAGIC, 'INPUT_BYTES': INPUT_BYTES, 'O_BYTES': OUTPUT_BYTES,
    'W_BYTES': WORKSPACE_BYTES, 'S': 4096, 'P': 8192, 'C': 16384,
    'M': 32768, 'I': 327680, 'REGION': 262144,
    'N': (1 << 64) - 1, 'ABI': 0xfffffff1}

BODY = r'''
def task_helper_cache(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) > INPUT_BYTES or length(o) < O_BYTES or length(w) < W_BYTES:
        return ABI
    if validate(s, w) == 0 or tag(s, 0) != 5 or total(s, 0) != 5:
        return ABI
    i = 0
    while i < 64:
        put(w, S + i, 0)
        i = i + 8
    serial = unsigned(s, element(s, 0, 2))
    if serial > 8192:
        return ABI
    if get(w, P) == 0:
        if initialize(s, w) == 0:
            return ABI
    else:
        if get(w, P) != MAGIC or get(w, P + 16) == 7:
            return ABI
        if unsigned(s, element(s, 0, 1)) != get(w, P + 8):
            return ABI
        if region(s, w, element(s, 0, 0), M, 88, 0) == 0:
            return ABI
        if continuation(s, w) == 0:
            return ABI
    put(w, P + 8, get(w, P + 8) + 1)
    put(w, S + 24, 64)
    request = render(s, o, w)
    if get(w, S + 32) != 0:
        return ABI
    put(o, 0, MAGIC)
    put(o, 8, get(w, P + 32))
    put(o, 16, request)
    put(o, 24, get(w, S + 24) - 64)
    put(o, 32, get(w, P + 8))
    put(o, 40, 0)
    put(o, 48, 0)
    put(o, 56, 0)
    return get(w, S + 24)

def region(s:readbuf, w:mutbuf, node:u64, base:u64, slot:u64, capture:u64) -> u64:
    count = end(s, node) - node
    if count > REGION:
        return 0
    if capture == 0 and get(w, P + slot) != count:
        return 0
    if capture != 0:
        put(w, P + slot, count)
    i = 0
    while i < count:
        if capture != 0:
            store(w, base + i, byte(s, node + i))
        elif byte(s, node + i) != byte(w, base + i):
            return 0
        i = i + 1
    return 1

def string_ok(s:readbuf, node:u64) -> u64:
    return choose(tag(s, node) == 4 and size_of(s, node) > 0 and size_of(s, node) <= 128, 1, 0)

def initialize(s:readbuf, w:mutbuf) -> u64:
    meta = element(s, 0, 0)
    if tag(s, meta) != 5 or total(s, meta) != 5:
        return 0
    if unsigned(s, element(s, 0, 1)) != 0 or tag(s, element(s, 0, 3)) != 0 or tag(s, element(s, 0, 4)) != 0:
        return 0
    key = unsigned(s, element(s, meta, 0))
    operation = operation_id(s, element(s, meta, 1))
    required = element(s, meta, 2)
    nonce = element(s, meta, 4)
    if key == 0 or key == N or operation == 0 or tag(s, required) != 1:
        return 0
    if tag(s, nonce) != 4 or size_of(s, nonce) != 32:
        return 0
    rows = element(s, meta, 3)
    if tag(s, rows) != 5 or total(s, rows) > 640:
        return 0
    i = 0
    while i < 160:
        put(w, P + i, 0)
        i = i + 8
    put(w, P + 40, N)
    put(w, P + 48, N)
    put(w, P + 56, N)
    put(w, P + 120, total(s, rows))
    node = rows + 24
    i = 0
    while i < total(s, rows):
        if tag(s, node) != 5 or total(s, node) != 4:
            return 0
        identity = unsigned(s, element(s, node, 0))
        op = operation_id(s, element(s, node, 1))
        if identity == 0 or identity == N or op == 0 or string_ok(s, element(s, node, 2)) == 0:
            return 0
        if unsigned(s, element(s, node, 3)) != i:
            return 0
        previous = 0
        while previous < i:
            if get(w, C + previous * 16) == identity and get(w, C + previous * 16 + 8) == op:
                return 0
            previous = previous + 1
        put(w, C + i * 16, identity)
        put(w, C + i * 16 + 8, op)
        if identity == key and op == operation:
            put(w, P + 40, i)
        node = end(s, node)
        i = i + 1
    if region(s, w, meta, M, 88, 1) == 0:
        return 0
    put(w, P, MAGIC)
    if get(w, P + 40) != N:
        put(w, P + 16, 7)
        put(w, P + 48, get(w, P + 40))
    else:
        put(w, P + 16, 1)
    return 1

def inventory(s:readbuf, w:mutbuf) -> u64:
    held = element(s, 0, 4)
    if tag(s, held) != 5 or total(s, held) != 3:
        return 0
    poll = element(s, held, 0)
    cancel = element(s, held, 1)
    names = element(s, held, 2)
    if string_ok(s, poll) == 0 or string_ok(s, cancel) == 0:
        return 0
    if tag(s, names) != 5 or total(s, names) > 1024:
        return 0
    put(w, P + 96, N)
    put(w, P + 104, N)
    node = names + 24
    i = 0
    while i < total(s, names):
        if name_status(s, node) != 0:
            return 0
        if same_text(s, node, poll) != 0:
            put(w, P + 96, i)
        if same_text(s, node, cancel) != 0:
            put(w, P + 104, i)
        node = end(s, node)
        i = i + 1
    if region(s, w, held, I, 144, 1) == 0:
        return 0
    put(w, P + 16, 4)
    if get(w, P + 96) == N:
        put(w, P + 16, 8)
        put(w, P + 152, 0)
    return 1

def continuation(s:readbuf, w:mutbuf) -> u64:
    phase = get(w, P + 16)
    reply = element(s, 0, 3)
    held = element(s, 0, 4)
    if phase < 3 and tag(s, held) != 0:
        return 0
    if phase > 3 and region(s, w, held, I, 144, 0) == 0:
        return 0
    if phase == 1:
        if tag(s, reply) != 1:
            return 0
        if byte(s, reply + 16) == 0:
            required = element(s, element(s, 0, 0), 2)
            put(w, P + 32, choose(byte(s, required + 16) != 0, 4, 5))
            put(w, P + 16, 7)
        else:
            put(w, P + 16, 2)
        return 1
    if phase == 2:
        if tag(s, reply) != 0:
            return 0
        put(w, P + 16, 3)
        return 1
    if phase == 3:
        if tag(s, reply) != 0:
            return 0
        return inventory(s, w)
    if phase == 4:
        if tag(s, reply) != 0:
            return 0
        put(w, P + 16, 5)
        if get(w, P + 104) == N:
            put(w, P + 16, 8)
            put(w, P + 152, 1)
        return 1
    if phase == 5:
        if tag(s, reply) != 0:
            return 0
        put(w, P + 128, unsigned(s, element(s, 0, 2)))
        put(w, P + 16, 6)
        return 1
    if phase == 6:
        if tag(s, reply) != 5 or total(s, reply) != 5:
            return 0
        serial = unsigned(s, element(s, reply, 0))
        error = unsigned(s, element(s, reply, 1))
        name = element(s, reply, 2)
        if serial < get(w, P + 128) or serial > 8192 or error > 3:
            return 0
        if error == 1 and serial != 8192:
            return 0
        if tag(s, name) == 0:
            if error != 1:
                return 0
        elif string_ok(s, name) == 0:
            return 0
        if unsigned(s, element(s, reply, 3)) != get(w, P + 120):
            return 0
        if unsigned(s, element(s, reply, 4)) != get(w, P + 120) + 1:
            return 0
        put(w, P + 136, 1)
        put(w, P + 32, error)
        if tag(s, name) != 0:
            put(w, P + 48, unsigned(s, element(s, reply, 3)))
        put(w, P + 56, unsigned(s, element(s, reply, 4)))
        put(w, P + 16, 7)
        return 1
    return 0

def graph_number(o:mutbuf, w:mutbuf, value:u64) -> u64:
    at = get(w, S + 24)
    graph_word(o, w, 2)
    graph_word(o, w, 0)
    number(o, w, value)
    return graph_end(o, w, at)

def render_result(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    root = graph_begin(o, w, 6, 4)
    generated = get(w, P + 136)
    name = get(w, P + 48)
    meta = element(s, 0, 0)
    reply = element(s, 0, 3)
    graph_string(o, w, L_serial)
    values = graph_begin(o, w, 5, generated)
    if generated != 0:
        graph_ref(o, w, element(s, reply, 0))
    graph_end(o, w, values)
    graph_string(o, w, L_cache)
    update = choose(generated != 0 and name != N, 1, 0)
    values = graph_begin(o, w, 5, update)
    if update != 0:
        row = graph_begin(o, w, 5, 3)
        graph_ref(o, w, element(s, meta, 0))
        graph_ref(o, w, element(s, meta, 1))
        graph_external_ref(o, w, name)
        graph_end(o, w, row)
    graph_end(o, w, values)
    graph_string(o, w, L_helpers)
    publish = choose(generated != 0 and get(w, P + 32) == 0, 1, 0)
    values = graph_begin(o, w, 5, publish)
    if publish != 0:
        graph_external_ref(o, w, get(w, P + 56))
    graph_end(o, w, values)
    graph_string(o, w, L_name)
    if name == N:
        graph_null(o, w)
    else:
        graph_external_ref(o, w, name)
    graph_end(o, w, root)
    return 0

def render(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    phase = get(w, P + 16)
    if phase == 7:
        return render_result(s, o, w)
    if phase == 4 or phase == 5:
        root = graph_begin(o, w, 6, 2)
        graph_string(o, w, L_index)
        graph_number(o, w, choose(phase == 4, get(w, P + 96), get(w, P + 104)))
        graph_string(o, w, L_slot)
        graph_number(o, w, choose(phase == 4, 0, 1))
        graph_end(o, w, root)
        return 4
    if phase == 6:
        root = graph_begin(o, w, 6, 1)
        graph_string(o, w, L_serial)
        graph_ref(o, w, element(s, 0, 2))
        graph_end(o, w, root)
        return 5
    if phase == 8:
        root = graph_begin(o, w, 6, 1)
        graph_string(o, w, L_key)
        graph_ref(o, w, element(s, element(s, 0, 4), get(w, P + 152)))
        graph_end(o, w, root)
        return 6
    root = graph_begin(o, w, 6, 0)
    graph_end(o, w, root)
    return phase
'''


def source_program():
    literals = {'L_' + value: packed(value) for value in
                ('serial', 'cache', 'helpers', 'name', 'index', 'slot', 'key')}
    class Expand(ast.NodeTransformer):
        def visit_Name(self, node):
            return ast.Constant(CONSTANTS[node.id]) if node.id in CONSTANTS else node
        def visit_Call(self, node):
            node = self.generic_visit(node)
            args = []
            for arg in node.args:
                if isinstance(arg, ast.Name) and arg.id in literals:
                    args.extend(ast.Constant(value) for value in literals[arg.id])
                else:
                    args.append(arg)
            node.args = args
            return node
    own = ast.parse(BODY)
    common = {'validate', 'word', 'put', 'get', 'tag', 'size_of', 'end', 'total',
              'element', 'text_is', 'same_text'}
    raw = TRANSPORT_SOURCE.replace('    DISPATCH', '    pass').replace('1048576', '8192')
    own.body.extend(node for node in ast.parse(raw).body
                    if isinstance(node, ast.FunctionDef) and node.name in common)
    raw = MATCH_BODY.replace('size_of(s, node) > 6', 'size_of(s, node) > 10').replace(
        'if value > 262144:', 'if value > 4294967295:')
    own.body.extend(node for node in ast.parse(raw).body
                    if isinstance(node, ast.FunctionDef) and node.name in {'unsigned', 'prefix', 'name_status'})
    own.body.extend(ast.parse(GRAPH_BODY + EXTERNAL_BODY).body)
    own.body.extend(node for node in ast.parse(HELPER_BODY).body
                    if isinstance(node, ast.FunctionDef) and node.name in {'append_byte', 'emit', 'number'})
    own = Expand().visit(own)
    suffix = ['def operation_id(s:readbuf, node:u64) -> u64:']
    for identifier, operation in enumerate(('start', 'poll', 'cancel', 'join', 'close'), 1):
        suffix.extend(['    if text_is(s, node, ' + ', '.join(map(str, packed(operation))) + ') != 0:',
                       '        return ' + str(identifier)])
    suffix.append('    return 0')
    return ast.unparse(ast.fix_missing_locations(own)) + '\n' + '\n'.join(suffix) + '\n'


def document():
    nodes = ast.parse(source_program()).body
    assert len({node.name for node in nodes}) == len(nodes)
    names = {node.name: 'f' + str(index) for index, node in enumerate(nodes)}
    signatures = {node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id) for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = Builder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(arg) for arg in builder.params],
            'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
            'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8',
                                  'module': 'task_helper_cache', 'functions': functions})


if __name__ == '__main__':
    path = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap/task_helper_cache.hepta'
    path.write_text(render_assembly(document()))
    print(path.name, path.stat().st_size)
