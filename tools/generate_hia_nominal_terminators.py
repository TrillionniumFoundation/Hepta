"""Author complete nominal jump, branch, return and trap policy in HIA.

HIA chooses complete logical Core terms. Generic source references and array
concatenations retain repeated aliases without a smaller flattened-output cap.
The independent original elaborator remains available only when unselected.
"""
from __future__ import annotations

import ast
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_core_json_frontend import packed
from tools.generate_hia_instruction_policy import SOURCE as TRANSPORT_SOURCE
from tools.generate_hia_enum_match import BODY as MATCH_BODY
from tools.generate_hia_task_helpers import BODY as HELPER_BODY, PRIMITIVES
from tools.hia_native_value_graph import BODY as GRAPH_BODY
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

MAGIC = int.from_bytes(b'HIANTM01', 'little')
INPUT_BYTES = 256 << 20
OUTPUT_BYTES = 16 << 20
WORKSPACE_BYTES = 32 << 20
CONSTANTS = {
    'MAGIC': MAGIC, 'INPUT_BYTES': INPUT_BYTES, 'O_BYTES': OUTPUT_BYTES,
    'W_BYTES': WORKSPACE_BYTES, 'S': 4096, 'T': 8192,
    'EV': 4202496, 'EH': 6299648, 'MARK': 10493952,
    'VF': 12591104, 'UNIQUE': 14688256, 'SG': 16785408,
    'HEAP': 16826368, 'N': (1 << 64) - 1, 'ABI': 0xfffffff1,
}

BODY = r'''
def nominal_terminators(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) > INPUT_BYTES or length(w) < W_BYTES or length(o) < O_BYTES:
        return ABI
    if validate(s, w) == 0:
        return ABI
    if tag(s, 0) != 5 or total(s, 0) != 6:
        return ABI
    i = 0
    while i < 256:
        put(w, S + i, 0)
        i = i + 8
    put(w, S + 16, HEAP)
    put(w, S + 96, 1)
    if admit(s, w) == 0:
        return ABI
    lower(s, w)
    if get(w, S + 32) != 0:
        return ABI
    put(w, S + 24, 64)
    i = 0
    while i < get(w, S + 80):
        graph_word(o, w, get(w, VF + i * 8))
        i = i + 1
    if get(w, S + 8) != 0 or get(w, S + 88) != 0:
        graph_null(o, w)
    else:
        render(s, o, w)
    if get(w, S + 32) != 0:
        return ABI
    put(o, 0, MAGIC)
    put(o, 8, get(w, S + 8))
    put(o, 16, get(w, S))
    put(o, 24, get(w, S + 24) - 64)
    put(o, 32, get(w, S + 88))
    put(o, 40, get(w, S + 96))
    put(o, 48, get(w, S + 80))
    put(o, 56, 0)
    return get(w, S + 24)

def keys(s:readbuf, node:u64, mask:u64, count:u64) -> u64:
    if tag(s, node) != 6 or total(s, node) != count:
        return 0
    at = node + 24
    seen = 0
    i = 0
    while i < count:
        ident = field_id(s, at)
        if ident == 0 or (seen & ident) != 0:
            return 0
        seen = seen | ident
        at = end(s, end(s, at))
        i = i + 1
    return choose(seen == mask, 1, 0)

def descriptor_ok(s:readbuf, node:u64) -> u64:
    if tag(s, node) != 5 or total(s, node) != 3:
        return 0
    kind = kind_id(s, element(s, node, 0))
    flat = flat_node(s, node)
    if kind == 0 or tag(s, flat) != 5 or total(s, flat) > 512:
        return 0
    if tag(s, element(s, node, 2)) != 1:
        return 0
    if kind == 1 and total(s, flat) != 1:
        return 0
    at = flat + 24
    i = 0
    while i < total(s, flat):
        if type_id(s, at) == 0:
            return 0
        at = end(s, at)
        i = i + 1
    return 1

def value_id(s:readbuf, w:mutbuf, index:u64) -> u64:
    return unsigned(s, element(s, get(w, EV + index * 8), 5))

def same_alias(s:readbuf, left:u64, right:u64) -> u64:
    if unsigned(s, element(s, left, 1)) != unsigned(s, element(s, right, 1)):
        return 0
    if truth(s, element(s, left, 3)) != truth(s, element(s, right, 3)):
        return 0
    if truth(s, element(s, left, 4)) != truth(s, element(s, right, 4)):
        return 0
    a = element(s, left, 2)
    b = element(s, right, 2)
    if total(s, a) != total(s, b):
        return 0
    x = a + 24
    y = b + 24
    i = 0
    while i < total(s, a):
        if same_text(s, x, y) == 0:
            return 0
        x = end(s, x)
        y = end(s, y)
        i = i + 1
    return 1

def admit_values(s:readbuf, w:mutbuf, values:u64) -> u64:
    count = total(s, values)
    capacity = 1
    while capacity < count * 2:
        capacity = capacity * 2
    put(w, S + 64, capacity)
    i = 0
    while i < capacity:
        put(w, EH + i * 8, 0)
        i = i + 1
    node = values + 24
    slots = 0
    i = 0
    while i < count:
        if tag(s, node) != 5 or total(s, node) != 6:
            return 0
        name = element(s, node, 0)
        ident = unsigned(s, element(s, node, 1))
        names = element(s, node, 2)
        if name_status(s, name) != 0 or ident >= get(w, S + 48) or tag(s, names) != 5:
            return 0
        if tag(s, element(s, node, 3)) != 1 or tag(s, element(s, node, 4)) != 1:
            return 0
        if total(s, names) != type_width(s, typename(s, w, ident)):
            return 0
        slots = slots + total(s, names)
        if slots > 32768:
            return 0
        at = names + 24
        j = 0
        while j < total(s, names):
            if name_status(s, at) == 1:
                return 0
            at = end(s, at)
            j = j + 1
        sid = unsigned(s, element(s, node, 5))
        if sid > get(w, S + 80):
            return 0
        if sid == get(w, S + 80):
            put(w, UNIQUE + sid * 8, node)
            put(w, VF + sid * 8, truth(s, element(s, node, 4)))
            put(w, S + 80, sid + 1)
        else:
            if same_alias(s, node, get(w, UNIQUE + sid * 8)) == 0:
                return 0
        put(w, EV + i * 8, node)
        put(w, MARK + i * 8, 0)
        slot = hash_name(s, name) & (capacity - 1)
        while get(w, EH + slot * 8) != 0:
            previous = get(w, EV + (get(w, EH + slot * 8) - 1) * 8)
            if same_text(s, name, element(s, previous, 0)) != 0:
                return 0
            slot = (slot + 1) & (capacity - 1)
        put(w, EH + slot * 8, i + 1)
        node = end(s, node)
        i = i + 1
    return 1

def type_inventory(s:readbuf, w:mutbuf, node:u64) -> u64:
    if tag(s, node) != 5 or total(s, node) > 262144:
        return 0
    at = node + 24
    i = 0
    while i < total(s, node):
        if unsigned(s, at) >= get(w, S + 48):
            return 0
        at = end(s, at)
        i = i + 1
    return 1

def admit(s:readbuf, w:mutbuf) -> u64:
    serial = unsigned(s, element(s, 0, 0))
    if serial > 8192:
        return 0
    put(w, S, serial)
    types = element(s, 0, 2)
    values = element(s, 0, 3)
    signatures = element(s, 0, 4)
    if tag(s, types) != 5 or tag(s, values) != 5 or tag(s, signatures) != 5:
        return 0
    tc = total(s, types)
    ec = total(s, values)
    sc = total(s, signatures)
    if tc > 524288 or ec > 262144 or sc > 4096:
        return 0
    put(w, S + 48, tc)
    put(w, S + 56, ec)
    put(w, S + 72, sc)
    node = types + 24
    i = 0
    while i < tc:
        put(w, T + i * 8, node)
        if descriptor_ok(s, node) == 0:
            return 0
        node = end(s, node)
        i = i + 1
    if admit_values(s, w, values) == 0:
        return 0
    node = signatures + 24
    i = 0
    while i < sc:
        if tag(s, node) != 5 or total(s, node) != 2:
            return 0
        if name_status(s, element(s, node, 0)) != 0:
            return 0
        if type_inventory(s, w, element(s, node, 1)) == 0:
            return 0
        put(w, SG + i * 8, node)
        node = end(s, node)
        i = i + 1
    return type_inventory(s, w, element(s, 0, 5))

def admitted_value(s:readbuf, w:mutbuf, name:u64) -> u64:
    if name_check(s, w, name, 4) == 0:
        return N
    index = env_lookup(s, w, name)
    if index == N:
        refuse(w, 6)
        return N
    if get(w, VF + value_id(s, w, index) * 8) != 0:
        refuse(w, 7)
        return N
    return index

def names_check(s:readbuf, w:mutbuf, names:u64, first:u64) -> u64:
    if tag(s, names) != 5:
        refuse(w, first)
        return 0
    at = names + 24
    i = 0
    while i < total(s, names):
        if name_status(s, at) == 1:
            refuse(w, first + 1)
            return 0
        at = end(s, at)
        i = i + 1
    return 1

def live(s:readbuf, w:mutbuf, index:u64) -> u64:
    node = get(w, EV + index * 8)
    return choose(linear(s, typename(s, w, env_type(s, w, index))) != 0 and truth(s, element(s, node, 3)) == 0 and get(w, VF + value_id(s, w, index) * 8) == 0, 1, 0)

def find_signature(s:readbuf, w:mutbuf, target:u64) -> u64:
    i = 0
    while i < get(w, S + 72):
        node = get(w, SG + i * 8)
        if same_text(s, target, element(s, node, 0)) != 0:
            return element(s, node, 1)
        i = i + 1
    return N

def same_types(s:readbuf, w:mutbuf, actual:u64, count:u64, expected:u64) -> u64:
    if count != total(s, expected):
        return 0
    at = expected + 24
    i = 0
    while i < count:
        if type_equal(s, w, env_type(s, w, get(w, actual + i * 8)), unsigned(s, at)) == 0:
            return 0
        at = end(s, at)
        i = i + 1
    return 1

def edge_values(s:readbuf, w:mutbuf, names:u64) -> u64:
    count = total(s, names)
    vector = allocate(w, count * 8)
    if get(w, S + 32) != 0:
        return N
    epoch = get(w, S + 192) + 1
    put(w, S + 192, epoch)
    at = names + 24
    i = 0
    while i < count:
        index = admitted_value(s, w, at)
        if index == N:
            return N
        if linear(s, typename(s, w, env_type(s, w, index))) != 0:
            if get(w, MARK + index * 8) == epoch:
                refuse(w, 15)
                return N
            put(w, MARK + index * 8, epoch)
        put(w, vector + i * 8, index)
        at = end(s, at)
        i = i + 1
    i = 0
    while i < get(w, S + 56):
        if live(s, w, i) != 0 and get(w, MARK + i * 8) != epoch:
            refuse(w, 16)
            return N
        i = i + 1
    return vector

def lower_edge(s:readbuf, w:mutbuf, raw:u64, outer:u64, destination:u64) -> u64:
    if outer == 0 and keys(s, raw, 6, 2) == 0:
        return refuse(w, 9)
    target = field(s, raw, 2)
    if name_check(s, w, target, 10) == 0:
        return 0
    names = field(s, raw, 4)
    if names_check(s, w, names, 12) == 0:
        return 0
    expected = find_signature(s, w, target)
    if expected == N:
        return refuse(w, 14)
    vector = edge_values(s, w, names)
    if vector == N:
        return 0
    count = total(s, names)
    if same_types(s, w, vector, count, expected) == 0:
        return refuse(w, 17)
    i = 0
    while i < count:
        put(w, vector + i * 8, env_values(s, w, get(w, vector + i * 8)))
        i = i + 1
    put(w, S + destination, target)
    put(w, S + destination + 8, vector)
    put(w, S + destination + 16, count)
    return 0

def lower_return(s:readbuf, w:mutbuf, term:u64) -> u64:
    if keys(s, term, 65, 2) == 0:
        return refuse(w, 18)
    names = field(s, term, 64)
    if names_check(s, w, names, 19) == 0:
        return 0
    count = total(s, names)
    vector = allocate(w, count * 8)
    if get(w, S + 32) != 0:
        return 0
    at = names + 24
    i = 0
    while i < count:
        index = admitted_value(s, w, at)
        if index == N:
            return 0
        put(w, vector + i * 8, index)
        at = end(s, at)
        i = i + 1
    if same_types(s, w, vector, count, element(s, 0, 5)) == 0:
        return refuse(w, 21)
    i = 0
    while i < count:
        index = get(w, vector + i * 8)
        sid = value_id(s, w, index)
        if get(w, VF + sid * 8) != 0:
            return refuse(w, 7)
        if linear(s, typename(s, w, env_type(s, w, index))) != 0:
            put(w, VF + sid * 8, 1)
        i = i + 1
    i = 0
    while i < get(w, S + 56):
        if live(s, w, i) != 0:
            return refuse(w, 22)
        i = i + 1
    i = 0
    while i < count:
        put(w, vector + i * 8, env_values(s, w, get(w, vector + i * 8)))
        i = i + 1
    put(w, S + 168, vector)
    put(w, S + 176, count)
    return 0

def lower(s:readbuf, w:mutbuf) -> u64:
    term = element(s, 0, 1)
    op = field(s, term, 1)
    if tag(s, term) != 6 or op == N or tag(s, op) != 4:
        put(w, S + 96, 0)
        return refuse(w, 1)
    code = op_id(s, op)
    put(w, S + 104, code)
    if code == 1:
        if keys(s, term, 7, 3) == 0:
            return refuse(w, 2)
        lower_edge(s, w, term, 1, 112)
    elif code == 2:
        if keys(s, term, 57, 4) == 0:
            return refuse(w, 3)
        cond = admitted_value(s, w, field(s, term, 8))
        if cond == N:
            return 0
        descriptor = typename(s, w, env_type(s, w, cond))
        if kind_id(s, element(s, descriptor, 0)) != 1 or text_is(s, element(s, flat_node(s, descriptor), 0), L_bool) == 0:
            return refuse(w, 8)
        put(w, S + 160, element(s, env_values(s, w, cond), 0))
        lower_edge(s, w, field(s, term, 16), 0, 112)
        if get(w, S + 8) == 0 and get(w, S + 32) == 0:
            lower_edge(s, w, field(s, term, 32), 0, 136)
    elif code == 3:
        lower_return(s, w, term)
    elif code == 4:
        if keys(s, term, 129, 2) == 0:
            return refuse(w, 23)
        put(w, S + 184, term)
    elif code == 5:
        put(w, S + 88, 1)
    else:
        return refuse(w, 24)
    return 0

def render_edge(o:mutbuf, w:mutbuf, position:u64) -> u64:
    at = graph_begin(o, w, 6, 2)
    graph_string(o, w, L_target)
    graph_ref(o, w, get(w, S + position))
    graph_string(o, w, L_args)
    graph_concat(o, w, get(w, S + position + 8), get(w, S + position + 16))
    graph_end(o, w, at)
    return 0

def render(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    code = get(w, S + 104)
    if code == 4:
        graph_ref(o, w, get(w, S + 184))
        return 0
    count = 2
    if code == 1:
        count = 3
    if code == 2:
        count = 4
    at = graph_begin(o, w, 6, count)
    graph_string(o, w, L_op)
    if code == 1:
        graph_string(o, w, L_jump)
        graph_string(o, w, L_target)
        graph_ref(o, w, get(w, S + 112))
        graph_string(o, w, L_args)
        graph_concat(o, w, get(w, S + 120), get(w, S + 128))
    elif code == 2:
        graph_string(o, w, L_branch)
        graph_string(o, w, L_cond)
        graph_ref(o, w, get(w, S + 160))
        graph_string(o, w, L_then)
        render_edge(o, w, 112)
        graph_string(o, w, L_else)
        render_edge(o, w, 136)
    else:
        graph_string(o, w, L_ret)
        graph_string(o, w, L_values)
        graph_concat(o, w, get(w, S + 168), get(w, S + 176))
    graph_end(o, w, at)
    return 0
'''


def source_program():
    literals = {'L_' + word: packed(word) for word in
                ('bool', 'target', 'args', 'op', 'jump', 'branch', 'cond',
                 'then', 'else', 'ret', 'values')}

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
    text = TRANSPORT_SOURCE.replace('    DISPATCH', '    pass').replace('1048576', '8388608')
    own.body.extend(node for node in ast.parse(text).body
                    if isinstance(node, ast.FunctionDef) and node.name in common)
    shared = {'unsigned', 'truth', 'prefix', 'name_status', 'name_check', 'hash_name',
              'field', 'typename', 'flat_node', 'type_width', 'linear', 'type_equal',
              'env_type', 'env_values', 'env_lookup', 'refuse', 'allocate'}
    text = MATCH_BODY.replace('if value > 262144:', 'if value > 524288:')
    own.body.extend(node for node in ast.parse(text).body
                    if isinstance(node, ast.FunctionDef) and node.name in shared)
    own.body.extend(ast.parse(GRAPH_BODY).body)
    own.body.extend(node for node in ast.parse(HELPER_BODY).body
                    if isinstance(node, ast.FunctionDef) and node.name in {'append_byte', 'emit'})
    own = Expand().visit(own)
    suffix = []
    for function, values in [
        ('type_id', enumerate(PRIMITIVES, 1)),
        ('kind_id', enumerate(('primitive', 'record', 'enum', 'task', 'partial_record'), 1)),
        ('field_id', zip((1, 2, 4, 8, 16, 32, 64, 128),
                         ('op', 'target', 'args', 'cond', 'then', 'else', 'values', 'code'))),
        ('op_id', enumerate(('jump', 'branch', 'ret', 'trap', 'match'), 1)),
    ]:
        suffix.append('def ' + function + '(s:readbuf, node:u64) -> u64:')
        for identifier, value in values:
            suffix += ['    if text_is(s, node, ' + ', '.join(map(str, packed(value))) + ') != 0:',
                       '        return ' + str(identifier)]
        suffix += ['    return 0']
    return ast.unparse(ast.fix_missing_locations(own)) + '\n' + '\n'.join(suffix) + '\n'


def document():
    nodes = ast.parse(source_program()).body
    assert len({node.name for node in nodes}) == len(nodes)
    names = {node.name: 'f' + str(i) for i, node in enumerate(nodes)}
    signatures = {node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id) for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = Builder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(p) for p in builder.params],
            'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
            'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8',
                                 'module': 'nominal_terminators', 'functions': functions})


if __name__ == '__main__':
    target = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap/nominal_terminators.hepta'
    target.write_text(render_assembly(document()))
    print(target.name, target.stat().st_size)
