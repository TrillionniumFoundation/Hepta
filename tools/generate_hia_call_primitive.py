"""Author full nominal call and primitive erasure with lossless object graphs."""
from __future__ import annotations

import ast
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_core_json_frontend import packed
from tools.generate_hia_instruction_policy import SOURCE as TRANSPORT_SOURCE
from tools.generate_hia_enum_match import BODY as MATCH_BODY
from tools.generate_hia_enum_operations import BODY as ENUM_BODY
from tools.generate_hia_record_operations import BODY as RECORD_BODY
from tools.generate_hia_task_helpers import BODY as HELPER_BODY, PRIMITIVES
from tools.hia_native_value_graph import BODY as GRAPH_BODY
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

MAGIC = int.from_bytes(b'HIACPR01', 'little')
INPUT_BYTES = 256 << 20
OUTPUT_BYTES = 64 << 20
WORKSPACE_BYTES = 32 << 20
CONSTANTS = {'MAGIC': MAGIC, 'INPUT_BYTES': INPUT_BYTES, 'O_BYTES': OUTPUT_BYTES,
    'W_BYTES': WORKSPACE_BYTES, 'S': 4096, 'T': 8192, 'TO': 4202496,
    'V': 8396800, 'VF': 10493952, 'FS': 12591104, 'HEAP': 12607488,
    'G': 1 << 63, 'N': (1 << 64) - 1, 'ABI': 0xfffffff1}

BODY = r'''
def call_primitive(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) > INPUT_BYTES or length(o) < O_BYTES or length(w) < W_BYTES:
        return ABI
    if validate(s, w) == 0 or tag(s, 0) != 5 or total(s, 0) != 10:
        return ABI
    i = 0
    while i < 256:
        put(w, S + i, 0)
        i = i + 8
    i = 0
    while i < 2048:
        put(w, FS + i * 8, 0)
        i = i + 1
    put(w, S + 16, HEAP)
    if admit(s, w) == 0:
        return ABI
    if text_is(s, element(s, 0, 2), L_call) != 0:
        lower_call(s, w)
    else:
        lower_primitive(s, w)
    if get(w, S + 32) != 0:
        return ABI
    put(w, S + 24, 64)
    render(s, o, w)
    if get(w, S + 32) != 0:
        return ABI
    put(o, 0, MAGIC)
    put(o, 8, get(w, S + 8))
    put(o, 16, get(w, S))
    put(o, 24, get(w, S + 56))
    put(o, 32, get(w, S + 24) - 64)
    put(o, 40, 0)
    put(o, 48, 0)
    put(o, 56, 0)
    return get(w, S + 24)

def descriptor_ok(s:readbuf, w:mutbuf, node:u64, index:u64) -> u64:
    if tag(s, node) != 5 or total(s, node) != 3:
        return 0
    kind = kind_id(s, element(s, node, 0))
    flat = flat_node(s, node)
    if kind == 0 or tag(s, flat) != 5 or total(s, flat) > 512:
        return 0
    if tag(s, element(s, node, 2)) != 1 or (kind == 1 and total(s, flat) != 1):
        return 0
    at = flat + 24
    owns = 0
    i = 0
    while i < total(s, flat):
        primitive = type_id(s, at)
        if primitive == 0:
            return 0
        if primitive == 13 or primitive == 16:
            owns = 1
        at = end(s, at)
        i = i + 1
    put(w, TO + index * 8, owns)
    return 1

def declarations_ok(s:readbuf, w:mutbuf, node:u64) -> u64:
    if declared_ok(s, w, node) == 0:
        return 0
    at = node + 24
    slots = 0
    i = 0
    while i < total(s, node):
        slots = slots + type_width(s, typename(s, w, unsigned(s, element(s, at, 1))))
        if slots > 32768:
            return 0
        at = end(s, at)
        i = i + 1
    return 1

def admit(s:readbuf, w:mutbuf) -> u64:
    phase = unsigned(s, element(s, 0, 0))
    serial = unsigned(s, element(s, 0, 1))
    operation = element(s, 0, 2)
    if phase > 2 or serial > 8192 or tag(s, operation) != 4:
        return 0
    if text_is(s, operation, L_call) == 0 and phase != 0:
        return 0
    put(w, S, serial)
    types = element(s, 0, 4)
    values = element(s, 0, 5)
    args = element(s, 0, 6)
    if tag(s, types) != 5 or tag(s, values) != 5 or tag(s, args) != 5:
        return 0
    tc = total(s, types)
    vc = total(s, values)
    if tc > 524288 or vc > 262144 or total(s, args) > 262144:
        return 0
    put(w, S + 48, tc)
    put(w, S + 40, vc)
    node = types + 24
    i = 0
    while i < tc:
        put(w, T + i * 8, node)
        if descriptor_ok(s, w, node, i) == 0:
            return 0
        node = end(s, node)
        i = i + 1
    if admit_values(s, w, values) == 0:
        return 0
    at = args + 24
    i = 0
    while i < total(s, args):
        if tag(s, at) != 5 or total(s, at) != 2:
            return 0
        if name_status(s, element(s, at, 0)) != 0 or unsigned(s, element(s, at, 1)) >= vc:
            return 0
        at = end(s, at)
        i = i + 1
    if declarations_ok(s, w, element(s, 0, 7)) == 0:
        return 0
    signatures = element(s, 0, 8)
    outputs = element(s, 0, 9)
    if phase == 0:
        if tag(s, signatures) != 0 or tag(s, outputs) != 0:
            return 0
    else:
        if signatures_ok(s, w, signatures) == 0:
            return 0
        if phase == 1:
            if tag(s, outputs) != 0:
                return 0
        elif declarations_ok(s, w, outputs) == 0:
            return 0
    return 1

def ids_ok(s:readbuf, w:mutbuf, node:u64) -> u64:
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

def signatures_ok(s:readbuf, w:mutbuf, signatures:u64) -> u64:
    if tag(s, signatures) != 5 or total(s, signatures) > 1024:
        return 0
    at = signatures + 24
    i = 0
    while i < total(s, signatures):
        if tag(s, at) != 5 or total(s, at) != 3:
            return 0
        name = element(s, at, 0)
        if name_status(s, name) != 0 or ids_ok(s, w, element(s, at, 1)) == 0 or ids_ok(s, w, element(s, at, 2)) == 0:
            return 0
        if index_signature(s, w, at) == 0:
            return 0
        at = end(s, at)
        i = i + 1
    return 1

def index_signature(s:readbuf, w:mutbuf, node:u64) -> u64:
    name = element(s, node, 0)
    slot = hash_name(s, name) & 2047
    while get(w, FS + slot * 8) != 0:
        other = get(w, FS + slot * 8)
        if same_text(s, name, element(s, other, 0)) != 0:
            return 0
        slot = (slot + 1) & 2047
    put(w, FS + slot * 8, node)
    return 1

def lookup_signature(s:readbuf, w:mutbuf, name:u64) -> u64:
    slot = hash_name(s, name) & 2047
    while True:
        node = get(w, FS + slot * 8)
        if node == 0:
            return N
        if same_text(s, name, element(s, node, 0)) != 0:
            return node
        slot = (slot + 1) & 2047
    return N

def consume(s:readbuf, w:mutbuf, arg:u64) -> u64:
    ident = arg_id(s, arg)
    if get(w, VF + ident * 8) != 0:
        return refuse(w, 8)
    if linear(s, typename(s, w, arg_type(s, w, arg))) != 0:
        put(w, VF + ident * 8, 1)
    return 1

def bind_output(s:readbuf, w:mutbuf, name:u64, typ:u64) -> u64:
    descriptor = typename(s, w, typ)
    width = type_width(s, descriptor)
    vector = allocate(w, width * 8)
    if kind_id(s, element(s, descriptor, 0)) == 1:
        put(w, vector, name)
    else:
        i = 0
        while i < width:
            put(w, vector + i * 8, fresh(w))
            if get(w, S + 8) != 0:
                return 0
            i = i + 1
    bind(w, name, typ, vector, width, 0)
    put(w, S + 88, get(w, S + 88) + width)
    return 1

def argument_arrays(s:readbuf, w:mutbuf) -> u64:
    args = element(s, 0, 6)
    count = total(s, args)
    vector = allocate(w, count * 8)
    at = args + 24
    i = 0
    while i < count:
        put(w, vector + i * 8, arg_names(s, w, at))
        at = end(s, at)
        i = i + 1
    put(w, S + 104, vector)
    put(w, S + 112, count)
    put(w, S + 96, 1)
    return 0

def compare_arguments(s:readbuf, w:mutbuf, params:u64) -> u64:
    args = element(s, 0, 6)
    if total(s, args) != total(s, params):
        return refuse(w, 6)
    arg = args + 24
    param = params + 24
    i = 0
    while i < total(s, args):
        if type_equal(s, w, arg_type(s, w, arg), unsigned(s, param)) == 0:
            return refuse(w, 6)
        arg = end(s, arg)
        param = end(s, param)
        i = i + 1
    return 1

def compare_outputs(s:readbuf, w:mutbuf, expected:u64) -> u64:
    outputs = element(s, 0, 9)
    if total(s, outputs) != total(s, expected):
        return refuse(w, 7)
    output = outputs + 24
    typ = expected + 24
    i = 0
    while i < total(s, outputs):
        if type_equal(s, w, unsigned(s, element(s, output, 1)), unsigned(s, typ)) == 0:
            return refuse(w, 7)
        output = end(s, output)
        typ = end(s, typ)
        i = i + 1
    return 1

def consume_owned(s:readbuf, w:mutbuf) -> u64:
    args = element(s, 0, 6)
    at = args + 24
    i = 0
    while i < total(s, args):
        if get(w, TO + arg_type(s, w, at) * 8) != 0:
            if consume(s, w, at) == 0:
                return 0
        at = end(s, at)
        i = i + 1
    return 1

def bind_returns(s:readbuf, w:mutbuf, returns:u64) -> u64:
    outputs = element(s, 0, 9)
    output = outputs + 24
    typ = returns + 24
    i = 0
    while i < total(s, returns):
        if bind_output(s, w, element(s, output, 0), unsigned(s, typ)) == 0:
            return 0
        output = end(s, output)
        typ = end(s, typ)
        i = i + 1
    return 1

def lower_call(s:readbuf, w:mutbuf) -> u64:
    attrs = element(s, 0, 3)
    if tag(s, attrs) != 6 or total(s, attrs) != 1:
        return refuse(w, 2)
    if text_is(s, attrs + 24, L_function) == 0:
        return refuse(w, 2)
    callee = end(s, attrs + 24)
    if name_check(s, w, callee, 3) == 0:
        return 0
    put(w, S + 120, callee)
    phase = unsigned(s, element(s, 0, 0))
    if phase == 0:
        put(w, S + 56, 1)
        return 0
    signature = lookup_signature(s, w, callee)
    if signature == N:
        return refuse(w, 5)
    if compare_arguments(s, w, element(s, signature, 1)) == 0:
        return 0
    if phase == 1:
        put(w, S + 56, 2)
        return 0
    returns = element(s, signature, 2)
    if compare_outputs(s, w, returns) == 0:
        return 0
    if consume_owned(s, w) == 0 or bind_returns(s, w, returns) == 0:
        return 0
    return argument_arrays(s, w)

def primitive_inputs(s:readbuf, w:mutbuf) -> u64:
    args = element(s, 0, 6)
    arg = args + 24
    i = 0
    while i < total(s, args):
        if kind_id(s, element(s, typename(s, w, arg_type(s, w, arg)), 0)) != 1:
            return refuse(w, 9)
        arg = end(s, arg)
        i = i + 1
    declared = element(s, 0, 7)
    at = declared + 24
    i = 0
    while i < total(s, declared):
        if kind_id(s, element(s, typename(s, w, unsigned(s, element(s, at, 1))), 0)) != 1:
            return refuse(w, 9)
        at = end(s, at)
        i = i + 1
    return 1

def lower_primitive(s:readbuf, w:mutbuf) -> u64:
    if primitive_inputs(s, w) == 0:
        return 0
    operation = element(s, 0, 2)
    if consumes_arguments(s, operation) != 0:
        args = element(s, 0, 6)
        at = args + 24
        i = 0
        while i < total(s, args):
            if consume(s, w, at) == 0:
                return 0
            at = end(s, at)
            i = i + 1
    declared = element(s, 0, 7)
    at = declared + 24
    i = 0
    while i < total(s, declared):
        bind_output(s, w, element(s, at, 0), unsigned(s, element(s, at, 1)))
        at = end(s, at)
        i = i + 1
    return argument_arrays(s, w)

def graph_number(o:mutbuf, w:mutbuf, value:u64) -> u64:
    at = get(w, S + 24)
    graph_word(o, w, 2)
    graph_word(o, w, 0)
    number(o, w, value)
    return graph_end(o, w, at)

def graph_flag(o:mutbuf, w:mutbuf, value:u64) -> u64:
    graph_word(o, w, 1)
    graph_word(o, w, 1)
    return append_byte(o, w, value)

def graph_name(o:mutbuf, w:mutbuf, value:u64) -> u64:
    if value < G:
        return graph_ref(o, w, value)
    at = get(w, S + 24)
    graph_word(o, w, 4)
    graph_word(o, w, 0)
    emit_text(o, w, 'h2internal_')
    number(o, w, value - G)
    return graph_end(o, w, at)

def graph_names(o:mutbuf, w:mutbuf, vector:u64, count:u64) -> u64:
    at = graph_begin(o, w, 5, count)
    i = 0
    while i < count:
        graph_name(o, w, get(w, vector + i * 8))
        i = i + 1
    return graph_end(o, w, at)

def graph_binding(o:mutbuf, w:mutbuf, binding:u64) -> u64:
    at = graph_begin(o, w, 5, 5)
    graph_ref(o, w, get(w, binding))
    graph_number(o, w, get(w, binding + 8))
    graph_names(o, w, get(w, binding + 16), get(w, binding + 24))
    graph_flag(o, w, 0)
    graph_flag(o, w, 0)
    return graph_end(o, w, at)

def graph_parameter(o:mutbuf, w:mutbuf, name:u64, typ:u64) -> u64:
    at = graph_begin(o, w, 6, 2)
    gtext(o, w, 'name')
    graph_name(o, w, name)
    gtext(o, w, 'type')
    graph_ref(o, w, typ)
    return graph_end(o, w, at)

def graph_parameters(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    at = graph_begin(o, w, 5, get(w, S + 88))
    binding = get(w, S + 64)
    while binding != 0:
        flat = flat_node(s, typename(s, w, get(w, binding + 8)))
        typ = flat + 24
        names = get(w, binding + 16)
        i = 0
        while i < get(w, binding + 24):
            graph_parameter(o, w, get(w, names + i * 8), typ)
            typ = end(s, typ)
            i = i + 1
        binding = get(w, binding + 40)
    return graph_end(o, w, at)

def graph_operation(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    at = graph_begin(o, w, 6, 4)
    gtext(o, w, 'op')
    graph_ref(o, w, element(s, 0, 2))
    gtext(o, w, 'args')
    graph_concat(o, w, get(w, S + 104), get(w, S + 112))
    gtext(o, w, 'out')
    graph_parameters(s, o, w)
    gtext(o, w, 'attrs')
    if text_is(s, element(s, 0, 2), L_call) != 0:
        attrs = graph_begin(o, w, 6, 1)
        gtext(o, w, 'function')
        graph_ref(o, w, get(w, S + 120))
        graph_end(o, w, attrs)
    else:
        graph_ref(o, w, element(s, 0, 3))
    return graph_end(o, w, at)

def render(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    root = graph_begin(o, w, 6, 4)
    gtext(o, w, 'ops')
    container = graph_begin(o, w, 5, get(w, S + 96))
    if get(w, S + 96) != 0:
        graph_operation(s, o, w)
    graph_end(o, w, container)
    gtext(o, w, 'consumed')
    container = graph_begin(o, w, 5, get(w, S + 40))
    i = 0
    while i < get(w, S + 40):
        graph_flag(o, w, get(w, VF + i * 8))
        i = i + 1
    graph_end(o, w, container)
    gtext(o, w, 'values')
    container = graph_begin(o, w, 5, get(w, S + 80))
    binding = get(w, S + 64)
    while binding != 0:
        graph_binding(o, w, binding)
        binding = get(w, binding + 40)
    graph_end(o, w, container)
    gtext(o, w, 'query')
    if get(w, S + 56) == 0:
        graph_null(o, w)
    else:
        container = graph_begin(o, w, 6, 0)
        graph_end(o, w, container)
    return graph_end(o, w, root)
'''


def source_program():
    literals = {'L_' + name: packed(value) for name, value in [('call', 'call'), ('function', 'function')]}
    class Expand(ast.NodeTransformer):
        def visit_Expr(self, node):
            if (isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name)
                    and node.value.func.id == 'emit_text'):
                output, workspace, literal = node.value.args
                assert isinstance(literal, ast.Constant) and type(literal.value) is str
                return [ast.Expr(ast.Call(ast.Name('emit', ast.Load()),
                    [output, workspace, *(ast.Constant(value) for value in packed(literal.value[i:i+24]))], []))
                    for i in range(0, len(literal.value), 24)]
            return self.generic_visit(node)
        def visit_Name(self, node):
            return ast.Constant(CONSTANTS[node.id]) if node.id in CONSTANTS else node
        def visit_Call(self, node):
            if isinstance(node.func, ast.Name) and node.func.id == 'gtext':
                output, workspace, literal = node.args
                assert isinstance(literal, ast.Constant) and type(literal.value) is str and len(literal.value) <= 24
                return ast.Call(ast.Name('graph_string', ast.Load()),
                    [output, workspace, *(ast.Constant(value) for value in packed(literal.value))], [])
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
              'typename', 'flat_node', 'type_width', 'linear', 'type_equal', 'refuse', 'allocate', 'fresh'}
    match = MATCH_BODY.replace('if value > 262144:', 'if value > 524288:')
    own.body.extend(node for node in ast.parse(match).body
                    if isinstance(node, ast.FunctionDef) and node.name in shared)
    shared = {'declared_ok', 'arg_id', 'arg_type', 'arg_names', 'number'}
    own.body.extend(node for node in ast.parse(ENUM_BODY).body
                    if isinstance(node, ast.FunctionDef) and node.name in shared)
    shared = {'admit_values', 'bind'}
    own.body.extend(node for node in ast.parse(RECORD_BODY).body
                    if isinstance(node, ast.FunctionDef) and node.name in shared)
    utility = {'append_byte', 'emit'}
    own.body.extend(node for node in ast.parse(HELPER_BODY).body
                    if isinstance(node, ast.FunctionDef) and node.name in utility)
    own.body.extend(ast.parse(GRAPH_BODY).body)
    own = Expand().visit(own)
    suffix = []
    for function, values in [('type_id', enumerate(PRIMITIVES, 1)),
        ('kind_id', enumerate(('primitive', 'record', 'enum', 'task', 'partial_record'), 1)),
        ('consumes_arguments', [(1, value) for value in ('owner.move', 'owner.drop', 'loan.end', 'chain.try_push', 'chain.pop')])]:
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
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8', 'module': 'call_primitive', 'functions': functions})


if __name__ == '__main__':
    target = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap/call_primitive.hepta'
    target.write_text(render_assembly(document()))
    print(target.name, target.stat().st_size)
