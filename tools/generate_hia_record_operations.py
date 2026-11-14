"""Author complete record.make/unpack/get policy and alias bindings in HIA."""
from __future__ import annotations

import ast
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_core_json_frontend import packed
from tools.generate_hia_instruction_policy import SOURCE as TRANSPORT_SOURCE
from tools.generate_hia_enum_match import BODY as MATCH_BODY
from tools.generate_hia_enum_operations import BODY as ENUM_BODY
from tools.generate_hia_task_helpers import BODY as HELPER_BODY, PRIMITIVES
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

MAGIC = int.from_bytes(b'HIAREC01', 'little')
INPUT_BYTES = 256 << 20
OUTPUT_BYTES = 8 << 20
WORKSPACE_BYTES = 16 << 20
CONSTANTS = {'MAGIC': MAGIC, 'INPUT_BYTES': INPUT_BYTES, 'O_BYTES': OUTPUT_BYTES,
    'W_BYTES': WORKSPACE_BYTES, 'S': 4096, 'T': 8192, 'V': 2105344,
    'VF': 4202496, 'HEAP': 6303744,
    'G': 1 << 63, 'N': (1 << 64) - 1, 'ABI': 0xfffffff1}

BODY = r'''
def record_operations(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) > INPUT_BYTES or length(o) < O_BYTES or length(w) < W_BYTES:
        return ABI
    if validate(s, w) == 0 or tag(s, 0) != 5 or total(s, 0) != 9:
        return ABI
    i = 0
    while i < 256:
        put(w, S + i, 0)
        i = i + 8
    put(w, S + 16, HEAP)
    if admit(s, w) == 0:
        return ABI
    operation = element(s, 0, 2)
    if text_is(s, operation, L_make) != 0:
        lower_make(s, w)
    elif text_is(s, operation, L_unpack) != 0:
        lower_unpack(s, w)
    else:
        lower_get(s, w)
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

def descriptor_ok(s:readbuf, node:u64, count:u64) -> u64:
    if tag(s, node) != 5 or total(s, node) != 5:
        return 0
    kind = kind_id(s, element(s, node, 0))
    flat = flat_node(s, node)
    fields = element(s, node, 3)
    base = element(s, node, 4)
    if kind == 0 or tag(s, flat) != 5 or total(s, flat) > 512:
        return 0
    if tag(s, element(s, node, 2)) != 1 or tag(s, fields) != 5 or total(s, fields) > 64:
        return 0
    if kind == 1 and total(s, flat) != 1:
        return 0
    if kind != 2 and kind != 5 and total(s, fields) != 0:
        return 0
    if kind == 5:
        if unsigned(s, base) >= count:
            return 0
    elif tag(s, base) != 0:
        return 0
    at = flat + 24
    i = 0
    while i < total(s, flat):
        if type_id(s, at) == 0:
            return 0
        at = end(s, at)
        i = i + 1
    at = fields + 24
    i = 0
    while i < total(s, fields):
        if tag(s, at) != 5 or total(s, at) != 2:
            return 0
        if name_status(s, element(s, at, 0)) != 0:
            return 0
        if unsigned(s, element(s, at, 1)) >= count:
            return 0
        at = end(s, at)
        i = i + 1
    return 1

def record_shape(s:readbuf, w:mutbuf, descriptor:u64) -> u64:
    kind = kind_id(s, element(s, descriptor, 0))
    if kind != 2 and kind != 5:
        return 1
    flat = flat_node(s, descriptor)
    expected = flat + 24
    width = 0
    if kind == 5:
        if total(s, flat) == 0 or type_id(s, expected) != 13:
            return 0
        base = typename(s, w, unsigned(s, element(s, descriptor, 4)))
        if kind_id(s, element(s, base, 0)) != 2:
            return 0
        width = 1
        expected = end(s, expected)
    fields = element(s, descriptor, 3)
    field_node = fields + 24
    i = 0
    while i < total(s, fields):
        nested = flat_node(s, typename(s, w, unsigned(s, element(s, field_node, 1))))
        source = nested + 24
        j = 0
        while j < total(s, nested):
            if width >= total(s, flat) or same_text(s, source, expected) == 0:
                return 0
            width = width + 1
            expected = end(s, expected)
            source = end(s, source)
            j = j + 1
        field_node = end(s, field_node)
        i = i + 1
    return choose(width == total(s, flat), 1, 0)

def admit_values(s:readbuf, w:mutbuf, values:u64) -> u64:
    node = values + 24
    slots = 0
    i = 0
    while i < total(s, values):
        if tag(s, node) != 5 or total(s, node) != 4:
            return 0
        ident = unsigned(s, element(s, node, 0))
        names = element(s, node, 1)
        if ident >= get(w, S + 48) or tag(s, names) != 5:
            return 0
        if tag(s, element(s, node, 2)) != 1 or tag(s, element(s, node, 3)) != 1:
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
        put(w, V + i * 8, node)
        put(w, VF + i * 8, truth(s, element(s, node, 3)))
        node = end(s, node)
        i = i + 1
    return 1

def admit(s:readbuf, w:mutbuf) -> u64:
    phase = unsigned(s, element(s, 0, 0))
    serial = unsigned(s, element(s, 0, 1))
    operation = element(s, 0, 2)
    if phase > 1 or serial > 8192:
        return 0
    if text_is(s, operation, L_make) == 0 and text_is(s, operation, L_unpack) == 0 and text_is(s, operation, L_get) == 0:
        return 0
    if text_is(s, operation, L_make) != 0 and phase != 0:
        return 0
    put(w, S, serial)
    types = element(s, 0, 4)
    values = element(s, 0, 5)
    args = element(s, 0, 6)
    if tag(s, types) != 5 or tag(s, values) != 5 or tag(s, args) != 5:
        return 0
    tc = total(s, types)
    vc = total(s, values)
    if tc > 262144 or vc > 262144 or total(s, args) > 262144:
        return 0
    put(w, S + 48, tc)
    put(w, S + 40, vc)
    node = types + 24
    i = 0
    while i < tc:
        put(w, T + i * 8, node)
        if descriptor_ok(s, node, tc) == 0:
            return 0
        node = end(s, node)
        i = i + 1
    i = 0
    while i < tc:
        if record_shape(s, w, get(w, T + i * 8)) == 0:
            return 0
        i = i + 1
    if admit_values(s, w, values) == 0:
        return 0
    at = args + 24
    i = 0
    while i < total(s, args):
        if tag(s, at) != 5 or total(s, at) != 2:
            return 0
        if name_status(s, element(s, at, 0)) != 0:
            return 0
        if unsigned(s, element(s, at, 1)) >= vc:
            return 0
        at = end(s, at)
        i = i + 1
    if declared_ok(s, w, element(s, 0, 7)) == 0:
        return 0
    outputs = element(s, 0, 8)
    if phase == 0:
        if tag(s, outputs) != 0:
            return 0
    elif declared_ok(s, w, outputs) == 0:
        return 0
    return 1

def consume(s:readbuf, w:mutbuf, arg:u64) -> u64:
    ident = arg_id(s, arg)
    if get(w, VF + ident * 8) != 0:
        return refuse(w, 4)
    if linear(s, typename(s, w, arg_type(s, w, arg))) != 0:
        put(w, VF + ident * 8, 1)
    return 1

def owns(s:readbuf, descriptor:u64) -> u64:
    flat = flat_node(s, descriptor)
    at = flat + 24
    i = 0
    while i < total(s, flat):
        typ = type_id(s, at)
        if typ == 13 or typ == 16:
            return 1
        at = end(s, at)
        i = i + 1
    return 0

def copy_range(s:readbuf, w:mutbuf, names:u64, offset:u64, count:u64) -> u64:
    vector = allocate(w, count * 8)
    at = names + 24
    i = 0
    while i < offset:
        at = end(s, at)
        i = i + 1
    i = 0
    while i < count:
        put(w, vector + i * 8, at)
        at = end(s, at)
        i = i + 1
    return vector

def concatenate(s:readbuf, w:mutbuf, args:u64, count:u64) -> u64:
    vector = allocate(w, count * 8)
    cursor = 0
    arg = args + 24
    i = 0
    while i < total(s, args):
        names = arg_names(s, w, arg)
        at = names + 24
        j = 0
        while j < total(s, names):
            put(w, vector + cursor * 8, at)
            cursor = cursor + 1
            at = end(s, at)
            j = j + 1
        arg = end(s, arg)
        i = i + 1
    return vector

def bind(w:mutbuf, name:u64, typ:u64, vector:u64, count:u64, external:u64) -> u64:
    at = allocate(w, 48)
    put(w, at, name)
    put(w, at + 8, typ)
    put(w, at + 16, vector)
    put(w, at + 24, count)
    put(w, at + 32, external)
    put(w, at + 40, 0)
    if get(w, S + 64) == 0:
        put(w, S + 64, at)
    else:
        put(w, get(w, S + 72) + 40, at)
    put(w, S + 72, at)
    put(w, S + 80, get(w, S + 80) + 1)
    return 0

def lower_make(s:readbuf, w:mutbuf) -> u64:
    attrs = element(s, 0, 3)
    if tag(s, attrs) != 6 or total(s, attrs) != 0:
        return refuse(w, 1)
    declared = element(s, 0, 7)
    if total(s, declared) != 1:
        return refuse(w, 2)
    output = declared + 24
    ident = unsigned(s, element(s, output, 1))
    descriptor = typename(s, w, ident)
    if kind_id(s, element(s, descriptor, 0)) != 2:
        return refuse(w, 2)
    fields = element(s, descriptor, 3)
    args = element(s, 0, 6)
    if total(s, args) != total(s, fields):
        return refuse(w, 3)
    arg = args + 24
    field_node = fields + 24
    i = 0
    while i < total(s, args):
        if type_equal(s, w, arg_type(s, w, arg), unsigned(s, element(s, field_node, 1))) == 0:
            return refuse(w, 3)
        arg = end(s, arg)
        field_node = end(s, field_node)
        i = i + 1
    arg = args + 24
    external = 1
    i = 0
    while i < total(s, args):
        if consume(s, w, arg) == 0:
            return 0
        value = get(w, V + arg_id(s, arg) * 8)
        if truth(s, element(s, value, 2)) == 0 and linear(s, typename(s, w, arg_type(s, w, arg))) != 0:
            external = 0
        arg = end(s, arg)
        i = i + 1
    if owns(s, descriptor) != 0:
        external = 0
    count = type_width(s, descriptor)
    return bind(w, element(s, output, 0), ident, concatenate(s, w, args, count), count, external)

def unpack_outputs(s:readbuf, w:mutbuf, fields:u64, outputs:u64) -> u64:
    if total(s, fields) != total(s, outputs):
        return refuse(w, 7)
    field_node = fields + 24
    output = outputs + 24
    i = 0
    while i < total(s, fields):
        expected = unsigned(s, element(s, field_node, 1))
        if type_equal(s, w, expected, unsigned(s, element(s, output, 1))) == 0:
            return refuse(w, 7)
        field_node = end(s, field_node)
        output = end(s, output)
        i = i + 1
    return 1

def unpack_bindings(s:readbuf, w:mutbuf, arg:u64, fields:u64, outputs:u64) -> u64:
    value = get(w, V + arg_id(s, arg) * 8)
    names = arg_names(s, w, arg)
    offset = 0
    field_node = fields + 24
    output = outputs + 24
    i = 0
    while i < total(s, fields):
        typ = unsigned(s, element(s, field_node, 1))
        count = type_width(s, typename(s, w, typ))
        bind(w, element(s, output, 0), typ, copy_range(s, w, names, offset, count),
             count, truth(s, element(s, value, 2)))
        offset = offset + count
        field_node = end(s, field_node)
        output = end(s, output)
        i = i + 1
    return 0

def lower_unpack(s:readbuf, w:mutbuf) -> u64:
    attrs = element(s, 0, 3)
    if tag(s, attrs) != 6 or total(s, attrs) != 0:
        return refuse(w, 5)
    args = element(s, 0, 6)
    if total(s, args) != 1:
        return refuse(w, 6)
    arg = args + 24
    descriptor = typename(s, w, arg_type(s, w, arg))
    if kind_id(s, element(s, descriptor, 0)) != 2:
        return refuse(w, 6)
    if unsigned(s, element(s, 0, 0)) == 0:
        put(w, S + 56, 1)
        return 0
    fields = element(s, descriptor, 3)
    outputs = element(s, 0, 8)
    if unpack_outputs(s, w, fields, outputs) == 0:
        return 0
    if consume(s, w, arg) == 0:
        return 0
    return unpack_bindings(s, w, arg, fields, outputs)

def field_lookup(s:readbuf, w:mutbuf, descriptor:u64, name:u64) -> u64:
    fields = element(s, descriptor, 3)
    offset = choose(kind_id(s, element(s, descriptor, 0)) == 5, 1, 0)
    field_node = fields + 24
    i = 0
    while i < total(s, fields):
        if same_text(s, element(s, field_node, 0), name) != 0:
            put(w, S + 96, offset)
            return field_node
        offset = offset + type_width(s, typename(s, w, unsigned(s, element(s, field_node, 1))))
        field_node = end(s, field_node)
        i = i + 1
    return N

def lower_get(s:readbuf, w:mutbuf) -> u64:
    attrs = element(s, 0, 3)
    if tag(s, attrs) != 6 or total(s, attrs) != 1:
        return refuse(w, 8)
    if text_is(s, attrs + 24, L_field) == 0:
        return refuse(w, 8)
    args = element(s, 0, 6)
    if total(s, args) != 1:
        return refuse(w, 9)
    arg = args + 24
    descriptor = typename(s, w, arg_type(s, w, arg))
    kind = kind_id(s, element(s, descriptor, 0))
    if kind != 2 and kind != 5:
        return refuse(w, 9)
    name = end(s, attrs + 24)
    if name_check(s, w, name, 10) == 0:
        return 0
    field_node = field_lookup(s, w, descriptor, name)
    if field_node == N:
        if kind == 5:
            base = typename(s, w, unsigned(s, element(s, descriptor, 4)))
            if field_lookup(s, w, base, name) != N:
                return refuse(w, 12)
        return refuse(w, 13)
    typ = unsigned(s, element(s, field_node, 1))
    selected = typename(s, w, typ)
    if linear(s, selected) != 0:
        return refuse(w, 14)
    if unsigned(s, element(s, 0, 0)) == 0:
        put(w, S + 56, 1)
        return 0
    outputs = element(s, 0, 8)
    if total(s, outputs) != 1:
        return refuse(w, 7)
    output = outputs + 24
    if type_equal(s, w, typ, unsigned(s, element(s, output, 1))) == 0:
        return refuse(w, 7)
    count = type_width(s, selected)
    return bind(w, element(s, output, 0), typ,
        copy_range(s, w, arg_names(s, w, arg), get(w, S + 96), count), count, 0)

def render(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    emit_text(o, w, '{"ops":[],"consumed":[')
    i = 0
    while i < get(w, S + 40):
        if i != 0:
            append_byte(o, w, 44)
        if get(w, VF + i * 8) == 0:
            emit_text(o, w, 'false')
        else:
            emit_text(o, w, 'true')
        i = i + 1
    emit_text(o, w, '],"values":[')
    at = get(w, S + 64)
    previous = 0
    while at != 0:
        if previous != 0:
            append_byte(o, w, 44)
        append_byte(o, w, 91)
        source_name(s, o, w, get(w, at))
        append_byte(o, w, 44)
        number(o, w, get(w, at + 8))
        append_byte(o, w, 44)
        render_names(s, o, w, get(w, at + 16), get(w, at + 24))
        if get(w, at + 32) == 0:
            emit_text(o, w, ',false,false]')
        else:
            emit_text(o, w, ',true,false]')
        at = get(w, at + 40)
        previous = 1
    emit_text(o, w, ']}')
    return 0
'''


def source_program():
    literals = {'L_' + name: packed(value) for name, value in
                [('make', 'record.make'), ('unpack', 'record.unpack'),
                 ('get', 'record.get'), ('field', 'field')]}
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
    shared = {'unsigned', 'truth', 'prefix', 'name_status', 'name_check', 'typename',
              'flat_node', 'type_width', 'linear', 'type_equal', 'refuse', 'allocate',
              'render_name', 'render_names'}
    own.body.extend(node for node in ast.parse(MATCH_BODY).body
                    if isinstance(node, ast.FunctionDef) and node.name in shared)
    shared = {'declared_ok', 'arg_id', 'arg_type', 'arg_names', 'number'}
    own.body.extend(node for node in ast.parse(ENUM_BODY).body
                    if isinstance(node, ast.FunctionDef) and node.name in shared)
    utility = {'append_byte', 'emit', 'source_name'}
    own.body.extend(node for node in ast.parse(HELPER_BODY).body
                    if isinstance(node, ast.FunctionDef) and node.name in utility)
    own = Expand().visit(own)
    suffix = []
    for function, values in [('type_id', enumerate(PRIMITIVES, 1)),
        ('kind_id', enumerate(('primitive', 'record', 'enum', 'task', 'partial_record'), 1))]:
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
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8', 'module': 'record_operations', 'functions': functions})


if __name__ == '__main__':
    target = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap/record_operations.hepta'
    target.write_text(render_assembly(document()))
    print(target.name, target.stat().st_size)
