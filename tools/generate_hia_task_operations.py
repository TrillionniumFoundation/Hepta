"""Author complete ordinary task instruction lowering and ordered continuations."""
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
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

MAGIC = int.from_bytes(b'HIATOP01', 'little')
INPUT_BYTES = 256 << 20
OUTPUT_BYTES = 8 << 20
WORKSPACE_BYTES = 16 << 20
CONSTANTS = {'MAGIC': MAGIC, 'INPUT_BYTES': INPUT_BYTES, 'O_BYTES': OUTPUT_BYTES,
    'W_BYTES': WORKSPACE_BYTES, 'S': 4096, 'T': 8192, 'V': 2105344,
    'VF': 4202496, 'B': 6299648, 'HEAP': 6303744,
    'G': 1 << 63, 'N': (1 << 64) - 1, 'ABI': 0xfffffff1}

BODY = r'''
def task_operations(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) > INPUT_BYTES or length(o) < O_BYTES or length(w) < W_BYTES:
        return ABI
    if validate(s, w) == 0 or tag(s, 0) != 5 or total(s, 0) != 12:
        return ABI
    i = 0
    while i < 256:
        put(w, S + i, 0)
        i = i + 8
    i = 0
    while i < 128:
        put(w, B + i, 0)
        i = i + 8
    put(w, S + 16, HEAP)
    if admit(s, w) == 0:
        return ABI
    operation = operation_id(s, element(s, 0, 2))
    attrs = element(s, 0, 3)
    if tag(s, attrs) != 6 or total(s, attrs) != 0:
        refuse(w, 3)
    elif operation == 1:
        lower_create(s, w)
    else:
        arg = task_arg(s, w)
        if arg != N:
            if operation == 2:
                lower_state(s, w, arg)
            elif operation >= 3:
                lower_helper(s, w, arg, operation)
            else:
                refuse(w, 9)
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
    state = element(s, node, 3)
    result = element(s, node, 4)
    if kind == 0 or tag(s, flat) != 5 or total(s, flat) > 512:
        return 0
    if tag(s, element(s, node, 2)) != 1:
        return 0
    if kind == 1 and total(s, flat) != 1:
        return 0
    if kind == 4:
        if unsigned(s, state) >= count or unsigned(s, result) >= count:
            return 0
    elif tag(s, state) != 0 or tag(s, result) != 0:
        return 0
    at = flat + 24
    i = 0
    while i < total(s, flat):
        if type_id(s, at) == 0:
            return 0
        at = end(s, at)
        i = i + 1
    return 1

def task_shape(s:readbuf, w:mutbuf, descriptor:u64) -> u64:
    if kind_id(s, element(s, descriptor, 0)) != 4:
        return 1
    flat = flat_node(s, descriptor)
    if total(s, flat) < 2 or type_id(s, element(s, flat, 0)) != 7 or type_id(s, element(s, flat, 1)) != 13:
        return 0
    expected = element(s, flat, 2)
    width = 2
    i = 3
    while i < 5:
        nested = flat_node(s, typename(s, w, unsigned(s, element(s, descriptor, i))))
        at = nested + 24
        j = 0
        while j < total(s, nested):
            if width >= total(s, flat) or same_text(s, expected, at) == 0:
                return 0
            expected = end(s, expected)
            at = end(s, at)
            width = width + 1
            j = j + 1
        i = i + 1
    return choose(width == total(s, flat), 1, 0)

def admit(s:readbuf, w:mutbuf) -> u64:
    phase = unsigned(s, element(s, 0, 0))
    serial = unsigned(s, element(s, 0, 1))
    operation = operation_id(s, element(s, 0, 2))
    if serial > 8192 or tag(s, element(s, 0, 2)) != 4:
        return 0
    if phase > 3 or (operation == 0 and phase != 0) or (operation == 1 and phase > 1) or (operation >= 3 and phase > 2):
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
        if task_shape(s, w, get(w, T + i * 8)) == 0:
            return 0
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
    if declared_ok(s, w, element(s, 0, 7)) == 0:
        return 0
    return continuation_ok(s, w, operation, phase)

def continuation_ok(s:readbuf, w:mutbuf, operation:u64, phase:u64) -> u64:
    receipts = element(s, 0, 8)
    outputs = element(s, 0, 9)
    helper = element(s, 0, 10)
    saved = element(s, 0, 11)
    count = 0
    if operation == 1 and phase == 1:
        count = 1
    if operation == 2 and phase > 0:
        count = choose(phase == 3, 2, 1)
    if tag(s, receipts) != 5 or total(s, receipts) != count:
        return 0
    i = 0
    while i < count:
        if unsigned(s, element(s, receipts, i)) >= get(w, S + 48):
            return 0
        i = i + 1
    needs_outputs = (operation == 2 and phase >= 2) or (operation >= 3 and phase >= 1)
    if needs_outputs:
        if declared_ok(s, w, outputs) == 0:
            return 0
    elif tag(s, outputs) != 0:
        return 0
    if operation >= 3 and phase == 2:
        if generated_index(s, helper) == 0 or generated_index(s, helper) > get(w, S):
            return 0
        if tag(s, saved) != 5 or total(s, saved) != 2:
            return 0
        if unsigned(s, element(s, saved, 0)) > get(w, S):
            return 0
        bindings = element(s, saved, 1)
        if tag(s, bindings) != 5 or total(s, bindings) > 1:
            return 0
    elif tag(s, helper) != 0 or tag(s, saved) != 0:
        return 0
    return 1

def generated_index(s:readbuf, node:u64) -> u64:
    if name_status(s, node) != 2 or size_of(s, node) < 12 or size_of(s, node) > 15:
        return 0
    i = 11
    value = 0
    while i < size_of(s, node):
        digit = byte(s, node + 16 + i)
        if digit < 48 or digit > 57 or (i == 11 and digit == 48):
            return 0
        value = value * 10 + digit - 48
        i = i + 1
    if value > 8192:
        return 0
    return value

def task_arg(s:readbuf, w:mutbuf) -> u64:
    args = element(s, 0, 6)
    if total(s, args) != 1:
        refuse(w, 6)
        return N
    arg = args + 24
    if kind_id(s, element(s, typename(s, w, arg_type(s, w, arg)), 0)) != 4:
        refuse(w, 6)
        return N
    return arg

def consume(s:readbuf, w:mutbuf, arg:u64) -> u64:
    ident = arg_id(s, arg)
    if get(w, VF + ident * 8) != 0:
        return refuse(w, 8)
    if linear(s, typename(s, w, arg_type(s, w, arg))) != 0:
        put(w, VF + ident * 8, 1)
    return 1

def check_outputs(s:readbuf, w:mutbuf, expected:u64, count:u64) -> u64:
    outputs = element(s, 0, 9)
    if total(s, outputs) != count:
        return refuse(w, 7)
    if count != 0:
        if type_equal(s, w, expected, unsigned(s, element(s, outputs + 24, 1))) == 0:
            return refuse(w, 7)
    return 1

def lower_create(s:readbuf, w:mutbuf) -> u64:
    declared = element(s, 0, 7)
    args = element(s, 0, 6)
    if total(s, declared) != 1 or total(s, args) != 1:
        return refuse(w, 4)
    out = declared + 24
    typ = unsigned(s, element(s, out, 1))
    descriptor = typename(s, w, typ)
    if kind_id(s, element(s, descriptor, 0)) != 4:
        return refuse(w, 4)
    if unsigned(s, element(s, 0, 0)) == 0:
        put(w, S + 112, typ)
        put(w, S + 56, 1)
        return 0
    if unsigned(s, element(s, element(s, 0, 8), 0)) != typ:
        put(w, S + 32, 1)
        return 0
    if type_equal(s, w, arg_type(s, w, args + 24), unsigned(s, element(s, descriptor, 3))) == 0:
        return refuse(w, 5)
    if consume(s, w, args + 24) == 0:
        return 0
    return create_value(s, w, typ, args + 24, element(s, out, 0))

def create_value(s:readbuf, w:mutbuf, typ:u64, arg:u64, name:u64) -> u64:
    descriptor = typename(s, w, typ)
    vector = allocate(w, type_width(s, descriptor) * 8)
    put(w, vector, constant(w, 7, 0))
    if get(w, S + 8) != 0:
        return 0
    put(w, vector + 8, zero(w, 13))
    if get(w, S + 8) != 0:
        return 0
    source = arg_names(s, w, arg)
    at = source + 24
    index = 2
    i = 0
    while i < total(s, source):
        put(w, vector + index * 8, at)
        at = end(s, at)
        index = index + 1
        i = i + 1
    result = flat_node(s, typename(s, w, unsigned(s, element(s, descriptor, 4))))
    at = result + 24
    i = 0
    while i < total(s, result):
        put(w, vector + index * 8, zero(w, type_id(s, at)))
        if get(w, S + 8) != 0:
            return 0
        at = end(s, at)
        index = index + 1
        i = i + 1
    return bind(w, name, typ, vector, index, 0)

def is_u8(s:readbuf, w:mutbuf, typ:u64) -> u64:
    descriptor = typename(s, w, typ)
    if kind_id(s, element(s, descriptor, 0)) != 1:
        return 0
    return choose(type_id(s, element(s, flat_node(s, descriptor), 0)) == 7, 1, 0)

def lower_state(s:readbuf, w:mutbuf, arg:u64) -> u64:
    phase = unsigned(s, element(s, 0, 0))
    if phase == 0:
        put(w, S + 56, 2)
        return 0
    receipts = element(s, 0, 8)
    expected = unsigned(s, element(s, receipts, 0))
    if is_u8(s, w, expected) == 0:
        put(w, S + 32, 1)
        return 0
    if phase == 1:
        put(w, S + 56, 3)
        return 0
    if check_outputs(s, w, expected, 1) == 0:
        return 0
    if phase == 2:
        put(w, S + 56, 2)
        return 0
    typ = unsigned(s, element(s, receipts, 1))
    if is_u8(s, w, typ) == 0:
        put(w, S + 32, 1)
        return 0
    name = element(s, element(s, 0, 9) + 24, 0)
    return bind(w, name, typ, singleton(w, element(s, arg_names(s, w, arg), 0)), 1, 0)

def expected_type(s:readbuf, w:mutbuf, typ:u64, operation:u64) -> u64:
    if operation == 6:
        return unsigned(s, element(s, typename(s, w, typ), 4))
    return typ

def lower_helper(s:readbuf, w:mutbuf, arg:u64, operation:u64) -> u64:
    phase = unsigned(s, element(s, 0, 0))
    if phase == 0:
        put(w, S + 56, 3)
        return 0
    typ = arg_type(s, w, arg)
    expected = expected_type(s, w, typ, operation)
    count = choose(operation == 7, 0, 1)
    if check_outputs(s, w, expected, count) == 0:
        return 0
    if phase == 2:
        return resume_helper(s, w, arg, expected, count)
    if consume(s, w, arg) == 0:
        return 0
    if count != 0:
        descriptor = typename(s, w, expected)
        width = type_width(s, descriptor)
        names = allocate(w, width * 8)
        i = 0
        while i < width:
            put(w, names + i * 8, fresh(w))
            if get(w, S + 8) != 0:
                return 0
            i = i + 1
        name = element(s, element(s, 0, 9) + 24, 0)
        bind(w, name, expected, names, width, 0)
    put(w, S + 112, typ)
    put(w, S + 120, operation)
    put(w, S + 56, 4)
    return 0

def prefix_names(s:readbuf, w:mutbuf, expected:u64, count:u64) -> u64:
    saved = element(s, 0, 11)
    serial = unsigned(s, element(s, saved, 0))
    bindings = element(s, saved, 1)
    if total(s, bindings) != count:
        return N
    if count == 0:
        return 0
    binding = bindings + 24
    if tag(s, binding) != 5 or total(s, binding) != 5:
        return N
    output = element(s, 0, 9) + 24
    if same_text(s, element(s, binding, 0), element(s, output, 0)) == 0:
        return N
    if unsigned(s, element(s, binding, 1)) != expected:
        return N
    if tag(s, element(s, binding, 3)) != 1 or tag(s, element(s, binding, 4)) != 1:
        return N
    if truth(s, element(s, binding, 3)) != 0 or truth(s, element(s, binding, 4)) != 0:
        return N
    names = element(s, binding, 2)
    width = type_width(s, typename(s, w, expected))
    if tag(s, names) != 5 or total(s, names) != width or serial < width:
        return N
    at = names + 24
    i = 0
    while i < width:
        if generated_index(s, at) != serial - width + i + 1:
            return N
        at = end(s, at)
        i = i + 1
    return names

def resume_helper(s:readbuf, w:mutbuf, arg:u64, expected:u64, count:u64) -> u64:
    names = prefix_names(s, w, expected, count)
    if names == N:
        put(w, S + 32, 1)
        return 0
    if linear(s, typename(s, w, arg_type(s, w, arg))) != 0 and get(w, VF + arg_id(s, arg) * 8) == 0:
        put(w, S + 32, 1)
        return 0
    output_names = 0
    output_types = 0
    width = 0
    if count != 0:
        width = total(s, names)
        output_names = copy_range(s, w, names, 0, width)
        output_types = primitive_vector(s, w, flat_node(s, typename(s, w, expected)))
    args = arg_names(s, w, arg)
    argc = total(s, args)
    arguments = copy_range(s, w, args, 0, argc)
    return instruction(w, B, 9, arguments, argc, output_names, output_types, width, element(s, 0, 10))

def primitive_vector(s:readbuf, w:mutbuf, flat:u64) -> u64:
    vector = allocate(w, total(s, flat) * 8)
    at = flat + 24
    i = 0
    while i < total(s, flat):
        put(w, vector + i * 8, type_id(s, at))
        at = end(s, at)
        i = i + 1
    return vector

def render_query(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    request = get(w, S + 56)
    if request == 0:
        emit_text(o, w, 'null')
    elif request == 2:
        emit_text(o, w, '{"type":"u8"}')
    elif request == 3:
        emit_text(o, w, '{}')
    else:
        emit_text(o, w, '{"type":')
        number(o, w, get(w, S + 112))
        if request == 4:
            emit_text(o, w, ',"operation":"')
            helper_operation_name(o, w, get(w, S + 120))
            append_byte(o, w, 34)
        append_byte(o, w, 125)
    return 0

def render(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    emit_text(o, w, '{"ops":')
    render_ops(s, o, w)
    emit_text(o, w, ',"consumed":[')
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
        emit_text(o, w, ',false,false]')
        at = get(w, at + 40)
        previous = 1
    emit_text(o, w, '],"query":')
    render_query(s, o, w)
    append_byte(o, w, 125)
    return 0
'''


def source_program():
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
    own = ast.parse(BODY)
    common = {'validate', 'word', 'put', 'get', 'tag', 'size_of', 'end', 'total',
              'element', 'text_is', 'same_text'}
    text = TRANSPORT_SOURCE.replace('    DISPATCH', '    pass').replace('1048576', '8388608')
    own.body.extend(node for node in ast.parse(text).body
                    if isinstance(node, ast.FunctionDef) and node.name in common)
    shared = {'unsigned', 'truth', 'prefix', 'name_status', 'typename', 'flat_node',
              'type_width', 'linear', 'type_equal', 'refuse', 'allocate', 'fresh',
              'singleton', 'pair', 'instruction', 'render_name', 'render_names', 'render_params'}
    own.body.extend(node for node in ast.parse(MATCH_BODY).body
                    if isinstance(node, ast.FunctionDef) and node.name in shared)
    shared = {'declared_ok', 'arg_id', 'arg_type', 'arg_names', 'number', 'constant', 'zero', 'render_ops'}
    enum = ENUM_BODY.replace("        emit_text(o, w, '}}')\n        previous = 1",
        "        if code == 9:\n            emit_text(o, w, '\"function\":')\n"
        "            source_name(s, o, w, get(w, at + 48))\n"
        "        emit_text(o, w, '}}')\n        previous = 1")
    own.body.extend(node for node in ast.parse(enum).body
                    if isinstance(node, ast.FunctionDef) and node.name in shared)
    shared = {'admit_values', 'copy_range', 'bind'}
    own.body.extend(node for node in ast.parse(RECORD_BODY).body
                    if isinstance(node, ast.FunctionDef) and node.name in shared)
    utility = {'append_byte', 'emit', 'source_name'}
    own.body.extend(node for node in ast.parse(HELPER_BODY).body
                    if isinstance(node, ast.FunctionDef) and node.name in utility)
    own = Expand().visit(own)
    suffix = []
    for function, values in [('type_id', enumerate(PRIMITIVES, 1)),
        ('kind_id', enumerate(('primitive', 'record', 'enum', 'task', 'partial_record'), 1)),
        ('operation_id', enumerate(('task.create', 'task.state', 'task.start', 'task.poll', 'task.cancel', 'task.join', 'task.close'), 1))]:
        suffix.append('def ' + function + '(s:readbuf, node:u64) -> u64:')
        for identifier, value in values:
            suffix += ['    if text_is(s, node, ' + ', '.join(map(str, packed(value))) + ') != 0:',
                       '        return ' + str(identifier)]
        suffix += ['    return 0']
    for function, values in [('type_name', enumerate(PRIMITIVES, 1)),
        ('instruction_name', [(1, 'const'), (7, 'buffer.try_new'), (8, 'chain.empty'), (9, 'call')]),
        ('helper_operation_name', enumerate(('start', 'poll', 'cancel', 'join', 'close'), 3))]:
        suffix.append('def ' + function + '(o:mutbuf, w:mutbuf, identifier:u64) -> u64:')
        for identifier, value in values:
            suffix += ['    if identifier == ' + str(identifier) + ':',
                       '        return emit(o, w, ' + ', '.join(map(str, packed(value))) + ')']
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
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8', 'module': 'task_operations', 'functions': functions})


if __name__ == '__main__':
    target = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap/task_operations.hepta'
    target.write_text(render_assembly(document()))
    print(target.name, target.stat().st_size)
