"""Author complete enum.make/enum.tag lowering, effects and continuations in HIA."""
from __future__ import annotations

import ast
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_core_json_frontend import packed
from tools.generate_hia_instruction_policy import SOURCE as TRANSPORT_SOURCE
from tools.generate_hia_enum_match import BODY as MATCH_BODY
from tools.generate_hia_task_helpers import BODY as HELPER_BODY, PRIMITIVES
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

MAGIC = int.from_bytes(b'HIAEOP01', 'little')
INPUT_BYTES = 256 << 20
OUTPUT_BYTES = 8 << 20
WORKSPACE_BYTES = 16 << 20
CONSTANTS = {'MAGIC': MAGIC, 'INPUT_BYTES': INPUT_BYTES, 'O_BYTES': OUTPUT_BYTES,
    'W_BYTES': WORKSPACE_BYTES, 'S': 4096, 'T': 8192, 'V': 2105344,
    'VF': 4202496, 'B': 6299648, 'HEAP': 6303744,
    'G': 1 << 63, 'N': (1 << 64) - 1, 'ABI': 0xfffffff1}

BODY = r'''
def enum_operations(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) > INPUT_BYTES or length(o) < O_BYTES or length(w) < W_BYTES:
        return ABI
    if validate(s, w) == 0 or tag(s, 0) != 5 or total(s, 0) != 11:
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
    operation = element(s, 0, 2)
    if text_is(s, operation, L_make) != 0:
        lower_make(s, w)
    else:
        lower_tag(s, w)
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

def declared_ok(s:readbuf, w:mutbuf, node:u64) -> u64:
    if tag(s, node) != 5 or total(s, node) > 262144:
        return 0
    at = node + 24
    i = 0
    while i < total(s, node):
        if tag(s, at) != 5 or total(s, at) != 2:
            return 0
        if name_status(s, element(s, at, 0)) != 0:
            return 0
        if unsigned(s, element(s, at, 1)) >= get(w, S + 48):
            return 0
        at = end(s, at)
        i = i + 1
    return 1

def admit(s:readbuf, w:mutbuf) -> u64:
    phase = unsigned(s, element(s, 0, 0))
    serial = unsigned(s, element(s, 0, 1))
    operation = element(s, 0, 2)
    if phase > 2 or serial > 8192:
        return 0
    if text_is(s, operation, L_make) == 0 and text_is(s, operation, L_tag) == 0:
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
        if tag(s, node) != 5 or total(s, node) != 4:
            return 0
        kind = kind_id(s, element(s, node, 0))
        flat = flat_node(s, node)
        variants = element(s, node, 3)
        if kind == 0 or tag(s, flat) != 5 or total(s, flat) > 512:
            return 0
        if tag(s, element(s, node, 2)) != 1 or tag(s, variants) != 5 or total(s, variants) > 32:
            return 0
        if kind == 1 and total(s, flat) != 1:
            return 0
        if kind == 3 and total(s, variants) == 0:
            return 0
        if kind != 3 and total(s, variants) != 0:
            return 0
        at = flat + 24
        j = 0
        while j < total(s, flat):
            if type_id(s, at) == 0:
                return 0
            at = end(s, at)
            j = j + 1
        variant = variants + 24
        j = 0
        while j < total(s, variants):
            if tag(s, variant) != 5 or total(s, variant) != 2:
                return 0
            if name_status(s, element(s, variant, 0)) != 0:
                return 0
            fields = element(s, variant, 1)
            if tag(s, fields) != 5 or total(s, fields) > 64:
                return 0
            at = fields + 24
            k = 0
            while k < total(s, fields):
                if unsigned(s, at) >= tc:
                    return 0
                at = end(s, at)
                k = k + 1
            variant = end(s, variant)
            j = j + 1
        node = end(s, node)
        i = i + 1
    i = 0
    while i < tc:
        descriptor = get(w, T + i * 8)
        if kind_id(s, element(s, descriptor, 0)) == 3:
            if enum_shape(s, w, descriptor) == 0:
                return 0
        i = i + 1
    node = values + 24
    slots = 0
    i = 0
    while i < vc:
        if tag(s, node) != 5 or total(s, node) != 4:
            return 0
        ident = unsigned(s, element(s, node, 0))
        names = element(s, node, 1)
        if ident >= tc or tag(s, names) != 5:
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
    expected = element(s, 0, 8)
    outputs = element(s, 0, 9)
    bound = element(s, 0, 10)
    if phase == 0:
        if tag(s, expected) != 0 or tag(s, outputs) != 0 or tag(s, bound) != 0:
            return 0
    else:
        if unsigned(s, expected) >= tc or declared_ok(s, w, outputs) == 0:
            return 0
        if phase == 1 and tag(s, bound) != 0:
            return 0
        if phase == 2 and unsigned(s, bound) >= tc:
            return 0
    return 1

def arg_id(s:readbuf, arg:u64) -> u64:
    return unsigned(s, element(s, arg, 1))

def arg_type(s:readbuf, w:mutbuf, arg:u64) -> u64:
    return unsigned(s, element(s, get(w, V + arg_id(s, arg) * 8), 0))

def arg_names(s:readbuf, w:mutbuf, arg:u64) -> u64:
    return element(s, get(w, V + arg_id(s, arg) * 8), 1)

def lower_make(s:readbuf, w:mutbuf) -> u64:
    attrs = element(s, 0, 3)
    if tag(s, attrs) != 6 or total(s, attrs) != 1:
        return refuse(w, 3)
    if text_is(s, attrs + 24, L_variant) == 0:
        return refuse(w, 3)
    declared = element(s, 0, 7)
    if total(s, declared) != 1:
        return refuse(w, 4)
    output = declared + 24
    ident = unsigned(s, element(s, output, 1))
    descriptor = typename(s, w, ident)
    if kind_id(s, element(s, descriptor, 0)) != 3:
        return refuse(w, 4)
    selected_name = end(s, attrs + 24)
    if name_check(s, w, selected_name, 5) == 0:
        return 0
    variants = element(s, descriptor, 3)
    selected = N
    index = 0
    variant = variants + 24
    i = 0
    while i < total(s, variants):
        if same_text(s, selected_name, element(s, variant, 0)) != 0:
            selected = variant
            index = i
        variant = end(s, variant)
        i = i + 1
    if selected == N:
        return refuse(w, 7)
    fields = element(s, selected, 1)
    args = element(s, 0, 6)
    if total(s, args) != total(s, fields):
        return refuse(w, 7)
    arg = args + 24
    field_node = fields + 24
    i = 0
    while i < total(s, args):
        if type_equal(s, w, arg_type(s, w, arg), unsigned(s, field_node)) == 0:
            return refuse(w, 7)
        arg = end(s, arg)
        field_node = end(s, field_node)
        i = i + 1
    arg = args + 24
    i = 0
    while i < total(s, args):
        value_id = arg_id(s, arg)
        if get(w, VF + value_id * 8) != 0:
            return refuse(w, 8)
        if linear(s, typename(s, w, arg_type(s, w, arg))) != 0:
            put(w, VF + value_id * 8, 1)
        arg = end(s, arg)
        i = i + 1
    tag_name = constant(w, 9, index)
    if get(w, S + 8) != 0:
        return 0
    flat = allocate(w, type_width(s, descriptor) * 8)
    put(w, flat, tag_name)
    cursor = 1
    variant = variants + 24
    i = 0
    while i < total(s, variants):
        if variant == selected:
            arg = args + 24
            j = 0
            while j < total(s, args):
                names = arg_names(s, w, arg)
                at = names + 24
                k = 0
                while k < total(s, names):
                    put(w, flat + cursor * 8, at)
                    cursor = cursor + 1
                    at = end(s, at)
                    k = k + 1
                arg = end(s, arg)
                j = j + 1
        else:
            fields = element(s, variant, 1)
            cursor = pad_fields(s, w, fields, flat, cursor)
            if get(w, S + 8) != 0:
                return 0
        variant = end(s, variant)
        i = i + 1
    put(w, S + 64, ident)
    put(w, S + 72, element(s, output, 0))
    put(w, S + 80, flat)
    put(w, S + 88, cursor)
    put(w, S + 96, 1)
    return 0

def pad_fields(s:readbuf, w:mutbuf, fields:u64, flat:u64, cursor:u64) -> u64:
    field_node = fields + 24
    j = 0
    while j < total(s, fields):
        types = flat_node(s, typename(s, w, unsigned(s, field_node)))
        typ = types + 24
        k = 0
        while k < total(s, types):
            name = zero(w, type_id(s, typ))
            if get(w, S + 8) != 0:
                return cursor
            put(w, flat + cursor * 8, name)
            cursor = cursor + 1
            typ = end(s, typ)
            k = k + 1
        field_node = end(s, field_node)
        j = j + 1
    return cursor

def is_u32(s:readbuf, w:mutbuf, ident:u64) -> u64:
    descriptor = typename(s, w, ident)
    if kind_id(s, element(s, descriptor, 0)) != 1:
        return 0
    return choose(type_id(s, element(s, flat_node(s, descriptor), 0)) == 9, 1, 0)

def lower_tag(s:readbuf, w:mutbuf) -> u64:
    attrs = element(s, 0, 3)
    if tag(s, attrs) != 6 or total(s, attrs) != 0:
        return refuse(w, 9)
    args = element(s, 0, 6)
    if total(s, args) != 1:
        return refuse(w, 10)
    arg = args + 24
    descriptor = typename(s, w, arg_type(s, w, arg))
    if kind_id(s, element(s, descriptor, 0)) != 3:
        return refuse(w, 10)
    phase = unsigned(s, element(s, 0, 0))
    if phase == 0:
        put(w, S + 56, 1)
        return 0
    expected = unsigned(s, element(s, 0, 8))
    if is_u32(s, w, expected) == 0:
        put(w, S + 32, 1)
        return 0
    declared = element(s, 0, 9)
    if total(s, declared) != 1:
        return refuse(w, 11)
    out = declared + 24
    if type_equal(s, w, unsigned(s, element(s, out, 1)), expected) == 0:
        return refuse(w, 11)
    if phase == 1:
        put(w, S + 56, 2)
        return 0
    bound = unsigned(s, element(s, 0, 10))
    if is_u32(s, w, bound) == 0:
        put(w, S + 32, 1)
        return 0
    put(w, S + 64, bound)
    put(w, S + 72, element(s, out, 0))
    put(w, S + 80, singleton(w, element(s, arg_names(s, w, arg), 0)))
    put(w, S + 88, 1)
    put(w, S + 96, 1)
    return 0

def constant(w:mutbuf, typ:u64, value:u64) -> u64:
    ident = fresh(w)
    if get(w, S + 8) != 0:
        return 0
    instruction(w, B, 1, 0, 0, singleton(w, ident), singleton(w, typ), 1, value)
    return ident

def zero(w:mutbuf, typ:u64) -> u64:
    if typ == 13:
        zero_value = constant(w, 12, 0)
        if get(w, S + 8) != 0:
            return 0
        owner = fresh(w)
        if get(w, S + 8) != 0:
            return 0
        ok = fresh(w)
        if get(w, S + 8) != 0:
            return 0
        instruction(w, B, 7, singleton(w, zero_value), 1, pair(w, owner, ok), pair(w, 13, 1), 2, 0)
        return owner
    if typ == 16:
        owner = fresh(w)
        if get(w, S + 8) != 0:
            return 0
        instruction(w, B, 8, 0, 0, singleton(w, owner), singleton(w, 16), 1, 0)
        return owner
    if typ == 14 or typ == 15:
        return refuse(w, 2)
    return constant(w, typ, 0)

def number(o:mutbuf, w:mutbuf, value:u64) -> u64:
    divisor = 1000000
    started = 0
    while divisor != 0:
        digit = 0
        while value >= divisor:
            value = value - divisor
            digit = digit + 1
        if digit != 0 or started != 0 or divisor == 1:
            append_byte(o, w, digit + 48)
            started = 1
        if divisor == 1000000:
            divisor = 100000
        elif divisor == 100000:
            divisor = 10000
        elif divisor == 10000:
            divisor = 1000
        elif divisor == 1000:
            divisor = 100
        elif divisor == 100:
            divisor = 10
        elif divisor == 10:
            divisor = 1
        else:
            divisor = 0
    return 0

def render_ops(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    append_byte(o, w, 91)
    at = get(w, B + 32)
    previous = 0
    while at != 0:
        if previous != 0:
            append_byte(o, w, 44)
        code = get(w, at)
        emit_text(o, w, '{"op":"')
        instruction_name(o, w, code)
        emit_text(o, w, '","args":')
        render_names(s, o, w, get(w, at + 8), get(w, at + 16))
        emit_text(o, w, ',"out":')
        render_params(s, o, w, get(w, at + 24), get(w, at + 32), get(w, at + 40))
        emit_text(o, w, ',"attrs":{')
        if code == 1:
            emit_text(o, w, '"value":')
            typ = get(w, get(w, at + 32))
            if typ == 1:
                emit_text(o, w, 'false')
            elif typ == 2:
                emit_text(o, w, 'null')
            else:
                number(o, w, get(w, at + 48))
        emit_text(o, w, '}}')
        previous = 1
        at = get(w, at + 56)
    append_byte(o, w, 93)
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
    if get(w, S + 96) != 0:
        append_byte(o, w, 91)
        source_name(s, o, w, get(w, S + 72))
        append_byte(o, w, 44)
        number(o, w, get(w, S + 64))
        append_byte(o, w, 44)
        render_names(s, o, w, get(w, S + 80), get(w, S + 88))
        emit_text(o, w, ',false,false]')
    emit_text(o, w, ']}')
    return 0
'''


def source_program():
    literals = {'L_' + name: packed(value) for name, value in
                [('make', 'enum.make'), ('tag', 'enum.tag'), ('variant', 'variant')]}
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
              'flat_node', 'type_width', 'linear', 'type_equal', 'enum_shape',
              'refuse', 'fresh', 'allocate', 'singleton', 'pair', 'instruction',
              'render_name', 'render_names', 'render_params'}
    own.body.extend(node for node in ast.parse(MATCH_BODY).body
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
    for function, values in [('type_name', enumerate(PRIMITIVES, 1)),
        ('instruction_name', [(1, 'const'), (7, 'buffer.try_new'), (8, 'chain.empty')])]:
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
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8', 'module': 'enum_operations', 'functions': functions})


if __name__ == '__main__':
    target = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap/enum_operations.hiaasm'
    target.write_text(render_assembly(document()))
    print(target.name, target.stat().st_size)
