"""Author the complete composite function owner as source-bound HIA kernels.

This candidate is under construction. The renderer is a generic object codec;
it contains no nominal lowering rules and imposes no total-output byte quota.
The semantic owner must be complete before any production selector is exposed.
"""
from __future__ import annotations

import ast
from pathlib import Path
from pprint import pformat

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_core_json_frontend import packed
from tools.generate_hia_instruction_policy import SOURCE as TRANSPORT_SOURCE
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

WORKSPACE_BYTES = 192 << 20
INPUT_BYTES = 64 << 20
OUTPUT_BYTES = 64 << 10
SOURCE_BASE = 65536
ARENA_BASE = (64 << 20) + SOURCE_BASE
MAGIC = int.from_bytes(b'HIAFNC01', 'little')
STATE_MAGIC = int.from_bytes(b'HIAFNS01', 'little')
CONSTANTS = {
    'MAGIC': MAGIC, 'STATE_MAGIC': STATE_MAGIC, 'W_BYTES': WORKSPACE_BYTES,
    'I_BYTES': INPUT_BYTES, 'O_BYTES': OUTPUT_BYTES, 'SOURCE_BASE': SOURCE_BASE,
    'ARENA': ARENA_BASE, 'S': 4096, 'STACK': 8192,
    'N': (1 << 64) - 1, 'ABI': 0xfffffff1,
}

# State words: 0 magic, 8 arena cursor, 16 source size, 24 source root,
# 32 stream root, 40 stream depth, 48 stream completion, 56 stream sequence,
# 64 action, 72 fresh serial, 80 value slots, 88 request sequence,
# 96 fatal ABI flag, 104 output cursor, 112 semantic error, 120 phase.
# The renderer stack contains 128 independent 40-byte traversal frames.
# No limit below the original language ceiling is inferred from fresh/slots:
# zero-width nominal values are bounded separately by source node counts.

COMMON = r'''
def fatal(w:mutbuf) -> u64:
    put(w, S + 96, 1)
    return ABI

def word(s:readbuf, at:u64) -> u64:
    i = 0
    value = 0
    while i < 8:
        value = value | (byte(s, at + i) << (i * 8))
        i = i + 1
    return value

def put(w:mutbuf, at:u64, value:u64) -> u64:
    i = 0
    while i < 8:
        store(w, at + i, (value >> (i * 8)) & 255)
        i = i + 1
    return 0

def get(w:mutbuf, at:u64) -> u64:
    i = 0
    value = 0
    while i < 8:
        value = value | (byte(w, at + i) << (i * 8))
        i = i + 1
    return value

def allocate(w:mutbuf, size:u64) -> u64:
    cursor = get(w, S + 8)
    rounded = (size + 7) & 18446744073709551608
    if cursor < ARENA or cursor > W_BYTES or rounded > W_BYTES - cursor:
        put(w, S + 96, 1)
        return ARENA
    put(w, S + 8, cursor + rounded)
    i = 0
    while i < rounded:
        put(w, cursor + i, 0)
        i = i + 8
    return cursor

def ir_node(w:mutbuf, kind:u64, a:u64, b:u64, c:u64) -> u64:
    node = allocate(w, 32)
    put(w, node, kind)
    put(w, node + 8, a)
    put(w, node + 16, b)
    put(w, node + 24, c)
    return node

def ir_source(w:mutbuf, source:u64) -> u64:
    return ir_node(w, 0, source - SOURCE_BASE, 0, 0)

def ir_integer(w:mutbuf, value:u64) -> u64:
    return ir_node(w, 2, value, 0, 0)

def ir_bool(w:mutbuf, value:u64) -> u64:
    return ir_node(w, 3, value, 0, 0)

def ir_null(w:mutbuf) -> u64:
    return ir_node(w, 4, 0, 0, 0)

def ir_list(w:mutbuf) -> u64:
    return ir_node(w, 5, 0, 0, 0)

def ir_object(w:mutbuf) -> u64:
    return ir_node(w, 6, 0, 0, 0)

def ir_segment(w:mutbuf, target:u64, kind:u64, data:u64, count:u64) -> u64:
    if count == 0:
        return 0
    segment = allocate(w, 32)
    put(w, segment + 8, kind)
    put(w, segment + 16, data)
    put(w, segment + 24, count)
    previous = get(w, target + 16)
    if previous == 0:
        put(w, target + 8, segment)
    else:
        put(w, previous, segment)
    put(w, target + 16, segment)
    put(w, target + 24, get(w, target + 24) + count)
    return 0

def ir_append(w:mutbuf, target:u64, item:u64) -> u64:
    return ir_segment(w, target, 0, item, 1)

def ir_extend(w:mutbuf, target:u64, vector:u64, count:u64) -> u64:
    return ir_segment(w, target, 1, vector, count)

def ir_pair(w:mutbuf, target:u64, key:u64, value:u64) -> u64:
    pair = allocate(w, 24)
    put(w, pair + 8, key)
    put(w, pair + 16, value)
    previous = get(w, target + 16)
    if previous == 0:
        put(w, target + 8, pair)
    else:
        put(w, previous, pair)
    put(w, target + 16, pair)
    put(w, target + 24, get(w, target + 24) + 1)
    return 0

def ir_text(w:mutbuf, n:u64, a:u64, b:u64, c:u64) -> u64:
    data = allocate(w, n)
    i = 0
    while i < n:
        part = a
        shift = i * 8
        if i >= 8:
            part = b
            shift = (i - 8) * 8
        if i >= 16:
            part = c
            shift = (i - 16) * 8
        store(w, data + i, (part >> shift) & 255)
        i = i + 1
    return ir_node(w, 1, data, n, 0)

def ir_generated(w:mutbuf, identifier:u64) -> u64:
    data = allocate(w, 32)
    put(w, data, 7958535042260087400)
    store(w, data + 8, 97)
    store(w, data + 9, 108)
    store(w, data + 10, 95)
    divisor = 1000
    if identifier < 1000:
        divisor = 100
    if identifier < 100:
        divisor = 10
    if identifier < 10:
        divisor = 1
    at = 11
    while divisor != 0:
        digit = 0
        while identifier >= divisor:
            identifier = identifier - divisor
            digit = digit + 1
        store(w, data + at, 48 + digit)
        if divisor == 1000:
            divisor = 100
        elif divisor == 100:
            divisor = 10
        elif divisor == 10:
            divisor = 1
        else:
            divisor = 0
        at = at + 1
    return ir_node(w, 1, data, at, 0)

def stream_begin(w:mutbuf, root:u64, action:u64) -> u64:
    put(w, S + 32, root)
    put(w, S + 40, 0)
    put(w, S + 48, 0)
    put(w, S + 56, 0)
    put(w, S + 64, action)
    put(w, STACK, root)
    put(w, STACK + 8, 0)
    put(w, STACK + 16, 0)
    put(w, STACK + 24, 0)
    put(w, STACK + 32, 0)
    return 0

def stream_push(w:mutbuf, node:u64) -> u64:
    depth = get(w, S + 40)
    if depth >= 127:
        put(w, S + 96, 1)
        return 0
    depth = depth + 1
    put(w, S + 40, depth)
    frame = STACK + depth * 40
    put(w, frame, node)
    put(w, frame + 8, 0)
    put(w, frame + 16, 0)
    put(w, frame + 24, 0)
    put(w, frame + 32, 0)
    return 0

def stream_pop(w:mutbuf) -> u64:
    depth = get(w, S + 40)
    if depth == 0:
        put(w, S + 48, 1)
    else:
        put(w, S + 40, depth - 1)
    return 0

def stream_scalar(o:mutbuf, w:mutbuf, node:u64) -> u64:
    kind = get(w, node)
    at = get(w, S + 104)
    put(o, at, kind)
    if kind == 1:
        size = get(w, node + 16)
        if size > 128:
            put(w, S + 96, 1)
            return 0
        put(o, at + 8, size)
        i = 0
        while i < size:
            store(o, at + 16 + i, byte(w, get(w, node + 8) + i))
            i = i + 1
        put(w, S + 104, at + 16 + size)
    else:
        put(o, at + 8, get(w, node + 8))
        put(w, S + 104, at + 16)
    return 0

def stream_step(o:mutbuf, w:mutbuf) -> u64:
    frame = STACK + get(w, S + 40) * 40
    node = get(w, frame)
    if node < ARENA or node + 32 > get(w, S + 8):
        put(w, S + 96, 1)
        return 0
    kind = get(w, node)
    phase = get(w, frame + 8)
    if phase == 0:
        if kind < 5:
            stream_scalar(o, w, node)
            stream_pop(w)
            return 0
        if kind > 6:
            put(w, S + 96, 1)
            return 0
        at = get(w, S + 104)
        put(o, at, kind)
        put(o, at + 8, get(w, node + 24))
        put(w, S + 104, at + 16)
        put(w, frame + 8, 1)
        put(w, frame + 16, get(w, node + 8))
        put(w, frame + 24, 0)
        return 0
    item = get(w, frame + 16)
    if item == 0:
        stream_pop(w)
        return 0
    if kind == 6:
        if phase == 1:
            put(w, frame + 8, 2)
            stream_push(w, get(w, item + 8))
        else:
            put(w, frame + 8, 1)
            put(w, frame + 16, get(w, item))
            stream_push(w, get(w, item + 16))
        return 0
    index = get(w, frame + 24)
    if index == get(w, item + 24):
        put(w, frame + 16, get(w, item))
        put(w, frame + 24, 0)
        return 0
    child = get(w, item + 16)
    segment_kind = get(w, item + 8)
    if segment_kind == 1:
        child = get(w, child + index * 8)
    elif segment_kind != 0 or index != 0:
        put(w, S + 96, 1)
        return 0
    put(w, frame + 24, index + 1)
    stream_push(w, child)
    return 0
'''

RENDER = r'''
def function_render(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < W_BYTES:
        return ABI
    if length(o) < O_BYTES or get(w, S) != STATE_MAGIC:
        return fatal(w)
    if get(w, S + 96) != 0 or get(w, S + 32) == 0 or get(w, S + 48) != 0:
        return fatal(w)
    put(w, S + 104, 64)
    while get(w, S + 48) == 0 and get(w, S + 96) == 0 and get(w, S + 104) + 144 <= O_BYTES:
        stream_step(o, w)
    if get(w, S + 96) != 0:
        return fatal(w)
    put(o, 0, MAGIC)
    put(o, 8, get(w, S + 64))
    put(o, 16, get(w, S + 56))
    put(o, 24, get(w, S + 48))
    put(o, 32, get(w, S + 72))
    put(o, 40, get(w, S + 80))
    put(o, 48, get(w, S + 88))
    put(o, 56, get(w, S + 104) - 64)
    put(w, S + 56, get(w, S + 56) + 1)
    return get(w, S + 104)
'''

# A separate development-only fixture exercises complete native graph creation,
# vector expansion, multiple chunks and generated strings. It is never installed
# or included in the production bundle. The production semantic owner will call
# exactly these same arena and stream routines.
STREAM_FIXTURE = r'''
def stream_fixture(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < W_BYTES or length(o) < 64 or length(s) != 32:
        return ABI
    copies = word(s, 0)
    width = word(s, 8)
    source = word(s, 16)
    first = word(s, 24)
    if copies > 262144 or width > 512 or first > 8192:
        return ABI
    put(w, S, STATE_MAGIC)
    put(w, S + 8, ARENA)
    put(w, S + 96, 0)
    put(w, S + 72, first)
    put(w, S + 80, width)
    put(w, S + 88, 1)
    values = allocate(w, width * 8)
    i = 0
    while i < width:
        put(w, values + i * 8, ir_generated(w, first + i))
        i = i + 1
    root = ir_object(w)
    names = ir_list(w)
    i = 0
    while i < copies:
        ir_extend(w, names, values, width)
        i = i + 1
    ir_pair(w, root, ir_text(w, L_names), names)
    ir_pair(w, root, ir_text(w, L_source), ir_source(w, SOURCE_BASE + source))
    ir_pair(w, root, ir_text(w, L_null), ir_null(w))
    ir_pair(w, root, ir_text(w, L_bool), ir_bool(w, 1))
    ir_pair(w, root, ir_text(w, L_integer), ir_integer(w, 8192))
    stream_begin(w, root, 0)
    if get(w, S + 96) != 0:
        return ABI
    return 0
'''


def _expanded(source):
    from tools.generate_hia_composite_function_admission import CONSTANTS as ADMISSION_CONSTANTS, LITERALS
    from tools.generate_hia_composite_function_lowering import CONSTANTS as LOWER_CONSTANTS
    constants = {**CONSTANTS, **ADMISSION_CONSTANTS, **LOWER_CONSTANTS}
    literals = {'L_' + value: packed(value)
                for value in ('names', 'source', 'null', 'bool', 'integer')}
    literals.update({
        'L_reserved_core': packed('__hia_'),
        'L_reserved_nominal': packed('h2internal_'),
        'L_record_prefix': packed('record.'),
        'L_enum_prefix': packed('enum.'),
        'L_task_prefix': packed('task.'),
    })
    literals.update({'L_' + value.replace('.', '_'): packed(value) for value in LITERALS})

    class Expand(ast.NodeTransformer):
        def visit_Name(self, node):
            return ast.Constant(constants[node.id]) if node.id in constants else node

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

    return ast.fix_missing_locations(Expand().visit(ast.parse(source)))


def source_program(kernel):
    from tools.generate_hia_composite_function_admission import BODY as ADMISSION, suffix
    from tools.generate_hia_composite_function_lowering import (
        COMMON as LOWER_COMMON, RECORDS, CONTROLLER, ADVANCED, suffix as lower_suffix)
    from tools.generate_hia_composite_function_terms import BODY as TERMS
    validation = next(node for node in ast.parse(TRANSPORT_SOURCE.replace('    DISPATCH', '    pass')).body
                      if isinstance(node, ast.FunctionDef) and node.name == 'validate')
    validation.name = 'validate_packet'
    bodies = {'render': RENDER, 'stream_fixture': STREAM_FIXTURE,
              'admit': ADMISSION + '\n' + suffix(packed) + '\n' + ast.unparse(validation),
              'records': CONTROLLER + '\n' + RECORDS + '\n' + LOWER_COMMON + '\n'
                  + ADMISSION + '\n' + suffix(packed) + '\n' + lower_suffix(packed),
              'advanced': ADVANCED + '\n' + CONTROLLER + '\n' + LOWER_COMMON + '\n'
                  + ADMISSION + '\n' + suffix(packed) + '\n' + lower_suffix(packed),
              'terms': TERMS + '\n' + LOWER_COMMON + '\n' + ADMISSION + '\n' + suffix(packed)}
    tree = _expanded(bodies[kernel] + '\n' + COMMON)
    # Keep only reachable generic routines. The fixture and renderer are
    # distinct images; a production image never includes a test entry point.
    names = {node.name: node for node in tree.body}
    reachable = {tree.body[0].name}
    pending = list(reachable)
    while pending:
        for node in ast.walk(names[pending.pop()]):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                name = node.func.id
                if name in names and name not in reachable:
                    reachable.add(name)
                    pending.append(name)
    tree.body = [node for node in tree.body if node.name in reachable]
    return ast.unparse(tree) + '\n'


def document(kernel):
    nodes = ast.parse(source_program(kernel)).body
    names = {node.name: 'f' + str(i) for i, node in enumerate(nodes)}
    signatures = {node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id)
                  for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = Builder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(p) for p in builder.params],
            'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
            'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8',
        'module': 'composite_function_' + kernel, 'functions': functions})


if __name__ == '__main__':
    for kernel in ('admit', 'records', 'advanced', 'terms', 'render'):
        target = Path(__file__).resolve().parents[1] / ('examples/hia_bootstrap/composite_function_' + kernel + '.hepta')
        target.write_text(render_assembly(document(kernel)))
        print(target.name, target.stat().st_size)
    from tools.generate_hia_composite_function_admission import ERRORS as ADMISSION_ERRORS
    from tools.generate_hia_composite_function_lowering import ERRORS as LOWER_ERRORS
    from tools.generate_hia_composite_function_terms import ERRORS as TERM_ERRORS
    target = Path(__file__).resolve().parents[1] / 'hepta/hia_composite_functions_errors.py'
    target.write_text('"""Generated diagnostic ABI data; all rejection decisions are HIA-owned."""\n'
        + 'ERRORS = ' + pformat(dict(sorted({**ADMISSION_ERRORS, **LOWER_ERRORS, **TERM_ERRORS}.items())), width=100) + '\n')
