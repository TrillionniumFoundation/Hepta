"""Author a real-array, no-key HIA PowerSort component for CLI JSON.

This is an isolated development source.  It is not installed, selected by the
CLI, generated, or executed merely by importing this file.  The old 078d job
identity is never read or replayed.  Its frozen authoring source is the basis
of the explicit, separately retained algorithm/error-continuation delta.
"""
from __future__ import annotations

import ast
from pathlib import Path

from tools.hia_cli_json_continuation import (
    FRAME_BYTES, FRAME_POINTER, PHASE_BASE, PHASE_STRIDE,
    emit_routine, routines, signature_node,
)
from tools.hia_cli_json_sort_algorithm import ALGORITHM_SOURCE, PURE_SOURCE
from tools.hia_cli_json_sort_comparison import COMPARISON_SOURCE

SYMBOLS = {
    'MAGIC': int.from_bytes(b'HCLISRT1', 'little'),
    'ABI': 0xfffffffd, 'ERROR': 0xffffffffffffffff,
    'STATE_BYTES': 20480, 'TEMP_BASE': 20480, 'ORIGINAL_BASE': 1 << 63,
    'PHASE': 8, 'SEQUENCE': 16, 'PENDING': 24,
    'REPLY_SEQUENCE': 32, 'REPLY_OPERATION': 40, 'REPLY_ERROR': 48,
    'ABORT': 56, 'OPERATION': 64, 'ARGUMENTS': 72,
    'FINAL_STATUS': 112, 'ROOT_OBJECT': 120, 'PROFILE': 128,
    'ANSWER': 160, 'SORT_N': 256, 'SORT_ARRAY': 264, 'SORT_TMP': 272,
    'TS_COUNT': 280, 'TS_MIN_GALLOP': 288, 'TS_RUN_VERSION': 296,
    'TS_TUPLES': 304, 'TS_COMPARE_MODE': 312, 'TS_CACHED_SLOT': 320,
    'TUPLE_TYPE': 336, 'VALUE_ERROR_TYPE': 344, 'TEMP_CAPACITY': 360,
    'MERGE_KIND': 368, 'MERGE_FROM': 376, 'MERGE_TO': 384, 'MERGE_COUNT': 392,
    'ERROR_TEXT_OFFSET': 416, 'CONTEXT_SLOT': 448, 'CONTEXT_PHASE': 456,
    'DISPLACED_COUNT': 464, 'TS_FRAME': FRAME_POINTER,
}

SOURCE = r'''
def cli_json_sort(s:mutbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) != STATE_BYTES:
        return ABI
    if get(w, 0) != MAGIC:
        return ABI
    if get(w, FINAL_STATUS) != 0:
        return ABI
    if get(w, ABORT) != 0:
        put(w, ABORT, 0)
        put(w, PENDING, 0)
        put(w, TS_FRAME, 4096)
        put(w, 4096 + CLEANUP_ARGUMENT, ERROR)
        put(w, 4096 + CLEANUP_RETURN, 901)
        put(w, PHASE, CLEANUP_ENTRY)
    elif get(w, PENDING) != 0:
        if get(w, REPLY_SEQUENCE) != get(w, SEQUENCE) or get(w, REPLY_OPERATION) != get(w, OPERATION):
            return ABI
        put(w, PENDING, 0)
    elif get(w, PHASE) != 0:
        return ABI
    if get(w, PHASE) == 0:
        if get(w, ROOT_OBJECT) == 0:
            return ABI
        put(w, TS_FRAME, 4096)
        put(w, 4096 + SORT_ARGUMENT, get(w, ROOT_OBJECT))
        put(w, 4096 + SORT_RETURN, 900)
        put(w, PHASE, SORT_ENTRY)
    while True:
        phase = get(w, PHASE)
        if phase == 900 or phase == 901:
            result = choose(phase == 900, get(w, 4096 + SORT_RESULT), get(w, 4096 + CLEANUP_RESULT))
            status = choose(result == 0 and get(w, REPLY_ERROR) == 0, 0, 1)
            put(w, FINAL_STATUS, status + 1)
            return status
        status = dispatch(s, o, w, phase)
        if status != 4:
            return status
    return ABI

def request(w:mutbuf, operation:u64, a:u64, b:u64, c:u64, d:u64, phase:u64) -> u64:
    if get(w, PENDING) != 0 or get(w, SEQUENCE) == ERROR:
        return ABI
    put(w, SEQUENCE, get(w, SEQUENCE) + 1)
    put(w, OPERATION, operation)
    put(w, ARGUMENTS, a)
    put(w, ARGUMENTS + 8, b)
    put(w, ARGUMENTS + 16, c)
    put(w, ARGUMENTS + 24, d)
    put(w, PHASE, phase)
    put(w, PENDING, 1)
    return 2

def answer(w:mutbuf, index:u64) -> u64:
    return get(w, ANSWER + index * 8)

def mutation_message(w:mutbuf) -> u64:
    put(w, ERROR_TEXT_OFFSET, MESSAGE0)
    put(w, ERROR_TEXT_OFFSET + 8, MESSAGE1)
    put(w, ERROR_TEXT_OFFSET + 16, MESSAGE2)
    put(w, ERROR_TEXT_OFFSET + 24, MESSAGE3)
    return 0

def binary64_less(left:u64, right:u64) -> u64:
    left_magnitude = left & 9223372036854775807
    right_magnitude = right & 9223372036854775807
    if left_magnitude > 9218868437227405312 or right_magnitude > 9218868437227405312:
        return 0
    if left_magnitude == 0 and right_magnitude == 0:
        return 0
    left_negative = left >> 63
    right_negative = right >> 63
    if left_negative != right_negative:
        return left_negative
    if left_negative != 0:
        return choose(left_magnitude > right_magnitude, 1, 0)
    return choose(left_magnitude < right_magnitude, 1, 0)

def routed_get(s:mutbuf, o:mutbuf, w:mutbuf, address:u64) -> u64:
    if address >= ORIGINAL_BASE:
        return get(o, address - ORIGINAL_BASE)
    if address >= TEMP_BASE:
        return get(s, address - TEMP_BASE)
    return get(w, address)

def routed_put(s:mutbuf, o:mutbuf, w:mutbuf, address:u64, value:u64) -> u64:
    if address >= ORIGINAL_BASE:
        return put(o, address - ORIGINAL_BASE, value)
    if address >= TEMP_BASE:
        return put(s, address - TEMP_BASE, value)
    return put(w, address, value)

def routed_copy(s:mutbuf, o:mutbuf, w:mutbuf, destination:u64, source:u64, count:u64) -> u64:
    if destination >= ORIGINAL_BASE:
        if source >= ORIGINAL_BASE:
            copy_span(o, destination - ORIGINAL_BASE, o, source - ORIGINAL_BASE, count)
        elif source >= TEMP_BASE:
            copy_span(o, destination - ORIGINAL_BASE, s, source - TEMP_BASE, count)
        else:
            copy_span(o, destination - ORIGINAL_BASE, w, source, count)
    elif destination >= TEMP_BASE:
        if source >= ORIGINAL_BASE:
            copy_span(s, destination - TEMP_BASE, o, source - ORIGINAL_BASE, count)
        elif source >= TEMP_BASE:
            copy_span(s, destination - TEMP_BASE, s, source - TEMP_BASE, count)
        else:
            copy_span(s, destination - TEMP_BASE, w, source, count)
    else:
        if source >= ORIGINAL_BASE:
            copy_span(w, destination, o, source - ORIGINAL_BASE, count)
        elif source >= TEMP_BASE:
            copy_span(w, destination, s, source - TEMP_BASE, count)
        else:
            copy_span(w, destination, w, source, count)
    return 0

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


def _routed(text, *, pure=False):
    """Mechanical buffer relocation; not a Python sorting implementation."""
    parsed = ast.parse(text)
    buffer_functions = {'ts_at', 'ts_move', 'ts_reverse', 'ts_pending'}

    class Route(ast.NodeTransformer):
        def visit_FunctionDef(self, node):
            if pure and node.name in buffer_functions:
                node.args.args[0:0] = [ast.arg('s', ast.Name('mutbuf', ast.Load())),
                                      ast.arg('o', ast.Name('mutbuf', ast.Load()))]
            return self.generic_visit(node)

        def visit_Call(self, node):
            node = self.generic_visit(node)
            if not isinstance(node.func, ast.Name):
                return node
            name = node.func.id
            buffers = [ast.Name(value, ast.Load()) for value in ('s', 'o', 'w')]
            if name in ('get', 'put'):
                if not isinstance(node.args[0], ast.Name) or node.args[0].id != 'w':
                    raise ValueError('unexpected old sort buffer')
                node.func.id = 'routed_' + name
                node.args = buffers + node.args[1:]
            elif name == 'copy_work':
                if len(node.args) != 5 or any(not isinstance(node.args[i], ast.Name) or node.args[i].id != 'w' for i in (0, 2)):
                    raise ValueError('unexpected old sort copy')
                node.func.id = 'routed_copy'
                node.args = buffers + [node.args[1], node.args[3], node.args[4]]
            elif name in buffer_functions:
                node.args = [ast.Name('s', ast.Load()), ast.Name('o', ast.Load())] + node.args
            return node

    return ast.unparse(ast.fix_missing_locations(Route().visit(parsed))) + '\n'


def _expand(text, extra=None):
    values = dict(SYMBOLS)
    if extra:
        values.update(extra)
    message = b'list modified during sort\0'.ljust(32, b'\0')
    values.update({'MESSAGE' + str(index): int.from_bytes(message[index * 8:index * 8 + 8], 'little')
                   for index in range(4)})

    class Constants(ast.NodeTransformer):
        def visit_Name(self, node):
            if node.id in values:
                return ast.copy_location(ast.Constant(values[node.id]), node)
            return node

    return ast.unparse(ast.fix_missing_locations(Constants().visit(ast.parse(text)))) + '\n'


def _continuations():
    return routines(_expand(COMPARISON_SOURCE + '\n' + _routed(ALGORITHM_SOURCE)))


def source_program():
    compiled, _ = _continuations()
    by_name = {item.name: item for item in compiled}
    start, cleanup = by_name['ts_sort'], by_name['ts_cleanup']
    dispatch = ['def dispatch(s:mutbuf, o:mutbuf, w:mutbuf, phase:u64) -> u64:']
    for item in compiled:
        dispatch += [f'    if phase >= {item.phase_base} and phase < {item.phase_base + PHASE_STRIDE}:',
                     f'        return {item.name}(s, o, w)']
    dispatch += ['    return ABI']
    additions = {
        'SORT_ARGUMENT': start.slots['object'], 'SORT_RETURN': start.continuation,
        'SORT_RESULT': start.result, 'SORT_ENTRY': start.phase_base + start.entry,
        'CLEANUP_ARGUMENT': cleanup.slots['result'], 'CLEANUP_RETURN': cleanup.continuation,
        'CLEANUP_RESULT': cleanup.result, 'CLEANUP_ENTRY': cleanup.phase_base + cleanup.entry,
    }
    return _expand(SOURCE + '\n' + _routed(PURE_SOURCE, pure=True) + '\n' + '\n'.join(dispatch), additions)


def document():
    from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

    class SortBuilder(Builder):
        def expr(self, node):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'copy_span':
                if len(node.args) != 5 or node.keywords:
                    raise ValueError('copy_span arity')
                args = [self.expr(value) for value in node.args]
                if ast.dump(node.args[0]) == ast.dump(node.args[2]):
                    return self.op('buffer.move_within', [args[0], self.cast(args[1], 'usize'),
                                   self.cast(args[3], 'usize'), self.cast(args[4], 'usize')])
                # A cross-buffer source remains a mutbuf parameter.  Borrow an
                # actual readbuf for this one copy, then end its local loan
                # before any later source mutation or call.  The same-buffer
                # path above uses move_within and creates no loan.
                destination_at = self.cast(args[1], 'usize')
                source_at = self.cast(args[3], 'usize')
                count = self.cast(args[4], 'usize')
                source_view = self.op('borrow.read', [args[2]], 'readbuf')
                result = self.op('buffer.copy_range', [args[0], source_view,
                                 destination_at, source_at, count])
                self.op('loan.end', [source_view])
                return result
            return super().expr(node)

    nodes = ast.parse(source_program()).body
    compiled, local_bytes = _continuations()
    if FRAME_POINTER != 3264 or FRAME_BYTES != 16384 or local_bytes > 4096:
        raise ValueError('sort continuation frame differs')
    declarations = nodes + [signature_node(item.name) for item in compiled]
    names = {node.name: 'f' + str(index) for index, node in enumerate(declarations)}
    if len(names) != len(declarations):
        raise ValueError('duplicate JSON sort function')
    signatures = {node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id)
                  for node in declarations}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = SortBuilder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(p) for p in builder.params],
                          'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
                          'entry': 'b0', 'blocks': builder.blocks})
    for item in compiled:
        functions.append(emit_routine(item, compiled, names, signatures, SortBuilder))
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8',
                                  'module': 'cli_json_items_sort', 'functions': functions})


if __name__ == '__main__':
    import argparse
    from hepta.hia_agent_assembly import render_assembly
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    with args.output.open('x') as stream:
        stream.write(render_assembly(document()))
