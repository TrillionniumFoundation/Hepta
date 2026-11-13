"""HIA continuation for the Python-profile deferred chunk collection.

This owns list-construction iteration and cleanup, not a string builder.
Every yielded object, including a non-str, is retained unchanged.  The
encoding frame performs its final join only after this continuation returns
the complete list.  No early string check or C-profile string error is used.

An ordinary foreign iterator uses its original cached tp_iternext.  A known
HIA-owned JSON generator must instead use operation 230, whose separately
bound dispatcher resumes that generator's HIA continuation.  That full
generator dispatcher/frame activation is not supplied or qualified here.
The default CLI and the original 17/46 populations are unchanged.
"""
from __future__ import annotations

import ast
from pathlib import Path

SYMBOLS = {
    'MAGIC': int.from_bytes(b'HCLIJCH1', 'little'),
    'ABI': 4294967293, 'MAX_SIZE': 9223372036854775807,
    'PHASE': 8, 'SEQUENCE': 16, 'PENDING': 24,
    'REPLY_SEQUENCE': 32, 'REPLY_OPERATION': 40, 'RAISED': 48,
    'ABORT': 56, 'OPERATION': 64, 'ARGUMENTS': 72, 'FINAL': 112,
    'ITERABLE': 120, 'HIA_GENERATOR': 128, 'LIST': 136,
    'ITERATOR': 144, 'NEXT': 152, 'CHECK_CELL': 160,
    'ANSWER': 256, 'SLOT': 320,
}

SOURCE = r'''
def cli_json_py312_chunks(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) != 512 or get(w, 0) != MAGIC or get(w, FINAL) != 0:
        return ABI
    if get(w, ABORT) != 0:
        put(w, ABORT, 0)
        put(w, PENDING, 0)
        put(w, PHASE, 900)
    elif get(w, PENDING) != 0:
        if get(w, REPLY_SEQUENCE) != get(w, SEQUENCE) or get(w, REPLY_OPERATION) != get(w, OPERATION):
            return ABI
        put(w, PENDING, 0)
    elif get(w, PHASE) != 0:
        return ABI
    if get(w, PHASE) == 0:
        if get(w, ITERABLE) == 0 or get(w, HIA_GENERATOR) > 1 or get(w, SLOT) != 0 or get(w, RAISED) != 0:
            return ABI
        put(w, CHECK_CELL, 0)
        put(w, PHASE, 1)
    while True:
        phase = get(w, PHASE)
        if phase < 100:
            status = setup(w, phase)
        elif phase < 200:
            status = collect(w, phase)
        elif phase < 900:
            status = complete(w, phase)
        else:
            status = unwind(w, phase)
        if status != 4:
            return status
    return ABI

def setup(w:mutbuf, phase:u64) -> u64:
    if phase == 1:
        return request(w, 46, get(w, CHECK_CELL), 0, 0, 0, 0, 2)
    if phase == 2:
        if answer(w, 0) != 0:
            return ABI
        cell = get(w, CHECK_CELL) + 1
        put(w, CHECK_CELL, cell)
        if cell < 8:
            put(w, PHASE, 1)
            return 4
        # list_vectorcall allocates its empty list before list_extend.
        return request(w, 51, 0, 0, 0, 0, 0, 3)
    if phase == 3:
        if get(w, SLOT) == 0:
            return failed(w)
        return request(w, 44, 0, 0, 0, 0, 0, 4)
    if phase == 4:
        put(w, LIST, answer(w, 0))
        return request(w, 22, get(w, ITERABLE), 0, 0, 0, 0, 5)
    if phase == 5:
        if get(w, SLOT) == 0:
            return failed(w)
        put(w, NEXT, answer(w, 1))
        if get(w, NEXT) == 0:
            return ABI
        return request(w, 44, 1, 0, 0, 0, 0, 6)
    if phase == 6:
        put(w, ITERATOR, answer(w, 0))
        return request(w, 90, get(w, ITERABLE), 8, 0, 0, 0, 7)
    if phase == 7:
        if get(w, RAISED) != 0:
            return failed(w)
        hint = answer(w, 0)
        if hint > MAX_SIZE:
            return ABI
        if hint != 0:
            return request(w, 88, get(w, LIST), hint, 0, 0, 0, 8)
        put(w, PHASE, 100)
        return 4
    if phase == 8:
        if get(w, RAISED) != 0:
            return failed(w)
        if answer(w, 0) != 0:
            return ABI
        put(w, PHASE, 100)
        return 4
    return ABI

def collect(w:mutbuf, phase:u64) -> u64:
    if phase == 100:
        operation = choose(get(w, HIA_GENERATOR) == 1, 230, 91)
        return request(w, operation, get(w, ITERATOR), get(w, NEXT), 0, 0, 0, 101)
    if phase == 101:
        if get(w, SLOT) != 0:
            if get(w, RAISED) != 0:
                return ABI
            # No string-kind observation is made before or during append.
            return request(w, 87, get(w, LIST), 0, 0, 0, 0, 102)
        if get(w, RAISED) != 0:
            return request(w, 92, 0, 0, 0, 0, 0, 103)
        put(w, PHASE, 200)
        return 4
    if phase == 102:
        if get(w, RAISED) != 0:
            return failed(w)
        if answer(w, 0) != 0 or get(w, SLOT) != 0:
            return ABI
        put(w, PHASE, 100)
        return 4
    if phase == 103:
        if answer(w, 0) == 0:
            return failed(w)
        if answer(w, 0) != 1 or get(w, RAISED) != 0:
            return ABI
        put(w, PHASE, 200)
        return 4
    return ABI

def complete(w:mutbuf, phase:u64) -> u64:
    if phase == 200:
        return request(w, 26, get(w, LIST), 1, 0, 0, 0, 201)
    if phase == 201:
        if answer(w, 0) < answer(w, 1):
            return request(w, 89, get(w, LIST), 0, 0, 0, 0, 202)
        put(w, PHASE, 202)
        return 4
    if phase == 202:
        if get(w, RAISED) != 0:
            return failed(w)
        return request(w, 45, 1, 0, 0, 0, 0, 203)
    if phase == 203:
        return request(w, 93, 0, 0, 0, 0, 0, 204)
    if phase == 204:
        if get(w, SLOT) == 0 or get(w, RAISED) != 0:
            return ABI
        put(w, FINAL, 1)
        return 0
    return ABI

def unwind(w:mutbuf, phase:u64) -> u64:
    if phase == 900:
        if get(w, SLOT) != 0:
            return request(w, 6, 0, 0, 0, 0, 0, 901)
        put(w, PHASE, 901)
        return 4
    if phase == 901:
        return request(w, 46, 1, 0, 0, 0, 0, 902)
    if phase == 902:
        if answer(w, 0) != 0:
            return request(w, 45, 1, 0, 0, 0, 0, 903)
        put(w, PHASE, 903)
        return 4
    if phase == 903:
        return request(w, 46, 0, 0, 0, 0, 0, 904)
    if phase == 904:
        if answer(w, 0) != 0:
            return request(w, 45, 0, 0, 0, 0, 0, 905)
        put(w, PHASE, 905)
        return 4
    if phase == 905:
        if get(w, SLOT) != 0 or get(w, RAISED) == 0:
            return ABI
        put(w, FINAL, 2)
        return 1
    return ABI

def failed(w:mutbuf) -> u64:
    put(w, PHASE, 900)
    return 4

def request(w:mutbuf, operation:u64, a:u64, b:u64, c:u64, d:u64, e:u64, following:u64) -> u64:
    sequence = get(w, SEQUENCE)
    if sequence == 18446744073709551615:
        return ABI
    put(w, SEQUENCE, sequence + 1)
    put(w, PENDING, 1)
    put(w, OPERATION, operation)
    put(w, ARGUMENTS, a)
    put(w, ARGUMENTS + 8, b)
    put(w, ARGUMENTS + 16, c)
    put(w, ARGUMENTS + 24, d)
    put(w, ARGUMENTS + 32, e)
    put(w, PHASE, following)
    return 2

def answer(w:mutbuf, index:u64) -> u64:
    return get(w, ANSWER + index * 8)

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


def source_program():
    class Constants(ast.NodeTransformer):
        def visit_Name(self, node):
            if node.id in SYMBOLS:
                return ast.copy_location(ast.Constant(SYMBOLS[node.id]), node)
            return node

    return ast.unparse(ast.fix_missing_locations(
        Constants().visit(ast.parse(SOURCE)))) + '\n'


def document():
    from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

    nodes = ast.parse(source_program()).body
    if any(not isinstance(node, ast.FunctionDef) for node in nodes):
        raise ValueError('only chunk-control function definitions may enter HIA')
    names = {node.name: 'f' + str(index) for index, node in enumerate(nodes)}
    if len(names) != len(nodes):
        raise ValueError('duplicate chunk authoring function')
    signatures = {node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id) for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = Builder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(value) for value in builder.params],
                          'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
                          'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8',
                                  'module': 'cli_json_py312_chunks', 'functions': functions})


if __name__ == '__main__':
    import argparse
    from hepta.hia_agent_assembly import render_assembly
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    with args.output.open('x') as stream:
        stream.write(render_assembly(document()))
