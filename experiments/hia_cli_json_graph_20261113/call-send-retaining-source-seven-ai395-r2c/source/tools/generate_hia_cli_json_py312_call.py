"""New source rebuild of the HIA post-dispatch CPython 3.12.14 CALL owner.

This is newly authored source after the previous volatile CALL generator
was lost.  It is not claimed to reproduce that file's cef9191b hash.
The companion C leaves were recovered exactly (5abf9deb); this continuation
uses their existing HCLICL01 single-use request and actual-stack ABI.

HIA chooses exact-method normalization, the three-fact inline call route,
callable-first/arguments-forward release, stack COMMIT and result ownership.
It introduces no value count, depth or observation limit.  Binding returns
an actual thread-frame owner; operation 9 remains an explicit inlined-child
request until the adaptive/instrumented and inlined dispatcher are complete.
There is no extra EvalFrame C-entry and no retained JSON-body fallback.
Unparsed, ungenerated and unexecuted. Original 17/46 and all caps unchanged.
"""
from __future__ import annotations

import ast
from pathlib import Path

SYMBOLS = {
    'MAGIC': int.from_bytes(b'HCLICL01', 'little'),
    'PACKET_MAGIC': int.from_bytes(b'HCLIBC31', 'little'),
    'ABI': 4294967293,
    'PHASE': 8, 'SEQUENCE': 16, 'PENDING': 24,
    'REPLY_SEQUENCE': 32, 'REPLY_OPERATION': 40,
    'RAISED': 48, 'RESULT': 56, 'OPERATION': 64, 'ARG': 72,
    'FINAL': 112, 'GEN': 120, 'CODE': 128, 'PC': 136,
    'OPARG': 144, 'KWNAMES': 152, 'ORIGINAL_TOP': 160,
    'BASE': 168, 'CALLABLE': 176, 'ARG_BASE': 184, 'TOTAL': 192,
    'KWCOUNT': 200, 'IS_METHOD': 208, 'ROUTE': 216,
    'INDEX': 224, 'CHILD': 232, 'INSTRUMENTED': 240, 'ANSWER': 256,
}

SOURCE = r'''
def cli_json_py312_call(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) != 512 or get(w, 0) != MAGIC or get(w, FINAL) != 0:
        return ABI
    if length(s) < 64 or read(s, 0) != PACKET_MAGIC or read(s, 8) != 31214:
        return ABI
    units = read(s, 16)
    if units == 0 or units > 288230376151711742 or length(s) != 64 + units * 64:
        return ABI
    pc = get(w, PC)
    if pc >= units or get(w, GEN) == 0 or get(w, CODE) == 0:
        return ABI
    at = 64 + pc * 64
    if read(s, at) != 171 or read(s, at + 8) != get(w, OPARG) or read(s, at + 56) != 1:
        return ABI
    if get(w, PENDING) != 0:
        if get(w, REPLY_SEQUENCE) != get(w, SEQUENCE) or get(w, REPLY_OPERATION) != get(w, OPERATION):
            return ABI
        put(w, PENDING, 0)
    elif get(w, PHASE) != 0:
        return ABI
    if get(w, PHASE) == 0:
        if get(w, RAISED) != 0 or get(w, RESULT) != 0 or get(w, SEQUENCE) != 0 or get(w,INSTRUMENTED) > 1:
            return ABI
        return request(w, 1, 0, 1)
    while True:
        phase = get(w, PHASE)
        if phase < 4:
            status = route(w, phase)
        elif phase < 10:
            status = bound(w, phase)
        else:
            status = foreign(w, phase)
        if status != 4:
            return status
    return ABI

def metadata(w:mutbuf) -> u64:
    top = answer(w, 0)
    base = answer(w, 1)
    arg_base = answer(w, 3)
    count = answer(w, 4)
    keywords = answer(w, 5)
    method = answer(w, 6)
    if top > 2147483647 or base > top or arg_base > top or count > 2147483647 or method > 1 or answer(w, 7) > 1:
        return ABI
    if answer(w, 2) == 0 or get(w, OPARG) > 2147483647 or keywords > count:
        return ABI
    if top - base != get(w, OPARG) + 2 or top - arg_base != count or count != get(w, OPARG) + method:
        return ABI
    put(w, ORIGINAL_TOP, top)
    put(w, BASE, base)
    put(w, CALLABLE, answer(w, 2))
    put(w, ARG_BASE, arg_base)
    put(w, TOTAL, count)
    put(w, KWCOUNT, keywords)
    put(w, IS_METHOD, method)
    return 4

def route(w:mutbuf, phase:u64) -> u64:
    if get(w, RAISED) != 0 or get(w, RESULT) != 0:
        return ABI
    if phase == 1 or phase == 2:
        status = metadata(w)
        if status != 4:
            return status
        if phase == 1 and get(w, IS_METHOD) == 0 and answer(w, 7) == 1:
            return request(w, 2, 0, 2)
        if phase == 2 and get(w, IS_METHOD) != 1:
            return ABI
        return request(w, 3, 0, 3)
    if phase == 3:
        exact = answer(w, 0)
        ordinary_eval = answer(w, 1)
        standard_vectorcall = answer(w, 2)
        if exact > 1 or ordinary_eval > 1 or standard_vectorcall > 1:
            return ABI
        if exact == 1 and ordinary_eval == 1 and standard_vectorcall == 1:
            put(w, ROUTE, 1)
            return request(w, 8, 0, 4)
        put(w, ROUTE, 2)
        return request(w, 4, 0, 10)
    return ABI

def bound(w:mutbuf, phase:u64) -> u64:
    if get(w, ROUTE) != 1 or (phase < 6 and get(w, RESULT) != 0):
        return ABI
    if phase == 4:
        child = answer(w, 0)
        if child == 0:
            if get(w, RAISED) == 0:
                return ABI
        elif get(w, RAISED) != 0:
            return ABI
        put(w, CHILD, child)
        return request(w, 7, 0, 5)
    if phase == 5:
        if answer(w, 0) != get(w, BASE):
            return ABI
        if get(w, CHILD) == 0:
            if get(w, RAISED) == 0:
                return ABI
            put(w, FINAL, 2)
            return 1
        if get(w, RAISED) != 0:
            return ABI
        # This request has no ACK until a real inlined child owner has
        # consumed it. Binding is not replayed and no C-entry is inserted.
        return request(w, 9, get(w, CHILD), 6)
    if phase == 6:
        # The same-C-frame prologue owns the real binder-produced child.
        # Its actual pop/restore precedes this ACK; no second CALL occurs.
        if answer(w,0) == 1:
            if get(w,RESULT) != 0 or get(w,RAISED) == 0 or answer(w,3) != 1:
                return ABI
            put(w,FINAL,2)
            return 1
        if answer(w,0) != 0 or get(w,RESULT) == 0 or get(w,RAISED) != 0 or answer(w,3) != 0:
            return ABI
        put(w,FINAL,1)
        return 0
    return ABI

def foreign(w:mutbuf, phase:u64) -> u64:
    if get(w, ROUTE) != 2:
        return ABI
    if phase == 10:
        if get(w,INSTRUMENTED) != 0:
            return request(w,11,0,16)
        return cleanup(w)
    if phase == 16:
        if get(w,RESULT) != 0 and (answer(w,0)>>63) != 0:
            if get(w,RAISED) == 0:
                return ABI
            return request(w,12,0,17)
        return cleanup(w)
    if phase == 17:
        if get(w,RESULT) != 0 or get(w,RAISED) == 0 or answer(w,0) != 1:
            return ABI
        return cleanup(w)
    if phase == 11:
        if answer(w, 0) != 1:
            return ABI
        put(w, PHASE, 12)
        return 4
    if phase == 12:
        index = get(w, INDEX)
        if index < get(w, TOTAL):
            return request(w, 6, index, 13)
        if index != get(w, TOTAL):
            return ABI
        return request(w, 7, 0, 14)
    if phase == 13:
        index = get(w, INDEX) + 1
        if index > get(w, TOTAL) or answer(w, 0) != index:
            return ABI
        put(w, INDEX, index)
        put(w, PHASE, 12)
        return 4
    if phase == 14:
        if answer(w, 0) != get(w, BASE):
            return ABI
        return request(w, 10, 0, 15)
    if phase == 15:
        if get(w, RESULT) == 0:
            if get(w, RAISED) == 0:
                return ABI
            put(w, FINAL, 2)
            return 1
        if get(w, RAISED) != 0:
            return ABI
        put(w, FINAL, 1)
        return 0
    return ABI

def cleanup(w:mutbuf) -> u64:
    if (get(w,RESULT) == 0) == (get(w,RAISED) == 0):
        return ABI
    put(w,INDEX,0)
    return request(w,5,0,11)

def answer(w:mutbuf, index:u64) -> u64:
    return get(w, ANSWER + index * 8)

def request(w:mutbuf, operation:u64, argument:u64, phase:u64) -> u64:
    sequence = get(w, SEQUENCE)
    if sequence == 18446744073709551615:
        return ABI
    put(w, SEQUENCE, sequence + 1)
    put(w, PENDING, 1)
    put(w, OPERATION, operation)
    put(w, ARG, argument)
    put(w, 80, 0)
    put(w, 88, 0)
    put(w, 96, 0)
    put(w, 104, 0)
    put(w, PHASE, phase)
    return 2

WORD_HELPERS
'''


def source_program():
    helpers = []
    for name, kind in (('read', 'readbuf'), ('get', 'mutbuf')):
        helpers += [f'def {name}(s:{kind}, at:u64) -> u64:', '    value = 0']
        for i in range(8):
            helpers.append(f'    value = value | (byte(s, at + {i}) << {i * 8})')
        helpers.append('    return value')
    helpers.append('def put(w:mutbuf, at:u64, value:u64) -> u64:')
    for i in range(8):
        helpers.append(f'    store(w, at + {i}, value >> {i * 8})')
    helpers.append('    return 0')
    source = SOURCE.replace('WORD_HELPERS', '\n'.join(helpers))

    class Constants(ast.NodeTransformer):
        def visit_Name(self, node):
            if node.id in SYMBOLS:
                return ast.copy_location(ast.Constant(SYMBOLS[node.id]), node)
            return node

    return ast.unparse(ast.fix_missing_locations(Constants().visit(ast.parse(source)))) + '\n'


def document():
    from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
    nodes = ast.parse(source_program()).body
    names = {node.name: 'f' + str(i) for i, node in enumerate(nodes)}
    signatures = {node.name: ([a.annotation.id for a in node.args.args], node.returns.id) for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = Builder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(p) for p in builder.params],
                          'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
                          'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8',
                                  'module': 'cli_json_py312_call', 'functions': functions})


if __name__ == '__main__':
    import argparse
    from hepta.hia_agent_assembly import render_assembly
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    with args.output.open('x') as stream:
        stream.write(render_assembly(document()))
