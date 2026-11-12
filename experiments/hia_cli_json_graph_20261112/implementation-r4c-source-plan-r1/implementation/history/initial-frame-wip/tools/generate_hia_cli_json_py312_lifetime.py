"""HIA-owned terminal/yield lifetime for an actual 3.12 JSON generator frame.

This is an internal component. The graph bytecode owner must already have
processed that original code's exception handlers, including PEP479. It passes
the actual PyGenObject, original code pointer, parent frame, and original
instruction offset. It never supplies a copied locals dictionary.

HIA chooses traceback creation, reverse operand-stack release, the original
runtime frame clear, result disposal, and then gi_exc_state disposal. The
private C leaf supplies one reference/frame primitive per request. The full
generator body, SEND/throw/close, entry recursion/monitoring, and the C driver
that eliminates Python transport GC windows remain separate open work.
"""
from __future__ import annotations

import ast
from pathlib import Path

SYMBOLS = {
    'MAGIC': int.from_bytes(b'HCLIGLF1', 'little'), 'ABI': 4294967293,
    'PHASE': 8, 'SEQUENCE': 16, 'PENDING': 24,
    'REPLY_SEQUENCE': 32, 'REPLY_OPERATION': 40, 'RAISED': 48,
    'OPERATION': 64, 'ARGUMENTS': 72, 'FINAL': 112,
    'GENERATOR': 120, 'CODE': 128, 'PARENT': 136, 'INSTRUCTION': 144,
    'MODE': 152, 'LOCALS': 160, 'TOP': 168,
    'ANSWER': 256, 'SLOT': 320,
}

SOURCE = r'''
def cli_json_py312_lifetime(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) != 512 or get(w, 0) != MAGIC or get(w, FINAL) != 0:
        return ABI
    if get(w, PENDING) != 0:
        if get(w, REPLY_SEQUENCE) != get(w, SEQUENCE) or get(w, REPLY_OPERATION) != get(w, OPERATION):
            return ABI
        put(w, PENDING, 0)
    elif get(w, PHASE) != 0:
        return ABI
    if get(w, PHASE) == 0:
        if get(w, GENERATOR) == 0 or get(w, CODE) == 0 or get(w, MODE) > 2:
            return ABI
        if get(w, MODE) == 1:
            if get(w, SLOT) != 0 or get(w, RAISED) == 0:
                return ABI
        elif get(w, SLOT) == 0 or get(w, RAISED) != 0:
            return ABI
        put(w, PHASE, 1)
    while True:
        phase = get(w, PHASE)
        if phase < 20:
            status = prepare(w, phase)
        elif phase < 30:
            status = release_stack(w, phase)
        else:
            status = finish(w, phase)
        if status != 4:
            return status
    return ABI

def prepare(w:mutbuf, phase:u64) -> u64:
    if phase == 1:
        return request(w, 95, get(w, GENERATOR), 0, 0, 0, 0, 2)
    if phase == 2:
        if answer(w, 0) != get(w, CODE):
            return ABI
        if answer(w, 6) != 18446744073709551614 and answer(w, 6) != 18446744073709551615:
            return ABI
        locals = answer(w, 2)
        top = answer(w, 4)
        if top < locals or top - locals > answer(w, 3):
            return ABI
        put(w, LOCALS, locals)
        put(w, TOP, top)
        mode = get(w, MODE)
        if mode == 2:
            return request(w, 107, get(w, GENERATOR), get(w, INSTRUCTION), 0, 0, 0, 50)
        if mode == 1:
            return request(w, 97, get(w, GENERATOR), get(w, INSTRUCTION), 0, 0, 0, 20)
        if top != locals:
            return ABI
        return request(w, 17, 0, 0, 0, 0, 0, 10)
    if phase == 10:
        # Only the original three JSON generator code objects enter here;
        # their normal RETURN_CONST is None. Foreign generators stay foreign.
        if get(w, SLOT) != answer(w, 6) or get(w, RAISED) != 0:
            return ABI
        return request(w, 96, get(w, GENERATOR), get(w, PARENT), 0, 0, 0, 30)
    return ABI

def release_stack(w:mutbuf, phase:u64) -> u64:
    if phase == 20:
        if get(w, RAISED) == 0 or get(w, SLOT) != 0:
            return ABI
        if get(w, TOP) == get(w, LOCALS):
            return request(w, 96, get(w, GENERATOR), get(w, PARENT), 0, 0, 0, 30)
        return request(w, 100, get(w, GENERATOR), 0, 0, 0, 0, 21)
    if phase == 21:
        if answer(w, 1) + 1 != get(w, TOP) or answer(w, 1) < get(w, LOCALS):
            return ABI
        put(w, TOP, answer(w, 1))
        if answer(w, 2) != 0:
            if get(w, SLOT) == 0 or get(w, SLOT) != answer(w, 0):
                return ABI
            return request(w, 6, 0, 0, 0, 0, 0, 22)
        if get(w, SLOT) != 0 or answer(w, 0) != 0:
            return ABI
        put(w, PHASE, 20)
        return 4
    if phase == 22:
        if get(w, SLOT) != 0 or get(w, RAISED) == 0:
            return ABI
        put(w, PHASE, 20)
        return 4
    return ABI

def finish(w:mutbuf, phase:u64) -> u64:
    if phase == 30:
        if answer(w, 0) != 4:
            return ABI
        if get(w, MODE) == 0:
            if get(w, SLOT) == 0 or get(w, RAISED) != 0:
                return ABI
            # gen_send_ex2 disposes None from tp_iternext only after the
            # evaluator has cleared the actual frame, before exc_state.
            return request(w, 6, 0, 0, 0, 0, 0, 31)
        if get(w, SLOT) != 0 or get(w, RAISED) == 0:
            return ABI
        put(w, PHASE, 31)
        return 4
    if phase == 31:
        if get(w, SLOT) != 0:
            return ABI
        return request(w, 106, get(w, GENERATOR), 0, 0, 0, 0, 32)
    if phase == 32:
        if get(w, SLOT) != 0:
            return ABI
        if get(w, MODE) == 1:
            if get(w, RAISED) == 0:
                return ABI
            put(w, FINAL, 2)
            return 1
        if get(w, RAISED) != 0:
            return ABI
        put(w, FINAL, 1)
        return 0
    if phase == 50:
        if answer(w, 0) != 18446744073709551615 or get(w, SLOT) == 0 or get(w, RAISED) != 0:
            return ABI
        put(w, FINAL, 4)
        return 3
    return ABI

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
    return ast.unparse(ast.fix_missing_locations(Constants().visit(ast.parse(SOURCE)))) + '\n'


def document():
    from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
    nodes = ast.parse(source_program()).body
    if any(not isinstance(node, ast.FunctionDef) for node in nodes):
        raise ValueError('only complete authoring function definitions are admitted')
    names = {node.name: 'f' + str(index) for index, node in enumerate(nodes)}
    if len(names) != len(nodes):
        raise ValueError('duplicate generator lifetime function')
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
                                  'module': 'cli_json_py312_lifetime', 'functions': functions})


if __name__ == '__main__':
    import argparse
    from hepta.hia_agent_assembly import render_assembly
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    with args.output.open('x') as stream:
        stream.write(render_assembly(document()))
