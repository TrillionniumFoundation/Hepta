"""HIA owner for the original JSON generator functions' thread-frame prologue.

This is a new unexecuted component, not an arbitrary Python-frame evaluator.
The retaining CALL driver must independently bind the actual binder-produced
thread frame to the complete original code packet. HIA executes its complete
COPY_FREE_VARS / EXTENDED_ARG / RETURN_GENERATOR prelude and selects ordinary
allocation-error monitoring or direct recursion-entry unwind. Actual C
frame links/slots are used; no extra EvalFrame entry or generator wrapper.

An unrecognized frame/packet remains an unactivated private port. This is
not a new public value restriction or permission to fall back to a retained
JSON body. Arbitrary foreign Python function bodies remain OPEN. Original
17/46 and all compiler/native caps remain unchanged and unexecuted here.
"""
from __future__ import annotations

import ast
from pathlib import Path

SYMBOLS = {
    'MAGIC': int.from_bytes(b'HCLIPR01', 'little'),
    'PACKET_MAGIC': int.from_bytes(b'HCLIBC31', 'little'),
    'ABI': 4294967293, 'NONE': 18446744073709551615,
    'PHASE':8, 'SEQUENCE':16, 'PENDING':24, 'REPLY_SEQUENCE':32,
    'REPLY_OPERATION':40, 'RAISED':48, 'RESULT':56, 'OPERATION':64,
    'FINAL':112, 'FRAME':120, 'CODE':128, 'PC':136, 'UNITS':144,
    'LOCALS':152, 'TOP':160, 'FREE_COUNT':168, 'INDEX':176,
    'NEXT':184, 'RETURN_PC':192, 'ENTRY_ERROR':200, 'ANSWER':256,
}

SOURCE = r'''
def cli_json_py312_call_prologue(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) != 512 or get(w,0) != MAGIC or get(w,FINAL) != 0:
        return ABI
    if length(s) < 64 or read(s,0) != PACKET_MAGIC or read(s,8) != 31214:
        return ABI
    units = read(s,16)
    if units == 0 or units > 288230376151711742 or length(s) != 64 + units * 64:
        return ABI
    if get(w,FRAME) == 0 or get(w,CODE) == 0 or get(w,UNITS) != units:
        return ABI
    if get(w,PENDING) != 0:
        if get(w,REPLY_SEQUENCE) != get(w,SEQUENCE) or get(w,REPLY_OPERATION) != get(w,OPERATION):
            return ABI
        put(w,PENDING,0)
    elif get(w,PHASE) != 0:
        return ABI
    if get(w,PHASE) == 0:
        if get(w,PC) != 0 or get(w,SEQUENCE) != 0 or get(w,RAISED) != 0 or get(w,RESULT) != 0:
            return ABI
        return request(w,1,0,0,1)
    while True:
        phase = get(w,PHASE)
        if phase == 1:
            status = entry(s,w)
        elif phase == 10:
            status = decode(s,w)
        elif phase < 30:
            status = closure(w,phase)
        elif phase < 80:
            status = construct(w,phase)
        else:
            status = unwind(w,phase)
        if status != 4:
            return status
    return ABI

def entry(s:readbuf,w:mutbuf) -> u64:
    if get(w,RESULT) != 0 or answer(w,0) > 1 or answer(w,1) != read(s,40):
        return ABI
    put(w,LOCALS,answer(w,1))
    put(w,TOP,answer(w,2))
    if answer(w,2) != answer(w,1):
        return ABI
    if answer(w,0) == 1:
        if get(w,RAISED) == 0:
            return ABI
        put(w,ENTRY_ERROR,1)
        return request(w,8,0,0,83)
    if get(w,RAISED) != 0:
        return ABI
    put(w,PHASE,10)
    return 4

def decode(s:readbuf,w:mutbuf) -> u64:
    pc = get(w,PC)
    if pc >= get(w,UNITS) or get(w,RAISED) != 0 or get(w,RESULT) != 0:
        return ABI
    at = 64 + pc * 64
    if read(s,at+56) != 1 or read(s,at+32) != NONE:
        return ABI
    opcode = read(s,at)
    argument = read(s,at+8)
    following = read(s,at+16)
    if following <= pc or following >= get(w,UNITS):
        return ABI
    put(w,NEXT,following)
    if opcode == 144:
        # The immutable packet already has the full EXTENDED_ARG operand.
        return request(w,12,pc,opcode,21)
    if opcode == 149:
        if argument > get(w,LOCALS):
            return ABI
        put(w,FREE_COUNT,argument)
        put(w,INDEX,0)
        return request(w,12,pc,opcode,20)
    if opcode == 75:
        put(w,RETURN_PC,pc)
        return request(w,3,pc,0,30)
    return ABI

def closure(w:mutbuf,phase:u64) -> u64:
    if get(w,RAISED) != 0 or get(w,RESULT) != 0:
        return ABI
    if phase == 20:
        index = get(w,INDEX)
        if index < get(w,FREE_COUNT):
            return request(w,2,index,get(w,FREE_COUNT),22)
        if index != get(w,FREE_COUNT):
            return ABI
        put(w,PC,get(w,NEXT))
        put(w,PHASE,10)
        return 4
    if phase == 21:
        put(w,PC,get(w,NEXT))
        put(w,PHASE,10)
        return 4
    if phase == 22:
        index = get(w,INDEX)+1
        if answer(w,0) != index or index > get(w,FREE_COUNT):
            return ABI
        put(w,INDEX,index)
        put(w,PHASE,20)
        return 4
    return ABI

def construct(w:mutbuf,phase:u64) -> u64:
    if phase == 30:
        if get(w,RESULT) == 0:
            if get(w,RAISED) == 0:
                return ABI
            # This original pre-RESUME frame is incomplete, so there is
            # no traceback-frame allocation. Both monitor sites still run.
            return request(w,4,get(w,RETURN_PC),0,80)
        if get(w,RAISED) != 0:
            return ABI
        return request(w,6,0,0,31)
    if phase == 31:
        if get(w,RESULT) == 0 or get(w,RAISED) != 0 or answer(w,0) != 1:
            return ABI
        return request(w,7,0,0,32)
    if phase == 32:
        if get(w,RESULT) == 0 or get(w,RAISED) != 0 or answer(w,0) != 1:
            return ABI
        put(w,FINAL,1)
        return 0
    return ABI

def unwind(w:mutbuf,phase:u64) -> u64:
    if get(w,RESULT) != 0 or get(w,RAISED) == 0:
        return ABI
    if phase == 80:
        # The admitted original prologue has an empty operand stack and
        # no exception-table handler. No fabricated POP or exception is
        # inserted before original monitor_unwind.
        return request(w,5,get(w,RETURN_PC),0,81)
    if phase == 81:
        return request(w,8,0,0,83)
    if phase == 83:
        return request(w,9,0,0,84)
    if phase == 84:
        return request(w,10,0,0,85)
    if phase == 85:
        return request(w,11,0,0,86)
    if phase == 86:
        if answer(w,0) != 1:
            return ABI
        put(w,FINAL,2)
        return 1
    return ABI

def answer(w:mutbuf,index:u64) -> u64:
    return get(w,ANSWER+index*8)

def request(w:mutbuf,operation:u64,a:u64,b:u64,phase:u64) -> u64:
    sequence = get(w,SEQUENCE)
    if sequence == 18446744073709551615:
        return ABI
    put(w,SEQUENCE,sequence+1)
    put(w,PENDING,1)
    put(w,OPERATION,operation)
    put(w,72,a)
    put(w,80,b)
    put(w,88,0)
    put(w,96,0)
    put(w,104,0)
    put(w,PHASE,phase)
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
                                  'module': 'cli_json_py312_call_prologue', 'functions': functions})


if __name__ == '__main__':
    import argparse
    from hepta.hia_agent_assembly import render_assembly
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    with args.output.open('x') as stream:
        stream.write(render_assembly(document()))
