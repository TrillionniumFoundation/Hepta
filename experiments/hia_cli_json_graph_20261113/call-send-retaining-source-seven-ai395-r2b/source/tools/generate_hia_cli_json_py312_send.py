"""HIA-owned CPython 3.12.14 SEND and SEND_GEN continuation.

New, unexecuted body component. HIA selects adaptive cache transitions,
inlined-generator versus current iterator/send primitive, StopIteration
monitor/fetch ordering, the original v DECREF, stack COMMIT and result move.
The C port performs those individual operations against the actual stack.
An inlined child suspends this continuation without a fake ACK or a new
EvalFrame C entry. The enclosing retaining driver must admit that child's
original packet and transfer its real result/error before acknowledging.

This file does not replace FOR_ITER's separate fast families. The existing
17 CLI / 46 trace population and original source/native caps are unchanged.
No generation, compilation, native run or full-body equivalence is claimed.
"""
from __future__ import annotations

import ast
from pathlib import Path

SYMBOLS = {
    'MAGIC': int.from_bytes(b'HCLISD01', 'little'),
    'PACKET_MAGIC': int.from_bytes(b'HCLIBC31', 'little'),
    'ABI': 4294967293,
    'PHASE': 8, 'SEQUENCE': 16, 'PENDING': 24,
    'REPLY_SEQUENCE': 32, 'REPLY_OPERATION': 40,
    'RAISED': 48, 'RESULT': 56, 'OPERATION': 64, 'ARG': 72,
    'FINAL': 112, 'GEN': 120, 'CODE': 128, 'PC': 136,
    'OPARG': 144, 'FOLLOWING': 152, 'ORIGINAL_TOP': 160,
    'BASE': 168, 'RECEIVER': 176, 'VALUE': 184, 'MODE': 192,
    'COUNTER': 200, 'FACTS': 208, 'ROUTE': 216, 'FLOW': 224,
    'ANSWER': 256,
}

SOURCE = r'''
def cli_json_py312_send(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
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
    if read(s, at) != 123 or read(s, at + 8) != get(w, OPARG) or read(s, at + 56) != 1:
        return ABI
    if get(w, FOLLOWING) != pc + 2 or get(w, FOLLOWING) >= units:
        return ABI
    if get(w, PENDING) != 0:
        if get(w, REPLY_SEQUENCE) != get(w, SEQUENCE) or get(w, REPLY_OPERATION) != get(w, OPERATION):
            return ABI
        put(w, PENDING, 0)
    elif get(w, PHASE) != 0:
        return ABI
    if get(w, PHASE) == 0:
        if get(w, RAISED) != 0 or get(w, RESULT) != 0 or get(w, SEQUENCE) != 0:
            return ABI
        return request(w, 1, 0, 0, 0, 0, 1)
    while True:
        phase = get(w, PHASE)
        if phase < 10:
            status = adaptive(w, phase)
        elif phase < 20:
            status = foreign(w, phase)
        elif phase < 30:
            status = inline_result(w, phase)
        else:
            status = release(w, phase)
        if status != 4:
            return status
    return ABI

def adaptive(w:mutbuf, phase:u64) -> u64:
    if get(w, RAISED) != 0 or get(w, RESULT) != 0:
        return ABI
    if phase == 1:
        top = answer(w, 0)
        facts = answer(w, 5)
        if top < 2 or top > 2147483647 or answer(w, 1) == 0 or answer(w, 2) == 0 or facts > 63:
            return ABI
        if answer(w, 3) != 123 and answer(w, 3) != 168:
            return ABI
        if answer(w, 4) > 65535 or answer(w, 6) != get(w, FOLLOWING) or answer(w, 7) != 0:
            return ABI
        put(w, ORIGINAL_TOP, top)
        put(w, BASE, top - 1)
        put(w, RECEIVER, answer(w, 1))
        put(w, VALUE, answer(w, 2))
        put(w, MODE, answer(w, 3))
        put(w, COUNTER, answer(w, 4))
        put(w, FACTS, facts)
        put(w, PHASE, 2)
        return 4
    if phase == 2:
        mode = get(w, MODE)
        facts = get(w, FACTS)
        generator_type = (facts & 3) != 0
        default_eval = (facts & 4) != 0
        executable_state = (facts & 8) != 0
        if mode == 168 and generator_type and default_eval and executable_state:
            put(w, ROUTE, 1)
            return request(w, 3, 0, 0, 0, 0, 20)
        # SEND_GEN deoptimization enters SEND with the same opcode/cache.
        # Only a selected specialization/cache-write leaf changes it.
        counter = get(w, COUNTER)
        if counter >> 4 == 0:
            updated = 123
            if generator_type and default_eval:
                updated = 168
                following_counter = 832
            else:
                backoff = (counter & 15) + 1
                if backoff > 12:
                    backoff = 12
                following_counter = (((1 << backoff) - 1) << 4) | backoff
            put(w, MODE, updated)
            put(w, COUNTER, following_counter)
            return request(w, 2, updated, following_counter, mode, counter, 3)
        put(w, COUNTER, counter - 16)
        return request(w, 2, mode, counter - 16, mode, counter, 4)
    if phase == 3:
        if answer(w, 0) != get(w, MODE) or answer(w, 1) != get(w, COUNTER):
            return ABI
        put(w, PHASE, 2)
        return 4
    if phase == 4:
        if answer(w, 0) != get(w, MODE) or answer(w, 1) != get(w, COUNTER):
            return ABI
        facts = get(w, FACTS)
        if (facts & 3) != 0 and (facts & 4) != 0 and (facts & 8) != 0:
            put(w, ROUTE, 1)
            return request(w, 3, 0, 0, 0, 0, 20)
        put(w, ROUTE, 2)
        # None + current tp_iternext exists is the original short circuit.
        if (facts & 16) != 0 and (facts & 32) != 0:
            return request(w, 4, 0, 0, 0, 0, 10)
        return request(w, 5, 0, 0, 0, 0, 10)
    return ABI

def foreign(w:mutbuf, phase:u64) -> u64:
    if get(w, ROUTE) != 2:
        return ABI
    if phase == 10:
        if get(w, RESULT) != 0:
            if get(w, RAISED) != 0:
                return ABI
            put(w, FLOW, 1)
            return request(w, 9, 0, 0, 0, 0, 30)
        # A bare iterator exhaustion has no raised E. It must still call
        # FetchStopIterationValue, which produces the owned None result.
        return request(w, 6, 0, 0, 0, 0, 11)
    if phase == 11:
        if get(w, RESULT) != 0 or answer(w, 0) > 1:
            return ABI
        if answer(w, 0) == 1:
            return request(w, 7, 0, 0, 0, 0, 12)
        put(w, PHASE, 12)
        return 4
    if phase == 12:
        if get(w, RESULT) != 0:
            return ABI
        # The monitor is allowed to replace the raised error. The fetch
        # must operate on that actual post-monitor state, not a saved E.
        return request(w, 8, 0, 0, 0, 0, 13)
    if phase == 13:
        if answer(w, 0) == 0:
            if get(w, RESULT) == 0 or get(w, RAISED) != 0:
                return ABI
            put(w, FLOW, 0)
            return request(w, 9, 0, 0, 0, 0, 30)
        if answer(w, 0) != 18446744073709551615 or get(w, RESULT) != 0 or get(w, RAISED) == 0:
            return ABI
        # Original error path has NOT DECREF'd v or shrunk its stack.
        return request(w, 12, 0, 0, 0, 0, 33)
    return ABI

def inline_result(w:mutbuf, phase:u64) -> u64:
    if phase != 20 or get(w, ROUTE) != 1 or answer(w, 0) > 3:
        return ABI
    status = answer(w, 0)
    if status == 1:
        if get(w, RESULT) != 0 or get(w, RAISED) == 0 or answer(w, 3) != 1:
            return ABI
        put(w, FINAL, 2)
        return 1
    if status != 0 and status != 3:
        return ABI
    if get(w, RESULT) == 0 or get(w, RAISED) != 0 or answer(w, 3) != 0:
        return ABI
    put(w, FLOW, choose(status == 3, 1, 0))
    put(w, FINAL, 1)
    return 0

def release(w:mutbuf, phase:u64) -> u64:
    if get(w, ROUTE) != 2:
        return ABI
    if phase == 30:
        if get(w, RESULT) == 0 or get(w, RAISED) != 0 or answer(w, 0) != 1:
            return ABI
        return request(w, 10, 0, 0, 0, 0, 31)
    if phase == 31:
        if get(w, RESULT) == 0 or get(w, RAISED) != 0 or answer(w, 0) != get(w, BASE):
            return ABI
        return request(w, 11, 0, 0, 0, 0, 32)
    if phase == 32:
        if get(w, RESULT) == 0 or get(w, RAISED) != 0:
            return ABI
        put(w, FINAL, 1)
        return 0
    if phase == 33:
        if get(w, RESULT) != 0 or get(w, RAISED) == 0 or answer(w, 0) != get(w, ORIGINAL_TOP):
            return ABI
        put(w, FINAL, 2)
        return 1
    return ABI

def answer(w:mutbuf, index:u64) -> u64:
    return get(w, ANSWER + index * 8)

def request(w:mutbuf, operation:u64, a:u64, b:u64, c:u64, d:u64, phase:u64) -> u64:
    sequence = get(w, SEQUENCE)
    if sequence == 18446744073709551615:
        return ABI
    put(w, SEQUENCE, sequence + 1)
    put(w, PENDING, 1)
    put(w, OPERATION, operation)
    put(w, 72, a)
    put(w, 80, b)
    put(w, 88, c)
    put(w, 96, d)
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
                                  'module': 'cli_json_py312_send', 'functions': functions})


if __name__ == '__main__':
    import argparse
    from hepta.hia_agent_assembly import render_assembly
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    with args.output.open('x') as stream:
        stream.write(render_assembly(document()))
