"""HIA owner for CPython 3.12.14 UNPACK_SEQUENCE in the real value stack.

This successor composes with body port 242. HIA chooses the adaptive route,
exact tuple/list guards, generic iterator cardinality, diagnostics and every
ordinary reference release. C leaves perform one selected object/cache/stack
operation. No intermediate Python tuple exports the values. UNPACK_EX is a
different opcode and is not present in the three retained JSON generators.

This source has not been generated, compiled or executed. It does not supply
the remaining CALL/SEND/monitoring activation or qualify original 17/46.
"""
from __future__ import annotations

import ast
from pathlib import Path

SYMBOLS = {
    'MAGIC': int.from_bytes(b'HCLIUN31', 'little'),
    'ABI': 4294967293,
    'PHASE': 8, 'SEQUENCE': 16, 'OPERATION': 24, 'COUNT': 32,
    'GOT': 40, 'MODE': 48, 'KIND': 56, 'SIZE': 64, 'COUNTER': 72,
    'VALUE': 80, 'ERROR': 88, 'FINAL': 96, 'SUCCEEDED': 104,
    'FAST_INDEX': 112, 'ITERATOR': 120,
}

SOURCE = r'''
def cli_json_py312_unpack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) != 128 or length(o) != 256 or length(w) != 512:
        return ABI
    if read(s, 0) != MAGIC or read(s, 32) != 31214 or read(s, 40) > 1:
        return ABI
    if get(w, 0) == 0:
        if read(s, 8) != 0 or read(s, 16) != 0 or read(s, 24) > 2147483647:
            return ABI
        at = 40
        while at < 128:
            if read(s, at) != 0:
                return ABI
            at = at + 8
        at = 0
        while at < 512:
            if get(w, at) != 0:
                return ABI
            at = at + 8
        put(w, 0, MAGIC)
        put(w, COUNT, read(s, 24))
        return request(o, w, 1, 0, 0, 0, 0, 1)
    if get(w, 0) != MAGIC or get(w, FINAL) != 0:
        return ABI
    if read(s, 8) != 1 or read(s, 16) != get(w, SEQUENCE) or read(s, 24) != get(w, OPERATION):
        return ABI
    at = 88
    while at < 128:
        if read(s, at) != 0:
            return ABI
        at = at + 8
    put(w, ERROR, read(s, 40))
    put(w, VALUE, read(s, 48))
    while True:
        phase = get(w, PHASE)
        if phase < 20:
            status = route(s, o, w, phase)
        elif phase < 60:
            status = iterate(o, w, phase)
        elif phase < 80:
            status = fast(o, w, phase)
        else:
            status = cleanup(o, w, phase)
        if status != 4:
            return status
    return ABI

def route(s:readbuf, o:mutbuf, w:mutbuf, phase:u64) -> u64:
    if get(w, ERROR) != 0:
        return ABI
    if phase == 1:
        if get(w, VALUE) != 1 or read(s, 64) > 2 or read(s, 80) > 65535:
            return ABI
        put(w, MODE, read(s, 56))
        put(w, KIND, read(s, 64))
        put(w, SIZE, read(s, 72))
        put(w, COUNTER, read(s, 80))
        put(w, VALUE, 0)
        put(w, PHASE, 2)
        return 4
    if phase == 2:
        mode = get(w, MODE)
        kind = get(w, KIND)
        count = get(w, COUNT)
        sized = get(w, SIZE) == count
        if mode == 167:
            if kind == 1 and count == 2 and sized:
                put(w, FAST_INDEX, count)
                put(w, PHASE, 60)
                return 4
        elif mode == 166:
            if kind == 1 and sized:
                put(w, FAST_INDEX, count)
                put(w, PHASE, 60)
                return 4
        elif mode == 161:
            if kind == 2 and sized:
                put(w, FAST_INDEX, count)
                put(w, PHASE, 60)
                return 4
        elif mode != 92:
            return ABI
        # DEOPT_IF does not rewrite the opcode. It enters the generic route
        # with the very same counter, which then specializes or decrements.
        counter = get(w, COUNTER)
        if counter >> 4 == 0:
            updated = 92
            if sized:
                if kind == 1:
                    updated = choose(count == 2, 167, 166)
                elif kind == 2:
                    updated = 161
            if updated != 92:
                following_counter = 832
            else:
                backoff = (counter & 15) + 1
                if backoff > 12:
                    backoff = 12
                following_counter = (((1 << backoff) - 1) << 4) | backoff
            put(w, MODE, updated)
            put(w, COUNTER, following_counter)
            return request(o, w, 2, updated, following_counter, mode, counter, 3)
        put(w, COUNTER, counter - 16)
        return request(o, w, 2, mode, counter - 16, mode, counter, 4)
    if phase == 3:
        if get(w, VALUE) != 0:
            return ABI
        put(w, PHASE, 2)
        return 4
    if phase == 4:
        if get(w, VALUE) != 0:
            return ABI
        return request(o, w, 3, 0, 0, 0, 0, 20)
    return ABI

def iterate(o:mutbuf, w:mutbuf, phase:u64) -> u64:
    value = get(w, VALUE)
    error = get(w, ERROR)
    if phase == 20:
        if value == 0:
            if error != 1:
                return ABI
            return request(o, w, 10, 0, 0, 0, 0, 21)
        if value != 1 or error != 0:
            return ABI
        put(w, ITERATOR, 1)
        put(w, PHASE, 30)
        return 4
    if phase == 21:
        if value > 1 or error != 1:
            return ABI
        if value == 0:
            return fail(o, w)
        return request(o, w, 11, 0, 0, 0, 0, 22)
    if phase == 22:
        if value > 1 or error != 1:
            return ABI
        if value != 0:
            return fail(o, w)
        return request(o, w, 12, 0, 0, 0, 0, 23)
    if phase == 23:
        if value > 1 or error != 1:
            return ABI
        if value != 0:
            return fail(o, w)
        return diagnostic(o, w, 13, 0, 0, 24)
    if phase == 24:
        if value != 0 or error != 1:
            return ABI
        return fail(o, w)
    if phase == 30:
        return request(o, w, 4, 0, 0, 0, 0, 31)
    if phase == 31:
        got = get(w, GOT)
        if value == 0:
            if error != 0:
                return fail(o, w)
            if got < get(w, COUNT):
                return diagnostic(o, w, 14, get(w, COUNT), got, 24)
            put(w, SUCCEEDED, 1)
            put(w, PHASE, 90)
            return 4
        if value != 1 or error != 0:
            return ABI
        if got == get(w, COUNT):
            return request(o, w, 9, 0, 0, 0, 0, 33)
        return request(o, w, 5, got, 0, 0, 0, 32)
    if phase == 32:
        if value != 0 or error != 0:
            return ABI
        put(w, GOT, get(w, GOT) + 1)
        put(w, PHASE, 30)
        return 4
    if phase == 33:
        if value != 0 or error != 0:
            return ABI
        # The excess result has already been released. 3.12 never performs
        # the 3.14 exact-container got-size observation on this path.
        return diagnostic(o, w, 15, get(w, COUNT), 0, 24)
    return ABI

def fast(o:mutbuf, w:mutbuf, phase:u64) -> u64:
    if get(w, VALUE) != 0 or get(w, ERROR) != 0:
        return ABI
    if phase == 60:
        index = get(w, FAST_INDEX)
        if index == 0:
            put(w, SUCCEEDED, 1)
            put(w, PHASE, 90)
            return 4
        return request(o, w, 16, get(w, KIND), index - 1,
                       get(w, COUNT) - index, 0, 61)
    if phase == 61:
        put(w, FAST_INDEX, get(w, FAST_INDEX) - 1)
        put(w, GOT, get(w, GOT) + 1)
        put(w, PHASE, 60)
        return 4
    return ABI

def fail(o:mutbuf, w:mutbuf) -> u64:
    put(w, SUCCEEDED, 0)
    put(w, PHASE, 80)
    return 4

def cleanup(o:mutbuf, w:mutbuf, phase:u64) -> u64:
    if phase == 80:
        if get(w, ERROR) != 1:
            return ABI
        got = get(w, GOT)
        if got != 0:
            return request(o, w, 6, got - 1, 0, 0, 0, 81)
        put(w, PHASE, 90)
        return 4
    if phase == 81:
        if get(w, VALUE) != 0 or get(w, ERROR) != 1:
            return ABI
        put(w, GOT, get(w, GOT) - 1)
        put(w, PHASE, 80)
        return 4
    if phase == 90:
        if get(w, ITERATOR) != 0:
            return request(o, w, 7, 0, 0, 0, 0, 91)
        put(w, PHASE, 92)
        return 4
    if phase == 91:
        if get(w, VALUE) != 0:
            return ABI
        put(w, ITERATOR, 0)
        put(w, PHASE, 92)
        return 4
    if phase == 92:
        # This is the generated opcode's Py_DECREF(seq), after all inner
        # unpack_iterable item/iterator work and before its stack update.
        return request(o, w, 8, 0, 0, 0, 0, 93)
    if phase == 93:
        if get(w, VALUE) != 0 or get(w, ERROR) == get(w, SUCCEEDED):
            return ABI
        return request(o, w, 17, get(w, SUCCEEDED), 0, 0, 0, 94)
    if phase == 94:
        if get(w, VALUE) != 0 or get(w, ERROR) == get(w, SUCCEEDED):
            return ABI
        put(w, FINAL, 1)
        return 1 - get(w, SUCCEEDED)
    return ABI

def request(o:mutbuf, w:mutbuf, operation:u64, a:u64, b:u64, c:u64, d:u64, phase:u64) -> u64:
    sequence = get(w, SEQUENCE)
    if sequence == 18446744073709551615:
        return ABI
    sequence = sequence + 1
    put(w, SEQUENCE, sequence)
    put(w, OPERATION, operation)
    put(w, PHASE, phase)
    at = 0
    while at < 256:
        put(o, at, 0)
        at = at + 8
    put(o, 0, MAGIC)
    put(o, 8, sequence)
    put(o, 16, operation)
    put(o, 24, a)
    put(o, 32, b)
    put(o, 40, c)
    put(o, 48, d)
    return 2

def diagnostic(o:mutbuf, w:mutbuf, operation:u64, a:u64, b:u64, phase:u64) -> u64:
    status = request(o, w, operation, a, b, 0, 0, phase)
    if status != 2:
        return status
    FORMAT_BYTES
    return status

WORD_HELPERS
'''

FORMATS = {
    13: 'cannot unpack non-iterable %.200s object',
    14: 'not enough values to unpack (expected %d, got %d)',
    15: 'too many values to unpack (expected %d)',
}


def source_program():
    lines = []
    for index, (op, text) in enumerate(FORMATS.items()):
        lines.append(('if' if index == 0 else 'elif') + f' operation == {op}:')
        for offset, value in enumerate(text.encode('ascii') + b'\0', 128):
            lines.append(f'    store(o, {offset}, {value})')
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
    source = SOURCE.replace('FORMAT_BYTES', '\n    '.join(lines)).replace('WORD_HELPERS', '\n'.join(helpers))
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
                                  'module': 'cli_json_py312_unpack', 'functions': functions})


if __name__ == '__main__':
    import argparse
    from hepta.hia_agent_assembly import render_assembly
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    with args.output.open('x') as stream:
        stream.write(render_assembly(document()))
