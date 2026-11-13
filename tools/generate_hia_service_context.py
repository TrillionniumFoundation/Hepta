"""Author the context service's retained, once-only HIA continuation policy.

The numeric phases below are the policy, not a runtime Python instruction
interpreter.  They are compiled to ordinary Core control flow.  Foreign object
operations, SQLite and the existing artifact/schema/profile providers remain
explicit dependencies of this opt-in owner.
"""
from __future__ import annotations

import ast
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import compact_authoring_cfg, total_scalar_functions
from tools.hia_program_execution_scalars import ScalarBuilder as Builder
from tools.hia_exception_delivery import BODY as DELIVERY_BODY, EMIT_MAGIC
from tools.hia_service_context_arithmetic import body as arithmetic_body, MAGIC as MATH_MAGIC, OPERATIONS

REQUEST_MAGIC = int.from_bytes(b'HIACTQ01', 'little')
STATE_MAGIC = int.from_bytes(b'HIACTS01', 'little')
RESULT_MAGIC = int.from_bytes(b'HIACTR01', 'little')
STATE_BYTES = 128

# Physical object names are transport slots. HIA owns their live mask, cleanup
# order and one-use effect permissions. Original function/genexpr locals are
# deliberately not included in this temporary-operand inventory.
TEMPORARIES = ('sum', 'values_iterator', 'size', 'record_fields', 'exports_list',
    'exports_iterator', 'pair', 'system', 'machine', 'cpu_count', 'context_id',
    'execute', 'insert_id', 'insert_hash', 'artifact_wire', 'created_ns', 'cursor',
    'get_json', 'artifact', 'now', 'created', 'elapsed', 'wall', 'remaining', 'quotient',
    'math_left', 'math_right')


def mask(*names):
    return sum(1 << TEMPORARIES.index(name) for name in names)


CREATED = {8: mask('sum'), 10: mask('values_iterator'), 13: mask('size'),
    50: mask('record_fields'), 58: mask('exports_list', 'exports_iterator'), 59: mask('pair'),
    63: mask('system'), 64: mask('machine'), 65: mask('cpu_count'), 68: mask('context_id'),
    70: mask('execute'), 71: mask('insert_id', 'insert_hash'), 72: mask('artifact_wire'),
    73: mask('created_ns'), 102: mask('cursor'), 106: mask('get_json'), 107: mask('artifact'),
    201: mask('cursor'), 204: mask('now'), 205: mask('created'), 206: mask('elapsed'),
    207: mask('wall'), 210: mask('cursor'), 301: mask('cursor'), 303: mask('created'),
    304: mask('wall'), 306: mask('now'), 307: mask('remaining'), 308: mask('quotient'),
    401: mask('cursor'), 403: mask('created'), 404: mask('wall'), 501: mask('now'),
    502: mask('remaining'), 503: mask('quotient')}
CLEARED = {11: (mask('values_iterator'), 0), 14: mask('size'), 16: mask('sum'),
    59: (mask('exports_list', 'exports_iterator', 'pair'), 0),
    66: mask('record_fields', 'system', 'machine', 'cpu_count'), 69: mask('context_id'),
    74: mask('execute', 'insert_id', 'insert_hash', 'artifact_wire', 'created_ns'),
    103: mask('cursor'), 108: mask('get_json', 'artifact'), 202: mask('cursor'),
    206: mask('now', 'created'), 208: mask('elapsed', 'wall'), 211: mask('cursor'),
    302: mask('cursor'), 305: mask('created', 'wall'), 307: mask('now'),
    308: mask('remaining'), 309: mask('quotient'), 402: mask('cursor'),
    405: mask('created', 'wall'), 502: mask('now'), 503: mask('remaining'), 504: mask('quotient')}

for _action in OPERATIONS:
    CREATED[_action] = CREATED.get(_action, 0) | mask('math_left', 'math_right')
    _prior = CLEARED.get(_action, 0)
    CLEARED[_action] = (tuple(value | mask('math_left', 'math_right') for value in _prior)
                        if type(_prior) is tuple else _prior | mask('math_left', 'math_right'))

# A pair means (next phase for false, next phase for true).  A scalar means a
# void observation and an unconditional transition.  Zero is a terminal result.
# All branches, iteration and service rejection choices belong to this table.
GRAPHS = {
    1: {
        1: 2, 2: 3, 3: 4, 4: 5, 5: 6, 6: 7, 7: 8, 8: 9,
        9: (16, 10), 10: 11, 11: (9, 12), 12: (11, 13), 13: 14, 14: 11,
        16: 17, 17: (18, 90), 18: 19, 19: 20,
        20: 21, 21: 22, 22: 23, 23: 24, 24: 25,
        25: 26, 26: (91, 27), 27: (91, 28), 28: (29, 92),
        29: (31, 30), 30: 31, 31: (33, 32), 32: 33,
        33: 34, 34: (36, 35), 35: (36, 93), 36: (41, 37),
        37: 38, 38: (40, 39), 39: (38, 94), 40: 41,
        41: 42, 42: (44, 43), 43: 44, 44: 50,
        50: 51, 51: 52, 52: 53, 53: 54, 54: 55, 55: 56, 56: 57,
        57: 58, 58: 59, 59: (61, 60), 60: 59,
        61: 62, 62: 63, 63: 64, 64: 65, 65: 66, 66: 67,
        67: 68, 68: 69, 69: 70, 70: 71, 71: 72, 72: 73, 73: 74,
        74: 75, 75: 76, 76: 0,
        90: 0, 91: 0, 92: 0, 93: 0, 94: 0,
    },
    2: {101: 102, 102: 103, 103: 104, 104: (105, 190),
        105: (106, 190), 106: 107, 107: 108, 108: 109,
        109: (110, 191), 110: (111, 191), 111: 112, 112: 113, 113: 0,
        190: 0, 191: 0},
    3: {201: 202, 202: 203, 203: 204, 204: 205, 205: 206,
        206: 207, 207: 208, 208: (209, 290), 209: (0, 213),
        210: 211, 211: 212, 212: (0, 291),
        213: (210, 214), 214: 0, 290: 0, 291: 0},
    4: {301: 302, 302: 303, 303: 304, 304: 305, 305: 306,
        306: 307, 307: 308, 308: 309, 309: 0},
    5: {401: 402, 402: 403, 403: 404, 404: 405, 405: 0},
    6: {501: 502, 502: 503, 503: 504, 504: 0},
}

SOURCE = r'''
def context_main(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) >= 64:
        if read_word(s, 0) == @MATH_MAGIC@:
            return ctx_math_main(s, o, w)
    if length(s) == 64:
        if read_word(s, 0) == @EMIT_MAGIC@:
            return emit_exception_delivery(s, o, w)
    if length(s) != 64 or length(o) < 144 or length(w) != 128:
        return 4294967293
    if read_word(s, 0) != @REQUEST_MAGIC@ or read_word(s, 56) != 0:
        return refuse(o, 1)
    event = read_word(s, 8)
    if event == 0:
        return initialize(s, o, w)
    if valid(w) == 0:
        return refuse(o, 2)
    if read_word(s, 24) != get(w, 6) or read_word(s, 32) != get(w, 7):
        return refuse(o, 3)
    if read_word(s, 16) != get(w, 4) or read_word(s, 48) != get(w, 2):
        return refuse(o, 4)
    if event == 1:
        if get(w, 5) != 1 or read_word(s, 40) != 0 or get(w, 4) == 18446744073709551615:
            return refuse(o, 5)
        if get(w, 10) == 0:
            put(w, 9, get(w, 9) | created_mask(get(w, 3)))
        put(w, 5, 2)
        seal(w)
        return answer(o, w)
    if event == 2 or event == 3:
        return outcome(s, o, w, event)
    if event == 4:
        if read_word(s, 40) != 0 or get(w, 9) != 0:
            return refuse(o, 5)
        if get(w, 5) == 3 and get(w, 10) == 0:
            put(w, 5, 5)
        elif get(w, 5) == 4 and get(w, 10) == 1:
            put(w, 5, 7)
        else:
            return refuse(o, 5)
        seal(w)
        return answer(o, w)
    return refuse(o, 1)

def initialize(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    kind = read_word(s, 48)
    if kind < 1 or kind > 6 or read_word(s, 16) != 0 or read_word(s, 40) != 0:
        return refuse(o, 1)
    if read_word(s, 24) == 0 and read_word(s, 32) == 0:
        return refuse(o, 3)
    i = 0
    while i < 16:
        if get(w, i) != 0:
            return refuse(o, 2)
        i = i + 1
    put(w, 0, @STATE_MAGIC@)
    put(w, 1, 3)
    put(w, 2, kind)
    put(w, 3, (kind - 1) * 100 + 1)
    put(w, 4, 1)
    put(w, 5, 1)
    put(w, 6, read_word(s, 24))
    put(w, 7, read_word(s, 32))
    seal(w)
    return answer(o, w)

def outcome(s:readbuf, o:mutbuf, w:mutbuf, event:u64) -> u32:
    if get(w, 5) != 2 or get(w, 4) == 18446744073709551615:
        return refuse(o, 5)
    observed = read_word(s, 40)
    if event == 3:
        if observed != 0 or get(w, 10) != 0:
            return refuse(o, 1)
        put(w, 10, 1)
        put(w, 11, get(w, 3))
        next = cleanup_next(get(w, 9))
        put(w, 3, next)
        put(w, 5, choose(next == 0, 4, 1))
        put(w, 4, get(w, 4) + 1)
        seal(w)
        return answer(o, w)
    if get(w, 10) == 1:
        if observed != 0 or get(w, 3) < 600 or get(w, 3) >= @CLEANUP_END@:
            return refuse(o, 1)
        put(w, 9, get(w, 9) & (18446744073709551615 ^ (1 << (get(w, 3) - 600))))
        next = cleanup_next(get(w, 9))
        put(w, 3, next)
        put(w, 5, choose(next == 0, 4, 1))
        put(w, 4, get(w, 4) + 1)
        seal(w)
        return answer(o, w)
    next = next_phase(get(w, 2), get(w, 3), observed)
    if next == 18446744073709551615:
        return refuse(o, 6)
    remaining = get(w, 9) & (18446744073709551615 ^ cleared_mask(get(w, 3), observed))
    if next == 0 and remaining != 0:
        return refuse(o, 7)
    put(w, 9, remaining)
    put(w, 3, next)
    put(w, 4, get(w, 4) + 1)
    put(w, 5, choose(next == 0, 3, 1))
    seal(w)
    return answer(o, w)

def valid(w:mutbuf) -> u64:
    if get(w, 0) != @STATE_MAGIC@ or get(w, 1) != 3 or get(w, 2) < 1 or get(w, 2) > 6:
        return 0
    if get(w, 5) < 1 or get(w, 5) > 7 or get(w, 5) == 6 or get(w, 4) == 0:
        return 0
    if get(w, 9) > @ALL_TEMPORARIES@ or get(w, 10) > 1:
        return 0
    if get(w, 10) == 0:
        if get(w, 11) != 0 or get(w, 5) == 4 or get(w, 5) == 7:
            return 0
        if get(w, 5) <= 2 and next_phase(get(w, 2), get(w, 3), 0) == 18446744073709551615:
            return 0
    else:
        if get(w, 5) == 3 or get(w, 5) == 5 or next_phase(get(w, 2), get(w, 11), 0) == 18446744073709551615:
            return 0
        if get(w, 5) <= 2 and (get(w, 9) == 0 or get(w, 3) != cleanup_next(get(w, 9))):
            return 0
    if get(w, 5) >= 3 and (get(w, 3) != 0 or get(w, 9) != 0):
        return 0
    i = 12
    while i < 16:
        if get(w, i) != 0:
            return 0
        i = i + 1
    return choose(get(w, 8) == checksum(w), 1, 0)

def cleanup_next(live:u64) -> u64:
    i = @TEMPORARY_COUNT@
    while i > 0:
        i = i - 1
        if (live & (1 << i)) != 0:
            return 600 + i
    return 0

def checksum(w:mutbuf) -> u64:
    result = 1469598103934665603
    i = 0
    while i < 16:
        if i != 8:
            result = ((result << 7) | (result >> 57)) ^ get(w, i)
        i = i + 1
    return result

def seal(w:mutbuf) -> u64:
    put(w, 8, checksum(w))
    return 0

def answer(o:mutbuf, w:mutbuf) -> u32:
    put(o, 0, @RESULT_MAGIC@)
    put(o, 1, 0)
    i = 0
    while i < 128:
        store(o, 16 + i, byte(w, i))
        i = i + 1
    return 144

def refuse(o:mutbuf, status:u64) -> u32:
    put(o, 0, @RESULT_MAGIC@)
    put(o, 1, status)
    return 16

def get(w:mutbuf, index:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(w, index * 8 + i) << (i * 8))
        i = i + 1
    return value

def read_word(s:readbuf, index:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(s, index + i) << (i * 8))
        i = i + 1
    return value

def put(w:mutbuf, index:u64, value:u64) -> u64:
    i = 0
    while i < 8:
        store(w, index * 8 + i, value >> (i * 8))
        i = i + 1
    return value
'''


def source_program():
    source = SOURCE
    for name, value in (('REQUEST_MAGIC', REQUEST_MAGIC), ('STATE_MAGIC', STATE_MAGIC),
                        ('RESULT_MAGIC', RESULT_MAGIC), ('EMIT_MAGIC', EMIT_MAGIC),
                        ('MATH_MAGIC', MATH_MAGIC),
                        ('ALL_TEMPORARIES', (1 << len(TEMPORARIES)) - 1),
                        ('CLEANUP_END', 600 + len(TEMPORARIES)), ('TEMPORARY_COUNT', len(TEMPORARIES))):
        source = source.replace('@' + name + '@', str(value))
    source += '\ndef created_mask(phase:u64) -> u64:\n'
    for phase, value in sorted(CREATED.items()):
        source += f'    if phase == {phase}:\n        return {value}\n'
    source += '    return 0\n'
    source += '\ndef cleared_mask(phase:u64, observed:u64) -> u64:\n'
    for phase, value in sorted(CLEARED.items()):
        source += f'    if phase == {phase}:\n'
        if type(value) is tuple:
            source += f'        return choose(observed == 0, {value[0]}, {value[1]})\n'
        else:
            source += f'        return {value}\n'
    source += '    return 0\n'
    source += '\ndef next_phase(kind:u64, phase:u64, observed:u64) -> u64:\n'
    for kind in GRAPHS:
        source += f'    if kind == {kind}:\n        return next_{kind}(phase, observed)\n'
    source += '    return 18446744073709551615\n'
    for kind, graph in GRAPHS.items():
        # Split the large context policy without raising the compiler's CFG
        # block limit or transforming an original rejected compilation.
        chunks = [list(graph.items())[i:i + 24] for i in range(0, len(graph), 24)]
        source += f'\ndef next_{kind}(phase:u64, observed:u64) -> u64:\n'
        for index, chunk in enumerate(chunks):
            source += f'    if phase <= {max(p for p, _ in chunk)}:\n        return next_{kind}_{index}(phase, observed)\n'
        source += '    return 18446744073709551615\n'
        for index, chunk in enumerate(chunks):
            source += f'\ndef next_{kind}_{index}(phase:u64, observed:u64) -> u64:\n'
            for phase, target in chunk:
                source += f'    if phase == {phase}:\n'
                if type(target) is tuple:
                    source += ('        if observed > 1:\n            return 18446744073709551615\n'
                               f'        return choose(observed == 1, {target[1]}, {target[0]})\n')
                else:
                    source += ('        if observed != 0:\n            return 18446744073709551615\n'
                               f'        return {target}\n')
            source += '    return 18446744073709551615\n'
    return source + '\n' + DELIVERY_BODY + '\n' + arithmetic_body()


def document():
    nodes = ast.parse(source_program()).body
    names = {node.name: 'f' + str(i) for i, node in enumerate(nodes)}
    signatures = {node.name: ([a.annotation.id for a in node.args.args], node.returns.id)
                  for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = Builder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(v) for v in builder.params],
            'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
            'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8',
        'module': 'service_context', 'functions': functions})


def main():
    target = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap/service_context.hepta'
    target.write_text(render_assembly(document()))
    print(target.name, target.stat().st_size)


if __name__ == '__main__':
    main()
