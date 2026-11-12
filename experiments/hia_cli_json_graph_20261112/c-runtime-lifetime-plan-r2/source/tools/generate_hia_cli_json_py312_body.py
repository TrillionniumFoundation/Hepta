"""HIA instruction/exception continuation for the three original JSON generators.

The immutable instruction packet is derived from the retained 3.12.14 source
without executing it.  Runtime admission must bind that packet to the actual
generator code object, globals, closure cells and constant/name tuples.  All
objects stay in that generator's real localsplus stack, or in one explicit
raw owned result.  No handle list, copied locals map or eager str conversion
is a substitute for those references.

This is a component, not the complete evaluator driver. Operations 240--244
are explicit integration requests: CALL routing, SEND, raw-stack UNPACK,
entry/monitoring and eval-breaker.  They have
no retained-body fallback.  Source/Core validation does not qualify these
missing bindings, C recursion/monitoring, specialization, throw/close or the
removal of Python transport GC windows. Default CLI and original 17/46 stay
unchanged. This authoring source has not been generated or executed.
"""
from __future__ import annotations

import ast
from pathlib import Path

SYMBOLS = {
    'MAGIC': int.from_bytes(b'HCLIBDY1', 'little'),
    'PACKET_MAGIC': int.from_bytes(b'HCLIBC31', 'little'),
    'ABI': 4294967293, 'NO_HANDLER': 18446744073709551615,
    'PHASE': 8, 'SEQUENCE': 16, 'PENDING': 24,
    'REPLY_SEQUENCE': 32, 'REPLY_OPERATION': 40, 'RAISED': 48,
    'OPERATION': 64, 'ARGUMENTS': 72, 'FINAL': 112,
    'GENERATOR': 120, 'CODE': 128, 'PARENT': 136, 'PC': 144,
    'ACTUAL_PC': 152, 'UNITS': 160, 'TOP': 168, 'LOCALS': 176,
    'NEXT': 184, 'TARGET': 192, 'OPCODE': 200, 'OPARG': 208,
    'KWNAMES': 216, 'HANDLER': 224, 'DEPTH': 232, 'LASTI': 240,
    'ANSWER': 256, 'SLOT': 320, 'ERROR_TRACE': 328,
    'DROP_LEFT': 336, 'NAME': 344, 'GLOBALS': 352, 'BUILTINS': 360,
    'ENTRY_MODE': 368, 'UNWIND_TOP': 376, 'TRACEBACK_HANDLED': 384,
    'CALL_KIND': 392,
}

SOURCE = r'''
def cli_json_py312_body(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) != 1024 or get(w, 0) != MAGIC or get(w, FINAL) != 0:
        return ABI
    if length(s) < 64 or read(s, 0) != PACKET_MAGIC or read(s, 8) != 31214:
        return ABI
    units = read(s, 16)
    if units == 0 or units > 288230376151711742 or length(s) != 64 + units * 64:
        return ABI
    if get(w, PENDING) != 0:
        if get(w, REPLY_SEQUENCE) != get(w, SEQUENCE) or get(w, REPLY_OPERATION) != get(w, OPERATION):
            return ABI
        put(w, PENDING, 0)
    elif get(w, PHASE) != 0:
        return ABI
    if get(w, PHASE) == 0:
        if get(w, GENERATOR) == 0 or get(w, CODE) == 0 or get(w, SLOT) != 0 or get(w, PC) >= units or get(w, ENTRY_MODE) > 1:
            return ABI
        if get(w, ENTRY_MODE) == 0:
            if get(w, RAISED) != 0:
                return ABI
        elif get(w, RAISED) == 0:
            return ABI
        put(w, UNITS, units)
        put(w, KWNAMES, 0)
        put(w, TRACEBACK_HANDLED, 0)
        return request(w, 95, get(w, GENERATOR), 0, 0, 0, 0, 1)
    while True:
        phase = get(w, PHASE)
        if phase < 10:
            status = enter(s, w, phase)
        elif phase == 10:
            status = decode(s, w)
        elif phase < 100:
            status = completed(s, w, phase)
        elif phase < 200:
            status = globals(w, phase)
        elif phase < 800:
            status = exits(w, phase)
        else:
            status = unwind(s, w, phase)
        if status != 4:
            return status
    return ABI

def enter(s:readbuf, w:mutbuf, phase:u64) -> u64:
    if phase == 1:
        if answer(w, 0) != get(w, CODE) or answer(w, 2) != read(s, 40) or answer(w, 3) != read(s, 48):
            return ABI
        top = answer(w, 4)
        if top < answer(w, 2) or top - answer(w, 2) > answer(w, 3):
            return ABI
        state = answer(w, 6)
        if state != 0 and state != 18446744073709551614 and state != 18446744073709551615:
            return ABI
        put(w, LOCALS, answer(w, 2))
        put(w, TOP, top)
        # Actual entry/throw/resume and its owned send value are a separate
        # driver event. It must bind original runtime state before returning.
        return request(w, 243, get(w, GENERATOR), get(w, ENTRY_MODE), get(w, PC), get(w, ACTUAL_PC), 0, 2)
    if phase == 2:
        if get(w, ENTRY_MODE) == 1:
            if get(w, RAISED) == 0:
                return ABI
            put(w, ERROR_TRACE, 1)
            put(w, PHASE, 800)
            return 4
        if get(w, RAISED) != 0:
            return error(w, 1)
        put(w, PHASE, 10)
        return 4
    return ABI

def decode(s:readbuf, w:mutbuf) -> u64:
    pc = get(w, PC)
    if pc >= get(w, UNITS) or field(s, pc, 56) != 1 or get(w, SLOT) != 0 or get(w, RAISED) != 0:
        return ABI
    opcode = field(s, pc, 0)
    argument = field(s, pc, 8)
    following = field(s, pc, 16)
    if following > get(w, UNITS):
        return ABI
    put(w, OPCODE, opcode)
    put(w, OPARG, argument)
    put(w, NEXT, following)
    put(w, TARGET, field(s, pc, 24))
    put(w, ACTUAL_PC, pc)
    put(w, TRACEBACK_HANDLED, 0)
    if opcode < 90:
        return low(w, opcode, argument)
    if opcode < 128:
        return middle(w, opcode, argument)
    return high(w, opcode, argument)

def low(w:mutbuf, opcode:u64, argument:u64) -> u64:
    gen = get(w, GENERATOR)
    if opcode == 1 or opcode == 4:
        put(w, DROP_LEFT, choose(opcode == 4, 2, 1))
        return request(w, 100, gen, 0, 0, 0, 0, 30)
    if opcode == 2:
        return request(w, 102, gen, 0, 0, 0, 0, 22)
    if opcode == 5:
        return request(w, 135, gen, 0, 0, 0, 0, 22)
    if opcode == 9:
        return advance(w)
    if opcode == 35:
        return request(w, 132, gen, 0, 0, 0, 0, 22)
    if opcode == 55:
        return request(w, 136, gen, 0, 0, 0, 0, 205)
    if opcode == 60:
        return request(w, 123, gen, 0, 0, 0, 0, 22)
    if opcode == 61:
        return request(w, 124, gen, 0, 0, 0, 0, 22)
    if opcode == 68:
        return request(w, 118, gen, 0, 0, 0, 0, 20)
    if opcode == 69:
        return request(w, 119, gen, 0, 0, 0, 0, 20)
    if opcode == 83:
        return request(w, 100, gen, 0, 0, 0, 0, 201)
    if opcode == 89:
        return request(w, 133, gen, 0, 0, 0, 0, 22)
    return ABI

def middle(w:mutbuf, opcode:u64, argument:u64) -> u64:
    gen = get(w, GENERATOR)
    if opcode == 92:
        # The shared HIA UNPACK algorithm needs an owned value-stack export.
        # Its public tuple-returning adapter is not an equivalent substitute.
        return request(w, 242, gen, argument, get(w, PC), 0, 0, 22)
    if opcode == 93:
        # The integration owner routes known HIA generators before any
        # foreign current-tp_iternext leaf. Success leaves one owned item.
        return request(w, 241, gen, 0, get(w, PC), get(w, TARGET), 0, 40)
    if opcode == 99:
        if argument < 2:
            return ABI
        return request(w, 109, gen, argument - 1, 0, 0, 0, 22)
    if opcode == 100:
        return request(w, 114, gen, argument, 0, 0, 0, 20)
    if opcode == 102:
        return request(w, 125, gen, argument, 0, 0, 0, 20)
    if opcode == 106:
        return request(w, 126, gen, argument, 0, 0, 0, 22)
    if opcode == 110:
        return jump(w, get(w, TARGET))
    if opcode == 114 or opcode == 115:
        return request(w, 116, gen, 0, 0, 0, 0, 23)
    if opcode == 116:
        return request(w, 115, gen, argument >> 1, 0, 0, 0, 100)
    if opcode == 117:
        return request(w, 122, gen, argument, 0, 0, 0, 20)
    if opcode == 118:
        return request(w, 121, gen, argument, 0, 0, 0, 20)
    if opcode == 119:
        return request(w, 131, gen, argument, 0, 0, 0, 204)
    if opcode == 120:
        if argument == 0:
            return ABI
        return request(w, 112, gen, argument - 1, 0, 0, 0, 20)
    if opcode == 121:
        return request(w, 114, gen, argument, 0, 0, 0, 201)
    if opcode == 122:
        return request(w, 117, gen, argument, 0, 0, 0, 20)
    if opcode == 123:
        return request(w, 241, gen, 1, get(w, PC), get(w, TARGET), 0, 41)
    if opcode == 124 or opcode == 127:
        return request(w, 99, gen, argument, 0, 0, 0, 24)
    if opcode == 125:
        return request(w, 138, gen, argument, 0, 0, 0, 22)
    return ABI

def high(w:mutbuf, opcode:u64, argument:u64) -> u64:
    gen = get(w, GENERATOR)
    if opcode == 128 or opcode == 129:
        return request(w, 116, gen, 1, 0, 0, 0, 23)
    if opcode == 130:
        return request(w, 130, gen, argument, 0, 0, 0, 203)
    if opcode == 134:
        return jump(w, get(w, TARGET))
    if opcode == 136:
        return request(w, 99, gen, argument, 0, 0, 0, 24)
    if opcode == 137:
        return request(w, 104, gen, argument, 0, 0, 0, 24)
    if opcode == 138:
        return request(w, 138, gen, argument, 1, 0, 0, 22)
    if opcode == 140:
        return request(w, 244, gen, get(w, PC), 1, 0, 0, 42)
    if opcode == 144:
        # Packet operands already contain the complete EXTENDED_ARG value.
        return advance(w)
    if opcode == 150:
        return request(w, 100, gen, 0, 0, 0, 0, 200)
    if opcode == 151:
        return request(w, 244, gen, get(w, PC), 2, argument, 0, 22)
    if opcode == 155:
        return request(w, 127, gen, argument, 0, 0, 0, 20)
    if opcode == 157:
        return request(w, 128, gen, argument, 0, 0, 0, 20)
    if opcode == 171:
        # No direct fallback to the old scalar/sort/JSON generator body.
        # HIA call routing examines actual callable identity and owned args.
        return request(w, 240, gen, argument, get(w, KWNAMES), get(w, PC), 0, 43)
    if opcode == 172:
        return request(w, 114, gen, argument, 1, 0, 0, 110)
    if opcode == 173 and argument == 3:
        return request(w, 134, gen, 0, 0, 0, 0, 20)
    return ABI

def completed(s:readbuf, w:mutbuf, phase:u64) -> u64:
    gen = get(w, GENERATOR)
    if phase == 20:
        if get(w, RAISED) != 0:
            if get(w, SLOT) != 0:
                return ABI
            return error(w, 1)
        if get(w, SLOT) == 0:
            return ABI
        return request(w, 101, gen, 0, 0, 0, 0, 21)
    if phase == 21 or phase == 22:
        if get(w, RAISED) != 0:
            return error(w, 1)
        if get(w, SLOT) != 0:
            return ABI
        return advance(w)
    if phase == 23:
        if get(w, RAISED) != 0:
            return error(w, 1)
        if answer(w, 0) > 1 or get(w, SLOT) != 0:
            return ABI
        opcode = get(w, OPCODE)
        taken = answer(w, 0) == 1
        if opcode == 114 or opcode == 128:
            taken = answer(w, 0) == 0
        if taken:
            return jump(w, get(w, TARGET))
        return advance(w)
    if phase == 24:
        if get(w, RAISED) != 0:
            return error(w, 1)
        if get(w, SLOT) != 0:
            put(w, PHASE, 20)
            return 4
        if get(w, OPCODE) == 124:
            return ABI
        return request(w, 139, gen, get(w, OPARG), choose(get(w, OPCODE) == 137, 1, 0), 0, 0, 202)
    if phase == 30:
        if get(w, RAISED) != 0 or get(w, SLOT) == 0 or get(w, SLOT) != answer(w, 0):
            return ABI
        return request(w, 6, 0, 0, 0, 0, 0, 31)
    if phase == 31:
        if get(w, RAISED) != 0:
            return error(w, 1)
        if get(w, SLOT) != 0 or get(w, DROP_LEFT) == 0:
            return ABI
        remaining = get(w, DROP_LEFT) - 1
        put(w, DROP_LEFT, remaining)
        if remaining != 0:
            return request(w, 100, gen, 0, 0, 0, 0, 30)
        return advance(w)
    if phase == 40 or phase == 41:
        if get(w, RAISED) != 0:
            return error(w, 1)
        # The routed next/SEND returns {item-or-return, original jump flag}.
        # FOR_ITER exhaustion consumes its iterator; SEND retains receiver.
        flag = answer(w, 2)
        if flag > 1:
            return ABI
        if phase == 40 and flag == 0:
            if get(w, SLOT) != 0:
                return ABI
            return jump(w, get(w, TARGET) + 1)
        if get(w, SLOT) == 0:
            return ABI
        if phase == 41 and flag == 0:
            put(w, NEXT, get(w, TARGET))
        return request(w, 101, gen, 0, 0, 0, 0, 21)
    if phase == 42:
        if get(w, RAISED) != 0:
            return error(w, 1)
        return jump(w, get(w, TARGET))
    if phase == 43:
        put(w, KWNAMES, 0)
        if get(w, RAISED) != 0:
            return error(w, 1)
        if get(w, SLOT) == 0 or answer(w, 2) < 1 or answer(w, 2) > 2:
            return ABI
        put(w, CALL_KIND, answer(w, 2))
        return request(w, 101, gen, 0, 0, 0, 0, 44)
    if phase == 44:
        if get(w, RAISED) != 0 or get(w, SLOT) != 0:
            return ABI
        # The generated original CALL pushes its result BEFORE the generic
        # call's eval-breaker. A failure there unwinds that actual stack
        # owner. The inlined-Python return has no such CALL-site breaker.
        if get(w, CALL_KIND) == 2:
            return request(w, 244, gen, get(w, PC), 3, 0, 0, 22)
        return advance(w)
    return ABI

def globals(w:mutbuf, phase:u64) -> u64:
    gen = get(w, GENERATOR)
    if phase == 100:
        if get(w, RAISED) != 0 or answer(w, 0) == 0:
            return ABI
        put(w, NAME, answer(w, 0))
        return request(w, 111, gen, 0, 0, 0, 0, 101)
    if phase == 101:
        put(w, GLOBALS, answer(w, 0))
        put(w, BUILTINS, answer(w, 1))
        return request(w, 82, answer(w, 0), answer(w, 1), get(w, NAME), 0, 0, 102)
    if phase == 102:
        if get(w, RAISED) != 0:
            return error(w, 1)
        if get(w, SLOT) == 0:
            return ABI
        if (get(w, OPARG) & 1) != 0:
            return request(w, 102, gen, 0, 0, 0, 0, 20)
        put(w, PHASE, 20)
        return 4
    if phase == 110:
        if get(w, RAISED) != 0 or get(w, SLOT) != 0 or answer(w, 0) == 0:
            return ABI
        # KW_NAMES borrows directly from co_consts. No temporary INCREF,
        # result owner or later DECREF is inserted.
        put(w, KWNAMES, answer(w, 0))
        return advance(w)
    return ABI

def exits(w:mutbuf, phase:u64) -> u64:
    if phase == 200 or phase == 201:
        if get(w, RAISED) != 0:
            return error(w, 1)
        if get(w, SLOT) == 0:
            return ABI
        if phase == 200:
            put(w, FINAL, 4)
            return 3
        put(w, FINAL, 1)
        return 0
    if phase == 202:
        if get(w, RAISED) == 0 or get(w, SLOT) != 0:
            return ABI
        return error(w, 1)
    if phase == 203:
        if get(w, RAISED) == 0 or get(w, SLOT) != 0 or answer(w, 0) > 1:
            return ABI
        return error(w, choose(answer(w, 0) == 1, 0, 1))
    if phase == 204:
        if get(w, RAISED) == 0 or get(w, SLOT) != 0:
            return ABI
        if answer(w, 2) == 0:
            put(w, ACTUAL_PC, answer(w, 0))
            return error(w, 0)
        return error(w, 1)
    if phase == 205:
        if get(w, RAISED) != 0:
            return error(w, 0)
        return advance(w)
    return ABI

def error(w:mutbuf, traceback:u64) -> u64:
    if get(w, RAISED) == 0 or get(w, SLOT) != 0:
        return ABI
    put(w, KWNAMES, 0)
    put(w, ERROR_TRACE, traceback)
    put(w, PHASE, 800)
    return 4

def unwind(s:readbuf, w:mutbuf, phase:u64) -> u64:
    gen = get(w, GENERATOR)
    if phase == 800:
        if get(w, RAISED) == 0 or get(w, SLOT) != 0:
            return ABI
        if get(w, ERROR_TRACE) != 0:
            return request(w, 97, gen, get(w, ACTUAL_PC), 0, 0, 0, 801)
        put(w, PHASE, 801)
        return 4
    if phase == 801:
        if get(w, RAISED) == 0 or get(w, SLOT) != 0:
            return ABI
        # This includes the original no-new-traceback RERAISE route. The
        # terminal lifetime owner must not append another traceback.
        put(w, TRACEBACK_HANDLED, 1)
        pc = get(w, PC)
        handler = field(s, pc, 32)
        if handler == NO_HANDLER:
            put(w, FINAL, 2)
            return 1
        if handler >= get(w, UNITS):
            return ABI
        packed = field(s, pc, 40)
        put(w, HANDLER, handler)
        put(w, DEPTH, packed >> 1)
        put(w, LASTI, packed & 1)
        return request(w, 95, gen, 0, 0, 0, 0, 802)
    if phase == 802:
        top = answer(w, 4)
        locals = get(w, LOCALS)
        depth = get(w, DEPTH)
        if top < locals or depth > top - locals:
            return ABI
        put(w, TOP, top)
        put(w, UNWIND_TOP, locals + depth)
        put(w, PHASE, 803)
        return 4
    if phase == 803:
        if get(w, TOP) > get(w, UNWIND_TOP):
            return request(w, 100, gen, 0, 0, 0, 0, 804)
        if get(w, LASTI) != 0:
            return request(w, 137, gen, 0, 0, 0, 0, 806)
        put(w, PHASE, 808)
        return 4
    if phase == 804:
        if answer(w, 1) + 1 != get(w, TOP) or answer(w, 1) < get(w, UNWIND_TOP):
            return ABI
        put(w, TOP, answer(w, 1))
        if get(w, SLOT) != 0:
            return request(w, 6, 0, 0, 0, 0, 0, 805)
        put(w, PHASE, 803)
        return 4
    if phase == 805:
        if get(w, SLOT) != 0 or get(w, RAISED) == 0:
            return ABI
        put(w, PHASE, 803)
        return 4
    if phase == 806:
        if get(w, RAISED) == 0:
            return ABI
        if get(w, SLOT) == 0:
            # Original exception_unwind restarts its same table lookup when
            # creating lasti fails; it does not synthesize a second traceback.
            put(w, PHASE, 801)
            return 4
        return request(w, 101, gen, 0, 0, 0, 0, 808)
    if phase == 808:
        if get(w, SLOT) != 0 or get(w, RAISED) == 0:
            return ABI
        return request(w, 129, gen, 0, 0, 0, 0, 809)
    if phase == 809:
        if get(w, SLOT) == 0 or get(w, RAISED) != 0:
            return ABI
        return request(w, 101, gen, 0, 0, 0, 0, 810)
    if phase == 810:
        if get(w, SLOT) != 0 or get(w, RAISED) != 0:
            return ABI
        return request(w, 244, gen, get(w, HANDLER), 4, 0, 0, 811)
    if phase == 811:
        if get(w, RAISED) != 0:
            # monitor_handled runs after JUMPTO(handler); the original
            # exception_unwind retries at next_instr - 1, NOT at the old
            # failing opcode. Packet handler rows include CACHE words.
            handler = get(w, HANDLER)
            if handler == 0:
                return ABI
            put(w, PC, handler - 1)
            put(w, PHASE, 801)
            return 4
        return jump(w, get(w, HANDLER))
    return ABI

def advance(w:mutbuf) -> u64:
    return jump(w, get(w, NEXT))

def jump(w:mutbuf, target:u64) -> u64:
    if target >= get(w, UNITS):
        return ABI
    put(w, PC, target)
    put(w, PHASE, 10)
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

def field(s:readbuf, pc:u64, at:u64) -> u64:
    return read(s, 64 + pc * 64 + at)

def read(s:readbuf, at:u64) -> u64:
    value = 0
    index = 0
    while index < 8:
        value = value | (byte(s, at + index) << (index * 8))
        index = index + 1
    return value

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
        raise ValueError('only complete body-controller function definitions are admitted')
    names = {node.name: 'f' + str(index) for index, node in enumerate(nodes)}
    if len(names) != len(nodes):
        raise ValueError('duplicate body-controller function')
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
                                  'module': 'cli_json_py312_body', 'functions': functions})


if __name__ == '__main__':
    import argparse
    from hepta.hia_agent_assembly import render_assembly
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    with args.output.open('x') as stream:
        stream.write(render_assembly(document()))
