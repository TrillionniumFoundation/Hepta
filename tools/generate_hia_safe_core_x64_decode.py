"""Generate the closed Safe Core x86 decoder independently of machine emission."""
from __future__ import annotations

import ast
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_safe_core_x64_decode_native import MAX_INSTRUCTIONS, MAX_TEXT, OPERATION_IDS, REFUSAL_IDS, WORKSPACE
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

SOURCE_PATH = 'examples/hia_bootstrap/safe_core_x64_decode.hepta'
FIELDS = {
    'CURSOR': 0, 'ERROR': 8, 'MODE': 16, 'GROUP': 24, 'REG': 32, 'RM': 40, 'DISP': 48,
    'OP': 64, 'A': 72, 'B': 80, 'C': 88,
    'BOUNDARIES': 128, 'MAX_TEXT': MAX_TEXT, 'MAX_CODE': MAX_INSTRUCTIONS, 'WORKSPACE': WORKSPACE,
}
FIELDS.update({'OP_' + name.upper(): index for name, index in OPERATION_IDS.items()})
FIELDS.update({'E_' + name.upper(): index for name, index in REFUSAL_IDS.items()})

SOURCE = r'''
def decode_text(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    size = length(s)
    if length(o) < 24 or length(w) < WORKSPACE:
        return 4294967294
    if size == 0 or size > MAX_TEXT:
        return terminal(o, E_TEXT_BUDGET, 0, 0)
    if length(o) < 24 + choose(size < MAX_CODE, size, MAX_CODE) * 48:
        return 4294967294
    put(w, CURSOR, 0)
    put(w, ERROR, 0)
    index = 0
    while index < size:
        store(w, BOUNDARIES + index, 0)
        index = index + 1
    count = 0
    while get(w, CURSOR) < size:
        begin = get(w, CURSOR)
        decode_instruction(s, w)
        error = get(w, ERROR)
        if error != 0:
            return terminal(o, error, begin, 0)
        if count == MAX_CODE:
            return terminal(o, E_INSTRUCTION_BUDGET, begin, 0)
        row = 24 + count * 48
        store(w, BOUNDARIES + begin, 1)
        put(o, row, begin)
        put(o, row + 8, get(w, OP))
        put(o, row + 16, get(w, CURSOR) - begin)
        put(o, row + 24, get(w, A))
        put(o, row + 32, get(w, B))
        put(o, row + 40, get(w, C))
        count = count + 1
    return review_targets(o, w, size, count)

def review_targets(o:mutbuf, w:mutbuf, size:u64, count:u64) -> u64:
    index = 0
    while index < count:
        row = 24 + index * 48
        op = get(o, row + 8)
        if op == OP_JMP or op == OP_JCC:
            target = get(o, row + choose(op == OP_JMP, 24, 32))
            if target >= size:
                return terminal(o, E_TARGET, get(o, row), 0)
            if byte(w, BOUNDARIES + target) != 1:
                return terminal(o, E_TARGET, get(o, row), 0)
        if op == OP_JCC or op == OP_SETCC:
            condition = get(o, row + 24)
            if condition < 2 or condition > 7:
                return terminal(o, E_CONDITION, get(o, row), 0)
        index = index + 1
    return terminal(o, 0, 0, count)

def terminal(o:mutbuf, error:u64, detail:u64, count:u64) -> u64:
    put(o, 0, error)
    put(o, 8, detail)
    put(o, 16, count)
    return 24 + count * 48

def get(w:mutbuf, offset:u64) -> u64:
    value = 0
    index = 0
    while index < 8:
        value = value | (byte(w, offset + index) << (8 * index))
        index = index + 1
    return value

def put(w:mutbuf, offset:u64, value:u64) -> u64:
    index = 0
    while index < 8:
        store(w, offset + index, (value >> (8 * index)) & 255)
        index = index + 1
    return 0

def fail(w:mutbuf, reason:u64) -> u64:
    if get(w, ERROR) == 0:
        put(w, ERROR, reason)
    return 0

def take(s:readbuf, w:mutbuf, count:u64) -> u64:
    if get(w, ERROR) != 0:
        return 0
    offset = get(w, CURSOR)
    if count > length(s) - offset:
        return fail(w, E_TRUNCATED)
    value = 0
    index = 0
    while index < count:
        value = value | (byte(s, offset + index) << (8 * index))
        index = index + 1
    put(w, CURSOR, offset + count)
    return value

def take_signed(s:readbuf, w:mutbuf, count:u64) -> u64:
    value = take(s, w, count)
    bits = count * 8
    if (value & (1 << (bits - 1))) != 0:
        return value - (1 << bits)
    return value

def emit(w:mutbuf, op:u64, left:u64, right:u64, extra:u64) -> u64:
    put(w, OP, op)
    put(w, A, left)
    put(w, B, right)
    put(w, C, extra)
    return 0

def modrm(s:readbuf, w:mutbuf, rex:u64) -> u64:
    raw = take(s, w, 1)
    mode = raw >> 6
    group = (raw >> 3) & 7
    low = raw & 7
    if mode != 2 and mode != 3:
        return fail(w, E_MODE)
    put(w, MODE, mode)
    put(w, GROUP, group)
    put(w, REG, group + ((rex & 4) << 1))
    put(w, RM, low + ((rex & 1) << 3))
    disp = 0
    if mode == 2:
        if low == 4 and take(s, w, 1) != 0x24:
            return fail(w, E_SIB)
        disp = take_signed(s, w, 4)
    put(w, DISP, disp)
    return 0

def alu_operation(opcode:u64) -> u64:
    if opcode == 0x01:
        return OP_ADD
    if opcode == 0x29:
        return OP_SUB
    if opcode == 0x21:
        return OP_AND
    if opcode == 0x09:
        return OP_OR
    if opcode == 0x31:
        return OP_XOR
    if opcode == 0x39:
        return OP_CMP
    if opcode == 0x85:
        return OP_TEST
    return 0

def decode_extension(s:readbuf, w:mutbuf, rex:u64) -> u64:
    extension = take(s, w, 1)
    wide = (rex & 8) != 0
    if extension >= 0x80 and extension <= 0x8f:
        if rex != 0:
            return fail(w, E_CONDITIONAL_PREFIX)
        relative = take_signed(s, w, 4)
        return emit(w, OP_JCC, extension & 15, get(w, CURSOR) + relative, 0)
    if extension == 0x0b:
        if rex != 0:
            return fail(w, E_UD2_PREFIX)
        return emit(w, OP_UD2, 0, 0, 0)
    is_set = extension >= 0x90 and extension <= 0x9f
    if (extension < 0x90 or extension > 0x9f) and extension != 0x45 and extension != 0xaf and extension != 0xb6:
        return fail(w, E_OPCODE_0F)
    modrm(s, w, rex)
    mode = get(w, MODE)
    reg = get(w, REG)
    rm = get(w, RM)
    if is_set:
        if wide or mode != 3 or get(w, GROUP) != 0 or (rex & 4) != 0 or rex == 0:
            return fail(w, E_SETCC)
        return emit(w, OP_SETCC, extension & 15, rm, 0)
    if extension == 0xb6:
        if (rex & 8) == 0 or mode != 2:
            return fail(w, E_LOAD8)
        return emit(w, OP_LOAD8, reg, rm, get(w, DISP))
    if (rex & 8) == 0 or mode != 3:
        return fail(w, choose(extension == 0x45, E_CMOVNE, E_IMUL))
    return emit(w, choose(extension == 0x45, OP_CMOVNE, OP_IMUL), reg, rm, 0)

def decode_operands(s:readbuf, w:mutbuf, rex:u64, opcode:u64) -> u64:
    alu = alu_operation(opcode)
    if alu == 0 and opcode != 0x89 and opcode != 0x8b and opcode != 0x8d and opcode != 0x88 and opcode != 0x81 and opcode != 0x83 and opcode != 0xc1 and opcode != 0xf7:
        return fail(w, E_OPCODE)
    modrm(s, w, rex)
    wide = (rex & 8) != 0
    mode = get(w, MODE)
    group = get(w, GROUP)
    reg = get(w, REG)
    rm = get(w, RM)
    disp = get(w, DISP)
    if opcode == 0x88:
        if wide or rex == 0 or mode != 2:
            return fail(w, E_STORE8)
        return emit(w, OP_STORE8, rm, disp, reg)
    if opcode == 0x89 or opcode == 0x8b or opcode == 0x8d:
        if (rex & 8) == 0:
            return fail(w, E_MOVE_WIDTH)
        if opcode == 0x89:
            if mode == 3:
                return emit(w, OP_MOV, rm, reg, 0)
            return emit(w, OP_STORE, rm, disp, reg)
        if mode != 2:
            return fail(w, E_MOVE_MODE)
        return emit(w, choose(opcode == 0x8b, OP_LOAD, OP_LEA), reg, rm, disp)
    if alu != 0:
        if (rex & 8) == 0 or mode != 3:
            return fail(w, E_ALU_WIDTH)
        return emit(w, alu, rm, reg, 0)
    invalid_group = (rex & 8) == 0 or mode != 3 or (rex & 4) != 0
    if opcode == 0x81 or opcode == 0x83:
        if invalid_group or group == 2 or group == 3:
            return fail(w, E_IMMEDIATE_ALU)
        immediate = take_signed(s, w, choose(opcode == 0x81, 4, 1))
        return emit(w, OP_IMMEDIATE_ALU, group, rm, immediate)
    if opcode == 0xc1:
        count = take(s, w, 1)
        if invalid_group or (group != 4 and group != 5) or count >= 64:
            return fail(w, E_SHIFT)
        return emit(w, choose(group == 4, OP_SHL, OP_SHR), rm, count, 0)
    if invalid_group or group != 2:
        return fail(w, E_UNARY)
    return emit(w, OP_NOT, rm, 0, 0)

def decode_instruction(s:readbuf, w:mutbuf) -> u64:
    opcode = take(s, w, 1)
    rex = 0
    if opcode >= 0x40 and opcode <= 0x4f:
        rex = opcode
        if (rex & 2) != 0:
            return fail(w, E_INDEXED)
        opcode = take(s, w, 1)
    high_b = (rex & 1) << 3
    if opcode >= 0x50 and opcode <= 0x5f:
        if rex != 0 and rex != 0x41:
            return fail(w, E_STACK_PREFIX)
        return emit(w, choose(opcode < 0x58, OP_PUSH, OP_POP), (opcode & 7) + high_b, 0, 0)
    if opcode >= 0xb8 and opcode <= 0xbf:
        if rex != 0 and rex != 0x41 and rex != 0x48 and rex != 0x49:
            return fail(w, E_IMM_PREFIX)
        immediate = take(s, w, choose((rex & 8) != 0, 8, 4))
        return emit(w, OP_IMM, (opcode & 7) + high_b, immediate, 0)
    if opcode == 0xc3 or opcode == 0xc9 or opcode == 0x90:
        if rex != 0:
            return fail(w, E_SINGLE_PREFIX)
        single = choose(opcode == 0xc3, OP_RET, choose(opcode == 0xc9, OP_LEAVE, OP_NOP))
        return emit(w, single, 0, 0, 0)
    if opcode == 0xe8 or opcode == 0xe9:
        if rex != 0:
            return fail(w, E_BRANCH_PREFIX)
        relative = take_signed(s, w, 4)
        return emit(w, choose(opcode == 0xe8, OP_CALL, OP_JMP), get(w, CURSOR) + relative, 0, 0)
    if opcode == 0x0f:
        return decode_extension(s, w, rex)
    return decode_operands(s, w, rex, opcode)
'''


def document():
    class Constants(ast.NodeTransformer):
        def visit_Name(self, node):
            return ast.copy_location(ast.Constant(FIELDS[node.id]), node) if node.id in FIELDS else node

    nodes = ast.fix_missing_locations(Constants().visit(ast.parse(SOURCE))).body
    names = {node.name: f'f{index}' for index, node in enumerate(nodes)}
    signatures = {node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id)
                  for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = Builder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(value) for value in builder.params],
                          'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
                          'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8', 'module': 'safe_core_x64_decode',
                                  'functions': functions})


if __name__ == '__main__':
    target = Path(__file__).resolve().parents[1] / SOURCE_PATH
    target.write_text(render_assembly(document()))
