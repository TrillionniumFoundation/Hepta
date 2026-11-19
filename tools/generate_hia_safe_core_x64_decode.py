"""Generate the closed Safe Core x86 decoder independently of machine emission."""
from __future__ import annotations

import ast
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_safe_core_x64_decode_native import (
    CORE_FORMULA_IDS, CORE_GRAPH_LIMIT, CORE_GRAPH_REQUEST, MAX_INSTRUCTIONS, MAX_RECIPE_NODES, MAX_TEXT,
    OPERATION_IDS, RECIPE_IDS, RECIPE_INPUTS,
    REFUSAL_IDS, SCHEDULER_BITMAP, SCHEDULER_FRAMES, SCHEDULER_HEADER, SCHEDULER_VISITS,
    SCHEDULER_WORKSPACE, WORKSPACE,
)
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

SOURCE_PATH = 'examples/hia_bootstrap/safe_core_x64_decode.hepta'
FIELDS = {
    'CURSOR': 0, 'ERROR': 8, 'MODE': 16, 'GROUP': 24, 'REG': 32, 'RM': 40, 'DISP': 48,
    'OP': 64, 'A': 72, 'B': 80, 'C': 88,
    'BOUNDARIES': 128, 'MAX_TEXT': MAX_TEXT, 'MAX_CODE': MAX_INSTRUCTIONS, 'WORKSPACE': WORKSPACE,
}
FIELDS.update({'OP_' + name.upper(): index for name, index in OPERATION_IDS.items()})
FIELDS.update({'E_' + name.upper(): index for name, index in REFUSAL_IDS.items()})
FIELDS.update({'R_' + name.upper(): index for name, index in RECIPE_IDS.items()})
FIELDS.update({'C_' + name.upper().replace('.', '_'): index for name, index in CORE_FORMULA_IDS.items()})
FIELDS.update(CORE_GRAPH_LIMIT=CORE_GRAPH_LIMIT, CORE_GRAPH_SIZE=CORE_GRAPH_REQUEST.size)
FIELDS.update(MAX_RECIPE_NODES=MAX_RECIPE_NODES, RECIPE_INPUTS=RECIPE_INPUTS,
              LEFT=1, RIGHT=2, THIRD=3, ZF=3, CF=4, ARBITRARY=5)
FIELDS.update(SCHED_STEPS=0, SCHED_PATHS=8, SCHED_DEPTH=16, SCHED_PHASE=24, SCHED_ACTIVE=32,
              SCHED_HEADER=SCHEDULER_HEADER, SCHED_VISITS=SCHEDULER_VISITS,
              SCHED_BITMAP=SCHEDULER_BITMAP, SCHED_FRAMES=SCHEDULER_FRAMES,
              SCHED_WORKSPACE=SCHEDULER_WORKSPACE)

SOURCE = r'''
def decode_text(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    size = length(s)
    if size == 32 and length(w) == SCHED_WORKSPACE:
        return schedule_machine(s, o, w)
    if size == 0 and length(w) == 16:
        return machine_formula(o, get(w, 0), get(w, 8))
    if size == 0 and length(w) == 24:
        return core_scalar_formula(o, get(w, 0), get(w, 8), get(w, 16))
    if size == 0 and length(w) == 40:
        return memory_admission(w)
    if size == 0 and length(w) == CORE_GRAPH_SIZE:
        return review_core_graph(w)
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
    if length(w) != WORKSPACE:
        if length(w) < WORKSPACE + 8:
            return terminal(o, E_CALL_INVENTORY, 0, 0)
        return review_call_bindings(o, w, count, size)
    return terminal(o, 0, 0, count)

def review_call_bindings(o:mutbuf, w:mutbuf, count:u64, size:u64) -> u64:
    expected = get(w, WORKSPACE)
    if expected > MAX_CODE or length(w) != WORKSPACE + 8 + expected * 24:
        return terminal(o, E_CALL_INVENTORY, 0, 0)
    matched = 0
    first_wrong = size
    index = 0
    while index < count:
        row = 24 + index * 48
        if get(o, row + 8) == OP_CALL:
            pc = get(o, row)
            if matched >= expected:
                return terminal(o, E_CALL_INVENTORY, pc, 0)
            binding = WORKSPACE + 8 + matched * 24
            if get(w, binding) != pc:
                return terminal(o, E_CALL_INVENTORY, pc, 0)
            external = get(w, binding + 8)
            target = get(w, binding + 16)
            if external == 0 and first_wrong == size:
                if target >= size or target != get(o, row + 24):
                    first_wrong = pc
                else:
                    if byte(w, BOUNDARIES + target) != 1:
                        first_wrong = pc
            matched = matched + 1
        index = index + 1
    if matched != expected:
        return terminal(o, E_CALL_INVENTORY, 0, 0)
    if first_wrong != size:
        return terminal(o, E_CALL_TARGET, first_wrong, 0)
    return terminal(o, 0, 0, count)

def memory_admission(w:mutbuf) -> u64:
    kind = get(w, 0)
    first = get(w, 8)
    second = get(w, 16)
    size = get(w, 24)
    write = get(w, 32)
    if kind == 1:
        return choose(size == 1 and first != 0 and (write == 0 or first == 2), 1, 0)
    ceiling = choose(write == 0, 8, 0)
    sign = 9223372036854775808
    biased = first ^ sign
    if biased < (second ^ sign) or biased > (ceiling ^ sign):
        return 0
    return choose(size <= ceiling - first, 1, 0)

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

def machine_formula(o:mutbuf, op:u64, param:u64) -> u64:
    if length(o) < 40 + MAX_RECIPE_NODES * 32:
        return 4294967294
    put(o, 0, 0)
    if op == OP_JCC or op == OP_SETCC:
        condition = condition_formula(o, param)
        if condition == 0:
            return 4294967293
        if op == OP_JCC:
            return formula_done(o, 0, 0, 0, condition)
        mask = node(o, R_LITERAL64, 18446744073709551360, 0, 0)
        low = node(o, R_AND, LEFT, mask, 0)
        one = node(o, R_LITERAL64, 1, 0, 0)
        zero = node(o, R_LITERAL64, 0, 0, 0)
        bit = node(o, R_CHOOSE, condition, one, zero)
        result = node(o, R_OR, low, bit, 0)
        return formula_done(o, node(o, R_SIMPLIFY, result, 0, 0), 0, 0, 0)
    if op == OP_SHL or op == OP_SHR:
        return shift_formula(o, op, param)
    if param != 0:
        return 4294967293
    if op == OP_NOT:
        return formula_done(o, node(o, R_NOT, LEFT, 0, 0), 0, 0, 0)
    if op == OP_CMOVNE:
        take = node(o, R_BOOL_NOT, ZF, 0, 0)
        result = node(o, R_CHOOSE, take, RIGHT, LEFT)
        return formula_done(o, node(o, R_SIMPLIFY, result, 0, 0), 0, 0, 0)
    if op == OP_IMUL:
        return imul_formula(o)
    return alu_formula(o, op)

def node(o:mutbuf, code:u64, left:u64, right:u64, extra:u64) -> u64:
    count = get(o, 0)
    at = 40 + count * 32
    put(o, at, code)
    put(o, at + 8, left)
    put(o, at + 16, right)
    put(o, at + 24, extra)
    put(o, 0, count + 1)
    return RECIPE_INPUTS + count + 1

def formula_done(o:mutbuf, value:u64, zf:u64, cf:u64, branch:u64) -> u64:
    put(o, 8, value)
    put(o, 16, zf)
    put(o, 24, cf)
    put(o, 32, branch)
    return 40 + get(o, 0) * 32

def condition_formula(o:mutbuf, condition:u64) -> u64:
    if condition == 2:
        return CF
    if condition == 3:
        return node(o, R_BOOL_NOT, CF, 0, 0)
    if condition == 4:
        return ZF
    if condition == 5:
        return node(o, R_BOOL_NOT, ZF, 0, 0)
    if condition == 6:
        return node(o, R_BOOL_OR, CF, ZF, 0)
    if condition == 7:
        not_cf = node(o, R_BOOL_NOT, CF, 0, 0)
        not_zf = node(o, R_BOOL_NOT, ZF, 0, 0)
        return node(o, R_BOOL_AND, not_cf, not_zf, 0)
    return 0

def alu_formula(o:mutbuf, op:u64) -> u64:
    if op == OP_ADD:
        result = node(o, R_ADD, LEFT, RIGHT, 0)
        cf = node(o, R_ULT, result, LEFT, 0)
    else:
        if op == OP_SUB or op == OP_CMP:
            result = node(o, R_SUB, LEFT, RIGHT, 0)
            cf = node(o, R_ULT, LEFT, RIGHT, 0)
        else:
            primitive = 0
            if op == OP_AND or op == OP_TEST:
                primitive = R_AND
            if op == OP_OR:
                primitive = R_OR
            if op == OP_XOR:
                primitive = R_XOR
            if primitive == 0:
                return 4294967293
            result = node(o, primitive, LEFT, RIGHT, 0)
            cf = node(o, R_FALSE, 0, 0, 0)
    zf = node(o, R_ZERO, result, 0, 0)
    if op == OP_CMP or op == OP_TEST:
        return formula_done(o, 0, zf, cf, 0)
    return formula_done(o, node(o, R_SIMPLIFY, result, 0, 0), zf, cf, 0)

def shift_formula(o:mutbuf, op:u64, count:u64) -> u64:
    if count >= 64:
        return 4294967293
    if count == 0:
        return formula_done(o, 0, 0, 0, 0)
    left = op == OP_SHL
    shifted = node(o, choose(left, R_SHL, R_LSHR), LEFT, count, 0)
    result = node(o, R_SIMPLIFY, shifted, 0, 0)
    zf = node(o, R_ZERO, result, 0, 0)
    carry_bit = choose(left, 64 - count, count - 1)
    bit = node(o, R_EXTRACT, LEFT, carry_bit, carry_bit)
    cf = node(o, R_ONE, bit, 0, 0)
    return formula_done(o, result, zf, cf, 0)

def imul_formula(o:mutbuf) -> u64:
    # The low bits are written; carry reflects signed truncation. Undefined
    # ZF is a separate arbitrary input, never preserved or inferred.
    left = node(o, R_SIGNEXT, LEFT, 64, 0)
    right = node(o, R_SIGNEXT, RIGHT, 64, 0)
    full = node(o, R_IMUL, left, right, 0)
    low = node(o, R_EXTRACT, full, 63, 0)
    restored = node(o, R_SIGNEXT, low, 64, 0)
    cf = node(o, R_NE, full, restored, 0)
    return formula_done(o, node(o, R_SIMPLIFY, low, 0, 0), ARBITRARY, cf, 0)

def core_scalar_formula(o:mutbuf, op:u64, width:u64, literal:u64) -> u64:
    if length(o) < 40 + MAX_RECIPE_NODES * 32:
        return 4294967294
    if width != 1 and width != 8 and width != 16 and width != 32 and width != 64:
        return 4294967293
    put(o, 0, 0)
    if op == C_CONST:
        return formula_done(o, node(o, R_LITERAL64, literal, 0, 0), 0, 0, 0)
    if op >= C_BORROW_EXTENT and op <= C_BORROW_WRAP and width == 64:
        return core_borrow_formula(o, op, literal)
    if literal != 0:
        return 4294967293
    if op == C_BUFFER_ADDRESS and width == 64:
        address = node(o, R_ADD, LEFT, THIRD, 0)
        outside = node(o, R_UGE, THIRD, RIGHT, 0)
        return formula_done(o, address, 0, 0, outside)
    if op >= C_COMPARE_EQ and op <= C_COMPARE_GE:
        return core_compare_formula(o, op)
    if op == C_SELECT:
        use_then = node(o, R_NONZERO, LEFT, 0, 0)
        return formula_done(o, node(o, R_CHOOSE, use_then, RIGHT, THIRD), 0, 0, 0)
    if op >= C_INT_ADD_WRAP and op <= C_INT_SUB_CHECKED:
        return core_numeric_formula(o, op, width)
    if op == C_INT_CAST_WRAP or op == C_INT_CAST_CHECKED:
        mask = core_mask(o, width)
        value = core_normalized(o, LEFT, mask)
        trap = 0
        if op == C_INT_CAST_CHECKED:
            trap = node(o, R_UGT, LEFT, mask, 0)
        return formula_done(o, value, 0, 0, trap)
    if op == C_BIT_NOT or op == C_BOOL_NOT:
        flipped = node(o, R_NOT, LEFT, 0, 0)
        return formula_done(o, core_normalized(o, flipped, core_mask(o, width)), 0, 0, 0)
    if op == C_BIT_AND or op == C_BOOL_AND:
        return formula_done(o, node(o, R_AND, LEFT, RIGHT, 0), 0, 0, 0)
    if op == C_BIT_OR or op == C_BOOL_OR:
        return formula_done(o, node(o, R_OR, LEFT, RIGHT, 0), 0, 0, 0)
    if op == C_BIT_XOR:
        return formula_done(o, node(o, R_XOR, LEFT, RIGHT, 0), 0, 0, 0)
    return 4294967293

def core_mask(o:mutbuf, width:u64) -> u64:
    mask = 18446744073709551615
    if width < 64:
        mask = (1 << width) - 1
    return node(o, R_LITERAL64, mask, 0, 0)

def core_normalized(o:mutbuf, value:u64, mask:u64) -> u64:
    truncated = node(o, R_AND, value, mask, 0)
    return node(o, R_SIMPLIFY, truncated, 0, 0)

def core_numeric_formula(o:mutbuf, op:u64, width:u64) -> u64:
    primitive = R_SUB
    if op == C_INT_ADD_WRAP or op == C_INT_ADD_CHECKED:
        primitive = R_ADD
    if op == C_INT_MUL_WRAP:
        primitive = R_IMUL
    raw = node(o, primitive, LEFT, RIGHT, 0)
    value = core_normalized(o, raw, core_mask(o, width))
    trap = 0
    if op == C_INT_ADD_CHECKED:
        trap = node(o, R_ULT, value, LEFT, 0)
    if op == C_INT_SUB_CHECKED:
        trap = node(o, R_ULT, LEFT, RIGHT, 0)
    return formula_done(o, value, 0, 0, trap)

def core_compare_formula(o:mutbuf, op:u64) -> u64:
    primitive = R_EQ
    if op == C_COMPARE_NE:
        primitive = R_NE
    if op == C_COMPARE_LT:
        primitive = R_ULT
    if op == C_COMPARE_LE:
        primitive = R_ULE
    if op == C_COMPARE_GT:
        primitive = R_UGT
    if op == C_COMPARE_GE:
        primitive = R_UGE
    condition = node(o, primitive, LEFT, RIGHT, 0)
    one = node(o, R_LITERAL64, 1, 0, 0)
    zero = node(o, R_LITERAL64, 0, 0, 0)
    return formula_done(o, node(o, R_CHOOSE, condition, one, zero), 0, 0, 0)

def core_borrow_formula(o:mutbuf, op:u64, literal:u64) -> u64:
    if op == C_BORROW_EXTENT:
        if literal == 0 or literal > 1048576:
            return 4294967293
        extent = node(o, R_LITERAL64, literal, 0, 0)
        outside = node(o, R_UGT, RIGHT, extent, 0)
        packed = node(o, R_LITERAL64, 4294967296, 0, 0)
        return formula_done(o, packed, 0, 0, outside)
    if literal != 0:
        return 4294967293
    nonempty = node(o, R_NONZERO, RIGHT, 0, 0)
    if op == C_BORROW_NULL:
        zero = node(o, R_ZERO, LEFT, 0, 0)
        outside = node(o, R_BOOL_AND, nonempty, zero, 0)
        packed = node(o, R_LITERAL64, 8589934592, 0, 0)
        return formula_done(o, packed, 0, 0, outside)
    end = node(o, R_ADD, LEFT, RIGHT, 0)
    wraps = node(o, R_ULT, end, LEFT, 0)
    outside = node(o, R_BOOL_AND, nonempty, wraps, 0)
    packed = node(o, R_LITERAL64, 12884901888, 0, 0)
    return formula_done(o, packed, 0, 0, outside)

def review_core_graph(w:mutbuf) -> u64:
    count = get(w, 0)
    if count == 0 or count > CORE_GRAPH_LIMIT:
        return 0
    limit = 1 << count
    index = 0
    while index < count:
        if get(w, 8 + index * 8) >= limit:
            return 0
        index = index + 1
    pivot = 0
    while pivot < count:
        target = get(w, 8 + pivot * 8)
        reachable = 1 << pivot
        index = 0
        while index < count:
            at = 8 + index * 8
            row = get(w, at)
            if (row & reachable) != 0:
                put(w, at, row | target)
            index = index + 1
        pivot = pivot + 1
    index = 0
    while index < count:
        if (get(w, 8 + index * 8) & (1 << index)) != 0:
            return 0
        index = index + 1
    return 1

def schedule_request(s:readbuf, offset:u64) -> u64:
    value = 0
    index = 0
    while index < 8:
        value = value | (byte(s, offset + index) << (8 * index))
        index = index + 1
    return value

def schedule_reply(o:mutbuf, w:mutbuf, action:u64, handle:u64) -> u64:
    put(o, 0, action)
    put(o, 8, handle)
    put(o, 16, get(w, SCHED_STEPS))
    return 24

def schedule_path(o:mutbuf, w:mutbuf, handle:u64) -> u64:
    paths = get(w, SCHED_PATHS) + 1
    put(w, SCHED_PATHS, paths)
    if paths > 4096:
        return schedule_reply(o, w, 3, 0)
    put(w, SCHED_ACTIVE, handle)
    put(w, SCHED_PHASE, 1)
    return schedule_reply(o, w, 1, handle)

def schedule_finish_path(o:mutbuf, w:mutbuf) -> u64:
    depth = get(w, SCHED_DEPTH)
    if depth == 0:
        put(w, SCHED_PHASE, 3)
        return schedule_reply(o, w, 0, 0)
    depth = depth - 1
    put(w, SCHED_DEPTH, depth)
    return schedule_path(o, w, get(w, SCHED_HEADER + depth * 8))

def schedule_visit(o:mutbuf, w:mutbuf, ordinal:u64) -> u64:
    steps = get(w, SCHED_STEPS) + 1
    put(w, SCHED_STEPS, steps)
    if steps > 65536:
        return schedule_reply(o, w, 4, 0)
    if ordinal >= MAX_CODE:
        return schedule_reply(o, w, 5, 0)
    bitmap = SCHED_VISITS + get(w, SCHED_DEPTH) * SCHED_BITMAP
    at = bitmap + (ordinal >> 3)
    visited = byte(w, at)
    bit = 1 << (ordinal & 7)
    if (visited & bit) != 0:
        return schedule_reply(o, w, 5, 0)
    store(w, at, visited | bit)
    put(w, SCHED_PHASE, 2)
    return schedule_reply(o, w, 2, get(w, SCHED_ACTIVE))

def schedule_fork(w:mutbuf, handle:u64) -> u64:
    depth = get(w, SCHED_DEPTH)
    if depth + 1 >= SCHED_FRAMES:
        return 0
    put(w, SCHED_HEADER + depth * 8, handle)
    bitmap = SCHED_VISITS + depth * SCHED_BITMAP
    index = 0
    while index < SCHED_BITMAP:
        put(w, bitmap + SCHED_BITMAP + index, get(w, bitmap + index))
        index = index + 8
    put(w, SCHED_DEPTH, depth + 1)
    return 1

def schedule_machine(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if length(o) != 24 or schedule_request(s, 24) != 0:
        return 4294967293
    op = schedule_request(s, 0)
    first = schedule_request(s, 8)
    second = schedule_request(s, 16)
    phase = get(w, SCHED_PHASE)
    if op == 0 and phase == 0:
        if first == 0 or second != 0:
            return 4294967293
        return schedule_path(o, w, first)
    if op == 1 and phase == 1:
        if first == 0:
            return schedule_finish_path(o, w)
        if first == 1:
            return schedule_visit(o, w, second)
    if op == 2 and phase == 2:
        if first == 1 and second == 0:
            return schedule_finish_path(o, w)
        if first == 0:
            if second != 0 and schedule_fork(w, second) == 0:
                return schedule_reply(o, w, 3, 0)
            put(w, SCHED_PHASE, 1)
            return schedule_reply(o, w, 1, get(w, SCHED_ACTIVE))
    return 4294967293
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
