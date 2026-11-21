"""Generate the closed Safe Core x86 decoder independently of machine emission."""
from __future__ import annotations

import ast
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_cnf_native import (CIRCUIT_CAPACITY, CIRCUIT_NODES, SPARSE_CLAUSES,
                                 SPARSE_REQUEST, SPARSE_VARIABLES, WORD_ARITHMETIC_SHR, WORD_PRODUCT_EXCEEDS,
                                 WORD_VARIABLE_SHL, WORD_VARIABLE_SHR, WRAPPING_PRODUCT)
from hepta.hia_safe_core_x64_decode_native import (
    CORE_FORMULA_IDS, CORE_GRAPH_LIMIT, CORE_GRAPH_REQUEST, MACHINE_FORMULA_IDS, MAX_INSTRUCTIONS,
    MAX_RECIPE_NODES, MAX_TEXT, MEMORY_GRAPH_REQUEST, MEMORY_GRAPH_ROWS, PROFILE_OFFSET, RECIPE_IDS, RECIPE_INPUTS,
    REFUSAL_IDS, SCHEDULER_BITMAP, SCHEDULER_FRAMES, SCHEDULER_HEADER, SCHEDULER_VISITS,
    SCHEDULER_WORKSPACE, WORKSPACE, MACHINE_VALUES_BRANCH_DEPTH, MACHINE_VALUES_BRANCHES,
    MACHINE_VALUES_INDEX, MACHINE_VALUES_REPLY,
    MACHINE_VALUES_HEADER, MACHINE_VALUES_REQUEST, MACHINE_VALUES_STACK_BYTES, MACHINE_VALUES_WORKSPACE,
    QUERY_FORMAT_WORKSPACE,
)
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

SOURCE_PATH = 'examples/hia_bootstrap/safe_core_x64_decode.hepta'
FIELDS = {
    'CURSOR': 0, 'ERROR': 8, 'MODE': 16, 'GROUP': 24, 'REG': 32, 'RM': 40, 'DISP': 48,
    'OP': 64, 'A': 72, 'B': 80, 'C': 88,
    'PROFILE': PROFILE_OFFSET,
    'BOUNDARIES': 128, 'MAX_TEXT': MAX_TEXT, 'MAX_CODE': MAX_INSTRUCTIONS, 'WORKSPACE': WORKSPACE,
}
FIELDS.update({'OP_' + name.upper(): index for name, index in MACHINE_FORMULA_IDS.items()})
FIELDS.update({'E_' + name.upper(): index for name, index in REFUSAL_IDS.items()})
FIELDS.update({'R_' + name.upper(): index for name, index in RECIPE_IDS.items()})
FIELDS.update({'C_' + name.upper().replace('.', '_'): index for name, index in CORE_FORMULA_IDS.items()})
FIELDS.update(CORE_GRAPH_LIMIT=CORE_GRAPH_LIMIT, CORE_GRAPH_SIZE=CORE_GRAPH_REQUEST.size)
FIELDS.update(MEMORY_GRAPH_ROWS=MEMORY_GRAPH_ROWS, MEMORY_GRAPH_SIZE=MEMORY_GRAPH_REQUEST.size)
FIELDS.update(MAX_RECIPE_NODES=MAX_RECIPE_NODES, RECIPE_INPUTS=RECIPE_INPUTS,
              LEFT=1, RIGHT=2, THIRD=3, FOURTH=4, FIFTH=5, ZF=3, CF=4, ARBITRARY=5)
FIELDS.update(SCHED_STEPS=0, SCHED_PATHS=8, SCHED_DEPTH=16, SCHED_PHASE=24, SCHED_ACTIVE=32,
              SCHED_HEADER=SCHEDULER_HEADER, SCHED_VISITS=SCHEDULER_VISITS,
              SCHED_BITMAP=SCHEDULER_BITMAP, SCHED_FRAMES=SCHEDULER_FRAMES,
              SCHED_WORKSPACE=SCHEDULER_WORKSPACE)
FIELDS.update(MV_REQUEST=MACHINE_VALUES_REQUEST, MV_REPLY=MACHINE_VALUES_REPLY,
              MV_WORKSPACE=MACHINE_VALUES_WORKSPACE, MV_INDEX=MACHINE_VALUES_INDEX,
              MV_HEADER=MACHINE_VALUES_HEADER.size,
              MV_STACK=192, MV_STACK_BASE=20000, MV_STACK_TOP=20000 + MACHINE_VALUES_STACK_BYTES,
              MV_CALLER=40000, MV_SAVED=40016, MV_LOCAL_RETURN=50000,
              MV_MUL_HIGH_TOKEN=200000, MV_MUL_HIGH_TEST=1000,
              MV_PC=128, MV_STEPS=136, MV_LOW=144, MV_NODES=152, MV_COUNT=CIRCUIT_NODES,
              MV_FLAGS=160, MV_LEFT=168, MV_RIGHT=176,
              MV_FLAG_RESULT=MACHINE_VALUES_BRANCHES - 32,
              MV_ABORT=MACHINE_VALUES_BRANCHES - 24, MV_BRANCH_SEEN=MACHINE_VALUES_BRANCHES - 16,
              MV_PREFIX=MACHINE_VALUES_BRANCHES - 8, MV_BRANCHES=MACHINE_VALUES_BRANCHES,
              MV_BRANCH_DEPTH=MACHINE_VALUES_BRANCH_DEPTH, MV_TERMINALS=1 << MACHINE_VALUES_BRANCH_DEPTH,
              MV_PRODUCT=WRAPPING_PRODUCT, MV_PRODUCT_LIMIT=WORD_PRODUCT_EXCEEDS, MV_SHIFT_LEFT=WORD_VARIABLE_SHL,
              MV_SHIFT_RIGHT=WORD_VARIABLE_SHR, MV_SHIFT_ARITHMETIC=WORD_ARITHMETIC_SHR)
FIELDS.update(QUERY_WORKSPACE=QUERY_FORMAT_WORKSPACE, QUERY_REQUEST=SPARSE_REQUEST,
              QUERY_BYTES=CIRCUIT_CAPACITY, QUERY_VARIABLES=SPARSE_VARIABLES,
              QUERY_CLAUSES=SPARSE_CLAUSES)

QUERY_FRAGMENTS = {
    'prefix': b'(set-logic QF_UF)\n',
    'declare': b'(declare-fun v',
    'sort': b' () Bool)\n',
    'assert': b'(assert ',
    'empty': b'false',
    'group': b'(or ',
    'negative': b'(not ',
    'end_clause': b')\n',
    'check': b'(check-sat)\n',
}

SOURCE = r'''
def decode_text(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    size = length(s)
    if length(w) == QUERY_WORKSPACE:
        return format_proof_query(s, o)
    if length(w) == MV_WORKSPACE:
        return project_machine_values(s, o, w)
    if size == 32 and length(w) == SCHED_WORKSPACE:
        return schedule_machine(s, o, w)
    if size == 0 and length(w) == 8:
        return caller_abi_rule(get(w, 0))
    if size == 0 and length(w) == 16:
        return machine_formula(o, get(w, 0), get(w, 8))
    if size == 0 and length(w) == 24:
        return core_scalar_formula(o, get(w, 0), get(w, 8), get(w, 16))
    if size == 0 and length(w) == 40:
        return memory_admission(w)
    if size == 0 and length(w) == CORE_GRAPH_SIZE:
        if length(o) != 0:
            return ordered_core_graph(w, o)
        return review_core_graph(w)
    if size == 0 and length(w) == MEMORY_GRAPH_SIZE:
        return memory_write_inventory(o, w)
    if length(o) < 24 or length(w) < WORKSPACE:
        return 4294967294
    if size == 0 or size > MAX_TEXT:
        return terminal(o, E_TEXT_BUDGET, 0, 0)
    if get(w, PROFILE) > 15:
        return 4294967293
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
            unsigned_profile = (get(w, PROFILE) & 8) == 0
            if (condition < 2 or condition > 7) and (unsigned_profile or condition == 10 or condition == 11):
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

def memory_write_inventory(o:mutbuf, w:mutbuf) -> u64:
    count = get(w, 0)
    first = get(w, 8)
    second = get(w, 16)
    if count == 0 or count > MEMORY_GRAPH_ROWS or first >= count or second >= count or length(o) < 8:
        return 4294967293
    index = 0
    while index < count:
        row = 24 + index * 24
        kind = get(w, row)
        parent = get(w, row + 8)
        alternative = get(w, row + 16)
        mask = 0
        if kind == 0:
            if index != 0 or parent != 0 or alternative != 0:
                return 4294967293
        else:
            if parent >= index:
                return 4294967293
            mask = get(w, 24 + parent * 24)
            if kind == 1 and alternative == 0:
                mask = mask | (1 << index)
            elif kind == 2 and alternative < index:
                mask = mask | get(w, 24 + alternative * 24)
            else:
                return 4294967293
        put(w, row, mask)
        index = index + 1
    put(o, 0, get(w, 24 + first * 24) | get(w, 24 + second * 24))
    return 8

def memory_admission(w:mutbuf) -> u64:
    kind = get(w, 0)
    first = get(w, 8)
    second = get(w, 16)
    size = get(w, 24)
    write = get(w, 32)
    if kind == 1:
        return choose(size == 1 and first != 0 and (write == 0 or first == 2), 1, 0)
    sign = 9223372036854775808
    biased = first ^ sign
    if kind == 2:
        return choose(second == 1 and biased >= sign - 16384 and biased <= sign + 8, 1, 0)
    if kind != 0:
        return 4294967293
    ceiling = choose(write == 0, 8, 0)
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
    unsigned_profile = (get(w, PROFILE) & 8) == 0
    if opcode == 0xd3 and (get(w, PROFILE) & 1) == 0:
        return fail(w, E_VARIABLE_SHIFT_PROFILE)
    if alu == 0 and opcode != 0x89 and opcode != 0x8b and opcode != 0x8d and opcode != 0x88 and opcode != 0x81 and opcode != 0x83 and opcode != 0xc1 and opcode != 0xd3 and opcode != 0xf7:
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
        if invalid_group or (group != 4 and group != 5 and (unsigned_profile or group != 7)) or count >= 64:
            return fail(w, E_SHIFT)
        return emit(w, choose(group == 4, OP_SHL, choose(group == 5, OP_SHR, OP_SAR)), rm, count, 0)
    if opcode == 0xd3:
        if invalid_group or (group != 4 and group != 5 and (unsigned_profile or group != 7)):
            return fail(w, E_VARIABLE_SHIFT)
        return emit(w, choose(group == 4, OP_SHL_CL, choose(group == 5, OP_SHR_CL, OP_SAR_CL)), rm, 0, 0)
    if invalid_group or group < 2 or (unsigned_profile and (group & 1) != 0):
        return fail(w, E_UNARY)
    if group == 4:
        if (get(w, PROFILE) & 2) == 0:
            return fail(w, E_UNSIGNED_MULTIPLY_PROFILE)
        return emit(w, OP_MUL, rm, 0, 0)
    if group == 6:
        if (get(w, PROFILE) & 4) == 0:
            return fail(w, E_UNSIGNED_DIVIDE_PROFILE)
        return emit(w, OP_DIV, rm, 0, 0)
    if group == 3:
        return emit(w, OP_NEG, rm, 0, 0)
    if group == 5:
        return emit(w, OP_IMUL_FULL, rm, 0, 0)
    if group == 7:
        return emit(w, OP_IDIV, rm, 0, 0)
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
    if opcode == 0x99:
        if rex != 0x48 or (get(w, PROFILE) & 8) == 0:
            return fail(w, E_CQO)
        return emit(w, OP_CQO, 0, 0, 0)
    if opcode == 0xe8 or opcode == 0xe9:
        if rex != 0:
            return fail(w, E_BRANCH_PREFIX)
        relative = take_signed(s, w, 4)
        return emit(w, choose(opcode == 0xe8, OP_CALL, OP_JMP), get(w, CURSOR) + relative, 0, 0)
    if opcode == 0x0f:
        return decode_extension(s, w, rex)
    return decode_operands(s, w, rex, opcode)

def caller_abi_rule(role:u64) -> u64:
    if role == 1:
        # System V AMD64 preserves RBX, RBP and R12–R15; RSP is checked separately.
        return 61480
    if role == 2:
        # The six integer argument registers are RDI, RSI, RDX, RCX, R8, R9.
        return 7 | (6 << 4) | (2 << 8) | (1 << 12) | (8 << 16) | (9 << 20)
    return 4294967293

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
    if op == OP_SHL or op == OP_SHR or op == OP_SAR:
        return shift_formula(o, op, param)
    if op == OP_SIGNED_FLAGS:
        return signed_flag_formula(o, param & 255, param >> 8)
    if op == OP_IDIV:
        if param > 1 and param != 8 and param != 16 and param != 32:
            return 4294967293
        return signed_divide_formula(o, param)
    if op == OP_IMUL:
        return imul_formula(o, param)
    if op == OP_IMUL_FULL:
        return pair_formula(o, op, param)
    if param != 0:
        return 4294967293
    if op == OP_LOAD or op == OP_LOAD8 or op == OP_STORE or op == OP_STORE8 or op == OP_LEA:
        result = node(o, R_ADD, LEFT, RIGHT, 0)
        return formula_done(o, node(o, R_SIMPLIFY, result, 0, 0), 0, 0, 0)
    if op == OP_PUSH or op == OP_POP or op == OP_LEAVE or op == OP_CALL or op == OP_RET:
        return stack_formula(o, op)
    if op == OP_BORROW_RANGE:
        limit = node(o, R_ADD, RIGHT, THIRD, 0)
        nonempty = node(o, R_NONZERO, THIRD, 0, 0)
        above_start = node(o, R_UGE, LEFT, RIGHT, 0)
        below_end = node(o, R_ULT, LEFT, limit, 0)
        inside = node(o, R_BOOL_AND3, nonempty, above_start, below_end)
        return formula_done(o, 0, 0, 0, inside)
    if op == OP_CALL_ADDRESS:
        return formula_done(o, node(o, R_ADD, LEFT, RIGHT, 0), 0, 0, 0)
    if op == OP_RETURN_OFFSET:
        difference = node(o, R_SUB, LEFT, RIGHT, 0)
        return formula_done(o, node(o, R_SIMPLIFY, difference, 0, 0), 0, 0, 0)
    if op == OP_RETURN_STACK:
        word = node(o, R_LITERAL64, 8, 0, 0)
        adjusted = node(o, R_ADD, RIGHT, word, 0)
        return formula_done(o, 0, 0, 0, node(o, R_EQ, LEFT, adjusted, 0))
    if op == OP_MEMORY_READ_STORE:
        same = node(o, R_EQ, LEFT, RIGHT, 0)
        return formula_done(o, node(o, R_CHOOSE, same, THIRD, FOURTH), 0, 0, 0)
    if op == OP_MEMORY_READ_JOIN:
        return formula_done(o, node(o, R_CHOOSE, LEFT, RIGHT, THIRD), 0, 0, 0)
    if op == OP_MEMORY_READ_AGREES:
        different = node(o, R_NE, LEFT, RIGHT, 0)
        same_byte = node(o, R_EQ, THIRD, FOURTH, 0)
        return formula_done(o, 0, 0, 0, node(o, R_BOOL_OR, different, same_byte, 0))
    if op >= OP_CALLER_STACK_FLOOR and op <= OP_OBSERVABLE_REFINEMENT_ERROR:
        return artifact_formula(o, op)
    if op == OP_NOT:
        return formula_done(o, node(o, R_NOT, LEFT, 0, 0), 0, 0, 0)
    if op == OP_CQO:
        count = node(o, R_LITERAL64, 63, 0, 0)
        high = node(o, R_ASHR_DYNAMIC, LEFT, count, 0)
        return formula_done(o, node(o, R_SIMPLIFY, high, 0, 0), 0, 0, 0)
    if op == OP_NEG:
        raw = node(o, R_SUB, node(o, R_LITERAL64, 0, 0, 0), LEFT, 0)
        return formula_done(o, node(o, R_SIMPLIFY, raw, 0, 0), node(o, R_ZERO, raw, 0, 0), node(o, R_NONZERO, LEFT, 0, 0), 0)
    if op == OP_CMOVNE:
        take = node(o, R_BOOL_NOT, ZF, 0, 0)
        result = node(o, R_CHOOSE, take, RIGHT, LEFT)
        return formula_done(o, node(o, R_SIMPLIFY, result, 0, 0), 0, 0, 0)
    if op == OP_VARIABLE_SHL or op == OP_VARIABLE_SHR or op == OP_SAR_CL:
        return variable_shift_formula(o, op)
    if op == OP_MULTIPLY_WORDS or op == OP_DIVIDE_WORDS:
        return pair_formula(o, op, param)
    return alu_formula(o, op)

def stack_formula(o:mutbuf, op:u64) -> u64:
    word = node(o, R_LITERAL64, 8, 0, 0)
    decrement = op == OP_PUSH or op == OP_CALL
    rsp = node(o, choose(decrement, R_SUB, R_ADD), LEFT, word, 0)
    adjusted = node(o, R_SIMPLIFY, rsp, 0, 0)
    if op == OP_CALL:
        mask = node(o, R_LITERAL64, 15, 0, 0)
        misalignment = node(o, R_AND, LEFT, mask, 0)
        fault = node(o, R_NONZERO, misalignment, 0, 0)
        return formula_done(o, adjusted, 0, 0, fault)
    return formula_done(o, adjusted, 0, 0, 0)

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
    # RIGHT and ARBITRARY carry the pre-instruction SF and OF for signed Jcc/SETcc.
    if condition == 0:
        return ARBITRARY
    if condition == 1:
        return node(o, R_BOOL_NOT, ARBITRARY, 0, 0)
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
    if condition == 8:
        return RIGHT
    if condition == 9:
        return node(o, R_BOOL_NOT, RIGHT, 0, 0)
    if condition == 12 or condition == 14:
        different = node(o, R_NE, RIGHT, ARBITRARY, 0)
        return choose(condition == 12, different, node(o, R_BOOL_OR, ZF, different, 0))
    if condition == 13 or condition == 15:
        equal = node(o, R_EQ, RIGHT, ARBITRARY, 0)
        return choose(condition == 13, equal, node(o, R_BOOL_AND, node(o, R_BOOL_NOT, ZF, 0, 0), equal, 0))
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
    if op == OP_SAR:
        surviving = node(o, R_EXTRACT, LEFT, 63, count)
        shifted = node(o, R_SIGNEXT, surviving, count, 0)
    else:
        shifted = node(o, choose(left, R_SHL, R_LSHR), LEFT, count, 0)
    result = node(o, R_SIMPLIFY, shifted, 0, 0)
    zf = node(o, R_ZERO, result, 0, 0)
    carry_bit = choose(left, 64 - count, count - 1)
    bit = node(o, R_EXTRACT, LEFT, carry_bit, carry_bit)
    cf = node(o, R_ONE, bit, 0, 0)
    return formula_done(o, result, zf, cf, 0)

def imul_formula(o:mutbuf, width:u64) -> u64:
    # The low bits are written; carry reflects signed truncation. Undefined
    # ZF is a separate arbitrary input, never preserved or inferred.
    if width == 8 or width == 16 or width == 32:
        narrow = signed_product(o, LEFT, RIGHT, width)
        exact = node(o, R_SIGNEXT, narrow, 64 - 2 * width, 0)
        return formula_done(o, node(o, R_SIMPLIFY, exact, 0, 0), ARBITRARY, node(o, R_FALSE, 0, 0, 0), 0)
    if width != 0:
        return 4294967293
    left = node(o, R_SIGNEXT, LEFT, 64, 0)
    right = node(o, R_SIGNEXT, RIGHT, 64, 0)
    full = node(o, R_IMUL, left, right, 0)
    low = node(o, R_EXTRACT, full, 63, 0)
    restored = node(o, R_SIGNEXT, low, 64, 0)
    cf = node(o, R_NE, full, restored, 0)
    return formula_done(o, node(o, R_SIMPLIFY, low, 0, 0), ARBITRARY, cf, 0)

def variable_shift_formula(o:mutbuf, op:u64) -> u64:
    # CL is captured from the pre-instruction state; the masked zero count
    # retains both flags and the old destination, including RCX aliases.
    left = op == OP_VARIABLE_SHL
    count = node(o, R_AND, RIGHT, node(o, R_LITERAL64, 63, 0, 0), 0)
    zero = node(o, R_ZERO, count, 0, 0)
    primitive = choose(left, R_SHL_DYNAMIC, choose(op == OP_SAR_CL, R_ASHR_DYNAMIC, R_LSHR_DYNAMIC))
    raw = node(o, primitive, LEFT, count, 0)
    base = node(o, R_LITERAL64, choose(left, 64, 1), 0, 0)
    index = node(o, R_SUB, choose(left, base, count), choose(left, count, base), 0)
    shifted = node(o, R_LSHR_DYNAMIC, LEFT, index, 0)
    bit = node(o, R_EXTRACT, shifted, 0, 0)
    carry = node(o, R_ONE, bit, 0, 0)
    result = node(o, R_CHOOSE, zero, LEFT, raw)
    zf = node(o, R_CHOOSE, zero, ZF, node(o, R_ZERO, raw, 0, 0))
    cf = node(o, R_CHOOSE, zero, CF, carry)
    return formula_done(o, result, zf, cf, 0)

def pair_formula(o:mutbuf, op:u64, width:u64) -> u64:
    if op == OP_DIVIDE_WORDS:
        quotient = node(o, R_UDIV_WORDS, RIGHT, LEFT, THIRD)
        remainder = node(o, R_UREM_WORDS, RIGHT, LEFT, THIRD)
        nonzero = node(o, R_NONZERO, THIRD, 0, 0)
        fits = node(o, R_ULT, RIGHT, THIRD, 0)
        admitted = node(o, R_BOOL_AND, nonzero, fits, 0)
        return formula_done(o, quotient, remainder, ARBITRARY, admitted)
    if op == OP_IMUL_FULL and (width == 8 or width == 16 or width == 32):
        narrow = signed_product(o, LEFT, THIRD, width)
        low = node(o, R_SIGNEXT, narrow, 64 - 2 * width, 0)
        sign = node(o, R_EXTRACT, narrow, 2 * width - 1, 2 * width - 1)
        high = node(o, R_SIGNEXT, sign, 63, 0)
        return formula_done(o, node(o, R_SIMPLIFY, low, 0, 0), node(o, R_SIMPLIFY, high, 0, 0),
                            node(o, R_FALSE, 0, 0, 0), 0)
    if width != 0:
        return 4294967293
    extension = choose(op == OP_IMUL_FULL, R_SIGNEXT, R_ZEROEXT)
    a = node(o, extension, LEFT, 64, 0)
    b = node(o, extension, THIRD, 64, 0)
    product = node(o, R_IMUL, a, b, 0)
    low = node(o, R_EXTRACT, product, 63, 0)
    high = node(o, R_EXTRACT, product, 127, 64)
    if op == OP_IMUL_FULL:
        carry = node(o, R_NE, product, node(o, R_SIGNEXT, low, 64, 0), 0)
    else:
        carry = node(o, R_NONZERO, high, 0, 0)
    return formula_done(o, node(o, R_SIMPLIFY, low, 0, 0), node(o, R_SIMPLIFY, high, 0, 0), carry, 0)

def signed_division_input(o:mutbuf, source:u64, width:u64) -> u64:
    # One extra signed bit preserves the mathematical MIN/-1 quotient.
    if width == 64:
        return source
    return node(o, R_SIGNEXT, node(o, R_EXTRACT, source, width - 1, 0), 1, 0)

def signed_division_result(o:mutbuf, value:u64, width:u64) -> u64:
    if width == 64:
        return value
    return node(o, R_SIGNEXT, value, 63 - width, 0)

def signed_product(o:mutbuf, left:u64, right:u64, width:u64) -> u64:
    # Each input is already normalized by its Core type or independently
    # recognized as an exact sign extension of the actual machine word.
    # Twice that width retains the mathematical product without overflow.
    a = node(o, R_SIGNEXT, node(o, R_EXTRACT, left, width - 1, 0), width, 0)
    b = node(o, R_SIGNEXT, node(o, R_EXTRACT, right, width - 1, 0), width, 0)
    return node(o, R_IMUL, a, b, 0)

def signed_divide_formula(o:mutbuf, profile:u64) -> u64:
    nonzero = node(o, R_NONZERO, THIRD, 0, 0)
    if profile > 1:
        dividend = signed_division_input(o, LEFT, profile)
        divisor = signed_division_input(o, THIRD, profile)
        quotient = signed_division_result(o, node(o, R_SDIV, dividend, divisor, 0), profile)
        remainder = signed_division_result(o, node(o, R_SREM, dividend, divisor, 0), profile)
        return formula_done(o, node(o, R_SIMPLIFY, quotient, 0, 0), node(o, R_SIMPLIFY, remainder, 0, 0), ARBITRARY, nonzero)
    if profile == 1:
        quotient = node(o, R_SDIV, LEFT, THIRD, 0)
        remainder = node(o, R_SREM, LEFT, THIRD, 0)
        minword = node(o, R_LITERAL64, 9223372036854775808, 0, 0)
        minusone = node(o, R_LITERAL64, 18446744073709551615, 0, 0)
        minimum = node(o, R_EQ, LEFT, minword, 0)
        negative_one = node(o, R_EQ, THIRD, minusone, 0)
        bad = node(o, R_BOOL_AND, minimum, negative_one, 0)
        fits = node(o, R_BOOL_NOT, bad, 0, 0)
    else:
        dividend = node(o, R_CONCAT, RIGHT, LEFT, 0)
        divisor = node(o, R_SIGNEXT, THIRD, 64, 0)
        full = node(o, R_SDIV, dividend, divisor, 0)
        quotient = node(o, R_EXTRACT, full, 63, 0)
        remainder = node(o, R_EXTRACT, node(o, R_SREM, dividend, divisor, 0), 63, 0)
        fits = node(o, R_EQ, full, node(o, R_SIGNEXT, quotient, 64, 0), 0)
    valid = node(o, R_BOOL_AND, nonzero, fits, 0)
    return formula_done(o, node(o, R_SIMPLIFY, quotient, 0, 0), node(o, R_SIMPLIFY, remainder, 0, 0), ARBITRARY, valid)

def machine_sign(o:mutbuf, value:u64) -> u64:
    return node(o, R_ONE, node(o, R_EXTRACT, value, 63, 63), 0, 0)

def signed_sum_overflow(o:mutbuf, a:u64, b:u64, result:u64, add:bool) -> u64:
    operand_signs = node(o, choose(add, R_EQ, R_NE), a, b, 0)
    changed = node(o, R_NE, a, result, 0)
    return node(o, R_BOOL_AND, operand_signs, changed, 0)

def signed_flag_formula(o:mutbuf, op:u64, count:u64) -> u64:
    if op == OP_SHL or op == OP_SHR or op == OP_SAR or op == OP_VARIABLE_SHL or op == OP_VARIABLE_SHR or op == OP_SAR_CL:
        return signed_shift_flags(o, op, count)
    if count != 0:
        return 4294967293
    if op == OP_NEG:
        zero = node(o, R_LITERAL64, 0, 0, 0)
        raw = node(o, R_SUB, zero, LEFT, 0)
        minimum = node(o, R_LITERAL64, 9223372036854775808, 0, 0)
        return formula_done(o, 0, machine_sign(o, raw), node(o, R_EQ, LEFT, minimum, 0), 0)
    if op == OP_ADD or op == OP_SUB or op == OP_CMP:
        add = op == OP_ADD
        raw = node(o, choose(add, R_ADD, R_SUB), LEFT, RIGHT, 0)
        sign = machine_sign(o, raw)
        a = machine_sign(o, LEFT)
        b = machine_sign(o, RIGHT)
        return formula_done(o, 0, sign, signed_sum_overflow(o, a, b, sign, add), 0)
    primitive = 0
    if op == OP_AND or op == OP_TEST:
        primitive = R_AND
    if op == OP_OR:
        primitive = R_OR
    if op == OP_XOR:
        primitive = R_XOR
    if primitive == 0:
        return 4294967293
    raw = node(o, primitive, LEFT, RIGHT, 0)
    return formula_done(o, 0, machine_sign(o, raw), node(o, R_FALSE, 0, 0, 0), 0)

def signed_shift_flags(o:mutbuf, op:u64, count:u64) -> u64:
    variable = op == OP_VARIABLE_SHL or op == OP_VARIABLE_SHR or op == OP_SAR_CL
    if count >= 64 or (variable and count != 0):
        return 4294967293
    if (variable == False) and count == 0:
        return formula_done(o, 0, 0, 0, 0)
    amount = 0
    if variable:
        amount = node(o, R_AND, RIGHT, node(o, R_LITERAL64, 63, 0, 0), 0)
    else:
        amount = node(o, R_LITERAL64, count, 0, 0)
    left = op == OP_SHL or op == OP_VARIABLE_SHL
    arithmetic = op == OP_SAR or op == OP_SAR_CL
    primitive = choose(left, R_SHL_DYNAMIC, choose(arithmetic, R_ASHR_DYNAMIC, R_LSHR_DYNAMIC))
    sign = machine_sign(o, node(o, primitive, LEFT, amount, 0))
    single = 0
    if arithmetic:
        single = node(o, R_FALSE, 0, 0, 0)
    else:
        old_sign = machine_sign(o, LEFT)
        single = old_sign
        if left:
            single = node(o, R_NE, sign, old_sign, 0)
    overflow = ARBITRARY
    if variable:
        overflow = node(o, R_CHOOSE, node(o, R_ONE, amount, 0, 0), single, ARBITRARY)
        zero = node(o, R_ZERO, amount, 0, 0)
        sign = node(o, R_CHOOSE, zero, ZF, sign)
        overflow = node(o, R_CHOOSE, zero, CF, overflow)
    else:
        if count == 1:
            overflow = single
    return formula_done(o, 0, sign, overflow, 0)

def core_scalar_formula(o:mutbuf, op:u64, profile:u64, literal:u64) -> u64:
    if length(o) < 40 + MAX_RECIPE_NODES * 32:
        return 4294967294
    width = profile & 127
    signed_result = (profile & 128) != 0
    signed_input = (profile & 256) != 0
    if profile > 511 or (signed_result and width == 1):
        return 4294967293
    if width != 1 and width != 8 and width != 16 and width != 32 and width != 64:
        return 4294967293
    put(o, 0, 0)
    if op == C_CONST:
        return formula_done(o, node(o, R_LITERAL64, literal, 0, 0), 0, 0, 0)
    if op >= C_BORROW_EXTENT and op <= C_BORROW_WRAP and width == 64:
        return core_borrow_formula(o, op, literal)
    if literal != 0:
        return 4294967293
    if op == C_PARAMETER:
        if signed_result:
            value = core_signed_normalized(o, LEFT, width)
        else:
            value = core_normalized(o, LEFT, core_mask(o, width))
        return formula_done(o, value, 0, 0, 0)
    if op == C_BUFFER_ADDRESS and width == 64:
        address = node(o, R_ADD, LEFT, THIRD, 0)
        outside = node(o, R_UGE, THIRD, RIGHT, 0)
        return formula_done(o, address, 0, 0, outside)
    if op >= C_COMPARE_EQ and op <= C_COMPARE_GE:
        return core_compare_formula(o, op, signed_input)
    if op == C_SELECT:
        use_then = node(o, R_NONZERO, LEFT, 0, 0)
        return formula_done(o, node(o, R_CHOOSE, use_then, RIGHT, THIRD), 0, 0, 0)
    if signed_input or signed_result:
        if op == C_INT_CAST_WRAP or op == C_INT_CAST_CHECKED:
            return core_signed_cast(o, op, width, signed_result, signed_input)
        if signed_result:
            return core_signed_arithmetic(o, op, width)
        return 4294967293
    if op >= C_INT_ADD_WRAP and op <= C_INT_SUB_CHECKED:
        return core_numeric_formula(o, op, width)
    if op >= C_INT_MUL_CHECKED and op <= C_INT_SHR_CHECKED and width != 1:
        return core_checked_formula(o, op, width)
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

def core_checked_formula(o:mutbuf, op:u64, width:u64) -> u64:
    if op == C_INT_MUL_CHECKED:
        a = node(o, R_ZEROEXT, LEFT, 64, 0)
        b = node(o, R_ZEROEXT, RIGHT, 64, 0)
        product = node(o, R_IMUL, a, b, 0)
        high = node(o, R_EXTRACT, product, 127, width)
        trap = node(o, R_NONZERO, high, 0, 0)
        low = node(o, R_EXTRACT, product, 63, 0)
        return formula_done(o, core_normalized(o, low, core_mask(o, width)), 0, 0, trap)
    if op == C_INT_DIV_CHECKED or op == C_INT_REM_CHECKED:
        value = node(o, choose(op == C_INT_DIV_CHECKED, R_UDIV, R_UREM), LEFT, RIGHT, 0)
        return formula_done(o, value, 0, 0, node(o, R_ZERO, RIGHT, 0, 0))
    if op == C_INT_NEG_CHECKED:
        raw = node(o, R_SUB, node(o, R_LITERAL64, 0, 0, 0), LEFT, 0)
        return formula_done(o, core_normalized(o, raw, core_mask(o, width)), 0, 0, node(o, R_NONZERO, LEFT, 0, 0))
    trap = node(o, R_UGE, RIGHT, node(o, R_LITERAL64, width, 0, 0), 0)
    value = node(o, choose(op == C_INT_SHL_CHECKED, R_SHL_DYNAMIC, R_LSHR_DYNAMIC), LEFT, RIGHT, 0)
    return formula_done(o, core_normalized(o, value, core_mask(o, width)), 0, 0, trap)

def core_compare_formula(o:mutbuf, op:u64, signed:bool) -> u64:
    primitive = R_EQ
    if op == C_COMPARE_NE:
        primitive = R_NE
    if op == C_COMPARE_LT:
        primitive = choose(signed, R_SLT, R_ULT)
    if op == C_COMPARE_LE:
        primitive = choose(signed, R_SLE, R_ULE)
    if op == C_COMPARE_GT:
        primitive = choose(signed, R_SGT, R_UGT)
    if op == C_COMPARE_GE:
        primitive = choose(signed, R_SGE, R_UGE)
    condition = node(o, primitive, LEFT, RIGHT, 0)
    one = node(o, R_LITERAL64, 1, 0, 0)
    zero = node(o, R_LITERAL64, 0, 0, 0)
    return formula_done(o, node(o, R_CHOOSE, condition, one, zero), 0, 0, 0)

def core_signed_normalized(o:mutbuf, raw:u64, width:u64) -> u64:
    if width != 64:
        raw = node(o, R_EXTRACT, raw, width - 1, 0)
        raw = node(o, R_SIGNEXT, raw, 64 - width, 0)
    return node(o, R_SIMPLIFY, raw, 0, 0)

def core_signed_cast(o:mutbuf, op:u64, width:u64, signed_result:bool, signed_input:bool) -> u64:
    value = 0
    if signed_result:
        value = core_signed_normalized(o, LEFT, width)
    else:
        value = core_normalized(o, LEFT, core_mask(o, width))
    if op == C_INT_CAST_WRAP:
        return formula_done(o, value, 0, 0, 0)
    # Use the source value's ordering. Unsigned values cannot fall below
    # either lower bound; signed-to-unsigned also checks negativity.
    high = core_mask(o, width - choose(signed_result, 1, 0))
    upper_order = choose(signed_input and signed_result, R_SGT, R_UGT)
    above = node(o, upper_order, LEFT, high, 0)
    if signed_input:
        low = node(o, R_LITERAL64, choose(signed_result, 0 - (1 << (width - 1)), 0), 0, 0)
        below = node(o, R_SLT, LEFT, low, 0)
        above = node(o, R_BOOL_OR, below, above, 0)
    return formula_done(o, value, 0, 0, above)

def core_signed_arithmetic(o:mutbuf, op:u64, width:u64) -> u64:
    if op == C_INT_MUL_WRAP and width < 64:
        return formula_done(o, core_signed_normalized(o, signed_product(o, LEFT, RIGHT, width), width), 0, 0, 0)
    if op >= C_INT_ADD_WRAP and op <= C_INT_SUB_CHECKED:
        primitive = choose(op == C_INT_ADD_WRAP or op == C_INT_ADD_CHECKED, R_ADD, R_SUB)
        if op == C_INT_MUL_WRAP:
            primitive = R_IMUL
        raw = node(o, primitive, LEFT, RIGHT, 0)
        result = core_signed_normalized(o, raw, width)
        if op < C_INT_ADD_CHECKED:
            return formula_done(o, result, 0, 0, 0)
        a = machine_sign(o, LEFT)
        b = machine_sign(o, RIGHT)
        trap = signed_sum_overflow(o, a, b, machine_sign(o, result), op == C_INT_ADD_CHECKED)
        return formula_done(o, result, 0, 0, trap)
    if op == C_BIT_NOT:
        return formula_done(o, core_signed_normalized(o, node(o, R_NOT, LEFT, 0, 0), width), 0, 0, 0)
    if op == C_BIT_AND or op == C_BIT_OR or op == C_BIT_XOR:
        primitive = choose(op == C_BIT_AND, R_AND, choose(op == C_BIT_OR, R_OR, R_XOR))
        return formula_done(o, node(o, primitive, LEFT, RIGHT, 0), 0, 0, 0)
    if op >= C_INT_MUL_CHECKED and op <= C_INT_SHR_CHECKED:
        return core_signed_checked(o, op, width)
    return 4294967293

def core_signed_checked(o:mutbuf, op:u64, width:u64) -> u64:
    if op == C_INT_MUL_CHECKED:
        if width < 64:
            product = signed_product(o, LEFT, RIGHT, width)
            low = node(o, R_EXTRACT, product, width - 1, 0)
            value = node(o, R_SIGNEXT, low, 64 - width, 0)
            trap = node(o, R_NE, product, node(o, R_SIGNEXT, low, width, 0), 0)
            return formula_done(o, node(o, R_SIMPLIFY, value, 0, 0), 0, 0, trap)
        a = node(o, R_SIGNEXT, LEFT, 64, 0)
        b = node(o, R_SIGNEXT, RIGHT, 64, 0)
        product = node(o, R_IMUL, a, b, 0)
        low = node(o, R_EXTRACT, product, 63, 0)
        result = core_signed_normalized(o, low, width)
        trap = node(o, R_NE, product, node(o, R_SIGNEXT, result, 64, 0), 0)
        return formula_done(o, result, 0, 0, trap)
    if op == C_INT_SHL_CHECKED or op == C_INT_SHR_CHECKED:
        trap = node(o, R_UGE, RIGHT, node(o, R_LITERAL64, width, 0, 0), 0)
        raw = node(o, choose(op == C_INT_SHL_CHECKED, R_SHL_DYNAMIC, R_ASHR_DYNAMIC), LEFT, RIGHT, 0)
        return formula_done(o, core_signed_normalized(o, raw, width), 0, 0, trap)
    minimum = node(o, R_LITERAL64, 0 - (1 << (width - 1)), 0, 0)
    at_minimum = node(o, R_EQ, LEFT, minimum, 0)
    if op == C_INT_NEG_CHECKED:
        raw = node(o, R_SUB, node(o, R_LITERAL64, 0, 0, 0), LEFT, 0)
        return formula_done(o, core_signed_normalized(o, raw, width), 0, 0, at_minimum)
    minus_one = node(o, R_LITERAL64, 18446744073709551615, 0, 0)
    overflow = node(o, R_BOOL_AND, at_minimum, node(o, R_EQ, RIGHT, minus_one, 0), 0)
    trap = node(o, R_BOOL_OR, node(o, R_ZERO, RIGHT, 0, 0), overflow, 0)
    dividend = signed_division_input(o, LEFT, width)
    divisor = signed_division_input(o, RIGHT, width)
    raw = node(o, choose(op == C_INT_DIV_CHECKED, R_SDIV, R_SREM), dividend, divisor, 0)
    # The only out-of-width quotient already traps; normalize the admitted
    # result just as the final machine ABI does.
    return formula_done(o, core_signed_normalized(o, raw, width), 0, 0, trap)

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

def ordered_core_graph(w:mutbuf, o:mutbuf) -> u64:
    count = get(w, 0)
    if count == 0 or count > CORE_GRAPH_LIMIT or length(o) != count * 8:
        return 0
    if review_core_graph(w) == 0:
        return 0
    # Only emit a node once no unconsumed node precedes it. The existing
    # acyclicity check has established this will consume every vertex.
    limit = (1 << count) - 1
    pending = limit
    index = 0
    while pending != 0:
        incoming = 0
        scan = 0
        while scan < count:
            if (pending & (1 << scan)) != 0:
                incoming = incoming | get(w, 8 + 8 * scan)
            scan = scan + 1
        options = pending & (limit ^ incoming)
        if options == 0:
            return 0
        node = 0
        while (options & (1 << node)) == 0:
            node = node + 1
        put(o, index * 8, node)
        pending = pending ^ (1 << node)
        index = index + 1
    return index * 8

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
def artifact_formula(o:mutbuf, op:u64) -> u64:
    if op == OP_CALLER_STACK_FLOOR:
        floor = node(o, R_LITERAL64, 16384, 0, 0)
        predicate = node(o, R_UGE, LEFT, floor, 0)
    elif op == OP_CALLER_STACK_CEILING:
        ceiling = node(o, R_LITERAL64, 18446744073709551600, 0, 0)
        predicate = node(o, R_ULE, LEFT, ceiling, 0)
    elif op == OP_CALLER_STACK_ALIGNMENT:
        mask = node(o, R_LITERAL64, 15, 0, 0)
        bits = node(o, R_AND, LEFT, mask, 0)
        predicate = node(o, R_EQUAL_LITERAL, bits, 8, 0)
    elif op == OP_CALLER_LOAN_DISJOINT:
        predicate = caller_disjoint_formula(o)
    elif op == OP_TERMINAL_COVERAGE_ERROR:
        incomplete_core = node(o, R_BOOL_NOT, LEFT, 0, 0)
        incomplete_machine = node(o, R_BOOL_NOT, RIGHT, 0, 0)
        predicate = node(o, R_BOOL_OR, incomplete_core, incomplete_machine, 0)
    elif op == OP_CALLER_MEMORY_DIFFERENCE:
        predicate = node(o, R_NE, LEFT, RIGHT, 0)
    else:
        different_exit = node(o, R_NE, LEFT, RIGHT, 0)
        returned = node(o, R_BOOL_NOT, LEFT, 0, 0)
        different_value = node(o, R_NE, THIRD, FOURTH, 0)
        different_return = node(o, R_BOOL_AND, returned, different_value, 0)
        predicate = node(o, R_BOOL_OR3, different_exit, different_return, FIFTH)
    return formula_done(o, 0, 0, 0, predicate)

def caller_disjoint_formula(o:mutbuf) -> u64:
    # Inputs: entry stack pointer, loan pointer, loan extent, declared maximum.
    bounded = node(o, R_ULE, THIRD, FOURTH, 0)
    empty = node(o, R_ZERO, THIRD, 0, 0)
    nonnull = node(o, R_NONZERO, RIGHT, 0, 0)
    end = node(o, R_ADD, RIGHT, THIRD, 0)
    nonwrapping = node(o, R_UGE, end, RIGHT, 0)
    valid = node(o, R_BOOL_AND, nonnull, nonwrapping, 0)
    valid_or_empty = node(o, R_BOOL_OR, empty, valid, 0)
    admitted = node(o, R_BOOL_AND, bounded, valid_or_empty, 0)
    floor = node(o, R_LITERAL64, 16384, 0, 0)
    low = node(o, R_SUB, LEFT, floor, 0)
    before_stack = node(o, R_ULE, end, low, 0)
    word = node(o, R_LITERAL64, 8, 0, 0)
    high = node(o, R_ADD, LEFT, word, 0)
    after_stack = node(o, R_UGE, RIGHT, high, 0)
    disjoint = node(o, R_BOOL_OR3, empty, before_stack, after_stack)
    return node(o, R_IMPLIES, admitted, disjoint, 0)

# Finite symbolic semantics for acyclic, word-only scalar images.
# Abstract register/stack values are either circuit nodes, stack positions,
# opaque caller registers or return sites. An unknown value is never a circuit
# input and cannot determine memory, control flow or the observed return.
def project_machine_values(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if length(s) < 32 or length(o) < MV_HEADER + MV_COUNT * 40 or schedule_request(s, 0) != MV_REQUEST:
        return 4294967293
    words = schedule_request(s, 16)
    count = schedule_request(s, 24)
    if words > 6 or count == 0 or count > MAX_CODE or length(s) != 32 + count * 48:
        return 4294967293
    put(w, MV_NODES, 0)
    index = 0
    while index < words:
        mv_node(o, w, 1, 0, 0, 0)
        index = index + 1
    put(w, MV_PREFIX, 0)
    return mv_tree(s, o, w, words, count)

def mv_tree(s:readbuf, o:mutbuf, w:mutbuf, words:u64, count:u64) -> u64:
    steps = 0
    depth = 0
    paths = 0
    while paths < MV_TERMINALS:
        value = mv_next_terminal(s, o, w, words, count)
        if value == 0:
            return 0
        steps = steps + get(w, MV_STEPS)
        path_depth = MV_STACK_TOP - get(w, MV_LOW)
        depth = choose(path_depth > depth, path_depth, depth)
        paths = paths + 1
        value = mv_fold_path(o, w, value)
        if value == 0:
            return 0
        if get(w, MV_PREFIX) == 0:
            return mv_finish_tree(o, w, value, steps, depth, paths)
    return 0

def mv_next_terminal(s:readbuf, o:mutbuf, w:mutbuf, words:u64, count:u64) -> u64:
    if mv_prime_path(s, w, words, count) == 0:
        return 0
    value = mv_run_path(s, o, w)
    if get(w, MV_BRANCH_SEEN) < get(w, MV_PREFIX):
        return 0
    return value

def mv_fold_path(o:mutbuf, w:mutbuf, terminal:u64) -> u64:
    # Each frame describes an exact prefix. Save a completed fall-through
    # subtree, or join it with its checked taken subtree and continue upwards.
    depth = get(w, MV_BRANCH_SEEN)
    value = terminal
    while depth != 0:
        frame = MV_BRANCHES + (depth - 1) * 32
        not_taken = get(w, frame + 16)
        if not_taken == 0:
            put(w, frame + 16, value)
            put(w, frame + 24, get(w, MV_ABORT))
            put(w, MV_PREFIX, depth)
            return value
        predicate = get(w, frame + 8)
        value = mv_node(o, w, 11, predicate - 1, value - 1, not_taken - 1)
        if value == 0:
            return 0
        stopped = mv_join_abort(o, w, predicate - 1, get(w, MV_ABORT) - 1, get(w, frame + 24) - 1)
        if stopped == 0:
            return 0
        put(w, MV_ABORT, stopped)
        depth = depth - 1
    put(w, MV_PREFIX, 0)
    return value

def mv_join_abort(o:mutbuf, w:mutbuf, condition:u64, yes:u64, no:u64) -> u64:
    first = MV_HEADER + yes * 40
    second = MV_HEADER + no * 40
    if get(o, first) == 2 and get(o, second) == 2:
        left = get(o, first + 32)
        right = get(o, second + 32)
        if left == right:
            return yes + 1
        if left == 1:
            return condition + 1
        predicate = MV_HEADER + condition * 40
        if get(o, predicate) == 6:
            return get(o, predicate + 16) + 1
        return mv_word(o, w, 6, 1, condition, 0, 0)
    return mv_word(o, w, 11, 1, condition, yes, no)

def mv_finish_tree(o:mutbuf, w:mutbuf, value:u64, steps:u64, depth:u64, paths:u64) -> u64:
    nodes = get(w, MV_NODES)
    put(o, 0, MV_REPLY)
    put(o, 8, nodes)
    put(o, 16, value - 1)
    put(o, 24, steps)
    put(o, 32, depth)
    put(o, 40, paths)
    put(o, 48, get(w, MV_ABORT) - 1)
    return MV_HEADER + nodes * 40

def mv_prime_path(s:readbuf, w:mutbuf, words:u64, count:u64) -> u64:
    position = 0
    while position < 128:
        put(w, position, MV_SAVED + (position >> 3))
        position = position + 8
    fill_range(w, MV_STACK, MV_STACK_TOP - MV_STACK_BASE + 8, 0)
    # The input's instruction offsets have already been decoded and checked
    # against the final ELF and its call relocations. Build a bounded PC index.
    index = 0
    pc = 0
    while index < count:
        row = 32 + index * 48
        size = schedule_request(s, row + 16)
        if schedule_request(s, row) != pc or size == 0 or size > MAX_TEXT - pc:
            return 0
        put(w, MV_INDEX + pc * 8, row)
        pc = pc + size
        index = index + 1
    put(w, 32, MV_STACK_TOP)
    put(w, MV_STACK + MV_STACK_TOP - MV_STACK_BASE, MV_CALLER)
    put(w, MV_LOW, MV_STACK_TOP)
    put(w, MV_PC, schedule_request(s, 8))
    put(w, MV_STEPS, 0)
    put(w, MV_FLAGS, 0)
    put(w, MV_BRANCH_SEEN, 0)
    index = 0
    while index < words:
        register = (caller_abi_rule(2) >> (4 * index)) & 15
        put(w, register * 8, index + 1)
        index = index + 1
    return 1

def mv_run_path(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    while get(w, MV_STEPS) < MAX_CODE:
        pc = get(w, MV_PC)
        if pc >= MAX_TEXT:
            return 0
        row = get(w, MV_INDEX + pc * 8)
        sp = get(w, 32)
        if row < 32 or row > length(s) - 48 or mv_stack_position(sp) == False:
            return 0
        if schedule_request(s, row) != pc:
            return 0
        # The Safe Core profile does not admit cycles or repeated calls to
        # an already visited machine instruction on this path.
        put(w, MV_INDEX + pc * 8, 0)
        if sp < get(w, MV_LOW):
            put(w, MV_LOW, sp)
        put(w, MV_PC, pc + schedule_request(s, row + 16))
        put(w, MV_STEPS, get(w, MV_STEPS) + 1)
        action = mv_step(s, o, w, row, sp)
        if action == 0:
            return 0
        if action == 2:
            nodes = get(w, MV_NODES)
            value = get(w, 0)
            if value == 0 or value > nodes or mv_caller_preserved(w) == False:
                return 0
            stopped = mv_word(o, w, 2, 1, 0, 0, 0)
            if stopped == 0:
                return 0
            put(w, MV_ABORT, stopped)
            return value
        if action == 3:
            stopped = mv_word(o, w, 2, 1, 0, 0, 1)
            if stopped == 0:
                return 0
            put(w, MV_ABORT, stopped)
            return mv_node(o, w, 2, 0, 0, 0)
    return 0

def mv_node(o:mutbuf, w:mutbuf, op:u64, left:u64, right:u64, immediate:u64) -> u64:
    return mv_word(o, w, op, 64, left, right, immediate)

def mv_word(o:mutbuf, w:mutbuf, op:u64, width:u64, left:u64, right:u64, immediate:u64) -> u64:
    index = get(w, MV_NODES)
    if index == MV_COUNT:
        return 0
    row = MV_HEADER + index * 40
    put(o, row, op)
    put(o, row + 8, width)
    put(o, row + 16, left)
    put(o, row + 24, right)
    put(o, row + 32, immediate)
    put(w, MV_NODES, index + 1)
    return index + 1

def mv_stack_position(address:u64) -> bool:
    return address >= MV_STACK_BASE and address <= MV_STACK_TOP and (address & 7) == 0

def mv_stack_access(sp:u64, address:u64, writing:bool) -> bool:
    return mv_stack_position(address) and address >= sp and (writing == False or address < MV_STACK_TOP)

def mv_stack_slot(address:u64) -> u64:
    return MV_STACK + address - MV_STACK_BASE

def mv_caller_preserved(w:mutbuf) -> bool:
    if get(w, 32) != MV_STACK_TOP + 8:
        return False
    register = 0
    while register < 16:
        if ((caller_abi_rule(1) >> register) & 1) != 0:
            if get(w, register * 8) != MV_SAVED + register:
                return False
        register = register + 1
    return True

def mv_step(s:readbuf, o:mutbuf, w:mutbuf, row:u64, sp:u64) -> u64:
    op = schedule_request(s, row + 8)
    a = schedule_request(s, row + 24)
    b = schedule_request(s, row + 32)
    c = schedule_request(s, row + 40)
    if op == OP_JMP:
        put(w, MV_PC, a)
        return 1
    if op == OP_JCC:
        return mv_branch(o, w, schedule_request(s, row), a, b)
    if op == OP_PUSH or op == OP_POP or op == OP_LEAVE or op == OP_CALL or op == OP_RET:
        return mv_control(w, op, a, sp)
    if op == OP_NOP:
        return 1
    if op == OP_MUL:
        return mv_unsigned_multiply(o, w, a)
    if op == OP_CMP or op == OP_TEST:
        if a >= 16 or b >= 16:
            return 0
        left = get(w, a * 8)
        right = get(w, b * 8)
        if op == OP_TEST and left == right and left > MV_MUL_HIGH_TOKEN:
            tested = left - MV_MUL_HIGH_TOKEN
            if tested > get(w, MV_NODES):
                return 0
            put(w, MV_FLAGS, MV_MUL_HIGH_TEST)
            put(w, MV_FLAG_RESULT, tested)
        else:
            mv_remember_flags(w, op, left, right)
        return 1
    if op == OP_SETCC:
        return mv_setcc(o, w, a, b)
    if op == OP_CMOVNE:
        return mv_cmovne(o, w, a, b)
    if a >= 16:
        return 0
    if op == OP_IMM:
        value = mv_node(o, w, 2, 0, 0, b)
        if value == 0:
            return 0
        put(w, a * 8, value)
        return 1
    if op == OP_LOAD or op == OP_STORE or op == OP_LEA:
        return mv_memory(w, op, a, b, c, sp)
    if op == OP_IMMEDIATE_ALU:
        return mv_immediate(o, w, a, b, c)
    if op == OP_SHL or op == OP_SHR or op == OP_SAR or op == OP_NOT:
        return mv_unary(o, w, op, a, b)
    if b >= 16:
        return 0
    if op == OP_MOV:
        put(w, a * 8, get(w, b * 8))
        return 1
    return mv_arithmetic(o, w, op, a, get(w, b * 8))

def mv_control(w:mutbuf, op:u64, argument:u64, sp:u64) -> u64:
    if op == OP_PUSH or op == OP_CALL:
        if sp == MV_STACK_BASE:
            return 0
        if op == OP_CALL:
            # Entry RSP is 8 mod 16. A local CALL must execute with
            # RSP 16-aligned and use only a checked internal target.
            if (sp & 15) != 8:
                return 0
            # The independently bound relocation names only libc abort.
            # Its return-address push is the one terminal stack effect.
            if argument == 18446744073709551615:
                if sp - 8 < get(w, MV_LOW):
                    put(w, MV_LOW, sp - 8)
                return 3
            if argument >= MAX_TEXT:
                return 0
            value = MV_LOCAL_RETURN + get(w, MV_PC)
            put(w, MV_PC, argument)
        else:
            if argument >= 16:
                return 0
            value = get(w, argument * 8)
        put(w, 32, sp - 8)
        put(w, mv_stack_slot(sp - 8), value)
        return 1
    register = argument
    if op == OP_LEAVE:
        register = 5
        sp = get(w, 40)
    if mv_stack_position(sp) == False:
        return 0
    value = get(w, mv_stack_slot(sp))
    put(w, 32, sp + 8)
    if op == OP_RET:
        if value == MV_CALLER:
            return 2
        if value < MV_LOCAL_RETURN:
            return 0
        put(w, MV_PC, value - MV_LOCAL_RETURN)
    else:
        if register >= 16 or register == 4:
            return 0
        put(w, register * 8, value)
    return 1

def mv_memory(w:mutbuf, op:u64, a:u64, b:u64, c:u64, sp:u64) -> u64:
    if op == OP_STORE:
        base = a
        displacement = b
        register = c
    else:
        base = b
        displacement = c
        register = a
    if base >= 16 or register >= 16:
        return 0
    origin = get(w, base * 8)
    address = origin + displacement
    if mv_stack_position(origin) == False or mv_stack_access(sp, address, op == OP_STORE) == False:
        return 0
    if op == OP_STORE:
        put(w, mv_stack_slot(address), get(w, register * 8))
    elif op == OP_LOAD:
        put(w, register * 8, get(w, mv_stack_slot(address)))
    else:
        put(w, register * 8, address)
    return 1

def mv_immediate(o:mutbuf, w:mutbuf, group:u64, register:u64, immediate:u64) -> u64:
    if register >= 16:
        return 0
    if group == 7:
        value = mv_node(o, w, 2, 0, 0, immediate)
        if value == 0:
            return 0
        mv_remember_flags(w, OP_CMP, get(w, register * 8), value)
        return 1
    put(w, MV_FLAGS, 0)
    op = choose(group == 0, OP_ADD, choose(group == 1, OP_OR, choose(group == 4, OP_AND,
                choose(group == 5, OP_SUB, choose(group == 6, OP_XOR, 0)))))
    left = get(w, register * 8)
    if mv_stack_position(left):
        if op != OP_ADD and op != OP_SUB:
            return 0
        value = choose(op == OP_ADD, left + immediate, left - immediate)
        if mv_stack_position(value) == False:
            return 0
        put(w, register * 8, value)
        return 1
    right = mv_node(o, w, 2, 0, 0, immediate)
    return mv_arithmetic(o, w, op, register, right)

def mv_arithmetic(o:mutbuf, w:mutbuf, op:u64, register:u64, right:u64) -> u64:
    put(w, MV_FLAGS, 0)
    left = get(w, register * 8)
    nodes = get(w, MV_NODES)
    if left == 0 or left > nodes or right == 0 or right > nodes:
        return 0
    word = choose(op == OP_ADD, 9, choose(op == OP_SUB, 10, choose(op == OP_AND, 3,
           choose(op == OP_OR, 4, choose(op == OP_XOR, 5, choose(op == OP_IMUL, MV_PRODUCT, 0))))))
    if word == 0:
        return 0
    value = mv_node(o, w, word, left - 1, right - 1, 0)
    if value == 0:
        return 0
    put(w, register * 8, value)
    mv_remember_flags(w, op, left, right)
    put(w, MV_FLAG_RESULT, value)
    return 1

def mv_unsigned_multiply(o:mutbuf, w:mutbuf, source:u64) -> u64:
    if source >= 16:
        return 0
    left = get(w, 0)
    right = get(w, source * 8)
    nodes = get(w, MV_NODES)
    if left == 0 or left > nodes or right == 0 or right > nodes:
        return 0
    value = mv_node(o, w, MV_PRODUCT, left - 1, right - 1, 0)
    high_nonzero = mv_unsigned_product_flag(o, w, left - 1, right - 1)
    if value == 0 or high_nonzero == 0:
        return 0
    put(w, 0, value)
    # The high word is represented only by its exact nonzero predicate.
    # A later TEST of the same value is meaningful; generic reads refuse.
    put(w, 16, MV_MUL_HIGH_TOKEN + high_nonzero)
    mv_remember_flags(w, OP_MUL, left, right)
    put(w, MV_FLAG_RESULT, high_nonzero)
    return 1

def mv_unsigned_product_flag(o:mutbuf, w:mutbuf, left:u64, right:u64) -> u64:
    limit = mv_node(o, w, 2, 0, 0, 18446744073709551615)
    if limit == 0:
        return 0
    return mv_word(o, w, MV_PRODUCT_LIMIT, 1, left, right, limit - 1)

def mv_product_flag(o:mutbuf, w:mutbuf, operation:u64, condition:u64, left:u64, right:u64) -> u64:
    # MUL and two-operand IMUL define OF and CF identically. Other status
    # flags are undefined; no conditional read may silently use old flags.
    if (condition & 14) > 2:
        return 0
    if operation == OP_IMUL:
        flag = mv_signed_product_flag(o, w, left, right)
    else:
        flag = get(w, MV_FLAG_RESULT)
    if flag == 0 or (condition & 1) == 0:
        return flag
    return mv_word(o, w, 6, 1, flag - 1, 0, 0)

def mv_signed_product_flag(o:mutbuf, w:mutbuf, left:u64, right:u64) -> u64:
    # Unsigned magnitudes are exact, even for the signed minimum. The
    # independently checked product can be one larger on the negative side.
    zero = mv_node(o, w, 2, 0, 0, 0)
    sign_a = mv_word(o, w, 26, 1, left, 0, 63)
    sign_b = mv_word(o, w, 26, 1, right, 0, 63)
    if zero == 0 or sign_a == 0 or sign_b == 0:
        return 0
    negative_a = mv_node(o, w, 10, zero - 1, left, 0)
    negative_b = mv_node(o, w, 10, zero - 1, right, 0)
    if negative_a == 0 or negative_b == 0:
        return 0
    a = mv_node(o, w, 11, sign_a - 1, negative_a - 1, left)
    b = mv_node(o, w, 11, sign_b - 1, negative_b - 1, right)
    lower = mv_node(o, w, 2, 0, 0, 9223372036854775808)
    upper = mv_node(o, w, 2, 0, 0, 9223372036854775807)
    sign = mv_word(o, w, 5, 1, sign_a - 1, sign_b - 1, 0)
    if a == 0 or b == 0 or lower == 0 or upper == 0 or sign == 0:
        return 0
    limit = mv_node(o, w, 11, sign - 1, lower - 1, upper - 1)
    if limit == 0:
        return 0
    return mv_word(o, w, MV_PRODUCT_LIMIT, 1, a - 1, b - 1, limit - 1)

def mv_unary(o:mutbuf, w:mutbuf, op:u64, register:u64, count:u64) -> u64:
    left = get(w, register * 8)
    if left == 0 or left > get(w, MV_NODES):
        return 0
    if op == OP_NOT:
        value = mv_node(o, w, 6, left - 1, 0, 0)
    else:
        put(w, MV_FLAGS, 0)
        right = mv_node(o, w, 2, 0, 0, count & 63)
        if right == 0:
            return 0
        word = choose(op == OP_SHL, MV_SHIFT_LEFT, choose(op == OP_SHR, MV_SHIFT_RIGHT, MV_SHIFT_ARITHMETIC))
        value = mv_node(o, w, word, left - 1, right - 1, 0)
    if value == 0:
        return 0
    put(w, register * 8, value)
    return 1

def mv_remember_flags(w:mutbuf, operation:u64, left:u64, right:u64) -> u64:
    nodes = get(w, MV_NODES)
    if left == 0 or right == 0 or left > nodes or right > nodes:
        operation = 0
    put(w, MV_FLAGS, operation)
    put(w, MV_LEFT, left)
    put(w, MV_RIGHT, right)
    return 0

def mv_condition(o:mutbuf, w:mutbuf, condition:u64) -> u64:
    operation = get(w, MV_FLAGS)
    if operation == 0:
        return 0
    left = get(w, MV_LEFT) - 1
    right = get(w, MV_RIGHT) - 1
    if operation == OP_IMUL or operation == OP_MUL:
        return mv_product_flag(o, w, operation, condition, left, right)
    if operation == MV_MUL_HIGH_TEST:
        high_nonzero = get(w, MV_FLAG_RESULT)
        if condition == 5:
            return high_nonzero
        if condition == 4 and high_nonzero != 0:
            return mv_word(o, w, 6, 1, high_nonzero - 1, 0, 0)
        return 0
    if operation == OP_TEST:
        both = left + 1
        if left != right:
            both = mv_node(o, w, 3, left, right, 0)
        if both == 0:
            return 0
        return mv_result_condition(o, w, operation, condition, left, right, both - 1)
    if operation != OP_CMP and operation != OP_SUB:
        result = get(w, MV_FLAG_RESULT)
        if result == 0:
            return 0
        return mv_result_condition(o, w, operation, condition, left, right, result - 1)
    if operation == OP_SUB and (condition == 2 or condition == 3):
        borrow = mv_word(o, w, 23, 1, left, right, 0)
        if borrow == 0 or condition == 2:
            return borrow
        return mv_word(o, w, 6, 1, borrow - 1, 0, 0)
    predicate = choose(condition == 2, 12, choose(condition == 3, 15,
                choose(condition == 4, 7, choose(condition == 5, 8,
                choose(condition == 6, 13, choose(condition == 7, 14,
                choose(condition == 12, 16, choose(condition == 13, 19,
                choose(condition == 14, 17, choose(condition == 15, 18, 0))))))))))
    if predicate != 0:
        return mv_word(o, w, predicate, 1, left, right, 0)
    result = get(w, MV_FLAG_RESULT)
    if operation == OP_CMP:
        result = mv_node(o, w, 10, left, right, 0)
    if result == 0:
        return 0
    return mv_result_condition(o, w, OP_SUB, condition, left, right, result - 1)

def mv_result_condition(o:mutbuf, w:mutbuf, operation:u64, condition:u64, left:u64, right:u64, result:u64) -> u64:
    zero = mv_node(o, w, 2, 0, 0, 0)
    if zero == 0:
        return 0
    family = condition & 14
    if family == 4:
        return mv_word(o, w, choose(condition == 4, 7, 8), 1, result, zero - 1, 0)
    bit = mv_flag_family(o, w, operation, family, left, right, result, zero - 1)
    if bit == 0 or (condition & 1) == 0:
        return bit
    return mv_word(o, w, 6, 1, bit - 1, 0, 0)

def mv_flag_family(o:mutbuf, w:mutbuf, op:u64, family:u64, left:u64, right:u64, result:u64, zero:u64) -> u64:
    if family == 8:
        return mv_word(o, w, 16, 1, result, zero, 0)
    if family == 0 or family == 12 or family == 14:
        predicate = mv_sign_flag(o, w, op, family, left, right, result, zero)
    elif family == 2 or family == 6:
        if op == OP_ADD:
            predicate = mv_word(o, w, 22, 1, left, right, 0)
        else:
            # SUB was reduced to ordered operands before this helper.
            predicate = mv_word(o, w, 2, 1, 0, 0, 0)
    else:
        # Parity branches are not admitted by the decoder.
        return 0
    if predicate == 0 or (family != 6 and family != 14):
        return predicate
    equal = mv_word(o, w, 7, 1, result, zero, 0)
    if equal == 0:
        return 0
    return mv_word(o, w, 4, 1, predicate - 1, equal - 1, 0)

def mv_sign_flag(o:mutbuf, w:mutbuf, op:u64, family:u64, left:u64, right:u64, result:u64, zero:u64) -> u64:
    if op != OP_ADD and op != OP_SUB:
        if family != 0:
            return mv_word(o, w, 16, 1, result, zero, 0)
        return mv_word(o, w, 2, 1, 0, 0, 0)
    # These are the existing exact, width-parametric overflow predicates.
    # The x86 operand width here is 64, irrespective of the Core source type.
    overflow = mv_word(o, w, choose(op == OP_ADD, 24, 25), 1, left, right, 0)
    if overflow == 0 or family == 0:
        return overflow
    sign = mv_word(o, w, 16, 1, result, zero, 0)
    if sign == 0:
        return 0
    return mv_word(o, w, 5, 1, overflow - 1, sign - 1, 0)

def mv_setcc(o:mutbuf, w:mutbuf, condition:u64, register:u64) -> u64:
    if register >= 16 or register == 4:
        return 0
    previous = get(w, register * 8)
    if previous == 0 or previous > get(w, MV_NODES):
        return 0
    bit = mv_condition(o, w, condition)
    if bit == 0:
        return 0
    # SETcc writes one byte and preserves the upper 56 bits and flags.
    start = MV_HEADER + 40 * (previous - 1)
    upper_zero = get(o, start) == 2 and get(o, start + 32) < 256
    value = mv_node(o, w, 30, bit - 1, 0, 0)
    if value == 0:
        return 0
    if upper_zero == False:
        mask = mv_node(o, w, 2, 0, 0, 18446744073709551360)
        if mask == 0:
            return 0
        upper = mv_node(o, w, 3, previous - 1, mask - 1, 0)
        if upper == 0:
            return 0
        value = mv_node(o, w, 4, upper - 1, value - 1, 0)
        if value == 0:
            return 0
    put(w, register * 8, value)
    return 1

def mv_cmovne(o:mutbuf, w:mutbuf, register:u64, source:u64) -> u64:
    if register >= 16 or source >= 16 or register == 4:
        return 0
    old = get(w, register * 8)
    new = get(w, source * 8)
    nodes = get(w, MV_NODES)
    if old == 0 or new == 0 or old > nodes or new > nodes:
        return 0
    condition = mv_condition(o, w, 5)
    if condition == 0:
        return 0
    value = mv_node(o, w, 11, condition - 1, new - 1, old - 1)
    if value == 0:
        return 0
    put(w, register * 8, value)
    return 1

def mv_branch(o:mutbuf, w:mutbuf, pc:u64, condition:u64, target:u64) -> u64:
    depth = get(w, MV_BRANCH_SEEN)
    if depth >= MV_BRANCH_DEPTH or target >= MAX_TEXT:
        return 0
    frame = MV_BRANCHES + depth * 32
    put(w, MV_BRANCH_SEEN, depth + 1)
    if depth < get(w, MV_PREFIX):
        # Nothing from an alternative prefix is reused. Replay starts from
        # the fixed ABI state, chasing precisely the prior branch decisions.
        if pc != get(w, frame):
            return 0
        if get(w, frame + 16) != 0:
            put(w, MV_PC, target)
        return 1
    predicate = mv_condition(o, w, condition)
    if predicate == 0:
        return 0
    put(w, frame, pc)
    put(w, frame + 8, predicate)
    put(w, frame + 16, 0)
    return 1

'''

QUERY_SOURCE = r'''
def format_proof_query(s:readbuf, o:mutbuf) -> u32:
    if length(s) < 40 or length(s) > QUERY_BYTES:
        return 4294967295
    if query_uint(s, 0, 8) != QUERY_REQUEST or query_uint(s, 24, 8) != 0:
        return 4294967295
    variables = query_uint(s, 8, 8)
    clauses = query_uint(s, 16, 8)
    entries = query_uint(s, 32, 8)
    if variables > QUERY_VARIABLES or clauses > QUERY_CLAUSES or entries > ((QUERY_BYTES - 40) >> 1):
        return 4294967295
    if length(s) != 40 + entries * 2 or length(o) < 64 + variables * 40 + entries * 24:
        return 4294967295
    at = query_prefix(o, 0)
    variable = 1
    while variable <= variables:
        at = query_declare(o, at)
        at = query_decimal(o, at, variable)
        at = query_sort(o, at)
        variable = variable + 1
    cursor = 0
    count = 0
    while cursor < entries:
        size = query_clause_size(s, cursor, entries, variables)
        if size == 18446744073709551615:
            return 4294967295
        at = query_assert(o, at)
        if size == 0:
            at = query_empty(o, at)
        elif size > 1:
            at = query_group(o, at)
        index = 0
        while index < size:
            token = query_uint(s, 40 + (cursor + index) * 2, 2)
            if index != 0:
                store(o, at, 32)
                at = at + 1
            at = query_literal(o, at, token)
            index = index + 1
        if size > 1:
            store(o, at, 41)
            at = at + 1
        at = query_end_clause(o, at)
        cursor = cursor + size + 1
        count = count + 1
    if count != clauses:
        return 4294967295
    return query_check(o, at)

def query_uint(s:readbuf, at:u64, count:u64) -> u64:
    result = 0
    i = 0
    while i < count:
        result = result | (byte(s, at + i) << (i * 8))
        i = i + 1
    return result

def query_clause_size(s:readbuf, first:u64, entries:u64, variables:u64) -> u64:
    cursor = first
    while cursor < entries:
        token = query_uint(s, 40 + cursor * 2, 2)
        if token == 0:
            return cursor - first
        variable = token >> 1
        if variable == 0 or variable > variables:
            return 18446744073709551615
        cursor = cursor + 1
    return 18446744073709551615

def query_literal(o:mutbuf, at:u64, token:u64) -> u64:
    start = at
    negative = token & 1
    if negative != 0:
        start = query_negative(o, start)
    store(o, start, 118)
    end = query_decimal(o, start + 1, token >> 1)
    if negative != 0:
        store(o, end, 41)
        end = end + 1
    return end

def query_decimal(o:mutbuf, at:u64, value:u64) -> u64:
    place = 1000
    end = at
    remaining = value
    while place != 0:
        digit = 0
        while remaining >= place:
            remaining = remaining - place
            digit = digit + 1
        if digit != 0 or end != at or place == 1:
            store(o, end, 48 + digit)
            end = end + 1
        place = choose(place == 1000, 100, choose(place == 100, 10, choose(place == 10, 1, 0)))
    return end

def query_write(o:mutbuf, at:u64, value:u64, count:u64) -> u64:
    index = 0
    while index < count:
        store(o, at + index, (value >> (index * 8)) & 255)
        index = index + 1
    return at + count
'''


def query_fragments():
    functions = []
    for name, raw in QUERY_FRAGMENTS.items():
        lines = [f'def query_{name}(o:mutbuf, at:u64) -> u64:']
        for offset in range(0, len(raw), 8):
            piece = raw[offset:offset + 8]
            lines.append(f'    at = query_write(o, at, {int.from_bytes(piece, "little")}, {len(piece)})')
        functions.append('\n'.join(lines + ['    return at', '']))
    return '\n'.join(functions)


def document():
    class Constants(ast.NodeTransformer):
        def visit_Name(self, node):
            return ast.copy_location(ast.Constant(FIELDS[node.id]), node) if node.id in FIELDS else node

    nodes = ast.fix_missing_locations(Constants().visit(ast.parse(
        SOURCE + QUERY_SOURCE + '\n' + query_fragments()))).body
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
