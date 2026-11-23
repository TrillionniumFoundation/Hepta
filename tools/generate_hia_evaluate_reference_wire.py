"""Author HIA's independent scalar reference program wire projection."""

from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_program import MAX_BYTES, MAX_DEPTH, MAX_FUNCTIONS, MAX_NODES
from hepta.hia_scalar_reference_native import OPCODES
from hepta.hia_scalar_reference_wire import (
    BRANCH, CALL, CONSTANT, JUMP, MAX_FRAME_WORDS, MAX_PACKET_BYTES, RETURN, TRAP,
)
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_worker_finite_reference import (
    KEYS, POLICY as FINITE, enum_reader, program as finite_program,
)
from tools.generate_hia_worker_inspection_effect import function

SOURCE = Path('examples/hia_bootstrap/evaluate_reference_wire.hepta')
MAGIC = int.from_bytes(b'HIAERW01', 'little')
WORK_BYTES = 48 << 20

POLICY = r'''
# Input: [admitted canonical Core, selected function name].
# Output: HIAERW01, slot bound, bounce bound, program end, return count, three
# zero words, the interpreter's exact immutable instructions (from byte 64),
# then the scalar return type words. This kernel does not execute Core.
def reference_wire(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 8 or length(s) > INPUT_MAX or length(o) < PACKET_MAX or length(w) < WORK_MAX:
        return BAD
    put(o, 48, NODE_MAX + 2)
    put(o, 56, DEPTH_MAX + 1)
    used = widen(decode_json(s, w, o))
    if used >= 4294967292 or get(w, 64) != 5 or get(w, 96) != 2:
        return BAD
    core = child(w, 64)
    wanted = next(w, core)
    if object(w, core) == False or kind(w, wanted) != 4:
        return BAD
    functions = lookup(w, core, K_functions)
    entry = named(w, functions, wanted, K_name)
    if entry == NONE:
        return BAD
    a = (used + 7) & 18446744073709551608
    if length(w) - a < MAP_BYTES:
        return BAD
    put(w, a + 8, 1)
    put(w, a + 16, 1)
    put(w, a + 56, 1)
    put(w, a + 64, 0)
    put(w, a + 96, entry)
    if collect_functions(w, a, functions) == False:
        return BAD
    if index_program(o, w, a) == False or emit_program(s, o, w, a) == False:
        return BAD
    return finish_program(o, w, a, lookup(w, entry, K_returns))

# Reachable function order is the interpreter wire's breadth-first call order,
# not declaration order. Cycles need no special case: append each function once.
def collect_functions(w:mutbuf, a:u64, functions:u64) -> bool:
    index = 0
    while index < get(w, a + 56):
        fn = get(w, a + 96 + index * 32)
        block = child(w, lookup(w, fn, K_blocks))
        while block != NONE:
            ins = child(w, lookup(w, block, K_ops))
            while ins != NONE:
                if opcode(w, lookup(w, ins, K_op)) == T_CALL:
                    name = lookup(w, lookup(w, ins, K_attrs), K_function)
                    if function_index(w, a, name) == NONE:
                        added = named(w, functions, name, K_name)
                        count = get(w, a + 56)
                        if added == NONE or count == FUNCTION_MAX:
                            return False
                        put(w, a + 96 + count * 32, added)
                        put(w, a + 56, count + 1)
                ins = next(w, ins)
            block = next(w, block)
        index = index + 1
    return True

def function_index(w:mutbuf, a:u64, name:u64) -> u64:
    index = 0
    while index < get(w, a + 56):
        fn = get(w, a + 96 + 32 * index)
        if eq_text(w, name, lookup(w, fn, K_name)):
            return index
        index = index + 1
    return NONE

def index_program(o:mutbuf, w:mutbuf, a:u64) -> bool:
    cursor = 64 + 8 * get(w, a + 56)
    put(w, a, cursor)
    index = 0
    while index < get(w, a + 56):
        fn_row = a + 96 + 32 * index
        if index_blocks(o, w, a, fn_row) == False:
            return False
        put(o, 64 + 8 * index, get(w, fn_row + 24))
        index = index + 1
    return True

def index_blocks(o:mutbuf, w:mutbuf, a:u64, row:u64) -> bool:
    fn = get(w, row)
    params = lookup(w, fn, K_params)
    returns = lookup(w, fn, K_returns)
    blocks = lookup(w, fn, K_blocks)
    if kind(w, blocks) != 5 or kind(w, params) != 5 or kind(w, returns) != 5:
        return False
    typ = child(w, returns)
    while typ != NONE:
        if type_code(w, typ) == NONE:
            return False
        typ = next(w, typ)
    start = get(w, a + 64)
    count = get(w, blocks + 32)
    if count == 0 or count > NODE_MAX - start:
        return False
    put(w, row + 8, start)
    put(w, row + 16, count)
    put(w, row + 24, 0)
    entry = lookup(w, fn, K_entry)
    block = child(w, blocks)
    while block != NONE:
        ops = lookup(w, block, K_ops)
        if kind(w, ops) != 5:
            return False
        pc = reserve(o, w, a, 8 * (get(w, ops + 32) + 1))
        if pc == NONE:
            return False
        if eq_text(w, entry, lookup(w, block, K_id)):
            if same_parameters(w, params, lookup(w, block, K_params)) == False:
                return False
            put(w, row + 24, pc)
        put(w, a + BLOCK_BASE + start * 16, block)
        put(w, a + BLOCK_BASE + start * 16 + 8, pc)
        start = start + 1
        block = next(w, block)
    put(w, a + 64, start)
    return get(w, row + 24) != 0

def same_parameters(w:mutbuf, params:u64, block_params:u64) -> bool:
    if kind(w, block_params) != 5 or get(w, params + 32) != get(w, block_params + 32):
        return False
    left = child(w, params)
    right = child(w, block_params)
    while left != NONE:
        if eq_text(w, lookup(w, left, K_name), lookup(w, right, K_name)) == False:
            return False
        if eq_text(w, lookup(w, left, K_type), lookup(w, right, K_type)) == False:
            return False
        left = next(w, left)
        right = next(w, right)
    return True

def emit_program(s:readbuf, o:mutbuf, w:mutbuf, a:u64) -> bool:
    index = 0
    while index < get(w, a + 56):
        row = a + 96 + 32 * index
        start = get(w, row + 8)
        count = get(w, row + 16)
        put(w, a + 24, count)
        put(w, a + 40, start)
        at = 0
        while at < count:
            block = a + BLOCK_BASE + 16 * (start + at)
            if project_block(s, o, w, a, get(w, block), get(w, block + 8)) == False:
                return False
            at = at + 1
        index = index + 1
    return True

def emit_instruction(s:readbuf, o:mutbuf, w:mutbuf, a:u64, ins:u64, pc:u64) -> bool:
    if opcode(w, lookup(w, ins, K_op)) != T_CALL:
        return emit_scalar(s, o, w, a, ins, pc)
    inputs = lookup(w, ins, K_args)
    outputs = lookup(w, ins, K_out)
    if kind(w, inputs) != 5 or kind(w, outputs) != 5:
        return False
    callee = function_index(w, a, lookup(w, lookup(w, ins, K_attrs), K_function))
    if callee == NONE:
        return False
    args = value_list(o, w, a, inputs)
    count = get(w, outputs + 32)
    at = reserve(o, w, a, count)
    if args == NONE or at == NONE:
        return False
    if count > get(w, a + 16):
        put(w, a + 16, count)
    value = child(w, outputs)
    index = 0
    while value != NONE:
        slot = define_value(w, a, value)
        if slot == NONE:
            return False
        put(o, at + 8 * index, slot)
        value = next(w, value)
        index = index + 1
    clear_command(o, pc)
    put(o, pc, T_CALL)
    put(o, pc + 8, callee)
    put(o, pc + 16, args)
    put(o, pc + 24, get(w, inputs + 32))
    put(o, pc + 32, at)
    put(o, pc + 40, count)
    return True

def block_row(w:mutbuf, a:u64, name:u64) -> u64:
    start = get(w, a + 40)
    index = 0
    while index < get(w, a + 24):
        row = a + BLOCK_BASE + 16 * (start + index)
        if eq_text(w, name, lookup(w, get(w, row), K_id)):
            return row
        index = index + 1
    return NONE

def finish_program(o:mutbuf, w:mutbuf, a:u64, returns:u64) -> u64:
    registers = get(w, a + 8)
    bounce = get(w, a + 16)
    count = get(w, returns + 32)
    end = get(w, a)
    if registers + bounce > FRAME_MAX or count > (length(o) - end) >> 3:
        return BAD
    typ = child(w, returns)
    index = 0
    while typ != NONE:
        put(o, end + 8 * index, type_code(w, typ))
        typ = next(w, typ)
        index = index + 1
    clear_command(o, 0)
    put(o, 0, WIRE)
    put(o, 8, registers)
    put(o, 16, bounce)
    put(o, 24, end)
    put(o, 32, count)
    return end + 8 * count
'''


def program():
    finite = finite_program()
    # The finite proof role retains its smaller admission bounds; reuse only
    # grammar readers and the interpreter's instruction/edge encoders.
    shared = ('project_block', 'scalar_operands', 'emit_terminal', 'emit_edge',
              'value_list', 'capture_value', 'define_value', 'def_type', 'value_row',
              'named', 'reserve', 'clear_command', 'object', 'kind', 'child',
              'next', 'eq_text')
    values = {
        'BAD': 0xfffffffd, 'NONE': (1 << 64) - 1, 'INPUT_MAX': MAX_BYTES + 140,
        'PACKET_MAX': MAX_PACKET_BYTES, 'WORK_MAX': WORK_BYTES, 'NODE_MAX': MAX_NODES,
        'DEPTH_MAX': MAX_DEPTH, 'FUNCTION_MAX': MAX_FUNCTIONS, 'FRAME_MAX': MAX_FRAME_WORDS,
        'WIRE': MAGIC, 'T_CALL': CALL, 'CONST': CONSTANT, 'RET': RETURN, 'T_TRAP': TRAP,
        'T_JUMP': JUMP, 'T_BRANCH': BRANCH, 'VALUE_MAX': MAX_NODES,
        'BLOCK_BASE': 96 + 32 * MAX_FUNCTIONS,
    }
    values['VALUE_BASE'] = values['BLOCK_BASE'] + 16 * MAX_NODES
    values['MAP_BYTES'] = values['VALUE_BASE'] + 24 * MAX_NODES
    values.update({f'K_{key}': index for index, key in enumerate(KEYS, 1)})
    scalar = function(FINITE, 'emit_instruction').replace('def emit_instruction(', 'def emit_scalar(')
    source = '\n'.join((POLICY, scalar, *(function(FINITE, name) for name in shared)))
    source = re.sub(r'\b(' + '|'.join(values) + r')\b', lambda match: str(values[match[0]]), source)
    start = finite.index('\ndef opcode(')
    end = finite.index('\ndef cast_opcode(', start)
    opcodes = [('const', CONSTANT), ('call', CALL), *sorted(OPCODES.items())]
    grammar = (finite[finite.index('\ndef key_id('):start], enum_reader('opcode', opcodes), finite[end:])
    return '\n'.join((source, *grammar))


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)), encoding='utf-8')
