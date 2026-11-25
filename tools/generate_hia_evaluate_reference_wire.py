"""Author HIA's independent reference program wire projection."""

from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_program import MAX_BYTES, MAX_DEPTH, MAX_FUNCTIONS, MAX_NODES
from hepta.hia_scalar_reference_native import OPCODES
from hepta.hia_scalar_reference_wire import (
    BRANCH, CALL, CONSTANT, JUMP, MAX_FRAME_WORDS, MAX_PACKET_BYTES, RETURN, TRAP,
    RESOURCE, RESOURCE_CODES, RESOURCE_KINDS, RESOURCE_SIGNATURES, RESOURCE_RETURN, RETURN_LOANS_CODE, TYPES,
)
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_worker_finite_reference import (
    KEYS, POLICY as FINITE, enum_reader, key_reader, program as finite_program,
)
from tools.generate_hia_worker_inspection_effect import function

SOURCE = Path('examples/hia_bootstrap/evaluate_reference_wire.hepta')
MAGIC = int.from_bytes(b'HIAERW01', 'little')
RESOURCE_MAGIC = int.from_bytes(b'HIAERW02', 'little')
WORK_BYTES = 48 << 20

POLICY = r'''
# Optional third item true selects owned buffers, chains and returned loans.
# Internal compact calls use numeric 0 or 1 for the scalar or owned profile.
# Both packet versions carry slot bound, bounce bound, program end, return
# count, resource-site flag and two zero words, followed by the interpreter's
# immutable instructions (from byte 64) and the return type words.
def reference_wire(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 8 or length(s) > INPUT_MAX or length(o) < 4096 or length(w) < 4096:
        return BAD
    put(o, 48, NODE_MAX + 3)
    put(o, 56, DEPTH_MAX + 1)
    used = widen(decode_json(s, w, o))
    if used >= 4294967292 or get(w, 64) != 5:
        return BAD
    arity = get(w, 96)
    if (arity != 2 and arity != 3) or get(w, 8) > NODE_MAX + arity:
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
    if length(w) - a < BLOCK_BASE + 40 * get(w, 8):
        return BAD
    mode = next(w, wanted)
    if arity == 3 and kind(w, mode) == 3:
        if get(w, mode + 32) != 1:
            return BAD
        digit = byte(s, get(w, mode + 24))
        if digit != 48 and digit != 49:
            return BAD
        put(w, a + 72, widen(digit) - 48)
    else:
        if length(o) < PACKET_MAX or length(w) < WORK_MAX:
            return BAD
        if arity == 3 and kind(w, mode) != 2:
            return BAD
        put(w, a + 72, choose(arity == 3, 1, 0))
    put(w, a + 80, 0)
    put(w, a + 8, 1)
    put(w, a + 16, 1)
    put(w, a + 56, 1)
    put(w, a + 64, 0)
    put(w, a + 96, entry)
    if collect_functions(w, a, functions) == False:
        return BAD
    if index_program(o, w, a) == False or index_loans(o, w, a) == False:
        return BAD
    if emit_program(s, o, w, a) == False:
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
        if admitted_type(w, a, typ) == NONE:
            return False
        typ = next(w, typ)
    loan = a + LOAN_BASE + row - (a + 96)
    origins = lookup(w, fn, K_return_loans)
    put(w, loan, 0)
    put(w, loan + 8, 0)
    put(w, loan + 16, 0)
    put(w, loan + 24, NONE)
    if origins != NONE:
        if kind(w, origins) != 5 or get(w, origins + 32) != get(w, returns + 32):
            return False
        origin = child(w, origins)
        while origin != NONE:
            if kind(w, origin) != 0:
                put(w, loan + 24, origins)
            origin = next(w, origin)
    start = get(w, a + 64)
    count = get(w, blocks + 32)
    if count == 0 or count > get(w, 8) - start:
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
        extra = 0
        if get(w, loan + 24) != NONE:
            nslots = get(w, lookup(w, block, K_params) + 32)
            ins = child(w, ops)
            while ins != NONE:
                nslots = nslots + get(w, lookup(w, ins, K_out) + 32)
                ins = next(w, ins)
            if nslots > get(w, loan):
                put(w, loan, nslots)
            term = lookup(w, block, K_term)
            extra = choose(term_code(w, lookup(w, term, K_op)) == RET, 1, 0)
        pc = reserve(o, w, a, 8 * (get(w, ops + 32) + 1 + extra))
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

# Reserve entry parameter copies before appending any instruction operands.
# The wire records parameter position and persistent frame slot for each
# distinct origin in the function's declared return order.
def parameter_index(w:mutbuf, params:u64, name:u64) -> u64:
    index = 0
    param = child(w, params)
    while param != NONE:
        if eq_text(w, lookup(w, param, K_name), name):
            return index
        index = index + 1
        param = next(w, param)
    return NONE

def binding_index(o:mutbuf, at:u64, count:u64, position:u64) -> u64:
    index = 0
    while index < count:
        if get(o, at + 16 * index) == position:
            return index
        index = index + 1
    return NONE

def index_loans(o:mutbuf, w:mutbuf, a:u64) -> bool:
    index = 0
    while index < get(w, a + 56):
        loan = a + LOAN_BASE + 32 * index
        origins = get(w, loan + 24)
        if origins != NONE:
            fn = get(w, a + 96 + 32 * index)
            params = lookup(w, fn, K_params)
            first = get(w, loan)
            table = get(w, a)
            count = 0
            origin = child(w, origins)
            while origin != NONE:
                if kind(w, origin) != 0:
                    pos = parameter_index(w, params, origin)
                    if pos == NONE:
                        return False
                    if binding_index(o, table, count, pos) == NONE:
                        pair = reserve(o, w, a, 2)
                        if pair == NONE:
                            return False
                        put(o, pair, pos)
                        put(o, pair + 8, first + count)
                        count = count + 1
                origin = next(w, origin)
            put(w, loan + 8, count)
            put(w, loan + 16, table)
            slots = first + count + get(w, origins + 32)
            if slots > get(w, a + 8):
                put(w, a + 8, slots)
        index = index + 1
    return True

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
        put(w, a + 88, index)
        at = 0
        while at < count:
            block = a + BLOCK_BASE + 16 * (start + at)
            if project_block(s, o, w, a, get(w, block), get(w, block + 8)) == False:
                return False
            at = at + 1
        index = index + 1
    return True

def emit_instruction(s:readbuf, o:mutbuf, w:mutbuf, a:u64, ins:u64, pc:u64) -> bool:
    operation = lookup(w, ins, K_op)
    tag = opcode(w, operation)
    callee = 0
    resource = NONE
    if tag == T_CALL:
        callee = function_index(w, a, lookup(w, lookup(w, ins, K_attrs), K_function))
        if callee == NONE:
            return False
    else:
        if get(w, a + 72) != 0 and tag == NONE:
            resource = resource_opcode(w, operation)
        if resource == NONE:
            return emit_scalar(s, o, w, a, ins, pc)
    inputs = lookup(w, ins, K_args)
    outputs = lookup(w, ins, K_out)
    if kind(w, inputs) != 5 or kind(w, outputs) != 5:
        return False
    operation_code = T_CALL
    if resource != NONE:
        first = 0
        if child(w, inputs) != NONE:
            first_row = value_row(w, a, child(w, inputs))
            if first_row == NONE:
                return False
            first_type = get(w, first_row + 8)
            if first_type >= SCALAR_COUNT:
                first = first_type - SCALAR_COUNT + 1
        if resource_accepts(resource, first) == False:
            return False
        site = reserve(o, w, a, 4)
        if site == NONE:
            return False
        put(o, site, resource)
        put(o, site + 8, first)
        put(o, site + 16, get(w, inputs + 32))
        put(o, site + 24, get(w, outputs + 32))
        operation_code = T_RESOURCE
        callee = site
        put(w, a + 80, 1)
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
    put(o, pc, operation_code)
    put(o, pc + 8, callee)
    put(o, pc + 16, args)
    put(o, pc + 24, get(w, inputs + 32))
    put(o, pc + 32, at)
    put(o, pc + 40, count)
    if operation_code == T_CALL:
        loan = a + LOAN_BASE + 32 * callee
        put(o, pc + 48, get(w, loan + 16))
        put(o, pc + 56, get(w, loan + 8))
    return True

def slot_run(o:mutbuf, w:mutbuf, a:u64, start:u64, count:u64) -> u64:
    at = reserve(o, w, a, count)
    if at == NONE:
        return NONE
    i = 0
    while i < count:
        put(o, at + 8 * i, start + i)
        i = i + 1
    return at

def write_restorations(o:mutbuf, w:mutbuf, loan:u64, fn:u64, site:u64) -> bool:
    params = lookup(w, fn, K_params)
    returned = child(w, lookup(w, fn, K_returns))
    origins = get(w, loan + 24)
    count = get(w, origins + 32)
    origin = child(w, origins)
    i = 0
    while i < count:
        tag = 0
        if kind(w, origin) != 0:
            pos = parameter_index(w, params, origin)
            bind = binding_index(o, get(w, loan + 16), get(w, loan + 8), pos)
            if pos == NONE or bind == NONE or returned == NONE:
                return False
            tag = ((count + bind + 1) << 1) | choose(type_code(w, returned) == MUT_TYPE, 1, 0)
        put(o, site + 32 + 8 * i, tag)
        returned = next(w, returned)
        i = i + 1
        origin = next(w, origin)
    return True

def write_return_inputs(o:mutbuf, w:mutbuf, a:u64, loan:u64, values:u64, at:u64) -> bool:
    value = child(w, values)
    i = 0
    while value != NONE:
        row = value_row(w, a, value)
        if row == NONE:
            return False
        put(o, at + 8 * i, get(w, row + 16))
        i = i + 1
        value = next(w, value)
    j = 0
    while j < get(w, loan + 8):
        put(o, at + 8 * (i + j), get(w, loan) + j)
        j = j + 1
    return True

def wire_terminal(o:mutbuf, w:mutbuf, a:u64, term:u64, pc:u64) -> bool:
    index = get(w, a + 88)
    loan = a + LOAN_BASE + 32 * index
    origins = get(w, loan + 24)
    if origins == NONE or term_code(w, lookup(w, term, K_op)) != RET:
        return emit_terminal(o, w, a, term, pc)
    fn = get(w, a + 96 + 32 * index)
    count = get(w, origins + 32)
    saved = get(w, loan + 8)
    values = lookup(w, term, K_values)
    if get(w, values + 32) != count:
        return False
    site = reserve(o, w, a, 4 + count)
    args = reserve(o, w, a, count + saved)
    first = get(w, loan)
    outs = slot_run(o, w, a, first + saved, count)
    final = slot_run(o, w, a, first + saved, count)
    if site == NONE or args == NONE or outs == NONE or final == NONE:
        return False
    put(o, site, T_RESTORE)
    put(o, site + 8, 0)
    put(o, site + 16, count + saved)
    put(o, site + 24, count)
    if write_restorations(o, w, loan, fn, site) == False:
        return False
    if write_return_inputs(o, w, a, loan, values, args) == False:
        return False
    if count + saved > get(w, a + 16):
        put(w, a + 16, count + saved)
    clear_command(o, pc)
    put(o, pc, T_RESOURCE)
    put(o, pc + 8, site)
    put(o, pc + 16, args)
    put(o, pc + 24, count + saved)
    put(o, pc + 32, outs)
    put(o, pc + 40, count)
    clear_command(o, pc + 64)
    put(o, pc + 64, T_RESOURCE_RETURN)
    put(o, pc + 72, final)
    put(o, pc + 80, count)
    put(w, a + 80, 1)
    return True


# Optional scratch beyond the historical arena accelerates lookup. A caller
# supplying exactly the original extent retains the original linear fallback.
# Every block resets the index; duplicates preserve the first declared row.
def value_index_base(w:mutbuf, a:u64) -> u64:
    return a + BLOCK_BASE + 40 * get(w, 8)

def value_name_hash(w:mutbuf, name:u64) -> u64:
    at = get(w, name + 24)
    end = at + get(w, name + 32)
    result = 14695981039346656037
    while at < end:
        result = (result ^ widen(byte(w, at))) * 1099511628211
        at = at + 1
    return result

def value_index_prepare(w:mutbuf, a:u64, params:u64, ops:u64) -> u64:
    base = value_index_base(w, a)
    if base > length(w) or length(w) - base < 16:
        return 0
    put(w, base, 0)
    if kind(w, ops) != 5:
        return 0
    size = get(w, params + 32)
    ins = child(w, ops)
    while ins != NONE:
        outputs = lookup(w, ins, K_out)
        if kind(w, outputs) != 5:
            return 0
        size = size + get(w, outputs + 32)
        ins = next(w, ins)
    if size > get(w, 8):
        return 0
    capacity = 2
    while capacity < size * 2:
        capacity = capacity * 2
    if capacity > (length(w) - base - 16) >> 3:
        return 0
    put(w, base, capacity - 1)
    index = 0
    while index < capacity:
        put(w, base + 16 + 8 * index, 0)
        index = index + 1
    return 0

def value_index_insert(w:mutbuf, a:u64, row:u64) -> u64:
    base = value_index_base(w, a)
    if base > length(w) or length(w) - base < 16:
        return 0
    mask = get(w, base)
    if mask == 0:
        return 0
    name = get(w, row)
    index = value_name_hash(w, name) & mask
    checked = 0
    while checked <= mask:
        at = base + 16 + 8 * index
        old = get(w, at)
        if old == 0:
            put(w, at, row)
            return 0
        if eq_text(w, name, get(w, old)):
            return 0
        index = (index + 1) & mask
        checked = checked + 1
    # No valid block can fill a table sized for twice its definitions.
    # Preserve the prior lookup behavior if private malformed input does.
    put(w, base, 0)
    return 0

def value_row(w:mutbuf, a:u64, name:u64) -> u64:
    if kind(w, name) != 4:
        return NONE
    base = value_index_base(w, a)
    mask = 0
    if base <= length(w) and length(w) - base >= 16:
        mask = get(w, base)
    if mask == 0:
        index = 0
        while index < get(w, a + 32):
            row = a + VALUE_BASE + 24 * index
            if eq_text(w, name, get(w, row)):
                return row
            index = index + 1
        return NONE
    index = value_name_hash(w, name) & mask
    checked = 0
    while checked <= mask:
        row = get(w, base + 16 + 8 * index)
        if row == 0:
            return NONE
        if eq_text(w, name, get(w, row)):
            return row
        index = (index + 1) & mask
        checked = checked + 1
    return NONE

def admitted_type(w:mutbuf, a:u64, node:u64) -> u64:
    typ = type_code(w, node)
    if get(w, a + 72) == 0 and typ >= SCALAR_COUNT:
        return NONE
    return typ

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
    put(o, 0, choose(get(w, a + 72) == 1, RESOURCE_WIRE, WIRE))
    put(o, 40, get(w, a + 80))
    put(o, 8, registers)
    put(o, 16, bounce)
    put(o, 24, end)
    put(o, 32, count)
    return end + 8 * count
'''


def compact_enum(name, members):
    """Match verified ASCII schema lexemes in one Core function."""
    lines = [f'def {name}(w:mutbuf, node:u64) -> u64:',
             '    if kind(w, node) != 4:', f'        return {(1 << 64) - 1}',
             '    size = get(w, node + 32)', '    at = get(w, node + 24)']
    for label, value in members:
        raw = label.encode('ascii')
        terms = []
        for offset in range(0, len(raw), 8):
            chunk = raw[offset:offset + 8]
            terms.append(f'match_word(w, at + {offset}, {len(chunk)}) == {int.from_bytes(chunk, "little")}')
        lines.extend((f'    if size == {len(raw)} and ' + ' and '.join(terms) + ':',
                      f'        return {value}'))
    return '\n'.join((*lines, f'    return {(1 << 64) - 1}'))


def program():
    # The wrapper adds the selected function name and the optional resource mode
    # to an admitted Core document, which can itself fill MAX_BYTES.
    finite = finite_program().replace(f'length(s) > {MAX_BYTES} or',
                                     f'length(s) > {MAX_BYTES + 140} or')
    # The finite proof role retains its smaller admission bounds; reuse only
    # grammar readers and the interpreter's instruction/edge encoders.
    shared = ('scalar_operands', 'emit_terminal', 'emit_edge',
              'value_list', 'capture_value', 'def_type',
              'named', 'reserve', 'clear_command', 'object', 'kind', 'child',
              'next', 'eq_text')
    values = {
        'BAD': 0xfffffffd, 'NONE': (1 << 64) - 1, 'INPUT_MAX': MAX_BYTES + 140,
        'PACKET_MAX': MAX_PACKET_BYTES, 'WORK_MAX': WORK_BYTES, 'NODE_MAX': MAX_NODES,
        'DEPTH_MAX': MAX_DEPTH, 'FUNCTION_MAX': MAX_FUNCTIONS, 'FRAME_MAX': MAX_FRAME_WORDS,
        'WIRE': MAGIC, 'RESOURCE_WIRE': RESOURCE_MAGIC, 'T_RESOURCE': RESOURCE,
        'SCALAR_COUNT': len(TYPES), 'MUT_TYPE': len(TYPES) + RESOURCE_KINDS[1:].index('mutbuf'),
        'T_RESTORE': RETURN_LOANS_CODE, 'T_RESOURCE_RETURN': RESOURCE_RETURN, 'T_CALL': CALL, 'CONST': CONSTANT, 'RET': RETURN, 'T_TRAP': TRAP,
        'T_JUMP': JUMP, 'T_BRANCH': BRANCH,
        'LOAN_BASE': 96 + 32 * MAX_FUNCTIONS, 'BLOCK_BASE': 96 + 64 * MAX_FUNCTIONS,
    }
    keys = (*KEYS, 'return_loans')
    values.update({f'K_{key}': index for index, key in enumerate(keys, 1)})
    scalar = function(FINITE, 'emit_instruction').replace('def emit_instruction(', 'def emit_scalar(')
    define = function(FINITE, 'define_value').replace('typ = def_type(w, node)',
                'typ = admitted_type(w, a, lookup(w, node, K_type))')
    define = define.replace('    put(w, a + 32, cursor + 1)', '    put(w, a + 32, cursor + 1)\n    value_index_insert(w, a, row)')
    signature = ['def resource_accepts(code:u64, kind:u64) -> bool:']
    for name, kinds in RESOURCE_SIGNATURES.items():
        signature.extend((f'    if code == {RESOURCE_CODES[name]}:',
                          '        return ' + ' or '.join(f'kind == {RESOURCE_KINDS.index(k)}' for k in kinds)))
    signature.append('    return False')
    block = function(FINITE, 'project_block').replace('return emit_terminal(', 'return wire_terminal(')
    block = block.replace('    put(w, a + 32, 0)', '    put(w, a + 32, 0)\n    value_index_prepare(w, a, params, lookup(w, block, K_ops))')
    source = '\n'.join((POLICY, scalar, define, block, *signature, *(function(FINITE, name) for name in shared)))
    source = source.replace('a + VALUE_BASE', 'a + BLOCK_BASE + 16 * get(w, 8)')
    source = source.replace('cursor == VALUE_MAX', 'cursor >= get(w, 8)')
    source = re.sub(r'\b(' + '|'.join(values) + r')\b', lambda match: str(values[match[0]]), source)
    start = finite.index('\ndef opcode(')
    end = finite.index('\ndef cast_opcode(', start)
    opcodes = [('const', CONSTANT), ('call', CALL), *sorted(OPCODES.items())]
    types = (*TYPES, *RESOURCE_KINDS[1:])
    prefix = finite[finite.index('\ndef key_id('):start]
    prefix = prefix.replace(key_reader(KEYS), key_reader(keys)).replace(
        enum_reader('type_code', list(zip(TYPES, range(len(TYPES))))),
        compact_enum('type_code', list(zip(types, range(len(types))))))
    grammar = (prefix, compact_enum('opcode', opcodes),
               compact_enum('resource_opcode', list(RESOURCE_CODES.items())), finite[end:])
    return '\n'.join((source, *grammar))


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)), encoding='utf-8')
