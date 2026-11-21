"""Author the Safe Core scalar proof frame after independent Core admission."""
from __future__ import annotations

import ast
import re
import struct
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_cnf_native import (
    CIRCUIT_NODES, CIRCUIT_REQUEST, GRAPH_PROJECTION_REQUEST, PROJECT_CHECKED_CAST, PROJECTION_INPUT_LIMIT,
    LEARNING_REQUEST, RESTART_REQUEST, SAT, SEARCH_PLAN_REQUEST, SPARSE_CLAUSES,
    SPARSE_ENTRIES, SPARSE_REPLY, SPARSE_REQUEST, SPARSE_VARIABLES, STEP_LIMIT, WORD_WITNESS_REQUEST,
    WORD_PRODUCT_EXCEEDS, WORD_TABLE_INPUT_BITS, WORD_TABLE_REQUEST, WORD_TABLE_WORK_LIMIT,
    _CORE_TRAP_TAGS, _GRAPH_OPERATIONS, _word_type,
)
from hepta.hia_core_proof_wire_native import (
    ELF_FUNCTION_LINK_REQUEST, ELF_OBJECT_RELOCATION_REQUEST, MACHINE_RELOCATION_REQUEST, OBLIGATION_REQUEST,
    OBLIGATION_SOLVER_REQUEST, OBLIGATION_WITNESS_REQUEST,
)
from hepta.hia_safe_core import LIMITS, WIDTHS_V6, _scalar_caller_contract
from hepta.hia_safe_core_elf_inventory_native import (
    AUTHORITY_BYTES, FUNCTION_LINK_BYTES, FUNCTION_LINK_NAME_BYTES, FUNCTION_LINK_SOURCE_OFFSET,
    FUNCTION_LINK_TARGET_OFFSET, FUNCTION_RECEIPT_BYTES, FUNCTION_RECEIPT_GEOMETRY,
    HEADER as ELF_RECEIPT_HEADER, MAX_SECTIONS, OBJECT_INVENTORY_CONTROL_BYTES, OBJECT_INVENTORY_MAGIC,
    OBJECT_RELOCATION_CONTROL_BYTES, SECTION as ELF_SECTION, SECTION_AUTHORITIES, SYMBOL as ELF_SYMBOL,
)
from hepta.hia_safe_core_x64_decode_native import (
    DECODE_FRAME_OFFSET, MACHINE_VALUES_REQUEST, MAX_TEXT, PROFILE_OFFSET, WORKSPACE,
)
from hepta.hia_schema import PRIMITIVE_PROFILES
from tools.generate_hia_core_inspect_json import document, source_program
from tools.generate_hia_core_json_frontend import packed


SOURCE = Path('examples/hia_bootstrap/core_proof_wire.hepta')
REFUSED = 0xfffffffc
POLICY = r'''
def proof_wire(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) >= 32 and obligation_word(s, 0) == OBLIGATION_REQUEST:
        return obligations(s, o, w)
    if length(s) >= 32 and obligation_word(s, 0) == OBLIGATION_SOLVER_REQUEST:
        return obligation_solver_wire(s, o)
    if length(s) >= 32 and obligation_word(s, 0) == OBLIGATION_WITNESS_REQUEST:
        return obligation_witness_wire(s, o)
    if length(s) >= 48 and obligation_word(s, 0) == MACHINE_RELOCATION_REQUEST:
        return machine_relocation_wire(s, o)
    if length(s) >= 32 and obligation_word(s, 0) == ELF_FUNCTION_LINK_REQUEST:
        return elf_function_link_wire(s, o)
    if length(s) >= 40 and obligation_word(s, 0) == ELF_OBJECT_RELOCATION_REQUEST:
        return elf_object_relocation_wire(s, o)
    if length(o) < 32768 or length(o) < length(s) or length(w) < 4096:
        return REFUSED
    put(o, 48, 262144)
    put(o, 56, 64)
    end = widen(decode_json(s, w, o))
    if end >= 4294967292:
        return end
    if end + 4096 > length(w) or proof_schema(w, field(w, 0, K_schema)) == 0:
        return REFUSED
    functions = field(w, 0, K_functions)
    if count(w, functions) != 1:
        return REFUSED
    fn = child(w, functions)
    params = field(w, fn, K_params)
    returns = field(w, fn, K_returns)
    blocks = field(w, fn, K_blocks)
    n = count(w, blocks)
    inputs = count(w, params)
    if n < 1 or n > BLOCKS or inputs > ABI_WORDS or count(w, returns) != 1:
        return REFUSED
    result = proof_type(w, child(w, returns))
    if result == 0:
        return REFUSED
    put(w, 8, end)
    put(w, 16, 0)
    put(w, 24, end + BLOCKS * 48)
    put(w, 32, end + BLOCKS * 48 + 8 * NODE_BUDGET)
    i = 0
    b = child(w, blocks)
    while b != NONE:
        record = end + 48 * i
        put(w, record, b)
        put(w, record + 8, field(w, b, K_id))
        put(w, record + 16, n)
        put(w, record + 24, n)
        put(w, record + 32, n)
        i = i + 1
        b = next_node(w, b)
    entry = block_slot(w, n, field(w, fn, K_entry))
    if entry >= n or graph_order(w, n, entry) == 0:
        return REFUSED
    put(o, 0, REQUEST)
    put(o, 8, 2)
    put(o, 16, inputs)
    put(o, 24, 1)
    at = 32
    p = child(w, params)
    while p != NONE:
        typ = proof_type(w, field(w, p, K_type))
        if typ == 0:
            return REFUSED
        put(o, at, typ)
        at = at + 8
        p = next_node(w, p)
    put(o, at, result)
    start = at + 8
    put(o, start + 8, n)
    put(o, start + 16, get(w, end + 48 * entry + 32))
    put(w, 0, start + 24)
    i = 0
    while i < n:
        source_index = get(w, end + 48 * i + 40)
        b = get(w, end + 48 * source_index)
        if write_block(s, o, w, n, b) == 0:
            return REFUSED
        i = i + 1
    size = get(w, 0) - start
    if get(w, 0) + size > length(o) or get(w, 0) + size > WIRE_LIMIT:
        return REFUSED
    put(o, start, size)
    i = 0
    while i < size:
        store(o, start + size + i, byte(o, start + i))
        i = i + 1
    return start + size * 2

def same_name(w:mutbuf, first:u64, second:u64) -> bool:
    return kind(w, first) == 4 and kind(w, second) == 4 and name_before(w, first, second) == 0 and name_before(w, second, first) == 0

def block_slot(w:mutbuf, n:u64, name:u64) -> u64:
    table = get(w, 8)
    i = 0
    while i < n:
        if same_name(w, name, get(w, table + 48 * i + 8)):
            return i
        i = i + 1
    return n

def graph_order(w:mutbuf, n:u64, entry:u64) -> u64:
    table = get(w, 8)
    i = 0
    while i < n:
        row = table + 48 * i
        term = field(w, get(w, row), K_term)
        role = proof_term(w, field(w, term, K_op))
        if role == 0:
            return 0
        if role == 3 or role == 4:
            first = term
            if role == 4:
                first = field(w, term, K_then)
                second = block_slot(w, n, field(w, field(w, term, K_else), K_target))
                if second >= n:
                    return 0
                put(w, row + 24, second)
            target = block_slot(w, n, field(w, first, K_target))
            if target >= n:
                return 0
            put(w, row + 16, target)
        i = i + 1
    pending = (1 << n) - 1
    i = 0
    while pending != 0:
        incoming = 0
        j = 0
        while j < n:
            if (pending & (1 << j)) != 0:
                row = table + 48 * j
                incoming = incoming | (1 << get(w, row + 16)) | (1 << get(w, row + 24))
            j = j + 1
        possible = pending ^ (incoming & pending)
        if possible == 0:
            return 0
        next = 0
        while (possible & (1 << next)) == 0:
            next = next + 1
        put(w, table + 48 * next + 32, i)
        put(w, table + 48 * i + 40, next)
        pending = pending ^ (1 << next)
        i = i + 1
    while i != 0:
        i = i - 1
        next = get(w, table + 48 * i + 40)
        row = table + 48 * next
        first = get(w, row + 16)
        second = get(w, row + 24)
        paths = 1
        if first != n:
            paths = get(w, table + 48 * first + 16)
        if second != n:
            paths = paths + get(w, table + 48 * second + 16)
        put(w, row + 16, choose(paths <= PATHS, paths, PATHS + 1))
    paths = get(w, table + 48 * entry + 16)
    put(w, 40, paths)
    return choose(paths <= PATHS, 1, 0)

def value_slot(w:mutbuf, size:u64, name:u64) -> u64:
    table = get(w, 24)
    i = 0
    while i < size:
        if same_name(w, name, get(w, table + 8 * i)):
            return i
        i = i + 1
    return size

def capture_slots(o:mutbuf, w:mutbuf, at:u64, values:u64, slots:u64) -> u64:
    node = child(w, values)
    while node != NONE:
        slot = value_slot(w, slots, node)
        if slot >= slots:
            return 0
        put(o, at, slot)
        at = at + 8
        node = next_node(w, node)
    return at

def attr(w:mutbuf, attrs:u64, mode:bool) -> u64:
    node = child(w, attrs)
    while node != NONE:
        at = 64 + node * 56
        start = get(w, at + 40)
        size = get(w, at + 48)
        if mode:
            if same(w, start, size, MODE_KEY) != 0:
                return node
        else:
            if same(w, start, size, VALUE_KEY) != 0:
                return node
        node = next_node(w, node)
    return NONE

def write_literal(s:readbuf, o:mutbuf, w:mutbuf, at:u64, node:u64) -> u64:
    tag = kind(w, node)
    if tag == 1 or tag == 2:
        put(o, at, choose(tag == 2, 1, 0))
        return 1
    if tag != 3:
        return 0
    row = 64 + node * 56
    start = get(w, row + 24)
    end = start + get(w, row + 32)
    negative = byte(s, start) == 45
    pos = start + choose(negative, 1, 0)
    if pos == end:
        return 0
    value = 0
    while pos < end:
        digit = byte(s, pos) - 48
        if digit > 9 or value > 1844674407370955161 or (value == 1844674407370955161 and digit > 5):
            return 0
        value = value * 10 + digit
        pos = pos + 1
    put(o, at, choose(negative, 0 - value, value))
    return 1

def write_operation(s:readbuf, o:mutbuf, w:mutbuf, at:u64, node:u64, slots:u64) -> u64:
    role = proof_op(w, field(w, node, K_op))
    outs = field(w, node, K_out)
    args = field(w, node, K_args)
    if role == 0 or count(w, outs) != 1 or count(w, args) > 3:
        return 0
    output = child(w, outs)
    typ = proof_type(w, field(w, output, K_type))
    if typ == 0:
        return 0
    attrs = field(w, node, K_attrs)
    if role == 20 and proof_checked(w, attr(w, attrs, True)) != 0:
        role = CHECKED_CAST
    put(o, at, role)
    put(o, at + 8, typ)
    put(o, at + 16, 0)
    put(o, at + 24, 0)
    put(o, at + 32, 0)
    put(o, at + 40, 0)
    if role == 2 and write_literal(s, o, w, at + 40, attr(w, attrs, False)) == 0:
        return 0
    if capture_slots(o, w, at + 16, args, slots) == 0:
        return 0
    put(w, get(w, 24) + 8 * slots, field(w, output, K_name))
    return 1

def block_edges(w:mutbuf, n:u64, term:u64, role:u64) -> u64:
    first = field(w, term, K_values)
    second = NONE
    target = 0
    other = 0
    if role == 3 or role == 4:
        edge = term
        if role == 4:
            edge = field(w, term, K_then)
            tail = field(w, term, K_else)
            next = block_slot(w, n, field(w, tail, K_target))
            other = get(w, get(w, 8) + 48 * next + 32)
            second = field(w, tail, K_args)
        next = block_slot(w, n, field(w, edge, K_target))
        target = get(w, get(w, 8) + 48 * next + 32)
        first = field(w, edge, K_args)
    put(w, get(w, 32), first)
    put(w, get(w, 32) + 8, second)
    put(w, get(w, 32) + 16, target)
    put(w, get(w, 32) + 24, other)
    return 0

def write_block(s:readbuf, o:mutbuf, w:mutbuf, n:u64, b:u64) -> u64:
    term = field(w, b, K_term)
    role = proof_term(w, field(w, term, K_op))
    params = field(w, b, K_params)
    ops = field(w, b, K_ops)
    nparams = count(w, params)
    nops = count(w, ops)
    total = get(w, 16) + nops
    slots = nparams + nops
    if total > OP_BUDGET or slots > NODE_BUDGET:
        return 0
    put(w, 16, total)
    block_edges(w, n, term, role)
    cursor = get(w, 0)
    if block_header(o, w, cursor, role, nparams, nops) == 0:
        return 0
    at = write_block_values(s, o, w, cursor + 64, params, ops)
    if at == 0:
        return 0
    return finish_block(o, w, cursor, role, at, slots, term)

def block_header(o:mutbuf, w:mutbuf, cursor:u64, role:u64, nparams:u64, nops:u64) -> u64:
    a = count(w, get(w, get(w, 32)))
    z = count(w, get(w, get(w, 32) + 8))
    size = 64 + 8 * (nparams + a + z) + 48 * nops
    if a > NODE_BUDGET or z > NODE_BUDGET or size > length(o) - cursor:
        return 0
    put(w, 0, cursor + size)
    put(o, cursor, nparams)
    put(o, cursor + 8, nops)
    put(o, cursor + 16, role)
    put(o, cursor + 32, get(w, get(w, 32) + 16))
    put(o, cursor + 40, a)
    put(o, cursor + 48, get(w, get(w, 32) + 24))
    put(o, cursor + 56, z)
    return 1

def write_block_values(s:readbuf, o:mutbuf, w:mutbuf, at:u64, params:u64, ops:u64) -> u64:
    slot = 0
    param = child(w, params)
    while param != NONE:
        typ = proof_type(w, field(w, param, K_type))
        if typ == 0:
            return 0
        put(o, at, typ)
        put(w, get(w, 24) + slot * 8, field(w, param, K_name))
        param = next_node(w, param)
        slot = slot + 1
        at = at + 8
    op = child(w, ops)
    while op != NONE:
        if write_operation(s, o, w, at, op, slot) == 0:
            return 0
        op = next_node(w, op)
        slot = slot + 1
        at = at + 48
    return at

def finish_block(o:mutbuf, w:mutbuf, cursor:u64, role:u64, at:u64, slots:u64, term:u64) -> u64:
    control = 0
    if role == 4:
        control = value_slot(w, slots, field(w, term, K_cond))
        if control >= slots:
            return 0
    if role == 2:
        control = proof_trap(w, field(w, term, K_code))
        if control == 0:
            return 0
    put(o, cursor + 24, control)
    next = capture_slots(o, w, at, get(w, get(w, 32)), slots)
    if next == 0:
        return 0
    return choose(capture_slots(o, w, next, get(w, get(w, 32) + 8), slots) == get(w, 0), 1, 0)
'''


OBLIGATIONS = f'''
def obligations(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 32 or obligation_word(s, 0) != {OBLIGATION_REQUEST}:
        return {REFUSED}
    role = obligation_word(s, 8)
    extent = obligation_word(s, 16)
    if role > 4 or obligation_word(s, 24) != 0 or extent != length(s) - 32:
        return {REFUSED}
    if role < 3:
        if extent != 0 or length(o) < 32:
            return {REFUSED}
        if role == 0:
            return caller_contract(o)
        return circuit_header(o, 0, 0)
    return observed_obligation(s, o, role)

def observed_obligation(s:readbuf, o:mutbuf, role:u64) -> u64:
    if length(s) < 112 or obligation_word(s, 32) != {CIRCUIT_REQUEST}:
        return {REFUSED}
    nodes = obligation_word(s, 40)
    if nodes == 0 or nodes > {CIRCUIT_NODES} or obligation_word(s, 48) != 3 or obligation_word(s, 56) != 0:
        return {REFUSED}
    node_bytes = 40 * nodes
    if length(s) != 112 + node_bytes:
        return {REFUSED}
    if length(o) < 64 + node_bytes:
        return {REFUSED}
    if valid_pairs(s, nodes, node_bytes) == 0:
        return {REFUSED}
    obligation_copy(s, o, 64, 32, node_bytes)
    start = choose(role == 3, 0, 1)
    end = choose(role == 3, 1, 3)
    index = start
    written = 0
    while index < end:
        row = 64 + node_bytes + 16 * index
        left = obligation_word(s, row)
        right = obligation_word(s, row + 8)
        if left != right:
            at = 32 + node_bytes + 16 * written
            put(o, at, left)
            put(o, at + 8, right)
            written = written + 1
        index = index + 1
    return circuit_header(o, nodes, written)

def valid_pairs(s:readbuf, nodes:u64, node_bytes:u64) -> u64:
    offset = 0
    while offset < 48:
        if obligation_word(s, 64 + node_bytes + offset) >= nodes:
            return 0
        offset = offset + 8
    return 1

def circuit_header(o:mutbuf, nodes:u64, pairs:u64) -> u64:
    put(o, 0, {CIRCUIT_REQUEST})
    put(o, 8, nodes)
    put(o, 16, pairs)
    put(o, 24, 0)
    return 32 + 40 * nodes + 16 * pairs

def obligation_word(s:readbuf, offset:u64) -> u64:
    result = 0
    index = 0
    while index < 8:
        result = result | (byte(s, offset + index) << (index * 8))
        index = index + 1
    return result

def obligation_copy(s:readbuf, o:mutbuf, start:u64, target:u64, extent:u64) -> u64:
    offset = 0
    while offset < extent:
        put(o, target + offset, obligation_word(s, start + offset))
        offset = offset + 8
    return extent
'''


def caller_contract_source():
    nodes, pairs, guards = _scalar_caller_contract()
    assert guards is None
    frame = struct.pack('<4Q', CIRCUIT_REQUEST, len(nodes), len(pairs), 0)
    frame += b''.join(struct.pack('<5Q', *node) for node in nodes)
    frame += b''.join(struct.pack('<2Q', *pair) for pair in pairs)
    lines = ['def caller_contract(o:mutbuf) -> u64:',
             f'    if length(o) < {len(frame)}:', f'        return {REFUSED}']
    for offset, (word,) in enumerate(struct.iter_unpack('<Q', frame)):
        lines.append(f'    put(o, {8 * offset}, {word})')
    lines.append(f'    return {len(frame)}')
    return '\n' + '\n'.join(lines) + '\n'


SOLVER_WIRE = f'''
def obligation_solver_wire(s:readbuf, o:mutbuf) -> u64:
    phase = obligation_word(s, 8)
    ordinal = obligation_word(s, 16)
    parameter = obligation_word(s, 24)
    if ordinal > 4:
        return {REFUSED}
    if phase == 0:
        return solver_plan_frame(s, o, ordinal, parameter)
    if phase == 4 and ordinal >= 3:
        return solver_word_table(s, o, parameter)
    if parameter != 0 or length(s) < 96:
        return {REFUSED}
    if obligation_word(s, 32) != {SEARCH_PLAN_REQUEST}:
        return {REFUSED}
    steps = obligation_word(s, 40)
    learn = obligation_word(s, 48)
    restart = obligation_word(s, 56)
    if steps == 0 or steps > {STEP_LIMIT} or learn > 1 or restart > 1:
        return {REFUSED}
    if phase == 1:
        return solver_attach_lease(s, o, steps)
    if phase == 2:
        return solver_search_frame(s, o, steps, learn, restart)
    if phase == 3:
        return solver_reduce_signed_products(s, o, steps)
    return {REFUSED}

def solver_circuit_ok(s:readbuf, at:u64) -> bool:
    if length(s) < at + 32 or obligation_word(s, at) != {CIRCUIT_REQUEST}:
        return False
    nodes = obligation_word(s, at + 8)
    pairs = obligation_word(s, at + 16)
    if nodes > {CIRCUIT_NODES} or pairs > 2 or obligation_word(s, at + 24) != 0:
        return False
    return length(s) == at + 32 + nodes * 40 + pairs * 16

def solver_plan_frame(s:readbuf, o:mutbuf, ordinal:u64, remaining:u64) -> u64:
    if remaining == 0 or solver_circuit_ok(s, 32) == False:
        return {REFUSED}
    count = obligation_word(s, 40)
    extent = 32 + count * 16
    if length(o) < extent:
        return {REFUSED}
    put(o, 0, {SEARCH_PLAN_REQUEST})
    put(o, 8, remaining)
    put(o, 16, 0)
    put(o, 24, choose(ordinal >= 3, 1, 0))
    ordinal_node = 0
    while ordinal_node < count:
        start = 64 + ordinal_node * 40
        destination = 32 + ordinal_node * 16
        put(o, destination, obligation_word(s, start))
        put(o, destination + 8, obligation_word(s, start + 8))
        ordinal_node = ordinal_node + 1
    return extent

def solver_attach_lease(s:readbuf, o:mutbuf, steps:u64) -> u64:
    if solver_circuit_ok(s, 64) == False or length(o) < length(s) - 64:
        return {REFUSED}
    obligation_copy(s, o, 64, 0, length(s) - 64)
    put(o, 24, steps)
    return length(s) - 64

def solver_search_frame(s:readbuf, o:mutbuf, steps:u64, learn:u64, restart:u64) -> u64:
    if length(s) < 104 or obligation_word(s, 64) != {SPARSE_REQUEST}:
        return {REFUSED}
    variables = obligation_word(s, 72)
    clauses = obligation_word(s, 80)
    entries = obligation_word(s, 96)
    if variables > {SPARSE_VARIABLES} or clauses > {SPARSE_CLAUSES} or entries > {SPARSE_ENTRIES}:
        return {REFUSED}
    if length(s) != 104 + entries * 2 or obligation_word(s, 88) != steps or length(o) < length(s) - 64:
        return {REFUSED}
    mode = choose(restart == 1, {RESTART_REQUEST}, choose(learn == 1, {LEARNING_REQUEST}, {SPARSE_REQUEST}))
    put(o, 0, mode)
    offset = 8
    while offset < length(s) - 64:
        store(o, offset, byte(s, 64 + offset))
        offset = offset + 1
    return length(s) - 64

def solver_reduce_signed_products(s:readbuf, o:mutbuf, steps:u64) -> u64:
    # A signed m-bit by signed n-bit product fits in m+n signed bits.
    # This retry changes only encoding size, never the input domain or lease.
    mapping = 64 + 40 * {CIRCUIT_NODES}
    if solver_circuit_ok(s, 64) == False or length(o) < mapping + 8 * {CIRCUIT_NODES}:
        return {REFUSED}
    input_count = obligation_word(s, 72)
    pairs = obligation_word(s, 80)
    put(o, 0, {CIRCUIT_REQUEST})
    put(o, 16, pairs)
    put(o, 24, steps)
    index = 0
    count = 0
    changed = False
    while index < input_count:
        row = 96 + index * 40
        operation = obligation_word(s, row)
        if count >= {CIRCUIT_NODES} or (operation == 1 and count != index):
            return {REFUSED}
        bound = bounded_signed_product(s, row, index)
        if bound != 0:
            if count + 3 >= {CIRCUIT_NODES}:
                return {REFUSED}
            write_bounded_signed_product(s, o, row, count, bound, mapping)
            count = count + 3
            changed = True
        elif bounded_signed_product_exceeds(s, row, index):
            write_solver_node(o, 32 + count * 40, 2, 1, 0, 0)
            changed = True
        else:
            if copy_solver_node(s, o, row, count, index, mapping) == 0:
                return {REFUSED}
        put(o, mapping + index * 8, count)
        count = count + 1
        index = index + 1
    if changed == False:
        return {REFUSED}
    put(o, 8, count)
    index = 0
    while index < 2 * pairs:
        previous = obligation_word(s, 96 + input_count * 40 + index * 8)
        if previous >= input_count:
            return {REFUSED}
        put(o, 32 + count * 40 + index * 8, get(o, mapping + previous * 8))
        index = index + 1
    return 32 + count * 40 + pairs * 16

def bounded_signed_product(s:readbuf, row:u64, ordinal:u64) -> u64:
    if obligation_word(s, row) != 32:
        return 0
    width = obligation_word(s, row + 8)
    a = obligation_word(s, row + 16)
    b = obligation_word(s, row + 24)
    if width > 64 or a >= ordinal or b >= ordinal:
        return 0
    left = 96 + a * 40
    right = 96 + b * 40
    if obligation_word(s, left) != 31 or obligation_word(s, right) != 31:
        return 0
    if obligation_word(s, left + 8) != width or obligation_word(s, right + 8) != width:
        return 0
    first = obligation_word(s, left + 16)
    second = obligation_word(s, right + 16)
    if first >= a or second >= b:
        return 0
    m = obligation_word(s, 104 + first * 40)
    n = obligation_word(s, 104 + second * 40)
    if m == 0 or n == 0 or m >= width or n >= width or m + n >= width:
        return 0
    return m + n

def bounded_signed_product_exceeds(s:readbuf, row:u64, ordinal:u64) -> bool:
    # The independent x86 model computes signed overflow using unsigned
    # magnitudes. A reviewed bound may make the overflow predicate false
    # without bit blasting a product that cannot reach either threshold.
    if obligation_word(s, row) != {WORD_PRODUCT_EXCEEDS}:
        return False
    a = obligation_word(s, row + 16)
    b = obligation_word(s, row + 24)
    threshold = obligation_word(s, row + 32)
    if a >= ordinal or b >= ordinal or threshold >= ordinal:
        return False
    m = signed_magnitude_bits(s, a)
    n = signed_magnitude_bits(s, b)
    if m == 0 or n == 0 or m + n > 65:
        return False
    maximum = 1 << (m + n - 2)
    return threshold_at_least(s, threshold, maximum)

def signed_magnitude_bits(s:readbuf, index:u64) -> u64:
    row = 96 + index * 40
    if obligation_word(s, row) != 11:
        return 0
    width = obligation_word(s, row + 8)
    sign = obligation_word(s, row + 16)
    negation = obligation_word(s, row + 24)
    input_node = obligation_word(s, row + 32)
    if width == 0 or width > 64 or sign >= index or negation >= index or input_node >= index:
        return 0
    sign_row = 96 + sign * 40
    if obligation_word(s, sign_row) != 26 or obligation_word(s, sign_row + 8) != 1:
        return 0
    if obligation_word(s, sign_row + 16) != input_node or obligation_word(s, sign_row + 32) != width - 1:
        return 0
    negation_row = 96 + negation * 40
    if obligation_word(s, negation_row) != 10 or obligation_word(s, negation_row + 24) != input_node:
        return 0
    zero = obligation_word(s, negation_row + 16)
    if zero >= negation:
        return 0
    zero_row = 96 + zero * 40
    if obligation_word(s, zero_row) != 2 or obligation_word(s, zero_row + 32) != 0:
        return 0
    input_row = 96 + input_node * 40
    if obligation_word(s, input_row) != 31 or obligation_word(s, input_row + 8) != width:
        return 0
    narrower = obligation_word(s, input_row + 16)
    if narrower >= input_node:
        return 0
    bits = obligation_word(s, 104 + narrower * 40)
    return choose(bits > 0 and bits < width, bits, 0)

def exact_constant_at_least(s:readbuf, index:u64, value:u64) -> u64:
    row = 96 + index * 40
    return choose(obligation_word(s, row) == 2 and obligation_word(s, row + 32) >= value, 1, 0)

def threshold_at_least(s:readbuf, index:u64, value:u64) -> bool:
    row = 96 + index * 40
    if obligation_word(s, row) == 2:
        return exact_constant_at_least(s, index, value) != 0
    if obligation_word(s, row) != 11:
        return False
    a = obligation_word(s, row + 24)
    b = obligation_word(s, row + 32)
    if a >= index or b >= index:
        return False
    return exact_constant_at_least(s, a, value) != 0 and exact_constant_at_least(s, b, value) != 0

def write_bounded_signed_product(s:readbuf, o:mutbuf, row:u64, count:u64, bound:u64, mapping:u64) -> u64:
    a = obligation_word(s, row + 16)
    b = obligation_word(s, row + 24)
    a = get(o, mapping + obligation_word(s, 112 + a * 40) * 8)
    b = get(o, mapping + obligation_word(s, 112 + b * 40) * 8)
    destination = 32 + count * 40
    write_solver_node(o, destination, 31, bound, a, 0)
    write_solver_node(o, destination + 40, 31, bound, b, 0)
    write_solver_node(o, destination + 80, 32, bound, count, count + 1)
    write_solver_node(o, destination + 120, 31, obligation_word(s, row + 8), count + 2, 0)
    return 0

def write_solver_node(o:mutbuf, row:u64, operation:u64, width:u64, a:u64, b:u64) -> u64:
    put(o, row, operation)
    put(o, row + 8, width)
    put(o, row + 16, a)
    put(o, row + 24, b)
    put(o, row + 32, 0)
    return 0

def copy_solver_node(s:readbuf, o:mutbuf, old:u64, count:u64, ordinal:u64, mapping:u64) -> u64:
    target = 32 + count * 40
    obligation_copy(s, o, old, target, 40)
    operands = solver_node_operands(obligation_word(s, old))
    index = 0
    while index < operands:
        offset = 16 + index * 8
        previous = obligation_word(s, old + offset)
        if previous >= ordinal:
            return 0
        put(o, target + offset, get(o, mapping + previous * 8))
        index = index + 1
    return 1

def solver_node_operands(operation:u64) -> u64:
    if operation <= 2:
        return 0
    if operation == 6 or operation == 20 or operation == 21 or operation == 26 or (operation >= 28 and operation <= 31):
        return 1
    if operation == 11 or operation == {WORD_PRODUCT_EXCEEDS}:
        return 3
    return 2

def solver_word_table(s:readbuf, o:mutbuf, remaining:u64) -> u64:
    if remaining == 0 or solver_circuit_ok(s, 32) == False:
        return {REFUSED}
    nodes = obligation_word(s, 40)
    pairs = obligation_word(s, 48)
    mapping = 72 + 40 * {CIRCUIT_NODES}
    live = mapping + 8 * {CIRCUIT_NODES}
    bounds = live + 8 * {CIRCUIT_NODES}
    if length(o) < bounds + 8 * {CIRCUIT_NODES}:
        return {REFUSED}
    index = 0
    while index < nodes:
        put(o, live + index * 8, 0)
        put(o, bounds + index * 8, 0)
        index = index + 1
    if mark_word_table(s, o, nodes, pairs, live, bounds) == 0:
        return {REFUSED}
    return emit_word_table(s, o, nodes, pairs, mapping, remaining)

def mark_word_table(s:readbuf, o:mutbuf, nodes:u64, pairs:u64, live:u64, bounds:u64) -> u64:
    index = 0
    while index < pairs * 2:
        observed = obligation_word(s, 64 + nodes * 40 + index * 8)
        if observed >= nodes:
            return 0
        put(o, live + observed * 8, 1)
        put(o, bounds + observed * 8, obligation_word(s, 72 + observed * 40))
        index = index + 1
    index = nodes
    while index > 0:
        index = index - 1
        if get(o, live + index * 8) != 0:
            if follow_word_table(s, o, index, live, bounds) == 0:
                return 0
    return 1

def follow_word_table(s:readbuf, o:mutbuf, node:u64, live:u64, bounds:u64) -> u64:
    row = 64 + node * 40
    operation = obligation_word(s, row)
    operands = solver_node_operands(operation)
    index = 0
    while index < operands:
        argument = obligation_word(s, row + 16 + index * 8)
        if argument >= node:
            return 0
        put(o, live + argument * 8, 1)
        operand_row = 64 + argument * 40
        if obligation_word(s, operand_row) == 1:
            width = obligation_word(s, operand_row + 8)
            if operation == 26:
                low = obligation_word(s, row + 32)
                span = obligation_word(s, row + 8)
                if low > width or span > width - low:
                    return 0
                width = low + span
            old = get(o, bounds + argument * 8)
            put(o, bounds + argument * 8, choose(width > old, width, old))
        index = index + 1
    return 1

def emit_word_table(s:readbuf, o:mutbuf, nodes:u64, pairs:u64, mapping:u64, remaining:u64) -> u64:
    live = mapping + 8 * {CIRCUIT_NODES}
    bounds = live + 8 * {CIRCUIT_NODES}
    count = 0
    bits = 0
    index = 0
    while index < nodes:
        row = 64 + index * 40
        operation = obligation_word(s, row)
        if operation == 1 or get(o, live + index * 8) != 0:
            if operation == 1:
                width = get(o, bounds + index * 8)
                width = choose(width == 0, 1, width)
                if width > {WORD_TABLE_INPUT_BITS} - bits:
                    return {REFUSED}
                bits = bits + width
                write_solver_node(o, 32 + count * 40, 1, width, 0, 0)
            elif copy_solver_node(s, o, row, count, index, mapping) == 0:
                return {REFUSED}
            put(o, mapping + index * 8, count)
            count = count + 1
        index = index + 1
    put(o, 0, {WORD_TABLE_REQUEST})
    put(o, 8, count)
    put(o, 16, pairs)
    put(o, 24, 0)
    index = 0
    while index < 2 * pairs:
        previous = obligation_word(s, 64 + nodes * 40 + index * 8)
        put(o, 32 + count * 40 + index * 8, get(o, mapping + previous * 8))
        index = index + 1
    at = 32 + count * 40 + pairs * 16
    # Only bits that reach reviewed extract operations are enumerated.
    # No assumption restricts the omitted high ABI bits.
    work = choose(remaining < ({WORD_TABLE_WORK_LIMIT} >> 14), remaining << 14, {WORD_TABLE_WORK_LIMIT})
    put(o, at, work)
    return at + 8
'''


WITNESS_WIRE = f'''
def obligation_witness_wire(s:readbuf, o:mutbuf) -> u64:
    circuit = obligation_word(s, 8)
    decision = obligation_word(s, 16)
    mapping = obligation_word(s, 24)
    if circuit < 32 or circuit > 64 + 40 * {CIRCUIT_NODES} or decision < 32 or decision > 32 + ({SPARSE_VARIABLES} >> 3):
        return {REFUSED}
    if mapping < 32 or mapping > 32 + 128 * {CIRCUIT_NODES}:
        return {REFUSED}
    if length(s) != 32 + circuit + decision + mapping or obligation_word(s, 32) != {CIRCUIT_REQUEST}:
        return {REFUSED}
    nodes = obligation_word(s, 40)
    pairs = obligation_word(s, 48)
    if nodes > {CIRCUIT_NODES} or pairs > 2 or circuit != 32 + 40 * nodes + 16 * pairs:
        return {REFUSED}
    if obligation_word(s, 56) != 0 or mapping != 32 + 128 * nodes:
        return {REFUSED}
    reply = 32 + circuit
    variables = witness_reply_shape(s, reply, decision)
    if variables == 0:
        return {REFUSED}
    return witness_inputs(s, o, reply, reply + decision, variables, nodes)

def witness_reply_shape(s:readbuf, reply:u64, extent:u64) -> u64:
    variables = obligation_word(s, reply + 16)
    if obligation_word(s, reply) != {SPARSE_REPLY} or obligation_word(s, reply + 8) != {SAT}:
        return 0
    if variables == 0 or variables > {SPARSE_VARIABLES} or extent != 32 + ((variables + 7) >> 3):
        return 0
    tail = variables & 7
    if tail != 0 and (byte(s, reply + extent - 1) >> tail) != 0:
        return 0
    return variables

def witness_inputs(s:readbuf, o:mutbuf, reply:u64, mapping:u64, variables:u64, nodes:u64) -> u64:
    inputs = 0
    index = 0
    while index < nodes:
        row = 64 + index * 40
        if obligation_word(s, row) == 1:
            width = obligation_word(s, row + 8)
            if width == 0 or width > 64 or witness_tokens(s, mapping + 32 + 128 * index, width, variables) == 0:
                return {REFUSED}
            inputs = inputs + 1
        index = index + 1
    circuit = reply - 32
    if length(o) < circuit + 8 * inputs:
        return {REFUSED}
    put(o, 0, {WORD_WITNESS_REQUEST})
    obligation_copy(s, o, 40, 8, circuit - 8)
    index = 0
    at = circuit
    while index < nodes:
        row = 64 + index * 40
        if obligation_word(s, row) == 1:
            value = witness_word(s, mapping + 32 + 128 * index, reply + 32, obligation_word(s, row + 8))
            put(o, at, value)
            at = at + 8
        index = index + 1
    return at

def witness_tokens(s:readbuf, at:u64, width:u64, variables:u64) -> u64:
    bit = 0
    while bit < width:
        position = at + 2 * bit
        token = byte(s, position) | (byte(s, position + 1) << 8)
        if token < 4 or (token & 1) != 0 or (token >> 1) > variables:
            return 0
        bit = bit + 1
    return 1

def witness_word(s:readbuf, at:u64, model:u64, width:u64) -> u64:
    result = 0
    bit = 0
    while bit < width:
        position = at + 2 * bit
        token = byte(s, position) | (byte(s, position + 1) << 8)
        variable = (token >> 1) - 1
        value = (byte(s, model + (variable >> 3)) >> (variable & 7)) & 1
        result = result | (value << bit)
        bit = bit + 1
    return result
'''

RELOCATION_WIRE = f'''
def machine_relocation_wire(s:readbuf, o:mutbuf) -> u64:
    if length(s) < 104 or obligation_word(s, 48) != 0 or obligation_word(s, 64) != 0:
        return {REFUSED}
    count = obligation_word(s, 56)
    if count < 1 or count > 2 or length(s) != 72 + 32 * count:
        return {REFUSED}
    span = obligation_word(s, 8)
    entry = obligation_word(s, 24)
    profile = obligation_word(s, 40)
    arguments = obligation_word(s, 32)
    if span < 5 or span > {MAX_TEXT} or entry >= span or profile > 15 or arguments > 6:
        return {REFUSED}
    extent = {WORKSPACE} + 8 + 24 * count
    if length(o) < extent or relocation_rows(s, count, span) == 0:
        return {REFUSED}
    offset = 0
    while offset < extent:
        put(o, offset, 0)
        offset = offset + 8
    put(o, {PROFILE_OFFSET}, profile)
    put(o, {DECODE_FRAME_OFFSET}, {MACHINE_VALUES_REQUEST})
    put(o, {DECODE_FRAME_OFFSET + 8}, entry)
    put(o, {DECODE_FRAME_OFFSET + 16}, arguments)
    put(o, {WORKSPACE}, count)
    first = 72
    second = 104
    if count == 2 and obligation_word(s, 72) > obligation_word(s, 104):
        first = 104
        second = 72
    address = obligation_word(s, 16)
    write_machine_call(s, o, first, {WORKSPACE + 8}, address)
    if count == 2:
        write_machine_call(s, o, second, {WORKSPACE + 32}, address)
    return extent

def relocation_rows(s:readbuf, count:u64, span:u64) -> u64:
    a = obligation_word(s, 72)
    kind = obligation_word(s, 80)
    if a == 0 or a > span - 4 or kind == 0 or kind > count:
        return 0
    if count == 1:
        return 1
    b = obligation_word(s, 104)
    other = obligation_word(s, 112)
    if b == 0 or b > span - 4 or a == b or other != 3 - kind:
        return 0
    helper = obligation_word(s, choose(kind == 2, 88, 120))
    address = obligation_word(s, 16)
    return choose(helper >= address and helper - address < span, 1, 0)

def write_machine_call(s:readbuf, o:mutbuf, start:u64, at:u64, address:u64) -> u64:
    external = obligation_word(s, start + 8) == 1
    put(o, at, obligation_word(s, start) - 1)
    put(o, at + 8, choose(external, 1, 0))
    put(o, at + 16, choose(external, 0, obligation_word(s, start + 16) - address))
    return 0

def elf_function_link_wire(s:readbuf, o:mutbuf) -> u64:
    first = {32 + FUNCTION_LINK_NAME_BYTES}
    if length(s) < first or length(o) < {FUNCTION_LINK_BYTES}:
        return {REFUSED}
    object_bytes = obligation_word(s, 8)
    linked_bytes = obligation_word(s, 16)
    name_size = obligation_word(s, 24)
    if object_bytes > length(s) - first or linked_bytes != length(s) - first - object_bytes:
        return {REFUSED}
    if name_size > {FUNCTION_LINK_NAME_BYTES}:
        return {REFUSED}
    second = first + object_bytes
    source_count = function_receipt_count(s, first, object_bytes)
    target_count = function_receipt_count(s, second, linked_bytes)
    if source_count == 0 or target_count != source_count:
        return {REFUSED}
    source = first + {ELF_RECEIPT_HEADER.size} + {ELF_SYMBOL.size} * source_count
    target = second + {ELF_RECEIPT_HEADER.size} + {ELF_SYMBOL.size} * target_count
    span = obligation_word(s, source + 8)
    if obligation_word(s, source) != 0 or obligation_word(s, target + 8) != span:
        return {REFUSED}
    put(o, 0, obligation_word(s, target))
    put(o, 8, span)
    put(o, 16, source_count)
    put(o, 24, target_count)
    put(o, 32, name_size)
    put(o, 40, 0)
    put(o, 48, 0)
    put(o, 56, 0)
    obligation_copy(s, o, 32, 64, {FUNCTION_LINK_NAME_BYTES})
    obligation_copy(s, o, source + {FUNCTION_RECEIPT_GEOMETRY.size}, {FUNCTION_LINK_SOURCE_OFFSET},
                    {FUNCTION_RECEIPT_BYTES - FUNCTION_RECEIPT_GEOMETRY.size})
    obligation_copy(s, o, target + {FUNCTION_RECEIPT_GEOMETRY.size}, {FUNCTION_LINK_TARGET_OFFSET},
                    {FUNCTION_RECEIPT_BYTES - FUNCTION_RECEIPT_GEOMETRY.size})
    return {FUNCTION_LINK_BYTES}

def function_receipt_count(s:readbuf, at:u64, size:u64) -> u64:
    if size < {ELF_RECEIPT_HEADER.size + FUNCTION_RECEIPT_BYTES}:
        return 0
    if obligation_word(s, at) != 0 or obligation_word(s, at + 16) != 0:
        return 0
    n = obligation_word(s, at + 8)
    if n > 2 or size != {ELF_RECEIPT_HEADER.size + FUNCTION_RECEIPT_BYTES} + {ELF_SYMBOL.size} * n:
        return 0
    return n

def elf_object_relocation_wire(s:readbuf, o:mutbuf) -> u64:
    extent = obligation_word(s, 8)
    if extent < {ELF_RECEIPT_HEADER.size + AUTHORITY_BYTES} or extent > length(s) - 40:
        return {REFUSED}
    count = obligation_word(s, 48)
    if count == 0 or count > {MAX_SECTIONS} or obligation_word(s, 40) != 0 or obligation_word(s, 56) != 0:
        return {REFUSED}
    if extent != {ELF_RECEIPT_HEADER.size + AUTHORITY_BYTES} + {ELF_SECTION.size} * count:
        return {REFUSED}
    roles = 40 + extent - {AUTHORITY_BYTES}
    text = obligation_word(s, roles + {8 * SECTION_AUTHORITIES.index('.text')})
    rela = obligation_word(s, roles + {8 * SECTION_AUTHORITIES.index('.rela.text')})
    symbols = obligation_word(s, roles + {8 * SECTION_AUTHORITIES.index('.symtab')})
    if text == 0 or rela == 0 or symbols == 0 or text > count or rela > count or symbols > count:
        return {REFUSED}
    source = 40 + extent
    span = length(s) - source
    size = {OBJECT_INVENTORY_CONTROL_BYTES + OBJECT_RELOCATION_CONTROL_BYTES} + span
    if span > {MAX_TEXT} or length(o) < size:
        return {REFUSED}
    if write_object_relocation_control(s, o, text - 1, rela - 1, symbols - 1, span) == 0:
        return {REFUSED}
    index = 0
    while index < span:
        store(o, {OBJECT_INVENTORY_CONTROL_BYTES + OBJECT_RELOCATION_CONTROL_BYTES} + index, byte(s, source + index))
        index = index + 1
    return size

def write_object_relocation_control(s:readbuf, o:mutbuf, text:u64, rela:u64, symbols:u64, span:u64) -> u64:
    text_row = {40 + ELF_RECEIPT_HEADER.size} + text * {ELF_SECTION.size}
    rela_row = {40 + ELF_RECEIPT_HEADER.size} + rela * {ELF_SECTION.size}
    if obligation_word(s, text_row) != text or obligation_word(s, rela_row) != rela:
        return 0
    if obligation_word(s, text_row + 24) != 1 or obligation_word(s, rela_row + 24) != 4:
        return 0
    if obligation_word(s, text_row + 32) != 6 or obligation_word(s, text_row + 40) != 0:
        return 0
    if span != obligation_word(s, text_row + 56):
        return 0
    helper = obligation_word(s, 32)
    put(o, 0, {OBJECT_INVENTORY_MAGIC})
    put(o, 8, rela)
    put(o, 16, text)
    put(o, 24, symbols)
    put(o, 32, choose(helper == 0, 1, 0))
    put(o, 40, 0)
    put(o, 48, 0)
    put(o, 56, 0)
    put(o, 64, 0)
    first = {OBJECT_INVENTORY_CONTROL_BYTES}
    put(o, first, 2)
    put(o, first + 8, obligation_word(s, rela_row + 48))
    put(o, first + 16, obligation_word(s, text_row + 48))
    put(o, first + 24, span)
    put(o, first + 32, obligation_word(s, 16))
    put(o, first + 40, obligation_word(s, 24))
    put(o, first + 48, helper)
    put(o, first + 56, obligation_word(s, rela_row + 64))
    return 1
'''


def match(name, domain):
    result = [f'def proof_{name}(w:mutbuf, node:u64) -> u64:',
              '    if kind(w, node) != 4:', '        return 0',
              '    at = 64 + node * 56', '    start = get(w, at + 24)', '    size = get(w, at + 32)']
    for value, tag in sorted(domain.items()):
        literal = ', '.join(map(str, packed(value)))
        result += [f'    if same(w, start, size, {literal}) != 0:', f'        return {tag}']
    return '\n'.join([*result, '    return 0', ''])


ELF_POLICY = """
def proof_wire(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) >= 48 and obligation_word(s, 0) == MACHINE_RELOCATION_REQUEST:
        return machine_relocation_wire(s, o)
    if length(s) >= 32 and obligation_word(s, 0) == ELF_FUNCTION_LINK_REQUEST:
        return elf_function_link_wire(s, o)
    if length(s) >= 40 and obligation_word(s, 0) == ELF_OBJECT_RELOCATION_REQUEST:
        return elf_object_relocation_wire(s, o)
    return REFUSED
"""


def program(*, elf_only=False):
    entry = ELF_POLICY if elf_only else POLICY
    constants = dict(REFUSED=REFUSED, REQUEST=GRAPH_PROJECTION_REQUEST,
                     OBLIGATION_REQUEST=OBLIGATION_REQUEST,
                     OBLIGATION_SOLVER_REQUEST=OBLIGATION_SOLVER_REQUEST,
                     OBLIGATION_WITNESS_REQUEST=OBLIGATION_WITNESS_REQUEST,
                     MACHINE_RELOCATION_REQUEST=MACHINE_RELOCATION_REQUEST,
                     ELF_FUNCTION_LINK_REQUEST=ELF_FUNCTION_LINK_REQUEST,
                     ELF_OBJECT_RELOCATION_REQUEST=ELF_OBJECT_RELOCATION_REQUEST,
                     BLOCKS=LIMITS['blocks'], PATHS=LIMITS['core_paths'], OP_BUDGET=LIMITS['operations'],
                     ABI_WORDS=LIMITS['abi_argument_words'], NODE_BUDGET=CIRCUIT_NODES,
                     WIRE_LIMIT=PROJECTION_INPUT_LIMIT, CHECKED_CAST=PROJECT_CHECKED_CAST)
    for name, value in constants.items():
        entry = re.sub(rf'\b{name}\b', str(value), entry)
    entry = entry.replace('MODE_KEY', ', '.join(map(str, packed('mode'))))
    entry = entry.replace('VALUE_KEY', ', '.join(map(str, packed('value'))))
    for name, domain in (
            ('schema', {name: 1 for name in tuple(PRIMITIVE_PROFILES)[:8]}),
            ('type', {name: _word_type(name) for name in WIDTHS_V6}),
            ('op', _GRAPH_OPERATIONS), ('trap', _CORE_TRAP_TAGS),
            ('term', {'ret': 1, 'trap': 2, 'jump': 3, 'branch': 4}), ('checked', {'checked': 1})):
        entry += '\n' + match(name, domain)
    entry += OBLIGATIONS + caller_contract_source() + SOLVER_WIRE + WITNESS_WIRE + RELOCATION_WIRE
    nodes = ast.parse(source_program(entry=entry)).body
    retained = {'proof_wire'}
    while True:
        called = {call.func.id for node in nodes if node.name in retained for call in ast.walk(node)
                  if isinstance(call, ast.Call) and isinstance(call.func, ast.Name)}
        if called <= retained:
            break
        retained.update(called)
    source = ast.unparse(ast.Module(body=[node for node in nodes if node.name in retained], type_ignores=[]))
    return document(source, 'core_elf_binding_wire' if elf_only else 'core_proof_wire')


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(program()))
    SOURCE.with_name('core_elf_binding_wire.hepta').write_text(render_assembly(program(elf_only=True)))
