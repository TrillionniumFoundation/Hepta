"""Author the Safe Core scalar proof frame after independent Core admission."""
from __future__ import annotations

import ast
import re
import struct
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_cnf_native import (
    CIRCUIT_NODES, CIRCUIT_REQUEST, GRAPH_PROJECTION_REQUEST, PROJECT_CHECKED_CAST, PROJECTION_INPUT_LIMIT,
    _CORE_TRAP_TAGS, _GRAPH_OPERATIONS, _word_type,
)
from hepta.hia_core_proof_wire_native import OBLIGATION_REQUEST
from hepta.hia_safe_core import LIMITS, WIDTHS_V6, _scalar_caller_contract
from hepta.hia_schema import PRIMITIVE_PROFILES
from tools.generate_hia_core_inspect_json import document, source_program
from tools.generate_hia_core_json_frontend import packed


SOURCE = Path('examples/hia_bootstrap/core_proof_wire.hepta')
REFUSED = 0xfffffffc
POLICY = r'''
def proof_wire(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) >= 32 and obligation_word(s, 0) == OBLIGATION_REQUEST:
        return obligations(s, o, w)
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


def match(name, domain):
    result = [f'def proof_{name}(w:mutbuf, node:u64) -> u64:',
              '    if kind(w, node) != 4:', '        return 0',
              '    at = 64 + node * 56', '    start = get(w, at + 24)', '    size = get(w, at + 32)']
    for value, tag in sorted(domain.items()):
        literal = ', '.join(map(str, packed(value)))
        result += [f'    if same(w, start, size, {literal}) != 0:', f'        return {tag}']
    return '\n'.join([*result, '    return 0', ''])


def program():
    entry = POLICY
    constants = dict(REFUSED=REFUSED, REQUEST=GRAPH_PROJECTION_REQUEST,
                     OBLIGATION_REQUEST=OBLIGATION_REQUEST,
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
    entry += OBLIGATIONS + caller_contract_source()
    nodes = ast.parse(source_program(entry=entry)).body
    retained = {'proof_wire'}
    while True:
        called = {call.func.id for node in nodes if node.name in retained for call in ast.walk(node)
                  if isinstance(call, ast.Call) and isinstance(call.func, ast.Name)}
        if called <= retained:
            break
        retained.update(called)
    source = ast.unparse(ast.Module(body=[node for node in nodes if node.name in retained], type_ignores=[]))
    return document(source, 'core_proof_wire')


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(program()))
