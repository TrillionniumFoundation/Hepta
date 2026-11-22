"""Derive paired scalar obligations at every typed Core effect and CFG edge."""

from pathlib import Path
import ast
import re

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_cnf_native import (
    CIRCUIT_NODES, CIRCUIT_RETURNS, GRAPH_PROJECTION_REQUEST, PROJECT_CHECKED_CAST,
    PROJECTION_INPUT_LIMIT, SUMMARIZED_CALL_INPUTS, _CORE_TRAP_TAGS, _GRAPH_OPERATIONS, _word_type,
)
from hepta.hia_opcodes import RESOURCES
from hepta.hia_optimization import DEFAULT_POLICY, PURE
from hepta.hia_program import SCALARS
from hepta.hia_schema import PRIMITIVE_PROFILES
from tools.generate_hia_core_inspect_json import document, source_program
from tools.generate_hia_core_json_frontend import packed
from tools.generate_hia_core_proof_wire import POLICY as SCALAR_PROOF, match
from tools.generate_hia_worker_inspection_effect import function

SOURCE = Path('examples/hia_bootstrap/worker_compositional_barrier.hepta')
OBLIGATION_BATCH = int.from_bytes(b'HIACSB01', 'little')
INVALID = 0xfffffffd

POLICY = r'''
# Both Core documents are independently admitted and their ordered skeletons
# must be compared by the caller on these exact immutable bytes. Produce one
# bit-vector obligation per scalar segment, interleaved with paired barriers.
# Loops need no graph unrolling: each edge passes identical typed values to
# the same successor, from identical incoming scalars and resource state.
def barriers(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(o) < 64 or length(s) > INPUT_MAX:
        return BAD
    put(o, 48, 262144)
    put(o, 56, 128)
    base = widen(decode_json(s, w, o))
    if base >= BAD or base > length(w) or length(w) - base < WORK_BYTES:
        return BAD
    a = (base + 7) & 18446744073709551608
    left = bound_subject(w, True)
    right = bound_subject(w, False)
    if proof_schema(w, field(w, left, K_schema)) == 0 or proof_schema(w, field(w, right, K_schema)) == 0:
        return BAD
    put(w, 8, a)
    put(w, 16, 32)
    put(w, 32, 0)
    lfn = child(w, field(w, left, K_functions))
    rfn = child(w, field(w, right, K_functions))
    if lfn == NONE or rfn == NONE:
        return BAD
    while lfn != NONE and rfn != NONE:
        if same_name(w, field(w, lfn, K_name), field(w, rfn, K_name)) == False:
            return BAD
        if function_blocks(s, o, w, lfn, rfn) == False:
            return BAD
        lfn = next_node(w, lfn)
        rfn = next_node(w, rfn)
    if lfn != NONE or rfn != NONE:
        return BAD
    put(o, 0, BATCH)
    put(o, 8, 0)
    put(o, 16, get(w, 32))
    put(o, 24, get(w, 16) - 32)
    return get(w, 16)

def bound_subject(w:mutbuf, before:bool) -> u64:
    node = child(w, 0)
    while node != NONE:
        at = 64 + node * 56
        start = get(w, at + 40)
        size = get(w, at + 48)
        if before and same(w, start, size, LEFT_KEY) == 1:
            return node
        if before == False and same(w, start, size, RIGHT_KEY) == 1:
            return node
        node = next_node(w, node)
    return NONE

def function_blocks(s:readbuf, o:mutbuf, w:mutbuf, left:u64, right:u64) -> bool:
    lb = child(w, field(w, left, K_blocks))
    rb = child(w, field(w, right, K_blocks))
    if lb == NONE or rb == NONE:
        return False
    while lb != NONE and rb != NONE:
        if same_name(w, field(w, lb, K_id), field(w, rb, K_id)) == False:
            return False
        if block_segments(s, o, w, lb, rb) == False:
            return False
        lb = next_node(w, lb)
        rb = next_node(w, rb)
    return lb == NONE and rb == NONE

def block_segments(s:readbuf, o:mutbuf, w:mutbuf, lb:u64, rb:u64) -> bool:
    a = get(w, 8)
    params = field(w, lb, K_params)
    n = add_declarations(w, a + INPUTS, 0, params)
    if n > DECL_MAX:
        return False
    put(w, a, n)
    put(w, 40, field(w, lb, K_term))
    put(w, 48, field(w, rb, K_term))
    left = child(w, field(w, lb, K_ops))
    right = child(w, field(w, rb, K_ops))
    again = True
    while again:
        lbarrier = scan(w, a + LEFT, a + 16, left)
        rbarrier = scan(w, a + RIGHT, a + 24, right)
        if lbarrier == INVALID_NODE or rbarrier == INVALID_NODE:
            return False
        if (lbarrier == NONE) != (rbarrier == NONE):
            return False
        put(w, a + 32, lbarrier)
        put(w, a + 40, rbarrier)
        if observations(w, a) == False or emit_obligation(s, o, w, left, right) == False:
            return False
        if lbarrier == NONE:
            again = False
        else:
            if carry_inputs(w, a) == False:
                return False
            left = next_node(w, lbarrier)
            right = next_node(w, rbarrier)
    return True

def add_declarations(w:mutbuf, table:u64, used:u64, sequence:u64) -> u64:
    node = child(w, sequence)
    while node != NONE:
        if used >= DECL_MAX or decl_type(w, node) == 0:
            return DECL_MAX + 1
        put(w, table + 8 * used, node)
        used = used + 1
        node = next_node(w, node)
    return used

def decl_type(w:mutbuf, decl:u64) -> u64:
    return proof_type(w, field(w, decl, K_type))

def scan(w:mutbuf, table:u64, metadata:u64, row:u64) -> u64:
    a = get(w, 8)
    inputs = get(w, a)
    n = 0
    while n < inputs:
        put(w, table + 8 * n, get(w, a + INPUTS + 8 * n))
        n = n + 1
    while row != NONE and proof_pure(w, field(w, row, K_op)) != 0:
        outputs = field(w, row, K_out)
        if count(w, outputs) != 1:
            return INVALID_NODE
        n = add_declarations(w, table, n, outputs)
        if n > DECL_MAX:
            return INVALID_NODE
        row = next_node(w, row)
    put(w, metadata, n)
    return row

def find_decl(w:mutbuf, table:u64, count:u64, name:u64) -> u64:
    index = 0
    while index < count:
        decl = get(w, table + 8 * index)
        if same_name(w, name, field(w, decl, K_name)):
            return decl
        index = index + 1
    return NONE

def observe(w:mutbuf, a:u64, name:u64) -> bool:
    left = find_decl(w, a + LEFT, get(w, a + 16), name)
    right = find_decl(w, a + RIGHT, get(w, a + 24), name)
    if left == NONE or right == NONE or decl_type(w, left) != decl_type(w, right):
        return False
    typ = decl_type(w, left)
    if typ == OPAQUE:
        return True
    n = get(w, a + 48)
    p = 0
    while p < n:
        if same_name(w, name, field(w, get(w, a + OBSERVED + 8 * p), K_name)):
            return True
        p = p + 1
    if n >= OUTPUT_MAX:
        return False
    put(w, a + OBSERVED + 8 * n, left)
    put(w, a + 48, n + 1)
    return True

def observe_list(w:mutbuf, a:u64, args:u64) -> bool:
    name = child(w, args)
    while name != NONE:
        if observe(w, a, name) == False:
            return False
        name = next_node(w, name)
    return True

def observations(w:mutbuf, a:u64) -> bool:
    put(w, a + 48, 0)
    put(w, a + 56, 0)
    lb = get(w, a + 32)
    if lb == NONE:
        return observe_exit(w, a, get(w, 40))
    if observe_list(w, a, field(w, lb, K_args)) == False:
        return False
    index = 0
    while index < get(w, a + 16):
        decl = get(w, a + LEFT + 8 * index)
        if retain(w, a, decl) == False:
            return False
        index = index + 1
    return True

def retain(w:mutbuf, a:u64, decl:u64) -> bool:
    name = field(w, decl, K_name)
    rb = get(w, a + 40)
    if used_later(w, next_node(w, get(w, a + 32)), get(w, 40), name) == False:
        if used_later(w, next_node(w, rb), get(w, 48), name) == False:
            return True
    other = find_decl(w, a + RIGHT, get(w, a + 24), name)
    if other == NONE or decl_type(w, decl) != decl_type(w, other):
        return False
    if observe(w, a, name) == False:
        return False
    count = get(w, a + 56)
    put(w, a + NEXT + 8 * count, decl)
    put(w, a + 56, count + 1)
    return True

def list_uses(w:mutbuf, list:u64, name:u64) -> bool:
    entry = child(w, list)
    while entry != NONE:
        if same_name(w, entry, name):
            return True
        entry = next_node(w, entry)
    return False

def used_later(w:mutbuf, row:u64, term:u64, name:u64) -> bool:
    while row != NONE:
        if list_uses(w, field(w, row, K_args), name):
            return True
        row = next_node(w, row)
    role = proof_term(w, field(w, term, K_op))
    if role == 1:
        return list_uses(w, field(w, term, K_values), name)
    if role == 3:
        return list_uses(w, field(w, term, K_args), name)
    if role == 4:
        if same_name(w, field(w, term, K_cond), name):
            return True
        taken = field(w, term, K_then)
        other = field(w, term, K_else)
        return list_uses(w, field(w, taken, K_args), name) or list_uses(w, field(w, other, K_args), name)
    return False

def observe_exit(w:mutbuf, a:u64, term:u64) -> bool:
    role = proof_term(w, field(w, term, K_op))
    if role == 1:
        return observe_list(w, a, field(w, term, K_values))
    if role == 3:
        return observe_list(w, a, field(w, term, K_args))
    if role == 4:
        taken = field(w, term, K_then)
        other = field(w, term, K_else)
        return observe(w, a, field(w, term, K_cond)) and observe_list(w, a, field(w, taken, K_args)) and observe_list(w, a, field(w, other, K_args))
    return role == 2

def carry_inputs(w:mutbuf, a:u64) -> bool:
    index = 0
    count = get(w, a + 56)
    while index < count:
        put(w, a + INPUTS + 8 * index, get(w, a + NEXT + 8 * index))
        index = index + 1
    count = add_declarations(w, a + INPUTS, count, field(w, get(w, a + 32), K_out))
    put(w, a, count)
    return count <= DECL_MAX

def emit_obligation(s:readbuf, o:mutbuf, w:mutbuf, left:u64, right:u64) -> bool:
    a = get(w, 8)
    n = get(w, 32)
    at = get(w, 16)
    if n >= OBLIGATION_MAX or length(o) - at < 40 + 8 * (INPUT_MAXIMUM + OUTPUT_MAX):
        return False
    put(w, 24, a + SLOTS)
    cursor = at + 40
    inputs = emit_input_types(o, w, a, cursor)
    if inputs > INPUT_MAXIMUM:
        return False
    cursor = cursor + 8 * inputs
    outputs = get(w, a + 48)
    index = 0
    while index < outputs:
        put(o, cursor, decl_type(w, get(w, a + OBSERVED + 8 * index)))
        cursor = cursor + 8
        index = index + 1
    tail = provisional_graph(s, o, w, cursor, left, inputs, get(w, a + 16) - get(w, a))
    if tail == 0:
        return False
    tail = provisional_graph(s, o, w, tail, right, inputs, get(w, a + 24) - get(w, a))
    if tail == 0 or tail - at - 8 > GRAPH_MAX:
        return False
    put(o, at, tail - at - 8)
    put(o, at + 8, REQUEST)
    put(o, at + 16, 2)
    put(o, at + 24, inputs)
    put(o, at + 32, outputs)
    put(w, 16, tail)
    put(w, 32, n + 1)
    return True

def emit_input_types(o:mutbuf, w:mutbuf, a:u64, cursor:u64) -> u64:
    index = 0
    n = 0
    while index < get(w, a):
        decl = get(w, a + INPUTS + 8 * index)
        typ = decl_type(w, decl)
        if typ != OPAQUE:
            if n >= INPUT_MAXIMUM:
                return INPUT_MAXIMUM + 1
            put(o, cursor + 8 * n, typ)
            put(w, a + SLOTS + 8 * n, field(w, decl, K_name))
            n = n + 1
        index = index + 1
    return n

def provisional_graph(s:readbuf, o:mutbuf, w:mutbuf, at:u64, row:u64, inputs:u64, ops:u64) -> u64:
    a = get(w, 8)
    outputs = get(w, a + 48)
    terminal = get(w, 40)
    role = proof_term(w, field(w, terminal, K_op))
    trap = 0
    if get(w, a + 32) == NONE and role == 2:
        trap = proof_trap(w, field(w, terminal, K_code))
        if trap == 0 or outputs != 0:
            return 0
    size = 88 + 48 * ops + 8 * (inputs + outputs)
    if inputs + ops > NODE_MAX or size > length(o) - at:
        return 0
    put(o, at, size)
    put(o, at + 8, 1)
    put(o, at + 16, 0)
    put(o, at + 24, inputs)
    put(o, at + 32, ops)
    put(o, at + 40, choose(trap == 0, 1, 2))
    put(o, at + 48, trap)
    put(o, at + 56, 0)
    put(o, at + 64, outputs)
    put(o, at + 72, 0)
    put(o, at + 80, 0)
    cursor = at + 88
    index = 0
    while index < get(w, a):
        typ = decl_type(w, get(w, a + INPUTS + 8 * index))
        if typ != OPAQUE:
            put(o, cursor, typ)
            cursor = cursor + 8
        index = index + 1
    slot = inputs
    while slot < inputs + ops:
        if write_operation(s, o, w, cursor, row, slot) == 0:
            return 0
        row = next_node(w, row)
        slot = slot + 1
        cursor = cursor + 48
    index = 0
    while index < outputs:
        name = field(w, get(w, a + OBSERVED + 8 * index), K_name)
        found = value_slot(w, slot, name)
        if found == slot:
            return 0
        put(o, cursor, found)
        cursor = cursor + 8
        index = index + 1
    return cursor
'''


def program():
    bank = 8 * CIRCUIT_NODES
    constants = dict(BAD=INVALID, INVALID_NODE=(1 << 64) - 2, INPUT_MAX=8 << 20,
                     NODE_MAX=CIRCUIT_NODES, DECL_MAX=CIRCUIT_NODES,
                     INPUT_MAXIMUM=SUMMARIZED_CALL_INPUTS, OUTPUT_MAX=CIRCUIT_RETURNS - 2,
                     GRAPH_MAX=PROJECTION_INPUT_LIMIT, REQUEST=GRAPH_PROJECTION_REQUEST,
                     BATCH=OBLIGATION_BATCH, CHECKED_CAST=PROJECT_CHECKED_CAST,
                     OBLIGATION_MAX=DEFAULT_POLICY['max_obligations'], OPAQUE=256,
                     INPUTS=64, LEFT=64 + bank, RIGHT=64 + 2 * bank, NEXT=64 + 3 * bank,
                     SLOTS=64 + 4 * bank, OBSERVED=64 + 5 * bank,
                     WORK_BYTES=128 + 5 * bank + 8 * CIRCUIT_RETURNS)
    helpers = ('same_name', 'value_slot', 'capture_slots', 'attr', 'write_literal', 'write_operation')
    body = '\n'.join((POLICY, *(function(SCALAR_PROOF, name) for name in helpers)))
    body = re.sub(r'\b(' + '|'.join(constants) + r')\b',
                  lambda found: str(constants[found[0]]), body)
    for constant, key in (('LEFT_KEY', 'left'), ('RIGHT_KEY', 'right'),
                          ('MODE_KEY', 'mode'), ('VALUE_KEY', 'value')):
        body = body.replace(constant, ', '.join(map(str, packed(key))))
    for name, domain in (
        ('schema', dict.fromkeys(tuple(PRIMITIVE_PROFILES)[:8], 1)),
        ('type', {**{name: _word_type(name) for name in sorted(SCALARS)},
                  **dict.fromkeys(sorted(RESOURCES), constants['OPAQUE'])}),
        ('op', _GRAPH_OPERATIONS), ('pure', dict.fromkeys(sorted(PURE), 1)),
        ('trap', _CORE_TRAP_TAGS), ('term', {'ret': 1, 'trap': 2, 'jump': 3, 'branch': 4}),
        ('checked', {'checked': 1}),
    ):
        body += '\n' + match(name, domain)
    nodes = ast.parse(source_program(entry=body)).body
    retained = {'barriers'}
    while True:
        called = {call.func.id for node in nodes if node.name in retained for call in ast.walk(node)
                  if isinstance(call, ast.Call) and isinstance(call.func, ast.Name)}
        if called <= retained:
            break
        retained.update(called)
    source = ast.unparse(ast.Module(body=[node for node in nodes if node.name in retained], type_ignores=[]))
    return document(source, SOURCE.stem)


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(program()), encoding='utf-8')
