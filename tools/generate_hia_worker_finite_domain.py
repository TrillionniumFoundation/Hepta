"""Author the HIA planner for complete, pure finite-domain replay."""

from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_optimization import PURE
from hepta.hia_program import MAX_FUNCTIONS
from hepta.hia_schema import PRIMITIVE_PROFILES, supports_feature
from hepta.hia_scalar_reference_native import OPCODES
from hepta.hia_scalar_reference_wire import CONSTANT, RETURN, TRAP, JUMP, BRANCH, TYPES
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_json_decode import source_program as json_decoder
from tools.generate_hia_mcp_request import WIRE_HELPERS
from tools.generate_hia_worker_emit_verification import literal_match
from tools.generate_hia_worker_finite_reference import (
    INVALID, MAX_BLOCKS, MAX_INPUT, MAX_OPERATIONS, NONE, POLICY as REFERENCE, enum_reader, key_reader,
)
from tools.generate_hia_worker_inspection_effect import function

SOURCE = Path('examples/hia_bootstrap/worker_finite_domain.hepta')
MAGIC = int.from_bytes(b'HIAVFD01', 'little')
INELIGIBLE = int.from_bytes(b'HIAVFI01', 'little')
KEYS = ('functions', 'exports', 'name', 'blocks', 'params', 'returns', 'effects',
        'entry', 'id', 'ops', 'term', 'op', 'args', 'target', 'then', 'else', 'type', 'schema')

POLICY = r'''
# [independently admitted base Core, independently admitted candidate Core].
# A third, literal true asks for a typed ineligibility outcome on fresh
# verification. Historical retained-proof requests still fail closed.
# Header: tag, base/candidate ledger bits, public functions, argument tuples.
# Each 56-byte row is [base name span, arity, tuples, result type, 12 kinds].
# A plan is not an equivalence verdict: it authorizes exact enumeration order.
def domain_plan(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 5 or length(s) > INPUT_MAX or length(o) < 1048576 or length(w) < 33554432:
        return BAD
    put(o, 48, 262144)
    put(o, 56, 128)
    used = widen(decode_json(s, w, o))
    count = get(w, 96)
    if used >= 4294967292 or get(w, 64) != 5 or (count != 2 and count != 3):
        return BAD
    arena = (used + 7) & 18446744073709551608
    if length(w) - arena < MAP_BYTES:
        return BAD
    base = child(w, 64)
    candidate = next(w, base)
    if object(w, base) == False or object(w, candidate) == False:
        return BAD
    fresh = count == 3
    if fresh and kind(w, next(w, candidate)) != 2:
        return BAD
    before = chain_ledger(w, lookup(w, base, K_schema))
    after = chain_ledger(w, lookup(w, candidate, K_schema))
    if before > 1 or after > 1:
        return BAD
    planned = plan_functions(o, w, arena, base, candidate, before | (after << 1))
    if planned == BAD and fresh:
        put(o, 0, INELIGIBLE)
        put(o, 8, 0)
        return 16
    return planned

def plan_functions(o:mutbuf, w:mutbuf, a:u64, base:u64, candidate:u64, ledgers:u64) -> u64:
    left = lookup(w, base, K_functions)
    right = lookup(w, candidate, K_functions)
    if kind(w, left) != 5 or kind(w, right) != 5:
        return BAD
    count = get(w, left + 32)
    if count == 0 or count > FN_MAX or count != get(w, right + 32):
        return BAD
    put(w, a + 48, 0)
    cursor = 32
    selected = 0
    fn = child(w, left)
    while fn != NONE:
        name = lookup(w, fn, K_name)
        other = named(w, right, name, K_name)
        if other == NONE or same_interface(w, fn, other) == False:
            return BAD
        if pure_dag(w, a, fn) == False or pure_dag(w, a, other) == False:
            return BAD
        returns = lookup(w, fn, K_returns)
        params = lookup(w, fn, K_params)
        signature = public_signature(w, returns, params)
        first = signature != NOT_PUBLIC and published(w, lookup(w, base, K_exports), name)
        second = signature != NOT_PUBLIC and published(w, lookup(w, candidate, K_exports), name)
        if first != second:
            return BAD
        if first:
            if publish_domain(o, w, a, cursor, name, params, signature) == False:
                return BAD
            cursor = cursor + 56
            selected = selected + 1
        fn = next(w, fn)
    total = get(w, a + 48)
    if total == 0:
        return BAD
    put(o, 0, PLAN)
    put(o, 8, ledgers)
    put(o, 16, selected)
    put(o, 24, total)
    return cursor

def same_interface(w:mutbuf, left:u64, right:u64) -> bool:
    if same_types(w, lookup(w, left, K_returns), lookup(w, right, K_returns)) == False:
        return False
    if same_types(w, lookup(w, left, K_effects), lookup(w, right, K_effects)) == False:
        return False
    a = lookup(w, left, K_params)
    b = lookup(w, right, K_params)
    if kind(w, a) != 5 or kind(w, b) != 5 or get(w, a + 32) != get(w, b + 32):
        return False
    p = child(w, a)
    q = child(w, b)
    while p != NONE:
        if eq_text(w, lookup(w, p, K_type), lookup(w, q, K_type)) == False:
            return False
        if eq_text(w, lookup(w, p, K_name), lookup(w, q, K_name)) == False:
            return False
        p = next(w, p)
        q = next(w, q)
    return True

def same_types(w:mutbuf, a:u64, b:u64) -> bool:
    if kind(w, a) != 5 or kind(w, b) != 5 or get(w, a + 32) != get(w, b + 32):
        return False
    p = child(w, a)
    q = child(w, b)
    while p != NONE:
        if eq_text(w, p, q) == False:
            return False
        p = next(w, p)
        q = next(w, q)
    return True

def pure_dag(w:mutbuf, a:u64, fn:u64) -> bool:
    blocks = lookup(w, fn, K_blocks)
    effects = lookup(w, fn, K_effects)
    if kind(w, blocks) != 5 or kind(w, effects) != 5:
        return False
    count = get(w, blocks + 32)
    if count == 0 or count > BLOCK_MAX:
        return False
    if get(w, effects + 32) > 1 or (get(w, effects + 32) == 1 and trap_name(w, child(w, effects)) == False):
        return False
    put(w, a + 24, count)
    if index_blocks(w, a, blocks, lookup(w, fn, K_entry)) == False or graph_is_acyclic(w, a) == False:
        return False
    block = child(w, blocks)
    while block != NONE:
        op = child(w, lookup(w, block, K_ops))
        while op != NONE:
            name = lookup(w, op, K_op)
            if opcode(w, name) == NONE and cast_name(w, name) == False:
                return False
            op = next(w, op)
        block = next(w, block)
    return True

def public_signature(w:mutbuf, returns:u64, params:u64) -> u64:
    if get(w, returns + 32) > 1:
        return NOT_PUBLIC
    return_type = NONE
    if get(w, returns + 32) == 1:
        return_type = type_code(w, child(w, returns))
        if return_type == NONE:
            return NOT_PUBLIC
    param = child(w, params)
    while param != NONE:
        typ = def_type(w, param)
        if typ == NONE or typ == 1:
            return NOT_PUBLIC
        param = next(w, param)
    return return_type

def publish_domain(o:mutbuf, w:mutbuf, a:u64, cursor:u64, name:u64, params:u64, returns:u64) -> bool:
    count = get(w, params + 32)
    if count > 12 or cursor > length(o) - 56:
        return False
    put(o, cursor, get(w, name + 56))
    put(o, cursor + 8, get(w, name + 64))
    put(o, cursor + 16, count)
    put(o, cursor + 32, returns)
    put(o, cursor + 40, 0)
    put(o, cursor + 48, 0)
    bits = 0
    at = cursor + 40
    param = child(w, params)
    while param != NONE:
        typ = def_type(w, param)
        kind = domain_kind(typ)
        if kind == 0:
            return False
        bits = bits + (kind & 127)
        if bits > 12:
            return False
        store(o, at, kind)
        at = at + 1
        param = next(w, param)
    required = 1 << bits
    total = get(w, a + 48)
    if required > 4096 - total:
        return False
    put(w, a + 48, total + required)
    put(o, cursor + 24, required)
    return True

def domain_kind(typ:u64) -> u64:
    if typ == BOOL_TYPE:
        return 1
    if typ == U8_TYPE:
        return 8
    if typ == I8_TYPE:
        return 136
    return 0
'''


def program():
    shared = ('published', 'index_blocks', 'graph_is_acyclic', 'terminal_ready', 'target_ready',
              'def_type', 'block_row', 'named', 'object', 'kind', 'child', 'next', 'eq_text')
    values = dict(BAD=INVALID, NONE=NONE, NOT_PUBLIC=NONE - 1, PLAN=MAGIC, INELIGIBLE=INELIGIBLE,
                  INPUT_MAX=MAX_INPUT, FN_MAX=MAX_FUNCTIONS, BLOCK_MAX=MAX_BLOCKS,
                  OP_MAX=MAX_OPERATIONS, MAP_BYTES=64 + 24 * MAX_BLOCKS,
                  RET=RETURN, T_TRAP=TRAP, T_JUMP=JUMP, T_BRANCH=BRANCH,
                  BOOL_TYPE=TYPES.index('bool'), U8_TYPE=TYPES.index('u8'), I8_TYPE=TYPES.index('i8'))
    values.update({f'K_{name}': index for index, name in enumerate(KEYS, 1)})
    policy = '\n'.join((POLICY, *(function(REFERENCE, name) for name in shared)))
    policy = re.sub(r'\b(' + '|'.join(values) + r')\b', lambda match: str(values[match[0]]), policy)
    ops = [('const', CONSTANT), *((op, OPCODES[op]) for op in sorted(PURE - {'const', 'int.cast'}))]
    return '\n'.join((
        policy, key_reader(KEYS), WIRE_HELPERS.split('\ndef signed_id', 1)[0].replace('NONE', str(NONE)),
        enum_reader('type_code', [(name, index) for index, name in enumerate(TYPES)]),
        enum_reader('opcode', ops),
        enum_reader('term_code', (('ret', RETURN), ('trap', TRAP), ('jump', JUMP), ('branch', BRANCH))),
        enum_reader('chain_ledger', [(schema, int(supports_feature(schema, 'recursive_chain')))
                                     for schema in PRIMITIVE_PROFILES]),
        literal_match('trap_name', 'trap'), literal_match('cast_name', 'int.cast'),
        json_decoder(wire_spans=True),
    ))


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)), encoding='utf-8')
