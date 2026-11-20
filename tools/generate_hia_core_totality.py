"""Author the structural totality stage after exact native Core admission."""
from __future__ import annotations

import ast
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_core_admission_cli import ARENA_BYTES, STATE_BYTES
from tools.generate_hia_core_inspect_json import document, source_program
from tools.generate_hia_core_json_frontend import packed
from tools.generate_hia_native_filter import document as filter_document
from tools.generate_hia_scalar_symbolic import NONTRAPPING_OPS

MAGIC = int.from_bytes(b'HIATOT01', 'little')


PROOF = r'''
def totality_filter(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(o) < length(s) or length(o) < 1024 or length(w) < 9280:
        return 4294967293
    put(o, 48, 262144)
    put(o, 56, 64)
    decoded_size = widen(decode_json(s, w, o))
    if decoded_size >= 4294967292:
        return decoded_size
    if decoded_size + 9280 > length(w):
        return 4294967293
    functions = field(w, 0, K_functions)
    fn = choose(count(w, functions) == 1, child(w, functions), NONE)
    proved = 0
    version = field(w, 0, K_schema)
    loc = get(w, 64 + version * 56 + 24)
    if byte(w, loc + 19) >= 54:
        proved = totality_module(w, functions, decoded_size)
    i = 0
    while i < length(s):
        store(o, i, byte(s, i))
        i = i + 1
    digest(o, w, length(s))
    put(w, 56, 0)
    lit(o, w, '{"schema":"hepta.hia.core-structural-totality.v1","input_sha256":')
    quoted_hash(o, w)
    lit(o, w, ',"function":')
    if fn == NONE:
        lit(o, w, 'null')
    else:
        fragment(s, o, w, field(w, fn, K_name), 0, 0)
    if proved != 0:
        lit(o, w, ',"status":"proved","reason":"acyclic_nontrapping_core",')
        lit(o, w, '"all_inputs_return_normally_proved":true')
    else:
        lit(o, w, ',"status":"unknown","reason":"outside_structural_totality_profile",')
        lit(o, w, '"all_inputs_return_normally_proved":false')
    lit(o, w, ',"native_backend_refinement_proved":false,"execution_authority":false}\n')
    return get(w, 56)

def totality_module(w:mutbuf, functions:u64, table:u64) -> u64:
    size = count(w, functions)
    if size < 1 or size > 32:
        return 0
    directory = table + 4096
    fn = child(w, functions)
    index = 0
    while fn != NONE:
        put(w, directory + index * 32, field(w, fn, K_name))
        fn = next_node(w, fn)
        index = index + 1
    put(w, directory + 1024, 0)
    fn = child(w, functions)
    index = 0
    while fn != NONE:
        calls = structural_function(w, fn, table, directory, size)
        if calls == NONE:
            return 0
        put(w, directory + index * 32 + 8, calls)
        fn = next_node(w, fn)
        index = index + 1
    proved = 0
    complete = (1 << size) - 1
    while proved != complete:
        previous = proved
        index = 0
        while index < size:
            calls = get(w, directory + index * 32 + 8)
            if (calls & proved) == calls:
                proved = proved | (1 << index)
            index = index + 1
        if previous == proved:
            return 0
    return 1

def structural_function(w:mutbuf, fn:u64, table:u64, directory:u64, function_count:u64) -> u64:
    effects = field(w, fn, K_effects)
    if count(w, effects) > 1:
        return NONE
    if count(w, effects) == 1 and text_is(w, child(w, effects), TRAP_LITERAL) == 0:
        return NONE
    if totality_values(w, field(w, fn, K_params)) == 0:
        return NONE
    node = child(w, field(w, fn, K_returns))
    while node != NONE:
        if scalar_type(w, node) == 0:
            return NONE
        node = next_node(w, node)
    blocks = field(w, fn, K_blocks)
    size = count(w, blocks)
    if size < 1 or size > 128:
        return NONE
    node = child(w, blocks)
    index = 0
    operations = get(w, directory + 1024)
    calls = 0
    while node != NONE:
        record = table + index * 32
        put(w, record, field(w, node, K_id))
        put(w, record + 24, 0)
        if totality_values(w, field(w, node, K_params)) == 0:
            return NONE
        ops = field(w, node, K_ops)
        operations = operations + count(w, ops)
        if operations > 4096:
            return NONE
        dependencies = totality_operations(w, ops, directory, function_count)
        if dependencies == NONE:
            return NONE
        calls = calls | dependencies
        node = next_node(w, node)
        index = index + 1
    node = child(w, blocks)
    index = 0
    while node != NONE:
        if totality_edges(w, table, size, index, field(w, node, K_term)) == 0:
            return NONE
        node = next_node(w, node)
        index = index + 1
    put(w, directory + 1024, operations)
    if totality_order(w, table, size) == 0:
        return NONE
    return calls

def totality_values(w:mutbuf, values:u64) -> u64:
    node = child(w, values)
    while node != NONE:
        if scalar_type(w, field(w, node, K_type)) == 0:
            return 0
        node = next_node(w, node)
    return 1

def totality_operations(w:mutbuf, values:u64, directory:u64, function_count:u64) -> u64:
    node = child(w, values)
    calls = 0
    while node != NONE:
        op = field(w, node, K_op)
        if text_is(w, op, CALL_LITERAL) != 0:
            # Core admission already authenticated the call's name, arity,
            # argument and result types, and allowed effects.
            name = child(w, field(w, node, K_attrs))
            index = totality_target(w, directory, function_count, name)
            if index == NONE:
                return NONE
            calls = calls | (1 << index)
        else:
            if nontrapping(w, op) == 0:
                return NONE
        if totality_values(w, field(w, node, K_out)) == 0:
            return NONE
        node = next_node(w, node)
    return calls

def totality_edges(w:mutbuf, table:u64, size:u64, index:u64, term:u64) -> u64:
    record = table + index * 32
    kind = field(w, term, K_op)
    if text_is(w, kind, RET_LITERAL) != 0:
        put(w, record + 8, NONE)
        put(w, record + 16, NONE)
        return 1
    if text_is(w, kind, JUMP_LITERAL) != 0:
        left = totality_target(w, table, size, field(w, term, K_target))
        put(w, record + 8, left)
        put(w, record + 16, NONE)
        return choose(left < size, 1, 0)
    if text_is(w, kind, BRANCH_LITERAL) != 0:
        left = totality_target(w, table, size, field(w, field(w, term, K_then), K_target))
        right = totality_target(w, table, size, field(w, field(w, term, K_else), K_target))
        put(w, record + 8, left)
        put(w, record + 16, right)
        return choose(left < size and right < size, 1, 0)
    return 0

def totality_target(w:mutbuf, table:u64, size:u64, target:u64) -> u64:
    index = 0
    while index < size:
        name = get(w, table + index * 32)
        if name_before(w, name, target) == 0 and name_before(w, target, name) == 0:
            return index
        index = index + 1
    return NONE

def totality_order(w:mutbuf, table:u64, size:u64) -> u64:
    remaining = size
    while remaining != 0:
        previous = remaining
        index = 0
        while index < size:
            record = table + index * 32
            if get(w, record + 24) == 0:
                left = get(w, record + 8)
                right = get(w, record + 16)
                if totality_done(w, table, left) and totality_done(w, table, right):
                    put(w, record + 24, 1)
                    remaining = remaining - 1
            index = index + 1
        if previous == remaining:
            return 0
    return 1

def totality_done(w:mutbuf, table:u64, index:u64) -> bool:
    return index == NONE or get(w, table + index * 32 + 24) != 0
'''


def proof_document():
    entry = PROOF
    for name in ('trap', 'ret', 'jump', 'branch', 'call'):
        entry = entry.replace(name.upper() + '_LITERAL', ', '.join(map(str, packed(name))))
    entry += '\n\ndef nontrapping(w:mutbuf, op:u64) -> u64:\n'
    for name in ('const', *NONTRAPPING_OPS):
        entry += '    if text_is(w, op, ' + ', '.join(map(str, packed(name))) + ') != 0:\n'
        entry += '        return 1\n'
    entry += '    return 0\n'
    functions = ast.parse(source_program(entry=entry)).body
    used = {'totality_filter'}
    while True:
        reachable = {call.func.id for fn in functions if fn.name in used for call in ast.walk(fn)
                     if isinstance(call, ast.Call) and isinstance(call.func, ast.Name)}
        if reachable <= used:
            break
        used.update(reachable)
    source = ast.unparse(ast.Module(body=[fn for fn in functions if fn.name in used], type_ignores=[]))
    program = document(source, 'core_structural_totality')
    program['schema'] = 'hepta.hia.program.v9'
    return program


def packer_document():
    return filter_document(output_bytes=STATE_BYTES, workspace_bytes=ARENA_BYTES, magic=MAGIC,
                           module='core_totality_cli_packer', formatter=True)


if __name__ == '__main__':
    root = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap'
    for name, build in (('core_structural_totality', proof_document),
                        ('core_totality_cli_packer', packer_document)):
        (root / f'{name}.hepta').write_text(render_assembly(build()))
