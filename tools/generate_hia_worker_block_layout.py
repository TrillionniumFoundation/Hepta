"""Bind checked Core to explicit layout, encoding, and scalar-select choices."""
from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_machine_plan import LAYOUT_V1, MACHINE_V2, MACHINE_V3
from hepta.hia_program import MAX_BLOCKS, MAX_FUNCTIONS
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_json_decode import source_program as json_decoder
from tools.generate_hia_mcp_request import WIRE_HELPERS, comparison_table
from tools.generate_hia_worker_context_request import POLICY as CONTEXT, literal_match
from tools.generate_hia_worker_inspection_effect import function

SOURCE = Path('examples/hia_bootstrap/worker_block_layout.hepta')
KEYS = ('schema', 'core_sha256', 'block_order', 'functions', 'name', 'blocks', 'id',
        'function_order', 'function_alignment', 'scratch_registers', 'r10', 'r11',
        'instruction_selection', 'move_immediate', 'alu_immediate', 'scalar_select', 'value_registers')
PACKET = b'HIABLP01'
MACHINE_PACKET = b'HIABLP02'
SELECT_PACKET = b'HIABLP03'
MAX_NODES = 524288 + 2
INPUT_BYTES = (16 << 20) + 80
PREFLIGHT_BYTES = 8 << (2 * MAX_NODES - 1).bit_length()
WORKSPACE_BYTES = 64 + 72 * MAX_NODES + INPUT_BYTES

POLICY = r'''
# Input: [verified Core, independently observed Core SHA-256, plan].
# Output layout coordinates never mutate the original function or slot order.
# V2 adds an encoding header and a function permutation; the spill-only V3
# header also selects the scalar SELECT implementation. Block rows stay in
# original Core ordinal order.
def block_layout(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 8 or length(s) > INPUT_MAX or length(o) < PREFLIGHT or length(w) < WORKSPACE:
        return INVALID
    put(o, 48, NODES)
    put(o, 56, 128)
    if widen(decode_json(s, w, o)) >= 4294967292 or get(w, 64) != 5 or get(w, 96) != 3:
        return INVALID
    core = 64 + get(w, 88) * 72
    digest = next(w, core)
    plan = next(w, digest)
    if get(w, core) != 6 or get(w, plan) != 6:
        return INVALID
    schema = lookup(w, plan, K_schema)
    select_version = select_schema(w, schema)
    advanced = select_version or machine_schema(w, schema)
    if advanced == False and layout_schema(w, schema) == False:
        return INVALID
    fields = choose(select_version, 8, choose(advanced, 7, 3))
    if get(w, plan + 32) != fields or digest_text(w, digest, False) == False:
        return INVALID
    pinned = lookup(w, plan, K_core_sha256)
    if pinned == NONE or equal_span(s, w, digest, pinned) == False:
        return INVALID
    orders = lookup(w, plan, K_block_order)
    functions = lookup(w, core, K_functions)
    if orders == NONE or get(w, orders) != 6 or (advanced == False and get(w, orders + 32) == 0):
        return INVALID
    if functions == NONE or get(w, functions) != 5:
        return INVALID
    count = get(w, functions + 32)
    if count == 0 or count > FN_MAX:
        return INVALID
    if advanced:
        return machine_layout(s, w, o, plan, functions, orders, count, select_version)
    return emit_layout(w, o, functions, orders, count, 24, TAG)

def machine_layout(s:readbuf, w:mutbuf, o:mutbuf, plan:u64, functions:u64, orders:u64, count:u64, select_version:bool) -> u64:
    if machine_options(s, w, o, plan, select_version) == False:
        return INVALID
    order = lookup(w, plan, K_function_order)
    cursor = function_ordinals(w, o, functions, order, count, choose(select_version, 64, 56))
    if cursor == INVALID:
        return INVALID
    return emit_layout(w, o, functions, orders, count, cursor, choose(select_version, SELECT_TAG, MACHINE_TAG))

def machine_options(s:readbuf, w:mutbuf, o:mutbuf, plan:u64, select_version:bool) -> bool:
    registers = lookup(w, plan, K_scratch_registers)
    choices = lookup(w, plan, K_instruction_selection)
    if registers == NONE or get(w, registers) != 6 or get(w, registers + 32) != 2:
        return False
    if choices == NONE or get(w, choices) != 6 or get(w, choices + 32) != choose(select_version, 3, 2):
        return False
    if select_version and scalar_select(w, o, plan, choices) == False:
        return False
    first = lookup(w, registers, K_r10)
    second = lookup(w, registers, K_r11)
    swap = register_11(w, first) and register_10(w, second)
    if swap == False and (register_10(w, first) == False or register_11(w, second) == False):
        return False
    move = lookup(w, choices, K_move_immediate)
    alu = lookup(w, choices, K_alu_immediate)
    small_move = narrow_move(w, move)
    small_alu = narrow_alu(w, alu)
    if (small_move == False and wide_move(w, move) == False) or (small_alu == False and wide_alu(w, alu) == False):
        return False
    alignment = function_alignment(s, w, lookup(w, plan, K_function_alignment))
    if alignment == 0:
        return False
    put(o, 24, alignment)
    put(o, 32, choose(swap, 1, 0))
    put(o, 40, choose(small_move, 1, 0))
    put(o, 48, choose(small_alu, 1, 0))
    return True

def scalar_select(w:mutbuf, o:mutbuf, plan:u64, choices:u64) -> bool:
    assigned = lookup(w, plan, K_value_registers)
    if assigned == NONE or get(w, assigned) != 6 or get(w, assigned + 32) != 0:
        return False
    field = lookup(w, choices, K_scalar_select)
    cmov = select_cmov(w, field)
    if cmov == False and select_branch(w, field) == False:
        return False
    put(o, 56, choose(cmov, 1, 0))
    return True

def function_alignment(s:readbuf, w:mutbuf, field:u64) -> u64:
    if field == NONE or get(w, field) != 3:
        return 0
    at = get(w, field + 24)
    size = get(w, field + 32)
    if size == 1 and byte(s, at) == 49:
        return 1
    if size == 2:
        if byte(s, at) == 49 and byte(s, at + 1) == 54:
            return 16
        if byte(s, at) == 51 and byte(s, at + 1) == 50:
            return 32
        if byte(s, at) == 54 and byte(s, at + 1) == 52:
            return 64
    return 0

def function_ordinals(w:mutbuf, o:mutbuf, functions:u64, order:u64, count:u64, cursor:u64) -> u64:
    if order == NONE or get(w, order) != 5 or get(w, order + 32) != count:
        return INVALID
    seen = length(o) - BLOCK_MAX
    index = 0
    while index < count:
        store(o, seen + index, 0)
        index = index + 1
    index = get(w, order + 24)
    while index != NONE:
        name = 64 + index * 72
        if get(w, name) != 4:
            return INVALID
        ordinal = find_member(w, functions, name, K_name)
        if ordinal >= count or byte(o, seen + ordinal) != 0:
            return INVALID
        store(o, seen + ordinal, 1)
        put(o, cursor, ordinal)
        cursor = cursor + 8
        index = get(w, name + 16)
    return cursor

def emit_layout(w:mutbuf, o:mutbuf, functions:u64, orders:u64, count:u64, start:u64, tag:u64) -> u64:
    cursor = start
    remaining = get(w, orders + 32)
    index = get(w, functions + 24)
    while index != NONE:
        fn = 64 + index * 72
        if get(w, fn) != 6:
            return INVALID
        name = lookup(w, fn, K_name)
        blocks = lookup(w, fn, K_blocks)
        if name == NONE or get(w, name) != 4 or blocks == NONE or get(w, blocks) != 5:
            return INVALID
        order = find_order(w, orders, name)
        span = get(w, blocks + 32)
        if span == 0 or span > BLOCK_MAX or cursor + 8 + 8 * span > length(o) - BLOCK_MAX:
            return INVALID
        put(o, cursor, span)
        cursor = cursor + 8
        if order == NONE:
            ordinal = 0
            while ordinal < span:
                put(o, cursor, ordinal)
                cursor = cursor + 8
                ordinal = ordinal + 1
        else:
            if remaining == 0:
                return INVALID
            remaining = remaining - 1
            cursor = planned_ordinals(w, o, blocks, order, span, cursor)
            if cursor == INVALID:
                return INVALID
        index = get(w, fn + 16)
    if remaining != 0:
        return INVALID
    put(o, 0, tag)
    put(o, 8, count)
    put(o, 16, cursor)
    return cursor

def planned_ordinals(w:mutbuf, o:mutbuf, blocks:u64, order:u64, span:u64, cursor:u64) -> u64:
    if get(w, order) != 5 or get(w, order + 32) != span:
        return INVALID
    seen = length(o) - BLOCK_MAX
    ordinal = 0
    while ordinal < span:
        store(o, seen + ordinal, 0)
        ordinal = ordinal + 1
    index = get(w, order + 24)
    while index != NONE:
        name = 64 + index * 72
        if get(w, name) != 4:
            return INVALID
        ordinal = find_member(w, blocks, name, K_id)
        if ordinal >= span or byte(o, seen + ordinal) != 0:
            return INVALID
        store(o, seen + ordinal, 1)
        put(o, cursor, ordinal)
        cursor = cursor + 8
        index = get(w, name + 16)
    return cursor

def find_order(w:mutbuf, orders:u64, name:u64) -> u64:
    index = get(w, orders + 24)
    while index != NONE:
        value = 64 + index * 72
        if same_name(w, name, get(w, value + 40), get(w, value + 48)):
            return value
        index = get(w, value + 16)
    return NONE

def find_member(w:mutbuf, members:u64, name:u64, field:u64) -> u64:
    index = get(w, members + 24)
    ordinal = 0
    while index != NONE:
        member = 64 + index * 72
        if get(w, member) != 6:
            return NONE
        label = lookup(w, member, field)
        if label == NONE or get(w, label) != 4:
            return NONE
        if same_name(w, name, get(w, label + 24), get(w, label + 32)):
            return ordinal
        index = get(w, member + 16)
        ordinal = ordinal + 1
    return NONE

def same_name(w:mutbuf, name:u64, at:u64, size:u64) -> bool:
    if size != get(w, name + 32):
        return False
    start = get(w, name + 24)
    index = 0
    while index < size:
        if byte(w, start + index) != byte(w, at + index):
            return False
        index = index + 1
    return True

def next(w:mutbuf, node:u64) -> u64:
    return 64 + get(w, node + 16) * 72
'''


def program():
    constants = {f'K_{name}': index for index,name in enumerate(KEYS, 1)}
    constants.update(INVALID=4294967293, NONE=(1 << 64) - 1,
                     TAG=int.from_bytes(PACKET, 'little'), MACHINE_TAG=int.from_bytes(MACHINE_PACKET, 'little'),
                     SELECT_TAG=int.from_bytes(SELECT_PACKET, 'little'),
                     NODES=MAX_NODES, INPUT_MAX=INPUT_BYTES,
                     PREFLIGHT=PREFLIGHT_BYTES, WORKSPACE=WORKSPACE_BYTES,
                     FN_MAX=MAX_FUNCTIONS, BLOCK_MAX=MAX_BLOCKS)
    decoder = json_decoder(wire_spans=True)
    original_guard = 'if length(s) > 8388608 or length(w) < 128'
    assert decoder.count(original_guard) == 2
    decoder = decoder.replace(original_guard, original_guard.replace('8388608', str(INPUT_BYTES)))
    policy = re.sub(r'\b(' + '|'.join(constants) + r')\b', lambda m: str(constants[m[0]]), POLICY)
    return '\n'.join((
        policy, WIRE_HELPERS.split('\ndef signed_id', 1)[0].replace('NONE', str(constants['NONE'])),
        comparison_table('key_id', KEYS), literal_match('layout_schema', LAYOUT_V1),
        *(literal_match(name, value) for name, value in (
            ('machine_schema', MACHINE_V2), ('select_schema', MACHINE_V3),
            ('select_cmov', 'cmov_scalar'), ('select_branch', 'branch'), ('register_10', 'r10'), ('register_11', 'r11'),
            ('narrow_move', 'mov32_if_exact'), ('wide_move', 'movabs'),
            ('narrow_alu', 'imm8_if_exact'), ('wide_alu', 'imm32'),
        )),
        *(function(CONTEXT, name).replace('NONE', str(constants['NONE']))
          for name in ('digest_text', 'equal_span')),
        decoder,
    ))


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)), encoding='utf-8')
