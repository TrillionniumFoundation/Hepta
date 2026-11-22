"""Bind a v1 layout to the original checked Core block ordinals in HIA."""
from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_machine_plan import LAYOUT_V1
from hepta.hia_program import MAX_BLOCKS, MAX_FUNCTIONS
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_json_decode import source_program as json_decoder
from tools.generate_hia_mcp_request import WIRE_HELPERS, comparison_table
from tools.generate_hia_worker_context_request import POLICY as CONTEXT, literal_match
from tools.generate_hia_worker_inspection_effect import function

SOURCE = Path('examples/hia_bootstrap/worker_block_layout.hepta')
KEYS = ('schema', 'core_sha256', 'block_order', 'functions', 'name', 'blocks', 'id')
PACKET = b'HIABLP01'
MAX_NODES = 524288 + 2
INPUT_BYTES = (16 << 20) + 80
PREFLIGHT_BYTES = 8 << (2 * MAX_NODES - 1).bit_length()
WORKSPACE_BYTES = 64 + 72 * MAX_NODES + INPUT_BYTES

POLICY = r'''
# Input: [verified Core, independently observed Core SHA-256, v1 plan].
# The output is not a trust or refinement receipt. It is only the execution
# order, without mutating the source/slot or function-definition order.
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
    if get(w, core) != 6 or get(w, plan) != 6 or get(w, plan + 32) != 3:
        return INVALID
    schema = lookup(w, plan, K_schema)
    if layout_schema(w, schema) == False or digest_text(w, digest, False) == False:
        return INVALID
    pinned = lookup(w, plan, K_core_sha256)
    if pinned == NONE or equal_span(s, w, digest, pinned) == False:
        return INVALID
    orders = lookup(w, plan, K_block_order)
    functions = lookup(w, core, K_functions)
    if orders == NONE or get(w, orders) != 6 or get(w, orders + 32) == 0:
        return INVALID
    if functions == NONE or get(w, functions) != 5:
        return INVALID
    count = get(w, functions + 32)
    if count == 0 or count > FN_MAX:
        return INVALID
    return layout_functions(w, o, functions, orders, count)

def layout_functions(w:mutbuf, o:mutbuf, functions:u64, orders:u64, count:u64) -> u64:
    cursor = 24
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
    put(o, 0, TAG)
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
        ordinal = find_block(w, blocks, name)
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

def find_block(w:mutbuf, blocks:u64, name:u64) -> u64:
    index = get(w, blocks + 24)
    ordinal = 0
    while index != NONE:
        block = 64 + index * 72
        if get(w, block) != 6:
            return NONE
        label = lookup(w, block, K_id)
        if label == NONE or get(w, label) != 4:
            return NONE
        if same_name(w, name, get(w, label + 24), get(w, label + 32)):
            return ordinal
        index = get(w, block + 16)
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
                     TAG=int.from_bytes(PACKET, 'little'), NODES=MAX_NODES, INPUT_MAX=INPUT_BYTES,
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
        *(function(CONTEXT, name).replace('NONE', str(constants['NONE']))
          for name in ('digest_text', 'equal_span')),
        decoder,
    ))


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)), encoding='utf-8')
