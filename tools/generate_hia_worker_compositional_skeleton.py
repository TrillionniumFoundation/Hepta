"""Project the exact ordered Core skeleton before compositional proof."""

from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_optimization import PURE
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_json_decode import source_program as json_decoder
from tools.generate_hia_mcp_request import WIRE_HELPERS
from tools.generate_hia_worker_artifact_authority import source_program as authority
from tools.generate_hia_worker_finite_reference import (
    INVALID, MAX_INPUT, NONE, POLICY as REFERENCE, enum_reader, key_reader,
)
from tools.generate_hia_worker_inspection_effect import function

SOURCE = Path('examples/hia_bootstrap/worker_compositional_skeleton.hepta')
STAMP = int.from_bytes(b'HIACSS01', 'little')
PAIR = int.from_bytes(b'HIACSP01', 'little')
DECISION = int.from_bytes(b'HIACSD01', 'little')
KEYS = ('functions', 'blocks', 'ops', 'op')

POLICY = r'''
# On an immutable, canonical, previously admitted Core document, delete
# exactly the scalar proof vocabulary from every ordered operation list.
# Preserve the complete remaining grammar: signatures, CFG, attributes,
# typed resource operands/results, exports and metadata. Equality is a
# compositional precondition, never a semantic proof.
def skeleton(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 8 or length(o) < 32:
        return BAD
    if input_word(s, 0) == PAIR:
        return compare_skeletons(s, o)
    if length(s) > INPUT_MAX or length(o) < 32 + length(s) or length(w) < 65536:
        return BAD
    put(o, 48, 262144)
    put(o, 56, 128)
    used = widen(decode_json(s, w, o))
    if used >= 4294967292 or kind(w, 64) != 6:
        return BAD
    a = (used + 7) & 18446744073709551608
    if a > length(w) or length(w) - a < 24:
        return BAD
    put(w, a, 0)
    put(w, a + 8, 32)
    put(w, a + 16, 0)
    functions = lookup(w, 64, K_functions)
    if kind(w, functions) != 5 or get(w, functions + 32) == 0:
        return BAD
    fn = child(w, functions)
    while fn != NONE:
        if project_function(s, o, w, a, fn) == False:
            return BAD
        fn = next(w, fn)
    end = copy_span(s, o, get(w, a), length(s), get(w, a + 8))
    put(o, 0, STAMP)
    put(o, 8, 0)
    put(o, 16, get(w, a + 16))
    put(o, 24, end - 32)
    return end

def project_function(s:readbuf, o:mutbuf, w:mutbuf, a:u64, fn:u64) -> bool:
    if kind(w, fn) != 6:
        return False
    blocks = lookup(w, fn, K_blocks)
    if kind(w, blocks) != 5 or get(w, blocks + 32) == 0:
        return False
    block = child(w, blocks)
    while block != NONE:
        if kind(w, block) != 6 or project_operations(s, o, w, a, lookup(w, block, K_ops)) == False:
            return False
        block = next(w, block)
    return True

def project_operations(s:readbuf, o:mutbuf, w:mutbuf, a:u64, operations:u64) -> bool:
    if kind(w, operations) != 5:
        return False
    start = get(w, operations + 56)
    size = get(w, operations + 64)
    if start < get(w, a) or start > length(s) or size < 2 or size > length(s) - start:
        return False
    end = start + size
    at = copy_span(s, o, get(w, a), start + 1, get(w, a + 8))
    count = 0
    first = True
    row = child(w, operations)
    while row != NONE:
        opcode = lookup(w, row, K_op)
        if kind(w, row) != 6 or kind(w, opcode) != 4:
            return False
        if pure_opcode(w, opcode) != NONE:
            count = count + 1
        else:
            if first == False:
                store(o, at, 44)
                at = at + 1
            start = get(w, row + 56)
            extent = get(w, row + 64)
            if extent > end - start or start >= end:
                return False
            at = copy_span(s, o, start, start + extent, at)
            first = False
        row = next(w, row)
    store(o, at, 93)
    put(w, a, end)
    put(w, a + 8, at + 1)
    put(w, a + 16, get(w, a + 16) + count)
    return True

def copy_span(s:readbuf, o:mutbuf, start:u64, stop:u64, dest:u64) -> u64:
    while start < stop:
        store(o, dest, byte(s, start))
        start = start + 1
        dest = dest + 1
    return dest

# [pair tag, left packet extent, right packet extent, policy op cap,
#  left and right physically projected skeletons].
# Status 1: different structure. Status 2: scalar operation cap crossed.
def compare_skeletons(s:readbuf, o:mutbuf) -> u64:
    if length(s) < 100:
        return BAD
    left = input_word(s, 8)
    right = input_word(s, 16)
    cap = input_word(s, 24)
    if left < 34 or right < 34 or left > length(s) - 32 or right != length(s) - 32 - left:
        return BAD
    if valid_skeleton(s, 32, left) == False or valid_skeleton(s, 32 + left, right) == False:
        return BAD
    count = input_word(s, 48) + input_word(s, 48 + left)
    status = 0
    if left != right or same_body(s, 64, 64 + left, left - 32) == False:
        status = 1
    elif count > cap:
        status = 2
    put(o, 0, DECISION)
    put(o, 8, status)
    put(o, 16, count)
    return 24

def valid_skeleton(s:readbuf, at:u64, size:u64) -> bool:
    return input_word(s, at) == STAMP and input_word(s, at + 8) == 0 and input_word(s, at + 16) <= INPUT_MAX and input_word(s, at + 24) == size - 32 and byte(s, at + 32) == 123 and byte(s, at + size - 1) == 125

def same_body(s:readbuf, left:u64, right:u64, size:u64) -> bool:
    index = 0
    while index < size:
        if byte(s, left + index) != byte(s, right + index):
            return False
        index = index + 1
    return True
'''


def program():
    values = dict(BAD=INVALID, INPUT_MAX=MAX_INPUT, NONE=NONE, PAIR=PAIR, STAMP=STAMP, DECISION=DECISION)
    values.update({f'K_{name}': index for index, name in enumerate(KEYS, 1)})
    declarations = (POLICY, *(function(REFERENCE, name) for name in ('kind', 'child', 'next')))
    policy = re.sub(r'\b(' + '|'.join(values) + r')\b', lambda match: str(values[match[0]]),
                    '\n'.join(declarations))
    return '\n'.join((
        policy, key_reader(KEYS), WIRE_HELPERS.split('\ndef signed_id', 1)[0].replace('NONE', str(NONE)),
        function(authority(), 'input_word'),
        enum_reader('pure_opcode', [(op, 1) for op in sorted(PURE)]),
        json_decoder(wire_spans=True),
    ))


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)), encoding='utf-8')
