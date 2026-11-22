"""Author the Evaluate case plan from retained ABI and workload bytes."""

from pathlib import Path
import re

from hepta.hia_agent_buffers import PROFILE
from hepta.hia_agent_identity_native import ABI_SCALAR_IDS
from tools.generate_hia_agent_identity import source_program as identity
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_json_decode import source_program as json_decoder
from tools.generate_hia_mcp_request import WIRE_HELPERS, comparison_table
from tools.generate_hia_worker_context_workload import POLICY as WORKLOAD
from tools.generate_hia_worker_emit_verification import POLICY as VERIFICATION, key_table
from tools.generate_hia_worker_inspection_effect import function
from hepta.hia_agent_assembly import render_assembly

SOURCE = Path('examples/hia_bootstrap/worker_evaluate_case.hepta')
FIELDS = ('params', 'returns', 'abi', 'max_buffer_bytes', 'function', 'arguments', 'expected',
          'bytes_hex', 'byte_length', 'fill_byte')
TYPES = (*ABI_SCALAR_IDS, 'readbuf', 'mutbuf')

POLICY = r'''
# Input is [retained signatures, one admitted case]. The extent and spans below
# name data, not descriptors. Only the runner may supply distinct owned FDs.
# Refusals distinguish absent entry, argument shape/type, ABI, and snapshot
# descriptor/extent. No output marked ready is emitted on a refusal.
def evaluate_case(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 8 or length(s) > 8388608 or length(o) < 6208 or length(w) < 4096:
        return INVALID
    put(o, 48, 32768)
    put(o, 56, 24)
    if widen(decode_json(s, w, o)) >= 4294967292 or get(w, 64) != 5 or get(w, 96) != 2:
        return INVALID
    signatures = first(w, 64)
    case = next(w, signatures)
    if is_object(w, signatures) == False or is_object(w, case) == False:
        return INVALID
    name = lookup(w, case, K_function)
    if name == NONE or get(w, name) != 4:
        return INVALID
    signature = find_signature(w, signatures, name)
    if signature == NONE:
        return refusal(o, 1)
    return plan_case(s, o, w, signature, case, name)

def find_signature(w:mutbuf, signatures:u64, name:u64) -> u64:
    width = get(w, name + 32)
    offset = get(w, name + 24)
    row = first(w, signatures)
    while row != NONE:
        if get(w, row + 48) == width:
            key = get(w, row + 40)
            n = 0
            while n < width and byte(w, offset + n) == byte(w, key + n):
                n = n + 1
            if n == width:
                return row
        row = next(w, row)
    return NONE

def plan_case(s:readbuf, o:mutbuf, w:mutbuf, signature:u64, case:u64, name:u64) -> u64:
    if is_object(w, signature) == False:
        return INVALID
    params = lookup(w, signature, K_params)
    returns = lookup(w, signature, K_returns)
    args = lookup(w, case, K_arguments)
    if params == NONE or get(w, params) != 5 or returns == NONE or get(w, returns) != 5:
        return INVALID
    count = get(w, params + 32)
    if count > 128 or get(w, returns + 32) > 1:
        return INVALID
    if args == NONE or get(w, args) != 5 or get(w, args + 32) != count:
        return refusal(o, 2)
    abi = lookup(w, signature, K_abi)
    extent = NONE
    result = type_role(w, first(w, returns))
    if get(w, returns + 32) == 1 and (result < 1 or result > UNIT):
        return INVALID
    if abi != NONE:
        if get(w, abi) != 4 or borrowed_profile(w, get(w, abi + 24), get(w, abi + 32)) == 0:
            return refusal(o, 3)
        extent = uint(s, w, lookup(w, signature, K_max_buffer_bytes), 1048576)
        if extent == 0 or extent == NONE or result != U32:
            return INVALID
        result = 256
    expected = lookup(w, case, K_expected)
    span(w, o, name, 48)
    if expected == NONE:
        put(o, 64, 0)
        put(o, 72, 0)
    else:
        span(w, o, expected, 64)
    put(o, 16, count)
    put(o, 24, result)
    return plan_arguments(s, o, w, first(w, params), first(w, args), extent)

def plan_arguments(s:readbuf, o:mutbuf, w:mutbuf, typ:u64, value:u64, extent:u64) -> u64:
    index = 0
    total = 0
    loans = 0
    while typ != NONE:
        role = type_role(w, typ)
        at = 80 + index * 48
        if role == READBUF or role == MUTBUF:
            if extent == NONE or loans == 8:
                return refusal(o, 3)
            if is_object(w, value) == False:
                return refusal(o, 4)
            size = snapshot(s, w, value)
            if size >= NONE - 2:
                return refusal(o, 5 + NONE - size)
            if size > extent:
                return refusal(o, 8)
            if snapshot_plan(s, o, w, value, at, size, role - UNIT) == 0:
                return INVALID
            total = total + size
            loans = loans + 1
        else:
            if scalar_plan(s, o, w, value, at, role) == 0:
                return refusal(o, 2)
        typ = next(w, typ)
        value = next(w, value)
        index = index + 1
    if extent != NONE and loans == 0:
        return refusal(o, 3)
    put(o, 0, PLAN)
    put(o, 8, 0)
    put(o, 32, total)
    put(o, 40, loans)
    return 80 + 48 * index

def snapshot_plan(s:readbuf, o:mutbuf, w:mutbuf, node:u64, at:u64, size:u64, role:u64) -> u64:
    put(o, at, role)
    put(o, at + 8, size)
    hex = lookup(w, node, K_bytes_hex)
    if hex == NONE:
        put(o, at + 16, 2)
        put(o, at + 24, uint(s, w, lookup(w, node, K_fill_byte), 255))
        put(o, at + 32, 0)
        put(o, at + 40, 0)
    else:
        if get(w, hex + 64) != size * 2 + 2:
            return 0
        put(o, at + 16, 1)
        put(o, at + 24, 0)
        put(o, at + 32, get(w, hex + 56) + 1)
        put(o, at + 40, size * 2)
    return 1

def scalar_plan(s:readbuf, o:mutbuf, w:mutbuf, node:u64, at:u64, role:u64) -> u64:
    kind = get(w, node)
    word = 0
    if kind == 1 or kind == 2:
        word = kind - 1
        kind = 2
    elif kind == 0:
        kind = 1
    elif kind == 3:
        start = get(w, node + 24)
        end = start + get(w, node + 32)
        if byte(s, start) == 45:
            start = start + 1
            kind = 4
        while start < end:
            point = byte(s, start)
            if point < 48 or point > 57 or word > 1844674407370955161 or (word == 1844674407370955161 and point > 53):
                return 0
            word = word * 10 + point - 48
            start = start + 1
        if word == 0:
            kind = 3
    else:
        return 0
    if abi_scalar_valid(role, kind, word) == 0:
        return 0
    put(o, at, 0)
    put(o, at + 8, choose(kind == 4, 0 - word, word))
    put(o, at + 16, 0)
    put(o, at + 24, 0)
    put(o, at + 32, 0)
    put(o, at + 40, 0)
    return 1

def next(w:mutbuf, node:u64) -> u64:
    index = get(w, node + 16)
    return choose(index == NONE, NONE, 64 + index * 72)

def first(w:mutbuf, list:u64) -> u64:
    index = get(w, list + 24)
    return choose(index == NONE, NONE, 64 + index * 72)

def type_role(w:mutbuf, node:u64) -> u64:
    if node == NONE or get(w, node) != 4:
        return 0
    return abi_role(w, get(w, node + 24), get(w, node + 32))

def refusal(o:mutbuf, reason:u64) -> u64:
    put(o, 0, PLAN)
    put(o, 8, reason)
    return 16
'''


def source_program():
    constants = {f'K_{name}': index for index, name in enumerate(FIELDS, 1)}
    constants.update(INVALID=4294967293, NONE=(1 << 64) - 1,
                     PLAN=int.from_bytes(b'HIAEVC01', 'little'),
                     UNIT=ABI_SCALAR_IDS['unit'], U32=ABI_SCALAR_IDS['u32'],
                     READBUF=len(TYPES) - 1, MUTBUF=len(TYPES))
    snapshot = function(WORKLOAD, 'snapshot')
    snapshot = re.sub(r'lookup\(w, row, ([789])\)',
                      lambda match: 'lookup(w, row, K_' + FIELDS[int(match[1])] + ')', snapshot)
    policy = '\n'.join((
        POLICY, snapshot, function(WORKLOAD, 'uint'),
        *(function(VERIFICATION, name) for name in ('is_object', 'span')),
        *(function(identity(), name) for name in ('abi_scalar_valid', 'scalar_abi_type')),
        WIRE_HELPERS.split('\ndef signed_id', 1)[0], key_table(FIELDS),
        comparison_table('abi_role', TYPES), comparison_table('borrowed_profile', (PROFILE,)),
    ))
    return re.sub(r'\b(' + '|'.join(constants) + r')\b',
                  lambda match: str(constants[match[0]]), policy) + '\n' + json_decoder(wire_spans=True)


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(source_program(), SOURCE.stem)), encoding='utf-8')
