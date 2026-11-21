"""Author the exact native borrowed-buffer export choices for Core emission."""
from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_native_byte_abi import MAX_EXTENT, MAX_RANGES
from hepta.hia_program import SCALARS, MAX_FUNCTIONS
from hepta.hia_program_native import IMPORTS, MAX_FRAME_BYTES, _LOADER_HOOKS
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_json_decode import source_program as json_decoder
from tools.generate_hia_mcp_request import WIRE_HELPERS, comparison_table
from tools.generate_hia_worker_context_request import NONE

SOURCE = Path('examples/hia_bootstrap/borrowed_export_wire.hepta')
FIELDS = ('functions', 'name', 'params', 'returns', 'type', 'exports')
KINDS = ('readbuf', 'mutbuf', 'u32', *sorted(SCALARS - {'u32', 'unit'}))
BLOCKED = tuple(sorted(IMPORTS | _LOADER_HOOKS))
TAG = int.from_bytes(b'HIABEX01', 'little')
WRAPPER_REQUEST = int.from_bytes(b'HIABWR01', 'little')
CORE_BYTES = 8 << 20
CORE_WITH_EXPORTS_BYTES = CORE_BYTES + 65536
CORE_WITH_EXPORTS_NODES = 262144 + 512
ARENA_BYTES = 64 + CORE_WITH_EXPORTS_NODES * 72 + CORE_WITH_EXPORTS_BYTES
# Preflight reserves a power-of-two table of 64-bit cells for twice the
# maximum key count. Crossing the original node cap doubles that table.
PREFLIGHT_BYTES = 8 << (CORE_WITH_EXPORTS_NODES * 2 - 1).bit_length()
ORDERED_AT = PREFLIGHT_BYTES - 4096

POLICY = r'''
# Input [admitted canonical Core, exact retained [[name,extent],...],
# admitted nominal profile number]. Output original function ordinals and
# extents in the legacy name order. The program is verified before this role.
def borrowed_exports(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 8 or length(s) > MAX_PACKET or length(o) < OUTPUT_MIN or length(w) < ARENA_MIN:
        return INVALID
    put(o, 48, MAX_NODES)
    put(o, 56, 128)
    if widen(decode_json(s, w, o)) >= 4294967292:
        return INVALID
    root = 64
    width = get(w, root + 32)
    if get(w, root) != 5 or (width != 3 and width != 4):
        return INVALID
    core = 64 + get(w, root + 24) * 72
    manifest = 64 + get(w, core + 16) * 72
    nominal = 64 + get(w, manifest + 16) * 72
    if get(w, core) != 6 or get(w, nominal) != 3 or get(w, nominal + 32) != 1:
        return INVALID
    level = byte(s, get(w, nominal + 24))
    if level < 48 or level > 52:
        return INVALID
    binding = 0
    if width == 4:
        mode = 64 + get(w, nominal + 16) * 72
        if get(w, mode) != 3 or get(w, mode + 32) != 1:
            return INVALID
        binding = byte(s, get(w, mode + 24)) - 48
        if binding != 1 and binding != 2:
            return INVALID
    if get(w, manifest) != 5 or get(w, manifest + 32) > 128:
        return BAD_TUPLE
    count = get(w, manifest + 32)
    at = 16
    put(o, 0, choose(binding == 1, BOUND, TAG))
    put(o, 8, count)
    if binding == 2:
        # This span is of the same Core consumed by the admission above.
        # The builder must not accept a second candidate from the caller.
        start = get(w, core + 56)
        extent = get(w, core + 64)
        if count == 0 or extent == 0 or extent > CORE_LIMIT or start > length(s) or extent > length(s) - start:
            return INVALID
        put(o, 0, BOUND_CORE)
        put(o, 16, start)
        put(o, 24, extent)
        at = 32
    if count == 0:
        return 16
    if level != 48 or lookup(w, core, 6) != NONE:
        return NOMINAL_CONFLICT
    fns = lookup(w, core, 1)
    if fns == NONE or get(w, fns) != 5 or get(w, fns + 32) == 0 or get(w, fns + 32) > FN_LIMIT:
        return INVALID
    child = get(w, manifest + 24)
    index = 0
    while index < count:
        pair = 64 + child * 72
        if get(w, pair) != 5 or get(w, pair + 32) != 2:
            return BAD_ENTRY
        name = 64 + get(w, pair + 24) * 72
        extent = 64 + get(w, name + 16) * 72
        amount = bounded_extent(s, w, extent)
        if get(w, name) != 4 or amount == 0:
            return BAD_ENTRY
        start = get(w, name + 24)
        width = get(w, name + 32)
        if blocked(w, start, width) != 0 or (width >= 6 and match_word(w, start, 6) == RESERVED_HEAD):
            return RESERVED
        position = find_function(w, fns, name)
        if position == NONE:
            return MISSING
        fn = get(w, fns + 24)
        ordinal = 0
        while ordinal < position:
            fn = get(w, 64 + fn * 72 + 16)
            ordinal = ordinal + 1
        if valid_signature(w, 64 + fn * 72) == False:
            return SIGNATURE
        if insert_ordered(o, w, name, position, amount, index) == False:
            return BAD_ENTRY
        index = index + 1
        child = get(w, pair + 16)
    if binding != 0:
        return wrapper_requests(w, o, fns, count, at)
    index = 0
    while index < count:
        at = ORDERED_AT + index * 24
        put(o, 16 + index * 16, get(o, at + 8))
        put(o, 24 + index * 16, get(o, at + 16))
        index = index + 1
    return 16 + count * 16

# Same name-ordered exports, followed by the actual checked public
# signature of each function. The wrapper sees only this bounded packet.
def wrapper_requests(w:mutbuf, o:mutbuf, fns:u64, count:u64, start:u64) -> u64:
    end = start
    index = 0
    while index < count:
        row = ORDERED_AT + index * 24
        ordinal = get(o, row + 8)
        extent = get(o, row + 16)
        child = get(w, fns + 24)
        skip = 0
        while skip < ordinal:
            child = get(w, 64 + child * 72 + 16)
            skip = skip + 1
        params = lookup(w, 64 + child * 72, 3)
        n = get(w, params + 32)
        if n > (FRAME_CAP >> 3) or end + 40 + n * 8 > ORDERED_AT:
            return BAD_FRAME
        put(o, end, ordinal)
        put(o, end + 8, 24 + n * 8)
        put(o, end + 16, WRAPPER)
        put(o, end + 24, extent)
        put(o, end + 32, n)
        end = end + 40
        param = get(w, params + 24)
        words = n
        while param != NONE:
            node = 64 + param * 72
            kind = type_id(w, lookup(w, node, 5))
            put(o, end, kind)
            words = words + choose(kind <= 2, 1, 0)
            end = end + 8
            param = get(w, node + 16)
        if ((words + 1) * 8 + 15) & 18446744073709551600 > FRAME_CAP:
            return BAD_FRAME
        index = index + 1
    return end

def bounded_extent(s:readbuf, w:mutbuf, node:u64) -> u64:
    if get(w, node) != 3:
        return 0
    at = get(w, node + 24)
    width = get(w, node + 32)
    if width < 1 or width > 7:
        return 0
    end = at + width
    value = 0
    while at < end:
        unit = byte(s, at)
        if unit < 48 or unit > 57:
            return 0
        value = value * 10 + unit - 48
        at = at + 1
    return choose(value <= EXTENT_LIMIT, value, 0)

def find_function(w:mutbuf, fns:u64, target:u64) -> u64:
    index = 0
    child = get(w, fns + 24)
    while child != NONE:
        fn = 64 + child * 72
        name = lookup(w, fn, 2)
        if name != NONE and name_order(w, name, target) == 0:
            return index
        index = index + 1
        child = get(w, fn + 16)
    return NONE

def name_order(w:mutbuf, left:u64, right:u64) -> u64:
    a = get(w, left + 24)
    b = get(w, right + 24)
    na = get(w, left + 32)
    nb = get(w, right + 32)
    limit = choose(na < nb, na, nb)
    index = 0
    while index < limit:
        one = byte(w, a + index)
        two = byte(w, b + index)
        if one != two:
            return choose(one < two, 1, 2)
        index = index + 1
    if na == nb:
        return 0
    return choose(na < nb, 1, 2)

def insert_ordered(o:mutbuf, w:mutbuf, name:u64, ordinal:u64, amount:u64, count:u64) -> bool:
    at = ORDERED_AT + count * 24
    while at > ORDERED_AT:
        previous = get(o, at - 24)
        order = name_order(w, previous, name)
        if order == 0:
            return False
        if order == 1:
            put(o, at, name)
            put(o, at + 8, ordinal)
            put(o, at + 16, amount)
            return True
        put(o, at, previous)
        put(o, at + 8, get(o, at - 16))
        put(o, at + 16, get(o, at - 8))
        at = at - 24
    put(o, at, name)
    put(o, at + 8, ordinal)
    put(o, at + 16, amount)
    return True

def valid_signature(w:mutbuf, fn:u64) -> bool:
    returns = lookup(w, fn, 4)
    if returns == NONE or get(w, returns) != 5 or get(w, returns + 32) != 1:
        return False
    result = 64 + get(w, returns + 24) * 72
    if type_id(w, result) != 3:
        return False
    params = lookup(w, fn, 3)
    if params == NONE or get(w, params) != 5:
        return False
    loans = 0
    child = get(w, params + 24)
    while child != NONE:
        param = 64 + child * 72
        kind = type_id(w, lookup(w, param, 5))
        if kind == 0:
            return False
        if kind <= 2:
            loans = loans + 1
        child = get(w, param + 16)
    return loans != 0 and loans <= LOAN_LIMIT

def type_id(w:mutbuf, node:u64) -> u64:
    if node == NONE or get(w, node) != 4:
        return 0
    return type_kind(w, get(w, node + 24), get(w, node + 32))
'''


def source_program():
    constants = {
        'TAG': TAG, 'BOUND': int.from_bytes(b'HIABEX02', 'little'),
        'BOUND_CORE': int.from_bytes(b'HIABEX03', 'little'), 'WRAPPER': WRAPPER_REQUEST,
        'RESERVED_HEAD': int.from_bytes(b'__hia_', 'little'),
        'FN_LIMIT': MAX_FUNCTIONS, 'LOAN_LIMIT': MAX_RANGES, 'EXTENT_LIMIT': MAX_EXTENT,
        'MAX_PACKET': CORE_WITH_EXPORTS_BYTES, 'MAX_NODES': CORE_WITH_EXPORTS_NODES, 'ARENA_MIN': ARENA_BYTES,
        'OUTPUT_MIN': PREFLIGHT_BYTES, 'ORDERED_AT': ORDERED_AT, 'FRAME_CAP': MAX_FRAME_BYTES,
        'CORE_LIMIT': CORE_BYTES,
        'BAD_FRAME': 4294967286,
        'NONE': NONE, 'INVALID': 4294967293, 'BAD_TUPLE': 4294967280, 'NOMINAL_CONFLICT': 4294967281,
        'BAD_ENTRY': 4294967282, 'RESERVED': 4294967283, 'MISSING': 4294967284, 'SIGNATURE': 4294967285,
    }
    policy = re.sub(r'\b(' + '|'.join(constants) + r')\b',
                    lambda token: str(constants[token[0]]), POLICY)
    decoder = json_decoder(wire_spans=True)
    # Both arena decode and its structural preflight see the outer envelope,
    # not just the bounded Core bytes carried inside it.
    guard = 'if length(s) > 8388608 or length(w) < 128'
    assert decoder.count(guard) == 2
    decoder = decoder.replace(guard, guard.replace('8388608', str(CORE_WITH_EXPORTS_BYTES)))
    return '\n'.join((policy, WIRE_HELPERS.split('\ndef signed_id', 1)[0].replace('NONE', NONE),
                      comparison_table('key_id', FIELDS), comparison_table('blocked', BLOCKED),
                      comparison_table('type_kind', KINDS), decoder))


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(source_program(), SOURCE.stem)), encoding='utf-8')
