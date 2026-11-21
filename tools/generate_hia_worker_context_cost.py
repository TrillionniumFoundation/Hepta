"""Author pinned Context cost-policy observations with exact u64 and JSON numbers."""
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_mcp_request import WIRE_HELPERS, comparison_table
from tools.generate_hia_worker_request import data_source, decimal_program

SOURCE = Path('examples/hia_bootstrap/worker_context_cost.hepta')
FIELDS = ('expected_invocations', 'external_costs', 'external_costs_complete',
          'model_tokens', 'model_wall_ns', 'discovery_wall_ns')
NONE = '18446744073709551615'

POLICY = r'''
# The old controller remains responsible for observation order. No invalid
# memory, invocation count or wall value is silently treated as valid zero.
def context_cost(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) == 0 or length(s) > 8388608 or length(o) < 128 or length(w) <= 8192:
        return 4294967293
    put(o, 48, 262144)
    put(o, 56, 128)
    decoded = widen(decode_json(s, w, o))
    if decoded >= 4294967292 or decoded > length(w) - 8192:
        return 4294967293
    root = 64
    if get(w, root) == 4:
        put(o, 0, AMOUNT_RESULT)
        put(o, 16, 0)
        valid = unsigned_string(w, o, root, 16)
        put(o, 8, valid)
        return 24
    if get(w, root) != 6:
        return 4294967293
    externals = lookup(w, root, 2)
    complete = lookup(w, root, 3)
    if externals == NONE or get(w, externals) != 6 or complete == NONE:
        return 4294967293
    complete_kind = get(w, complete)
    if complete_kind != 1 and complete_kind != 2:
        return 4294967293
    put(o, 0, COST_RESULT)
    put(o, 16, 0)
    put(o, 24, 0)
    put(o, 32, 0)
    put(o, 40, 0)
    invocation = unsigned_string(w, o, lookup(w, root, 1), 16)
    tokens = lookup(w, externals, 4)
    model = lookup(w, externals, 5)
    discovery = lookup(w, externals, 6)
    if tokens == NONE or model == NONE or discovery == NONE:
        return 4294967293
    token_status = 0
    if get(w, tokens) != 0:
        value = token_count(s, w, tokens)
        if value != NONE:
            put(o, 24, value)
            token_status = 3
        else:
            token_status = 1
    model_status = wall_observation(w, o, model, 32)
    discovery_status = wall_observation(w, o, discovery, 40)
    flags = invocation | (token_status << 1) | (model_status << 3) | (discovery_status << 5)
    put(o, 8, flags | (choose(complete_kind == 2, 1, 0) << 7))
    return 48

def wall_observation(w:mutbuf, o:mutbuf, node:u64, at:u64) -> u64:
    if get(w, node) == 0:
        return 0
    return 1 | (unsigned_string(w, o, node, at) << 1)

def unsigned_string(w:mutbuf, o:mutbuf, node:u64, destination:u64) -> u64:
    if node == NONE or get(w, node) != 4:
        return 0
    start = get(w, node + 24)
    width = get(w, node + 32)
    if width == 0 or width > 20 or (width > 1 and byte(w, start) == 48):
        return 0
    end = start + width
    value = 0
    while start < end:
        ch = byte(w, start)
        if ch < 48 or ch > 57:
            return 0
        digit = ch - 48
        if value > 1844674407370955161 or (value == 1844674407370955161 and digit > 5):
            return 0
        value = value * 10 + digit
        start = start + 1
    put(o, destination, value)
    return 1

def token_count(s:readbuf, w:mutbuf, node:u64) -> u64:
    kind = get(w, node)
    start = get(w, node + 24)
    width = get(w, node + 32)
    value = 0
    if kind == 3:
        negative = byte(s, start) == 45
        end = start + width
        if negative:
            start = start + 1
        while start < end:
            value = value * 10 + byte(s, start) - 48
            if value > 100000000:
                return NONE
            start = start + 1
        if negative and value != 0:
            return NONE
    elif kind == 7:
        if widen(decimal_convert(s, w, start, width)) != 8:
            return NONE
        bits = get(w, length(w) - 8192 + 8000)
        exponent = (bits >> 52) & 2047
        fraction = bits & 4503599627370495
        if exponent == 0:
            return choose(fraction == 0, 0, NONE)
        if exponent < 1023 or exponent > 1053 or (bits >> 63) != 0:
            return NONE
        shift = 1075 - exponent
        significand = 4503599627370496 | fraction
        value = significand >> shift
        if (value << shift) != significand:
            return NONE
    else:
        return NONE
    return choose(value <= 100000000, value, NONE)
'''


def program():
    policy = (POLICY.replace('NONE', NONE)
              .replace('AMOUNT_RESULT', str(int.from_bytes(b'HIACTM01', 'little')))
              .replace('COST_RESULT', str(int.from_bytes(b'HIACTC01', 'little'))))
    helpers = WIRE_HELPERS.split('\ndef signed_id', 1)[0].replace('NONE', NONE).replace('* 72', '* 56')
    return '\n'.join((policy, helpers, comparison_table('key_id', FIELDS), data_source(), decimal_program()))


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)), encoding='utf-8')
