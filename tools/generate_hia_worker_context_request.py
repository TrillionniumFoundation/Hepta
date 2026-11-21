"""Author the Context request projection following public schema admission."""
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_exec_release import POLICY_SOURCE as RELEASE_POLICY
from tools.generate_hia_json_decode import source_program as json_decoder
from tools.generate_hia_mcp_request import WIRE_HELPERS, comparison_table

SOURCE = Path('examples/hia_bootstrap/worker_context_request.hepta')
FIELDS = ('compiler_profile', 'target_profile', 'baseline_program', 'workload', 'objective',
          'budget', 'cost_policy', 'max_candidates', 'max_model_tokens', 'max_total_wall_ms',
          'max_native_wall_ms', 'max_memory_bytes')
NONE = '18446744073709551615'

POLICY = r'''
# Output: four exact bounded budget integers followed by the seven sealed
# length-prefixed JSON fragments used by the actual Context ports.
def context_request(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 2 or length(s) > 16384 or length(o) < 16384 or length(w) < 65536:
        return 4294967293
    put(o, 48, 4096)
    put(o, 56, 32)
    if widen(decode_json(s, w, o)) >= 4294967292:
        return 4294967293
    root = 64
    if get(w, root) != 6 or get(w, root + 32) != 8:
        return 4294967293
    budget = lookup(w, root, 6)
    if budget == NONE or get(w, budget) != 6 or get(w, budget + 32) != 6:
        return 4294967293
    cost = lookup(w, budget, 7)
    memory = lookup(w, budget, 12)
    if cost == NONE or get(w, cost) != 6 or memory == NONE or get(w, memory) != 4:
        return 4294967293
    candidates = budget_integer(s, w, lookup(w, budget, 8), 1, 4096)
    tokens = budget_integer(s, w, lookup(w, budget, 9), 0, 100000000)
    total_wall = budget_integer(s, w, lookup(w, budget, 10), 1, 86400000)
    native_wall = budget_integer(s, w, lookup(w, budget, 11), 1, 3600000)
    if (candidates | tokens | total_wall | native_wall) == NONE:
        return 4294967293
    put(o, 0, PLAN)
    put(o, 8, candidates)
    put(o, 16, tokens)
    put(o, 24, total_wall)
    put(o, 32, native_wall)
    cursor = 40
    index = 1
    while index <= 5:
        item = lookup(w, root, index)
        if item == NONE:
            return 4294967293
        tag = get(w, item)
        if tag != 6 and (index != 3 or tag != 0):
            return 4294967293
        cursor = fragment(s, w, o, item, cursor)
        index = index + 1
    cursor = fragment(s, w, o, cost, cursor)
    start = cursor + 8
    cursor = budget_open(o, start)
    cursor = copy_value(s, w, o, cost, cursor)
    cursor = budget_candidates(o, cursor)
    cursor = decimal(o, cursor, candidates)
    cursor = budget_memory(o, cursor)
    cursor = copy_value(s, w, o, memory, cursor)
    cursor = budget_tokens(o, cursor)
    cursor = decimal(o, cursor, tokens)
    cursor = budget_native_wall(o, cursor)
    cursor = decimal(o, cursor, native_wall)
    cursor = budget_total_wall(o, cursor)
    cursor = decimal(o, cursor, total_wall)
    store(o, cursor, 125)
    put(o, start - 8, cursor + 1 - start)
    return cursor + 1

def budget_integer(s:readbuf, w:mutbuf, node:u64, minimum:u64, maximum:u64) -> u64:
    if node == NONE or get(w, node) != 3:
        return NONE
    start = get(w, node + 24)
    end = start + get(w, node + 32)
    negative = byte(s, start) == 45
    if negative:
        start = start + 1
    # The admitted Worker canonicalizes these bounded finite numbers before
    # dispatch. Whole binary64 values have a final .0 in that wire.
    if end >= start + 3 and byte(s, end - 2) == 46 and byte(s, end - 1) == 48:
        end = end - 2
    if end <= start or end - start > 9:
        return NONE
    number = 0
    while start < end:
        unit = byte(s, start)
        if unit < 48 or unit > 57:
            return NONE
        number = number * 10 + unit - 48
        start = start + 1
    if (negative and number != 0) or number < minimum or number > maximum:
        return NONE
    return number

def fragment(s:readbuf, w:mutbuf, o:mutbuf, node:u64, cursor:u64) -> u64:
    end = copy_value(s, w, o, node, cursor + 8)
    put(o, cursor, end - cursor - 8)
    return end

def copy_value(s:readbuf, w:mutbuf, o:mutbuf, node:u64, cursor:u64) -> u64:
    start = get(w, node + 56)
    width = get(w, node + 64)
    if get(w, node) == 0:
        start = get(w, node + 24)
        width = get(w, node + 32)
    index = 0
    while index < width:
        store(o, cursor + index, byte(s, start + index))
        index = index + 1
    return cursor + width
'''


def literal(name, value):
    lines = [f'def {name}(o:mutbuf, at:u64) -> u64:']
    for index, byte in enumerate(value.encode('ascii')):
        lines.append(f'    store(o, at + {index}, {byte})')
    lines.append(f'    return at + {len(value)}')
    return '\n'.join(lines)


def program():
    policy = (POLICY.replace('NONE', NONE)
              .replace('PLAN', str(int.from_bytes(b'HIACTP01', 'little'))))
    literals = {'budget_open': '{"cost_policy":', 'budget_candidates': ',"max_candidates":',
                'budget_memory': ',"max_memory_bytes":', 'budget_tokens': ',"max_model_tokens":',
                'budget_native_wall': ',"max_native_wall_ms":',
                'budget_total_wall': ',"max_total_wall_ms":'}
    return '\n'.join((policy, WIRE_HELPERS.split('\ndef signed_id', 1)[0].replace('NONE', NONE),
                     comparison_table('key_id', FIELDS),
                     RELEASE_POLICY[RELEASE_POLICY.index('\ndef decimal('):RELEASE_POLICY.index('\ndef hex(')],
                     *(literal(name, value) for name, value in literals.items()),
                     json_decoder(wire_spans=True)))


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)), encoding='utf-8')
