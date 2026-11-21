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
          'max_native_wall_ms', 'max_memory_bytes', 'catalog_sha256', 'profiles',
          'compiler', 'target', 'id', 'sha256', 'schema', 'installation',
          'foreign_buffer_exports', 'baseline_core_sha256', 'lowering')
NONE = '18446744073709551615'

POLICY = r'''
# Output: four exact bounded budget integers followed by eight sealed
# length-prefixed JSON fragments used by the actual Context ports.
def context_request(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 2 or length(s) > 16384 or length(o) < 16384 or length(w) < 65536:
        return 4294967293
    put(o, 48, 4096)
    put(o, 56, 32)
    if widen(decode_json(s, w, o)) >= 4294967292:
        return 4294967293
    root = 64
    if get(w, root) == 5:
        if get(w, root + 32) == 3:
            return retained_context(s, w, o, root)
        return catalog_observation(s, w, o, root)
    if get(w, root) == 6 and get(w, root + 32) == 2:
        return context_reference(w, o, root)
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
    return fragment(s, w, o, memory, cursor + 1)

# The envelope carries the installed digest and the same request already
# admitted by the public schema. Compare its exact canonical string bytes.
def catalog_observation(s:readbuf, w:mutbuf, o:mutbuf, root:u64) -> u64:
    if get(w, root + 32) != 2:
        return 4294967293
    pinned = 64 + get(w, root + 24) * 72
    if digest_text(w, pinned, False) == False:
        return 4294967293
    args = 64 + get(w, pinned + 16) * 72
    if get(w, args) != 6:
        return 4294967293
    profiles = lookup(w, args, 14)
    if profiles != NONE:
        return installed_profiles(w, o, args, profiles, pinned)
    if get(w, args + 32) != 8:
        return 4294967293
    supplied = lookup(w, args, 13)
    if digest_text(w, supplied, True) == False:
        return 4294967293
    end = copy_value(s, w, o, supplied, 24)
    total = copy_value(s, w, o, pinned, end)
    put(o, 0, end - 24)
    put(o, 8, total - end)
    put(o, 16, 0)
    return total

def installed_profiles(w:mutbuf, o:mutbuf, manifest:u64, profiles:u64, pinned:u64) -> u64:
    if installed_manifest(w, manifest, profiles, pinned) == False:
        return 4294967293
    if profile_pin(w, o, lookup(w, profiles, 15), 0) == False:
        return 4294967293
    if profile_pin(w, o, lookup(w, profiles, 16), 64) == False:
        return 4294967293
    return 128

def installed_manifest(w:mutbuf, manifest:u64, profiles:u64, pinned:u64) -> bool:
    if profiles == NONE:
        return False
    if get(w, profiles) != 6 or get(w, profiles + 32) != 7:
        return False
    if manifest_schema(w, lookup(w, manifest, 19)) == False:
        return False
    catalog = lookup(w, manifest, 13)
    if digest_text(w, catalog, False) == False:
        return False
    left = get(w, catalog + 24)
    right = get(w, pinned + 24)
    index = 0
    while index < 64:
        if byte(w, left + index) != byte(w, right + index):
            return False
        index = index + 1
    return True

# Inspection binds its published profile to the admitted discovery manifest,
# rather than accepting a distinct profile reference supplied by its host.
def lowering_profile(s:readbuf, w:mutbuf, o:mutbuf, catalog:u64, manifest:u64) -> u64:
    profiles = lookup(w, manifest, 14)
    if installed_manifest(w, manifest, profiles, catalog) == False:
        return 4294967293
    ref = lookup(w, profiles, 23)
    if ref == NONE or get(w, ref) != 6 or get(w, ref + 32) != 2:
        return 4294967293
    if lowering_id(w, lookup(w, ref, 17)) == False or digest_text(w, lookup(w, ref, 18), False) == False:
        return 4294967293
    return copy_value(s, w, o, ref, 0)

def context_reference(w:mutbuf, o:mutbuf, root:u64) -> u64:
    id = lookup(w, root, 17)
    digest = lookup(w, root, 18)
    if id == NONE or get(w, id) != 4 or get(w, id + 32) != 36:
        return 4294967288
    if digest_text(w, digest, False) == False:
        return 4294967288
    start = get(w, id + 24)
    if byte(w, start) != 99 or byte(w, start + 1) != 116 or byte(w, start + 2) != 120 or byte(w, start + 3) != 45:
        return 4294967288
    index = 4
    while index < 36:
        unit = byte(w, start + index)
        if (unit < 48 or unit > 57) and (unit < 97 or unit > 102):
            return 4294967288
        index = index + 1
    put(o, 0, REFERENCE)
    copy_decoded(w, o, id, 8, 36)
    return copy_decoded(w, o, digest, 44, 64)

# The first two elements are the authenticated installation bindings, not
# caller input. The third is the manifest just opened through native Store.
def retained_context(s:readbuf, w:mutbuf, o:mutbuf, root:u64) -> u64:
    catalog = 64 + get(w, root + 24) * 72
    current = 64 + get(w, catalog + 16) * 72
    context = 64 + get(w, current + 16) * 72
    if digest_text(w, catalog, False) == False or get(w, current) != 6:
        return 4294967293
    if lowering_mode(w, context):
        return lowering_profile(s, w, o, catalog, current)
    if get(w, context) != 6:
        return 4294967293
    if context_schema(w, lookup(w, context, 19)) == False:
        return 4294967293
    installation = lookup(w, context, 20)
    pinned = lookup(w, context, 13)
    if installation == NONE or digest_text(w, pinned, False) == False:
        return 4294967293
    if equal_span(s, w, current, installation) == False or equal_span(s, w, catalog, pinned) == False:
        return 4294967286
    put(o, 0, RETAINED)
    at = 8
    index = 1
    while index <= 6:
        field = lookup(w, context, index)
        if field == NONE:
            return 4294967293
        at = fragment(s, w, o, field, at)
        index = index + 1
    exports = lookup(w, context, 21)
    baseline = lookup(w, context, 22)
    if exports == NONE or get(w, exports) != 5 or baseline == NONE:
        return 4294967293
    if get(w, baseline) != 0 and digest_text(w, baseline, False) == False:
        return 4294967293
    at = fragment(s, w, o, exports, at)
    return fragment(s, w, o, baseline, at)

def equal_span(s:readbuf, w:mutbuf, left:u64, right:u64) -> bool:
    width = get(w, left + 64)
    if width != get(w, right + 64):
        return False
    first = get(w, left + 56)
    second = get(w, right + 56)
    index = 0
    while index < width:
        if byte(s, first + index) != byte(s, second + index):
            return False
        index = index + 1
    return True

def profile_pin(w:mutbuf, o:mutbuf, profile:u64, target:u64) -> bool:
    if profile == NONE or get(w, profile) != 6 or get(w, profile + 32) != 2:
        return False
    identifier = lookup(w, profile, 17)
    if (target == 0 and compiler_id(w, identifier) == False) or (target == 64 and target_id(w, identifier) == False):
        return False
    sha = lookup(w, profile, 18)
    if digest_text(w, sha, False) == False:
        return False
    copy_decoded(w, o, sha, target, 64)
    return True

def copy_decoded(w:mutbuf, o:mutbuf, node:u64, target:u64, count:u64) -> u64:
    start = get(w, node + 24)
    index = 0
    while index < count:
        store(o, target + index, byte(w, start + index))
        index = index + 1
    return target + count

def digest_text(w:mutbuf, node:u64, allow_line_feed:bool) -> bool:
    if node == NONE or get(w, node) != 4:
        return False
    width = get(w, node + 32)
    start = get(w, node + 24)
    if width != 64 and (allow_line_feed == False or width != 65 or byte(w, start + 64) != 10):
        return False
    index = 0
    while index < 64:
        unit = byte(w, start + index)
        if (unit < 48 or unit > 57) and (unit < 97 or unit > 102):
            return False
        index = index + 1
    return True

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


def literal_match(name, value):
    tests = ' and '.join(f'byte(w, at + {index}) == {unit}'
                         for index, unit in enumerate(value.encode('ascii')))
    return (f'def {name}(w:mutbuf, node:u64) -> bool:\n'
            f'    if node == {NONE} or get(w, node) != 4 or get(w, node + 32) != {len(value)}:\n'
            '        return False\n'
            '    at = get(w, node + 24)\n'
            f'    return {tests}')


def program():
    tags = {'PLAN': b'HIACTP01', 'REFERENCE': b'HIACTRL1', 'RETAINED': b'HIACTR02'}
    policy = POLICY.replace('NONE', NONE)
    for tag, magic in tags.items():
        policy = policy.replace(tag, str(int.from_bytes(magic, 'little')))
    literals = {'budget_open': '{"cost_policy":', 'budget_candidates': ',"max_candidates":',
                'budget_memory': ',"max_memory_bytes":', 'budget_tokens': ',"max_model_tokens":',
                'budget_native_wall': ',"max_native_wall_ms":',
                'budget_total_wall': ',"max_total_wall_ms":'}
    matches = {'manifest_schema': 'hepta.hia.agent.manifest.v1',
               'context_schema': 'hepta.hia.agent.context.v1',
               'compiler_id': 'hia-compiler-v1', 'target_id': 'hia-target-v1',
               'lowering_mode': 'lowering', 'lowering_id': 'hia-lowering-v1'}
    return '\n'.join((policy, WIRE_HELPERS.split('\ndef signed_id', 1)[0].replace('NONE', NONE),
                     comparison_table('key_id', FIELDS),
                     RELEASE_POLICY[RELEASE_POLICY.index('\ndef decimal('):RELEASE_POLICY.index('\ndef hex(')],
                     *(literal(name, value) for name, value in literals.items()),
                     *(literal_match(name, value) for name, value in matches.items()),
                     json_decoder(wire_spans=True)))


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)), encoding='utf-8')
