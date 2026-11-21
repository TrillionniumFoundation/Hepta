"""Project admitted Candidate arguments and immutable result fragments in HIA."""
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_json_decode import source_program as json_decoder
from tools.generate_hia_mcp_request import WIRE_HELPERS, comparison_table
from tools.generate_hia_worker_context_request import NONE, POLICY as CONTEXT_POLICY, literal, literal_match
from tools.generate_hia_worker_inspection_effect import function
from tools.generate_hia_worker_inspection_request import POLICY as INSPECTION_POLICY

SOURCE = Path('examples/hia_bootstrap/worker_candidate_request.hepta')
FIELDS = ('catalog_sha256', 'context', 'change', 'kind', 'format', 'source',
          'base_program', 'patch_schema', 'patch', 'budget', 'max_candidates', 'max_total_wall_ms')
CHOICES = {
    'import_kind': 'import',
    'patch_kind': 'patch',
    'assembly_format': 'hia-asm.v1',
    'json_format': 'core-json',
    'patch_one': 'hepta.hia.patch.v1',
    'patch_two': 'hepta.hia.patch.v2',
}
RESULT = {
    'result_open': '{"adopted":false,"base_program":',
    'result_candidate': ',"behavior_equivalence_proved":false,"candidate":',
    'result_diagnostic': ',"core_admitted":true,"diagnostics":',
}

POLICY = r'''
# [pinned catalog, args] -> mode 1=JSON, 2=assembly, 3=patch.v1, 4=patch.v2.
# The output is a context fragment plus ordered immutable source references.
# [pinned catalog, args, null] returns the existing Journal admission frame.
# [verified context manifest] returns the bounded attempt and wall limits.
# [base-or-null, candidate, diagnostics] issues the exact public receipt.
def candidate_request(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 2 or length(s) > 16384 or length(o) < 16384 or length(w) < 65536:
        return 4294967293
    if length(s) >= 8 and input_word(s, 0) == ATTEMPT_TAG:
        return decide_attempt(s, o)
    put(o, 48, 4096)
    put(o, 56, 32)
    if widen(decode_json(s, w, o)) >= 4294967292 or get(w, 64) != 5:
        return 4294967293
    arity = get(w, 96)
    first = 64 + get(w, 88) * 72
    if arity == 1:
        return candidate_budget(s, w, o, first)
    if arity != 2 and arity != 3:
        return 4294967293
    second = 64 + get(w, first + 16) * 72
    if get(w, second) != 6:
        return 4294967293
    if arity == 3:
        third = 64 + get(w, second + 16) * 72
        if get(w, first) == 0 or get(w, first) == 6:
            return candidate_result(s, w, o, first, second, third)
        if get(w, third) != 0:
            return 4294967293
    if digest_text(w, first, False) == False:
        return 4294967293
    catalog = lookup(w, second, K_catalog_sha256)
    if digest_text(w, catalog, True) == False:
        return 4294967293
    if arity == 3:
        actual = copy_value(s, w, o, catalog, 24)
        end = copy_value(s, w, o, first, actual)
        put(o, 0, actual - 24)
        put(o, 8, end - actual)
        put(o, 16, 0)
        return end
    if equal_span(s, w, first, catalog) == False:
        return 4294967286
    context = lookup(w, second, K_context)
    change = lookup(w, second, K_change)
    if is_object(w, context) == False or is_object(w, change) == False:
        return 4294967293
    kind = lookup(w, change, K_kind)
    if import_kind(w, kind):
        return candidate_import(s, w, o, context, change)
    if patch_kind(w, kind):
        return candidate_patch(s, w, o, context, change)
    return 4294967293

def is_object(w:mutbuf, node:u64) -> bool:
    return node != NONE and get(w, node) == 6

def candidate_import(s:readbuf, w:mutbuf, o:mutbuf, context:u64, change:u64) -> u64:
    format = lookup(w, change, K_format)
    source = lookup(w, change, K_source)
    if is_object(w, source) == False:
        return 4294967293
    if json_format(w, format):
        put(o, 8, 1)
    elif assembly_format(w, format):
        put(o, 8, 2)
    else:
        return 4294967293
    put(o, 0, REQUEST_TAG)
    return fragment(s, w, o, source, fragment(s, w, o, context, 16))

def candidate_patch(s:readbuf, w:mutbuf, o:mutbuf, context:u64, change:u64) -> u64:
    schema = lookup(w, change, K_patch_schema)
    base = lookup(w, change, K_base_program)
    patch = lookup(w, change, K_patch)
    if is_object(w, base) == False or is_object(w, patch) == False:
        return 4294967293
    if patch_one(w, schema):
        put(o, 8, 3)
    elif patch_two(w, schema):
        put(o, 8, 4)
    else:
        return 4294967293
    put(o, 0, REQUEST_TAG)
    cursor = fragment(s, w, o, context, 16)
    return fragment(s, w, o, patch, fragment(s, w, o, base, cursor))

def candidate_budget(s:readbuf, w:mutbuf, o:mutbuf, context:u64) -> u64:
    if is_object(w, context) == False:
        return 4294967293
    budget = lookup(w, context, K_budget)
    if is_object(w, budget) == False:
        return 4294967293
    attempts = budget_integer(s, w, lookup(w, budget, K_max_candidates), 1, 4096)
    total = budget_integer(s, w, lookup(w, budget, K_max_total_wall_ms), 1, 86400000)
    if attempts == NONE or total == NONE:
        return 4294967293
    put(o, 0, BUDGET_TAG)
    put(o, 8, attempts)
    put(o, 16, total)
    return 24

def candidate_result(s:readbuf, w:mutbuf, o:mutbuf, base:u64, candidate:u64, diagnostics:u64) -> u64:
    if is_object(w, diagnostics) == False:
        return 4294967293
    at = copy_value(s, w, o, base, result_open(o, 0))
    at = copy_value(s, w, o, candidate, result_candidate(o, at))
    at = copy_value(s, w, o, diagnostics, result_diagnostic(o, at))
    store(o, at, 125)
    return at + 1

# The caller delivers the previously admitted Context row and an observed
# CLOCK_REALTIME value. Keep exact boundary and future-clock semantics.
# Refused plans are distinct from the Store's zero-change CAS observation.
def decide_attempt(s:readbuf, o:mutbuf) -> u64:
    if length(s) != 84:
        return 4294967293
    maximum = input_word(s, 8)
    current = input_word(s, 16)
    created = input_word(s, 24)
    now = input_word(s, 32)
    total = input_word(s, 40)
    if maximum == 0 or maximum > 4096 or total == 0 or total > 86400000:
        return 4294967293
    if current > 9223372036854775807 or valid_context_id(s) == False:
        return 4294967293
    if now >= created and now - created > total * 1000000:
        return 4294967288
    if current >= maximum:
        return 4294967287
    put(o, 0, UPDATE_TAG)
    put(o, 8, 1)
    put(o, 16, 8)
    put(o, 24, 0)
    put(o, 32, 3)
    cell(o, 40, 1, 112, 8)
    cell(o, 64, 3, 120, 36)
    cell(o, 88, 1, 156, 8)
    put(o, 112, current + 1)
    index = 0
    while index < 36:
        store(o, 120 + index, byte(s, 48 + index))
        index = index + 1
    put(o, 156, current)
    return 164

def cell(o:mutbuf, at:u64, kind:u64, offset:u64, size:u64) -> u64:
    put(o, at, kind)
    put(o, at + 8, offset)
    return put(o, at + 16, size)

def valid_context_id(s:readbuf) -> bool:
    if input_word(s, 48) & 4294967295 != CONTEXT_PREFIX:
        return False
    index = 52
    while index < 84:
        ch = byte(s, index)
        if (ch < 48 or ch > 57) and (ch < 97 or ch > 102):
            return False
        index = index + 1
    return True
'''


def program():
    substitutions = {
        'NONE': NONE,
        'REQUEST_TAG': int.from_bytes(b'HIACAN01', 'little'),
        'BUDGET_TAG': int.from_bytes(b'HIACAB01', 'little'),
        'ATTEMPT_TAG': int.from_bytes(b'HIACAP01', 'little'),
        'UPDATE_TAG': int.from_bytes(b'HIAUPB01', 'little'),
        'CONTEXT_PREFIX': int.from_bytes(b'ctx-', 'little'),
        **{f'K_{key}': index for index, key in enumerate(FIELDS, 1)},
    }
    span = CONTEXT_POLICY[CONTEXT_POLICY.index('\ndef equal_span('):
                          CONTEXT_POLICY.index('\ndef profile_pin(')]
    digest = CONTEXT_POLICY[CONTEXT_POLICY.index('\ndef digest_text('):]
    helpers = WIRE_HELPERS.split('\ndef signed_id', 1)[0]
    source = '\n'.join((POLICY, span, digest, helpers, function(INSPECTION_POLICY, 'input_word'),
                       comparison_table('key_id', FIELDS),
                       *(literal_match(name, value) for name, value in CHOICES.items()),
                       *(literal(name, value) for name, value in RESULT.items()),
                       json_decoder(wire_spans=True)))
    for token, value in substitutions.items():
        source = source.replace(token, str(value))
    return source


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)), encoding='utf-8')
