"""Generate the typed ingress and admitted Core/subject projection for Verify."""
from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_json_decode import source_program as json_decoder
from tools.generate_hia_mcp_request import WIRE_HELPERS
from tools.generate_hia_worker_context_request import POLICY as CONTEXT
from tools.generate_hia_worker_emit_verification import POLICY as VERIFICATION, key_table, literal_match
from tools.generate_hia_worker_inspection_effect import function

SUBJECT_FIELDS = ('kind', 'backend_profile', 'lowering_profile', 'plan_profile',
                  'plan', 'native_artifact', 'build_receipt')
SCOPE_FIELDS = ('context', 'target_profile', 'candidate', 'candidate_core_sha256',
                'base_program', 'base_core_sha256')
KEYS = (*SUBJECT_FIELDS, *SCOPE_FIELDS, 'catalog_sha256', 'request_key',
        'claims', 'validation_profile', 'id', 'sha256', 'uri')
SUBJECTS = ('core', 'canonical_lowering', 'agent_machine_plan', 'native_artifact')
CLAIMS = ('core_admission', 'behavior_equivalence', 'lowering_refinement', 'encoding_check')

SOURCE = Path('examples/hia_bootstrap/worker_verify_request.hepta')

POLICY = r'''
# [trusted catalog, admitted arguments] returns only capabilities needed
# for the ordered Store reads and ordered checks; it cannot establish a proof.
# [same arguments, retained target, admitted Core SHA, admitted base SHA/null]
# renders the exact scope against which results and receipt files will bind.
def verify_request(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 20 or length(s) > 65536 or length(o) < length(s) + 256 or length(w) < 65536:
        return INVALID
    put(o, 48, 65536)
    put(o, 56, 64)
    if widen(decode_json(s, w, o)) >= 4294967292 or get(w, 64) != 5:
        return INVALID
    first = 64 + get(w, 88) * 72
    count = get(w, 96)
    if count == 2:
        return request(s, o, w, first, next(w, first))
    if count == 4:
        target = next(w, first)
        core = next(w, target)
        return scope(s, o, w, first, target, core, next(w, core))
    return INVALID

def request(s:readbuf, o:mutbuf, w:mutbuf, pinned:u64, args:u64) -> u64:
    if arguments(w, args) == False or digest_text(w, pinned, False) == False:
        return INVALID
    catalog = lookup(w, args, K_catalog_sha256)
    if equal_span(s, w, pinned, catalog) == False:
        return CATALOG_MISMATCH
    subject = lookup(w, args, K_subject)
    kind = subject_shape(w, subject)
    if kind == 0:
        return INVALID
    checks = lookup(w, args, K_claims)
    base = lookup(w, args, K_base_program)
    count = get(w, checks + 32)
    check = 64 + get(w, checks + 24) * 72
    seen = 0
    index = 0
    while index < count:
        claim = claim_id(w, check)
        if claim == 0 or (seen & (1 << claim)) != 0:
            return INVALID
        if (claim == 2 and get(w, base) == 0) or (claim == 3 and kind == 1) or (claim == 4 and kind != 4):
            return INVALID
        seen = seen | (1 << claim)
        put(o, 24 + index * 8, claim)
        check = next(w, check)
        index = index + 1
    put(o, 0, REQUEST)
    put(o, 8, kind)
    put(o, 16, count)
    at = fragment(s, w, o, lookup(w, args, K_context), 24 + count * 8)
    at = fragment(s, w, o, lookup(w, args, K_validation_profile), at)
    at = fragment(s, w, o, lookup(w, args, K_candidate), at)
    at = fragment(s, w, o, base, at)
    return fragment(s, w, o, subject, at)

def arguments(w:mutbuf, args:u64) -> bool:
    if is_object(w, args) == False or get(w, args + 32) != 8:
        return False
    if digest_text(w, lookup(w, args, K_catalog_sha256), False) == False:
        return False
    if typed_ref(w, lookup(w, args, K_context), False) == False or typed_ref(w, lookup(w, args, K_validation_profile), False) == False:
        return False
    if typed_ref(w, lookup(w, args, K_candidate), True) == False:
        return False
    base = lookup(w, args, K_base_program)
    key = lookup(w, args, K_request_key)
    checks = lookup(w, args, K_claims)
    return base != NONE and (get(w, base) == 0 or typed_ref(w, base, True)) and text(w, key) and checks != NONE and get(w, checks) == 5 and get(w, checks + 32) >= 1 and get(w, checks + 32) <= 4

def typed_ref(w:mutbuf, ref:u64, artifact:bool) -> bool:
    size = 2
    if artifact:
        size = 3
    if is_object(w, ref) == False or get(w, ref + 32) != size:
        return False
    if text(w, lookup(w, ref, K_id)) == False or digest_text(w, lookup(w, ref, K_sha256), False) == False:
        return False
    return artifact == False or text(w, lookup(w, ref, K_uri))

def text(w:mutbuf, node:u64) -> bool:
    return node != NONE and get(w, node) == 4 and get(w, node + 32) != 0 and get(w, node + 32) <= 208

def subject_shape(w:mutbuf, subject:u64) -> u64:
    if is_object(w, subject) == False:
        return 0
    kind = subject_id(w, lookup(w, subject, K_kind))
    width = get(w, subject + 32)
    if kind == 1 and width == 1:
        return kind
    if typed_ref(w, lookup(w, subject, K_backend_profile), False) == False:
        return 0
    if kind == 2 and width == 3 and typed_ref(w, lookup(w, subject, K_lowering_profile), False):
        return kind
    if kind == 3 and width == 4 and typed_ref(w, lookup(w, subject, K_plan_profile), False) and typed_ref(w, lookup(w, subject, K_plan), True):
        return kind
    if kind == 4 and width == 4 and typed_ref(w, lookup(w, subject, K_native_artifact), True) and typed_ref(w, lookup(w, subject, K_build_receipt), True):
        return kind
    return 0

def scope(s:readbuf, o:mutbuf, w:mutbuf, args:u64, target:u64, core:u64, original:u64) -> u64:
    if arguments(w, args) == False or typed_ref(w, target, False) == False:
        return INVALID
    subject = lookup(w, args, K_subject)
    if subject_shape(w, subject) == 0 or digest_text(w, core, False) == False:
        return INVALID
    program = lookup(w, args, K_base_program)
    if get(w, program) == 0:
        if get(w, original) != 0:
            return INVALID
    elif digest_text(w, original, False) == False:
        return INVALID
    cursor = 16
    store(o, cursor, 123)
    cursor = cursor + 1
    field = 0
    while field < SCOPE_FIELD_COUNT:
        key = scope_field(field)
        node = scope_value(w, args, subject, target, core, original, key)
        if node != NONE:
            if cursor != 17:
                store(o, cursor, 44)
                cursor = cursor + 1
            cursor = scope_key(o, cursor, key)
            cursor = copy_value(s, w, o, node, cursor)
        field = field + 1
    store(o, cursor, 125)
    put(o, 0, SCOPE)
    put(o, 8, cursor + 1 - 16)
    return cursor + 1

def scope_value(w:mutbuf, args:u64, subject:u64, target:u64, core:u64, original:u64, key:u64) -> u64:
    if key == K_target_profile:
        return target
    if key == K_candidate_core_sha256:
        return core
    if key == K_base_core_sha256:
        return original
    if key <= SUBJECT_FIELD_COUNT:
        return lookup(w, subject, key)
    return lookup(w, args, key)
'''


def enumerated(name, values):
    branches = [f'    if {name}_{value}(w, node):\n        return {index}'
                for index, value in enumerate(values, 1)]
    return '\n'.join([
        f'def {name}_id(w:mutbuf, node:u64) -> u64:', *branches, '    return 0',
        *(literal_match(f'{name}_{value}', value) for value in values),
    ])


def scope_renderers():
    ordered = sorted((*SUBJECT_FIELDS, *SCOPE_FIELDS))
    order = '\n'.join(f'    if index == {index}:\n        return K_{key}'
                      for index, key in enumerate(ordered))
    render = []
    for key in ordered:
        prefix = f'"{key}":'.encode()
        render.append(f'    if key == K_{key}:')
        render.extend(f'        store(o, at + {index}, {byte})' for index, byte in enumerate(prefix))
        render.append(f'        return at + {len(prefix)}')
    return '\n'.join(('def scope_field(index:u64) -> u64:', order, '    return 0',
        'def scope_key(o:mutbuf, at:u64, key:u64) -> u64:', *render, '    return at'))


def source_program():
    constants = {f'K_{name}': index for index, name in enumerate(KEYS + ('subject',), 1)}
    constants.update(REQUEST=int.from_bytes(b'HIAVRQ01', 'little'),
                     SCOPE=int.from_bytes(b'HIAVSC01', 'little'), NONE=(1 << 64) - 1,
                     INVALID=4294967293, CATALOG_MISMATCH=4294967286,
                     SUBJECT_FIELD_COUNT=len(SUBJECT_FIELDS),
                     SCOPE_FIELD_COUNT=len(SUBJECT_FIELDS) + len(SCOPE_FIELDS))
    source = '\n'.join((POLICY, enumerated('subject', SUBJECTS), enumerated('claim', CLAIMS),
                        scope_renderers(), key_table(KEYS + ('subject',)),
                        *(function(CONTEXT, name) for name in ('copy_value', 'fragment', 'digest_text', 'equal_span')),
                        *(function(VERIFICATION, name) for name in ('next', 'is_object')),
                        WIRE_HELPERS.split('\ndef signed_id', 1)[0]))
    return re.sub(r'\b(' + '|'.join(constants) + r')\b',
                  lambda match: str(constants[match[0]]), source) + '\n' + json_decoder(wire_spans=True)


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(source_program(), SOURCE.stem)), encoding='utf-8')
