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
from tools.generate_hia_worker_inspection_request import POLICY as INSPECTION

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
# [trusted catalog, admitted arguments, null] returns both catalog spans for
# the Journal's own exact comparison before dispatch.
# [admitted subject] indexes references for the subject-specific Store reads.
# [same arguments, retained target, admitted Core SHA, admitted base SHA/null]
# renders the exact scope against which results and receipt files will bind.
def verify_request(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) >= 8 and input_word(s, 0) == INDEX_REQUEST:
        return request_index(s, o)
    if length(s) < 17 or length(s) > 65536 or length(o) < length(s) + 256 or length(w) < 65536:
        return INVALID
    put(o, 48, 65536)
    put(o, 56, 64)
    if widen(decode_json(s, w, o)) >= 4294967292 or get(w, 64) != 5:
        return INVALID
    first = 64 + get(w, 88) * 72
    count = get(w, 96)
    if count == 1:
        return subject_index(w, o, first)
    if count == 2:
        return request(s, o, w, first, next(w, first))
    if count == 3:
        args = next(w, first)
        marker = next(w, args)
        if marker == NONE or get(w, marker) != 0:
            return INVALID
        return journal_catalog(s, o, w, first, args)
    if count == 4:
        target = next(w, first)
        core = next(w, target)
        return scope(s, o, w, first, target, core, next(w, core))
    return INVALID

def journal_catalog(s:readbuf, o:mutbuf, w:mutbuf, pinned:u64, args:u64) -> u64:
    if is_object(w, args) == False or digest_text(w, pinned, False) == False:
        return INVALID
    supplied = lookup(w, args, K_catalog_sha256)
    if digest_text(w, supplied, True) == False:
        return INVALID
    at = copy_value(s, w, o, supplied, 24)
    end = copy_value(s, w, o, pinned, at)
    put(o, 0, at - 24)
    put(o, 8, end - at)
    put(o, 16, 0)
    return end

def subject_index(w:mutbuf, o:mutbuf, subject:u64) -> u64:
    kind = subject_shape(w, subject)
    if kind == 0:
        return INVALID
    count = choose(kind == 1, 0, choose(kind == 2, 2, 3))
    put(o, 0, SUBJECT_INDEX)
    put(o, 8, kind)
    put(o, 16, count)
    if count == 0:
        return 24
    subject_ref(w, o, subject, K_backend_profile, 24)
    if kind == 2:
        subject_ref(w, o, subject, K_lowering_profile, 40)
        return 56
    if kind == 3:
        subject_ref(w, o, subject, K_plan_profile, 40)
        subject_ref(w, o, subject, K_plan, 56)
    else:
        subject_ref(w, o, subject, K_native_artifact, 40)
        subject_ref(w, o, subject, K_build_receipt, 56)
    return 72

def subject_ref(w:mutbuf, o:mutbuf, subject:u64, key:u64, at:u64) -> u64:
    node = lookup(w, subject, key)
    put(o, at, get(w, node + 56))
    put(o, at + 8, get(w, node + 64))
    return 0

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

# Consume only the earlier admitted sealed request. Offsets are relative to
# that request, so a continuation can retain spans without copying values.
def request_index(s:readbuf, o:mutbuf) -> u64:
    extent = length(s)
    if extent < 88 or extent > 65544 or length(o) < 136 or input_word(s, 8) != REQUEST:
        return INVALID
    kind = input_word(s, 16)
    count = input_word(s, 24)
    if kind < 1 or kind > 4 or count < 1 or count > 4:
        return INVALID
    put(o, 0, INDEX_RESULT)
    put(o, 8, kind)
    put(o, 16, count)
    seen = 0
    claim_index = 0
    while claim_index < 4:
        claim = 0
        if claim_index < count:
            claim = input_word(s, 32 + 8 * claim_index)
            if claim < 1 or claim > 4 or (seen & (1 << claim)) != 0:
                return INVALID
            if (claim == 3 and kind == 1) or (claim == 4 and kind != 4):
                return INVALID
            seen = seen | (1 << claim)
        put(o, 24 + 8 * claim_index, claim)
        claim_index = claim_index + 1
    at = 32 + 8 * count
    field = 0
    while field < 5:
        if extent - at < 10:
            return INVALID
        size = input_word(s, at)
        at = at + 8
        if size < 2 or size > extent - at:
            return INVALID
        if field == 3 and size == 4 and byte(s, at) == 110:
            if byte(s, at + 1) != 117 or byte(s, at + 2) != 108 or byte(s, at + 3) != 108 or (seen & 4) != 0:
                return INVALID
        elif byte(s, at) != 123 or byte(s, at + size - 1) != 125:
            return INVALID
        put(o, 56 + 16 * field, at - 8)
        put(o, 64 + 16 * field, size)
        at = at + size
        field = field + 1
    if at != extent:
        return INVALID
    return 136

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
                     INDEX_REQUEST=int.from_bytes(b'HIAVRI01', 'little'),
                     INDEX_RESULT=int.from_bytes(b'HIAVRI02', 'little'),
                     SUBJECT_INDEX=int.from_bytes(b'HIAVSB01', 'little'),
                     SCOPE=int.from_bytes(b'HIAVSC01', 'little'), NONE=(1 << 64) - 1,
                     INVALID=4294967293, CATALOG_MISMATCH=4294967286,
                     SUBJECT_FIELD_COUNT=len(SUBJECT_FIELDS),
                     SCOPE_FIELD_COUNT=len(SUBJECT_FIELDS) + len(SCOPE_FIELDS))
    source = '\n'.join((POLICY, enumerated('subject', SUBJECTS), enumerated('claim', CLAIMS),
                        scope_renderers(), key_table(KEYS + ('subject',)),
                        *(function(CONTEXT, name) for name in ('copy_value', 'fragment', 'digest_text', 'equal_span')),
                        *(function(VERIFICATION, name) for name in ('next', 'is_object')),
                        function(INSPECTION, 'input_word'),
                        WIRE_HELPERS.split('\ndef signed_id', 1)[0]))
    return re.sub(r'\b(' + '|'.join(constants) + r')\b',
                  lambda match: str(constants[match[0]]), source) + '\n' + json_decoder(wire_spans=True)


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(source_program(), SOURCE.stem)), encoding='utf-8')
