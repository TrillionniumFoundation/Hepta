"""Bind retained native build data to trusted installation and physical bytes."""
from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_json_decode import source_program as json_decoder
from tools.generate_hia_mcp_request import WIRE_HELPERS
from tools.generate_hia_worker_artifact_authority import source_program as authority
from tools.generate_hia_worker_context_request import POLICY as CONTEXT, literal_match
from tools.generate_hia_worker_inspection_effect import function
from tools.generate_hia_worker_proof_scope import split_key_table

SOURCE = Path('examples/hia_bootstrap/worker_build_custody.hepta')
METADATA = ('candidate', 'codegen', 'context', 'core_sha256', 'foreign_buffer_exports',
            'installation', 'machine_plan', 'object_artifact', 'object_sha256', 'output_kind', 'signatures')
KEYS = (*METADATA, 'artifact_bytes', 'artifact_sha256', 'backend_profile', 'backend_sha256',
        'implementation_sha256', 'input_sha256', 'kind', 'machine_plan_sha256', 'native_artifact',
        'native_build', 'schema', 'sha256', 'target_profile', 'plan')

POLICY = r'''
# Protected input:
# [installation, separately pinned packed producer or null, active Context,
# active backend, active target, native ref, retained build receipt,
# retained native metadata, retained object metadata,
# [verified Core digest, checked input digest, candidate ABI, Context exports,
#  exact object digest, exact image digest, image length, object_bytes == image_bytes,
#  and for explicit plans: canonical Plan, raw Store SHA-256, canonical Plan SHA-256]].
# No field in a retained receipt supplies an installation binding or physical fact.
# For downstream readers, the six-field form binds the subject before issuing
# the two exact retained references. It is not a physical custody receipt.
# [installation, active Context, active backend, active target, native ref, build receipt]
def build_custody(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 32 or length(s) > 8388608 or length(o) < 64 or length(w) < 65536:
        return INVALID
    put(o, 48, 262144)
    put(o, 56, 128)
    if widen(decode_json(s, w, o)) >= 4294967292 or get(w, 64) != 5:
        return INVALID
    fields = get(w, 96)
    if fields != 6 and fields != 10:
        return INVALID
    install = 64 + get(w, 88) * 72
    packed = NONE
    context = next(w, install)
    if fields == 10:
        packed = context
        context = next(w, packed)
    backend = next(w, context)
    target = next(w, backend)
    native = next(w, target)
    record = next(w, native)
    if get(w, install) != 6 or get(w, context) != 6 or get(w, backend) != 6 or get(w, target) != 6:
        return INVALID
    if get(w, record) != 6 or build_schema(w, lookup(w, record, K_schema)) == False:
        return INVALID
    if exact_reference(s, w, native) == False:
        return INVALID
    same_subject = field_matches(s, w, record, K_installation, install) and field_matches(s, w, record, K_context, context) and field_matches(s, w, record, K_native_artifact, native) and field_matches(s, w, record, K_backend_profile, backend) and field_matches(s, w, record, K_target_profile, target)
    if fields == 6:
        return build_references(s, w, o, record, same_subject)
    metadata = next(w, record)
    object_info = next(w, metadata)
    facts = next(w, object_info)
    if get(w, metadata) != 6 or get(w, object_info) != 6 or get(w, facts) != 5:
        return INVALID
    count = get(w, facts + 32)
    if count != 8 and count != 11:
        return INVALID
    if same_subject == False:
        return answer(o, 1)
    if matches_metadata(s, w, record, metadata) == False:
        return answer(o, 2)
    result = bind_products(s, w, o, install, packed, record, object_info, facts)
    if result == 24 and observed_plan(s, w, record, facts) == False:
        return answer(o, 5)
    return result

def build_references(s:readbuf, w:mutbuf, o:mutbuf, record:u64, same_subject:bool) -> u64:
    if length(o) < 368:
        return INVALID
    put(o, 0, LOOKUP)
    if same_subject == False:
        put(o, 8, 1)
        return 16
    candidate = lookup(w, record, K_candidate)
    object_ref = lookup(w, record, K_object_artifact)
    if exact_reference(s, w, candidate) == False or exact_reference(s, w, object_ref) == False:
        put(o, 8, 2)
        return 16
    plan = retained_plan(s, w, record)
    if plan == NONE:
        put(o, 8, 2)
        return 16
    if plan != 0 and length(o) < 544:
        return INVALID
    put(o, 8, 0)
    copy_reference(s, o, get(w, candidate + 56), 16)
    copy_reference(s, o, get(w, object_ref + 56), 192)
    if plan == 0:
        return 368
    copy_reference(s, o, get(w, plan + 56), 368)
    return 544

def copy_reference(s:readbuf, o:mutbuf, at:u64, offset:u64) -> u64:
    index = 0
    while index < 176:
        store(o, offset + index, byte(s, at + index))
        index = index + 1
    return 0

def bind_products(s:readbuf, w:mutbuf, o:mutbuf, install:u64, packed:u64, record:u64, object_info:u64, facts:u64) -> u64:
    core = 64 + get(w, facts + 24) * 72
    input_digest = next(w, core)
    signatures = next(w, input_digest)
    exports = next(w, signatures)
    obj = next(w, exports)
    image = next(w, obj)
    extent = next(w, image)
    equal = next(w, extent)
    if digest_text(w, core, False) == False or digest_text(w, input_digest, False) == False or digest_text(w, obj, False) == False or digest_text(w, image, False) == False:
        return INVALID
    if get(w, signatures) != 6 or get(w, exports) != 5 or get(w, extent) != 3 or (get(w, equal) != 1 and get(w, equal) != 2):
        return INVALID
    if field_matches(s, w, record, K_core_sha256, core) == False or field_matches(s, w, record, K_signatures, signatures) == False:
        return answer(o, 2)
    if exports_match(s, w, record, exports) == False:
        return answer(o, 2)
    built = lookup(w, record, K_native_build)
    if built == NONE or get(w, built) != 6:
        return answer(o, 3)
    producer = producer_kind(s, w, install, packed, built)
    if producer == 0:
        return answer(o, 3)
    if field_matches(s, w, built, K_core_sha256, core) == False or field_matches(s, w, built, K_input_sha256, input_digest) == False:
        return answer(o, 3)
    if field_matches(s, w, built, K_foreign_buffer_exports, exports) == False or field_matches(s, w, built, K_artifact_sha256, image) == False:
        return answer(o, 3)
    if field_matches(s, w, lookup(w, record, K_native_artifact), K_sha256, image) == False:
        return answer(o, 3)
    if field_matches(s, w, built, K_artifact_bytes, extent) == False:
        return answer(o, 3)
    kind = lookup(w, record, K_output_kind)
    if object_kind(w, kind) == False and shared_kind(w, kind) == False:
        return answer(o, 3)
    if field_matches(s, w, built, K_kind, kind) == False:
        return answer(o, 3)
    if object_kind(w, kind) and get(w, equal) != 2:
        return answer(o, 4)
    if object_binding(s, w, install, record, built, object_info, core, obj) == False:
        return answer(o, 4)
    put(o, 16, producer)
    answer(o, 0)
    return 24

# The legacy record's normalized Plan is not proof that its original input
# artifact was present. Return a typed read reference before the caller
# derives the independent normalized content and the two digest domains.
def retained_plan(s:readbuf, w:mutbuf, record:u64) -> u64:
    plan = lookup(w, record, K_machine_plan)
    codegen = lookup(w, record, K_codegen)
    if plan == NONE or codegen == NONE or get(w, codegen) != 6:
        return NONE
    kind = lookup(w, codegen, K_kind)
    if get(w, plan) == 0 and canonical_kind(w, kind) and get(w, codegen + 32) == 2:
        return 0
    if get(w, plan) != 6 or explicit_kind(w, kind) == False or get(w, codegen + 32) != 4:
        return NONE
    ref = lookup(w, codegen, K_plan)
    return choose(exact_reference(s, w, ref), ref, NONE)

def observed_plan(s:readbuf, w:mutbuf, record:u64, facts:u64) -> bool:
    ref = retained_plan(s, w, record)
    digest = lookup(w, lookup(w, record, K_native_build), K_machine_plan_sha256)
    if ref == NONE or digest == NONE:
        return False
    if ref == 0:
        return get(w, facts + 32) == 8 and get(w, digest) == 0
    if get(w, facts + 32) != 11:
        return False
    physical = 64 + get(w, facts + 24) * 72
    count = 0
    while count < 8:
        physical = next(w, physical)
        count = count + 1
    raw = next(w, physical)
    normalized = next(w, raw)
    if get(w, physical) != 6 or digest_text(w, raw, False) == False or digest_text(w, normalized, False) == False:
        return False
    return field_matches(s, w, record, K_machine_plan, physical) and field_matches(s, w, ref, K_sha256, raw) and equal_span(s, w, digest, normalized)

def object_binding(s:readbuf, w:mutbuf, install:u64, record:u64, built:u64, object_info:u64, core:u64, obj:u64) -> bool:
    objref = lookup(w, record, K_object_artifact)
    if exact_reference(s, w, objref) == False or field_matches(s, w, objref, K_sha256, obj) == False:
        return False
    if field_matches(s, w, built, K_object_artifact, objref) == False:
        return False
    if field_matches(s, w, record, K_object_sha256, obj) == False or field_matches(s, w, built, K_object_sha256, obj) == False:
        return False
    if get(w, object_info + 32) != 4 or object_schema(w, lookup(w, object_info, K_schema)) == False:
        return False
    if field_matches(s, w, object_info, K_core_sha256, core) == False or field_matches(s, w, object_info, K_installation, install) == False:
        return False
    plan = lookup(w, built, K_machine_plan_sha256)
    if plan == NONE or (get(w, plan) != 0 and digest_text(w, plan, False) == False):
        return False
    return field_matches(s, w, object_info, K_machine_plan_sha256, plan)

def producer_kind(s:readbuf, w:mutbuf, install:u64, packed:u64, built:u64) -> u64:
    reference = lookup(w, install, K_backend_sha256)
    observed = lookup(w, built, K_implementation_sha256)
    if digest_text(w, reference, False) == False or digest_text(w, observed, False) == False:
        return 0
    if equal_span(s, w, reference, observed):
        return 1
    if digest_text(w, packed, False) and equal_span(s, w, packed, observed):
        return 2
    return 0

def exports_match(s:readbuf, w:mutbuf, record:u64, expected:u64) -> bool:
    field = lookup(w, record, K_foreign_buffer_exports)
    if field == NONE:
        return get(w, expected + 32) == 0
    return equal_span(s, w, field, expected)

def matches_metadata(s:readbuf, w:mutbuf, record:u64, metadata:u64) -> bool:
    matched = 0
    field = 1
    while field <= META_COUNT:
        observed = lookup(w, metadata, field)
        if observed != NONE:
            if field_matches(s, w, record, field, observed) == False:
                return False
            matched = matched + 1
        field = field + 1
    if matched != get(w, metadata + 32):
        return False
    return lookup(w, metadata, K_candidate) != NONE and lookup(w, metadata, K_core_sha256) != NONE and lookup(w, metadata, K_context) != NONE and lookup(w, metadata, K_installation) != NONE and lookup(w, metadata, K_signatures) != NONE

def exact_reference(s:readbuf, w:mutbuf, node:u64) -> bool:
    if node == NONE or get(w, node) != 6 or get(w, node + 64) != 176:
        return False
    return artifact_reference(s, get(w, node + 56))

def field_matches(s:readbuf, w:mutbuf, node:u64, key:u64, value:u64) -> bool:
    found = lookup(w, node, key)
    if value == NONE or found == NONE or get(w, found) != get(w, value):
        return False
    kind = get(w, found)
    if kind < 3:
        return True
    if kind == 3:
        size = get(w, found + 32)
        if size != get(w, value + 32):
            return False
        return matches(s, get(w, found + 24), get(w, value + 24), size)
    return equal_span(s, w, found, value)

def next(w:mutbuf, node:u64) -> u64:
    return 64 + get(w, node + 16) * 72

def answer(o:mutbuf, status:u64) -> u64:
    put(o, 0, RESPONSE)
    put(o, 8, status)
    return 16
'''


def program():
    tags = {f'K_{name}': ordinal for ordinal, name in enumerate(KEYS, 1)}
    tags.update(META_COUNT=len(METADATA), INVALID=4294967293, NONE=(1 << 64) - 1,
                RESPONSE=int.from_bytes(b'HIABCO01', 'little'), LOOKUP=int.from_bytes(b'HIABCP01', 'little'))
    custody = authority()
    return '\n'.join((
        re.sub(r'\b(' + '|'.join(tags) + r')\b', lambda match: str(tags[match[0]]), POLICY),
        WIRE_HELPERS.split('\ndef signed_id', 1)[0].replace('NONE', str(tags['NONE'])),
        split_key_table(KEYS[:16], KEYS[16:]),
        literal_match('build_schema', 'hepta.hia.agent.build.v1'),
        literal_match('object_schema', 'hepta.hia.agent.build-object.v1'),
        literal_match('object_kind', 'object'),
        literal_match('shared_kind', 'shared'),
        literal_match('canonical_kind', 'canonical'),
        literal_match('explicit_kind', 'agent_plan'),
        *(function(CONTEXT, name).replace('NONE', str(tags['NONE']))
          for name in ('digest_text', 'equal_span')),
        *(function(custody, name) for name in ('artifact_reference', 'artifact_start', 'artifact_digest',
                                               'artifact_uri', 'valid_hex', 'matches')),
        json_decoder(wire_spans=True),
    ))


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)), encoding='utf-8')
