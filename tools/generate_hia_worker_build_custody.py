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
        'native_build', 'schema', 'sha256', 'target_profile')

POLICY = r'''
# Protected input:
# [installation, separately pinned packed producer or null, active Context,
# active backend, active target, native ref, retained build receipt,
# retained native metadata, retained object metadata,
# [verified Core digest, checked input digest, candidate ABI, Context exports,
#  exact object digest, exact image digest, image length, object_bytes == image_bytes]].
# No field in a retained receipt supplies an installation binding or physical fact.
def build_custody(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 32 or length(s) > 8388608 or length(o) < 64 or length(w) < 65536:
        return INVALID
    put(o, 48, 262144)
    put(o, 56, 128)
    if widen(decode_json(s, w, o)) >= 4294967292 or get(w, 64) != 5 or get(w, 96) != 10:
        return INVALID
    install = 64 + get(w, 88) * 72
    packed = next(w, install)
    context = next(w, packed)
    backend = next(w, context)
    target = next(w, backend)
    native = next(w, target)
    record = next(w, native)
    metadata = next(w, record)
    object_info = next(w, metadata)
    facts = next(w, object_info)
    if get(w, install) != 6 or get(w, context) != 6 or get(w, backend) != 6 or get(w, target) != 6:
        return INVALID
    if get(w, record) != 6 or build_schema(w, lookup(w, record, K_schema)) == False:
        return INVALID
    if get(w, metadata) != 6 or get(w, object_info) != 6 or get(w, facts) != 5 or get(w, facts + 32) != 8:
        return INVALID
    if exact_reference(s, w, native) == False:
        return INVALID
    if field_matches(s, w, record, K_installation, install) == False or field_matches(s, w, record, K_context, context) == False:
        return answer(o, 1)
    if field_matches(s, w, record, K_native_artifact, native) == False or field_matches(s, w, record, K_backend_profile, backend) == False or field_matches(s, w, record, K_target_profile, target) == False:
        return answer(o, 1)
    if matches_metadata(s, w, record, metadata) == False:
        return answer(o, 2)
    return bind_products(s, w, o, install, packed, record, object_info, facts)

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
    return value != NONE and found != NONE and equal_span(s, w, found, value)

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
                RESPONSE=int.from_bytes(b'HIABCO01', 'little'))
    custody = authority()
    return '\n'.join((
        re.sub(r'\b(' + '|'.join(tags) + r')\b', lambda match: str(tags[match[0]]), POLICY),
        WIRE_HELPERS.split('\ndef signed_id', 1)[0].replace('NONE', str(tags['NONE'])),
        split_key_table(KEYS[:16], KEYS[16:]),
        literal_match('build_schema', 'hepta.hia.agent.build.v1'),
        literal_match('object_schema', 'hepta.hia.agent.build-object.v1'),
        literal_match('object_kind', 'object'),
        literal_match('shared_kind', 'shared'),
        *(function(CONTEXT, name).replace('NONE', str(tags['NONE']))
          for name in ('digest_text', 'equal_span')),
        *(function(custody, name) for name in ('artifact_reference', 'artifact_start', 'artifact_digest',
                                               'artifact_uri', 'valid_hex')),
        json_decoder(wire_spans=True),
    ))


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)), encoding='utf-8')
