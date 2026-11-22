"""Author the typed publication and exact readback of native Verify products."""

from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_worker_adopt_proof import reachable_policy
from tools.generate_hia_worker_context_flow import flow_source, function
from tools.generate_hia_worker_emit_measurement import MEASUREMENT, splice_list
from tools.generate_hia_worker_emit_publication import PUBLICATION
from tools.generate_hia_worker_emit_record import RECORD
from tools.generate_hia_worker_verify_flow import recipe as front_recipe

SOURCE = Path('examples/hia_bootstrap/worker_verify_publication_flow.hepta')

ENTRY = r'''
def verify_publication_flow(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) != EMIT_WORK_BYTES or length(o) != 2048:
        return BAD
    state = get(w, 0)
    if state == VERIFY_FINDINGS_START:
        if (get(w, VERIFY_CLAIM_COUNT) < 1 or get(w, VERIFY_CLAIM_COUNT) > 4
                or get(w, VERIFY_CLAIM_INDEX) != get(w, VERIFY_CLAIM_COUNT)):
            return BAD
        return inspection_hash(o, w, VERIFY_HASH_NOMINAL, VERIFY_NOMINAL_IMAGE)
    if (length(s) < 64 or input_word(s, 0) != OBSERVATION or input_word(s, 8) != get(w, 8)
            or input_word(s, 16) != get(w, 16) or input_word(s, 24) != 0):
        return BAD
    operation = get(w, 16)
    start = input_word(s, 48)
    size = input_word(s, 40)
    capture = input_word(s, 56)
    if size > 67112960 or start > size or capture > size - start or capture != length(s) - 64:
        return BAD
    if operation == READ and (input_word(s, 32) != get(w, 80) or start != get(w, 88) or capture != get(w, 96)):
        return BAD
    if ((operation == RUN or operation == MAKE) and
            (start != 0 or valid_fd(input_word(s, 32)) == False)):
        return BAD
    if state == INSPECTION_HASH_RETURNED:
        if size < 88 or size > 105:
            return BAD
        return read_span(o, w, INSPECTION_HASH_FRAME, input_word(s, 32), 0, size)
    if state == INSPECTION_HASH_FRAME:
        return inspection_hash_result(s, o, w)
    if state >= PEER_STARTED and state <= PEER_CLOSED:
        return observe_store(s, o, w, state)
    if state >= EMIT_PUB_QUERY and state <= EMIT_PUB_COMPARE:
        return emit_publication_state(s, o, w, state)
    return verify_publication_reply(s, o, w, state)
'''

DOCUMENTS = r'''
def inspection_hash_bound(s:readbuf, o:mutbuf, w:mutbuf, at:u64) -> u64:
    resume = get(w, INSPECTION_HASH_RESUME)
    fd = input_word(s, 32)
    if resume == VERIFY_HASH_NOMINAL:
        hold(w, VERIFY_NOMINAL_PIN, fd, at - 65, 66)
        return inspection_hash(o, w, VERIFY_HASH_OBSERVER, VERIFY_OBSERVER_IMAGE)
    if resume == VERIFY_HASH_OBSERVER:
        hold(w, VERIFY_OBSERVER_PIN, fd, at - 65, 66)
        put(o, HEADER, 32123)
        return action(o, w, VERIFY_EMPTY_METADATA, MAKE, 0, 0, 0, 2)
    return emit_publication_hash(s, o, w, at, resume)

def verify_observation_header(o:mutbuf, w:mutbuf) -> u64:
    index = get(w, VERIFY_PUBLISH_INDEX)
    if index >= get(w, VERIFY_CLAIM_COUNT):
        return BAD
    slot = VERIFY_EVIDENCE_SPANS + index * 24
    size = get(w, slot + 16)
    if size < 34 or size > 4088:
        return BAD
    return read_span(o, w, VERIFY_EVIDENCE_HEADER, get(w, slot), get(w, slot + 8), 32)

def verify_finding_packet(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    index = get(w, VERIFY_PUBLISH_INDEX)
    slot = VERIFY_EVIDENCE_SPANS + index * 24
    status = input_word(s, 72)
    mode = input_word(s, 80)
    if (length(s) != 96 or input_word(s, 64) != VERIFY_FINITE_REPORT or mode < 1 or mode > 9
            or status < 1 or status > 4 or input_word(s, 88) != get(w, slot + 16) - 32):
        return BAD
    claim = get(w, VERIFY_CLAIM_ORDINALS + 8 * index)
    if claim != choose(mode == 7, 1, choose(mode == 8, 3, 2)):
        return BAD
    hold(w, VERIFY_FACTS, get(w, slot), get(w, slot + 8) + 32, get(w, slot + 16) - 32)
    store(o, HEADER, 91)
    store(o, HEADER + 1, mode + 48)
    store(o, HEADER + 2, 44)
    store(o, HEADER + 3, status + 48)
    store(o, HEADER + 4, 44)
    store(o, 384, 44)
    store(o, 392, 93)
    vector_span(w, o, VERIFY_SCOPE, HEADER + 5)
    vector_part(o, HEADER + 29, INLINE_FRAGMENT, 384, 1)
    vector_span(w, o, VERIFY_VALIDATION, HEADER + 53)
    vector_part(o, HEADER + 77, INLINE_FRAGMENT, 384, 1)
    vector_span(w, o, EMIT_INSTALLATION, HEADER + 101)
    vector_part(o, HEADER + 125, INLINE_FRAGMENT, 384, 1)
    vector_span(w, o, EMIT_PROOF_TRUST_SELECTION, HEADER + 149)
    vector_part(o, HEADER + 173, INLINE_FRAGMENT, 384, 1)
    vector_span(w, o, choose(mode == 7, VERIFY_NOMINAL_PIN, VERIFY_OBSERVER_PIN), HEADER + 197)
    vector_part(o, HEADER + 221, INLINE_FRAGMENT, 392, 1)
    return wide_inspection(o, w, VERIFY_FINDING_BOUND, VERIFY_FINDING_ROLE, 0, 10, 5)

def verify_publication_reply(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    size = input_word(s, 40)
    fd = input_word(s, 32)
    if state == VERIFY_EMPTY_METADATA:
        if size != 2 or length(s) != 66 or byte(s, 64) != 123 or byte(s, 65) != 125:
            return BAD
        sample_span(s, w, EMIT_EMPTY_METADATA)
        return verify_observation_header(o, w)
    if state == VERIFY_EVIDENCE_HEADER:
        return verify_finding_packet(s, o, w)
    if state == VERIFY_FINDING_BOUND:
        if plan_ok(s) == False or size < 26 or input_word(s, 72) != VERIFY_FINDING_TAG or input_word(s, 80) != size - 24:
            return BAD
        hold(w, VERIFY_FINDING_DOC, fd, 24, size - 24)
        return verify_document_packet(o, w)
    if state == VERIFY_DOCUMENTS_BOUND:
        if plan_ok(s) == False or size < 36 or input_word(s, 72) != VERIFY_FILES_TAG:
            return BAD
        assumptions = input_word(s, 80)
        evidence = input_word(s, 88)
        if assumptions < 2 or assumptions > size - 34 or evidence != size - 32 - assumptions:
            return BAD
        hold(w, VERIFY_ASSUMPTIONS_DOC, fd, 32, assumptions)
        hold(w, VERIFY_EVIDENCE_DOC, fd, 32 + assumptions, evidence)
        return emit_publish(o, w, 16, VERIFY_ASSUMPTIONS_DOC, EMIT_EMPTY_METADATA)
    if state == VERIFY_CHECK_BOUND:
        if plan_ok(s) == False or size < 26 or input_word(s, 72) != VERIFY_CHECK_TAG or input_word(s, 80) != size - 24:
            return BAD
        index = get(w, VERIFY_PUBLISH_INDEX)
        hold(w, VERIFY_CHECKS + 24 * index, fd, 24, size - 24)
        put(w, VERIFY_PUBLISH_INDEX, index + 1)
        if index + 1 < get(w, VERIFY_CLAIM_COUNT):
            return verify_observation_header(o, w)
        return verify_list_checks(o, w)
    if state == VERIFY_CHECKS_BOUND:
        if size < 4:
            return BAD
        sample_span(s, w, VERIFY_CHECK_LIST)
        return verify_receipt_packet(o, w)
    if state == VERIFY_RECEIPT_BOUND:
        if plan_ok(s) == False or size < 10:
            return BAD
        body_span(s, w, VERIFY_RECEIPT_DOC)
        return emit_publish(o, w, 18, VERIFY_RECEIPT_DOC, EMIT_EMPTY_METADATA)
    if state == VERIFY_RESULT_BOUND:
        if plan_ok(s) == False or size < 10:
            return BAD
        body_span(s, w, VERIFY_RESULT)
        put(w, 0, VERIFY_RESULT_READY)
        return VERIFY_NEEDS_TERMINAL
    return BAD

def verify_list_checks(o:mutbuf, w:mutbuf) -> u64:
    store(o, HEADER, 91)
    store(o, 384, 44)
    store(o, 392, 93)
    count = get(w, VERIFY_PUBLISH_INDEX)
    index = 0
    while index < count:
        offset = HEADER + 1 + 48 * index
        vector_span(w, o, VERIFY_CHECKS + 24 * index, offset)
        vector_part(o, offset + 24, INLINE_FRAGMENT, choose(index + 1 == count, 392, 384), 1)
        index = index + 1
    return emit_wide_make(o, w, VERIFY_CHECKS_BOUND, count * 2, 1)

def verify_receipt_packet(o:mutbuf, w:mutbuf) -> u64:
    put(w, EMIT_RENDER_FIELDS, VERIFY_ORIGINAL_SHA)
    put(w, EMIT_RENDER_FIELDS + 8, VERIFY_BASE)
    put(w, EMIT_RENDER_FIELDS + 16, EMIT_FIELDS + 48)
    put(w, EMIT_RENDER_FIELDS + 24, VERIFY_CANDIDATE_SHA)
    put(w, EMIT_RENDER_FIELDS + 32, VERIFY_CHECK_LIST)
    put(w, EMIT_RENDER_FIELDS + 40, EMIT_FIELDS + 24)
    put(w, EMIT_RENDER_FIELDS + 48, EMIT_INSTALLATION)
    put(w, EMIT_RENDER_FIELDS + 56, VERIFY_SUBJECT)
    put(w, EMIT_RENDER_FIELDS + 64, VERIFY_VALIDATION)
    return emit_render_arguments(o, w, VERIFY_RECEIPT_REQUEST, VERIFY_RECEIPT_ROLE, 1, VERIFY_RECEIPT_BOUND, 9)

def verify_result_packet(o:mutbuf, w:mutbuf) -> u64:
    put(w, EMIT_RENDER_FIELDS, EMIT_FIELDS + 48)
    put(w, EMIT_RENDER_FIELDS + 8, VERIFY_CHECK_LIST)
    put(w, EMIT_RENDER_FIELDS + 16, VERIFY_SUBJECT)
    put(w, EMIT_RENDER_FIELDS + 24, EMIT_ARTIFACT_REFS + 48)
    return emit_render_arguments(o, w, VERIFY_RECEIPT_REQUEST, VERIFY_RECEIPT_ROLE, 2, VERIFY_RESULT_BOUND, 4)

def emit_publication_complete(o:mutbuf, w:mutbuf) -> u64:
    kind = get(w, EMIT_PUB_KIND)
    if kind == 16:
        return emit_publish(o, w, 17, VERIFY_EVIDENCE_DOC, EMIT_EMPTY_METADATA)
    if kind == 17:
        return verify_check_packet(o, w)
    if kind == 18:
        return verify_result_packet(o, w)
    return BAD
'''

STORE = r'''
def opened_store(o:mutbuf, w:mutbuf) -> u64:
    if get(w, STORE_PURPOSE) != EMIT_PUB_OPEN:
        return BAD
    return emit_query_key(o, w)

def closed_store(o:mutbuf, w:mutbuf) -> u64:
    if get(w, STORE_PURPOSE) != EMIT_PUB_CLOSE:
        return BAD
    copy_private(w, o, EMIT_PUB_CONTENT_HASH, 416, 64)
    store(o, 480, 0)
    return artifact_command(o, w, EMIT_PUB_REOPENED, STORE_GET, STORE_GET_END, 0)
'''


def recipe():
    constants, _, controls = front_recipe()
    states = ('HASH_NOMINAL', 'HASH_OBSERVER', 'EMPTY_METADATA', 'EVIDENCE_HEADER', 'FINDING_BOUND',
              'DOCUMENTS_BOUND', 'CHECK_BOUND', 'CHECKS_BOUND', 'RECEIPT_BOUND', 'RESULT_BOUND', 'RESULT_READY')
    constants.update({f'VERIFY_{name}': 1361 + index for index, name in enumerate(states)})
    spans = ('NOMINAL_PIN', 'OBSERVER_PIN', 'FACTS', 'FINDING_DOC', 'ASSUMPTIONS_DOC',
             'EVIDENCE_DOC', 'CHECK_LIST', 'RECEIPT_DOC', 'RESULT')
    constants.update({f'VERIFY_{name}': 11064 + 24 * index for index, name in enumerate(spans)})
    constants.update(VERIFY_PUBLISH_INDEX=11280, VERIFY_CHECKS=11288, VERIFY_FINDING_ROLE=74,
                     VERIFY_DOCUMENTS_ROLE=75, VERIFY_RECEIPT_ROLE=76, VERIFY_NEEDS_TERMINAL=0xffffffe1)
    constants.update({f'VERIFY_{name}': int.from_bytes(tag, 'little') for name, tag in {
        'FINDING_TAG': b'HIAVFN01', 'FILES_TAG': b'HIAVDF01', 'CHECK_TAG': b'HIAVDC01', 'RECEIPT_REQUEST': b'HIAVRC01',
    }.items()})
    control = '\n'.join(controls)
    bound = function(control, 'settle_transaction')
    bound = bound[:bound.index('    if purpose == EMIT_PUB_LOOKUP')] + (
        '    if purpose != EMIT_PUB_LOOKUP and purpose != EMIT_PUB_INSERT:\n'
        '        return BAD\n'
        '    return emit_publication_store(s, o, w, STORE_SETTLED)\n'
    )
    control = '\n'.join(part for part in controls
                        if part.split('(', 1)[0].strip() not in (
                            'def opened_store', 'def closed_store', 'def settle_transaction',
                            'def inspection_hash_bound',
                        ))
    publication = PUBLICATION[:PUBLICATION.index('\ndef emit_publication_complete(')]
    publication = publication.replace('kind < 12 or kind > 14', 'kind < 16 or kind > 18')
    publication = publication.replace(
        '        if emit_authorized_digest(w, EMIT_PUBLIC_AUTHORITY) == False:\n            return BAD\n', '')
    publication = publication.replace(
        '    use_span(w, o, EMIT_PUB_METADATA, 0)\n'
        '    if insert:\n'
        '        fragment(o, 1, INLINE_FRAGMENT, 416, 32)\n'
        '        return action(o, w, EMIT_PUB_ISSUED, RUN, DOCUMENT_PLAN_ROLE, 0, 2, 80)\n'
        '    return action(o, w, EMIT_PUB_QUERY, RUN, DOCUMENT_PLAN_ROLE, 0, 1, 80)',
        '    if insert:\n'
        '        fragment(o, 0, INLINE_FRAGMENT, 416, 32)\n'
        '        return action(o, w, EMIT_PUB_ISSUED, RUN, DOCUMENT_PLAN_ROLE, 0, 1, 80)\n'
        '    return action(o, w, EMIT_PUB_QUERY, RUN, DOCUMENT_PLAN_ROLE, 0, 0, 80)',
    )
    publication = publication.replace('(kind - 12)', '(kind - 16)')
    document_packet = splice_list('verify_document_packet', 'VERIFY_DOCUMENTS_BOUND',
                                  ('VERIFY_FINDING_DOC', 'VERIFY_FACTS'), role='VERIFY_DOCUMENTS_ROLE')
    check_packet = splice_list('verify_check_packet', 'VERIFY_CHECK_BOUND',
                               ('VERIFY_FINDING_DOC', 'EMIT_ARTIFACT_REFS', 'EMIT_ARTIFACT_REFS + 24'),
                               role='VERIFY_DOCUMENTS_ROLE')
    entry, functions = reachable_policy('\n'.join((
        ENTRY, DOCUMENTS, STORE, bound, control, publication, document_packet, check_packet,
        function(MEASUREMENT, 'emit_wide_make'), function(RECORD, 'emit_render_arguments'),
    )), 'verify_publication_flow')
    return constants, entry, functions


def program():
    constants, entry, functions = recipe()
    return flow_source(entry, functions, constants)


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)), encoding='utf-8')
