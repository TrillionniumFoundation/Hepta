"""Adopt slot decisions and writes on the Worker's one exclusive Store peer."""

from tools.generate_hia_worker_context_flow import function
from tools.generate_hia_worker_rollback_flow import PUBLICATION, ROWS

SLOT = r'''
def adopt_open_slot(o:mutbuf, w:mutbuf) -> u64:
    slot = ADOPT_INTAKE_FIELDS
    width = get(w, slot + 16)
    if width < 3 or width > 194:
        return BAD
    hold(w, ROLLBACK_NAME, get(w, slot), get(w, slot + 8) + 1, width - 2)
    return open_store(o, w, ADOPT_SLOT_OPEN)

def adopt_slot_state(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    if state == ADOPT_SLOT_OPENED:
        put(w, ADOPT_SLOT_ACTIVE, 1)
        return rollback_query(o, w, 1, 0, ROLLBACK_SLOT)
    if state == ADOPT_SLOT_CLOSED:
        put(w, ADOPT_SLOT_ACTIVE, 0)
        return rollback_snapshot(o, w)
    if state == ADOPT_SLOT_SETTLED:
        return adopt_slot_settled(s, o, w)
    if (state >= RB_STALE_EMPTY and state <= RB_ERROR_RENDERED) or (state >= RB_DOC_PARAMETERS and state <= RB_RESULT_JSON):
        return adopt_slot_document(s, o, w, state)
    if state >= ROLLBACK_ROW_PLAN and state <= ROLLBACK_PREVIOUS:
        return adopt_slot_row(s, o, w, state)
    if state == ADOPT_LIVE_ABI:
        if rollback_binding(s) == False:
            return BAD
        if input_word(s, 80) == 0:
            return adopt_locked_error(o, w, 17)
        return adopt_image(o, w, 3, ROLLBACK_ACTIVE_REF)
    if state == ADOPT_SLOT_FOLD:
        if length(s) != 88 or input_word(s, 64) != ADOPT_FOLD_TAG:
            return BAD
        put(w, ADOPT_SLOT_MAXIMUM, input_word(s, 72))
        put(w, ADOPT_SLOT_COUNT, input_word(s, 80))
        return adopt_slot_decide(o, w)
    if state == ADOPT_LIVE_BASELINE:
        if rollback_binding(s) == False:
            return BAD
        if input_word(s, 80) == 0:
            return adopt_locked_error(o, w, 18)
        return rollback_query(o, w, 4, 0, ADOPT_SLOT_FOLD)
    return adopt_slot_write(s, o, w, state)

def adopt_slot_row(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    size = input_word(s, 40)
    fd = input_word(s, 32)
    if state == ROLLBACK_ROW_PLAN:
        if plan_ok(s) == False or size < 64 or size > 320:
            return BAD
        kind = get(w, ROLLBACK_ROW_KIND)
        return store_transaction(o, w, ADOPT_SLOT_READ, choose(kind == 4, 33, 27 + kind), 0, fd, 8, size - 8)
    if state == ROLLBACK_SLOT or state == ROLLBACK_ACTIVE:
        if plan_ok(s) == False or input_word(s, 72) != ROLLBACK_BOUND_ROW:
            return BAD
        present = input_word(s, 80)
        if state == ROLLBACK_ACTIVE:
            if size != 200 or present != 1:
                return BAD
            hold(w, ROLLBACK_ACTIVE_REF, fd, 24, 176)
            return rollback_query(o, w, 3, 0, ROLLBACK_LEASES)
        if size != 24 and size != 140:
            return BAD
        if present != choose(size == 140, 1, 0):
            return BAD
        put(w, ROLLBACK_PRESENT, present)
        if present == 0:
            return rollback_conditional(o, w)
        put(w, ROLLBACK_SLOT_GENERATION, input_word(s, 88))
        put(w, ROLLBACK_SLOT_EPOCH, input_word(s, 96))
        hold(w, ROLLBACK_SLOT_CONTEXT, fd, 40, 36)
        hold(w, ROLLBACK_SLOT_ABI, fd, 76, 64)
        return rollback_query(o, w, 2, get(w, ROLLBACK_SLOT_GENERATION), ROLLBACK_ACTIVE)
    if state == ROLLBACK_LEASES:
        if plan_ok(s) == False or size != 24 or input_word(s, 72) != ROLLBACK_LEASE_COUNT:
            return BAD
        put(w, ROLLBACK_COUNT, input_word(s, 80))
        return rollback_conditional(o, w)
    if state == ROLLBACK_CONDITIONAL:
        if rollback_answer(s) == False:
            return BAD
        status = input_word(s, 80)
        if status != choose(get(w, ROLLBACK_PRESENT) == 0, 5, 0) and status != 4:
            return BAD
        put(w, ROLLBACK_STATUS, status)
        return rollback_format_generation(o, w, ROLLBACK_PREVIOUS, get(w, ROLLBACK_SLOT_GENERATION), get(w, ROLLBACK_SLOT_EPOCH))
    if state == ROLLBACK_PREVIOUS:
        if plan_ok(s) == False or size < 16 or size > 128:
            return BAD
        body_span(s, w, ROLLBACK_PREVIOUS_VIEW)
        if get(w, ROLLBACK_STATUS) == 4:
            return close_store(o, w, ADOPT_SLOT_STALE)
        if get(w, ROLLBACK_PRESENT) == 0:
            return adopt_slot_decide(o, w)
        return rollback_compare(o, w, ADOPT_LIVE_ABI, ROLLBACK_SLOT_ABI, ADOPT_CANDIDATE_ABI)
    return BAD

def adopt_slot_decide(o:mutbuf, w:mutbuf) -> u64:
    put(o, HEADER, ADOPT_SLOT_PLAN)
    put(o, HEADER + 8, get(w, ROLLBACK_PRESENT))
    put(o, HEADER + 16, get(w, ADOPT_EXPECT_GENERATION))
    put(o, HEADER + 24, get(w, ADOPT_EXPECT_EPOCH))
    put(o, HEADER + 32, get(w, ROLLBACK_SLOT_GENERATION))
    put(o, HEADER + 40, get(w, ROLLBACK_SLOT_EPOCH))
    put(o, HEADER + 48, get(w, ADOPT_SLOT_MAXIMUM))
    put(o, HEADER + 56, get(w, ADOPT_SLOT_COUNT))
    if get(w, ROLLBACK_PRESENT) == 0:
        return action(o, w, ADOPT_SLOT_ADVANCE, RUN, ADOPT_AUTHORITY_ROLE, 0, 0, 64)
    vector_span(w, o, ROLLBACK_SLOT_ABI, HEADER + 64)
    vector_span(w, o, ADOPT_CANDIDATE_ABI, HEADER + 88)
    vector_span(w, o, ADOPT_LIVE_SHA, HEADER + 112)
    baseline = ADOPT_EVAL_FIELDS + 96
    if get(w, baseline + 16) != 176:
        return BAD
    vector_part(o, HEADER + 136, get(w, baseline), get(w, baseline + 8) + ARTIFACT_SHA_OFFSET, 64)
    return wide_inspection(o, w, ADOPT_SLOT_ADVANCE, ADOPT_AUTHORITY_ROLE, 0, 4, 64)

def adopt_locked_error(o:mutbuf, w:mutbuf, code:u64) -> u64:
    put(w, ADOPT_CUSTODY_ERROR, code)
    return close_store(o, w, ADOPT_SLOT_FAILED)

def adopt_slot_settled(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    purpose = get(w, STORE_PURPOSE)
    bytes = input_word(s, 72)
    found = input_word(s, 80)
    if purpose == ADOPT_SLOT_READ:
        if get(w, ROLLBACK_ROW_KIND) != 4:
            return rollback_row_observed(o, w, bytes)
        if bytes != 24 or found != 1:
            return BAD
        return read_span(o, w, ADOPT_SLOT_FOLD, slot_fd(w, STORE_RESULT), 0, bytes)
    if purpose == ADOPT_SLOT_READ_DOCUMENT:
        return rollback_doc_observe(o, w, bytes)
    return adopt_write_settled(s, o, w, purpose, bytes, found)

def adopt_slot_write(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    size = input_word(s, 40)
    fd = input_word(s, 32)
    if state == ADOPT_SLOT_PARAMETERS:
        if plan_ok(s) == False or size < 120 or size > 560:
            return BAD
        purpose = get(w, ADOPT_WRITE_PURPOSE)
        plan = choose(purpose == ADOPT_SLOT_CREATE, 34, choose(purpose == ADOPT_SLOT_MOVE, 31, 35))
        return store_transaction(o, w, purpose, plan, 0, fd, 8, size - 8)
    if state == ADOPT_SLOT_UPDATED:
        if plan_ok(s) == False or size < 16 or size > 128:
            return BAD
        body_span(s, w, ADOPT_UPDATED_VIEW)
        return adopt_record(o, w)
    if state == ADOPT_SLOT_COMMITTED:
        if length(s) != 72 or input_word(s, 64) != RB_COMMITTED_TAG:
            return BAD
        return close_store(o, w, ADOPT_SLOT_CLOSE_COMMIT)
    if state != ADOPT_SLOT_ADVANCE or plan_ok(s) == False:
        return BAD
    if input_word(s, 72) == ADOPT_EVAL_TAG and input_word(s, 40) == 24 and input_word(s, 80) == 7:
        return adopt_locked_error(o, w, 19)
    if input_word(s, 72) != ADOPT_ADVANCE_TAG or input_word(s, 40) != 32:
        return BAD
    put(w, ADOPT_NEXT_GENERATION, input_word(s, 80))
    put(w, ADOPT_NEXT_EPOCH, input_word(s, 88))
    if get(w, ROLLBACK_PRESENT) == 0:
        return adopt_create_slot(o, w)
    return adopt_version(o, w, ADOPT_SLOT_CANDIDATE, get(w, ADOPT_NEXT_GENERATION), ADOPT_CLAIM_FIELDS + 24)

def adopt_create_slot(o:mutbuf, w:mutbuf) -> u64:
    put(w, ADOPT_WRITE_PURPOSE, ADOPT_SLOT_CREATE)
    put(o, HEADER, ADOPT_WRITE_TAG)
    put(o, HEADER + 8, 7)
    put(o, HEADER + 16, get(w, ROLLBACK_NAME + 16))
    put(o, HEADER + 24, 0)
    use_span(w, o, ROLLBACK_NAME, 0)
    use_span(w, o, ADOPT_CONTEXT_ID, 1)
    use_span(w, o, ADOPT_CANDIDATE_ABI, 2)
    return action(o, w, ADOPT_SLOT_PARAMETERS, RUN, ADOPT_AUTHORITY_ROLE, 0, 3, 32)

def adopt_version(o:mutbuf, w:mutbuf, purpose:u64, generation:u64, reference:u64) -> u64:
    put(w, ADOPT_WRITE_PURPOSE, purpose)
    put(o, HEADER, ADOPT_WRITE_TAG)
    put(o, HEADER + 8, 8)
    put(o, HEADER + 16, get(w, ROLLBACK_NAME + 16))
    put(o, HEADER + 24, generation)
    use_span(w, o, ROLLBACK_NAME, 0)
    use_span(w, o, reference, 1)
    return action(o, w, ADOPT_SLOT_PARAMETERS, RUN, ADOPT_AUTHORITY_ROLE, 0, 2, 32)

def adopt_move_slot(o:mutbuf, w:mutbuf) -> u64:
    put(w, ADOPT_WRITE_PURPOSE, ADOPT_SLOT_MOVE)
    put(o, HEADER, ROLLBACK_QUERY)
    put(o, HEADER + 8, 3)
    put(o, HEADER + 16, get(w, ADOPT_NEXT_GENERATION))
    put(o, HEADER + 24, get(w, ADOPT_NEXT_EPOCH))
    put(o, HEADER + 32, get(w, ROLLBACK_NAME + 16))
    use_span(w, o, ADOPT_CONTEXT_ID, 0)
    use_span(w, o, ROLLBACK_NAME, 1)
    return action(o, w, ADOPT_SLOT_PARAMETERS, RUN, ADOPT_SLOT_ROLE, 0, 2, 40)

def adopt_write_settled(s:readbuf, o:mutbuf, w:mutbuf, purpose:u64, bytes:u64, found:u64) -> u64:
    count = get(w, ADOPT_WRITE_COUNT)
    if purpose == ADOPT_SLOT_COMMIT:
        if bytes != 8 or found != count or count < 3 or count > 6:
            return BAD
        return read_span(o, w, ADOPT_SLOT_COMMITTED, slot_fd(w, STORE_RESULT), 0, 8)
    if bytes != 0 or found != 1 or count >= 6:
        return BAD
    copy_span(s, w, 64, ADOPT_WRITE_RECEIPTS + 48 * count, 48)
    put(w, ADOPT_WRITE_COUNT, count + 1)
    if purpose == ADOPT_SLOT_CREATE and count == 0:
        return adopt_version(o, w, ADOPT_SLOT_BASELINE, 0, ADOPT_EVAL_FIELDS + 96)
    if purpose == ADOPT_SLOT_BASELINE and count == 1:
        return adopt_version(o, w, ADOPT_SLOT_CANDIDATE, get(w, ADOPT_NEXT_GENERATION), ADOPT_CLAIM_FIELDS + 24)
    prior = 2 * (1 - get(w, ROLLBACK_PRESENT))
    if purpose == ADOPT_SLOT_CANDIDATE and count == prior:
        return adopt_move_slot(o, w)
    if purpose == ADOPT_SLOT_MOVE and count == prior + 1:
        return rollback_format_generation(o, w, ADOPT_SLOT_UPDATED, get(w, ADOPT_NEXT_GENERATION), get(w, ADOPT_NEXT_EPOCH))
    if purpose == ADOPT_SLOT_DOCUMENT and count == prior + 2:
        return adopt_result(o, w)
    if purpose == ADOPT_SLOT_TERMINAL and (count == prior + 2 or count == prior + 3):
        put(o, HEADER + 48, ADOPT_COMMIT_TAG)
        put(o, HEADER + 56, count + 1)
        copy_private(w, o, ADOPT_WRITE_RECEIPTS, HEADER + 64, 48 * (count + 1))
        return store_transaction(o, w, ADOPT_SLOT_COMMIT, 36, 0, 0, 0, 16 + 48 * (count + 1))
    return BAD

def adopt_record(o:mutbuf, w:mutbuf) -> u64:
    move_fragment(w, ADOPT_CLAIM_FIELDS + 24, RB_FIELDS)
    move_fragment(w, EMIT_FIELDS + 24, RB_FIELDS + 24)
    move_fragment(w, ADOPT_UPDATED_VIEW, RB_FIELDS + 48)
    move_fragment(w, ADOPT_EVALUATION_REF, RB_FIELDS + 72)
    move_fragment(w, ROLLBACK_PREVIOUS_VIEW, RB_FIELDS + 96)
    move_fragment(w, ADOPT_EVAL_FIELDS + 96, RB_FIELDS + 120)
    move_fragment(w, ADOPT_INTAKE_FIELDS, RB_FIELDS + 144)
    move_fragment(w, ADOPT_INTAKE_FIELDS + 96, RB_FIELDS + 168)
    return adopt_receipt_json(o, w, 1, RB_FIELDS, 8, RB_RECORD_JSON)

def adopt_result(o:mutbuf, w:mutbuf) -> u64:
    move_fragment(w, ADOPT_CLAIM_FIELDS + 24, RB_FIELDS)
    move_fragment(w, RB_DOCUMENT_RECEIPT, RB_FIELDS + 24)
    move_fragment(w, ADOPT_UPDATED_VIEW, RB_FIELDS + 48)
    move_fragment(w, ROLLBACK_PREVIOUS_VIEW, RB_FIELDS + 72)
    move_fragment(w, ADOPT_INTAKE_FIELDS, RB_FIELDS + 96)
    return adopt_receipt_json(o, w, 2, RB_FIELDS, 5, RB_RESULT_JSON)

def adopt_slot_document(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    size = input_word(s, 40)
    fd = input_word(s, 32)
    if state == RB_STALE_EMPTY:
        if size != 5:
            return BAD
        hold(w, ROLLBACK_SLOT_CONTEXT, fd, 0, 4)
        hold(w, ROLLBACK_ACTIVE_REF, fd, 0, 4)
        hold(w, RB_COUNT_TEXT, fd, 4, 1)
        return rollback_stale_json(o, w)
    if state == RB_STALE_COUNT:
        if plan_ok(s) == False or size < 17 or size > 36 or input_word(s, 72) != ROLLBACK_FORMAT_COUNT:
            return BAD
        hold(w, RB_COUNT_TEXT, fd, 16, size - 16)
        return read_span(o, w, RB_STALE_CONTEXT_BYTES, get(w, ROLLBACK_SLOT_CONTEXT), get(w, ROLLBACK_SLOT_CONTEXT + 8), 36)
    if state == RB_STALE_CONTEXT_BYTES:
        if size != 36:
            return BAD
        store(o, HEADER, 34)
        copy_span(s, o, 64, HEADER + 1, 36)
        store(o, HEADER + 37, 34)
        return action(o, w, RB_STALE_CONTEXT_JSON, MAKE, 0, 0, 0, 38)
    if state == RB_STALE_CONTEXT_JSON:
        if size != 38:
            return BAD
        sample_span(s, w, ROLLBACK_SLOT_CONTEXT)
        return rollback_stale_json(o, w)
    if state == RB_STALE_JSON:
        if plan_ok(s) == False or size < 10:
            return BAD
        return rollback_publish_stale(o, w, fd, size)
    if state == RB_STALE_PUBLISHED:
        if size != 200 or input_word(s, 64) != RB_DOCUMENT_RECEIPT_TAG:
            return BAD
        sample_span(s, w, RB_DOCUMENT_RECEIPT)
        return rollback_render_error(o, w, 4, RB_DOCUMENT_RECEIPT)
    if state == RB_ERROR_RENDERED and plan_ok(s) and size >= 10:
        body_span(s, w, EMIT_PUBLIC_ERROR)
        put(w, 0, ADOPT_SLOT_ERROR_READY)
        return ADOPT_DEFER_FRONT
    if state == RB_RECORD_JSON:
        if plan_ok(s) == False or size < 10:
            return BAD
        body_span(s, w, RB_DOCUMENT_BYTES)
        put(w, ADOPT_CUSTODY_ACTIVE, 1)
        return inspection_hash(o, w, RB_DOCUMENT_HASH, RB_DOCUMENT_BYTES)
    if state == RB_RESULT_JSON:
        if plan_ok(s) == False or size < 10:
            return BAD
        body_span(s, w, EMIT_PUBLIC_ERROR)
        put(w, 0, ADOPT_SLOT_RESULT_READY)
        return ADOPT_DEFER_FRONT
    return adopt_document_io(s, o, w, state)
'''


def slot_constants(c):
    c.update(ADOPT_SLOT_ROLE=c['ADOPT_AUTHORITY_ROLE'] + 1, ADOPT_SLOT_ACTIVE=10648,
             ADOPT_SLOT_MAXIMUM=10656, ADOPT_SLOT_COUNT=10664, ADOPT_NEXT_GENERATION=10672,
             ADOPT_NEXT_EPOCH=10680, ROLLBACK_ROW_KIND=10688, ROLLBACK_ROW_GENERATION=10696,
             ROLLBACK_ROW_RESUME=10704, ROLLBACK_PRESENT=10712, ROLLBACK_SLOT_GENERATION=10720,
             ROLLBACK_SLOT_EPOCH=10728, ROLLBACK_COUNT=10736, ROLLBACK_STATUS=10744,
             ADOPT_LIVE_SHA=10752, ROLLBACK_NAME=10776, ROLLBACK_ACTIVE_REF=10800,
             ROLLBACK_SLOT_CONTEXT=10824, ROLLBACK_SLOT_ABI=10848, ROLLBACK_PREVIOUS_VIEW=10872,
             RB_COUNT_TEXT=10896, RB_FIELDS=10920, RB_DOCUMENT_RECEIPT=11112, ADOPT_UPDATED_VIEW=11136,
             ADOPT_WRITE_PURPOSE=11160, ADOPT_WRITE_COUNT=11168, ADOPT_SLOT_DURABLE=11176,
             ADOPT_WRITE_RECEIPTS=11184, RB_DOC_HASH=11472, RB_DOC_KEY=11536, RB_DOCUMENT_BYTES=11560,
             RANDOM=10, ADOPT_DOCUMENT_KIND=15,
             ROLLBACK_EXPECT_GENERATION=c['ADOPT_EXPECT_GENERATION'],
             ROLLBACK_EXPECT_EPOCH=c['ADOPT_EXPECT_EPOCH'], ROLLBACK_FIELDS=c['ADOPT_INTAKE_FIELDS'] - 24)
    names = (
        'ADOPT_SLOT_OPENED', 'ADOPT_SLOT_CLOSED', 'ADOPT_SLOT_SETTLED', 'ROLLBACK_ROW_PLAN',
        'ROLLBACK_SLOT', 'ROLLBACK_ACTIVE', 'ROLLBACK_LEASES', 'ROLLBACK_CONDITIONAL', 'ROLLBACK_PREVIOUS',
        'ADOPT_LIVE_ABI', 'ADOPT_LIVE_BASELINE', 'ADOPT_SLOT_FOLD', 'ADOPT_SLOT_ADVANCE',
        'RB_STALE_EMPTY', 'RB_STALE_COUNT', 'RB_STALE_CONTEXT_BYTES', 'RB_STALE_CONTEXT_JSON',
        'RB_STALE_JSON', 'RB_STALE_PUBLISHED', 'RB_ERROR_RENDERED',
        'ADOPT_SLOT_PARAMETERS', 'ADOPT_SLOT_UPDATED', 'ADOPT_SLOT_COMMITTED',
        'RB_DOC_PARAMETERS', 'RB_DOC_OBSERVED', 'RB_DOC_REUSED', 'RB_DOC_STORED', 'RB_DOC_NONCE',
        'RB_DOC_ISSUED', 'RB_RECORD_JSON', 'RB_RESULT_JSON',
    )
    c.update({name: 1210 + i for i, name in enumerate(names)})
    c.update(ADOPT_SLOT_ERROR_READY=1248, ADOPT_LIVE_CONTEXT=1249, ADOPT_LIVE_HASH=1250,
             RB_DOCUMENT_HASH=1251, ADOPT_SLOT_RESULT_READY=1252, ADOPT_SLOT_RENDER_ERROR=1253,
             ARTIFACT_SHA_OFFSET=53)
    purposes = ('ADOPT_SLOT_OPEN', 'ADOPT_SLOT_STALE', 'ADOPT_SLOT_FAILED', 'ADOPT_SLOT_CLOSE_COMMIT',
                'ADOPT_SLOT_READ', 'ADOPT_SLOT_CREATE', 'ADOPT_SLOT_BASELINE', 'ADOPT_SLOT_CANDIDATE',
                'ADOPT_SLOT_MOVE', 'ADOPT_SLOT_READ_DOCUMENT', 'ADOPT_SLOT_DOCUMENT', 'ADOPT_SLOT_TERMINAL',
                'ADOPT_SLOT_COMMIT')
    for i, name in enumerate(purposes, 96):
        c[name] = i
    words = {
        'ROLLBACK_DECISION': b'HIARLD01', 'ROLLBACK_ANSWER': b'HIARLA01',
        'ROLLBACK_QUERY': b'HIARLS01', 'ROLLBACK_OBSERVE': b'HIARLO01', 'ROLLBACK_BOUND_ROW': b'HIARLB01',
        'ROLLBACK_LEASE_COUNT': b'HIASTLC1', 'ROLLBACK_FORMAT_GENERATION': b'HIARLF01',
        'ROLLBACK_FORMAT_COUNT': b'HIARLN01', 'ROLLBACK_RECORD': b'HIARLR01',
        'ROLLBACK_PUBLIC_ERROR': b'HIARLE01', 'RB_DOCUMENT_RECEIPT_TAG': b'HIADOC01',
        'NULL_VALUE': b'null', 'ADOPT_SLOT_PLAN': b'HIAADS01', 'ADOPT_ADVANCE_TAG': b'HIAADA01',
        'ADOPT_FOLD_TAG': b'HIASTGM1', 'ADOPT_WRITE_TAG': b'HIAADW01',
        'ADOPT_COMMIT_TAG': b'HIAADC01', 'RB_COMMITTED_TAG': b'HIASTCP1',
        'ADOPT_SLOT_RECEIPT': b'HIAADP01', 'RB_LOOKUP_DOC': b'HIADAL01', 'RB_DOCUMENT_OBSERVE': b'HIARLP01',
        'RB_DOC_BOUND': b'HIARLP02', 'RB_ISSUE_DOC': b'HIADAI01', 'RB_DOC_ISSUED_TAG': b'HIADAR01',
        'STORE_PUT': b'store-pu', 'STORE_PUT_END': b't',
    }
    c.update({name: int.from_bytes(value, 'little') for name, value in words.items()})


def slot_sections():
    prefix = SLOT
    for source, names in (
        (ROWS, ('rollback_query', 'rollback_row_observed', 'rollback_conditional', 'rollback_format_generation')),
        (PUBLICATION, ('rollback_json', 'rollback_snapshot', 'rollback_stale_json', 'rollback_render_error',
                       'rollback_publish_stale')),
    ):
        for name in names:
            prefix += function(source, name).replace('INSPECTION_REQUEST_ROLE', 'ADOPT_SLOT_ROLE')
    receipt = function(PUBLICATION, 'rollback_json').replace('rollback_json(', 'adopt_receipt_json(')
    prefix += receipt.replace('ROLLBACK_RECORD', 'ADOPT_SLOT_RECEIPT').replace('INSPECTION_REQUEST_ROLE', 'ADOPT_AUTHORITY_ROLE')
    for name in ('rollback_doc_lookup', 'rollback_doc_observe', 'rollback_store_document'):
        prefix += function(PUBLICATION, name).replace('HEADER + 8, 10)', 'HEADER + 8, ADOPT_DOCUMENT_KIND)').replace(
            'HEADER + 32, 10)', 'HEADER + 32, ADOPT_DOCUMENT_KIND)').replace('INSPECTION_REQUEST_ROLE', 'ADOPT_SLOT_ROLE')
    source = function(PUBLICATION, 'rollback_document_state')
    body = source[source.index('    if state == RB_DOC_PARAMETERS:'):source.index('    if state == RB_OUTCOME:')]
    prefix += source[:source.index('    if state == ROLLBACK_UPDATED:')].replace('rollback_document_state(', 'adopt_document_io(')
    prefix += body.replace('ROLLBACK_READ_DOC', 'ADOPT_SLOT_READ_DOCUMENT').replace('ROLLBACK_WRITE_DOC', 'ADOPT_SLOT_DOCUMENT').replace(
        'return rollback_result(', 'return adopt_result(').replace('HEADER + 8, 10)', 'HEADER + 8, ADOPT_DOCUMENT_KIND)') + '    return BAD\n'
    # The row/previous-snapshot authority is the same HIA code as Rollback.
    return prefix + '''\ndef rollback_answer(s:readbuf) -> bool:
    return plan_ok(s) and length(s) >= 112 and input_word(s, 40) == 48 and input_word(s, 72) == ROLLBACK_ANSWER and input_word(s, 80) <= 8
'''


def slot_store_control(control):
    if control.startswith('\ndef open_store('):
        return control.replace('    put(w, STORE_PURPOSE, purpose)',
            '    if get(w, ADOPT_SLOT_ACTIVE) != 0 and purpose >= OPEN_CONTEXT_ROW and purpose <= OPEN_PROFILE_ROW:\n'
            '        return inspection_store_opened(o, w, purpose)\n'
            '    put(w, STORE_PURPOSE, purpose)')
    if control.startswith('\ndef close_store('):
        return control.replace('    put(w, STORE_PURPOSE, purpose)',
            '    if get(w, ADOPT_SLOT_ACTIVE) != 0 and purpose >= CLOSE_CONTEXT_ROW and purpose <= CLOSE_PROFILE_REFUSED:\n'
            '        return inspection_store_closed(o, w, purpose)\n'
            '    put(w, STORE_PURPOSE, purpose)')
    if '\ndef inspection_store_opened(' in control:
        control = control.replace('    query = slot_fd(w, QUERY_FD)',
            '    if purpose == ADOPT_SLOT_OPEN:\n'
            '        put(w, 0, ADOPT_SLOT_OPENED)\n'
            '        return ADOPT_DEFER_CUSTODY\n'
            '    transfer = choose(get(w, ADOPT_SLOT_ACTIVE) == 0, 1, 0)\n'
            '    query = slot_fd(w, QUERY_FD)').replace(', 1, query,', ', transfer, query,')
    if '\ndef inspection_store_closed(' in control:
        control = control.replace('    if purpose == CLOSE_CONTEXT_UNAVAILABLE:',
            '    if purpose == ADOPT_SLOT_CLOSE_COMMIT:\n'
            '        put(w, ADOPT_SLOT_ACTIVE, 0)\n'
            '        put(w, ADOPT_SLOT_DURABLE, 1)\n'
            '        return clock_sample(o, w, COST_CLOCK, 0)\n'
            '    if purpose == ADOPT_SLOT_STALE:\n'
            '        put(w, 0, ADOPT_SLOT_CLOSED)\n'
            '        return ADOPT_DEFER_CUSTODY\n'
            '    if purpose == ADOPT_SLOT_FAILED:\n'
            '        put(w, ADOPT_SLOT_ACTIVE, 0)\n'
            '        return adopt_error(o, w, get(w, ADOPT_CUSTODY_ERROR))\n'
            '    if purpose == CLOSE_CONTEXT_UNAVAILABLE:')
    if control.startswith('\ndef settle_transaction('):
        return control.replace('    old_request = get(w, STORE_REQUEST)',
            '    purpose = get(w, STORE_PURPOSE)\n    old_request = get(w, STORE_REQUEST)').replace(
            'found > 1', 'found > choose(purpose == ADOPT_SLOT_COMMIT, 6, 1)').replace(
            '    purpose = get(w, STORE_PURPOSE)\n    if purpose == EMIT_PUB_LOOKUP',
            '    if purpose >= ADOPT_SLOT_READ and purpose <= ADOPT_SLOT_COMMIT:\n'
            '        put(w, 0, ADOPT_SLOT_SETTLED)\n'
            '        return ADOPT_DEFER_CUSTODY\n'
            '    if purpose == EMIT_PUB_LOOKUP').replace('purpose == STORE_COST and get(w, JOURNAL_NEXT) == 20:',
            'purpose == STORE_COST and get(w, JOURNAL_NEXT) == 20 and get(w, ADOPT_SLOT_DURABLE) == 0:')
    if control.startswith('\ndef typed_job('):
        return control.replace('    return store_transaction(o, w, purpose, 22, 1, fd, 8, span - 8)',
            '    if get(w, ADOPT_SLOT_ACTIVE) == 1:\n'
            '        return store_transaction(o, w, ADOPT_SLOT_TERMINAL, 22, 0, fd, 8, span - 8)\n'
            '    return store_transaction(o, w, purpose, 22, 1, fd, 8, span - 8)')
    if control.startswith('\ndef journal_action('):
        return control.replace('        return clock_sample(o, w, COST_CLOCK, 0)',
            '        if get(w, ADOPT_SLOT_ACTIVE) == 1:\n'
            '            if get(w, EFFECT_STATUS) != 1 or get(w, ADOPT_WRITE_COUNT) < 2:\n'
            '                return BAD\n'
            '            return typed_request(o, w, STORE_TERMINAL, 0)\n'
            '        return clock_sample(o, w, COST_CLOCK, 0)')
    if control.startswith('\ndef store_transaction('):
        return control.replace('or plan == 23:', 'or plan == 23 or plan == 36:').replace(
            'if purpose == STORE_RESERVATION_COMMIT:', 'if purpose == STORE_RESERVATION_COMMIT or purpose == ADOPT_SLOT_COMMIT:')
    return control
