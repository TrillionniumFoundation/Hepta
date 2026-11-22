"""Author the HIA Rollback driver using the authenticated Worker ports."""

from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_worker_context_flow import flow_source, function
from tools.generate_hia_worker_candidate_flow import replace_function
from tools import generate_hia_worker_inspection_flow as worker

SOURCE = Path('examples/hia_bootstrap/worker_rollback_flow.hepta')

REQUEST = r'''
def authorize_business(o:mutbuf, w:mutbuf) -> u64:
    inspection_catalog(o, w)
    after_prefix(w, o, ARGUMENT_FD, 0)
    store(o, 496, 93)
    fragment(o, 1, INLINE_FRAGMENT, 496, 1)
    return action(o, w, ROLLBACK_PROJECTED, RUN, INSPECTION_REQUEST_ROLE, 0, 2, 68)

def rollback_request(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    if state == ROLLBACK_PROJECTED:
        if plan_ok(s) == False or input_word(s, 72) != ROLLBACK_REQUEST or input_word(s, 40) < 71:
            return BAD
        body_span(s, w, ROLLBACK_ARGUMENTS)
        put(w, ROLLBACK_CURSOR, 16)
        return rollback_field(o, w, ROLLBACK_ARGUMENTS, ROLLBACK_ARGUMENT_FIELD)
    if state == ROLLBACK_ARGUMENT_FIELD:
        if rollback_bind_field(s, w, ROLLBACK_ARGUMENTS, ROLLBACK_FIELDS, 0, 6) == False:
            return BAD
        if get(w, ROLLBACK_FIELD_INDEX) < 6:
            return rollback_field(o, w, ROLLBACK_ARGUMENTS, ROLLBACK_ARGUMENT_FIELD)
        move_fragment(w, ROLLBACK_FIELDS, INSPECTION_ACTUAL)
        return inspection_context(o, w)
    if state == ROLLBACK_RANGE:
        if rollback_answer(s) == False:
            return BAD
        status = input_word(s, 80)
        if status != 0:
            return rollback_fail(o, w, status, 0)
        put(w, ROLLBACK_GENERATION, input_word(s, 88))
        put(w, ROLLBACK_EXPECT_GENERATION, input_word(s, 96))
        put(w, ROLLBACK_EXPECT_EPOCH, input_word(s, 104))
        return open_store(o, w, ROLLBACK_OPEN)
    return BAD

def rollback_field(o:mutbuf, w:mutbuf, source:u64, state:u64) -> u64:
    cursor = get(w, ROLLBACK_CURSOR)
    end = get(w, source + 8) + get(w, source + 16)
    if cursor > end or end - cursor < 8:
        return BAD
    return read_span(o, w, state, get(w, source), cursor, 8)

def rollback_bind_field(s:readbuf, w:mutbuf, source:u64, fields:u64, minimum:u64, count:u64) -> bool:
    i = get(w, ROLLBACK_FIELD_INDEX)
    at = get(w, ROLLBACK_CURSOR) + 8
    end = get(w, source + 8) + get(w, source + 16)
    size = input_word(s, 64)
    if i >= count or size < minimum or at > end or size > end - at:
        return False
    if i + 1 == count and at + size != end:
        return False
    hold(w, fields + 24 * i, get(w, source), at, size)
    put(w, ROLLBACK_FIELD_INDEX, i + 1)
    put(w, ROLLBACK_CURSOR, at + size)
    return True

def rollback_answer(s:readbuf) -> bool:
    return plan_ok(s) and length(s) >= 112 and input_word(s, 40) == 48 and input_word(s, 72) == ROLLBACK_ANSWER and input_word(s, 80) <= 8

def rollback_context_done(o:mutbuf, w:mutbuf, event:u64, status:u64, data:u64) -> u64:
    if event == 3:
        if status != 0:
            return rollback_fail(o, w, 11, 0)
        move_fragment(w, RB_NATIVE_FIELDS + 24, INSPECTION_ACTUAL)
        return inspection_context(o, w)
    if event != 2:
        return BAD
    if status != 0:
        if status == 3:
            return rollback_profile_error(o, w, 2, 1)
        if status == 7:
            return rollback_profile_error(o, w, 2, 2)
        if status == 8:
            return rollback_profile_error(o, w, 7, 1)
        code = choose(status == 1, 13, choose(status == 2, 14, choose(status == 5, 11, 16)))
        return rollback_fail(o, w, code, 0)
    if get(w, ROLLBACK_CUSTODY) != 0:
        return inspection_hash(o, w, RB_CORE_HASH, INSPECTION_CORE)
    span = ROLLBACK_FIELDS
    if get(w, span + 16) < 43:
        return BAD
    hold(w, ROLLBACK_CONTEXT_ID, get(w, span), get(w, span + 8) + 7, 36)
    slot = span + 24
    if get(w, slot + 16) < 3:
        return BAD
    hold(w, ROLLBACK_NAME, get(w, slot), get(w, slot + 8) + 1, get(w, slot + 16) - 2)
    put(o, HEADER, ROLLBACK_DECISION)
    put(o, HEADER + 8, 1)
    i = 0
    while i < 3:
        field = ROLLBACK_FIELDS + 48 + 24 * i
        size = get(w, field + 16)
        if size < 3 or size > 22:
            return BAD
        put(o, HEADER + 16 + 8 * i, size - 2)
        fragment(o, i, get(w, field), get(w, field + 8) + 1, size - 2)
        i = i + 1
    return action(o, w, ROLLBACK_RANGE, RUN, INSPECTION_REQUEST_ROLE, 0, 3, 40)
'''

ROWS = r'''
def rollback_query(o:mutbuf, w:mutbuf, kind:u64, generation:u64, resume:u64) -> u64:
    put(w, ROLLBACK_ROW_KIND, kind)
    put(w, ROLLBACK_ROW_GENERATION, generation)
    put(w, ROLLBACK_ROW_RESUME, resume)
    put(o, HEADER, ROLLBACK_QUERY)
    put(o, HEADER + 8, choose(kind == 2, 2, 1))
    put(o, HEADER + 16, generation)
    put(o, HEADER + 24, 0)
    put(o, HEADER + 32, get(w, ROLLBACK_NAME + 16))
    use_span(w, o, ROLLBACK_NAME, 0)
    return action(o, w, ROLLBACK_ROW_PLAN, RUN, INSPECTION_REQUEST_ROLE, 0, 1, 40)

def rollback_row_observed(o:mutbuf, w:mutbuf, bytes:u64) -> u64:
    kind = get(w, ROLLBACK_ROW_KIND)
    named = kind != 3
    put(o, HEADER, ROLLBACK_OBSERVE)
    put(o, HEADER + 8, bytes)
    put(o, HEADER + 16, get(w, STORE_REQUEST))
    put(o, HEADER + 24, get(w, STORE_EPOCH))
    put(o, HEADER + 32, kind)
    put(o, HEADER + 40, choose(named, get(w, ROLLBACK_NAME + 16), 0))
    put(o, HEADER + 48, choose(named, get(w, ROLLBACK_ROW_GENERATION), 0))
    if named:
        use_span(w, o, ROLLBACK_NAME, 0)
    whole_slot(w, o, STORE_RESULT, choose(named, 1, 0))
    return action(o, w, get(w, ROLLBACK_ROW_RESUME), RUN, INSPECTION_REQUEST_ROLE, 0, choose(named, 2, 1), 56)

def rollback_conditional(o:mutbuf, w:mutbuf) -> u64:
    put(o, HEADER, ROLLBACK_DECISION)
    put(o, HEADER + 8, 2)
    put(o, HEADER + 16, get(w, ROLLBACK_PRESENT))
    put(o, HEADER + 24, get(w, ROLLBACK_EXPECT_GENERATION))
    put(o, HEADER + 32, get(w, ROLLBACK_EXPECT_EPOCH))
    put(o, HEADER + 40, get(w, ROLLBACK_SLOT_GENERATION))
    put(o, HEADER + 48, get(w, ROLLBACK_SLOT_EPOCH))
    return action(o, w, ROLLBACK_CONDITIONAL, RUN, INSPECTION_REQUEST_ROLE, 0, 0, 56)

def rollback_format_generation(o:mutbuf, w:mutbuf, state:u64, generation:u64, epoch:u64) -> u64:
    put(o, HEADER, ROLLBACK_FORMAT_GENERATION)
    put(o, HEADER + 8, generation)
    put(o, HEADER + 16, epoch)
    return action(o, w, state, RUN, INSPECTION_REQUEST_ROLE, 0, 0, 24)

def rollback_row_state(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    size = input_word(s, 40)
    fd = input_word(s, 32)
    if state == ROLLBACK_ROW_PLAN:
        if plan_ok(s) == False or size < 64 or size > 320:
            return BAD
        return store_transaction(o, w, ROLLBACK_READ_SLOT, 27 + get(w, ROLLBACK_ROW_KIND), 0, fd, 8, size - 8)
    if state == ROLLBACK_SLOT:
        if plan_ok(s) == False or (size != 24 and size != 140) or input_word(s, 72) != ROLLBACK_BOUND_ROW:
            return BAD
        present = input_word(s, 80)
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
    if state == ROLLBACK_ACTIVE or state == ROLLBACK_RETAINED:
        if plan_ok(s) == False or (size != 24 and size != 200) or input_word(s, 72) != ROLLBACK_BOUND_ROW:
            return BAD
        present = input_word(s, 80)
        if present != choose(size == 200, 1, 0):
            return BAD
        if state == ROLLBACK_ACTIVE:
            if present != 1:
                return BAD
            hold(w, ROLLBACK_ACTIVE_REF, fd, 24, 176)
            return rollback_query(o, w, 3, 0, ROLLBACK_LEASES)
        if present == 0:
            return rollback_abi_decision(o, w, False)
        hold(w, ROLLBACK_RETAINED_REF, fd, 24, 176)
        return rollback_native_query(o, w)
    if state == ROLLBACK_LEASES:
        if plan_ok(s) == False or size != 24 or input_word(s, 72) != ROLLBACK_LEASE_COUNT:
            return BAD
        put(w, ROLLBACK_COUNT, input_word(s, 80))
        return rollback_conditional(o, w)
    if state == ROLLBACK_CONDITIONAL:
        if rollback_answer(s) == False:
            return BAD
        status = input_word(s, 80)
        put(w, ROLLBACK_STATUS, status)
        return rollback_format_generation(o, w, ROLLBACK_PREVIOUS, get(w, ROLLBACK_SLOT_GENERATION),
                                          get(w, ROLLBACK_SLOT_EPOCH))
    if state == ROLLBACK_PREVIOUS:
        if plan_ok(s) == False or size < 16 or size > 128:
            return BAD
        body_span(s, w, ROLLBACK_PREVIOUS_VIEW)
        status = get(w, ROLLBACK_STATUS)
        if status == 4:
            return close_store(o, w, ROLLBACK_CLOSE_STALE)
        if status != 0:
            return rollback_fail(o, w, status, 0)
        return rollback_query(o, w, 2, get(w, ROLLBACK_GENERATION), ROLLBACK_RETAINED)
    return BAD
'''

NATIVE = r'''
def rollback_native_query(o:mutbuf, w:mutbuf) -> u64:
    put(o, HEADER, RETAINED_QUERY_ANY)
    put(o, HEADER + 8, 0)
    use_span(w, o, ROLLBACK_RETAINED_REF, 0)
    return action(o, w, RB_NATIVE_QUERY, RUN, PROFILE_ROLE, 0, 1, 16)

def rollback_native_observed(o:mutbuf, w:mutbuf, bytes:u64) -> u64:
    put(o, HEADER, RB_NATIVE_OBSERVE)
    put(o, HEADER + 8, bytes)
    put(o, HEADER + 16, get(w, STORE_REQUEST))
    put(o, HEADER + 24, get(w, STORE_EPOCH))
    use_span(w, o, ROLLBACK_RETAINED_REF, 0)
    whole_slot(w, o, STORE_RESULT, 1)
    return action(o, w, RB_NATIVE_FRAME, MAKE, 0, 0, 2, 32)

def rollback_compare(o:mutbuf, w:mutbuf, state:u64, left:u64, right:u64) -> u64:
    put(o, HEADER, RB_COMPARE)
    put(o, HEADER + 8, get(w, left + 16))
    put(o, HEADER + 16, get(w, right + 16))
    use_span(w, o, left, 0)
    use_span(w, o, right, 1)
    return action(o, w, state, RUN, RB_NATIVE_ROLE, 0, 2, 24)

def rollback_binding(s:readbuf) -> bool:
    return plan_ok(s) and input_word(s, 40) == 24 and input_word(s, 72) == RB_MATCH and input_word(s, 80) <= 1

def rollback_abi_decision(o:mutbuf, w:mutbuf, present:bool) -> u64:
    put(o, HEADER, ROLLBACK_DECISION)
    put(o, HEADER + 8, 3)
    put(o, HEADER + 16, choose(present, 1, 0))
    put(o, HEADER + 24, get(w, ROLLBACK_SLOT_EPOCH))
    if present:
        use_span(w, o, ROLLBACK_SLOT_ABI, 0)
        use_span(w, o, RB_DIGEST_SPAN, 1)
    return action(o, w, ROLLBACK_APPROVED, RUN, INSPECTION_REQUEST_ROLE, 0, choose(present, 2, 0), 32)

def rollback_native_state(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    size = input_word(s, 40)
    fd = input_word(s, 32)
    if state == RB_NATIVE_QUERY:
        if plan_ok(s) == False or size != 98:
            return BAD
        return store_transaction(o, w, ROLLBACK_READ_NATIVE, 2, 0, fd, 8, size - 8)
    if state == RB_NATIVE_FRAME:
        if size < 256:
            return BAD
        sample_span(s, w, RB_NATIVE_INPUT)
        use_span(w, o, RB_NATIVE_INPUT, 0)
        return action(o, w, RB_NATIVE_WITNESS, RUN, RB_NATIVE_ROLE, 0, 1, 0)
    if state == RB_NATIVE_WITNESS:
        if reply_word(s, RETAINED_REFUSAL) or reply_word(s, RETAINED_CORRUPT):
            return rollback_fail(o, w, choose(reply_word(s, RETAINED_REFUSAL), 11, 12), 0)
        if plan_ok(s) == False or size != 96:
            return BAD
        return read_span(o, w, RB_NATIVE_BIND, fd, 8, 88)
    if state == RB_NATIVE_BIND:
        at = input_word(s, 136)
        bytes = input_word(s, 144)
        if input_word(s, 64) != RB_NATIVE_ARTIFACT or at > get(w, RB_NATIVE_INPUT + 16) or bytes > get(w, RB_NATIVE_INPUT + 16) - at:
            return BAD
        hold(w, RB_NATIVE_METADATA, get(w, RB_NATIVE_INPUT), at, bytes)
        return rollback_get_digest(s, o, w, 72, RB_NATIVE_LOADED)
    if state == RB_NATIVE_LOADED:
        if size == 0:
            return BAD
        use_span(w, o, RB_NATIVE_METADATA, 0)
        return action(o, w, RB_METADATA_PLAN, RUN, RB_NATIVE_ROLE, 0, 1, 0)
    if state == RB_METADATA_PLAN:
        if plan_ok(s) == False or size != 120:
            return BAD
        return read_span(o, w, RB_METADATA_FIELDS, fd, 8, 112)
    if state == RB_METADATA_FIELDS:
        return rollback_metadata(s, o, w)
    if state == RB_INSTALLED_MATCH or state == RB_CORE_MATCH or state == RB_EXPORTS_MATCH or state == RB_SIGNATURES_MATCH:
        if rollback_binding(s) == False:
            return BAD
        if input_word(s, 80) != 1:
            return rollback_fail(o, w, choose(state == RB_INSTALLED_MATCH, 9, 10), 0)
        if state == RB_INSTALLED_MATCH:
            move_fragment(w, RB_NATIVE_FIELDS + 48, INSPECTION_ACTUAL)
            return inspection_program(o, w)
        if state == RB_CORE_MATCH:
            if get(w, RB_NATIVE_FIELDS + 112) == 0:
                put(o, HEADER, 23899)
                return action(o, w, RB_EMPTY_EXPORTS, MAKE, 0, 0, 0, 2)
            return rollback_compare(o, w, RB_EXPORTS_MATCH, RB_NATIVE_FIELDS + 96, INSPECTION_EXPORTS)
        if state == RB_EXPORTS_MATCH:
            return rollback_signatures(o, w)
        return inspection_hash(o, w, RB_ABI_HASH, RB_SIGNATURES)
    if state == RB_EMPTY_EXPORTS:
        if size != 2:
            return BAD
        sample_span(s, w, RB_NATIVE_FIELDS + 96)
        return rollback_compare(o, w, RB_EXPORTS_MATCH, RB_NATIVE_FIELDS + 96, INSPECTION_EXPORTS)
    if state == RB_SIGNATURES_RENDERED:
        if plan_ok(s) == False or size < 10:
            return BAD
        body_span(s, w, RB_SIGNATURES)
        return rollback_compare(o, w, RB_SIGNATURES_MATCH, RB_SIGNATURES, RB_NATIVE_FIELDS + 120)
    if state == ROLLBACK_APPROVED:
        if rollback_answer(s) == False:
            return BAD
        status = input_word(s, 80)
        if status != 0:
            return rollback_fail(o, w, status, 0)
        epoch = input_word(s, 88)
        put(w, ROLLBACK_APPROVED_EPOCH, epoch)
        put(o, HEADER, ROLLBACK_QUERY)
        put(o, HEADER + 8, 3)
        put(o, HEADER + 16, get(w, ROLLBACK_GENERATION))
        put(o, HEADER + 24, epoch)
        put(o, HEADER + 32, get(w, ROLLBACK_NAME + 16))
        use_span(w, o, ROLLBACK_CONTEXT_ID, 0)
        use_span(w, o, ROLLBACK_NAME, 1)
        return action(o, w, ROLLBACK_UPDATE_PLAN, RUN, INSPECTION_REQUEST_ROLE, 0, 2, 40)
    if state == ROLLBACK_UPDATE_PLAN:
        if plan_ok(s) == False or size < 182 or size > 420:
            return BAD
        return store_transaction(o, w, ROLLBACK_WRITE_UPDATE, 31, 0, fd, 8, size - 8)
    return BAD

def rollback_metadata(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if length(s) != 176 or input_word(s, 64) != RB_METADATA_TAG or input_word(s, 72) != 6:
        return BAD
    start = get(w, RB_NATIVE_METADATA + 8)
    extent = get(w, RB_NATIVE_METADATA + 16)
    idx = 0
    while idx < 6:
        at = input_word(s, 80 + idx * 16)
        bytes = input_word(s, 88 + idx * 16)
        if at > extent or bytes > extent - at or (bytes == 0 and idx != 4) or (idx == 3 and bytes != 64):
            return BAD
        hold(w, RB_NATIVE_FIELDS + idx * 24, get(w, RB_NATIVE_METADATA), start + at, bytes)
        idx = idx + 1
    hold(w, RB_INSTALLATION, slot_fd(w, DOSSIER_FD), DOSSIER_HEAD + get(w, 40), get(w, 48))
    return rollback_compare(o, w, RB_INSTALLED_MATCH, RB_NATIVE_FIELDS, RB_INSTALLATION)

def rollback_get_digest(s:readbuf, o:mutbuf, w:mutbuf, start:u64, state:u64) -> u64:
    i = 0
    while i < 64:
        c = byte(s, start + i)
        if is_hex(c) == False:
            return BAD
        store(o, 416 + i, c)
        i = i + 1
    store(o, 480, 0)
    return artifact_command(o, w, state, STORE_GET, STORE_GET_END, 0)

def rollback_signature_padding(o:mutbuf, w:mutbuf) -> u64:
    store(o, 496, 44)
    store(o, 497, 48 + get(w, RB_PROFILE_LEVEL))
    store(o, 498, 44)
    store(o, 499, 51)
    store(o, 500, 93)
    return 0

def rollback_signatures(o:mutbuf, w:mutbuf) -> u64:
    store(o, HEADER, 91)
    store(o, 495, 44)
    rollback_signature_padding(o, w)
    vector_span(w, o, INSPECTION_CORE, HEADER + 1)
    vector_part(o, HEADER + 25, INLINE_FRAGMENT, 495, 1)
    vector_span(w, o, INSPECTION_EXPORTS, HEADER + 49)
    vector_part(o, HEADER + 73, INLINE_FRAGMENT, 496, 5)
    return wide_inspection(o, w, RB_SIGNATURES_RENDERED, RB_SIGNATURES_ROLE, 0, 4, 1)
'''

PUBLICATION = r'''
def rollback_json(o:mutbuf, w:mutbuf, kind:u64, fields:u64, count:u64, state:u64) -> u64:
    put(o, HEADER, ROLLBACK_RECORD)
    put(o, HEADER + 8, kind)
    i = 0
    while i < count:
        record = fields + 24 * i
        width = 400 + 8 * i
        put(o, width, get(w, record + 16))
        vector_part(o, HEADER + 16 + 48 * i, INLINE_FRAGMENT, width, 8)
        vector_span(w, o, record, HEADER + 40 + 48 * i)
        i = i + 1
    return wide_inspection(o, w, state, INSPECTION_REQUEST_ROLE, 0, 2 * count, 16)

def rollback_snapshot(o:mutbuf, w:mutbuf) -> u64:
    if get(w, ROLLBACK_PRESENT) == 0:
        put(o, HEADER, NULL_VALUE)
        store(o, HEADER + 4, 48)
        return action(o, w, RB_STALE_EMPTY, MAKE, 0, 0, 0, 5)
    put(o, HEADER, ROLLBACK_FORMAT_COUNT)
    put(o, HEADER + 8, get(w, ROLLBACK_COUNT))
    return action(o, w, RB_STALE_COUNT, RUN, INSPECTION_REQUEST_ROLE, 0, 0, 16)

def rollback_stale_json(o:mutbuf, w:mutbuf) -> u64:
    move_fragment(w, ROLLBACK_ACTIVE_REF, RB_FIELDS)
    move_fragment(w, ROLLBACK_SLOT_CONTEXT, RB_FIELDS + 24)
    move_fragment(w, ROLLBACK_PREVIOUS_VIEW, RB_FIELDS + 48)
    move_fragment(w, RB_COUNT_TEXT, RB_FIELDS + 72)
    move_fragment(w, ROLLBACK_FIELDS + 24, RB_FIELDS + 96)
    return rollback_json(o, w, 3, RB_FIELDS, 5, RB_STALE_JSON)

def rollback_record(o:mutbuf, w:mutbuf) -> u64:
    move_fragment(w, ROLLBACK_RETAINED_REF, RB_FIELDS)
    move_fragment(w, ROLLBACK_FIELDS, RB_FIELDS + 24)
    move_fragment(w, ROLLBACK_UPDATED_VIEW, RB_FIELDS + 48)
    move_fragment(w, ROLLBACK_PREVIOUS_VIEW, RB_FIELDS + 72)
    move_fragment(w, ROLLBACK_FIELDS + 120, RB_FIELDS + 96)
    move_fragment(w, ROLLBACK_FIELDS + 24, RB_FIELDS + 120)
    return rollback_json(o, w, 1, RB_FIELDS, 6, RB_RECORD_JSON)

def rollback_result(o:mutbuf, w:mutbuf) -> u64:
    move_fragment(w, ROLLBACK_RETAINED_REF, RB_FIELDS)
    move_fragment(w, ROLLBACK_UPDATED_VIEW, RB_FIELDS + 24)
    move_fragment(w, ROLLBACK_PREVIOUS_VIEW, RB_FIELDS + 48)
    move_fragment(w, RB_DOCUMENT_RECEIPT, RB_FIELDS + 72)
    move_fragment(w, ROLLBACK_FIELDS + 24, RB_FIELDS + 96)
    return rollback_json(o, w, 2, RB_FIELDS, 5, RB_RESULT_JSON)

def rollback_fail(o:mutbuf, w:mutbuf, code:u64, detail:u64) -> u64:
    if get(w, ROLLBACK_CUSTODY) != 0:
        put(w, ROLLBACK_ERROR, code)
        return rollback_queue_close(o, w, ROLLBACK_CLOSE_FAILED)
    return rollback_render_error(o, w, code, detail)

def rollback_render_error(o:mutbuf, w:mutbuf, code:u64, detail:u64) -> u64:
    put(o, HEADER, ROLLBACK_PUBLIC_ERROR)
    put(o, HEADER + 8, code)
    if code == 4:
        use_span(w, o, detail, 0)
    return action(o, w, RB_ERROR_RENDERED, RUN, INSPECTION_REQUEST_ROLE, 0, choose(code == 4, 1, 0), 16)

def rollback_profile_error(o:mutbuf, w:mutbuf, scope:u64, reason:u64) -> u64:
    put(w, ROLLBACK_ERROR_SCOPE, scope)
    put(w, ROLLBACK_ERROR, reason)
    if get(w, ROLLBACK_CUSTODY) != 0:
        return rollback_queue_close(o, w, ROLLBACK_CLOSE_FAILED)
    return rollback_render_profile(o, w, scope, reason)

def rollback_render_profile(o:mutbuf, w:mutbuf, scope:u64, reason:u64) -> u64:
    zero_range(o, HEADER, 40)
    put(o, HEADER, ERROR_PACKET)
    put(o, HEADER + 8, scope)
    put(o, HEADER + 16, reason)
    return action(o, w, RB_PROFILE_ERROR, RUN, FLOW_ROLE, 0, 0, 40)

def rollback_outcome(o:mutbuf, w:mutbuf, status:u64) -> u64:
    context = get(w, ROLLBACK_CONTEXT_ID + 16)
    zero_range(o, HEADER, 32)
    put(o, HEADER, RB_OUTCOME_REQUEST)
    put(o, HEADER + 8, status)
    put(o, HEADER + 16, context)
    put(o, HEADER + 24, get(w, RB_PAYLOAD + 16))
    if context == 36:
        use_span(w, o, ROLLBACK_CONTEXT_ID, 0)
    use_span(w, o, RB_PAYLOAD, choose(context == 36, 1, 0))
    put(w, INSPECTION_STATUS, status)
    return action(o, w, RB_OUTCOME, RUN, INSPECTION_REQUEST_ROLE, 0, choose(context == 36, 2, 1), 32)

def rollback_publish_stale(o:mutbuf, w:mutbuf, fd:u64, size:u64) -> u64:
    launch_directory(w, o, 0)
    role_argument(w, o, 2, STORE_ROLE)
    role_argument(w, o, 3, READY_ROLE)
    role_argument(w, o, 4, UNIQUE_ROLE)
    role_argument(w, o, 5, PUBLISHER_ROLE)
    role_argument(w, o, 6, DOCUMENT_PLAN_ROLE)
    role_argument(w, o, 7, DOCUMENT_EFFECT_ROLE)
    argv(o, 8, DECIMAL_ARG, 11)
    argv(o, 9, DECIMAL_ARG, 0)
    fragment(o, 0, fd, 8, size - 8)
    return action(o, w, RB_STALE_PUBLISHED, RUN, DOCUMENT_ROLE, 10, 1, 0)

def rollback_doc_lookup(o:mutbuf, w:mutbuf) -> u64:
    put(o, HEADER, RB_LOOKUP_DOC)
    put(o, HEADER + 8, 10)
    copy_private(w, o, RB_DOC_HASH, HEADER + 16, 64)
    return action(o, w, RB_DOC_PARAMETERS, RUN, DOCUMENT_PLAN_ROLE, 0, 0, 80)

def rollback_doc_observe(o:mutbuf, w:mutbuf, bytes:u64) -> u64:
    put(o, HEADER, RB_DOCUMENT_OBSERVE)
    put(o, HEADER + 8, bytes)
    put(o, HEADER + 16, get(w, STORE_REQUEST))
    put(o, HEADER + 24, get(w, STORE_EPOCH))
    put(o, HEADER + 32, 10)
    copy_private(w, o, RB_DOC_HASH, HEADER + 40, 64)
    fragment(o, 0, get(w, RB_DOC_KEY), 64, 64)
    whole_slot(w, o, STORE_RESULT, 1)
    return action(o, w, RB_DOC_OBSERVED, RUN, INSPECTION_REQUEST_ROLE, 0, 2, 104)

def rollback_store_document(o:mutbuf, w:mutbuf) -> u64:
    put(o, 416, 45)
    use_span(w, o, RB_DOCUMENT_BYTES, 0)
    return artifact_command(o, w, RB_DOC_STORED, STORE_PUT, STORE_PUT_END, 1)

def rollback_document_state(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    size = input_word(s, 40)
    fd = input_word(s, 32)
    if state == ROLLBACK_UPDATED:
        if plan_ok(s) == False or size < 16 or size > 128:
            return BAD
        body_span(s, w, ROLLBACK_UPDATED_VIEW)
        return rollback_record(o, w)
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
        store(o, HEADER, 34)
        copy_span(s, o, 64, HEADER + 1, 36)
        store(o, HEADER + 37, 34)
        return action(o, w, RB_STALE_CONTEXT_JSON, MAKE, 0, 0, 0, 38)
    if state == RB_STALE_CONTEXT_JSON:
        if size != 38:
            return BAD
        sample_span(s, w, ROLLBACK_SLOT_CONTEXT)
        return rollback_stale_json(o, w)
    if state == RB_STALE_JSON or state == RB_RECORD_JSON or state == RB_RESULT_JSON or state == RB_ERROR_RENDERED:
        if plan_ok(s) == False or size < 10:
            return BAD
        if state == RB_STALE_JSON:
            return rollback_publish_stale(o, w, fd, size)
        if state == RB_RECORD_JSON:
            body_span(s, w, RB_DOCUMENT_BYTES)
            return inspection_hash(o, w, RB_DOCUMENT_HASH, RB_DOCUMENT_BYTES)
        body_span(s, w, RB_PAYLOAD)
        return rollback_outcome(o, w, choose(state == RB_RESULT_JSON, 1, 2))
    if state == RB_PROFILE_ERROR:
        if size < 2:
            return BAD
        sample_span(s, w, RB_PAYLOAD)
        return rollback_outcome(o, w, 2)
    if state == RB_STALE_PUBLISHED:
        if size != 200 or input_word(s, 64) != RB_DOCUMENT_RECEIPT_TAG:
            return BAD
        sample_span(s, w, RB_DOCUMENT_RECEIPT)
        return rollback_fail(o, w, 4, RB_DOCUMENT_RECEIPT)
    if state == RB_DOC_PARAMETERS:
        if plan_ok(s) == False or size != 128:
            return BAD
        body_span(s, w, RB_DOC_KEY)
        return store_transaction(o, w, ROLLBACK_READ_DOC, 1, 0, fd, 8, 120)
    if state == RB_DOC_OBSERVED:
        if plan_ok(s) == False or (size != 24 and size != 200) or input_word(s, 72) != RB_DOC_BOUND:
            return BAD
        if input_word(s, 80) != choose(size == 200, 1, 0):
            return BAD
        if size == 24:
            return rollback_store_document(o, w)
        hold(w, RB_DOCUMENT_RECEIPT, fd, 24, 176)
        copy_private(w, o, RB_DOC_HASH, 416, 64)
        store(o, 480, 0)
        return artifact_command(o, w, RB_DOC_REUSED, STORE_GET, STORE_GET_END, 0)
    if state == RB_DOC_REUSED:
        if size == 0:
            return BAD
        return rollback_result(o, w)
    if state == RB_DOC_STORED:
        if size < 88 or size > 105:
            return BAD
        put(w, INSPECTION_HASH_RESUME, RB_DOC_STORED)
        return read_span(o, w, INSPECTION_HASH_FRAME, fd, 0, size)
    if state == RB_DOC_NONCE:
        if size != 32 or length(s) != 96:
            return BAD
        put(o, HEADER, RB_ISSUE_DOC)
        put(o, HEADER + 8, 10)
        copy_private(w, o, RB_DOC_HASH, HEADER + 16, 64)
        copy_span(s, o, 64, HEADER + 80, 32)
        return action(o, w, RB_DOC_ISSUED, RUN, DOCUMENT_PLAN_ROLE, 0, 0, 112)
    if state == RB_DOC_ISSUED:
        if plan_ok(s) == False or size <= 208 or input_word(s, 72) != RB_DOC_ISSUED_TAG:
            return BAD
        body = input_word(s, 80)
        if body != size - 208 or input_word(s, 88) != 176:
            return BAD
        hold(w, RB_DOCUMENT_RECEIPT, fd, 32 + body, 176)
        return store_transaction(o, w, ROLLBACK_WRITE_DOC, 20, 0, fd, 32, body)
    if state == RB_OUTCOME:
        status = get(w, INSPECTION_STATUS)
        if plan_ok(s) == False or size != 76 + get(w, RB_PAYLOAD + 16) or input_word(s, 72) != RB_OUTCOME_TAG or input_word(s, 80) != status:
            return BAD
        body_span(s, w, INSPECTION_OUTCOME)
        keep(w, EFFECT_FD, fd, size)
        return end_effect(o, w, status, 76)
    return BAD

def rollback_hash_bound(s:readbuf, o:mutbuf, w:mutbuf, at:u64) -> u64:
    resume = get(w, INSPECTION_HASH_RESUME)
    if resume == RB_CORE_HASH:
        hold(w, RB_DIGEST_SPAN, input_word(s, 32), at - 64, 64)
        return rollback_compare(o, w, RB_CORE_MATCH, RB_DIGEST_SPAN, RB_NATIVE_FIELDS + 72)
    if resume == RB_ABI_HASH:
        hold(w, RB_DIGEST_SPAN, input_word(s, 32), at - 64, 64)
        return rollback_abi_decision(o, w, True)
    if resume == RB_DOCUMENT_HASH:
        copy_span(s, w, at, RB_DOC_HASH, 64)
        return rollback_doc_lookup(o, w)
    if resume == RB_DOC_STORED:
        i = 0
        while i < 64:
            if byte(s, at + i) != byte(w, RB_DOC_HASH + i):
                return BAD
            i = i + 1
        put(o, 144, 32)
        return action(o, w, RB_DOC_NONCE, RANDOM, 0, 0, 0, 0)
    return BAD
'''

CUSTODY = r'''
def rollback_opened(o:mutbuf, w:mutbuf) -> u64:
    put(w, ROLLBACK_CUSTODY, 1)
    return rollback_query(o, w, 1, 0, ROLLBACK_SLOT)

def rollback_queue_close(o:mutbuf, w:mutbuf, purpose:u64) -> u64:
    put(w, STORE_PURPOSE, purpose)
    put(o, 176, STORE_PEER)
    return action(o, w, PEER_CLOSED, FINISH_PEER, 0, 0, 0, 0)

def rollback_closed(o:mutbuf, w:mutbuf, purpose:u64) -> u64:
    if get(w, ROLLBACK_CUSTODY) != 1:
        return BAD
    put(w, ROLLBACK_CUSTODY, 0)
    if purpose == ROLLBACK_CLOSE_STALE:
        return rollback_snapshot(o, w)
    if purpose == ROLLBACK_CLOSE_COMMITTED:
        put(w, ROLLBACK_DURABLE, 1)
        return clock_sample(o, w, COST_CLOCK, 0)
    if get(w, ROLLBACK_ERROR_SCOPE) != 0:
        return rollback_render_profile(o, w, get(w, ROLLBACK_ERROR_SCOPE), get(w, ROLLBACK_ERROR))
    return rollback_render_error(o, w, get(w, ROLLBACK_ERROR), 0)

def rollback_settlement(s:readbuf, o:mutbuf, w:mutbuf, purpose:u64, bytes:u64, found:u64) -> u64:
    if get(w, ROLLBACK_CUSTODY) != 1:
        return BAD
    if purpose == ROLLBACK_READ_SLOT:
        return rollback_row_observed(o, w, bytes)
    if purpose == ROLLBACK_READ_NATIVE:
        return rollback_native_observed(o, w, bytes)
    if purpose == ROLLBACK_READ_DOC:
        return rollback_doc_observe(o, w, bytes)
    count = get(w, RB_RECEIPT_COUNT)
    if purpose == ROLLBACK_COMMIT:
        if bytes != 8 or found != count or (count != 2 and count != 3):
            return BAD
        return read_span(o, w, RB_COMMIT_MARKER, slot_fd(w, STORE_RESULT), 0, 8)
    if bytes != 0 or found != 1 or count > 2:
        return BAD
    if (purpose == ROLLBACK_WRITE_UPDATE and count != 0) or (purpose == ROLLBACK_WRITE_DOC and count != 1):
        return BAD
    copy_span(s, w, 64, RB_RECEIPTS + 48 * count, 48)
    put(w, RB_RECEIPT_COUNT, count + 1)
    if purpose == ROLLBACK_WRITE_UPDATE:
        return rollback_format_generation(o, w, ROLLBACK_UPDATED, get(w, ROLLBACK_GENERATION),
                                          get(w, ROLLBACK_APPROVED_EPOCH))
    if purpose == ROLLBACK_WRITE_DOC:
        return rollback_result(o, w)
    if purpose == ROLLBACK_WRITE_TERMINAL and count >= 1:
        put(o, HEADER + 48, ROLLBACK_COMMIT_TAG)
        put(o, HEADER + 56, count + 1)
        copy_private(w, o, RB_RECEIPTS, HEADER + 64, 48 * (count + 1))
        return store_transaction(o, w, ROLLBACK_COMMIT, 32, 0, 0, 0, 16 + 48 * (count + 1))
    return BAD
'''


def retained_controls():
    # Context lookup is shared. Under a pending rollback, all reads must
    # borrow that same Store peer rather than start a second transaction.
    retained = worker.RETAINED_DRIVER.replace('inspection_feedback(', 'rollback_context_done(')
    retained = retained.replace(
        '    if reason == READ_PROFILE and corruption == False:\n'
        '        return rollback_context_done(o, w, 2, 3, 0)',
        '    if reason == READ_PROFILE:\n'
        '        if corruption:\n'
        '            return BAD\n'
        '        return rollback_context_done(o, w, 2, 8, 0)',
    ).replace('    if profile != 0:', '    put(w, RB_PROFILE_LEVEL, profile)\n    if profile != 0:')
    store = worker.STORE_DRIVER.replace('inspection_feedback(', 'rollback_context_done(')
    store = store.replace(
        '    if purpose == OPEN_CONTEXT_ROW:',
        '    if purpose == ROLLBACK_OPEN:\n'
        '        return rollback_opened(o, w)\n'
        '    transfer = choose(get(w, ROLLBACK_CUSTODY) == 1, 0, 1)\n'
        '    if purpose == OPEN_CONTEXT_ROW:',
    ).replace(', 1, query, 8, bytes - 8)', ', transfer, query, 8, bytes - 8)')
    store = store.replace(
        '    if purpose == CLOSE_CONTEXT_UNAVAILABLE:',
        '    if purpose >= ROLLBACK_CLOSE_STALE and purpose <= ROLLBACK_CLOSE_COMMITTED:\n'
        '        return rollback_closed(o, w, purpose)\n'
        '    if purpose == CLOSE_CONTEXT_UNAVAILABLE:',
    ).replace(
        '    if purpose == CLOSE_PROFILE_REFUSED:\n        return rollback_context_done(o, w, 2, 3, 0)',
        '    if purpose == CLOSE_PROFILE_REFUSED:\n        return rollback_context_done(o, w, 2, 7, 0)',
    )
    return retained, store


def control_source(controls):
    for control in controls:
        if control.startswith('\ndef issue('):
            control = control.replace(
                'choose(role == NOMINAL_ROLE, 1, choose(role == INSPECTION_QUERY_ROLE, 2, '
                'choose(role == INSPECTION_EMIT_ROLE, 3, 0)))', 'choose(role == NOMINAL_ROLE, 1, 0)',
            )
        elif control.startswith('\ndef open_store('):
            control = control.replace(
                '    put(w, STORE_PURPOSE, purpose)',
                '    if get(w, ROLLBACK_CUSTODY) == 1 and purpose >= OPEN_CONTEXT_ROW and purpose <= OPEN_PROFILE_ROW:\n'
                '        return inspection_store_opened(o, w, purpose)\n'
                '    put(w, STORE_PURPOSE, purpose)',
            )
        elif control.startswith('\ndef close_store('):
            control = control.replace(
                '    put(w, STORE_PURPOSE, purpose)',
                '    if get(w, ROLLBACK_CUSTODY) == 1 and purpose >= CLOSE_CONTEXT_ROW and purpose <= CLOSE_PROFILE_REFUSED:\n'
                '        return inspection_store_closed(o, w, purpose)\n'
                '    put(w, STORE_PURPOSE, purpose)',
            )
        elif control.startswith('\ndef store_transaction('):
            control = control.replace('or plan == 23', 'or plan == 23 or plan == 32').replace(
                'if purpose == STORE_RESERVATION_COMMIT:', 'if purpose == STORE_RESERVATION_COMMIT or purpose == ROLLBACK_COMMIT:')
        elif control.startswith('\ndef settle_transaction('):
            control = control.replace(
                '    old_request = get(w, STORE_REQUEST)\n',
                '    purpose = get(w, STORE_PURPOSE)\n    old_request = get(w, STORE_REQUEST)\n',
            ).replace('found > 1', 'found > choose(purpose == ROLLBACK_COMMIT, 3, 1)').replace(
                '    purpose = get(w, STORE_PURPOSE)\n    if purpose >= CONTEXT_ROW',
                '    if purpose >= ROLLBACK_READ_SLOT and purpose <= ROLLBACK_COMMIT:\n'
                '        return rollback_settlement(s, o, w, purpose, bytes, found)\n'
                '    if purpose >= CONTEXT_ROW',
            ).replace('purpose == STORE_COST and get(w, JOURNAL_NEXT) == 20:',
                      'purpose == STORE_COST and get(w, JOURNAL_NEXT) == 20 and get(w, ROLLBACK_DURABLE) == 0:')
        elif control.startswith('\ndef typed_job('):
            control = control.replace(
                '    return store_transaction(o, w, purpose, 22, 1, fd, 8, span - 8)',
                '    if get(w, ROLLBACK_CUSTODY) == 1:\n'
                '        return store_transaction(o, w, ROLLBACK_WRITE_TERMINAL, 22, 0, fd, 8, span - 8)\n'
                '    return store_transaction(o, w, purpose, 22, 1, fd, 8, span - 8)',
            )
        elif control.startswith('\ndef journal_action('):
            control = control.replace(
                '        return clock_sample(o, w, COST_CLOCK, 0)',
                '        if get(w, ROLLBACK_CUSTODY) == 1:\n'
                '            if get(w, EFFECT_STATUS) != 1 or get(w, RB_RECEIPT_COUNT) == 0:\n'
                '                return BAD\n'
                '            return typed_request(o, w, STORE_TERMINAL, 0)\n'
                '        return clock_sample(o, w, COST_CLOCK, 0)',
            )
        yield control


def program():
    constants, controls = worker.recipe()
    constants.update(ROLE_COUNT=35, ENTRY_BYTES=64 + 312 + 35 * 40, SCHEMA_TOOL=11,
                     RB_NATIVE_ROLE=32, RB_SIGNATURES_ROLE=34, RANDOM=10)
    states = (
        'ROLLBACK_PROJECTED', 'ROLLBACK_ARGUMENT_FIELD', 'ROLLBACK_RANGE',
        'ROLLBACK_ROW_PLAN', 'ROLLBACK_SLOT', 'ROLLBACK_ACTIVE', 'ROLLBACK_RETAINED', 'ROLLBACK_LEASES',
        'ROLLBACK_CONDITIONAL', 'ROLLBACK_PREVIOUS',
        'RB_NATIVE_QUERY', 'RB_NATIVE_FRAME', 'RB_NATIVE_WITNESS', 'RB_NATIVE_BIND', 'RB_NATIVE_LOADED',
        'RB_METADATA_PLAN', 'RB_METADATA_FIELDS', 'RB_INSTALLED_MATCH', 'RB_CORE_MATCH',
        'RB_EXPORTS_MATCH', 'RB_SIGNATURES_MATCH', 'RB_SIGNATURES_RENDERED', 'RB_EMPTY_EXPORTS',
        'ROLLBACK_APPROVED', 'ROLLBACK_UPDATE_PLAN',
        'ROLLBACK_UPDATED', 'RB_STALE_EMPTY', 'RB_STALE_COUNT', 'RB_STALE_CONTEXT_BYTES',
        'RB_STALE_CONTEXT_JSON', 'RB_STALE_JSON', 'RB_STALE_PUBLISHED', 'RB_RECORD_JSON', 'RB_RESULT_JSON',
        'RB_DOC_PARAMETERS', 'RB_DOC_OBSERVED', 'RB_DOC_REUSED', 'RB_DOC_STORED', 'RB_DOC_NONCE',
        'RB_DOC_ISSUED', 'RB_ERROR_RENDERED', 'RB_PROFILE_ERROR', 'RB_OUTCOME',
        'RB_COMMIT_MARKER', 'RB_CORE_HASH', 'RB_ABI_HASH', 'RB_DOCUMENT_HASH',
    )
    constants.update({name: value for value, name in enumerate(states, constants['INSPECTION_LOWERING_PROFILE_BOUND'] + 1)})
    purposes = (
        'ROLLBACK_OPEN', 'ROLLBACK_CLOSE_STALE', 'ROLLBACK_CLOSE_FAILED', 'ROLLBACK_CLOSE_COMMITTED',
        'ROLLBACK_READ_SLOT', 'ROLLBACK_READ_NATIVE', 'ROLLBACK_READ_DOC', 'ROLLBACK_WRITE_UPDATE',
        'ROLLBACK_WRITE_DOC', 'ROLLBACK_WRITE_TERMINAL', 'ROLLBACK_COMMIT',
    )
    constants.update({name: value for value, name in enumerate(purposes, constants['PROFILE_ROW'] + 1)})
    constants.update(ROLLBACK_FIELDS=3144, RB_NATIVE_FIELDS=3288, RB_FIELDS=3432,
                     RB_RECEIPTS=3576, RB_DOC_HASH=3720)
    reused_slots = (
        'INSPECTION_INPUT', 'INSPECTION_PENDING', 'INSPECTION_RECEIPT', 'INSPECTION_SELECTION',
        'INSPECTION_TEXT', 'INSPECTION_FACTS', 'INSPECTION_FRAMES', 'INSPECTION_LOWERING_PROFILE',
    )
    offsets = (*(constants[name] for name in reused_slots), *range(2944, 3136, 24), 3784, 3808, 3832)
    spans = (
        'ROLLBACK_ARGUMENTS', 'ROLLBACK_CONTEXT_ID', 'ROLLBACK_NAME', 'ROLLBACK_SLOT_CONTEXT',
        'ROLLBACK_SLOT_ABI', 'ROLLBACK_ACTIVE_REF', 'ROLLBACK_RETAINED_REF', 'ROLLBACK_PREVIOUS_VIEW',
        'ROLLBACK_UPDATED_VIEW', 'RB_NATIVE_INPUT', 'RB_NATIVE_METADATA', 'RB_INSTALLATION',
        'RB_DIGEST_SPAN', 'RB_SIGNATURES', 'RB_COUNT_TEXT', 'RB_DOCUMENT_RECEIPT',
        'RB_PAYLOAD', 'RB_DOC_KEY', 'RB_DOCUMENT_BYTES',
    )
    constants.update(dict(zip(spans, offsets, strict=True)))
    scalars = (
        'ROLLBACK_CURSOR', 'ROLLBACK_FIELD_INDEX', 'ROLLBACK_GENERATION', 'ROLLBACK_EXPECT_GENERATION',
        'ROLLBACK_EXPECT_EPOCH', 'ROLLBACK_CUSTODY', 'ROLLBACK_ROW_KIND', 'ROLLBACK_ROW_GENERATION',
        'ROLLBACK_ROW_RESUME', 'ROLLBACK_PRESENT', 'ROLLBACK_SLOT_GENERATION', 'ROLLBACK_SLOT_EPOCH',
        'ROLLBACK_COUNT', 'ROLLBACK_STATUS', 'ROLLBACK_APPROVED_EPOCH', 'ROLLBACK_ERROR',
        'ROLLBACK_ERROR_SCOPE', 'ROLLBACK_DURABLE', 'RB_RECEIPT_COUNT', 'RB_PROFILE_LEVEL',
    )
    constants.update({name: 3856 + 8 * index for index, name in enumerate(scalars)})
    words = {
        'ROLLBACK_REQUEST': b'HIARLQ01', 'ROLLBACK_DECISION': b'HIARLD01', 'ROLLBACK_ANSWER': b'HIARLA01',
        'ROLLBACK_QUERY': b'HIARLS01', 'ROLLBACK_OBSERVE': b'HIARLO01', 'ROLLBACK_BOUND_ROW': b'HIARLB01',
        'ROLLBACK_LEASE_COUNT': b'HIASTLC1', 'ROLLBACK_FORMAT_GENERATION': b'HIARLF01',
        'ROLLBACK_FORMAT_COUNT': b'HIARLN01', 'ROLLBACK_RECORD': b'HIARLR01', 'ROLLBACK_PUBLIC_ERROR': b'HIARLE01',
        'RB_NATIVE_OBSERVE': b'HIAARN01', 'RB_NATIVE_ARTIFACT': b'HIAARN02', 'RB_METADATA_TAG': b'HIAANM01',
        'RB_COMPARE': b'HIAABC01', 'RB_MATCH': b'HIAABR01', 'RB_OUTCOME_REQUEST': b'HIARLT01',
        'RB_OUTCOME_TAG': b'HIAIND01', 'RB_DOCUMENT_RECEIPT_TAG': b'HIADOC01',
        'RB_LOOKUP_DOC': b'HIADAL01', 'RB_DOCUMENT_OBSERVE': b'HIARLP01', 'RB_DOC_BOUND': b'HIARLP02',
        'RB_ISSUE_DOC': b'HIADAI01', 'RB_DOC_ISSUED_TAG': b'HIADAR01', 'STORE_PUT': b'store-pu',
        'STORE_PUT_END': b't', 'ROLLBACK_COMMIT_TAG': b'HIARLC01', 'RB_COMMITTED_TAG': b'HIASTCP1',
        'NULL_VALUE': b'null',
    }
    constants.update({name: int.from_bytes(word, 'little') for name, word in words.items()})
    # Rollback never starts an effect reactor: this state machine holds the
    # original request and the pending physical Store transaction itself.
    driver = worker.DRIVER.replace('def inspection_flow(', 'def rollback_flow(')
    start = driver.index('    if state <= INSPECTION_PEER_CLOSED:')
    end = driver.index('\ndef inspection_catalog', start)
    driver = driver[:start] + '''    if state >= INSPECTION_CONTEXT_REFERENCE and state <= INSPECTION_PROFILE_BOUND:
        return inspect_retained(s, o, w, state)
    if state >= ROLLBACK_PROJECTED and state <= ROLLBACK_RANGE:
        return rollback_request(s, o, w, state)
    if state >= ROLLBACK_ROW_PLAN and state <= ROLLBACK_PREVIOUS:
        return rollback_row_state(s, o, w, state)
    if state >= RB_NATIVE_QUERY and state <= ROLLBACK_UPDATE_PLAN:
        return rollback_native_state(s, o, w, state)
    if state == RB_COMMIT_MARKER:
        if length(s) != 72 or input_word(s, 64) != RB_COMMITTED_TAG:
            return BAD
        return close_store(o, w, ROLLBACK_CLOSE_COMMITTED)
    if state == INSPECTION_HASH_RETURNED:
        size = input_word(s, 40)
        if size < 88 or size > 100:
            return BAD
        return read_span(o, w, INSPECTION_HASH_FRAME, input_word(s, 32), 0, size)
    if state == INSPECTION_HASH_FRAME:
        return inspection_hash_result(s, o, w)
    return rollback_document_state(s, o, w, state)
''' + driver[end:]
    startup = function(driver, 'install_inspection')
    direct = startup[startup.index('        put(o, HEADER, ADMISSION)'): startup.rindex('    return BAD')]
    startup = startup[:startup.index('        return installation_profile_request(o, w, True)')] + direct + '    return BAD\n'
    driver = replace_function(driver, 'install_inspection', startup)
    journal = function(driver, 'inspection_journal_plan')
    driver = replace_function(driver, 'inspection_journal_plan', journal.replace(
        '    after_prefix(w, o, ARGUMENT_FD, 0)', '    inspection_catalog(o, w)\n    after_prefix(w, o, ARGUMENT_FD, 0)',
    ).replace('0, 2, inline)', '0, 2, 68)'))
    wire = (function(worker.DOCUMENT_DRIVER, 'vector_span'), function(worker.DOCUMENT_DRIVER, 'wide_inspection'))
    hashed = (function(worker.VIEW_DRIVER, 'inspection_hash'),
              function(worker.VIEW_DRIVER, 'inspection_hash_result').replace('inspection_hash_bound(', 'rollback_hash_bound('))
    return flow_source(driver, (REQUEST, ROWS, NATIVE, PUBLICATION, CUSTODY, *retained_controls(), *wire, *hashed,
                                *control_source(controls)), constants)


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)), encoding='utf-8')
