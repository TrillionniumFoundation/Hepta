"""Author the descriptor driver for the installed HIA Inspection effect."""

from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_worker_context_flow import (
    ARTIFACT, COST, DESCRIBE, ENTRY_POLICY, MANIFEST_POLICY, POLICY as CONTEXT,
    PUBLICATION, READ_POLICY, RELEASE_WRITER, RETAINED_POLICY, STORE,
    entry_program, flow_source, function, policy_constants,
)

SOURCE = Path('examples/hia_bootstrap/worker_inspection_flow.hepta')

DRIVER = r'''
def inspection_flow(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 8 or length(o) != 2048 or length(w) != 4096:
        return BAD
    state = get(w, 0)
    if state == 0:
        return artifact_entry(s, o, w)
    if length(s) < 64 or input_word(s, 0) != OBSERVATION or input_word(s, 8) != get(w, 8):
        return BAD
    operation = get(w, 16)
    if input_word(s, 16) != operation or input_word(s, 24) != 0:
        return BAD
    extent = input_word(s, 40)
    offset = choose(operation == RUN or operation == MAKE, 0, input_word(s, 48))
    captured = input_word(s, 56)
    if extent > 67112960 or offset > extent or captured > extent - offset or captured != length(s) - 64:
        return BAD
    if (operation == RUN or operation == MAKE) and valid_fd(input_word(s, 32)) == False:
        return BAD
    if operation == READ and (input_word(s, 32) != get(w, 80) or offset != get(w, 88) or captured != get(w, 96)):
        return BAD
    if state <= INSPECTION_LOWERING_PROFILE_BOUND and state >= INSPECTION_CLOCK:
        return install_inspection(s, o, w, state)
    if state <= ARGUMENT_PLAN:
        return project_request(s, o, w, state)
    if state <= JOURNAL_RECIPE:
        return observe_journal(s, o, w, state)
    if state <= TYPED:
        return typed_job(s, o, w, state)
    if state <= PEER_CLOSED:
        return observe_store(s, o, w, state)
    if state == LOOKUP_AUDITED:
        return lookup_observation(s, o, w, state)
    if state == ERROR_RENDERED:
        if extent == 0:
            return BAD
        observe_slot(s, w, EFFECT_FD)
        return end_effect(o, w, 2, 0)
    if state <= REPORT_PUBLISHED:
        return publish_artifact(s, o, w, state)
    if state <= INSPECTION_PEER_CLOSED:
        return inspection_effect(s, o, w, state)
    if state <= INSPECTION_PROFILE_BOUND:
        return inspect_retained(s, o, w, state)
    return inspection_render(s, o, w, state)

def inspection_catalog(o:mutbuf, w:mutbuf) -> u64:
    put(o, HEADER, 8795)
    copy_private(w, o, TRUST, HEADER + 2, 64)
    store(o, HEADER + 66, 34)
    store(o, HEADER + 67, 44)
    return 0

def install_inspection(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    if state == INSPECTION_CLOCK:
        if length(s) != 72 or input_word(s, 40) != 8:
            return BAD
        put(w, START_TIME, input_word(s, 64))
        put(o, HEADER, INSTALL_MANIFEST_REF)
        whole_slot(w, o, METADATA_FD, 0)
        return action(o, w, INSPECTION_INSTALL_REFERENCE, RUN, PROFILE_ROLE, 0, 1, 8)
    if state == INSPECTION_INSTALL_REFERENCE:
        if plan_ok(s) == False or input_word(s, 40) != 184:
            return BAD
        body_span(s, w, INSPECTION_REFERENCE)
        put(w, RETAINED_PURPOSE, READ_INSTALLATION)
        return inspection_retained_query(o, w, 0)
    if state == INSPECTION_INSTALL_PINS:
        if plan_ok(s) == False or input_word(s, 40) != 136:
            return BAD
        return read_span(o, w, INSPECTION_PIN_FRAME, input_word(s, 32), 8, 128)
    if state == INSPECTION_PIN_FRAME:
        i = 0
        while i < 128:
            digit = byte(s, 64 + i)
            if is_hex(digit) == False:
                return BAD
            store(w, PROFILE_PIN + i, digit)
            i = i + 1
        return installation_profile_request(o, w, True)
    if state == INSPECTION_LOWERING_PROFILE_BOUND:
        if plan_ok(s) == False or input_word(s, 40) != 108:
            return BAD
        body_span(s, w, INSPECTION_LOWERING_PROFILE)
        put(o, HEADER, ADMISSION)
        put(o, HEADER + 8, get(w, 24))
        copy_private(w, o, TRUST, HEADER + 16, 64)
        whole_slot(w, o, ORIGINAL, 0)
        return action(o, w, REQUEST_ADMITTED, RUN, ADMIT_ROLE, 0, 1, 80)
    return BAD

def installation_profile_request(o:mutbuf, w:mutbuf, lowering:bool) -> u64:
    inspection_catalog(o, w)
    use_span(w, o, INSPECTION_INSTALL_MANIFEST, 0)
    if lowering:
        put(o, 480, LOWERING_SELECT_0)
        put(o, 488, LOWERING_SELECT_1)
        fragment(o, 1, INLINE_FRAGMENT, 480, 12)
        return action(o, w, INSPECTION_LOWERING_PROFILE_BOUND, RUN, PLAN_ROLE, 0, 2, 68)
    store(o, 496, 93)
    fragment(o, 1, INLINE_FRAGMENT, 496, 1)
    return action(o, w, INSPECTION_INSTALL_PINS, RUN, PLAN_ROLE, 0, 2, 68)

def inspection_journal_plan(o:mutbuf, w:mutbuf, state:u64, inline:u64) -> u64:
    after_prefix(w, o, ARGUMENT_FD, 0)
    put(o, 496, JOURNAL_NULL_SUFFIX)
    fragment(o, 1, INLINE_FRAGMENT, 496, 6)
    return action(o, w, state, RUN, INSPECTION_REQUEST_ROLE, 0, 2, inline)
'''

EFFECT_DRIVER = r'''
def authorize_business(o:mutbuf, w:mutbuf) -> u64:
    # The Journal's authorization precedes projection and effect execution.
    inspection_catalog(o, w)
    after_prefix(w, o, ARGUMENT_FD, 0)
    store(o, 496, 93)
    fragment(o, 1, INLINE_FRAGMENT, 496, 1)
    return action(o, w, INSPECTION_PLAN, RUN, INSPECTION_REQUEST_ROLE, 0, 2, 68)

def inspection_effect(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    if state == INSPECTION_PLAN:
        if plan_ok(s) == False or input_word(s, 40) < 50 or input_word(s, 40) > 2608:
            return BAD
        body_span(s, w, INSPECTION_INPUT)
        put(o, 176, INSPECTION_PEER)
        return action(o, w, INSPECTION_PEER_OPEN, START_PEER, INSPECTION_EFFECT_ROLE, 0, 0, 0)
    if state == INSPECTION_PEER_OPEN:
        if length(s) != 80 or input_word(s, 40) != 16:
            return BAD
        return inspection_feedback(o, w, 1, 0, INSPECTION_INPUT)
    if state == INSPECTION_SENT:
        if length(s) != 64:
            return BAD
        return receive(o, w, INSPECTION_LENGTH, INSPECTION_PEER, 8, False)
    if state == INSPECTION_LENGTH:
        bytes = input_word(s, 64)
        if length(s) != 72 or input_word(s, 40) != 8 or bytes < 48 or bytes > 8192:
            return BAD
        put(w, INSPECTION_BYTES, bytes)
        return receive(o, w, INSPECTION_ACTION, INSPECTION_PEER, bytes, True)
    if state == INSPECTION_ACTION:
        return inspect_command(s, o, w)
    if state == INSPECTION_PEER_CLOSED and length(s) == 64:
        return end_effect(o, w, get(w, INSPECTION_STATUS), 116)
    return BAD

def inspect_command(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    total = get(w, INSPECTION_BYTES)
    seq = get(w, INSPECTION_SEQUENCE) + 1
    fd = input_word(s, 32)
    if input_word(s, 40) != total or length(s) != total + 64 or valid_fd(fd) == False:
        return BAD
    if input_word(s, 64) != INSPECTION_ACTION_TAG or input_word(s, 80) != seq or seq > 8:
        return BAD
    bytes = total - 48
    if input_word(s, 96) != 0 or input_word(s, 104) != bytes:
        return BAD
    put(w, INSPECTION_SEQUENCE, seq)
    role = input_word(s, 72)
    kind = input_word(s, 88)
    hold(w, INSPECTION_ACTUAL, fd, 48, bytes)
    if role == 1 and seq == 1 and kind == 0 and bytes >= 2 and bytes <= 320:
        return inspection_context(o, w)
    if role == 2 and seq == 2 and kind == 0 and bytes >= 2 and bytes <= 512:
        return inspection_program(o, w)
    if role == 3 and seq == 3 and kind >= 1 and kind <= 5:
        return inspection_view(o, w, kind, bytes)
    if role == 4 and seq >= 4 and seq <= 6 and bytes == 64:
        if equal_inspection_digest(s, w, 112) == False:
            return BAD
        return inspection_publish(o, w, kind, seq)
    if role == 5 and seq == 5 and kind == 0 and bytes == 176:
        return inspection_lowering(o, w)
    if role == 6 or role == 7:
        return inspection_result(s, o, w, role, bytes)
    return BAD

def equal_inspection_digest(s:readbuf, w:mutbuf, at:u64) -> bool:
    i = 0
    while i < 64:
        if byte(s, at + i) != byte(w, INSPECTION_DIGEST + i):
            return False
        i = i + 1
    return True

def inspection_result(s:readbuf, o:mutbuf, w:mutbuf, role:u64, bytes:u64) -> u64:
    if bytes < 70 or input_word(s, 112) != INSPECTION_OUTCOME_TAG:
        return BAD
    status = input_word(s, 120)
    context = input_word(s, 128)
    if status != role - 5 or (context != 0 and context != 36) or input_word(s, 136) != bytes - 68:
        return BAD
    put(w, INSPECTION_STATUS, status)
    hold(w, INSPECTION_OUTCOME, input_word(s, 32), 48, bytes)
    observe_slot(s, w, EFFECT_FD)
    put(o, 176, INSPECTION_PEER)
    return action(o, w, INSPECTION_PEER_CLOSED, FINISH_PEER, 0, 0, 0, 0)

def inspection_feedback(o:mutbuf, w:mutbuf, event:u64, status:u64, data:u64) -> u64:
    extent = 0
    if data != 0:
        extent = get(w, data + 16)
        if extent > 8192:
            return BAD
        use_span(w, o, data, 0)
    put(o, HEADER, INSPECTION_EVENT_TAG)
    put(o, HEADER + 8, event)
    put(o, HEADER + 16, get(w, INSPECTION_SEQUENCE) + 1)
    put(o, HEADER + 24, status)
    put(o, HEADER + 32, extent)
    put(o, 176, INSPECTION_PEER)
    return action(o, w, INSPECTION_SENT, SEND_PEER, 0, 0, choose(data != 0, 1, 0), 40)

def inspection_feedback_digest(o:mutbuf, w:mutbuf, event:u64) -> u64:
    put(o, HEADER, INSPECTION_EVENT_TAG)
    put(o, HEADER + 8, event)
    put(o, HEADER + 16, get(w, INSPECTION_SEQUENCE) + 1)
    put(o, HEADER + 24, 0)
    put(o, HEADER + 32, 64)
    copy_private(w, o, INSPECTION_DIGEST, HEADER + 40, 64)
    put(o, 176, INSPECTION_PEER)
    return action(o, w, INSPECTION_SENT, SEND_PEER, 0, 0, 0, 104)
'''

VIEW_DRIVER = r'''
def inspection_view(o:mutbuf, w:mutbuf, mode:u64, bytes:u64) -> u64:
    put(w, INSPECTION_VIEW, mode)
    if mode == 5:
        if bytes != 0:
            return BAD
        return inspection_object(o, w)
    if mode == 1:
        if bytes != 0:
            return BAD
        if get(w, INSPECTION_STRUCTURED + 16) != 0:
            return inspection_frame_request(o, w, INSPECTION_PROBE_FRAME, 6, 0)
        return inspection_frame_request(o, w, INSPECTION_VIEW_FRAME, 1, 0)
    return inspection_frame_request(o, w, INSPECTION_VIEW_FRAME, mode, INSPECTION_ACTUAL)

def inspection_frame_request(o:mutbuf, w:mutbuf, state:u64, mode:u64, payload:u64) -> u64:
    put(o, HEADER, INSPECTION_FRAME_TAG)
    put(o, HEADER + 8, mode)
    if payload != 0:
        use_span(w, o, payload, 0)
    return action(o, w, state, RUN, INSPECTION_REQUEST_ROLE, 0, choose(payload != 0, 1, 0), 16)

def inspection_render(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    if state == INSPECTION_PROBE_FRAME:
        return inspect_wire(s, o, w, INSPECTION_PROBE, INSPECTION_STRUCTURED)
    if state == INSPECTION_PROBE:
        version = input_word(s, 64)
        if input_word(s, 40) != 8 or version < 1 or version > 4:
            return BAD
        put(w, INSPECTION_VERSION, version)
        return inspection_hash(o, w, INSPECTION_NOMINAL_READY, INSPECTION_STRUCTURED)
    if state == INSPECTION_VIEW_FRAME:
        return inspect_wire(s, o, w, INSPECTION_VIEW_BODY, INSPECTION_CORE)
    if state == INSPECTION_VIEW_BODY:
        if get(w, INSPECTION_VIEW) == 4:
            return inspection_dependency(s, o, w)
        if input_word(s, 40) == 8:
            status = input_word(s, 64)
            if status < 4294967288 or status > 4294967290:
                return BAD
            return inspection_feedback(o, w, 4, status, 0)
        if plan_ok(s) == False:
            return BAD
        return canonicalize_inspection(s, o, w, INSPECTION_VIEW_CANONICAL)
    if state == INSPECTION_VIEW_CANONICAL:
        if prefixed(s) == False:
            return BAD
        body_span(s, w, INSPECTION_PENDING)
        return inspection_hash(o, w, INSPECTION_VIEW_READY, INSPECTION_PENDING)
    if state == INSPECTION_HASH_RETURNED:
        size = input_word(s, 40)
        if size < 75 or size >= 160:
            return BAD
        return read_span(o, w, INSPECTION_HASH_FRAME, input_word(s, 32), 0, size)
    if state == INSPECTION_HASH_FRAME:
        return inspection_hash_result(s, o, w)
    if state == INSPECTION_DOCUMENT:
        if input_word(s, 40) != 200:
            return BAD
        sample_span(s, w, INSPECTION_RECEIPT)
        kind = get(w, INSPECTION_KIND)
        return inspection_feedback(o, w, choose(kind == 5, 7, 5), kind, INSPECTION_RECEIPT)
    if state >= INSPECTION_DEPENDENCY_SELECTION and state <= INSPECTION_LOWERING_CANONICAL:
        return inspection_extended_view(s, o, w, state)
    return BAD

def inspect_wire(s:readbuf, o:mutbuf, w:mutbuf, state:u64, payload:u64) -> u64:
    if plan_ok(s) == False or input_word(s, 40) != 9480:
        return BAD
    fragment(o, 0, input_word(s, 32), 8, 9472)
    use_span(w, o, payload, 1)
    return action(o, w, state, RUN, INSPECTION_WIRE_ROLE, 0, 2, 0)

def canonicalize_inspection(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    put(o, HEADER, get(w, 24))
    fragment(o, 0, input_word(s, 32), 8, input_word(s, 40) - 8)
    return action(o, w, state, RUN, INSPECTION_CANONICAL_ROLE, 0, 1, 8)

def inspection_hash(o:mutbuf, w:mutbuf, state:u64, data:u64) -> u64:
    put(w, INSPECTION_HASH_RESUME, state)
    put(o, 416, 45)
    use_span(w, o, data, 0)
    return artifact_command(o, w, INSPECTION_HASH_RETURNED, STORE_HASH, STORE_HASH_END, 1)

def inspection_hash_result(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    at = 64
    while at + 75 <= length(s):
        if (input_word(s, at) == SHA_JSON and byte(s, at + 8) == 58
                and byte(s, at + 9) == 34 and byte(s, at + 74) == 34):
            i = 0
            while i < 64 and is_hex(byte(s, at + 10 + i)):
                i = i + 1
            if i == 64:
                return inspection_hash_bound(s, o, w, at + 10)
        at = at + 1
    return BAD

def inspection_hash_bound(s:readbuf, o:mutbuf, w:mutbuf, at:u64) -> u64:
    resume = get(w, INSPECTION_HASH_RESUME)
    if resume == INSPECTION_VIEW_READY or resume == INSPECTION_LOWERING_READY:
        copy_span(s, w, at, INSPECTION_DIGEST, 64)
        return inspection_feedback_digest(o, w, choose(resume == INSPECTION_VIEW_READY, 4, 6))
    if resume == INSPECTION_CORE_READY:
        copy_span(s, w, at, INSPECTION_CORE_HASH, 64)
        return inspection_hash(o, w, INSPECTION_VIEW_READY, INSPECTION_PENDING)
    if resume == INSPECTION_QUERY_READY:
        copy_span(s, w, at, INSPECTION_SOURCE_HASH, 64)
        return inspection_query(o, w)
    if resume == INSPECTION_NOMINAL_READY:
        put(o, HEADER, INSPECTION_FRAME_TAG)
        put(o, HEADER + 8, 7)
        put(o, HEADER + 16, get(w, INSPECTION_VERSION))
        copy_span(s, o, at, HEADER + 24, 64)
        return action(o, w, INSPECTION_VIEW_FRAME, RUN, INSPECTION_REQUEST_ROLE, 0, 0, 88)
    return BAD
'''

DOCUMENT_DRIVER = r'''
def inspection_publish(o:mutbuf, w:mutbuf, kind:u64, seq:u64) -> u64:
    view = get(w, INSPECTION_VIEW)
    if seq == 4:
        if kind != choose(view >= 4, view + 2, 5):
            return BAD
    elif kind != 5 or seq != choose(view == 4, 5, 6) or view < 4:
        return BAD
    put(w, INSPECTION_KIND, kind)
    launch_directory(w, o, 0)
    role_argument(w, o, 2, STORE_ROLE)
    role_argument(w, o, 3, READY_ROLE)
    role_argument(w, o, 4, UNIQUE_ROLE)
    role_argument(w, o, 5, PUBLISHER_ROLE)
    role_argument(w, o, 6, DOCUMENT_PLAN_ROLE)
    role_argument(w, o, 7, DOCUMENT_EFFECT_ROLE)
    argv(o, 8, DECIMAL_ARG, kind)
    argv(o, 9, DECIMAL_ARG, 0)
    use_span(w, o, INSPECTION_PENDING, 0)
    return action(o, w, INSPECTION_DOCUMENT, RUN, DOCUMENT_ROLE, 10, 1, 0)

def inspection_dependency(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    status = input_word(s, 72)
    if plan_ok(s) == False or input_word(s, 40) != 16 or status > 3:
        return BAD
    if status != 0:
        return inspection_feedback(o, w, 4, status, 0)
    put(o, HEADER, INSPECTION_DEPENDENCY_TAG)
    use_span(w, o, INSPECTION_ACTUAL, 0)
    return action(o, w, INSPECTION_DEPENDENCY_SELECTION, RUN, INSPECTION_REQUEST_ROLE, 0, 1, 8)

def inspection_query(o:mutbuf, w:mutbuf) -> u64:
    structured = get(w, INSPECTION_STRUCTURED + 16) != 0
    put(o, 384, QUERY_OPTION_0)
    put(o, 392, QUERY_OPTION_1)
    argv(o, 0, LITERAL_ARG, 384)
    if structured:
        copy_private(w, o, INSPECTION_SOURCE_HASH, 400, 64)
        store(o, 464, 0)
        argv(o, 1, LITERAL_ARG, 400)
    store(o, HEADER, 91)
    store(o, 480, 44)
    store(o, 481, 93)
    vector_span(w, o, INSPECTION_CORE, HEADER + 1)
    vector_part(o, HEADER + 25, INLINE_FRAGMENT, 480, 1)
    vector_span(w, o, INSPECTION_SELECTION, HEADER + 49)
    vector_part(o, HEADER + 73, INLINE_FRAGMENT, 481, 1)
    return wide_inspection(o, w, INSPECTION_QUERY_RESULT, INSPECTION_QUERY_ROLE,
                           choose(structured, 2, 1), 4, 1)

def inspection_object(o:mutbuf, w:mutbuf) -> u64:
    size = get(w, INSPECTION_EXPORTS + 16)
    if size < 2:
        return BAD
    if size == 2:
        return read_span(o, w, INSPECTION_EXPORTS_CHECKED, get(w, INSPECTION_EXPORTS),
                         get(w, INSPECTION_EXPORTS + 8), 2)
    return inspection_emit(o, w, False)

def inspection_emit(o:mutbuf, w:mutbuf, empty:bool) -> u64:
    if empty:
        use_span(w, o, INSPECTION_CORE, 0)
        return action(o, w, INSPECTION_OBJECT_RESULT, RUN, INSPECTION_EMIT_ROLE, 0, 1, 0)
    store(o, HEADER, 91)
    store(o, 480, 44)
    put(o, 488, OBJECT_EXPORT_SUFFIX)
    vector_span(w, o, INSPECTION_CORE, HEADER + 1)
    vector_part(o, HEADER + 25, INLINE_FRAGMENT, 480, 1)
    vector_span(w, o, INSPECTION_EXPORTS, HEADER + 49)
    vector_part(o, HEADER + 73, INLINE_FRAGMENT, 488, 5)
    return wide_inspection(o, w, INSPECTION_OBJECT_RESULT, INSPECTION_EMIT_ROLE, 0, 4, 1)

def inspection_lowering(o:mutbuf, w:mutbuf) -> u64:
    if get(w, INSPECTION_VIEW) != 5:
        return BAD
    return inspection_frame_request(o, w, INSPECTION_LOWERING_FRAME, 8, 0)

def bind_lowering_description(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if plan_ok(s) == False or input_word(s, 40) != 9480:
        return BAD
    # The 9472-byte control packet is followed by three extents, two
    # digests, and the current immutable text/frame/profile/reference spans.
    body_span(s, w, INSPECTION_FACTS)
    put(o, HEADER, get(w, INSPECTION_TEXT + 16))
    put(o, HEADER + 8, get(w, INSPECTION_FRAMES + 16))
    put(o, HEADER + 16, get(w, INSPECTION_LOWERING_PROFILE + 16))
    copy_private(w, o, INSPECTION_CORE_HASH, HEADER + 24, 64)
    copy_private(w, o, INSPECTION_DIGEST, HEADER + 88, 64)
    return action(o, w, INSPECTION_LOWERING_EXTENTS, MAKE, 0, 0, 0, 152)

def join_lowering_description(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if input_word(s, 40) != 152:
        return BAD
    vector_span(w, o, INSPECTION_FACTS, HEADER)
    vector_part(o, HEADER + 24, input_word(s, 32), 0, 152)
    vector_span(w, o, INSPECTION_TEXT, HEADER + 48)
    vector_span(w, o, INSPECTION_FRAMES, HEADER + 72)
    vector_span(w, o, INSPECTION_LOWERING_PROFILE, HEADER + 96)
    vector_span(w, o, INSPECTION_ACTUAL, HEADER + 120)
    return wide_inspection(o, w, INSPECTION_LOWERING_BODY, INSPECTION_WIRE_ROLE, 0, 6, 0)

def inspection_extended_view(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    size = input_word(s, 40)
    if state == INSPECTION_DEPENDENCY_SELECTION:
        if plan_ok(s) == False or size <= 8 or size > 4096:
            return BAD
        body_span(s, w, INSPECTION_SELECTION)
        if get(w, INSPECTION_STRUCTURED + 16) != 0:
            return inspection_hash(o, w, INSPECTION_QUERY_READY, INSPECTION_STRUCTURED)
        return inspection_query(o, w)
    if state == INSPECTION_QUERY_RESULT:
        if size < 2:
            return BAD
        sample_span(s, w, INSPECTION_PENDING)
        return inspection_hash(o, w, INSPECTION_VIEW_READY, INSPECTION_PENDING)
    if state == INSPECTION_EXPORTS_CHECKED:
        empty = byte(s, 64) == 91 and byte(s, 65) == 93
        return inspection_emit(o, w, empty)
    if state == INSPECTION_OBJECT_RESULT:
        if size < 64 or input_word(s, 64) & 4294967295 != ELF_MAGIC:
            return BAD
        sample_span(s, w, INSPECTION_PENDING)
        use_span(w, o, INSPECTION_PENDING, 0)
        return action(o, w, INSPECTION_OBJECT_FACTS, RUN, INSPECTION_ELF_ROLE, 0, 1, 0)
    if state == INSPECTION_OBJECT_FACTS:
        offset = input_word(s, 80)
        extent = input_word(s, 88)
        count = input_word(s, 96)
        object_bytes = get(w, INSPECTION_PENDING + 16)
        if (plan_ok(s) == False or size < 48 or size > 8232 or input_word(s, 72) != INSPECTION_ELF_FACTS
                or count > 1024 or count * 8 + 40 != size or offset > object_bytes
                or extent > object_bytes - offset):
            return BAD
        hold(w, INSPECTION_TEXT, get(w, INSPECTION_PENDING), offset, extent)
        body_span(s, w, INSPECTION_FACTS)
        return inspection_frame_request(o, w, INSPECTION_OBJECT_FRAME, 9, INSPECTION_FACTS)
    if state == INSPECTION_OBJECT_FRAME:
        if plan_ok(s) == False or size != 9480:
            return BAD
        fragment(o, 0, input_word(s, 32), 8, 9472)
        use_span(w, o, INSPECTION_CORE, 1)
        return action(o, w, INSPECTION_FRAME_BODY, RUN, INSPECTION_FRAMES_ROLE, 0, 2, 0)
    if state == INSPECTION_FRAME_BODY:
        if plan_ok(s) == False:
            return BAD
        return canonicalize_inspection(s, o, w, INSPECTION_FRAME_CANONICAL)
    if state == INSPECTION_FRAME_CANONICAL:
        if prefixed(s) == False:
            return BAD
        body_span(s, w, INSPECTION_FRAMES)
        return inspection_hash(o, w, INSPECTION_CORE_READY, INSPECTION_CORE)
    if state == INSPECTION_LOWERING_FRAME:
        return bind_lowering_description(s, o, w)
    if state == INSPECTION_LOWERING_EXTENTS:
        return join_lowering_description(s, o, w)
    if state == INSPECTION_LOWERING_BODY:
        if plan_ok(s) == False:
            return BAD
        return canonicalize_inspection(s, o, w, INSPECTION_LOWERING_CANONICAL)
    if state == INSPECTION_LOWERING_CANONICAL:
        if prefixed(s) == False:
            return BAD
        body_span(s, w, INSPECTION_PENDING)
        return inspection_hash(o, w, INSPECTION_LOWERING_READY, INSPECTION_PENDING)
    return BAD

def vector_span(w:mutbuf, o:mutbuf, record:u64, at:u64) -> u64:
    return vector_part(o, at, get(w, record), get(w, record + 8), get(w, record + 16))

def wide_inspection(o:mutbuf, w:mutbuf, state:u64, role:u64, args:u64, parts:u64, inline:u64) -> u64:
    total = action(o, w, state, RUN, role, args, parts, inline)
    if total == BAD:
        return BAD
    put(o, 136, 1)
    return total + 24 * parts
'''

RETAINED_DRIVER = r'''
def inspection_context(o:mutbuf, w:mutbuf) -> u64:
    use_span(w, o, INSPECTION_ACTUAL, 0)
    return action(o, w, INSPECTION_CONTEXT_REFERENCE, RUN, INSPECTION_CONTEXT_ROLE, 0, 1, 0)

def inspection_program(o:mutbuf, w:mutbuf) -> u64:
    put(w, RETAINED_PURPOSE, READ_PROGRAM)
    move_fragment(w, INSPECTION_ACTUAL, INSPECTION_REFERENCE)
    return inspection_retained_query(o, w, 0)

def inspection_retained_query(o:mutbuf, w:mutbuf, kind:u64) -> u64:
    put(w, RETAINED_KIND, kind)
    put(o, HEADER, choose(kind == 0, RETAINED_QUERY_ANY, RETAINED_QUERY_KIND))
    put(o, HEADER + 8, kind)
    use_span(w, o, INSPECTION_REFERENCE, 0)
    return action(o, w, RETAINED_QUERY_BOUND, RUN, PROFILE_ROLE, 0, 1, 16)

def inspection_refused(o:mutbuf, w:mutbuf, corruption:bool) -> u64:
    reason = get(w, RETAINED_PURPOSE)
    if reason == READ_CONTEXT:
        return inspection_feedback(o, w, 2, choose(corruption, 6, 5), 0)
    if reason == READ_PROFILE and corruption == False:
        return inspection_feedback(o, w, 2, 3, 0)
    if reason == READ_PROGRAM:
        return inspection_feedback(o, w, 3, 1, 0)
    return BAD

def inspect_retained(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    if state == INSPECTION_CONTEXT_REFERENCE:
        if reply_word(s, RETAINED_REFUSAL):
            return inspection_feedback(o, w, 2, 1, 0)
        if plan_ok(s) == False or input_word(s, 40) != 116 or input_word(s, 72) != CONTEXT_REFERENCE_TAG:
            return BAD
        hold(w, INSPECTION_REFERENCE, input_word(s, 32), 16, 100)
        put(o, HEADER, CONTEXT_QUERY_TAG)
        fragment(o, 0, input_word(s, 32), 16, 36)
        return action(o, w, INSPECTION_CONTEXT_QUERY, RUN, CONTEXT_BIND_ROLE, 0, 1, 8)
    if state == INSPECTION_CONTEXT_QUERY:
        if plan_ok(s) == False or input_word(s, 40) != 100:
            return BAD
        observe_slot(s, w, QUERY_FD)
        return open_store(o, w, OPEN_CONTEXT_ROW)
    if state == INSPECTION_CONTEXT_OBSERVED:
        status = input_word(s, 80)
        if plan_ok(s) == False or input_word(s, 40) < 24 or input_word(s, 72) != CONTEXT_OBSERVED_TAG or status > 2:
            return BAD
        if status != 0:
            return close_store(o, w, CLOSE_CONTEXT_UNAVAILABLE)
        if input_word(s, 40) < 217:
            return BAD
        hold(w, INSPECTION_REFERENCE, input_word(s, 32), 40, 176)
        return close_store(o, w, CLOSE_CONTEXT_ROW)
    if state == RETAINED_QUERY_BOUND:
        if reply_word(s, RETAINED_REFUSAL):
            return inspection_refused(o, w, False)
        if plan_ok(s) == False or input_word(s, 40) != 98:
            return BAD
        observe_slot(s, w, QUERY_FD)
        return open_store(o, w, OPEN_RETAINED_ROW)
    if state == RETAINED_ROW_BOUND:
        if reply_word(s, RETAINED_REFUSAL) or reply_word(s, RETAINED_CORRUPT):
            put(w, RETAINED_ERROR, choose(reply_word(s, RETAINED_CORRUPT), 2, 1))
            return close_store(o, w, CLOSE_RETAINED_REFUSED)
        if plan_ok(s) == False or input_word(s, 40) != 80:
            return BAD
        observe_slot(s, w, PROFILE_FD)
        return close_store(o, w, CLOSE_RETAINED_ROW)
    if state == RETAINED_DIGEST:
        return capture_retained_inspection(s, o, w)
    if state == RETAINED_BYTES:
        return open_recovered_inspection(s, o, w)
    if state == INSPECTION_PROGRAM_ADMITTED:
        return bind_inspection_program(s, o, w)
    return inspect_manifest(s, o, w, state)

def capture_retained_inspection(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if length(s) != 136 or input_word(s, 64) != RETAINED_AUTHORITY:
        return BAD
    i = 0
    while i < 64:
        c = byte(s, 72 + i)
        if is_hex(c) == False:
            return BAD
        store(o, 416 + i, c)
        i = i + 1
    store(o, 480, 0)
    return artifact_command(o, w, RETAINED_BYTES, STORE_GET, STORE_GET_END, 0)

def open_recovered_inspection(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    size = input_word(s, 40)
    reason = get(w, RETAINED_PURPOSE)
    if size < 2:
        return BAD
    if reason == READ_INSTALLATION:
        sample_span(s, w, INSPECTION_INSTALL_MANIFEST)
        return installation_profile_request(o, w, False)
    if reason == READ_PROFILE:
        if get(w, INSPECTION_FIELD) == 0:
            move_fragment(w, INSPECTION_PROFILE_1 + 24, INSPECTION_REFERENCE)
            return inspect_profile(o, w, 1)
        return inspection_feedback(o, w, 2, 0, 0)
    if reason == READ_PROGRAM:
        fragment(o, 0, input_word(s, 32), 0, size)
        return action(o, w, INSPECTION_PROGRAM_ADMITTED, RUN, NOMINAL_ROLE, 0, 1, 0)
    if reason != READ_CONTEXT:
        return BAD
    store(o, 492, 44)
    store(o, 493, 93)
    inspection_catalog(o, w)
    vector_part(o, HEADER + 68, slot_fd(w, DOSSIER_FD), DOSSIER_HEAD + get(w, 40), get(w, 48))
    vector_part(o, HEADER + 92, INLINE_FRAGMENT, 492, 1)
    vector_part(o, HEADER + 116, input_word(s, 32), 0, size)
    vector_part(o, HEADER + 140, INLINE_FRAGMENT, 493, 1)
    return wide_inspection(o, w, INSPECTION_CONTEXT_MANIFEST, INSPECTION_CONTEXT_ROLE, 0, 4, 68)

def bind_inspection_program(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    size = input_word(s, 40)
    profile = input_word(s, 88)
    types = input_word(s, 96)
    body = input_word(s, 104)
    if (length(s) != 128 or size < 64 or input_word(s, 64) != NOMINAL_PACKET
            or input_word(s, 72) != 0 or input_word(s, 80) != 0 or profile > 4
            or types == 0 or body == 0 or types > size - 64 or body != size - 64 - types
            or input_word(s, 112) != 0 or input_word(s, 120) != 0):
        return BAD
    fd = input_word(s, 32)
    if profile != 0:
        hold(w, INSPECTION_STRUCTURED, fd, 64, types)
    hold(w, INSPECTION_CORE, fd, 64 + types, body)
    return inspection_feedback(o, w, 3, 0, 0)

def inspect_manifest(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    if state == INSPECTION_CONTEXT_MANIFEST:
        if reply_word(s, PROFILE_STALE):
            return inspection_feedback(o, w, 2, 2, 0)
        size = input_word(s, 40)
        if plan_ok(s) == False or size < 80 or input_word(s, 72) != CONTEXT_MANIFEST_TAG:
            return BAD
        body_span(s, w, INSPECTION_CONTEXT_WIRE)
        put(w, INSPECTION_FIELD, 0)
        put(w, INSPECTION_CURSOR, 16)
        return inspect_manifest_field(o, w)
    if state == INSPECTION_CONTEXT_FIELD:
        return bind_inspection_field(s, o, w)
    if state == INSPECTION_PROFILE_QUERY:
        if reply_word(s, PROFILE_STALE):
            return inspection_feedback(o, w, 2, 3, 0)
        if plan_ok(s) == False or input_word(s, 40) <= 8 or input_word(s, 40) > 168:
            return BAD
        observe_slot(s, w, QUERY_FD)
        return open_store(o, w, OPEN_PROFILE_ROW)
    if state == INSPECTION_PROFILE_BOUND:
        if reply_word(s, PROFILE_REFUSAL):
            return close_store(o, w, CLOSE_PROFILE_REFUSED)
        if (plan_ok(s) == False or input_word(s, 40) != 290 or length(s) < 88
                or input_word(s, 72) != PROFILE_BINDING or input_word(s, 80) != 176):
            return BAD
        hold(w, INSPECTION_REFERENCE, input_word(s, 32), 24, 176)
        return close_store(o, w, CLOSE_PROFILE_ROW)
    return BAD

def inspect_manifest_field(o:mutbuf, w:mutbuf) -> u64:
    at = get(w, INSPECTION_CURSOR)
    if at + 8 > 8 + get(w, INSPECTION_CONTEXT_WIRE + 16):
        return BAD
    return read_span(o, w, INSPECTION_CONTEXT_FIELD, get(w, INSPECTION_CONTEXT_WIRE), at, 8)

def bind_inspection_field(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    size = input_word(s, 64)
    index = get(w, INSPECTION_FIELD)
    at = get(w, INSPECTION_CURSOR) + 8
    total = get(w, INSPECTION_CONTEXT_WIRE + 16) + 8
    if total < at or size == 0 or size > total - at:
        return BAD
    if index <= 1:
        hold(w, INSPECTION_PROFILE_1 + 24 * index, input_word(s, 32), at, size)
    if index == 6:
        hold(w, INSPECTION_EXPORTS, input_word(s, 32), at, size)
        move_fragment(w, INSPECTION_PROFILE_1, INSPECTION_REFERENCE)
        return inspect_profile(o, w, 0)
    put(w, INSPECTION_CURSOR, at + size)
    put(w, INSPECTION_FIELD, index + 1)
    return inspect_manifest_field(o, w)

def move_fragment(w:mutbuf, src:u64, dest:u64) -> u64:
    return hold(w, dest, get(w, src), get(w, src + 8), get(w, src + 16))

def inspect_profile(o:mutbuf, w:mutbuf, index:u64) -> u64:
    put(w, INSPECTION_FIELD, index)
    put(o, HEADER, PROFILE_BY_REFERENCE)
    put(o, HEADER + 8, index + 1)
    copy_private(w, o, PROFILE_PIN + 64 * index, HEADER + 16, 64)
    use_span(w, o, INSPECTION_REFERENCE, 0)
    return action(o, w, INSPECTION_PROFILE_QUERY, RUN, PROFILE_ROLE, 0, 1, 80)
'''

STORE_DRIVER = r'''
def inspection_store_opened(o:mutbuf, w:mutbuf, purpose:u64) -> u64:
    query = slot_fd(w, QUERY_FD)
    bytes = slot_bytes(w, QUERY_FD)
    if purpose == OPEN_CONTEXT_ROW:
        return store_transaction(o, w, CONTEXT_ROW, 4, 1, query, 8, bytes - 8)
    if purpose == OPEN_RETAINED_ROW:
        return store_transaction(o, w, RETAINED_ROW, 2, 1, query, 8, bytes - 8)
    if purpose == OPEN_PROFILE_ROW:
        return store_transaction(o, w, PROFILE_ROW, 12, 1, query, 8, bytes - 8)
    return BAD

def inspection_store_closed(o:mutbuf, w:mutbuf, purpose:u64) -> u64:
    if purpose == CLOSE_CONTEXT_UNAVAILABLE:
        return inspection_feedback(o, w, 2, 1, 0)
    if purpose == CLOSE_CONTEXT_ROW:
        put(w, RETAINED_PURPOSE, READ_CONTEXT)
        return inspection_retained_query(o, w, 3)
    if purpose == CLOSE_RETAINED_REFUSED:
        return inspection_refused(o, w, get(w, RETAINED_ERROR) == 2)
    if purpose == CLOSE_RETAINED_ROW:
        return read_span(o, w, RETAINED_DIGEST, slot_fd(w, PROFILE_FD), 8, 72)
    if purpose == CLOSE_PROFILE_REFUSED:
        return inspection_feedback(o, w, 2, 3, 0)
    if purpose == CLOSE_PROFILE_ROW:
        put(w, RETAINED_PURPOSE, READ_PROFILE)
        return inspection_retained_query(o, w, 0)
    return BAD

def inspection_store_row(o:mutbuf, w:mutbuf, purpose:u64, bytes:u64) -> u64:
    put(o, HEADER + 8, bytes)
    put(o, HEADER + 16, get(w, STORE_REQUEST))
    put(o, HEADER + 24, get(w, STORE_EPOCH))
    if purpose == CONTEXT_ROW:
        put(o, HEADER, CONTEXT_OBSERVE_TAG)
        put(o, HEADER + 32, 0)
        use_span(w, o, INSPECTION_REFERENCE, 0)
        whole_slot(w, o, STORE_RESULT, 1)
        return action(o, w, INSPECTION_CONTEXT_OBSERVED, RUN, CONTEXT_BIND_ROLE, 0, 2, 36)
    if purpose == RETAINED_ROW:
        put(o, HEADER, RETAINED_OBSERVED)
        put(o, HEADER + 32, get(w, RETAINED_KIND))
        use_span(w, o, INSPECTION_REFERENCE, 0)
        whole_slot(w, o, STORE_RESULT, 1)
        return action(o, w, RETAINED_ROW_BOUND, RUN, PROFILE_ROLE, 0, 2, 40)
    if purpose == PROFILE_ROW:
        index = get(w, INSPECTION_FIELD)
        put(o, HEADER, PROFILE_OBSERVED_BY_REFERENCE)
        put(o, HEADER + 32, index + 1)
        copy_private(w, o, PROFILE_PIN + 64 * index, HEADER + 40, 64)
        whole_slot(w, o, STORE_RESULT, 0)
        return action(o, w, INSPECTION_PROFILE_BOUND, RUN, PROFILE_ROLE, 0, 1, 104)
    return BAD
'''


def store_controls():
    opened = function(STORE, 'opened_store')
    start = opened.index('    if purpose == OPEN_PROFILE:')
    end = opened.index('    if purpose == OPEN_COST:', start)
    opened = (opened[:start] + opened[end:]).replace(
        '    return BAD', '    return inspection_store_opened(o, w, purpose)')
    closed = function(STORE, 'closed_store')
    start = closed.index('    if purpose == CLOSED_PROFILE_REFUSED:')
    end = closed.index('    if purpose == CLOSED_COST:', start)
    closed = closed[:start] + closed[end:]
    last = closed.rindex('    return BAD')
    closed = closed[:last] + '    return inspection_store_closed(o, w, purpose)\n'
    settled = function(STORE, 'settle_transaction').replace(
        '    if purpose == STORE_LOOKUP or purpose == STORE_PROFILE_ROW or purpose == STORE_PROFILE_ID:',
        '    if purpose >= CONTEXT_ROW and purpose <= PROFILE_ROW:\n'
        '        return inspection_store_row(o, w, purpose, bytes)\n'
        '    if purpose == STORE_LOOKUP:')
    interpreted = function(STORE, 'interpret_row')
    interpreted = interpreted[:interpreted.index('    if purpose == STORE_PROFILE_ROW:')] + '    return BAD\n'
    return (
        *(function(STORE, name) for name in (
            'typed_request', 'typed_job', 'open_store', 'close_store', 'observe_store',
            'lookup_observation', 'store_transaction')),
        opened, closed, settled, interpreted,
    )


def recipe():
    constants = policy_constants()
    roles = ('CONTEXT_BIND_ROLE', 'NOMINAL_ROLE')
    constants.update({name: index for name, index in zip(roles, (25, 30))})
    extras = (
        'INSPECTION_REQUEST_ROLE', 'INSPECTION_EFFECT_ROLE', 'INSPECTION_CONTEXT_ROLE', 'INSPECTION_WIRE_ROLE',
        'INSPECTION_CANONICAL_ROLE', 'INSPECTION_QUERY_ROLE', 'INSPECTION_EMIT_ROLE', 'INSPECTION_ELF_ROLE',
        'INSPECTION_FRAMES_ROLE',
    )
    constants.update({name: index for index, name in enumerate(extras, 31)})
    states = (
        'INSPECTION_PLAN', 'INSPECTION_PEER_OPEN', 'INSPECTION_SENT', 'INSPECTION_LENGTH', 'INSPECTION_ACTION',
        'INSPECTION_PEER_CLOSED', 'INSPECTION_CONTEXT_REFERENCE', 'INSPECTION_CONTEXT_QUERY',
        'INSPECTION_CONTEXT_OBSERVED', 'RETAINED_QUERY_BOUND', 'RETAINED_ROW_BOUND', 'RETAINED_DIGEST',
        'RETAINED_BYTES', 'INSPECTION_PROGRAM_ADMITTED', 'INSPECTION_CONTEXT_MANIFEST',
        'INSPECTION_CONTEXT_FIELD', 'INSPECTION_PROFILE_QUERY', 'INSPECTION_PROFILE_BOUND',
        'INSPECTION_PROBE_FRAME', 'INSPECTION_PROBE', 'INSPECTION_VIEW_FRAME', 'INSPECTION_VIEW_BODY',
        'INSPECTION_VIEW_CANONICAL', 'INSPECTION_HASH_RETURNED', 'INSPECTION_HASH_FRAME', 'INSPECTION_NOMINAL_READY',
        'INSPECTION_VIEW_READY', 'INSPECTION_QUERY_READY', 'INSPECTION_CORE_READY', 'INSPECTION_LOWERING_READY',
        'INSPECTION_DOCUMENT', 'INSPECTION_DEPENDENCY_SELECTION', 'INSPECTION_QUERY_RESULT',
        'INSPECTION_EXPORTS_CHECKED', 'INSPECTION_OBJECT_RESULT', 'INSPECTION_OBJECT_FACTS',
        'INSPECTION_OBJECT_FRAME', 'INSPECTION_FRAME_BODY', 'INSPECTION_FRAME_CANONICAL',
        'INSPECTION_LOWERING_FRAME', 'INSPECTION_LOWERING_EXTENTS',
        'INSPECTION_LOWERING_BODY', 'INSPECTION_LOWERING_CANONICAL',
        'INSPECTION_CLOCK', 'INSPECTION_INSTALL_REFERENCE', 'INSPECTION_INSTALL_PINS', 'INSPECTION_PIN_FRAME',
        'INSPECTION_LOWERING_PROFILE_BOUND',
    )
    constants.update({name: index for index, name in enumerate(states, constants['REPORT_PUBLISHED'] + 1)})
    purposes = (
        'OPEN_CONTEXT_ROW', 'OPEN_RETAINED_ROW', 'OPEN_PROFILE_ROW', 'CLOSE_CONTEXT_ROW', 'CLOSE_CONTEXT_UNAVAILABLE',
        'CLOSE_RETAINED_ROW', 'CLOSE_RETAINED_REFUSED', 'CLOSE_PROFILE_ROW', 'CLOSE_PROFILE_REFUSED',
        'CONTEXT_ROW', 'RETAINED_ROW', 'PROFILE_ROW',
    )
    constants.update({name: index for index, name in enumerate(purposes, constants['STORE_TERMINAL'] + 1)})
    spans = (
        'INSPECTION_INPUT', 'INSPECTION_ACTUAL', 'INSPECTION_PENDING', 'INSPECTION_STRUCTURED', 'INSPECTION_CORE',
        'INSPECTION_RECEIPT', 'INSPECTION_SELECTION', 'INSPECTION_EXPORTS', 'INSPECTION_TEXT', 'INSPECTION_FACTS',
        'INSPECTION_FRAMES', 'INSPECTION_LOWERING_PROFILE', 'INSPECTION_REFERENCE', 'INSPECTION_CONTEXT_WIRE',
        'INSPECTION_PROFILE_1', 'INSPECTION_PROFILE_2', 'INSPECTION_INSTALL_MANIFEST', 'INSPECTION_OUTCOME',
    )
    constants.update({name: 2400 + 24 * index for index, name in enumerate(spans)})
    fields = (
        'INSPECTION_SEQUENCE', 'INSPECTION_BYTES', 'INSPECTION_STATUS', 'INSPECTION_VIEW', 'INSPECTION_VERSION',
        'INSPECTION_HASH_RESUME', 'INSPECTION_KIND', 'RETAINED_PURPOSE', 'RETAINED_KIND', 'RETAINED_ERROR',
        'INSPECTION_FIELD', 'INSPECTION_CURSOR',
    )
    constants.update({name: 2848 + 8 * index for index, name in enumerate(fields)})
    constants.update(
        ROLE_COUNT=40, ENTRY_BYTES=64 + 312 + 40 * 40, SCHEMA_TOOL=5, INSPECTION_PEER=1, SEND_PEER=9, MAKE=11,
        INSPECTION_DIGEST=2944, INSPECTION_SOURCE_HASH=3008, INSPECTION_CORE_HASH=3072,
        READ_INSTALLATION=1, READ_CONTEXT=2, READ_PROFILE=3, READ_PROGRAM=4,
        RETAINED_REFUSAL=4294967288, RETAINED_CORRUPT=4294967287, PROFILE_STALE=4294967286,
    )
    words = {
        'INSPECTION_EVENT_TAG': b'HIAFDE01', 'INSPECTION_ACTION_TAG': b'HIAINA01',
        'INSPECTION_OUTCOME_TAG': b'HIAIND01', 'INSPECTION_FRAME_TAG': b'HIAICF01',
        'INSPECTION_DEPENDENCY_TAG': b'HIAINQ01', 'INSPECTION_ELF_FACTS': b'HIAILF01',
        'SHA_JSON': b'"sha256"', 'STORE_HASH': b'store-ha', 'STORE_HASH_END': b'sh',
        'QUERY_OPTION_0': b'--agent-', 'QUERY_OPTION_1': b'compact',
        'OBJECT_EXPORT_SUFFIX': b',0,2]', 'CONTEXT_REFERENCE_TAG': b'HIACTRL1', 'CONTEXT_QUERY_TAG': b'HIACTL01',
        'CONTEXT_OBSERVED_TAG': b'HIACTO02', 'CONTEXT_OBSERVE_TAG': b'HIACTO01', 'CONTEXT_MANIFEST_TAG': b'HIACTR02',
        'RETAINED_QUERY_ANY': b'HIARFG03', 'RETAINED_QUERY_KIND': b'HIARFG01',
        'RETAINED_OBSERVED': b'HIARFG02', 'RETAINED_AUTHORITY': b'HIARFO02',
        'NOMINAL_PACKET': b'HIAVCF01', 'PROFILE_BY_REFERENCE': b'HIARFP03',
        'PROFILE_OBSERVED_BY_REFERENCE': b'HIARFP02', 'INSTALL_MANIFEST_REF': b'HIARFM01',
        'LOWERING_SELECT_0': b',"loweri', 'LOWERING_SELECT_1': b'ng"]',
        'JOURNAL_NULL_SUFFIX': b',null]',
    }
    constants.update({name: int.from_bytes(value, 'little') for name, value in words.items()})
    issue = function(DESCRIBE, 'issue').replace('seq > 160', 'seq > 4096').replace(
        '    put(o, 152,',
        '    put(o, 136, 0)\n'
        '    alias = choose(role == NOMINAL_ROLE, 1, choose(role == INSPECTION_QUERY_ROLE, 2, '
        'choose(role == INSPECTION_EMIT_ROLE, 3, 0)))\n'
        '    put(o, 168, choose(op == RUN, alias, 0))\n'
        '    put(o, 152,',
    )
    publish = function(PUBLICATION, 'publish_artifact').replace(
        '        return action(o, w, COST_OBSERVED, RUN, FLOW_ROLE, 0, 1, 24)',
        '        sideband = get(w, INSPECTION_OUTCOME + 16) != 0\n'
        '        if sideband:\n'
        '            use_span(w, o, INSPECTION_OUTCOME, 1)\n'
        '        return action(o, w, COST_OBSERVED, RUN, FLOW_ROLE, 0, choose(sideband, 2, 1), 24)',
    )
    descriptors = function(ENTRY_POLICY, 'trusted_descriptors').replace(
        '        previous = 0',
        '        if index == INSPECTION_CONTEXT_ROLE and fd != input_word(s, start + DESCRIPTOR_BYTES * PLAN_ROLE):\n'
        '            return False\n'
        '        previous = 0',
    ).replace(
        '            if input_word(s, start + DESCRIPTOR_BYTES * previous) == fd:',
        '            shared = previous == PLAN_ROLE and index == INSPECTION_CONTEXT_ROLE\n'
        '            if input_word(s, start + DESCRIPTOR_BYTES * previous) == fd and shared == False:',
    )
    entry = entry_program()
    controls = (
        function(ARTIFACT, 'artifact_entry').replace(
            '    return read_span(o, w, CONFIG_HEADER, slot_fd(w, METADATA_FD), 0, 88)',
            '    return clock_sample(o, w, INSPECTION_CLOCK, 0)'),
        function(ARTIFACT, 'project_request').replace('return json_pair(', 'return inspection_journal_plan('),
        function(ARTIFACT, 'send_journal').replace('        put(o, HEADER + local + 16, 0)',
                                                  '        put(o, HEADER + local + 16, 1)'),
        *(function(ARTIFACT, name) for name in (
            'clock_sample', 'project_artifact', 'schema_receipt', 'plan_ok', 'observe_journal',
            'bind_journal', 'artifact_edge', 'journal_action', 'artifact_error', 'end_effect')),
        *store_controls(),
        publish, function(PUBLICATION, 'send_report'), function(COST, 'action'), issue,
        function(ENTRY_POLICY, 'admit_entry'), function(ENTRY_POLICY, 'dossier_identity'), descriptors,
        *(function(DESCRIBE, name) for name in (
            'argv', 'fragment', 'keep', 'observe_slot', 'slot_fd', 'slot_bytes', 'whole_slot',
            'after_prefix', 'prefixed', 'reply_word', 'copy_private', 'zero_range', 'launch_directory', 'role_argument')),
        *(function(READ_POLICY, name) for name in ('receive', 'read_span')),
        *(function(entry, name) for name in ('valid_fd', 'is_hex', 'copy_span', 'input_word', 'put', 'write')),
        *(function(CONTEXT, name) for name in ('hold', 'use_span', 'sample_span', 'body_span')),
        function(MANIFEST_POLICY, 'vector_part'), function(RETAINED_POLICY, 'artifact_command'),
        function(RELEASE_WRITER, 'get'),
    )
    return constants, controls


def program():
    constants, controls = recipe()
    return flow_source(DRIVER, (EFFECT_DRIVER, VIEW_DRIVER, DOCUMENT_DRIVER, RETAINED_DRIVER, STORE_DRIVER, *controls),
                       constants)


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)), encoding='utf-8')
