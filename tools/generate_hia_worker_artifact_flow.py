"""Author the sealed HIA Artifact Worker; the platform only executes issued I/O."""

from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_release_install import POLICY_SOURCE as RELEASE_WRITER
from tools.generate_hia_worker_cost_flow import POLICY as COST_POLICY
from tools.generate_hia_worker_describe_flow import POLICY as DESCRIBE, flow_source
from tools.generate_hia_worker_describe_reactor import POLICY as ENTRY_POLICY, program as entry_program
from tools.generate_hia_worker_inspection_effect import function
from tools.generate_hia_worker_read_store_flow import POLICY as READ_POLICY

SOURCE = Path('examples/hia_bootstrap/worker_artifact_flow.hepta')

POLICY = r'''
def artifact_flow(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 8 or length(o) != 2048 or length(w) != 4096:
        return BAD
    state = get(w, 0)
    if state == 0:
        return artifact_entry(s, o, w)
    if length(s) < 64 or input_word(s, 0) != OBSERVATION or input_word(s, 8) != get(w, 8):
        return BAD
    operation = get(w, 16)
    status = input_word(s, 24)
    if input_word(s, 16) != operation:
        return BAD
    if status != 0 and state != INPUT_FILE and state != DOCUMENT:
        return BAD
    extent = input_word(s, 40)
    offset = choose(operation == RUN, 0, input_word(s, 48))
    captured = input_word(s, 56)
    if extent > 67112960 or offset > extent or captured > extent - offset or captured != length(s) - 64:
        return BAD
    if operation == RUN and valid_fd(input_word(s, 32)) == False:
        return BAD
    if operation == READ and (input_word(s, 32) != get(w, 80) or offset != get(w, 88) or captured != get(w, 96)):
        return BAD
    if state <= STARTED:
        return configure_artifact(s, o, w, state)
    if state <= ARGUMENT_PLAN:
        return project_request(s, o, w, state)
    if state <= JOURNAL_RECIPE:
        return observe_journal(s, o, w, state)
    if state <= TYPED:
        return typed_job(s, o, w, state)
    if state <= PEER_CLOSED:
        return observe_store(s, o, w, state)
    if state <= LOOKUP_AUDITED:
        return lookup_observation(s, o, w, state)
    if state <= PROFILE_CAPTURED:
        return profile_continuation(s, o, w, state)
    if state <= EFFECT_RENDERED:
        return materialization(s, o, w, state)
    return publish_artifact(s, o, w, state)

def artifact_entry(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if input_word(s, 0) != ENTRY or admit_entry(s, o) != 344:
        return BAD
    keep(w, ORIGINAL, 0, input_word(s, 8))
    keep(w, DOSSIER_FD, input_word(s, 32), input_word(s, 16))
    keep(w, METADATA_FD, input_word(s, 40), input_word(s, 24))
    put(w, 24, get(o, 56))
    put(w, 32, get(o, 64))
    put(w, 40, get(o, 32))
    put(w, 48, get(o, 40))
    put(w, 56, get(o, 48))
    i = 0
    while i < 256:
        store(w, TRUST + i, byte(o, 88 + i))
        i = i + 1
    i = 0
    while i < ROLE_COUNT:
        put(w, ROLE_BASE + 8 * i, input_word(s, ENTRY_HEAD + DOSSIER_HEAD + DESCRIPTOR_BYTES * i))
        i = i + 1
    return read_span(o, w, CONFIG_HEADER, slot_fd(w, METADATA_FD), 0, 88)

def configure_artifact(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    total = slot_bytes(w, METADATA_FD)
    if state == CONFIG_HEADER:
        profile = input_word(s, 136)
        count = input_word(s, 144)
        if input_word(s, 64) != CONFIG or profile < 86 or profile > 384 or count > 32 or profile > total - 88:
            return BAD
        i = 0
        while i < 64:
            pin = byte(s, 72 + i)
            if is_hex(pin) == False:
                return BAD
            store(w, PROFILE_PIN + i, pin)
            i = i + 1
        put(w, PROFILE_SIZE, profile)
        put(w, ROOTS_COUNT, count)
        put(w, CONFIG_AT, 88 + profile)
        return next_root(o, w)
    if state == ROOT_LENGTH:
        extent = input_word(s, 64)
        at = get(w, CONFIG_AT) + 8
        if extent == 0 or extent > 4095 or extent > total - at:
            return BAD
        root = ROOTS_BASE + 16 * get(w, ROOT_INDEX)
        put(w, root, at)
        put(w, root + 8, extent)
        put(w, CONFIG_AT, at)
        put(w, ROOT_REMAINING, extent)
        return root_chunk(o, w)
    if state == ROOT_BYTES:
        at = get(w, CONFIG_AT)
        root = ROOTS_BASE + 16 * get(w, ROOT_INDEX)
        if at == get(w, root) and byte(s, 64) != 47:
            return BAD
        n = length(s) - 64
        i = 0
        while i < n:
            if byte(s, 64 + i) == 0:
                return BAD
            i = i + 1
        left = get(w, ROOT_REMAINING) - n
        put(w, CONFIG_AT, at + n)
        put(w, ROOT_REMAINING, left)
        if left != 0:
            return root_chunk(o, w)
        put(w, ROOT_INDEX, get(w, ROOT_INDEX) + 1)
        return next_root(o, w)
    if length(s) != 72 or input_word(s, 40) != 8:
        return BAD
    put(w, START_TIME, input_word(s, 64))
    put(o, HEADER, ADMISSION)
    put(o, HEADER + 8, get(w, 24))
    copy_private(w, o, TRUST, HEADER + 16, 64)
    whole_slot(w, o, ORIGINAL, 0)
    return action(o, w, REQUEST_ADMITTED, RUN, ADMIT_ROLE, 0, 1, 80)

def next_root(o:mutbuf, w:mutbuf) -> u64:
    at = get(w, CONFIG_AT)
    total = slot_bytes(w, METADATA_FD)
    if get(w, ROOT_INDEX) == get(w, ROOTS_COUNT):
        if at != total:
            return BAD
        return clock_sample(o, w, STARTED, 0)
    if at > total or total - at < 8:
        return BAD
    return read_span(o, w, ROOT_LENGTH, slot_fd(w, METADATA_FD), at, 8)

def root_chunk(o:mutbuf, w:mutbuf) -> u64:
    left = get(w, ROOT_REMAINING)
    return read_span(o, w, ROOT_BYTES, slot_fd(w, METADATA_FD), get(w, CONFIG_AT),
                     choose(left > 1024, 1024, left))

def clock_sample(o:mutbuf, w:mutbuf, state:u64, source:u64) -> u64:
    put(o, 144, source)
    return action(o, w, state, CLOCK, 0, 0, 0, 0)

def project_request(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    if state == REQUEST_ADMITTED:
        observe_slot(s, w, ADMITTED_FD)
        return project_artifact(o, w, CALL_PROJECTED, PROJECT, PROJECT_ROLE)
    if state == CALL_PROJECTED:
        if prefixed(s) == False:
            return BAD
        observe_slot(s, w, CALL_FD)
        return send_journal(o, w, 9)
    if state == ARGUMENT_PROJECTED:
        if prefixed(s) == False:
            return BAD
        observe_slot(s, w, ARGUMENT_FD)
        return schema_receipt(o, w, INPUT_SCHEMA, INPUT_SCHEMA_ROLE, ARGUMENT_FD)
    if state == INPUT_SCHEMA:
        if reply_word(s, 1):
            after_prefix(w, o, ARGUMENT_FD, 0)
            return action(o, w, DIAGNOSTIC, RUN, DIAGNOSTIC_ROLE, 0, 1, 0)
        if reply_word(s, 0) == False:
            return BAD
        put(o, HEADER, 8795)
        copy_private(w, o, TRUST, HEADER + 2, 64)
        store(o, HEADER + 66, 34)
        store(o, HEADER + 67, 44)
        return json_pair(o, w, ARGUMENT_PLAN, 68)
    if state == DIAGNOSTIC:
        if plan_ok(s) == False:
            return BAD
        observe_slot(s, w, EFFECT_FD)
        return end_effect(o, w, 2, 8)
    if plan_ok(s) == False:
        return BAD
    observe_slot(s, w, PLAN_FD)
    return send_journal(o, w, 11)

def project_artifact(o:mutbuf, w:mutbuf, state:u64, tag:u64, role:u64) -> u64:
    put(o, HEADER, get(w, 24))
    put(o, HEADER + 8, tag)
    whole_slot(w, o, ADMITTED_FD, 0)
    return action(o, w, state, RUN, role, 0, 1, 16)

def schema_receipt(o:mutbuf, w:mutbuf, state:u64, role:u64, slot:u64) -> u64:
    put(o, HEADER, 2)
    copy_private(w, o, TRUST, HEADER + 8, 64)
    after_prefix(w, o, slot, 0)
    return action(o, w, state, RUN, role, 0, 1, 72)

def plan_ok(s:readbuf) -> bool:
    return length(s) >= 72 and input_word(s, 40) <= 8389632 and input_word(s, 64) == input_word(s, 40) - 8

def json_pair(o:mutbuf, w:mutbuf, state:u64, inline:u64) -> u64:
    # Preserve the installed canonical profile and original argument bytes.
    after_prefix(w, o, ARGUMENT_FD, 0)
    store(o, 496, 93)
    fragment(o, 1, INLINE_FRAGMENT, 496, 1)
    return action(o, w, state, RUN, PLAN_ROLE, 0, 2, inline)

def send_journal(o:mutbuf, w:mutbuf, stage:u64) -> u64:
    put(w, JOURNAL_STAGE, stage)
    previous = choose(stage == 9, 0, 512)
    put(o, HEADER, JOURNAL_COMMAND)
    put(o, HEADER + 8, stage)
    put(o, HEADER + 16, get(w, 24))
    put(o, HEADER + 24, previous)
    put(o, HEADER + 32, 0)
    copy_private(w, o, JOURNAL_STATE, HEADER + 40, previous)
    local = 40 + previous
    parts = 0
    payload = 0
    if stage == 9:
        payload = get(w, 40)
        fragment(o, 0, slot_fd(w, DOSSIER_FD), DOSSIER_HEAD, payload)
        parts = 1
    elif stage == 0 or stage == 11 or stage == 8:
        slot = choose(stage == 0, CALL_FD, choose(stage == 11, PLAN_FD, RENDERED_FD))
        payload = slot_bytes(w, slot) - 8
        after_prefix(w, o, slot, 0)
        parts = 1
    elif stage == 1 or stage == 3:
        at = choose(stage == 1, get(w, LOOKUP_AT), get(w, CACHED_AT))
        payload = choose(stage == 1, get(w, LOOKUP_BYTES), get(w, CACHED_BYTES))
        fragment(o, 0, slot_fd(w, LOOKUP_FD), at, payload)
        parts = 1
    elif stage == 12:
        catalog = get(w, 40)
        current = get(w, 48)
        pinned = get(w, 56)
        put(o, HEADER + local, current)
        put(o, HEADER + local + 8, pinned)
        put(o, HEADER + local + 16, 0)
        fragment(o, 0, slot_fd(w, DOSSIER_FD), DOSSIER_HEAD + catalog, current)
        fragment(o, 1, slot_fd(w, DOSSIER_FD), DOSSIER_HEAD + catalog + current, pinned)
        payload = 24 + current + pinned
        local = local + 24
        parts = 2
    if payload > 8388608:
        return BAD
    put(o, HEADER + 32, payload)
    return action(o, w, JOURNAL_REQUEST, RUN, FLOW_ROLE, 0, parts, local)

def observe_journal(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    if state == JOURNAL_REQUEST:
        fragment(o, 0, input_word(s, 32), 0, input_word(s, 40))
        return action(o, w, JOURNAL_REACTOR, RUN, JOURNAL_ROLE, 0, 1, 0)
    if state == JOURNAL_REACTOR:
        observe_slot(s, w, REPLY_FD)
        stage = get(w, JOURNAL_STAGE)
        previous = choose(stage == 9, 0, 512)
        put(o, HEADER, JOURNAL_OBSERVED)
        put(o, HEADER + 8, stage)
        put(o, HEADER + 16, previous)
        put(o, HEADER + 24, slot_bytes(w, REPLY_FD))
        put(o, HEADER + 32, 0)
        copy_private(w, o, JOURNAL_STATE, HEADER + 40, previous)
        whole_slot(w, o, REPLY_FD, 0)
        return action(o, w, JOURNAL_PROOF, RUN, FLOW_ROLE, 0, 1, 40 + previous)
    if state == JOURNAL_PROOF:
        return bind_journal(s, o, w)
    if state == JOURNAL_STATE_FRAME:
        copy_span(s, w, 64, JOURNAL_STATE, 512)
        return journal_action(o, w)
    zero_range(o, HEADER, 224)
    put(o, HEADER, get(w, 24))
    put(o, HEADER + 8, RESPONSE)
    put(o, HEADER + 16, get(w, JOURNAL_BYTES))
    copy_span(s, o, 64, HEADER + 32, get(w, JOURNAL_BYTES))
    fragment(o, 0, slot_fd(w, EFFECT_FD), get(w, EFFECT_AT), slot_bytes(w, EFFECT_FD) - get(w, EFFECT_AT))
    return action(o, w, RESPONSE_RENDERED, RUN, COMPOSE_ROLE, 0, 1, 224)

def bind_journal(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    stage = get(w, JOURNAL_STAGE)
    if input_word(s, 40) != 64 or length(s) != 128 or input_word(s, 64) != JOURNAL_REPLY or input_word(s, 72) != stage:
        return BAD
    next = input_word(s, 80)
    status = input_word(s, 88)
    at = input_word(s, 96)
    bytes = input_word(s, 104)
    prior = input_word(s, 112)
    count = input_word(s, 120)
    volume = slot_bytes(w, REPLY_FD)
    if at > volume or bytes > volume - at or prior > volume or count > volume - prior:
        return BAD
    if artifact_edge(stage, next, status, bytes) == False:
        return BAD
    copy_span(s, w, 64, JOURNAL_ROUTE, 64)
    put(w, JOURNAL_AT, at)
    put(w, JOURNAL_BYTES, bytes)
    put(w, JOURNAL_NEXT, next)
    put(w, JOURNAL_STATUS, status)
    if next == 17:
        if count != 0 or bytes > 192:
            return BAD
        return read_span(o, w, JOURNAL_RECIPE, slot_fd(w, REPLY_FD), at, bytes)
    if count == 512:
        return read_span(o, w, JOURNAL_STATE_FRAME, slot_fd(w, REPLY_FD), prior, count)
    if count == 0:
        return journal_action(o, w)
    return BAD

def artifact_edge(stage:u64, next:u64, status:u64, bytes:u64) -> bool:
    if stage == 9:
        return next == 0 and status == 0
    if stage == 0:
        return (next == 1 or next == 11) and status == 0
    if stage == 1:
        return (next == 2 or next == 3 or next == 14) and status == 0
    if stage == 2:
        return next == 11 and status == 0
    if stage == 3:
        return next == 19
    if stage == 11:
        return (next == 12 or next == 14) and status == 0
    if stage == 12:
        return (next == 5 or next == 14) and status == 0
    if stage == 5:
        return next == 16 and status == 0
    if stage == 13 or stage == 14:
        return next == 17 and bytes <= 192
    return stage == 8 and (next == 18 or next == 20) and (status == 1 or status == 2)

def journal_action(o:mutbuf, w:mutbuf) -> u64:
    next = get(w, JOURNAL_NEXT)
    stage = get(w, JOURNAL_STAGE)
    if next == 0 or next == 12 or next == 5:
        return send_journal(o, w, next)
    if next == 1:
        return open_store(o, w, OPEN_LOOKUP)
    if stage == 1:
        if next == 2:
            return clock_sample(o, w, RESERVATION_CLOCK, 1)
        return close_store(o, w, CLOSED_LOOKUP)
    if next == 11:
        if stage == 2:
            copy_private(w, o, JOURNAL_ROUTE, HEADER + 48, 64)
            return store_transaction(o, w, STORE_RESERVATION_COMMIT, 23, 0, 0, 0, 64)
        return project_artifact(o, w, ARGUMENT_PROJECTED, ARGUMENT, ARGUMENT_ROLE)
    if next == 19:
        return send_report(o, w, True)
    if next == 14:
        return artifact_error(o, w, 1, get(w, JOURNAL_STATE + 56))
    if next == 16:
        return authorize_business(o, w)
    if next == 18 or next == 20:
        if get(w, EFFECT_STATUS) != get(w, JOURNAL_STATUS):
            return BAD
        return clock_sample(o, w, COST_CLOCK, 0)
    return BAD

def artifact_error(o:mutbuf, w:mutbuf, scope:u64, code:u64) -> u64:
    zero_range(o, HEADER, 40)
    put(o, HEADER, ERROR_PACKET)
    put(o, HEADER + 8, scope)
    put(o, HEADER + 16, code)
    return action(o, w, ERROR_RENDERED, RUN, FLOW_ROLE, 0, 0, 40)

def end_effect(o:mutbuf, w:mutbuf, status:u64, at:u64) -> u64:
    put(w, EFFECT_STATUS, status)
    put(w, EFFECT_AT, at)
    return send_journal(o, w, choose(status == 1, 13, 14))
'''

STORE_POLICY = r'''
def typed_request(o:mutbuf, w:mutbuf, purpose:u64, elapsed:u64) -> u64:
    put(w, TYPED_PURPOSE, purpose)
    operation = choose(purpose == STORE_LOOKUP, 1, choose(purpose == STORE_RESERVATION, 2, 3))
    extent = choose(operation == 3, get(w, JOURNAL_BYTES), 0)
    zero_range(o, HEADER, 40)
    put(o, HEADER, JOURNAL_KEY)
    put(o, HEADER + 8, operation)
    put(o, HEADER + 16, elapsed)
    put(o, HEADER + 24, extent)
    copy_private(w, o, JOURNAL_STATE, HEADER + 40, 512)
    if operation == 3:
        fragment(o, 0, slot_fd(w, REPLY_FD), get(w, JOURNAL_AT), extent)
    return action(o, w, TYPED_REQUEST, RUN, FLOW_ROLE, 0, choose(operation == 3, 1, 0), 552)

def typed_job(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    if state == RESERVATION_CLOCK:
        if length(s) != 72 or input_word(s, 40) != 8:
            return BAD
        return typed_request(o, w, STORE_RESERVATION, input_word(s, 64))
    fd = input_word(s, 32)
    span = input_word(s, 40)
    if state == TYPED_REQUEST:
        fragment(o, 0, fd, 0, span)
        return action(o, w, TYPED, RUN, RECORD_ROLE, 0, 1, 0)
    if plan_ok(s) == False or span < 9:
        return BAD
    purpose = get(w, TYPED_PURPOSE)
    if purpose == STORE_LOOKUP:
        if span != 128:
            return BAD
        keep(w, QUERY_FD, fd, span)
        return store_transaction(o, w, purpose, 9, 0, fd, 8, span - 8)
    if purpose == STORE_RESERVATION:
        return store_transaction(o, w, purpose, 21, 0, fd, 8, span - 8)
    return store_transaction(o, w, purpose, 22, 1, fd, 8, span - 8)

def open_store(o:mutbuf, w:mutbuf, purpose:u64) -> u64:
    put(w, STORE_PURPOSE, purpose)
    put(w, STORE_REQUEST, 0)
    put(w, STORE_MODE, 2)
    argv(o, 0, INPUT_ARG, 2)
    put(o, 160, STORE_ARG)
    argv(o, 1, LITERAL_ARG, 160)
    argv(o, 2, INPUT_ARG, 3)
    put(o, 176, STORE_PEER)
    return action(o, w, PEER_STARTED, START_PEER, STORE_ROLE, 3, 0, 0)

def close_store(o:mutbuf, w:mutbuf, purpose:u64) -> u64:
    put(w, STORE_PURPOSE, purpose)
    put(o, 176, STORE_PEER)
    return action(o, w, PEER_CLOSED, FINISH_PEER, 0, 0, 0, 0)

def observe_store(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    if state == PEER_STARTED:
        if length(s) != 80 or input_word(s, 40) != 16:
            return BAD
        reply = input_word(s, 64)
        request = input_word(s, 72)
        if valid_fd(reply) == False or valid_fd(request) == False or reply == request:
            return BAD
        put(w, STORE_REPLY_FD, reply)
        put(w, STORE_COMMAND_FD, request)
        return receive(o, w, PEER_READY, STORE_PEER, 80, False)
    if state == PEER_READY:
        if length(s) != 144 or input_word(s, 40) != 80:
            return BAD
        copy_span(s, o, 64, HEADER, 80)
        return action(o, w, PEER_ADMITTED, RUN, READY_ROLE, 0, 0, 80)
    if state == PEER_ADMITTED:
        if length(s) != 80 or input_word(s, 40) != 16 or input_word(s, 64) != 1:
            return BAD
        put(w, STORE_EPOCH, input_word(s, 72))
        return opened_store(o, w)
    if state == PEER_CLOSED:
        if length(s) != 64:
            return BAD
        return closed_store(o, w)
    if state == STORE_RETURNED:
        if input_word(s, 40) < 48:
            return BAD
        observe_slot(s, w, STORE_RESULT)
        return read_span(o, w, STORE_SETTLED, slot_fd(w, STORE_RESULT), slot_bytes(w, STORE_RESULT) - 48, 48)
    return settle_transaction(s, o, w)

def opened_store(o:mutbuf, w:mutbuf) -> u64:
    purpose = get(w, STORE_PURPOSE)
    if purpose == OPEN_LOOKUP:
        return typed_request(o, w, STORE_LOOKUP, 0)
    if purpose == OPEN_PROFILE:
        return store_transaction(o, w, STORE_PROFILE_ROW, 12, 1, slot_fd(w, QUERY_FD), 8, slot_bytes(w, QUERY_FD) - 8)
    if purpose == OPEN_COST:
        return store_transaction(o, w, STORE_COST, 18, 1, slot_fd(w, COST_FD), 8, slot_bytes(w, COST_FD) - 8)
    return BAD

def closed_store(o:mutbuf, w:mutbuf) -> u64:
    purpose = get(w, STORE_PURPOSE)
    if purpose == CLOSED_LOOKUP:
        following = get(w, JOURNAL_NEXT)
        if following == 3 and get(w, CACHED_BYTES) > 0:
            return send_journal(o, w, 3)
        if following == 14:
            return artifact_error(o, w, 1, get(w, JOURNAL_STATE + 56))
        return BAD
    if purpose == CLOSED_RESERVATION:
        return project_artifact(o, w, ARGUMENT_PROJECTED, ARGUMENT, ARGUMENT_ROLE)
    if purpose == CLOSED_PROFILE_REFUSED:
        return artifact_error(o, w, 2, 2)
    if purpose == CLOSED_PROFILE:
        return capture_profile(o, w)
    if purpose == CLOSED_COST:
        return send_report(o, w, False)
    return BAD

def store_transaction(o:mutbuf, w:mutbuf, purpose:u64, plan:u64, transfer:u64, fd:u64, at:u64, extent:u64) -> u64:
    if extent == 0 or extent > 67112960:
        return BAD
    mode = choose(transfer == 1, get(w, STORE_MODE), 0)
    put(w, STORE_PURPOSE, purpose)
    put(w, STORE_STEP, choose(mode == 0, 1, choose(mode == 2, 2, 3)))
    if mode != 0 or plan == 23:
        put(w, STORE_MODE, 1)
    put(o, HEADER, UNIQUE)
    put(o, HEADER + 8, get(w, STORE_REQUEST))
    put(o, HEADER + 16, plan)
    put(o, HEADER + 24, mode)
    put(o, HEADER + 32, get(w, STORE_EPOCH))
    put(o, HEADER + 40, extent)
    argv(o, 0, FD_ARG, get(w, STORE_REPLY_FD))
    argv(o, 1, FD_ARG, get(w, STORE_COMMAND_FD))
    if purpose == STORE_RESERVATION_COMMIT:
        return action(o, w, STORE_RETURNED, RUN, UNIQUE_ROLE, 2, 0, 48 + extent)
    fragment(o, 0, fd, at, extent)
    return action(o, w, STORE_RETURNED, RUN, UNIQUE_ROLE, 2, 1, 48)

def settle_transaction(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    total = input_word(s, 40)
    if length(s) != 112 or total != slot_bytes(w, STORE_RESULT):
        return BAD
    bytes = input_word(s, 72)
    found = input_word(s, 80)
    request = input_word(s, 96)
    epoch = input_word(s, 104)
    old_request = get(w, STORE_REQUEST)
    if input_word(s, 64) != 5 or bytes != total - 48 or found > 1 or input_word(s, 88) != 0:
        return BAD
    if request < old_request or request - old_request != get(w, STORE_STEP) or epoch < get(w, STORE_EPOCH):
        return BAD
    put(w, STORE_REQUEST, request)
    put(w, STORE_EPOCH, epoch)
    purpose = get(w, STORE_PURPOSE)
    if purpose == STORE_LOOKUP or purpose == STORE_PROFILE_ROW or purpose == STORE_PROFILE_ID:
        return interpret_row(o, w, purpose, bytes)
    if found != 1:
        return BAD
    if purpose == STORE_RESERVATION:
        if bytes != 0:
            return BAD
        return send_journal(o, w, 2)
    if bytes != 8:
        return BAD
    if purpose == STORE_RESERVATION_COMMIT:
        return close_store(o, w, CLOSED_RESERVATION)
    if purpose == STORE_COST and get(w, JOURNAL_NEXT) == 20:
        return typed_request(o, w, STORE_TERMINAL, 0)
    if purpose == STORE_COST or purpose == STORE_TERMINAL:
        return close_store(o, w, CLOSED_COST)
    return BAD

def interpret_row(o:mutbuf, w:mutbuf, purpose:u64, bytes:u64) -> u64:
    put(o, HEADER + 8, bytes)
    put(o, HEADER + 16, get(w, STORE_REQUEST))
    put(o, HEADER + 24, get(w, STORE_EPOCH))
    if purpose == STORE_LOOKUP:
        put(o, HEADER, LOOKUP_OBSERVATION)
        fragment(o, 0, slot_fd(w, QUERY_FD), 64, 64)
        whole_slot(w, o, STORE_RESULT, 1)
        return action(o, w, LOOKUP_AUDITED, RUN, OBSERVE_ROLE, 0, 2, 32)
    if purpose == STORE_PROFILE_ROW:
        put(o, HEADER, PROFILE_OBSERVED)
        copy_private(w, o, PROFILE_PIN, HEADER + 32, 64)
        whole_slot(w, o, STORE_RESULT, 0)
        return action(o, w, PROFILE_AUTHORIZED, RUN, PROFILE_ROLE, 0, 1, 96)
    put(o, HEADER, PROFILE_ATTESTATION)
    fragment(o, 0, slot_fd(w, PROFILE_FD), 24, 176)
    whole_slot(w, o, STORE_RESULT, 1)
    return action(o, w, PROFILE_PROOF, RUN, PROFILE_ROLE, 0, 2, 32)

def lookup_observation(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    if state != LOOKUP_AUDITED or plan_ok(s) == False or length(s) < 104 or input_word(s, 72) != LOOKUP_LAYOUT:
        return BAD
    type = input_word(s, 80)
    observation = input_word(s, 88)
    replay = input_word(s, 96)
    extent = input_word(s, 40)
    if extent < 40 or type > 2 or observation > extent - 40 or replay != extent - 40 - observation:
        return BAD
    observe_slot(s, w, LOOKUP_FD)
    put(w, LOOKUP_AT, 40)
    put(w, LOOKUP_BYTES, observation)
    put(w, CACHED_AT, 40 + observation)
    put(w, CACHED_BYTES, replay)
    return send_journal(o, w, 1)
'''

EFFECT_POLICY = r'''
def authorize_business(o:mutbuf, w:mutbuf) -> u64:
    return read_span(o, w, PROFILE_JSON, slot_fd(w, METADATA_FD), 88, get(w, PROFILE_SIZE))

def profile_continuation(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    if state == PROFILE_JSON:
        size = get(w, PROFILE_SIZE)
        store(o, HEADER, 91)
        copy_span(s, o, 64, HEADER + 1, size)
        store(o, HEADER + 1 + size, 44)
        return json_pair(o, w, PROFILE_ACTION, size + 2)
    if state == PROFILE_ACTION:
        if reply_word(s, PROFILE_REFUSAL):
            return artifact_error(o, w, 2, 1)
        if plan_ok(s) == False or input_word(s, 40) < 56:
            return BAD
        observe_slot(s, w, ACTION_FD)
        put(o, HEADER, PROFILE_QUERY_TAG)
        copy_private(w, o, PROFILE_PIN, HEADER + 8, 64)
        return action(o, w, PROFILE_QUERY, RUN, PROFILE_ROLE, 0, 0, 72)
    if state == PROFILE_QUERY:
        if plan_ok(s) == False or input_word(s, 40) <= 8:
            return BAD
        observe_slot(s, w, QUERY_FD)
        return open_store(o, w, OPEN_PROFILE)
    if state == PROFILE_AUTHORIZED:
        if reply_word(s, PROFILE_REFUSAL):
            return close_store(o, w, CLOSED_PROFILE_REFUSED)
        if (plan_ok(s) == False or input_word(s, 40) != 290 or length(s) < 88
                or input_word(s, 72) != PROFILE_BINDING or input_word(s, 80) != 176):
            return BAD
        observe_slot(s, w, PROFILE_FD)
        return store_transaction(o, w, STORE_PROFILE_ID, 2, 1, slot_fd(w, PROFILE_FD), 200, 90)
    if state == PROFILE_PROOF:
        if plan_ok(s) == False or input_word(s, 40) != 80:
            return BAD
        return read_span(o, w, PROFILE_PIN_FRAME, input_word(s, 32), 8, 72)
    if state == PROFILE_PIN_FRAME:
        if input_word(s, 64) != PROFILE_AUTHORITY:
            return BAD
        i = 0
        while i < 64:
            if byte(s, 72 + i) != byte(w, PROFILE_PIN + i):
                return BAD
            i = i + 1
        return close_store(o, w, CLOSED_PROFILE)
    return read_span(o, w, MATERIALIZATION_PLAN, slot_fd(w, ACTION_FD), 8, 48)

def capture_profile(o:mutbuf, w:mutbuf) -> u64:
    put(o, 384, STORE_GET)
    put(o, 392, STORE_GET_END)
    put(o, 400, ARTIFACT_ROOT)
    put(o, 408, ARTIFACT_ROOT_END)
    copy_private(w, o, PROFILE_PIN, 416, 64)
    store(o, 480, 0)
    argv(o, 0, LITERAL_ARG, 384)
    argv(o, 1, JOINED_ARG, 400)
    argv(o, 2, LITERAL_ARG, 416)
    return action(o, w, PROFILE_CAPTURED, RUN, PUBLISHER_ROLE, 3, 0, 0)

def materialization(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    if state == MATERIALIZATION_PLAN:
        return plan_materialization(s, o, w)
    if state == FILE_PATH:
        return confirm_file_path(s, o, w)
    if state == INPUT_FILE:
        return file_observation(s, o, w)
    if state == DOCUMENT:
        return document_observation(s, o, w)
    if state == ERROR_RENDERED:
        if input_word(s, 40) == 0:
            return BAD
        observe_slot(s, w, EFFECT_FD)
        return end_effect(o, w, 2, 0)
    if state == EFFECT_RENDERED and plan_ok(s):
        observe_slot(s, w, EFFECT_FD)
        return end_effect(o, w, 1, 8)
    return BAD

def plan_materialization(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    extent = input_word(s, 88)
    digest = input_word(s, 96)
    available = slot_bytes(w, ACTION_FD) - 56
    if input_word(s, 64) != ACTION_PLAN or input_word(s, 104) != 0 or extent > available or digest != available - extent:
        return BAD
    role = input_word(s, 72)
    limit = input_word(s, 80)
    put(w, REQUIRE_DIGEST, digest)
    put(w, INPUT_EXTENT, extent)
    if role == 1:
        if limit != 0 or digest != 0 or extent > 262144:
            return BAD
        keep(w, INPUT_FD, slot_fd(w, ACTION_FD), extent)
        put(w, INPUT_AT, 56)
        return invoke_document(o, w)
    if role != 2 or limit == 0 or limit > 8388608 or extent == 0 or extent > 16384:
        return BAD
    if digest != 0 and digest != 64:
        return BAD
    put(w, FILE_LIMIT, limit)
    put(w, FILE_LENGTH, extent)
    put(w, FILE_OFFSET, 56)
    put(w, ROOT_INDEX, 0)
    return read_file_path(o, w, extent)

def read_file_path(o:mutbuf, w:mutbuf, left:u64) -> u64:
    return read_span(o, w, FILE_PATH, slot_fd(w, ACTION_FD), get(w, FILE_OFFSET),
                     choose(left > 1024, 1024, left))

def confirm_file_path(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    at = get(w, FILE_OFFSET)
    n = length(s) - 64
    if n == 0:
        return BAD
    if at == 56 and byte(s, 64) != 47:
        return artifact_error(o, w, 3, 65)
    i = 0
    while i < n:
        if byte(s, 64 + i) == 0:
            return artifact_error(o, w, 3, 69)
        i = i + 1
    at = at + n
    limit = get(w, FILE_LENGTH) + 56
    if at > limit:
        return BAD
    if at < limit:
        put(w, FILE_OFFSET, at)
        return read_file_path(o, w, limit - at)
    return capture_file(o, w)

def span_argument(o:mutbuf, item:u64, location:u64, fd:u64, at:u64, extent:u64) -> u64:
    put(o, location, fd)
    put(o, location + 8, at)
    put(o, location + 16, extent)
    return argv(o, item, SPAN_ARG, location)

def capture_file(o:mutbuf, w:mutbuf) -> u64:
    count = get(w, ROOTS_COUNT)
    index = get(w, ROOT_INDEX)
    if count == 0:
        store(o, 448, 0)
        argv(o, 0, LITERAL_ARG, 448)
    else:
        root = ROOTS_BASE + 16 * index
        span_argument(o, 0, 384, slot_fd(w, METADATA_FD), get(w, root), get(w, root + 8))
    span_argument(o, 1, 408, slot_fd(w, ACTION_FD), 56, get(w, FILE_LENGTH))
    argv(o, 2, DECIMAL_ARG, get(w, FILE_LIMIT))
    return action(o, w, INPUT_FILE, RUN, CAPTURE_ROLE, 3, 0, 0)

def file_observation(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    status = input_word(s, 24)
    size = input_word(s, 40)
    if status == 0:
        if size > get(w, FILE_LIMIT):
            return BAD
        observe_slot(s, w, INPUT_FD)
        put(w, INPUT_AT, 0)
        put(w, INPUT_EXTENT, size)
        return invoke_document(o, w)
    code = status >> 8
    if size != 0 or status != code * 256 or code < 65 or code > 71:
        return BAD
    index = get(w, ROOT_INDEX) + 1
    if code != 66 or index >= get(w, ROOTS_COUNT):
        return artifact_error(o, w, 3, code)
    put(w, ROOT_INDEX, index)
    return capture_file(o, w)

def invoke_document(o:mutbuf, w:mutbuf) -> u64:
    launch_directory(w, o, 0)
    role_argument(w, o, 2, STORE_ROLE)
    role_argument(w, o, 3, READY_ROLE)
    role_argument(w, o, 4, UNIQUE_ROLE)
    role_argument(w, o, 5, PUBLISHER_ROLE)
    role_argument(w, o, 6, DOCUMENT_PLAN_ROLE)
    role_argument(w, o, 7, DOCUMENT_EFFECT_ROLE)
    if get(w, REQUIRE_DIGEST) == 64:
        span_argument(o, 8, 384, slot_fd(w, ACTION_FD), 56 + get(w, FILE_LENGTH), 64)
    else:
        put(o, 416, 45)
        argv(o, 8, LITERAL_ARG, 416)
    fragment(o, 0, slot_fd(w, INPUT_FD), get(w, INPUT_AT), get(w, INPUT_EXTENT))
    return action(o, w, DOCUMENT, RUN, DOCUMENT_ROLE, 9, 1, 0)

def document_observation(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    status = input_word(s, 24)
    size = input_word(s, 40)
    if input_word(s, 48) != 15:
        return BAD
    if status == 18688 and size == 0:
        return artifact_error(o, w, 2, 3)
    if status != 0 or size != 200:
        return BAD
    put(o, HEADER, PROFILE_COMPOSE)
    put(o, HEADER + 8, get(w, INPUT_EXTENT))
    fragment(o, 0, input_word(s, 32), 0, size)
    return action(o, w, EFFECT_RENDERED, RUN, PROFILE_ROLE, 0, 1, 16)

def publish_artifact(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    if state == RESPONSE_RENDERED:
        if prefixed(s) == False:
            return BAD
        observe_slot(s, w, RENDERED_FD)
        if get(w, EFFECT_STATUS) == 1:
            return schema_receipt(o, w, OUTPUT_SCHEMA, OUTPUT_SCHEMA_ROLE, RENDERED_FD)
        return send_journal(o, w, 8)
    if state == OUTPUT_SCHEMA:
        if reply_word(s, 0) == False:
            return BAD
        return send_journal(o, w, 8)
    if state == COST_CLOCK:
        tick = input_word(s, 64)
        started = get(w, START_TIME)
        if length(s) != 72 or input_word(s, 40) != 8 or tick < started:
            return BAD
        put(o, HEADER, COST_OBSERVATION)
        put(o, HEADER + 8, tick - started)
        put(o, HEADER + 16, slot_bytes(w, REPLY_FD))
        whole_slot(w, o, REPLY_FD, 0)
        return action(o, w, COST_OBSERVED, RUN, FLOW_ROLE, 0, 1, 24)
    if state == COST_OBSERVED:
        fragment(o, 0, input_word(s, 32), 0, input_word(s, 40))
        return action(o, w, COST_TYPED, RUN, COST_ROLE, 0, 1, 0)
    if state == COST_TYPED:
        if plan_ok(s) == False or input_word(s, 40) <= 8:
            return BAD
        observe_slot(s, w, COST_FD)
        return open_store(o, w, OPEN_COST)
    if state == TERMINAL:
        size = input_word(s, 40)
        if size < 3 or size > 8388609:
            return BAD
        observe_slot(s, w, REPORT_FD)
        return read_span(o, w, REPORT_END, input_word(s, 32), size - 1, 1)
    if state == REPORT_END:
        if length(s) != 65 or byte(s, 64) != 10:
            return BAD
        whole_slot(w, o, REPORT_FD, 0)
        return action(o, w, REPORT_PUBLISHED, PUBLISH, 0, 0, 1, 0)
    if state == REPORT_PUBLISHED and length(s) == 64:
        return action(o, w, REPORT_PUBLISHED, FINISHED, 0, 0, 0, 0)
    return BAD

def send_report(o:mutbuf, w:mutbuf, replay:bool) -> u64:
    at = choose(replay, get(w, CACHED_AT), get(w, JOURNAL_AT))
    extent = choose(replay, get(w, CACHED_BYTES), get(w, JOURNAL_BYTES))
    slot = choose(replay, LOOKUP_FD, REPLY_FD)
    put(o, HEADER, PUBLICATION_REQUEST)
    put(o, HEADER + 8, slot_bytes(w, ORIGINAL))
    put(o, HEADER + 16, extent)
    put(o, HEADER + 24, get(w, 24))
    put(o, HEADER + 32, get(w, 32))
    copy_private(w, o, TRUST, HEADER + 40, 256)
    whole_slot(w, o, ORIGINAL, 0)
    fragment(o, 1, slot_fd(w, slot), at, extent)
    return action(o, w, TERMINAL, RUN, TERMINAL_ROLE, 0, 2, 296)
'''


def program():
    words = {
        'ENTRY': b'HIADRI01', 'OBSERVATION': b'HIADFO01', 'COMMAND': b'HIADFC01',
        'DOSSIER': b'HIARWD01', 'ADMITTED': b'HIADRA01', 'CONFIG': b'HIARAC01',
        'ADMISSION': b'HIAWRA01', 'ADMIT_HEADER': b'HIAWRA01', 'PROJECT': b'HIAWJP01',
        'ARGUMENT': b'HIAWAP01', 'RESPONSE': b'HIAWRC01', 'PUBLICATION_REQUEST': b'HIATRP01',
        'JOURNAL_COMMAND': b'HIAJMP01', 'JOURNAL_OBSERVED': b'HIAJMV01',
        'JOURNAL_REPLY': b'HIAJMO01', 'JOURNAL_KEY': b'HIAJMK01', 'ERROR_PACKET': b'HIAJME01',
        'COST_OBSERVATION': b'HIAJMC01',
        'STORE_ARG': b'store', 'UNIQUE': b'HIASTUP1', 'LOOKUP_OBSERVATION': b'HIARJO01',
        'LOOKUP_LAYOUT': b'HIARJO02', 'PROFILE_QUERY_TAG': b'HIARPF01',
        'PROFILE_OBSERVED': b'HIARPF02', 'PROFILE_ATTESTATION': b'HIARPF03',
        'PROFILE_COMPOSE': b'HIARPF04', 'PROFILE_BINDING': b'HIARPO01',
        'PROFILE_AUTHORITY': b'HIARPO02', 'ACTION_PLAN': b'HIARAP01',
        'STORE_GET': b'store-ge', 'STORE_GET_END': b't', 'ARTIFACT_ROOT': b'/artifac',
        'ARTIFACT_ROOT_END': b'ts',
    }
    constants = {label: int.from_bytes(value, 'little') for label, value in words.items()}
    constants.update(BAD=0xfffffffd, HEADER=512, ENTRY_HEAD=64, DOSSIER_HEAD=312,
                     DESCRIPTOR_BYTES=40, ROLE_COUNT=23, ENTRY_BYTES=64 + 312 + 23 * 40,
                     ELF_MAGIC=0x464c457f, MAX_INPUT=8388608, ARGUMENTS=192,
                     INLINE_FRAGMENT=(1 << 64) - 1, PROFILE_REFUSAL=4294967289,
                     DEFAULT_CHILD_LEASE=10_000_000_000, TRUST=512, PROFILE_PIN=768,
                     SLOT_BASE=896, JOURNAL_STATE=1280, JOURNAL_ROUTE=1792,
                     ROLE_BASE=2048, ROOTS_BASE=2304, STORE_PEER=0,
                     RUN=1, READ=2, PUBLISH=3, CLOCK=4, FINISHED=5,
                     START_PEER=6, RECEIVE_PEER=7, FINISH_PEER=8,
                     INPUT_ARG=1, LITERAL_ARG=2, DECIMAL_ARG=3, FD_ARG=4, JOINED_ARG=5, SPAN_ARG=6)
    roles = ('ADMIT', 'PROJECT', 'ARGUMENT', 'INPUT_SCHEMA', 'FLOW', 'JOURNAL',
             'STORE', 'READY', 'UNIQUE', 'RECORD', 'OBSERVE', 'CAPTURE', 'PROFILE',
             'PUBLISHER', 'PLAN', 'DOCUMENT', 'DOCUMENT_PLAN', 'DOCUMENT_EFFECT',
             'COMPOSE', 'OUTPUT_SCHEMA', 'COST', 'TERMINAL', 'DIAGNOSTIC')
    constants.update({name + '_ROLE': index for index, name in enumerate(roles)})
    states = ('CONFIG_HEADER', 'ROOT_LENGTH', 'ROOT_BYTES', 'STARTED', 'REQUEST_ADMITTED',
              'CALL_PROJECTED', 'ARGUMENT_PROJECTED', 'INPUT_SCHEMA', 'DIAGNOSTIC',
              'ARGUMENT_PLAN', 'JOURNAL_REQUEST', 'JOURNAL_REACTOR', 'JOURNAL_PROOF',
              'JOURNAL_STATE_FRAME', 'JOURNAL_RECIPE', 'RESERVATION_CLOCK', 'TYPED_REQUEST',
              'TYPED', 'PEER_STARTED', 'PEER_READY', 'PEER_ADMITTED', 'STORE_RETURNED',
              'STORE_SETTLED', 'PEER_CLOSED', 'LOOKUP_AUDITED', 'PROFILE_JSON',
              'PROFILE_ACTION', 'PROFILE_QUERY', 'PROFILE_AUTHORIZED', 'PROFILE_PROOF',
              'PROFILE_PIN_FRAME', 'PROFILE_CAPTURED', 'MATERIALIZATION_PLAN', 'FILE_PATH',
              'INPUT_FILE', 'DOCUMENT', 'ERROR_RENDERED', 'EFFECT_RENDERED',
              'RESPONSE_RENDERED', 'OUTPUT_SCHEMA', 'COST_CLOCK', 'COST_OBSERVED',
              'COST_TYPED', 'TERMINAL', 'REPORT_END', 'REPORT_PUBLISHED')
    constants.update({name: index for index, name in enumerate(states, 1)})
    purposes = ('OPEN_LOOKUP', 'OPEN_PROFILE', 'OPEN_COST', 'CLOSED_LOOKUP',
                'CLOSED_RESERVATION', 'CLOSED_PROFILE_REFUSED', 'CLOSED_PROFILE', 'CLOSED_COST',
                'STORE_LOOKUP', 'STORE_RESERVATION', 'STORE_RESERVATION_COMMIT',
                'STORE_PROFILE_ROW', 'STORE_PROFILE_ID', 'STORE_COST', 'STORE_TERMINAL')
    constants.update({name: index for index, name in enumerate(purposes, 1)})
    slots = ('ORIGINAL', 'DOSSIER_FD', 'METADATA_FD', 'ADMITTED_FD', 'CALL_FD',
             'ARGUMENT_FD', 'PLAN_FD', 'REPLY_FD', 'EFFECT_FD', 'RENDERED_FD',
             'QUERY_FD', 'STORE_RESULT', 'LOOKUP_FD', 'ACTION_FD', 'PROFILE_FD',
             'INPUT_FD', 'COST_FD', 'REPORT_FD')
    constants.update({name: index for index, name in enumerate(slots)})
    fields = ('START_TIME', 'PROFILE_SIZE', 'ROOTS_COUNT', 'ROOT_INDEX', 'ROOT_REMAINING',
              'CONFIG_AT', 'JOURNAL_STAGE', 'JOURNAL_AT', 'JOURNAL_BYTES', 'JOURNAL_NEXT',
              'JOURNAL_STATUS', 'EFFECT_AT', 'EFFECT_STATUS', 'LOOKUP_AT', 'LOOKUP_BYTES',
              'CACHED_AT', 'CACHED_BYTES', 'TYPED_PURPOSE', 'STORE_PURPOSE', 'STORE_MODE',
              'STORE_STEP', 'STORE_REPLY_FD', 'STORE_COMMAND_FD', 'STORE_REQUEST', 'STORE_EPOCH',
              'INPUT_EXTENT', 'INPUT_AT', 'REQUIRE_DIGEST', 'FILE_LIMIT', 'FILE_LENGTH', 'FILE_OFFSET')
    constants.update({name: 128 + 8 * index for index, name in enumerate(fields)})
    entry = entry_program()
    controls = (
        function(COST_POLICY, 'action'),
        function(DESCRIBE, 'issue').replace('seq > 160', 'seq > 512'),
        function(ENTRY_POLICY, 'admit_entry').replace('metadata < 224 or metadata > 32768',
                                                    'metadata < 88 or metadata > 132000'),
        *(function(ENTRY_POLICY, name) for name in ('trusted_descriptors', 'dossier_identity')),
        *(function(DESCRIBE, name) for name in (
            'argv', 'fragment', 'keep', 'observe_slot', 'slot_fd', 'slot_bytes', 'whole_slot',
            'after_prefix', 'prefixed', 'reply_word', 'copy_private', 'zero_range',
            'role_argument', 'launch_directory')),
        *(function(READ_POLICY, name) for name in ('receive', 'read_span')),
        *(function(entry, name) for name in ('valid_fd', 'is_hex', 'copy_span', 'input_word', 'put', 'write')),
        function(RELEASE_WRITER, 'get'),
    )
    return flow_source(POLICY, (STORE_POLICY, EFFECT_POLICY, *controls), constants)


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)), encoding='utf-8')
