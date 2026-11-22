"""Author the native Context Worker and its descriptor-scoped effect schedule."""

from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_release_install import POLICY_SOURCE as RELEASE_WRITER
from tools.generate_hia_worker_artifact_flow import (
    POLICY as ARTIFACT, STORE_POLICY as STORE, EFFECT_POLICY as PUBLICATION, policy_constants,
)
from tools.generate_hia_worker_cost_flow import POLICY as COST
from tools.generate_hia_worker_describe_flow import POLICY as DESCRIBE, flow_source
from tools.generate_hia_worker_describe_reactor import POLICY as ENTRY_POLICY, program as entry_program
from tools.generate_hia_worker_inspection_effect import function
from tools.generate_hia_worker_read_store_flow import POLICY as READ_POLICY

SOURCE = Path('examples/hia_bootstrap/worker_context_flow.hepta')

POLICY = r'''
def context_flow(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
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
    offset = choose(operation == RUN or operation == MAKE or operation == CPU, 0, input_word(s, 48))
    captured = input_word(s, 56)
    if extent > 67112960 or offset > extent or captured > extent - offset or captured != length(s) - 64:
        return BAD
    if (operation == RUN or operation == MAKE or operation == CPU) and valid_fd(input_word(s, 32)) == False:
        return BAD
    if operation == READ and (input_word(s, 32) != get(w, 80) or offset != get(w, 88) or captured != get(w, 96)):
        return BAD
    if state == INSTALL_REFERENCE or state == INSTALL_PROFILES:
        return observe_installation(s, o, w, state)
    if state <= STARTED:
        return configure_context(s, o, w, state)
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
    if state <= CONTROL_CLOSED:
        return control_flow(s, o, w, state)
    if state <= PROFILE_ROW_BOUND:
        return retained_flow(s, o, w, state)
    if state <= BASE_READY:
        return baseline_flow(s, o, w, state)
    if state <= MANIFEST_PUBLISHED:
        return manifest_flow(s, o, w, state)
    return context_results(s, o, w, state)

def configure_context(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    if state != STARTED or length(s) != 72 or input_word(s, 40) != 8:
        return BAD
    put(w, START_TIME, input_word(s, 64))
    put(o, HEADER, ADMISSION)
    put(o, HEADER + 8, get(w, 24))
    copy_private(w, o, TRUST, HEADER + 16, 64)
    whole_slot(w, o, ORIGINAL, 0)
    return action(o, w, REQUEST_ADMITTED, RUN, ADMIT_ROLE, 0, 1, 80)

def observe_installation(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    if plan_ok(s) == False:
        return BAD
    if state == INSTALL_REFERENCE:
        if input_word(s, 40) != 184:
            return BAD
        body_span(s, w, CONTEXT_REFERENCE_QUERY)
        return artifact_lookup(o, w)
    if input_word(s, 40) != 136:
        return BAD
    return read_span(o, w, INSTALL_PROFILE_PINS, input_word(s, 32), 8, 128)

def install_profile_pins(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    i = 0
    while i < 128:
        v = byte(s, 64 + i)
        if is_hex(v) == False:
            return BAD
        store(w, PROFILE_PIN + i, v)
        i = i + 1
    put(w, INSTALL_PENDING, 0)
    return clock_sample(o, w, STARTED, 0)

def authorize_business(o:mutbuf, w:mutbuf) -> u64:
    if slot_bytes(w, ARGUMENT_FD) < 10:
        return BAD
    after_prefix(w, o, ARGUMENT_FD, 0)
    return action(o, w, CTX_REQUEST_PLAN, RUN, PLAN_ROLE, 0, 1, 0)

def control_flow(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    if state <= CTX_NULL:
        return parse_context(s, o, w, state)
    if state == CONTROL_NONCE:
        if length(s) != 80 or input_word(s, 40) != 16:
            return BAD
        copy_span(s, w, 64, CONTROL_ID, 16)
        put(o, 176, CONTROL_PEER)
        return action(o, w, CONTROL_OPEN, START_PEER, CONTROL_ROLE, 0, 0, 0)
    if state == CONTROL_OPEN:
        if length(s) != 80 or input_word(s, 40) != 16:
            return BAD
        return control_event(o, w, 0, 0)
    if state == CONTROL_SENT:
        return receive(o, w, CONTROL_RECEIVED, CONTROL_PEER, 80, False)
    if state == CONTROL_RECEIVED:
        return control_reply(s, o, w)
    if state == CONTROL_WORKLOAD or state == CONTROL_COSTS or state == CONTROL_MEMORY:
        return measured_costs(s, o, w, state)
    if state == CONTROL_EFFECT:
        return effect_route(s, o, w)
    if state == CONTEXT_ERROR:
        if input_word(s, 40) == 0:
            return BAD
        observe_slot(s, w, EFFECT_FD)
        put(w, CTX_FAILED, 1)
        return control_event(o, w, 3, 0)
    if state == CONTROL_CLOSED and length(s) == 64:
        if get(w, CTX_FAILED) == 1:
            return end_effect(o, w, 2, 0)
        slot = get(w, CTX_ANSWER)
        keep(w, EFFECT_FD, get(w, slot), get(w, slot + 8) + get(w, slot + 16))
        return end_effect(o, w, 1, get(w, slot + 8))
    return BAD

def parse_context(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    if state == CTX_REQUEST_PLAN:
        if plan_ok(s) == False or length(s) < 112 or input_word(s, 72) != CONTEXT_PLAN_TAG:
            return BAD
        observe_slot(s, w, ACTION_FD)
        copy_span(s, w, 72, CONTEXT_REQUEST, 40)
        put(w, CTX_FIELD_AT, 48)
        return next_context_field(o, w)
    if state == CTX_FIELD_WIDTH:
        n = input_word(s, 64)
        at = get(w, CTX_FIELD_AT) + 8
        extent = slot_bytes(w, ACTION_FD)
        field = get(w, CTX_FIELD)
        if n == 0 or at > extent or n > extent - at or field >= 8:
            return BAD
        hold(w, CONTEXT_VALUES + 24 * field, slot_fd(w, ACTION_FD), at, n)
        put(w, CTX_FIELD_AT, at + n)
        put(w, CTX_FIELD, field + 1)
        return next_context_field(o, w)
    if input_word(s, 40) != 4:
        return BAD
    sample_span(s, w, CONTEXT_BASE)
    return random_sample(o, w, CONTROL_NONCE)

def next_context_field(o:mutbuf, w:mutbuf) -> u64:
    at = get(w, CTX_FIELD_AT)
    extent = slot_bytes(w, ACTION_FD)
    if get(w, CTX_FIELD) == 8:
        if at != extent:
            return BAD
        put(o, HEADER, NULL_VALUE)
        return action(o, w, CTX_NULL, MAKE, 0, 0, 0, 4)
    if at > extent or extent - at < 8:
        return BAD
    return read_span(o, w, CTX_FIELD_WIDTH, slot_fd(w, ACTION_FD), at, 8)

def random_sample(o:mutbuf, w:mutbuf, state:u64) -> u64:
    put(o, 144, 16)
    return action(o, w, state, RANDOM, 0, 0, 0, 0)

def control_event(o:mutbuf, w:mutbuf, event:u64, value:u64) -> u64:
    zero_range(o, HEADER, 80)
    put(w, CTX_EVENT, event)
    put(o, HEADER, CONTROL_EVENT_TAG)
    put(o, HEADER + 8, event)
    put(o, HEADER + 16, get(w, CONTEXT_CLAIM + 24))
    put(o, HEADER + 24, get(w, CONTEXT_CLAIM + 16))
    put(o, HEADER + 32, value)
    put(o, HEADER + 40, 1)
    copy_private(w, o, CONTROL_ID, HEADER + 48, 16)
    put(o, 176, CONTROL_PEER)
    return action(o, w, CONTROL_SENT, SEND_PEER, 0, 0, 0, 80)

def control_reply(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if length(s) != 144 or input_word(s, 40) != 80 or input_word(s, 64) != CONTROL_REPLY_TAG:
        return BAD
    if input_word(s, 72) != 0 or input_word(s, 104) != 1 or input_word(s, 88) == 0:
        return BAD
    if input_word(s, 112) > 3 or input_word(s, 120) > 1:
        return BAD
    if input_word(s, 128) != get(w, CONTROL_ID) or input_word(s, 136) != get(w, CONTROL_ID + 8):
        return BAD
    event = get(w, CTX_EVENT)
    phase = input_word(s, 96)
    port = input_word(s, 80)
    if event == 1 and (phase != 2 or port != get(w, CONTEXT_CLAIM + 16) or input_word(s, 88) != get(w, CONTEXT_CLAIM + 24)):
        return BAD
    copy_span(s, w, 64, CONTEXT_CLAIM, 80)
    if event == 1:
        if port == 8:
            use_span(w, o, CONTEXT_DATA, 0)
            return action(o, w, CONTROL_WORKLOAD, RUN, WORKLOAD_ROLE, 0, 1, 0)
        if port == 21:
            use_span(w, o, CONTEXT_DATA + 48, 0)
            return action(o, w, CONTROL_COSTS, RUN, FACTS_ROLE, 0, 1, 0)
        return request_effect(o, w)
    if phase == 1 and event != 3:
        visits = get(w, CTX_VISITS) + 1
        if visits > 256:
            return BAD
        put(w, CTX_VISITS, visits)
        return control_event(o, w, 1, 0)
    answer = get(w, CTX_ANSWER)
    if (phase == 4 and answer != 0 and get(w, CTX_FAILED) == 0) or (phase == 5 and answer == 0 and get(w, CTX_FAILED) == 1):
        put(o, 176, CONTROL_PEER)
        return action(o, w, CONTROL_CLOSED, FINISH_PEER, 0, 0, 0, 0)
    return BAD

def measured_costs(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    if plan_ok(s) == False:
        return BAD
    span = input_word(s, 40)
    if state == CONTROL_WORKLOAD:
        if span < 56 or length(s) < 120 or input_word(s, 112) != span - 56:
            return BAD
        copy_span(s, w, 72, CONTEXT_WORKLOAD, 48)
        hold(w, CONTEXT_EXPORTS, input_word(s, 32), 56, span - 56)
        return request_effect(o, w)
    if state == CONTROL_COSTS:
        if span != 56:
            return BAD
        copy_span(s, w, 72, CONTEXT_COSTS, 48)
        use_span(w, o, CONTEXT_VALUES + 168, 0)
        return action(o, w, CONTROL_MEMORY, RUN, FACTS_ROLE, 0, 1, 0)
    if span != 32:
        return BAD
    copy_span(s, w, 72, CONTEXT_MEMORY, 24)
    return request_effect(o, w)

def request_effect(o:mutbuf, w:mutbuf) -> u64:
    put(o, HEADER, CONTEXT_EFFECT_TAG)
    put(o, HEADER + 8, get(w, CONTEXT_VALUES + 48 + 16))
    copy_private(w, o, CONTEXT_CLAIM, HEADER + 16, 80)
    copy_private(w, o, CONTEXT_REQUEST, HEADER + 96, 40)
    copy_private(w, o, CONTEXT_WORKLOAD, HEADER + 136, 48)
    copy_private(w, o, CONTEXT_COSTS, HEADER + 184, 48)
    copy_private(w, o, CONTEXT_MEMORY, HEADER + 232, 24)
    use_span(w, o, CONTEXT_VALUES + 48, 0)
    return action(o, w, CONTROL_EFFECT, RUN, CONTEXT_EFFECT_ROLE, 0, 1, 256)

def effect_route(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if plan_ok(s) == False or input_word(s, 40) != 40 or input_word(s, 72) != CONTEXT_DECISION:
        return BAD
    kind = input_word(s, 80)
    first = input_word(s, 88)
    second = input_word(s, 96)
    if kind == 2:
        return context_error(o, w, first, second)
    if kind == 1 and first <= 1 and second == 0:
        return control_event(o, w, 2, first)
    port = get(w, CONTEXT_CLAIM + 16)
    if kind != 0 or first != port or second != 0:
        return BAD
    if port == 1:
        return control_event(o, w, 2, 0)
    if port == 2 or port == 3:
        return authorize_profile(o, w, port - 1)
    if (port >= 4 and port <= 6) or port == 39:
        field = choose(port == 39, 2, port - 1)
        src = CONTEXT_VALUES + 24 * field
        hold(w, CONTEXT_REFERENCE_QUERY, get(w, src), get(w, src + 8), get(w, src + 16))
        return artifact_lookup(o, w)
    if port == 7 or port == 18 or port == 19:
        role = choose(port == 7, 1, port - 16)
        put(o, HEADER, role)
        copy_private(w, o, TRUST, HEADER + 8, 64)
        use_span(w, o, CONTEXT_DATA + 24 * (role - 1), 0)
        return action(o, w, PAYLOAD_CHECKED, RUN, PAYLOAD_ROLE, 0, 1, 72)
    if port == 40:
        return clock_sample(o, w, UTC_SAMPLED, 2)
    if port == 41:
        return action(o, w, PLATFORM_SAMPLED, UNAME, 0, 0, 0, 0)
    if port == 42:
        return publish_manifest(o, w)
    if port == 43:
        return random_sample(o, w, CONTEXT_NONCE)
    if port == 44:
        return clock_sample(o, w, CONTEXT_CREATED, 1)
    if port == 45:
        return context_create(o, w)
    if port == 46:
        return render_context(o, w)
    return BAD

def context_error(o:mutbuf, w:mutbuf, scope:u64, reason:u64) -> u64:
    zero_range(o, HEADER, 40)
    put(o, HEADER, ERROR_PACKET)
    put(o, HEADER + 8, scope)
    put(o, HEADER + 16, reason)
    return action(o, w, CONTEXT_ERROR, RUN, FLOW_ROLE, 0, 0, 40)

def hold(w:mutbuf, record:u64, fd:u64, at:u64, extent:u64) -> u64:
    put(w, record, fd)
    put(w, record + 8, at)
    put(w, record + 16, extent)
    return 0

def use_span(w:mutbuf, o:mutbuf, record:u64, index:u64) -> u64:
    return fragment(o, index, get(w, record), get(w, record + 8), get(w, record + 16))

def sample_span(s:readbuf, w:mutbuf, record:u64) -> u64:
    return hold(w, record, input_word(s, 32), 0, input_word(s, 40))

def body_span(s:readbuf, w:mutbuf, record:u64) -> u64:
    return hold(w, record, input_word(s, 32), 8, input_word(s, 40) - 8)
'''

RETAINED_POLICY = r'''
def authorize_profile(o:mutbuf, w:mutbuf, role:u64) -> u64:
    put(w, CTX_PROFILE_ROLE, role)
    put(o, HEADER, PROFILE_BY_REFERENCE)
    put(o, HEADER + 8, role)
    copy_private(w, o, PROFILE_PIN + (role - 1) * 64, HEADER + 16, 64)
    use_span(w, o, CONTEXT_VALUES + (role - 1) * 24, 0)
    return action(o, w, PROFILE_QUERY_BOUND, RUN, PROFILE_ROLE, 0, 1, 80)

def artifact_lookup(o:mutbuf, w:mutbuf) -> u64:
    put(o, HEADER, RETAINED_QUERY)
    put(o, HEADER + 8, 0)
    use_span(w, o, CONTEXT_REFERENCE_QUERY, 0)
    return action(o, w, RETAINED_QUERY_BOUND, RUN, PROFILE_ROLE, 0, 1, 16)

def retained_flow(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    if state == PROFILE_QUERY_BOUND:
        if reply_word(s, PROFILE_REFERENCE_REFUSED):
            return context_error(o, w, 2, 1)
        if plan_ok(s) == False or input_word(s, 40) <= 8 or input_word(s, 40) > 168:
            return BAD
        observe_slot(s, w, QUERY_FD)
        return open_store(o, w, OPEN_CONTEXT_PROFILE)
    if state == PROFILE_ROW_BOUND:
        if reply_word(s, PROFILE_REFUSAL):
            return close_store(o, w, CLOSE_CONTEXT_PROFILE_REFUSED)
        if (plan_ok(s) == False or input_word(s, 40) != 290 or length(s) < 88
                or input_word(s, 72) != PROFILE_BINDING or input_word(s, 80) != 176):
            return BAD
        hold(w, CONTEXT_REFERENCE_QUERY, input_word(s, 32), 24, 176)
        return close_store(o, w, CLOSE_CONTEXT_PROFILE)
    if state == RETAINED_QUERY_BOUND:
        if reply_word(s, RETAINED_REFUSAL):
            if get(w, INSTALL_PENDING) == 1:
                return BAD
            return context_error(o, w, 7, 1)
        if plan_ok(s) == False or input_word(s, 40) != 98:
            return BAD
        observe_slot(s, w, QUERY_FD)
        return open_store(o, w, OPEN_CONTEXT_ARTIFACT)
    if state == RETAINED_ROW_BOUND:
        if reply_word(s, RETAINED_REFUSAL):
            return close_store(o, w, CLOSE_CONTEXT_ARTIFACT_REFUSED)
        if plan_ok(s) == False or input_word(s, 40) != 80:
            return BAD
        observe_slot(s, w, PROFILE_FD)
        return close_store(o, w, CLOSE_CONTEXT_ARTIFACT)
    if state == RETAINED_DIGEST:
        if input_word(s, 64) != RETAINED_AUTHORITY:
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
    if state == RETAINED_BYTES:
        if get(w, INSTALL_PENDING) == 1:
            return bind_installation_profiles(s, o, w)
        port = get(w, CONTEXT_CLAIM + 16)
        if port == 2 or port == 3:
            return control_event(o, w, 2, 0)
        if port >= 4 and port <= 6:
            sample_span(s, w, CONTEXT_DATA + (port - 4) * 24)
            return control_event(o, w, 2, 0)
        if port == 39:
            fragment(o, 0, input_word(s, 32), 0, input_word(s, 40))
            return action(o, w, BASE_ADMISSION, RUN, NOMINAL_ROLE, 0, 1, 0)
    return BAD

def bind_installation_profiles(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    size = input_word(s, 40)
    if size < 2 or size > 16315:
        return BAD
    store(o, HEADER, 91)
    store(o, HEADER + 1, 34)
    copy_private(w, o, TRUST, HEADER + 2, 64)
    store(o, HEADER + 66, 34)
    store(o, HEADER + 67, 44)
    fragment(o, 0, input_word(s, 32), 0, size)
    store(o, 496, 93)
    fragment(o, 1, INLINE_FRAGMENT, 496, 1)
    return action(o, w, INSTALL_PROFILES, RUN, PLAN_ROLE, 0, 2, 68)

def context_store_opened(o:mutbuf, w:mutbuf, purpose:u64) -> u64:
    query = slot_fd(w, QUERY_FD)
    bytes = slot_bytes(w, QUERY_FD)
    if purpose == OPEN_CONTEXT_PROFILE:
        return store_transaction(o, w, CONTEXT_PROFILE_ROW, 12, 1, query, 8, bytes - 8)
    if purpose == OPEN_CONTEXT_ARTIFACT:
        return store_transaction(o, w, CONTEXT_ARTIFACT_ROW, 2, 1, query, 8, bytes - 8)
    if purpose == OPEN_CONTEXT_CREATE:
        return context_insert(o, w)
    return BAD

def context_store_closed(o:mutbuf, w:mutbuf, purpose:u64) -> u64:
    if purpose == CLOSE_CONTEXT_PROFILE:
        return artifact_lookup(o, w)
    if purpose == CLOSE_CONTEXT_PROFILE_REFUSED:
        return context_error(o, w, 2, 2)
    if purpose == CLOSE_CONTEXT_ARTIFACT:
        return read_span(o, w, RETAINED_DIGEST, slot_fd(w, PROFILE_FD), 8, 72)
    if purpose == CLOSE_CONTEXT_ARTIFACT_REFUSED:
        if get(w, INSTALL_PENDING) == 1:
            return BAD
        return context_error(o, w, 7, 1)
    if purpose == CLOSE_CONTEXT_CREATE:
        return create_reference(o, w)
    return BAD

def context_row(o:mutbuf, w:mutbuf, purpose:u64, bytes:u64) -> u64:
    put(o, HEADER + 8, bytes)
    put(o, HEADER + 16, get(w, STORE_REQUEST))
    put(o, HEADER + 24, get(w, STORE_EPOCH))
    if purpose == CONTEXT_PROFILE_ROW:
        role = get(w, CTX_PROFILE_ROLE)
        put(o, HEADER, CONTEXT_PROFILE_OBSERVED)
        put(o, HEADER + 32, role)
        copy_private(w, o, PROFILE_PIN + 64 * (role - 1), HEADER + 40, 64)
        whole_slot(w, o, STORE_RESULT, 0)
        return action(o, w, PROFILE_ROW_BOUND, RUN, PROFILE_ROLE, 0, 1, 104)
    put(o, HEADER, RETAINED_OBSERVED)
    put(o, HEADER + 32, 0)
    use_span(w, o, CONTEXT_REFERENCE_QUERY, 0)
    whole_slot(w, o, STORE_RESULT, 1)
    return action(o, w, RETAINED_ROW_BOUND, RUN, PROFILE_ROLE, 0, 2, 40)

def artifact_command(o:mutbuf, w:mutbuf, state:u64, verb:u64, tail:u64, parts:u64) -> u64:
    put(o, 384, verb)
    put(o, 392, tail)
    put(o, 400, ARTIFACT_ROOT)
    put(o, 408, ARTIFACT_ROOT_END)
    argv(o, 0, LITERAL_ARG, 384)
    argv(o, 1, JOINED_ARG, 400)
    argv(o, 2, LITERAL_ARG, 416)
    return action(o, w, state, RUN, PUBLISHER_ROLE, 3, parts, 0)

def baseline_flow(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    if state == BASE_ADMISSION:
        size = input_word(s, 40)
        types = input_word(s, 96)
        payload = input_word(s, 104)
        if (length(s) != 128 or size < 64 or input_word(s, 64) != NOMINAL_PACKET
                or input_word(s, 72) != 0 or input_word(s, 80) != 0 or input_word(s, 88) > 4
                or types == 0 or payload == 0 or types > size - 64 or payload != size - 64 - types
                or input_word(s, 112) != 0 or input_word(s, 120) != 0):
            return BAD
        put(o, 416, 45)
        fragment(o, 0, input_word(s, 32), 64 + types, payload)
        return artifact_command(o, w, BASE_DIGEST, STORE_HASH, STORE_HASH_END, 1)
    if state == BASE_DIGEST:
        size = input_word(s, 40)
        if size == 0 or size >= 160:
            return BAD
        return read_span(o, w, BASE_DIGEST_FRAME, input_word(s, 32), 0, size)
    if state == BASE_DIGEST_FRAME:
        return digest_frame(s, o, w)
    if state == BASE_READY and input_word(s, 40) == 66:
        sample_span(s, w, CONTEXT_BASE)
        return control_event(o, w, 2, 0)
    return BAD

def digest_frame(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    size = length(s) - 64
    i = 0
    while i + 75 < size:
        pos = 64 + i
        if input_word(s, pos) == SHA_JSON and byte(s, pos + 8) == 58 and byte(s, pos + 9) == 34 and byte(s, pos + 74) == 34:
            j = 0
            while j < 64 and is_hex(byte(s, pos + 10 + j)):
                j = j + 1
            if j == 64:
                copy_span(s, o, pos + 9, HEADER, 66)
                return action(o, w, BASE_READY, MAKE, 0, 0, 0, 66)
        i = i + 1
    return BAD
'''

MANIFEST_POLICY = r'''
def manifest_flow(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    if state == UTC_SAMPLED:
        if length(s) != 80 or input_word(s, 40) != 16:
            return BAD
        put(o, HEADER, UTC_FRAME)
        copy_span(s, o, 64, HEADER + 8, 16)
        return action(o, w, UTC_FORMED, RUN, CONTEXT_EFFECT_ROLE, 0, 0, 24)
    if state == UTC_FORMED:
        if prefixed(s) == False:
            return BAD
        body_span(s, w, CONTEXT_SAMPLE)
        return control_event(o, w, 2, 0)
    if state == PLATFORM_SAMPLED:
        if length(s) != 194 or input_word(s, 40) != 130:
            return BAD
        system = quote_platform(s, o, 64, HEADER)
        if system == 0:
            return BAD
        machine = quote_platform(s, o, 129, HEADER + system)
        if machine == 0:
            return BAD
        put(w, CTX_SYSTEM_SIZE, system)
        put(w, CTX_MACHINE_SIZE, machine)
        return action(o, w, PLATFORM_QUOTED, MAKE, 0, 0, 0, system + machine)
    if state == PLATFORM_QUOTED:
        system = get(w, CTX_SYSTEM_SIZE)
        machine = get(w, CTX_MACHINE_SIZE)
        if input_word(s, 40) != system + machine:
            return BAD
        fd = input_word(s, 32)
        hold(w, CONTEXT_SYSNAME, fd, 0, system)
        hold(w, CONTEXT_MACHINE, fd, system, machine)
        return action(o, w, CPU_SAMPLED, CPU, 0, 0, 0, 0)
    if state == CPU_SAMPLED:
        bytes = input_word(s, 40)
        if bytes < 2 or bytes >= 4096:
            return BAD
        put(o, HEADER, CPU_SAMPLE_TAG)
        fragment(o, 0, input_word(s, 32), 0, bytes)
        return action(o, w, CPU_FORMED, RUN, CONTEXT_EFFECT_ROLE, 0, 1, 8)
    if state == CPU_FORMED:
        bytes = input_word(s, 40)
        if plan_ok(s) == False or bytes < 17 or bytes > 23 or length(s) != 64 + bytes:
            return BAD
        if input_word(s, 72) != CPU_RESULT_TAG or byte(s, 80) < 49 or byte(s, 80) > 57:
            return BAD
        count = 0
        i = 80
        while i < length(s):
            digit = byte(s, i)
            if digit < 48 or digit > 57:
                return BAD
            count = count * 10 + digit - 48
            i = i + 1
        if count > 1048576:
            return BAD
        hold(w, CONTEXT_CPU, input_word(s, 32), 16, bytes - 16)
        store(o, HEADER, 34)
        copy_private(w, o, TRUST, HEADER + 1, 64)
        store(o, HEADER + 65, 34)
        return action(o, w, CATALOG_QUOTED, MAKE, 0, 0, 0, 66)
    if state == CATALOG_QUOTED:
        if input_word(s, 40) != 66:
            return BAD
        sample_span(s, w, CONTEXT_CATALOG)
        return form_manifest(o, w)
    if state == MANIFEST_FORMED:
        if prefixed(s) == False:
            return BAD
        body_span(s, w, CONTEXT_MANIFEST)
        return control_event(o, w, 2, 0)
    if state == MANIFEST_PUBLISHED:
        if length(s) < 88 or input_word(s, 40) != 200 or input_word(s, 48) != 15:
            return BAD
        if input_word(s, 64) != DOCUMENT_RECEIPT or input_word(s, 72) != 176 or input_word(s, 80) != 0:
            return BAD
        hold(w, CONTEXT_ARTIFACT, input_word(s, 32), 24, 176)
        return control_event(o, w, 2, 0)
    return BAD

def quote_platform(s:readbuf, o:mutbuf, start:u64, target:u64) -> u64:
    store(o, target, 34)
    i = 0
    while i < 65:
        value = byte(s, start + i)
        if value == 0:
            store(o, target + i + 1, 34)
            return i + 2
        if value < 32 or value > 126 or value == 34 or value == 92:
            return 0
        store(o, target + i + 1, value)
        i = i + 1
    return 0

def form_manifest(o:mutbuf, w:mutbuf) -> u64:
    catalog = get(w, 40)
    hold(w, CONTEXT_IDENTITIES, slot_fd(w, DOSSIER_FD), DOSSIER_HEAD + catalog, get(w, 48))
    put(w, CONTEXT_VECTOR, CONTEXT_BASE)
    put(w, CONTEXT_VECTOR + 8, CONTEXT_VALUES + 48)
    put(w, CONTEXT_VECTOR + 16, CONTEXT_VALUES + 144)
    put(w, CONTEXT_VECTOR + 24, CONTEXT_CATALOG)
    put(w, CONTEXT_VECTOR + 32, CONTEXT_VALUES)
    put(w, CONTEXT_VECTOR + 40, CONTEXT_EXPORTS)
    put(w, CONTEXT_VECTOR + 48, CONTEXT_IDENTITIES)
    put(w, CONTEXT_VECTOR + 56, CONTEXT_VALUES + 96)
    put(w, CONTEXT_VECTOR + 64, CONTEXT_SAMPLE)
    put(w, CONTEXT_VECTOR + 72, CONTEXT_CPU)
    put(w, CONTEXT_VECTOR + 80, CONTEXT_MACHINE)
    put(w, CONTEXT_VECTOR + 88, CONTEXT_SYSNAME)
    put(w, CONTEXT_VECTOR + 96, CONTEXT_VALUES + 24)
    put(w, CONTEXT_VECTOR + 104, CONTEXT_VALUES + 72)
    return record_context(o, w, MANIFEST_FORMED, 21, 14)

def render_context(o:mutbuf, w:mutbuf) -> u64:
    put(w, CONTEXT_VECTOR, CONTEXT_VALUES)
    put(w, CONTEXT_VECTOR + 8, CONTEXT_REFERENCE)
    put(w, CONTEXT_VECTOR + 16, CONTEXT_ARTIFACT)
    put(w, CONTEXT_VECTOR + 24, CONTEXT_SAMPLE)
    put(w, CONTEXT_VECTOR + 32, CONTEXT_VALUES + 24)
    return record_context(o, w, CONTEXT_RENDERED, 22, 5)

def record_context(o:mutbuf, w:mutbuf, state:u64, mode:u64, count:u64) -> u64:
    put(o, HEADER, CONTEXT_RECORD_TAG)
    put(o, HEADER + 8, mode)
    i = 0
    while i < count:
        record = get(w, CONTEXT_VECTOR + 8 * i)
        n = get(w, record + 16)
        at = 384 + 8 * i
        put(o, at, n)
        entry = HEADER + 16 + 48 * i
        vector_part(o, entry, INLINE_FRAGMENT, at, 8)
        vector_part(o, entry + 24, get(w, record), get(w, record + 8), n)
        i = i + 1
    total = action(o, w, state, RUN, CONTEXT_RECORD_ROLE, 0, 2 * count, 16)
    if total == BAD:
        return BAD
    put(o, 136, 1)
    return total + 48 * count

def vector_part(o:mutbuf, entry:u64, fd:u64, at:u64, bytes:u64) -> u64:
    put(o, entry, fd)
    put(o, entry + 8, at)
    put(o, entry + 16, bytes)
    return 0

def publish_manifest(o:mutbuf, w:mutbuf) -> u64:
    launch_directory(w, o, 0)
    role_argument(w, o, 2, STORE_ROLE)
    role_argument(w, o, 3, READY_ROLE)
    role_argument(w, o, 4, UNIQUE_ROLE)
    role_argument(w, o, 5, PUBLISHER_ROLE)
    role_argument(w, o, 6, DOCUMENT_PLAN_ROLE)
    role_argument(w, o, 7, DOCUMENT_EFFECT_ROLE)
    argv(o, 8, DECIMAL_ARG, 4)
    argv(o, 9, DECIMAL_ARG, 0)
    use_span(w, o, CONTEXT_MANIFEST, 0)
    return action(o, w, MANIFEST_PUBLISHED, RUN, DOCUMENT_ROLE, 10, 1, 0)
'''

RESULT_POLICY = r'''
def context_results(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    if state == INSTALL_PROFILE_PINS:
        return install_profile_pins(s, o, w)
    if state == PAYLOAD_CHECKED:
        if reply_word(s, 0) == False:
            return BAD
        return control_event(o, w, 2, 0)
    if state == CONTEXT_NONCE:
        if length(s) != 80 or input_word(s, 40) != 16:
            return BAD
        copy_span(s, w, 64, CONTEXT_UUID, 16)
        store(w, CONTEXT_UUID + 6, (byte(w, CONTEXT_UUID + 6) & 15) | 64)
        store(w, CONTEXT_UUID + 8, (byte(w, CONTEXT_UUID + 8) & 63) | 128)
        return control_event(o, w, 2, 0)
    if state == CONTEXT_CREATED:
        if length(s) != 72 or input_word(s, 40) != 8:
            return BAD
        put(w, CTX_TIME, input_word(s, 64))
        return control_event(o, w, 2, 0)
    if state == CONTEXT_BATCH:
        return bind_context_batch(s, o, w)
    if state == CREATE_MARKER:
        if reply_prefix(s, STORE_MARKER) == False:
            return BAD
        return close_store(o, w, CLOSE_CONTEXT_CREATE)
    if state == CREATE_REFERENCE:
        if plan_ok(s) == False or input_word(s, 40) != 129:
            return BAD
        body_span(s, w, CONTEXT_REFERENCE)
        return control_event(o, w, 2, 0)
    if state == CONTEXT_RENDERED:
        if prefixed(s) == False:
            return BAD
        body_span(s, w, CONTEXT_RESPONSE)
        put(w, CTX_ANSWER, CONTEXT_RESPONSE)
        return control_event(o, w, 2, 0)
    return BAD

def context_create(o:mutbuf, w:mutbuf) -> u64:
    if get(w, CTX_TIME) == 0 or get(w, CONTEXT_ARTIFACT + 16) != 176:
        return BAD
    put(o, HEADER, CONTEXT_CREATE_TAG)
    put(o, HEADER + 8, get(w, CTX_TIME))
    copy_private(w, o, CONTEXT_UUID, HEADER + 16, 16)
    use_span(w, o, CONTEXT_ARTIFACT, 0)
    return action(o, w, CONTEXT_BATCH, RUN, CONTEXT_BIND_ROLE, 0, 1, 32)

def bind_context_batch(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    size = input_word(s, 40)
    row = input_word(s, 80)
    if plan_ok(s) == False or length(s) < 104 or size < 176 or input_word(s, 72) != CONTEXT_BATCH_TAG:
        return BAD
    if input_word(s, 88) != 100 or input_word(s, 96) != 36 or row != size - 176 or row == 0:
        return BAD
    observe_slot(s, w, BATCH_FD)
    put(w, CTX_ROW_BYTES, row)
    return open_store(o, w, OPEN_CONTEXT_CREATE)

def context_insert(o:mutbuf, w:mutbuf) -> u64:
    return store_transaction(o, w, CONTEXT_INSERT, 24, 0, slot_fd(w, BATCH_FD), 76, get(w, CTX_ROW_BYTES))

def context_settle(o:mutbuf, w:mutbuf, purpose:u64, bytes:u64, found:u64) -> u64:
    if purpose == CONTEXT_INSERT and found == 1 and bytes == 0:
        return store_transaction(o, w, CONTEXT_BUDGET, 25, 0, slot_fd(w, BATCH_FD), 76 + get(w, CTX_ROW_BYTES), 100)
    if purpose == CONTEXT_BUDGET and found == 1 and bytes == 0:
        copy_private(w, o, CONTEXT_CLAIM, HEADER + 48, 80)
        return store_transaction(o, w, CONTEXT_COMMIT, 26, 0, 0, 0, 80)
    if purpose == CONTEXT_COMMIT and found == 2 and bytes == 8:
        return read_span(o, w, CREATE_MARKER, slot_fd(w, STORE_RESULT), 0, 8)
    return BAD

def reply_prefix(s:readbuf, value:u64) -> bool:
    return length(s) == 72 and input_word(s, 64) == value

def create_reference(o:mutbuf, w:mutbuf) -> u64:
    put(o, HEADER, CONTEXT_REFERENCE_TAG)
    copy_private(w, o, CONTEXT_CLAIM, HEADER + 8, 80)
    fragment(o, 0, slot_fd(w, BATCH_FD), 40, 36)
    use_span(w, o, CONTEXT_ARTIFACT, 1)
    whole_slot(w, o, STORE_RESULT, 2)
    return action(o, w, CREATE_REFERENCE, RUN, CONTEXT_BIND_ROLE, 0, 3, 88)
'''


def shared_store():
    selected = [function(STORE, name) for name in (
        'typed_request', 'typed_job', 'open_store', 'close_store', 'observe_store',
        'lookup_observation')]
    opened = function(STORE, 'opened_store')
    start = opened.index('    if purpose == OPEN_PROFILE:')
    end = opened.index('    if purpose == OPEN_COST:', start)
    selected.append((opened[:start] + opened[end:]).replace(
        '    return BAD', '    return context_store_opened(o, w, purpose)'))
    closed = function(STORE, 'closed_store')
    start = closed.index('    if purpose == CLOSED_PROFILE_REFUSED:')
    end = closed.index('    if purpose == CLOSED_COST:', start)
    closed = closed[:start] + closed[end:]
    last = closed.rindex('    return BAD')
    selected.append(closed[:last] + closed[last:].replace(
        '    return BAD', '    return context_store_closed(o, w, purpose)', 1))
    transaction = function(STORE, 'store_transaction').replace(
        'mode != 0 or plan == 23', 'mode != 0 or plan == 23 or plan == 26').replace(
        'purpose == STORE_RESERVATION_COMMIT:', 'purpose == STORE_RESERVATION_COMMIT or purpose == CONTEXT_COMMIT:')
    settled = function(STORE, 'settle_transaction').replace(
        '    old_request = get(w, STORE_REQUEST)\n',
        '    old_request = get(w, STORE_REQUEST)\n    purpose = get(w, STORE_PURPOSE)\n').replace(
        'found > 1', 'found > choose(purpose == CONTEXT_COMMIT, 2, 1)').replace(
        '    purpose = get(w, STORE_PURPOSE)\n    if purpose == STORE_LOOKUP or purpose == STORE_PROFILE_ROW or purpose == STORE_PROFILE_ID:',
        '''    if purpose == CONTEXT_PROFILE_ROW or purpose == CONTEXT_ARTIFACT_ROW:
        return context_row(o, w, purpose, bytes)
    if purpose >= CONTEXT_INSERT and purpose <= CONTEXT_COMMIT:
        return context_settle(o, w, purpose, bytes, found)
    if purpose == STORE_LOOKUP:''')
    interpreted = function(STORE, 'interpret_row')
    start = interpreted.index('    if purpose == STORE_PROFILE_ROW:')
    interpreted = interpreted[:start] + '    return BAD\n'
    return (*selected, transaction, settled, interpreted)


def program():
    constants = policy_constants()
    roles = ('CONTROL_ROLE', 'CONTEXT_EFFECT_ROLE', 'CONTEXT_BIND_ROLE', 'CONTEXT_RECORD_ROLE',
             'PAYLOAD_ROLE', 'WORKLOAD_ROLE', 'FACTS_ROLE', 'NOMINAL_ROLE')
    constants.update({name: n for n, name in enumerate(roles, 23)})
    states = (
        'CTX_REQUEST_PLAN', 'CTX_FIELD_WIDTH', 'CTX_NULL', 'CONTROL_NONCE', 'CONTROL_OPEN',
        'CONTROL_SENT', 'CONTROL_RECEIVED', 'CONTROL_WORKLOAD', 'CONTROL_COSTS', 'CONTROL_MEMORY',
        'CONTROL_EFFECT', 'CONTEXT_ERROR', 'CONTROL_CLOSED', 'PROFILE_QUERY_BOUND',
        'RETAINED_QUERY_BOUND', 'RETAINED_ROW_BOUND', 'RETAINED_DIGEST', 'RETAINED_BYTES',
        'PROFILE_ROW_BOUND', 'BASE_ADMISSION', 'BASE_DIGEST', 'BASE_DIGEST_FRAME', 'BASE_READY',
        'UTC_SAMPLED', 'UTC_FORMED', 'PLATFORM_SAMPLED', 'PLATFORM_QUOTED', 'CPU_SAMPLED',
        'CPU_FORMED', 'CATALOG_QUOTED', 'MANIFEST_FORMED', 'MANIFEST_PUBLISHED',
        'PAYLOAD_CHECKED', 'CONTEXT_NONCE', 'CONTEXT_CREATED', 'CONTEXT_BATCH', 'CREATE_MARKER',
        'CREATE_REFERENCE', 'CONTEXT_RENDERED', 'INSTALL_REFERENCE', 'INSTALL_PROFILES',
        'INSTALL_PROFILE_PINS',
    )
    constants.update({name: n for n, name in enumerate(states, constants['REPORT_PUBLISHED'] + 1)})
    purposes = (
        'OPEN_CONTEXT_PROFILE', 'OPEN_CONTEXT_ARTIFACT', 'OPEN_CONTEXT_CREATE',
        'CLOSE_CONTEXT_PROFILE', 'CLOSE_CONTEXT_PROFILE_REFUSED', 'CLOSE_CONTEXT_ARTIFACT',
        'CLOSE_CONTEXT_ARTIFACT_REFUSED', 'CLOSE_CONTEXT_CREATE', 'CONTEXT_PROFILE_ROW',
        'CONTEXT_ARTIFACT_ROW', 'CONTEXT_INSERT', 'CONTEXT_BUDGET', 'CONTEXT_COMMIT',
    )
    constants.update({name: n for n, name in enumerate(purposes, constants['STORE_TERMINAL'] + 1)})
    spans = ('CONTEXT_BASE', 'CONTEXT_EXPORTS', 'CONTEXT_SAMPLE', 'CONTEXT_MANIFEST',
             'CONTEXT_ARTIFACT', 'CONTEXT_REFERENCE', 'CONTEXT_RESPONSE', 'CONTEXT_CPU',
             'CONTEXT_MACHINE', 'CONTEXT_SYSNAME', 'CONTEXT_CATALOG', 'CONTEXT_IDENTITIES',
             'CONTEXT_REFERENCE_QUERY')
    constants.update({name: 2592 + 24 * n for n, name in enumerate(spans)})
    fields = ('CTX_FIELD_AT', 'CTX_FIELD', 'CTX_EVENT', 'CTX_VISITS', 'CTX_FAILED', 'CTX_ANSWER',
              'CTX_PROFILE_ROLE', 'CTX_SYSTEM_SIZE', 'CTX_MACHINE_SIZE', 'CTX_TIME', 'CTX_ROW_BYTES',
              'INSTALL_PENDING')
    constants.update({name: 3328 + 8 * n for n, name in enumerate(fields)})
    constants.update(ROLE_COUNT=31, ENTRY_BYTES=64 + 312 + 31 * 40, BATCH_FD=18,
                     SCHEMA_TOOL=4,
                     CONTROL_PEER=1, SEND_PEER=9, RANDOM=10, MAKE=11, UNAME=12, CPU=13,
                     CONTEXT_VALUES=2304, CONTEXT_DATA=2496, CONTEXT_CLAIM=2912,
                     CONTEXT_REQUEST=2992, CONTEXT_WORKLOAD=3032, CONTEXT_COSTS=3080,
                     CONTEXT_MEMORY=3128, CONTEXT_UUID=3152, CONTROL_ID=3168, CONTEXT_VECTOR=3184,
                     PROFILE_REFERENCE_REFUSED=4294967286, RETAINED_REFUSAL=4294967288)
    words = {
        'CONTEXT_PLAN_TAG': b'HIACTP01', 'CONTROL_EVENT_TAG': b'HCTXREQ1',
        'INSTALL_MANIFEST_REF': b'HIARFM01',
        'CONTROL_REPLY_TAG': b'HCTXRSP1', 'CONTEXT_EFFECT_TAG': b'HIACTE01',
        'CONTEXT_DECISION': b'HIACTE02', 'PROFILE_BY_REFERENCE': b'HIARFP03',
        'CONTEXT_PROFILE_OBSERVED': b'HIARFP02', 'RETAINED_QUERY': b'HIARFG03',
        'RETAINED_OBSERVED': b'HIARFG02', 'RETAINED_AUTHORITY': b'HIARFO02',
        'NOMINAL_PACKET': b'HIAVCF01', 'SHA_JSON': b'"sha256"', 'STORE_HASH': b'store-ha',
        'STORE_HASH_END': b'sh', 'UTC_FRAME': b'HIACTT01', 'CPU_SAMPLE_TAG': b'HIACTN01',
        'CPU_RESULT_TAG': b'HIACTN02',
        'CONTEXT_RECORD_TAG': b'HIAIDP01', 'DOCUMENT_RECEIPT': b'HIADOC01',
        'CONTEXT_CREATE_TAG': b'HIACTS01', 'CONTEXT_BATCH_TAG': b'HIACTB01',
        'CONTEXT_REFERENCE_TAG': b'HIACRI01', 'STORE_MARKER': b'HIASTCP1', 'NULL_VALUE': b'null',
    }
    constants.update({name: int.from_bytes(value, 'little') for name, value in words.items()})
    entry = entry_program()
    controls = (
        function(ARTIFACT, 'artifact_entry').replace(
            '    return read_span(o, w, CONFIG_HEADER, slot_fd(w, METADATA_FD), 0, 88)',
            '    put(w, INSTALL_PENDING, 1)\n'
            '    put(o, HEADER, INSTALL_MANIFEST_REF)\n'
            '    whole_slot(w, o, METADATA_FD, 0)\n'
            '    return action(o, w, INSTALL_REFERENCE, RUN, PROFILE_ROLE, 0, 1, 8)'),
        *(function(ARTIFACT, name) for name in (
            'clock_sample', 'project_request', 'project_artifact', 'schema_receipt', 'plan_ok',
            'json_pair', 'send_journal', 'observe_journal', 'bind_journal', 'artifact_edge',
            'journal_action', 'artifact_error', 'end_effect')),
        *shared_store(),
        *(function(PUBLICATION, name) for name in ('publish_artifact', 'send_report')),
        function(COST, 'action'),
        function(DESCRIBE, 'issue').replace('seq > 160', 'seq > 4096').replace(
            '    put(o, 152,',
            '    put(o, 136, 0)\n'
            '    put(o, 168, choose(op == RUN and role == NOMINAL_ROLE, 1, 0))\n'
            '    put(o, 152,'),
        function(ENTRY_POLICY, 'admit_entry'),
        *(function(ENTRY_POLICY, name) for name in ('trusted_descriptors', 'dossier_identity')),
        *(function(DESCRIBE, name) for name in (
            'argv', 'fragment', 'keep', 'observe_slot', 'slot_fd', 'slot_bytes', 'whole_slot',
            'after_prefix', 'prefixed', 'reply_word', 'copy_private', 'zero_range', 'role_argument',
            'launch_directory')),
        *(function(READ_POLICY, name) for name in ('receive', 'read_span')),
        *(function(entry, name) for name in ('valid_fd', 'is_hex', 'copy_span', 'input_word', 'put', 'write')),
        function(RELEASE_WRITER, 'get'),
    )
    return flow_source(POLICY, (RETAINED_POLICY, MANIFEST_POLICY, RESULT_POLICY, *controls), constants)


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)), encoding='utf-8')
