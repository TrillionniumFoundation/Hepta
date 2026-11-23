"""Collect fresh Evaluate input records from the live typed Store."""

from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_worker_artifact_flow import POLICY as ARTIFACT, STORE_POLICY
from tools.generate_hia_worker_context_flow import POLICY as CONTROL_POLICY, RETAINED_POLICY
from tools.generate_hia_worker_describe_flow import POLICY as DESCRIBE, flow_source
from tools.generate_hia_worker_evaluate_replay_flow import DRIVER as REPLAY, ROLES as REPLAY_ROLES, recipe
from tools.generate_hia_worker_inspection_effect import function

SOURCE = Path('examples/hia_bootstrap/worker_evaluate_intake_flow.hepta')
ROLES = (*REPLAY_ROLES,
         ('ARGUMENT', 'hia-agent-worker-arguments'), ('INPUT_SCHEMA', 'hia-agent-mcp-input-schema'),
         ('PLAN', 'hia-agent-worker-evaluate-request'), ('CONTEXT', 'hia-agent-context-request'),
         ('CONTEXT_STORE', 'hia-agent-context-store'), ('PROFILE', 'hia-agent-artifact-authority'),
         ('PUBLISHER', 'hia-artifact'), ('BINDING', 'hia-agent-worker-evaluate-input-binding'),
         ('NOMINAL', 'hia-nominal-constructor'), ('REFERENCE_BATCH', 'hia-evaluate-reference-batch'),
         ('PROJECTOR', 'hia-evaluate-projector'), ('OWNED', 'hia-owned-reference-wire'))

POLICY = r'''
# A novel key is eligible for reversible intake. The request is not reserved
# here: a successor must still authorize both programs, proofs, and budget.
def closed_store(o:mutbuf, w:mutbuf) -> u64:
    purpose = get(w, STORE_PURPOSE)
    if purpose == CLOSED_LOOKUP and get(w, JOURNAL_NEXT) == 2:
        return project_artifact(o, w, ARGUMENT_PROJECTED, ARGUMENT, ARGUMENT_ROLE)
    if purpose == CLOSE_INTAKE:
        return clock_sample(o, w, REFERENCE_WINDOW, 1)
    return BAD

def intake(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    size = input_word(s, 40)
    fd = input_word(s, 32)
    if state >= PREFIX_MADE:
        return runtime_state(s, o, w, state)
    if state == ARGUMENT_PROJECTED:
        if prefixed(s) == False:
            return BAD
        observe_slot(s, w, ARGUMENT_FD)
        return schema_receipt(o, w, INPUT_SCHEMA, INPUT_SCHEMA_ROLE, ARGUMENT_FD)
    if state == INPUT_SCHEMA:
        if reply_word(s, 0) == False:
            return BAD
        put(o, HEADER, 8795)
        copy_private(w, o, TRUST, HEADER + 2, 64)
        store(o, HEADER + 66, 34)
        store(o, HEADER + 67, 44)
        return json_pair(o, w, ARGUMENT_PLAN, 68)
    if state == ARGUMENT_PLAN:
        if plan_ok(s) == False or size < 136 or size > 376:
            return BAD
        return read_span(o, w, REQUEST_SPANS, fd, 0, size)
    if state == REQUEST_SPANS:
        return bind_request_spans(s, o, w)
    if state == CTX_REFERENCE:
        if plan_ok(s) == False or size != 116 or input_word(s, 72) != CONTEXT_REFERENCE_TAG:
            return BAD
        hold(w, ACTIVE_REFERENCE, fd, 16, 100)
        put(o, HEADER, CONTEXT_QUERY_TAG)
        fragment(o, 0, fd, 16, 36)
        return action(o, w, CTX_QUERY, RUN, CONTEXT_STORE_ROLE, 0, 1, 8)
    if state == CTX_QUERY:
        if plan_ok(s) == False or size != 100:
            return BAD
        observe_slot(s, w, QUERY_FD)
        return open_store(o, w, OPEN_INTAKE)
    if state == CTX_OBSERVED:
        if plan_ok(s) == False or size < 217 or size > 236 or input_word(s, 72) != CONTEXT_OBSERVED_TAG or input_word(s, 80) != 0:
            return close_store(o, w, CLOSE_REFUSED)
        hold(w, ACTIVE_REFERENCE, fd, 40, 176)
        hold(w, CREATION, fd, 216, size - 216)
        put(w, ACTIVE_KIND, 3)
        return retained_query(o, w)
    if state == ART_QUERY:
        if plan_ok(s) == False or size != 98:
            return close_store(o, w, CLOSE_REFUSED)
        return store_transaction(o, w, ART_ROW, 2, 0, fd, 8, size - 8)
    if state == ART_OBSERVED:
        if plan_ok(s) == False or (size != 80 and size != 96):
            return close_store(o, w, CLOSE_REFUSED)
        return read_span(o, w, ART_AUTH, fd, 8, size - 8)
    if state == ART_AUTH:
        return capture_artifact(s, o, w)
    if state == ART_BODY:
        if size < 1 or size > 67108864:
            return close_store(o, w, CLOSE_REFUSED)
        index = get(w, SELECTOR)
        retained = 4 + get(w, RECEIPT_COUNT)
        if index < retained:
            return append_binding(o, w, fd, size)
        if index < retained + 2:
            keep(w, RAW_BODY, fd, size)
            fragment(o, 0, fd, 0, size)
            return action(o, w, CORE_NOMINAL, RUN, NOMINAL_ROLE, 0, 1, 0)
        if index == retained + 4:
            put(w, WORKLOAD_FD, fd)
        return retain_body(o, w, fd, size)
    if state == ROW_MADE:
        if size != get(w, RECORD_SIZE):
            return BAD
        if get(w, SELECTOR) == 0:
            keep(w, INTAKE_PACKET, fd, size)
            return next_artifact(o, w)
        whole_slot(w, o, INTAKE_PACKET, 0)
        fragment(o, 1, fd, 0, size)
        return action(o, w, ROW_JOINED, MAKE, 0, 0, 2, 0)
    if state == ROW_JOINED:
        if size != slot_bytes(w, INTAKE_PACKET) + get(w, RECORD_SIZE):
            return BAD
        keep(w, INTAKE_PACKET, fd, size)
        return next_artifact(o, w)
    if state == INTAKE_PUBLISHED and length(s) == 64:
        return action(o, w, INTAKE_PUBLISHED, FINISHED, 0, 0, 0, 0)
    return BAD

def bind_request_spans(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    size = input_word(s, 40)
    count = input_word(s, 80)
    if input_word(s, 64) != size - 8 or input_word(s, 72) != REQUEST_LAYOUT or count < 1 or count > 16 or size != 120 + 16 * count:
        return BAD
    put(w, RECEIPT_COUNT, count)
    fd = slot_fd(w, ARGUMENT_FD)
    total = slot_bytes(w, ARGUMENT_FD)
    i = 0
    while i < count + 4:
        p = 88 + 16 * choose(i < 4, i, i + 2)
        offset = input_word(s, p)
        span = input_word(s, p + 8)
        if span != choose(i == 0, 121, 176) or offset < 68 or offset - 60 > total or span > total - (offset - 60):
            return BAD
        hold(w, SELECTORS + 24 * i, fd, offset - 60, span)
        i = i + 1
    return start_binding(o, w)

def opened_intake(o:mutbuf, w:mutbuf) -> u64:
    fd = slot_fd(w, QUERY_FD)
    return store_transaction(o, w, CTX_ROW, 4, 0, fd, 8, slot_bytes(w, QUERY_FD) - 8)

def inspect_row(o:mutbuf, w:mutbuf, purpose:u64, bytes:u64) -> u64:
    put(o, HEADER + 8, bytes)
    put(o, HEADER + 16, get(w, STORE_REQUEST))
    put(o, HEADER + 24, get(w, STORE_EPOCH))
    use_span(w, o, ACTIVE_REFERENCE, 0)
    whole_slot(w, o, STORE_RESULT, 1)
    if purpose == CTX_ROW:
        put(o, HEADER, CONTEXT_OBSERVE_TAG)
        put(o, HEADER + 32, 0)
        return action(o, w, CTX_OBSERVED, RUN, CONTEXT_STORE_ROLE, 0, 2, 36)
    if purpose != ART_ROW:
        return BAD
    put(o, HEADER, RETAINED_OBSERVED)
    put(o, HEADER + 32, get(w, ACTIVE_KIND))
    return action(o, w, ART_OBSERVED, RUN, PROFILE_ROLE, 0, 2, 40)

def retained_query(o:mutbuf, w:mutbuf) -> u64:
    put(o, HEADER, RETAINED_QUERY)
    put(o, HEADER + 8, get(w, ACTIVE_KIND))
    use_span(w, o, ACTIVE_REFERENCE, 0)
    return action(o, w, ART_QUERY, RUN, PROFILE_ROLE, 0, 1, 16)

def capture_artifact(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    kind = get(w, ACTIVE_KIND)
    if kind <= 4:
        if length(s) != 136 or input_word(s, 64) != RETAINED_AUTHORITY:
            return BAD
        hold(w, METADATA_SPAN, slot_fd(w, STORE_RESULT), 0, 0)
    else:
        if length(s) != 152 or input_word(s, 64) != BUILD_AUTHORITY:
            return BAD
        at = input_word(s, 136)
        bytes = input_word(s, 144)
        size = slot_bytes(w, STORE_RESULT) - 48
        if at > size or bytes > size - at:
            return BAD
        hold(w, METADATA_SPAN, slot_fd(w, STORE_RESULT), at, bytes)
    i = 0
    while i < 64:
        c = byte(s, 72 + i)
        if is_hex(c) == False:
            return BAD
        store(o, 416 + i, c)
        i = i + 1
    store(o, 480, 0)
    return artifact_command(o, w, ART_BODY, STORE_GET, STORE_GET_END, 0)

def retain_body(o:mutbuf, w:mutbuf, fd:u64, size:u64) -> u64:
    meta = get(w, METADATA_SPAN + 16)
    row = 32 + 176 + meta + size
    if row > 67108864 or row > 67108864 - slot_bytes(w, INTAKE_PACKET):
        return close_store(o, w, CLOSE_REFUSED)
    put(w, RECORD_SIZE, row)
    put(o, HEADER, get(w, SELECTOR))
    put(o, HEADER + 8, get(w, ACTIVE_KIND))
    put(o, HEADER + 16, meta)
    put(o, HEADER + 24, size)
    use_span(w, o, ACTIVE_REFERENCE, 0)
    use_span(w, o, METADATA_SPAN, 1)
    fragment(o, 2, fd, 0, size)
    return action(o, w, ROW_MADE, MAKE, 0, 0, 3, 32)

def next_artifact(o:mutbuf, w:mutbuf) -> u64:
    index = get(w, SELECTOR) + 1
    retained = 4 + get(w, RECEIPT_COUNT)
    if index == retained:
        return bind_runtime(o, w)
    if index == retained + 5:
        return read_span(o, w, CREATION_OBSERVED, get(w, CREATION), get(w, CREATION + 8), get(w, CREATION + 16))
    if index > retained:
        return read_runtime(o, w, index - retained)
    put(w, SELECTOR, index)
    put(w, ACTIVE_KIND, choose(index < 3, 7, choose(index == 3, 5, 8)))
    src = SELECTORS + 24 * index
    hold(w, ACTIVE_REFERENCE, get(w, src), get(w, src + 8), get(w, src + 16))
    return retained_query(o, w)

def publish_intake(o:mutbuf, w:mutbuf) -> u64:
    put(o, HEADER, INTAKE)
    put(o, HEADER + 8, get(w, RECEIPT_COUNT) + 9)
    put(o, HEADER + 16, get(w, WINDOW_UTC))
    put(o, HEADER + 24, get(w, UTC_DEADLINE))
    put(o, HEADER + 32, get(w, LIMIT_NATIVE))
    put(o, HEADER + 40, get(w, LIMIT_MEMORY))
    put(o, HEADER + 48, slot_bytes(w, ORIGINAL))
    put(o, HEADER + 56, slot_bytes(w, INTAKE_PACKET))
    put(o, HEADER + 64, get(w, BASE_REFERENCE + 16))
    put(o, HEADER + 72, get(w, CANDIDATE_REFERENCE + 16))
    i = 0
    while i < 4:
        put(o, HEADER + 80 + 8 * i, get(w, REFERENCE_CLOCKS + 8 * i))
        i = i + 1
    whole_slot(w, o, COMBINED, 0)
    return action(o, w, INTAKE_PUBLISHED, PUBLISH, 0, 0, 1, 112)
'''


RUNTIME_POLICY = r'''
def start_binding(o:mutbuf, w:mutbuf) -> u64:
    # The installation and request originate in the authenticated launcher
    # dossier and native admission, independently of any retained document.
    store(o, HEADER, 91)
    store(o, 496, 44)
    fragment(o, 0, slot_fd(w, DOSSIER_FD), DOSSIER_HEAD + get(w, 40), get(w, 48))
    fragment(o, 1, INLINE_FRAGMENT, 496, 1)
    after_prefix(w, o, ARGUMENT_FD, 2)
    return action(o, w, PREFIX_MADE, MAKE, 0, 0, 3, 1)

def append_binding(o:mutbuf, w:mutbuf, fd:u64, size:u64) -> u64:
    keep(w, RAW_BODY, fd, size)
    whole_slot(w, o, BIND_PREFIX, 0)
    store(o, 496, 44)
    fragment(o, 1, INLINE_FRAGMENT, 496, 1)
    if get(w, ACTIVE_KIND) == 7:
        use_span(w, o, METADATA_SPAN, 2)
    else:
        fragment(o, 2, fd, 0, size)
    return action(o, w, DOCUMENT_BOUND, MAKE, 0, 0, 3, 0)

def bind_runtime(o:mutbuf, w:mutbuf) -> u64:
    whole_slot(w, o, BIND_PREFIX, 0)
    store(o, 496, 93)
    fragment(o, 1, INLINE_FRAGMENT, 496, 1)
    return action(o, w, RUNTIME_BOUND, RUN, BINDING_ROLE, 0, 2, 0)

def read_runtime(o:mutbuf, w:mutbuf, index:u64) -> u64:
    put(w, SELECTOR, get(w, RECEIPT_COUNT) + 4 + index)
    put(w, ACTIVE_KIND, choose(index == 2, 6, 0))
    hold(w, ACTIVE_REFERENCE, slot_fd(w, RUNTIME_SELECTION), 40 + 176 * index, 176)
    return retained_query(o, w)

def sample_budget(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    size = get(w, CREATION + 16)
    if length(s) != 64 + size or size == 0 or size > 20:
        return BAD
    stamp = 0
    i = 0
    while i < size:
        c = byte(s, 64 + i)
        if c < 48 or c > 57 or stamp > 1844674407370955161 or (stamp == 1844674407370955161 and c > 53):
            return BAD
        stamp = stamp * 10 + c - 48
        i = i + 1
    limit = 1000000 * get(w, LIMIT_WALL)
    if stamp > 18446744073709551615 - limit:
        return BAD
    put(w, UTC_DEADLINE, stamp + limit)
    return clock_sample(o, w, WINDOW_SAMPLED, 1)

def validate_core(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    size = input_word(s, 40)
    prefix = input_word(s, 96)
    span = input_word(s, 104)
    if length(s) < 128 or size < 64 or input_word(s, 64) != NOMINAL_PACKET or input_word(s, 72) != 0 or input_word(s, 80) != 0:
        return close_store(o, w, CLOSE_REFUSED)
    if prefix == 0 or prefix > size - 64 or span == 0 or span != size - 64 - prefix:
        return close_store(o, w, CLOSE_REFUSED)
    fd = input_word(s, 32)
    hold(w, CANONICAL, fd, 64 + prefix, span)
    put(o, 416, 45)
    use_span(w, o, CANONICAL, 0)
    return artifact_command(o, w, CORE_HASHED, STORE_HASH, STORE_HASH_END, 1)

def observed_digest(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    at = 64
    while at + 75 <= length(s):
        if input_word(s, at) == SHA_JSON and byte(s, at + 8) == 58 and byte(s, at + 9) == 34 and byte(s, at + 74) == 34:
            i = 0
            while i < 64:
                if is_hex(byte(s, at + 10 + i)) == False:
                    return BAD
                store(w, EXPECTED_SHA + i, byte(s, at + 10 + i))
                i = i + 1
            arm = get(w, SELECTOR) - 4 - get(w, RECEIPT_COUNT)
            return read_span(o, w, CORE_COMPARED, slot_fd(w, RUNTIME_SELECTION), 920 + 64 * arm, 64)
        at = at + 1
    return BAD

def runtime_state(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    fd = input_word(s, 32)
    size = input_word(s, 40)
    if state == PREFIX_MADE:
        observe_slot(s, w, BIND_PREFIX)
        use_span(w, o, SELECTORS, 0)
        return action(o, w, CTX_REFERENCE, RUN, CONTEXT_ROLE, 0, 1, 0)
    if state == DOCUMENT_BOUND:
        observe_slot(s, w, BIND_PREFIX)
        return retain_body(o, w, slot_fd(w, RAW_BODY), slot_bytes(w, RAW_BODY))
    if state == RUNTIME_BOUND:
        if plan_ok(s) == False or size != 1048 or input_word(s, 72) != BIND_RESULT:
            return close_store(o, w, CLOSE_REFUSED)
        observe_slot(s, w, RUNTIME_SELECTION)
        put(w, LIMIT_WALL, input_word(s, 80))
        put(w, LIMIT_NATIVE, input_word(s, 88))
        put(w, LIMIT_MEMORY, input_word(s, 96))
        return read_runtime(o, w, 0)
    if state == CORE_NOMINAL:
        return validate_core(s, o, w)
    if state == CORE_HASHED:
        if size == 0 or size > 1024:
            return BAD
        return read_span(o, w, CORE_HASH_FRAME, fd, 0, size)
    if state == CORE_HASH_FRAME:
        return observed_digest(s, o, w)
    if state == CORE_COMPARED:
        i = 0
        while i < 64:
            if byte(s, 64 + i) != byte(w, EXPECTED_SHA + i):
                return close_store(o, w, CLOSE_REFUSED)
            i = i + 1
        use_span(w, o, CANONICAL, 0)
        return action(o, w, CORE_FILE_MADE, MAKE, 0, 0, 1, 0)
    if state == CORE_FILE_MADE:
        if size != get(w, CANONICAL + 16):
            return close_store(o, w, CLOSE_REFUSED)
        arm = get(w, SELECTOR) - 4 - get(w, RECEIPT_COUNT)
        put(w, CANONICAL_FDS + 8 * arm, fd)
        hold(w, METADATA_SPAN, fd, 0, size)
        return retain_body(o, w, slot_fd(w, RAW_BODY), slot_bytes(w, RAW_BODY))
    if state == CREATION_OBSERVED:
        return sample_budget(s, o, w)
    if state == WINDOW_SAMPLED:
        if length(s) != 72 or size != 8:
            return BAD
        now = input_word(s, 64)
        deadline = get(w, UTC_DEADLINE)
        if now >= deadline or deadline - now < 1000000:
            return close_store(o, w, CLOSE_REFUSED)
        put(w, WINDOW_UTC, now)
        return close_store(o, w, CLOSE_INTAKE)
    if state == REFERENCE_WINDOW:
        if length(s) != 72 or size != 8:
            return BAD
        put(w, REFERENCE_UTC, input_word(s, 64))
        return clock_sample(o, w, REFERENCE_STARTED, 0)
    if state == REFERENCE_STARTED:
        if length(s) != 72 or size != 8:
            return BAD
        arm = get(w, REFERENCE_ARM)
        stamp = input_word(s, 64)
        if arm > 1 or stamp == 0 or (arm == 1 and stamp < get(w, REFERENCE_CLOCKS + 8)):
            return BAD
        put(w, REFERENCE_CLOCKS + 16 * arm, stamp)
        return reference_batch(o, w, get(w, REFERENCE_UTC))
    if state == REFERENCE_RETURNED:
        return reference_returned(s, o, w)
    if state == REFERENCE_REAPED:
        if length(s) != 72 or size != 8:
            return BAD
        return reaped_reference(o, w, input_word(s, 64))
    if state == COMBINED_MADE:
        if size != slot_bytes(w, INTAKE_PACKET) + get(w, BASE_REFERENCE + 16) + get(w, CANDIDATE_REFERENCE + 16):
            return BAD
        whole_slot(w, o, ORIGINAL, 0)
        fragment(o, 1, fd, 0, size)
        put(w, COMBINED_BYTES, size + slot_bytes(w, ORIGINAL))
        return action(o, w, ORIGINAL_JOINED, MAKE, 0, 0, 2, 0)
    if state == ORIGINAL_JOINED:
        if size != get(w, COMBINED_BYTES):
            return BAD
        observe_slot(s, w, COMBINED)
        return publish_intake(o, w)
    return BAD

def reference_batch(o:mutbuf, w:mutbuf, now:u64) -> u64:
    deadline = get(w, UTC_DEADLINE)
    arm = get(w, REFERENCE_ARM)
    if arm > 1 or now < get(w, WINDOW_UTC) or now >= deadline or deadline - now < 1000000:
        return BAD
    remaining = deadline - now
    argv(o, 0, FD_ARG, get(w, CANONICAL_FDS + 8 * arm))
    argv(o, 1, FD_ARG, get(w, WORKLOAD_FD))
    argv(o, 2, FD_ARG, get(w, ROLE_BASE + 8 * PROJECTOR_ROLE))
    argv(o, 3, FD_ARG, get(w, ROLE_BASE + 8 * OWNED_ROLE))
    argv(o, 4, DECIMAL_ARG, get(w, LIMIT_MEMORY))
    argv(o, 5, DECIMAL_ARG, remaining)
    count = action(o, w, REFERENCE_RETURNED, RUN, REFERENCE_BATCH_ROLE, 6, 0, 0)
    put(o, 152, remaining)
    return count

def reference_returned(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    size = input_word(s, 40)
    requested = input_word(s, 72)
    done = input_word(s, 80)
    if length(s) < 88 or size < 40 or input_word(s, 64) != REFERENCE_RESULT or requested < 1 or requested > 512 or done == 0 or done > requested:
        return BAD
    if get(w, REFERENCE_ARM) == 0:
        put(w, CASE_COUNT, requested)
        hold(w, BASE_REFERENCE, input_word(s, 32), 0, size)
        return clock_sample(o, w, REFERENCE_REAPED, 0)
    if requested != get(w, CASE_COUNT):
        return BAD
    hold(w, CANDIDATE_REFERENCE, input_word(s, 32), 0, size)
    return clock_sample(o, w, REFERENCE_REAPED, 0)

def reaped_reference(o:mutbuf, w:mutbuf, now:u64) -> u64:
    arm = get(w, REFERENCE_ARM)
    if arm > 1 or now < get(w, REFERENCE_CLOCKS + 16 * arm):
        return BAD
    put(w, REFERENCE_CLOCKS + 16 * arm + 8, now)
    if arm == 0:
        put(w, REFERENCE_ARM, 1)
        return clock_sample(o, w, REFERENCE_WINDOW, 1)
    total = 112 + slot_bytes(w, ORIGINAL) + slot_bytes(w, INTAKE_PACKET) + get(w, BASE_REFERENCE + 16) + get(w, CANDIDATE_REFERENCE + 16)
    if total > 67108864:
        return BAD
    whole_slot(w, o, INTAKE_PACKET, 0)
    use_span(w, o, BASE_REFERENCE, 1)
    use_span(w, o, CANDIDATE_REFERENCE, 2)
    return action(o, w, COMBINED_MADE, MAKE, 0, 0, 3, 0)
'''


def program():
    constants, controls = recipe(ROLES)
    constants.update(SCHEMA_TOOL=9, MAKE=11, RECEIPT_COUNT=2304, SELECTOR=2312, ACTIVE_KIND=2320,
                     RECORD_SIZE=2328, SELECTORS=2368, ACTIVE_REFERENCE=2848, METADATA_SPAN=2872,
                     CREATION=2896, CANONICAL=2920, EXPECTED_SHA=2944, LIMIT_WALL=3008,
                     LIMIT_NATIVE=3016, LIMIT_MEMORY=3024, UTC_DEADLINE=3032, WINDOW_UTC=3040,
                     CANONICAL_FDS=3048, WORKLOAD_FD=3064, REFERENCE_ARM=3072, CASE_COUNT=3080,
                     BASE_REFERENCE=3088, CANDIDATE_REFERENCE=3112, COMBINED_BYTES=3136, REFERENCE_CLOCKS=3160, REFERENCE_UTC=3192, COMBINED=22,
                     BIND_PREFIX=19, RUNTIME_SELECTION=20, RAW_BODY=21, INTAKE_PACKET=18, OPEN_INTAKE=50, CTX_ROW=51, ART_ROW=52,
                     CLOSE_INTAKE=53, CLOSE_REFUSED=54)
    states = ('REQUEST_SPANS','CTX_REFERENCE','CTX_QUERY','CTX_OBSERVED','ART_QUERY','ART_OBSERVED',
              'ART_AUTH','ART_BODY','ROW_MADE','ROW_JOINED','INTAKE_PUBLISHED','PREFIX_MADE','DOCUMENT_BOUND',
              'RUNTIME_BOUND','CREATION_OBSERVED','WINDOW_SAMPLED','CORE_NOMINAL','CORE_HASHED','CORE_HASH_FRAME','CORE_COMPARED',
              'CORE_FILE_MADE','REFERENCE_WINDOW','REFERENCE_RETURNED','COMBINED_MADE','ORIGINAL_JOINED','REFERENCE_STARTED','REFERENCE_REAPED')
    constants.update({name: i for i, name in enumerate(states, 60)})
    tags = dict(REQUEST_LAYOUT=b'HIAEVQ01', INTAKE=b'HIAEFI04', REFERENCE_RESULT=b'HIAEBT01', BIND_RESULT=b'HIAEFB02', NOMINAL_PACKET=b'HIAVCF01',
                SHA_JSON=b'"sha256"', STORE_HASH=b'store-ha', STORE_HASH_END=b'sh', CONTEXT_REFERENCE_TAG=b'HIACTRL1',
                CONTEXT_QUERY_TAG=b'HIACTL01', CONTEXT_OBSERVE_TAG=b'HIACTO01', CONTEXT_OBSERVED_TAG=b'HIACTO02',
                RETAINED_QUERY=b'HIARFG01', RETAINED_OBSERVED=b'HIARFG02', RETAINED_AUTHORITY=b'HIARFO02',
                BUILD_AUTHORITY=b'HIABRD01')
    constants.update({name: int.from_bytes(value,'little') for name,value in tags.items()})
    driver = REPLAY[:REPLAY.index('def closed_store(')]
    driver = driver.replace('    return publish_cached(s, o, w, state)', '    return intake(s, o, w, state)')
    driver = driver.replace('    if get(w, STORE_PURPOSE) != OPEN_LOOKUP:',
                            '    if get(w, STORE_PURPOSE) == OPEN_INTAKE:\n        return opened_intake(o, w)\n'
                            '    if get(w, STORE_PURPOSE) != OPEN_LOOKUP:')
    settled = function(STORE_POLICY, 'settle_transaction').split('    if purpose == STORE_LOOKUP')[0]
    settled += ('    if purpose == STORE_LOOKUP:\n        return interpret_row(o, w, purpose, bytes)\n'
                '    return inspect_row(o, w, purpose, bytes)\n')
    controls = [settled if c.lstrip().startswith('def settle_transaction(') else c for c in controls]
    issue = function(DESCRIBE, 'issue').replace('seq > 160', 'seq > 4096').replace(
        '    put(o, 152,',
        '    put(o, 136, 0)\n    put(o, 168, choose(op == RUN and role == NOMINAL_ROLE, 1, 0))\n    put(o, 152,')
    controls = [issue if c.lstrip().startswith('def issue(') else c for c in controls]
    controls.extend((function(ARTIFACT,'clock_sample'),function(ARTIFACT,'json_pair'),function(ARTIFACT,'schema_receipt'),
                     function(DESCRIBE,'reply_word'),function(CONTROL_POLICY,'hold'),function(CONTROL_POLICY,'use_span'),
                     function(RETAINED_POLICY,'artifact_command')))
    return flow_source(driver + POLICY + RUNTIME_POLICY, controls, constants)


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)), encoding='utf-8')
    from tools.generate_hia_readonly_worker_capsule import INTAKE_SOURCE as capsule, source_program
    from tools.generate_hia_worker_launcher_flow import INTAKE_SOURCE as launcher, program as launcher_program
    for target, candidate in ((Path(capsule), source_program(artifact=True, evaluate_intake=True)),
                              (launcher, launcher_program(evaluate_intake=True))):
        target.write_text(render_assembly(document(candidate, target.stem)), encoding='utf-8')
