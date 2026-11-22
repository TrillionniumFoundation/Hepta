"""Author fresh finite-domain Verify using the same physical replay engine as Emit."""

from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_worker_adopt_proof import reachable_policy
from tools.generate_hia_worker_candidate_flow import replace_function
from tools.generate_hia_worker_context_flow import flow_source, function
from tools.generate_hia_worker_describe_reactor import POLICY as ENTRY_POLICY
from tools.generate_hia_worker_emit_flow import ADMISSION, PROFILES, native_recipe
from tools.generate_hia_worker_emit_measurement import splice_list
from tools.generate_hia_worker_emit_layout_replay import REPLAY as LAYOUT_REPLAY
from tools.generate_hia_worker_emit_product import PRODUCTION
from tools.generate_hia_worker_emit_proof import proof_recipe
from tools.generate_hia_worker_emit_scalar import SCALAR
from tools.generate_hia_worker_finite_domain import INELIGIBLE
from tools.generate_hia_worker_inspection_flow import VIEW_DRIVER
from tools.generate_hia_worker_register_layout import WITNESS_TAG
from tools.generate_hia_worker_verify_evidence import PLAN_EVIDENCE_LIMIT

SOURCE = Path('examples/hia_bootstrap/worker_verify_finite_flow.hepta')

ENTRY = r'''
# The parent supplies only sealed base/candidate Core and their independently
# measured digests, plus a deadline bound to the reopened frozen Context.
# A ready transition returns a sealed evidence span, not a proof or receipt.
def verify_finite_flow(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) != EMIT_WORK_BYTES or length(o) < 1536:
        return BAD
    state = get(w, 0)
    if state == VERIFY_FINITE_START:
        return verify_finite_start(o, w)
    if state == VERIFY_PLAN_CHECK:
        return verify_plan_check(o, w)
    if state == VERIFY_ENCODE_START:
        return verify_encoding_start(o, w)
    if (length(s) < 64 or input_word(s, 0) != OBSERVATION
            or input_word(s, 8) != get(w, 8) or input_word(s, 16) != get(w, 16)):
        return BAD
    operation = get(w, 16)
    size = input_word(s, 40)
    start = choose(operation == RUN or operation == MAKE, 0, input_word(s, 48))
    capture = input_word(s, 56)
    if size > 67112960 or start > size or capture > size - start or capture != length(s) - 64:
        return BAD
    if operation == READ and (input_word(s, 32) != get(w, 80) or start != get(w, 88) or capture != get(w, 96)):
        return BAD
    status = input_word(s, 24)
    if state >= EMIT_SCALAR_NONCE and state <= EMIT_SCALAR_SNAPSHOT:
        if status != 0 and (state != EMIT_SCALAR_REPORT_READY or status != EMIT_EXPIRED):
            return BAD
        if state == EMIT_SCALAR_REPORT_READY and status == 0 and valid_fd(input_word(s, 32)) == False:
            return BAD
        return emit_scalar_state(s, o, w, state)
    if status != 0:
        if (status == EMIT_EXPIRED and get(w, 16) == RUN and length(s) == 64
                and state >= EMIT_COMPLETE_PLAN and state <= EMIT_COMPLETE_RENDERED):
            return verify_finite_partial(o, w)
        return BAD
    if (operation == RUN or operation == MAKE) and valid_fd(input_word(s, 32)) == False:
        return BAD
    if state == RETAINED_DIGEST:
        return emit_proof_typed_artifact(s, o, w)
    if state == RETAINED_BYTES and get(w, RETAINED_PURPOSE) >= READ_EMIT_CUSTODY_BUILD:
        return emit_proof_custody_reopened(s, o, w, get(w, RETAINED_PURPOSE))
    if state >= VERIFY_ENCODE_SCHEDULE and state <= VERIFY_ENCODE_PERMIT:
        return verify_encoding_plan(s, o, w, state)
    if state >= VERIFY_ENCODE_OBJECT_MATCH and state <= VERIFY_ENCODE_EVIDENCE:
        return verify_encoding_observation(s, o, w, state)
    if state == EMIT_RETAINED_REPORT_BOUND:
        if plan_ok(s) == False or size < 10 or size >= VERIFY_PLAN_EVIDENCE_LIMIT - 256:
            return BAD
        body_span(s, w, EMIT_RETAINED_REPORT)
        return verify_encoding_compare(o, w)
    if state >= EMIT_CUSTODY_PROJECTED and state <= EMIT_CUSTODY_VERIFIED:
        return emit_proof_custody_state(s, o, w, state)
    if state == RETAINED_BYTES or (state >= VERIFY_PLAN_CANONICAL and state <= VERIFY_PLAN_REGISTERS):
        return verify_plan_observation(s, o, w, state)
    if state == VERIFY_PLAN_WITNESS:
        return verify_plan_witness_observed(s, o, w)
    if state == VERIFY_PLAN_EVIDENCE:
        return verify_plan_evidence_observed(s, w)
    if state >= EMIT_REPLAY_PLAN_INPUT and state <= EMIT_REPLAY_CANONICAL:
        return emit_replay_layout_state(s, o, w, state)
    if state == INSPECTION_HASH_RETURNED:
        if size < 88 or size > 105:
            return BAD
        return read_span(o, w, INSPECTION_HASH_FRAME, input_word(s, 32), 0, size)
    if state == INSPECTION_HASH_FRAME:
        return inspection_hash_result(s, o, w)
    if state >= EMIT_COMPLETE_INPUT and state <= EMIT_COMPLETE_SUMMARIES:
        return emit_complete_state(s, o, w, state)
    return verify_finite_observation(s, o, w, state)
'''

SUBJECT_PLAN = r'''
def verify_plan_observation(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    size = input_word(s, 40)
    if state == RETAINED_BYTES:
        if get(w, RETAINED_PURPOSE) != READ_EMIT_PLAN or size < 2:
            return BAD
        sample_span(s, w, EMIT_RAW_PLAN)
        put(o, HEADER, get(w, 24))
        use_span(w, o, EMIT_RAW_PLAN, 0)
        return action(o, w, VERIFY_PLAN_CANONICAL, RUN, EMIT_CANONICAL_ROLE, 0, 1, 8)
    if state == VERIFY_PLAN_CANONICAL:
        if plan_ok(s) == False or size < 10:
            return verify_plan_result(w, VERIFY_PLAN_INVALID)
        body_span(s, w, EMIT_CANONICAL_PLAN)
        return verify_plan_schedule(o, w)
    if state == VERIFY_PLAN_SCHEDULE:
        version = emit_schedule_version(s)
        if version == 0:
            return verify_plan_result(w, VERIFY_PLAN_INVALID)
        put(w, EMIT_REPLAY_VERSION, version)
        fragment(o, 0, input_word(s, 32), 8, size - 8)
        return action(o, w, VERIFY_PLAN_DESCRIPTOR, MAKE, 0, 0, 1, 0)
    if state == VERIFY_PLAN_DESCRIPTOR:
        if size < 40:
            return BAD
        sample_span(s, w, EMIT_REPLAY_DESCRIPTOR)
        if get(w, EMIT_REPLAY_VERSION) == 4:
            return verify_plan_registers(o, w)
        return verify_plan_result(w, VERIFY_PLAN_ADMITTED)
    if state == VERIFY_PLAN_REGISTERS:
        version = input_word(s, 80)
        if (plan_ok(s) == False or size < 104 or input_word(s, 72) != EMIT_REPLAY_REGISTER_TAG
                or (version != 3 and version != 4) or input_word(s, 96) != size - 8):
            return verify_plan_result(w, VERIFY_PLAN_INVALID)
        return verify_plan_result(w, VERIFY_PLAN_ADMITTED)
    return BAD

def verify_plan_result(w:mutbuf, next:u64) -> u64:
    put(w, 0, next)
    return VERIFY_FINITE_READY

def verify_plan_check(o:mutbuf, w:mutbuf) -> u64:
    version = get(w, EMIT_REPLAY_VERSION)
    if version < 1 or version > 4 or get(w, EMIT_REPLAY_DESCRIPTOR + 16) < 40:
        return BAD
    move_fragment(w, EMIT_CANONICAL_PLAN, EMIT_PROOF_SUBJECT_PLAN)
    put(w, EMIT_REPLAY_PLANNED, 0)
    return emit_replay_object(o, w)

def verify_plan_witness(o:mutbuf, w:mutbuf) -> u64:
    store(o, HEADER, 91)
    store(o, 384, 44)
    put(o, 400, VERIFY_DERIVE_PREFIX)
    put(o, 408, VERIFY_DERIVE_SUFFIX)
    vector_span(w, o, INSPECTION_CORE, HEADER + 1)
    vector_part(o, HEADER + 25, INLINE_FRAGMENT, 384, 1)
    vector_span(w, o, VERIFY_CANDIDATE_SHA, HEADER + 49)
    vector_part(o, HEADER + 73, INLINE_FRAGMENT, 384, 1)
    vector_span(w, o, EMIT_CANONICAL_PLAN, HEADER + 97)
    vector_part(o, HEADER + 121, INLINE_FRAGMENT, 400, 10)
    return wide_inspection(o, w, VERIFY_PLAN_WITNESS, EMIT_REPLAY_WITNESS_ROLE, 0, 6, 1)

def verify_plan_witness_observed(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    size = input_word(s, 40)
    if (plan_ok(s) == False or size < 26 or size >= VERIFY_PLAN_EVIDENCE_LIMIT
            or input_word(s, 72) != VERIFY_REGISTER_WITNESS or input_word(s, 80) != size - 24):
        return BAD
    hold(w, EMIT_REPLAY_WITNESS_SPAN, input_word(s, 32), 24, size - 24)
    return verify_plan_register_evidence(o, w)

def verify_plan_evidence_observed(s:readbuf, w:mutbuf) -> u64:
    size = input_word(s, 40)
    if (plan_ok(s) == False or size < 42 or size > VERIFY_PLAN_EVIDENCE_LIMIT + 8
            or input_word(s, 72) != VERIFY_FINITE_REPORT or input_word(s, 80) != 1
            or input_word(s, 88) != 10 or input_word(s, 96) != size - 40):
        return BAD
    body_span(s, w, VERIFY_FINITE_RESULT)
    return verify_finite_deliver(w)
'''

NATIVE_CUSTODY = r'''
# The front section owns the Store transaction. Return there only after a
# typed request (purpose, kind, sealed reference) has been fully selected.
def emit_proof_read(o:mutbuf, w:mutbuf, purpose:u64, kind:u64) -> u64:
    put(w, RETAINED_PURPOSE, purpose)
    put(w, RETAINED_KIND, kind)
    put(w, 0, VERIFY_NATIVE_STORE)
    return VERIFY_FINITE_READY

def emit_proof_open_claims(o:mutbuf, w:mutbuf) -> u64:
    put(w, 0, VERIFY_NATIVE_BOUND)
    return VERIFY_FINITE_READY

def emit_custody_inputs(o:mutbuf, w:mutbuf) -> u64:
    move_fragment(w, VERIFY_CANDIDATE_INPUT_QUOTED, EMIT_CUSTODY_INPUT_SHA)
    producer = choose(get(w, INSPECTION_EXPORTS + 16) > 2, EMIT_BORROWED_EXE, EMIT_SCALAR_EXE)
    return inspection_hash(o, w, EMIT_CUSTODY_PRODUCER_HASH, producer)
'''


ENCODING = r'''
def verify_encoding_start(o:mutbuf, w:mutbuf) -> u64:
    kind = get(w, EMIT_OUTPUT_KIND)
    if kind < 1 or kind > 2 or get(w, INSPECTION_EXPORTS + 16) != 2:
        return BAD
    move_fragment(w, VERIFY_ENCODE_STRUCTURED, INSPECTION_STRUCTURED)
    put(w, EMIT_PROFILE_LEVEL, get(w, VERIFY_ENCODE_PROFILE))
    put(w, VERIFY_ENCODE_AT, 0)
    planned = get(w, EMIT_CUSTODY_PLAN_REF + 16) != 0
    put(w, EMIT_CODEGEN_KIND, choose(planned, 2, 1))
    if planned:
        return verify_encoding_schedule(o, w)
    return emit_scalar_product(o, w, 12, get(w, EMIT_ABSOLUTE_DEADLINE))

def verify_encoding_plan(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    size = input_word(s, 40)
    if state == VERIFY_ENCODE_SCHEDULE:
        version = emit_schedule_version(s)
        if version == 0:
            return BAD
        put(w, EMIT_LAYOUT_FORMAT, version)
        if version == 4:
            return verify_encoding_registers(o, w)
        fragment(o, 0, input_word(s, 32), 8, size - 8)
        return action(o, w, VERIFY_ENCODE_LAYOUT, MAKE, 0, 0, 1, 0)
    if state == VERIFY_ENCODE_LAYOUT:
        if size < 40:
            return BAD
        sample_span(s, w, EMIT_LAYOUT)
        return verify_encoding_permit(o, w, EMIT_LAYOUT, EMIT_PLAN_STANDARD)
    if state == VERIFY_ENCODE_REGISTERS:
        version = input_word(s, 80)
        if (plan_ok(s) == False or size < 104 or input_word(s, 72) != EMIT_REPLAY_REGISTER_TAG
                or (version != 3 and version != 4) or input_word(s, 96) != size - 8):
            return BAD
        return verify_encoding_permit(o, w, EMIT_CUSTODY_CANONICAL_PLAN, EMIT_PLAN_REGISTER)
    if size < 168 or size != get(w, VERIFY_ENCODE_PERMIT_SIZE):
        return BAD
    sample_span(s, w, EMIT_LAYOUT_PERMIT)
    return emit_scalar_product(o, w, 12, get(w, EMIT_ABSOLUTE_DEADLINE))

def verify_encoding_permit(o:mutbuf, w:mutbuf, source:u64, tag:u64) -> u64:
    # The plan came from the authenticated build record and the HIA layout
    # checker bound it to the actual candidate. This packet is consumed by
    # the private compiler invocation, not an execution authorization.
    if get(w, EMIT_CUSTODY_RAW_SHA + 16) != 66 or get(w, EMIT_CUSTODY_CANONICAL_SHA + 16) != 66:
        return BAD
    put(w, VERIFY_ENCODE_PERMIT_SIZE, 144 + get(w, source + 16))
    put(o, HEADER, tag)
    put(o, HEADER + 8, 0)
    fragment(o, 0, get(w, EMIT_CUSTODY_RAW_SHA), get(w, EMIT_CUSTODY_RAW_SHA + 8) + 1, 64)
    fragment(o, 1, get(w, EMIT_CUSTODY_CANONICAL_SHA), get(w, EMIT_CUSTODY_CANONICAL_SHA + 8) + 1, 64)
    use_span(w, o, source, 2)
    return action(o, w, VERIFY_ENCODE_PERMIT, MAKE, 0, 0, 3, 16)

def emit_admission_error(o:mutbuf, w:mutbuf, scope:u64, reason:u64) -> u64:
    put(w, 0, VERIFY_ENCODE_EXPIRED)
    return VERIFY_FINITE_READY

def verify_encoding_hash(s:readbuf, o:mutbuf, w:mutbuf, at:u64, state:u64) -> u64:
    fd = input_word(s, 32)
    if state == EMIT_IMAGE_HASHED:
        hold(w, EMIT_IMAGE_QUOTED, fd, at - 65, 66)
        return verify_encoding_report(o, w)
    hold(w, EMIT_OBJECT_QUOTED, fd, at - 65, 66)
    put(o, HEADER, EMIT_COMPARE_REQUEST)
    put(o, HEADER + 8, 66)
    put(o, HEADER + 16, 66)
    use_span(w, o, EMIT_OBJECT_QUOTED, 0)
    use_span(w, o, EMIT_CUSTODY_OBJECT_SHA, 1)
    return action(o, w, VERIFY_ENCODE_OBJECT_MATCH, RUN, EMIT_NATIVE_ARTIFACT_ROLE, 0, 2, 24)

def verify_encoding_report(o:mutbuf, w:mutbuf) -> u64:
    # The ref denotes this particular rebuild's bytes only after matching
    # the measured object. The normalizer checks both fresh report hashes.
    store(o, HEADER, 91)
    store(o, 384, 44)
    store(o, 385, 48)
    store(o, 386, 44)
    store(o, 392, 93)
    vector_span(w, o, EMIT_CUSTODY_OBJECT_REF, HEADER + 1)
    vector_part(o, HEADER + 25, INLINE_FRAGMENT, 384, 1)
    vector_span(w, o, EMIT_PRODUCT_REPORT, HEADER + 49)
    vector_part(o, HEADER + 73, INLINE_FRAGMENT, 384, 3)
    vector_span(w, o, EMIT_IMAGE_QUOTED, HEADER + 97)
    vector_part(o, HEADER + 121, INLINE_FRAGMENT, 392, 1)
    return wide_inspection(o, w, EMIT_RETAINED_REPORT_BOUND, EMIT_RETAINED_REPORT_ROLE, 0, 6, 1)

def verify_encoding_observation(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    if state == VERIFY_ENCODE_OBJECT_MATCH:
        if emit_custody_compare_reply(s) == False or input_word(s, 80) != 1:
            return BAD
        if get(w, EMIT_OUTPUT_KIND) == 2:
            return emit_scalar_product(o, w, 13, get(w, EMIT_ABSOLUTE_DEADLINE))
        move_fragment(w, EMIT_OBJECT_QUOTED, EMIT_IMAGE_QUOTED)
        return verify_encoding_report(o, w)
    if state == VERIFY_ENCODE_IMAGE_MATCH:
        if emit_custody_compare_reply(s) == False:
            return BAD
        if input_word(s, 80) == 0:
            return verify_encoding_evidence(o, w, False)
        return verify_encoding_compare(o, w)
    size = input_word(s, 40)
    mode = get(w, VERIFY_FINITE_MODE)
    if (plan_ok(s) == False or size < 42 or size > VERIFY_PLAN_EVIDENCE_LIMIT
            or input_word(s, 72) != VERIFY_FINITE_REPORT or input_word(s, 88) != mode
            or input_word(s, 80) != mode - 10 or input_word(s, 96) != size - 40):
        return BAD
    body_span(s, w, VERIFY_FINITE_RESULT)
    return verify_finite_deliver(w)

def verify_encoding_compare(o:mutbuf, w:mutbuf) -> u64:
    at = get(w, VERIFY_ENCODE_AT)
    size = get(w, EMIT_IMAGE + 16)
    if size != get(w, EMIT_CUSTODY_NATIVE + 16):
        return verify_encoding_evidence(o, w, False)
    if at == size:
        return verify_encoding_evidence(o, w, True)
    if at > size:
        return BAD
    count = choose(size - at > 1048576, 1048576, size - at)
    put(w, VERIFY_ENCODE_AT, at + count)
    put(o, HEADER, EMIT_COMPARE_REQUEST)
    put(o, HEADER + 8, count)
    put(o, HEADER + 16, count)
    fragment(o, 0, get(w, EMIT_CUSTODY_NATIVE), get(w, EMIT_CUSTODY_NATIVE + 8) + at, count)
    fragment(o, 1, get(w, EMIT_IMAGE), get(w, EMIT_IMAGE + 8) + at, count)
    return action(o, w, VERIFY_ENCODE_IMAGE_MATCH, RUN, EMIT_NATIVE_ARTIFACT_ROLE, 0, 2, 24)

def verify_encoding_evidence(o:mutbuf, w:mutbuf, equal:bool) -> u64:
    put(w, VERIFY_FINITE_MODE, choose(equal, 11, 12))
    put(o, HEADER, VERIFY_FINITE_REQUEST)
    put(o, HEADER + 8, get(w, VERIFY_FINITE_MODE))
    use_span(w, o, EMIT_CUSTODY_NATIVE_SHA, 0)
    use_span(w, o, EMIT_IMAGE_QUOTED, 1)
    use_span(w, o, EMIT_RETAINED_REPORT, 2)
    return action(o, w, VERIFY_ENCODE_EVIDENCE, RUN, VERIFY_FINITE_EVIDENCE_ROLE, 0, 3, 16)
'''


FRESH = r'''
def verify_finite_start(o:mutbuf, w:mutbuf) -> u64:
    if (get(w, EMIT_PROOF_BASE_CORE + 16) == 0 or get(w, INSPECTION_CORE + 16) == 0
            or get(w, VERIFY_FINITE_BASE_SHA + 16) != 64 or get(w, VERIFY_FINITE_CANDIDATE_SHA + 16) != 64
            or get(w, VERIFY_FINITE_CONTEXT_END) == 0):
        return BAD
    put(w, EMIT_COMPLETE_REQUIRED, 0)
    put(w, EMIT_COMPLETE_INDEX, 0)
    put(w, EMIT_COMPLETE_TALLY, 0)
    put(w, EMIT_COMPLETE_EXTENT, 0)
    put(w, VERIFY_FINITE_END, 0)
    put(w, VERIFY_FINITE_TEMPORARIES, 0)
    return clock_sample(o, w, VERIFY_FINITE_INITIAL_CLOCK, 0)

def emit_complete_next(o:mutbuf, w:mutbuf) -> u64:
    return clock_sample(o, w, VERIFY_FINITE_CASE_CLOCK, 0)

def verify_finite_observation(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    size = input_word(s, 40)
    if state == VERIFY_FINITE_INITIAL_CLOCK or state == VERIFY_FINITE_CASE_CLOCK:
        if length(s) != 72 or size != 8:
            return BAD
        return verify_finite_clock(o, w, state, input_word(s, 64))
    if state == VERIFY_FINITE_EVIDENCE:
        mode = get(w, VERIFY_FINITE_MODE)
        status = choose(mode == 2, 1, choose(mode == 6, 2, 3))
        if (plan_ok(s) == False or size < 42 or size > 4096 or input_word(s, 72) != VERIFY_FINITE_REPORT
                or input_word(s, 80) != status
                or input_word(s, 88) != get(w, VERIFY_FINITE_MODE) or input_word(s, 96) != size - 40):
            return BAD
        body_span(s, w, VERIFY_FINITE_RESULT)
        if get(w, VERIFY_FINITE_MODE) != 2 and get(w, EMIT_COMPLETE_INDEX) != 0:
            return emit_seal_stream(o, w, VERIFY_FINITE_DISCARD_TRANSCRIPT, 0, get(w, EMIT_COMPLETE_EXTENT))
        return verify_finite_cleanup(o, w)
    if state == VERIFY_FINITE_DISCARD_TRANSCRIPT:
        if size != get(w, EMIT_COMPLETE_EXTENT):
            return BAD
        return emit_seal_stream(o, w, VERIFY_FINITE_DISCARD_SUMMARY, 1, 64 * get(w, EMIT_COMPLETE_INDEX))
    if state == VERIFY_FINITE_DISCARD_SUMMARY:
        if size != 64 * get(w, EMIT_COMPLETE_INDEX):
            return BAD
        return verify_finite_cleanup(o, w)
    if state == VERIFY_FINITE_CLEAN and length(s) == 64 and size == 0:
        return verify_finite_deliver(w)
    return BAD

def verify_finite_clock(o:mutbuf, w:mutbuf, state:u64, now:u64) -> u64:
    if state == VERIFY_FINITE_INITIAL_CLOCK:
        context_end = get(w, VERIFY_FINITE_CONTEXT_END)
        if now >= context_end or context_end - now < 1000000:
            return verify_finite_unknown(o, w, 9)
        put(w, VERIFY_FINITE_LAST_CLOCK, now)
        return emit_complete_input(o, w)
    if now < get(w, VERIFY_FINITE_LAST_CLOCK):
        return BAD
    put(w, VERIFY_FINITE_LAST_CLOCK, now)
    if get(w, VERIFY_FINITE_END) == 0:
        context_end = get(w, VERIFY_FINITE_CONTEXT_END)
        if now >= context_end:
            return verify_finite_unknown(o, w, 3)
        put(w, VERIFY_FINITE_END, choose(context_end - now > VERIFY_FINITE_CAP, now + VERIFY_FINITE_CAP, context_end))
    index = get(w, EMIT_COMPLETE_INDEX)
    if index == get(w, EMIT_COMPLETE_COUNT):
        if get(w, EMIT_COMPLETE_TALLY) != get(w, EMIT_COMPLETE_REQUIRED):
            return BAD
        if now > get(w, VERIFY_FINITE_END):
            return verify_finite_unknown(o, w, 5)
        return emit_seal_stream(o, w, EMIT_COMPLETE_STREAM, 0, get(w, EMIT_COMPLETE_EXTENT))
    if now > get(w, VERIFY_FINITE_END):
        return verify_finite_unknown(o, w, 3)
    put(w, VERIFY_FINITE_TEMPORARIES, 1)
    domains = EMIT_COMPLETE_DOMAINS
    return read_span(o, w, EMIT_COMPLETE_ROW, get(w, domains), get(w, domains + 8) + 32 + 56 * index, 56)

def verify_finite_plan(o:mutbuf, w:mutbuf) -> u64:
    command = action(o, w, EMIT_COMPLETE_PLAN, RUN, EMIT_COMPLETE_PLAN_ROLE, 0, 1, 0)
    put(o, 144, get(w, VERIFY_FINITE_CONTEXT_END))
    return command

def verify_finite_partial(o:mutbuf, w:mutbuf) -> u64:
    # Do not credit a tuple that the native reference roles did not return.
    if get(w, EMIT_COMPLETE_REQUIRED) == 0:
        return verify_finite_unknown(o, w, 9)
    return verify_finite_unknown(o, w, 3)

def verify_finite_unknown(o:mutbuf, w:mutbuf, mode:u64) -> u64:
    put(w, VERIFY_FINITE_MODE, mode)
    put(o, HEADER, VERIFY_FINITE_REQUEST)
    put(o, HEADER + 8, mode)
    put(o, HEADER + 16, get(w, EMIT_COMPLETE_TALLY))
    put(o, HEADER + 24, get(w, EMIT_COMPLETE_REQUIRED))
    return action(o, w, VERIFY_FINITE_EVIDENCE, RUN, VERIFY_FINITE_EVIDENCE_ROLE, 0, 0, choose(mode == 9, 16, 32))

def verify_finite_cleanup(o:mutbuf, w:mutbuf) -> u64:
    if get(w, VERIFY_FINITE_TEMPORARIES) == 0:
        return verify_finite_deliver(w)
    return action(o, w, VERIFY_FINITE_CLEAN, EMIT_RELEASE_TEMPORARIES, 0, 0, 0, 0)

def verify_finite_deliver(w:mutbuf) -> u64:
    put(w, 0, VERIFY_FINITE_DELIVERED)
    return VERIFY_FINITE_READY

def verify_finite_row(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    difference = input_word(s, 96)
    if difference == EMIT_NO_VALUE:
        return emit_complete_append_transcript(s, o, w)
    checked = input_word(s, 80)
    required = input_word(s, 88)
    start = input_word(s, 104)
    bytes = input_word(s, 112)
    extent = input_word(s, 120)
    if (length(s) != 128 or input_word(s, 64) != EMIT_COMPLETE_TRANSCRIPT_REPLY or input_word(s, 72) != 0
            or required != get(w, EMIT_COMPLETE_TUPLES) or difference >= required or checked != difference + 1
            or extent != input_word(s, 40) - 72 or start < 64 or start - 64 > extent
            or bytes < 32 or bytes > 2048 or bytes != extent - (start - 64)):
        return BAD
    store(o, HEADER, 91)
    at = decimal(o, HEADER + 1, get(w, EMIT_COMPLETE_TALLY) + checked)
    store(o, at, 44)
    at = decimal(o, at + 1, get(w, EMIT_COMPLETE_REQUIRED))
    store(o, at, 44)
    store(o, 496, 93)
    fragment(o, 0, input_word(s, 32), 8 + start, bytes)
    fragment(o, 1, INLINE_FRAGMENT, 496, 1)
    put(w, VERIFY_FINITE_MODE, 6)
    return action(o, w, VERIFY_FINITE_EVIDENCE, RUN, VERIFY_FINITE_EVIDENCE_ROLE, 0, 2, at + 1 - HEADER)

def inspection_hash_bound(s:readbuf, o:mutbuf, w:mutbuf, at:u64) -> u64:
    resume = get(w, INSPECTION_HASH_RESUME)
    if resume >= EMIT_CUSTODY_RAW_HASH and resume <= EMIT_CUSTODY_OBJECT_HASH:
        return emit_custody_hash(s, o, w, at, resume)
    if resume == EMIT_REPLAY_OBJECT_HASH:
        return emit_replay_object_hash(s, o, w, at)
    if resume == EMIT_OBJECT_HASHED or resume == EMIT_IMAGE_HASHED:
        return verify_encoding_hash(s, o, w, at, resume)
    if resume != EMIT_COMPLETE_HASH:
        return BAD
    put(w, VERIFY_FINITE_MODE, 2)
    put(o, HEADER, VERIFY_FINITE_REQUEST)
    put(o, HEADER + 8, 2)
    vector_span(w, o, VERIFY_FINITE_BASE_SHA, HEADER + 16)
    vector_span(w, o, VERIFY_FINITE_CANDIDATE_SHA, HEADER + 40)
    vector_part(o, HEADER + 64, input_word(s, 32), at - 64, 64)
    vector_span(w, o, EMIT_COMPLETE_DOMAINS, HEADER + 88)
    vector_span(w, o, EMIT_COMPLETE_SUMMARY_ROWS, HEADER + 112)
    return wide_inspection(o, w, VERIFY_FINITE_EVIDENCE, VERIFY_FINITE_EVIDENCE_ROLE, 0, 5, 16)
'''


def finite_constants(constants):
    states = ('START', 'INITIAL_CLOCK', 'CASE_CLOCK', 'EVIDENCE', 'DISCARD_TRANSCRIPT',
              'DISCARD_SUMMARY', 'CLEAN', 'DELIVERED')
    spans = ('BASE_SHA', 'CANDIDATE_SHA', 'RESULT')
    scalars = ('CONTEXT_END', 'END', 'LAST_CLOCK', 'TEMPORARIES', 'MODE')
    constants.update({f'VERIFY_FINITE_{name}': 1290 + i for i, name in enumerate(states)})
    constants.update({f'VERIFY_FINITE_{name}': 10368 + 24 * i for i, name in enumerate(spans)})
    constants.update({f'VERIFY_FINITE_{name}': 10440 + 8 * i for i, name in enumerate(scalars)})
    constants.update(VERIFY_FINITE_EVIDENCE_ROLE=71, VERIFY_FINITE_READY=0xffffffe7,
                     VERIFY_FINITE_INELIGIBLE=0xffffffe6, VERIFY_FINITE_INELIGIBLE_TAG=INELIGIBLE,
                     VERIFY_FINITE_CAP=10_000_000_000,
                     VERIFY_FINITE_REQUEST=int.from_bytes(b'HIAVEV01', 'little'),
                     VERIFY_FINITE_REPORT=int.from_bytes(b'HIAVER01', 'little'))

def plan_constants(constants):
    states = ('CANONICAL', 'SCHEDULE', 'DESCRIPTOR', 'REGISTERS', 'ADMITTED', 'INVALID',
              'CHECK', 'EVIDENCE', 'WITNESS')
    constants.update({f'VERIFY_PLAN_{name}': 1330 + i for i, name in enumerate(states)})
    constants.update(VERIFY_CANDIDATE_SHA=10608, VERIFY_PLAN_EVIDENCE_LIMIT=PLAN_EVIDENCE_LIMIT,
                     VERIFY_REGISTER_WITNESS=WITNESS_TAG,
                     VERIFY_DERIVE_PREFIX=int.from_bytes(b',"derive', 'little'),
                     VERIFY_DERIVE_SUFFIX=int.from_bytes(b'"]', 'little'))


def custody_constants(constants):
    constants.update(VERIFY_NATIVE_STORE=1380, VERIFY_NATIVE_BOUND=1381, VERIFY_CANDIDATE_INPUT_QUOTED=11480)


def encoding_constants(constants):
    states = ('START', 'OBJECT_MATCH', 'IMAGE_MATCH', 'EVIDENCE', 'EXPIRED',
              'SCHEDULE', 'LAYOUT', 'REGISTERS', 'PERMIT')
    constants.update({f'VERIFY_ENCODE_{name}': 1382 + i for i, name in enumerate(states)})
    constants.update(VERIFY_ENCODE_STRUCTURED=11504, VERIFY_ENCODE_PROFILE=11528,
                     VERIFY_ENCODE_AT=11536, VERIFY_ENCODE_PERMIT_SIZE=11544)


def finite_recipe():
    _, parts = proof_recipe(function(ADMISSION, 'emit_admission_error'),
                            function(PROFILES, 'emit_open_profile'))
    policy = replace_function('\n'.join(parts), 'inspection_hash_result',
                              function(VIEW_DRIVER, 'inspection_hash_result'))
    state = function(policy, 'emit_complete_state')
    state = state.replace('    if state == EMIT_COMPLETE_PLAN:\n',
                          '    if state == EMIT_COMPLETE_PLAN:\n'
                          '        if (plan_ok(s) and size == 24 and input_word(s, 72) == VERIFY_FINITE_INELIGIBLE_TAG\n'
                          '                and input_word(s, 80) == 0):\n'
                          '            return VERIFY_FINITE_INELIGIBLE\n')
    state = state.replace('or input_word(s, 96) != get(w, EMIT_COMPLETE_REQUIRED)',
                          'or input_word(s, 96) == 0 or input_word(s, 96) > 4096')
    state = state.replace('put(w, EMIT_COMPLETE_FLAGS,', 'put(w, EMIT_COMPLETE_REQUIRED, input_word(s, 96))\n        put(w, EMIT_COMPLETE_FLAGS,')
    state = state.replace('return emit_complete_append_transcript(s, o, w)', 'return verify_finite_row(s, o, w)')
    state = state.replace('return action(o, w, EMIT_COMPLETE_PLAN, RUN, EMIT_COMPLETE_PLAN_ROLE, 0, 1, 0)',
                          'return verify_finite_plan(o, w)')
    state = state.replace('put(w, EMIT_COMPLETE_INDEX, get(w, EMIT_COMPLETE_INDEX) + 1)',
                          'put(w, VERIFY_FINITE_TEMPORARIES, 0)\n        put(w, EMIT_COMPLETE_INDEX, get(w, EMIT_COMPLETE_INDEX) + 1)')
    start = state.index('    if state == EMIT_COMPLETE_EXPECTATION:')
    stop = state.index('    if state == EMIT_COMPLETE_INPUT:')
    state = state[:start] + state[stop:]
    checked = state.index('    if state == EMIT_COMPLETE_CHECKED:')
    state = state[:checked] + '    return BAD\n'
    policy = replace_function(policy, 'emit_complete_state', state)
    custody = function(policy, 'emit_proof_custody_state')
    custody = custody[:custody.index('    if state == EMIT_CUSTODY_EFFECT:')] + '    return BAD\n'
    policy = replace_function(policy, 'emit_proof_custody_state', custody)
    policy = replace_function(policy, 'emit_proof_read', '')
    policy = replace_function(policy, 'emit_proof_open_claims', '')
    policy = replace_function(policy, 'emit_custody_inputs', '')
    reopen = function(policy, 'emit_proof_custody_reopened').replace(
        '            sample_span(s, w, EMIT_CUSTODY_NATIVE)',
        '            put(w, EMIT_OUTPUT_KIND, choose(kind == EMIT_ELF_OBJECT, 1, 2))\n'
        '            sample_span(s, w, EMIT_CUSTODY_NATIVE)')
    policy = replace_function(policy, 'emit_proof_custody_reopened', reopen)
    policy = replace_function(policy, 'emit_admission_error', '')
    policy = replace_function(policy, 'emit_complete_next', '')
    policy = replace_function(policy, 'emit_complete_input',
                              splice_list('emit_complete_input', 'EMIT_COMPLETE_INPUT',
                                          ('EMIT_PROOF_BASE_CORE', 'INSPECTION_CORE'), suffix=b',true]'))
    for name in ('emit_complete_row', 'emit_complete_run_wire', 'emit_complete_batch',
                 'emit_complete_transcript'):
        source = function(policy, name).replace('    put(o, 184, 1)',
                                                 '    put(o, 144, get(w, VERIFY_FINITE_END))\n    put(o, 184, 1)')
        policy = replace_function(policy, name, source)
    plan_inputs = ('INSPECTION_CORE', 'VERIFY_CANDIDATE_SHA', 'EMIT_CANONICAL_PLAN')
    replay = function(LAYOUT_REPLAY, 'emit_replay_layout_state')
    start = replay.index('    if state == EMIT_REPLAY_LAYOUT:')
    end = replay.index('    if state == EMIT_REPLAY_PLAN_INPUT:')
    replay = replay[:start] + replay[end:]
    start = replay.index('        if get(w, EMIT_REPLAY_VERSION) == 4:')
    replay = replay[:start] + (
        '        if get(w, EMIT_REPLAY_VERSION) == 4:\n'
        '            return verify_plan_witness(o, w)\n'
        '        return verify_plan_evidence(o, w)\n'
        '    return BAD\n'
    )
    policy = replace_function(policy, 'emit_replay_layout_state', replay)
    evidence = ('VERIFY_CANDIDATE_SHA', 'EMIT_CANONICAL_PLAN', 'EMIT_REPLAY_BASE_HASH',
                'EMIT_REPLAY_PLAN_HASH', 'EMIT_REPLAY_BASE_FRAMES', 'EMIT_REPLAY_PLAN_FRAMES')
    encoding_plan = ('INSPECTION_CORE', 'VERIFY_CANDIDATE_SHA', 'EMIT_CUSTODY_CANONICAL_PLAN')
    return reachable_policy('\n'.join((
        ENTRY, FRESH, NATIVE_CUSTODY, ENCODING, policy, function(ENTRY_POLICY, 'valid_fd'), SUBJECT_PLAN,
        SCALAR, function(PRODUCTION, 'emit_product_observed'),
        splice_list('verify_encoding_schedule', 'VERIFY_ENCODE_SCHEDULE', encoding_plan, role='EMIT_LAYOUT_ROLE'),
        splice_list('verify_encoding_registers', 'VERIFY_ENCODE_REGISTERS', encoding_plan,
                    role='EMIT_REPLAY_WITNESS_ROLE'),
        splice_list('verify_plan_schedule', 'VERIFY_PLAN_SCHEDULE', plan_inputs, role='EMIT_LAYOUT_ROLE'),
        splice_list('verify_plan_registers', 'VERIFY_PLAN_REGISTERS', plan_inputs,
                    role='EMIT_REPLAY_WITNESS_ROLE'),
        splice_list('verify_plan_evidence', 'VERIFY_PLAN_EVIDENCE', evidence,
                    prefix=b'["plan",', role='VERIFY_FINITE_EVIDENCE_ROLE'),
        splice_list('verify_plan_register_evidence', 'VERIFY_PLAN_EVIDENCE', (*evidence, 'EMIT_REPLAY_WITNESS_SPAN'),
                    prefix=b'["plan",', role='VERIFY_FINITE_EVIDENCE_ROLE'),
    )),
                            'verify_finite_flow')


def program():
    constants, _, _ = native_recipe()
    constants.update(EMIT_WORK_BYTES=12288)
    finite_constants(constants)
    plan_constants(constants)
    custody_constants(constants)
    encoding_constants(constants)
    entry, controls = finite_recipe()
    return flow_source(entry, controls, constants)


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)), encoding='utf-8')
