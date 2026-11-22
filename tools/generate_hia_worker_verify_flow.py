"""Author Verify's sealed request, profile, and Core admission continuation."""

from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_worker_adopt_proof import reachable_policy
from tools.generate_hia_worker_candidate_flow import replace_function
from tools.generate_hia_worker_context_flow import flow_source, function
from tools.generate_hia_worker_adopt_flow import OUTCOME
from tools.generate_hia_worker_emit_flow import DISPATCH, REACTOR, REQUEST, native_recipe
from tools.generate_hia_worker_emit_measurement import MEASUREMENT, splice_list
from tools.generate_hia_worker_emit_proof import PLAN
from tools.generate_hia_worker_inspection_flow import VIEW_DRIVER
from tools.generate_hia_worker_verify_finite_flow import finite_constants, plan_constants

SOURCE = Path('examples/hia_bootstrap/worker_verify_flow.hepta')

INGRESS = r'''
def authorize_business(o:mutbuf, w:mutbuf) -> u64:
    inspection_catalog(o, w)
    after_prefix(w, o, ARGUMENT_FD, 0)
    store(o, 496, 93)
    fragment(o, 1, INLINE_FRAGMENT, 496, 1)
    return action(o, w, EMIT_PROJECTED, RUN, VERIFY_REQUEST_ROLE, 0, 2, 68)

def verify_ingress(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    fd = input_word(s, 32)
    size = input_word(s, 40)
    if state == EMIT_PROJECTED:
        if plan_ok(s) == False or size < 88 or input_word(s, 72) != VERIFY_REQUEST_TAG:
            return BAD
        body_span(s, w, EMIT_REQUEST_BODY)
        put(o, HEADER, VERIFY_INDEX)
        use_span(w, o, EMIT_REQUEST_BODY, 0)
        return action(o, w, EMIT_INDEX_BOUND, RUN, VERIFY_REQUEST_ROLE, 0, 1, 8)
    if state == EMIT_INDEX_BOUND:
        if plan_ok(s) == False or size != 144 or input_word(s, 72) != VERIFY_INDEX_TAG:
            return BAD
        return read_span(o, w, EMIT_INDEX_FRAME, fd, 8, 136)
    return verify_index(s, o, w)

def verify_index(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    kind = input_word(s, 72)
    count = input_word(s, 80)
    if length(s) != 200 or input_word(s, 64) != VERIFY_INDEX_TAG or kind < 1 or kind > 4 or count < 1 or count > 4:
        return BAD
    put(w, VERIFY_SUBJECT_KIND, kind)
    put(w, VERIFY_CLAIM_COUNT, count)
    copy_span(s, w, 88, VERIFY_CLAIM_ORDINALS, 32)
    fd = get(w, EMIT_REQUEST_BODY)
    origin = get(w, EMIT_REQUEST_BODY + 8)
    limit = get(w, EMIT_REQUEST_BODY + 16)
    field = 0
    end = 24 + 8 * count
    while field < 5:
        offset = input_word(s, 120 + 16 * field)
        size = input_word(s, 128 + 16 * field)
        if offset != end + 8 or offset > limit or size < 2 or size > limit - offset:
            return BAD
        hold(w, EMIT_FIELDS + 24 * (field + 1), fd, origin + offset, size)
        end = offset + size
        field = field + 1
    if end != limit:
        return BAD
    # Shared Emit helpers use field +24 for the Context and +48 for Core.
    move_fragment(w, EMIT_FIELDS + 48, VERIFY_VALIDATION)
    move_fragment(w, EMIT_FIELDS + 72, EMIT_FIELDS + 48)
    move_fragment(w, EMIT_FIELDS + 96, VERIFY_BASE)
    move_fragment(w, EMIT_FIELDS + 120, VERIFY_SUBJECT)
    put(w, EMIT_STAGE, VERIFY_STAGE_CONTEXT)
    move_fragment(w, EMIT_FIELDS + 24, INSPECTION_ACTUAL)
    return inspection_context(o, w)
'''

CUSTODY = r'''
def verify_context(o:mutbuf, w:mutbuf) -> u64:
    stage = get(w, EMIT_STAGE)
    if stage == VERIFY_STAGE_CONTEXT:
        context = EMIT_FIELDS + 24
        if get(w, context + 16) < 44:
            return BAD
        hold(w, VERIFY_CONTEXT_ID, get(w, context), get(w, context + 8) + 7, 36)
        put(w, EMIT_STAGE, 3)
        return emit_admission(o, w, 3, 0)
    return BAD

def verify_validation(o:mutbuf, w:mutbuf) -> u64:
    put(w, EMIT_STAGE, VERIFY_STAGE_VALIDATION)
    return emit_open_profile(o, w, 6, VERIFY_VALIDATION)

def verify_after_profile(o:mutbuf, w:mutbuf) -> u64:
    stage = get(w, EMIT_STAGE)
    if stage == VERIFY_STAGE_VALIDATION:
        put(w, EMIT_STAGE, VERIFY_STAGE_CANDIDATE)
        move_fragment(w, EMIT_FIELDS + 48, INSPECTION_ACTUAL)
        return inspection_program(o, w)
    kind = get(w, VERIFY_SUBJECT_KIND)
    if stage == VERIFY_STAGE_BACKEND:
        if kind == 4:
            return VERIFY_NEEDS_SUBJECT_CUSTODY
        put(w, EMIT_STAGE, VERIFY_STAGE_SUBJECT_PROFILE)
        return emit_open_profile(o, w, choose(kind == 2, 3, 4), VERIFY_SUBJECT_REFS + 24)
    if stage == VERIFY_STAGE_SUBJECT_PROFILE:
        if kind == 3:
            move_fragment(w, VERIFY_SUBJECT_REFS + 48, INSPECTION_REFERENCE)
            return emit_proof_read(o, w, READ_EMIT_PLAN, 0)
        return verify_scope_input(o, w)
    return BAD

def verify_core_admitted(o:mutbuf, w:mutbuf) -> u64:
    stage = get(w, EMIT_STAGE)
    if stage == VERIFY_STAGE_CANDIDATE:
        return inspection_hash(o, w, VERIFY_CANDIDATE_HASH, INSPECTION_CORE)
    if stage == VERIFY_STAGE_BASE:
        move_fragment(w, INSPECTION_CORE, EMIT_PROOF_BASE_CORE)
        move_fragment(w, VERIFY_CANDIDATE, INSPECTION_CORE)
        return inspection_hash(o, w, VERIFY_ORIGINAL_HASH, EMIT_PROOF_BASE_CORE)
    return BAD

def inspection_hash_bound(s:readbuf, o:mutbuf, w:mutbuf, at:u64) -> u64:
    state = get(w, INSPECTION_HASH_RESUME)
    fd = input_word(s, 32)
    if state == VERIFY_CANDIDATE_HASH:
        hold(w, VERIFY_CANDIDATE_SHA, fd, at - 65, 66)
        hold(w, VERIFY_FINITE_CANDIDATE_SHA, fd, at - 64, 64)
        move_fragment(w, INSPECTION_CORE, VERIFY_CANDIDATE)
        core_source = INSPECTION_CORE
        if get(w, INSPECTION_STRUCTURED + 16) != 0:
            core_source = INSPECTION_STRUCTURED
        return inspection_hash(o, w, VERIFY_CANDIDATE_INPUT_HASH, core_source)
    if state == VERIFY_CANDIDATE_INPUT_HASH:
        hold(w, VERIFY_CANDIDATE_INPUT_SHA, fd, at - 64, 64)
        base = VERIFY_BASE
        if get(w, base + 16) == 4:
            return read_span(o, w, VERIFY_BASE_NULL, get(w, base), get(w, base + 8), 4)
        put(w, EMIT_STAGE, VERIFY_STAGE_BASE)
        put(w, INSPECTION_STRUCTURED + 16, 0)
        move_fragment(w, base, INSPECTION_ACTUAL)
        return inspection_program(o, w)
    if state == VERIFY_ORIGINAL_HASH:
        hold(w, VERIFY_ORIGINAL_SHA, fd, at - 65, 66)
        hold(w, VERIFY_FINITE_BASE_SHA, fd, at - 64, 64)
        return verify_subject(o, w)
    return BAD
'''

SUBJECT = r'''
def verify_subject(o:mutbuf, w:mutbuf) -> u64:
    if get(w, VERIFY_SUBJECT_KIND) == 1:
        return verify_scope_input(o, w)
    store(o, HEADER, 91)
    store(o, 496, 93)
    use_span(w, o, VERIFY_SUBJECT, 0)
    fragment(o, 1, INLINE_FRAGMENT, 496, 1)
    return action(o, w, VERIFY_SUBJECT_FRAME, MAKE, 0, 0, 2, 1)

def verify_subject_reply(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    size = input_word(s, 40)
    if state == VERIFY_BASE_NULL:
        if length(s) != 68 or input_word(s, 56) != 4:
            return BAD
        if byte(s, 64) != 110 or byte(s, 65) != 117 or byte(s, 66) != 108 or byte(s, 67) != 108:
            return BAD
        move_fragment(w, VERIFY_BASE, VERIFY_ORIGINAL_SHA)
        return verify_subject(o, w)
    if state == VERIFY_SUBJECT_FRAME:
        if size < 4 or size != get(w, VERIFY_SUBJECT + 16) + 2:
            return BAD
        sample_span(s, w, VERIFY_SUBJECT_REQUEST)
        use_span(w, o, VERIFY_SUBJECT_REQUEST, 0)
        return action(o, w, VERIFY_SUBJECT_INDEX, RUN, VERIFY_REQUEST_ROLE, 0, 1, 0)
    if state == VERIFY_SUBJECT_INDEX:
        if plan_ok(s) == False or input_word(s, 72) != VERIFY_SUBJECT_TAG or (size != 64 and size != 80):
            return BAD
        return read_span(o, w, VERIFY_SUBJECT_OFFSETS, input_word(s, 32), 8, size - 8)
    if state == VERIFY_SUBJECT_OFFSETS:
        return verify_subject_offsets(s, o, w)
    if state == VERIFY_SCOPE_READY:
        if (plan_ok(s) == False or size < 26 or size > 8192 or input_word(s, 72) != VERIFY_SCOPE_TAG
                or input_word(s, 80) != size - 24):
            return BAD
        hold(w, VERIFY_SCOPE, input_word(s, 32), 24, size - 24)
        return verify_checks(o, w)
    return BAD

def verify_scope_input(o:mutbuf, w:mutbuf) -> u64:
    bytes = slot_bytes(w, ARGUMENT_FD)
    if bytes < 10 or get(w, INSPECTION_PROFILE_2 + 16) < 2:
        return BAD
    hold(w, VERIFY_ARGUMENTS, slot_fd(w, ARGUMENT_FD), 8, bytes - 8)
    return verify_scope_values(o, w)
'''

SUBJECT_INDEX = r'''
def verify_subject_offsets(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    kind = get(w, VERIFY_SUBJECT_KIND)
    count = input_word(s, 80)
    if (input_word(s, 64) != VERIFY_SUBJECT_TAG or input_word(s, 72) != kind
            or count != choose(kind == 2, 2, 3) or length(s) != 88 + 16 * count):
        return BAD
    fd = get(w, VERIFY_SUBJECT_REQUEST)
    limit = get(w, VERIFY_SUBJECT_REQUEST + 16)
    index = 0
    while index < count:
        offset = input_word(s, 88 + 16 * index)
        size = input_word(s, 96 + 16 * index)
        if offset == 0 or offset >= limit or size < 2 or size >= limit - offset:
            return BAD
        hold(w, VERIFY_SUBJECT_REFS + 24 * index, fd, offset, size)
        index = index + 1
    put(w, EMIT_STAGE, VERIFY_STAGE_BACKEND)
    return emit_open_profile(o, w, 1, VERIFY_SUBJECT_REFS)
'''

CHECKS = r'''
def verify_checks(o:mutbuf, w:mutbuf) -> u64:
    index = get(w, VERIFY_CLAIM_INDEX)
    if index == get(w, VERIFY_CLAIM_COUNT):
        put(w, 0, VERIFY_FINDINGS_START)
        return VERIFY_NEEDS_FINDINGS
    if index > get(w, VERIFY_CLAIM_COUNT):
        return BAD
    claim = get(w, VERIFY_CLAIM_ORDINALS + 8 * index)
    if claim == 1:
        put(o, HEADER, VERIFY_FINITE_REQUEST)
        put(o, HEADER + 8, 7)
        put(o, 496, get(w, INSPECTION_CORE + 16))
        use_span(w, o, VERIFY_FINITE_CANDIDATE_SHA, 0)
        use_span(w, o, VERIFY_CANDIDATE_INPUT_SHA, 1)
        fragment(o, 2, INLINE_FRAGMENT, 496, 8)
        put(w, VERIFY_DIRECT_MODE, 7)
        return action(o, w, VERIFY_CHECK_RESULT, RUN, VERIFY_FINITE_EVIDENCE_ROLE, 0, 3, 16)
    if claim == 2:
        if get(w, VERIFY_REPLAYING) != 0:
            if get(w, VERIFY_REPLAY_FROZEN_LIMIT) != 0:
                return verify_direct_evidence(o, w, 9)
            return clock_sample(o, w, VERIFY_REPLAY_CLOCK, 0)
        put(w, EMIT_STAGE, 11)
        return emit_wall_start(o, w)
    if claim == 3 and get(w, VERIFY_SUBJECT_KIND) == 2:
        return verify_direct_evidence(o, w, 8)
    return BAD

def verify_direct_evidence(o:mutbuf, w:mutbuf, mode:u64) -> u64:
    put(o, HEADER, VERIFY_FINITE_REQUEST)
    put(o, HEADER + 8, mode)
    put(w, VERIFY_DIRECT_MODE, mode)
    return action(o, w, VERIFY_CHECK_RESULT, RUN, VERIFY_FINITE_EVIDENCE_ROLE, 0, 0, 16)

def verify_behavior(o:mutbuf, w:mutbuf) -> u64:
    if get(w, VERIFY_FINITE_BASE_SHA + 16) != 64 or get(w, VERIFY_FINITE_CANDIDATE_SHA + 16) != 64:
        return BAD
    put(w, VERIFY_FINITE_CONTEXT_END, get(w, EMIT_ABSOLUTE_DEADLINE))
    use_span(w, o, VERIFY_FINITE_BASE_SHA, 0)
    use_span(w, o, VERIFY_FINITE_CANDIDATE_SHA, 1)
    return action(o, w, VERIFY_HASH_PAIR, MAKE, 0, 0, 2, 0)

def verify_check_reply(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    size = input_word(s, 40)
    if state == VERIFY_HASH_PAIR:
        if size != 128:
            return BAD
        return read_span(o, w, VERIFY_HASH_COMPARE, input_word(s, 32), 0, size)
    if state == VERIFY_HASH_COMPARE:
        index = 0
        while index < 64:
            if byte(s, 64 + index) != byte(s, 128 + index):
                put(w, 0, VERIFY_FINITE_START)
                return VERIFY_NEEDS_FINITE
            index = index + 1
        put(o, HEADER, VERIFY_FINITE_REQUEST)
        put(o, HEADER + 8, 1)
        fragment(o, 0, input_word(s, 32), 0, 128)
        put(w, VERIFY_DIRECT_MODE, 1)
        return action(o, w, VERIFY_CHECK_RESULT, RUN, VERIFY_FINITE_EVIDENCE_ROLE, 0, 1, 16)
    if state == VERIFY_CHECK_RESULT:
        if plan_ok(s) == False or size < 42 or size > 4096:
            return BAD
        mode = get(w, VERIFY_DIRECT_MODE)
        status = choose(mode == 9, 3, choose(mode == 8, 4, 1))
        if (input_word(s, 72) != VERIFY_FINITE_REPORT or input_word(s, 80) != status
                or input_word(s, 88) != mode or input_word(s, 96) != size - 40):
            return BAD
        body_span(s, w, VERIFY_FINITE_RESULT)
        return verify_observed(o, w)
    return BAD

def verify_observed(o:mutbuf, w:mutbuf) -> u64:
    index = get(w, VERIFY_CLAIM_INDEX)
    if index >= get(w, VERIFY_CLAIM_COUNT) or get(w, VERIFY_FINITE_RESULT + 16) < 34:
        return BAD
    move_fragment(w, VERIFY_FINITE_RESULT, VERIFY_EVIDENCE_SPANS + 24 * index)
    put(w, VERIFY_CLAIM_INDEX, index + 1)
    return verify_checks(o, w)

'''


REPLAY = r'''
def verify_cached(o:mutbuf, w:mutbuf) -> u64:
    put(w, VERIFY_REPLAYING, 1)
    return project_artifact(o, w, VERIFY_REPLAY_ARGUMENTS, ARGUMENT, ARGUMENT_ROLE)

def verify_replay_reply(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    if state == VERIFY_REPLAY_ARGUMENTS:
        if prefixed(s) == False or get(w, CACHED_BYTES) < 2:
            return BAD
        observe_slot(s, w, ARGUMENT_FD)
        store(o, HEADER, 91)
        store(o, HEADER + 1, 34)
        copy_private(w, o, JOURNAL_STATE + 192, HEADER + 2, 66)
        store(o, HEADER + 68, 34)
        store(o, HEADER + 69, 44)
        store(o, 400, 44)
        store(o, 401, 93)
        vector_part(o, HEADER + 70, slot_fd(w, ARGUMENT_FD), 8, slot_bytes(w, ARGUMENT_FD) - 8)
        vector_part(o, HEADER + 94, INLINE_FRAGMENT, 400, 1)
        vector_part(o, HEADER + 118, slot_fd(w, LOOKUP_FD), get(w, CACHED_AT), get(w, CACHED_BYTES))
        vector_part(o, HEADER + 142, INLINE_FRAGMENT, 401, 1)
        return emit_wide_make(o, w, VERIFY_REPLAY_PACKET_READY, 4, 70)
    if state == VERIFY_REPLAY_PACKET_READY:
        size = input_word(s, 40)
        if size != 72 + slot_bytes(w, ARGUMENT_FD) - 8 + get(w, CACHED_BYTES):
            return BAD
        sample_span(s, w, VERIFY_REPLAY_PACKET)
        use_span(w, o, VERIFY_REPLAY_PACKET, 0)
        return action(o, w, VERIFY_REPLAY_INDEXED, RUN, VERIFY_REPLAY_ROLE, 0, 1, 0)
    if state == VERIFY_REPLAY_INDEXED:
        if plan_ok(s) == False or input_word(s, 40) != 64 or length(s) != 128:
            return BAD
        count = input_word(s, 80)
        if input_word(s, 72) != VERIFY_REPLAY_TAG or count < 1 or count > 4 or input_word(s, 120) > 1:
            return BAD
        start = input_word(s, 88)
        bytes = input_word(s, 96)
        cache = get(w, CACHED_BYTES)
        prefix = get(w, VERIFY_REPLAY_PACKET + 16) - cache - 1
        if start < prefix or start > prefix + cache or bytes < 2 or bytes > prefix + cache - start:
            return BAD
        hold(w, VERIFY_REPLAY_EXPECTED, get(w, VERIFY_REPLAY_PACKET), start, bytes)
        put(w, VERIFY_REPLAY_FROZEN_LIMIT, input_word(s, 120))
        return authorize_business(o, w)
    if state == VERIFY_REPLAY_CLOCK:
        now = input_word(s, 64)
        if length(s) != 72 or input_word(s, 40) != 8 or now > MAX_CLOCK - VERIFY_FINITE_CAP:
            return BAD
        put(w, EMIT_ABSOLUTE_DEADLINE, now + VERIFY_FINITE_CAP)
        return verify_behavior(o, w)
    if state == VERIFY_REPLAY_COMPARED:
        if plan_ok(s) == False or input_word(s, 40) != 24 or input_word(s, 72) != EMIT_COMPARE_RESULT or input_word(s, 80) != 1:
            return BAD
        return send_report(o, w, True)
    return BAD

def verify_complete(o:mutbuf, w:mutbuf) -> u64:
    if get(w, VERIFY_REPLAYING) == 0:
        return verify_outcome(o, w, 1, VERIFY_RESULT)
    size = get(w, VERIFY_RESULT + 16)
    if size < 2 or size > 1048576 or size != get(w, VERIFY_REPLAY_EXPECTED + 16):
        return BAD
    put(o, HEADER, EMIT_COMPARE_REQUEST)
    put(o, HEADER + 8, size)
    put(o, HEADER + 16, size)
    use_span(w, o, VERIFY_REPLAY_EXPECTED, 0)
    use_span(w, o, VERIFY_RESULT, 1)
    return action(o, w, VERIFY_REPLAY_COMPARED, RUN, EMIT_NATIVE_ARTIFACT_ROLE, 0, 2, 24)
'''


def constants_for_verify(constants):
    finite_constants(constants)
    plan_constants(constants)
    states = ('BASE_NULL', 'SUBJECT_FRAME', 'SUBJECT_INDEX', 'SUBJECT_OFFSETS', 'SCOPE_READY',
              'CANDIDATE_HASH', 'CANDIDATE_INPUT_HASH', 'ORIGINAL_HASH', 'OUTCOME')
    spans = ('VALIDATION', 'BASE', 'SUBJECT', 'CONTEXT_ID', 'CANDIDATE_SHA', 'CANDIDATE',
             'CANDIDATE_INPUT_SHA', 'ORIGINAL_SHA', 'SUBJECT_REQUEST', 'SCOPE', 'ARGUMENTS')
    stages = ('CONTEXT', 'VALIDATION', 'CANDIDATE', 'BASE', 'BACKEND', 'SUBJECT_PROFILE')
    constants.update({f'VERIFY_{name}': 1300 + index for index, name in enumerate(states)})
    constants.update({f'VERIFY_{name}': 10512 + 24 * index for index, name in enumerate(spans)})
    constants.update({f'VERIFY_STAGE_{name}': 20 + index for index, name in enumerate(stages)})
    constants.update(VERIFY_REPLAY_ARGUMENTS=1310, VERIFY_REPLAY_PACKET_READY=1311, VERIFY_REPLAY_INDEXED=1312,
                     VERIFY_REPLAY_COMPARED=1313, VERIFY_REPLAY_CLOCK=1314,
                     VERIFY_REPLAY_PACKET=11384, VERIFY_REPLAY_EXPECTED=11408,
                     VERIFY_REPLAYING=11432, VERIFY_REPLAY_FROZEN_LIMIT=11440, VERIFY_REPLAY_ROLE=75,
                     MAX_CLOCK=(1 << 64) - 1, VERIFY_REPLAY_TAG=int.from_bytes(b'HIAVRP03', 'little'))
    constants.update(VERIFY_SUBJECT_REFS=10776, VERIFY_CLAIM_ORDINALS=10848, VERIFY_CLAIM_COUNT=10880,
                     VERIFY_SUBJECT_KIND=10888, VERIFY_OUTCOME_BYTES=10896,
                     VERIFY_CLAIM_INDEX=10904, VERIFY_DIRECT_MODE=10912, VERIFY_EVIDENCE_SPANS=10920,
                     VERIFY_HASH_PAIR=1340, VERIFY_HASH_COMPARE=1341, VERIFY_CHECK_RESULT=1342,
                     VERIFY_FINDINGS_START=1360, VERIFY_RESULT_READY=1371, VERIFY_RESULT=11256,
                     VERIFY_NOMINAL_IMAGE=11016, VERIFY_OBSERVER_IMAGE=11040,
                     VERIFY_NEEDS_TERMINAL=0xffffffe1,
                     VERIFY_REQUEST_ROLE=70, VERIFY_NEEDS_FINDINGS=0xffffffe5,
                     VERIFY_NEEDS_SUBJECT_CUSTODY=0xffffffe4,
                     VERIFY_NEEDS_FINITE=0xffffffe2,
                     ROLE_COUNT=76, ENTRY_BYTES=64 + 312 + 76 * 40,
                     EMIT_WORK_BYTES=12288, SCHEMA_TOOL=7)
    constants.update({name: int.from_bytes(tag, 'little') for name, tag in {
        'VERIFY_REQUEST_TAG': b'HIAVRQ01', 'VERIFY_INDEX': b'HIAVRI01',
        'VERIFY_INDEX_TAG': b'HIAVRI02', 'VERIFY_SUBJECT_TAG': b'HIAVSB01', 'VERIFY_SCOPE_TAG': b'HIAVSC01',
    }.items()})


def recipe():
    constants, driver, controls = native_recipe()
    constants_for_verify(constants)
    driver = driver.replace('def emit_flow(', 'def verify_flow(')
    driver = driver.replace(
        '    if state == 0:\n        return artifact_entry(s, o, w)',
        '    if state == 0:\n        return artifact_entry(s, o, w)\n'
        '    if state == VERIFY_FINITE_DELIVERED:\n        return verify_observed(o, w)\n'
        '    if state == VERIFY_PLAN_ADMITTED:\n        return verify_scope_input(o, w)\n'
        '    if state == VERIFY_PLAN_INVALID:\n        if get(w, VERIFY_REPLAYING) != 0:\n            return BAD\n'
        '        return emit_admission_error(o, w, 8, 5)\n'
        '    if state == VERIFY_RESULT_READY:\n'
        '        return verify_complete(o, w)',
    )
    driver = driver.replace(
        '    if state >= INSPECTION_SENT and state <= INSPECTION_PEER_CLOSED:\n'
        '        return emit_peer_observation(s, o, w, state)\n', '',
    ).replace(
        '    if state >= EMIT_PROJECTED and state <= EMIT_PEER_OPENED:\n'
        '        return emit_prepare(s, o, w, state)',
        '    if state >= EMIT_PROJECTED and state <= EMIT_INDEX_FRAME:\n'
        '        return verify_ingress(s, o, w, state)',
    ).replace(
        '    return emit_dispatch(w, state)',
        '    if state == INSPECTION_HASH_RETURNED:\n'
        '        if extent < 88 or extent > 105:\n'
        '            return BAD\n'
        '        return read_span(o, w, INSPECTION_HASH_FRAME, input_word(s, 32), 0, extent)\n'
        '    if state == INSPECTION_HASH_FRAME:\n'
        '        return inspection_hash_result(s, o, w)\n'
        '    if state >= VERIFY_BASE_NULL and state <= VERIFY_SCOPE_READY:\n'
        '        return verify_subject_reply(s, o, w, state)\n'
        '    if state == VERIFY_OUTCOME:\n'
        '        return verify_outcome_state(s, o, w, state)\n'
        '    if state >= VERIFY_REPLAY_ARGUMENTS and state <= VERIFY_REPLAY_CLOCK:\n'
        '        return verify_replay_reply(s, o, w, state)\n'
        '    if state >= VERIFY_HASH_PAIR and state <= VERIFY_CHECK_RESULT:\n'
        '        return verify_check_reply(s, o, w, state)\n'
        '    return BAD',
    )
    journal_plan = function(driver, 'inspection_journal_plan').replace('INSPECTION_REQUEST_ROLE', 'VERIFY_REQUEST_ROLE')
    driver = replace_function(driver, 'inspection_journal_plan', journal_plan)
    controls = '\n'.join(part for part in controls if part not in (REQUEST, REACTOR, DISPATCH))
    controls = replace_function(controls, 'inspection_feedback', '')
    controls = controls.replace('return inspection_feedback(o, w, 3, 0, 0)', 'return verify_validation(o, w)')
    controls = controls.replace('return inspection_feedback(o, w, 11, 0, EMIT_WALL_PERMIT)', 'return verify_behavior(o, w)')
    controls = controls.replace(
        '        if input_word(s, 80) != 0:\n            return emit_admission_error(o, w, 8, choose(launch, 4, 3))',
        '        if input_word(s, 80) != 0:\n'
        '            if launch:\n'
        '                return verify_direct_evidence(o, w, 9)\n'
        '            if get(w, VERIFY_REPLAYING) != 0:\n'
        '                return verify_validation(o, w)\n'
        '            return emit_admission_error(o, w, 8, 3)',
    )
    controls = controls.replace('return inspection_feedback(o, w, 5, 0, 0)', 'return verify_core_admitted(o, w)')
    controls = controls.replace('    if stage == 2:\n        return inspection_feedback(o, w, 2, 0, EMIT_FIELDS + 24)',
                                '    if stage == VERIFY_STAGE_CONTEXT:\n        return verify_context(o, w)')
    controls = controls.replace('return inspection_feedback(o, w, get(w, EMIT_STAGE), 0, 0)', 'return verify_after_profile(o, w)')
    controls = controls.replace('return inspection_feedback(o, w, get(w, EMIT_STAGE), 1, EMIT_PUBLIC_ERROR)',
                                'return verify_outcome(o, w, 2, EMIT_PUBLIC_ERROR)')
    controls = controls.replace(
        '    if reason >= READ_EMIT_PLAN:\n'
        '        return EMIT_DEFER_PROOF\n',
        '    if reason == READ_EMIT_PLAN:\n'
        '        return VERIFY_NEEDS_FINITE\n'
        '    if reason > READ_EMIT_PLAN:\n'
        '        return BAD\n',
    )
    controls = controls.replace(
        '    if reason == READ_EMIT_PROFILE and (get(w, EMIT_STAGE) == 6 or get(w, EMIT_STAGE) == 9):\n'
        '        return emit_proof_profile_finished(o, w)\n', '',
    )
    controls = controls.replace(
        '    object = entry + DESCRIPTOR_BYTES * INSPECTION_EMIT_ROLE',
        '    nominal = entry + DESCRIPTOR_BYTES * NOMINAL_ROLE\n'
        '    observer = entry + DESCRIPTOR_BYTES * VERIFY_FINITE_EVIDENCE_ROLE\n'
        '    hold(w, VERIFY_NOMINAL_IMAGE, input_word(s, nominal), 0, input_word(s, nominal + 24))\n'
        '    hold(w, VERIFY_OBSERVER_IMAGE, input_word(s, observer), 0, input_word(s, observer + 24))\n'
        '    object = entry + DESCRIPTOR_BYTES * INSPECTION_EMIT_ROLE',
    )
    controls = controls.replace('return next == 19', 'return (next == 19 or next == 21) and status == 0')
    controls = controls.replace('    if next == 19:\n        return send_report(o, w, True)',
                                '    if next == 21:\n        return verify_cached(o, w)\n'
                                '    if next == 19:\n        return send_report(o, w, True)')
    controls = controls.replace(
        '    put(w, EFFECT_STATUS, status)\n    put(w, EFFECT_AT, at)',
        '    if get(w, VERIFY_REPLAYING) != 0:\n        return BAD\n'
        '    put(w, EFFECT_STATUS, status)\n    put(w, EFFECT_AT, at)',
    )
    scope = splice_list('verify_scope_values', 'VERIFY_SCOPE_READY',
                        ('VERIFY_ARGUMENTS', 'INSPECTION_PROFILE_2', 'VERIFY_CANDIDATE_SHA', 'VERIFY_ORIGINAL_SHA'),
                        role='VERIFY_REQUEST_ROLE')
    support = '\n'.join(function(VIEW_DRIVER, name) for name in ('inspection_hash', 'inspection_hash_result'))
    outcome = '\n'.join(function(OUTCOME, name) for name in ('adopt_outcome', 'adopt_outcome_state'))
    outcome = outcome.replace('adopt_outcome', 'verify_outcome').replace('ADOPT_CONTEXT_ID', 'VERIFY_CONTEXT_ID')
    outcome = outcome.replace('ADOPT_OUTCOME', 'VERIFY_OUTCOME').replace('extent > 8192', 'extent > 1048576')
    outcome = outcome.replace(
        '    if state == ADOPT_ERROR_BODY:\n'
        '        sample_span(s, w, EMIT_PUBLIC_ERROR)\n'
        '        return verify_outcome(o, w, 2, EMIT_PUBLIC_ERROR)\n', '')
    trust = function(DISPATCH, 'emit_trust_spans')
    read_plan = function(PLAN, 'emit_proof_read')
    wide_make = function(MEASUREMENT, 'emit_wide_make')
    policy = '\n'.join((driver, controls, INGRESS, CUSTODY, SUBJECT, SUBJECT_INDEX, CHECKS, REPLAY,
                        scope, support, outcome, trust, wide_make, read_plan))
    entry, parts = reachable_policy(policy, 'verify_flow')
    return constants, entry, parts


def program():
    constants, entry, parts = recipe()
    return flow_source(entry, parts, constants)


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)), encoding='utf-8')
