"""Author the retained Emit proof continuation and explicit plan handoff."""

from tools import generate_hia_worker_inspection_flow as worker
from tools.generate_hia_exec_release import POLICY_SOURCE as release_policy
from tools.generate_hia_worker_context_effect import POLICY as context_effect
from tools.generate_hia_worker_context_flow import function
from tools.generate_hia_worker_emit_composition import COMPOSITION, composition_constants
from tools.generate_hia_worker_emit_complete_replay import complete_replay_constants, complete_replay_source
from tools.generate_hia_worker_emit_custody_replay import custody_replay_constants, custody_replay_source
from tools.generate_hia_worker_emit_finite_replay import finite_replay_constants, finite_replay_source
from tools.generate_hia_worker_emit_layout_replay import layout_replay_constants, layout_replay_source
from tools.generate_hia_worker_emit_machine_replay import machine_replay_constants, machine_replay_source
from tools.generate_hia_worker_emit_measurement import splice_list
from tools.generate_hia_worker_emit_product import producer_controls
from tools.generate_hia_worker_emit_record import RECORD


PLAN = r'''
def emit_plan_reference(o:mutbuf, w:mutbuf) -> u64:
    if get(w, EMIT_CODEGEN_KIND) != 2:
        return BAD
    slot = EMIT_FIELDS + 24 * (6 + get(w, EMIT_RECEIPT_COUNT))
    move_fragment(w, slot, INSPECTION_REFERENCE)
    return emit_proof_read(o, w, READ_EMIT_PLAN, 0)

def emit_proof_read(o:mutbuf, w:mutbuf, purpose:u64, kind:u64) -> u64:
    put(w, RETAINED_PURPOSE, purpose)
    put(w, RETAINED_KIND, kind)
    put(o, HEADER, choose(kind == 0, RETAINED_QUERY_ANY, RETAINED_QUERY_KIND))
    put(o, HEADER + 8, kind)
    use_span(w, o, INSPECTION_REFERENCE, 0)
    return action(o, w, RETAINED_QUERY_BOUND, RUN, PROFILE_ROLE, 0, 1, 16)

def emit_plan_reopened(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    sample_span(s, w, EMIT_RAW_PLAN)
    put(o, HEADER, get(w, 24))
    use_span(w, o, EMIT_RAW_PLAN, 0)
    return action(o, w, EMIT_PLAN_CANONICAL, RUN, EMIT_CANONICAL_ROLE, 0, 1, 8)

def emit_plan_bind(o:mutbuf, w:mutbuf) -> u64:
    size = get(w, EMIT_APPROVED_PLAN + 16)
    if size != 144 and size != 16:
        return BAD
    return read_span(o, w, EMIT_PLAN_APPROVAL, get(w, EMIT_APPROVED_PLAN), get(w, EMIT_APPROVED_PLAN + 8), size)

def emit_plan_check(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    size = length(s)
    tag = input_word(s, 64)
    if size == 80 and tag == EMIT_SCOPE_RESULT and input_word(s, 72) == 3:
        return emit_admission_error(o, w, 8, 5)
    if size != 208 or (tag != EMIT_PLAN_STANDARD and tag != EMIT_PLAN_REGISTER) or input_word(s, 72) != 0:
        return BAD
    i = 0
    while i < 128:
        if byte(s, 80 + i) != byte(w, EMIT_PROOF_DIGESTS + i):
            return BAD
        i = i + 1
    put(w, EMIT_PLAN_FLAVOR, tag)
    body = EMIT_CANONICAL_PLAN
    # Register plans are realized by the installed compiler from the exact
    # canonical JSON following the same sealed receipt prefix.
    if tag == EMIT_PLAN_REGISTER:
        use_span(w, o, body, 0)
        return action(o, w, EMIT_PLAN_REGISTER_LAYOUT, MAKE, 0, 0, 1, 0)
    return inspection_hash(o, w, EMIT_PLAN_CORE_HASH, INSPECTION_CORE)

def emit_plan_state(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    fd = input_word(s, 32)
    size = input_word(s, 40)
    if state == EMIT_PLAN_CANONICAL:
        if plan_ok(s) == False or size < 10:
            return BAD
        body_span(s, w, EMIT_CANONICAL_PLAN)
        return inspection_hash(o, w, EMIT_PLAN_RAW_HASH, EMIT_RAW_PLAN)
    if state == EMIT_PLAN_APPROVAL:
        return emit_plan_check(s, o, w)
    if state == EMIT_PLAN_LAYOUT_BOUND:
        version = emit_schedule_version(s)
        registers = get(w, EMIT_PLAN_FLAVOR) == EMIT_PLAN_REGISTER
        if version == 0 or registers != (version == 4):
            return BAD
        put(w, EMIT_LAYOUT_FORMAT, version)
        fragment(o, 0, fd, 8, size - 8)
        return action(o, w, EMIT_PLAN_LAYOUT_SEALED, MAKE, 0, 0, 1, 0)
    if state == EMIT_PLAN_LAYOUT_SEALED:
        if size < 40:
            return BAD
        sample_span(s, w, EMIT_LAYOUT)
        use_span(w, o, EMIT_APPROVED_PLAN, 0)
        source = choose(get(w, EMIT_LAYOUT_FORMAT) == 4, EMIT_REGISTER_JSON, EMIT_LAYOUT)
        use_span(w, o, source, 1)
        return action(o, w, EMIT_PLAN_PERMIT, MAKE, 0, 0, 2, 0)
    if state == EMIT_PLAN_PERMIT:
        if size < 146:
            return BAD
        sample_span(s, w, EMIT_LAYOUT_PERMIT)
        return inspection_feedback(o, w, 10, 0, EMIT_APPROVED_PLAN)
    if state == EMIT_PLAN_REGISTER_LAYOUT and size > 1:
        sample_span(s, w, EMIT_REGISTER_JSON)
        return inspection_hash(o, w, EMIT_PLAN_CORE_HASH, INSPECTION_CORE)
    return BAD

def emit_schedule_version(s:readbuf) -> u64:
    size = input_word(s, 40)
    if plan_ok(s) == False or size < 48:
        return 0
    format = input_word(s, 72)
    version = (format >> 56) - (EMIT_LAYOUT_V1 >> 56) + 1
    if (version < 1 or version > 4
            or (format & 72057594037927935) != (EMIT_LAYOUT_V1 & 72057594037927935)):
        return 0
    if input_word(s, 80) == 0 or input_word(s, 88) != size - 8:
        return 0
    return version

def emit_hash_capture(s:readbuf, o:mutbuf, w:mutbuf, at:u64) -> u64:
    state = get(w, INSPECTION_HASH_RESUME)
    fd = input_word(s, 32)
    if state == EMIT_PLAN_RAW_HASH:
        hold(w, EMIT_PHYSICAL_PLAN_SHA, fd, at - 65, 66)
        copy_span(s, w, at, EMIT_PROOF_DIGESTS, 64)
        return inspection_hash(o, w, EMIT_PLAN_CANONICAL_HASH, EMIT_CANONICAL_PLAN)
    if state == EMIT_PLAN_CANONICAL_HASH:
        hold(w, EMIT_CANONICAL_PLAN_SHA, fd, at - 65, 66)
        copy_span(s, w, at, EMIT_PROOF_DIGESTS + 64, 64)
        hold(w, EMIT_RAW_PLAN_RESULT, get(w, EMIT_PHYSICAL_PLAN_SHA), get(w, EMIT_PHYSICAL_PLAN_SHA + 8) + 1, 64)
        return inspection_feedback(o, w, 8, 0, EMIT_RAW_PLAN_RESULT)
    if state == EMIT_PLAN_CORE_HASH:
        hold(w, EMIT_PLAN_CORE_SHA, fd, at - 65, 66)
        return emit_layout_request(o, w)
    if state == EMIT_REPLAY_OBJECT_HASH:
        return emit_replay_object_hash(s, o, w, at)
    if state >= EMIT_CUSTODY_RAW_HASH and state <= EMIT_CUSTODY_OBJECT_HASH:
        return emit_custody_hash(s, o, w, at, state)
    if state == EMIT_COMPLETE_HASH:
        return emit_complete_transcript_hash(s, o, w, at)
    if state == EMIT_MACHINE_IMAGE_HASH:
        hold(w, EMIT_MACHINE_PIN, fd, at - 65, 66)
        return emit_machine_native_evidence(o, w)
    return emit_retained_proof_hash(s, o, w, at, state)
'''


RETAINED = r'''
def emit_retained_proof(o:mutbuf, w:mutbuf, stage:u64, ordinal:u64) -> u64:
    count = get(w, EMIT_RECEIPT_COUNT)
    if stage == 6 and ordinal < count:
        move_fragment(w, EMIT_FIELDS + 24 * (4 + ordinal), INSPECTION_REFERENCE)
        put(w, EMIT_PROOF_PLANNED, 0)
    elif stage == 9 and ordinal == 0 and get(w, EMIT_CODEGEN_KIND) == 2:
        move_fragment(w, EMIT_FIELDS + 24 * (7 + count), INSPECTION_REFERENCE)
        put(w, EMIT_PROOF_PLANNED, 1)
    else:
        return BAD
    return emit_proof_read(o, w, READ_EMIT_PROOF, 8)

def emit_proof_reopened(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    purpose = get(w, RETAINED_PURPOSE)
    if purpose == READ_EMIT_PROOF:
        sample_span(s, w, EMIT_PROOF_RECORD)
        return emit_proof_profiles(o, w)
    if purpose == READ_EMIT_BASE:
        fragment(o, 0, input_word(s, 32), 0, input_word(s, 40))
        return action(o, w, EMIT_PROOF_BASE_ADMITTED, RUN, NOMINAL_ROLE, 0, 1, 0)
    return emit_proof_files_reopened(s, o, w, purpose)

def emit_retained_proof_state(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    fd = input_word(s, 32)
    size = input_word(s, 40)
    if state == EMIT_PROOF_PROFILES and size > 8:
        sample_span(s, w, EMIT_PROOF_PROFILE_BUNDLE)
        return emit_proof_identity(o, w)
    if state == EMIT_PROOF_IDENTITY and size > 16:
        sample_span(s, w, EMIT_PROOF_FRAME)
        use_span(w, o, EMIT_PROOF_FRAME, 0)
        return action(o, w, EMIT_PROOF_RECEIPT_BOUND, RUN, EMIT_VERIFY_ROLE, 0, 1, 0)
    if state == EMIT_PROOF_RECEIPT_BOUND:
        if (plan_ok(s) == False or (size != 128 and size != 304 and size != 480)
                or input_word(s, 72) != EMIT_SCOPE_RESULT or input_word(s, 80) != 0):
            return BAD
        return read_span(o, w, EMIT_PROOF_RECEIPT_MAP, fd, 8, size - 8)
    if state == EMIT_PROOF_RECEIPT_MAP:
        return emit_proof_anchor_plan(s, o, w)
    if state == EMIT_PROOF_BASE_ADMITTED:
        if (size < 64 or length(s) != 128 or input_word(s, 64) != NOMINAL_PACKET
                or input_word(s, 72) != 0 or input_word(s, 80) != 0 or input_word(s, 88) > 4
                or input_word(s, 112) != 0 or input_word(s, 120) != 0):
            return BAD
        types = input_word(s, 96)
        bytes = input_word(s, 104)
        if types == 0 or bytes == 0 or types > size - 64 or bytes != size - 64 - types:
            return BAD
        hold(w, EMIT_PROOF_BASE_CORE, fd, 64 + types, bytes)
        return inspection_hash(o, w, EMIT_PROOF_BASE_HASH, EMIT_PROOF_BASE_CORE)
    if state == EMIT_PROOF_NULL_CHECK:
        if length(s) != 72 or input_word(s, 64) != EMIT_PROOF_NULL_PAIR:
            return BAD
        return inspection_hash(o, w, EMIT_PROOF_CANDIDATE_HASH, INSPECTION_CORE)
    if state == EMIT_PROOF_CORE_MATCHED:
        if plan_ok(s) == False or size != 24 or input_word(s, 72) != EMIT_COMPARE_RESULT or input_word(s, 80) != 1:
            return BAD
        if get(w, EMIT_PROOF_ANCHOR) == EMIT_PROOF_BASE_HASH:
            return inspection_hash(o, w, EMIT_PROOF_CANDIDATE_HASH, INSPECTION_CORE)
        return emit_proof_open_subject(o, w)
    return emit_proof_file_state(s, o, w, state)

def emit_proof_anchor_plan(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if input_word(s, 64) != EMIT_SCOPE_RESULT or input_word(s, 72) != 0:
        return BAD
    kind = input_word(s, 176)
    bytes = length(s) - 64
    if kind < 1 or kind > 4 or (get(w, EMIT_PROOF_PLANNED) != 0 and kind != 3):
        return BAD
    if bytes != choose(kind == 4, 472, choose(kind == 3, 296, 120)):
        return BAD
    put(w, EMIT_PROOF_SUBJECT, kind)
    hold(w, EMIT_PROOF_BOUND, input_word(s, 32), 8, bytes)
    source = get(w, EMIT_PROOF_FRAME)
    extent = get(w, EMIT_PROOF_FRAME + 16)
    i = 0
    while i < 4:
        at = input_word(s, 80 + i * 16)
        size = input_word(s, 88 + i * 16)
        if at > extent or size > extent - at or size < 4:
            return BAD
        hold(w, EMIT_PROOF_ANCHORS + 24 * i, source, at, size)
        i = i + 1
    base = EMIT_PROOF_ANCHORS + 48
    digest = get(w, base + 40)
    if get(w, EMIT_PROOF_ANCHORS + 40) != 66 or (digest != 4 and digest != 66):
        return BAD
    if get(w, base + 16) == 4:
        if digest != 4:
            return BAD
        # The value projector determines the locations; confirm both
        # retained slices are the exact JSON null before skipping base reads.
        use_span(w, o, base, 0)
        use_span(w, o, base + 24, 1)
        return action(o, w, EMIT_PROOF_NULL_CHECK, MAKE, 0, 0, 2, 0)
    if digest != 66:
        return BAD
    move_fragment(w, base, INSPECTION_REFERENCE)
    return emit_proof_read(o, w, READ_EMIT_BASE, 0)

def emit_retained_proof_hash(s:readbuf, o:mutbuf, w:mutbuf, at:u64, state:u64) -> u64:
    base = state == EMIT_PROOF_BASE_HASH
    if base == False and state != EMIT_PROOF_CANDIDATE_HASH:
        return emit_proof_subject_hash(s, o, w, at, state)
    put(w, EMIT_PROOF_ANCHOR, state)
    if base == False:
        hold(w, EMIT_PROOF_CANDIDATE_SHA, input_word(s, 32), at - 65, 66)
    put(o, HEADER, EMIT_COMPARE_REQUEST)
    put(o, HEADER + 8, 66)
    put(o, HEADER + 16, 66)
    expected = EMIT_PROOF_ANCHORS + choose(base, 72, 24)
    use_span(w, o, expected, 0)
    fragment(o, 1, input_word(s, 32), at - 65, 66)
    return action(o, w, EMIT_PROOF_CORE_MATCHED, RUN, EMIT_NATIVE_ARTIFACT_ROLE, 0, 2, 24)
'''


FILES = r'''
def emit_proof_open_subject(o:mutbuf, w:mutbuf) -> u64:
    subject = get(w, EMIT_PROOF_SUBJECT)
    if subject == 2 or subject == 3:
        index = subject + 1
        put(w, EMIT_PROOF_PROFILE_PHASE, 3)
        return emit_open_profile(o, w, index, EMIT_PROFILES + 48 * index)
    return emit_proof_subject_ready(o, w)

def emit_proof_subject_ready(o:mutbuf, w:mutbuf) -> u64:
    subject = get(w, EMIT_PROOF_SUBJECT)
    if subject == 1 or subject == 2:
        return emit_proof_open_claims(o, w)
    if subject == 3:
        source = EMIT_PROOF_BOUND
        hold(w, INSPECTION_REFERENCE, get(w, source), get(w, source + 8) + 120, 176)
        return emit_proof_read(o, w, READ_EMIT_SUBJECT_PLAN, 0)
    return emit_proof_open_custody(o, w)

def emit_proof_open_claims(o:mutbuf, w:mutbuf) -> u64:
    store(o, HEADER, 91)
    store(o, 480, 93)
    use_span(w, o, EMIT_PROOF_RECORD, 0)
    fragment(o, 1, INLINE_FRAGMENT, 480, 1)
    return action(o, w, EMIT_PROOF_CLAIMS_BOUND, RUN, EMIT_VERIFY_ROLE, 0, 2, 1)

def emit_proof_files_reopened(s:readbuf, o:mutbuf, w:mutbuf, purpose:u64) -> u64:
    if purpose == READ_EMIT_ASSUMPTIONS:
        sample_span(s, w, EMIT_PROOF_ASSUMPTIONS)
        move_fragment(w, EMIT_PROOF_EVIDENCE_REF, INSPECTION_REFERENCE)
        return emit_proof_read(o, w, READ_EMIT_EVIDENCE, 10)
    if purpose == READ_EMIT_EVIDENCE:
        sample_span(s, w, EMIT_PROOF_EVIDENCE)
        store(o, HEADER, 48 + get(w, EMIT_PROOF_INDEX))
        return action(o, w, EMIT_PROOF_ORDINAL, MAKE, 0, 0, 0, 1)
    if purpose == READ_EMIT_SUBJECT_PLAN:
        sample_span(s, w, EMIT_PROOF_SUBJECT_RAW)
        put(o, HEADER, get(w, 24))
        use_span(w, o, EMIT_PROOF_SUBJECT_RAW, 0)
        return action(o, w, EMIT_PROOF_SUBJECT_CANONICAL, RUN, EMIT_CANONICAL_ROLE, 0, 1, 8)
    if purpose == READ_EMIT_MACHINE_QUERY:
        return emit_machine_query_reopened(s, o, w)
    if purpose == READ_EMIT_MACHINE_CERTIFICATE:
        size = input_word(s, 40)
        if size < EMIT_MACHINE_PROVER_HEAD or size > EMIT_MACHINE_PROVER_MAX:
            return BAD
        sample_span(s, w, EMIT_MACHINE_CERTIFICATE)
        return clock_sample(o, w, EMIT_MACHINE_CLOCK, 1)
    return emit_proof_custody_reopened(s, o, w, purpose)

def emit_proof_file_state(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    fd = input_word(s, 32)
    size = input_word(s, 40)
    if state == EMIT_PROOF_SUBJECT_CANONICAL:
        if plan_ok(s) == False or size < 10:
            return BAD
        body_span(s, w, EMIT_PROOF_SUBJECT_PLAN)
        return inspection_hash(o, w, EMIT_PROOF_SUBJECT_RAW_HASH, EMIT_PROOF_SUBJECT_RAW)
    if state == EMIT_PROOF_CLAIMS_BOUND:
        count = input_word(s, 80)
        if (plan_ok(s) == False or input_word(s, 72) != EMIT_SCOPE_FILES
                or count < 1 or count > 4 or size != 24 + 360 * count):
            return BAD
        body_span(s, w, EMIT_PROOF_CLAIMS)
        put(w, EMIT_PROOF_COUNT, count)
        put(w, EMIT_PROOF_INDEX, 0)
        zero_range(w, EMIT_PROOF_VERDICTS, 192)
        return emit_proof_next_claim(o, w)
    if state == EMIT_PROOF_CLAIM:
        return emit_proof_claim_references(s, o, w)
    if state == EMIT_PROOF_ORDINAL and size == 1:
        sample_span(s, w, EMIT_PROOF_ORDINAL_SPAN)
        if get(w, EMIT_PROOF_TRUST_SELECTION + 16) != 66 or get(w, EMIT_PROOF_TRUST_RUNTIME + 16) < 2:
            return BAD
        if get(w, EMIT_PROOF_SUBJECT) == 4 and get(w, EMIT_PROOF_CLAIM_KIND) == 4:
            CHECK_ENCODING_REPORT
        return emit_proof_scope_request(o, w)
    if state == EMIT_PROOF_SCOPE_BOUND:
        if (plan_ok(s) == False or size != 56 or input_word(s, 72) != EMIT_SCOPE_PERMISSION
                or input_word(s, 80) != 0 or input_word(s, 96) != get(w, EMIT_PROOF_CLAIM_KIND)):
            return BAD
        put(o, HEADER, EMIT_SCOPE_EFFECT_REQUEST)
        put(o, HEADER + 8, get(w, EMIT_PROOF_SUBJECT))
        put(o, HEADER + 16, get(w, EMIT_PROOF_CLAIM_KIND))
        fragment(o, 0, fd, 8, 48)
        return action(o, w, EMIT_PROOF_EFFECT_BOUND, RUN, EMIT_VERIFY_ROLE, 0, 1, 24)
    if state == EMIT_PROOF_EFFECT_BOUND:
        operation = input_word(s, 88)
        if (plan_ok(s) == False or size != 32 or input_word(s, 72) != EMIT_SCOPE_EFFECT
                or input_word(s, 80) != 0 or operation < 1 or operation > 8):
            return BAD
        verdict = EMIT_PROOF_VERDICTS + 48 * get(w, EMIT_PROOF_INDEX)
        copy_span(s, w, 72, verdict, 24)
        if operation == 1:
            return emit_proof_record_local(o, w)
        if operation == 2:
            return emit_replay_layout(o, w)
        if operation == 3:
            return emit_custody_effect(o, w)
        if operation == 5 or operation == 8:
            return emit_machine_proof(o, w, operation == 8)
        if operation == 6:
            return emit_finite_counterexample(o, w)
        if operation == 7:
            return emit_complete_domain(o, w)
        return emit_composition(o, w)
    if state == EMIT_PROOF_FINISHED:
        return emit_proof_finished(s, o, w)
    if state == EMIT_PROOF_RENDERED_SUBJECT:
        if plan_ok(s) == False or size < 10:
            return BAD
        body_span(s, w, EMIT_PROOF_REQUESTED_SUBJECT)
        return emit_proof_approve_plan(o, w)
    if state == EMIT_PROOF_QUALIFIED_PLAN:
        tag = input_word(s, 72)
        if plan_ok(s) == False:
            return BAD
        if tag == EMIT_SCOPE_RESULT:
            if size != 24 or input_word(s, 80) != 3:
                return BAD
        elif size != 152 or (tag != EMIT_PLAN_STANDARD and tag != EMIT_PLAN_REGISTER) or input_word(s, 80) != 0:
            return BAD
        body_span(s, w, EMIT_APPROVED_PLAN)
        return inspection_feedback(o, w, 9, 0, EMIT_PROOF_TERMINAL)
    return emit_proof_custody_state(s, o, w, state)

def emit_proof_next_claim(o:mutbuf, w:mutbuf) -> u64:
    index = get(w, EMIT_PROOF_INDEX)
    if index >= get(w, EMIT_PROOF_COUNT):
        return emit_proof_finish_claims(o, w)
    offset = get(w, EMIT_PROOF_CLAIMS + 8) + 16 + 360 * index
    return read_span(o, w, EMIT_PROOF_CLAIM, get(w, EMIT_PROOF_CLAIMS), offset, 8)

def emit_proof_claim_references(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    claim = input_word(s, 64)
    if length(s) != 72 or claim < 1 or claim > 4:
        return BAD
    put(w, EMIT_PROOF_CLAIM_KIND, claim)
    fd = input_word(s, 32)
    offset = input_word(s, 48) + 8
    hold(w, EMIT_PROOF_ASSUMPTIONS_REF, fd, offset, 176)
    hold(w, EMIT_PROOF_EVIDENCE_REF, fd, offset + 176, 176)
    move_fragment(w, EMIT_PROOF_ASSUMPTIONS_REF, INSPECTION_REFERENCE)
    return emit_proof_read(o, w, READ_EMIT_ASSUMPTIONS, 9)

def emit_proof_subject_hash(s:readbuf, o:mutbuf, w:mutbuf, at:u64, state:u64) -> u64:
    fd = input_word(s, 32)
    if state == EMIT_PROOF_SUBJECT_RAW_HASH:
        hold(w, EMIT_PROOF_SUBJECT_RAW_SHA, fd, at - 65, 66)
        return inspection_hash(o, w, EMIT_PROOF_SUBJECT_CANONICAL_HASH, EMIT_PROOF_SUBJECT_PLAN)
    if state == EMIT_PROOF_SUBJECT_CANONICAL_HASH:
        hold(w, EMIT_PROOF_SUBJECT_CANONICAL_SHA, fd, at - 65, 66)
        return emit_proof_open_claims(o, w)
    return BAD

def emit_proof_record_local(o:mutbuf, w:mutbuf) -> u64:
    put(w, EMIT_PROOF_INDEX, get(w, EMIT_PROOF_INDEX) + 1)
    return emit_proof_next_claim(o, w)

def emit_proof_finish_claims(o:mutbuf, w:mutbuf) -> u64:
    count = get(w, EMIT_PROOF_COUNT)
    put(o, HEADER, EMIT_SCOPE_COMPLETE)
    put(o, HEADER + 8, get(w, EMIT_PROOF_PLANNED))
    put(o, HEADER + 16, count)
    copy_private(w, o, EMIT_PROOF_VERDICTS, HEADER + 24, count * 48)
    return action(o, w, EMIT_PROOF_FINISHED, RUN, EMIT_VERIFY_ROLE, 0, 0, 24 + count * 48)

def emit_proof_finished(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if plan_ok(s) == False or input_word(s, 40) != 24:
        return BAD
    if get(w, EMIT_PROOF_PLANNED) == 0:
        if input_word(s, 72) != EMIT_SCOPE_RESULT or input_word(s, 80) != 0:
            return BAD
        body_span(s, w, EMIT_PROOF_TERMINAL)
        return FINISH_RETAINED_PROOF
    if input_word(s, 72) != EMIT_SCOPE_PLAN_COMPLETE or input_word(s, 80) != get(w, EMIT_PROOF_COUNT):
        return BAD
    body_span(s, w, EMIT_PROOF_TERMINAL)
    return emit_requested_plan_subject(o, w)

def emit_requested_plan_subject(o:mutbuf, w:mutbuf) -> u64:
    codegen_plan = EMIT_FIELDS + 24 * (5 + get(w, EMIT_RECEIPT_COUNT))
    put(o, HEADER, EMIT_RENDER_REQUEST)
    put(o, HEADER + 8, 7)
    put(o, 384, get(w, EMIT_FIELDS + 16))
    put(o, 392, get(w, codegen_plan + 24 + 16))
    put(o, 400, get(w, codegen_plan + 16))
    vector_part(o, HEADER + 16, INLINE_FRAGMENT, 384, 8)
    vector_span(w, o, EMIT_FIELDS, HEADER + 40)
    vector_part(o, HEADER + 64, INLINE_FRAGMENT, 392, 8)
    vector_span(w, o, codegen_plan + 24, HEADER + 88)
    vector_part(o, HEADER + 112, INLINE_FRAGMENT, 400, 8)
    vector_span(w, o, codegen_plan, HEADER + 136)
    return wide_inspection(o, w, EMIT_PROOF_RENDERED_SUBJECT, EMIT_RECEIPT_ROLE, 0, 6, 16)
'''


ENTRY = r'''
def emit_proof_flow(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    state = get(w, 0)
    if state == EMIT_ENCODING_REPORT_BOUND:
        if plan_ok(s) == False or input_word(s, 40) != 24 or input_word(s, 72) != EMIT_CUSTODY_PACKET or input_word(s, 80) != 0:
            return BAD
        return emit_proof_scope_request(o, w)
    if state == RETAINED_DIGEST:
        return emit_proof_typed_artifact(s, o, w)
    if state == INSPECTION_ACTION:
        stage = get(w, EMIT_STAGE)
        if stage == 8:
            return emit_plan_reference(o, w)
        if stage == 10:
            return emit_plan_bind(o, w)
        return emit_retained_proof(o, w, stage, get(w, EMIT_OPERAND))
    if state == RETAINED_BYTES:
        if input_word(s, 40) < 2:
            return BAD
        if get(w, RETAINED_PURPOSE) == READ_EMIT_PROFILE:
            if get(w, EMIT_PROOF_PROFILE_PHASE) == 2:
                return emit_retained_proof(o, w, get(w, EMIT_STAGE), get(w, EMIT_OPERAND))
            if get(w, EMIT_PROOF_PROFILE_PHASE) == 3:
                return emit_proof_subject_ready(o, w)
            return BAD
        if get(w, RETAINED_PURPOSE) == READ_EMIT_PLAN:
            return emit_plan_reopened(s, o, w)
        return emit_proof_reopened(s, o, w)
    if state == INSPECTION_HASH_RETURNED:
        size = input_word(s, 40)
        if size < 88 or size > 105:
            return BAD
        return read_span(o, w, INSPECTION_HASH_FRAME, input_word(s, 32), 0, size)
    if state == INSPECTION_HASH_FRAME:
        return inspection_hash_result(s, o, w)
    if state >= EMIT_PLAN_CANONICAL and state <= EMIT_PLAN_REGISTER_LAYOUT:
        return emit_plan_state(s, o, w, state)
    if state >= EMIT_REPLAY_LAYOUT and state <= EMIT_REPLAY_CHECKED:
        return emit_replay_layout_state(s, o, w, state)
    if state >= EMIT_FINITE_FRAME and state <= EMIT_FINITE_CHECKED:
        return emit_finite_replay_state(s, o, w, state)
    if state >= EMIT_COMPLETE_EXPECTATION and state <= EMIT_COMPLETE_CHECKED:
        return emit_complete_state(s, o, w, state)
    if (state >= EMIT_MACHINE_ANCHORED and state <= EMIT_MACHINE_CHECKED
            or state == EMIT_MACHINE_NATIVE_ANCHORED):
        return emit_machine_proof_state(s, o, w, state)
    if state >= COMP_MONOTONIC and state <= COMP_CHECKED:
        return composition_state(s, o, w, state)
    return emit_retained_proof_state(s, o, w, state)
'''


def proof_constants():
    names = ('CANONICAL', 'APPROVAL', 'LAYOUT_BOUND', 'LAYOUT_SEALED',
             'PERMIT', 'REGISTER_LAYOUT', 'RAW_HASH', 'CANONICAL_HASH', 'CORE_HASH')
    words = {
        'EMIT_PLAN_STANDARD': b'HIAEVQ02', 'EMIT_PLAN_REGISTER': b'HIAEVQ03',
        'EMIT_SCOPE_RESULT': b'HIAEVR01', 'EMIT_LAYOUT_V1': b'HIABLP01',
        'EMIT_SCOPE_FILES': b'HIAEVP01', 'EMIT_SCOPE_PERMISSION': b'HIAPSC01',
        'EMIT_SCOPE_EFFECT_REQUEST': b'HIAEVT01', 'EMIT_SCOPE_EFFECT': b'HIAEVH01',
        'EMIT_SCOPE_COMPLETE': b'HIAEVA01', 'EMIT_SCOPE_PLAN_COMPLETE': b'HIAPVR01',
    }
    bind_states = ('PROFILES', 'IDENTITY', 'RECEIPT_BOUND', 'RECEIPT_MAP', 'BASE_ADMITTED',
                   'CORE_MATCHED', 'BASE_HASH', 'CANDIDATE_HASH', 'NULL_CHECK', 'CLAIMS_BOUND',
                   'CLAIM', 'ORDINAL', 'SCOPE_BOUND', 'EFFECT_BOUND', 'FINISHED', 'SUBJECT_CANONICAL',
                   'SUBJECT_RAW_HASH', 'SUBJECT_CANONICAL_HASH', 'RENDERED_SUBJECT', 'QUALIFIED_PLAN')
    return {
        **custody_replay_constants(),
        **finite_replay_constants(),
        **complete_replay_constants(),
        **machine_replay_constants(), **composition_constants(),
        **layout_replay_constants(),
        **{f'EMIT_PLAN_{name}': 512 + i for i, name in enumerate(names)},
        **{f'EMIT_PROOF_{name}': 528 + i for i, name in enumerate(bind_states)},
        **{name: int.from_bytes(value, 'little') for name, value in words.items()},
        'EMIT_ENCODING_REPORT_BOUND': 767,
        'READ_EMIT_PLAN': 6, 'READ_EMIT_PROOF': 7, 'READ_EMIT_BASE': 8,
        'READ_EMIT_SUBJECT_PLAN': 9, 'READ_EMIT_ASSUMPTIONS': 10, 'READ_EMIT_EVIDENCE': 11,
        'EMIT_LAYOUT_ROLE': 46, 'EMIT_VERIFY_ROLE': 44, 'EMIT_SCOPE_ROLE': 45, 'EMIT_APPROVED_PLAN': 6616,
        'EMIT_RAW_PLAN': 6640, 'EMIT_RAW_PLAN_RESULT': 6664, 'EMIT_PLAN_CORE_SHA': 6688,
        'EMIT_PLAN_FLAVOR': 6712, 'EMIT_PROOF_DIGESTS': 6720, 'EMIT_REGISTER_JSON': 6848,
        'EMIT_PROOF_RECORD': 6872, 'EMIT_PROOF_FRAME': 6896, 'EMIT_PROOF_BOUND': 6920,
        'EMIT_PROOF_PROFILE_BUNDLE': 6944, 'EMIT_PROOF_BASE_CORE': 6968,
        'EMIT_PROOF_ANCHORS': 6992, 'EMIT_PROOF_ANCHOR': 7088,
        'EMIT_PROOF_PLANNED': 7096, 'EMIT_PROOF_SUBJECT': 7104,
        'EMIT_PROOF_COUNT': 7112, 'EMIT_PROOF_INDEX': 7120, 'EMIT_PROOF_CLAIM_KIND': 7128,
        'EMIT_PROOF_PROFILE_PHASE': 7136,
        'EMIT_PROOF_VERDICTS': 7648,
        'EMIT_PROOF_SUBJECT_RAW': 7840, 'EMIT_PROOF_SUBJECT_PLAN': 7864,
        'EMIT_PROOF_SUBJECT_RAW_SHA': 7888, 'EMIT_PROOF_SUBJECT_CANONICAL_SHA': 7912,
        'EMIT_PROOF_CLAIMS': 7936, 'EMIT_PROOF_ASSUMPTIONS_REF': 7960, 'EMIT_PROOF_EVIDENCE_REF': 7984,
        'EMIT_PROOF_ASSUMPTIONS': 8008, 'EMIT_PROOF_EVIDENCE': 8032, 'EMIT_PROOF_ORDINAL_SPAN': 8056,
        'EMIT_PROOF_TRUST_SELECTION': 8080, 'EMIT_PROOF_TRUST_RUNTIME': 8104, 'EMIT_PROOF_TERMINAL': 8128,
        'EMIT_PROOF_REQUESTED_SUBJECT': 8152,
        'EMIT_PROOF_CANDIDATE_SHA': 4896,
        'EMIT_PROOF_NULL_PAIR': int.from_bytes(b'nullnull', 'little'),
    }


def proof_recipe(shared_error, open_profile, *,
                 finish_retained='inspection_feedback(o, w, 6, 0, EMIT_PROOF_TERMINAL)'):
    _, controls = worker.recipe()
    names = ('get', 'put', 'input_word', 'write', 'action', 'issue', 'fragment', 'hold', 'body_span',
             'sample_span', 'use_span', 'read_span', 'copy_span', 'copy_private', 'is_hex', 'plan_ok',
             'artifact_command', 'argv', 'zero_range', 'vector_part', 'slot_fd', 'slot_bytes', 'clock_sample')
    required = {f'\ndef {name}(' for name in names}
    used = tuple(part for part in controls if part.split('(', 1)[0] + '(' in required)
    layout = splice_list('emit_layout_request', 'EMIT_PLAN_LAYOUT_BOUND',
                         ('INSPECTION_CORE', 'EMIT_PLAN_CORE_SHA', 'EMIT_CANONICAL_PLAN'), role='EMIT_LAYOUT_ROLE')
    profiles = splice_list('emit_proof_profiles', 'EMIT_PROOF_PROFILES',
                           ('EMIT_PROFILES + 48', 'EMIT_PROFILES + 144', 'EMIT_PROFILES + 192'))
    binding = splice_list('emit_proof_identity', 'EMIT_PROOF_IDENTITY',
                          ('EMIT_INSTALLATION', 'EMIT_FIELDS + 24', 'EMIT_FIELDS + 48',
                           'EMIT_PROFILES + 288', 'EMIT_PROOF_RECORD', 'EMIT_PROOF_PROFILE_BUNDLE'))
    scope = splice_list('emit_proof_scope_request', 'EMIT_PROOF_SCOPE_BOUND',
                        ('EMIT_PROOF_RECORD', 'EMIT_PROFILES + 240', 'EMIT_PROOF_ORDINAL_SPAN',
                         'EMIT_PROOF_ASSUMPTIONS_REF', 'EMIT_PROOF_ASSUMPTIONS', 'EMIT_PROOF_EVIDENCE_REF',
                         'EMIT_PROOF_EVIDENCE', 'EMIT_PROOF_TRUST_SELECTION', 'EMIT_PROOF_TRUST_RUNTIME',
                         ('EMIT_PROOF_TRUST_RUNTIME', 'EMIT_TRUST_NATIVE_OFFSET', 'EMIT_TRUST_NATIVE_BYTES')),
                        role='EMIT_SCOPE_ROLE')
    encoding = splice_list('emit_encoding_report', 'EMIT_ENCODING_REPORT_BOUND',
                           ('EMIT_CUSTODY_BUILD', 'EMIT_PROOF_EVIDENCE'), role='EMIT_CUSTODY_ROLE')
    approve = splice_list('emit_proof_approve_plan', 'EMIT_PROOF_QUALIFIED_PLAN',
                          ('EMIT_PROOF_REQUESTED_SUBJECT', 'EMIT_PROOF_RECORD', 'EMIT_PROOF_SUBJECT_RAW_SHA',
                           'EMIT_PROOF_SUBJECT_CANONICAL_SHA', 'EMIT_PROOF_SUBJECT_PLAN'), role='EMIT_VERIFY_ROLE')
    support = (
        function(worker.RETAINED_DRIVER, 'move_fragment'),
        function(worker.EFFECT_DRIVER, 'inspection_feedback'),
        function(worker.DOCUMENT_DRIVER, 'vector_span'),
        function(worker.DOCUMENT_DRIVER, 'wide_inspection'),
        function(worker.DOCUMENT_DRIVER, 'wide_inspection').replace(
            'def wide_inspection(o:mutbuf, w:mutbuf, state:u64, role:u64, args:u64, parts:u64, inline:u64)',
            'def emit_wide_make(o:mutbuf, w:mutbuf, state:u64, parts:u64, inline:u64)',
        ).replace('RUN, role, args, parts', 'MAKE, 0, 0, parts'),
        function(release_policy, 'decimal'),
        function(release_policy, 'divide10'),
        function(context_effect, 'quotient'),
        shared_error,
        open_profile,
    )
    # Emit already uses all 128 Selfhost-Core function slots. Keep the sealed
    # encoding/build comparison in the claim branch of the same function.
    encoding_body = encoding.strip().splitlines()[1:]
    files = FILES.replace('            CHECK_ENCODING_REPORT',
                          '\n'.join('        ' + line for line in encoding_body))
    files = files.replace('FINISH_RETAINED_PROOF', finish_retained)
    return ENTRY, (PLAN, RETAINED, files, layout, profiles, binding, scope, approve,
                   *layout_replay_source(), *custody_replay_source(function(RECORD, 'emit_signature')),
                   *finite_replay_source(), *complete_replay_source(), *machine_replay_source(), COMPOSITION,
                   *producer_controls(used), *support)
