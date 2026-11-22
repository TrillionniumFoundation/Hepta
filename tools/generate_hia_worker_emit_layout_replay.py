"""Author independent object and frame replay for a retained plan proof."""

from tools.generate_hia_worker_emit_measurement import splice_list


REPLAY = r'''
def emit_replay_layout(o:mutbuf, w:mutbuf) -> u64:
    if (get(w, EMIT_PROOF_SUBJECT) != 3 or get(w, EMIT_PROOF_SUBJECT_PLAN + 16) < 2
            or get(w, EMIT_PROOF_SUBJECT_RAW_SHA + 16) != 66):
        return BAD
    put(w, EMIT_REPLAY_PLANNED, 0)
    return emit_replay_schedule(o, w)

def emit_replay_layout_state(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    fd = input_word(s, 32)
    size = input_word(s, 40)
    if state == EMIT_REPLAY_LAYOUT:
        version = emit_schedule_version(s)
        if version == 0:
            return BAD
        put(w, EMIT_REPLAY_VERSION, version)
        fragment(o, 0, fd, 8, size - 8)
        return action(o, w, EMIT_REPLAY_SCHEDULE, MAKE, 0, 0, 1, 0)
    if state == EMIT_REPLAY_SCHEDULE:
        if size < 40:
            return BAD
        sample_span(s, w, EMIT_REPLAY_DESCRIPTOR)
        if get(w, EMIT_REPLAY_VERSION) == 4:
            return emit_replay_open_witness(o, w)
        return emit_replay_object(o, w)
    if state == EMIT_REPLAY_WITNESS:
        if plan_ok(s) == False or size != 40 or input_word(s, 72) != EMIT_REPLAY_WITNESS_TAG or input_word(s, 80) != 0:
            return BAD
        source = EMIT_PROOF_EVIDENCE
        extent = get(w, source + 16)
        at = input_word(s, 88)
        bytes = input_word(s, 96)
        # Projection used the array [evidence], adding one byte to offsets.
        if at < 1 or at > extent or bytes < 2 or bytes > extent - (at - 1):
            return BAD
        hold(w, EMIT_REPLAY_WITNESS_SPAN, get(w, source), get(w, source + 8) + at - 1, bytes)
        return emit_replay_check_witness(o, w)
    if state == EMIT_REPLAY_WITNESSED:
        version = input_word(s, 80)
        if (plan_ok(s) == False or size < 104 or input_word(s, 72) != EMIT_REPLAY_REGISTER_TAG
                or (version != 3 and version != 4) or input_word(s, 96) != size - 8):
            return BAD
        return emit_replay_object(o, w)
    if state == EMIT_REPLAY_PLAN_INPUT:
        if size != get(w, EMIT_PROOF_SUBJECT_PLAN + 16):
            return BAD
        sample_span(s, w, EMIT_REPLAY_REGISTER_PLAN)
        return emit_replay_object_request(o, w, True)
    if state == EMIT_REPLAY_OBJECT:
        if length(s) != 128 or size < 64 or (input_word(s, 64) & EMIT_IDENT_MASK) != EMIT_IDENT:
            return BAD
        if (input_word(s, 80) & 4294967295) != EMIT_ELF_OBJECT:
            return BAD
        sample_span(s, w, EMIT_REPLAY_OBJECT_SPAN)
        return inspection_hash(o, w, EMIT_REPLAY_OBJECT_HASH, EMIT_REPLAY_OBJECT_SPAN)
    if state == EMIT_REPLAY_GEOMETRY:
        return emit_replay_frame_control(s, o, w)
    if state == EMIT_REPLAY_FRAME_CONTROL:
        if size != 9480 or plan_ok(s) == False:
            return BAD
        fragment(o, 0, fd, 8, 9472)
        use_span(w, o, INSPECTION_CORE, 1)
        return action(o, w, EMIT_REPLAY_FRAMES, RUN, EMIT_FRAMES_ROLE, 0, 2, 0)
    if state == EMIT_REPLAY_FRAMES:
        if plan_ok(s) == False or size < 10:
            return BAD
        put(o, HEADER, get(w, 24))
        fragment(o, 0, fd, 8, size - 8)
        return action(o, w, EMIT_REPLAY_CANONICAL, RUN, EMIT_CANONICAL_ROLE, 0, 1, 8)
    if state == EMIT_REPLAY_CANONICAL:
        if plan_ok(s) == False or size < 10:
            return BAD
        if get(w, EMIT_REPLAY_PLANNED) == 0:
            body_span(s, w, EMIT_REPLAY_BASE_FRAMES)
            put(w, EMIT_REPLAY_PLANNED, 1)
            return emit_replay_object(o, w)
        body_span(s, w, EMIT_REPLAY_PLAN_FRAMES)
        if get(w, EMIT_REPLAY_VERSION) == 4:
            return emit_replay_register_verdict(o, w)
        return emit_replay_layout_verdict(o, w)
    if state == EMIT_REPLAY_CHECKED:
        if plan_ok(s) == False or size != 24 or input_word(s, 72) != EMIT_SCOPE_RESULT or input_word(s, 80) != 0:
            return BAD
        verdict = EMIT_PROOF_VERDICTS + 48 * get(w, EMIT_PROOF_INDEX) + 24
        copy_span(s, w, 72, verdict, 16)
        return emit_proof_record_local(o, w)
    return BAD

def emit_replay_object(o:mutbuf, w:mutbuf) -> u64:
    planned = get(w, EMIT_REPLAY_PLANNED) == 1
    registers = planned and get(w, EMIT_REPLAY_VERSION) == 4
    if registers:
        # The register ingress reads the complete sealed file, not a slice
        # in the canonicalizer's prefixed answer.
        use_span(w, o, EMIT_PROOF_SUBJECT_PLAN, 0)
        return action(o, w, EMIT_REPLAY_PLAN_INPUT, MAKE, 0, 0, 1, 0)
    return emit_replay_object_request(o, w, False)

def emit_replay_object_request(o:mutbuf, w:mutbuf, registers:bool) -> u64:
    args = 0
    if get(w, EMIT_REPLAY_PLANNED) == 1:
        selected = choose(registers, EMIT_REPLAY_REGISTER_PLAN, EMIT_REPLAY_DESCRIPTOR)
        put(o, 384, EMIT_LAYOUT_OPTION_0)
        put(o, 392, choose(registers, EMIT_REGISTER_OPTION_1, EMIT_LAYOUT_OPTION_1))
        put(o, 400, choose(registers, EMIT_REGISTER_OPTION_2, 0))
        argv(o, 0, LITERAL_ARG, 384)
        argv(o, 1, FD_ARG, get(w, selected))
        args = 2
    extent = get(w, INSPECTION_EXPORTS + 16)
    if extent < 2:
        return BAD
    if extent == 2:
        use_span(w, o, INSPECTION_CORE, 0)
        return action(o, w, EMIT_REPLAY_OBJECT, RUN, INSPECTION_EMIT_ROLE, args, 1, 0)
    store(o, HEADER, 91)
    store(o, 480, 44)
    put(o, 488, OBJECT_EXPORT_SUFFIX)
    vector_span(w, o, INSPECTION_CORE, HEADER + 1)
    vector_part(o, HEADER + 25, INLINE_FRAGMENT, 480, 1)
    vector_span(w, o, INSPECTION_EXPORTS, HEADER + 49)
    vector_part(o, HEADER + 73, INLINE_FRAGMENT, 488, 5)
    return wide_inspection(o, w, EMIT_REPLAY_OBJECT, INSPECTION_EMIT_ROLE, args, 4, 1)

def emit_replay_object_hash(s:readbuf, o:mutbuf, w:mutbuf, at:u64) -> u64:
    planned = get(w, EMIT_REPLAY_PLANNED) == 1
    span = choose(planned, EMIT_REPLAY_PLAN_HASH, EMIT_REPLAY_BASE_HASH)
    hold(w, span, input_word(s, 32), at - 65, 66)
    if planned and get(w, EMIT_REPLAY_VERSION) >= 2:
        put(o, HEADER, EMIT_LAYOUT_OBSERVATION)
        put(o, HEADER + 8, get(w, EMIT_REPLAY_DESCRIPTOR + 16))
        use_span(w, o, EMIT_REPLAY_DESCRIPTOR, 0)
        use_span(w, o, EMIT_REPLAY_OBJECT_SPAN, 1)
        return action(o, w, EMIT_REPLAY_GEOMETRY, RUN, EMIT_GEOMETRY_ROLE, 0, 2, 16)
    use_span(w, o, EMIT_REPLAY_OBJECT_SPAN, 0)
    return action(o, w, EMIT_REPLAY_GEOMETRY, RUN, EMIT_GEOMETRY_ROLE, 0, 1, 0)

def emit_replay_frame_control(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    size = input_word(s, 40)
    if plan_ok(s) == False or size < 48 or size > 8232 or input_word(s, 72) != EMIT_GEOMETRY:
        return BAD
    at = input_word(s, 80)
    extent = input_word(s, 88)
    entries = input_word(s, 96)
    total = get(w, EMIT_REPLAY_OBJECT_SPAN + 16)
    if entries > 1024 or size != 40 + 8 * entries or at > total or extent == 0 or extent > total - at:
        return BAD
    put(o, HEADER, EMIT_FRAME_PADDING)
    fragment(o, 0, input_word(s, 32), 8, size - 8)
    return action(o, w, EMIT_REPLAY_FRAME_CONTROL, RUN, INSPECTION_REQUEST_ROLE, 0, 1, 8)
'''


def layout_replay_constants():
    states = ('LAYOUT', 'SCHEDULE', 'WITNESS', 'WITNESSED', 'PLAN_INPUT', 'OBJECT',
              'OBJECT_HASH', 'GEOMETRY', 'FRAME_CONTROL', 'FRAMES', 'CANONICAL', 'CHECKED')
    spans = ('DESCRIPTOR', 'WITNESS_SPAN', 'REGISTER_PLAN', 'OBJECT_SPAN', 'BASE_HASH',
             'PLAN_HASH', 'BASE_FRAMES', 'PLAN_FRAMES')
    return {
        **{f'EMIT_REPLAY_{name}': 552 + i for i, name in enumerate(states)},
        **{f'EMIT_REPLAY_{name}': 4688 + 24 * i for i, name in enumerate(spans)},
        'EMIT_REPLAY_VERSION': 4880, 'EMIT_REPLAY_PLANNED': 4888,
        'EMIT_REPLAY_WITNESS_ROLE': 56,
        'EMIT_REPLAY_WITNESS_TAG': int.from_bytes(b'HIAEVW01', 'little'),
        'EMIT_REPLAY_REGISTER_TAG': int.from_bytes(b'HIAREG01', 'little'),
    }


def layout_replay_source():
    core = ('INSPECTION_CORE', 'EMIT_PROOF_CANDIDATE_SHA', 'EMIT_PROOF_SUBJECT_PLAN')
    evidence = ('EMIT_PROOF_CANDIDATE_SHA', 'EMIT_PROOF_SUBJECT_PLAN', 'EMIT_PROOF_SUBJECT_RAW_SHA',
                'EMIT_REPLAY_BASE_HASH', 'EMIT_REPLAY_PLAN_HASH', 'EMIT_REPLAY_BASE_FRAMES',
                'EMIT_REPLAY_PLAN_FRAMES', 'EMIT_PROOF_EVIDENCE')
    return (
        REPLAY,
        splice_list('emit_replay_schedule', 'EMIT_REPLAY_LAYOUT', core, role='EMIT_LAYOUT_ROLE'),
        splice_list('emit_replay_open_witness', 'EMIT_REPLAY_WITNESS', ('EMIT_PROOF_EVIDENCE',), role='EMIT_VERIFY_ROLE'),
        splice_list('emit_replay_check_witness', 'EMIT_REPLAY_WITNESSED',
                    (*core, 'EMIT_REPLAY_WITNESS_SPAN'), role='EMIT_REPLAY_WITNESS_ROLE'),
        splice_list('emit_replay_layout_verdict', 'EMIT_REPLAY_CHECKED', evidence, role='EMIT_VERIFY_ROLE'),
        splice_list('emit_replay_register_verdict', 'EMIT_REPLAY_CHECKED',
                    (*evidence, 'EMIT_REPLAY_WITNESS_SPAN'), role='EMIT_VERIFY_ROLE'),
    )
