"""Author retained build custody replay from the physical Store."""

from tools.generate_hia_worker_emit_measurement import splice_list


CUSTODY = r'''
def emit_proof_typed_artifact(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if length(s) != 152 or input_word(s, 64) != EMIT_PROOF_ARTIFACT_BINDING:
        return BAD
    purpose = get(w, RETAINED_PURPOSE)
    if purpose == READ_EMIT_CUSTODY_NATIVE or purpose == READ_EMIT_CUSTODY_OBJECT:
        row = slot_bytes(w, STORE_RESULT)
        at = input_word(s, 136)
        size = input_word(s, 144)
        if at > row or size < 2 or size > row - at:
            return BAD
        metadata = choose(purpose == READ_EMIT_CUSTODY_NATIVE, EMIT_CUSTODY_NATIVE_META, EMIT_CUSTODY_OBJECT_META)
        hold(w, metadata, slot_fd(w, STORE_RESULT), at, size)
    i = 0
    while i < 64:
        c = byte(s, 72 + i)
        if is_hex(c) == False:
            return BAD
        store(o, 416 + i, c)
        i = i + 1
    store(o, 480, 0)
    return artifact_command(o, w, RETAINED_BYTES, STORE_GET, STORE_GET_END, 0)

def emit_proof_open_custody(o:mutbuf, w:mutbuf) -> u64:
    source = EMIT_PROOF_BOUND
    fd = get(w, source)
    start = get(w, source + 8)
    if get(w, source + 16) != 472:
        return BAD
    hold(w, EMIT_CUSTODY_NATIVE_REF, fd, start + 120, 176)
    hold(w, EMIT_CUSTODY_BUILD_REF, fd, start + 296, 176)
    move_fragment(w, EMIT_CUSTODY_BUILD_REF, INSPECTION_REFERENCE)
    return emit_proof_read(o, w, READ_EMIT_CUSTODY_BUILD, 5)

def emit_proof_custody_reopened(s:readbuf, o:mutbuf, w:mutbuf, purpose:u64) -> u64:
    fd = input_word(s, 32)
    size = input_word(s, 40)
    if purpose == READ_EMIT_CUSTODY_BUILD:
        sample_span(s, w, EMIT_CUSTODY_BUILD)
        return emit_custody_projection(o, w)
    if purpose == READ_EMIT_CUSTODY_PLAN:
        sample_span(s, w, EMIT_CUSTODY_RAW_PLAN)
        put(o, HEADER, get(w, 24))
        use_span(w, o, EMIT_CUSTODY_RAW_PLAN, 0)
        return action(o, w, EMIT_CUSTODY_CANONICAL, RUN, EMIT_CANONICAL_ROLE, 0, 1, 8)
    if purpose == READ_EMIT_CUSTODY_NATIVE or purpose == READ_EMIT_CUSTODY_OBJECT:
        if size < 64:
            return BAD
        if (input_word(s, 64) & EMIT_IDENT_MASK) != EMIT_IDENT:
            return BAD
        kind = input_word(s, 80) & 4294967295
        if purpose == READ_EMIT_CUSTODY_NATIVE:
            if kind != EMIT_ELF_OBJECT and kind != EMIT_ELF_SHARED:
                return BAD
            sample_span(s, w, EMIT_CUSTODY_NATIVE)
            return inspection_hash(o, w, EMIT_CUSTODY_NATIVE_HASH, EMIT_CUSTODY_NATIVE)
        if kind != EMIT_ELF_OBJECT:
            return BAD
        sample_span(s, w, EMIT_CUSTODY_OBJECT)
        return inspection_hash(o, w, EMIT_CUSTODY_OBJECT_HASH, EMIT_CUSTODY_OBJECT)
    return BAD

def emit_proof_custody_state(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    fd = input_word(s, 32)
    size = input_word(s, 40)
    if state == EMIT_CUSTODY_PROJECTED:
        if (plan_ok(s) == False or (size != 376 and size != 552)
                or input_word(s, 72) != EMIT_CUSTODY_PROJECTION or input_word(s, 80) != 0):
            return BAD
        hold(w, EMIT_CUSTODY_OBJECT_REF, fd, 200, 176)
        hold(w, EMIT_CUSTODY_PLAN_REF, fd, 376, choose(size == 552, 176, 0))
        put(o, HEADER, EMIT_COMPARE_REQUEST)
        put(o, HEADER + 8, 176)
        put(o, HEADER + 16, get(w, EMIT_FIELDS + 64))
        fragment(o, 0, fd, 24, 176)
        use_span(w, o, EMIT_FIELDS + 48, 1)
        return action(o, w, EMIT_CUSTODY_CANDIDATE, RUN, EMIT_NATIVE_ARTIFACT_ROLE, 0, 2, 24)
    if state == EMIT_CUSTODY_CANDIDATE:
        if emit_custody_compare_reply(s) == False or input_word(s, 80) != 1:
            return BAD
        if get(w, EMIT_CUSTODY_PLAN_REF + 16) != 0:
            move_fragment(w, EMIT_CUSTODY_PLAN_REF, INSPECTION_REFERENCE)
            return emit_proof_read(o, w, READ_EMIT_CUSTODY_PLAN, 0)
        return emit_custody_inputs(o, w)
    if state == EMIT_CUSTODY_CANONICAL:
        if plan_ok(s) == False or size < 10:
            return BAD
        body_span(s, w, EMIT_CUSTODY_CANONICAL_PLAN)
        return inspection_hash(o, w, EMIT_CUSTODY_RAW_HASH, EMIT_CUSTODY_RAW_PLAN)
    if state == EMIT_CUSTODY_SIGNED:
        if plan_ok(s) == False or size < 10:
            return BAD
        body_span(s, w, EMIT_CUSTODY_SIGNATURE)
        move_fragment(w, EMIT_CUSTODY_NATIVE_REF, INSPECTION_REFERENCE)
        return emit_proof_read(o, w, READ_EMIT_CUSTODY_NATIVE, 7)
    if state == EMIT_CUSTODY_EQUAL:
        if emit_custody_compare_reply(s) == False:
            return BAD
        if input_word(s, 80) == 0:
            return emit_custody_literals(o, w, False)
        return emit_custody_compare(o, w)
    if state == EMIT_CUSTODY_LITERALS:
        if size < 9 or size > 28:
            return BAD
        hold(w, EMIT_CUSTODY_EQUALITY, fd, 0, choose(input_word(s, 64) == EMIT_TRUE, 4, 5))
        hold(w, EMIT_CUSTODY_DECIMAL, fd, 8, size - 8)
        if get(w, EMIT_CUSTODY_PLAN_REF + 16) != 0:
            return emit_custody_proof_tail_planned(o, w)
        return emit_custody_proof_tail(o, w)
    if state == EMIT_CUSTODY_TAIL:
        if size < 280:
            return BAD
        sample_span(s, w, EMIT_CUSTODY_PROOF_TAIL)
        return emit_custody_proof_bundle(o, w)
    if state == EMIT_CUSTODY_VERIFIED:
        return emit_custody_verified(s, o, w)
    if state == EMIT_CUSTODY_EFFECT:
        if length(s) != 88 or input_word(s, 64) != EMIT_CUSTODY_PACKET or input_word(s, 72) != 0:
            return BAD
        kind = input_word(s, 80)
        if kind < 1 or kind > 2:
            return BAD
        copy_span(s, w, 64, EMIT_PROOF_VERDICTS + 48 * get(w, EMIT_PROOF_INDEX) + 24, 24)
        return emit_proof_record_local(o, w)
    return BAD

def emit_custody_inputs(o:mutbuf, w:mutbuf) -> u64:
    source = choose(get(w, EMIT_PROFILE_LEVEL) != 0, INSPECTION_STRUCTURED, INSPECTION_CORE)
    return inspection_hash(o, w, EMIT_CUSTODY_INPUT_HASH, source)

def emit_custody_hash(s:readbuf, o:mutbuf, w:mutbuf, at:u64, state:u64) -> u64:
    fd = input_word(s, 32)
    if state == EMIT_CUSTODY_RAW_HASH:
        hold(w, EMIT_CUSTODY_RAW_SHA, fd, at - 65, 66)
        return inspection_hash(o, w, EMIT_CUSTODY_CANONICAL_HASH, EMIT_CUSTODY_CANONICAL_PLAN)
    if state == EMIT_CUSTODY_CANONICAL_HASH:
        hold(w, EMIT_CUSTODY_CANONICAL_SHA, fd, at - 65, 66)
        return emit_custody_inputs(o, w)
    if state == EMIT_CUSTODY_INPUT_HASH:
        hold(w, EMIT_CUSTODY_INPUT_SHA, fd, at - 65, 66)
        producer = choose(get(w, INSPECTION_EXPORTS + 16) > 2, EMIT_BORROWED_EXE, EMIT_SCALAR_EXE)
        return inspection_hash(o, w, EMIT_CUSTODY_PRODUCER_HASH, producer)
    if state == EMIT_CUSTODY_PRODUCER_HASH:
        hold(w, EMIT_CUSTODY_PRODUCER_SHA, fd, at - 65, 66)
        return emit_custody_signature(o, w)
    if state == EMIT_CUSTODY_NATIVE_HASH:
        hold(w, EMIT_CUSTODY_NATIVE_SHA, fd, at - 65, 66)
        move_fragment(w, EMIT_CUSTODY_OBJECT_REF, INSPECTION_REFERENCE)
        return emit_proof_read(o, w, READ_EMIT_CUSTODY_OBJECT, 6)
    if state == EMIT_CUSTODY_OBJECT_HASH:
        hold(w, EMIT_CUSTODY_OBJECT_SHA, fd, at - 65, 66)
        if get(w, EMIT_CUSTODY_NATIVE + 16) != get(w, EMIT_CUSTODY_OBJECT + 16):
            return emit_custody_literals(o, w, False)
        put(w, EMIT_CUSTODY_COMPARE_AT, 0)
        return emit_custody_compare(o, w)
    return BAD

def emit_custody_compare_reply(s:readbuf) -> bool:
    return (plan_ok(s) and input_word(s, 40) == 24
            and input_word(s, 72) == EMIT_COMPARE_RESULT and input_word(s, 80) <= 1)

def emit_custody_compare(o:mutbuf, w:mutbuf) -> u64:
    at = get(w, EMIT_CUSTODY_COMPARE_AT)
    extent = get(w, EMIT_CUSTODY_NATIVE + 16)
    if at == extent:
        return emit_custody_literals(o, w, True)
    if at > extent:
        return BAD
    remaining = extent - at
    count = choose(remaining > 1048576, 1048576, remaining)
    put(w, EMIT_CUSTODY_COMPARE_AT, at + count)
    put(o, HEADER, EMIT_COMPARE_REQUEST)
    put(o, HEADER + 8, count)
    put(o, HEADER + 16, count)
    fragment(o, 0, get(w, EMIT_CUSTODY_NATIVE), get(w, EMIT_CUSTODY_NATIVE + 8) + at, count)
    fragment(o, 1, get(w, EMIT_CUSTODY_OBJECT), get(w, EMIT_CUSTODY_OBJECT + 8) + at, count)
    return action(o, w, EMIT_CUSTODY_EQUAL, RUN, EMIT_NATIVE_ARTIFACT_ROLE, 0, 2, 24)

def emit_custody_literals(o:mutbuf, w:mutbuf, equal:bool) -> u64:
    put(o, HEADER, choose(equal, EMIT_TRUE, EMIT_FALSE))
    end = decimal(o, HEADER + 8, get(w, EMIT_CUSTODY_NATIVE + 16))
    return action(o, w, EMIT_CUSTODY_LITERALS, MAKE, 0, 0, 0, end - HEADER)

def emit_custody_verified(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if (plan_ok(s) == False or input_word(s, 40) != 32 or input_word(s, 72) != EMIT_CUSTODY_PACKET
            or input_word(s, 80) != 0 or input_word(s, 88) < 1 or input_word(s, 88) > 2):
        return BAD
    body_span(s, w, EMIT_CUSTODY_OBSERVATION)
    return emit_proof_open_claims(o, w)

def emit_custody_effect(o:mutbuf, w:mutbuf) -> u64:
    if get(w, EMIT_PROOF_SUBJECT) != 4 or get(w, EMIT_CUSTODY_OBSERVATION + 16) != 24:
        return BAD
    return read_span(o, w, EMIT_CUSTODY_EFFECT, get(w, EMIT_CUSTODY_OBSERVATION), get(w, EMIT_CUSTODY_OBSERVATION + 8), 24)
'''


def custody_replay_constants():
    spans = (
        'NATIVE_REF', 'OBJECT_REF', 'PLAN_REF', 'BUILD', 'NATIVE_META', 'OBJECT_META', 'NATIVE',
        'OBJECT', 'RAW_PLAN', 'CANONICAL_PLAN', 'RAW_SHA', 'CANONICAL_SHA', 'INPUT_SHA', 'PRODUCER_SHA',
        'SIGNATURE', 'NATIVE_SHA', 'OBJECT_SHA', 'EQUALITY', 'DECIMAL', 'PROOF_TAIL', 'OBSERVATION',
    )
    states = ('PROJECTED', 'CANDIDATE', 'CANONICAL', 'SIGNED', 'EQUAL', 'LITERALS', 'TAIL', 'VERIFIED',
              'EFFECT', 'RAW_HASH', 'CANONICAL_HASH', 'INPUT_HASH', 'PRODUCER_HASH', 'NATIVE_HASH', 'OBJECT_HASH')
    return {
        **{f'EMIT_CUSTODY_{name}': 4960 + 24 * i for i, name in enumerate(spans)},
        **{f'EMIT_CUSTODY_{name}': 568 + i for i, name in enumerate(states)},
        'EMIT_CUSTODY_COMPARE_AT': 5464,
        'EMIT_CUSTODY_BUILD_REF': 5504,
        'EMIT_CUSTODY_PROJECTION': int.from_bytes(b'HIABCP01', 'little'),
        'EMIT_PROOF_ARTIFACT_BINDING': int.from_bytes(b'HIABRD01', 'little'),
        'READ_EMIT_CUSTODY_BUILD': 12, 'READ_EMIT_CUSTODY_PLAN': 13,
        'READ_EMIT_CUSTODY_NATIVE': 14, 'READ_EMIT_CUSTODY_OBJECT': 15,
    }


def custody_replay_source(signature):
    facts = ('EMIT_PROOF_CANDIDATE_SHA', 'EMIT_CUSTODY_INPUT_SHA', 'EMIT_CUSTODY_SIGNATURE',
             'INSPECTION_EXPORTS', 'EMIT_CUSTODY_OBJECT_SHA', 'EMIT_CUSTODY_NATIVE_SHA',
             'EMIT_CUSTODY_DECIMAL', 'EMIT_CUSTODY_EQUALITY')
    return (
        CUSTODY, signature.replace('emit_signature(', 'emit_custody_signature(')
        .replace('EMIT_SIGNATURE_BOUND', 'EMIT_CUSTODY_SIGNED'),
        splice_list('emit_custody_projection', 'EMIT_CUSTODY_PROJECTED',
                    ('EMIT_INSTALLATION', 'EMIT_FIELDS + 24', 'EMIT_PROFILES + 48', 'EMIT_PROFILES + 240',
                     'EMIT_CUSTODY_NATIVE_REF', 'EMIT_CUSTODY_BUILD'), role='EMIT_CUSTODY_ROLE'),
        splice_list('emit_custody_proof_tail', 'EMIT_CUSTODY_TAIL', facts, suffix=b']]'),
        splice_list('emit_custody_proof_tail_planned', 'EMIT_CUSTODY_TAIL',
                    (*facts, 'EMIT_CUSTODY_CANONICAL_PLAN', 'EMIT_CUSTODY_RAW_SHA', 'EMIT_CUSTODY_CANONICAL_SHA'), suffix=b']]'),
        splice_list('emit_custody_proof_bundle', 'EMIT_CUSTODY_VERIFIED',
                    ('EMIT_INSTALLATION', 'EMIT_CUSTODY_PRODUCER_SHA', 'EMIT_FIELDS + 24', 'EMIT_PROFILES + 48',
                     'EMIT_PROFILES + 240', 'EMIT_CUSTODY_NATIVE_REF', 'EMIT_CUSTODY_BUILD', 'EMIT_CUSTODY_NATIVE_META',
                     'EMIT_CUSTODY_OBJECT_META', 'EMIT_CUSTODY_PROOF_TAIL'), suffix=b'', role='EMIT_CUSTODY_ROLE'),
    )
