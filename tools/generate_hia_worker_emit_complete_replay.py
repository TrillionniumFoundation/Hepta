"""Author complete finite-domain replay preserving historical transcript bytes."""

from tools.generate_hia_worker_emit_measurement import splice_list
from tools.hia_retained_proof_method import FINITE_COMPLETION


COMPLETE = r'''
def emit_complete_domain(o:mutbuf, w:mutbuf) -> u64:
    if get(w, EMIT_PROOF_BASE_CORE + 16) == 0:
        return BAD
    return emit_complete_expectation(o, w)

def emit_complete_state(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    fd = input_word(s, 32)
    size = input_word(s, 40)
    if state == EMIT_COMPLETE_EXPECTATION:
        count = input_word(s, 88)
        if (plan_ok(s) == False or size != 96 or input_word(s, 72) != EMIT_COMPLETE_PROJECTION
                or input_word(s, 80) != 0 or count == 0 or count > 4096):
            return BAD
        put(w, EMIT_COMPLETE_REQUIRED, count)
        body_span(s, w, EMIT_COMPLETE_EXPECTED)
        return emit_complete_input(o, w)
    if state == EMIT_COMPLETE_INPUT:
        if size < 5:
            return BAD
        sample_span(s, w, EMIT_COMPLETE_FRAME)
        use_span(w, o, EMIT_COMPLETE_FRAME, 0)
        return action(o, w, EMIT_COMPLETE_PLAN, RUN, EMIT_COMPLETE_PLAN_ROLE, 0, 1, 0)
    if state == EMIT_COMPLETE_PLAN:
        count = input_word(s, 88)
        if (plan_ok(s) == False or input_word(s, 72) != EMIT_COMPLETE_PLAN_TAG
                or input_word(s, 80) > 3 or count == 0 or count > 1024 or size != 40 + 56 * count
                or input_word(s, 96) != get(w, EMIT_COMPLETE_REQUIRED)):
            return BAD
        body_span(s, w, EMIT_COMPLETE_DOMAINS)
        put(w, EMIT_COMPLETE_FLAGS, input_word(s, 80))
        put(w, EMIT_COMPLETE_COUNT, count)
        put(w, EMIT_COMPLETE_INDEX, 0)
        put(w, EMIT_COMPLETE_TALLY, 0)
        put(w, EMIT_COMPLETE_EXTENT, 0)
        return emit_complete_next(o, w)
    if state == EMIT_COMPLETE_ROW:
        return emit_complete_row(s, o, w)
    if state == EMIT_COMPLETE_CASE:
        if plan_ok(s) == False or size < 10 or size > 264:
            return BAD
        body_span(s, w, EMIT_FINITE_CASE)
        put(w, EMIT_FINITE_SIDE, 0)
        return emit_complete_base_wire(o, w)
    if state == EMIT_COMPLETE_WIRE:
        return emit_complete_batch(s, o, w)
    if state == EMIT_COMPLETE_BATCH:
        if (plan_ok(s) == False or size != 48 + 40 * get(w, EMIT_COMPLETE_TUPLES)
                or input_word(s, 72) != EMIT_COMPLETE_BATCH_REPLY or input_word(s, 80) != 0):
            return BAD
        if get(w, EMIT_FINITE_SIDE) == 0:
            body_span(s, w, EMIT_FINITE_LEFT)
            put(w, EMIT_FINITE_SIDE, 1)
            return emit_complete_candidate_wire(o, w)
        return emit_complete_transcript(o, w, fd, size)
    if state == EMIT_COMPLETE_RENDERED:
        if plan_ok(s) == False or size < 74 or size > 6291528:
            return BAD
        return read_span(o, w, EMIT_COMPLETE_CHECKED_ROW, fd, 8, 64)
    if state == EMIT_COMPLETE_CHECKED_ROW:
        return emit_complete_append_transcript(s, o, w)
    if state == EMIT_COMPLETE_BYTES_APPENDED:
        if length(s) != 64 or size != get(w, EMIT_COMPLETE_EXTENT):
            return BAD
        use_span(w, o, EMIT_COMPLETE_SUMMARY, 0)
        return emit_append_stream(o, w, EMIT_COMPLETE_SUMMARY_APPENDED, 1, 1, 0, 64 * (get(w, EMIT_COMPLETE_INDEX) + 1))
    if state == EMIT_COMPLETE_SUMMARY_APPENDED:
        if length(s) != 64 or size != 64 * (get(w, EMIT_COMPLETE_INDEX) + 1):
            return BAD
        return action(o, w, EMIT_COMPLETE_RELEASED, EMIT_RELEASE_TEMPORARIES, 0, 0, 0, 0)
    if state == EMIT_COMPLETE_RELEASED:
        if length(s) != 64 or size != 0:
            return BAD
        put(w, EMIT_COMPLETE_INDEX, get(w, EMIT_COMPLETE_INDEX) + 1)
        return emit_complete_next(o, w)
    if state == EMIT_COMPLETE_STREAM:
        if size != get(w, EMIT_COMPLETE_EXTENT) or size == 0:
            return BAD
        sample_span(s, w, EMIT_COMPLETE_TRANSCRIPT)
        return emit_seal_stream(o, w, EMIT_COMPLETE_SUMMARIES, 1, 64 * get(w, EMIT_COMPLETE_COUNT))
    if state == EMIT_COMPLETE_SUMMARIES:
        if size != 64 * get(w, EMIT_COMPLETE_COUNT):
            return BAD
        sample_span(s, w, EMIT_COMPLETE_SUMMARY_ROWS)
        return inspection_hash(o, w, EMIT_COMPLETE_HASH, EMIT_COMPLETE_TRANSCRIPT)
    if state == EMIT_COMPLETE_CHECKED:
        return emit_independent_verdict(s, o, w, EMIT_COMPLETE_VERDICT, 1)
    return BAD

def emit_complete_next(o:mutbuf, w:mutbuf) -> u64:
    index = get(w, EMIT_COMPLETE_INDEX)
    if index == get(w, EMIT_COMPLETE_COUNT):
        if get(w, EMIT_COMPLETE_TALLY) != get(w, EMIT_COMPLETE_REQUIRED):
            return BAD
        return emit_seal_stream(o, w, EMIT_COMPLETE_STREAM, 0, get(w, EMIT_COMPLETE_EXTENT))
    domains = EMIT_COMPLETE_DOMAINS
    return read_span(o, w, EMIT_COMPLETE_ROW, get(w, domains), get(w, domains + 8) + 32 + 56 * index, 56)

def emit_complete_row(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    name = input_word(s, 64)
    bytes = input_word(s, 72)
    arity = input_word(s, 80)
    tuples = input_word(s, 88)
    total = get(w, EMIT_COMPLETE_TALLY)
    frame = EMIT_COMPLETE_FRAME
    extent = get(w, frame + 16)
    if (length(s) != 120 or bytes < 3 or bytes > 130 or name > extent or bytes > extent - name
            or arity > 12 or tuples == 0 or tuples > get(w, EMIT_COMPLETE_REQUIRED) - total):
        return BAD
    hold(w, EMIT_COMPLETE_NAME, get(w, frame), get(w, frame + 8) + name, bytes)
    put(w, EMIT_COMPLETE_ARITY, arity)
    put(w, EMIT_COMPLETE_TUPLES, tuples)
    put(w, EMIT_COMPLETE_TYPE, input_word(s, 96))
    put(w, EMIT_COMPLETE_KINDS, input_word(s, 104))
    put(w, EMIT_COMPLETE_KINDS + 8, input_word(s, 112))
    put(o, HEADER, EMIT_COMPLETE_SELECT_TAG)
    put(o, HEADER + 8, 0)
    put(o, HEADER + 16, arity)
    put(o, HEADER + 24, bytes)
    put(o, HEADER + 32, 0)
    put(o, HEADER + 40, 0)
    put(o, HEADER + 48, get(w, EMIT_COMPLETE_KINDS))
    put(o, HEADER + 56, get(w, EMIT_COMPLETE_KINDS + 8))
    use_span(w, o, EMIT_COMPLETE_NAME, 0)
    command = action(o, w, EMIT_COMPLETE_CASE, RUN, EMIT_COMPLETE_TRANSCRIPT_ROLE, 0, 1, 64)
    put(o, 184, 1)
    return command

def emit_complete_run_wire(o:mutbuf, w:mutbuf, base:bool) -> u64:
    count = 0
    if base:
        count = emit_complete_base_wire_input(o, w)
    else:
        count = emit_complete_candidate_wire_input(o, w)
    put(o, 184, 1)
    return count

def emit_complete_base_wire(o:mutbuf, w:mutbuf) -> u64:
    return emit_complete_run_wire(o, w, True)

def emit_complete_candidate_wire(o:mutbuf, w:mutbuf) -> u64:
    return emit_complete_run_wire(o, w, False)

def emit_complete_batch(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    size = input_word(s, 40)
    if (plan_ok(s) == False or size < 80 or size > 1048584
            or input_word(s, 72) != EMIT_FINITE_PROGRAM or input_word(s, 80) != 10000
            or input_word(s, 120) != get(w, EMIT_COMPLETE_ARITY)):
        return BAD
    put(o, HEADER, EMIT_COMPLETE_BATCH_REQUEST)
    put(o, HEADER + 8, 10000)
    put(o, HEADER + 16, 1)
    put(o, 384, get(w, EMIT_COMPLETE_KINDS))
    put(o, 392, get(w, EMIT_COMPLETE_KINDS + 8))
    fragment(o, 0, input_word(s, 32), 32, size - 32)
    fragment(o, 1, INLINE_FRAGMENT, 384, 12)
    command = action(o, w, EMIT_COMPLETE_BATCH, RUN, EMIT_COMPLETE_BATCH_ROLE, 0, 2, 24)
    put(o, 184, 1)
    return command

def emit_complete_transcript(o:mutbuf, w:mutbuf, fd:u64, size:u64) -> u64:
    put(o, HEADER, EMIT_COMPLETE_TRANSCRIPT_REQUEST)
    put(o, HEADER + 8, get(w, EMIT_COMPLETE_FLAGS))
    put(o, HEADER + 16, get(w, EMIT_COMPLETE_TYPE))
    put(o, HEADER + 24, get(w, EMIT_COMPLETE_NAME + 16))
    put(o, HEADER + 32, get(w, EMIT_FINITE_LEFT + 16))
    put(o, HEADER + 40, size - 8)
    put(o, HEADER + 48, get(w, EMIT_COMPLETE_KINDS))
    put(o, HEADER + 56, get(w, EMIT_COMPLETE_KINDS + 8))
    use_span(w, o, EMIT_COMPLETE_NAME, 0)
    use_span(w, o, EMIT_FINITE_LEFT, 1)
    fragment(o, 2, fd, 8, size - 8)
    command = action(o, w, EMIT_COMPLETE_RENDERED, RUN, EMIT_COMPLETE_TRANSCRIPT_ROLE, 0, 3, 64)
    put(o, 184, 1)
    return command

def emit_complete_append_transcript(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    tuples = get(w, EMIT_COMPLETE_TUPLES)
    size = input_word(s, 120)
    if (length(s) != 128 or input_word(s, 64) != EMIT_COMPLETE_TRANSCRIPT_REPLY or input_word(s, 72) != 0
            or input_word(s, 80) != tuples or input_word(s, 88) != tuples or input_word(s, 96) != EMIT_NO_VALUE
            or size == 0 or size != input_word(s, 40) - 72):
        return BAD
    total = get(w, EMIT_COMPLETE_EXTENT)
    if size > 8388608 - total:
        return BAD
    fd = input_word(s, 32)
    hold(w, EMIT_COMPLETE_SUMMARY, fd, 8, 64)
    put(w, EMIT_COMPLETE_EXTENT, total + size)
    put(w, EMIT_COMPLETE_TALLY, get(w, EMIT_COMPLETE_TALLY) + tuples)
    fragment(o, 0, fd, 72, size)
    return emit_append_stream(o, w, EMIT_COMPLETE_BYTES_APPENDED, 0, 1, 0, total + size)

def emit_append_stream(o:mutbuf, w:mutbuf, state:u64, stream:u64, parts:u64, inline:u64, size:u64) -> u64:
    command = action(o, w, state, EMIT_APPEND_STREAM, 0, 0, parts, inline)
    put(o, 144, stream)
    put(o, 176, size)
    return command

def emit_seal_stream(o:mutbuf, w:mutbuf, state:u64, stream:u64, size:u64) -> u64:
    command = action(o, w, state, EMIT_SEAL_STREAM, 0, 0, 0, 0)
    put(o, 144, stream)
    put(o, 176, size)
    return command

def emit_complete_transcript_hash(s:readbuf, o:mutbuf, w:mutbuf, at:u64) -> u64:
    put(o, HEADER, EMIT_COMPLETE_JOIN)
    put(o, HEADER + 8, get(w, EMIT_COMPLETE_DOMAINS + 16))
    put(o, HEADER + 16, get(w, EMIT_COMPLETE_COUNT))
    vector_span(w, o, EMIT_COMPLETE_EXPECTED, HEADER + 24)
    vector_part(o, HEADER + 48, input_word(s, 32), at - 64, 64)
    vector_span(w, o, EMIT_COMPLETE_DOMAINS, HEADER + 72)
    vector_span(w, o, EMIT_COMPLETE_SUMMARY_ROWS, HEADER + 96)
    return wide_inspection(o, w, EMIT_COMPLETE_CHECKED, EMIT_FINITE_OBSERVATION_ROLE, 0, 4, 24)
'''


def complete_replay_constants():
    names = ('EXPECTED', 'FRAME', 'DOMAINS', 'NAME', 'SUMMARY', 'TRANSCRIPT', 'SUMMARY_ROWS')
    states = ('EXPECTATION', 'INPUT', 'PLAN', 'ROW', 'CASE', 'WIRE', 'BATCH', 'RENDERED',
              'CHECKED_ROW', 'BYTES_APPENDED', 'SUMMARY_APPENDED', 'RELEASED', 'STREAM',
              'SUMMARIES', 'HASH', 'CHECKED')
    integers = ('REQUIRED', 'FLAGS', 'COUNT', 'INDEX', 'TALLY', 'EXTENT', 'ARITY', 'TUPLES', 'TYPE', 'KINDS')
    tags = {
        'PROJECTION': b'HIAFIP01', 'PLAN_TAG': b'HIAVFD01', 'SELECT_TAG': b'HIAVFS01',
        'BATCH_REQUEST': b'HIAVFB01', 'BATCH_REPLY': b'HIAVFR01', 'TRANSCRIPT_REQUEST': b'HIAVFT01',
        'TRANSCRIPT_REPLY': b'HIAVFJ01', 'JOIN': b'HIAVFC02',
    }
    return {
        **{f'EMIT_COMPLETE_{name}': 608 + i for i, name in enumerate(states)},
        **{f'EMIT_COMPLETE_{name}': 5864 + 24 * i for i, name in enumerate(names)},
        **{f'EMIT_COMPLETE_{name}': 6032 + 8 * i for i, name in enumerate(integers)},
        **{f'EMIT_COMPLETE_{name}': int.from_bytes(value, 'little') for name, value in tags.items()},
        'EMIT_NO_VALUE': (1 << 64) - 1, 'EMIT_COMPLETE_VERDICT': FINITE_COMPLETION,
        'EMIT_COMPLETE_PLAN_ROLE': 60, 'EMIT_COMPLETE_BATCH_ROLE': 61, 'EMIT_COMPLETE_TRANSCRIPT_ROLE': 62,
        'EMIT_APPEND_STREAM': 25, 'EMIT_SEAL_STREAM': 26, 'EMIT_RELEASE_TEMPORARIES': 27,
    }


def complete_replay_source():
    return (
        COMPLETE,
        splice_list('emit_complete_expectation', 'EMIT_COMPLETE_EXPECTATION',
                    ('EMIT_PROOF_EVIDENCE',), role='EMIT_FINITE_OBSERVATION_ROLE'),
        splice_list('emit_complete_input', 'EMIT_COMPLETE_INPUT', ('EMIT_PROOF_BASE_CORE', 'INSPECTION_CORE')),
        splice_list('emit_complete_base_wire_input', 'EMIT_COMPLETE_WIRE',
                    ('EMIT_PROOF_BASE_CORE', 'EMIT_FINITE_CASE'), role='EMIT_FINITE_REFERENCE_ROLE'),
        splice_list('emit_complete_candidate_wire_input', 'EMIT_COMPLETE_WIRE',
                    ('INSPECTION_CORE', 'EMIT_FINITE_CASE'), role='EMIT_FINITE_REFERENCE_ROLE'),
    )
