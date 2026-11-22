"""Replay retained compositional proofs by physically discharging each barrier."""

from hepta.hia_cnf_native import (
    CIRCUIT_CAPACITY, CIRCUIT_REQUEST, PROJECTION_INPUT_LIMIT,
    SEARCH_PLAN_REQUEST, SPARSE_REPLY, SPARSE_REQUEST,
)
from hepta.hia_optimization import DEFAULT_POLICY
from tools.generate_hia_worker_compositional_barrier import OBLIGATION_BATCH
from tools.generate_hia_worker_compositional_skeleton import DECISION, PAIR, STAMP
from tools.hia_retained_proof_method import COMPOSITION_VERDICT


COMPOSITION = r'''
def emit_composition(o:mutbuf, w:mutbuf) -> u64:
    if get(w, EMIT_PROOF_BASE_CORE + 16) == 0 or get(w, EMIT_CONTEXT_ROW + 16) == 0:
        return BAD
    return clock_sample(o, w, COMP_MONOTONIC, 0)

def composition_run(o:mutbuf, w:mutbuf, next:u64, role:u64, parts:u64, inline:u64, temporary:bool) -> u64:
    result = action(o, w, next, RUN, role, 0, parts, inline)
    put(o, 144, get(w, COMP_DEADLINE))
    put(o, 184, choose(temporary, 1, 0))
    return result

def composition_state(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    fd = input_word(s, 32)
    size = input_word(s, 40)
    if state == COMP_MONOTONIC or state == COMP_REALTIME:
        if length(s) != 72 or size != 8:
            return BAD
        if state == COMP_MONOTONIC:
            put(w, COMP_TICK, input_word(s, 64))
            return clock_sample(o, w, COMP_REALTIME, 1)
        put(o, HEADER, EMIT_LAUNCH_WINDOW)
        put(o, HEADER + 8, 2)
        put(o, HEADER + 16, get(w, EMIT_WALL_LIMIT))
        put(o, HEADER + 24, input_word(s, 64))
        put(o, HEADER + 32, get(w, COMP_TICK))
        use_span(w, o, EMIT_FIELDS + 24, 0)
        use_span(w, o, EMIT_CONTEXT_ROW, 1)
        return action(o, w, COMP_WINDOW, RUN, INSPECTION_REQUEST_ROLE, 0, 2, 40)
    if state == COMP_WINDOW:
        tick = get(w, COMP_TICK)
        end = input_word(s, 104)
        if (plan_ok(s) == False or size != 48 or input_word(s, 72) != EMIT_LAUNCH_PERMIT
                or input_word(s, 80) != 0 or input_word(s, 96) != tick or end <= tick):
            return BAD
        put(w, COMP_DEADLINE, choose(end - tick > COMP_NANOS, tick + COMP_NANOS, end))
        use_span(w, o, EMIT_PROOF_BASE_CORE, 0)
        return composition_run(o, w, COMP_LEFT, COMP_SKELETON_ROLE, 1, 0, True)
    if state == COMP_LEFT or state == COMP_RIGHT:
        if plan_ok(s) == False or size < 41 or input_word(s, 72) != COMP_STAMP or input_word(s, 80) != 0:
            return BAD
        if state == COMP_LEFT:
            body_span(s, w, COMP_LEFT_SPAN)
            use_span(w, o, INSPECTION_CORE, 0)
            return composition_run(o, w, COMP_RIGHT, COMP_SKELETON_ROLE, 1, 0, True)
        put(o, HEADER, COMP_PAIR)
        put(o, HEADER + 8, get(w, COMP_LEFT_SPAN + 16))
        put(o, HEADER + 16, size - 8)
        put(o, HEADER + 24, COMP_SCALAR_MAX)
        use_span(w, o, COMP_LEFT_SPAN, 0)
        fragment(o, 1, fd, 8, size - 8)
        return composition_run(o, w, COMP_MATCH, COMP_SKELETON_ROLE, 2, 32, False)
    if state == COMP_MATCH:
        if (plan_ok(s) == False or size != 32 or input_word(s, 72) != COMP_DECISION
                or input_word(s, 80) != 0 or input_word(s, 88) > COMP_SCALAR_MAX):
            return BAD
        body_span(s, w, COMP_MATCH_SPAN)
        return action(o, w, COMP_MATCH_RELEASED, EMIT_RELEASE_TEMPORARIES, 0, 0, 0, 0)
    if state == COMP_MATCH_RELEASED:
        if length(s) != 64 or size != 0:
            return BAD
        return composition_subject(o, w)
    if state == COMP_BATCH:
        count = input_word(s, 88)
        if (plan_ok(s) == False or size < 256 or input_word(s, 72) != COMP_BATCH_TAG
                or input_word(s, 80) != 0 or count == 0 or count > COMP_OBLIGATION_MAX
                or input_word(s, 96) != size - 40):
            return BAD
        body_span(s, w, COMP_BATCH_SPAN)
        put(w, COMP_CURSOR, 32)
        put(w, COMP_INDEX, 0)
        put(w, COMP_COUNT, count)
        put(o, HEADER, COMP_FINISH_PHASE)
        use_span(w, o, COMP_MATCH_SPAN, 0)
        fragment(o, 1, fd, 8, 32)
        return emit_append_stream(o, w, COMP_BATCH_OPEN, 0, 2, 8, 64)
    if state == COMP_BATCH_OPEN:
        if length(s) != 64 or size != 64:
            return BAD
        return composition_next(o, w)
    if state == COMP_GRAPH:
        return composition_graph(s, o, w)
    if state == COMP_CIRCUIT:
        if size < 104 or size > COMP_CIRCUIT_CAPACITY or input_word(s, 64) != COMP_CIRCUIT_TAG:
            return BAD
        sample_span(s, w, COMP_CIRCUIT_SPAN)
        return clock_sample(o, w, COMP_SEARCH_CLOCK, 0)
    if state == COMP_SEARCH_CLOCK:
        now = input_word(s, 64)
        end = get(w, COMP_DEADLINE)
        if length(s) != 72 or size != 8 or now >= end or end - now < 1000000:
            return BAD
        put(o, HEADER, COMP_PLAN_PHASE)
        put(o, HEADER + 8, quotient(end - now, 1000000))
        use_span(w, o, COMP_CIRCUIT_SPAN, 0)
        return composition_run(o, w, COMP_PLAN_INPUT, COMP_REPLAY_ROLE, 1, 16, True)
    if state == COMP_PLAN_INPUT:
        if plan_ok(s) == False or size < 56 or input_word(s, 72) != COMP_PLAN_TAG:
            return BAD
        fragment(o, 0, fd, 8, size - 8)
        return composition_run(o, w, COMP_PLAN, COMP_SOLVER_ROLE, 1, 0, True)
    if state == COMP_PLAN:
        if size != 32 or input_word(s, 64) != COMP_PLAN_TAG:
            return BAD
        sample_span(s, w, COMP_PLAN_SPAN)
        put(o, HEADER, COMP_PREPARE_PHASE)
        use_span(w, o, COMP_PLAN_SPAN, 0)
        use_span(w, o, COMP_CIRCUIT_SPAN, 1)
        return composition_run(o, w, COMP_PREPARED, COMP_REPLAY_ROLE, 2, 8, True)
    if state == COMP_PREPARED:
        if plan_ok(s) == False or size != get(w, COMP_CIRCUIT_SPAN + 16) + 8 or input_word(s, 72) != COMP_CIRCUIT_TAG:
            return BAD
        fragment(o, 0, fd, 8, size - 8)
        return composition_run(o, w, COMP_SPARSE, COMP_SOLVER_ROLE, 1, 0, True)
    if state == COMP_SPARSE:
        if size < 32 or size > COMP_CIRCUIT_CAPACITY or input_word(s, 64) != COMP_SPARSE_TAG:
            return BAD
        put(o, HEADER, COMP_SEARCH_PHASE)
        use_span(w, o, COMP_PLAN_SPAN, 0)
        fragment(o, 1, fd, 0, size)
        return composition_run(o, w, COMP_SEARCH, COMP_REPLAY_ROLE, 2, 8, True)
    if state == COMP_SEARCH:
        if plan_ok(s) == False or size < 40 or size > COMP_CIRCUIT_CAPACITY + 8:
            return BAD
        hold(w, COMP_SEARCH_SPAN, fd, 8, 32)
        fragment(o, 0, fd, 8, size - 8)
        return composition_run(o, w, COMP_SOLVED, COMP_SOLVER_ROLE, 1, 0, True)
    if state == COMP_SOLVED:
        if size < 32 or input_word(s, 64) != COMP_REPLY_TAG:
            return BAD
        put(o, HEADER, get(w, COMP_INDEX))
        put(o, HEADER + 8, get(w, COMP_GRAPH_BYTES))
        use_span(w, o, COMP_PLAN_SPAN, 0)
        use_span(w, o, COMP_SEARCH_SPAN, 1)
        fragment(o, 2, fd, 0, 32)
        return emit_append_stream(o, w, COMP_RECORDED, 0, 3, 16, 64 + 112 * (get(w, COMP_INDEX) + 1))
    if state == COMP_RECORDED:
        if length(s) != 64 or size != (64 + 112 * (get(w, COMP_INDEX) + 1)):
            return BAD
        return action(o, w, COMP_RELEASED, EMIT_RELEASE_TEMPORARIES, 0, 0, 0, 0)
    if state == COMP_RELEASED:
        if length(s) != 64 or size != 0:
            return BAD
        put(w, COMP_INDEX, get(w, COMP_INDEX) + 1)
        return composition_next(o, w)
    if state == COMP_SUMMARY:
        if size != (64 + 112 * get(w, COMP_INDEX)):
            return BAD
        fragment(o, 0, fd, 0, size)
        return composition_run(o, w, COMP_CHECKED, COMP_REPLAY_ROLE, 1, 0, False)
    if state == COMP_CHECKED:
        return emit_independent_verdict(s, o, w, COMP_VERDICT, 1)
    return BAD

def composition_subject(o:mutbuf, w:mutbuf) -> u64:
    put(o, HEADER, COMP_LEFT_JSON)
    put(o, 456, COMP_RIGHT_JSON)
    store(o, 464, 58)
    store(o, 465, 125)
    vector_span(w, o, EMIT_PROOF_BASE_CORE, HEADER + 8)
    vector_part(o, HEADER + 32, INLINE_FRAGMENT, 456, 9)
    vector_span(w, o, INSPECTION_CORE, HEADER + 56)
    vector_part(o, HEADER + 80, INLINE_FRAGMENT, 465, 1)
    result = wide_inspection(o, w, COMP_BATCH, COMP_BARRIER_ROLE, 0, 4, 8)
    put(o, 144, get(w, COMP_DEADLINE))
    return result

def composition_next(o:mutbuf, w:mutbuf) -> u64:
    cursor = get(w, COMP_CURSOR)
    extent = get(w, COMP_BATCH_SPAN + 16)
    if get(w, COMP_INDEX) == get(w, COMP_COUNT):
        if cursor != extent:
            return BAD
        return emit_seal_stream(o, w, COMP_SUMMARY, 0, (64 + 112 * get(w, COMP_INDEX)))
    if cursor > extent or extent - cursor < 216:
        return BAD
    return read_span(o, w, COMP_GRAPH, get(w, COMP_BATCH_SPAN),
                     get(w, COMP_BATCH_SPAN + 8) + cursor, 8)

def composition_graph(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    bytes = input_word(s, 64)
    cursor = get(w, COMP_CURSOR)
    if (length(s) != 72 or bytes < 208 or bytes > COMP_GRAPH_MAX
            or bytes > get(w, COMP_BATCH_SPAN + 16) - cursor - 8):
        return BAD
    put(w, COMP_GRAPH_BYTES, bytes)
    put(w, COMP_CURSOR, cursor + 8 + bytes)
    fragment(o, 0, get(w, COMP_BATCH_SPAN), get(w, COMP_BATCH_SPAN + 8) + cursor + 8, bytes)
    return composition_run(o, w, COMP_CIRCUIT, COMP_SOLVER_ROLE, 1, 0, True)

'''


def composition_constants():
    states = ('MONOTONIC', 'REALTIME', 'WINDOW', 'LEFT', 'RIGHT', 'MATCH', 'MATCH_RELEASED',
              'BATCH', 'BATCH_OPEN', 'GRAPH', 'CIRCUIT', 'SEARCH_CLOCK', 'PLAN_INPUT', 'PLAN',
              'PREPARED', 'SPARSE', 'SEARCH', 'SOLVED', 'RECORDED', 'RELEASED', 'SUMMARY', 'CHECKED')
    spans = ('LEFT_SPAN', 'MATCH_SPAN', 'BATCH_SPAN', 'CIRCUIT_SPAN', 'PLAN_SPAN', 'SEARCH_SPAN')
    words = ('TICK', 'DEADLINE', 'CURSOR', 'INDEX', 'COUNT', 'GRAPH_BYTES')
    tags = {'PLAN_PHASE': b'HIACPL01', 'PREPARE_PHASE': b'HIACPP01', 'SEARCH_PHASE': b'HIACPS01',
            'FINISH_PHASE': b'HIACPB01', 'LEFT_JSON': b'{"left":', 'RIGHT_JSON': b',"right"'}
    return {
        **{f'COMP_{key}': 650 + i for i, key in enumerate(states)},
        **{f'COMP_{key}': 5864 + i * 24 for i, key in enumerate(spans)},
        **{f'COMP_{key}': 6008 + i * 8 for i, key in enumerate(words)},
        **{f'COMP_{key}': int.from_bytes(value, 'little') for key, value in tags.items()},
        'COMP_OBLIGATION_MAX': DEFAULT_POLICY['max_obligations'],
        'COMP_SCALAR_MAX': DEFAULT_POLICY['max_scalar_operations'],
        'COMP_NANOS': DEFAULT_POLICY['timeout_ms'] * 1000000,
        'COMP_STAMP': STAMP, 'COMP_DECISION': DECISION, 'COMP_PAIR': PAIR, 'COMP_BATCH_TAG': OBLIGATION_BATCH,
        'COMP_GRAPH_MAX': PROJECTION_INPUT_LIMIT, 'COMP_CIRCUIT_CAPACITY': CIRCUIT_CAPACITY,
        'COMP_CIRCUIT_TAG': CIRCUIT_REQUEST, 'COMP_PLAN_TAG': SEARCH_PLAN_REQUEST,
        'COMP_SPARSE_TAG': SPARSE_REQUEST, 'COMP_REPLY_TAG': SPARSE_REPLY, 'COMP_VERDICT': COMPOSITION_VERDICT,
        'COMP_SKELETON_ROLE': 65, 'COMP_REPLAY_ROLE': 66, 'COMP_BARRIER_ROLE': 67, 'COMP_SOLVER_ROLE': 68,
    }
