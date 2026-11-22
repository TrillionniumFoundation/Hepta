"""Author retained finite reference replay from admitted Core bytes."""

from hepta.hia_scalar_reference_wire import PROGRAM_MAGIC, PROGRAM_RESULT
from tools.generate_hia_worker_emit_measurement import splice_list
from tools.hia_retained_proof_method import FINITE_OBSERVATION


FINITE = r'''
def emit_finite_counterexample(o:mutbuf, w:mutbuf) -> u64:
    if get(w, EMIT_PROOF_BASE_CORE + 16) == 0:
        return BAD
    return emit_finite_counterexample_frame(o, w)

def emit_finite_replay_state(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    fd = input_word(s, 32)
    size = input_word(s, 40)
    if state == EMIT_FINITE_FRAME:
        if size < 10:
            return BAD
        sample_span(s, w, EMIT_FINITE_INPUT)
        use_span(w, o, EMIT_FINITE_INPUT, 0)
        return action(o, w, EMIT_FINITE_PROJECTED, RUN, EMIT_FINITE_OBSERVATION_ROLE, 0, 1, 0)
    if state == EMIT_FINITE_PROJECTED:
        if plan_ok(s) == False or size != 120 or input_word(s, 72) != EMIT_FINITE_PROJECTION or input_word(s, 80) != 0:
            return BAD
        base = EMIT_FINITE_INPUT
        at = input_word(s, 88)
        bytes = input_word(s, 96)
        extent = get(w, base + 16)
        if at > extent or bytes < 2 or bytes > extent - at:
            return BAD
        body_span(s, w, EMIT_FINITE_EXPECTATION)
        hold(w, EMIT_FINITE_CASE, get(w, base), get(w, base + 8) + at, bytes)
        put(w, EMIT_FINITE_SIDE, 0)
        return emit_finite_base_wire(o, w)
    if state == EMIT_FINITE_WIRE:
        if (plan_ok(s) == False or size < 80 or size > 1048584
                or input_word(s, 72) != EMIT_FINITE_PROGRAM):
            return BAD
        fragment(o, 0, fd, 8, size - 8)
        return action(o, w, EMIT_FINITE_EXECUTED, RUN, EMIT_FINITE_VM_ROLE, 0, 1, 0)
    if state == EMIT_FINITE_EXECUTED:
        if (size != 32 and size != 40) or input_word(s, 64) != EMIT_FINITE_PROGRAM_REPLY:
            return BAD
        side = get(w, EMIT_FINITE_SIDE)
        if side == 0:
            sample_span(s, w, EMIT_FINITE_LEFT)
            put(w, EMIT_FINITE_SIDE, 1)
            return emit_finite_candidate_wire(o, w)
        if side != 1:
            return BAD
        put(o, HEADER, EMIT_FINITE_JOIN)
        put(o, HEADER + 8, get(w, EMIT_FINITE_LEFT + 16))
        put(o, HEADER + 16, size)
        use_span(w, o, EMIT_FINITE_EXPECTATION, 0)
        use_span(w, o, EMIT_FINITE_LEFT, 1)
        fragment(o, 2, fd, 0, size)
        return action(o, w, EMIT_FINITE_CHECKED, RUN, EMIT_FINITE_OBSERVATION_ROLE, 0, 3, 24)
    if state == EMIT_FINITE_CHECKED:
        return emit_independent_verdict(s, o, w, EMIT_FINITE_OBSERVATION, 2)
    return BAD

def emit_independent_verdict(s:readbuf, o:mutbuf, w:mutbuf, tag:u64, outcome:u64) -> u64:
    if (plan_ok(s) == False or input_word(s, 40) != 32 or input_word(s, 72) != tag
            or input_word(s, 80) != 0 or input_word(s, 88) != outcome):
        return BAD
    copy_span(s, w, 72, EMIT_PROOF_VERDICTS + 48 * get(w, EMIT_PROOF_INDEX) + 24, 24)
    return emit_proof_record_local(o, w)
'''


def finite_replay_constants():
    values = {
        'EMIT_FINITE_PROJECTION': b'HIAFRP01',
        'EMIT_FINITE_JOIN': b'HIAFRJ01',
    }
    return {
        **{name: int.from_bytes(tag, 'little') for name, tag in values.items()},
        **{f'EMIT_FINITE_{name}': 592 + i for i, name in enumerate(
            ('FRAME', 'PROJECTED', 'WIRE', 'EXECUTED', 'CHECKED'))},
        **{f'EMIT_FINITE_{name}': 5760 + 24 * i for i, name in enumerate(
            ('INPUT', 'EXPECTATION', 'CASE', 'LEFT'))},
        'EMIT_FINITE_SIDE': 5856, 'EMIT_FINITE_OBSERVATION': FINITE_OBSERVATION,
        'EMIT_FINITE_PROGRAM': PROGRAM_MAGIC, 'EMIT_FINITE_PROGRAM_REPLY': PROGRAM_RESULT,
        'EMIT_FINITE_OBSERVATION_ROLE': 57, 'EMIT_FINITE_REFERENCE_ROLE': 58,
        'EMIT_FINITE_VM_ROLE': 59,
    }


def finite_replay_source():
    return (
        FINITE,
        splice_list('emit_finite_counterexample_frame', 'EMIT_FINITE_FRAME',
                    ('EMIT_PROOF_BASE_CORE', 'INSPECTION_CORE', 'EMIT_PROOF_EVIDENCE')),
        splice_list('emit_finite_base_wire', 'EMIT_FINITE_WIRE',
                    ('EMIT_PROOF_BASE_CORE', 'EMIT_FINITE_CASE'), role='EMIT_FINITE_REFERENCE_ROLE'),
        splice_list('emit_finite_candidate_wire', 'EMIT_FINITE_WIRE',
                    ('INSPECTION_CORE', 'EMIT_FINITE_CASE'), role='EMIT_FINITE_REFERENCE_ROLE'),
    )
