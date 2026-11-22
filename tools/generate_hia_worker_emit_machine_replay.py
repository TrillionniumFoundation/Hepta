"""Author Emit's independent proof replay over retained Core and ELF custody."""

from tools.generate_hia_worker_emit_measurement import splice_list
from tools.generate_hia_worker_machine_replay import (
    NATIVE_ANCHOR, NATIVE_ANCHOR_BYTES, NATIVE_ANCHOR_HEAD, NATIVE_FINISH, TYPED_REQUEST,
)
from tools.generate_hia_supplied_safe_core_proof import OUTPUT_LIMIT, RECEIPT_HEAD, TYPED_REQUEST_MAGIC
from tools.hia_retained_proof_method import MACHINE_VERDICT


MACHINE = r'''
def emit_machine_proof(o:mutbuf, w:mutbuf, native:bool) -> u64:
    if get(w, EMIT_PROOF_SUBJECT) != 4 or get(w, EMIT_CUSTODY_OBSERVATION + 16) != 24:
        return BAD
    if get(w, INSPECTION_EXPORTS + 16) != 2 or get(w, EMIT_CONTEXT_ROW + 16) == 0:
        return BAD
    put(w, EMIT_MACHINE_NATIVE_MODE, choose(native, 1, 0))
    if native:
        return inspection_hash(o, w, EMIT_MACHINE_IMAGE_HASH, EMIT_MACHINE_IMAGE)
    return emit_machine_evidence(o, w)

def emit_machine_proof_state(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    fd = input_word(s, 32)
    size = input_word(s, 40)
    if state == EMIT_MACHINE_NATIVE_ANCHORED:
        if (plan_ok(s) == False or size != 8 + EMIT_MACHINE_NATIVE_ANCHOR_BYTES
                or input_word(s, 72) != EMIT_MACHINE_NATIVE_ANCHOR or input_word(s, 80) != 0):
            return BAD
        body_span(s, w, EMIT_MACHINE_BINDING)
        hold(w, INSPECTION_REFERENCE, fd, 8 + EMIT_MACHINE_NATIVE_ANCHOR_HEAD, 176)
        return emit_proof_read(o, w, READ_EMIT_MACHINE_CERTIFICATE, 15)
    if state == EMIT_MACHINE_ANCHORED:
        if (plan_ok(s) == False or size != 1304 or input_word(s, 72) != EMIT_MACHINE_ANCHOR
                or input_word(s, 80) != 0):
            return BAD
        body_span(s, w, EMIT_MACHINE_BINDING)
        put(w, EMIT_MACHINE_QUERY_INDEX, 0)
        return emit_machine_next_query(o, w)
    if state == EMIT_MACHINE_CLOCK:
        if length(s) != 72 or size != 8:
            return BAD
        put(o, HEADER, EMIT_ADMISSION_WINDOW)
        put(o, HEADER + 8, 2)
        put(o, HEADER + 16, get(w, EMIT_WALL_LIMIT))
        put(o, HEADER + 24, input_word(s, 64))
        use_span(w, o, EMIT_FIELDS + 24, 0)
        use_span(w, o, EMIT_CONTEXT_ROW, 1)
        return action(o, w, EMIT_MACHINE_WALL, RUN, INSPECTION_REQUEST_ROLE, 0, 2, 32)
    if state == EMIT_MACHINE_WALL:
        if (plan_ok(s) == False or size != 32 or input_word(s, 72) != EMIT_WINDOW_RESULT
                or input_word(s, 80) != 0 or input_word(s, 88) < 100):
            return BAD
        remaining = input_word(s, 88)
        native = get(w, EMIT_MACHINE_NATIVE_MODE) == 1
        put(o, HEADER, choose(native, EMIT_MACHINE_TYPED_REQUEST, EMIT_MACHINE_REQUEST))
        put(o, HEADER + 8, choose(remaining > 60000, 60000, remaining))
        put(o, HEADER + 16, get(w, INSPECTION_CORE + 16))
        put(o, HEADER + 24, get(w, EMIT_CUSTODY_OBJECT + 16))
        put(o, HEADER + 32, get(w, EMIT_CUSTODY_NATIVE + 16))
        return action(o, w, EMIT_MACHINE_HEADER, RUN, EMIT_MACHINE_REPLAY_ROLE, 0, 0, 40)
    if state == EMIT_MACHINE_HEADER:
        native = get(w, EMIT_MACHINE_NATIVE_MODE) == 1
        expected = choose(native, EMIT_MACHINE_PROVER_TYPED_REQUEST, EMIT_MACHINE_PROVER_REQUEST)
        if plan_ok(s) == False or size != 56 or input_word(s, 72) != expected:
            return BAD
        vector_part(o, HEADER, fd, 8, 48)
        vector_span(w, o, INSPECTION_CORE, HEADER + 24)
        vector_span(w, o, EMIT_CUSTODY_OBJECT, HEADER + 48)
        vector_span(w, o, EMIT_CUSTODY_NATIVE, HEADER + 72)
        return wide_inspection(o, w, EMIT_MACHINE_PROVED, EMIT_MACHINE_PROVER_ROLE, 0, 4, 0)
    if state == EMIT_MACHINE_PROVED:
        if size < EMIT_MACHINE_PROVER_HEAD or size > EMIT_MACHINE_PROVER_MAX or input_word(s, 64) != EMIT_MACHINE_PROVER_REPLY:
            return BAD
        if get(w, EMIT_MACHINE_NATIVE_MODE) == 1:
            if size != get(w, EMIT_MACHINE_CERTIFICATE + 16) or fd == get(w, EMIT_MACHINE_CERTIFICATE):
                return BAD
            put(o, HEADER, EMIT_MACHINE_NATIVE_FINISH)
            put(o, HEADER + 8, size)
            vector_span(w, o, EMIT_MACHINE_BINDING, HEADER + 16)
            vector_span(w, o, EMIT_MACHINE_CERTIFICATE, HEADER + 40)
            vector_part(o, HEADER + 64, fd, 0, size)
            return wide_inspection(o, w, EMIT_MACHINE_CHECKED, EMIT_MACHINE_REPLAY_ROLE, 0, 3, 16)
        put(o, HEADER, EMIT_MACHINE_FINISH)
        put(o, HEADER + 8, size)
        binding = EMIT_MACHINE_BINDING
        fragment(o, 0, get(w, binding), get(w, binding + 8), 416)
        fragment(o, 1, fd, 0, size)
        return action(o, w, EMIT_MACHINE_CHECKED, RUN, EMIT_MACHINE_REPLAY_ROLE, 0, 2, 16)
    if state == EMIT_MACHINE_CHECKED:
        return emit_independent_verdict(s, o, w, EMIT_MACHINE_VERDICT, 1)
    return BAD

def emit_machine_next_query(o:mutbuf, w:mutbuf) -> u64:
    index = get(w, EMIT_MACHINE_QUERY_INDEX)
    if index == 5:
        return clock_sample(o, w, EMIT_MACHINE_CLOCK, 1)
    if index > 5:
        return BAD
    binding = EMIT_MACHINE_BINDING
    hold(w, INSPECTION_REFERENCE, get(w, binding), get(w, binding + 8) + 416 + 176 * index, 176)
    return emit_proof_read(o, w, READ_EMIT_MACHINE_QUERY, 11)

def emit_machine_query_reopened(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if input_word(s, 40) < 2 or input_word(s, 40) > 8388608:
        return BAD
    # store-get verified the whole physical extent against the exact query
    # reference; it is custody evidence, never submitted to the new solver.
    put(w, EMIT_MACHINE_QUERY_INDEX, get(w, EMIT_MACHINE_QUERY_INDEX) + 1)
    return emit_machine_next_query(o, w)
'''


def machine_replay_constants():
    tags = {'ANCHOR': b'HIAMAP01', 'REQUEST': b'HIAMRQ01', 'FINISH': b'HIAMRV01',
            'PROVER_REQUEST': b'HIAPRF01', 'PROVER_REPLY': b'HIAPRR01'}
    states = ('ANCHORED', 'CLOCK', 'WALL', 'HEADER', 'PROVED', 'CHECKED')
    return {
        **{f'EMIT_MACHINE_{key}': int.from_bytes(value, 'little') for key, value in tags.items()},
        **{f'EMIT_MACHINE_{key}': 632 + i for i, key in enumerate(states)},
        'EMIT_MACHINE_BINDING': 5864, 'EMIT_MACHINE_QUERY_INDEX': 5888,
        'EMIT_MACHINE_REPLAY_ROLE': 63, 'EMIT_MACHINE_PROVER_ROLE': 64,
        'EMIT_MACHINE_VERDICT': MACHINE_VERDICT, 'READ_EMIT_MACHINE_QUERY': 16,
        'EMIT_MACHINE_IMAGE_HASH': 638, 'EMIT_MACHINE_NATIVE_ANCHORED': 639,
        'EMIT_MACHINE_IMAGE': 9000, 'EMIT_MACHINE_PIN': 9024,
        'EMIT_MACHINE_CERTIFICATE': 9048, 'EMIT_MACHINE_NATIVE_MODE': 9072,
        'EMIT_MACHINE_NATIVE_ANCHOR': NATIVE_ANCHOR, 'EMIT_MACHINE_NATIVE_FINISH': NATIVE_FINISH,
        'EMIT_MACHINE_NATIVE_ANCHOR_BYTES': NATIVE_ANCHOR_BYTES,
        'EMIT_MACHINE_NATIVE_ANCHOR_HEAD': NATIVE_ANCHOR_HEAD,
        'EMIT_MACHINE_TYPED_REQUEST': TYPED_REQUEST, 'EMIT_MACHINE_PROVER_TYPED_REQUEST': TYPED_REQUEST_MAGIC,
        'EMIT_MACHINE_PROVER_HEAD': RECEIPT_HEAD, 'EMIT_MACHINE_PROVER_MAX': OUTPUT_LIMIT,
        'READ_EMIT_MACHINE_CERTIFICATE': 22,
    }


def machine_replay_source():
    return (
        MACHINE,
        splice_list('emit_machine_evidence', 'EMIT_MACHINE_ANCHORED',
                    ('EMIT_PROOF_EVIDENCE', 'EMIT_CUSTODY_NATIVE_REF', 'EMIT_CUSTODY_BUILD_REF',
                     'EMIT_CUSTODY_OBJECT_REF'), role='EMIT_MACHINE_REPLAY_ROLE'),
        splice_list('emit_machine_native_evidence', 'EMIT_MACHINE_NATIVE_ANCHORED',
                    ('EMIT_PROOF_EVIDENCE', 'EMIT_CUSTODY_NATIVE_REF', 'EMIT_CUSTODY_BUILD_REF',
                     'EMIT_CUSTODY_OBJECT_REF', 'EMIT_PROOF_CANDIDATE_SHA', 'EMIT_MACHINE_PIN'),
                    role='EMIT_MACHINE_REPLAY_ROLE'),
    )
