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
from tools.generate_hia_worker_emit_proof import proof_recipe
from tools.generate_hia_worker_finite_domain import INELIGIBLE
from tools.generate_hia_worker_inspection_flow import VIEW_DRIVER

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
    if status != 0:
        if (status == EMIT_EXPIRED and get(w, 16) == RUN and length(s) == 64
                and state >= EMIT_COMPLETE_PLAN and state <= EMIT_COMPLETE_RENDERED):
            return verify_finite_partial(o, w)
        return BAD
    if (operation == RUN or operation == MAKE) and valid_fd(input_word(s, 32)) == False:
        return BAD
    if state == RETAINED_BYTES or (state >= VERIFY_PLAN_CANONICAL and state <= VERIFY_PLAN_REGISTERS):
        return verify_plan_observation(s, o, w, state)
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
        if version == 4:
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
    if get(w, INSPECTION_HASH_RESUME) != EMIT_COMPLETE_HASH:
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
    states = ('CANONICAL', 'SCHEDULE', 'REGISTERS', 'ADMITTED', 'INVALID')
    constants.update({f'VERIFY_PLAN_{name}': 1330 + i for i, name in enumerate(states)})
    constants['VERIFY_CANDIDATE_SHA'] = 10608


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
    return reachable_policy('\n'.join((
        ENTRY, FRESH, policy, function(ENTRY_POLICY, 'valid_fd'), SUBJECT_PLAN,
        splice_list('verify_plan_schedule', 'VERIFY_PLAN_SCHEDULE', plan_inputs, role='EMIT_LAYOUT_ROLE'),
        splice_list('verify_plan_registers', 'VERIFY_PLAN_REGISTERS', plan_inputs,
                    role='EMIT_REPLAY_WITNESS_ROLE'),
    )),
                            'verify_finite_flow')


def program():
    constants, _, _ = native_recipe()
    constants.update(EMIT_WORK_BYTES=12288)
    finite_constants(constants)
    plan_constants(constants)
    entry, controls = finite_recipe()
    return flow_source(entry, controls, constants)


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)), encoding='utf-8')
