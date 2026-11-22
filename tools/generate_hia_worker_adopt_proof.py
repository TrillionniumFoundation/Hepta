"""Reuse the native retained-proof reactor for Adopt's ordered acceptance."""

from pathlib import Path
import ast

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_worker_context_flow import flow_source, function
from tools.generate_hia_worker_emit_flow import ADMISSION, PROFILES, native_recipe
from tools.generate_hia_worker_emit_measurement import splice_list
from tools.generate_hia_worker_emit_proof import proof_recipe

SOURCE = Path('examples/hia_bootstrap/worker_adopt_proof.hepta')
WORKSPACE_BYTES = 10752

ADOPT_PROOF = r'''
def adopt_proof_start(o:mutbuf, w:mutbuf) -> u64:
    count = get(w, EMIT_RECEIPT_COUNT)
    if count < 1 or count > 16:
        return BAD
    put(w, ADOPT_PROOF_CURSOR, 0)
    return adopt_proof_prepare(w, 0)

def adopt_proof_prepare(w:mutbuf, index:u64) -> u64:
    # The front independently reopens the context and installed profiles before
    # returning with the exact index. No receipt is read before that custody.
    put(w, EMIT_STAGE, 6)
    put(w, EMIT_OPERAND, index)
    put(w, EMIT_PROOF_PROFILE_PHASE, 1)
    put(w, 0, ADOPT_PROFILES_REQUIRED)
    return ADOPT_DEFER_FRONT

def adopt_proof_accepted(o:mutbuf, w:mutbuf) -> u64:
    count = get(w, EMIT_RECEIPT_COUNT)
    index = get(w, ADOPT_PROOF_CURSOR)
    if index >= count or index != get(w, EMIT_OPERAND) or get(w, EMIT_PROOF_RECORD + 16) < 2:
        return BAD
    # Hold the exact raw Store observation, not an unverified second read.
    move_fragment(w, EMIT_PROOF_RECORD, ADOPT_RECEIPTS + 24 * index)
    index = index + 1
    put(w, ADOPT_PROOF_CURSOR, index)
    if index < count:
        return adopt_proof_prepare(w, index)
    return adopt_claim_input(o, w, False)

def adopt_claim_input(o:mutbuf, w:mutbuf, continuation:bool) -> u64:
    count = get(w, EMIT_RECEIPT_COUNT)
    # The carrier permits at most 32 fragments. For nine or more receipts,
    # seal the exact initial prefix and use it once in the final command.
    start = choose(continuation, 8, 0)
    stop = choose(continuation or count <= 8, count, 8)
    lead = choose(continuation, 0, 1)
    fragments = 0
    at = HEADER + lead
    store(o, 384, 44)
    put(o, 392, 23340)
    put(o, 400, 23901)
    if continuation:
        vector_span(w, o, ADOPT_CLAIM_PREFIX, at)
        at = at + 24
        fragments = 1
    else:
        store(o, HEADER, 91)
        index = 0
        while index < 4:
            if index != 0:
                vector_part(o, at, INLINE_FRAGMENT, 384, 1)
                at = at + 24
                fragments = fragments + 1
            vector_span(w, o, ADOPT_CLAIM_FIELDS + 24 * index, at)
            at = at + 24
            fragments = fragments + 1
            index = index + 1
        vector_part(o, at, INLINE_FRAGMENT, 392, 2)
        at = at + 24
        fragments = fragments + 1
    index = start
    while index < stop:
        if index != 0:
            vector_part(o, at, INLINE_FRAGMENT, 384, 1)
            at = at + 24
            fragments = fragments + 1
        vector_span(w, o, ADOPT_RECEIPTS + 24 * index, at)
        at = at + 24
        fragments = fragments + 1
        index = index + 1
    if stop != count:
        return emit_wide_make(o, w, ADOPT_CLAIMS_PREFIX_READY, fragments, lead)
    vector_part(o, at, INLINE_FRAGMENT, 400, 2)
    return wide_inspection(o, w, ADOPT_CLAIMS_OBSERVED, ADOPT_CLAIMS_ROLE, 0, fragments + 1, lead)

def adopt_claim_reply(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    size = input_word(s, 40)
    fd = input_word(s, 32)
    if state == ADOPT_CLAIMS_PREFIX_READY:
        if size < 10 or get(w, EMIT_RECEIPT_COUNT) <= 8:
            return BAD
        sample_span(s, w, ADOPT_CLAIM_PREFIX)
        return adopt_claim_input(o, w, True)
    if state == ADOPT_CLAIMS_OBSERVED:
        if plan_ok(s) == False or size < 32 or size > 96:
            return BAD
        body_span(s, w, ADOPT_CLAIM_SCHEDULE)
        return read_span(o, w, ADOPT_CLAIMS_BOUND, fd, 8, size - 8)
    if length(s) < 88 or input_word(s, 64) != ADOPT_CLAIM_TAG:
        return BAD
    missing = input_word(s, 72)
    rechecks = input_word(s, 80)
    if missing > 4 or rechecks > 64 or length(s) != 88 + rechecks:
        return BAD
    index = 0
    while index < rechecks:
        if byte(s, 88 + index) >= get(w, EMIT_RECEIPT_COUNT):
            return BAD
        index = index + 1
    put(w, 0, ADOPT_CLAIMS_READY)
    return ADOPT_DEFER_FRONT
'''

ADOPT_EVIDENCE = r'''
def adopt_open_evidence(o:mutbuf, w:mutbuf, purpose:u64) -> u64:
    reference = ADOPT_EVALUATION_REF
    if purpose != READ_ADOPT_EVALUATION:
        reference = ADOPT_EVAL_FIELDS + choose(purpose == READ_ADOPT_MEASUREMENTS, 48, 72)
    if get(w, reference + 16) != 176:
        return BAD
    move_fragment(w, reference, INSPECTION_REFERENCE)
    return emit_proof_read(o, w, purpose, 12 + purpose - READ_ADOPT_EVALUATION)

def adopt_evidence_reopened(s:readbuf, o:mutbuf, w:mutbuf, purpose:u64) -> u64:
    if purpose == READ_ADOPT_EVALUATION:
        if input_word(s, 40) < 2:
            return BAD
        sample_span(s, w, ADOPT_EVAL_RECORD)
        return adopt_evaluation_input(o, w)
    # Retaining the measurements and cost bytes is required even for a later
    # net-benefit refusal, but neither document may provide execution authority.
    if purpose == READ_ADOPT_MEASUREMENTS:
        return adopt_open_evidence(o, w, READ_ADOPT_COST)
    put(w, 0, ADOPT_MEASURES_READY)
    return ADOPT_DEFER_FRONT

def adopt_evaluation_reply(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    fd = input_word(s, 32)
    size = input_word(s, 40)
    if state == ADOPT_EVAL_PACKET_READY:
        if size < 32 or size > 8388608:
            return BAD
        sample_span(s, w, ADOPT_EVAL_PACKET)
        use_span(w, o, ADOPT_EVAL_PACKET, 0)
        return action(o, w, ADOPT_EVAL_OBSERVED, RUN, ADOPT_AUTHORITY_ROLE, 0, 1, 0)
    if state == ADOPT_EVAL_OBSERVED:
        if plan_ok(s) == False or (size != 24 and size != 104) or input_word(s, 72) != ADOPT_EVAL_TAG:
            return BAD
        status = input_word(s, 80)
        if size == 24 and status == 1:
            put(w, 0, ADOPT_EVAL_BINDING_REFUSED)
            return ADOPT_DEFER_FRONT
        if size != 104 or status != 0:
            return BAD
        return read_span(o, w, ADOPT_EVAL_BOUND, fd, 8, 96)
    if length(s) != 160 or input_word(s, 64) != ADOPT_EVAL_TAG or input_word(s, 72) != 0:
        return BAD
    packet_fd = get(w, ADOPT_EVAL_PACKET)
    base = get(w, ADOPT_EVAL_PACKET + 8)
    extent = get(w, ADOPT_EVAL_PACKET + 16)
    idx = 0
    while idx < 5:
        start = input_word(s, 80 + 16 * idx)
        bytes = input_word(s, 88 + 16 * idx)
        if start > extent or bytes > extent - start or bytes != choose(idx == 0, 66, 176):
            return BAD
        hold(w, ADOPT_EVAL_FIELDS + 24 * idx, packet_fd, base + start, bytes)
        idx = idx + 1
    put(w, 0, ADOPT_EVAL_READY)
    return ADOPT_DEFER_FRONT
'''


def adopt_proof_constants(constants):
    constants.update(
        ADOPT_PROOF_START=1100, ADOPT_CLAIMS_PREFIX_READY=1101, ADOPT_CLAIMS_OBSERVED=1102,
        ADOPT_CLAIMS_BOUND=1103, ADOPT_CLAIMS_READY=1104, ADOPT_PROFILES_REQUIRED=1105,
        ADOPT_CLAIMS_ROLE=constants['EMIT_TRUST_ROLE'] + 1,
        ADOPT_DEFER_FRONT=4294967278, ADOPT_CLAIM_FIELDS=9216, ADOPT_RECEIPTS=9312,
        ADOPT_PROOF_CURSOR=9696, ADOPT_CLAIM_PREFIX=9704, ADOPT_CLAIM_SCHEDULE=9728,
        ADOPT_CLAIM_TAG=int.from_bytes(b'HIAADK01', 'little'),
        READ_ADOPT_EVALUATION=17, READ_ADOPT_MEASUREMENTS=18, READ_ADOPT_COST=19,
        ADOPT_EVAL_START=1110, ADOPT_MEASURES_START=1111, ADOPT_EVAL_PACKET_READY=1112,
        ADOPT_EVAL_OBSERVED=1113, ADOPT_EVAL_BOUND=1114, ADOPT_EVAL_READY=1115,
        ADOPT_EVAL_BINDING_REFUSED=1116, ADOPT_MEASURES_READY=1117,
        ADOPT_EVALUATION_REF=9752, ADOPT_EVAL_RECORD=9776, ADOPT_EVAL_PACKET=9800,
        ADOPT_EVAL_FIELDS=9824, ADOPT_AUTHORITY_ROLE=constants['EMIT_TRUST_ROLE'] + 2,
        ADOPT_EVAL_TAG=int.from_bytes(b'HIAADR01', 'little'),
    )


def adopt_proof_recipe(constants):
    """Share the verified proof chain; change only the successful continuation."""
    adopt_proof_constants(constants)
    entry, controls = proof_recipe(
        function(ADMISSION, 'emit_admission_error'), function(PROFILES, 'emit_open_profile'),
        finish_retained='adopt_proof_accepted(o, w)',
    )
    entry = entry.replace('def emit_proof_flow(', 'def adopt_proof_flow(')
    entry = entry.replace('    state = get(w, 0)', '''    if length(o) != 2048 or length(w) != EMIT_WORK_BYTES:
        return BAD
    state = get(w, 0)
    if state == ADOPT_PROOF_START:
        return adopt_proof_start(o, w)
    if state >= ADOPT_CLAIMS_PREFIX_READY and state <= ADOPT_CLAIMS_BOUND:
        return adopt_claim_reply(s, o, w, state)
    if state == ADOPT_EVAL_START or state == ADOPT_MEASURES_START:
        purpose = choose(state == ADOPT_EVAL_START, READ_ADOPT_EVALUATION, READ_ADOPT_MEASUREMENTS)
        return adopt_open_evidence(o, w, purpose)
    if state >= ADOPT_EVAL_PACKET_READY and state <= ADOPT_EVAL_BOUND:
        return adopt_evaluation_reply(s, o, w, state)''')
    start = entry.index('        if stage == 8:')
    stop = entry.index('        return emit_retained_proof(', start)
    entry = entry[:start] + entry[stop:]
    entry = entry.replace(
        '    if state == RETAINED_BYTES:\n',
        '    if state == RETAINED_BYTES:\n'
        '        purpose = get(w, RETAINED_PURPOSE)\n'
        '        if purpose >= READ_ADOPT_EVALUATION and purpose <= READ_ADOPT_COST:\n'
        '            return adopt_evidence_reopened(s, o, w, purpose)\n',
    ).replace(
        '        if get(w, RETAINED_PURPOSE) == READ_EMIT_PLAN:\n'
        '            return emit_plan_reopened(s, o, w)\n', '',
    ).replace(
        '    if state >= EMIT_PLAN_CANONICAL and state <= EMIT_PLAN_REGISTER_LAYOUT:\n'
        '        return emit_plan_state(s, o, w, state)\n', '',
    )
    evaluation_packet = splice_list('adopt_evaluation_input', 'ADOPT_EVAL_PACKET_READY',
                                    ('EMIT_INSTALLATION', 'EMIT_FIELDS + 24',
                                     'ADOPT_CLAIM_FIELDS + 24', 'ADOPT_EVAL_RECORD'))
    policy = '\n'.join((entry, *controls, ADOPT_PROOF, ADOPT_EVIDENCE, evaluation_packet))
    # Explicit Emit plans are never requested by Adopt. Retained plan subjects
    # still take their checked replay path.
    start = policy.index('    if state == EMIT_PLAN_RAW_HASH:')
    stop = policy.index('    if state == EMIT_REPLAY_OBJECT_HASH:', start)
    policy = policy[:start] + policy[stop:]
    start = policy.index('    if state == EMIT_PROOF_RENDERED_SUBJECT:')
    stop = policy.index('    return emit_proof_custody_state(', start)
    policy = policy[:start] + policy[stop:]
    start = policy.index('    if input_word(s, 72) != EMIT_SCOPE_PLAN_COMPLETE')
    stop = policy.index('\ndef emit_requested_plan_subject(', start)
    policy = policy[:start] + '    return BAD\n' + policy[stop:]
    # Keep only functions reachable from the Adopt entry. This also avoids
    # putting uncallable Emit production and consumer roles in the carrier.
    return reachable_policy(policy, 'adopt_proof_flow')


def reachable_policy(policy, entry):
    nodes = ast.parse(policy).body
    functions = {node.name: node for node in nodes}
    if len(functions) != len(nodes):
        raise ValueError('duplicate function in native Worker continuation')
    live = set()
    pending = [entry]
    while pending:
        name = pending.pop()
        if name not in live:
            live.add(name)
            pending.extend(node.func.id for node in ast.walk(functions[name])
                           if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                           and node.func.id in functions)
    return function(policy, entry), tuple(
        function(policy, name) for name in functions if name in live and name != entry)


def program():
    constants, _front, _transport = native_recipe()
    constants.update(ROLE_COUNT=constants['ROLE_COUNT'] + 2, EMIT_WORK_BYTES=WORKSPACE_BYTES)
    entry, controls = adopt_proof_recipe(constants)
    return flow_source(entry, controls, constants)


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)), encoding='utf-8')
