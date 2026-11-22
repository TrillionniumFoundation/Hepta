"""Author Adopt's authenticated request and evidence continuation."""

import json
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_worker_adopt_custody import custody_constants
from tools.generate_hia_worker_adopt_proof import WORKSPACE_BYTES, adopt_proof_constants, reachable_policy
from tools.generate_hia_worker_candidate_flow import replace_function
from tools.generate_hia_worker_context_flow import flow_source, function
from tools.generate_hia_worker_emit_flow import ADMISSION, DISPATCH, REACTOR, REQUEST, native_recipe
from tools.generate_hia_worker_emit_verification import CLAIMS
from tools.generate_hia_worker_rollback import literal

SOURCE = Path('examples/hia_bootstrap/worker_adopt_flow.hepta')

INTAKE = r'''
def authorize_business(o:mutbuf, w:mutbuf) -> u64:
    inspection_catalog(o, w)
    after_prefix(w, o, ARGUMENT_FD, 0)
    store(o, 496, 93)
    fragment(o, 1, INLINE_FRAGMENT, 496, 1)
    return action(o, w, EMIT_PROJECTED, RUN, ADOPT_AUTHORITY_ROLE, 0, 2, 68)

def adopt_intake(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    size = input_word(s, 40)
    if state == EMIT_PROJECTED:
        if plan_ok(s) == False or input_word(s, 72) != ADOPT_REQUEST or size < 114:
            return BAD
        body_span(s, w, EMIT_REQUEST_BODY)
        put(o, HEADER, ADOPT_INDEX_REQUEST)
        use_span(w, o, EMIT_REQUEST_BODY, 0)
        return action(o, w, EMIT_INDEX_BOUND, RUN, ADOPT_AUTHORITY_ROLE, 0, 1, 8)
    if state == EMIT_INDEX_BOUND:
        if plan_ok(s) == False or input_word(s, 72) != ADOPT_INDEX_RESULT or size < 176 or size > 416:
            return BAD
        return read_span(o, w, EMIT_INDEX_FRAME, input_word(s, 32), 8, size - 8)
    return adopt_intake_fields(s, o, w)

def adopt_intake_fields(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    receipts = input_word(s, 72)
    count = input_word(s, 80)
    if input_word(s, 64) != ADOPT_INDEX_RESULT or receipts < 1 or receipts > 16:
        return BAD
    if count != 8 + receipts or length(s) != 88 + 16 * count:
        return BAD
    put(w, EMIT_RECEIPT_COUNT, receipts)
    base = get(w, EMIT_REQUEST_BODY + 8)
    limit = get(w, EMIT_REQUEST_BODY + 16)
    last = 16
    index = 0
    while index < count:
        at = input_word(s, 88 + 16 * index)
        size = input_word(s, 96 + 16 * index)
        if at != last + 8 or at > limit or size < 2 or size > limit - at:
            return BAD
        last = at + size
        if index >= 8:
            target = EMIT_FIELDS + 96 + 24 * (index - 8)
        elif index >= 3:
            target = ADOPT_INTAKE_FIELDS + 24 * (index - 3)
        else:
            target = choose(index == 0, EMIT_FIELDS + 24,
                        choose(index == 1, ADOPT_CLAIM_FIELDS + 24, ADOPT_EVALUATION_REF))
        hold(w, target, get(w, EMIT_REQUEST_BODY), base + at, size)
        index = index + 1
    if last != limit:
        return BAD
    put(w, EMIT_STAGE, 1)
    return adopt_context(o, w)

def adopt_context(o:mutbuf, w:mutbuf) -> u64:
    move_fragment(w, EMIT_FIELDS + 24, INSPECTION_ACTUAL)
    return inspection_context(o, w)
'''

EVIDENCE = r'''
def adopt_continue(o:mutbuf, w:mutbuf, state:u64) -> u64:
    if state == ADOPT_PROFILES_REQUIRED:
        if get(w, EMIT_STAGE) != 6 or get(w, EMIT_PROOF_PROFILE_PHASE) != 1:
            return BAD
        return adopt_context(o, w)
    if state == ADOPT_EVAL_BINDING_REFUSED:
        return adopt_error(o, w, 1)
    if state == ADOPT_CUSTODY_REFUSED:
        return adopt_error(o, w, get(w, ADOPT_CUSTODY_ERROR))
    if state == ADOPT_EVAL_READY:
        move_fragment(w, ADOPT_EVAL_FIELDS, ADOPT_CLAIM_FIELDS + 48)
        put(w, 0, ADOPT_CUSTODY_START)
        return ADOPT_DEFER_CUSTODY
    if state == ADOPT_PREPARED:
        put(w, 0, ADOPT_PROOF_START)
        return EMIT_DEFER_PROOF
    if state == ADOPT_NATIVE_OPEN_CORE:
        put(w, EMIT_STAGE, 12)
        return inspection_program(o, w)
    if state == ADOPT_BUILD_READY:
        move_fragment(w, ADOPT_OBJECTIVE_REF, INSPECTION_REFERENCE)
        put(w, RETAINED_PURPOSE, READ_ADOPT_OBJECTIVE)
        return inspection_retained_query(o, w, 0)
    if state == ADOPT_CLAIMS_READY:
        put(w, 0, ADOPT_CUSTODY_CLAIMS)
        return ADOPT_DEFER_CUSTODY
    if state == ADOPT_CLAIMS_ACCEPTED:
        store(o, HEADER, 91)
        store(o, 496, 44)
        store(o, 497, 93)
        vector_span(w, o, ADOPT_EVAL_RECORD, HEADER + 1)
        vector_part(o, HEADER + 25, INLINE_FRAGMENT, 496, 1)
        vector_span(w, o, ADOPT_CLAIM_FIELDS, HEADER + 49)
        vector_part(o, HEADER + 73, INLINE_FRAGMENT, 497, 1)
        return wide_inspection(o, w, ADOPT_EVALUATION_VERDICT, ADOPT_AUTHORITY_ROLE, 0, 4, 1)
    if state == ADOPT_MEASURES_READY:
        store(o, HEADER, 91)
        store(o, 496, 93)
        use_span(w, o, ADOPT_CLAIM_FIELDS, 0)
        fragment(o, 1, INLINE_FRAGMENT, 496, 1)
        return action(o, w, ADOPT_BENEFIT_VERDICT, RUN, ADOPT_AUTHORITY_ROLE, 0, 2, 1)
    return BAD

def adopt_evidence_state(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    if state == ADOPT_NO_PLAN:
        if (length(s) != 68 or input_word(s, 40) != 4 or byte(s, 64) != 110
                or byte(s, 65) != 117 or byte(s, 66) != 108 or byte(s, 67) != 108):
            return BAD
        sample_span(s, w, ADOPT_CLAIM_FIELDS + 72)
        return adopt_continue(o, w, ADOPT_BUILD_READY)
    if state == ADOPT_EVALUATION_VERDICT or state == ADOPT_BENEFIT_VERDICT:
        if plan_ok(s) == False or input_word(s, 40) != 24 or input_word(s, 72) != ADOPT_EVAL_TAG:
            return BAD
        status = input_word(s, 80)
        if status != 0:
            if status != choose(state == ADOPT_EVALUATION_VERDICT, 2, 3):
                return BAD
            return adopt_error(o, w, status)
        if state == ADOPT_EVALUATION_VERDICT:
            put(w, 0, ADOPT_MEASURES_START)
            return EMIT_DEFER_PROOF
        put(w, 0, ADOPT_CUSTODY_SLOT)
        return ADOPT_DEFER_CUSTODY
    return BAD

def adopt_after_context(o:mutbuf, w:mutbuf) -> u64:
    stage = get(w, EMIT_STAGE)
    if stage == 1:
        context = EMIT_FIELDS + 24
        if get(w, context + 16) < 44:
            return BAD
        hold(w, ADOPT_CONTEXT_ID, get(w, context), get(w, context + 8) + 7, 36)
        put(w, EMIT_STAGE, 3)
        return emit_admission(o, w, 3, 0)
    if stage == 2:
        put(w, 0, ADOPT_EVAL_START)
        return EMIT_DEFER_PROOF
    if stage == 6 and get(w, EMIT_PROOF_PROFILE_PHASE) == 1:
        return emit_open_profile(o, w, 1, EMIT_PROFILES + 48)
    return BAD

def adopt_after_budget(o:mutbuf, w:mutbuf) -> u64:
    put(w, EMIT_STAGE, 2)
    return adopt_context(o, w)
'''

OUTCOME = r'''
def adopt_error(o:mutbuf, w:mutbuf, status:u64) -> u64:
    at = adopt_error_body(o, status)
    if at == HEADER:
        return BAD
    return action(o, w, ADOPT_ERROR_BODY, MAKE, 0, 0, 0, at - HEADER)

def adopt_outcome(o:mutbuf, w:mutbuf, status:u64, payload:u64) -> u64:
    extent = get(w, payload + 16)
    context = get(w, ADOPT_CONTEXT_ID + 16)
    if extent < 2 or extent > 8192 or (context != 0 and context != 36):
        return BAD
    zero_range(o, HEADER, 68)
    put(o, HEADER, INSPECTION_OUTCOME_TAG)
    put(o, HEADER + 8, status)
    put(o, HEADER + 16, context)
    put(o, HEADER + 24, extent)
    parts = 0
    lead = 68
    if context == 36:
        use_span(w, o, ADOPT_CONTEXT_ID, 0)
        parts = 1
        lead = 32
    use_span(w, o, payload, parts)
    put(w, INSPECTION_STATUS, status)
    put(w, ADOPT_OUTCOME_BYTES, 68 + extent)
    return action(o, w, ADOPT_OUTCOME, MAKE, 0, 0, parts + 1, lead)

def adopt_outcome_state(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    extent = input_word(s, 40)
    if state == ADOPT_ERROR_BODY:
        sample_span(s, w, EMIT_PUBLIC_ERROR)
        return adopt_outcome(o, w, 2, EMIT_PUBLIC_ERROR)
    status = get(w, INSPECTION_STATUS)
    if extent != get(w, ADOPT_OUTCOME_BYTES) or input_word(s, 64) != INSPECTION_OUTCOME_TAG or input_word(s, 72) != status:
        return BAD
    sample_span(s, w, INSPECTION_OUTCOME)
    observe_slot(s, w, EFFECT_FD)
    return end_effect(o, w, status, 68)
'''


def outcome_errors():
    cases = (
        ('E_HIA_RECEIPT_BINDING', 'evaluation does not authorize this candidate/context'),
        ('E_HIA_EVALUATION_REQUIRED', 'evaluation did not meet the frozen correctness/performance acceptance'),
        ('E_HIA_COST_INCOMPLETE', 'full model/discovery/adoption/future-use cost is not established by this prefix; '
                                 'net-benefit requirement cannot pass'),
        ('E_HIA_RECEIPT_BINDING', 'build receipt belongs to a different native subject'),
        ('E_HIA_RECEIPT_BINDING', 'build record differs from retained native metadata'),
        ('E_HIA_RECEIPT_BINDING', 'native artifact belongs to a different context or implementation'),
        ('E_HIA_RECEIPT_BINDING', "native artifact's admitted Core identity differs"),
        ('E_HIA_RECEIPT_BINDING', 'build record differs from actual artifact bytes'),
        ('E_HIA_RECEIPT_BINDING', 'retained object differs from its exact build binding'),
        *(('E_HIA_CLAIM_REQUIRED', 'missing exact proved acceptance claim: ' + claim) for claim in CLAIMS),
        ('E_HIA_ABI', 'candidate and baseline are not ABI compatible'),
        ('E_HIA_RANGE', 'generation must be a canonical u64 decimal string'),
        ('E_HIA_RANGE', 'epoch must be a canonical u64 decimal string'),
    )
    dispatch = ['\ndef adopt_error_body(o:mutbuf, status:u64) -> u64:']
    bodies = []
    for index, (code, message) in enumerate(cases, 1):
        name = f'adopt_error_{index}'
        phase = 'admission'
        if index <= 3 or index == 14:
            phase = 'adoption'
        elif 10 <= index <= 13:
            phase = 'verification'
        body = json.dumps(dict(code=code, message=message, phase=phase, details_artifact=None,
                               retry_action='correct_input'), sort_keys=True, separators=(',', ':'))
        dispatch.extend((f'    if status == {index}:', f'        return {name}(o, HEADER)'))
        bodies.append(literal(name, body))
    return '\n'.join((*dispatch, '    return HEADER', *bodies))


def recipe():
    constants, driver, controls = native_recipe()
    adopt_proof_constants(constants)
    roles = constants['ADOPT_AUTHORITY_ROLE'] + 1
    constants.update(ROLE_COUNT=roles, ENTRY_BYTES=64 + 312 + roles * 40, SCHEMA_TOOL=10,
                     EMIT_WORK_BYTES=WORKSPACE_BYTES, ADOPT_INTAKE_FIELDS=9944, ADOPT_OBJECTIVE_REF=10064,
                     ADOPT_CONTEXT_ID=10088, ADOPT_OUTCOME_BYTES=10112, ADOPT_DEFER_CUSTODY=0xffffffed)
    states = (
        'ADOPT_CUSTODY_START', 'ADOPT_PREPARED', 'ADOPT_CUSTODY_CLAIMS', 'ADOPT_CLAIMS_ACCEPTED',
        'ADOPT_CUSTODY_SLOT', 'ADOPT_EVALUATION_VERDICT', 'ADOPT_BENEFIT_VERDICT',
        'ADOPT_ERROR_BODY', 'ADOPT_OUTCOME',
    )
    constants.update({name: value for value, name in enumerate(states, 1140)})
    constants.update({name: int.from_bytes(tag, 'little') for name, tag in (
        ('ADOPT_REQUEST', b'HIAADQ01'), ('ADOPT_INDEX_REQUEST', b'HIAADI01'),
        ('ADOPT_INDEX_RESULT', b'HIAADI02'),
    )})
    custody_constants(constants)
    driver = driver.replace('def emit_flow(', 'def adopt_flow(')
    driver = driver.replace('    if length(s) < 64 or input_word(s, 0) != OBSERVATION',
        '    if (state == ADOPT_PROFILES_REQUIRED or state == ADOPT_EVAL_READY or state == ADOPT_EVAL_BINDING_REFUSED\n'
        '            or state == ADOPT_PREPARED or state == ADOPT_CLAIMS_READY or state == ADOPT_CLAIMS_ACCEPTED\n'
        '            or state == ADOPT_MEASURES_READY or state == ADOPT_NATIVE_OPEN_CORE\n'
        '            or state == ADOPT_BUILD_READY or state == ADOPT_CUSTODY_REFUSED):\n'
        '        return adopt_continue(o, w, state)\n'
        '    if length(s) < 64 or input_word(s, 0) != OBSERVATION',
    ).replace(
        '    if state >= INSPECTION_SENT and state <= INSPECTION_PEER_CLOSED:\n'
        '        return emit_peer_observation(s, o, w, state)\n', '',
    ).replace(
        '    if state >= EMIT_PROJECTED and state <= EMIT_PEER_OPENED:\n'
        '        return emit_prepare(s, o, w, state)',
        '    if state >= EMIT_PROJECTED and state <= EMIT_INDEX_FRAME:\n'
        '        return adopt_intake(s, o, w, state)',
    ).replace(
        '    return emit_dispatch(w, state)',
        '    if state == ADOPT_EVALUATION_VERDICT or state == ADOPT_BENEFIT_VERDICT or state == ADOPT_NO_PLAN:\n'
        '        return adopt_evidence_state(s, o, w, state)\n'
        '    if state == ADOPT_ERROR_BODY or state == ADOPT_OUTCOME:\n'
        '        return adopt_outcome_state(s, o, w, state)\n'
        '    if state >= ADOPT_CUSTODY_START and state <= ADOPT_CUSTODY_SLOT:\n'
        '        return ADOPT_DEFER_CUSTODY\n'
        '    if state == ADOPT_EVAL_START or state == ADOPT_MEASURES_START or state == ADOPT_PROOF_START:\n'
        '        return EMIT_DEFER_PROOF\n'
        '    if (state >= ADOPT_CLAIMS_PREFIX_READY and state <= ADOPT_CLAIMS_BOUND) or (state >= ADOPT_EVAL_PACKET_READY and state <= ADOPT_EVAL_BOUND):\n'
        '        return EMIT_DEFER_PROOF\n'
        '    if ((state >= ADOPT_NATIVE_METADATA and state <= ADOPT_NATIVE_SIGNATURE_MATCH) or\n'
        '            (state >= ADOPT_CLAIM_FRAME and state <= ADOPT_CLAIM_BUILD_BOUND) or\n'
        '            state == ADOPT_ABI_MATCH or state == ADOPT_EXPECTED_BOUND or\n'
        '            (get(w, ADOPT_CUSTODY_ACTIVE) != 0 and (state == INSPECTION_HASH_RETURNED or state == INSPECTION_HASH_FRAME or\n'
        '             (state >= EMIT_CUSTODY_PROJECTED and state <= EMIT_CUSTODY_VERIFIED)))):\n'
        '        return ADOPT_DEFER_CUSTODY\n'
        '    if state == INSPECTION_HASH_RETURNED or state == INSPECTION_HASH_FRAME or (state >= EMIT_PROOF_BEGIN and state < EMIT_PROOF_LIMIT):\n'
        '        return EMIT_DEFER_PROOF\n'
        '    return BAD',
    )
    selected = []
    for control in controls:
        if control in (REQUEST, REACTOR, DISPATCH):
            continue
        if '\ndef emit_retained_checked(' in control:
            control = control.replace(
                '    if stage == 2:\n        return inspection_feedback(o, w, 2, 0, EMIT_FIELDS + 24)\n'
                '    if (stage == 6 or stage == 9) and get(w, EMIT_PROOF_PROFILE_PHASE) == 1:\n'
                '        return emit_open_profile(o, w, 1, EMIT_PROFILES + 48)\n    return BAD',
                '    return adopt_after_context(o, w)',
            ).replace('return inspection_feedback(o, w, 3, 0, 0)', 'return adopt_after_budget(o, w)'
            ).replace('return inspection_feedback(o, w, get(w, EMIT_STAGE), 1, EMIT_PUBLIC_ERROR)',
                       'return adopt_outcome(o, w, 2, EMIT_PUBLIC_ERROR)'
            ).replace('return inspection_feedback(o, w, 5, 0, 0)',
                       'put(w, 0, ADOPT_NATIVE_CORE_READY)\n        return ADOPT_DEFER_CUSTODY'
            ).replace('return inspection_feedback(o, w, 11, 0, EMIT_WALL_PERMIT)', 'return BAD')
        if '\ndef bind_inspection_field(' in control:
            control = control.replace(
                '    if index == 5:',
                '    if index == 4:\n        hold(w, ADOPT_OBJECTIVE_REF, input_word(s, 32), at, size)\n'
                '    if index == 5:',
            ).replace(
                'return inspection_feedback(o, w, get(w, EMIT_STAGE), 0, 0)',
                'return BAD',
            ).replace(
                '    if reason >= READ_EMIT_PLAN:\n        return EMIT_DEFER_PROOF',
                '    if reason == READ_ADOPT_OBJECTIVE:\n'
                '        sample_span(s, w, ADOPT_CLAIM_FIELDS)\n'
                '        return adopt_continue(o, w, ADOPT_PREPARED)\n'
                '    if reason >= READ_EMIT_PLAN:\n'
                '        return choose(get(w, ADOPT_CUSTODY_ACTIVE) != 0, ADOPT_DEFER_CUSTODY, EMIT_DEFER_PROOF)',
            ).replace(
                '        if get(w, RETAINED_KIND) >= 5:\n            return EMIT_DEFER_PROOF',
                '        if get(w, RETAINED_KIND) >= 5:\n'
                '            return choose(get(w, ADOPT_CUSTODY_ACTIVE) != 0, ADOPT_DEFER_CUSTODY, EMIT_DEFER_PROOF)',
            )
        selected.append(control)
    driver = replace_function(driver, 'inspection_journal_plan',
        function(driver, 'inspection_journal_plan').replace('INSPECTION_REQUEST_ROLE', 'ADOPT_AUTHORITY_ROLE'))
    source = '\n'.join((driver, *selected, INTAKE, EVIDENCE, OUTCOME, outcome_errors(),
                        function(DISPATCH, 'emit_trust_spans'), function(DISPATCH, 'emit_proof_profile_finished')))
    entry, parts = reachable_policy(source, 'adopt_flow')
    return constants, entry, parts


def program():
    constants, entry, parts = recipe()
    return flow_source(entry, parts, constants)


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)), encoding='utf-8')
