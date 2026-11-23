"""Author the private, single-reservation handoff after native Evaluate intake."""

from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_worker_artifact_flow import STORE_POLICY
from tools.generate_hia_worker_inspection_effect import function

SOURCE = Path('examples/hia_bootstrap/worker_evaluate_claim_flow.hepta')

CLAIM_POLICY = r'''
def journal_action(o:mutbuf, w:mutbuf) -> u64:
    stage = get(w, JOURNAL_STAGE)
    next = get(w, JOURNAL_NEXT)
    if stage == 9:
        return send_journal(o, w, 0)
    if stage == 0:
        return open_store(o, w, OPEN_LOOKUP)
    if stage == 1:
        if get(w, CLAIM_ACTIVE) == 1 and next == 2:
            return clock_sample(o, w, RESERVATION_CLOCK, 1)
        return close_store(o, w, CLOSED_LOOKUP)
    if stage == 2 and next == 11 and get(w, CLAIM_ACTIVE) == 1:
        copy_private(w, o, JOURNAL_ROUTE, HEADER + 48, 64)
        return store_transaction(o, w, STORE_RESERVATION_COMMIT, 23, 0, 0, 0, 64)
    return BAD

def opened_store(o:mutbuf, w:mutbuf) -> u64:
    if get(w, STORE_PURPOSE) == OPEN_INTAKE:
        return opened_intake(o, w)
    if get(w, STORE_PURPOSE) == OPEN_LOOKUP:
        return typed_request(o, w, STORE_LOOKUP, 0)
    return BAD

def claim_transition(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    if state == RESERVATION_CLOCK:
        if length(s) != 72 or input_word(s, 40) != 8 or get(w, CLAIM_ACTIVE) != 1:
            return BAD
        now = input_word(s, 64)
        deadline = get(w, UTC_DEADLINE)
        if now < get(w, WINDOW_UTC) or now >= deadline or deadline - now < 1000000:
            return close_store(o, w, CLOSE_REFUSED)
        put(w, CLAIM_UTC, now)
    return typed_job(s, o, w, state)

def claimed_input(o:mutbuf, w:mutbuf) -> u64:
    # Only the real unique Store transaction can reach this point, after
    # both the reserve and the typed lifecycle commit have been acknowledged.
    if get(w, CLAIM_ACTIVE) != 1 or get(w, JOURNAL_STAGE) != 2 or get(w, JOURNAL_NEXT) != 11:
        return BAD
    if slot_bytes(w, STORE_RESULT) != 56 or slot_bytes(w, CLAIM_INPUT) != 112 + get(w, COMBINED_BYTES):
        return BAD
    put(o, HEADER, CLAIMED_HANDOFF)
    put(o, HEADER + 8, slot_bytes(w, CLAIM_INPUT))
    put(o, HEADER + 16, get(w, STORE_REQUEST))
    put(o, HEADER + 24, get(w, STORE_EPOCH))
    put(o, HEADER + 32, get(w, CLAIM_UTC))
    put(o, HEADER + 40, 512)
    put(o, HEADER + 48, 64)
    put(o, HEADER + 56, 8)
    copy_private(w, o, JOURNAL_STATE, HEADER + 64, 512)
    copy_private(w, o, JOURNAL_ROUTE, HEADER + 576, 64)
    fragment(o, 0, slot_fd(w, STORE_RESULT), 0, 8)
    whole_slot(w, o, CLAIM_INPUT, 1)
    return action(o, w, CLAIM_HANDOFF_READY, MAKE, 0, 0, 2, 640)

def publish_claim(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    size = input_word(s, 40)
    if size != 648 + slot_bytes(w, CLAIM_INPUT) or size > 67108864:
        return BAD
    fragment(o, 0, input_word(s, 32), 0, size)
    return action(o, w, INTAKE_PUBLISHED, PUBLISH, 0, 0, 1, 0)
'''


def reservation_recipe(driver, policy, controls, constants):
    constants.update(CLAIM_ACTIVE=3144, CLAIM_UTC=3152, CLAIM_INPUT=23,
                     CLAIM_INPUT_MADE=100, CLAIM_HANDOFF_READY=101,
                     CLAIMED_HANDOFF=int.from_bytes(b'HIAEJC01', 'little'))
    driver = driver.replace('    if state == TYPED_REQUEST or state == TYPED:\n        return typed_lookup(s, o, w, state)',
                            '    if state == RESERVATION_CLOCK or state == TYPED_REQUEST or state == TYPED:\n'
                            '        return claim_transition(s, o, w, state)')
    driver = driver.replace('    return stage == 3 and next == 19',
                            '    if stage == 2:\n        return next == 11 and status == 0\n'
                            '    return stage == 3 and next == 19')
    for name in ('journal_action', 'opened_store', 'typed_lookup'):
        driver = driver.replace(function(driver, name).strip(), '')
    policy = policy.replace('    if purpose == CLOSED_LOOKUP and get(w, JOURNAL_NEXT) == 2:',
                            '    if purpose == CLOSED_RESERVATION:\n        return claimed_input(o, w)\n'
                            '    if purpose == CLOSED_LOOKUP and get(w, CLAIM_ACTIVE) == 0 and get(w, JOURNAL_NEXT) == 2:')
    policy = policy.replace('    return action(o, w, INTAKE_PUBLISHED, PUBLISH, 0, 0, 1, 112)',
                            '    return action(o, w, CLAIM_INPUT_MADE, MAKE, 0, 0, 1, 112)')
    policy = policy.replace('    if state == PREFIX_MADE:', '''    if state == CLAIM_INPUT_MADE:
        if size != 112 + get(w, COMBINED_BYTES) or size > 67108864 - 648:
            return BAD
        observe_slot(s, w, CLAIM_INPUT)
        put(w, CLAIM_ACTIVE, 1)
        return send_journal(o, w, 9)
    if state == CLAIM_HANDOFF_READY:
        return publish_claim(s, o, w)
    if state == PREFIX_MADE:''')
    updated = []
    for part in controls:
        if part.lstrip().startswith('def settle_transaction('):
            part = part.replace('    return inspect_row(o, w, purpose, bytes)', '''    if purpose == STORE_RESERVATION:
        if found != 1 or bytes != 0:
            return BAD
        return send_journal(o, w, 2)
    if purpose == STORE_RESERVATION_COMMIT:
        if found != 1 or bytes != 8:
            return BAD
        return close_store(o, w, CLOSED_RESERVATION)
    return inspect_row(o, w, purpose, bytes)''')
        updated.append(part)
    updated.extend(function(STORE_POLICY, name) for name in ('typed_request', 'typed_job'))
    return driver, policy + CLAIM_POLICY, updated


if __name__ == '__main__':
    from tools.generate_hia_worker_evaluate_intake_flow import program
    SOURCE.write_text(render_assembly(document(program(claim=True), SOURCE.stem)), encoding='utf-8')
