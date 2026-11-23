"""Retain the authentic public request and inbound monotonic sample across Evaluate stages."""
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_worker_inspection_effect import function

SOURCE = Path('examples/hia_bootstrap/worker_evaluate_run_input_flow.hepta')

# HIAEFH01 carries the same durable HIAEJC01 followed by the original native
# admission and call projections. The clock is sampled before request parsing.
POLICY = '''
def publish_execution_input(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    size = input_word(s,40)
    admitted = slot_bytes(w,ADMITTED_FD)
    call = slot_bytes(w,CALL_FD)
    entered = get(w,64)
    if entered == 0 or entered > get(w,REFERENCE_CLOCKS) or admitted < 2 or call < 10 or admitted > 8388608 or call > 8388616:
        return BAD
    if size != 648 + slot_bytes(w,CLAIM_INPUT) or size + admitted + call + 32 > 67108864:
        return BAD
    put(o,HEADER,RUN_INPUT)
    put(o,HEADER+8,entered)
    put(o,HEADER+16,size)
    put(o,HEADER+24,admitted)
    put(o,HEADER+32,call-8)
    fragment(o,0,input_word(s,32),0,size)
    whole_slot(w,o,ADMITTED_FD,1)
    after_prefix(w,o,CALL_FD,2)
    return action(o,w,RUN_INPUT_MADE,MAKE,0,0,3,40)
'''


def run_input_recipe(driver, policy, controls, constants):
    constants.update(RUN_INPUT=int.from_bytes(b'HIAEFH01', 'little'), ENTRY_TICK=102, RUN_INPUT_MADE=103)
    entry = next(i for i, item in enumerate(controls) if item.lstrip().startswith('def artifact_entry('))
    controls[entry] = controls[entry].replace('return start_replay(o, w)',
                                              'return clock_sample(o, w, ENTRY_TICK, 0)')
    driver = driver.replace('return next == 1 and status == 0',
                            'return (next == 1 or next == 11) and status == 0')
    constants['UNKEYED_HANDOFF'] = int.from_bytes(b'HIAENK01', 'little')
    policy = policy.replace('    if stage == 0:\n        return open_store(o, w, OPEN_LOOKUP)', '''    if stage == 0:
        if next == 11 and get(w, CLAIM_ACTIVE) == 0:
            put(o, HEADER, UNKEYED_HANDOFF)
            put(o, HEADER + 8, get(w, 64))
            put(o, HEADER + 16, slot_bytes(w, ORIGINAL))
            whole_slot(w, o, ORIGINAL, 0)
            return action(o, w, INTAKE_PUBLISHED, PUBLISH, 0, 0, 1, 24)
        return open_store(o, w, OPEN_LOOKUP)''')
    driver = driver.replace('    if state == REQUEST_ADMITTED:', '''    if state == RUN_INPUT_MADE:
        size = input_word(s,40)
        if size < 648 or input_word(s,64) != RUN_INPUT:
            return BAD
        fragment(o,0,input_word(s,32),0,size)
        return action(o,w,INTAKE_PUBLISHED,PUBLISH,0,0,1,0)
    if state == ENTRY_TICK:
        if length(s) != 72 or input_word(s,40) != 8 or input_word(s,64) == 0:
            return BAD
        put(w,64,input_word(s,64))
        return start_replay(o,w)
    if state == REQUEST_ADMITTED:
        if input_word(s,40) < 2 or input_word(s,56) == 0 or byte(s,64) != 123:
            return BAD''')
    # A completed row is observed under the same initial read-only transaction
    # as a miss. Replay it using the original Journal terminal and public report.
    policy = policy.replace('    if purpose == CLOSED_RESERVATION:',
                            '    if purpose == CLOSED_LOOKUP and get(w,CLAIM_ACTIVE) == 0 and get(w,JOURNAL_NEXT) == 3 and get(w,CACHED_BYTES) > 0:\n'
                            '        return send_journal(o,w,3)\n'
                            '    if purpose == CLOSED_RESERVATION:')
    policy = policy.replace('    if stage == 2 and next == 11 and get(w, CLAIM_ACTIVE) == 1:',
                            '    if stage == 3 and next == 19 and get(w,CLAIM_ACTIVE) == 0:\n'
                            '        return send_report(o,w,True)\n'
                            '    if stage == 2 and next == 11 and get(w, CLAIM_ACTIVE) == 1:')
    driver = driver.replace('    return intake(s, o, w, state)',
                            '    if state == TERMINAL or state == REPORT_END or state == REPORT_PUBLISHED:\n'
                            '        return publish_cached(s,o,w,state)\n'
                            '    return intake(s, o, w, state)')
    old = function(policy, 'publish_claim')
    policy = policy.replace(old.strip(), POLICY.strip()).replace(
        'return publish_claim(s, o, w)', 'return publish_execution_input(s, o, w)')
    return driver, policy, controls


if __name__ == '__main__':
    from tools.generate_hia_worker_evaluate_intake_flow import program
    SOURCE.write_text(render_assembly(document(program(claim=True, run_input=True), SOURCE.stem)))
