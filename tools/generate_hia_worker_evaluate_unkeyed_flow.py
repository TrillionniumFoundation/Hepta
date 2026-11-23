"""Reject unkeyed Evaluate requests with the original schema diagnostic and one Store cost."""
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_worker_artifact_flow import EFFECT_POLICY, POLICY as ARTIFACT, STORE_POLICY
from tools.generate_hia_worker_describe_flow import POLICY as DESCRIBE, flow_source
from tools.generate_hia_worker_evaluate_replay_flow import recipe
from tools.generate_hia_worker_inspection_effect import function

SOURCE = Path('examples/hia_bootstrap/worker_evaluate_unkeyed_flow.hepta')
ROLES = (
    ('ADMIT', 'hia-worker-admit'), ('PROJECT', 'hia-worker-journal-call'),
    ('FLOW', 'hia-agent-evaluate-journal'), ('JOURNAL', 'hia-agent-journal'),
    ('ARGUMENT', 'hia-agent-worker-arguments'), ('INPUT_SCHEMA', 'hia-agent-mcp-input-schema'),
    ('DIAGNOSTIC', 'hia-agent-evaluate-diagnostic'), ('COMPOSE', 'hia-worker-response'),
    ('COST', 'hia-agent-journal-cost'), ('STORE', 'hia-agent-store'),
    ('READY', 'hia-agent-store-ready'), ('UNIQUE', 'hia-agent-store-unique'),
    ('TERMINAL', 'hia-worker-terminal'),
)

DRIVER = '''
def reject_unkeyed(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 8 or length(o) != 2048 or length(w) != 4096:
        return BAD
    state = get(w, 0)
    if state == 0:
        return artifact_entry(s, o, w)
    if length(s) < 64 or input_word(s, 0) != OBSERVATION or input_word(s, 8) != get(w, 8):
        return BAD
    operation = get(w, 16)
    if input_word(s, 16) != operation or input_word(s, 24) != 0:
        return BAD
    extent = input_word(s, 40)
    offset = choose(operation == RUN, 0, input_word(s, 48))
    captured = input_word(s, 56)
    if extent > 67112960 or offset > extent or captured > extent - offset or captured != length(s) - 64:
        return BAD
    if operation == RUN and valid_fd(input_word(s, 32)) == False:
        return BAD
    if operation == READ and (input_word(s, 32) != get(w, 80) or offset != get(w, 88) or captured != get(w, 96)):
        return BAD
    if state == UNKEYED_HEADER:
        if length(s) != 88 or input_word(s, 64) != UNKEYED or input_word(s, 72) == 0:
            return BAD
        n = input_word(s, 80)
        if n < 2 or n > 8388608 or n + 24 != slot_bytes(w, ORIGINAL):
            return BAD
        put(w, START_TIME, input_word(s, 72))
        fragment(o, 0, 0, 24, n)
        return action(o, w, ORIGINAL_READY, MAKE, 0, 0, 1, 0)
    if state == ORIGINAL_READY:
        if extent + 24 != slot_bytes(w, ORIGINAL):
            return BAD
        observe_slot(s, w, ORIGINAL)
        put(o, HEADER, ADMISSION)
        put(o, HEADER + 8, get(w, 24))
        copy_private(w, o, TRUST, HEADER + 16, 64)
        whole_slot(w, o, ORIGINAL, 0)
        return action(o, w, REQUEST_ADMITTED, RUN, ADMIT_ROLE, 0, 1, 80)
    if state == REQUEST_ADMITTED:
        if extent < 2 or length(s) < 65 or byte(s, 64) != 123:
            return BAD
        observe_slot(s, w, ADMITTED_FD)
        return project_artifact(o, w, CALL_PROJECTED, PROJECT, PROJECT_ROLE)
    if state == CALL_PROJECTED:
        if prefixed(s) == False:
            return BAD
        observe_slot(s, w, CALL_FD)
        return send_journal(o, w, 9)
    if state >= JOURNAL_REQUEST and state <= JOURNAL_RECIPE:
        return observe_journal(s, o, w, state)
    if state == ARGUMENT_PROJECTED:
        if prefixed(s) == False:
            return BAD
        observe_slot(s, w, ARGUMENT_FD)
        return schema_receipt(o, w, INPUT_SCHEMA, INPUT_SCHEMA_ROLE, ARGUMENT_FD)
    if state == INPUT_SCHEMA:
        if reply_word(s, 1) == False:
            return BAD
        after_prefix(w, o, ARGUMENT_FD, 0)
        return action(o, w, DIAGNOSTIC, RUN, DIAGNOSTIC_ROLE, 0, 1, 0)
    if state == DIAGNOSTIC:
        if plan_ok(s) == False:
            return BAD
        observe_slot(s, w, EFFECT_FD)
        return end_effect(o, w, 2, 8)
    if state == RESPONSE_RENDERED:
        if prefixed(s) == False or get(w, EFFECT_STATUS) != 2:
            return BAD
        observe_slot(s, w, RENDERED_FD)
        return send_journal(o, w, 8)
    if state >= COST_CLOCK and state <= COST_TYPED:
        return publish_cost(s, o, w, state)
    if state == COST_ACK:
        if length(s) != 72 or input_word(s, 64) != COMMIT_INTENT:
            return BAD
        return close_store(o, w, CLOSED_COST)
    if state >= PEER_STARTED and state <= PEER_CLOSED:
        return observe_store(s, o, w, state)
    return publish_cached(s, o, w, state)

def artifact_edge(stage:u64, next:u64, status:u64, bytes:u64) -> bool:
    if stage == 9:
        return next == 0 and status == 0
    if stage == 0:
        return next == 11 and status == 0
    if stage == 14:
        return next == 17 and bytes <= 192
    return stage == 8 and next == 18 and status == 2

def journal_action(o:mutbuf, w:mutbuf) -> u64:
    stage = get(w, JOURNAL_STAGE)
    if stage == 9:
        return send_journal(o, w, 0)
    if stage == 0 and get(w, JOURNAL_NEXT) == 11:
        return project_artifact(o, w, ARGUMENT_PROJECTED, ARGUMENT, ARGUMENT_ROLE)
    if stage == 8 and get(w, JOURNAL_NEXT) == 18 and get(w, EFFECT_STATUS) == 2:
        return clock_sample(o, w, COST_CLOCK, 0)
    return BAD

def opened_store(o:mutbuf, w:mutbuf) -> u64:
    if get(w, STORE_PURPOSE) != OPEN_COST:
        return BAD
    return store_transaction(o, w, STORE_COST, 18, 1, slot_fd(w, COST_FD), 8, slot_bytes(w, COST_FD) - 8)

def closed_store(o:mutbuf, w:mutbuf) -> u64:
    if get(w, STORE_PURPOSE) != CLOSED_COST:
        return BAD
    return send_report(o, w, False)
'''


def program():
    constants, shared = recipe(ROLES)
    constants.update(SCHEMA_TOOL=9, UNKEYED=int.from_bytes(b'HIAENK01', 'little'),
                     UNKEYED_HEADER=60, ORIGINAL_READY=61, COST_ACK=62, MAKE=11,
                     COMMIT_INTENT=int.from_bytes(b'HIASTCP1', 'little'))
    controls = []
    for part in shared:
        if part.lstrip().startswith(('def interpret_row(', 'def lookup_observation(')):
            continue
        if part.lstrip().startswith('def admit_entry('):
            part = part.replace('n > MAX_INPUT', 'n > MAX_INPUT + 24')
        if part.lstrip().startswith('def issue('):
            # The Context descriptor carrier also recognizes wide commands and
            # special child names. Clear both fields on each ordinary command.
            part = part.replace('    put(o, 152,',
                                '    put(o, 136, 0)\n    put(o, 168, 0)\n    put(o, 152,')
        if part.lstrip().startswith('def artifact_entry('):
            part = part.replace('return start_replay(o, w)',
                                'return read_span(o, w, UNKEYED_HEADER, 0, 0, 24)')
        if part.lstrip().startswith('def settle_transaction('):
            standard = function(STORE_POLICY, 'settle_transaction')
            part = standard[:standard.index('    if purpose == STORE_LOOKUP')]
            part += '''    if purpose != STORE_COST or found != 1 or bytes != 8:
        return BAD
    return read_span(o, w, COST_ACK, slot_fd(w, STORE_RESULT), 0, 8)
'''
        controls.append(part)
    controls.extend(function(ARTIFACT, name) for name in ('schema_receipt', 'end_effect', 'clock_sample'))
    controls.append(function(DESCRIBE, 'reply_word'))
    publication = function(EFFECT_POLICY, 'publish_artifact')
    cost = publication[publication.index('    if state == COST_CLOCK:'):publication.index('    if state == TERMINAL:')]
    controls.append('def publish_cost(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:\n' + cost + '    return BAD\n')
    return flow_source(DRIVER, controls, constants)


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)), encoding='utf-8')
