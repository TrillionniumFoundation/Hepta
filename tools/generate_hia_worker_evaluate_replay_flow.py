"""Build the descriptor-only Evaluate journal replay carrier."""

from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_release_install import POLICY_SOURCE as RELEASE_WRITER
from tools.generate_hia_worker_artifact_flow import (
    EFFECT_POLICY, POLICY as ARTIFACT, STORE_POLICY as STORE, policy_constants,
)
from tools.generate_hia_worker_cost_flow import POLICY as COST
from tools.generate_hia_worker_describe_flow import POLICY as DESCRIBE, flow_source
from tools.generate_hia_worker_describe_reactor import POLICY as ENTRY, program as entry_program
from tools.generate_hia_worker_inspection_effect import function
from tools.generate_hia_worker_read_store_flow import POLICY as READ

SOURCE = Path('examples/hia_bootstrap/worker_evaluate_replay_flow.hepta')
ROLES = (
    ('ADMIT', 'hia-worker-admit'), ('PROJECT', 'hia-worker-journal-call'),
    ('FLOW', 'hia-agent-evaluate-journal'), ('JOURNAL', 'hia-agent-journal'),
    ('STORE', 'hia-agent-store'), ('READY', 'hia-agent-store-ready'),
    ('UNIQUE', 'hia-agent-store-unique'), ('RECORD', 'hia-agent-evaluate-journal-records'),
    ('OBSERVE', 'hia-agent-evaluate-journal-observation'), ('TERMINAL', 'hia-worker-terminal'),
)

DRIVER = r'''
def evaluate_replay(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
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
    if state == REQUEST_ADMITTED:
        observe_slot(s, w, ADMITTED_FD)
        return project_artifact(o, w, CALL_PROJECTED, PROJECT, PROJECT_ROLE)
    if state == CALL_PROJECTED:
        if prefixed(s) == False:
            return BAD
        observe_slot(s, w, CALL_FD)
        return send_journal(o, w, 9)
    if state >= JOURNAL_REQUEST and state <= JOURNAL_STATE_FRAME:
        return observe_journal(s, o, w, state)
    if state == TYPED_REQUEST or state == TYPED:
        return typed_lookup(s, o, w, state)
    if state >= PEER_STARTED and state <= PEER_CLOSED:
        return observe_store(s, o, w, state)
    if state == LOOKUP_AUDITED:
        return lookup_observation(s, o, w, state)
    return publish_cached(s, o, w, state)

def start_replay(o:mutbuf, w:mutbuf) -> u64:
    put(o, HEADER, ADMISSION)
    put(o, HEADER + 8, get(w, 24))
    copy_private(w, o, TRUST, HEADER + 16, 64)
    whole_slot(w, o, ORIGINAL, 0)
    return action(o, w, REQUEST_ADMITTED, RUN, ADMIT_ROLE, 0, 1, 80)

def artifact_edge(stage:u64, next:u64, status:u64, bytes:u64) -> bool:
    if stage == 9:
        return next == 0 and status == 0
    if stage == 0:
        return next == 1 and status == 0
    if stage == 1:
        return (next == 2 or next == 3 or next == 14) and status == 0
    return stage == 3 and next == 19

def journal_action(o:mutbuf, w:mutbuf) -> u64:
    stage = get(w, JOURNAL_STAGE)
    if stage == 9:
        return send_journal(o, w, 0)
    if stage == 0:
        return open_store(o, w, OPEN_LOOKUP)
    if stage == 1:
        return close_store(o, w, CLOSED_LOOKUP)
    if stage == 3:
        return send_report(o, w, True)
    return BAD

def opened_store(o:mutbuf, w:mutbuf) -> u64:
    if get(w, STORE_PURPOSE) != OPEN_LOOKUP:
        return BAD
    zero_range(o, HEADER, 40)
    put(o, HEADER, JOURNAL_KEY)
    put(o, HEADER + 8, 1)
    copy_private(w, o, JOURNAL_STATE, HEADER + 40, 512)
    return action(o, w, TYPED_REQUEST, RUN, FLOW_ROLE, 0, 0, 552)

def typed_lookup(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    fd = input_word(s, 32)
    span = input_word(s, 40)
    if state == TYPED_REQUEST:
        fragment(o, 0, fd, 0, span)
        return action(o, w, TYPED, RUN, RECORD_ROLE, 0, 1, 0)
    if plan_ok(s) == False or span != 128:
        return BAD
    keep(w, QUERY_FD, fd, span)
    return store_transaction(o, w, STORE_LOOKUP, 9, 0, fd, 8, span - 8)

def closed_store(o:mutbuf, w:mutbuf) -> u64:
    if get(w, STORE_PURPOSE) == CLOSED_LOOKUP and get(w, JOURNAL_NEXT) == 3 and get(w, CACHED_BYTES) > 0:
        return send_journal(o, w, 3)
    # Missing, in-progress or conflicting requests have no result to publish.
    return BAD
'''


def program():
    constants = policy_constants()
    constants.update({role + '_ROLE': ordinal for ordinal, (role, _) in enumerate(ROLES)})
    constants.update(ROLE_COUNT=len(ROLES), ENTRY_BYTES=64 + 312 + 40 * len(ROLES))
    entry = function(ARTIFACT, 'artifact_entry').replace(
        'return read_span(o, w, CONFIG_HEADER, slot_fd(w, METADATA_FD), 0, 88)',
        'return start_replay(o, w)')
    settle = function(STORE, 'settle_transaction').split('    if purpose == STORE_LOOKUP')[0]
    settle += '    if purpose != STORE_LOOKUP:\n        return BAD\n    return interpret_row(o, w, purpose, bytes)\n'
    interpret = function(STORE, 'interpret_row').split('    if purpose == STORE_PROFILE_ROW:')[0] + '    return BAD\n'
    publish = function(EFFECT_POLICY, 'publish_artifact')
    publish = 'def publish_cached(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:\n' + publish[publish.index('    if state == TERMINAL:'):]
    common = entry_program()
    controls = (
        entry, settle, interpret, publish,
        *(function(ARTIFACT, name) for name in ('project_artifact', 'plan_ok', 'send_journal', 'observe_journal', 'bind_journal')),
        *(function(STORE, name) for name in ('open_store', 'close_store', 'observe_store', 'store_transaction', 'lookup_observation')),
        function(EFFECT_POLICY, 'send_report'), function(COST, 'action'),
        function(DESCRIBE, 'issue').replace('seq > 160', 'seq > 512'),
        *(function(ENTRY, name) for name in ('admit_entry', 'trusted_descriptors', 'dossier_identity')),
        *(function(DESCRIBE, name) for name in ('argv', 'fragment', 'keep', 'observe_slot', 'slot_fd',
            'slot_bytes', 'whole_slot', 'after_prefix', 'prefixed', 'copy_private', 'zero_range')),
        *(function(READ, name) for name in ('receive', 'read_span')),
        *(function(common, name) for name in ('valid_fd', 'is_hex', 'copy_span', 'input_word', 'put', 'write')),
        function(RELEASE_WRITER, 'get'),
    )
    return flow_source(DRIVER, controls, constants)


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)), encoding='utf-8')
    from tools.generate_hia_readonly_worker_capsule import REPLAY_SOURCE as capsule, source_program
    from tools.generate_hia_worker_launcher_flow import REPLAY_SOURCE as launcher, program as launcher_program
    for target, candidate in ((Path(capsule), source_program(artifact=True, evaluate_replay=True)),
                              (launcher, launcher_program(evaluate_replay=True))):
        target.write_text(render_assembly(document(candidate, target.stem)), encoding='utf-8')
