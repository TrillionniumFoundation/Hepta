"""Compose the admitted fresh Evaluate stages and the completed-row public replay."""

from tools.generate_hia_readonly_worker_capsule import (
    ADOPT_ROLES, EMIT_ROLES, NATIVE_ROLES, evaluate_route,
)
from tools.generate_hia_worker_evaluate_document_flow import ROLES as DOCUMENT_ROLES

RUN_INPUT = 'hia-agent-evaluate-run-input-worker-carrier'
PROOF = 'hia-agent-evaluate-proof-worker-carrier'
PLANNER = 'hia-evaluate-run-plan'
RUNNER = 'hia-agent-evaluate-run-worker-carrier'
REPORT = 'hia-evaluate-report-flow'
LEDGER = 'hia-evaluate-cost-ledger-flow'
CLOSEOUT = 'hia-agent-evaluate-closeout-worker-carrier'
PAID_ROLES = ('hia-agent-store', 'hia-execution-budget-session', 'hia-evaluate-budget-observation',
              'hia-evaluate-budget-store', 'hia-evaluate-paired-batch', 'hia-direct-call')
REPORT_ROLES = ('hia-owned-reference-wire', 'hia-direct-call', 'hia-evaluate-reference-report',
                'hia-evaluate-native-report', 'hia-evaluate-settlement', 'hia-evaluate-measurements')
LEDGER_ROLES = ('hia-evaluate-cost-ledger', 'hia-agent-store', 'hia-artifact')
CLOSE_ROLES = (*DOCUMENT_ROLES, 'hia-evaluate-publication', 'hia-evaluate-settlement', 'hia-agent-journal-cost')
PROOF_ROLES = (*ADOPT_ROLES, 'hia-agent-worker-evaluate-request')


def public_route():
    _, mode, roles = evaluate_route(intake=True)
    return RUN_INPUT, mode, roles


def inventory():
    replay, _, replay_roles = evaluate_route()
    return tuple(dict.fromkeys((*NATIVE_ROLES, *public_route()[2], RUN_INPUT, *PROOF_ROLES, PROOF, PLANNER,
                                *PAID_ROLES, RUNNER, *REPORT_ROLES, REPORT, *LEDGER_ROLES, LEDGER,
                                *CLOSE_ROLES, CLOSEOUT, *replay_roles, replay)))


def child_calls(roles):
    # Large proof descriptors follow the original Adopt ABI, including the
    # independently sealed trust record immediately after the Emit role set.
    jobs = (
        ('proof', PROOF, '--worker-evaluate-proof', PROOF_ROLES, 'PROOF_DONE', True),
        ('paid', RUNNER, '--worker-evaluate-run', PAID_ROLES, 'PAID_DONE', False),
        ('closeout', CLOSEOUT, '--worker-evaluate-closeout', CLOSE_ROLES, 'CLOSED', False),
        ('replay', *evaluate_route(), 'WORKER_DONE', False),
    )
    text = []
    for label, executable, mode, children, state, trust in jobs:
        text.append(f'def full_{label}(o:mutbuf, w:mutbuf, input:u64, bytes:u64) -> u64:')
        raw = mode.encode() + bytes(1)
        for i in range(0, len(raw), 8):
            text.append(f'    put(o,{448+i},{int.from_bytes(raw[i:i+8], "little")})')
        text += ['    argv(o,0,LITERAL_ARG,448)', '    argv(o,1,INPUT_ARG,1)', '    argv(o,2,INPUT_ARG,2)',
                 '    argv(o,3,FD_ARG,get(w,PART_TABLE))',
                 f'    argv(o,4,FD_ARG,get(w,{"PART_TABLE+24" if label == "replay" else "DISCOVERY_META"}))']
        count = 5
        for i, role in enumerate(children):
            if trust and i == len(EMIT_ROLES):
                text.append(f'    argv(o,{count},FD_ARG,get(w,PART_TABLE+96))')
                count += 1
            text.append(f'    argv(o,{count},FD_ARG,role_fd(w,{roles.index(role)}))')
            count += 1
        owner = roles.index(executable)
        text += ['    fragment(o,0,input,0,bytes)', f'    child_name(o,{owner})',
                 f'    return issue(o,w,{state},RUN,role_fd(w,{owner}),{count},1,0)', '']
    for label, children, first in [('report', REPORT_ROLES, 3), ('ledger', LEDGER_ROLES, 1)]:
        text.append(f'def {label}_roles(o:mutbuf,w:mutbuf) -> u64:')
        for i, child in enumerate(children, first):
            text.append(f'    argv(o,{i},FD_ARG,role_fd(w,{roles.index(child)}))')
        text += ['    return 0', '']
    return '\n'.join(text)


STATES = ('INPUT_CLASSIFIED PROOF_DONE PLAN_DONE PAID_DONE CLAIM_MADE ARCHIVE_MADE RECEIPT_MADE '
          'TIMING_MADE REPORT_DONE LEDGER_DONE CLOSE_LEADING CLOSE_INPUT CLOSED').split()
FIELDS = ('PREP_FD PREP_BYTES CLAIM_BYTES ADMITTED_BYTES CALL_BYTES ADMITTED_AT CALL_AT ENTRY_TIME '
          'PAID_FD ARCHIVE_BYTES RECEIPT_BYTES CLAIM_FD ARCHIVE_FD RECEIPT_FD REPORT_FD REPORT_BYTES '
          'LEDGER_FD LEDGER_BYTES').split()

POLICY = '''
def full_next(s:readbuf,o:mutbuf,w:mutbuf,state:u64) -> u64:
    fd = capsule_word(s,32)
    size = capsule_word(s,40)
    if bound_fd(s) == False or size == 0 or size > MAX_PRIVATE:
        return BAD
    if state == INPUT_CLASSIFIED or state == PROOF_DONE or state == PAID_DONE or state == CLOSED:
        if capsule_word(s,48) != 15:
            return BAD
    if state == INPUT_CLASSIFIED:
        if length(s) < 72:
            return BAD
        if byte(s,64) == 123:
            if size > MAX_REQUEST+1:
                return BAD
            fragment(o,0,fd,0,size)
            return issue(o,w,PUBLISHED,PUBLISH,0,0,1,0)
        if length(s) < 104 or capsule_word(s,64) != PREPARED or size < 40:
            return BAD
        begin = capsule_word(s,72)
        claim = capsule_word(s,80)
        admitted = capsule_word(s,88)
        call = capsule_word(s,96)
        if begin == 0 or claim < 648 or claim > size-40 or admitted < 2 or admitted > size-40-claim or call < 2 or call != size-40-claim-admitted:
            return BAD
        put(w,ENTRY_TIME,begin)
        put(w,PREP_FD,fd)
        put(w,PREP_BYTES,size)
        put(w,CLAIM_BYTES,claim)
        put(w,ADMITTED_BYTES,admitted)
        put(w,CALL_BYTES,call)
        put(w,ADMITTED_AT,40+claim)
        put(w,CALL_AT,40+claim+admitted)
        return launch_bootstrap(o,w)
    if state == PROOF_DONE:
        if size < 80 or capsule_word(s,64) != PROVED:
            return BAD
        put(o,HEADER,PLAN_QUERY)
        put(o,HEADER+8,get(w,PREP_BYTES))
        put(o,HEADER+16,size)
        fragment(o,0,get(w,PREP_FD),0,get(w,PREP_BYTES))
        fragment(o,1,fd,0,size)
        child_name(o,PLANNER_ROLE)
        return issue(o,w,PLAN_DONE,RUN,role_fd(w,PLANNER_ROLE),0,2,24)
    if state == PLAN_DONE:
        if size < 196 or capsule_word(s,64) != PLAN or capsule_word(s,72) != get(w,ENTRY_TIME):
            return BAD
        return full_paid(o,w,fd,size)
    if state == PAID_DONE:
        if size < 32 or capsule_word(s,64) != PAID or capsule_word(s,72) != get(w,ENTRY_TIME):
            return BAD
        archive = capsule_word(s,80)
        receipt = capsule_word(s,88)
        if archive < 112 or archive > size-32 or receipt < 228 or receipt != size-32-archive:
            return BAD
        put(w,PAID_FD,fd)
        put(w,ARCHIVE_BYTES,archive)
        put(w,RECEIPT_BYTES,receipt)
        fragment(o,0,get(w,PREP_FD),40,get(w,CLAIM_BYTES))
        return issue(o,w,CLAIM_MADE,MAKE,0,0,1,0)
    if state == CLAIM_MADE:
        if size != get(w,CLAIM_BYTES) or capsule_word(s,64) != JOURNAL:
            return BAD
        put(w,CLAIM_FD,fd)
        fragment(o,0,get(w,PAID_FD),32,get(w,ARCHIVE_BYTES))
        return issue(o,w,ARCHIVE_MADE,MAKE,0,0,1,0)
    if state == ARCHIVE_MADE:
        if size != get(w,ARCHIVE_BYTES) or capsule_word(s,64) != ARCHIVE:
            return BAD
        put(w,ARCHIVE_FD,fd)
        fragment(o,0,get(w,PAID_FD),32+size,get(w,RECEIPT_BYTES))
        return issue(o,w,RECEIPT_MADE,MAKE,0,0,1,0)
    if state == RECEIPT_MADE:
        if size != get(w,RECEIPT_BYTES) or capsule_word(s,64) != BUDGET:
            return BAD
        put(w,RECEIPT_FD,fd)
        put(o,HEADER,CLOCK_WIRE)
        put(o,HEADER+8,get(w,ENTRY_TIME))
        return issue(o,w,TIMING_MADE,MAKE,0,0,0,16)
    if state == TIMING_MADE:
        if size != 16 or capsule_word(s,64) != CLOCK_WIRE or capsule_word(s,72) != get(w,ENTRY_TIME):
            return BAD
        argv(o,0,FD_ARG,get(w,CLAIM_FD))
        argv(o,1,FD_ARG,get(w,ARCHIVE_FD))
        argv(o,2,FD_ARG,get(w,RECEIPT_FD))
        report_roles(o,w)
        argv(o,9,FD_ARG,fd)
        child_name(o,REPORT_ROLE)
        return issue(o,w,REPORT_DONE,RUN,role_fd(w,REPORT_ROLE),10,0,0)
    if state == REPORT_DONE:
        if size < 64 or capsule_word(s,64) != REPORT_FRAME:
            return BAD
        put(w,REPORT_FD,fd)
        put(w,REPORT_BYTES,size)
        argv(o,0,FD_ARG,fd)
        ledger_roles(o,w)
        argv(o,4,INPUT_ARG,1)
        argv(o,5,INPUT_ARG,2)
        child_name(o,LEDGER_ROLE)
        return issue(o,w,LEDGER_DONE,RUN,role_fd(w,LEDGER_ROLE),6,0,0)
    if state == LEDGER_DONE:
        if size < 2 or byte(s,64) != 123:
            return BAD
        put(w,LEDGER_FD,fd)
        put(w,LEDGER_BYTES,size)
        put(o,HEADER,CLOSING)
        put(o,HEADER+8,get(w,ENTRY_TIME))
        put(o,HEADER+16,get(w,REPORT_BYTES))
        put(o,HEADER+24,get(w,CALL_BYTES))
        put(o,HEADER+32,get(w,ADMITTED_BYTES))
        put(o,HEADER+40,size)
        fragment(o,0,get(w,REPORT_FD),0,get(w,REPORT_BYTES))
        fragment(o,1,get(w,PREP_FD),get(w,CALL_AT),get(w,CALL_BYTES))
        fragment(o,2,get(w,PREP_FD),get(w,ADMITTED_AT),get(w,ADMITTED_BYTES))
        return issue(o,w,CLOSE_LEADING,MAKE,0,0,3,48)
    if state == CLOSE_LEADING:
        if size != 48+get(w,REPORT_BYTES)+get(w,CALL_BYTES)+get(w,ADMITTED_BYTES) or capsule_word(s,64) != CLOSING:
            return BAD
        fragment(o,0,fd,0,size)
        fragment(o,1,get(w,LEDGER_FD),0,get(w,LEDGER_BYTES))
        return issue(o,w,CLOSE_INPUT,MAKE,0,0,2,0)
    if state == CLOSE_INPUT:
        if size != 48+get(w,REPORT_BYTES)+get(w,CALL_BYTES)+get(w,ADMITTED_BYTES)+get(w,LEDGER_BYTES):
            return BAD
        return full_closeout(o,w,fd,size)
    if state == CLOSED and byte(s,64) == 123:
        return full_replay(o,w,get(w,REQUEST_FD),get(w,REQUEST_BYTES))
    return BAD
'''


def compose(source, roles):
    source = source.replace('bytes > MAX_REQUEST + 1 or offset', 'bytes > MAX_PRIVATE or offset')
    source = source.replace('    return dispatch(s, o, w, state)',
                            '    if state >= INPUT_CLASSIFIED:\n        return full_next(s,o,w,state)\n'
                            '    return dispatch(s, o, w, state)')
    source = source.replace('        return launch_worker(o, w, get(w, ROUTE))',
                            '        if get(w,ROUTE) == REPLAY_ROUTE:\n'
                            '            return full_proof(o,w,get(w,REQUEST_FD),get(w,REQUEST_BYTES))\n'
                            '        return launch_worker(o, w, get(w, ROUTE))')
    source = source.replace('    return issue(o, w, WORKER_DONE, RUN,',
                            '    return issue(o, w, choose(route == REPLAY_ROUTE, INPUT_CLASSIFIED, WORKER_DONE), RUN,')
    return source + POLICY + child_calls(roles)


def bindings(roles):
    labels = dict(PREPARED=b'HIAEFH01', PROVED=b'HIAEDP01', PLAN_QUERY=b'HIAEXQ01', PLAN=b'HIAEXI01',
                  PAID=b'HIAEXO01', JOURNAL=b'HIAEJC01', ARCHIVE=b'HIAEMT01', BUDGET=b'HIAEBRS1',
                  CLOCK_WIRE=b'HIAEMC01', REPORT_FRAME=b'HIAEMF01', CLOSING=b'HIAEFC01')
    values = {k: int.from_bytes(v, 'little') for k, v in labels.items()}
    values.update({n: 32+i for i, n in enumerate(STATES)})
    values.update({n: 2400+8*i for i, n in enumerate(FIELDS)})
    values.update(MAX_PRIVATE=64<<20, PLANNER_ROLE=roles.index(PLANNER), REPORT_ROLE=roles.index(REPORT),
                  LEDGER_ROLE=roles.index(LEDGER))
    return values


if __name__ == '__main__':
    from pathlib import Path
    from hepta.hia_agent_assembly import render_assembly
    from tools.generate_hia_artifact_publication import document
    from tools.generate_hia_readonly_worker_capsule import FULL_SOURCE, source_program
    from tools.generate_hia_worker_flow_packer import FULL_LAUNCHER_POLICY
    from tools.generate_hia_worker_launcher_flow import program

    policies = ((Path(FULL_SOURCE), source_program(artifact=True, evaluate_full=True)),
                (Path(FULL_LAUNCHER_POLICY), program(evaluate_full=True)))
    for path, source in policies:
        path.write_text(render_assembly(document(source, path.stem)), encoding='utf-8')
