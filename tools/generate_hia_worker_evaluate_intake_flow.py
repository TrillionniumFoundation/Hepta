"""Collect fresh Evaluate input records from the live typed Store."""

from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_worker_artifact_flow import POLICY as ARTIFACT, STORE_POLICY
from tools.generate_hia_worker_context_flow import POLICY as CONTROL_POLICY, RETAINED_POLICY
from tools.generate_hia_worker_describe_flow import POLICY as DESCRIBE, flow_source
from tools.generate_hia_worker_evaluate_replay_flow import DRIVER as REPLAY, ROLES as REPLAY_ROLES, recipe
from tools.generate_hia_worker_inspection_effect import function

SOURCE = Path('examples/hia_bootstrap/worker_evaluate_intake_flow.hepta')
ROLES = (*REPLAY_ROLES,
         ('ARGUMENT', 'hia-agent-worker-arguments'), ('INPUT_SCHEMA', 'hia-agent-mcp-input-schema'),
         ('PLAN', 'hia-agent-worker-evaluate-request'), ('CONTEXT', 'hia-agent-context-request'),
         ('CONTEXT_STORE', 'hia-agent-context-store'), ('PROFILE', 'hia-agent-artifact-authority'),
         ('PUBLISHER', 'hia-artifact'))

POLICY = r'''
# A novel key is eligible for reversible intake. The request is not reserved
# here: a successor must still authorize both programs, proofs, and budget.
def closed_store(o:mutbuf, w:mutbuf) -> u64:
    purpose = get(w, STORE_PURPOSE)
    if purpose == CLOSED_LOOKUP and get(w, JOURNAL_NEXT) == 2:
        return project_artifact(o, w, ARGUMENT_PROJECTED, ARGUMENT, ARGUMENT_ROLE)
    if purpose == CLOSE_INTAKE:
        return publish_intake(o, w)
    return BAD

def intake(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    size = input_word(s, 40)
    fd = input_word(s, 32)
    if state == ARGUMENT_PROJECTED:
        if prefixed(s) == False:
            return BAD
        observe_slot(s, w, ARGUMENT_FD)
        return schema_receipt(o, w, INPUT_SCHEMA, INPUT_SCHEMA_ROLE, ARGUMENT_FD)
    if state == INPUT_SCHEMA:
        if reply_word(s, 0) == False:
            return BAD
        put(o, HEADER, 8795)
        copy_private(w, o, TRUST, HEADER + 2, 64)
        store(o, HEADER + 66, 34)
        store(o, HEADER + 67, 44)
        return json_pair(o, w, ARGUMENT_PLAN, 68)
    if state == ARGUMENT_PLAN:
        if plan_ok(s) == False or size < 136 or size > 376:
            return BAD
        return read_span(o, w, REQUEST_SPANS, fd, 0, size)
    if state == REQUEST_SPANS:
        return bind_request_spans(s, o, w)
    if state == CTX_REFERENCE:
        if plan_ok(s) == False or size != 116 or input_word(s, 72) != CONTEXT_REFERENCE_TAG:
            return BAD
        hold(w, ACTIVE_REFERENCE, fd, 16, 100)
        put(o, HEADER, CONTEXT_QUERY_TAG)
        fragment(o, 0, fd, 16, 36)
        return action(o, w, CTX_QUERY, RUN, CONTEXT_STORE_ROLE, 0, 1, 8)
    if state == CTX_QUERY:
        if plan_ok(s) == False or size != 100:
            return BAD
        observe_slot(s, w, QUERY_FD)
        return open_store(o, w, OPEN_INTAKE)
    if state == CTX_OBSERVED:
        if plan_ok(s) == False or size < 217 or size > 236 or input_word(s, 72) != CONTEXT_OBSERVED_TAG or input_word(s, 80) != 0:
            return close_store(o, w, CLOSE_REFUSED)
        hold(w, ACTIVE_REFERENCE, fd, 40, 176)
        hold(w, CREATION, fd, 216, size - 216)
        put(w, ACTIVE_KIND, 3)
        return retained_query(o, w)
    if state == ART_QUERY:
        if plan_ok(s) == False or size != 98:
            return close_store(o, w, CLOSE_REFUSED)
        return store_transaction(o, w, ART_ROW, 2, 0, fd, 8, size - 8)
    if state == ART_OBSERVED:
        if plan_ok(s) == False or (size != 80 and size != 96):
            return close_store(o, w, CLOSE_REFUSED)
        return read_span(o, w, ART_AUTH, fd, 8, size - 8)
    if state == ART_AUTH:
        return capture_artifact(s, o, w)
    if state == ART_BODY:
        if size < 1 or size > 67108864:
            return close_store(o, w, CLOSE_REFUSED)
        return retain_body(o, w, fd, size)
    if state == ROW_MADE:
        if size != get(w, RECORD_SIZE):
            return BAD
        if get(w, SELECTOR) == 0:
            keep(w, INTAKE_PACKET, fd, size)
            return next_artifact(o, w)
        whole_slot(w, o, INTAKE_PACKET, 0)
        fragment(o, 1, fd, 0, size)
        return action(o, w, ROW_JOINED, MAKE, 0, 0, 2, 0)
    if state == ROW_JOINED:
        if size != slot_bytes(w, INTAKE_PACKET) + get(w, RECORD_SIZE):
            return BAD
        keep(w, INTAKE_PACKET, fd, size)
        return next_artifact(o, w)
    if state == INTAKE_PUBLISHED and length(s) == 64:
        return action(o, w, INTAKE_PUBLISHED, FINISHED, 0, 0, 0, 0)
    return BAD

def bind_request_spans(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    size = input_word(s, 40)
    count = input_word(s, 80)
    if input_word(s, 64) != size - 8 or input_word(s, 72) != REQUEST_LAYOUT or count < 1 or count > 16 or size != 120 + 16 * count:
        return BAD
    put(w, RECEIPT_COUNT, count)
    fd = slot_fd(w, ARGUMENT_FD)
    total = slot_bytes(w, ARGUMENT_FD)
    i = 0
    while i < count + 4:
        p = 88 + 16 * choose(i < 4, i, i + 2)
        offset = input_word(s, p)
        span = input_word(s, p + 8)
        if span != choose(i == 0, 121, 176) or offset < 68 or offset - 60 > total or span > total - (offset - 60):
            return BAD
        hold(w, SELECTORS + 24 * i, fd, offset - 60, span)
        i = i + 1
    use_span(w, o, SELECTORS, 0)
    return action(o, w, CTX_REFERENCE, RUN, CONTEXT_ROLE, 0, 1, 0)

def opened_intake(o:mutbuf, w:mutbuf) -> u64:
    fd = slot_fd(w, QUERY_FD)
    return store_transaction(o, w, CTX_ROW, 4, 0, fd, 8, slot_bytes(w, QUERY_FD) - 8)

def inspect_row(o:mutbuf, w:mutbuf, purpose:u64, bytes:u64) -> u64:
    put(o, HEADER + 8, bytes)
    put(o, HEADER + 16, get(w, STORE_REQUEST))
    put(o, HEADER + 24, get(w, STORE_EPOCH))
    use_span(w, o, ACTIVE_REFERENCE, 0)
    whole_slot(w, o, STORE_RESULT, 1)
    if purpose == CTX_ROW:
        put(o, HEADER, CONTEXT_OBSERVE_TAG)
        put(o, HEADER + 32, 0)
        return action(o, w, CTX_OBSERVED, RUN, CONTEXT_STORE_ROLE, 0, 2, 36)
    if purpose != ART_ROW:
        return BAD
    put(o, HEADER, RETAINED_OBSERVED)
    put(o, HEADER + 32, get(w, ACTIVE_KIND))
    return action(o, w, ART_OBSERVED, RUN, PROFILE_ROLE, 0, 2, 40)

def retained_query(o:mutbuf, w:mutbuf) -> u64:
    put(o, HEADER, RETAINED_QUERY)
    put(o, HEADER + 8, get(w, ACTIVE_KIND))
    use_span(w, o, ACTIVE_REFERENCE, 0)
    return action(o, w, ART_QUERY, RUN, PROFILE_ROLE, 0, 1, 16)

def capture_artifact(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    kind = get(w, ACTIVE_KIND)
    if kind == 3:
        if length(s) != 136 or input_word(s, 64) != RETAINED_AUTHORITY:
            return BAD
        hold(w, METADATA_SPAN, slot_fd(w, STORE_RESULT), 0, 0)
    else:
        if length(s) != 152 or input_word(s, 64) != BUILD_AUTHORITY:
            return BAD
        at = input_word(s, 136)
        bytes = input_word(s, 144)
        size = slot_bytes(w, STORE_RESULT) - 48
        if at > size or bytes > size - at:
            return BAD
        hold(w, METADATA_SPAN, slot_fd(w, STORE_RESULT), at, bytes)
    i = 0
    while i < 64:
        c = byte(s, 72 + i)
        if is_hex(c) == False:
            return BAD
        store(o, 416 + i, c)
        i = i + 1
    store(o, 480, 0)
    return artifact_command(o, w, ART_BODY, STORE_GET, STORE_GET_END, 0)

def retain_body(o:mutbuf, w:mutbuf, fd:u64, size:u64) -> u64:
    meta = get(w, METADATA_SPAN + 16)
    row = 32 + 176 + meta + size
    if row > 67108864 or row > 67108864 - slot_bytes(w, INTAKE_PACKET):
        return close_store(o, w, CLOSE_REFUSED)
    put(w, RECORD_SIZE, row)
    put(o, HEADER, get(w, SELECTOR))
    put(o, HEADER + 8, get(w, ACTIVE_KIND))
    put(o, HEADER + 16, meta)
    put(o, HEADER + 24, size)
    use_span(w, o, ACTIVE_REFERENCE, 0)
    use_span(w, o, METADATA_SPAN, 1)
    fragment(o, 2, fd, 0, size)
    return action(o, w, ROW_MADE, MAKE, 0, 0, 3, 32)

def next_artifact(o:mutbuf, w:mutbuf) -> u64:
    index = get(w, SELECTOR) + 1
    if index == 4 + get(w, RECEIPT_COUNT):
        return close_store(o, w, CLOSE_INTAKE)
    put(w, SELECTOR, index)
    put(w, ACTIVE_KIND, choose(index < 3, 7, choose(index == 3, 5, 8)))
    src = SELECTORS + 24 * index
    hold(w, ACTIVE_REFERENCE, get(w, src), get(w, src + 8), get(w, src + 16))
    return retained_query(o, w)

def publish_intake(o:mutbuf, w:mutbuf) -> u64:
    put(o, HEADER, INTAKE)
    put(o, HEADER + 8, get(w, RECEIPT_COUNT) + 4)
    whole_slot(w, o, INTAKE_PACKET, 0)
    return action(o, w, INTAKE_PUBLISHED, PUBLISH, 0, 0, 1, 16)
'''


def program():
    constants, controls = recipe(ROLES)
    constants.update(SCHEMA_TOOL=9, MAKE=11, RECEIPT_COUNT=2304, SELECTOR=2312, ACTIVE_KIND=2320,
                     RECORD_SIZE=2328, SELECTORS=2368, ACTIVE_REFERENCE=2848, METADATA_SPAN=2872,
                     CREATION=2896, INTAKE_PACKET=18, OPEN_INTAKE=50, CTX_ROW=51, ART_ROW=52,
                     CLOSE_INTAKE=53, CLOSE_REFUSED=54)
    states = ('REQUEST_SPANS','CTX_REFERENCE','CTX_QUERY','CTX_OBSERVED','ART_QUERY','ART_OBSERVED',
              'ART_AUTH','ART_BODY','ROW_MADE','ROW_JOINED','INTAKE_PUBLISHED')
    constants.update({name: i for i, name in enumerate(states, 60)})
    tags = dict(REQUEST_LAYOUT=b'HIAEVQ01', INTAKE=b'HIAEFI01', CONTEXT_REFERENCE_TAG=b'HIACTRL1',
                CONTEXT_QUERY_TAG=b'HIACTL01', CONTEXT_OBSERVE_TAG=b'HIACTO01', CONTEXT_OBSERVED_TAG=b'HIACTO02',
                RETAINED_QUERY=b'HIARFG01', RETAINED_OBSERVED=b'HIARFG02', RETAINED_AUTHORITY=b'HIARFO02',
                BUILD_AUTHORITY=b'HIABRD01')
    constants.update({name: int.from_bytes(value,'little') for name,value in tags.items()})
    driver = REPLAY[:REPLAY.index('def closed_store(')]
    driver = driver.replace('    return publish_cached(s, o, w, state)', '    return intake(s, o, w, state)')
    driver = driver.replace('    if get(w, STORE_PURPOSE) != OPEN_LOOKUP:',
                            '    if get(w, STORE_PURPOSE) == OPEN_INTAKE:\n        return opened_intake(o, w)\n'
                            '    if get(w, STORE_PURPOSE) != OPEN_LOOKUP:')
    settled = function(STORE_POLICY, 'settle_transaction').split('    if purpose == STORE_LOOKUP')[0]
    settled += ('    if purpose == STORE_LOOKUP:\n        return interpret_row(o, w, purpose, bytes)\n'
                '    return inspect_row(o, w, purpose, bytes)\n')
    controls = [settled if c.lstrip().startswith('def settle_transaction(') else c for c in controls]
    controls.extend((function(ARTIFACT,'json_pair'),function(ARTIFACT,'schema_receipt'),
                     function(DESCRIBE,'reply_word'),function(CONTROL_POLICY,'hold'),function(CONTROL_POLICY,'use_span'),
                     function(RETAINED_POLICY,'artifact_command')))
    return flow_source(driver + POLICY, controls, constants)


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)), encoding='utf-8')
    from tools.generate_hia_readonly_worker_capsule import INTAKE_SOURCE as capsule, source_program
    from tools.generate_hia_worker_launcher_flow import INTAKE_SOURCE as launcher, program as launcher_program
    for target, candidate in ((Path(capsule), source_program(artifact=True, evaluate_intake=True)),
                              (launcher, launcher_program(evaluate_intake=True))):
        target.write_text(render_assembly(document(candidate, target.stem)), encoding='utf-8')
