"""Author the HIA Read effect's two-channel transport and Store settlement."""

from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_release_install import POLICY_SOURCE as RELEASE_WRITER
from tools.generate_hia_worker_cost_flow import POLICY as COST_POLICY
from tools.generate_hia_worker_describe_flow import POLICY as FLOW_POLICY, flow_source
from tools.generate_hia_worker_describe_reactor import POLICY as ENTRY_POLICY, program as entry_program
from tools.generate_hia_worker_inspection_effect import function

SOURCE = Path('examples/hia_bootstrap/worker_read_store_flow.hepta')
EXTERNAL_SOURCE = Path('examples/hia_bootstrap/worker_read_external_flow.hepta')

POLICY = r'''
def read_store_flow(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 8 or length(o) != 2048 or length(w) != 4096:
        return BAD
    state = get(w, 0)
    if state == 0:
        return admit_read(s, o, w)
    if length(s) < 64 or input_word(s, 0) != OBSERVATION or input_word(s, 8) != get(w, 8):
        return BAD
    operation = get(w, 16)
    if input_word(s, 16) != operation or input_word(s, 24) != 0:
        return BAD
    captured = input_word(s, 56)
    if captured != length(s) - 64 or captured > input_word(s, 40):
        return BAD
    if operation == RUN and (valid_fd(input_word(s, 32)) == False or input_word(s, 48) != 0):
        return BAD
    if operation == READ and (input_word(s, 32) != get(w, 80) or input_word(s, 48) != get(w, 88) or captured != get(w, 96)):
        return BAD
    if state <= EFFECT_STARTED:
        return open_read(s, o, w, state)
    if state == OBSERVATION_SENT:
        return receive(o, w, ACTION_LENGTH, EFFECT_PEER, 8, False)
    if state == ACTION_LENGTH:
        if length(s) != 72 or input_word(s, 40) != 8:
            return BAD
        bytes = input_word(s, 64)
        if bytes < 48 or bytes > 8192:
            return BAD
        put(w, 104, bytes)
        return receive(o, w, ACTION_FRAME, EFFECT_PEER, bytes, True)
    if state == ACTION_FRAME:
        return dispatch_read(s, o, w)
    if state >= UNIQUE_RETURNED and state <= STORE_SETTLED:
        return settle_store(s, o, w, state)
    if state >= ADMISSION_OBSERVED and state <= PAGE_OBSERVED:
        return feedback_read(s, o, w, state)
    return close_read(s, o, w, state)

def admit_read(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if length(s) != ENTRY_HEAD + ROLE_COUNT * DESCRIPTOR_BYTES or input_word(s, 0) != ENTRY:
        return BAD
    size = input_word(s, 8)
    if size < 128 or size > 8192:
        return BAD
    keep(w, ORIGINAL, 0, size)
    if OWNED_STORE == 0:
        return use_external_store(s, o, w)
    path = input_word(s, 16)
    if path < 2 or path >= 4083 or input_word(s, 24) == 47 or trusted_descriptors(s, 0, 0) == False:
        return BAD
    argv(o, 0, INPUT_ARG, 2)
    put(o, 160, STORE_ARG)
    argv(o, 1, LITERAL_ARG, 160)
    argv(o, 2, INPUT_ARG, 3)
    put(o, 176, STORE_PEER)
    return action(o, w, STORE_STARTED, START_PEER, STORE_ROLE, 3, 0, 0)

def use_external_store(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    reply = input_word(s, 48)
    command = input_word(s, 56)
    if valid_fd(reply) == False or valid_fd(command) == False or reply == command:
        return BAD
    if trusted_descriptors(s, reply, command) == False:
        return BAD
    put(w, 32, reply)
    put(w, 40, command)
    put(w, 48, input_word(s, 40))
    put(w, 56, input_word(s, 32))
    put(w, 64, 1)
    return start_effect(o, w)

def start_effect(o:mutbuf, w:mutbuf) -> u64:
    put(o, 176, EFFECT_PEER)
    return action(o, w, EFFECT_STARTED, START_PEER, EFFECT_ROLE, 0, 0, 0)

def open_read(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    if state == STORE_STARTED:
        if length(s) != 80 or input_word(s, 40) != 16:
            return BAD
        reply = input_word(s, 64)
        command = input_word(s, 72)
        if valid_fd(reply) == False or valid_fd(command) == False or reply == command:
            return BAD
        put(w, 32, reply)
        put(w, 40, command)
        return receive(o, w, READINESS_FRAME, STORE_PEER, 80, False)
    if state == READINESS_FRAME:
        if length(s) != 144 or input_word(s, 40) != 80:
            return BAD
        copy_span(s, o, 64, HEADER, 80)
        return action(o, w, READY_VALIDATED, RUN, READY_ROLE, 0, 0, 80)
    if state == READY_VALIDATED:
        if length(s) != 80 or input_word(s, 40) != 16 or input_word(s, 64) != 1:
            return BAD
        put(w, 48, input_word(s, 72))
        put(w, 64, 2)
        return start_effect(o, w)
    if length(s) != 80 or input_word(s, 40) != 16:
        return BAD
    whole_slot(w, o, ORIGINAL, 0)
    return send_observation(o, w, 1, 0, slot_bytes(w, ORIGINAL), 1)

def dispatch_read(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    bytes = get(w, 104)
    fd = input_word(s, 32)
    if length(s) != 64 + bytes or input_word(s, 40) != bytes or valid_fd(fd) == False:
        return BAD
    step = get(w, 72) + 1
    if input_word(s, 64) != EFFECT_ACTION or input_word(s, 80) != step or step > 12:
        return BAD
    put(w, 72, step)
    role = input_word(s, 72)
    offset = input_word(s, 88)
    extent = input_word(s, 96)
    auxiliary = input_word(s, 104)
    payload = bytes - 48
    if role == 1 or role == 5:
        if offset != 0 or extent != 0 or payload == 0 or auxiliary != choose(role == 1, 2, 6):
            return BAD
        fragment(o, 0, fd, 48, payload)
        return store_operation(o, w, role, auxiliary, payload)
    if role == 2 or role == 6:
        if auxiliary != 0 or payload == 0:
            return BAD
        row = choose(role == 2, ARTIFACT_ROW, CURSOR_ROW)
        if good_span(w, row, offset, extent) == False:
            return BAD
        fragment(o, 0, fd, 48, payload)
        fragment(o, 1, slot_fd(w, row), offset, extent)
        return action(o, w, choose(role == 2, ADMISSION_OBSERVED, PRELUDE_OBSERVED),
                      RUN, choose(role == 2, PAGE_ROLE, PLAN_ROLE), 0, 2, 0)
    if role == 3:
        if offset != 0 or extent != 0 or payload != 64 or auxiliary > 2048:
            return BAD
        return artifact_capture(s, o, w)
    if role == 4:
        if payload != 0 or auxiliary != 0 or good_span(w, ARTIFACT_ROW, offset, extent) == False:
            return BAD
        put(o, HEADER, 4300)
        put(o, HEADER + 8, DATA_VALIDATE)
        fragment(o, 0, slot_fd(w, ARTIFACT_ROW), offset, extent)
        return action(o, w, METADATA_OBSERVED, RUN, DATA_ROLE, 0, 1, 16)
    if role == 7:
        if payload != 0 or offset != 0 or extent != slot_bytes(w, PRELUDE) or auxiliary != slot_bytes(w, CAPTURE):
            return BAD
        if slot_fd(w, PRELUDE) == 0 or slot_fd(w, CAPTURE) == 0:
            return BAD
        whole_slot(w, o, PRELUDE, 0)
        whole_slot(w, o, CAPTURE, 1)
        return action(o, w, PAGE_OBSERVED, RUN, PAGE_ROLE, 0, 2, 0)
    if role == 8:
        if payload != 0 or auxiliary != 10 or extent == 0 or good_span(w, PAGE, offset, extent) == False:
            return BAD
        fragment(o, 0, slot_fd(w, PAGE), offset, extent)
        return store_operation(o, w, role, auxiliary, extent)
    if (role == 9 or role == 10) and payload == 0:
        return terminal_plan(o, w, role, offset, extent, auxiliary)
    return BAD

def artifact_capture(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    i = 0
    while i < 64:
        v = byte(s, 112 + i)
        if is_hex(v) == False:
            return BAD
        store(o, 416 + i, v)
        i = i + 1
    store(o, 480, 0)
    put(o, 384, STORE_GET)
    put(o, 392, STORE_GET_END)
    put(o, 400, ARTIFACT_ROOT)
    put(o, 408, ARTIFACT_ROOT_END)
    argv(o, 0, LITERAL_ARG, 384)
    if OWNED_STORE == 1:
        argv(o, 1, JOINED_ARG, 400)
    else:
        argv(o, 1, INPUT_ARG, 1)
    argv(o, 2, LITERAL_ARG, 416)
    return action(o, w, CAPTURE_OBSERVED, RUN, CAPTURE_ROLE, 3, 0, 0)

def store_operation(o:mutbuf, w:mutbuf, stage:u64, plan:u64, bytes:u64) -> u64:
    limit = choose(stage == 8, 67112960, 8192)
    if bytes == 0 or bytes > limit:
        return BAD
    put(w, 112, stage)
    put(o, HEADER, UNIQUE)
    put(o, HEADER + 8, get(w, 56))
    put(o, HEADER + 16, plan)
    put(o, HEADER + 24, get(w, 64))
    put(o, HEADER + 32, get(w, 48))
    put(o, HEADER + 40, bytes)
    argv(o, 0, FD_ARG, get(w, 32))
    argv(o, 1, FD_ARG, get(w, 40))
    return action(o, w, UNIQUE_RETURNED, RUN, UNIQUE_ROLE, 2, 1, 48)

def settle_store(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    if state == UNIQUE_RETURNED:
        bytes = input_word(s, 40)
        if bytes < 48 or bytes > 67113008:
            return BAD
        observe_slot(s, w, STORE_RESULT)
        return read_span(o, w, STORE_SETTLED, slot_fd(w, STORE_RESULT), bytes - 48, 48)
    if length(s) != 112 or input_word(s, 40) != slot_bytes(w, STORE_RESULT):
        return BAD
    size = input_word(s, 40) - 48
    request = input_word(s, 96)
    generation = input_word(s, 104)
    next_request = get(w, 56) + choose(get(w, 64) == 2, 2, 3)
    if input_word(s, 64) != 5 or input_word(s, 72) != size or input_word(s, 80) > 1 or input_word(s, 88) != 0:
        return BAD
    if request != next_request or generation < get(w, 48):
        return BAD
    put(w, 56, request)
    put(w, 48, generation)
    put(w, 64, 1)
    stage = get(w, 112)
    fd = slot_fd(w, STORE_RESULT)
    if stage == 8:
        if size != 8:
            return BAD
        fragment(o, 0, fd, 0, 56)
        return send_observation(o, w, 9, 0, 56, 1)
    row = choose(stage == 1, ARTIFACT_ROW, CURSOR_ROW)
    keep(w, row, fd, size)
    return send_observation(o, w, choose(stage == 1, 2, 6), size, 0, 0)

def feedback_read(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    size = input_word(s, 40)
    fd = input_word(s, 32)
    if state == ADMISSION_OBSERVED:
        if size != 40:
            return BAD
        fragment(o, 0, fd, 0, size)
        return send_observation(o, w, 3, 0, size, 1)
    if state == CAPTURE_OBSERVED:
        if size > 67108864:
            return BAD
        observe_slot(s, w, CAPTURE)
        return send_observation(o, w, 4, size, 0, 0)
    if state == METADATA_OBSERVED:
        if size != 8 or length(s) != 72:
            return BAD
        return send_observation(o, w, 5, input_word(s, 64), 0, 0)
    if state == PRELUDE_OBSERVED:
        observe_slot(s, w, PRELUDE)
        return send_observation(o, w, 7, size, 0, 0)
    prefix = choose(size == 40, 40, 32)
    if size < prefix:
        return BAD
    observe_slot(s, w, PAGE)
    fragment(o, 0, fd, 0, prefix)
    return send_observation(o, w, 8, size, prefix, 1)

def terminal_plan(o:mutbuf, w:mutbuf, role:u64, offset:u64, extent:u64, code:u64) -> u64:
    if role == 9:
        if code != 0 or extent == 0 or good_span(w, PAGE, offset, extent) == False:
            return BAD
        put(w, 128, slot_fd(w, PAGE))
    else:
        if code == 0 or offset != 0 or extent != 0:
            return BAD
        put(w, 128, 0)
    put(w, 120, code)
    put(w, 136, offset)
    put(w, 144, extent)
    put(o, 176, EFFECT_PEER)
    return action(o, w, EFFECT_FINISHED, FINISH_PEER, 0, 0, 0, 0)

def close_read(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    if length(s) != 64 or input_word(s, 32) != 0 or input_word(s, 40) != 0:
        return BAD
    if state == EFFECT_FINISHED and OWNED_STORE == 1:
        put(o, 176, STORE_PEER)
        return action(o, w, STORE_FINISHED, FINISH_PEER, 0, 0, 0, 0)
    if state == STORE_FINISHED or (state == EFFECT_FINISHED and OWNED_STORE == 0):
        put(o, HEADER, EFFECT_RESULT)
        put(o, HEADER + 8, get(w, 120))
        put(o, HEADER + 16, get(w, 56))
        put(o, HEADER + 24, get(w, 48))
        put(o, HEADER + 32, get(w, 72))
        put(o, HEADER + 40, get(w, 144))
        fragment(o, 0, get(w, 128), get(w, 136), get(w, 144))
        return action(o, w, RESULT_PUBLISHED, PUBLISH, 0, 0, 1, 48)
    if state == RESULT_PUBLISHED:
        return action(o, w, RESULT_PUBLISHED, FINISHED, 0, 0, 0, 0)
    return BAD

def good_span(w:mutbuf, slot:u64, offset:u64, extent:u64) -> bool:
    size = slot_bytes(w, slot)
    return offset <= size and extent <= size - offset

def send_observation(o:mutbuf, w:mutbuf, event:u64, extent:u64, body:u64, parts:u64) -> u64:
    put(o, HEADER, EFFECT_EVENT)
    put(o, HEADER + 8, event)
    put(o, HEADER + 16, get(w, 72) + 1)
    put(o, HEADER + 24, extent)
    put(o, HEADER + 32, body)
    put(o, 176, EFFECT_PEER)
    return action(o, w, OBSERVATION_SENT, SEND_PEER, 0, 0, parts, 40)

def receive(o:mutbuf, w:mutbuf, state:u64, peer:u64, bytes:u64, sealed:bool) -> u64:
    put(o, 144, bytes)
    put(o, 176, peer)
    put(o, 184, choose(sealed, 1, 0))
    return action(o, w, state, RECEIVE_PEER, 0, 0, 0, 0)

def read_span(o:mutbuf, w:mutbuf, state:u64, fd:u64, at:u64, bytes:u64) -> u64:
    put(w, 80, fd)
    put(w, 88, at)
    put(w, 96, bytes)
    fragment(o, 0, fd, at, bytes)
    return action(o, w, state, READ, 0, 0, 1, 0)
'''


def program(*, external=False):
    constants = {name: int.from_bytes(value, 'little') for name, value in {
        'ENTRY': b'HIADRI01', 'OBSERVATION': b'HIADFO01', 'COMMAND': b'HIADFC01',
        'STORE_ARG': b'store', 'UNIQUE': b'HIASTUP1', 'EFFECT_EVENT': b'HIAFDE01',
        'EFFECT_ACTION': b'HIAFDA01', 'EFFECT_RESULT': b'HIAFDO01',
        'STORE_GET': b'store-ge', 'STORE_GET_END': b't',
        'ARTIFACT_ROOT': b'/artifac', 'ARTIFACT_ROOT_END': b'ts', 'DATA_VALIDATE': b'HIAWDV01',
    }.items()}
    constants.update(BAD=0xfffffffd, HEADER=512, ARGUMENTS=192, ELF_MAGIC=0x464c457f,
                     DEFAULT_CHILD_LEASE=10_000_000_000, ROLE_COUNT=6 if external else 8,
                     OWNED_STORE=0 if external else 1,
                     ENTRY_HEAD=64, DOSSIER_HEAD=0, DESCRIPTOR_BYTES=40, SLOT_BASE=256,
                     RUN=1, READ=2, PUBLISH=3, FINISHED=5, START_PEER=6, RECEIVE_PEER=7,
                     FINISH_PEER=8, SEND_PEER=9, INPUT_ARG=1, LITERAL_ARG=2, FD_ARG=4, JOINED_ARG=5,
                     STORE_PEER=0, EFFECT_PEER=1, STORE_ROLE=0, READY_ROLE=1, EFFECT_ROLE=2,
                     PLAN_ROLE=3, PAGE_ROLE=4, DATA_ROLE=5, CAPTURE_ROLE=6, UNIQUE_ROLE=7)
    for slot, name in enumerate(('ORIGINAL', 'ARTIFACT_ROW', 'CURSOR_ROW', 'CAPTURE', 'PRELUDE',
                                  'PAGE', 'STORE_RESULT')):
        constants[name] = slot
    for index, name in enumerate(('STORE_STARTED', 'READINESS_FRAME', 'READY_VALIDATED', 'EFFECT_STARTED',
                                   'OBSERVATION_SENT', 'ACTION_LENGTH', 'ACTION_FRAME', 'UNIQUE_RETURNED',
                                   'STORE_SETTLED', 'ADMISSION_OBSERVED', 'CAPTURE_OBSERVED',
                                   'METADATA_OBSERVED', 'PRELUDE_OBSERVED', 'PAGE_OBSERVED',
                                   'EFFECT_FINISHED', 'STORE_FINISHED', 'RESULT_PUBLISHED'), 1):
        constants[name] = index
    entry = entry_program()
    controls = (function(COST_POLICY, 'action'), function(ENTRY_POLICY, 'trusted_descriptors'),
                *(function(FLOW_POLICY, name) for name in ('argv', 'issue', 'fragment', 'keep', 'observe_slot',
                                                           'slot_fd', 'slot_bytes', 'whole_slot')),
                *(function(entry, name) for name in ('valid_fd', 'is_hex', 'copy_span', 'input_word', 'put', 'write')),
                function(RELEASE_WRITER, 'get'))
    return flow_source(POLICY, controls, constants)


if __name__ == '__main__':
    for path, external in ((SOURCE, False), (EXTERNAL_SOURCE, True)):
        path.write_text(render_assembly(document(program(external=external), path.stem)), encoding='utf-8')
