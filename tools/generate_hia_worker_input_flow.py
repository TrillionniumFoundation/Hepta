"""Author the native Worker input materialization and Store settlement flow."""

from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_release_install import POLICY_SOURCE as RELEASE_WRITER
from tools.generate_hia_worker_cost_flow import POLICY as COST_POLICY
from tools.generate_hia_worker_describe_flow import POLICY as FLOW_POLICY, flow_source
from tools.generate_hia_worker_describe_reactor import POLICY as ENTRY_POLICY, program as entry_program
from tools.generate_hia_worker_inspection_effect import function
from tools.generate_hia_worker_read_store_flow import POLICY as READ_POLICY

SOURCE = Path('examples/hia_bootstrap/worker_input_flow.hepta')
DISCOVERY = Path('examples/hia_bootstrap/worker_discovery_flow.hepta')

POLICY = r'''
def input_flow(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 8 or length(o) != 2048 or length(w) != 4096:
        return BAD
    state = get(w, 0)
    if state == 0:
        return admit_input(s, o, w)
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
        return open_input(s, o, w, state)
    if state == OBSERVATION_SENT:
        return receive(o, w, ACTION_LENGTH, EFFECT_PEER, 8, False)
    if state == ACTION_LENGTH:
        bytes = input_word(s, 64)
        if length(s) != 72 or input_word(s, 40) != 8 or bytes < 48 or bytes > 512:
            return BAD
        put(w, 104, bytes)
        return receive(o, w, ACTION_FRAME, EFFECT_PEER, bytes, True)
    if state == ACTION_FRAME:
        return dispatch_input(s, o, w)
    if state <= STORE_SETTLED:
        return observe_input(s, o, w, state)
    return close_input(s, o, w, state)

def admit_input(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if length(s) != ENTRY_HEAD + ROLE_COUNT * DESCRIPTOR_BYTES + 64 or input_word(s, 0) != ENTRY:
        return BAD
    extent = input_word(s, 8)
    path = input_word(s, 16)
    if extent > 8388608 or path < 2 or path >= 4083 or input_word(s, 24) == 47:
        return BAD
    expected = input_word(s, 32)
    if expected != 64 and (expected != 1 or byte(s, EXPECTED_START) != 45):
        return BAD
    if trusted_descriptors(s, 0, 0) == False:
        return BAD
    put(w, 120, extent)
    put(w, 128, choose(expected == 64, 64, 0))
    copy_span(s, w, EXPECTED_START, SCRATCH, get(w, 128))
    argv(o, 0, INPUT_ARG, 1)
    put(o, 160, STORE_ARG)
    argv(o, 1, LITERAL_ARG, 160)
    argv(o, 2, INPUT_ARG, 2)
    put(o, 176, STORE_PEER)
    return action(o, w, STORE_STARTED, START_PEER, STORE_ROLE, 3, 0, 0)

def open_input(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
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
    put(o, HEADER + 40, 3)
    put(o, HEADER + 48, 0)
    expected = get(w, 128)
    i = 0
    while i < expected:
        store(o, HEADER + 56 + i, byte(w, SCRATCH + i))
        i = i + 1
    return input_observation(o, w, 1, get(w, 120), 16 + expected, 16 + expected, 0)

def dispatch_input(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    bytes = get(w, 104)
    fd = input_word(s, 32)
    step = get(w, 72) + 1
    if length(s) != 64 + bytes or input_word(s, 40) != bytes or valid_fd(fd) == False:
        return BAD
    if input_word(s, 64) != EFFECT_ACTION or input_word(s, 80) != step or step > 12:
        return BAD
    payload = bytes - 48
    if input_word(s, 88) != 0 or input_word(s, 96) != payload:
        return BAD
    put(w, 72, step)
    role = input_word(s, 72)
    auxiliary = input_word(s, 104)
    extent = get(w, 120)
    if role == 1 or role == 3:
        if payload != 0 or auxiliary != extent:
            return BAD
        put(o, 384, choose(role == 1, STORE_HASH, STORE_PUT))
        put(o, 392, choose(role == 1, STORE_HASH_END, STORE_PUT_END))
        put(o, 416, 45)
        fragment(o, 0, 0, 0, extent)
        put(w, 112, choose(role == 1, 2, 4))
        return publisher(o, w, PUBLISHER_RETURNED, 1)
    if role == 2 or role == 4:
        if payload != 80:
            return BAD
        put(w, 112, role)
        if role == 2:
            fragment(o, 0, fd, 48, 80)
            return action(o, w, PLANNER_RETURNED, RUN, PLANNER_ROLE, 0, 1, 0)
        put(w, 128, fd)
        put(o, 144, 32)
        return action(o, w, NONCES_RETURNED, RANDOM, 0, 0, 0, 0)
    if role == 5:
        if payload != 64 or auxiliary != extent:
            return BAD
        put(o, 384, STORE_GET)
        put(o, 392, STORE_GET_END)
        i = 0
        while i < 64:
            v = byte(s, 112 + i)
            if is_hex(v) == False:
                return BAD
            store(o, 416 + i, v)
            i = i + 1
        store(o, 480, 0)
        return publisher(o, w, CAPTURE_RETURNED, 0)
    if role == 7 and payload == 176:
        put(w, 128, fd)
        put(w, 136, 0)
        return finish_effect(o, w)
    if role == 8 and payload == 0 and auxiliary == 0:
        put(w, 136, 73)
        return finish_effect(o, w)
    return BAD

def publisher(o:mutbuf, w:mutbuf, state:u64, parts:u64) -> u64:
    put(o, 400, ARTIFACT_ROOT)
    put(o, 408, ARTIFACT_ROOT_END)
    argv(o, 0, LITERAL_ARG, 384)
    argv(o, 1, JOINED_ARG, 400)
    argv(o, 2, LITERAL_ARG, 416)
    return action(o, w, state, RUN, PUBLISHER_ROLE, 3, parts, 0)

def observe_input(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    bytes = input_word(s, 40)
    fd = input_word(s, 32)
    if state == PUBLISHER_RETURNED:
        if bytes > 512:
            return BAD
        fragment(o, 0, fd, 0, bytes)
        return input_observation(o, w, get(w, 112), 0, bytes, 0, 1)
    if state == CAPTURE_RETURNED:
        return input_observation(o, w, 6, bytes, 0, 0, 0)
    if state == NONCES_RETURNED:
        if length(s) != 96 or bytes != 32:
            return BAD
        copy_span(s, w, 64, SCRATCH, 32)
        return read_span(o, w, INSERT_BODY, get(w, 128), 48, 80)
    if state == INSERT_BODY:
        copy_span(s, o, 64, HEADER, 80)
        i = 0
        while i < 32:
            store(o, HEADER + 80 + i, byte(w, SCRATCH + i))
            i = i + 1
        return action(o, w, PLANNER_RETURNED, RUN, PLANNER_ROLE, 0, 0, 112)
    if state == PLANNER_RETURNED:
        return planner_result(s, o, w, fd, bytes)
    if state == UNIQUE_RETURNED:
        if bytes < 48 or bytes > 512:
            return BAD
        put(w, 144, bytes)
        return read_span(o, w, STORE_SETTLED, fd, bytes - 48, 48)
    if state == STORE_SETTLED:
        return settled_input(s, o, w, fd, bytes)
    return BAD

def planner_result(s:readbuf, o:mutbuf, w:mutbuf, fd:u64, bytes:u64) -> u64:
    width = input_word(s, 64)
    if length(s) < 72 or width < 2 or width > 1024 or bytes != 8 + width:
        return BAD
    if get(w, 112) == 2:
        fragment(o, 0, fd, 8, width)
        return store_input(o, w, 1, width)
    if length(s) < 96 or input_word(s, 72) != TYPED:
        return BAD
    durable = input_word(s, 80)
    view = input_word(s, 88)
    if width < 24 or durable == 0 or view > 256 or view > width - 24 or durable != width - 24 - view:
        return BAD
    fragment(o, 0, fd, 32, durable)
    return store_input(o, w, 20, durable)

def store_input(o:mutbuf, w:mutbuf, plan:u64, bytes:u64) -> u64:
    put(o, HEADER, UNIQUE)
    put(o, HEADER + 8, get(w, 56))
    put(o, HEADER + 16, plan)
    put(o, HEADER + 24, get(w, 64))
    put(o, HEADER + 32, get(w, 48))
    put(o, HEADER + 40, bytes)
    argv(o, 0, FD_ARG, get(w, 32))
    argv(o, 1, FD_ARG, get(w, 40))
    return action(o, w, UNIQUE_RETURNED, RUN, UNIQUE_ROLE, 2, 1, 48)

def settled_input(s:readbuf, o:mutbuf, w:mutbuf, fd:u64, bytes:u64) -> u64:
    if length(s) != 112 or bytes != get(w, 144):
        return BAD
    request = input_word(s, 96)
    generation = input_word(s, 104)
    next_request = get(w, 56) + choose(get(w, 64) == 2, 2, 3)
    if input_word(s, 64) != 5 or input_word(s, 72) != bytes - 48 or input_word(s, 80) > 1 or input_word(s, 88) != 0:
        return BAD
    if request != next_request or generation < get(w, 48):
        return BAD
    put(w, 56, request)
    put(w, 48, generation)
    put(w, 64, 1)
    fragment(o, 0, fd, 0, bytes)
    return input_observation(o, w, get(w, 112) + 1, 0, bytes, 0, 1)

def input_observation(o:mutbuf, w:mutbuf, event:u64, extent:u64, body:u64, inline:u64, parts:u64) -> u64:
    put(o, HEADER, EFFECT_EVENT)
    put(o, HEADER + 8, event)
    put(o, HEADER + 16, get(w, 72) + 1)
    put(o, HEADER + 24, extent)
    put(o, HEADER + 32, body)
    put(o, 176, EFFECT_PEER)
    return action(o, w, OBSERVATION_SENT, SEND_PEER, 0, 0, parts, 40 + inline)

def finish_effect(o:mutbuf, w:mutbuf) -> u64:
    put(o, 176, EFFECT_PEER)
    return action(o, w, EFFECT_FINISHED, FINISH_PEER, 0, 0, 0, 0)

def close_input(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    if length(s) != 64 or input_word(s, 32) != 0 or input_word(s, 40) != 0:
        return BAD
    if state == EFFECT_FINISHED:
        put(o, 176, STORE_PEER)
        return action(o, w, STORE_FINISHED, FINISH_PEER, 0, 0, 0, 0)
    status = get(w, 136)
    if state == STORE_FINISHED:
        if status == 73:
            fragment(o, 0, 0, 0, 0)
            return action(o, w, RESULT_PUBLISHED, PUBLISH, 0, 0, 1, 0)
        put(o, HEADER, RESULT)
        put(o, HEADER + 8, 176)
        put(o, HEADER + 16, 0)
        fragment(o, 0, get(w, 128), 48, 176)
        return action(o, w, RESULT_PUBLISHED, PUBLISH, 0, 0, 1, 24)
    if state == RESULT_PUBLISHED:
        put(o, 144, status)
        return action(o, w, RESULT_PUBLISHED, FINISHED, 0, 0, 0, 0)
    return BAD
'''


def discovery_policy():
    # Discovery and Artifact input use the same scoped descriptor protocol.
    # Discovery sends the two numeric operands and can retain a profile view.
    # Candidate Core publication additionally carries the sealed Context wire.
    policy = POLICY.replace('extent > 8388608', 'extent > 67108864', 1)
    start = policy.index('    expected = input_word(s, 32)')
    end = policy.index('    argv(o, 0, INPUT_ARG, 1)', start)
    policy = policy[:start] + '''    if trusted_descriptors(s, 0, 0) == False:
        return BAD
    put(w, 120, extent)
    put(w, 152, input_word(s, 32))
    put(w, 160, input_word(s, 40))
    context = input_word(s, 48)
    if get(w, 152) == 8:
        if valid_fd(context) == False or input_word(s, 56) != 121:
            return BAD
        put(w, 192, context)
    elif context != 0:
        return BAD
''' + policy[end:]
    start = policy.index('    put(o, HEADER + 40, 3)')
    end = policy.index('\ndef dispatch_input(', start)
    policy = policy[:start] + '''    put(o, HEADER + 40, get(w, 152))
    put(o, HEADER + 48, get(w, 160))
    context = get(w, 192)
    if context != 0:
        fragment(o, 0, context, 0, 121)
        return input_observation(o, w, 1, get(w, 120), 137, 16, 1)
    return input_observation(o, w, 1, get(w, 120), 16, 16, 0)

''' + policy[end:]
    start = policy.index('    if role == 8 and payload == 0')
    end = policy.index('    return BAD', start)
    policy = policy[:start] + '''    if role == 6 and payload == 192 and get(w, 184) == 0:
        put(w, 112, role)
        fragment(o, 0, fd, 48, 192)
        return action(o, w, PLANNER_RETURNED, RUN, PLANNER_ROLE, 0, 1, 0)
''' + policy[end:]
    policy = policy.replace('    if length(s) < 96 or input_word(s, 72) != TYPED:',
                            '''    profile = get(w, 112) == 6
    if length(s) < 96 or input_word(s, 72) != choose(profile, TYPED_PROFILE, TYPED):''')
    policy = policy.replace('    return store_input(o, w, 20, durable)', '''    if profile:
        if view == 0:
            return BAD
        put(w, 168, fd)
        put(w, 176, bytes - view)
        put(w, 184, view)
    return store_input(o, w, choose(profile, 19, 20), durable)''')
    policy = policy.replace('bytes < 48 or bytes > 512:', 'bytes < 48 or bytes > 1024:')
    start = policy.index('    status = get(w, 136)\n')
    end = policy.index('    return BAD', start)
    return policy[:start] + '''    if state == STORE_FINISHED:
        view = get(w, 184)
        put(o, HEADER, RESULT)
        put(o, HEADER + 8, 176)
        put(o, HEADER + 16, view)
        fragment(o, 0, get(w, 128), 48, 176)
        if view != 0:
            fragment(o, 1, get(w, 168), get(w, 176), view)
        return action(o, w, RESULT_PUBLISHED, PUBLISH, 0, 0, choose(view == 0, 1, 2), 24)
    if state == RESULT_PUBLISHED:
        put(o, 144, 0)
        return action(o, w, RESULT_PUBLISHED, FINISHED, 0, 0, 0, 0)
''' + policy[end:]


def program(*, discovery=False):
    constants = {name: int.from_bytes(value, 'little') for name, value in {
        'ENTRY': b'HIADRI01', 'OBSERVATION': b'HIADFO01', 'COMMAND': b'HIADFC01',
        'STORE_ARG': b'store', 'UNIQUE': b'HIASTUP1', 'EFFECT_EVENT': b'HIAFDE01',
        'EFFECT_ACTION': b'HIAFDA01', 'RESULT': b'HIADOC01', 'TYPED': b'HIADAR01',
        'STORE_HASH': b'store-ha', 'STORE_HASH_END': b'sh', 'STORE_PUT': b'store-pu',
        'STORE_PUT_END': b't', 'STORE_GET': b'store-ge', 'STORE_GET_END': b't',
        'ARTIFACT_ROOT': b'/artifac', 'ARTIFACT_ROOT_END': b'ts',
    }.items()}
    constants.update(BAD=0xfffffffd, HEADER=512, ARGUMENTS=192, ELF_MAGIC=0x464c457f,
                     DEFAULT_CHILD_LEASE=10_000_000_000, ROLE_COUNT=6, ENTRY_HEAD=64,
                     DOSSIER_HEAD=0, DESCRIPTOR_BYTES=40, EXPECTED_START=304, SCRATCH=512,
                     RUN=1, READ=2, PUBLISH=3, FINISHED=5, START_PEER=6, RECEIVE_PEER=7,
                     FINISH_PEER=8, SEND_PEER=9, RANDOM=10,
                     INPUT_ARG=1, LITERAL_ARG=2, FD_ARG=4, JOINED_ARG=5,
                     STORE_PEER=0, EFFECT_PEER=1, STORE_ROLE=0, READY_ROLE=1, UNIQUE_ROLE=2,
                     PUBLISHER_ROLE=3, PLANNER_ROLE=4, EFFECT_ROLE=5)
    states = ('STORE_STARTED', 'READINESS_FRAME', 'READY_VALIDATED', 'EFFECT_STARTED',
              'OBSERVATION_SENT', 'ACTION_LENGTH', 'ACTION_FRAME', 'PUBLISHER_RETURNED',
              'CAPTURE_RETURNED', 'NONCES_RETURNED', 'INSERT_BODY', 'PLANNER_RETURNED',
              'UNIQUE_RETURNED', 'STORE_SETTLED', 'EFFECT_FINISHED', 'STORE_FINISHED',
              'RESULT_PUBLISHED')
    constants.update({name: index for index, name in enumerate(states, 1)})
    entry = entry_program()
    controls = (function(COST_POLICY, 'action'), function(ENTRY_POLICY, 'trusted_descriptors'),
                *(function(FLOW_POLICY, name) for name in ('argv', 'issue', 'fragment')),
                *(function(READ_POLICY, name) for name in ('receive', 'read_span', 'start_effect')),
                *(function(entry, name) for name in ('valid_fd', 'is_hex', 'copy_span', 'input_word', 'put', 'write')),
                function(RELEASE_WRITER, 'get'))
    if discovery:
        constants['TYPED_PROFILE'] = int.from_bytes(b'HIADPS01', 'little')
    return flow_source(discovery_policy() if discovery else POLICY, controls, constants)


if __name__ == '__main__':
    for path, discovery in ((SOURCE, False), (DISCOVERY, True)):
        policy = document(program(discovery=discovery), path.stem)
        path.write_text(render_assembly(policy), encoding='utf-8')
