"""Author the Worker cost transaction and its durable closeout in HIA."""

from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_release_install import POLICY_SOURCE as RELEASE_WRITER
from tools.generate_hia_worker_describe_flow import POLICY as FLOW_POLICY, flow_source
from tools.generate_hia_worker_describe_reactor import program as entry_program
from tools.generate_hia_worker_inspection_effect import function

SOURCE = Path('examples/hia_bootstrap/worker_cost_flow.hepta')

POLICY = r'''
def cost_flow(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 8 or length(o) != 2048 or length(w) != 4096:
        return BAD
    state = get(w, 0)
    if state == 0:
        return admit_cost(s, o, w)
    if length(s) < 64 or input_word(s, 0) != OBSERVATION or input_word(s, 8) != get(w, 8):
        return BAD
    if input_word(s, 16) != get(w, 16) or input_word(s, 24) != 0:
        return BAD
    if input_word(s, 48) != 0 or input_word(s, 56) != length(s) - 64:
        return BAD
    if state == PEER_STARTED:
        return observe_channels(s, o, w)
    if state == PEER_READY:
        if length(s) != 144 or input_word(s, 40) != 80:
            return BAD
        copy_span(s, o, 64, HEADER, 80)
        return action(o, w, READY_VALIDATED, RUN, 1, 0, 0, 80)
    if state == READY_VALIDATED:
        return insert_cost(s, o, w)
    if state == COST_COMMITTED:
        return settle_cost(s, o, w)
    if length(s) != 64 or input_word(s, 32) != 0 or input_word(s, 40) != 0:
        return BAD
    if state == PEER_FINISHED:
        fragment(o, 0, get(w, 56), 0, 56)
        return action(o, w, COST_PUBLISHED, PUBLISH, 0, 0, 1, 0)
    if state == COST_PUBLISHED:
        return action(o, w, COST_PUBLISHED, FINISHED, 0, 0, 0, 0)
    return BAD

def admit_cost(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if length(s) != 184 or input_word(s, 0) != ENTRY:
        return BAD
    size = input_word(s, 8)
    if size < 184 or size > 8390608:
        return BAD
    index = 0
    while index < 3:
        at = 64 + index * 40
        fd = input_word(s, at)
        if valid_fd(fd) == False or input_word(s, at + 8) != 15 or input_word(s, at + 16) != 32768:
            return BAD
        extent = input_word(s, at + 24)
        if extent < 64 or extent > 16777216 or input_word(s, at + 32) != ELF_MAGIC:
            return BAD
        prior = 0
        while prior < index:
            if input_word(s, 64 + prior * 40) == fd:
                return BAD
            prior = prior + 1
        index = index + 1
    put(w, 24, size)
    argv(o, 0, INPUT_ARG, 2)
    put(o, 160, STORE)
    argv(o, 1, LITERAL_ARG, 160)
    argv(o, 2, INPUT_ARG, 3)
    return action(o, w, PEER_STARTED, START_PEER, 0, 3, 0, 0)

def observe_channels(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if length(s) != 80 or input_word(s, 40) != 16:
        return BAD
    reply = input_word(s, 64)
    command = input_word(s, 72)
    if valid_fd(reply) == False or valid_fd(command) == False or reply == command:
        return BAD
    put(w, 32, reply)
    put(w, 40, command)
    put(o, 144, 80)
    return action(o, w, PEER_READY, RECEIVE_PEER, 0, 0, 0, 0)

def insert_cost(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if length(s) != 80 or input_word(s, 40) != 16 or input_word(s, 64) != 1:
        return BAD
    generation = input_word(s, 72)
    if generation == MAX_WORD:
        return BAD
    put(w, 48, generation)
    put(o, HEADER, UNIQUE)
    put(o, HEADER + 8, 0)
    put(o, HEADER + 16, 18)
    put(o, HEADER + 24, 2)
    put(o, HEADER + 32, generation)
    put(o, HEADER + 40, get(w, 24))
    fragment(o, 0, 0, 0, get(w, 24))
    argv(o, 0, FD_ARG, get(w, 32))
    argv(o, 1, FD_ARG, get(w, 40))
    return action(o, w, COST_COMMITTED, RUN, 2, 2, 1, 48)

def settle_cost(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if length(s) != 120 or input_word(s, 40) != 56:
        return BAD
    if input_word(s, 64) != INTENT or input_word(s, 72) != 5 or input_word(s, 80) != 8:
        return BAD
    if input_word(s, 88) != 1 or input_word(s, 96) != 0 or input_word(s, 104) != 2:
        return BAD
    fd = input_word(s, 32)
    if valid_fd(fd) == False or input_word(s, 112) != get(w, 48) + 1:
        return BAD
    put(w, 56, fd)
    return action(o, w, PEER_FINISHED, FINISH_PEER, 0, 0, 0, 0)

def action(o:mutbuf, w:mutbuf, next:u64, op:u64, role:u64, args:u64, parts:u64, local:u64) -> u64:
    bytes = issue(o, w, next, op, role, args, parts, local)
    if op >= START_PEER:
        put(o, 152, DEFAULT_CHILD_LEASE)
    return bytes
'''


def program():
    constants = {name: int.from_bytes(value, 'little') for name, value in {
        'ENTRY': b'HIADRI01', 'OBSERVATION': b'HIADFO01', 'COMMAND': b'HIADFC01',
        'STORE': b'store', 'UNIQUE': b'HIASTUP1', 'INTENT': b'HIASTCP1',
    }.items()}
    constants.update(BAD=0xfffffffd, HEADER=512, ARGUMENTS=192, ELF_MAGIC=0x464c457f,
                     MAX_WORD=(1 << 64) - 1, DEFAULT_CHILD_LEASE=10_000_000_000,
                     RUN=1, PUBLISH=3, FINISHED=5, START_PEER=6, RECEIVE_PEER=7,
                     FINISH_PEER=8, INPUT_ARG=1, LITERAL_ARG=2, FD_ARG=4,
                     PEER_STARTED=1, PEER_READY=2, READY_VALIDATED=3,
                     COST_COMMITTED=4, PEER_FINISHED=5, COST_PUBLISHED=6)
    entry = entry_program()
    controls = (*(function(FLOW_POLICY, name) for name in ('argv', 'issue', 'fragment')),
                *(function(entry, name) for name in ('valid_fd', 'copy_span', 'input_word', 'put', 'write')),
                function(RELEASE_WRITER, 'get'))
    return flow_source(POLICY, controls, constants)


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)), encoding='utf-8')
