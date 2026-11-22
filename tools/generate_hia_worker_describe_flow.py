"""Author the Descriptor-only Describe Worker program, not its Linux transport."""

from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_release_install import POLICY_SOURCE as RELEASE_WRITER
from tools.generate_hia_worker_describe_reactor import program as reactor
from tools.generate_hia_worker_inspection_effect import function

SOURCE = Path('examples/hia_bootstrap/worker_describe_flow.hepta')
# The executor performs one issued operation; it never selects the next role.
# A private live execution retains state until the OS returns the matching
# sequence, operation, physical result and its observed prefix/tail.
WORDS = {
    'OBSERVATION': b'HIADFO01', 'COMMAND': b'HIADFC01',
    'JOURNAL_COMMAND': b'HIAJWP01', 'JOURNAL_OBSERVED': b'HIAJWV01',
    'ADMISSION': b'HIAWRA01', 'PROJECT': b'HIAWJP01', 'ARGUMENT': b'HIAWAP01',
    'EFFECT_REFUSAL': b'HIAJDE01', 'DOCUMENT_BIND': b'HIADBD01', 'RESPONSE': b'HIAWRC01',
    'COST_OBSERVATION': b'HIAJWC01', 'COST_ATTESTATION': b'HIAJWZ01', 'COST_OK': b'HIAJWG01',
    'PUBLICATION_REQUEST': b'HIATRP01',
}
STEPS = {
    'AFTER_ADMIT': 1, 'AFTER_PROJECT': 2, 'AFTER_ARGUMENT': 3,
    'AFTER_CHECK_ARGUMENT': 4, 'AFTER_PLAN': 5, 'AFTER_QUERY': 6,
    'AFTER_DOCUMENT': 7, 'AFTER_BIND': 8, 'AFTER_ANSWER': 9,
    'AFTER_REFUSAL': 10, 'AFTER_RESPONSE': 11, 'AFTER_CHECK_OUTPUT': 12,
    'AFTER_COST_CONTROL': 13, 'AFTER_COST_TYPED': 14, 'AFTER_COST_WRITE': 15,
    'AFTER_COST_ATTEST': 16, 'AFTER_TERMINAL': 17,
    'AFTER_JOURNAL_REQUEST': 18, 'AFTER_JOURNAL_REACTOR': 19,
    'AFTER_JOURNAL_PROOF': 20, 'AFTER_JOURNAL_STATE': 21,
    'AFTER_JOURNAL_RECIPE': 22, 'AFTER_PUBLISH': 23, 'AFTER_START_CLOCK': 24,
    'AFTER_COST_CLOCK': 25, 'AFTER_END_BYTE': 26,
}
SLOTS = {
    'ORIGINAL': 0, 'DOSSIER_FD': 1, 'METADATA_FD': 2, 'ADMITTED_FD': 3,
    'CALL_FD': 4, 'PLAN_FD': 5, 'QUERY_FD': 6, 'EFFECT_FD': 7, 'REPLY_FD': 8,
    'RENDERED_FD': 9, 'TERMINAL_FD': 10,
}

POLICY = r'''
# Commands: type/name from the pinned role table, typed argv operands,
# payload header bytes and at most three immutable fd slices.
# An argv operand is an original argv slot, a command-local string, a
# decimal number, or an exact carried descriptor rendered as decimal.
# Observations: [tag, sequence, op, status, fd, physical extent, span offset,
# captured bytes] followed by a bounded prefix or the exact requested span.
def describe_flow(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 8 or length(o) < 2048 or length(w) < 4096:
        return BAD
    if get(w, 0) == 0:
        return configure_flow(s, o, w)
    if length(s) < 64 or input_word(s, 0) != OBSERVATION or input_word(s, 8) != get(w, 8):
        return BAD
    if input_word(s, 16) != get(w, 16) or input_word(s, 24) != 0:
        return BAD
    extent = input_word(s, 40)
    start = input_word(s, 48)
    seen = input_word(s, 56)
    if extent > TRANSPORT_MAX or start > extent or seen > extent - start or seen != length(s) - 64:
        return BAD
    op = get(w, 16)
    if op == RUN and (input_word(s, 32) < 3 or input_word(s, 32) > 2147483647 or start != 0):
        return BAD
    if op == READ and (input_word(s, 32) != get(w, 72) or start != get(w, 80) or seen != get(w, 88)):
        return BAD
    state = get(w, 0)
    if state >= AFTER_JOURNAL_REQUEST and state <= AFTER_JOURNAL_RECIPE:
        return continue_journal(s, o, w, state)
    if state == AFTER_START_CLOCK or state == AFTER_COST_CLOCK:
        return observe_clock(s, o, w, state)
    if state <= AFTER_CHECK_ARGUMENT:
        return open_flow(s, o, w, state)
    if state <= AFTER_REFUSAL:
        return discovery_flow(s, o, w, state)
    return close_flow(s, o, w, state)

def configure_flow(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if input_word(s, 0) != ENTRY or admit_entry(s, o) != 344:
        return BAD
    keep(w, ORIGINAL, 0, input_word(s, 8))
    keep(w, DOSSIER_FD, input_word(s, 32), input_word(s, 16))
    keep(w, METADATA_FD, input_word(s, 40), input_word(s, 24))
    put(w, 24, get(o, 56))
    put(w, 32, get(o, 64))
    put(w, 40, get(o, 32))
    put(w, 48, get(o, 40))
    put(w, 56, get(o, 48))
    p = 0
    while p < 256:
        store(w, TRUST + p, byte(o, 88 + p))
        p = p + 1
    role = 0
    while role < ROLE_COUNT:
        put(w, ROLE_BASE + role * 8, input_word(s, ENTRY_HEAD + DOSSIER_HEAD + 40 * role))
        role = role + 1
    return issue(o, w, AFTER_START_CLOCK, CLOCK, 0, 0, 0, 0)

def observe_clock(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    if length(s) != 72 or input_word(s, 40) != 8 or input_word(s, 48) != 0:
        return BAD
    tick = input_word(s, 64)
    if state == AFTER_START_CLOCK:
        put(w, 64, tick)
        put(o, HEADER, ADMISSION)
        put(o, HEADER + 8, get(w, 24))
        copy_private(w, o, TRUST, HEADER + 16, 64)
        whole_slot(w, o, ORIGINAL, 0)
        return issue(o, w, AFTER_ADMIT, RUN, 0, 0, 1, 80)
    started = get(w, 64)
    if tick < started:
        return BAD
    put(o, HEADER, COST_OBSERVATION)
    put(o, HEADER + 8, tick - started)
    put(o, HEADER + 16, slot_bytes(w, REPLY_FD))
    whole_slot(w, o, REPLY_FD, 0)
    return issue(o, w, AFTER_COST_CONTROL, RUN, 4, 0, 1, 24)

def open_flow(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    if state == AFTER_ADMIT:
        observe_slot(s, w, ADMITTED_FD)
        put(o, HEADER, get(w, 24))
        put(o, HEADER + 8, PROJECT)
        whole_slot(w, o, ADMITTED_FD, 0)
        return issue(o, w, AFTER_PROJECT, RUN, 1, 0, 1, 16)
    if state == AFTER_PROJECT:
        observe_slot(s, w, CALL_FD)
        if prefixed(s) == False:
            return BAD
        return next_journal(o, w, 9)
    if state == AFTER_ARGUMENT:
        if prefixed(s) == False:
            return BAD
        put(o, HEADER, 1)
        copy_private(w, o, TRUST, HEADER + 8, 64)
        fragment(o, 0, input_word(s, 32), 8, input_word(s, 40) - 8)
        return issue(o, w, AFTER_CHECK_ARGUMENT, RUN, 3, 0, 1, 72)
    if reply_word(s, 0) == False:
        return BAD
    whole_slot(w, o, ADMITTED_FD, 0)
    return issue(o, w, AFTER_PLAN, RUN, 10, 0, 1, 0)

def discovery_flow(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    if state == AFTER_PLAN:
        if prefixed(s) == False:
            return BAD
        observe_slot(s, w, PLAN_FD)
        return next_journal(o, w, 11)
    if state == AFTER_QUERY:
        return observe_discovery(s, o, w)
    if state == AFTER_DOCUMENT:
        put(o, HEADER, DOCUMENT_BIND)
        put(o, HEADER + 8, slot_bytes(w, METADATA_FD))
        put(o, HEADER + 16, slot_bytes(w, QUERY_FD) - 8)
        put(o, HEADER + 24, input_word(s, 40))
        whole_slot(w, o, METADATA_FD, 0)
        after_prefix(w, o, QUERY_FD, 1)
        fragment(o, 2, input_word(s, 32), 0, input_word(s, 40))
        return issue(o, w, AFTER_BIND, RUN, 12, 0, 3, 32)
    if state == AFTER_BIND:
        if prefixed(s) == False:
            return BAD
        fragment(o, 0, input_word(s, 32), 8, input_word(s, 40) - 8)
        return issue(o, w, AFTER_ANSWER, RUN, 21, 0, 1, 0)
    if state == AFTER_ANSWER and prefixed(s) == False:
        return BAD
    observe_slot(s, w, EFFECT_FD)
    put(w, 96, choose(state == AFTER_ANSWER, 1, 2))
    return next_journal(o, w, choose(state == AFTER_ANSWER, 13, 14))

def observe_discovery(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    amount = input_word(s, 40)
    if length(s) < 72 or amount < 8:
        return BAD
    first = input_word(s, 64)
    if first >= 4294967000:
        if amount != 8:
            return BAD
        zero_range(o, HEADER, 40)
        put(o, HEADER, EFFECT_REFUSAL)
        put(o, HEADER + 8, first)
        return issue(o, w, AFTER_REFUSAL, RUN, 4, 0, 0, 40)
    if length(s) < 80 or first != amount - 8 or first <= 32 or first > 65568:
        return BAD
    version = input_word(s, 72)
    if version < 1 or version > 9:
        return BAD
    observe_slot(s, w, QUERY_FD)
    fragment(o, 0, input_word(s, 32), 40, amount - 40)
    launch_directory(w, o, 0)
    role_argument(w, o, 2, 7)
    role_argument(w, o, 3, 8)
    role_argument(w, o, 4, 14)
    role_argument(w, o, 5, 13)
    role_argument(w, o, 6, 20)
    role_argument(w, o, 7, 9)
    argv(o, 8, DECIMAL_ARG, 1)
    argv(o, 9, DECIMAL_ARG, version)
    return issue(o, w, AFTER_DOCUMENT, RUN, 19, 10, 1, 0)

def close_flow(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    if state == AFTER_RESPONSE:
        if prefixed(s) == False:
            return BAD
        observe_slot(s, w, RENDERED_FD)
        if get(w, 96) != 1:
            return next_journal(o, w, 8)
        put(o, HEADER, 1)
        copy_private(w, o, TRUST, HEADER + 8, 64)
        after_prefix(w, o, RENDERED_FD, 0)
        return issue(o, w, AFTER_CHECK_OUTPUT, RUN, 16, 0, 1, 72)
    if state == AFTER_CHECK_OUTPUT:
        if reply_word(s, 0) == False:
            return BAD
        return next_journal(o, w, 8)
    if state == AFTER_COST_CONTROL:
        fragment(o, 0, input_word(s, 32), 0, input_word(s, 40))
        return issue(o, w, AFTER_COST_TYPED, RUN, 17, 0, 1, 0)
    if state == AFTER_COST_TYPED:
        if prefixed(s) == False:
            return BAD
        fragment(o, 0, input_word(s, 32), 8, input_word(s, 40) - 8)
        put(o, 160, OWN_COST_PREFIX)
        put(o, 168, OWN_COST_SUFFIX)
        argv(o, 0, LITERAL_ARG, 160)
        launch_directory(w, o, 1)
        role_argument(w, o, 3, 7)
        role_argument(w, o, 4, 8)
        role_argument(w, o, 5, 14)
        return issue(o, w, AFTER_COST_WRITE, RUN, 6, 6, 1, 0)
    if state == AFTER_COST_WRITE:
        put(o, HEADER, COST_ATTESTATION)
        fragment(o, 0, input_word(s, 32), 0, input_word(s, 40))
        return issue(o, w, AFTER_COST_ATTEST, RUN, 4, 0, 1, 8)
    if state == AFTER_COST_ATTEST:
        if length(s) < 72 or input_word(s, 40) != 40 or input_word(s, 64) != COST_OK:
            return BAD
        return terminal_request(o, w)
    if state == AFTER_TERMINAL:
        size = input_word(s, 40)
        if size < 3 or size > 8388609:
            return BAD
        observe_slot(s, w, TERMINAL_FD)
        return read_span(o, w, AFTER_END_BYTE, slot_fd(w, TERMINAL_FD), size - 1, 1)
    if state == AFTER_END_BYTE:
        if length(s) != 65 or byte(s, 64) != 10:
            return BAD
        whole_slot(w, o, TERMINAL_FD, 0)
        return issue(o, w, AFTER_PUBLISH, PUBLISH, 0, 0, 1, 0)
    if state == AFTER_PUBLISH and length(s) == 64:
        return issue(o, w, AFTER_PUBLISH, FINISHED, 0, 0, 0, 0)
    return BAD

def terminal_request(o:mutbuf, w:mutbuf) -> u64:
    put(o, HEADER, PUBLICATION_REQUEST)
    put(o, HEADER + 8, slot_bytes(w, ORIGINAL))
    put(o, HEADER + 16, get(w, 120))
    put(o, HEADER + 24, get(w, 24))
    put(o, HEADER + 32, get(w, 32))
    copy_private(w, o, TRUST, HEADER + 40, 256)
    whole_slot(w, o, ORIGINAL, 0)
    fragment(o, 1, slot_fd(w, REPLY_FD), get(w, 112), get(w, 120))
    return issue(o, w, AFTER_TERMINAL, RUN, 18, 0, 2, 296)

def next_journal(o:mutbuf, w:mutbuf, stage:u64) -> u64:
    put(w, 104, stage)
    state_bytes = choose(stage == 9, 0, 512)
    put(o, HEADER, JOURNAL_COMMAND)
    put(o, HEADER + 8, stage)
    put(o, HEADER + 16, get(w, 24))
    put(o, HEADER + 24, state_bytes)
    bytes = HEADER + 40
    copy_private(w, o, JOURNAL_STATE, bytes, state_bytes)
    bytes = bytes + state_bytes
    n = 0
    payload = 0
    inline = 0
    if stage == 9:
        payload = get(w, 40)
        fragment(o, 0, slot_fd(w, DOSSIER_FD), DOSSIER_HEAD, payload)
        n = 1
    elif stage == 0:
        payload = slot_bytes(w, CALL_FD) - 8
        after_prefix(w, o, CALL_FD, 0)
        n = 1
    elif stage == 11:
        put(o, bytes, 4)
        put(o, bytes + 8, 66)
        put(o, bytes + 16, 0)
        put(o, bytes + 24, NULL_PREFIX)
        copy_private(w, o, TRUST, bytes + 29, 64)
        store(o, bytes + 93, 34)
        payload = 94
        inline = 94
    elif stage == 12:
        catalog = get(w, 40)
        current = get(w, 48)
        retained = get(w, 56)
        put(o, bytes, current)
        put(o, bytes + 8, retained)
        put(o, bytes + 16, 0)
        fragment(o, 0, slot_fd(w, DOSSIER_FD), DOSSIER_HEAD + catalog, current)
        fragment(o, 1, slot_fd(w, DOSSIER_FD), DOSSIER_HEAD + catalog + current, retained)
        payload = 24 + current + retained
        inline = 24
        n = 2
    elif stage == 8:
        payload = slot_bytes(w, RENDERED_FD) - 8
        after_prefix(w, o, RENDERED_FD, 0)
        n = 1
    put(o, HEADER + 32, payload)
    return issue(o, w, AFTER_JOURNAL_REQUEST, RUN, 4, 0, n, bytes - HEADER + inline)

def continue_journal(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    if state == AFTER_JOURNAL_REQUEST:
        fragment(o, 0, input_word(s, 32), 0, input_word(s, 40))
        return issue(o, w, AFTER_JOURNAL_REACTOR, RUN, 5, 0, 1, 0)
    if state == AFTER_JOURNAL_REACTOR:
        observe_slot(s, w, REPLY_FD)
        count = choose(get(w, 104) == 9, 0, 512)
        put(o, HEADER, JOURNAL_OBSERVED)
        put(o, HEADER + 8, get(w, 104))
        put(o, HEADER + 16, count)
        put(o, HEADER + 24, slot_bytes(w, REPLY_FD))
        put(o, HEADER + 32, 0)
        copy_private(w, o, JOURNAL_STATE, HEADER + 40, count)
        whole_slot(w, o, REPLY_FD, 0)
        return issue(o, w, AFTER_JOURNAL_PROOF, RUN, 4, 0, 1, 40 + count)
    if state == AFTER_JOURNAL_PROOF:
        return observe_journal_proof(s, o, w)
    if state == AFTER_JOURNAL_STATE:
        if length(s) != 576:
            return BAD
        i = 0
        while i < 512:
            store(w, JOURNAL_STATE + i, byte(s, 64 + i))
            i = i + 1
        return journal_action(o, w)
    return compose_effect(s, o, w)

def observe_journal_proof(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if length(s) != 128 or input_word(s, 40) != 64 or input_word(s, 64) != JOURNAL_REPLY:
        return BAD
    stage = get(w, 104)
    if input_word(s, 72) != stage:
        return BAD
    next = input_word(s, 80)
    status = input_word(s, 88)
    at = input_word(s, 96)
    bytes = input_word(s, 104)
    start = input_word(s, 112)
    state_bytes = input_word(s, 120)
    volume = slot_bytes(w, REPLY_FD)
    if at > volume or bytes > volume - at or start > volume or state_bytes > volume - start:
        return BAD
    if stage_edge(stage, next, status, bytes) == False:
        return BAD
    put(w, 112, at)
    put(w, 120, bytes)
    put(w, 128, next)
    put(w, 136, status)
    if next == 17:
        if state_bytes != 0:
            return BAD
        return read_span(o, w, AFTER_JOURNAL_RECIPE, slot_fd(w, REPLY_FD), at, bytes)
    if state_bytes != 512:
        return BAD
    return read_span(o, w, AFTER_JOURNAL_STATE, slot_fd(w, REPLY_FD), start, state_bytes)

def journal_action(o:mutbuf, w:mutbuf) -> u64:
    next = get(w, 128)
    if next == 11:
        put(o, HEADER, get(w, 24))
        put(o, HEADER + 8, ARGUMENT)
        whole_slot(w, o, ADMITTED_FD, 0)
        return issue(o, w, AFTER_ARGUMENT, RUN, 2, 0, 1, 16)
    if next == 16:
        after_prefix(w, o, PLAN_FD, 0)
        return issue(o, w, AFTER_QUERY, RUN, 11, 0, 1, 0)
    if next == 18:
        if get(w, 136) != get(w, 96):
            return BAD
        return issue(o, w, AFTER_COST_CLOCK, CLOCK, 0, 0, 0, 0)
    return next_journal(o, w, next)

def compose_effect(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    bytes = get(w, 120)
    if length(s) != 64 + bytes or bytes > 192:
        return BAD
    zero_range(o, HEADER, 224)
    put(o, HEADER, get(w, 24))
    put(o, HEADER + 8, RESPONSE)
    put(o, HEADER + 16, bytes)
    copy_span(s, o, 64, HEADER + 32, bytes)
    if get(w, 96) == 1:
        after_prefix(w, o, EFFECT_FD, 0)
    else:
        whole_slot(w, o, EFFECT_FD, 0)
    return issue(o, w, AFTER_RESPONSE, RUN, 15, 0, 1, 224)

def launch_directory(w:mutbuf, o:mutbuf, first:u64) -> u64:
    argv(o, first, INPUT_ARG, 2)
    return argv(o, first + 1, INPUT_ARG, 3)

def role_argument(w:mutbuf, o:mutbuf, item:u64, role:u64) -> u64:
    return argv(o, item, FD_ARG, get(w, ROLE_BASE + 8 * role))

def argv(o:mutbuf, index:u64, kind:u64, value:u64) -> u64:
    at = ARGUMENTS + 16 * index
    put(o, at, kind)
    put(o, at + 8, value)
    return 0

def issue(o:mutbuf, w:mutbuf, next:u64, op:u64, role:u64, args:u64, parts:u64, local:u64) -> u64:
    seq = get(w, 8) + 1
    if seq > 160:
        return BAD
    put(w, 0, next)
    put(w, 8, seq)
    put(w, 16, op)
    put(o, 0, COMMAND)
    put(o, 8, seq)
    put(o, 16, op)
    put(o, 24, role)
    put(o, 32, args)
    put(o, 40, parts)
    put(o, 48, local)
    put(o, 56, HEADER)
    put(o, 152, choose(op == RUN, DEFAULT_CHILD_LEASE, 0))
    return HEADER + local

def read_span(o:mutbuf, w:mutbuf, next:u64, fd:u64, at:u64, bytes:u64) -> u64:
    put(w, 72, fd)
    put(w, 80, at)
    put(w, 88, bytes)
    fragment(o, 0, fd, at, bytes)
    return issue(o, w, next, READ, 0, 0, 1, 0)

def fragment(o:mutbuf, index:u64, fd:u64, offset:u64, size:u64) -> u64:
    at = 64 + 24 * index
    put(o, at, fd)
    put(o, at + 8, offset)
    put(o, at + 16, size)
    return 0

def keep(w:mutbuf, slot:u64, fd:u64, bytes:u64) -> u64:
    put(w, SLOT_BASE + 16 * slot, fd)
    put(w, SLOT_BASE + 16 * slot + 8, bytes)
    return 0

def observe_slot(s:readbuf, w:mutbuf, index:u64) -> u64:
    return keep(w, index, input_word(s, 32), input_word(s, 40))

def slot_fd(w:mutbuf, index:u64) -> u64:
    return get(w, SLOT_BASE + 16 * index)

def slot_bytes(w:mutbuf, index:u64) -> u64:
    return get(w, SLOT_BASE + 16 * index + 8)

def whole_slot(w:mutbuf, o:mutbuf, slot:u64, fragment_index:u64) -> u64:
    return fragment(o, fragment_index, slot_fd(w, slot), 0, slot_bytes(w, slot))

def after_prefix(w:mutbuf, o:mutbuf, slot:u64, fragment_index:u64) -> u64:
    return fragment(o, fragment_index, slot_fd(w, slot), 8, slot_bytes(w, slot) - 8)

def prefixed(s:readbuf) -> bool:
    if length(s) < 72 or input_word(s, 40) < 10 or input_word(s, 40) > 8388616:
        return False
    return input_word(s, 64) == input_word(s, 40) - 8

def reply_word(s:readbuf, value:u64) -> bool:
    return length(s) == 72 and input_word(s, 40) == 8 and input_word(s, 64) == value

def copy_private(w:mutbuf, o:mutbuf, source_at:u64, at:u64, count:u64) -> u64:
    i = 0
    while i < count:
        store(o, at + i, byte(w, source_at + i))
        i = i + 1
    return i

def zero_range(o:mutbuf, at:u64, count:u64) -> u64:
    i = 0
    while i < count:
        store(o, at + i, 0)
        i = i + 1
    return i
'''


def program():
    constants = {name: int.from_bytes(tag, 'little') for name, tag in WORDS.items()}
    constants.update(STEPS)
    constants.update(SLOTS)
    constants.update(BAD=0xfffffffd, HEADER=512, TRUST=512, SLOT_BASE=1024, JOURNAL_STATE=1536,
                     ROLE_BASE=2048, ARGUMENTS=192, ROLE_COUNT=22, ENTRY_HEAD=64,
                     INPUT_ARG=1, LITERAL_ARG=2, DECIMAL_ARG=3, FD_ARG=4,
                     OWN_COST_PREFIX=int.from_bytes(b'--own-co', 'little'),
                     OWN_COST_SUFFIX=int.from_bytes(b'st', 'little'), DEFAULT_CHILD_LEASE=10_000_000_000,
                     RUN=1, READ=2, PUBLISH=3, CLOCK=4, FINISHED=5, TRANSPORT_MAX=16 << 20,
                     DOSSIER_HEAD=312, ENTRY=int.from_bytes(b'HIADRI01', 'little'),
                     JOURNAL_REPLY=int.from_bytes(b'HIAJWO01', 'little'),
                     NULL_PREFIX=int.from_bytes(b'null"', 'little'))
    source = re.sub(r'\b(' + '|'.join(constants) + r')\b',
                    lambda matched: str(constants[matched[0]]), POLICY)
    controls = reactor()
    functions = ('admit_entry', 'stage_edge', 'valid_fd', 'dossier_identity', 'is_hex',
                 'trusted_descriptors', 'copy_span', 'input_word', 'put', 'write')
    return '\n'.join((source, *(function(controls, name) for name in functions), function(RELEASE_WRITER, 'get')))


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)), encoding='utf-8')
