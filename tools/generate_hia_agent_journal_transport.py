"""Author the sealed HIA journal codec and native Store cost binding.

The OS adapter owns descriptor transfer and mapping. This separate image keeps
the bounded journal transition compiler's function and block limits intact.
"""
from __future__ import annotations

import json
import re

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_agent_stdio import ROOT, document

SOURCE = 'examples/hia_bootstrap/agent_journal_transport.hepta'

def transport_program():
    source = '''
def transfer(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) == 24 and get(w, 0) == 17:
        return read_workflow(s, o)
    if length(s) >= 56 and input_word(s, 0) == COST_MAGIC:
        return cost_store_frame(s, o)
    if length(w) != 24:
        return 4294967293
    mode = get(w, 0)
    if mode == 15:
        return transport_admit(s, get(w, 8))
    if mode == 16:
        return transport_reply(s, o, get(w, 8), get(w, 16))
    return 4294967293

def read_workflow(s:readbuf, o:mutbuf) -> u64:
    if length(s) < 40:
        return 0
    mode = input_word(s, 0)
    if mode == READ_WORKFLOW_MAGIC:
        return read_workflow_request(s, o)
    if mode == READ_ERROR_MAGIC:
        return read_effect_error(s, o)
    if mode == READ_COST_MAGIC:
        return read_closeout_cost(s, o)
    if mode == READ_REPLY_MAGIC:
        return read_workflow_reply(s, o)
    if mode == COST_COMMIT_MAGIC:
        return attest_cost_commit(s, o)
    return 0

def attest_cost_commit(s:readbuf, o:mutbuf) -> u64:
    if length(s) != 64 or length(o) < 40 or input_word(s, 8) != COST_INTENT_MAGIC:
        return 0
    if input_word(s, 16) != 5 or input_word(s, 24) != 8 or input_word(s, 32) != 1:
        return 0
    if input_word(s, 40) != 0 or input_word(s, 48) != 2 or input_word(s, 56) == 0:
        return 0
    put(o, 0, COST_COMMITTED_MAGIC)
    put(o, 8, 1)
    put(o, 16, input_word(s, 48))
    put(o, 24, input_word(s, 56))
    put(o, 32, 0)
    return 40

def read_workflow_reply(s:readbuf, o:mutbuf) -> u64:
    stage = input_word(s, 8)
    previous = input_word(s, 16)
    reply = input_word(s, 24)
    if previous > 512 or reply < 48 or length(o) < 64 or input_word(s, 32) != 0:
        return 0
    at = 40 + previous
    if at > length(s) or reply != length(s) - at or input_word(s, at) != REPLY_MAGIC:
        return 0
    action = input_word(s, at + 8)
    response = input_word(s, at + 16)
    cost = input_word(s, at + 24)
    fixed = input_word(s, at + 32)
    if response > 8388608 or cost > 8388608 or fixed > 512 or input_word(s, at + 40) != 0:
        return 0
    if reply != 48 + response + cost + fixed:
        return 0
    state = at + 48 + response + cost
    status = 0
    if stage == 13 or stage == 14:
        if previous != 512 or fixed != 0 or cost != 0 or action != response:
            return 0
        if read_workflow_transition(s, stage, 0) == False:
            return 0
        if response > 192 or response < RECIPE_ID_OFFSET + 66:
            return 0
        if same_fields(s, 40 + 192, at + 48 + RECIPE_ID_OFFSET, 66) == False:
            return 0
        next = 17
    else:
        if fixed != 512 or input_word(s, state) != STATE_MAGIC or input_word(s, state + 48) != action:
            return 0
        if stage == 9:
            if previous != 0 or action != 12 or input_word(s, state + 8) != 0 or input_word(s, state + 16) != 0:
                return 0
        else:
            if previous != 512 or input_word(s, 40) != STATE_MAGIC:
                return 0
            if input_word(s, state + 16) != 3 or admitted_read_identity(s, state) == False:
                return 0
            if stage != 0 and same_fields(s, 40 + 64, state + 64, 194) == False:
                return 0
        if stage == 8:
            status = read_terminal_status(s, state, response, cost)
            if status == 0:
                return 0
            next = 18
        else:
            if response != 0 or cost != 0 or input_word(s, state + 56) != 0:
                return 0
            next = read_follow_journal(s, stage, state, action)
            if next == 255:
                return 0
    put(o, 0, READ_VERIFIED_MAGIC)
    put(o, 8, stage)
    put(o, 16, next)
    put(o, 24, status)
    put(o, 32, 48)
    put(o, 40, response)
    put(o, 48, choose(fixed != 0, state - at, 0))
    put(o, 56, fixed)
    return 64

def read_follow_journal(s:readbuf, stage:u64, state:u64, action:u64) -> u64:
    if stage == 9:
        return 0
    if action != 1 or input_word(s, state + 24) != 0 or input_word(s, state + 32) != 0 or input_word(s, state + 40) != 0:
        return 255
    if input_word(s, state + 320) != 0:
        return 255
    phase = input_word(s, state + 8)
    role = input_word(s, state + 328)
    if stage == 5 and phase == 10 and role == 3:
        return 16
    if phase != 4 or role != 0:
        return 255
    if stage == 0:
        return 11
    if stage == 11:
        return 12
    if stage == 12:
        return 5
    return 255

def same_fields(s:readbuf, left:u64, right:u64, extent:u64) -> bool:
    index = 0
    while index < extent:
        if byte(s, left + index) != byte(s, right + index):
            return False
        index = index + 1
    return True

def read_effect_error(s:readbuf, o:mutbuf) -> u64:
    if length(s) != 56 or length(o) < 256:
        return 0
    if input_word(s, 8) != EFFECT_CLOSEOUT or input_word(s, 24) < 2 or input_word(s, 48) != 0:
        return 0
    reason = input_word(s, 16)
    actions = input_word(s, 40)
    if reason == 1 and actions == 3:
        return read_artifact_error(o)
    if reason == 2 and actions == 8:
        return read_cursor_error(o)
    return 0

# The complete result came from stage 8 of the admitted Journal. Its ordinary
# no-context cost is derived from that sealed result, not from a caller's tool,
# request ID, status, or diagnostic string. The native typed INSERT selector
# independently admits the projected HIAJCF01 record.
def read_closeout_cost(s:readbuf, o:mutbuf) -> u64:
    if length(s) < 584 or input_word(s, 16) != length(s) - 24:
        return 0
    if input_word(s, 24) != REPLY_MAGIC or input_word(s, 32) != 10:
        return 0
    if input_word(s, 56) != 512 or input_word(s, 64) != 0:
        return 0
    response = input_word(s, 40)
    cost = input_word(s, 48)
    if response < 2 or response > 8388608 or cost < MIN_DETAILS or cost > 8388608:
        return 0
    state = 72 + response + cost
    if length(s) != state + 512 or length(o) < 130 + cost:
        return 0
    status = read_terminal_status(s, state, response, cost)
    if status == 0:
        return 0
    put(o, 0, COST_MAGIC)
    put(o, 8, input_word(s, 8))
    put(o, 16, status)
    put(o, 24, 0)
    put(o, 32, 8)
    put(o, 40, 66)
    put(o, 48, cost)
    put(o, 56, READ_TOOL)
    copy_cost_bytes(s, o, state + 192, 66, 64)
    copy_cost_bytes(s, o, 72 + response, cost, 130)
    return 130 + cost

def read_terminal_status(s:readbuf, state:u64, response:u64, cost:u64) -> u64:
    if response < 2 or cost < MIN_DETAILS:
        return 0
    if input_word(s, state) != STATE_MAGIC or input_word(s, state + 8) != 11:
        return 0
    if input_word(s, state + 16) != 3 or input_word(s, state + 48) != 10:
        return 0
    if input_word(s, state + 24) != 0 or input_word(s, state + 32) != 0 or input_word(s, state + 40) != 0:
        return 0
    if input_word(s, state + 272) != response or input_word(s, state + 280) != cost or input_word(s, state + 288) != 1:
        return 0
    status = input_word(s, state + 264)
    if status < 1 or status > 2 or admitted_read_identity(s, state) == False:
        return 0
    return status

def read_workflow_request(s:readbuf, o:mutbuf) -> u64:
    stage = input_word(s, 8)
    digits = input_word(s, 16)
    previous = input_word(s, 24)
    observed = input_word(s, 32)
    if digits > 2147483647 or observed > 8388608 or length(o) < 576 + observed:
        return 0
    if previous > 512 or length(s) != 40 + previous + observed:
        return 0
    if stage == 9:
        if previous != 0 or observed == 0:
            return 0
    elif previous != 512 or read_workflow_transition(s, stage, observed) == False:
        return 0
    put(o, 0, SINGLE_MAGIC)
    put(o, 8, observed)
    put(o, 16, read_workflow_scratch(stage, observed))
    put(o, 24, stage)
    put(o, 32, digits)
    put(o, 40, 0)
    put(o, 48, 0)
    put(o, 56, 0)
    if previous == 0:
        index = 0
        while index < 512:
            store(o, 64 + index, 0)
            index = index + 1
    else:
        copy_cost_bytes(s, o, 40, previous, 64)
    copy_cost_bytes(s, o, 40 + previous, observed, 576)
    return 576 + observed

# The installed read path has no durable request key or Context. A projection
# that enters either lane cannot be used for these private read continuations.
def read_workflow_transition(s:readbuf, stage:u64, observed:u64) -> bool:
    if input_word(s, 40) != STATE_MAGIC:
        return False
    phase = input_word(s, 48)
    tool = input_word(s, 56)
    prior = input_word(s, 88)
    reason = input_word(s, 96)
    if stage == 0:
        return phase == 0 and tool == 0 and prior == 12 and reason == 0 and observed != 0
    if tool != 3 or input_word(s, 64) != 0 or input_word(s, 72) != 0 or input_word(s, 80) != 0:
        return False
    if input_word(s, 360) != 0 or input_word(s, 376) != 0 or input_word(s, 384) != 0:
        return False
    if admitted_read_identity(s, 40) == False:
        return False
    if stage == 11 or stage == 12:
        if phase != 4 or prior != 1 or reason != 0 or observed < 26:
            return False
        actual = input_word(s, 552)
        expected = input_word(s, 560)
        return input_word(s, 568) == 0 and actual != 0 and actual < observed - 24 and expected == observed - 24 - actual
    if stage == 5:
        return phase == 4 and prior == 1 and reason == 0 and observed == 0
    if stage == 13:
        return phase == 10 and prior == 1 and reason == 0 and input_word(s, 368) == 3 and observed == 0
    if stage == 14:
        return (phase == 10 or phase == 4) and (prior == 1 or prior == 11) and observed == 0
    if stage == 8:
        return (phase == 10 or phase == 4) and (prior == 1 or prior == 11) and observed != 0
    return False

def admitted_read_identity(s:readbuf, at:u64) -> bool:
    if byte(s, at + 192) != 114 or byte(s, at + 193) != 45:
        return False
    index = 0
    while index < 64:
        digit = byte(s, at + 64 + index)
        if (digit < 48 or digit > 57) and (digit < 97 or digit > 102):
            return False
        if byte(s, at + 194 + index) != digit:
            return False
        index = index + 1
    return True

def read_workflow_scratch(stage:u64, size:u64) -> u64:
    if stage == 13 or stage == 14:
        return 520
    nodes = ((size + 1) >> 1) + 1
    if nodes > 262144:
        nodes = 262144
    fields = (size >> 2) + 1
    if fields > 262144:
        fields = 262144
    slots = 2
    while slots < 2 * fields:
        slots = slots * 2
    arena = 64 + nodes * 56 + size
    keys = slots * 8
    if keys < 6320:
        keys = 6320
    if arena < 4256 + keys:
        arena = 4256 + keys
    return arena + 32768

def transport_admit(s:readbuf, expected:u64) -> u32:
    prefix = 64
    magic = SESSION_MAGIC
    if expected == 0:
        prefix = 576
        magic = SINGLE_MAGIC
    total = length(s)
    if total < prefix:
        return 4294967293
    if input_word(s, 0) != magic or input_word(s, 56) != expected:
        return 4294967293
    tags = input_word(s, 48)
    if tags > 262144 or tags > total - prefix:
        return 4294967293
    size = input_word(s, 8)
    if size != total - prefix - tags:
        return 4294967293
    stage = input_word(s, 24)
    scratch = input_word(s, 16)
    if stage > 14 or input_word(s, 40) > 1:
        return 4294967293
    if stage != 10 and size > 8388608:
        return 4294967293
    if stage >= 13:
        if scratch != 520 or tags != 0:
            return 4294967293
    else:
        if scratch < 4256 + 32768 + tags or scratch > 8388608 + 56 * 262144 + 64 + 32768 + 262144:
            return 4294967293
        if stage != 0 and tags != 0:
            return 4294967293
    return 1

def transport_reply(s:readbuf, o:mutbuf, status:u64, stage:u64) -> u32:
    if length(o) != 48 or stage > 14 or status > 4294967295 or length(s) < 16777728 + 520:
        return 4294967293
    response = 0
    cost = 0
    state = 0
    arena = 0
    carry = 0
    if stage >= 13:
        if status <= 192:
            response = status
    else:
        state = 512
        if status <= 2147483647:
            response = input_word(s, 16777216 + 272)
            cost = input_word(s, 16777216 + 280)
            if response > 8388608 or cost > 8388608:
                return 4294967293
            if stage == 3:
                if length(s) < 16777728 + 32768:
                    return 4294967293
                arena = input_word(s, 16777728 + 32)
                if arena < 64 or arena > length(s) - 16777728 - 32768:
                    return 4294967293
            carry = 1
    put(o, 0, REPLY_MAGIC)
    put(o, 8, status)
    put(o, 16, response)
    put(o, 24, cost)
    put(o, 32, state)
    put(o, 40, arena)
    return carry


# Only raw, immutable observations of an admitted Journal transition are
# projected into the existing Store INSERT cost ABI. This does not own a
# journal session, clock, Store connection or request authorization.
def cost_store_frame(s:readbuf, o:mutbuf) -> u64:
    clock = input_word(s, 8)
    status = input_word(s, 16)
    context = input_word(s, 24)
    tool = input_word(s, 32)
    request = input_word(s, 40)
    details = input_word(s, 48)
    if status < 1 or status > 2 or context > 512 or tool > 512:
        return 4294967293
    if request != 66 and request != 43:
        return 4294967293
    if details < MIN_DETAILS or details > 8388608:
        return 4294967293
    if length(s) != 56 + context + tool + request + details:
        return 4294967293
    identity = 56 + context + tool
    if cost_request_identity(s, identity, request) == False:
        return 4294967293
    detail_at = identity + request
    if input_word(s, detail_at) != DETAILS_PREFIX or byte(s, detail_at + 8) != 58:
        return 4294967293
    suffix = length(s) - DETAILS_SUFFIX_SIZE
    if input_word(s, suffix) != DETAILS_SUFFIX_FIRST or input_word(s, suffix + 8) != DETAILS_SUFFIX_SECOND or byte(s, suffix + 16) != 101 or byte(s, suffix + 17) != 125:
        return 4294967293
    if status == 1 and (details != MIN_DETAILS or cost_completed_details(s, detail_at + 9) == False):
        return 4294967293
    if length(o) < 184 + context + tool + request + details + 29:
        return 4294967293
    put(o, 0, INSERT_MAGIC)
    put(o, 8, 1)
    put(o, 16, 2)
    put(o, 24, 0)
    put(o, 32, 6)
    at = 184
    cost_column(o, 0, choose(context > 0, 3, 0), at, context)
    at = copy_cost_bytes(s, o, 56, context, at)
    cost_column(o, 1, 3, at, tool)
    at = copy_cost_bytes(s, o, 56 + context, tool, at)
    cost_column(o, 2, 3, at, request)
    at = copy_cost_bytes(s, o, identity, request, at)
    after = cost_decimal(o, at, clock)
    cost_column(o, 3, 3, at, after - at)
    at = after
    status_size = choose(status == 1, 9, 8)
    cost_column(o, 4, 3, at, status_size)
    if status == 1:
        put(o, at, COMPLETED_INITIAL)
        store(o, at + 8, 100)
    else:
        put(o, at, REJECTED_LITERAL)
    at = at + status_size
    cost_column(o, 5, 3, at, details)
    return copy_cost_bytes(s, o, detail_at, details, at)

def cost_request_identity(s:readbuf, at:u64, size:u64) -> bool:
    if size == 66:
        if byte(s, at) != 114 or byte(s, at + 1) != 45:
            return False
        index = 2
    else:
        if input_word(s, at) != UNADMITTED_INITIAL or byte(s, at + 8) != 101 or byte(s, at + 9) != 100 or byte(s, at + 10) != 45:
            return False
        index = 11
    while index < size:
        digit = byte(s, at + index)
        if (digit < 48 or digit > 57) and (digit < 97 or digit > 102):
            return False
        index = index + 1
    return True

def cost_completed_details(s:readbuf, at:u64) -> bool:
    return byte(s, at) == 110 and byte(s, at + 1) == 117 and byte(s, at + 2) == 108 and byte(s, at + 3) == 108

def cost_column(o:mutbuf, column:u64, kind:u64, begin:u64, count:u64) -> u64:
    at = 40 + column * 24
    put(o, at, kind)
    put(o, at + 8, begin)
    put(o, at + 16, count)
    return 0

def copy_cost_bytes(s:readbuf, o:mutbuf, read_at:u64, size:u64, write_at:u64) -> u64:
    at = 0
    while at < size:
        store(o, write_at + at, byte(s, read_at + at))
        at = at + 1
    return write_at + size

def cost_decimal(o:mutbuf, at:u64, clock:u64) -> u64:
    # One hundred and eighty bounded subtractions at most. This transport
    # stays in the same baseline HIA profile as the original Journal codec.
    position = 20
    started = False
    while position > 0:
        position = position - 1
        place = decimal_place(position)
        if clock >= place or started or position == 0:
            digit = 0
            while clock >= place:
                clock = clock - place
                digit = digit + 1
            store(o, at, 48 + digit)
            at = at + 1
            started = True
    return at

def decimal_place(position:u64) -> u64:
PLACE_TABLE
    return 1

def input_word(s:readbuf, at:u64) -> u64:
    value = 0
    index = 0
    while index < 8:
        value = value | (byte(s, at + index) << (index * 8))
        index = index + 1
    return value

def get(w:mutbuf, at:u64) -> u64:
    value = 0
    index = 0
    while index < 8:
        value = value | (byte(w, at + index) << (index * 8))
        index = index + 1
    return value

def put(o:mutbuf, at:u64, value:u64) -> u64:
    index = 0
    while index < 8:
        store(o, at + index, (value >> (index * 8)) & 255)
        index = index + 1
    return 0
'''
    suffix = b',"replayed":false}'
    if len(suffix) != 18:
        raise ValueError('unexpected Journal cost suffix')
    literals = {
        'SINGLE_MAGIC': b'HIAJIN01', 'SESSION_MAGIC': b'HIAJIN02', 'REPLY_MAGIC': b'HIAJOU01',
        'READ_WORKFLOW_MAGIC': b'HIAJWP01', 'STATE_MAGIC': b'HIAJRN02',
        'READ_ERROR_MAGIC': b'HIAJWE01', 'READ_COST_MAGIC': b'HIAJWC01',
        'READ_REPLY_MAGIC': b'HIAJWV01', 'READ_VERIFIED_MAGIC': b'HIAJWO01',
        'COST_COMMIT_MAGIC': b'HIAJWZ01', 'COST_COMMITTED_MAGIC': b'HIAJWG01',
        'COST_INTENT_MAGIC': b'HIASTCP1',
        'EFFECT_CLOSEOUT': b'HIAFDO01', 'READ_TOOL': b'hia_read',
        'COST_MAGIC': b'HIAJCF01', 'INSERT_MAGIC': b'HIAINS01', 'DETAILS_PREFIX': b'{"error"',
        'DETAILS_SUFFIX_FIRST': suffix[:8], 'DETAILS_SUFFIX_SECOND': suffix[8:16],
        'UNADMITTED_INITIAL': b'unadmitt', 'COMPLETED_INITIAL': b'complete',
        'REJECTED_LITERAL': b'rejected',
    }
    source = re.sub(r'\b(' + '|'.join(literals) + r')\b',
                    lambda match: str(int.from_bytes(literals[match[0]], 'little')), source)
    source = source.replace('DETAILS_SUFFIX_SIZE', str(len(suffix)))
    source = source.replace('MIN_DETAILS', str(9 + 4 + len(suffix)))
    from tools.generate_hia_agent_journal import response_recipe
    source = source.replace('RECIPE_ID_OFFSET', str(response_recipe()[0]))
    places = '\n'.join(f'    if position == {i}:\n        return {10 ** i}' for i in range(1, 20))
    source = source.replace('PLACE_TABLE', places)
    return source + read_error_program()


def read_error_program():
    # Existing public error objects (before the Journal adds the request ID).
    errors = (
        ('read_artifact_error', 'E_HIA_ARTIFACT_IDENTITY',
         'artifact reference was not issued in this runtime namespace'),
        ('read_cursor_error', 'E_HIA_CURSOR', 'cursor is not bound to this exact artifact'),
    )
    source = ''
    for name, code, message in errors:
        raw = json.dumps(dict(code=code, details_artifact=None, message=message,
                              phase='admission', retry_action='correct_input'),
                         sort_keys=True, separators=(',', ':')).encode('ascii')
        source += f'\ndef {name}(o:mutbuf) -> u64:\n'
        for at in range(0, len(raw), 8):
            field = raw[at:at + 8]
            if len(field) == 8:
                source += f'    put(o, {at}, {int.from_bytes(field, "little")})\n'
            else:
                source += ''.join(f'    store(o, {at + i}, {byte})\n' for i, byte in enumerate(field))
        source += f'    return {len(raw)}\n'
    return source


if __name__ == '__main__':
    (ROOT / SOURCE).write_text(
        render_assembly(document(transport_program(), 'agent_journal_transport')), encoding='utf-8')
