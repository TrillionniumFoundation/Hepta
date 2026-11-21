"""Author the sealed HIA journal codec and native Store cost binding.

The OS adapter owns descriptor transfer and mapping. This separate image keeps
the bounded journal transition compiler's function and block limits intact.
"""
from __future__ import annotations

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_agent_stdio import ROOT, document

SOURCE = 'examples/hia_bootstrap/agent_journal_transport.hepta'

def transport_program():
    source = '''
def transfer(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
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
        'COST_MAGIC': b'HIAJCF01', 'INSERT_MAGIC': b'HIAINS01', 'DETAILS_PREFIX': b'{"error"',
        'DETAILS_SUFFIX_FIRST': suffix[:8], 'DETAILS_SUFFIX_SECOND': suffix[8:16],
        'UNADMITTED_INITIAL': b'unadmitt', 'COMPLETED_INITIAL': b'complete',
        'REJECTED_LITERAL': b'rejected',
    }
    for name, value in literals.items():
        source = source.replace(name, str(int.from_bytes(value, 'little')))
    source = source.replace('DETAILS_SUFFIX_SIZE', str(len(suffix)))
    source = source.replace('MIN_DETAILS', str(9 + 4 + len(suffix)))
    places = '\n'.join(f'    if position == {i}:\n        return {10 ** i}' for i in range(1, 20))
    source = source.replace('PLACE_TABLE', places)
    return source


if __name__ == '__main__':
    (ROOT / SOURCE).write_text(
        render_assembly(document(transport_program(), 'agent_journal_transport')), encoding='utf-8')
