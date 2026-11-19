"""Author the HIA codec for the sealed journal's input and output frames.

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
    for name, value in (('SINGLE_MAGIC', b'HIAJIN01'), ('SESSION_MAGIC', b'HIAJIN02'),
                        ('REPLY_MAGIC', b'HIAJOU01')):
        source = source.replace(name, str(int.from_bytes(value, 'little')))
    return source


if __name__ == '__main__':
    (ROOT / SOURCE).write_text(
        render_assembly(document(transport_program(), 'agent_journal_transport')), encoding='utf-8')
