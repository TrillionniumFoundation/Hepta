"""Author the retained HIA request-journal admission and effect state owner.

SQLite and existing tool handlers transport effects. HIA owns row admission,
single dispatch, replay validation custody, exact terminal bytes, and every
commit/rollback acknowledgement required to return a durable result.
"""
from __future__ import annotations

import ast
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

REQUEST_MAGIC = int.from_bytes(b'HIAJRQ01', 'little')
STATE_MAGIC = int.from_bytes(b'HIAJST01', 'little')
RESULT_MAGIC = int.from_bytes(b'HIAJRS01', 'little')
CLEANUP_MAGIC = int.from_bytes(b'HIAJCL01', 'little')
MAX_RESPONSE = 8 * 1024 * 1024

SOURCE = r'''
def journal_main(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 128 or length(s) > 8390656 or length(w) < 1025 or length(w) > 8389632 or length(o) < 32:
        return 4294967293
    if read_word(s, 0) != @REQUEST_MAGIC@:
        return 4294967293
    event = read_word(s, 8)
    if event == 91:
        return rollback_claim(s, o, w)
    if length(o) < length(w) - 576:
        return 4294967293
    if event == 0:
        return initialize(s, o, w)
    if valid_state(w) == 0:
        return invalid(o, 2)
    if read_word(s, 96) != get(w, 5) or read_word(s, 104) != get(w, 6) or read_word(s, 112) != get(w, 7) or read_word(s, 120) != get(w, 8):
        return invalid(o, 2)
    if event == 90:
        if length(s) != 128 or read_word(s, 16) != get(w, 3):
            return invalid(o, 7)
        return answer(o, w)
    if get(w, 2) == 9 or read_word(s, 16) != get(w, 3):
        return refuse(o, w, 7)
    if get(w, 3) == 18446744073709551615:
        return refuse(o, w, 5)
    if event == 2:
        return row_transition(s, o, w)
    if event == 6:
        return completion(s, o, w)
    if event == 12:
        return returned_response(s, o, w)
    if length(s) != 128:
        return refuse(o, w, 1)
    if event == 1:
        if get(w, 2) != 1 or read_word(s, 32) != 1:
            return refuse(o, w, 6)
        set(w, 2, 2)
        return advance(o, w, 2)
    if event == 3:
        if get(w, 2) != 3 or read_word(s, 32) != 1:
            return refuse(o, w, 3)
        set(w, 2, 4)
        return advance(o, w, 2)
    if event == 4:
        if get(w, 2) != 5 or read_word(s, 32) != 1:
            return refuse(o, w, 6)
        if get(w, 12) == 0:
            set(w, 2, 6)
        else:
            set(w, 2, 8)
            set(w, 13, 0)
        return advance(o, w, 0)
    if event == 5:
        return dispatch(s, o, w)
    if event == 7 or event == 8 or event == 9:
        return cleanup_or_replay(s, o, w, event)
    return refuse(o, w, 1)

def initialize(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    tool_size = read_word(s, 32)
    started_size = read_word(s, 40)
    key_kind = read_word(s, 48)
    key_size = read_word(s, 56)
    key_digest_size = read_word(s, 64)
    if tool_size == 0 or tool_size > 128 or started_size > 64 or key_kind > 2 or key_size > 768 or key_digest_size > 64:
        return invalid(o, 1)
    if length(s) != 192 + tool_size + started_size + key_size + key_digest_size:
        return invalid(o, 1)
    if read_word(s, 16) != 0 or read_word(s, 24) != 0 or read_word(s, 72) != 0 or read_word(s, 80) != 0 or read_word(s, 88) != 0:
        return invalid(o, 1)
    if read_word(s, 96) == 0 and read_word(s, 104) == 0:
        return invalid(o, 1)
    if read_word(s, 112) == 0 and read_word(s, 120) == 0:
        return invalid(o, 1)
    digest_start = 128 + tool_size
    started_start = digest_start + 64
    key_start = started_start + started_size
    key_digest_start = key_start + key_size
    if hexadecimal(s, digest_start, 64) == 0 or decimal(s, started_start, started_size) == 0:
        return invalid(o, 1)
    if ascii_text(s, 128, tool_size) == 0:
        return invalid(o, 1)
    key_characters = 0
    keyed = 0
    if key_kind == 1:
        if key_digest_size != 64 or hexadecimal(s, key_digest_start, 64) == 0:
            return invalid(o, 1)
        key_characters = unicode_count(s, key_start, key_size)
        if key_characters == 18446744073709551615:
            return invalid(o, 1)
        if key_characters >= 1 and key_characters <= 192:
            keyed = 1
    elif key_size != 0 or key_digest_size != 0:
        return invalid(o, 1)
    i = 0
    while i < 1024:
        if byte(w, i) != 0:
            return invalid(o, 2)
        i = i + 1
    set(w, 0, @STATE_MAGIC@)
    set(w, 1, 1)
    set(w, 2, 6)
    set(w, 3, 1)
    set(w, 4, keyed)
    set(w, 5, read_word(s, 96))
    set(w, 6, read_word(s, 104))
    set(w, 7, read_word(s, 112))
    set(w, 8, read_word(s, 120))
    set(w, 9, tool_size)
    set(w, 10, started_size)
    set(w, 22, key_characters)
    set(w, 24, length(w) - 1024)
    copy_input(s, digest_start, w, 320, 64)
    copy_input(s, 128, w, 384, tool_size)
    copy_input(s, started_start, w, 512, started_size)
    if literal(s, 128, tool_size, 9, @ADOPT_LOW@, @ADOPT_HIGH@) != 0:
        set(w, 15, 1)
    if literal(s, 128, tool_size, 12, @ROLLBACK_LOW@, @ROLLBACK_HIGH@) != 0:
        set(w, 15, 2)
    if keyed != 0:
        copy_input(s, key_digest_start, w, 256, 64)
        set(w, 2, 1)
        set(w, 16, 1)
        set(w, 25, 1)
    seal(w)
    return answer(o, w)

def row_transition(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if get(w, 2) != 2 and get(w, 2) != 4:
        return refuse(o, w, 7)
    found = read_word(s, 32)
    state_size = read_word(s, 40)
    tool_size = read_word(s, 48)
    started_size = read_word(s, 56)
    response_present = read_word(s, 64)
    response_size = read_word(s, 72)
    key_size = read_word(s, 80)
    digest_size = read_word(s, 88)
    if found > 1 or response_present > 1 or state_size > 16 or tool_size > 128 or started_size > 64 or response_size > get(w, 24) or key_size > 64 or digest_size > 64:
        return refuse(o, w, 1)
    if length(s) != 128 + key_size + digest_size + tool_size + state_size + started_size + response_size:
        return refuse(o, w, 1)
    if found == 0:
        if length(s) != 128 or response_present != 0 or state_size != 0 or tool_size != 0 or started_size != 0 or response_size != 0 or key_size != 0 or digest_size != 0:
            return refuse(o, w, 1)
        if get(w, 2) != 2 or get(w, 12) != 0:
            return refuse(o, w, 3)
        set(w, 2, 3)
        return advance(o, w, 3)
    if key_size != 64 or digest_size != 64 or same_input(s, 128, w, 256, 64) == 0:
        return refuse(o, w, 3)
    if same_input(s, 192, w, 320, 64) == 0:
        return refuse(o, w, 3)
    if tool_size != get(w, 9) or same_input(s, 256, w, 384, tool_size) == 0:
        return refuse(o, w, 1)
    state_start = 256 + tool_size
    started_start = state_start + state_size
    response_start = started_start + started_size
    if decimal(s, started_start, started_size) == 0 or response_present == 0 and response_size != 0:
        return refuse(o, w, 1)
    if get(w, 2) == 4:
        return verify_row(s, o, w, state_start, state_size, started_start, started_size, response_start, response_size, response_present)
    if get(w, 12) == 0:
        if literal(s, state_start, state_size, 9, @COMPLETED_LOW@, @COMPLETED_HIGH@) == 0:
            return refuse(o, w, 4)
        if response_present == 0 or response_size == 0:
            return refuse(o, w, 1)
        copy_input(s, started_start, w, 512, started_size)
        set(w, 10, started_size)
        copy_input(s, response_start, w, 1024, response_size)
        set(w, 11, response_size)
        set(w, 12, 3)
        set(w, 2, 11)
        set(w, 13, get(w, 3) + 1)
        return advance(o, w, 8)
    if literal(s, state_start, state_size, 7, @RUNNING_LOW@, 0) == 0 or response_present != 0:
        return refuse(o, w, 3)
    if started_size != get(w, 10) or same_input(s, started_start, w, 512, started_size) == 0:
        return refuse(o, w, 3)
    if get(w, 12) == 2:
        set(w, 2, 7)
        set(w, 13, get(w, 3) + 1)
        return advance(o, w, 7)
    if get(w, 12) != 1:
        return refuse(o, w, 7)
    set(w, 2, 3)
    return advance(o, w, 4)

def verify_row(s:readbuf, o:mutbuf, w:mutbuf, state_start:u64, state_size:u64, started_start:u64, started_size:u64, response_start:u64, response_size:u64, response_present:u64) -> u32:
    if started_size != get(w, 10) or same_input(s, started_start, w, 512, started_size) == 0:
        return refuse(o, w, 3)
    if get(w, 12) == 0:
        if literal(s, state_start, state_size, 7, @RUNNING_LOW@, 0) == 0 or response_present != 0:
            return refuse(o, w, 3)
    else:
        if literal(s, state_start, state_size, 9, @COMPLETED_LOW@, @COMPLETED_HIGH@) == 0 or response_present != 1 or response_size != get(w, 11):
            return refuse(o, w, 3)
        if same_input(s, response_start, w, 1024, response_size) == 0:
            return refuse(o, w, 3)
    set(w, 2, 5)
    return advance(o, w, 5)

def dispatch(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if get(w, 2) != 6 or get(w, 14) != 0 or get(w, 13) != 0:
        return refuse(o, w, 7)
    set(w, 14, 1)
    if get(w, 15) != 0:
        if get(w, 4) != 1:
            return refuse(o, w, 1)
        set(w, 12, 2)
        set(w, 2, 1)
        set(w, 25, get(w, 3) + 1)
        return advance(o, w, 1)
    set(w, 2, 7)
    set(w, 13, get(w, 3) + 1)
    return advance(o, w, 7)

def completion(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    size = read_word(s, 32)
    if size == 0 or size > get(w, 24) or length(s) != 128 + size or read_word(s, 40) != 1:
        return refuse(o, w, 1)
    if get(w, 2) == 8:
        if get(w, 12) == 3 or get(w, 21) != 1 or size != get(w, 11) or same_input(s, 128, w, 1024, size) == 0:
            return refuse(o, w, 7)
        return answer(o, w)
    if get(w, 2) == 12:
        if get(w, 21) != 1 or read_word(s, 24) != 0 or get(w, 13) != 0 or size != get(w, 11) or same_input(s, 128, w, 1024, size) == 0:
            return refuse(o, w, 7)
    elif get(w, 2) == 6:
        if read_word(s, 24) != 0 or get(w, 13) != 0 or get(w, 14) != 0 and get(w, 20) != 1:
            return refuse(o, w, 7)
    else:
        return refuse(o, w, 7)
    copy_input(s, 128, w, 1024, size)
    set(w, 11, size)
    set(w, 21, 1)
    if get(w, 4) == 0:
        set(w, 2, 8)
        set(w, 13, 0)
        return advance(o, w, 0)
    if get(w, 12) == 2:
        set(w, 2, 3)
        return advance(o, w, 4)
    set(w, 12, 1)
    set(w, 2, 1)
    set(w, 25, get(w, 3) + 1)
    return advance(o, w, 1)

def rollback_claim(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    set(o, 0, @CLEANUP_MAGIC@)
    set(o, 1, 2)
    set(o, 2, 0)
    set(o, 3, 0)
    if length(s) != 128 or valid_state(w) == 0:
        return 32
    if read_word(s, 96) != get(w, 5) or read_word(s, 104) != get(w, 6) or read_word(s, 112) != get(w, 7) or read_word(s, 120) != get(w, 8):
        return 32
    i = 2
    while i < 12:
        if read_word(s, i * 8) != 0:
            return 32
        i = i + 1
    epoch = get(w, 25)
    if epoch == 0:
        return 32
    set(o, 1, 0)
    set(o, 3, epoch)
    if get(w, 19) == epoch:
        return 32
    set(w, 19, epoch)
    seal(w)
    set(o, 2, 1)
    return 32

def returned_response(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    size = read_word(s, 32)
    if get(w, 2) != 7 or get(w, 13) == 0 or read_word(s, 24) != get(w, 13):
        return refuse(o, w, 7)
    if size == 0 or size > get(w, 24) or length(s) != 128 + size or read_word(s, 40) != 1:
        return refuse(o, w, 1)
    copy_input(s, 128, w, 1024, size)
    set(w, 11, size)
    set(w, 21, 1)
    set(w, 13, 0)
    set(w, 2, 12)
    return advance(o, w, 0)

def cleanup_or_replay(s:readbuf, o:mutbuf, w:mutbuf, event:u64) -> u32:
    if event == 7:
        if get(w, 2) != 7 and get(w, 2) != 11:
            return refuse(o, w, 7)
        if get(w, 12) != 2 and get(w, 12) != 3:
            return refuse(o, w, 7)
        if read_word(s, 24) != get(w, 13) or read_word(s, 32) > 1:
            return refuse(o, w, 7)
        set(w, 20, read_word(s, 32))
        set(w, 2, 10)
        return advance(o, w, 6)
    if event == 8:
        if get(w, 2) != 10 or read_word(s, 32) != 1 or get(w, 25) == 0 or get(w, 19) != get(w, 25):
            return refuse(o, w, 6)
        set(w, 13, 0)
        if get(w, 20) != 1:
            return refuse(o, w, 6)
        if get(w, 12) == 3:
            set(w, 2, 8)
        else:
            set(w, 2, 6)
            set(w, 12, 0)
        return advance(o, w, 0)
    if get(w, 2) != 11 or get(w, 12) != 3 or read_word(s, 24) != get(w, 13) or read_word(s, 32) != 1:
        return refuse(o, w, 7)
    set(w, 23, 1)
    set(w, 2, 5)
    return advance(o, w, 5)

def unicode_count(s:readbuf, start:u64, size:u64) -> u64:
    i = 0
    count = 0
    while i < size:
        ch = byte(s, start + i)
        width = 1
        if ch >= 128:
            if ch >= 194 and ch <= 223:
                width = 2
            elif ch >= 224 and ch <= 239:
                width = 3
            elif ch >= 240 and ch <= 244:
                width = 4
            else:
                return 18446744073709551615
            if i + width > size:
                return 18446744073709551615
            second = byte(s, start + i + 1)
            if (ch == 224 and second < 160) or (ch == 237 and second >= 160) or (ch == 240 and second < 144) or (ch == 244 and second >= 144):
                return 18446744073709551615
            j = 1
            while j < width:
                tail = byte(s, start + i + j)
                if tail < 128 or tail > 191:
                    return 18446744073709551615
                j = j + 1
        i = i + width
        count = count + 1
    return count

def decimal(s:readbuf, start:u64, size:u64) -> u64:
    if size == 0 or size > 64:
        return 0
    if size > 1 and byte(s, start) == 48:
        return 0
    i = 0
    while i < size:
        ch = byte(s, start + i)
        if ch < 48 or ch > 57:
            return 0
        i = i + 1
    return 1

def ascii_text(s:readbuf, start:u64, size:u64) -> u64:
    i = 0
    while i < size:
        ch = byte(s, start + i)
        if ch < 33 or ch > 126:
            return 0
        i = i + 1
    return 1

def hexadecimal(s:readbuf, start:u64, size:u64) -> u64:
    i = 0
    while i < size:
        ch = byte(s, start + i)
        if (ch < 48 or ch > 57) and (ch < 97 or ch > 102):
            return 0
        i = i + 1
    return 1

def literal(s:readbuf, start:u64, size:u64, expected_size:u64, low:u64, high:u64) -> u64:
    if size != expected_size:
        return 0
    i = 0
    while i < size:
        if i < 8:
            expected = (low >> (i * 8)) & 255
        else:
            expected = (high >> ((i - 8) * 8)) & 255
        if byte(s, start + i) != expected:
            return 0
        i = i + 1
    return 1

def valid_state(w:mutbuf) -> u64:
    if get(w, 0) != @STATE_MAGIC@ or get(w, 1) != 1 or get(w, 2) == 0 or get(w, 2) > 12 or get(w, 3) == 0 or get(w, 4) > 1:
        return 0
    if get(w, 9) == 0 or get(w, 9) > 128 or get(w, 10) == 0 or get(w, 10) > 64 or get(w, 11) > get(w, 24):
        return 0
    if get(w, 12) > 3 or get(w, 14) > 1 or get(w, 15) > 2 or get(w, 16) > 8 or get(w, 17) > 7 or get(w, 20) > 1 or get(w, 21) > 1 or get(w, 23) > 1:
        return 0
    if get(w, 24) == 0 or get(w, 24) > 8388608 or length(w) != 1024 + get(w, 24):
        return 0
    if get(w, 19) > get(w, 3) or get(w, 25) > get(w, 3):
        return 0
    i = 26
    while i < 32:
        if get(w, i) != 0:
            return 0
        i = i + 1
    if get(w, 18) != checksum(w):
        return 0
    return 1

def refuse(o:mutbuf, w:mutbuf, status:u64) -> u32:
    set(w, 2, 9)
    set(w, 16, 0)
    set(w, 17, status)
    seal(w)
    return answer(o, w)

def advance(o:mutbuf, w:mutbuf, action:u64) -> u32:
    set(w, 3, get(w, 3) + 1)
    set(w, 16, action)
    seal(w)
    return answer(o, w)

def invalid(o:mutbuf, status:u64) -> u32:
    i = 0
    while i < 16:
        set(o, i, 0)
        i = i + 1
    set(o, 0, @RESULT_MAGIC@)
    set(o, 1, status)
    return 128

def answer(o:mutbuf, w:mutbuf) -> u32:
    set(o, 0, @RESULT_MAGIC@)
    set(o, 1, get(w, 17))
    set(o, 2, get(w, 16))
    set(o, 3, get(w, 3))
    set(o, 4, get(w, 2))
    set(o, 5, get(w, 4))
    set(o, 6, get(w, 12))
    set(o, 7, get(w, 15))
    set(o, 8, get(w, 13))
    set(o, 9, get(w, 14))
    set(o, 10, get(w, 9))
    set(o, 11, get(w, 10))
    set(o, 12, get(w, 11))
    set(o, 13, get(w, 22))
    set(o, 14, get(w, 23))
    set(o, 15, 0)
    copy_output(w, 256, o, 128, 128)
    copy_output(w, 384, o, 256, get(w, 9))
    at = 256 + get(w, 9)
    copy_output(w, 512, o, at, get(w, 10))
    at = at + get(w, 10)
    copy_output(w, 1024, o, at, get(w, 11))
    return at + get(w, 11)

def same_input(s:readbuf, start:u64, w:mutbuf, target:u64, size:u64) -> u64:
    i = 0
    while i < size:
        if byte(s, start + i) != byte(w, target + i):
            return 0
        i = i + 1
    return 1

def copy_input(s:readbuf, start:u64, w:mutbuf, target:u64, size:u64) -> u64:
    i = 0
    while i < size:
        store(w, target + i, byte(s, start + i))
        i = i + 1
    return size

def copy_output(w:mutbuf, start:u64, o:mutbuf, target:u64, size:u64) -> u64:
    i = 0
    while i < size:
        store(o, target + i, byte(w, start + i))
        i = i + 1
    return size

def checksum(w:mutbuf) -> u64:
    value = 1469598103934665603
    i = 0
    while i < 128:
        if i != 18:
            value = ((value << 7) | (value >> 57)) ^ get(w, i)
        i = i + 1
    i = 0
    while i < get(w, 11):
        value = ((value << 7) | (value >> 57)) ^ byte(w, 1024 + i)
        i = i + 1
    return value

def seal(w:mutbuf) -> u64:
    value = checksum(w)
    set(w, 18, value)
    return value

def get(w:mutbuf, index:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(w, index * 8 + i) << (i * 8))
        i = i + 1
    return value

def read_word(s:readbuf, index:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(s, index + i) << (i * 8))
        i = i + 1
    return value

def set(w:mutbuf, index:u64, value:u64) -> u64:
    i = 0
    while i < 8:
        store(w, index * 8 + i, value >> (i * 8))
        i = i + 1
    return value
'''


def source_program():
    values = {'REQUEST_MAGIC': REQUEST_MAGIC, 'STATE_MAGIC': STATE_MAGIC,
              'RESULT_MAGIC': RESULT_MAGIC, 'CLEANUP_MAGIC': CLEANUP_MAGIC}
    for name, raw in (('ADOPT', b'hia_adopt'), ('ROLLBACK', b'hia_rollback'),
                      ('RUNNING', b'running'), ('COMPLETED', b'completed')):
        values[name + '_LOW'] = int.from_bytes(raw[:8], 'little')
        values[name + '_HIGH'] = int.from_bytes(raw[8:], 'little')
    source = SOURCE
    for name, number in values.items():
        source = source.replace('@' + name + '@', str(number))
    return source


def document():
    nodes = ast.parse(source_program()).body
    names = {node.name: 'f' + str(i) for i, node in enumerate(nodes)}
    signatures = {node.name: ([a.annotation.id for a in node.args.args], node.returns.id)
                  for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = Builder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(v) for v in builder.params],
            'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
            'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8',
        'module': 'request_journal', 'functions': functions})


def main():
    path = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap/request_journal.hiaasm'
    path.write_text(render_assembly(document()))
    print(path.name, path.stat().st_size)


if __name__ == '__main__':
    main()
