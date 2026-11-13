"""Author retained HIA artifact namespace and enclosing SQL-scope ownership.

The byte publisher and SQLite are fixed effect adapters. No operation may
repeat an effect after its native launch claim has been consumed.
"""
from __future__ import annotations

import ast
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

REQUEST_MAGIC = int.from_bytes(b'HIANSQ01', 'little')
STATE_MAGIC = int.from_bytes(b'HIANST01', 'little')
RESULT_MAGIC = int.from_bytes(b'HIANSR01', 'little')
GUARD_MAGIC = int.from_bytes(b'HIANSG01', 'little')
MAX_JSON = 8 * 1024 * 1024
PREFIX = 2048
MAX_STATE = 4 * MAX_JSON + PREFIX

CORE = r'''
def namespace_main(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 256 or length(s) > 33554688 or length(w) < 2048 or length(w) > 33556480 or length(o) < 32:
        return 4294967293
    if read_word(s, 0) != @REQUEST_MAGIC@:
        return invalid(o, 8)
    event = read_word(s, 8)
    if event == 0:
        return initialize(s, o, w)
    if valid_state(w) == 0:
        return invalid(o, 8)
    if read_word(s, 32) != get(w, 52) or read_word(s, 40) != get(w, 53):
        return invalid(o, 8)
    if event == 24 or event == 25:
        return cleanup_scope(s, o, w, event)
    if length(o) < get(w, 54) + 32:
        return invalid(o, 8)
    if event == 90:
        if length(s) != 256 or read_word(s, 16) != 0:
            return answer(o, w, 8)
        return answer(o, w, 0)
    if read_word(s, 16) != get(w, 2):
        return answer(o, w, 8)
    if get(w, 2) == 18446744073709551615:
        return answer(o, w, 10)
    if event >= 20 and event <= 23:
        return scope_transition(s, o, w, event)
    if event == 1:
        return begin_operation(s, o, w)
    if read_word(s, 48) != get(w, 8) or read_word(s, 56) != get(w, 9) or read_word(s, 120) != get(w, 4):
        return answer(o, w, 8)
    if read_word(s, 64) != get(w, 10) or read_word(s, 72) != get(w, 11):
        return answer(o, w, 8)
    if read_word(s, 80) != get(w, 12) or read_word(s, 88) != get(w, 15) or read_word(s, 96) != get(w, 13) or read_word(s, 104) != get(w, 14) or read_word(s, 112) != get(w, 16):
        return answer(o, w, 8)
    if event == 2:
        if length(s) != 256 or get(w, 3) != 1 or get(w, 6) == 0 or read_word(s, 24) != get(w, 6) or zero_words(s, 16) == 0:
            return answer(o, w, 11)
        set(w, 3, 2)
        set(w, 39, get(w, 39) + 1)
        return advance(o, w, 0)
    if event == 4:
        if length(s) != 256 or get(w, 3) != 1 or get(w, 39) != 0 or get(w, 6) == 0 or read_word(s, 24) != get(w, 6) or zero_words(s, 16) == 0:
            return answer(o, w, 8)
        return refuse_operation(o, w, 13)
    if event == 3:
        if get(w, 3) != 2 or get(w, 6) == 0 or read_word(s, 24) != get(w, 6):
            return answer(o, w, 8)
        return operation_outcome(s, o, w)
    return answer(o, w, 8)

def initialize(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) != 256 or length(o) < 2080:
        return invalid(o, 8)
    if read_word(s, 32) == 0 and read_word(s, 40) == 0:
        return invalid(o, 8)
    if read_word(s, 64) == 0 and read_word(s, 72) == 0:
        return invalid(o, 8)
    i = 2
    while i < 32:
        if i != 4 and i != 5 and i != 8 and i != 9 and read_word(s, i * 8) != 0:
            return invalid(o, 8)
        i = i + 1
    i = 0
    while i < 2048:
        if byte(w, i) != 0:
            return invalid(o, 8)
        i = i + 1
    set(w, 0, @STATE_MAGIC@)
    set(w, 1, 1)
    set(w, 2, 1)
    set(w, 50, read_word(s, 64))
    set(w, 51, read_word(s, 72))
    set(w, 52, read_word(s, 32))
    set(w, 53, read_word(s, 40))
    set(w, 24, 2048)
    set(w, 27, 2048)
    set(w, 54, 2048)
    seal(w)
    return answer(o, w, 0)

def capture_scope(s:readbuf, w:mutbuf) -> u64:
    kind = read_word(s, 80)
    if kind > 3:
        return 0
    if kind == 0:
        if get(w, 40) != 0 or read_word(s, 64) != get(w, 50) or read_word(s, 72) != get(w, 51):
            return 0
        if read_word(s, 88) != 0 or read_word(s, 96) != 0 or read_word(s, 104) != 0 or read_word(s, 112) != 0:
            return 0
    elif kind == 1:
        if get(w, 40) != 3 or read_word(s, 64) != get(w, 50) or read_word(s, 72) != get(w, 51):
            return 0
        if read_word(s, 88) != get(w, 41) or read_word(s, 96) != get(w, 42) or read_word(s, 104) != get(w, 43) or read_word(s, 112) != 0:
            return 0
    else:
        if get(w, 40) != 0 or read_word(s, 88) == 0 or read_word(s, 112) == 0:
            return 0
        if read_word(s, 64) == 0 and read_word(s, 72) == 0:
            return 0
        if read_word(s, 96) == 0 and read_word(s, 104) == 0:
            return 0
    set(w, 10, read_word(s, 64))
    set(w, 11, read_word(s, 72))
    set(w, 12, kind)
    set(w, 13, read_word(s, 96))
    set(w, 14, read_word(s, 104))
    set(w, 15, read_word(s, 88))
    set(w, 16, read_word(s, 112))
    return 1

def stage_operation(o:mutbuf, w:mutbuf, action:u64) -> u32:
    set(w, 3, 1)
    set(w, 5, action)
    set(w, 6, get(w, 2) + 1)
    set(w, 7, 0)
    return advance(o, w, 0)

def finish_operation(o:mutbuf, w:mutbuf, kind:u64) -> u32:
    set(w, 3, 3)
    set(w, 5, 0)
    set(w, 6, 0)
    set(w, 7, 0)
    set(w, 33, kind)
    return advance(o, w, 0)

def refuse_operation(o:mutbuf, w:mutbuf, status:u64) -> u32:
    set(w, 7, status)
    if status >= 8 and status <= 11:
        set(w, 3, 5)
    else:
        set(w, 3, 4)
        set(w, 5, 0)
        set(w, 6, 0)
    return advance(o, w, status)
'''

NAMESPACE = r'''
def begin_operation(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if get(w, 3) == 1 or get(w, 3) == 2 or get(w, 3) == 5 or get(w, 40) == 8:
        return answer(o, w, 11)
    if read_word(s, 48) == 0 and read_word(s, 56) == 0:
        return answer(o, w, 8)
    if valid_input_frame(s) == 0:
        return answer(o, w, 8)
    input_end = 2048 + read_word(s, 144) + read_word(s, 152) + read_word(s, 160)
    if input_end > length(w) or input_end + 32 > length(o):
        return answer(o, w, 10)
    if capture_scope(s, w) == 0:
        return answer(o, w, 8)
    i = 3
    while i < 40:
        if i < 10 or i > 16:
            set(w, i, 0)
        i = i + 1
    i = 512
    while i < 2048:
        store(w, i, 0)
        i = i + 1
    set(w, 4, read_word(s, 120))
    set(w, 8, read_word(s, 48))
    set(w, 9, read_word(s, 56))
    set(w, 17, read_word(s, 136))
    set(w, 18, read_word(s, 144))
    set(w, 19, read_word(s, 152))
    set(w, 20, read_word(s, 160))
    set(w, 21, read_word(s, 168))
    set(w, 24, input_end)
    set(w, 27, input_end)
    set(w, 54, input_end)
    copy_input(s, 256, w, 2048, input_end - 2048)
    copy_input(s, length(s) - 32, w, 1024, 32)
    return admit_operation(s, o, w)

def valid_input_frame(s:readbuf) -> u64:
    if read_word(s, 120) < 1 or read_word(s, 120) > 5 or read_word(s, 24) != 0:
        return 0
    if read_word(s, 144) > 8388608 or read_word(s, 152) > 8388608 or read_word(s, 160) > 8388608 or read_word(s, 208) > 8388608:
        return 0
    if read_word(s, 216) > 64 or read_word(s, 224) > 64 or read_word(s, 232) > 64 or read_word(s, 240) > 64:
        return 0
    if field_at(s, 8) + 32 != length(s):
        return 0
    return 1

def field_at(s:readbuf, field:u64) -> u64:
    at = 256
    if field == 0:
        return at
    at = at + read_word(s, 144)
    if field == 1:
        return at
    at = at + read_word(s, 152)
    if field == 2:
        return at
    at = at + read_word(s, 160)
    if field == 3:
        return at
    at = at + read_word(s, 208)
    if field == 4:
        return at
    at = at + read_word(s, 216)
    if field == 5:
        return at
    at = at + read_word(s, 224)
    if field == 6:
        return at
    at = at + read_word(s, 232)
    if field == 7:
        return at
    return at + read_word(s, 240)

def admit_operation(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    operation = get(w, 4)
    if get(w, 12) == 3 and (operation == 1 or operation == 4):
        return refuse_operation(o, w, 4)
    if read_word(s, 248) > 7 or get(w, 21) > 1:
        return refuse_operation(o, w, 2)
    if unicode_count(s, 256, get(w, 18)) == 18446744073709551615 or unicode_count(s, field_at(s, 2), get(w, 20)) == 18446744073709551615:
        return refuse_operation(o, w, 2)
    if operation == 1 or operation == 4:
        return admit_put(s, o, w)
    if read_word(s, 128) != 0 or get(w, 17) != 0 or get(w, 19) != 0:
        return refuse_operation(o, w, 2)
    if operation == 2:
        return admit_get(s, o, w)
    if operation == 3:
        return admit_uri(s, o, w)
    return admit_profile(s, o, w)

def admit_put(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if read_word(s, 128) != 1 or get(w, 17) > 67108864:
        return refuse_operation(o, w, 1)
    if read_word(s, 248) & 1 == 0 or get(w, 21) != 1 or get(w, 19) == 0:
        return refuse_operation(o, w, 2)
    if get(w, 4) == 4:
        if read_word(s, 248) & 2 == 0 or literal(s, 256, get(w, 18), 7, @PROFILE_LOW@, 0) == 0 or literal(s, field_at(s, 1), get(w, 19), 2, 32123, 0) == 0:
            return refuse_operation(o, w, 2)
    elif get(w, 20) != 0:
        return refuse_operation(o, w, 2)
    if read_word(s, 208) != 0 or read_word(s, 216) != 0 or read_word(s, 224) != 0 or read_word(s, 232) != 0 or read_word(s, 240) != 0 or read_word(s, 176) != 0 or read_word(s, 184) != 0 or read_word(s, 192) != 0 or read_word(s, 200) != 0:
        return refuse_operation(o, w, 2)
    return stage_operation(o, w, 1)

def admit_get(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if read_word(s, 176) != 1 or read_word(s, 184) != 7:
        return refuse_operation(o, w, 2)
    if get(w, 20) != 0 or read_word(s, 208) != 0 or read_word(s, 240) != 0 or read_word(s, 192) != 0 or read_word(s, 200) != 0:
        return refuse_operation(o, w, 2)
    if get(w, 21) == 0 and (get(w, 18) != 0 or read_word(s, 248) != 0):
        return refuse_operation(o, w, 2)
    if get(w, 21) == 1 and read_word(s, 248) != 1:
        return refuse_operation(o, w, 2)
    if artifact_id(s, field_at(s, 4), read_word(s, 216)) == 0 or read_word(s, 224) != 64 or hexadecimal(s, field_at(s, 5), 64) == 0 or artifact_uri(s, field_at(s, 6), read_word(s, 232)) == 0:
        return refuse_operation(o, w, 3)
    copy_input(s, field_at(s, 4), w, 640, 34)
    copy_input(s, field_at(s, 5), w, 512, 64)
    copy_input(s, field_at(s, 6), w, 704, 48)
    return stage_operation(o, w, 7)

def admit_uri(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if get(w, 18) != 0 or get(w, 20) != 0 or read_word(s, 208) != 0 or read_word(s, 216) != 0 or read_word(s, 224) != 0 or read_word(s, 240) != 0 or get(w, 21) != 0 or read_word(s, 176) != 0 or read_word(s, 184) != 4 or read_word(s, 192) != 0 or read_word(s, 200) != 0 or read_word(s, 248) != 0:
        return refuse_operation(o, w, 2)
    if artifact_uri(s, field_at(s, 6), read_word(s, 232)) == 0:
        return refuse_operation(o, w, 3)
    copy_input(s, field_at(s, 6), w, 704, 48)
    return stage_operation(o, w, 9)

def admit_profile(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if read_word(s, 176) != 1 or read_word(s, 184) != 3 or read_word(s, 192) != 1 or read_word(s, 200) != 3 or read_word(s, 248) != 6:
        return refuse_operation(o, w, 5)
    if get(w, 18) != 0 or get(w, 21) != 0 or read_word(s, 216) != 0 or read_word(s, 232) != 0 or get(w, 20) != read_word(s, 208) or read_word(s, 224) != 64 or read_word(s, 240) != 64:
        return refuse_operation(o, w, 5)
    if hexadecimal(s, field_at(s, 5), 64) == 0 or same_input(s, field_at(s, 3), w, 2048, get(w, 20)) == 0 or same_bytes(s, field_at(s, 5), field_at(s, 7), 64) == 0:
        return refuse_operation(o, w, 5)
    copy_input(s, field_at(s, 5), w, 896, 64)
    return stage_operation(o, w, 11)

def operation_outcome(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    action = get(w, 5)
    if (action == 1 or action == 2 or action == 8) and read_word(s, 128) == 2:
        if length(s) != 256 or zero_words(s, 18) == 0:
            return refuse_operation(o, w, 8)
        code = read_word(s, 136)
        if code == 11 or code == 12:
            return refuse_operation(o, w, 7)
        if code == 17:
            return refuse_operation(o, w, 1)
        if code == 10 or code == 14 or code == 15 or code == 16 or code == 64:
            return refuse_operation(o, w, 12)
        return refuse_operation(o, w, 9)
    if action == 1 or action == 2 or action == 4:
        return hash_outcome(s, o, w, action)
    if action == 3 or action == 6 or action == 7 or action == 9:
        return artifact_row(s, o, w, action)
    if action == 5 or action == 10:
        if length(s) != 256 or read_word(s, 128) != 1 or read_word(s, 136) > 1 or zero_words(s, 18) == 0:
            return refuse_operation(o, w, 9)
        set(w, 29, read_word(s, 136))
        if action == 5:
            return stage_operation(o, w, 6)
        return stage_operation(o, w, 11)
    if action == 8:
        if length(s) != 256 or read_word(s, 128) != 1 or read_word(s, 136) > 67108864 or zero_words(s, 18) == 0:
            return refuse_operation(o, w, 9)
        if (get(w, 4) == 1 or get(w, 4) == 4) and read_word(s, 136) != get(w, 17):
            return refuse_operation(o, w, 7)
        set(w, 28, read_word(s, 136))
        if get(w, 4) == 4:
            if profile_wire(w) == 0:
                return refuse_operation(o, w, 10)
            return stage_operation(o, w, 10)
        return finish_operation(o, w, get(w, 4))
    if action == 11:
        return profile_row(s, o, w)
    return refuse_operation(o, w, 8)

def hash_outcome(s:readbuf, o:mutbuf, w:mutbuf, action:u64) -> u32:
    if length(s) != 320 or read_word(s, 128) != 1 or read_word(s, 144) != 64 or hexadecimal(s, 256, 64) == 0 or zero_words(s, 19) == 0:
        return refuse_operation(o, w, 9)
    expected_size = get(w, 17)
    if action == 2:
        expected_size = get(w, 35)
    if read_word(s, 136) != expected_size:
        return refuse_operation(o, w, 9)
    if action == 1:
        copy_input(s, 256, w, 512, 64)
        if binding_wire(w) == 0:
            return refuse_operation(o, w, 1)
        return stage_operation(o, w, 2)
    if action == 2:
        if get(w, 30) == 2:
            if same_input(s, 256, w, 576, 64) == 0:
                return refuse_operation(o, w, 7)
            set(w, 34, 0)
            set(w, 35, 0)
            set(w, 54, get(w, 27))
            return stage_operation(o, w, 8)
        if get(w, 30) != 1:
            return refuse_operation(o, w, 8)
        copy_input(s, 256, w, 576, 64)
        set(w, 34, 0)
        set(w, 35, 0)
        set(w, 54, get(w, 24))
        return stage_operation(o, w, 3)
    if same_input(s, 256, w, 512, 64) == 0:
        return refuse_operation(o, w, 9)
    issue_reference(w)
    return stage_operation(o, w, 5)

def artifact_row(s:readbuf, o:mutbuf, w:mutbuf, action:u64) -> u32:
    found = read_word(s, 128)
    if found == 0:
        if length(s) != 256 or zero_words(s, 17) == 0:
            return refuse_operation(o, w, 8)
        if action == 3:
            return stage_operation(o, w, 4)
        if action == 6:
            return refuse_operation(o, w, 9)
        return refuse_operation(o, w, 3)
    id_size = read_word(s, 136)
    hash_size = read_word(s, 144)
    uri_size = read_word(s, 152)
    kind_size = read_word(s, 160)
    metadata_size = read_word(s, 168)
    key_size = read_word(s, 176)
    if found != 1 or id_size != 34 or hash_size != 64 or uri_size != 48 or kind_size > 8388608 or metadata_size == 0 or metadata_size > 8388608 or key_size != 64 or read_word(s, 184) != 63 or zero_words(s, 24) == 0:
        return refuse_operation(o, w, 7)
    if length(s) != 466 + kind_size + metadata_size:
        return refuse_operation(o, w, 8)
    kind_at = 402
    metadata_at = kind_at + kind_size
    key_at = metadata_at + metadata_size
    if artifact_id(s, 256, 34) == 0 or hexadecimal(s, 290, 64) == 0 or artifact_uri(s, 354, 48) == 0 or hexadecimal(s, key_at, 64) == 0 or unicode_count(s, kind_at, kind_size) == 18446744073709551615:
        return refuse_operation(o, w, 7)
    operation = get(w, 4)
    if operation == 1 or operation == 4:
        if same_input(s, 290, w, 512, 64) == 0 or same_input(s, key_at, w, 576, 64) == 0 or kind_size != get(w, 18) or metadata_size != get(w, 19):
            return refuse_operation(o, w, 7)
        if same_input(s, kind_at, w, 2048, kind_size) == 0 or same_input(s, metadata_at, w, 2048 + kind_size, metadata_size) == 0:
            return refuse_operation(o, w, 7)
        if action == 6 and get(w, 29) == 1:
            if same_input(s, 256, w, 768, 34) == 0 or same_input(s, 354, w, 832, 48) == 0:
                return refuse_operation(o, w, 9)
        if action == 3:
            set(w, 36, 1)
    elif action == 9:
        if same_input(s, 354, w, 704, 48) == 0:
            return refuse_operation(o, w, 3)
    else:
        if same_input(s, 256, w, 640, 34) == 0 or same_input(s, 290, w, 512, 64) == 0 or same_input(s, 354, w, 704, 48) == 0:
            return refuse_operation(o, w, 3)
        if operation == 2 and get(w, 21) == 1:
            if kind_size != get(w, 18) or same_input(s, kind_at, w, 2048, kind_size) == 0:
                return refuse_operation(o, w, 4)
        if operation == 5 and literal(s, kind_at, kind_size, 7, @PROFILE_LOW@, 0) == 0:
            return refuse_operation(o, w, 4)
    if get(w, 37) != 0:
        if kind_size != get(w, 25) or metadata_size != get(w, 26) or same_input(s, key_at, w, 576, 64) == 0:
            return refuse_operation(o, w, 7)
        if same_input(s, kind_at, w, get(w, 24), kind_size + metadata_size) == 0:
            return refuse_operation(o, w, 7)
    row_end = get(w, 24) + kind_size + metadata_size
    if row_end > length(w) or row_end + 32 > length(o):
        return refuse_operation(o, w, 10)
    copy_input(s, 256, w, 640, 34)
    copy_input(s, 290, w, 512, 64)
    copy_input(s, 354, w, 704, 48)
    copy_input(s, key_at, w, 576, 64)
    copy_input(s, kind_at, w, get(w, 24), kind_size + metadata_size)
    set(w, 25, kind_size)
    set(w, 26, metadata_size)
    set(w, 27, row_end)
    set(w, 54, row_end)
    set(w, 37, 1)
    if action == 9:
        return stage_operation(o, w, 7)
    if operation != 1 and operation != 4:
        if row_binding_wire(w) == 0:
            return refuse_operation(o, w, 7)
        return stage_operation(o, w, 2)
    return stage_operation(o, w, 8)

def profile_row(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if read_word(s, 128) == 0:
        if length(s) != 256 or zero_words(s, 17) == 0:
            return refuse_operation(o, w, 8)
        if get(w, 4) == 4:
            return refuse_operation(o, w, 9)
        return refuse_operation(o, w, 6)
    if length(s) != 432 or read_word(s, 128) != 1 or read_word(s, 136) != 176 or read_word(s, 144) != 1 or zero_words(s, 19) == 0:
        return refuse_operation(o, w, 6)
    if get(w, 4) == 4:
        if same_input(s, 256, w, get(w, 34), 176) == 0:
            return refuse_operation(o, w, 6)
        return finish_operation(o, w, 4)
    if literal(s, 256, 7, 7, @REF_ID_LOW@, 0) == 0 or literal(s, 297, 12, 12, @REF_HASH_LOW@, @REF_HASH_HIGH@) == 0 or literal(s, 373, 9, 9, @REF_URI_LOW@, @REF_URI_HIGH@) == 0 or literal(s, 430, 2, 2, 32034, 0) == 0:
        return refuse_operation(o, w, 6)
    if artifact_id(s, 263, 34) == 0 or hexadecimal(s, 309, 64) == 0 or artifact_uri(s, 382, 48) == 0 or same_input(s, 309, w, 896, 64) == 0:
        return refuse_operation(o, w, 6)
    copy_input(s, 263, w, 640, 34)
    copy_input(s, 309, w, 512, 64)
    copy_input(s, 382, w, 704, 48)
    return stage_operation(o, w, 7)
'''

SCOPES = r'''
def scope_transition(s:readbuf, o:mutbuf, w:mutbuf, event:u64) -> u32:
    if length(s) != 256 or read_word(s, 64) != get(w, 50) or read_word(s, 72) != get(w, 51):
        return answer(o, w, 8)
    if read_word(s, 48) != 0 or read_word(s, 56) != 0 or read_word(s, 80) != 1 or read_word(s, 112) != 0 or read_word(s, 120) != 0:
        return answer(o, w, 8)
    if (event == 20 or event == 21) and zero_words(s, 16) == 0:
        return answer(o, w, 8)
    if event == 22 and zero_words(s, 18) == 0:
        return answer(o, w, 8)
    if event == 23 and (read_word(s, 24) != 0 or zero_words(s, 17) == 0):
        return answer(o, w, 8)
    if event == 20:
        if read_word(s, 24) != 0 or read_word(s, 88) != 0:
            return answer(o, w, 8)
        if get(w, 40) != 0 or get(w, 3) == 1 or get(w, 3) == 2 or get(w, 3) == 5:
            return answer(o, w, 11)
        if read_word(s, 96) == 0 and read_word(s, 104) == 0:
            return answer(o, w, 8)
        set(w, 40, 1)
        set(w, 41, get(w, 2) + 1)
        set(w, 42, read_word(s, 96))
        set(w, 43, read_word(s, 104))
        set(w, 44, 14)
        set(w, 45, get(w, 2) + 1)
        set(w, 46, 0)
        set(w, 48, 0)
        set(w, 49, 0)
        set(w, 58, 0)
        set(w, 59, 0)
        return advance(o, w, 0)
    if read_word(s, 88) != get(w, 41) or read_word(s, 96) != get(w, 42) or read_word(s, 104) != get(w, 43):
        return answer(o, w, 8)
    if event == 21:
        if get(w, 40) != 1 or get(w, 45) == 0 or read_word(s, 24) != get(w, 45):
            return answer(o, w, 11)
        if get(w, 44) == 16:
            if get(w, 47) == get(w, 41):
                return answer(o, w, 11)
            set(w, 47, get(w, 41))
        set(w, 40, 2)
        return advance(o, w, 0)
    if event == 22:
        if get(w, 40) != 2 or get(w, 45) == 0 or read_word(s, 24) != get(w, 45):
            return answer(o, w, 8)
        expected = 0
        if get(w, 44) == 14:
            expected = 1
        if read_word(s, 128) != 1 or read_word(s, 136) != expected:
            set(w, 40, 8)
            set(w, 46, 9)
            return advance(o, w, 9)
        if get(w, 44) == 16 and get(w, 47) != get(w, 41):
            return answer(o, w, 8)
        if get(w, 44) == 14:
            set(w, 40, 3)
        elif get(w, 59) != 0:
            set(w, 40, 8)
            set(w, 46, 9)
        else:
            set(w, 40, 0)
        set(w, 44, 0)
        set(w, 45, 0)
        return advance(o, w, get(w, 46))
    if event == 23:
        if get(w, 40) != 3 or read_word(s, 128) > 1:
            return answer(o, w, 8)
        action = 15
        if read_word(s, 128) == 0:
            action = 16
        if get(w, 3) == 1 or get(w, 3) == 2 or get(w, 3) == 5:
            action = 16
            set(w, 59, 1)
        set(w, 40, 1)
        set(w, 44, action)
        set(w, 45, get(w, 2) + 1)
        return advance(o, w, 0)
    return answer(o, w, 8)

def cleanup_scope(s:readbuf, o:mutbuf, w:mutbuf, event:u64) -> u32:
    set(o, 0, @GUARD_MAGIC@)
    set(o, 1, 8)
    set(o, 2, 0)
    set(o, 3, 0)
    if length(s) != 256 or get(w, 41) == 0:
        return 32
    if read_word(s, 16) != 0 or read_word(s, 24) != 0 or read_word(s, 48) != 0 or read_word(s, 56) != 0 or read_word(s, 80) != 1 or read_word(s, 112) != 0 or read_word(s, 120) != 0 or zero_words(s, 17) == 0:
        return 32
    if read_word(s, 64) != get(w, 50) or read_word(s, 72) != get(w, 51):
        return 32
    if read_word(s, 88) != get(w, 41) or read_word(s, 96) != get(w, 42) or read_word(s, 104) != get(w, 43):
        return 32
    set(o, 1, 0)
    set(o, 3, get(w, 41))
    if event == 25:
        if get(w, 40) != 8 or get(w, 47) != get(w, 41) or get(w, 44) != 16 or read_word(s, 128) != 1:
            set(o, 1, 8)
            return 32
        set(w, 58, 1)
        set(w, 44, 0)
        set(w, 45, 0)
        seal(w)
        return 32
    if get(w, 40) == 0 or get(w, 47) == get(w, 41):
        return 32
    if read_word(s, 128) > 1:
        set(o, 1, 8)
        return 32
    set(w, 48, get(w, 44))
    set(w, 49, get(w, 45))
    set(w, 40, 8)
    set(w, 46, 9)
    set(w, 59, 1)
    set(w, 47, get(w, 41))
    if read_word(s, 128) == 0:
        set(w, 44, 0)
        set(w, 45, 0)
        seal(w)
        return 32
    set(w, 44, 16)
    set(w, 45, get(w, 41))
    set(o, 2, 1)
    seal(w)
    return 32
'''

HELPERS = r'''
def binding_wire(w:mutbuf) -> u64:
    set(w, 30, 1)
    return compose_binding(w, 2048, get(w, 18), 2048 + get(w, 18), get(w, 19), get(w, 24))

def row_binding_wire(w:mutbuf) -> u64:
    set(w, 30, 2)
    return compose_binding(w, get(w, 24), get(w, 25), get(w, 24) + get(w, 25), get(w, 26), get(w, 27))

def compose_binding(w:mutbuf, kind_at:u64, kind_size:u64, metadata_at:u64, metadata_size:u64, at:u64) -> u64:
    quoted = quoted_size(w, kind_at, kind_size)
    size = 8 + quoted + 12 + metadata_size + 11 + 64 + 2
    if size > 8388608 or at + size > length(w):
        return 0
    write_literal(w, at, 8, @KEY_KIND_LOW@, 0)
    next_at = at + 8
    quote_json(w, kind_at, kind_size, next_at)
    next_at = next_at + quoted
    write_literal(w, next_at, 12, @KEY_METADATA_LOW@, @KEY_METADATA_HIGH@)
    next_at = next_at + 12
    copy_within(w, metadata_at, next_at, metadata_size)
    next_at = next_at + metadata_size
    write_literal(w, next_at, 11, @KEY_HASH_LOW@, @KEY_HASH_HIGH@)
    next_at = next_at + 11
    copy_within(w, 512, next_at, 64)
    write_literal(w, next_at + 64, 2, 32034, 0)
    set(w, 34, at)
    set(w, 35, size)
    set(w, 54, at + size)
    return 1

def quoted_size(w:mutbuf, start:u64, size:u64) -> u64:
    total = 2
    i = 0
    while i < size:
        ch = byte(w, start + i)
        count = 1
        if ch == 34 or ch == 92 or ch == 8 or ch == 9 or ch == 10 or ch == 12 or ch == 13:
            count = 2
        elif ch < 32:
            count = 6
        total = total + count
        i = i + 1
    return total

def quote_json(w:mutbuf, start:u64, size:u64, target:u64) -> u64:
    at = target
    store(w, at, 34)
    at = at + 1
    i = 0
    while i < size:
        ch = byte(w, start + i)
        if ch == 34 or ch == 92:
            store(w, at, 92)
            store(w, at + 1, ch)
            at = at + 2
        elif ch == 8 or ch == 9 or ch == 10 or ch == 12 or ch == 13:
            escaped = 98
            if ch == 9:
                escaped = 116
            elif ch == 10:
                escaped = 110
            elif ch == 12:
                escaped = 102
            elif ch == 13:
                escaped = 114
            store(w, at, 92)
            store(w, at + 1, escaped)
            at = at + 2
        elif ch < 32:
            write_literal(w, at, 4, 808482140, 0)
            store(w, at + 4, hex_digit(ch >> 4))
            store(w, at + 5, hex_digit(ch & 15))
            at = at + 6
        else:
            store(w, at, ch)
            at = at + 1
        i = i + 1
    store(w, at, 34)
    return at + 1 - target

def issue_reference(w:mutbuf) -> u64:
    store(w, 768, 97)
    store(w, 769, 45)
    uuid_hex(w, 1024, 770)
    write_literal(w, 832, 16, @URI_PREFIX_LOW@, @URI_PREFIX_HIGH@)
    uuid_hex(w, 1040, 848)
    return 0

def uuid_hex(w:mutbuf, start:u64, target:u64) -> u64:
    i = 0
    while i < 16:
        value = byte(w, start + i)
        if i == 6:
            value = (value & 15) | 64
        elif i == 8:
            value = (value & 63) | 128
        store(w, target + i * 2, hex_digit(value >> 4))
        store(w, target + i * 2 + 1, hex_digit(value & 15))
        i = i + 1
    return 0

def profile_wire(w:mutbuf) -> u64:
    at = get(w, 27)
    if at + 176 > length(w):
        return 0
    write_literal(w, at, 7, @REF_ID_LOW@, 0)
    copy_within(w, 640, at + 7, 34)
    write_literal(w, at + 41, 12, @REF_HASH_LOW@, @REF_HASH_HIGH@)
    copy_within(w, 512, at + 53, 64)
    write_literal(w, at + 117, 9, @REF_URI_LOW@, @REF_URI_HIGH@)
    copy_within(w, 704, at + 126, 48)
    write_literal(w, at + 174, 2, 32034, 0)
    set(w, 34, at)
    set(w, 35, 176)
    set(w, 54, at + 176)
    return 1

def artifact_id(s:readbuf, start:u64, size:u64) -> u64:
    if size != 34 or byte(s, start) != 97 or byte(s, start + 1) != 45:
        return 0
    return hexadecimal(s, start + 2, 32)

def artifact_uri(s:readbuf, start:u64, size:u64) -> u64:
    if size != 48 or literal(s, start, 16, 16, @URI_PREFIX_LOW@, @URI_PREFIX_HIGH@) == 0:
        return 0
    return hexadecimal(s, start + 16, 32)

def hexadecimal(s:readbuf, start:u64, size:u64) -> u64:
    i = 0
    while i < size:
        ch = byte(s, start + i)
        if (ch < 48 or ch > 57) and (ch < 97 or ch > 102):
            return 0
        i = i + 1
    return 1

def hex_digit(value:u64) -> u64:
    if value < 10:
        return value + 48
    return value + 87

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

def write_literal(w:mutbuf, start:u64, size:u64, low:u64, high:u64) -> u64:
    i = 0
    while i < size:
        value = low
        shift = i
        if i >= 8:
            value = high
            shift = i - 8
        store(w, start + i, value >> (shift * 8))
        i = i + 1
    return size

def zero_words(s:readbuf, first:u64) -> u64:
    i = first
    while i < 32:
        if read_word(s, i * 8) != 0:
            return 0
        i = i + 1
    return 1

def same_input(s:readbuf, start:u64, w:mutbuf, target:u64, size:u64) -> u64:
    i = 0
    while i < size:
        if byte(s, start + i) != byte(w, target + i):
            return 0
        i = i + 1
    return 1

def same_bytes(s:readbuf, first:u64, second:u64, size:u64) -> u64:
    i = 0
    while i < size:
        if byte(s, first + i) != byte(s, second + i):
            return 0
        i = i + 1
    return 1

def copy_input(s:readbuf, start:u64, w:mutbuf, target:u64, size:u64) -> u64:
    i = 0
    while i < size:
        store(w, target + i, byte(s, start + i))
        i = i + 1
    return size

def copy_within(w:mutbuf, start:u64, target:u64, size:u64) -> u64:
    i = 0
    while i < size:
        store(w, target + i, byte(w, start + i))
        i = i + 1
    return size

def copy_output(w:mutbuf, start:u64, o:mutbuf, target:u64, size:u64) -> u64:
    i = 0
    while i < size:
        store(o, target + i, byte(w, start + i))
        i = i + 1
    return size

def valid_state(w:mutbuf) -> u64:
    if get(w, 0) != @STATE_MAGIC@ or get(w, 1) != 1 or get(w, 2) == 0:
        return 0
    if get(w, 3) > 5 or get(w, 4) > 5 or get(w, 5) > 11 or get(w, 7) > 13 or get(w, 12) > 3:
        return 0
    if get(w, 40) > 8 or get(w, 44) > 16 or get(w, 46) > 11 or get(w, 58) > 1 or get(w, 59) > 1:
        return 0
    if get(w, 52) == 0 and get(w, 53) == 0:
        return 0
    if get(w, 50) == 0 and get(w, 51) == 0:
        return 0
    if get(w, 54) < 2048 or get(w, 54) > length(w):
        return 0
    if get(w, 24) < 2048 or get(w, 24) > get(w, 54) or get(w, 27) < 2048 or get(w, 27) > get(w, 54):
        return 0
    if get(w, 18) > 8388608 or get(w, 19) > 8388608 or get(w, 20) > 8388608:
        return 0
    if get(w, 25) > 8388608 or get(w, 26) > 8388608 or (get(w, 3) != 4 and get(w, 17) > 67108864):
        return 0
    if get(w, 6) > get(w, 2) or get(w, 39) > get(w, 2) or get(w, 41) > get(w, 2) or get(w, 45) > get(w, 2) or get(w, 47) > get(w, 2):
        return 0
    i = 60
    while i < 64:
        if get(w, i) != 0:
            return 0
        i = i + 1
    if checksum(w) != get(w, 32):
        return 0
    return 1

def checksum(w:mutbuf) -> u64:
    value = 1469598103934665603
    i = 0
    while i < 64:
        if i != 32:
            value = ((value << 7) | (value >> 57)) ^ get(w, i)
        i = i + 1
    extent = get(w, 54)
    i = 512
    while i < extent:
        value = ((value << 7) | (value >> 57)) ^ byte(w, i)
        i = i + 1
    return value

def seal(w:mutbuf) -> u64:
    set(w, 32, checksum(w))
    return 0

def advance(o:mutbuf, w:mutbuf, status:u64) -> u32:
    set(w, 2, get(w, 2) + 1)
    seal(w)
    return answer(o, w, status)

def answer(o:mutbuf, w:mutbuf, status:u64) -> u32:
    size = get(w, 54)
    if length(o) < size + 32:
        return invalid(o, 8)
    set(o, 0, @RESULT_MAGIC@)
    set(o, 1, status)
    set(o, 2, get(w, 2))
    set(o, 3, size)
    i = 0
    while i < size:
        store(o, 32 + i, byte(w, i))
        i = i + 1
    return size + 32

def invalid(o:mutbuf, status:u64) -> u32:
    set(o, 0, @RESULT_MAGIC@)
    set(o, 1, status)
    set(o, 2, 0)
    set(o, 3, 0)
    return 32

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
              'RESULT_MAGIC': RESULT_MAGIC, 'GUARD_MAGIC': GUARD_MAGIC}
    for name, raw in (('PROFILE', b'profile'), ('URI_PREFIX', b'hia://artifacts/'),
                      ('REF_ID', b'{"id":"'), ('REF_HASH', b'","sha256":"'),
                      ('REF_URI', b'","uri":"'), ('KEY_KIND', b'{"kind":'),
                      ('KEY_METADATA', b',"metadata":'), ('KEY_HASH', b',"sha256":"')):
        values[name + '_LOW'] = int.from_bytes(raw[:8], 'little')
        values[name + '_HIGH'] = int.from_bytes(raw[8:], 'little')
    source = CORE + NAMESPACE + SCOPES + HELPERS
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
        'module': 'artifact_namespace', 'functions': functions})


def main():
    path = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap/artifact_namespace.hepta'
    path.write_text(render_assembly(document()))
    print(path.name, path.stat().st_size)


if __name__ == '__main__':
    main()
