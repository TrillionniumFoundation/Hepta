"""Author the complete immutable commit state owner over issued native leases.

This is development authoring. It does not install a namespace selector or a
hosted storage fallback. The syscall executor and admitted predecessor custody
are explicit integration gates, not supplied by a matching integer handle.
"""
from __future__ import annotations

import ast
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_agent_namespace_objects import ObjectBuilder
from tools.generate_hia_agent_namespace_store import VALUES
from tools.generate_hia_sha256 import source_program as sha_source
from tools.generate_hia_selfhost import compact_authoring_cfg, total_scalar_functions

ROOT = Path(__file__).resolve().parents[1]
MAGIC = int.from_bytes(b'HIANCM01', 'little')
HEAD_MAGIC = int.from_bytes(b'HIANHD01', 'little')
HASH_BASE = 16384
PHASES = {
    10: (1, 1), 11: (4, 1), 12: (2, 1), 13: (4, 1), 14: (8, 1),
    20: (4, 1), 21: (5, 1), 30: (2, 1), 31: (3, 1),
    40: (1, 1), 41: (3, 1), 42: (1, 1), 43: (4, 1), 44: (2, 1), 45: (4, 1),
    50: (6, 2), 51: (6, 2), 52: (6, 2),
    60: (1, 3), 61: (3, 3), 62: (6, 3), 63: (1, 3), 64: (4, 3),
    65: (2, 3), 66: (4, 3), 67: (8, 3), 68: (7, 3),
    70: (6, 4), 80: (8, 255), 81: (9, 255), 82: (8, 255), 83: (8, 255),
}

COMMIT = r'''
def namespace_commit(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < 24576:
        return 4294967293
    if get(w, 8) == 3 or get(w, 8) == 4:
        return emit(o, w, 4294967293, 0, 0)
    if length(o) < 4352:
        return poison(w, 1)
    if get(w, 0) == 0:
        if initialize(s, w) == 0:
            poison(w, 2)
            return emit(o, w, 4294967293, 0, 0)
        if read64(s, 8) == 9:
            return emit(o, w, 0, 4096, 160)
        return emit(o, w, 0, 1280, 32)
    if valid_state(w) == 0 or frame(s, w) == 0:
        poison(w, 3)
        return emit(o, w, 4294967293, 0, 0)
    command = read64(s, 8)
    if command == 7:
        return acknowledge(s, o, w)
    put(w, 32, read64(s, 32))
    if command == 6 or command == 8:
        return retire(o, w)
    if command == 2:
        current_path(w)
        return request(o, w, 10, 1, get(w, 104), 655360, 0, 0, 2048, 7)
    if command == 3:
        return request(o, w, 50, 6, get(w, 88), 0, 0, 0, 0, 0)
    if command == 4:
        temporary_path(w)
        return request(o, w, 60, 1, get(w, 104), 655553, 384, 0, 2176, 57)
    return request(o, w, 70, 6, get(w, 104), 0, 0, 0, 0, 0)

def zeros(s:readbuf, at:u64, end:u64) -> u64:
    while at < end:
        if read64(s, at) != 0:
            return 0
        at = at + 8
    return 1

def equal_bytes(w:mutbuf, a:u64, b:u64, size:u64) -> u64:
    at = 0
    while at < size:
        if byte(w, a + at) != byte(w, b + at):
            return 0
        at = at + 1
    return 1

def zero_bytes(w:mutbuf, at:u64, size:u64) -> u64:
    end = at + size
    while at < end:
        if byte(w, at) != 0:
            return 0
        at = at + 1
    return 1

def initialize(s:readbuf, w:mutbuf) -> u64:
    if length(s) < 256 or read64(s, 0) != COMMIT_MAGIC or read64(s, 32) != 1 or zeros(s, 40, 64) == 0:
        return 0
    if read64(s, 16) == 0 and read64(s, 24) == 0:
        return 0
    if zero_bytes(w, 0, 24576) == 0:
        return 0
    command = read64(s, 8)
    if command == 9:
        if length(s) != 288 or read64(s, 64) == 0 or zeros(s, 72, 256) == 0:
            return 0
        copy_input(w, s, 1424, 256, 32)
        if zero_bytes(w, 1424, 32) == 1:
            return 0
        put(w, 1408, HEAD_MAGIC_VALUE)
        put(w, 1416, 1)
        if hash_workspace(w, 1408, 128, 1568) != 32:
            return 0
        move_workspace(w, 4096, 1408, 128)
        move_workspace(w, 4224, 1568, 32)
        put(w, 72, read64(s, 64))
        put(w, 8, 4)
    else:
        if command != 1 or length(s) != 416 or zeros(s, 160, 256) == 0:
            return 0
        at = 64
        while at < 160:
            if read64(s, at) == 0:
                return 0
            at = at + 8
        at = 80
        while at < 112:
            other = at + 8
            while other < 112:
                if read64(s, at) == read64(s, other):
                    return 0
                other = other + 8
            at = at + 8
        copy_input(w, s, 1024, 256, 128)
        copy_input(w, s, 1328, 384, 32)
        if get(w, 1024) != HEAD_MAGIC_VALUE or get(w, 1032) != 1 or zero_bytes(w, 1040, 32) == 1:
            return 0
        base = get(w, 1112)
        if get(w, 1104) > base or base > 9223372036854775807:
            return 0
        if base == 0:
            if zero_bytes(w, 1072, 80) == 0:
                return 0
        elif get(w, 1104) == base:
            return 0
        if read64(s, 136) > 9223372036854775807 - base:
            return 0
        at = 64
        while at < 144:
            put(w, at + 8, read64(s, at))
            at = at + 8
        put(w, 344, read64(s, 144))
        put(w, 352, read64(s, 152))
        copy_input(w, s, 768, 64, 96)
        put(w, 152, base)
        put(w, 160, base + get(w, 144))
        if hash_workspace(w, 1024, 128, 1280) != 32:
            return 0
        put(w, 64, 1)
        put(w, 8, 1)
    put(w, 0, COMMIT_MAGIC)
    put(w, 16, read64(s, 16))
    put(w, 24, read64(s, 24))
    put(w, 32, 1)
    put(w, 368, 1)
    return 1

def poison(w:mutbuf, reason:u64) -> u64:
    if get(w, 8) != 3:
        put(w, 224, reason)
    put(w, 8, 3)
    return 4294967293

def known_error(o:mutbuf, w:mutbuf, code:u64, error:u64) -> u64:
    put(w, 208, code)
    put(w, 216, error)
    if get(w, 232) != 0:
        poison(w, 4)
        return emit(o, w, 4294967293, 0, 0)
    put(w, 8, 5)
    put(w, 48, 0)
    put(w, 56, 0)
    put(w, 368, 1)
    return emit(o, w, 2, 0, 0)

def valid_state(w:mutbuf) -> u64:
    if get(w, 0) != COMMIT_MAGIC or (get(w, 8) != 1 and get(w, 8) != 2 and get(w, 8) != 5):
        return 0
    if (get(w, 16) == 0 and get(w, 24) == 0) or get(w, 32) == 0 or get(w, 224) != 0:
        return 0
    if get(w, 64) < 1 or get(w, 64) > 5 or get(w, 232) > 1 or get(w, 272) > 1:
        return 0
    if get(w, 152) > get(w, 160) or get(w, 160) > 9223372036854775807 or get(w, 144) != get(w, 160) - get(w, 152):
        return 0
    if get(w, 168) > get(w, 144) or get(w, 176) > 4096:
        return 0
    at = 0
    while at < 80:
        if get(w, 72 + at) != get(w, 768 + at):
            return 0
        at = at + 8
    if get(w, 344) != get(w, 848) or get(w, 352) != get(w, 856) or valid_stage(w) == 0:
        return 0
    if get(w, 8) != 2:
        if get(w, 48) != 0 or get(w, 56) != 0 or get(w, 368) != 1:
            return 0
        return choose((get(w, 8) == 1 and get(w, 208) == 0) or (get(w, 8) == 5 and get(w, 208) != 0), 1, 0)
    if get(w, 368) != 0 or get(w, 40) == 0 or get(w, 48) != get(w, 376) or phase_opcode(get(w, 48)) != get(w, 56):
        return 0
    expected = phase_stage(get(w, 48))
    if expected == 0 or (expected != 255 and get(w, 64) != expected):
        return 0
    if expected == 255 and get(w, 64) == 4:
        return 0
    if get(w, 56) == 2 or get(w, 56) == 3:
        if expected_io(w) == 0:
            return 0
    return equal_bytes(w, 384, 640, 80)

def valid_stage(w:mutbuf) -> u64:
    stage = get(w, 64)
    state = get(w, 8)
    published = choose(stage >= 4 or (state == 2 and get(w, 48) == 68), 1, 0)
    if get(w, 232) != published:
        return 0
    if (get(w, 272) == 1 and get(w, 248) == 0) or (stage >= 4 and get(w, 272) != 0):
        return 0
    if state == 2:
        if get(w, 48) < 80 and get(w, 208) != 0:
            return 0
        if get(w, 48) >= 61 and get(w, 48) <= 68 and get(w, 272) != 1:
            return 0
    if state == 5 and stage >= 4:
        return 0
    if state == 1:
        if get(w, 256) != 0:
            return 0
        if stage == 1:
            return choose(get(w, 40) == 0 and get(w, 168) == 0 and get(w, 240) == 0 and get(w, 248) == 0 and zero_bytes(w, 1632, 32) == 1, 1, 0)
        if get(w, 168) != get(w, 144) or get(w, 240) == 0 or equal_bytes(w, 1328, 1632, 32) == 0:
            return 0
        if stage == 2 or stage == 3:
            return choose(get(w, 248) == 0 and get(w, 272) == 0, 1, 0)
        return choose(get(w, 248) != 0, 1, 0)
    return 1

def expected_io(w:mutbuf) -> u64:
    if get(w, 296) == 0 or get(w, 296) > 4096 or get(w, 304) >= get(w, 296):
        return 0
    if get(w, 312) > 8192 or get(w, 296) > 8192 - get(w, 312) or get(w, 288) > 9223372036854775807 or get(w, 296) > 9223372036854775807 - get(w, 288):
        return 0
    if get(w, 384) != get(w, 280) or get(w, 392) != get(w, 288) + get(w, 304) or get(w, 400) != get(w, 296) - get(w, 304) or get(w, 408) != 0:
        return 0
    phase = get(w, 48)
    fd = 0
    position = 0
    size = 0
    target = 0
    if phase == 12 or phase == 65:
        fd = get(w, 256)
        size = 32
        target = 2304
    elif phase == 30 or phase == 31:
        fd = choose(phase == 30, get(w, 96), get(w, 88))
        position = get(w, 168) + choose(phase == 30, 0, get(w, 152))
        size = get(w, 176)
        target = 4096
    elif phase == 41 or phase == 44:
        fd = get(w, 240)
        size = 128
        target = choose(phase == 41, 1408, 4096)
    elif phase == 61:
        fd = get(w, 248)
        size = 32
        target = 1568
    else:
        return 0
    return choose(fd != 0 and get(w, 280) == fd and get(w, 288) == position and get(w, 296) == size and get(w, 312) == target, 1, 0)

def frame(s:readbuf, w:mutbuf) -> u64:
    if length(s) < 256 or length(s) > 4352 or read64(s, 0) != COMMIT_MAGIC or read64(s, 16) != get(w, 16) or read64(s, 24) != get(w, 24):
        return 0
    command = read64(s, 8)
    if command == 7:
        if get(w, 8) != 2 or read64(s, 32) != get(w, 32) or read64(s, 40) != get(w, 40) or read64(s, 48) != get(w, 56):
            return 0
        if read64(s, 120) != 0 or read64(s, 128) != length(s) - 256 or zeros(s, 136, 256) == 0:
            return 0
        if read64(s, 56) == 0:
            return success_shape(s, w)
        if read64(s, 128) != 0 or zeros(s, 72, 120) == 0:
            return 0
        if read64(s, 56) == 1:
            return choose(read64(s, 64) > 0 and read64(s, 64) <= 4095, 1, 0)
        return choose(read64(s, 56) == 2 and read64(s, 64) == 0, 1, 0)
    if length(s) != 256 or get(w, 8) == 2 or command < 2 or command > 8:
        return 0
    if get(w, 32) == 18446744073709551615 or read64(s, 32) != get(w, 32) + 1 or zeros(s, 40, 64) == 0:
        return 0
    if read64(s, 64) != get(w, 136) or read64(s, 72) != get(w, 72) or read64(s, 80) != get(w, 80) or read64(s, 88) != get(w, 120) or read64(s, 96) != get(w, 128) or zeros(s, 104, 256) == 0:
        return 0
    if command == 6 or command == 8:
        return choose(get(w, 64) != 4, 1, 0)
    if get(w, 8) != 1:
        return 0
    return choose(command - 1 == get(w, 64), 1, 0)

def success_shape(s:readbuf, w:mutbuf) -> u64:
    operation = get(w, 56)
    a = read64(s, 64)
    if operation == 1:
        if a == 0 or zeros(s, 72, 120) == 0 or read64(s, 128) != 0:
            return 0
        at = 88
        while at < 120:
            if a == get(w, at):
                return 0
            at = at + 8
        return choose(a != get(w, 240) and a != get(w, 248) and a != get(w, 256), 1, 0)
    if a != get(w, 384):
        return 0
    if operation == 2 or operation == 3:
        if read64(s, 72) != get(w, 392) or read64(s, 80) > get(w, 400) or zeros(s, 88, 120) == 0:
            return 0
        return choose(read64(s, 128) == choose(operation == 2, read64(s, 80), 0), 1, 0)
    if operation == 4:
        return choose(read64(s, 128) == 0, 1, 0)
    if operation == 5:
        return choose(read64(s, 72) == get(w, 392) and zeros(s, 80, 120) == 1 and read64(s, 128) == 0, 1, 0)
    if operation == 7:
        return choose(read64(s, 72) == get(w, 392) and zeros(s, 80, 120) == 1 and read64(s, 128) == 0, 1, 0)
    return choose(zeros(s, 72, 120) == 1 and read64(s, 128) == 0, 1, 0)

def request(o:mutbuf, w:mutbuf, phase:u64, operation:u64, a:u64, b:u64, c:u64, d:u64, start:u64, count:u64) -> u64:
    if get(w, 40) == 18446744073709551615 or count > 4096 or start > 8192 or count > 8192 - start:
        poison(w, 5)
        return emit(o, w, 4294967293, 0, 0)
    put(w, 40, get(w, 40) + 1)
    put(w, 48, phase)
    put(w, 376, phase)
    put(w, 56, operation)
    put(w, 384, a)
    put(w, 392, b)
    put(w, 400, c)
    put(w, 408, d)
    put(w, 416, 0)
    put(w, 424, 0)
    put(w, 432, 0)
    put(w, 440, 0)
    put(w, 448, start)
    put(w, 456, count)
    move_workspace(w, 640, 384, 80)
    put(w, 8, 2)
    put(w, 368, 0)
    return emit(o, w, 1, start, count)

def io_start(o:mutbuf, w:mutbuf, phase:u64, operation:u64, fd:u64, position:u64, count:u64, target:u64) -> u64:
    put(w, 48, phase)
    put(w, 56, operation)
    put(w, 280, fd)
    put(w, 288, position)
    put(w, 296, count)
    put(w, 304, 0)
    put(w, 312, target)
    return io_more(o, w)

def io_more(o:mutbuf, w:mutbuf) -> u64:
    count = get(w, 296) - get(w, 304)
    start = choose(get(w, 56) == 3, get(w, 312) + get(w, 304), 0)
    payload = choose(get(w, 56) == 3, count, 0)
    return request(o, w, get(w, 48), get(w, 56), get(w, 280), get(w, 288) + get(w, 304), count, 0, start, payload)

def finish(o:mutbuf, w:mutbuf, stage:u64) -> u64:
    put(w, 64, stage)
    put(w, 8, 1)
    put(w, 48, 0)
    put(w, 56, 0)
    put(w, 208, 0)
    put(w, 216, 0)
    put(w, 368, 1)
    return emit(o, w, 0, 1568, 32)

def start_page(o:mutbuf, w:mutbuf) -> u64:
    remaining = get(w, 144) - get(w, 168)
    if remaining == 0:
        if equal_bytes(w, 1328, 1632, 32) == 0:
            return known_error(o, w, 11, 1)
        if make_head(w) != 32:
            poison(w, 7)
            return emit(o, w, 4294967293, 0, 0)
        hex_bytes(w, 1568, 32, 2048)
        return request(o, w, 40, 1, get(w, 112), 655553, 384, 0, 2048, 64)
    if remaining > 4096:
        remaining = 4096
    put(w, 176, remaining)
    fill_range(w, 4096, 4096, 0)
    return io_start(o, w, 30, 2, get(w, 96), get(w, 168), remaining, 4096)

def make_head(w:mutbuf) -> u64:
    fill_range(w, 1408, 128, 0)
    put(w, 1408, HEAD_MAGIC_VALUE)
    put(w, 1416, 1)
    move_workspace(w, 1424, 1040, 32)
    move_workspace(w, 1456, 1280, 32)
    put(w, 1488, get(w, 152))
    put(w, 1496, get(w, 160))
    move_workspace(w, 1504, 1632, 32)
    return hash_workspace(w, 1408, 128, 1568)

def current_path(w:mutbuf) -> u64:
    put(w, 2048, CURRENT_WORD)
    return 0

def temporary_path(w:mutbuf) -> u64:
    put(w, 2176, TEMP_WORD)
    store(w, 2184, 45)
    hex_word(w, get(w, 16), 2185)
    hex_word(w, get(w, 24), 2201)
    hex_word(w, get(w, 136), 2217)
    return 0

def hex_word(w:mutbuf, value:u64, target:u64) -> u64:
    at = 0
    while at < 16:
        digit = (value >> ((15 - at) * 4)) & 15
        store(w, target + at, choose(digit < 10, digit + 48, digit + 87))
        at = at + 1
    return 0

def hex_bytes(w:mutbuf, source:u64, size:u64, target:u64) -> u64:
    at = 0
    while at < size:
        value = byte(w, source + at)
        high = value >> 4
        low = value & 15
        store(w, target + at * 2, choose(high < 10, high + 48, high + 87))
        store(w, target + at * 2 + 1, choose(low < 10, low + 48, low + 87))
        at = at + 1
    return 0

def record_stat(s:readbuf, w:mutbuf, size:u64) -> u64:
    if (read64(s, 72) & 61440) != 32768 or read64(s, 80) != size:
        return 0
    copy_input(w, s, 512, 72, 48)
    return 1

def same_stat(s:readbuf, w:mutbuf) -> u64:
    at = 0
    while at < 48:
        if byte(s, 72 + at) != byte(w, 512 + at):
            return 0
        at = at + 1
    return 1

def acknowledge(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    status = read64(s, 56)
    if status == 2:
        poison(w, 6)
        return emit(o, w, 4294967293, 0, 0)
    if status == 1:
        return syscall_error(o, w, read64(s, 64))
    operation = get(w, 56)
    if operation == 2 or operation == 3:
        count = read64(s, 80)
        if count == 0:
            return known_error(o, w, choose(operation == 2, 522, 13), 0)
        if operation == 2:
            copy_input(w, s, get(w, 312) + get(w, 304), 256, count)
        put(w, 304, get(w, 304) + count)
        if get(w, 304) < get(w, 296):
            return io_more(o, w)
    phase = get(w, 48)
    if phase < 30:
        return prepare_prefix_reply(s, o, w, phase)
    if phase < 50:
        return prepare_bytes_reply(s, o, w, phase)
    if phase < 60:
        return sync_reply(o, w, phase)
    if phase < 80:
        return publish_reply(s, o, w, phase)
    return retire_reply(o, w, phase)

def prepare_prefix_reply(s:readbuf, o:mutbuf, w:mutbuf, phase:u64) -> u64:
    if phase == 10:
        put(w, 256, read64(s, 64))
        return request(o, w, 11, 4, get(w, 256), 0, 0, 0, 0, 0)
    if phase == 11:
        if record_stat(s, w, 32) == 0:
            return known_error(o, w, 11, 2)
        return io_start(o, w, 12, 2, get(w, 256), 0, 32, 2304)
    if phase == 12:
        return request(o, w, 13, 4, get(w, 256), 0, 0, 0, 0, 0)
    if phase == 13:
        if same_stat(s, w) == 0:
            return known_error(o, w, 11, 3)
        return request(o, w, 14, 8, get(w, 256), 0, 0, 0, 0, 0)
    if phase == 14:
        put(w, 256, 0)
        if equal_bytes(w, 2304, 1280, 32) == 0:
            return known_error(o, w, 5, 0)
        return request(o, w, 20, 4, get(w, 88), 0, 0, 0, 0, 0)
    if phase == 20:
        size = read64(s, 80)
        if (read64(s, 72) & 61440) != 32768 or size < get(w, 152) or size > 9223372036854775807:
            return known_error(o, w, 11, 4)
        if size != get(w, 152):
            return request(o, w, 21, 5, get(w, 88), get(w, 152), 0, 0, 0, 0)
        return start_page(o, w)
    return start_page(o, w)

def prepare_bytes_reply(s:readbuf, o:mutbuf, w:mutbuf, phase:u64) -> u64:
    if phase == 30:
        if hash_workspace(w, 4096, get(w, 176), 1696) != 32:
            poison(w, 7)
            return emit(o, w, 4294967293, 0, 0)
        move_workspace(w, 1760, 1632, 32)
        put(w, 1792, get(w, 176))
        move_workspace(w, 1800, 1696, 32)
        if hash_workspace(w, 1760, 72, 1632) != 32:
            poison(w, 7)
            return emit(o, w, 4294967293, 0, 0)
        return io_start(o, w, 31, 3, get(w, 88), get(w, 152) + get(w, 168), get(w, 176), 4096)
    if phase == 31:
        put(w, 168, get(w, 168) + get(w, 176))
        return start_page(o, w)
    if phase == 40:
        put(w, 240, read64(s, 64))
        return io_start(o, w, 41, 3, get(w, 240), 0, 128, 1408)
    if phase == 41:
        return finish(o, w, 2)
    if phase == 42:
        put(w, 240, read64(s, 64))
        return request(o, w, 43, 4, get(w, 240), 0, 0, 0, 0, 0)
    if phase == 43:
        if record_stat(s, w, 128) == 0:
            return known_error(o, w, 11, 5)
        return io_start(o, w, 44, 2, get(w, 240), 0, 128, 4096)
    if phase == 44:
        if equal_bytes(w, 4096, 1408, 128) == 0:
            return known_error(o, w, 11, 6)
        return request(o, w, 45, 4, get(w, 240), 0, 0, 0, 0, 0)
    if same_stat(s, w) == 0:
        return known_error(o, w, 11, 7)
    return finish(o, w, 2)

def sync_reply(o:mutbuf, w:mutbuf, phase:u64) -> u64:
    if phase == 50:
        return request(o, w, 51, 6, get(w, 240), 0, 0, 0, 0, 0)
    if phase == 51:
        return request(o, w, 52, 6, get(w, 112), 0, 0, 0, 0, 0)
    return finish(o, w, 3)

def publish_reply(s:readbuf, o:mutbuf, w:mutbuf, phase:u64) -> u64:
    if phase == 60:
        put(w, 248, read64(s, 64))
        put(w, 272, 1)
        return io_start(o, w, 61, 3, get(w, 248), 0, 32, 1568)
    if phase == 61:
        return request(o, w, 62, 6, get(w, 248), 0, 0, 0, 0, 0)
    if phase == 62:
        current_path(w)
        return request(o, w, 63, 1, get(w, 104), 655360, 0, 0, 2048, 7)
    if phase == 63:
        put(w, 256, read64(s, 64))
        return request(o, w, 64, 4, get(w, 256), 0, 0, 0, 0, 0)
    if phase == 64:
        if record_stat(s, w, 32) == 0:
            return known_error(o, w, 11, 8)
        return io_start(o, w, 65, 2, get(w, 256), 0, 32, 2304)
    if phase == 65:
        return request(o, w, 66, 4, get(w, 256), 0, 0, 0, 0, 0)
    if phase == 66:
        if same_stat(s, w) == 0:
            return known_error(o, w, 11, 9)
        return request(o, w, 67, 8, get(w, 256), 0, 0, 0, 0, 0)
    if phase == 67:
        put(w, 256, 0)
        if equal_bytes(w, 2304, 1280, 32) == 0:
            return known_error(o, w, 5, 0)
        move_workspace(w, 2368, 2176, 57)
        move_workspace(w, 2425, 2048, 7)
        put(w, 232, 1)
        return request(o, w, 68, 7, get(w, 104), get(w, 104), 57, 7, 2368, 64)
    if phase == 68:
        put(w, 272, 0)
        return finish(o, w, 4)
    return finish(o, w, 5)

def retire(o:mutbuf, w:mutbuf) -> u64:
    if get(w, 256) != 0:
        return request(o, w, 80, 8, get(w, 256), 0, 0, 0, 0, 0)
    if get(w, 272) != 0:
        temporary_path(w)
        return request(o, w, 81, 9, get(w, 104), 0, 0, 0, 2176, 57)
    if get(w, 248) != 0:
        return request(o, w, 82, 8, get(w, 248), 0, 0, 0, 0, 0)
    if get(w, 240) != 0:
        return request(o, w, 83, 8, get(w, 240), 0, 0, 0, 0, 0)
    put(w, 64, 6)
    put(w, 8, 4)
    put(w, 48, 0)
    put(w, 56, 0)
    put(w, 368, 1)
    put(w, 208, 0)
    put(w, 216, 0)
    return emit(o, w, 0, 0, 0)

def retire_reply(o:mutbuf, w:mutbuf, phase:u64) -> u64:
    if phase == 80:
        put(w, 256, 0)
    elif phase == 81:
        put(w, 272, 0)
    elif phase == 82:
        put(w, 248, 0)
    else:
        put(w, 240, 0)
    return retire(o, w)

def syscall_error(o:mutbuf, w:mutbuf, error:u64) -> u64:
    phase = get(w, 48)
    operation = get(w, 56)
    if phase == 68:
        if error == 5 or error == 4:
            return known_error(o, w, 10, error)
        put(w, 232, 0)
    if operation == 8:
        if phase == 14 or phase == 67 or phase == 80:
            put(w, 256, 0)
        elif phase == 82:
            put(w, 248, 0)
        elif phase == 83:
            put(w, 240, 0)
    elif error == 4 and operation != 7:
        return request(o, w, phase, operation, get(w, 384), get(w, 392), get(w, 400), get(w, 408), get(w, 448), get(w, 456))
    if phase == 40 and error == 17:
        return request(o, w, 42, 1, get(w, 112), 655360, 0, 0, 2048, 64)
    if phase == 60 and error == 17:
        return known_error(o, w, 5, error)
    if phase == 81 and error == 2:
        put(w, 272, 0)
        return retire(o, w)
    return known_error(o, w, sqlite_io_code(operation, error), error)

def sqlite_io_code(operation:u64, error:u64) -> u64:
    if operation == 1:
        return choose(error == 12, 7, 14)
    if operation == 2:
        return 266
    if operation == 3:
        return choose(error == 28, 13, 778)
    if operation == 4:
        return 1802
    if operation == 5:
        return 1546
    if operation == 6:
        return 1034
    if operation == 8:
        return 4106
    if operation == 9:
        return 2570
    return 10

def emit(o:mutbuf, w:mutbuf, status:u64, start:u64, count:u64) -> u64:
    if length(o) < 4352:
        return 4294967293
    fill_range(o, 0, length(o), 0)
    put(o, 0, COMMIT_MAGIC)
    put(o, 8, status)
    put(o, 16, get(w, 16))
    put(o, 24, get(w, 24))
    put(o, 32, get(w, 32))
    put(o, 40, get(w, 40))
    put(o, 48, get(w, 48))
    if status == 1:
        put(o, 56, get(w, 56))
        copy_workspace(o, w, 64, 384, 48)
    put(o, 112, count)
    put(o, 120, get(w, 64))
    copy_workspace(o, w, 128, 72, 16)
    put(o, 144, get(w, 120))
    put(o, 152, get(w, 96))
    put(o, 160, get(w, 136))
    put(o, 168, get(w, 152))
    put(o, 176, get(w, 160))
    put(o, 184, get(w, 168))
    put(o, 192, get(w, 208))
    put(o, 200, get(w, 216))
    put(o, 208, get(w, 224))
    put(o, 216, get(w, 232))
    put(o, 224, 1)
    if count != 0:
        copy_workspace(o, w, 256, start, count)
    return status
'''


class _HashInWorkspace(ast.NodeTransformer):
    """Relocate the qualified one-shot SHA algebra, without changing rounds."""
    def visit_Call(self, node):
        if isinstance(node.func, ast.Name):
            name = node.func.id
            if name == 'length' and isinstance(node.args[0], ast.Name) and node.args[0].id == 's':
                return ast.Name(id='size', ctx=ast.Load())
            if name == 'padded_byte':
                return ast.Call(func=ast.Name(id='hash_padded_byte', ctx=ast.Load()),
                                args=[ast.Name(id=n, ctx=ast.Load()) for n in ('w', 'start', 'size')]+[self.visit(x) for x in node.args[1:]], keywords=[])
            if name in ('get', 'put'):
                args = [self.visit(x) for x in node.args]
                args[1] = ast.BinOp(left=ast.Constant(HASH_BASE), op=ast.Add(), right=args[1])
                return ast.Call(func=node.func, args=args, keywords=[])
            if name == 'store' and isinstance(node.args[0], ast.Name) and node.args[0].id == 'o':
                return ast.Call(func=node.func, args=[ast.Name(id='w', ctx=ast.Load()),
                    ast.BinOp(left=ast.Name(id='target', ctx=ast.Load()), op=ast.Add(), right=self.visit(node.args[1])), self.visit(node.args[2])], keywords=[])
        return self.generic_visit(node)


def hash_source():
    nodes = {node.name: node for node in ast.parse(sha_source()).body}
    body = nodes['sha256'].body[1:]
    transformed = [_HashInWorkspace().visit(node) for node in body]
    prefix = ast.parse('''def hash_workspace(w:mutbuf, start:u64, size:u64, target:u64) -> u64:
    if size > 4096 or start > 8192 or size > 8192 - start or target > 8192 or 32 > 8192 - target:
        return 4294967293
''').body[0]
    prefix.body += transformed
    helper = ast.parse('''def hash_padded_byte(w:mutbuf, start:u64, size:u64, index:u64, total:u64) -> u64:
    if index < size:
        return byte(w, start + index)
    if index == size:
        return 128
    if index < total - 8:
        return 0
    return ((size << 3) >> ((total - 1 - index) * 8)) & 255
''').body[0]
    return ast.unparse(ast.fix_missing_locations(ast.Module(body=[prefix, helper, nodes['rotate']], type_ignores=[])))+'\n'


def source_program():
    text = (COMMIT.replace('HEAD_MAGIC_VALUE', str(HEAD_MAGIC)).replace('COMMIT_MAGIC', str(MAGIC))
            .replace('CURRENT_WORD', str(int.from_bytes(b'CURRENT\0', 'little')))
            .replace('TEMP_WORD', str(int.from_bytes(b'.current', 'little'))))
    for name, field in (('phase_opcode', 0), ('phase_stage', 1)):
        text += '\ndef %s(phase:u64) -> u64:\n' % name
        for phase, pair in PHASES.items():
            text += '    if phase == %d:\n        return %d\n' % (phase, pair[field])
        text += '    return 0\n'
    return text+'\n'+hash_source()+VALUES[VALUES.index('\ndef read64('):]


def document():
    nodes = ast.parse(source_program()).body
    names = {node.name: 'f'+str(i) for i, node in enumerate(nodes)}
    if len(names) != len(nodes):
        raise ValueError('duplicate namespace commit HIA symbol')
    signatures = {node.name: ([a.annotation.id for a in node.args.args], node.returns.id) for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = ObjectBuilder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(v) for v in builder.params],
                          'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
                          'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8', 'module': 'agent_namespace_commit', 'functions': functions})


def main():
    path = ROOT/'examples/hia_bootstrap/agent_namespace_commit.hiaasm'
    path.write_text(render_assembly(document()))
    print(path.name, path.stat().st_size)


if __name__ == '__main__':
    main()
