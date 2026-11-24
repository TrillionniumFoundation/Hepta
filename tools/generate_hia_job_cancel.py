"""Author the Linux HIA host of the pinned cancellation authority and writer."""
from __future__ import annotations

import ast
from pathlib import Path
import struct
import subprocess
import tempfile

from hepta.hia_agent_assembly import render_assembly
from tools import generate_hia_job_observation as observation
from tools.generate_hia_job_supervisor import document
from tools.generate_hia_native_filter import LINK_SOURCE

ROOT = Path(__file__).resolve().parents[1]
REQUEST_MAGIC = int.from_bytes(b'HIAJCQ02', 'little')
PACKER_MAGIC = int.from_bytes(b'HIAJCK02', 'little')
INPUT_BYTES = 3 << 20

POLICY = r'''
def advance(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(o) != 128 or length(w) != STATE_BYTES:
        return 0
    phase = get(w, 0)
    result = get(w, 8)
    if phase == 0:
        if admit(s, w) == 0:
            return 0
        return call(o, w, 1, 107, 0, 0, 0, 0, 0, 0, 0)
    if phase == 1:
        put(w, 16, result)
        return call(o, w, 5, 39, 0, 0, 0, 0, 0, 0, 0)
    if phase == 5:
        put(w, 1216, result)
        store(w, 8192, 47)
        store(w, 8193, 0)
        return call(o, w, 2, 257, NEG100, 8192, 2818048, 0, 0, 0, 12)
    if phase == 2:
        if failed(result) or result < 3:
            return 0
        put(w, 24, result)
        put(w, 32, 0)
        put(w, 40, 0)
        return next_directory(s, o, w)
    if phase == 3:
        if failed(result) or result < 3:
            return 0
        put(w, 24, result)
        return call(o, w, 4, 5, result, 4096, 0, 0, 0, 0, 12)
    if phase == 4:
        if failed(result) or getn(w, 4120, 4) & 61440 != 16384:
            return 0
        if get(w, 40) + 3 >= get(w, 48):
            if getn(w, 4124, 4) != get(w, 16) or getn(w, 4120, 4) & 4095 != 448:
                return 0
        put(w, 40, get(w, 40) + 1)
        return next_directory(s, o, w)
    if phase >= 10 and phase <= 19:
        return metadata(s, o, w, phase, result)
    if phase >= 150 and phase <= 160:
        return process_advance(s, o, w, phase, result)
    if phase >= 200 and phase <= 219:
        return image_advance(s, o, w, phase, result)
    if phase >= 300 and phase <= 319:
        return frame_advance(s, o, w, phase, result)
    if phase >= 400 and phase <= 449:
        return helper_advance(s, o, w, phase, result)
    if phase >= 500 and phase <= 519:
        return cancel_advance(s, o, w, phase, result)
    if phase == 90:
        if result == NEG4:
            return write_reply(o, w)
        if failed(result) or result == 0 or result > get(w, 176) - get(w, 184):
            return 0
        put(w, 184, get(w, 184) + result)
        if get(w, 184) < get(w, 176):
            return write_reply(o, w)
        return call(o, w, 99, 60, 0, 0, 0, 0, 0, 0, 0)
    return 0

def open_metadata(o:mutbuf, w:mutbuf) -> u32:
    which = get(w, 88)
    if which == 0 or which == 3:
        at = text_request_name(w, 8192)
    elif which == 1 or which == 5:
        at = text_launch_name(w, 8192)
    elif which == 6:
        at = text_started_name(w, 8192)
    else:
        at = text_exit_name(w, 8192)
    store(w, at, 0)
    put(w, 192, 0)
    return call(o, w, 10, 257, get(w, 24), 8192, 657408, 0, 0, 0, 12)

def metadata_failure(s:readbuf, o:mutbuf, w:mutbuf, malformed:bool) -> u32:
    return 0

def next_metadata(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    which = get(w, 88)
    present = get(w, 192)
    if which < 3:
        put(w, 88, which + 1)
        return open_metadata(o, w)
    if which == 3:
        if present == 0 or equal_input_field(s, w, lookup(w, 1), get(w, 56), uint(s, 48)) == 0:
            return 0
        if freeze_field(w, lookup(w, 1), 1) == False or freeze_field(w, lookup(w, 7), 3) == False:
            return 0
        copy_input(s, w, get(w, 56), 393216, uint(s, 48))
        put(w, 16384, uint(s, 48))
        put(w, 88, 4)
        return open_metadata(o, w)
    if which == 4 or which == 7:
        if present != 0 and get(w, ARENA + 96) != 0:
            return cancel_reply(s, o, w, which == 4)
        if which == 7:
            put(w, 1112, 3)
            return observe_process(o, w)
        put(w, 88, 5)
        return open_metadata(o, w)
    if which == 5:
        systemd = present != 0 and field_is(w, lookup(w, 8), 38)
        put(w, 216, choose(systemd, 1, 0))
        put(w, 88, 6)
        return open_metadata(o, w)
    if which == 6:
        root = choose(present != 0, ARENA + 64, NONE)
        put(w, 288, bounded_integer(w, lookup_in(w, root, 10)))
        put(w, 296, bounded_integer(w, lookup_in(w, root, 9)))
        if freeze_field(w, lookup_in(w, root, 1), 2) == False or freeze_field(w, lookup_in(w, root, 7), 4) == False:
            return 0
        if freeze_field(w, lookup_in(w, root, 14), 7) == False:
            return 0
        identity = lookup_in(w, root, 11)
        if identity_shape(w, identity) == False:
            identity = NONE
        if freeze_field(w, lookup_in(w, identity, 12), 5) == False or freeze_field(w, lookup_in(w, identity, 13), 6) == False:
            return 0
        put(w, 1040, 0)
        return image_start(s, o, w)
    return 0

def bounded_integer(w:mutbuf, record:u64) -> u64:
    value = decimal_field(w, record)
    return choose(value <= 4294967295, value, NONE)

def identity_shape(w:mutbuf, record:u64) -> bool:
    if record == NONE or get(w, record) != 6:
        return False
    child = get(w, record + 24)
    seen = 0
    while child != NONE:
        item = ARENA + 64 + child * 72
        key = key_id(w, ARENA + get(w, item + 40), get(w, item + 48))
        if key == 12:
            seen = seen | 1
        elif key == 13:
            seen = seen | 2
        else:
            return False
        child = get(w, item + 16)
    return seen == 3

def freeze_field(w:mutbuf, record:u64, field:u64) -> bool:
    size = 0
    if record != NONE and get(w, record) == 4:
        size = get(w, record + 32)
        if size > 4096:
            return False
        source = ARENA + get(w, record + 24)
        if valid_utf8(w, source, size) == False:
            return False
        copy_state(w, source, 393216 + field * 4096, size)
    put(w, 16384 + field * 8, size)
    return True

def copy_input(s:readbuf, w:mutbuf, source:u64, target:u64, size:u64) -> u64:
    index = 0
    while index < size:
        store(w, target + index, byte(s, source + index))
        index = index + 1
    return target + size

def image_start(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    which = get(w, 1040)
    put(w, 1048, 0)
    put(w, 1056, uint(s, 16 + which * 8))
    at = cancel_text(w, 0, 8192)
    store(w, at, 0)
    return call(o, w, 200, 319, 8192, 3, 0, 0, 0, 0, 3)

def image_advance(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 200:
        if failed(result) or result < 3:
            return 0
        put(w, 1064, result)
        return call(o, w, 201, 91, result, 320, 0, 0, 0, 0, 0)
    if phase == 201:
        if failed(result):
            return 0
        return sha(o, w, 202, 0, 1)
    if phase == 202 or phase == 205:
        if result != 0:
            return 0
        if get(w, 1048) == get(w, 1056):
            return sha(o, w, 206, 2, 1)
        size = get(w, 1056) - get(w, 1048)
        if size > 65536:
            size = 65536
        put(w, 1080, size)
        put(w, 1072, 0)
        source = get(w, 1000 + get(w, 1040) * 8) + get(w, 1048)
        copy_input(s, w, source, 65537, size)
        return image_write(o, w)
    if phase == 203:
        if result == NEG4:
            return image_write(o, w)
        if failed(result) or result == 0 or result > get(w, 1080) - get(w, 1072):
            return 0
        put(w, 1072, get(w, 1072) + result)
        if get(w, 1072) < get(w, 1080):
            return image_write(o, w)
        put(w, 1048, get(w, 1048) + get(w, 1080))
        return sha(o, w, 205, 1, get(w, 1080) + 1)
    if phase == 206:
        if result != 32:
            return 0
        pin = get(w, 1016 + get(w, 1040) * 8)
        index = 0
        while index < 32:
            if byte(w, 4096 + index) != byte(s, pin + index):
                return 0
            index = index + 1
        return call(o, w, 207, 72, get(w, 1064), 1033, 15, 0, 0, 0, 0)
    if phase == 207:
        if failed(result):
            return 0
        put(w, 1088 + get(w, 1040) * 8, get(w, 1064))
        if get(w, 1040) == 0:
            put(w, 1040, 1)
            return image_start(s, o, w)
        put(w, 1112, 0)
        return authority_start(s, o, w)
    return 0

def image_write(o:mutbuf, w:mutbuf) -> u32:
    return call(o, w, 203, 1, get(w, 1064), 65537 + get(w, 1072), get(w, 1080) - get(w, 1072), 0, 0, 0, 12)

def sha(o:mutbuf, w:mutbuf, phase:u64, command:u64, size:u64) -> u32:
    put(w, 0, phase)
    store(w, 65536, command)
    put(o, 0, size)
    return 3

def authority_start(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    put(w, 262144, AUTHORITY_MAGIC)
    put(w, 262152, get(w, 1112))
    put(w, 262160, get(w, 16))
    put(w, 262168, get(w, 296))
    put(w, 262176, get(w, 288))
    put(w, 262184, choose(get(w, 1112) == 0, 0, get(w, 320)))
    put(w, 262192, get(w, 216))
    size = 136
    index = 0
    while index < 10:
        count = 0
        source = 393216 + index * 4096
        if index < 8:
            count = get(w, 16384 + index * 8)
        elif get(w, 1112) == 1 and get(w, 312) != 0:
            if index == 8:
                source = 450560
                count = cancel_text(w, 1, source) - source
            else:
                source = 122880
                count = get(w, 312)
        put(w, 262200 + index * 8, count)
        copy_state(w, source, 262144 + size, count)
        size = size + count
        index = index + 1
    put(w, 1128, size)
    put(w, 1136, get(w, 1088))
    return frame_start(o, w)

def frame_start(o:mutbuf, w:mutbuf) -> u32:
    put(w, 1072, 0)
    at = cancel_text(w, 2, 8192)
    store(w, at, 0)
    return call(o, w, 300, 319, 8192, 3, 0, 0, 0, 0, 3)

def frame_advance(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 300:
        if failed(result) or result < 3:
            return 0
        put(w, 1120, result)
        return call(o, w, 301, 91, result, 256, 0, 0, 0, 0, 0)
    if phase == 301:
        if failed(result):
            return 0
        return frame_write(o, w)
    if phase == 302:
        if result == NEG4:
            return frame_write(o, w)
        if failed(result) or result == 0 or result > get(w, 1128) - get(w, 1072):
            return 0
        put(w, 1072, get(w, 1072) + result)
        if get(w, 1072) < get(w, 1128):
            return frame_write(o, w)
        return call(o, w, 303, 72, get(w, 1120), 1033, 15, 0, 0, 0, 0)
    if phase == 303:
        if failed(result):
            return 0
        return call(o, w, 304, 8, get(w, 1120), 0, 0, 0, 0, 0, 0)
    if phase == 304:
        if result != 0:
            return 0
        return helper_start(o, w)
    return 0

def frame_write(o:mutbuf, w:mutbuf) -> u32:
    return call(o, w, 302, 1, get(w, 1120), 262144 + get(w, 1072), get(w, 1128) - get(w, 1072), 0, 0, 0, 12)

def observe_process(o:mutbuf, w:mutbuf) -> u32:
    put(w, 312, 0)
    put(w, 320, NONE)
    put(w, 328, 0)
    return process_start(o, w)

def process_reply(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if get(w, 1112) == 1:
        if get(w, 320) == NONE:
            return 0
        return authority_start(s, o, w)
    if get(w, 1112) == 3:
        if identity_same(w) == False:
            return cancel_reply(s, o, w, False)
        put(w, 589920, 0)
        put(w, 589928, 100000000)
        return call(o, w, 507, 35, 589920, 589936, 0, 0, 0, 0, 15)
    return 0

def identity_same(w:mutbuf) -> bool:
    if get(w, 312) == 0 or get(w, 312) != get(w, 16432):
        return False
    index = 0
    while index < get(w, 312):
        if byte(w, 122880 + index) != byte(w, 417792 + index):
            return False
        index = index + 1
    return True

def cancel_advance(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 500:
        if failed(result) or result < 3:
            return 0
        put(w, 1104, result)
        put(w, 1112, 1)
        return observe_process(o, w)
    if phase == 501:
        if failed(result):
            return 0
        size = uint(s, 48)
        index = 0
        while index < size:
            if byte(s, get(w, 56) + index) > 127:
                return 0
            index = index + 1
        if get(w, 16408) != 32:
            return 0
        put(w, 262144, WRITER_MAGIC)
        put(w, 262152, get(w, 1216))
        put(w, 262160, get(w, 1104))
        put(w, 262168, get(w, 589952) * 1000 + get(w, 589960) // 1000000)
        put(w, 262176, size)
        put(w, 262184, 0)
        copy_state(w, 405504, 262192, 32)
        copy_input(s, w, get(w, 56), 262224, size)
        put(w, 1128, 80 + size)
        put(w, 1136, get(w, 1096))
        put(w, 1112, 2)
        return frame_start(o, w)
    if phase == 502:
        if failed(result):
            return 0
        put(w, 1224, get(w, 589952) * 1000000000 + get(w, 589960) + get(w, 1032))
        return call(o, w, 503, 228, 1, 589952, 0, 0, 0, 0, 12)
    if phase == 503:
        if failed(result):
            return 0
        if get(w, 589952) * 1000000000 + get(w, 589960) >= get(w, 1224):
            return cancel_reply(s, o, w, False)
        put(w, 88, 7)
        return open_metadata(o, w)
    if phase == 507:
        if result == NEG4:
            copy_state(w, 589936, 589920, 16)
            return call(o, w, 507, 35, 589920, 589936, 0, 0, 0, 0, 15)
        if failed(result):
            return 0
        return call(o, w, 503, 228, 1, 589952, 0, 0, 0, 0, 12)
    return 0

def cancel_reply(s:readbuf, o:mutbuf, w:mutbuf, exited:bool) -> u32:
    at = text_reply_open(w, OUTPUT)
    at = quoted_input(s, w, at, get(w, 56), uint(s, 48))
    if exited:
        at = cancel_text(w, 3, at)
    else:
        if get(w, 1208) == 4:
            at = cancel_text(w, 4, at)
        else:
            at = cancel_text(w, 5, at)
        at = decimal(w, at, get(w, 288))
        at = cancel_text(w, 6, at)
    put(w, 176, at)
    put(w, 184, OUTPUT)
    return write_reply(o, w)
'''

HELPER = r'''
def helper_start(o:mutbuf, w:mutbuf) -> u32:
    put(w, 1168, 0)
    put(w, 1176, 0)
    put(w, 1192, 0)
    put(w, 1232, 0)
    put(w, 1240, 0)
    at = cancel_text(w, 7, 86040)
    store(w, at, 0)
    store(w, 86072, 0)
    put(w, 86080, 0)
    put(w, 81920, 86040)
    put(w, 81928, NONE)
    return relocate(o, w, 400, 81920, 2, 86016)

def helper_advance(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 400:
        if failed(result):
            return 0
        return call(o, w, 401, 293, 589824, 526336, 0, 0, 0, 0, 3)
    if phase == 401:
        if failed(result):
            return 0
        put(w, 1152, getn(w, 589824, 4))
        put(w, 1160, getn(w, 589828, 4))
        return call(o, w, 402, 293, 589832, 526336, 0, 0, 0, 0, 3)
    if phase == 402:
        if failed(result):
            return 0
        put(w, 1248, getn(w, 589832, 4))
        put(w, 1256, getn(w, 589836, 4))
        return call(o, w, 403, 228, 1, 589952, 0, 0, 0, 0, 12)
    if phase == 403:
        if failed(result):
            return 0
        put(w, 1184, get(w, 589952) * 1000000000 + get(w, 589960) + 5000000000)
        return call(o, w, 404, 57, 0, 0, 0, 0, 0, 0, 0)
    if phase == 404:
        if failed(result):
            return 0
        if result == 0:
            return call(o, w, 430, 33, get(w, 1120), 0, 0, 0, 0, 0, 0)
        put(w, 1144, result)
        return call(o, w, 405, 3, get(w, 1160), 0, 0, 0, 0, 0, 0)
    if phase == 405:
        if failed(result):
            return helper_abort(o, w)
        return call(o, w, 406, 3, get(w, 1256), 0, 0, 0, 0, 0, 0)
    if phase == 406:
        if failed(result):
            return helper_abort(o, w)
        return helper_read(o, w, 0)
    if phase == 407 or phase == 408:
        which = phase - 407
        if result == NEG4:
            return helper_read(o, w, which)
        if result == NEG11:
            result = 0
        elif failed(result):
            return helper_abort(o, w)
        else:
            slot = 1168 + which * 8
            maximum = choose(which == 0, 16, 24)
            if result > maximum - get(w, slot):
                return helper_abort(o, w)
            if result == 0:
                put(w, 1232 + which * 8, 1)
            else:
                put(w, slot, get(w, slot) + result)
        if which == 0:
            return helper_read(o, w, 1)
        if get(w, 1192) == 0:
            return call(o, w, 409, 61, get(w, 1144), 589848, 1, 0, 0, 0, 12)
        return helper_progress(s, o, w)
    if phase == 409:
        if result == NEG4:
            return call(o, w, 409, 61, get(w, 1144), 589848, 1, 0, 0, 0, 12)
        if failed(result):
            return helper_abort(o, w)
        if result != 0:
            if result != get(w, 1144):
                return helper_abort(o, w)
            put(w, 1192, 1)
        return helper_progress(s, o, w)
    if phase == 410:
        if failed(result):
            return helper_abort(o, w)
        if get(w, 589952) * 1000000000 + get(w, 589960) >= get(w, 1184):
            return helper_abort(o, w)
        first = choose(get(w, 1232) != 0, 4294967295, get(w, 1152))
        second = choose(get(w, 1240) != 0, 4294967295, get(w, 1248))
        put(w, 589872, first | 4294967296)
        put(w, 589880, second | 4294967296)
        return call(o, w, 411, 7, 589872, 2, 10, 0, 0, 0, 3)
    if phase == 411:
        if failed(result) and result != NEG4:
            return helper_abort(o, w)
        return helper_read(o, w, 0)
    if phase == 412:
        if failed(result):
            return 0
        return call(o, w, 413, 3, get(w, 1248), 0, 0, 0, 0, 0, 0)
    if phase == 413:
        if failed(result):
            return 0
        return call(o, w, 414, 3, get(w, 1120), 0, 0, 0, 0, 0, 0)
    if phase == 414:
        if failed(result):
            return 0
        return helper_result(s, o, w)
    if phase == 420:
        return call(o, w, 421, 61, get(w, 1144), 589848, 0, 0, 0, 0, 12)
    if phase == 421:
        if result == NEG4:
            return call(o, w, 421, 61, get(w, 1144), 589848, 0, 0, 0, 0, 12)
        return 0
    if phase == 430:
        if failed(result):
            return helper_child_fail(o, w)
        target = choose(get(w, 1112) == 2, get(w, 24), get(w, 1160))
        return call(o, w, 431, 33, target, 1, 0, 0, 0, 0, 0)
    if phase == 431:
        if failed(result):
            return helper_child_fail(o, w)
        return call(o, w, 432, 33, get(w, 1256), 2, 0, 0, 0, 0, 0)
    if phase == 432:
        if failed(result):
            return helper_child_fail(o, w)
        if get(w, 1112) == 2:
            return call(o, w, 433, 72, get(w, 1104), 2, 0, 0, 0, 0, 0)
        return helper_exec(o, w)
    if phase == 433:
        if failed(result):
            return helper_child_fail(o, w)
        return helper_exec(o, w)
    if phase == 434:
        return helper_child_fail(o, w)
    return 0

def helper_exec(o:mutbuf, w:mutbuf) -> u32:
    return call(o, w, 434, 322, get(w, 1136), 86072, 86016, 86080, 4096, 0, 252)

def helper_child_fail(o:mutbuf, w:mutbuf) -> u32:
    return call(o, w, 449, 60, 127, 0, 0, 0, 0, 0, 0)

def helper_abort(o:mutbuf, w:mutbuf) -> u32:
    if get(w, 1192) != 0:
        return 0
    return call(o, w, 420, 62, get(w, 1144), 9, 0, 0, 0, 0, 0)

def helper_read(o:mutbuf, w:mutbuf, which:u64) -> u32:
    slot = 1168 + which * 8
    maximum = choose(which == 0, 17, 25)
    fd = choose(which == 0, get(w, 1152), get(w, 1248))
    return call(o, w, 407 + which, 0, fd, 590000 + which * 64 + get(w, slot), maximum - get(w, slot), 0, 0, 0, 12)

def helper_progress(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if get(w, 1192) != 0 and get(w, 1232) != 0 and get(w, 1240) != 0:
        if getn(w, 589848, 4) != 0:
            return 0
        return call(o, w, 412, 3, get(w, 1152), 0, 0, 0, 0, 0, 0)
    return call(o, w, 410, 228, 1, 589952, 0, 0, 0, 0, 12)

def helper_result(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if get(w, 1112) == 2:
        if get(w, 1168) != 0 or get(w, 1176) != 24 or get(w, 590064) != WRITER_RESULT or get(w, 590072) != 7 or get(w, 590080) != 0:
            return 0
        return call(o, w, 502, 228, 1, 589952, 0, 0, 0, 0, 12)
    if get(w, 1168) != 16 or get(w, 1176) != 0 or get(w, 590000) != AUTHORITY_RESULT:
        return 0
    decision = get(w, 590008)
    if get(w, 1112) == 0:
        if decision != 1:
            return 0
        return call(o, w, 500, 434, get(w, 288), 0, 0, 0, 0, 0, 0)
    if decision != 3 and decision != 4:
        return 0
    put(w, 1208, decision)
    return call(o, w, 501, 228, 0, 589952, 0, 0, 0, 0, 12)
'''

TEXT = (
    'hia-cancel-image', 'proc_start_ticks', 'hia-cancel-frame',
    ',"result":"already_exited"}\n',
    ',"result":"stop_requested","atomic_identity":true,"supervisor_pid":',
    ',"result":"term_sent","atomic_identity":true,"supervisor_pid":',
    ',"termination_confirmed":false,"reconcile_via":"process_status"}\n',
    'hia-cancel-native',
)


def replace_once(source, before, after):
    if source.count(before) != 1:
        raise ValueError('cancellation authoring dependency changed: ' + before[:100])
    return source.replace(before, after)


def policy_source():
    original = {node.name: node for node in ast.parse(observation.POLICY).body}
    admitted = ast.unparse(original['admit'])
    admitted = admitted.replace('length(s) > 65536', 'length(s) > INPUT_BYTES')
    admitted = replace_once(admitted, 'uint(s, 8) != 0 or uint(s, 72) != 0',
                            'uint(s, 32) != 0 or uint(s, 72) != 0')
    admitted = replace_once(admitted,
        'if length(s) != 80 + path_size + job_size + unit_size + 64 or byte(s, 80) != 47:',
        'query_end = 80 + path_size + job_size + unit_size + 64\n'
        '    authority = uint(s, 16)\n    writer = uint(s, 24)\n'
        '    if authority < 64 or authority > 1048576 or writer < 64 or writer > 1048576:\n        return 0\n'
        '    if length(s) != query_end + 64 + authority + writer or byte(s, 80) != 47:')
    admitted = admitted.replace('while at < length(s):', 'while at < query_end:')
    start = admitted.index('    limit = uint(s, 32)')
    admitted = admitted[:start] + '''    put(w, 1000, query_end + 64)
    put(w, 1008, query_end + 64 + authority)
    put(w, 1016, query_end)
    put(w, 1024, query_end + 32)
    put(w, 1032, choose(uint(s, 8) > 30000000000, 30000000000, uint(s, 8)))
    return 1
'''
    metadata = ast.unparse(original['metadata'])
    metadata = replace_once(metadata, 'result == NEG2 and get(w, 88) != 0',
                            'result == NEG2 and get(w, 88) != 0 and get(w, 88) != 3')
    metadata = replace_once(metadata, '        put(w, 96, result)',
                            '        put(w, 192, 1)\n        put(w, 96, result)')
    library = {node.name: node for node in ast.parse(observation.policy_source()).body}
    own = POLICY + HELPER + '\n' + admitted + '\n' + metadata
    own += '\n' + ast.unparse(original['read_metadata']) + '\n'
    own += '\ndef cancel_text(w:mutbuf, kind:u64, at:u64) -> u64:\n'
    for kind, value in enumerate(TEXT):
        raw = value.encode()
        own += f'    if kind == {kind}:\n'
        for index in range(0, len(raw) // 8 * 8, 8):
            own += f'        put(w, at + {index}, {int.from_bytes(raw[index:index + 8], "little")})\n'
        for index in range(len(raw) // 8 * 8, len(raw)):
            own += f'        store(w, at + {index}, {raw[index]})\n'
        own += f'        return at + {len(raw)}\n'
    own += '    return at\n'
    for index, (name, _) in enumerate(observation.TEXT.items()):
        own = own.replace(f'text_{name}(w, ', f'text_bank_{index // 16}(w, {index % 16}, ')
    definitions = {node.name: node for node in ast.parse(own).body}
    library.update(definitions)
    needed, pending = set(), ['advance']
    while pending:
        name = pending.pop()
        if name in needed:
            continue
        needed.add(name)
        for node in ast.walk(library[name]):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in library:
                pending.append(node.func.id)
    order = ['advance'] + [name for name in library if name != 'advance' and name in needed]
    source = '\n\n'.join(ast.unparse(library[name]) for name in order) + '\n'
    values = dict(STATE_BYTES=observation.STATE_BYTES, REQUEST_MAGIC=REQUEST_MAGIC, INPUT_BYTES=INPUT_BYTES,
        META=observation.META, OUTPUT=observation.OUTPUT, ARENA=observation.ARENA,
        SCRATCH=observation.SCRATCH, RAW_JSON=observation.RAW_JSON, NONE=(1 << 64) - 1,
        NEG100=(1 << 64) - 100, NEG4=(1 << 64) - 4, NEG2=(1 << 64) - 2, NEG11=(1 << 64) - 11,
        AUTHORITY_MAGIC=int.from_bytes(b'HIAJCX01', 'little'), AUTHORITY_RESULT=int.from_bytes(b'HIAJCY01', 'little'),
        WRITER_MAGIC=int.from_bytes(b'HIAJRC01', 'little'), WRITER_RESULT=int.from_bytes(b'HIAJRW01', 'little'))
    for name in sorted(values, key=len, reverse=True):
        source = source.replace(name, str(values[name]))
    return source


def template():
    adapter = ROOT / 'tools/hia_job_cancel_syscalls.S'
    with tempfile.TemporaryDirectory(prefix='hia-job-cancel-author-') as directory:
        obj, raw = Path(directory) / 'adapter.o', Path(directory) / 'adapter.bin'
        subprocess.run(['as', '--64', str(adapter), '-o', str(obj)], check=True, capture_output=True)
        subprocess.run(['objcopy', '-O', 'binary', '-j', '.text', str(obj), str(raw)], check=True, capture_output=True)
        symbols = {name: int(address, 16) for address, _, name in
                   (line.split() for line in subprocess.check_output(['nm', '-n', str(obj)], text=True).splitlines())}
        if symbols['_start'] != 0 or 'R_X86_64' in subprocess.check_output(['objdump', '-r', str(obj)], text=True):
            raise ValueError('cancellation adapter has unresolved relocations')
        code = raw.read_bytes()
    header = (b'\x7fELF\x02\x01\x01' + bytes(9)
              + struct.pack('<HHIQQQIHHHHHH', 2, 62, 1, 0x4000b0, 64, 0, 0, 64, 56, 2, 0, 0, 0)
              + struct.pack('<IIQQQQQQ', 1, 5, 0, 0x400000, 0x400000, 0, 0, 4096)
              + struct.pack('<IIQQQQQQ', 0x6474e551, 6, 0, 0, 0, 0, 0, 16))
    return header + code, {name: 176 + symbols[name] for name in
                           ('job_cancel_policy_hole', 'job_cancel_json_hole', 'job_cancel_sha_hole')}


def packer_source():
    prefix, holes = template()
    source = f'''def pack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 35 or uint(s, 0, 8) != {PACKER_MAGIC}:
        return 4294967295
    policy = uint(s, 8, 8)
    decoder = uint(s, 16, 8)
    sha = uint(s, 24, 8)
    if policy == 0 or decoder == 0 or sha == 0 or policy > 1048576 or decoder > 1048576 or sha > 1048576:
        return 4294967295
    if length(s) != 32 + policy + decoder + sha:
        return 4294967295
    size = {len(prefix)} + policy + decoder + sha
    if size > 1048576 or length(o) < size:
        return 4294967294
'''
    for at in range(0, len(prefix), 8):
        raw = prefix[at:at + 8]
        source += f'    write(o, {at}, {int.from_bytes(raw, "little")}, {len(raw)})\n'
    source += '    write(o, 96, size, 8)\n    write(o, 104, size, 8)\n'
    for name, at in holes.items():
        target = str(len(prefix))
        if name.endswith('json_hole') or name.endswith('sha_hole'):
            target += ' + policy'
        if name.endswith('sha_hole'):
            target += ' + decoder'
        source += f'    write(o, {at}, {target} - {at + 4}, 4)\n'
    source += f'    copy_bytes(s, o, 32, {len(prefix)}, policy + decoder + sha)\n    return size\n'
    return source + LINK_SOURCE[LINK_SOURCE.index('\ndef uint('):]


def main():
    for name, source in (('job_cancel', policy_source()), ('job_cancel_packer', packer_source())):
        target = ROOT / 'examples/hia_bootstrap' / (name + '.hepta')
        target.write_text(render_assembly(document(source, name)))
        print(target.name, target.stat().st_size)


if __name__ == '__main__':
    main()
