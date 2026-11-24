"""HIA descriptor-owned original engine directory creation, identity and cleanup."""
from __future__ import annotations
import argparse
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_system_jobctl_request import document
from tools.generate_hia_system_jobctl_scratch_common import compose
ROOT=Path(__file__).resolve().parents[1]
POLICY=r'''
def advance(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(o) != 128 or length(w) != STATE_BYTES:
        return 0
    phase = get(w, 0)
    result = get(w, 8)
    if phase >= 3120 and phase < 3130:
        return directory_walk(o, w, phase, result)
    if phase >= 3150 and phase < 3170:
        return directory_verify(o, w, phase, result)
    if phase >= 3200 and phase < 3260:
        return directory_clear(o, w, phase, result)
    if phase >= 3260 and phase < 3280:
        return directory_mount(o, w, phase, result)
    if phase >= 3390:
        return directory_cleanup(o, w, phase)
    return directory_start(o, w, phase, result)

def directory_start(o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 3100:
        put(w, SC_DIR_ERROR, 0)
        put(w, SC_FAILED, 0)
        put(w, SC_WALK_FD, NONE)
        put(w, SC_WALK_RESULT, NONE)
        put(w, SC_TEMP_FD, NONE)
        put(w, SC_MOUNT_FD, NONE)
        put(w, SC_CLEAR_ACTIVE, 0)
        operation = get(w, SC_DIR_OP)
        if operation <= 1:
            put(w, SC_DIR_FD, NONE)
            put(w, SC_DIR_PARENT, NONE)
            put(w, SC_DIR_BEFORE, choose(operation == 0, SC_BEFORE, SC_BEFORE_NEW))
            return directory_walk_begin(o, w, 3101, SC_STATE, get(w, SC_STATE_CANON_SIZE))
        if operation == 2:
            return directory_verify_begin(o, w, 3108)
        if operation == 3:
            return directory_verify_begin(o, w, 3200)
        return 0
    if phase == 3101:
        put(w, SC_DIR_PARENT, get(w, SC_WALK_RESULT))
        sc_nul(w, sc_text(w, SC_NAME, E_SCRATCH))
        if get(w, SC_DIR_OP) == 0:
            return call(o, w, 3102, 258, get(w, SC_DIR_PARENT), SC_NAME, 448, 0, 0, 0, 12)
        return directory_open_leaf(o, w)
    if phase == 3102:
        if result != 0:
            sc_result_error(w, E_DIRECTORY_CREATE, result)
            return directory_failure(o, w)
        return directory_open_leaf(o, w)
    if phase == 3103:
        if failed(result):
            sc_result_error(w, E_DIRECTORY_UNAVAILABLE, result)
            return directory_failure(o, w)
        put(w, SC_DIR_FD, result)
        return call(o, w, 3104, 5, result, get(w, SC_DIR_BEFORE), 0, 0, 0, 0, 12)
    if phase == 3104:
        if result != 0:
            sc_result_error(w, E_EMPTY, result)
            return directory_failure(o, w)
        before = get(w, SC_DIR_BEFORE)
        if get(w, SC_DIR_OP) == 0:
            put(w, SC_DEV, get(w, before))
            put(w, SC_INO, get(w, before + 8))
        elif get(w, before) != get(w, SC_DEV) or get(w, before + 8) != get(w, SC_INO):
            sc_error(w, E_DIRECTORY_ORIGINAL, 0)
            return directory_failure(o, w)
        return directory_verify_begin(o, w, 3105)
    if phase == 3105:
        if get(w, SC_DIR_OP) == 1:
            return directory_done(w)
        return call(o, w, 3106, 74, get(w, SC_DIR_FD), 0, 0, 0, 0, 0, 0)
    if phase == 3106:
        if result == NEG4:
            return call(o, w, 3106, 74, get(w, SC_DIR_FD), 0, 0, 0, 0, 0, 0)
        if result != 0:
            sc_result_error(w, E_EMPTY, result)
            return directory_failure(o, w)
        return call(o, w, 3107, 74, get(w, SC_DIR_PARENT), 0, 0, 0, 0, 0, 0)
    if phase == 3107:
        if result == NEG4:
            return call(o, w, 3107, 74, get(w, SC_DIR_PARENT), 0, 0, 0, 0, 0, 0)
        if result != 0:
            sc_result_error(w, E_EMPTY, result)
            return directory_failure(o, w)
        return directory_done(w)
    if phase == 3108:
        return directory_done(w)
    return 0

def directory_open_leaf(o:mutbuf, w:mutbuf) -> u32:
    sc_nul(w, sc_text(w, SC_NAME, E_SCRATCH))
    return call(o, w, 3103, 257, get(w, SC_DIR_PARENT), SC_NAME, DIR_FLAGS, 0, 0, 0, 12)

def directory_done(w:mutbuf) -> u32:
    put(w, 0, get(w, SC_DIR_NEXT))
    return 8

def directory_walk_begin(o:mutbuf, w:mutbuf, next:u64, at:u64, size:u64) -> u32:
    if size == 0 or byte(w, at) != 47:
        sc_error(w, E_DIRECTORY_ABSOLUTE, 0)
        return directory_failure(o, w)
    put(w, SC_WALK_NEXT, next)
    put(w, SC_WALK_AT, at)
    put(w, SC_WALK_SIZE, size)
    put(w, SC_WALK_USED, 0)
    put(w, SC_WALK_FD, NONE)
    sc_nul(w, sc_text(w, SC_NAME, E_ROOT))
    return call(o, w, 3120, 257, NEG100, SC_NAME, 524288, 0, 0, 0, 12)

def directory_walk(o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 3120:
        if result == NEG4:
            return call(o, w, 3120, 257, NEG100, SC_NAME, 524288, 0, 0, 0, 12)
        if failed(result):
            sc_result_error(w, E_EMPTY, result)
            return directory_failure(o, w)
        put(w, SC_WALK_FD, result)
        return directory_walk_next(o, w)
    if phase == 3121:
        if failed(result):
            sc_result_error(w, E_DIRECTORY_UNAVAILABLE, result)
            return directory_failure(o, w)
        old = get(w, SC_WALK_FD)
        put(w, SC_WALK_FD, result)
        return call(o, w, 3122, 3, old, 0, 0, 0, 0, 0, 0)
    if phase == 3122:
        return directory_walk_next(o, w)
    return 0

def directory_walk_next(o:mutbuf, w:mutbuf) -> u32:
    used = get(w, SC_WALK_USED)
    size = get(w, SC_WALK_SIZE)
    at = get(w, SC_WALK_AT)
    while used < size:
        while used < size and byte(w, at + used) == 47:
            used = used + 1
        start = used
        while used < size and byte(w, at + used) != 47:
            used = used + 1
        length = used - start
        put(w, SC_WALK_USED, used)
        if length != 0 and (length != 1 or byte(w, at + start) != 46):
            if length == 2 and getn(w, at + start, 2) == 11822:
                sc_error(w, E_DIRECTORY_NORMALIZED, 0)
                return directory_failure(o, w)
            if length > 1048575:
                sc_error(w, E_DIRECTORY_UNAVAILABLE, 36)
                return directory_failure(o, w)
            copy(w, SC_NAME, at + start, length)
            store(w, SC_NAME + length, 0)
            return call(o, w, 3121, 257, get(w, SC_WALK_FD), SC_NAME, DIR_FLAGS, 0, 0, 0, 12)
    put(w, SC_WALK_RESULT, get(w, SC_WALK_FD))
    put(w, SC_WALK_FD, NONE)
    return sc_go(w, get(w, SC_WALK_NEXT))

def directory_same(w:mutbuf, left:u64, right:u64) -> u64:
    return choose(getn(w, left + 24, 4) & 61440 == 16384 and getn(w, right + 24, 4) & 61440 == 16384 and get(w, left) == get(w, right) and get(w, left + 8) == get(w, right + 8) and getn(w, left + 28, 4) == getn(w, right + 28, 4), 1, 0)

def directory_verify_begin(o:mutbuf, w:mutbuf, next:u64) -> u32:
    put(w, SC_VERIFY_NEXT, next)
    return directory_walk_begin(o, w, 3150, SC_STATE, get(w, SC_STATE_CANON_SIZE))

def directory_verify(o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 3150:
        put(w, SC_TEMP_FD, get(w, SC_WALK_RESULT))
        return call(o, w, 3151, 5, get(w, SC_TEMP_FD), SC_STAT, 0, 0, 0, 0, 12)
    if phase == 3151 or phase == 3155 or phase == 3158:
        if result != 0:
            sc_result_error(w, E_EMPTY, result)
            return directory_failure(o, w)
        return call(o, w, phase + 1, 3, get(w, SC_TEMP_FD), 0, 0, 0, 0, 0, 0)
    if phase == 3152:
        put(w, SC_TEMP_FD, NONE)
        return call(o, w, 3153, 5, get(w, SC_DIR_PARENT), SC_STAT + 144, 0, 0, 0, 0, 12)
    if phase == 3153:
        if result != 0:
            sc_result_error(w, E_EMPTY, result)
            return directory_failure(o, w)
        sc_nul(w, sc_text(w, SC_NAME, E_SCRATCH))
        return call(o, w, 3154, 257, get(w, SC_DIR_PARENT), SC_NAME, DIR_FLAGS, 0, 0, 0, 12)
    if phase == 3154:
        if failed(result):
            sc_result_error(w, E_DIRECTORY_UNAVAILABLE, result)
            return directory_failure(o, w)
        put(w, SC_TEMP_FD, result)
        return call(o, w, 3155, 5, result, SC_STAT + 288, 0, 0, 0, 0, 12)
    if phase == 3156:
        put(w, SC_TEMP_FD, NONE)
        return directory_walk_begin(o, w, 3157, SC_PATH, get(w, SC_PATH_SIZE))
    if phase == 3157:
        put(w, SC_TEMP_FD, get(w, SC_WALK_RESULT))
        return call(o, w, 3158, 5, get(w, SC_TEMP_FD), SC_STAT + 432, 0, 0, 0, 0, 12)
    if phase == 3159:
        put(w, SC_TEMP_FD, NONE)
        return call(o, w, 3160, 5, get(w, SC_DIR_FD), SC_STAT + 576, 0, 0, 0, 0, 12)
    if phase == 3160:
        if result != 0:
            sc_result_error(w, E_EMPTY, result)
            return directory_failure(o, w)
        return call(o, w, 3161, 107, 0, 0, 0, 0, 0, 0, 0)
    if phase == 3161:
        held = SC_STAT + 576
        before = get(w, SC_DIR_BEFORE)
        if directory_same(w, SC_STAT + 144, SC_STAT) == 0 or directory_same(w, SC_STAT + 288, held) == 0 or directory_same(w, before, held) == 0 or directory_same(w, held, SC_STAT + 432) == 0 or getn(w, held + 28, 4) != result or getn(w, held + 24, 4) & 511 != 448:
            sc_error(w, E_DIRECTORY_IDENTITY, 0)
            return directory_failure(o, w)
        return sc_go(w, get(w, SC_VERIFY_NEXT))
    return 0

def clear_frame(w:mutbuf) -> u64:
    return SC_STACK + get(w, SC_DIR_DEPTH) * 33280

def clear_iterator(o:mutbuf, w:mutbuf) -> u32:
    frame = clear_frame(w)
    at = decimal(w, sc_text(w, SC_PATH_TEMP, E_PROCFD), get(w, frame))
    store(w, at, 0)
    return call(o, w, 3202, 257, NEG100, SC_PATH_TEMP, 65536 + 524288 + 2048, 0, 0, 0, 12)

def clear_next(o:mutbuf, w:mutbuf) -> u32:
    frame = clear_frame(w)
    used = get(w, frame + 24)
    size = get(w, frame + 16)
    while used < size:
        if size - used < 20:
            sc_error(w, E_EMPTY, 5)
            return directory_failure(o, w)
        row = frame + 512 + used
        length = getn(w, row + 16, 2)
        if length < 20 or length > size - used:
            sc_error(w, E_EMPTY, 5)
            return directory_failure(o, w)
        count = 0
        while count < length - 19 and byte(w, row + 19 + count) != 0:
            count = count + 1
        if count == length - 19 or count > 255:
            sc_error(w, E_EMPTY, 5)
            return directory_failure(o, w)
        used = used + length
        put(w, frame + 24, used)
        dot = count == 1 and byte(w, row + 19) == 46
        dotdot = count == 2 and getn(w, row + 19, 2) == 11822
        if dot == False and dotdot == False:
            copy(w, frame + 64, row + 19, count)
            store(w, frame + 64 + count, 0)
            put(w, frame + 32, count)
            put(w, frame + 48, byte(w, row + 18))
            put(w, SC_DIR_COUNT, get(w, SC_DIR_COUNT) + 1)
            put(w, SC_DIR_ENTRY_ERROR, 0)
            return call(o, w, 3212, 228, 1, SC_STAT, 0, 0, 0, 0, 12)
    put(w, frame + 16, 0)
    put(w, frame + 24, 0)
    return call(o, w, 3210, 217, get(w, frame + 8), frame + 512, 32768, 0, 0, 0, 12)

def directory_clear(o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    frame = clear_frame(w)
    if phase == 3200:
        return call(o, w, 3201, 228, 1, SC_STAT, 0, 0, 0, 0, 12)
    if phase == 3201:
        if result != 0:
            sc_result_error(w, E_EMPTY, result)
            return directory_failure(o, w)
        put(w, SC_DIR_DEADLINE, sc_now(w) + 3000000000)
        put(w, SC_DIR_COUNT, 0)
        put(w, SC_DIR_DEPTH, 0)
        put(w, SC_CLEAR_ACTIVE, 1)
        index = 0
        while index < 33:
            put(w, SC_STACK + index * 33280 + 8, NONE)
            put(w, SC_STACK + index * 33280 + 40, NONE)
            index = index + 1
        put(w, SC_STACK, get(w, SC_DIR_FD))
        return clear_iterator(o, w)
    if phase == 3202:
        if failed(result):
            sc_result_error(w, E_EMPTY, result)
            return directory_failure(o, w)
        put(w, frame + 8, result)
        put(w, frame + 16, 0)
        put(w, frame + 24, 0)
        return clear_next(o, w)
    if phase == 3210:
        if result == 0 or result == NEG2:
            return call(o, w, 3221, 3, get(w, frame + 8), 0, 0, 0, 0, 0, 0)
        if failed(result):
            put(w, SC_DIR_ENTRY_ERROR, 0 - result)
            put(w, SC_DIR_COUNT, get(w, SC_DIR_COUNT) + 1)
            return call(o, w, 3212, 228, 1, SC_STAT, 0, 0, 0, 0, 12)
        if result > 32768:
            sc_error(w, E_EMPTY, 5)
            return directory_failure(o, w)
        put(w, frame + 16, result)
        put(w, frame + 24, 0)
        return clear_next(o, w)
    if phase == 3212:
        if result != 0:
            sc_result_error(w, E_EMPTY, result)
            return directory_failure(o, w)
        if get(w, SC_DIR_COUNT) > 100000 or sc_now(w) >= get(w, SC_DIR_DEADLINE):
            sc_error(w, E_DIRECTORY_BUDGET, 0)
            return directory_failure(o, w)
        if get(w, SC_DIR_ENTRY_ERROR) != 0:
            sc_error(w, E_EMPTY, get(w, SC_DIR_ENTRY_ERROR))
            return directory_failure(o, w)
        kind = get(w, frame + 48)
        if kind == 4:
            return clear_open_child(o, w)
        if kind == 0:
            return call(o, w, 3214, 262, get(w, frame), frame + 64, SC_STAT, 256, 0, 0, 60)
        return clear_unlink(o, w, 0)
    if phase == 3214:
        if result != 0:
            sc_result_error(w, E_EMPTY, result)
            return directory_failure(o, w)
        if getn(w, SC_STAT + 24, 4) & 61440 == 16384:
            return clear_open_child(o, w)
        return clear_unlink(o, w, 0)
    if phase == 3215:
        if failed(result):
            sc_result_error(w, E_DIRECTORY_UNAVAILABLE, result)
            return directory_failure(o, w)
        put(w, frame + 40, result)
        return mount_begin(o, w, 3216, get(w, frame))
    if phase == 3216:
        put(w, SC_MOUNT_FIRST, get(w, SC_MOUNT_RESULT))
        return mount_begin(o, w, 3217, get(w, frame + 40))
    if phase == 3217:
        if get(w, SC_MOUNT_FIRST) != get(w, SC_MOUNT_RESULT):
            sc_error(w, E_DIRECTORY_MOUNT, 0)
            return directory_failure(o, w)
        depth = get(w, SC_DIR_DEPTH) + 1
        if depth > 32:
            sc_error(w, E_DIRECTORY_DEPTH, 0)
            return directory_failure(o, w)
        put(w, SC_STACK + depth * 33280, get(w, frame + 40))
        put(w, SC_DIR_DEPTH, depth)
        return clear_iterator(o, w)
    if phase == 3220:
        if result != 0:
            sc_result_error(w, E_DIRECTORY_INCOMPLETE, result)
            return directory_failure(o, w)
        return clear_next(o, w)
    if phase == 3221:
        put(w, frame + 8, NONE)
        if get(w, SC_DIR_DEPTH) == 0:
            put(w, SC_CLEAR_ACTIVE, 0)
            return directory_verify_begin(o, w, 3240)
        put(w, SC_DIR_DEPTH, get(w, SC_DIR_DEPTH) - 1)
        frame = clear_frame(w)
        return call(o, w, 3230, 5, get(w, frame + 40), SC_STAT, 0, 0, 0, 0, 12)
    if phase >= 3230 and phase < 3240:
        return clear_child_end(o, w, phase, result)
    if phase == 3240:
        sc_nul(w, sc_text(w, SC_NAME, E_SCRATCH))
        return call(o, w, 3241, 263, get(w, SC_DIR_PARENT), SC_NAME, 512, 0, 0, 0, 12)
    if phase == 3241:
        if result != 0:
            sc_result_error(w, E_DIRECTORY_REMOVE, result)
            return directory_failure(o, w)
        return call(o, w, 3242, 74, get(w, SC_DIR_PARENT), 0, 0, 0, 0, 0, 0)
    if phase == 3242:
        if result == NEG4:
            return call(o, w, 3242, 74, get(w, SC_DIR_PARENT), 0, 0, 0, 0, 0, 0)
        if result != 0:
            sc_result_error(w, E_DIRECTORY_DURABLE, result)
            return directory_failure(o, w)
        return directory_done(w)
    return 0

def clear_open_child(o:mutbuf, w:mutbuf) -> u32:
    frame = clear_frame(w)
    return call(o, w, 3215, 257, get(w, frame), frame + 64, DIR_FLAGS, 0, 0, 0, 12)

def clear_unlink(o:mutbuf, w:mutbuf, flags:u64) -> u32:
    frame = clear_frame(w)
    return call(o, w, 3220, 263, get(w, frame), frame + 64, flags, 0, 0, 0, 12)

def clear_child_end(o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    frame = clear_frame(w)
    if phase == 3230:
        if result != 0:
            sc_result_error(w, E_EMPTY, result)
            return directory_failure(o, w)
        return call(o, w, 3231, 257, get(w, frame), frame + 64, DIR_FLAGS, 0, 0, 0, 12)
    if phase == 3231:
        if failed(result):
            sc_result_error(w, E_DIRECTORY_UNAVAILABLE, result)
            return directory_failure(o, w)
        put(w, SC_TEMP_FD, result)
        return call(o, w, 3232, 5, result, SC_STAT + 144, 0, 0, 0, 0, 12)
    if phase == 3232:
        if result != 0:
            sc_result_error(w, E_EMPTY, result)
            return directory_failure(o, w)
        if directory_same(w, SC_STAT, SC_STAT + 144) == 0:
            sc_error(w, E_DIRECTORY_DESCENDANT, 0)
            return directory_failure(o, w)
        return call(o, w, 3233, 3, get(w, SC_TEMP_FD), 0, 0, 0, 0, 0, 0)
    if phase == 3233:
        put(w, SC_TEMP_FD, NONE)
        return call(o, w, 3234, 3, get(w, frame + 40), 0, 0, 0, 0, 0, 0)
    if phase == 3234:
        put(w, frame + 40, NONE)
        return clear_unlink(o, w, 512)
    return 0

def mount_begin(o:mutbuf, w:mutbuf, next:u64, directory:u64) -> u32:
    put(w, SC_MOUNT_NEXT, next)
    put(w, SC_USED, 0)
    at = decimal(w, sc_text(w, SC_PATH_TEMP, E_FDINFO), directory)
    store(w, at, 0)
    return call(o, w, 3260, 257, NEG100, SC_PATH_TEMP, 524288, 0, 0, 0, 12)

def mount_read(o:mutbuf, w:mutbuf) -> u32:
    used = get(w, SC_USED)
    if used == 16385:
        return call(o, w, 3262, 3, get(w, SC_MOUNT_FD), 0, 0, 0, 0, 0, 0)
    return call(o, w, 3261, 0, get(w, SC_MOUNT_FD), SC_IO + used, 16385 - used, 0, 0, 0, 12)

def directory_mount(o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 3260:
        if result == NEG4:
            return call(o, w, 3260, 257, NEG100, SC_PATH_TEMP, 524288, 0, 0, 0, 12)
        if failed(result):
            sc_result_error(w, E_EMPTY, result)
            return directory_failure(o, w)
        put(w, SC_MOUNT_FD, result)
        return mount_read(o, w)
    if phase == 3261:
        if result == NEG4:
            return mount_read(o, w)
        if failed(result) or result > 16385 - get(w, SC_USED):
            sc_result_error(w, E_EMPTY, result)
            return directory_failure(o, w)
        if result == 0:
            return call(o, w, 3262, 3, get(w, SC_MOUNT_FD), 0, 0, 0, 0, 0, 0)
        put(w, SC_USED, get(w, SC_USED) + result)
        return mount_read(o, w)
    if phase == 3262:
        put(w, SC_MOUNT_FD, NONE)
        if mount_parse(w, SC_IO, get(w, SC_USED)) == 0:
            return directory_failure(o, w)
        return sc_go(w, get(w, SC_MOUNT_NEXT))
    return 0

def mount_parse(w:mutbuf, at:u64, size:u64) -> u64:
    if size > 16384:
        return sc_error(w, E_MOUNT_ID_BOUND, 0)
    if sc_utf8(w, at, size) == 0:
        return sc_utf_error(w)
    end = at + size
    while at < end:
        line_end = at
        while line_end < end and byte(w, line_end) != 10:
            line_end = line_end + 1
        if line_end - at >= 7 and getn(w, at, 7) == 16435952385027693:
            start = at + 7
            last = start
            cursor = start
            while cursor < line_end:
                point = sc_point(w, cursor, line_end - cursor)
                width = point >> 32
                if sc_space(point & 4294967295) == 0:
                    last = cursor + width
                elif last == start:
                    start = cursor + width
                    last = start
                cursor = cursor + width
            value = sc_unsigned(w, start, last - start, NONE)
            if get(w, G_INT_ERROR) != 0:
                stop = sc_text(w, SC_ERROR_TEXT, E_MOUNT_ID_INVALID)
                stop = sc_text(w, stop, E_COLON)
                stop = sc_text(w, stop, get(w, G_INT_ERROR))
                put(w, SC_ERROR, SC_ERROR_TEXT)
                put(w, SC_ERROR_SIZE, stop - SC_ERROR_TEXT)
                put(w, SC_FAILED, 1)
                return 0
            put(w, SC_MOUNT_RESULT, value)
            return 1
        at = line_end + 1
    return sc_error(w, E_MOUNT_ID_ABSENT, 0)

def directory_failure(o:mutbuf, w:mutbuf) -> u32:
    put(w, SC_DIR_ERROR, 1)
    put(w, SC_CLEAN_INDEX, 0)
    return directory_cleanup(o, w, 3390)

def directory_cleanup(o:mutbuf, w:mutbuf, phase:u64) -> u32:
    if phase == 3391:
        put(w, SC_WALK_FD, NONE)
    elif phase == 3392:
        put(w, SC_TEMP_FD, NONE)
    elif phase == 3393:
        put(w, SC_MOUNT_FD, NONE)
    elif phase == 3394:
        index = get(w, SC_CLEAN_INDEX)
        put(w, SC_STACK + (index // 2) * 33280 + choose(index % 2 == 0, 8, 40), NONE)
        put(w, SC_CLEAN_INDEX, index + 1)
    if get(w, SC_WALK_FD) != NONE:
        return call(o, w, 3391, 3, get(w, SC_WALK_FD), 0, 0, 0, 0, 0, 0)
    if get(w, SC_TEMP_FD) != NONE:
        return call(o, w, 3392, 3, get(w, SC_TEMP_FD), 0, 0, 0, 0, 0, 0)
    if get(w, SC_MOUNT_FD) != NONE:
        return call(o, w, 3393, 3, get(w, SC_MOUNT_FD), 0, 0, 0, 0, 0, 0)
    index = get(w, SC_CLEAN_INDEX)
    if get(w, SC_CLEAR_ACTIVE) == 1:
        while index < 66:
            fd = get(w, SC_STACK + (index // 2) * 33280 + choose(index % 2 == 0, 8, 40))
            if fd != NONE:
                put(w, SC_CLEAN_INDEX, index)
                return call(o, w, 3394, 3, fd, 0, 0, 0, 0, 0, 0)
            index = index + 1
        put(w, SC_CLEAR_ACTIVE, 0)
    return directory_done(w)
'''

def source_program():return compose(POLICY)
def main():
 p=argparse.ArgumentParser();p.add_argument('--check',action='store_true');a=p.parse_args()
 doc=document(source_program(),'system_jobctl_scratch_directory');text=render_assembly(doc);path=ROOT/'examples/hia_bootstrap/system_jobctl_scratch_directory.hepta'
 if a.check:assert path.read_text()==text
 else:path.write_text(text)
 print(path.name,len(text),'functions',len(doc['functions']),'blocks',sum(len(f['blocks'])for f in doc['functions']),'ops',sum(len(b['ops'])for f in doc['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
