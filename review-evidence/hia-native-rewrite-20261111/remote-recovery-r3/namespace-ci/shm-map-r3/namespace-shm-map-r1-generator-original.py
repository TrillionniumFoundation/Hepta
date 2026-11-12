"""NEW selected Unix SHM mapping/region/purge owner, source r1.

HIA owns size checks, page-by-page extension, realloc/mmap ordering, partial
mapping state, readonly conversion, the result view and last-node purge.
An issued DMS-ready node and private FS/memory completion channels are mandatory.
These private headers are continuity checks, not arbitrary external authority.
The fixed DMS+map dispatcher and memory lease provider remain separate work.
"""
from __future__ import annotations
import ast
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_agent_namespace_objects import ObjectBuilder
from tools.generate_hia_agent_namespace_store import VALUES
from tools.generate_hia_selfhost import compact_authoring_cfg,total_scalar_functions
ROOT=Path(__file__).resolve().parents[1]
MAGIC=int.from_bytes(b"HIASMP01","little")
BAD=int.from_bytes(b"HIASMPB1","little")
CHANNEL=int.from_bytes(b"HIASMX01","little")
MAP=r'''
def sm_entry(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < 1536:
        if length(w) >= 8:
            put(w, 0, MAP_BAD)
        return 4294967293
    if get(w, 0) == MAP_BAD:
        return sm_emit(o, w, 4294967293)
    if length(o) < 256 or length(s) < 320:
        return sm_reject(o, w, 1)
    if read64(s, 0) != MAP_CHANNEL or read64(s, 32) != length(s) - 64 or (read64(s, 48) | read64(s, 56)) != 0:
        return sm_reject(o, w, 2)
    origin = read64(s, 8)
    cmd = read64(s, 72)
    if origin == 1:
        if (read64(s, 16) | read64(s, 24) | read64(s, 40)) != 0 or cmd < 1 or cmd > 4:
            return sm_reject(o, w, 3)
    elif origin == 2:
        if cmd != 5 or read64(s, 16) != read64(s, 128) or read64(s, 24) != 0 or read64(s, 40) != read64(s, 168):
            return sm_reject(o, w, 4)
    elif origin == 3:
        if cmd != 6 or (read64(s, 16) | read64(s, 24) | read64(s, 40)) != 0:
            return sm_reject(o, w, 5)
    elif origin == 4:
        if cmd != 7 or (read64(s, 16) | read64(s, 24) | read64(s, 40)) != 0:
            return sm_reject(o, w, 6)
    else:
        return sm_reject(o, w, 7)
    if sm_read(s, 0) != MAP_MAGIC or sm_read(s, 128) != sm_length(s) - 256:
        return sm_reject(o, w, 8)
    if get(w, 0) == 0:
        return sm_init(s, o, w)
    if sm_steady(w) == 0:
        return sm_reject(o, w, 9)
    if sm_read(s, 16) != get(w, 16) or sm_read(s, 24) != get(w, 24) or sm_read(s, 56) != get(w, 56):
        return sm_reject(o, w, 10)
    phase = get(w, 8)
    if cmd == 6:
        if (phase != 2 and phase != 3 and phase != 4) or sm_error_shape(s, w, 0) == 0:
            return sm_reject(o, w, 11)
        return sm_reject(o, w, 12)
    if cmd == 7:
        if (phase != 3 and phase != 4) or sm_error_shape(s, w, 12) == 0:
            return sm_reject(o, w, 13)
        return sm_result(o, w, 3082, 12)
    if phase == 3 or phase == 4:
        where = 512
        if phase == 4:
            where = 768
        at = 0
        while at < 256:
            if sm_byte(s, at) != byte(w, where + at):
                return sm_reject(o, w, 14)
            at = at + 1
        return sm_prepare(s, o, w)
    if phase == 2:
        if cmd != 5 or sm_ack_shape(s, w) == 0:
            return sm_reject(o, w, 15)
        copy_input(w, s, 768, 64, 256)
        if get(w, 280) == 1:
            put(w, 240, sm_read(s, 104))
        else:
            put(w, 232, sm_read(s, 104))
        return sm_reply(s, o, w)
    if phase != 1 or cmd < 2 or cmd > 4:
        return sm_reject(o, w, 16)
    if get(w, 32) == 18446744073709551615 or sm_read(s, 32) != get(w, 32) + 1 or sm_read(s, 40) != 0 or sm_read(s, 48) == 0:
        return sm_reject(o, w, 17)
    if sm_user_shape(s) == 0:
        return sm_reject(o, w, 18)
    copy_input(w, s, 512, 64, 256)
    put(w, 32, sm_read(s, 32))
    put(w, 48, sm_read(s, 48))
    put(w, 136, cmd)
    put(w, 224, 0)
    if cmd == 2:
        index = sm_read(s, 64)
        put(w, 144, index)
        if index < get(w, 88):
            return sm_result(o, w, 0, 0)
        nper = get(w, 456)
        if index > 18446744073709551615 - nper:
            return sm_result(o, w, 3082, 12)
        required = (index + nper) & (18446744073709551615 - (nper - 1))
        if required > 562949953421311:
            return sm_result(o, w, 3082, 12)
        put(w, 152, required)
        put(w, 160, required << 15)
        put(w, 104, 32768)
        if get(w, 80) == 0:
            put(w, 128, 10)
            return sm_peer(o, w, 1, 15, get(w, 64), 0, 0, 0, 0)
        return sm_prepare(s, o, w)
    if cmd == 3:
        put(w, 176, 0)
        return sm_purge_next(o, w)
    put(w, 128, 50)
    return sm_peer(o, w, 2, 6, 0, 0, 0, 0, 0)

def sm_length(s:readbuf) -> u64:
    return length(s) - 64

def sm_read(s:readbuf, at:u64) -> u64:
    return read64(s, at + 64)

def sm_byte(s:readbuf, at:u64) -> u64:
    return byte(s, at + 64)

def sm_init(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    at = 0
    while at < 1536:
        if byte(w, at) != 0:
            return sm_reject(o, w, 19)
        at = at + 1
    if sm_read(s, 8) != 1 or sm_length(s) != 256 or (sm_read(s, 16) | sm_read(s, 24)) == 0:
        return sm_reject(o, w, 20)
    if (sm_read(s, 32) | sm_read(s, 40)) != 0 or sm_read(s, 48) == 0 or sm_read(s, 56) == 0:
        return sm_reject(o, w, 20)
    readonly = sm_read(s, 88)
    process = sm_read(s, 96)
    if readonly > 1 or process > 1:
        return sm_reject(o, w, 20)
    if process == 0:
        if sm_read(s, 64) == 0 or sm_read(s, 136) != 1:
            return sm_reject(o, w, 20)
    elif sm_read(s, 64) != 0 or readonly != 0 or sm_read(s, 136) != 0:
        return sm_reject(o, w, 20)
    pagesize = sm_read(s, 104)
    if pagesize == 0 or pagesize > 1073741824 or (pagesize & (pagesize - 1)) != 0:
        return sm_reject(o, w, 20)
    if (sm_read(s, 112) | sm_read(s, 120)) == 0 or sm_read(s, 144) == 0:
        return sm_reject(o, w, 20)
    at = 152
    while at < 256:
        if sm_read(s, at) != 0:
            return sm_reject(o, w, 20)
        at = at + 8
    put(w, 0, MAP_MAGIC)
    put(w, 8, 1)
    put(w, 16, sm_read(s, 16))
    put(w, 24, sm_read(s, 24))
    put(w, 48, sm_read(s, 48))
    put(w, 56, sm_read(s, 56))
    put(w, 64, sm_read(s, 64))
    put(w, 72, readonly)
    put(w, 80, process)
    put(w, 416, sm_read(s, 112))
    put(w, 424, sm_read(s, 120))
    put(w, 432, sm_read(s, 72))
    put(w, 440, sm_read(s, 80))
    put(w, 448, pagesize)
    nper = pagesize >> 15
    if nper == 0:
        nper = 1
    put(w, 456, nper)
    shift = 0
    left = nper
    while left > 1:
        left = left >> 1
        shift = shift + 1
    put(w, 464, shift)
    put(w, 472, sm_read(s, 144))
    return sm_result(o, w, 0, 0)

def sm_user_shape(s:readbuf) -> u64:
    if sm_length(s) != 256:
        return 0
    cmd = sm_read(s, 8)
    at = 88
    while at < 256:
        if sm_read(s, at) != 0:
            return 0
        at = at + 8
    if cmd == 2:
        return choose(sm_read(s, 72) == 32768 and sm_read(s, 80) <= 1, 1, 0)
    return choose((sm_read(s, 64) | sm_read(s, 72) | sm_read(s, 80)) == 0, 1, 0)

def sm_error_shape(s:readbuf, w:mutbuf, error:u64) -> u64:
    if sm_length(s) != 256 or sm_read(s, 32) != get(w, 32) or sm_read(s, 40) != get(w, 40) or sm_read(s, 48) != get(w, 48) or sm_read(s, 64) != error:
        return 0
    at = 72
    while at < 256:
        if sm_read(s, at) != 0:
            return 0
        at = at + 8
    return 1

def sm_steady(w:mutbuf) -> u64:
    if get(w, 0) != MAP_MAGIC or get(w, 8) < 1 or get(w, 8) > 6 or get(w, 8) == 5:
        return 0
    if (get(w, 16) | get(w, 24)) == 0 or get(w, 56) == 0 or get(w, 48) == 0:
        return 0
    if get(w, 72) > 1 or get(w, 80) > 1 or get(w, 104) != 0 and get(w, 104) != 32768:
        return 0
    if get(w, 80) == 0:
        if get(w, 64) == 0:
            return 0
    elif get(w, 64) != 0 or get(w, 72) != 0:
        return 0
    pagesize = get(w, 448)
    if pagesize == 0 or pagesize > 1073741824 or (pagesize & (pagesize - 1)) != 0:
        return 0
    nper = pagesize >> 15
    if nper == 0:
        nper = 1
    if get(w, 456) != nper or get(w, 464) > 15 or (1 << get(w, 464)) != nper:
        return 0
    count = get(w, 96)
    if count > (length(w) - 1536) >> 5 or count > (18446744073709551615 >> get(w, 464)):
        return 0
    if get(w, 88) != count << get(w, 464):
        return 0
    if get(w, 88) != 0 and get(w, 104) != 32768:
        return 0
    if get(w, 112) == 0:
        if get(w, 120) != 0 or count != 0:
            return 0
    elif get(w, 120) < get(w, 88) << 3:
        return 0
    index = 0
    while index < count:
        row = 1536 + (index << 5)
        if get(w, row + 8) != index << get(w, 464) or get(w, row + 16) != nper or get(w, row + 24) != nper << 15:
            return 0
        token = get(w, row)
        if get(w, 136) == 3 and index < get(w, 176):
            if token != 0:
                return 0
        else:
            if token == 0 or token == get(w, 112):
                return 0
            earlier = 0
            while earlier < index:
                if get(w, 1536 + (earlier << 5)) == token:
                    return 0
                earlier = earlier + 1
        index = index + 1
    phase = get(w, 8)
    if phase == 2:
        stage = get(w, 128)
        wanted = sm_stage_op(stage)
        if wanted == 0 or get(w, 288) != wanted:
            return 0
        if get(w, 280) != choose(stage < 20, 1, 2):
            return 0
        if get(w, 40) == 0 or get(w, 272) > 1:
            return 0
    if phase == 3 or phase == 4:
        if get(w, 128) != 20 or get(w, 136) != 2 or get(w, 192) < 1536 or get(w, 200) != 256:
            return 0
    if phase == 6 and (count | get(w, 88) | get(w, 112) | get(w, 120)) != 0:
        return 0
    return 1

def sm_stage_op(stage:u64) -> u64:
    if stage == 10:
        return 15
    if stage == 11:
        return 3
    if stage == 20:
        return 1
    if stage == 30:
        return 2
    if stage == 31:
        return 3
    if stage == 40:
        return 4
    if stage == 42:
        return 5
    if stage == 41:
        return 5
    if stage == 50:
        return 6
    return 0

def sm_prepare(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    put(w, 128, 20)
    required = get(w, 152) >> get(w, 464)
    if required > 576460752303423439:
        return sm_result(o, w, 3082, 12)
    need = 1536 + (required << 5)
    if need > length(w):
        put(w, 192, need)
        put(w, 200, 256)
        if sm_read(s, 8) == 5:
            put(w, 8, 4)
        else:
            put(w, 8, 3)
        return sm_emit(o, w, 2)
    put(w, 192, 0)
    put(w, 200, 0)
    return sm_peer(o, w, 2, 1, get(w, 112), get(w, 152) << 3, get(w, 120), 0, 0)

def sm_map_next(o:mutbuf, w:mutbuf) -> u32:
    if get(w, 88) >= get(w, 152):
        return sm_result(o, w, 0, 0)
    if get(w, 80) == 0:
        put(w, 128, 30)
        return sm_peer(o, w, 2, 2, get(w, 64), get(w, 88) << 15, get(w, 456) << 15, choose(get(w, 72) == 1, 1, 3), 0)
    put(w, 128, 31)
    return sm_peer(o, w, 2, 3, 0, get(w, 456) << 15, 0, 0, 0)

def sm_write_next(o:mutbuf, w:mutbuf) -> u32:
    if get(w, 168) >= get(w, 160) >> 12:
        return sm_reject(o, w, 21)
    put(w, 128, 11)
    return sm_peer(o, w, 1, 3, get(w, 64), (get(w, 168) << 12) + 4095, 1, 0, 1)

def sm_purge_next(o:mutbuf, w:mutbuf) -> u32:
    if get(w, 176) < get(w, 96):
        row = 1536 + (get(w, 176) << 5)
        if get(w, 80) == 0:
            put(w, 128, 40)
            return sm_peer(o, w, 2, 4, get(w, row), get(w, 104), get(w, row + 24), 0, 0)
        put(w, 128, 42)
        return sm_peer(o, w, 2, 5, get(w, row), get(w, row + 24), 0, 0, 0)
    if get(w, 112) != 0:
        put(w, 128, 41)
        return sm_peer(o, w, 2, 5, get(w, 112), get(w, 120), 0, 0, 0)
    return sm_purge_done(o, w)

def sm_purge_done(o:mutbuf, w:mutbuf) -> u32:
    put(w, 112, 0)
    put(w, 120, 0)
    put(w, 88, 0)
    put(w, 96, 0)
    sm_result(o, w, 0, 0)
    put(w, 8, 6)
    put(o, 136, 6)
    return 0

def sm_peer(o:mutbuf, w:mutbuf, role:u64, operation:u64, token:u64, a:u64, b:u64, c:u64, payload:u64) -> u32:
    if get(w, 40) == 18446744073709551615 or payload > 1 or length(o) < 256 + payload:
        return sm_reject(o, w, 22)
    put(w, 40, get(w, 40) + 1)
    put(w, 280, role)
    put(w, 288, operation)
    put(w, 296, token)
    put(w, 304, a)
    put(w, 312, b)
    put(w, 320, c)
    put(w, 272, payload)
    put(w, 8, 2)
    sm_emit(o, w, 1)
    put(o, 48, role)
    put(o, 56, operation)
    put(o, 64, token)
    put(o, 72, a)
    put(o, 80, b)
    put(o, 88, c)
    put(o, 128, payload)
    if payload != 0:
        store(o, 256, 0)
    copy_workspace(w, o, 1024, 0, 256 + payload)
    return 1

def sm_ack_shape(s:readbuf, w:mutbuf) -> u64:
    if sm_read(s, 32) != get(w, 32) or sm_read(s, 40) != get(w, 40) or sm_read(s, 48) != get(w, 48):
        return 0
    if sm_read(s, 64) != get(w, 280) or sm_read(s, 72) != get(w, 288) or (sm_read(s, 112) | sm_read(s, 120)) != 0:
        return 0
    error = sm_read(s, 80)
    if error > 4095:
        return 0
    serial = sm_read(s, 104)
    if get(w, 280) == 1:
        if serial <= get(w, 240):
            return 0
    elif serial <= get(w, 232):
        return 0
    source_bytes = sm_read(s, 136)
    result_bytes = sm_read(s, 144)
    if source_bytes != 256 + get(w, 272) or source_bytes > sm_length(s) - 256 or result_bytes != sm_length(s) - 256 - source_bytes:
        return 0
    at = 152
    while at < 256:
        if sm_read(s, at) != 0:
            return 0
        at = at + 8
    at = 0
    while at < source_bytes:
        if sm_byte(s, 256 + at) != byte(w, 1024 + at):
            return 0
        at = at + 1
    if error != 0:
        return choose(result_bytes == 0 and sm_read(s, 88) == 0 and sm_read(s, 96) == 0, 1, 0)
    stage = get(w, 128)
    if stage == 10:
        return choose(result_bytes == 144 and sm_read(s, 88) == 0 and sm_read(s, 96) == 144, 1, 0)
    if stage == 11:
        return choose(result_bytes == 0 and sm_read(s, 88) <= 1 and sm_read(s, 96) == 0, 1, 0)
    if stage == 20:
        return choose(result_bytes == 0 and sm_read(s, 88) != 0 and sm_read(s, 96) == get(w, 304), 1, 0)
    if stage == 30 or stage == 31:
        return choose(result_bytes == 0 and sm_read(s, 88) != 0 and sm_read(s, 96) == get(w, 456) << 15, 1, 0)
    return choose(result_bytes == 0 and (sm_read(s, 88) | sm_read(s, 96)) == 0, 1, 0)

def sm_token_used(w:mutbuf, token:u64) -> u64:
    index = 0
    while index < get(w, 96):
        if get(w, 1536 + (index << 5)) == token:
            return 1
        index = index + 1
    return 0

def sm_reply(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    stage = get(w, 128)
    error = sm_read(s, 80)
    value = sm_read(s, 88)
    if stage == 10:
        if error != 0:
            return sm_result(o, w, 4874, error)
        start = 256 + sm_read(s, 136)
        size = sm_read(s, start + 48)
        if size > 9223372036854775807:
            return sm_reject(o, w, 23)
        if size < get(w, 160):
            if get(w, 592) == 0:
                return sm_result(o, w, 0, 0)
            put(w, 168, size >> 12)
            return sm_write_next(o, w)
        return sm_prepare(s, o, w)
    if stage == 11:
        if error == 4:
            return sm_write_next(o, w)
        if error != 0 or value != 1:
            return sm_result(o, w, 4874, error)
        put(w, 168, get(w, 168) + 1)
        if get(w, 168) < get(w, 160) >> 12:
            return sm_write_next(o, w)
        return sm_prepare(s, o, w)
    if stage == 20:
        if error != 0:
            return sm_result(o, w, 3082, error)
        if sm_token_used(w, value) != 0:
            return sm_reject(o, w, 24)
        put(w, 112, value)
        put(w, 120, sm_read(s, 96))
        return sm_map_next(o, w)
    if stage == 30 or stage == 31:
        if error != 0:
            return sm_result(o, w, choose(stage == 30, 5386, 7), error)
        if value == get(w, 112) or sm_token_used(w, value) != 0:
            return sm_reject(o, w, 25)
        row = 1536 + (get(w, 96) << 5)
        if row > length(w) or 32 > length(w) - row:
            return sm_reject(o, w, 26)
        put(w, row, value)
        put(w, row + 8, get(w, 88))
        put(w, row + 16, get(w, 456))
        put(w, row + 24, get(w, 456) << 15)
        put(w, 96, get(w, 96) + 1)
        put(w, 88, get(w, 88) + get(w, 456))
        return sm_map_next(o, w)
    if stage == 40 or stage == 42:
        if error != 0:
            put(w, 216, get(w, 216) + 1)
            put(w, 224, error)
        row = 1536 + (get(w, 176) << 5)
        put(w, row, 0)
        put(w, 176, get(w, 176) + 1)
        return sm_purge_next(o, w)
    if stage == 41:
        if error != 0:
            put(w, 216, get(w, 216) + 1)
            put(w, 224, error)
        return sm_purge_done(o, w)
    if stage == 50:
        if error != 0:
            return sm_reject(o, w, 27)
        return sm_result(o, w, 0, 0)
    return sm_reject(o, w, 28)

def sm_result(o:mutbuf, w:mutbuf, code:u64, error:u64) -> u32:
    put(w, 8, 1)
    put(w, 128, 0)
    put(w, 192, 0)
    put(w, 200, 0)
    sm_emit(o, w, 0)
    if get(w, 136) == 2 and get(w, 72) != 0 and code == 0:
        code = 8
    put(o, 48, code)
    put(o, 56, error)
    if get(w, 136) == 2 and get(w, 144) < get(w, 88):
        record = get(w, 144) >> get(w, 464)
        row = 1536 + (record << 5)
        put(o, 64, get(w, row))
        put(o, 72, (get(w, 144) - get(w, row + 8)) << 15)
        put(o, 80, 32768)
    put(o, 88, get(w, 88))
    put(o, 144, get(w, 72))
    put(o, 152, get(w, 104))
    put(o, 160, get(w, 112))
    put(o, 168, get(w, 216))
    put(o, 192, get(w, 224))
    return 0

def sm_reject(o:mutbuf, w:mutbuf, reason:u64) -> u32:
    if get(w, 0) != MAP_BAD:
        put(w, 208, reason)
    put(w, 0, MAP_BAD)
    put(w, 8, 7)
    return sm_emit(o, w, 4294967293)

def sm_emit(o:mutbuf, w:mutbuf, status:u64) -> u32:
    if length(o) < 256:
        return 4294967293
    at = 0
    while at < 256:
        put(o, at, 0)
        at = at + 8
    put(o, 0, MAP_MAGIC)
    put(o, 8, status)
    put(o, 16, get(w, 16))
    put(o, 24, get(w, 24))
    put(o, 32, get(w, 32))
    put(o, 40, get(w, 40))
    put(o, 96, get(w, 192))
    put(o, 104, get(w, 200))
    put(o, 112, get(w, 48))
    put(o, 120, get(w, 56))
    put(o, 136, get(w, 8))
    put(o, 144, get(w, 88))
    put(o, 152, get(w, 104))
    put(o, 160, get(w, 72))
    put(o, 168, get(w, 112))
    put(o, 176, get(w, 208))
    put(o, 184, 1)
    return status
'''
def source_program():
    text=MAP.replace("MAP_CHANNEL",str(CHANNEL)).replace("MAP_MAGIC",str(MAGIC)).replace("MAP_BAD",str(BAD))
    return text+VALUES[VALUES.index("\ndef read64("):]
def document():
    nodes=ast.parse(source_program()).body
    names={node.name:"f"+str(i) for i,node in enumerate(nodes)}
    if len(names)!=len(nodes):raise ValueError("duplicate SHM mapping symbol")
    signatures={node.name:([arg.annotation.id for arg in node.args.args],node.returns.id) for node in nodes}
    total=total_scalar_functions(nodes);functions=[]
    for node in nodes:
        b=ObjectBuilder(node,names,signatures,total);b.statements(node.body)
        functions.append({"name":names[node.name],"params":[b.param(v) for v in b.params],"returns":[b.returns],
            "effects":["read","write","trap"],"entry":"b0","blocks":b.blocks})
    return compact_authoring_cfg({"schema":"hepta.hia.program.v8","module":"agent_namespace_shm_map_r1","functions":functions})
if __name__=="__main__":
    path=ROOT/"examples/hia_bootstrap/agent_namespace_shm_map_r1.hiaasm"
    path.write_text(render_assembly(document()));print(path.name,path.stat().st_size)
