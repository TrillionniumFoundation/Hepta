"""NEW r6 complete selected Linux unixOpen policy continuation.

This source owns original order and partial UnixFile state. Completed effects
must be issued by the eventual actual fixed native dispatcher. It is not an
external authentication protocol and is not an installed Store implementation.
Existing lower6 / robust7 / create8 peers have separate evidence; new process
PRNG, recoverable allocator, tempname and logger peers remain explicit OPEN
dependencies until joined and tested. No execution is inherited by this draft.
"""
from __future__ import annotations
import ast
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_agent_namespace_objects import ObjectBuilder
from tools.generate_hia_agent_namespace_store import VALUES
from tools.generate_hia_selfhost import compact_authoring_cfg,total_scalar_functions
ROOT=Path(__file__).resolve().parents[1]
MAGIC=int.from_bytes(b"HIANUO01","little")
BAD=int.from_bytes(b"HIANUB01","little")
REQUEST=int.from_bytes(b"HIANUQ01","little")

POLICY=r'''
def unixopen_owner(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < 4096:
        if length(w) >= 8:
            put(w, 0, UNIXOPEN_BAD)
        return 4294967293
    if get(w, 0) == UNIXOPEN_BAD:
        return up_emit(o, w, 4294967293, 0)
    if length(s) < 512 or length(o) < 256:
        return up_refuse(o, w, 1)
    if read64(s, 0) != UNIXOPEN_MAGIC:
        return up_refuse(o, w, 2)
    phase = get(w, 8)
    if get(w, 0) == 0 or phase == 3:
        return up_begin(s, o, w)
    if up_steady(w) == 0:
        return up_refuse(o, w, 3)
    if read64(s, 16) != get(w, 16) or read64(s, 24) != get(w, 24) or read64(s, 32) != get(w, 32):
        return up_refuse(o, w, 4)
    if phase == 1:
        if length(s) != 512 + get(w, 400):
            return up_refuse(o, w, 5)
        at = 0
        while at < 512:
            if read64(s, at) != get(w, 1024 + at):
                return up_refuse(o, w, 5)
            at = at + 8
        return up_prepare(s, o, w)
    if phase != 2 or up_reply_shape(s, w) == 0:
        return up_refuse(o, w, 6)
    if length(o) < get(w, 456):
        return up_emit(o, w, 2, 0)
    return up_reply(s, o, w)

def up_zero(w:mutbuf, at:u64, amount:u64) -> u64:
    stop = at + amount
    while at < stop:
        put(w, at, 0)
        at = at + 8
    return 0

def up_stage_op(stage:u64) -> u64:
    if stage == 10 or stage == 11:
        return 1
    if stage == 12:
        return 2
    if stage == 20 or stage == 33:
        return 3
    if stage == 21:
        return 4
    if stage == 22:
        return 5
    if stage == 30:
        return 6
    if stage == 31 or stage == 35:
        return 7
    if stage == 32:
        return 8
    if stage == 40:
        return 9
    if stage == 41:
        return 10
    if stage == 50:
        return 11
    if stage == 60:
        return 12
    if stage == 61:
        return 13
    if stage == 62:
        return 14
    if stage == 70:
        return 15
    if stage == 71:
        return 16
    if stage == 36 or stage == 63 or stage == 72:
        return 17
    if stage == 34 or stage == 80:
        return 18
    return 0

def up_peer(op:u64) -> u64:
    if op == 2:
        return 10
    if op == 4 or op == 18:
        return 11
    if op == 5:
        return 12
    if op == 6 or op == 12:
        return 8
    if op == 7:
        return 7
    if op == 17:
        return 13
    return 6

def up_flag_shape(flags:u64, absent:u64) -> u64:
    if flags > 4294967295:
        return 0
    access = flags & 3
    if access != 1 and access != 2:
        return 0
    if (flags & 4) != 0 and access != 2:
        return 0
    if (flags & 24) != 0 and (flags & 4) == 0:
        return 0
    kind = flags & 1048320
    if kind != 256 and kind != 512 and kind != 1024 and kind != 2048 and kind != 4096 and kind != 8192 and kind != 16384 and kind != 524288:
        return 0
    if kind == 256 or kind == 2048 or kind == 16384 or kind == 524288:
        if absent != 0 or (flags & 8) != 0:
            return 0
    if absent != 0 and (flags & 8) == 0:
        return 0
    return 1

def up_begin_shape(s:readbuf, w:mutbuf) -> u64:
    if read64(s, 8) != 1 or (read64(s, 16) | read64(s, 24)) == 0 or read64(s, 32) == 0 or read64(s, 40) == 0:
        return 0
    n = read64(s, 64)
    absent = read64(s, 56)
    if absent > 1 or n != length(s) - 512 or n > 18446744073709547512:
        return 0
    if up_flag_shape(read64(s, 48), absent) == 0:
        return 0
    if read64(s, 72) > 1 or read64(s, 80) == 0 or read64(s, 88) > 1 or read64(s, 104) > 1 or read64(s, 112) > 4095:
        return 0
    if read64(s, 120) > 2147483647 or read64(s, 128) != 512 or read64(s, 184) == 0:
        return 0
    if (read64(s, 152) | read64(s, 160)) == 0:
        return 0
    if absent != 0:
        if n != 0 or read64(s, 192) != 0:
            return 0
    elif read64(s, 192) >= n:
        return 0
    if read64(s, 200) > 4294967295 or (read64(s, 72) == 0 and read64(s, 200) != 0):
        return 0
    at = 208
    while at < 512:
        if read64(s, at) != 0:
            return 0
        at = at + 8
    if get(w, 0) != 0:
        if get(w, 0) != UNIXOPEN_MAGIC or get(w, 8) != 3:
            return 0
        if read64(s, 16) != get(w, 16) or read64(s, 24) != get(w, 24) or get(w, 32) == 18446744073709551615 or read64(s, 32) != get(w, 32) + 1:
            return 0
        if read64(s, 120) != get(w, 336) or read64(s, 144) != get(w, 328) or read64(s, 184) != get(w, 464):
            return 0
        if read64(s, 152) != get(w, 64) or read64(s, 160) != get(w, 72) or read64(s, 168) < get(w, 80) or read64(s, 176) < get(w, 88):
            return 0
    return 1

def up_begin(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if up_begin_shape(s, w) == 0:
        return up_refuse(o, w, 7)
    if get(w, 0) == 0:
        at = 0
        while at < 4096:
            if get(w, at) != 0:
                return up_refuse(o, w, 8)
            at = at + 8
    up_zero(w, 0, 4096)
    put(w, 0, UNIXOPEN_MAGIC)
    put(w, 8, 1)
    put(w, 16, read64(s, 16))
    put(w, 24, read64(s, 24))
    put(w, 32, read64(s, 32))
    put(w, 64, read64(s, 152))
    put(w, 72, read64(s, 160))
    put(w, 80, read64(s, 168))
    put(w, 88, read64(s, 176))
    flags = read64(s, 48)
    put(w, 96, flags)
    put(w, 112, flags & 1048320)
    put(w, 120, choose((flags & 2) != 0, 1, 0))
    put(w, 128, choose((flags & 1) != 0, 1, 0))
    kind = flags & 1048320
    fresh = 0
    if (flags & 4) != 0 and (kind == 2048 or kind == 16384 or kind == 524288):
        fresh = 1
    put(w, 136, fresh)
    put(w, 144, read64(s, 56))
    put(w, 152, read64(s, 72))
    put(w, 232, read64(s, 200))
    put(w, 160, read64(s, 112))
    put(w, 184, 18446744073709551615)
    put(w, 328, read64(s, 144))
    put(w, 336, read64(s, 120))
    put(w, 392, read64(s, 192))
    put(w, 400, read64(s, 64))
    put(w, 408, read64(s, 192))
    put(w, 416, read64(s, 40))
    put(w, 424, read64(s, 88))
    put(w, 432, read64(s, 104))
    put(w, 440, read64(s, 136))
    put(w, 448, 4096 + ((read64(s, 64) + 7) & 18446744073709551608))
    out_need = 512 + read64(s, 64)
    if out_need < 1024:
        out_need = 1024
    put(w, 456, out_need)
    put(w, 464, read64(s, 184))
    copy_input(w, s, 1024, 0, 512)
    return up_prepare(s, o, w)

def up_prepare(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < get(w, 448) or length(o) < get(w, 456):
        return up_emit(o, w, 2, 0)
    n = get(w, 400)
    copy_input(w, s, 4096, 512, n)
    if get(w, 144) == 0:
        pos = get(w, 408)
        size = 0
        while pos + size < n and byte(s, 512 + pos + size) != 0:
            size = size + 1
        if size == n - pos:
            return up_refuse(o, w, 9)
        put(w, 384, size)
    return up_issue(o, w, 10, 0, 0, 0, 0, 0, 0, 0)

def up_steady(w:mutbuf) -> u64:
    if get(w, 0) != UNIXOPEN_MAGIC or get(w, 8) < 1 or get(w, 8) > 3:
        return 0
    if (get(w, 16) | get(w, 24)) == 0 or get(w, 32) == 0 or get(w, 416) == 0 or get(w, 464) == 0:
        return 0
    if get(w, 160) > 4095 or get(w, 168) > 4294967295 or get(w, 144) > 1:
        return 0
    n = get(w, 400)
    if n > 18446744073709547512 or get(w, 448) != 4096 + ((n + 7) & 18446744073709551608):
        return 0
    want = 512 + n
    if want < 1024:
        want = 1024
    if get(w, 456) != want:
        return 0
    if get(w, 8) != 1 and length(w) < get(w, 448):
        return 0
    if get(w, 8) == 2:
        if get(w, 40) == 0 or up_stage_op(get(w, 56)) != get(w, 48) or get(w, 48) == 0:
            return 0
        if get(w, 512) != UNIXOPEN_REQUEST or get(w, 552) != get(w, 40):
            return 0
    return 1

def up_path_size(w:mutbuf, mode:u64) -> u64:
    if mode == 0:
        return 0
    if mode == 1:
        return get(w, 384)
    if mode == 4:
        return choose(get(w, 144) == 0, get(w, 384), 0)
    if mode == 2 and get(w, 144) != 0:
        return get(w, 384) + 2
    return get(w, 400)

def up_path_offset(w:mutbuf, mode:u64) -> u64:
    if mode == 4:
        return 4096 + get(w, 408)
    if mode == 1:
        if get(w, 144) != 0:
            return 1536
        return 4096 + get(w, 408)
    if mode == 2 and get(w, 144) != 0:
        return 1536
    return 4096

def up_issue(o:mutbuf, w:mutbuf, stage:u64, a:u64, b:u64, c:u64, d:u64, e:u64, f:u64, pathmode:u64) -> u32:
    op = up_stage_op(stage)
    if op == 0 or pathmode > 4 or get(w, 40) == 18446744073709551615:
        return up_refuse(o, w, 10)
    n = up_path_size(w, pathmode)
    if length(o) < 512 or n > length(o) - 512:
        return up_refuse(o, w, 11)
    put(w, 40, get(w, 40) + 1)
    put(w, 48, op)
    put(w, 56, stage)
    put(w, 8, 2)
    up_zero(w, 512, 256)
    put(w, 512, UNIXOPEN_REQUEST)
    put(w, 520, 1)
    put(w, 528, get(w, 16))
    put(w, 536, get(w, 24))
    put(w, 544, get(w, 32))
    put(w, 552, get(w, 40))
    put(w, 560, op)
    put(w, 568, stage)
    put(w, 576, a)
    put(w, 584, b)
    put(w, 592, c)
    put(w, 600, d)
    put(w, 608, e)
    put(w, 616, f)
    put(w, 624, n)
    put(w, 632, pathmode)
    put(w, 640, get(w, 416))
    put(w, 648, get(w, 64))
    put(w, 656, get(w, 72))
    put(w, 664, get(w, 80))
    put(w, 672, get(w, 88))
    put(w, 680, up_peer(op))
    put(w, 688, get(w, 464))
    put(w, 696, get(w, 160))
    up_emit(o, w, 1, 256 + n)
    copy_workspace(o, w, 256, 512, 256)
    if n != 0:
        copy_workspace(o, w, 512, up_path_offset(w, pathmode), n)
    return 1

def up_reply_shape(s:readbuf, w:mutbuf) -> u64:
    if read64(s, 8) != 2 or read64(s, 40) != get(w, 40) or read64(s, 48) != get(w, 48) or read64(s, 56) != get(w, 56):
        return 0
    if read64(s, 64) > 4095 or read64(s, 136) != length(s) - 512:
        return 0
    if read64(s, 144) != up_peer(get(w, 48)) or read64(s, 152) == 0 or read64(s, 160) == 0 or read64(s, 168) == 0 or read64(s, 176) == 0:
        return 0
    at = 184
    while at < 256:
        if read64(s, at) != 0:
            return 0
        at = at + 8
    at = 0
    while at < 256:
        if read64(s, 256 + at) != get(w, 512 + at):
            return 0
        at = at + 8
    if get(w, 48) != 5 and length(s) != 512:
        return 0
    if up_receipt_watermarks(s, w) == 0:
        return 0
    return up_result_shape(s, w)

def up_receipt_watermarks(s:readbuf, w:mutbuf) -> u64:
    seq = read64(s, 120)
    sys = read64(s, 128)
    if seq < get(w, 80) or sys < get(w, 88):
        return 0
    op = get(w, 48)
    if op == 1 or (op >= 8 and op <= 11) or (op >= 14 and op <= 16):
        if get(w, 80) == 18446744073709551615 or get(w, 88) == 18446744073709551615:
            return 0
        if seq != get(w, 80) + 1 or sys != get(w, 88) + 1:
            return 0
        if op == 1 or op == 9 or read64(s, 72) == 0:
            return choose(read64(s, 64) == get(w, 160), 1, 0)
        return choose(read64(s, 64) == read64(s, 72), 1, 0)
    if op == 2 or op == 4 or op == 12 or op == 17 or op == 18:
        return choose(seq == get(w, 80) and sys == get(w, 88), 1, 0)
    if op == 3 or op == 6:
        if seq - get(w, 80) > 1 or sys - get(w, 88) != seq - get(w, 80):
            return 0
        return 1
    if op == 7:
        return choose(seq > get(w, 80) and sys - get(w, 88) == seq - get(w, 80), 1, 0)
    return 1

def up_result_shape(s:readbuf, w:mutbuf) -> u64:
    op = get(w, 48)
    a = read64(s, 72)
    b = read64(s, 80)
    c = read64(s, 88)
    d = read64(s, 96)
    e = read64(s, 104)
    f = read64(s, 112)
    if op == 1:
        return choose(a > 0 and a <= 2147483647 and (b | c | d | e | f) == 0, 1, 0)
    if op == 2 or op == 18:
        return choose((a | b | c | d | e | f) == 0, 1, 0)
    if op == 10 or op == 11 or op == 14:
        return choose(a <= 4095 and (b | c | d | e | f) == 0, 1, 0)
    if op == 3:
        if a == 0:
            return choose((b | c | d | e | f) == 0, 1, 0)
        return choose(b != 0 and c <= 2147483647 and d == (get(w, 576) & 3) and (e | f) == 0, 1, 0)
    if op == 4:
        return choose(a <= 1 and ((a == 0 and b == 0) or (a == 1 and b != 0)) and (c | d | e | f) == 0, 1, 0)
    if op == 5:
        if (a != 0 and a != 1 and a != 10 and a != 6410) or (b | c | d | e | f) != 0:
            return 0
        if a != 0:
            return choose(length(s) == 512, 1, 0)
        n = length(s) - 512
        if n < 3 or n > 512:
            return 0
        at = 0
        while at + 2 < n:
            if byte(s, 512 + at) == 0:
                return 0
            at = at + 1
        return choose(byte(s, length(s) - 2) == 0 and byte(s, length(s) - 1) == 0, 1, 0)
    if op == 6:
        if a != 0 and a != 1802:
            return 0
        if a == 1802 and (b | c | d) != 0:
            return 0
        return choose(b <= 511 and c <= 4294967295 and d <= 4294967295 and (e | f) == 0, 1, 0)
    if op == 7:
        if a == 0:
            return choose(b == 18446744073709551615 and (c | d | e | f) == 0, 1, 0)
        return choose(b >= 3 and b <= 2147483647 and (c | d | e | f) == 0, 1, 0)
    if op == 8:
        return choose(a <= 4095 and (b | c | d | e | f) == 0, 1, 0)
    if op == 9:
        return choose(a <= 4294967295 and (b | c | d | e | f) == 0, 1, 0)
    if op == 12:
        return choose(a <= 1 and (b | c | d | e | f) == 0, 1, 0)
    if op == 13:
        if a == 0:
            return choose(b != 0 and c != 0 and f == 0, 1, 0)
        return choose((a == 7 or a == 10) and (b | c | d | e | f) == 0, 1, 0)
    if op == 15 or op == 16:
        if a != 0:
            return choose(a <= 4095 and (b | c | d | e | f) == 0, 1, 0)
        return choose((d | e | f) == 0, 1, 0)
    if op == 17:
        return choose(a == get(w, 576) and (b | c | d | e | f) == 0, 1, 0)
    return 0

def up_reply(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    put(w, 160, read64(s, 64))
    put(w, 80, read64(s, 120))
    put(w, 88, read64(s, 128))
    stage = get(w, 56)
    if stage == 10:
        if read64(s, 72) != get(w, 336):
            return up_issue(o, w, 11, 0, 0, 0, 0, 0, 0, 0)
        return up_file_reset(o, w)
    if stage == 11:
        put(w, 336, read64(s, 72))
        return up_issue(o, w, 12, 0, 0, 0, 0, 0, 0, 0)
    if stage == 12:
        return up_file_reset(o, w)
    if stage == 20:
        if read64(s, 72) == 0:
            return up_issue(o, w, 21, 16, 0, 0, 0, 0, 0, 0)
        put(w, 192, read64(s, 72))
        put(w, 200, 1)
        put(w, 176, read64(s, 80))
        put(w, 184, read64(s, 88))
        put(w, 208, read64(s, 88))
        put(w, 216, read64(s, 96))
        put(w, 504, 1)
        return up_open_flags(o, w)
    if stage == 21:
        if read64(s, 72) == 0:
            put(w, 168, 7)
            return up_done(o, w)
        put(w, 192, read64(s, 80))
        put(w, 200, 1)
        return up_open_flags(o, w)
    if stage == 22:
        if read64(s, 72) != 0:
            put(w, 168, read64(s, 72))
            return up_done(o, w)
        copy_input(w, s, 1536, 512, length(s) - 512)
        put(w, 384, length(s) - 514)
        put(w, 392, 0)
        return up_open_flags(o, w)
    if stage == 30:
        put(w, 168, read64(s, 72))
        put(w, 352, read64(s, 80))
        put(w, 360, read64(s, 88))
        put(w, 368, read64(s, 96))
        if read64(s, 72) != 0:
            return up_done(o, w)
        return up_issue(o, w, 31, get(w, 104), get(w, 352), 0, 0, 0, 0, 1)
    if stage == 31 or stage == 35:
        put(w, 176, read64(s, 72))
        put(w, 184, read64(s, 80))
        if read64(s, 72) == 0:
            if stage == 31:
                if get(w, 136) != 0 and get(w, 160) == 13:
                    return up_issue(o, w, 32, 0, 0, 0, 0, 0, 0, 1)
                return up_fallback(o, w)
            return up_open_failed(o, w)
        return up_new_fd(o, w)
    if stage == 32:
        if read64(s, 72) != 0:
            put(w, 168, 1544)
            return up_open_failed(o, w)
        return up_fallback(o, w)
    if stage == 33:
        if read64(s, 72) == 0:
            return up_issue(o, w, 35, get(w, 104), get(w, 352), 0, 0, 0, 0, 1)
        put(w, 176, read64(s, 80))
        put(w, 184, read64(s, 88))
        return up_issue(o, w, 34, read64(s, 72), 0, 0, 0, 0, 0, 0)
    if stage == 34:
        return up_new_fd(o, w)
    if stage == 36:
        if get(w, 168) == 0:
            put(w, 168, read64(s, 72))
        return up_finish_failure(o, w)
    if stage == 40:
        if read64(s, 72) == 0:
            return up_issue(o, w, 41, get(w, 176), get(w, 360), get(w, 368), 0, 0, 0, 0)
        return up_publish_flags(o, w)
    if stage == 41:
        return up_publish_flags(o, w)
    if stage == 50:
        return up_fill(o, w)
    if stage == 60:
        if read64(s, 72) != 0:
            put(w, 272, get(w, 272) | 16)
        return up_inode(o, w)
    if stage == 61:
        put(w, 168, read64(s, 72))
        if read64(s, 72) != 0:
            if read64(s, 72) == 10:
                put(w, 288, get(w, 160))
            return up_issue(o, w, 62, get(w, 176), 0, 0, 0, 0, 0, 0)
        put(w, 472, read64(s, 80))
        put(w, 304, read64(s, 88))
        put(w, 312, read64(s, 96))
        put(w, 320, read64(s, 104))
        return up_after_inode(o, w)
    if stage == 62:
        if read64(s, 72) != 0:
            return up_issue(o, w, 63, 4106, 6, 0, 0, 0, 0, 4)
        return up_after_inode(o, w)
    if stage == 63:
        return up_after_inode(o, w)
    if stage == 70:
        if read64(s, 72) != 0:
            return up_issue(o, w, 72, 28, 1, 0, 0, 0, 0, 4)
        if read64(s, 88) == 0:
            return up_issue(o, w, 72, 28, 2, 0, 0, 0, 0, 4)
        if read64(s, 88) > 1:
            return up_issue(o, w, 72, 28, 3, 0, 0, 0, 0, 4)
        if get(w, 304) != 0:
            return up_issue(o, w, 71, 0, 0, 0, 0, 0, 0, 4)
        return up_done(o, w)
    if stage == 71:
        if read64(s, 72) != 0 or read64(s, 80) != get(w, 320):
            return up_issue(o, w, 72, 28, 4, 0, 0, 0, 0, 4)
        return up_done(o, w)
    if stage == 72:
        return up_done(o, w)
    if stage == 80:
        put(w, 200, 0)
        return up_done(o, w)
    return up_refuse(o, w, 12)

def up_file_reset(o:mutbuf, w:mutbuf) -> u32:
    put(w, 240, 1)
    if get(w, 112) == 256:
        return up_issue(o, w, 20, get(w, 96), 0, 0, 0, 0, 0, 1)
    if get(w, 144) != 0:
        return up_issue(o, w, 22, 512, get(w, 440), 0, 0, 0, 0, 0)
    return up_open_flags(o, w)

def up_open_flags(o:mutbuf, w:mutbuf) -> u32:
    flags = 131072
    if get(w, 120) != 0:
        flags = flags | 2
    if (get(w, 96) & 4) != 0:
        flags = flags | 64
    if (get(w, 96) & 16) != 0:
        flags = flags | 128
    put(w, 104, flags)
    if get(w, 176) != 0:
        return up_publish_flags(o, w)
    return up_issue(o, w, 30, get(w, 96), get(w, 392), 1, 0, 0, 0, 2)

def up_fallback(o:mutbuf, w:mutbuf) -> u32:
    if get(w, 160) == 21 or get(w, 120) == 0:
        return up_open_failed(o, w)
    put(w, 96, (get(w, 96) & 18446744073709551609) | 1)
    put(w, 104, get(w, 104) & 18446744073709551549)
    put(w, 128, 1)
    return up_issue(o, w, 33, get(w, 96), 0, 0, 0, 0, 0, 1)

def up_open_failed(o:mutbuf, w:mutbuf) -> u32:
    return up_issue(o, w, 36, 14, 5, 0, 0, 0, 0, 1)

def up_new_fd(o:mutbuf, w:mutbuf) -> u32:
    if get(w, 352) != 0 and (get(w, 96) & 526336) != 0:
        return up_issue(o, w, 40, 0, 0, 0, 0, 0, 0, 0)
    return up_publish_flags(o, w)

def up_publish_flags(o:mutbuf, w:mutbuf) -> u32:
    if get(w, 152) != 0:
        put(w, 224, 1)
        put(w, 232, get(w, 96))
    if get(w, 192) != 0:
        put(w, 208, get(w, 184))
        put(w, 216, get(w, 96) & 3)
        put(w, 504, 1)
    if (get(w, 96) & 8) != 0:
        return up_issue(o, w, 50, 0, 0, 0, 0, 0, 0, 1)
    return up_fill(o, w)

def up_fill(o:mutbuf, w:mutbuf) -> u32:
    put(w, 248, get(w, 184))
    put(w, 256, get(w, 1104))
    put(w, 280, get(w, 1120))
    put(w, 480, get(w, 184))
    if get(w, 144) == 0:
        put(w, 264, get(w, 416))
    ctrl = 0
    if (get(w, 96) & 8) != 0:
        ctrl = ctrl | 32
    if get(w, 128) != 0:
        ctrl = ctrl | 2
    if get(w, 112) != 256:
        ctrl = ctrl | 128
        put(w, 376, 1)
    if get(w, 136) != 0:
        ctrl = ctrl | 8
    if (get(w, 96) & 64) != 0:
        ctrl = ctrl | 64
    put(w, 272, ctrl)
    present = choose(get(w, 144) == 0 and (get(w, 96) & 64) != 0, 1, 0)
    if present == 0:
        return up_issue(o, w, 60, 0, 0, get(w, 432), 0, 0, 0, 0)
    return up_issue(o, w, 60, get(w, 408), 1, get(w, 432), 0, 0, 0, 3)

def up_inode(o:mutbuf, w:mutbuf) -> u32:
    if get(w, 424) != 0:
        put(w, 272, get(w, 272) | 1)
    if get(w, 376) != 0:
        put(w, 288, 0)
        put(w, 296, 1)
        return up_success(o, w)
    flags = get(w, 128) | (get(w, 424) << 1)
    put(w, 496, 1)
    return up_issue(o, w, 61, get(w, 176), flags, get(w, 192), 0, 0, 0, 0)

def up_after_inode(o:mutbuf, w:mutbuf) -> u32:
    if get(w, 168) != 0:
        put(w, 480, 18446744073709551615)
    put(w, 496, 0)
    put(w, 288, 0)
    if get(w, 168) != 0:
        return up_finish_failure(o, w)
    put(w, 296, 2)
    return up_success(o, w)

def up_success(o:mutbuf, w:mutbuf) -> u32:
    if get(w, 328) == 18446744073709551615:
        return up_refuse(o, w, 13)
    put(w, 328, get(w, 328) + 1)
    if get(w, 376) != 0:
        return up_done(o, w)
    return up_issue(o, w, 70, get(w, 176), 0, 0, 0, 0, 0, 0)

def up_finish_failure(o:mutbuf, w:mutbuf) -> u32:
    return up_issue(o, w, 80, get(w, 192), 0, 0, 0, 0, 0, 0)

def up_done(o:mutbuf, w:mutbuf) -> u32:
    put(w, 8, 3)
    put(w, 48, 0)
    put(w, 56, 0)
    return up_emit(o, w, 0, 0)

def up_refuse(o:mutbuf, w:mutbuf, reason:u64) -> u32:
    if get(w, 0) != UNIXOPEN_BAD:
        put(w, 488, reason)
    put(w, 0, UNIXOPEN_BAD)
    put(w, 8, 4)
    return up_emit(o, w, 4294967293, 0)

def up_emit(o:mutbuf, w:mutbuf, status:u64, amount:u64) -> u32:
    if length(o) < 256:
        return 4294967293
    up_zero(o, 0, 256)
    put(o, 0, UNIXOPEN_MAGIC)
    put(o, 8, status)
    put(o, 16, get(w, 16))
    put(o, 24, get(w, 24))
    put(o, 32, get(w, 32))
    put(o, 40, get(w, 40))
    put(o, 48, get(w, 48))
    put(o, 56, get(w, 56))
    put(o, 64, get(w, 168))
    put(o, 72, get(w, 160))
    put(o, 80, get(w, 176))
    put(o, 88, get(w, 184))
    put(o, 96, get(w, 96))
    put(o, 104, get(w, 104))
    put(o, 112, get(w, 192))
    put(o, 120, get(w, 200))
    put(o, 128, amount)
    put(o, 136, get(w, 448))
    put(o, 144, get(w, 456))
    put(o, 152, get(w, 488))
    put(o, 160, get(w, 472))
    put(o, 168, get(w, 304))
    put(o, 176, get(w, 240))
    put(o, 184, get(w, 224))
    put(o, 192, get(w, 232))
    put(o, 200, get(w, 248))
    put(o, 208, get(w, 272))
    put(o, 216, get(w, 288))
    put(o, 224, get(w, 296))
    put(o, 232, get(w, 328))
    put(o, 240, get(w, 336))
    put(o, 248, get(w, 416))
    return status

'''

def source_program():
    return (POLICY.replace("UNIXOPEN_BAD",str(BAD))
        .replace("UNIXOPEN_REQUEST",str(REQUEST))
        .replace("UNIXOPEN_MAGIC",str(MAGIC))
        +VALUES[VALUES.index("\ndef read64("):])
def document():
    nodes=ast.parse(source_program()).body
    names={node.name:"f"+str(i) for i,node in enumerate(nodes)}
    if len(names)!=len(nodes):raise ValueError("duplicate unixOpen symbol")
    signatures={node.name:([a.annotation.id for a in node.args.args],node.returns.id) for node in nodes}
    total=total_scalar_functions(nodes);functions=[]
    for node in nodes:
        b=ObjectBuilder(node,names,signatures,total);b.statements(node.body)
        functions.append({"name":names[node.name],"params":[b.param(v) for v in b.params],
            "returns":[b.returns],"effects":["read","write","trap"],"entry":"b0","blocks":b.blocks})
    return compact_authoring_cfg({"schema":"hepta.hia.program.v8",
        "module":"agent_namespace_unixopen_parent_r6","functions":functions})
if __name__=="__main__":
    path=ROOT/"examples/hia_bootstrap/agent_namespace_unixopen_parent_r6.hiaasm"
    path.write_text(render_assembly(document()))
    print(path.name,path.stat().st_size)
