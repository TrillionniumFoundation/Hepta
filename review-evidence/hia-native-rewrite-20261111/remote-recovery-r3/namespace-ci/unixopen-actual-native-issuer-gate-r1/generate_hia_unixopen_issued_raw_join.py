"""Native private unixOpen/raw-FS issuance coordinator, new source revision 2.

Owns the actual-parent -> actual-framer -> shared role-6 -> actual-framer
continuation. Inputs are mechanically issued completed capsules, never a
public byte-header authentication API. Other unixOpen effects remain pending.
No previous component execution is inherited by this new composition.
"""
from __future__ import annotations
import ast
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_agent_namespace_objects import ObjectBuilder
from tools.generate_hia_agent_namespace_store import VALUES
from tools.generate_hia_selfhost import compact_authoring_cfg,total_scalar_functions

ROOT=Path(__file__).resolve().parents[1]
CONSTANTS={
 "UI_MAGIC":int.from_bytes(b"HIAUIJ01","little"),
 "UI_BAD":int.from_bytes(b"HIAUIB01","little"),
 "UI_EVENT":int.from_bytes(b"HIAUIE01","little"),
 "UI_CHANNEL":int.from_bytes(b"HIAUIX01","little"),
 "UI_CAPSULE":int.from_bytes(b"HIAUIC01","little"),
 "UI_PARENT":int.from_bytes(b"HIANUO01","little"),
 "UI_PENDING":int.from_bytes(b"HIANUQ01","little"),
 "UI_JOIN":int.from_bytes(b"HIANDJ01","little"),
 "UI_FS_CHANNEL":int.from_bytes(b"HIANDJX1","little"),
 "UI_FRAMER":int.from_bytes(b"HIAUFS01","little"),
 "UI_FRAMER_EVENT":int.from_bytes(b"HIAUFE01","little"),
 "UI_FRAMER_PEER":int.from_bytes(b"HIAUFP01","little"),
}

POLICY=r'''
def unixopen_issued_raw_join(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < 1024:
        if length(w) >= 8:
            put(w, 0, UI_BAD)
        return 4294967293
    if get(w, 0) == UI_BAD:
        return ui_emit(o, w, 4294967293)
    if length(o) < 256 or length(s) < 256:
        return ui_refuse(o, w, 1)
    if read64(s, 0) != UI_CHANNEL:
        return ui_refuse(o, w, 2)
    command = read64(s, 8)
    if command == 1:
        return ui_begin(s, o, w)
    if command != 2 or get(w, 0) != UI_MAGIC:
        return ui_refuse(o, w, 3)
    if get(w, 8) != 2 and get(w, 8) != 3 and get(w, 8) != 4:
        return ui_refuse(o, w, 3)
    return ui_completed(s, o, w)

def ui_zero(w:mutbuf, at:u64, size:u64) -> u64:
    end = at + size
    while at < end:
        put(w, at, 0)
        at = at + 8
    return 0

def ui_align(at:u64, size:u64) -> u64:
    if at > 18446744073709551608:
        return 0
    if size > 18446744073709551608 - at:
        return 0
    return (at + size + 7) & 18446744073709551608

def ui_span(total:u64, at:u64, size:u64) -> u64:
    return choose(at <= total and size <= total - at, 1, 0)

def ui_capsule(s:readbuf, at:u64, size:u64, role:u64) -> u64:
    if size < 128 or ui_span(length(s), at, size) == 0:
        return 0
    if read64(s, at) != UI_CAPSULE or read64(s, at + 8) != role:
        return 0
    if read64(s, at + 16) == 0 or read64(s, at + 24) == 0 or read64(s, at + 32) == 0:
        return 0
    if read64(s, at + 40) > 4294967295 or read64(s, at + 72) == 0 or read64(s, at + 104) == 0:
        return 0
    if read64(s, at + 80) != 1 or read64(s, at + 88) != choose(role == 8, 1, 0):
        return 0
    if read64(s, at + 96) != 0:
        return 0
    left = size - 128
    first = read64(s, at + 48)
    second = read64(s, at + 56)
    if first == 0 or first > left:
        return 0
    left = left - first
    if second > left:
        return 0
    return choose(read64(s, at + 64) == left - second, 1, 0)

def ui_begin_shape(s:readbuf) -> u64:
    if (read64(s, 16) | read64(s, 24)) == 0 or read64(s, 32) == 0:
        return 0
    if read64(s, 40) == 0 or read64(s, 48) == 0 or read64(s, 56) == 0:
        return 0
    if read64(s, 64) == 0 or read64(s, 72) == 0 or read64(s, 64) == read64(s, 40):
        return 0
    left = length(s) - 256
    parent = read64(s, 88)
    if parent > left or read64(s, 96) != left - parent:
        return 0
    at = 104
    while at < 256:
        if read64(s, at) != 0:
            return 0
        at = at + 8
    if ui_capsule(s, 256, parent, 7) == 0:
        return 0
    fs = 256 + parent
    if ui_capsule(s, fs, read64(s, 96), 6) == 0:
        return 0
    if read64(s, 360) != read64(s, 56) or read64(s, fs + 104) != read64(s, 56):
        return 0
    if read64(s, 272) == read64(s, fs + 16):
        return 0
    if read64(s, 272) == read64(s, 40) or read64(s, 272) == read64(s, 64):
        return 0
    if read64(s, fs + 16) == read64(s, 40) or read64(s, fs + 16) == read64(s, 64):
        return 0
    if ui_parent(s, 256) == 0 or ui_fs_ready(s, fs) == 0:
        return 0
    return 1

def ui_parent(s:readbuf, cap:u64) -> u64:
    if read64(s, cap + 40) != 1 or read64(s, cap + 56) < 512 or read64(s, cap + 64) < 4096:
        return 0
    out = cap + 128 + read64(s, cap + 48)
    work = out + read64(s, cap + 56)
    if read64(s, out) != UI_PARENT or read64(s, out + 8) != 1:
        return 0
    if read64(s, out + 128) < 256 or read64(s, out + 128) > read64(s, cap + 56) - 256:
        return 0
    if read64(s, work) != UI_PARENT or read64(s, work + 8) != 2:
        return 0
    at = 16
    while at < 64:
        if read64(s, out + at) != read64(s, work + at):
            return 0
        at = at + 8
    if read64(s, out + 32) == 0 or read64(s, out + 40) == 0 or read64(s, out + 248) == 0:
        return 0
    if read64(s, out + 48) < 1 or read64(s, out + 48) > 18:
        return 0
    q = out + 256
    if read64(s, q) != UI_PENDING or read64(s, q + 8) != 1:
        return 0
    at = 16
    while at < 64:
        if read64(s, q + at) != read64(s, out + at):
            return 0
        at = at + 8
    if read64(s, q + 112) != read64(s, out + 128) - 256:
        return 0
    if read64(s, q + 128) != read64(s, out + 248) or read64(s, q + 176) != read64(s, cap + 104):
        return 0
    if read64(s, q + 184) != read64(s, out + 72):
        return 0
    at = 192
    while at < 256:
        if read64(s, q + at) != 0:
            return 0
        at = at + 8
    return 1

def ui_fs_ready(s:readbuf, cap:u64) -> u64:
    if read64(s, cap + 40) != 0 or read64(s, cap + 56) < 256 or read64(s, cap + 64) < 4096:
        return 0
    out = cap + 128 + read64(s, cap + 48)
    work = out + read64(s, cap + 56)
    if read64(s, out) != UI_JOIN or read64(s, out + 8) != 0:
        return 0
    if read64(s, out + 128) > read64(s, cap + 56) - 256:
        return 0
    if read64(s, work) != UI_JOIN or read64(s, work + 8) != 1:
        return 0
    at = 16
    while at < 48:
        if read64(s, out + at) != read64(s, work + at):
            return 0
        at = at + 8
    return choose(read64(s, work + 56) >= 4096 and read64(s, work + 56) <= read64(s, cap + 64), 1, 0)

def ui_begin(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if ui_begin_shape(s) == 0:
        return ui_refuse(o, w, 4)
    if get(w, 8) == 1 and get(w, 0) == UI_MAGIC:
        if length(s) != get(w, 72):
            return ui_refuse(o, w, 5)
        at = 0
        while at < 256:
            if read64(s, at) != get(w, 512 + at):
                return ui_refuse(o, w, 5)
            at = at + 8
        return ui_prepare(s, o, w)
    p = 256
    f = p + read64(s, 88)
    po = p + 128 + read64(s, p + 48)
    if get(w, 0) == 0:
        at = 0
        while at < 1024:
            if get(w, at) != 0:
                return ui_refuse(o, w, 6)
            at = at + 8
        if read64(s, 32) != 1 or read64(s, 80) != 0:
            return ui_refuse(o, w, 6)
    else:
        if get(w, 0) != UI_MAGIC or (get(w, 8) != 5 and get(w, 8) != 6):
            return ui_refuse(o, w, 6)
        if get(w, 32) == 18446744073709551615 or read64(s, 32) != get(w, 32) + 1:
            return ui_refuse(o, w, 7)
        at = 16
        while at < 64:
            if at != 32 and read64(s, at) != get(w, at):
                return ui_refuse(o, w, 7)
            at = at + 8
        if read64(s, 64) != get(w, 144) or read64(s, 72) != get(w, 152) or read64(s, 80) != get(w, 160):
            return ui_refuse(o, w, 7)
        if read64(s, p + 16) != get(w, 80) or read64(s, p + 24) != get(w, 88) or read64(s, p + 32) <= get(w, 96):
            return ui_refuse(o, w, 7)
        if read64(s, po + 32) < get(w, 104):
            return ui_refuse(o, w, 7)
        if read64(s, po + 32) == get(w, 104) and read64(s, po + 40) <= get(w, 112):
            return ui_refuse(o, w, 7)
        if read64(s, f + 16) != get(w, 120) or read64(s, f + 24) != get(w, 128) or read64(s, f + 32) < get(w, 136):
            return ui_refuse(o, w, 7)
    previous_framer_call = get(w, 352)
    ui_zero(w, 0, 512)
    put(w, 352, previous_framer_call)
    put(w, 0, UI_MAGIC)
    put(w, 8, 1)
    copy_input(w, s, 16, 16, 48)
    put(w, 72, length(s))
    put(w, 80, read64(s, p + 16))
    put(w, 88, read64(s, p + 24))
    put(w, 96, read64(s, p + 32))
    put(w, 104, read64(s, po + 32))
    put(w, 112, read64(s, po + 40))
    put(w, 120, read64(s, f + 16))
    put(w, 128, read64(s, f + 24))
    put(w, 136, read64(s, f + 32))
    put(w, 144, read64(s, 64))
    put(w, 152, read64(s, 72))
    put(w, 160, read64(s, 80))
    put(w, 168, read64(s, po + 248))
    put(w, 328, read64(s, po + 48))
    put(w, 336, read64(s, po + 408))
    put(w, 344, read64(s, po + 416))
    copy_input(w, s, 512, 0, 256)
    return ui_prepare(s, o, w)

def ui_raw(op:u64) -> u64:
    return choose(op == 1 or op == 8 or op == 9 or op == 10 or op == 11 or op == 14 or op == 15 or op == 16, 1, 0)

def ui_prepare(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    p = 256
    f = p + read64(s, 88)
    po = p + 128 + read64(s, p + 48)
    logical = 256 + read64(s, po + 128)
    alen = 128 + logical
    boff = ui_align(1024, alen)
    if boff == 0 or read64(s, f + 64) > 18446744073709551487:
        return ui_refuse(o, w, 8)
    blen = 128 + read64(s, f + 64)
    end = ui_align(boff, blen)
    if end == 0:
        return ui_refuse(o, w, 8)
    put(w, 296, end)
    if length(w) < end:
        return ui_emit(o, w, 2)
    put(w, 176, end)
    put(w, 184, 1024)
    put(w, 192, alen)
    put(w, 200, boff)
    put(w, 208, blen)
    ui_zero(w, 1024, 128)
    put(w, 1024, UI_FRAMER)
    put(w, 1032, 1)
    put(w, 1040, get(w, 16))
    put(w, 1048, get(w, 24))
    put(w, 1056, 0)
    put(w, 1064, logical)
    put(w, 1072, get(w, 168))
    put(w, 1080, get(w, 120))
    copy_input(w, s, 1152, po, logical)
    ui_peer_header(s, f, w, boff, 1)
    fw = f + 128 + read64(s, f + 48) + read64(s, f + 56)
    copy_input(w, s, boff + 128, fw, read64(s, f + 64))
    if ui_raw(get(w, 328)) == 0:
        put(w, 8, 6)
        put(w, 304, 1152)
        put(w, 312, logical)
        return ui_emit(o, w, 3)
    if get(w, 352) == 18446744073709551615:
        return ui_refuse(o, w, 20)
    put(w, 352, get(w, 352) + 1)
    put(w, 1056, get(w, 352))
    put(w, 8, 2)
    return ui_issue(o, w, 8, 1024, alen, boff, blen, 512)

def ui_peer_header(s:readbuf, cap:u64, w:mutbuf, at:u64, command:u64) -> u64:
    ui_zero(w, at, 128)
    put(w, at, UI_FRAMER_PEER)
    put(w, at + 8, command)
    put(w, at + 32, read64(s, cap + 64))
    put(w, at + 40, read64(s, cap + 16))
    put(w, at + 48, read64(s, cap + 24))
    put(w, at + 56, read64(s, cap + 40))
    put(w, at + 64, read64(s, cap + 72))
    put(w, at + 72, read64(s, cap + 32))
    put(w, at + 80, read64(s, cap + 104))
    return 0

def ui_issue(o:mutbuf, w:mutbuf, role:u64, first:u64, first_n:u64, second:u64, second_n:u64, work_n:u64) -> u32:
    if get(w, 64) == 18446744073709551615:
        return ui_refuse(o, w, 9)
    if ui_span(length(w), first, first_n) == 0 or ui_span(length(w), second, second_n) == 0:
        return ui_refuse(o, w, 9)
    put(w, 64, get(w, 64) + 1)
    put(w, 216, role)
    put(w, 224, first)
    put(w, 232, first_n)
    put(w, 240, second)
    put(w, 248, second_n)
    put(w, 288, work_n)
    if role == 8:
        put(w, 256, get(w, 144))
        put(w, 264, get(w, 152))
        put(w, 272, get(w, 160))
        put(w, 280, second_n)
    elif role == 6:
        put(w, 256, get(w, 120))
        put(w, 264, get(w, 128))
        put(w, 272, get(w, 136))
        put(w, 280, 256)
    else:
        return ui_refuse(o, w, 9)
    return ui_emit(o, w, 1)

def ui_child_shape(s:readbuf, w:mutbuf) -> u64:
    at = 16
    while at < 64:
        if read64(s, at) != get(w, at):
            return 0
        at = at + 8
    if read64(s, 64) != get(w, 64) or read64(s, 72) != length(s) - 256:
        return 0
    at = 80
    while at < 256:
        if read64(s, at) != 0:
            return 0
        at = at + 8
    if ui_capsule(s, 256, read64(s, 72), get(w, 216)) == 0:
        return 0
    if read64(s, 272) != get(w, 256) or read64(s, 280) != get(w, 264) or read64(s, 288) <= get(w, 272):
        return 0
    if read64(s, 360) != get(w, 56) or read64(s, 368) != get(w, 64) or read64(s, 376) != get(w, 32):
        return 0
    if read64(s, 304) != get(w, 232):
        return 0
    at = 0
    while at < get(w, 232):
        if byte(s, 384 + at) != byte(w, get(w, 224) + at):
            return 0
        at = at + 1
    if get(w, 216) == 8:
        if read64(s, 312) != get(w, 248):
            return 0
        start = 384 + read64(s, 304)
        at = 0
        while at < get(w, 248):
            if byte(s, start + at) != byte(w, get(w, 240) + at):
                return 0
            at = at + 1
    return 1

def ui_steady(w:mutbuf) -> u64:
    if get(w, 0) != UI_MAGIC or get(w, 8) < 2 or get(w, 8) > 4:
        return 0
    if (get(w, 16) | get(w, 24)) == 0 or get(w, 32) == 0 or get(w, 64) == 0:
        return 0
    if get(w, 40) == 0 or get(w, 48) == 0 or get(w, 56) == 0 or get(w, 168) == 0 or get(w, 352) == 0:
        return 0
    used = get(w, 176)
    if used < 1024 or used > length(w) or (used & 7) != 0:
        return 0
    first = get(w, 184)
    if first < 1024 or get(w, 192) < 640 or ui_span(used, first, get(w, 192)) == 0:
        return 0
    if get(w, 200) < 1024 or get(w, 208) < 128 or ui_span(used, get(w, 200), get(w, 208)) == 0:
        return 0
    if get(w, first) != UI_FRAMER or get(w, first + 8) != choose(get(w, 8) == 4, 2, 1):
        return 0
    if get(w, first + 16) != get(w, 16) or get(w, first + 24) != get(w, 24) or get(w, first + 32) != get(w, 352):
        return 0
    if get(w, first + 40) != get(w, 192) - 128 or get(w, first + 48) != get(w, 168) or get(w, first + 56) != get(w, 120):
        return 0
    if get(w, 224) < 1024 or ui_span(used, get(w, 224), get(w, 232)) == 0:
        return 0
    if get(w, 8) == 3:
        if get(w, 216) != 6 or get(w, 232) < 640 or (get(w, 240) | get(w, 248)) != 0:
            return 0
        if get(w, 256) != get(w, 120) or get(w, 264) != get(w, 128) or get(w, 272) != get(w, 136):
            return 0
        return choose(get(w, 280) == 256 and get(w, 288) == 4096, 1, 0)
    if get(w, 216) != 8 or get(w, 224) != first or get(w, 232) != get(w, 192):
        return 0
    if get(w, 240) != get(w, 200) or get(w, 248) != get(w, 208):
        return 0
    if get(w, 256) != get(w, 144) or get(w, 264) != get(w, 152) or get(w, 272) != get(w, 160):
        return 0
    return choose(get(w, 280) == get(w, 208) and get(w, 288) >= 512, 1, 0)

def ui_completed(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if ui_steady(w) == 0 or ui_child_shape(s, w) == 0:
        return ui_refuse(o, w, 10)
    if get(w, 216) == 6:
        if get(w, 8) != 3:
            return ui_refuse(o, w, 10)
        return ui_fs_completed(s, o, w)
    if get(w, 216) != 8 or (get(w, 8) != 2 and get(w, 8) != 4):
        return ui_refuse(o, w, 10)
    cap = 256
    work = 384 + read64(s, 304) + read64(s, 312)
    size = read64(s, 320)
    if size < 512 or read64(s, work) != UI_FRAMER:
        return ui_refuse(o, w, 11)
    status = read64(s, 296)
    if read64(s, work + 256) != UI_FRAMER_EVENT or read64(s, work + 264) != status or read64(s, work + 272) != get(w, 352):
        return ui_refuse(o, w, 11)
    if read64(s, work + 344) != 0:
        return ui_refuse(o, w, 11)
    if status == 2:
        if get(w, 8) != 2 or read64(s, work + 8) != 1 or read64(s, work + 320) <= size:
            return ui_refuse(o, w, 12)
        put(w, 160, read64(s, cap + 32))
        return ui_issue(o, w, 8, get(w, 184), get(w, 192), get(w, 200), get(w, 208), read64(s, work + 320))
    if ui_framer_result(s, work, w) == 0:
        return ui_refuse(o, w, 13)
    if status == 1 and get(w, 8) == 2:
        if read64(s, work + 8) != 2:
            return ui_refuse(o, w, 13)
        return ui_fs_request(s, o, w, work, size)
    if status == 0 and get(w, 8) == 4:
        if read64(s, work + 8) != 3:
            return ui_refuse(o, w, 13)
        return ui_ack(s, o, w, work, size)
    return ui_refuse(o, w, 13)

def ui_framer_result(s:readbuf, at:u64, w:mutbuf) -> u64:
    if read64(s, at + 16) != get(w, 16) or read64(s, at + 24) != get(w, 24) or read64(s, at + 32) != get(w, 352):
        return 0
    if read64(s, at + 280) != get(w, 104) or read64(s, at + 288) != get(w, 112) or read64(s, at + 296) != get(w, 328):
        return 0
    if read64(s, at + 328) != get(w, 168) or read64(s, at + 336) != get(w, 120):
        return 0
    if get(w, 336) == 18446744073709551615 or get(w, 344) == 18446744073709551615:
        return 0
    if read64(s, at + 368) != get(w, 336) + 1 or read64(s, at + 376) != get(w, 344) + 1:
        return 0
    return 1

def ui_fs_request(s:readbuf, o:mutbuf, w:mutbuf, work:u64, size:u64) -> u32:
    offset = read64(s, work + 304)
    amount = read64(s, work + 312)
    if offset < 512 or amount < 640 or ui_span(size, offset, amount) == 0:
        return ui_refuse(o, w, 14)
    start = work + offset
    if read64(s, start) != UI_FS_CHANNEL or read64(s, start + 8) != 1 or read64(s, start + 32) != amount - 128:
        return ui_refuse(o, w, 14)
    if read64(s, start + 128) != UI_JOIN:
        return ui_refuse(o, w, 14)
    at = get(w, 176)
    end = ui_align(at, amount)
    if end == 0:
        return ui_refuse(o, w, 15)
    put(w, 296, end)
    if length(w) < end:
        return ui_emit(o, w, 2)
    copy_input(w, s, at, start, amount)
    put(w, 176, end)
    put(w, 160, read64(s, 288))
    put(w, 8, 3)
    return ui_issue(o, w, 6, at, amount, 0, 0, 4096)

def ui_fs_completed(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    cap = 256
    if ui_fs_ready(s, cap) == 0:
        return ui_refuse(o, w, 16)
    first = read64(s, 304)
    out = 384 + first
    work = out + read64(s, 312)
    logical = 256 + read64(s, out + 128)
    if logical < 512:
        return ui_refuse(o, w, 16)
    if first > 18446744073709551487:
        return ui_refuse(o, w, 17)
    size = 128 + first
    if logical > 18446744073709551615 - size:
        return ui_refuse(o, w, 17)
    size = size + logical
    if read64(s, 320) > 18446744073709551615 - size:
        return ui_refuse(o, w, 17)
    size = size + read64(s, 320)
    at = get(w, 176)
    end = ui_align(at, size)
    if end == 0:
        return ui_refuse(o, w, 17)
    put(w, 296, end)
    if length(w) < end:
        return ui_emit(o, w, 2)
    ui_peer_header(s, cap, w, at, 2)
    put(w, at + 16, first)
    put(w, at + 24, logical)
    copy_input(w, s, at + 128, 384, first)
    copy_input(w, s, at + 128 + first, out, logical)
    copy_input(w, s, at + 128 + first + logical, work, read64(s, 320))
    put(w, get(w, 184) + 8, 2)
    put(w, 200, at)
    put(w, 208, size)
    put(w, 176, end)
    put(w, 136, read64(s, 288))
    put(w, 8, 4)
    return ui_issue(o, w, 8, get(w, 184), get(w, 192), at, size, 512)

def ui_ack_shape(s:readbuf, ack:u64, w:mutbuf) -> u64:
    if read64(s, ack) != UI_PARENT or read64(s, ack + 8) != 2:
        return 0
    parent = get(w, 184) + 128
    at = 16
    while at < 64:
        if read64(s, ack + at) != get(w, parent + at):
            return 0
        at = at + 8
    if read64(s, ack + 120) != get(w, 336) + 1 or read64(s, ack + 128) != get(w, 344) + 1:
        return 0
    if read64(s, ack + 144) != 6 or read64(s, ack + 152) != get(w, 120) or read64(s, ack + 160) != get(w, 128):
        return 0
    if read64(s, ack + 168) != get(w, 136) or read64(s, ack + 176) != get(w, 168):
        return 0
    if read64(s, ack + 136) != 0:
        return 0
    at = 184
    while at < 256:
        if read64(s, ack + at) != 0:
            return 0
        at = at + 8
    at = 0
    while at < 256:
        if read64(s, ack + 256 + at) != get(w, parent + 256 + at):
            return 0
        at = at + 8
    return 1

def ui_ack(s:readbuf, o:mutbuf, w:mutbuf, work:u64, size:u64) -> u32:
    offset = read64(s, work + 304)
    if read64(s, work + 312) != 512 or offset < 512 or ui_span(size, offset, 512) == 0:
        return ui_refuse(o, w, 18)
    ack = work + offset
    if ui_ack_shape(s, ack, w) == 0:
        return ui_refuse(o, w, 18)
    at = get(w, 176)
    end = ui_align(at, 512)
    if end == 0:
        return ui_refuse(o, w, 19)
    put(w, 296, end)
    if length(w) < end:
        return ui_emit(o, w, 2)
    copy_input(w, s, at, ack, 512)
    put(w, 176, end)
    put(w, 304, at)
    put(w, 312, 512)
    put(w, 160, read64(s, 288))
    put(w, 8, 5)
    return ui_emit(o, w, 0)

def ui_refuse(o:mutbuf, w:mutbuf, reason:u64) -> u32:
    if get(w, 0) != UI_BAD:
        put(w, 320, reason)
    put(w, 0, UI_BAD)
    put(w, 8, 7)
    return ui_emit(o, w, 4294967293)

def ui_emit(o:mutbuf, w:mutbuf, status:u64) -> u32:
    if length(o) < 256:
        return 4294967293
    ui_zero(o, 0, 256)
    put(o, 0, UI_EVENT)
    put(o, 8, status)
    copy_workspace(o, w, 16, 16, 56)
    put(o, 72, get(w, 8))
    put(o, 80, get(w, 216))
    put(o, 88, get(w, 224))
    put(o, 96, get(w, 232))
    put(o, 104, get(w, 240))
    put(o, 112, get(w, 248))
    put(o, 120, get(w, 256))
    put(o, 128, get(w, 264))
    put(o, 136, get(w, 272))
    put(o, 144, get(w, 280))
    put(o, 152, get(w, 288))
    put(o, 160, get(w, 296))
    put(o, 168, 256)
    put(o, 176, get(w, 304))
    put(o, 184, get(w, 312))
    put(o, 192, get(w, 320))
    put(o, 200, get(w, 328))
    put(o, 208, get(w, 80))
    put(o, 216, get(w, 88))
    put(o, 224, get(w, 96))
    put(o, 232, get(w, 104))
    put(o, 240, get(w, 112))
    return status
'''

def source_program():
    source=POLICY
    for name,value in CONSTANTS.items():
        source=source.replace(name,str(value))
    return source+VALUES[VALUES.index("\ndef read64("):]

def document():
    nodes=ast.parse(source_program()).body
    names={node.name:"f"+str(index) for index,node in enumerate(nodes)}
    if len(names)!=len(nodes):
        raise ValueError("duplicate unixOpen issued raw-join symbol")
    signatures={node.name:([a.annotation.id for a in node.args.args],node.returns.id) for node in nodes}
    total=total_scalar_functions(nodes)
    functions=[]
    for node in nodes:
        b=ObjectBuilder(node,names,signatures,total)
        b.statements(node.body)
        functions.append({"name":names[node.name],"params":[b.param(v) for v in b.params],
            "returns":[b.returns],"effects":["read","write","trap"],"entry":"b0","blocks":b.blocks})
    return compact_authoring_cfg({"schema":"hepta.hia.program.v8",
        "module":"agent_namespace_unixopen_issued_raw_join_r2","functions":functions})

if __name__=="__main__":
    destination=ROOT/"examples/hia_bootstrap/agent_namespace_unixopen_issued_raw_join_r2.hiaasm"
    destination.write_text(render_assembly(document()))
    print(destination.name,destination.stat().st_size)
