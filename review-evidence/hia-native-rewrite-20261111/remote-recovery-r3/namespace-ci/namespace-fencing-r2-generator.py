"""NEW fixed namespace fencing continuation owner, source-only draft r2.

The image joins actual FS and inode owners through a mechanical private
dispatcher. The dispatcher wraps ordinary source and actual child results in
different, non-client-forgeable channels; byte headers alone are not authority.
WAL DMS/open-root/migration/complete Store remain separate unfinished stages.
"""
from __future__ import annotations
import ast
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_agent_namespace_objects import ObjectBuilder
from tools.generate_hia_agent_namespace_store import VALUES
from tools.generate_hia_selfhost import compact_authoring_cfg,total_scalar_functions
ROOT=Path(__file__).resolve().parents[1]
MAGIC=int.from_bytes(b"HIANFC01","little")
BAD=int.from_bytes(b"HIANFB01","little")
CHANNEL=int.from_bytes(b"HIANFX01","little")
FS_MAGIC=int.from_bytes(b"HIANFR03","little")
INODE_MAGIC=int.from_bytes(b"HIANIR01","little")
BRIDGE=r'''
def fencing(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < 1536:
        if length(w) >= 8:
            put(w, 0, FENCE_BAD)
        return 4294967293
    if get(w, 0) == FENCE_BAD:
        return fence_emit(o, w, 4294967293, 0)
    if length(o) < 256:
        fence_poison(w, 1)
        return 4294967293
    if length(s) < 64 or read64(s, 0) != FENCE_CHANNEL:
        return fence_reject(o, w, 2)
    origin = read64(s, 8)
    if origin == 1:
        if read64(s, 16) != 0 or read64(s, 24) != 0 or read64(s, 32) != length(s) - 64:
            return fence_reject(o, w, 3)
        if (read64(s, 40) | read64(s, 48) | read64(s, 56)) != 0:
            return fence_reject(o, w, 3)
        if length(s) < 320 or read64(s, 64) != FENCE_MAGIC or read64(s, 152) != length(s) - 320:
            return fence_reject(o, w, 4)
        at = 160
        while at < 320:
            if read64(s, at) != 0:
                return fence_reject(o, w, 5)
            at = at + 8
        if get(w, 0) == 0:
            at = 0
            while at < 1536:
                if byte(w, at) != 0:
                    return fence_reject(o, w, 6)
                at = at + 1
            if read64(s, 72) != 1 or length(s) != 320 or (read64(s, 80) | read64(s, 88)) == 0:
                return fence_reject(o, w, 7)
            at = 96
            while at < 320:
                if read64(s, at) != 0:
                    return fence_reject(o, w, 7)
                at = at + 8
            put(w, 0, FENCE_MAGIC)
            put(w, 8, 3)
            put(w, 16, read64(s, 80))
            put(w, 24, read64(s, 88))
            put(w, 128, 256)
            put(w, 136, 912)
            put(w, 144, 512)
            put(w, 192, 10)
            put(w, 232, 512)
            copy_input(w, s, 320, 64, 256)
        elif fence_steady(w) == 0:
            return fence_reject(o, w, 8)
        if read64(s, 80) != get(w, 16) or read64(s, 88) != get(w, 24):
            return fence_reject(o, w, 9)
        if get(w, 8) == 1:
            if read64(s, 72) != 2 or read64(s, 96) == 0 or get(w, 32) == 18446744073709551615:
                return fence_reject(o, w, 10)
            if read64(s, 96) != get(w, 32) + 1 or read64(s, 144) == 0:
                return fence_reject(o, w, 10)
            if fence_client_shape(s) == 0:
                return fence_reject(o, w, 11)
            put(w, 32, read64(s, 96))
            put(w, 40, read64(s, 104))
            put(w, 48, read64(s, 144))
            put(w, 128, length(s) - 64)
            put(w, 136, length(s) - 64)
            if get(w, 136) < 912:
                put(w, 136, 912)
            put(w, 240, get(w, 160))
            if get(w, 40) == 1 and get(w, 168) == get(w, 160):
                if get(w, 160) > 2305843009213693935:
                    return fence_reject(o, w, 12)
                put(w, 240, get(w, 160) + 16)
            put(w, 232, get(w, 144))
            put(w, 8, 3)
            put(w, 192, 30)
            put(w, 176, 0)
            put(w, 184, read64(s, 112))
            put(w, 248, 0)
            copy_input(w, s, 320, 64, 256)
        if get(w, 8) != 3 or length(s) - 64 != get(w, 128):
            return fence_reject(o, w, 13)
        at = 0
        while at < 256:
            if byte(s, 64 + at) != byte(w, 320 + at):
                return fence_reject(o, w, 13)
            at = at + 1
        return fence_prepare_client(s, o, w)
    if origin != 2 or get(w, 0) != FENCE_MAGIC:
        return fence_reject(o, w, 14)
    if fence_steady(w) == 0 or (get(w, 8) != 2 and get(w, 8) != 4):
        return fence_reject(o, w, 15)
    if fence_child_frame(s, w) == 0:
        return fence_reject(o, w, 16)
    if get(w, 8) == 4:
        at = 0
        while at < 64:
            if read64(s, at) != get(w, 256 + at):
                return fence_reject(o, w, 17)
            at = at + 8
    return fence_accept_child(s, o, w)

def fence_client_shape(s:readbuf) -> u64:
    operation = read64(s, 104)
    handle = read64(s, 112)
    a = read64(s, 120)
    b = read64(s, 128)
    c = read64(s, 136)
    size = read64(s, 152)
    if operation == 1:
        if handle != 0 or a > 4294967295 or b > 4294967295 or c != 0 or size == 0:
            return 0
        return 1
    if operation == 2 or operation == 3:
        if handle == 0 or size != 0 or (a != 1 and a != 2):
            return 0
        if b >= 8 or c == 0 or c > 8 - b or (a == 1 and c != 1):
            return 0
        return 1
    if operation == 4:
        if handle == 0 or (a | b | c | size) != 0:
            return 0
        return 1
    return 0

def fence_snapshot_base(w:mutbuf) -> u64:
    return 1536 + get(w, 160) * 8

def fence_original_base(w:mutbuf) -> u64:
    return fence_snapshot_base(w) + get(w, 144)

def fence_child_base(w:mutbuf) -> u64:
    return fence_original_base(w) + get(w, 128)

def fence_required(w:mutbuf, orphan_cap:u64, snapshot_cap:u64) -> u64:
    if orphan_cap > 2305843009213693759:
        return 0
    size = 1536 + orphan_cap * 8
    if snapshot_cap > 18446744073709551615 - size:
        return 0
    size = size + snapshot_cap
    if get(w, 128) > 18446744073709551615 - size:
        return 0
    size = size + get(w, 128)
    if get(w, 136) > 18446744073709551615 - size:
        return 0
    return size + get(w, 136)

def fence_steady(w:mutbuf) -> u64:
    if get(w, 0) != FENCE_MAGIC or (get(w, 16) | get(w, 24)) == 0:
        return 0
    phase = get(w, 8)
    if phase != 1 and phase != 2 and phase != 3 and phase != 4:
        return 0
    if get(w, 128) < 256 or get(w, 136) < get(w, 128) or get(w, 136) < 912:
        return 0
    if get(w, 144) < 512 or get(w, 152) > get(w, 144) or get(w, 168) > get(w, 160):
        return 0
    if get(w, 160) > 2305843009213693759 or get(w, 160) > (length(w) - 1536) >> 3:
        return 0
    if get(w, 1088) != 0:
        return 0
    i = 0
    while i < get(w, 168):
        if get(w, 1536 + i * 8) == 0:
            return 0
        j = 0
        while j < i:
            if get(w, 1536 + j * 8) == get(w, 1536 + i * 8):
                return 0
            j = j + 1
        i = i + 1
    if get(w, 8) != 3:
        need = fence_required(w, get(w, 160), get(w, 144))
        if need == 0 or need > length(w):
            return 0
    if phase == 2 or phase == 4:
        if (get(w, 56) != 1 and get(w, 56) != 2) or get(w, 64) == 0:
            return 0
        if get(w, 72) < 256 or get(w, 72) > get(w, 136):
            return 0
    if get(w, 152) != 0:
        base = fence_snapshot_base(w)
        if get(w, 152) < 512 or base > length(w) or get(w, 152) > length(w) - base:
            return 0
        if get(w, base) != INODE_MAGIC or get(w, base + 16) != get(w, 16) or get(w, base + 24) != get(w, 24):
            return 0
        cap = get(w, base + 56)
        if get(w, base + 232) != 1 or cap > 192153584101141157:
            return 0
        if cap * 96 > get(w, 152) - 512 or get(w, base + 64) > cap:
            return 0
        if get(w, base + 8) != 1 and get(w, base + 8) != 2:
            return 0
    return 1

def fence_prepare_client(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    need = fence_required(w, get(w, 240), get(w, 232))
    if need == 0 or get(w, 136) > 18446744073709551359:
        return fence_reject(o, w, 18)
    needo = 256 + get(w, 136)
    if length(w) < need or length(o) < needo:
        put(w, 216, need)
        put(w, 224, needo)
        return fence_emit(o, w, 2, 0)
    oldbase = fence_snapshot_base(w)
    newbase = 1536 + get(w, 240) * 8
    if get(w, 152) != 0 and newbase != oldbase:
        move_workspace(w, newbase, oldbase, get(w, 152))
    at = get(w, 160)
    while at < get(w, 240):
        put(w, 1536 + at * 8, 0)
        at = at + 1
    put(w, 160, get(w, 240))
    put(w, 144, get(w, 232))
    put(w, 216, 0)
    put(w, 224, 0)
    copy_input(w, s, fence_original_base(w), 64, get(w, 128))
    if get(w, 192) == 10:
        fence_zero(o, 256, 256)
        put(o, 256, FS_MAGIC)
        put(o, 264, 1)
        put(o, 272, get(w, 16))
        put(o, 280, get(w, 24))
        copy_workspace(w, o, 576, 256, 256)
        return fence_issue(o, w, 1, 256)
    if get(w, 40) == 1:
        put(w, 192, 30)
        original = fence_original_base(w)
        return fence_fs(o, w, 1, 0, get(w, original + 56), get(w, original + 64), 0, get(w, 48), original + 256, get(w, 128) - 256)
    put(w, 192, 50)
    original = fence_original_base(w)
    command = get(w, 40) + 1
    if get(w, 40) == 4:
        command = 5
    return fence_inode(o, w, command, get(w, 184), get(w, original + 56), get(w, original + 64), get(w, original + 72))

def fence_child_frame(s:readbuf, w:mutbuf) -> u64:
    role = read64(s, 16)
    if role != get(w, 56) or read64(s, 32) != get(w, 72):
        return 0
    input_size = read64(s, 32)
    output_size = read64(s, 40)
    work_size = read64(s, 48)
    if output_size < 256 or work_size < 512 or input_size > length(s) - 64:
        return 0
    remaining = length(s) - 64 - input_size
    if output_size > remaining or work_size != remaining - output_size:
        return 0
    serial = get(w, 96)
    if role == 2:
        serial = get(w, 112)
    if read64(s, 56) <= serial:
        return 0
    at = 0
    base = fence_child_base(w)
    while at < input_size:
        if byte(s, 64 + at) != byte(w, base + at):
            return 0
        at = at + 1
    out = 64 + input_size
    if read64(s, out + 8) != read64(s, 24):
        return 0
    if read64(s, out + 16) != get(w, 16) or read64(s, out + 24) != get(w, 24):
        return 0
    if role == 1:
        if read64(s, out) != FS_MAGIC or read64(s, out + 176) != 3:
            return 0
        if read64(s, out + 32) != get(w, 80) or read64(s, out + 48) != get(w, 624):
            return 0
        if read64(s, out + 112) != get(w, 680):
            return 0
        if read64(s, out + 128) > output_size - 256:
            return 0
        if read64(s, 24) != 0 and read64(s, 24) != 4294967293:
            return 0
    else:
        if read64(s, out) != INODE_MAGIC or read64(s, out + 176) != 1:
            return 0
        if read64(s, out + 32) != get(w, 104):
            return 0
        if read64(s, 24) != 0 and read64(s, 24) != 1 and read64(s, 24) != 4294967293:
            return 0
    return 1

def fence_accept_child(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    role = get(w, 56)
    out = 64 + read64(s, 32)
    work = out + read64(s, 40)
    if read64(s, 24) == 4294967293:
        return fence_reject(o, w, 19)
    if role == 2:
        if read64(s, work) != INODE_MAGIC or read64(s, work + 16) != get(w, 16) or read64(s, work + 24) != get(w, 24):
            return fence_reject(o, w, 20)
        cap = read64(s, work + 56)
        if read64(s, work + 232) != 1 or cap > 192153584101141157:
            return fence_reject(o, w, 20)
        if cap * 96 > read64(s, 48) - 512 or read64(s, work + 64) > cap:
            return fence_reject(o, w, 20)
        if read64(s, work + 32) != get(w, 104) or read64(s, work + 8) != read64(s, out + 112):
            return fence_reject(o, w, 20)
        nextcap = get(w, 144)
        if read64(s, 48) > nextcap:
            nextcap = read64(s, 48)
        need = fence_required(w, get(w, 160), nextcap)
        if need == 0:
            return fence_reject(o, w, 21)
        if length(w) < need:
            put(w, 8, 4)
            put(w, 216, need)
            put(w, 224, length(o))
            put(w, 232, nextcap)
            copy_input(w, s, 256, 0, 64)
            return fence_emit(o, w, 2, 0)
        if nextcap != get(w, 144):
            old_original = fence_original_base(w)
            old_child = fence_child_base(w)
            delta = nextcap - get(w, 144)
            move_workspace(w, old_child + delta, old_child, get(w, 72))
            move_workspace(w, old_original + delta, old_original, get(w, 128))
            put(w, 144, nextcap)
        copy_input(w, s, fence_snapshot_base(w), work, read64(s, 48))
        put(w, 152, read64(s, 48))
        put(w, 112, read64(s, 56))
        put(w, 216, 0)
        put(w, 224, 0)
        put(w, 8, 2)
        return fence_inode_reply(s, o, w, out)
    if read64(s, out + 120) != 1 or read64(s, out + 56) > 4095:
        return fence_reject(o, w, 22)
    if read64(s, work) != FS_MAGIC or read64(s, work + 8) != 1 or read64(s, work + 248) != 3:
        return fence_reject(o, w, 22)
    if read64(s, work + 16) != get(w, 16) or read64(s, work + 24) != get(w, 24):
        return fence_reject(o, w, 22)
    if read64(s, work + 32) != get(w, 80) or read64(s, work + 40) != read64(s, out + 40):
        return fence_reject(o, w, 22)
    if read64(s, work + 72) != read64(s, out + 160) or read64(s, work + 64) != read64(s, out + 168):
        return fence_reject(o, w, 22)
    at = 200
    while at < 256:
        if read64(s, out + at) != 0:
            return fence_reject(o, w, 22)
        at = at + 8
    if read64(s, out + 56) != 0 and read64(s, out + 128) != 0:
        return fence_reject(o, w, 22)
    if get(w, 192) == 10:
        if read64(s, out + 40) != 0 or read64(s, out + 56) != 0:
            return fence_reject(o, w, 23)
    else:
        if get(w, 88) == 18446744073709551615 or read64(s, out + 40) != get(w, 88) + 1:
            return fence_reject(o, w, 24)
    put(w, 96, read64(s, 56))
    put(w, 88, read64(s, out + 40))
    return fence_fs_reply(s, o, w, out)

def fence_fs_reply(s:readbuf, o:mutbuf, w:mutbuf, out:u64) -> u32:
    phase = get(w, 192)
    if phase == 10:
        put(w, 192, 20)
        return fence_inode(o, w, 1, 0, 0, 0, 0)
    if phase == 30:
        if read64(s, out + 56) != 0:
            return fence_terminal(o, w, 1, read64(s, out + 56), 0)
        token = read64(s, out + 64)
        if token == 0:
            return fence_reject(o, w, 25)
        put(w, 176, token)
        put(w, 192, 40)
        return fence_inode(o, w, 2, 0, token, 0, 0)
    if phase == 60:
        amount = read64(s, out + 128)
        if amount > 144:
            return fence_reject(o, w, 26)
        return fence_inode_ack(s, o, w, out, 256 + amount)
    if phase == 90:
        if read64(s, out + 56) != 0 and get(w, 248) == 0:
            put(w, 248, read64(s, out + 56))
        return fence_drain_orphans(o, w)
    return fence_reject(o, w, 27)

def fence_inode_reply(s:readbuf, o:mutbuf, w:mutbuf, out:u64) -> u32:
    code = read64(s, out + 8)
    phase = get(w, 192)
    if read64(s, out + 48) != get(w, 184):
        return fence_reject(o, w, 38)
    if read64(s, out + 64) != 0 and read64(s, out + 64) != 1 and read64(s, out + 64) != 5:
        return fence_reject(o, w, 38)
    if read64(s, out + 72) > 4095:
        return fence_reject(o, w, 38)
    at = 192
    while at < 256:
        if read64(s, out + at) != 0:
            return fence_reject(o, w, 38)
        at = at + 8
    if code == 1:
        if phase != 40 and phase != 50 and phase != 70:
            return fence_reject(o, w, 28)
        operation = read64(s, out + 56)
        token = read64(s, out + 128)
        action = read64(s, out + 40)
        if (operation != 15 and operation != 17 and operation != 8) or token == 0 or action == 0:
            return fence_reject(o, w, 29)
        if read64(s, out + 112) != 2 or read64(s, out + 88) != get(w, 48):
            return fence_reject(o, w, 29)
        put(w, 120, operation)
        put(w, 208, action)
        put(w, 192, 60)
        if operation == 17:
            return fence_fs(o, w, 17, token, read64(s, out + 136), read64(s, out + 144), read64(s, out + 152), action, 0, 0)
        return fence_fs(o, w, operation, token, 0, 0, 0, action, 0, 0)
    if code != 0 or read64(s, out + 112) != 1:
        return fence_reject(o, w, 30)
    if phase == 20:
        if read64(s, out + 64) != 0 or get(w, 104) != 0:
            return fence_reject(o, w, 31)
        return fence_terminal(o, w, 0, 0, 0)
    if phase != 40 and phase != 50 and phase != 70:
        return fence_reject(o, w, 32)
    business = read64(s, out + 64)
    error = read64(s, out + 72)
    handle = read64(s, out + 80)
    if get(w, 40) == 1 and business != 0:
        count = get(w, 168)
        if count >= get(w, 160) or get(w, 176) == 0:
            return fence_reject(o, w, 33)
        put(w, 1536 + count * 8, get(w, 176))
        put(w, 168, count + 1)
    return fence_terminal(o, w, business, error, handle)

def fence_inode(o:mutbuf, w:mutbuf, command:u64, handle:u64, a:u64, b:u64, c:u64) -> u32:
    if command != 1:
        if get(w, 104) == 18446744073709551615:
            return fence_reject(o, w, 34)
        put(w, 104, get(w, 104) + 1)
    fence_zero(o, 256, 256)
    put(o, 256, INODE_MAGIC)
    put(o, 264, command)
    put(o, 272, get(w, 16))
    put(o, 280, get(w, 24))
    put(o, 288, get(w, 104))
    put(o, 304, handle)
    if command == 1:
        put(o, 328, get(w, 16))
        put(o, 336, get(w, 24))
        put(o, 344, get(w, 80))
        put(o, 352, get(w, 88))
    else:
        put(o, 328, a)
        put(o, 360, b)
        put(o, 368, c)
        put(o, 376, get(w, 48))
    return fence_issue(o, w, 2, 256)

def fence_inode_ack(s:readbuf, o:mutbuf, w:mutbuf, out:u64, amount:u64) -> u32:
    fence_zero(o, 256, 256)
    put(o, 256, INODE_MAGIC)
    put(o, 264, 6)
    put(o, 272, get(w, 16))
    put(o, 280, get(w, 24))
    put(o, 288, get(w, 104))
    put(o, 296, get(w, 208))
    put(o, 304, get(w, 184))
    put(o, 312, get(w, 120))
    put(o, 376, get(w, 48))
    put(o, 384, 256 + amount)
    copy_workspace(o, w, 512, 576, 256)
    copy_input(o, s, 768, out, amount)
    put(w, 192, 70)
    return fence_issue(o, w, 2, 512 + amount)

def fence_fs(o:mutbuf, w:mutbuf, operation:u64, a:u64, b:u64, c:u64, d:u64, lease:u64, start:u64, amount:u64) -> u32:
    if get(w, 80) == 18446744073709551615 or amount > get(w, 136) - 256:
        return fence_reject(o, w, 35)
    put(w, 80, get(w, 80) + 1)
    fence_zero(o, 256, 256)
    put(o, 256, FS_MAGIC)
    put(o, 264, 2)
    put(o, 272, get(w, 16))
    put(o, 280, get(w, 24))
    put(o, 288, get(w, 80))
    put(o, 304, operation)
    put(o, 320, a)
    put(o, 328, b)
    put(o, 336, c)
    put(o, 344, d)
    put(o, 352, amount)
    put(o, 360, lease)
    if amount != 0:
        copy_workspace(o, w, 512, start, amount)
    copy_workspace(w, o, 576, 256, 256)
    return fence_issue(o, w, 1, 256 + amount)

def fence_issue(o:mutbuf, w:mutbuf, role:u64, amount:u64) -> u32:
    if amount > get(w, 136) or amount > length(o) - 256 or get(w, 64) == 18446744073709551615:
        return fence_reject(o, w, 36)
    copy_workspace(w, o, fence_child_base(w), 256, amount)
    put(w, 72, amount)
    put(w, 56, role)
    put(w, 64, get(w, 64) + 1)
    put(w, 8, 2)
    return fence_emit(o, w, 1, amount)

def fence_any_mask(w:mutbuf) -> u64:
    if get(w, 152) == 0:
        return 0
    base = fence_snapshot_base(w)
    cap = get(w, base + 56)
    i = 0
    while i < cap:
        row = base + 512 + i * 96
        if (get(w, row + 32) | get(w, row + 40)) != 0:
            return 1
        i = i + 1
    return 0

def fence_terminal(o:mutbuf, w:mutbuf, business:u64, error:u64, handle:u64) -> u32:
    fence_zero(w, 832, 256)
    put(w, 832, FENCE_MAGIC)
    put(w, 848, get(w, 16))
    put(w, 856, get(w, 24))
    put(w, 864, get(w, 32))
    put(w, 872, get(w, 40))
    put(w, 880, business)
    put(w, 888, error)
    put(w, 896, handle)
    put(w, 904, get(w, 48))
    return fence_drain_orphans(o, w)

def fence_drain_orphans(o:mutbuf, w:mutbuf) -> u32:
    if get(w, 168) != 0 and fence_any_mask(w) == 0:
        count = get(w, 168) - 1
        token = get(w, 1536 + count * 8)
        if token == 0:
            return fence_reject(o, w, 37)
        put(w, 168, count)
        put(w, 1536 + count * 8, 0)
        put(w, 192, 90)
        return fence_fs(o, w, 8, token, 0, 0, 0, get(w, 48), 0, 0)
    put(w, 8, 1)
    put(w, 56, 0)
    put(w, 72, 0)
    put(w, 192, 0)
    copy_workspace(o, w, 0, 832, 256)
    put(o, 80, get(w, 248))
    put(o, 88, get(w, 168))
    if get(w, 152) != 0:
        put(o, 96, get(w, fence_snapshot_base(w) + 64))
    return 0

def fence_zero(w:mutbuf, at:u64, amount:u64) -> u64:
    end = at + amount
    while at < end:
        store(w, at, 0)
        at = at + 1
    return 0

def fence_poison(w:mutbuf, reason:u64) -> u64:
    if get(w, 0) != FENCE_BAD:
        put(w, 1088, reason)
    put(w, 0, FENCE_BAD)
    put(w, 8, 5)
    return 4294967293

def fence_reject(o:mutbuf, w:mutbuf, reason:u64) -> u32:
    fence_poison(w, reason)
    return fence_emit(o, w, 4294967293, 0)

def fence_emit(o:mutbuf, w:mutbuf, status:u64, amount:u64) -> u32:
    if length(o) < 256:
        return 4294967293
    fence_zero(o, 0, 256)
    put(o, 0, FENCE_MAGIC)
    put(o, 8, status)
    put(o, 16, get(w, 16))
    put(o, 24, get(w, 24))
    put(o, 32, get(w, 32))
    put(o, 40, get(w, 40))
    put(o, 48, get(w, 56))
    put(o, 56, get(w, 64))
    put(o, 64, amount)
    put(o, 72, get(w, 216))
    put(o, 80, get(w, 224))
    put(o, 88, get(w, 8))
    put(o, 96, get(w, 1088))
    put(o, 128, amount)
    return status
'''
def source_program():
    source=BRIDGE
    for name,value in [("FENCE_MAGIC",MAGIC),("FENCE_BAD",BAD),("FENCE_CHANNEL",CHANNEL),
                       ("FS_MAGIC",FS_MAGIC),("INODE_MAGIC",INODE_MAGIC)]:
        source=source.replace(name,str(value))
    return source+VALUES[VALUES.index("\ndef read64("):]
def document():
    nodes=ast.parse(source_program()).body
    names={node.name:"f"+str(index) for index,node in enumerate(nodes)}
    if len(names)!=len(nodes):raise ValueError("duplicate fencing function")
    signatures={node.name:([arg.annotation.id for arg in node.args.args],node.returns.id) for node in nodes}
    total=total_scalar_functions(nodes);functions=[]
    for node in nodes:
        b=ObjectBuilder(node,names,signatures,total);b.statements(node.body)
        functions.append({"name":names[node.name],"params":[b.param(v) for v in b.params],"returns":[b.returns],
            "effects":["read","write","trap"],"entry":"b0","blocks":b.blocks})
    return compact_authoring_cfg({"schema":"hepta.hia.program.v8","module":"agent_namespace_fencing_r2","functions":functions})
if __name__=="__main__":
    path=ROOT/"examples/hia_bootstrap/agent_namespace_fencing_r2.hiaasm"
    path.write_text(render_assembly(document()));print(path.name,path.stat().st_size)
