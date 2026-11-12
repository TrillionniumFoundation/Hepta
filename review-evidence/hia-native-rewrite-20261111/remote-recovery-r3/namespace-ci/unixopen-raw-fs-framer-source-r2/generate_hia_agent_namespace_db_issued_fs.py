"""NEW r5 six-image main DB / DMS / map / memory / filesystem continuation.

One native HIA outer owns the inode index, file handles, FS gateway exclusion,
single actual registration FSTAT, pending receipts and terminal retirement.
Existing commands 1..9 retain the same policy. Command 10 joins the separately
reconstructed DB reuse-r3 TAKE_UNUSED policy to this existing global directory.
Command 11 carries a complete privately issued FS request through that same
DMS16/FS instance. The actual FS header and path must match the saved request;
its caller/action and logical result bytes are not relabelled by the gateway.
Command 12 permits only FSTAT through an actual live file handle with the same
registered FS token. It does not relax the generic gateway or permit lock,
write, CLOSE or arbitrary descriptor access. The DMS policy is unchanged. A fixed native
carrier must issue immutable USER / CHILD / RETIRE channels. This source is
not externally authenticated by its byte headers. Ordinary Store and the
complete SQL/log/migration chain remain separate unfinished work.
"""
from __future__ import annotations
import ast
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_agent_namespace_objects import ObjectBuilder
from tools.generate_hia_agent_namespace_store import VALUES
from tools.generate_hia_selfhost import compact_authoring_cfg,total_scalar_functions
ROOT=Path(__file__).resolve().parents[1]
MAGIC=int.from_bytes(b"HIANDJ01","little")
BAD=int.from_bytes(b"HIADJB01","little")
CHANNEL=int.from_bytes(b"HIANDJX1","little")
DMS_MAGIC=int.from_bytes(b"HIANDM03","little")
DMS_CHANNEL=int.from_bytes(b"HIANDX03","little")
DB_MAGIC=int.from_bytes(b"HIANDB01","little")
FS_MAGIC=int.from_bytes(b"HIANFR03","little")
JOIN=r'''
def db_join(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < 4096:
        if length(w) >= 8:
            put(w, 0, JOIN_BAD)
        return 4294967293
    if get(w, 0) == JOIN_BAD:
        return j_emit(o, w, 4294967293, 0)
    if length(o) < 256 or length(s) < 128 or read64(s, 0) != JOIN_CHANNEL:
        return j_reject(o, w, 1)
    if read64(s, 88) != 4096 or (read64(s, 104) | read64(s, 112) | read64(s, 120)) != 0:
        return j_reject(o, w, 2)
    origin = read64(s, 8)
    if origin == 1:
        if (read64(s, 16) | read64(s, 24) | read64(s, 40) | read64(s, 48) | read64(s, 56) | read64(s, 64) | read64(s, 72) | read64(s, 80) | read64(s, 96)) != 0:
            return j_reject(o, w, 3)
        if length(s) < 384 or read64(s, 32) != length(s) - 128 or read64(s, 128) != JOIN_MAGIC:
            return j_reject(o, w, 4)
        if read64(s, 240) != length(s) - 384:
            return j_reject(o, w, 4)
        at = 248
        while at < 384:
            if read64(s, at) != 0:
                return j_reject(o, w, 4)
            at = at + 8
        if get(w, 0) == 0:
            return j_init(s, o, w)
        if j_steady(w) == 0:
            return j_reject(o, w, 5)
        if read64(s, 144) != get(w, 16) or read64(s, 152) != get(w, 24):
            return j_reject(o, w, 6)
        if get(w, 8) == 1:
            if j_user_shape(s, w) == 0:
                return j_reject(o, w, 7)
            if get(w, 32) == 18446744073709551615 or read64(s, 160) != get(w, 32) + 1 or read64(s, 176) == 0:
                return j_reject(o, w, 8)
            put(w, 32, read64(s, 160))
            put(w, 136, read64(s, 136))
            put(w, 144, read64(s, 176))
            put(w, 120, 0)
            put(w, 128, 0)
            put(w, 8, 2)
            copy_input(w, s, 512, 128, 256)
        if get(w, 8) != 2 or read64(s, 32) != 256 + get(w, 624):
            return j_reject(o, w, 9)
        at = 0
        while at < 256:
            if read64(s, 128 + at) != get(w, 512 + at):
                return j_reject(o, w, 9)
            at = at + 8
        return j_user(s, o, w)
    if get(w, 0) != JOIN_MAGIC or j_steady(w) == 0:
        return j_reject(o, w, 10)
    if origin == 2:
        if get(w, 8) != 3 or j_child_shape(s, w) == 0:
            return j_reject(o, w, 11)
        return j_child(s, o, w)
    if origin == 3:
        return j_retire_reply(s, o, w)
    return j_reject(o, w, 12)

def j_zero(w:mutbuf, at:u64, size:u64) -> u64:
    end = at + size
    while at < end:
        put(w, at, 0)
        at = at + 8
    return 0

def j_find(w:mutbuf, identity:u64, kind:u64) -> u64:
    if identity == 0:
        return 0
    at = 4096
    while at < get(w, 56):
        if get(w, at + 16) == identity:
            if get(w, at + 8) != kind or get(w, at + 24) == 0:
                return 0
            return at
        at = at + get(w, at)
    return 0

def j_node_key(w:mutbuf, device:u64, inode:u64) -> u64:
    at = 4096
    while at < get(w, 56):
        if get(w, at + 8) == 1 and get(w, at + 24) != 0:
            if get(w, at + 32) == device and get(w, at + 40) == inode:
                return at
        at = at + get(w, at)
    return 0

def j_token(w:mutbuf, token:u64) -> u64:
    at = 4096
    while at < get(w, 56):
        if get(w, at + 8) == 2 and get(w, at + 24) != 0 and get(w, at + 48) == token:
            return at
        at = at + get(w, at)
    return 0

def j_steady(w:mutbuf) -> u64:
    if get(w, 0) != JOIN_MAGIC or get(w, 8) < 1 or get(w, 8) > 5:
        return 0
    if (get(w, 16) | get(w, 24)) == 0 or (get(w, 80) | get(w, 88)) == 0:
        return 0
    if get(w, 48) == 0 or get(w, 56) < 4096 or get(w, 56) > length(w) or (get(w, 56) & 7) != 0:
        return 0
    at = 4096
    previous = 0
    while at < get(w, 56):
        if get(w, 56) - at < 32:
            return 0
        span = get(w, at)
        kind = get(w, at + 8)
        identity = get(w, at + 16)
        live = get(w, at + 24)
        if span < 32 or (span & 7) != 0 or span > get(w, 56) - at or identity <= previous or identity >= get(w, 48) or live > 3:
            return 0
        previous = identity
        if kind == 1:
            if span != 192:
                return 0
            if live != 0:
                if get(w, at + 56) != identity or (get(w, at + 48) | get(w, at + 56)) == 0:
                    return 0
                if get(w, at + 96) > 4 or get(w, at + 104) > 1:
                    return 0
                if live == 1 and (get(w, at + 80) == 0 or get(w, at + 88) == 0):
                    return 0
        elif kind == 2:
            if span != 128:
                return 0
            if live != 0:
                node = j_find(w, get(w, at + 32), 1)
                if node == 0 or get(w, at + 48) == 0 or get(w, at + 64) > 3:
                    return 0
                if live == 1 and get(w, at + 40) == 0:
                    return 0
        elif kind == 3:
            if live > 1 or span < 40 or get(w, at + 32) > span - 40:
                return 0
        else:
            return 0
        at = at + span
    if at != get(w, 56):
        return 0
    phase = get(w, 8)
    if phase == 1:
        if (get(w, 120) | get(w, 128) | get(w, 136) | get(w, 144) | get(w, 152) | get(w, 160) | get(w, 168) | get(w, 184)) != 0:
            return 0
        if (get(w, 192) | get(w, 200) | get(w, 248) | get(w, 256) | get(w, 264)) != 0:
            return 0
    elif phase == 2:
        if get(w, 512) != JOIN_MAGIC or get(w, 520) != get(w, 136) or get(w, 544) != get(w, 32):
            return 0
    elif phase == 3:
        role = get(w, 152)
        if role != 4 and role != 5:
            return 0
        source = j_find(w, get(w, 264), 3)
        if source == 0 or get(w, 184) == 0 or get(w, 40) == 0:
            return 0
        if role == 4:
            if get(w, 160) != 1 or get(w, 168) != 0:
                return 0
        else:
            node = j_find(w, get(w, 160), 1)
            if node == 0 or get(w, 160) != get(w, 120) or get(w, 168) > 1:
                return 0
    elif phase == 5:
        node = j_find(w, get(w, 120), 1)
        if node == 0 or get(w, node + 24) != 3 or get(w, 152) != 5 or get(w, 160) != get(w, 120) or get(w, 184) != 90:
            return 0
    return 1

def j_compact(w:mutbuf) -> u64:
    at = 4096
    target = 4096
    end = get(w, 56)
    while at < end:
        span = get(w, at)
        if get(w, at + 24) != 0:
            if at != target:
                move_workspace(w, target, at, span)
            target = target + span
        at = at + span
    j_zero(w, target, end - target)
    put(w, 56, target)
    return 0

def j_reserve(o:mutbuf, w:mutbuf, amount:u64, records:u64, output:u64) -> u64:
    if records > 18446744073709551615 - get(w, 48):
        return j_reject(o, w, 13)
    if amount > 18446744073709551615 - get(w, 56):
        return j_reject(o, w, 13)
    if amount > length(w) - get(w, 56):
        j_compact(w)
    if amount > 18446744073709551615 - get(w, 56):
        return j_reject(o, w, 13)
    need = get(w, 56) + amount
    if need > length(w) or output > length(o):
        put(w, 192, need)
        put(w, 200, output)
        j_emit(o, w, 2, 0)
        return 2
    put(w, 192, 0)
    put(w, 200, 0)
    return 0

def j_allocate(w:mutbuf, kind:u64, span:u64, live:u64) -> u64:
    at = get(w, 56)
    j_zero(w, at, span)
    put(w, at, span)
    put(w, at + 8, kind)
    put(w, at + 16, get(w, 48))
    put(w, at + 24, live)
    put(w, 48, get(w, 48) + 1)
    put(w, 56, at + span)
    return at

def j_blob(w:mutbuf, size:u64) -> u64:
    at = j_allocate(w, 3, 40 + ((size + 7) & 18446744073709551608), 1)
    put(w, at + 32, size)
    return at

def j_drop(w:mutbuf, field:u64) -> u64:
    at = j_find(w, get(w, field), 3)
    if at != 0:
        put(w, at + 24, 0)
    put(w, field, 0)
    return 0

def j_emit(o:mutbuf, w:mutbuf, status:u64, amount:u64) -> u32:
    if length(o) < 256:
        return 4294967293
    j_zero(o, 0, 256)
    put(o, 0, JOIN_MAGIC)
    put(o, 8, status)
    put(o, 16, get(w, 16))
    put(o, 24, get(w, 24))
    put(o, 32, get(w, 32))
    put(o, 40, get(w, 40))
    put(o, 48, get(w, 152))
    put(o, 56, get(w, 160))
    put(o, 64, amount)
    put(o, 72, get(w, 168))
    if get(w, 152) == 4:
        put(o, 80, 8192)
        put(o, 88, 1280)
    elif get(w, 152) == 5:
        put(o, 80, 1536)
        put(o, 88, 256)
    put(o, 96, get(w, 184))
    put(o, 104, get(w, 144))
    put(o, 112, get(w, 128))
    put(o, 120, get(w, 368))
    put(o, 128, amount)
    put(o, 136, get(w, 376))
    put(o, 144, get(w, 192))
    put(o, 152, get(w, 200))
    put(o, 176, 1)
    put(o, 184, get(w, 360))
    put(o, 192, get(w, 320))
    node = j_find(w, get(w, 120), 1)
    if node != 0:
        put(o, 160, get(w, node + 32))
        put(o, 168, get(w, node + 40))
        put(o, 200, get(w, node + 80))
    return status

def j_reject(o:mutbuf, w:mutbuf, reason:u64) -> u32:
    if get(w, 0) != JOIN_BAD:
        put(w, 360, reason)
    put(w, 0, JOIN_BAD)
    put(w, 8, 6)
    return j_emit(o, w, 4294967293, 0)

def j_issue(o:mutbuf, w:mutbuf, role:u64, identity:u64, create:u64, blob:u64, stage:u64) -> u32:
    if get(w, 40) == 18446744073709551615 or (role != 4 and role != 5) or blob == 0:
        return j_reject(o, w, 14)
    old = j_find(w, get(w, 264), 3)
    if old != 0 and old != blob:
        put(w, old + 24, 0)
    put(w, 264, get(w, blob + 16))
    put(w, 152, role)
    put(w, 160, identity)
    put(w, 168, create)
    put(w, 184, stage)
    put(w, 40, get(w, 40) + 1)
    put(w, 8, 3)
    amount = get(w, blob + 32)
    if amount > length(o) - 256:
        return j_reject(o, w, 15)
    j_emit(o, w, 1, amount)
    copy_workspace(o, w, 256, blob + 40, amount)
    return 1

def j_finish(o:mutbuf, w:mutbuf, code:u64, error:u64, amount:u64) -> u32:
    put(w, 368, code)
    put(w, 376, error)
    put(w, 152, 0)
    put(w, 160, 0)
    put(w, 168, 0)
    put(w, 184, 0)
    put(w, 192, 0)
    put(w, 200, 0)
    put(w, 8, 1)
    j_emit(o, w, 0, amount)
    j_drop(w, 248)
    j_drop(w, 256)
    j_drop(w, 264)
    put(w, 120, 0)
    put(w, 128, 0)
    put(w, 136, 0)
    put(w, 144, 0)
    put(w, 368, 0)
    put(w, 376, 0)
    j_zero(w, 512, 1024)
    return 0

def j_init(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    at = 0
    while at < 4096:
        if get(w, at) != 0:
            return j_reject(o, w, 16)
        at = at + 8
    if read64(s, 136) != 1 or length(s) != 384 or (read64(s, 144) | read64(s, 152)) == 0 or (read64(s, 192) | read64(s, 200)) == 0:
        return j_reject(o, w, 17)
    if (read64(s, 160) | read64(s, 168) | read64(s, 176) | read64(s, 184)) != 0:
        return j_reject(o, w, 17)
    at = 208
    while at < 384:
        if read64(s, at) != 0:
            return j_reject(o, w, 17)
        at = at + 8
    put(w, 0, JOIN_MAGIC)
    put(w, 8, 2)
    put(w, 16, read64(s, 144))
    put(w, 24, read64(s, 152))
    put(w, 48, 1)
    put(w, 56, 4096)
    put(w, 64, read64(s, 144))
    put(w, 72, read64(s, 152))
    put(w, 80, read64(s, 192))
    put(w, 88, read64(s, 200))
    put(w, 136, 1)
    copy_input(w, s, 512, 128, 256)
    return j_user(s, o, w)

def j_peer_fs_shape(s:readbuf, w:mutbuf) -> u64:
    if read64(s, 184) != 0 or read64(s, 240) < 256:
        return 0
    at = 192
    while at < 240:
        if read64(s, at) != 0:
            return 0
        at = at + 8
    request = 384
    if read64(s, request) != FS_MAGIC or read64(s, request + 8) != 2:
        return 0
    if read64(s, request + 16) != get(w, 80) or read64(s, request + 24) != get(w, 88):
        return 0
    if get(w, 216) == 18446744073709551615 or read64(s, request + 32) != get(w, 216) + 1:
        return 0
    if (read64(s, request + 40) | read64(s, request + 56)) != 0 or read64(s, request + 104) == 0:
        return 0
    if read64(s, request + 96) != read64(s, 240) - 256:
        return 0
    at = 112
    while at < 256:
        if read64(s, request + at) != 0:
            return 0
        at = at + 8
    op = read64(s, request + 48)
    a = read64(s, request + 64)
    if op < 1 or op > 31:
        return 0
    if op != 12 and op != 13 and op != 14 and op != 16 and op != 20:
        if j_token(w, a) != 0:
            return 0
    if op == 7 and j_token(w, read64(s, request + 72)) != 0:
        return 0
    return 1

def j_registered_fstat_shape(s:readbuf, w:mutbuf) -> u64:
    if read64(s, 240) != 256:
        return 0
    at = 192
    while at < 240:
        if read64(s, at) != 0:
            return 0
        at = at + 8
    file = j_find(w, read64(s, 184), 2)
    if file == 0 or get(w, file + 24) != 1:
        return 0
    node = j_find(w, get(w, file + 32), 1)
    if node == 0 or get(w, node + 24) != 1:
        return 0
    request = 384
    if read64(s, request) != FS_MAGIC or read64(s, request + 8) != 2:
        return 0
    if read64(s, request + 16) != get(w, 80) or read64(s, request + 24) != get(w, 88):
        return 0
    if get(w, 216) == 18446744073709551615 or read64(s, request + 32) != get(w, 216) + 1:
        return 0
    if (read64(s, request + 40) | read64(s, request + 56)) != 0 or read64(s, request + 104) == 0:
        return 0
    if read64(s, request + 48) != 15 or read64(s, request + 64) != get(w, file + 48):
        return 0
    if j_token(w, read64(s, request + 64)) != file:
        return 0
    if (read64(s, request + 72) | read64(s, request + 80) | read64(s, request + 88) | read64(s, request + 96)) != 0:
        return 0
    at = 112
    while at < 256:
        if read64(s, request + at) != 0:
            return 0
        at = at + 8
    return 1

def j_registered_fstat_pending(w:mutbuf, request:u64) -> u64:
    file = j_find(w, get(w, 128), 2)
    node = j_find(w, get(w, 120), 1)
    if file == 0 or node == 0 or get(w, file + 24) != 1 or get(w, node + 24) != 1:
        return 0
    if get(w, file + 16) != get(w, 568) or get(w, file + 32) != get(w, node + 16):
        return 0
    if get(w, request + 48) != 15 or get(w, request + 64) != get(w, file + 48):
        return 0
    if j_token(w, get(w, request + 64)) != file or get(w, request + 96) != 0:
        return 0
    return 1

def j_peer_fs_start(o:mutbuf, w:mutbuf, size:u64) -> u32:
    source = j_find(w, get(w, 256), 3)
    request = source + 296
    path_size = size - 256
    if get(w, 136) == 12:
        file = j_find(w, get(w, 568), 2)
        if file == 0 or get(w, file + 24) != 1:
            return j_reject(o, w, 76)
        put(w, 128, get(w, file + 16))
        put(w, 120, get(w, file + 32))
        if j_registered_fstat_pending(w, request) == 0:
            return j_reject(o, w, 76)
    j_dms_header(w, 16, get(w, request + 104), 0, path_size)
    put(w, 1664, get(w, request + 48))
    put(w, 1672, get(w, request + 64))
    put(w, 1680, get(w, request + 72))
    put(w, 1688, get(w, request + 80))
    put(w, 1696, get(w, request + 88))
    next_source = j_dms_blob(w, path_size)
    if path_size != 0:
        move_workspace(w, next_source + 360, request + 256, path_size)
    return j_issue(o, w, 4, 1, 0, next_source, 62)

def j_peer_fs_completed(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    out = 128 + read64(s, 32)
    work = out + read64(s, 40)
    source = j_find(w, get(w, 256), 3)
    if get(w, 248) != 0:
        return j_reject(o, w, 71)
    if get(w, 136) == 11:
        if (get(w, 120) | get(w, 128)) != 0:
            return j_reject(o, w, 71)
    elif get(w, 136) != 12:
        return j_reject(o, w, 71)
    if source == 0 or get(w, source + 32) < 512:
        return j_reject(o, w, 71)
    request = source + 296
    path_size = get(w, source + 32) - 512
    if get(w, 136) == 12:
        if path_size != 0 or j_registered_fstat_pending(w, request) == 0:
            return j_reject(o, w, 76)
    if read64(s, out + 48) != 0 or read64(s, out + 56) != 0:
        return j_reject(o, w, 72)
    if read64(s, 32) != 320 + path_size:
        return j_reject(o, w, 73)
    at = 0
    while at < 256:
        if read64(s, work + 768 + at) != get(w, request + at):
            return j_reject(o, w, 74)
        at = at + 8
    at = 0
    while at < path_size:
        if byte(s, 448 + at) != byte(w, request + 256 + at):
            return j_reject(o, w, 75)
        at = at + 1
    fs = out + 256
    amount = 256 + read64(s, fs + 128)
    status = j_reserve(o, w, 0, 0, 256 + amount)
    if status != 0:
        return status
    j_accept_dms(s, w)
    copy_input(o, s, 256, fs, amount)
    return j_finish(o, w, 0, 0, amount)

def j_user_shape(s:readbuf, w:mutbuf) -> u64:
    cmd = read64(s, 136)
    handle = read64(s, 184)
    size = read64(s, 240)
    if cmd < 2 or cmd > 12 or read64(s, 168) != 0:
        return 0
    if cmd == 11:
        return j_peer_fs_shape(s, w)
    if cmd == 12:
        return j_registered_fstat_shape(s, w)
    if cmd == 10:
        if handle != 0 or read64(s, 192) > 4294967295:
            return 0
        at = 200
        while at < 240:
            if read64(s, at) != 0:
                return 0
            at = at + 8
        at = 384
        while at < length(s):
            if byte(s, at) == 0:
                return 0
            at = at + 1
        return 1
    if cmd == 2:
        if handle != 0 or read64(s, 192) < 1 or read64(s, 192) > 31 or read64(s, 232) != 0:
            return 0
        op = read64(s, 192)
        a = read64(s, 200)
        if op != 12 and op != 13 and op != 14 and op != 16 and op != 20:
            if j_token(w, a) != 0:
                return 0
        if op == 7 and j_token(w, read64(s, 208)) != 0:
            return 0
        return 1
    if cmd == 3:
        if handle != 0 or size != 0 or read64(s, 192) == 0 or read64(s, 200) > 3:
            return 0
        if j_token(w, read64(s, 192)) != 0:
            return 0
        return choose((read64(s, 208) | read64(s, 216) | read64(s, 224) | read64(s, 232)) == 0, 1, 0)
    file = j_find(w, handle, 2)
    if file == 0 or get(w, file + 24) != 1:
        return 0
    if cmd == 8:
        if get(w, file + 56) != 0 or size == 0:
            return 0
        at = 192
        while at < 240:
            if read64(s, at) != 0:
                return 0
            at = at + 8
        at = 384
        while at < length(s):
            if byte(s, at) == 0:
                return 0
            at = at + 1
        return 1
    if size != 0:
        return 0
    if cmd != 9:
        if (read64(s, 200) | read64(s, 208) | read64(s, 216) | read64(s, 224) | read64(s, 232)) != 0:
            return 0
        target = read64(s, 192)
        if cmd == 4:
            return choose(target == 1 or target == 2 or target == 4, 1, 0)
        if cmd == 5:
            return choose(target <= 1, 1, 0)
        return choose(target == 0, 1, 0)
    if get(w, file + 56) == 0:
        return 0
    sub = read64(s, 192)
    if read64(s, 224) != 0 or read64(s, 232) != 0:
        return 0
    if sub == 3 or sub == 7 or sub == 15:
        return choose((read64(s, 200) | read64(s, 208) | read64(s, 216)) == 0, 1, 0)
    if sub == 12:
        return choose(read64(s, 200) <= 1 and (read64(s, 208) | read64(s, 216)) == 0, 1, 0)
    if sub == 14:
        return choose(read64(s, 208) <= 1 and read64(s, 216) == 32768, 1, 0)
    if sub == 4 or sub == 5:
        kind = read64(s, 200)
        offset = read64(s, 208)
        count = read64(s, 216)
        if (kind != 1 and kind != 2) or offset >= 8 or count == 0 or count > 8 - offset or (kind == 1 and count != 1):
            return 0
        return 1
    return 0

def j_dms_header(w:mutbuf, command:u64, lease:u64, handle:u64, size:u64) -> u64:
    j_zero(w, 1536, 320)
    put(w, 1536, DMS_CHANNEL)
    put(w, 1544, 1)
    put(w, 1568, 256 + size)
    put(w, 1584, 4096)
    put(w, 1600, DMS_MAGIC)
    put(w, 1608, command)
    put(w, 1616, get(w, 64))
    put(w, 1624, get(w, 72))
    if command != 1:
        put(w, 96, get(w, 96) + 1)
    put(w, 1632, get(w, 96))
    put(w, 1648, lease)
    put(w, 1656, handle)
    put(w, 1728, size)
    return 0

def j_dms_blob(w:mutbuf, size:u64) -> u64:
    at = j_blob(w, 320 + size)
    move_workspace(w, at + 40, 1536, 320)
    return at

def j_db_header(w:mutbuf, command:u64, lease:u64, handle:u64, value:u64, flags:u64) -> u64:
    node = j_find(w, get(w, 120), 1)
    j_zero(w, 1856, 256)
    put(w, 1856, DB_MAGIC)
    put(w, 1864, command)
    put(w, 1872, get(w, node + 48))
    put(w, 1880, get(w, node + 56))
    if command != 1 and command != 7:
        put(w, node + 64, get(w, node + 64) + 1)
    put(w, 1888, get(w, node + 64))
    put(w, 1904, handle)
    put(w, 1920, value)
    put(w, 1928, flags)
    put(w, 1976, lease)
    return 0

def j_db_blob(w:mutbuf, size:u64) -> u64:
    at = j_blob(w, 256 + size)
    move_workspace(w, at + 40, 1856, 256)
    put(w, at + 168, size)
    return at

def j_gateway(o:mutbuf, w:mutbuf, op:u64, a:u64, b:u64, c:u64, d:u64, lease:u64, stage:u64) -> u32:
    if get(w, 96) == 18446744073709551615:
        return j_reject(o, w, 18)
    j_dms_header(w, 16, lease, 0, 0)
    put(w, 1664, op)
    put(w, 1672, a)
    put(w, 1680, b)
    put(w, 1688, c)
    put(w, 1696, d)
    source = j_dms_blob(w, 0)
    return j_issue(o, w, 4, 1, 0, source, stage)

def j_user(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    size = get(w, 624)
    cmd = get(w, 136)
    if size > 18446744073709551039:
        return j_reject(o, w, 19)
    child_size = 320 + size
    if cmd == 11 or cmd == 12:
        child_size = 64 + size
    elif cmd == 4 or cmd == 5 or cmd == 6:
        child_size = 256
    elif cmd == 7:
        file = j_find(w, get(w, 568), 2)
        if get(w, file + 56) == 0:
            child_size = 256
    user_span = 296 + ((size + 7) & 18446744073709551608)
    child_span = 40 + ((child_size + 7) & 18446744073709551608)
    if child_span > 18446744073709551615 - user_span:
        return j_reject(o, w, 19)
    status = j_reserve(o, w, user_span + child_span, 2, 256 + child_size)
    if status != 0:
        return status
    source = j_blob(w, 256 + size)
    copy_input(w, s, source + 40, 128, 256 + size)
    put(w, 256, get(w, source + 16))
    cmd = get(w, 136)
    if cmd == 1:
        j_dms_header(w, 1, 0, 0, 0)
        put(w, 1664, get(w, 80))
        put(w, 1672, get(w, 88))
        put(w, 1704, 3)
        put(w, 1712, 420)
        put(w, 1720, 3)
        next_source = j_dms_blob(w, 0)
        return j_issue(o, w, 4, 1, 0, next_source, 1)
    if cmd == 10:
        return j_reuse_start(o, w, size)
    if get(w, 96) == 18446744073709551615:
        return j_reject(o, w, 18)
    if cmd == 11 or cmd == 12:
        return j_peer_fs_start(o, w, size)
    if cmd == 2:
        j_dms_header(w, 16, get(w, 144), 0, size)
        put(w, 1664, get(w, 576))
        put(w, 1672, get(w, 584))
        put(w, 1680, get(w, 592))
        put(w, 1688, get(w, 600))
        put(w, 1696, get(w, 608))
        next_source = j_dms_blob(w, size)
        if size != 0:
            source = j_find(w, get(w, 256), 3)
            move_workspace(w, next_source + 360, source + 296, size)
        return j_issue(o, w, 4, 1, 0, next_source, 2)
    if cmd == 3:
        put(w, 336, get(w, 216))
        put(w, 344, get(w, 224))
        return j_gateway(o, w, 15, get(w, 576), 0, 0, 0, 1, 10)
    file = j_find(w, get(w, 568), 2)
    node = j_find(w, get(w, file + 32), 1)
    put(w, 128, get(w, file + 16))
    put(w, 120, get(w, node + 16))
    if cmd == 4 or cmd == 5 or cmd == 6:
        if get(w, node + 64) == 18446744073709551615:
            return j_reject(o, w, 20)
        j_db_header(w, cmd - 1, get(w, 144), get(w, file + 40), get(w, 576), 0)
        next_source = j_db_blob(w, 0)
        return j_issue(o, w, 5, get(w, 120), 0, next_source, 30)
    if cmd == 7:
        if get(w, file + 56) != 0:
            j_dms_header(w, 12, get(w, 144), get(w, file + 56), 0)
            next_source = j_dms_blob(w, 0)
            return j_issue(o, w, 4, 1, 0, next_source, 40)
        return j_close_start(o, w)
    if cmd == 8:
        j_dms_header(w, 2, get(w, 144), 0, size)
        put(w, 1664, get(w, file + 48))
        put(w, 1672, get(w, node + 32))
        put(w, 1680, get(w, node + 40))
        put(w, 1688, get(w, file + 64) & 1)
        put(w, 1696, (get(w, file + 64) >> 1) & 1)
        next_source = j_dms_blob(w, size)
        source = j_find(w, get(w, 256), 3)
        move_workspace(w, next_source + 360, source + 296, size)
        return j_issue(o, w, 4, 1, 0, next_source, 50)
    sub = get(w, 576)
    j_dms_header(w, sub, get(w, 144), get(w, file + 56), 0)
    if sub == 4 or sub == 5:
        put(w, 1704, get(w, 584))
        put(w, 1712, get(w, 592))
        put(w, 1720, get(w, 600))
    elif sub == 12:
        put(w, 1736, get(w, 584))
    elif sub == 14:
        put(w, 1664, get(w, 584))
        put(w, 1672, get(w, 592))
        put(w, 1680, get(w, 600))
    next_source = j_dms_blob(w, 0)
    return j_issue(o, w, 4, 1, 0, next_source, 51)

def j_close_start(o:mutbuf, w:mutbuf) -> u32:
    file = j_find(w, get(w, 128), 2)
    node = j_find(w, get(w, 120), 1)
    if file == 0 or node == 0 or get(w, file + 56) != 0 or get(w, node + 64) == 18446744073709551615:
        return j_reject(o, w, 21)
    j_db_header(w, 6, get(w, 144), get(w, file + 40), 0, 0)
    next_source = j_db_blob(w, 0)
    return j_issue(o, w, 5, get(w, 120), 0, next_source, 30)

def j_child_shape(s:readbuf, w:mutbuf) -> u64:
    role = get(w, 152)
    if read64(s, 16) != role or read64(s, 64) != get(w, 160) or read64(s, 80) != get(w, 40) or read64(s, 96) != 0:
        return 0
    source = j_find(w, get(w, 264), 3)
    if source == 0 or read64(s, 32) != get(w, source + 32):
        return 0
    amount = read64(s, 32)
    outsize = read64(s, 40)
    worksize = read64(s, 48)
    if amount > length(s) - 128:
        return 0
    remaining = length(s) - 128 - amount
    if outsize < 256 or outsize > remaining or worksize != remaining - outsize:
        return 0
    at = 0
    while at < amount:
        if byte(s, 128 + at) != byte(w, source + 40 + at):
            return 0
        at = at + 1
    out = 128 + amount
    work = out + outsize
    if read64(s, 24) != read64(s, out + 8):
        return 0
    if role == 4:
        if amount < 320 or worksize < 8192 or read64(s, 24) != 0 or read64(s, 72) != 1 or read64(s, 56) <= get(w, 104):
            return 0
        if read64(s, out) != DMS_MAGIC or read64(s, out + 176) != 3 or read64(s, work) != DMS_MAGIC or read64(s, work + 8) != 1:
            return 0
        if read64(s, out + 16) != get(w, 64) or read64(s, out + 24) != get(w, 72) or read64(s, out + 32) != get(w, 96):
            return 0
        if read64(s, work + 16) != get(w, 64) or read64(s, work + 24) != get(w, 72) or read64(s, work + 32) != get(w, 96):
            return 0
        if read64(s, work + 232) != get(w, 80) or read64(s, work + 240) != get(w, 88) or read64(s, work + 1352) != 4096:
            return 0
        if read64(s, work + 48) < get(w, 216) or read64(s, work + 56) < get(w, 224) or read64(s, work + 64) < get(w, 232):
            return 0
        return 1
    node = j_find(w, get(w, 120), 1)
    if role != 5 or node == 0 or amount < 256 or worksize < 1536 or read64(s, 24) > 1:
        return 0
    if get(w, 168) == 1:
        if get(w, 184) != 11 or get(w, node + 24) != 2 or read64(s, 56) != 1 or read64(s, 72) <= get(w, 328):
            return 0
    elif read64(s, 72) != get(w, node + 80) or read64(s, 56) <= get(w, node + 72):
        return 0
    if read64(s, out) != DB_MAGIC or read64(s, out + 176) != 1 or read64(s, work) != DB_MAGIC:
        return 0
    if read64(s, out + 16) != get(w, node + 48) or read64(s, out + 24) != get(w, node + 56) or read64(s, out + 32) != get(w, node + 64):
        return 0
    if read64(s, work + 16) != get(w, node + 48) or read64(s, work + 24) != get(w, node + 56) or read64(s, work + 32) != get(w, node + 64):
        return 0
    if read64(s, out + 88) != read64(s, 248) or read64(s, out + 192) != read64(s, work + 8):
        return 0
    if read64(s, work + 128) != get(w, 80) or read64(s, work + 136) != get(w, 88):
        return 0
    cap = read64(s, work + 56)
    if cap > 144115188075855859 or 1536 + cap * 128 > worksize:
        return 0
    if read64(s, work + 120) != 0:
        if read64(s, work + 104) != get(w, node + 32) or read64(s, work + 112) != get(w, node + 40):
            return 0
    at = 232
    while at < 256:
        if read64(s, out + at) != 0:
            return 0
        at = at + 8
    if read64(s, 24) == 1:
        return choose(read64(s, work + 8) == 2 and read64(s, out + 56) != 0, 1, 0)
    return choose(read64(s, work + 8) == 1 or read64(s, work + 8) == 4, 1, 0)

def j_gateway_frame(s:readbuf, w:mutbuf) -> u64:
    out = 128 + read64(s, 32)
    work = out + read64(s, 40)
    size = read64(s, out + 128)
    if read64(s, 200) != 16 or size < 256 or size > read64(s, 40) - 256 or read64(s, out + 184) != size:
        return 0
    fs = out + 256
    request = work + 768
    if read64(s, request) != FS_MAGIC or read64(s, request + 8) != 2 or read64(s, request + 16) != get(w, 80) or read64(s, request + 24) != get(w, 88):
        return 0
    if read64(s, request + 32) != read64(s, work + 48) or read64(s, request + 40) != 0 or read64(s, request + 56) != 0:
        return 0
    if read64(s, request + 48) != read64(s, 256) or read64(s, request + 64) != read64(s, 264):
        return 0
    if read64(s, request + 72) != read64(s, 272) or read64(s, request + 80) != read64(s, 280) or read64(s, request + 88) != read64(s, 288):
        return 0
    if read64(s, request + 96) != read64(s, 320) or read64(s, request + 104) != read64(s, 240):
        return 0
    at = 112
    while at < 256:
        if read64(s, request + at) != 0:
            return 0
        at = at + 8
    if read64(s, fs) != FS_MAGIC or read64(s, fs + 8) != 0 or read64(s, fs + 16) != get(w, 80) or read64(s, fs + 24) != get(w, 88):
        return 0
    if read64(s, fs + 32) != read64(s, work + 48) or read64(s, fs + 40) != read64(s, work + 56) or read64(s, fs + 48) != read64(s, 256):
        return 0
    if read64(s, fs + 56) > 4095 or read64(s, fs + 112) != read64(s, 240) or read64(s, fs + 120) != 1 or read64(s, fs + 176) != 3:
        return 0
    if read64(s, fs + 128) > size - 256 or read64(s, out + 192) != read64(s, work + 64):
        return 0
    return 1

def j_stat_frame(s:readbuf, w:mutbuf) -> u64:
    out = 128 + read64(s, 32)
    fs = out + 256
    if read64(s, fs + 48) != 15 or read64(s, fs + 112) != 1:
        return 0
    if read64(s, fs + 56) != 0:
        if read64(s, fs + 128) != 0 or read64(s, fs + 192) != 0:
            return 0
        at = 64
        while at < 112:
            if read64(s, fs + at) != 0:
                return 0
            at = at + 8
        return 1
    if read64(s, out + 128) < 400 or read64(s, fs + 128) != 144:
        return 0
    stat = fs + 256
    if read64(s, fs + 64) != read64(s, stat) or read64(s, fs + 72) != read64(s, stat + 8) or read64(s, fs + 192) != read64(s, stat + 16):
        return 0
    if read64(s, fs + 80) != (read64(s, stat + 24) & 4294967295) or read64(s, fs + 88) != (read64(s, stat + 24) >> 32):
        return 0
    if read64(s, fs + 96) != (read64(s, stat + 32) & 4294967295) or read64(s, fs + 104) != read64(s, stat + 48):
        return 0
    return 1

def j_accept_dms(s:readbuf, w:mutbuf) -> u64:
    work = 128 + read64(s, 32) + read64(s, 40)
    put(w, 104, read64(s, 56))
    put(w, 112, read64(s, 72))
    put(w, 216, read64(s, work + 48))
    put(w, 224, read64(s, work + 56))
    put(w, 232, read64(s, work + 64))
    return 0

def j_accept_db(s:readbuf, w:mutbuf) -> u64:
    node = j_find(w, get(w, 120), 1)
    put(w, node + 72, read64(s, 56))
    if get(w, 168) == 1:
        put(w, node + 80, read64(s, 72))
        put(w, 328, read64(s, 72))
    return 0

def j_child(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    role = get(w, 152)
    stage = get(w, 184)
    out = 128 + read64(s, 32)
    if role == 4:
        if stage == 2 or stage == 10 or stage == 31 or stage == 60 or stage == 62:
            if j_gateway_frame(s, w) == 0:
                return j_reject(o, w, 22)
        if stage == 1:
            j_accept_dms(s, w)
            return j_finish(o, w, 0, 0, 0)
        if stage == 10:
            return j_pre_stat(s, o, w)
        if stage == 60:
            return j_reuse_stat(s, o, w)
        if stage == 62:
            return j_peer_fs_completed(s, o, w)
        if stage == 31:
            return j_db_actual_fs(s, o, w)
        if stage == 40:
            status = j_reserve(o, w, 296, 1, 512)
            if status != 0:
                return status
            j_accept_dms(s, w)
            if read64(s, out + 48) != 0:
                return j_reject(o, w, 23)
            file = j_find(w, get(w, 128), 2)
            put(w, file + 56, 0)
            return j_close_start(o, w)
        if stage != 2 and stage != 50 and stage != 51:
            return j_reject(o, w, 24)
        amount = read64(s, 40)
        if amount > 18446744073709551359:
            return j_reject(o, w, 25)
        status = j_reserve(o, w, 0, 0, 256 + amount)
        if status != 0:
            return status
        j_accept_dms(s, w)
        if stage == 50 and read64(s, out + 48) == 0:
            file = j_find(w, get(w, 128), 2)
            if read64(s, out + 64) == 0 or get(w, file + 56) != 0:
                return j_reject(o, w, 26)
            put(w, file + 56, read64(s, out + 64))
        if stage == 51 and get(w, 576) == 12:
            if read64(s, out + 48) != 0:
                return j_reject(o, w, 23)
            file = j_find(w, get(w, 128), 2)
            put(w, file + 56, 0)
        copy_input(o, s, 256, out, amount)
        return j_finish(o, w, read64(s, out + 48), read64(s, out + 56), amount)
    if stage == 11:
        status = j_reserve(o, w, 296, 1, 512)
        if status != 0:
            return status
        if read64(s, 24) != 0 or read64(s, out + 64) != 0 or read64(s, out + 96) != 0:
            return j_reject(o, w, 27)
        j_accept_db(s, w)
        return j_register_start(o, w)
    if stage == 61:
        return j_reuse_completed(s, o, w)
    if stage != 12 and stage != 30 and stage != 32:
        return j_reject(o, w, 28)
    if read64(s, 24) == 1:
        return j_db_pending(s, o, w)
    return j_db_completed(s, o, w)

def j_pre_stat(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if j_stat_frame(s, w) == 0:
        return j_reject(o, w, 29)
    out = 128 + read64(s, 32)
    work = out + read64(s, 40)
    fs = out + 256
    size = read64(s, out + 128)
    if read64(s, fs + 56) != 0:
        j_accept_dms(s, w)
        return j_finish(o, w, 10, read64(s, fs + 56), 0)
    if size > 18446744073709549560:
        return j_reject(o, w, 30)
    status = j_reserve(o, w, size + 2048, 5, size + 768)
    if status != 0:
        return status
    if get(w, 248) != 0 or read64(s, work + 48) <= get(w, 336) or read64(s, work + 56) <= get(w, 344):
        return j_reject(o, w, 31)
    j_accept_dms(s, w)
    saved = j_blob(w, 256 + size)
    copy_input(w, s, saved + 40, work + 768, 256)
    copy_input(w, s, saved + 296, fs, size)
    put(w, 248, get(w, saved + 16))
    node = j_node_key(w, read64(s, fs + 64), read64(s, fs + 72))
    created = 0
    if node == 0:
        node = j_allocate(w, 1, 192, 2)
        put(w, node + 32, read64(s, fs + 64))
        put(w, node + 40, read64(s, fs + 72))
        put(w, node + 48, get(w, 16) ^ get(w, 24) ^ 4924195321757843249)
        put(w, node + 56, get(w, node + 16))
        created = 1
    elif get(w, node + 24) != 1:
        return j_reject(o, w, 32)
    put(w, 120, get(w, node + 16))
    file = j_allocate(w, 2, 128, 2)
    put(w, file + 32, get(w, 120))
    put(w, file + 48, get(w, 576))
    put(w, file + 64, get(w, 584))
    put(w, 128, get(w, file + 16))
    if created != 0:
        j_db_header(w, 1, 0, 0, 0, 0)
        put(w, 1936, get(w, 80))
        put(w, 1944, get(w, 88))
        put(w, 1952, get(w, 336))
        put(w, 1960, get(w, 344))
        source = j_db_blob(w, 0)
        return j_issue(o, w, 5, get(w, 120), 1, source, 11)
    return j_register_start(o, w)

def j_register_start(o:mutbuf, w:mutbuf) -> u32:
    node = j_find(w, get(w, 120), 1)
    file = j_find(w, get(w, 128), 2)
    if node == 0 or file == 0 or get(w, node + 64) == 18446744073709551615 or get(w, file + 40) != 0 or get(w, 248) == 0:
        return j_reject(o, w, 33)
    j_db_header(w, 2, get(w, 144), 0, get(w, file + 48), get(w, file + 64))
    source = j_db_blob(w, 0)
    return j_issue(o, w, 5, get(w, 120), 0, source, 12)

def j_ack_header(w:mutbuf, payload:u64) -> u64:
    j_db_header(w, 7, get(w, 1112), get(w, 1072), 0, 0)
    put(w, 1896, get(w, 1064))
    put(w, 1912, get(w, 1080))
    put(w, 1984, payload)
    return 0

def j_db_pending(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    out = 128 + read64(s, 32)
    op = read64(s, out + 56)
    if read64(s, out + 40) == 0 or read64(s, out + 128) == 0 or read64(s, out + 88) != get(w, 144):
        return j_reject(o, w, 34)
    if get(w, 248) != 0:
        if get(w, 184) != 12 or get(w, 136) != 3 or op != 15 or read64(s, out + 40) != 1:
            return j_reject(o, w, 35)
        saved = j_find(w, get(w, 248), 3)
        if saved == 0:
            return j_reject(o, w, 35)
        size = get(w, saved + 32)
        if size > 18446744073709550840:
            return j_reject(o, w, 36)
        status = j_reserve(o, w, size + 304, 1, size + 512)
        if status != 0:
            return status
        saved = j_find(w, get(w, 248), 3)
        file = j_find(w, get(w, 128), 2)
        if read64(s, out + 128) != get(w, file + 48) or (read64(s, out + 136) | read64(s, out + 144) | read64(s, out + 152)) != 0:
            return j_reject(o, w, 35)
        j_accept_db(s, w)
        copy_input(w, s, 1024, out, 256)
        j_ack_header(w, size)
        source = j_db_blob(w, size)
        move_workspace(w, source + 296, saved + 40, size)
        j_drop(w, 248)
        return j_issue(o, w, 5, get(w, 120), 0, source, 32)
    if op != 8 and op != 17 and op != 23:
        return j_reject(o, w, 37)
    status = j_reserve(o, w, 360, 1, 576)
    if status != 0:
        return status
    j_accept_db(s, w)
    copy_input(w, s, 1024, out, 256)
    return j_gateway(o, w, op, read64(s, out + 128), read64(s, out + 136), read64(s, out + 144), read64(s, out + 152), read64(s, out + 40), 31)

def j_db_actual_fs(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    out = 128 + read64(s, 32)
    work = out + read64(s, 40)
    size = read64(s, out + 128)
    if size > 18446744073709550840:
        return j_reject(o, w, 38)
    if get(w, 1024) != DB_MAGIC or get(w, 1032) != 1 or get(w, 248) != 0:
        return j_reject(o, w, 39)
    if read64(s, work + 816) != get(w, 1080) or read64(s, work + 832) != get(w, 1152):
        return j_reject(o, w, 39)
    if read64(s, work + 840) != get(w, 1160) or read64(s, work + 848) != get(w, 1168) or read64(s, work + 856) != get(w, 1176):
        return j_reject(o, w, 39)
    if read64(s, work + 872) != get(w, 1064):
        return j_reject(o, w, 39)
    status = j_reserve(o, w, size + 560, 1, size + 768)
    if status != 0:
        return status
    j_accept_dms(s, w)
    j_ack_header(w, 256 + size)
    source = j_db_blob(w, 256 + size)
    copy_input(w, s, source + 296, work + 768, 256)
    copy_input(w, s, source + 552, out + 256, size)
    return j_issue(o, w, 5, get(w, 120), 0, source, 32)

def j_db_row(s:readbuf, work:u64, handle:u64) -> u64:
    at = work + 1536
    end = at + read64(s, work + 56) * 128
    found = 0
    while at < end:
        if read64(s, at + 16) != 0 and read64(s, at) == handle:
            if found != 0:
                return 0
            found = at
        at = at + 128
    return found

def j_sync_db(s:readbuf, w:mutbuf, work:u64) -> u64:
    node = j_find(w, get(w, 120), 1)
    count = 0
    at = 4096
    while at < get(w, 56):
        if get(w, at + 8) == 2 and get(w, at + 24) != 0 and get(w, at + 32) == get(w, 120):
            row = j_db_row(s, work, get(w, at + 40))
            if row == 0:
                if get(w, at + 24) == 1 or get(w, at + 56) != 0:
                    return 0
                put(w, at + 24, 0)
            else:
                if read64(s, row + 8) != get(w, at + 48) or read64(s, row + 32) != (get(w, at + 64) & 1) or read64(s, row + 40) != ((get(w, at + 64) >> 1) & 1):
                    return 0
                if read64(s, row + 16) != get(w, at + 24):
                    return 0
                if get(w, at + 24) == 1:
                    count = count + 1
                elif get(w, at + 56) != 0:
                    return 0
                put(w, at + 72, read64(s, row + 24))
                put(w, at + 80, read64(s, row + 48))
        at = at + get(w, at)
    if count != read64(s, work + 64):
        return 0
    put(w, node + 88, count)
    put(w, node + 96, read64(s, work + 88))
    put(w, node + 104, read64(s, work + 96))
    put(w, node + 112, read64(s, work + 72))
    put(w, node + 120, read64(s, work + 80))
    put(w, node + 128, read64(s, work + 48))
    return 1

def j_db_completed(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    out = 128 + read64(s, 32)
    work = out + read64(s, 40)
    if get(w, 248) != 0 or read64(s, 40) != 256:
        return j_reject(o, w, 40)
    status = j_reserve(o, w, 0, 0, 512)
    if status != 0:
        return status
    j_accept_db(s, w)
    node = j_find(w, get(w, 120), 1)
    file = j_find(w, get(w, 128), 2)
    if node == 0 or file == 0:
        return j_reject(o, w, 41)
    if get(w, 136) == 3:
        if read64(s, out + 64) != 0 or read64(s, out + 80) == 0 or get(w, file + 40) != 0 or get(w, file + 24) != 2:
            return j_reject(o, w, 42)
        put(w, file + 40, read64(s, out + 80))
        put(w, file + 24, 1)
        put(w, node + 24, 1)
    if get(w, 136) == 7:
        if read64(s, out + 64) != 0 or get(w, file + 56) != 0:
            return j_reject(o, w, 43)
        put(w, file + 24, 2)
    if j_sync_db(s, w, work) == 0:
        return j_reject(o, w, 44)
    if read64(s, out + 96) != read64(s, work + 64) or read64(s, out + 104) != read64(s, work + 72) or read64(s, out + 112) != read64(s, work + 80):
        return j_reject(o, w, 45)
    if read64(s, work + 8) == 4:
        if get(w, 136) != 7 or get(w, node + 88) != 0 or get(w, 40) == 18446744073709551615 or get(w, 320) == 18446744073709551615:
            return j_reject(o, w, 46)
        copy_input(w, s, 1280, out, 256)
        put(w, node + 24, 3)
        put(w, 40, get(w, 40) + 1)
        put(w, 152, 5)
        put(w, 160, get(w, 120))
        put(w, 168, 0)
        put(w, 184, 90)
        put(w, 8, 5)
        j_emit(o, w, 3, 0)
        put(o, 192, get(w, 320) + 1)
        return 3
    if get(w, node + 88) == 0:
        return j_reject(o, w, 47)
    copy_input(o, s, 256, out, 256)
    return j_finish(o, w, read64(s, out + 64), read64(s, out + 72), 256)

def j_retire_reply(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    node = j_find(w, get(w, 120), 1)
    if get(w, 8) != 5 or node == 0 or length(s) != 128 or read64(s, 16) != 5 or read64(s, 24) != 0:
        return j_reject(o, w, 48)
    if (read64(s, 32) | read64(s, 40) | read64(s, 48)) != 0 or read64(s, 56) != get(w, node + 72):
        return j_reject(o, w, 48)
    if read64(s, 64) != get(w, node + 16) or read64(s, 72) != get(w, node + 80) or read64(s, 80) != get(w, 40):
        return j_reject(o, w, 48)
    if read64(s, 96) != get(w, 320) + 1:
        return j_reject(o, w, 48)
    status = j_reserve(o, w, 0, 0, 512)
    if status != 0:
        return status
    node = j_find(w, get(w, 120), 1)
    put(w, 320, read64(s, 96))
    copy_workspace(o, w, 256, 1280, 256)
    code = get(w, 1344)
    error = get(w, 1352)
    j_finish(o, w, code, error, 256)
    put(w, node + 24, 0)
    return 0
def j_reuse_start(o:mutbuf, w:mutbuf, size:u64) -> u32:
    # SQLite only stats the path when its process-global inode list is nonempty.
    # No filesystem/gateway call is consumed for the empty-list fast path.
    at = 4096
    found = 0
    while at < get(w, 56):
        if get(w, at + 8) == 1 and get(w, at + 24) == 1:
            found = 1
        at = at + get(w, at)
    if found == 0:
        return j_finish(o, w, 0, 0, 0)
    if get(w, 96) == 18446744073709551615:
        return j_reject(o, w, 18)
    j_dms_header(w, 16, get(w, 144), 0, size)
    put(w, 1664, choose(size == 0, 29, 18))
    source = j_dms_blob(w, size)
    original = j_find(w, get(w, 256), 3)
    move_workspace(w, source + 360, original + 296, size)
    return j_issue(o, w, 4, 1, 0, source, 60)

def j_reuse_stat_frame(s:readbuf, w:mutbuf) -> u64:
    out = 128 + read64(s, 32)
    fs = out + 256
    # This is the actual path STAT, not a renamed registration FSTAT.
    expected_op = choose(get(w, 624) == 0, 29, 18)
    if read64(s, fs + 48) != expected_op or read64(s, fs + 112) != get(w, 144):
        return 0
    if read64(s, fs + 56) != 0:
        if read64(s, fs + 128) != 0 or read64(s, fs + 192) != 0:
            return 0
        at = 64
        while at < 112:
            if read64(s, fs + at) != 0:
                return 0
            at = at + 8
        return 1
    if read64(s, out + 128) < 400 or read64(s, fs + 128) != 144:
        return 0
    stat = fs + 256
    if read64(s, fs + 64) != read64(s, stat) or read64(s, fs + 72) != read64(s, stat + 8) or read64(s, fs + 192) != read64(s, stat + 16):
        return 0
    if read64(s, fs + 80) != (read64(s, stat + 24) & 4294967295) or read64(s, fs + 88) != (read64(s, stat + 24) >> 32):
        return 0
    if read64(s, fs + 96) != (read64(s, stat + 32) & 4294967295) or read64(s, fs + 104) != read64(s, stat + 48):
        return 0
    return 1

def j_reuse_stat(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if get(w, 136) != 10 or get(w, 120) != 0 or get(w, 128) != 0 or get(w, 248) != 0:
        return j_reject(o, w, 51)
    if j_reuse_stat_frame(s, w) == 0:
        return j_reject(o, w, 52)
    out = 128 + read64(s, 32)
    fs = out + 256
    if read64(s, fs + 56) != 0:
        # findReusableFd deliberately treats a failing stat as no reusable fd.
        # Accept the actual call/syscall watermarks, without changing DB state.
        j_accept_dms(s, w)
        return j_finish(o, w, 0, 0, 0)
    node = j_node_key(w, read64(s, fs + 64), read64(s, fs + 72))
    if node == 0:
        j_accept_dms(s, w)
        return j_finish(o, w, 0, 0, 0)
    if get(w, node + 24) != 1 or get(w, node + 64) == 18446744073709551615:
        return j_reject(o, w, 53)
    status = j_reserve(o, w, 296, 1, 512)
    if status != 0:
        return status
    # reserve may compact the directory. Reacquire this immutable inode key.
    node = j_node_key(w, read64(s, fs + 64), read64(s, fs + 72))
    if node == 0 or get(w, node + 24) != 1:
        return j_reject(o, w, 53)
    j_accept_dms(s, w)
    put(w, 120, get(w, node + 16))
    j_db_header(w, 9, get(w, 144), 0, get(w, 576), 0)
    source = j_db_blob(w, 0)
    return j_issue(o, w, 5, get(w, 120), 0, source, 61)

def j_reuse_completed(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    out = 128 + read64(s, 32)
    work = out + read64(s, 40)
    if get(w, 136) != 10 or get(w, 128) != 0 or get(w, 248) != 0:
        return j_reject(o, w, 54)
    if read64(s, 24) != 0 or read64(s, 40) != 256 or read64(s, out + 56) != 0:
        return j_reject(o, w, 54)
    if (read64(s, out + 64) | read64(s, out + 72)) != 0 or read64(s, work + 8) != 1:
        return j_reject(o, w, 54)
    node = j_find(w, get(w, 120), 1)
    if node == 0 or get(w, node + 24) != 1:
        return j_reject(o, w, 55)
    # Removing a pUnused cell cannot change reference or lock counters.
    if read64(s, work + 64) != get(w, node + 88) or read64(s, work + 72) != get(w, node + 112) or read64(s, work + 80) != get(w, node + 120):
        return j_reject(o, w, 55)
    if read64(s, work + 88) != get(w, node + 96) or read64(s, work + 96) != get(w, node + 104):
        return j_reject(o, w, 55)
    if read64(s, out + 96) != read64(s, work + 64) or read64(s, out + 104) != read64(s, work + 72) or read64(s, out + 112) != read64(s, work + 80):
        return j_reject(o, w, 55)
    token = read64(s, out + 80)
    file = 0
    if token != 0:
        file = j_token(w, token)
        if file == 0 or get(w, file + 24) != 2 or get(w, file + 32) != get(w, 120) or get(w, file + 56) != 0:
            return j_reject(o, w, 56)
        if 2 - (get(w, file + 64) & 1) != (get(w, 576) & 3):
            return j_reject(o, w, 56)
        row = j_db_row(s, work, get(w, file + 40))
        if row != 0:
            # Failed unlock can leave a token-free counter witness. It must
            # never remain a live descriptor capability after TAKE_UNUSED.
            if read64(s, row + 16) != 3 or read64(s, row + 8) != 0 or read64(s, row + 24) == 0 or read64(s, row + 56) != 0:
                return j_reject(o, w, 56)
    status = j_reserve(o, w, 0, 0, 512)
    if status != 0:
        return status
    j_accept_db(s, w)
    if file != 0:
        put(w, file + 24, 0)
    if j_sync_db(s, w, work) == 0:
        return j_reject(o, w, 57)
    copy_input(o, s, 256, out, 256)
    return j_finish(o, w, 0, 0, 256)

'''
def source_program():
    source=JOIN
    for name,value in (("JOIN_MAGIC",MAGIC),("JOIN_BAD",BAD),("JOIN_CHANNEL",CHANNEL),
                       ("DMS_MAGIC",DMS_MAGIC),("DMS_CHANNEL",DMS_CHANNEL),
                       ("DB_MAGIC",DB_MAGIC),("FS_MAGIC",FS_MAGIC)):
        source=source.replace(name,str(value))
    return source+VALUES[VALUES.index("\ndef read64("):]
def document():
    nodes=ast.parse(source_program()).body
    names={node.name:"f"+str(index) for index,node in enumerate(nodes)}
    if len(names)!=len(nodes):raise ValueError("duplicate main DB fixed join function")
    signatures={node.name:([arg.annotation.id for arg in node.args.args],node.returns.id) for node in nodes}
    total=total_scalar_functions(nodes);functions=[]
    for node in nodes:
        builder=ObjectBuilder(node,names,signatures,total);builder.statements(node.body)
        functions.append({"name":names[node.name],"params":[builder.param(v) for v in builder.params],
            "returns":[builder.returns],"effects":["read","write","trap"],"entry":"b0","blocks":builder.blocks})
    return compact_authoring_cfg({"schema":"hepta.hia.program.v8","module":"agent_namespace_db_issued_fs_r4","functions":functions})
if __name__=="__main__":
    path=ROOT/"examples/hia_bootstrap/agent_namespace_db_issued_fs_r4.hiaasm"
    path.write_text(render_assembly(document()));print(path.name,path.stat().st_size)
