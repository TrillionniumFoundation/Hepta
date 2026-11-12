"""NEW native SQLite-compatible DB-node/DMS/connection lifecycle and explicit fixed-join handoffs, integrated private join draft r7.

This file owns the selected ordinary Linux unix VFS open/DMS/WAL-lock/last-close
policy in HIA. Its input is private: a predecessor must issue the DB descriptor,
stable inode identity and canonical path, and a fixed dispatcher must issue FS
completion frames. Byte headers do not authenticate arbitrary external callers.
Map and memory continuations are joined here in HIA; the new dynamic fixed
carrier, actual joined validation and ordinary AgentStore integration remain OPEN.
"""
from __future__ import annotations
import ast
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_agent_namespace_objects import ObjectBuilder
from tools.generate_hia_agent_namespace_store import VALUES
from tools.generate_hia_selfhost import compact_authoring_cfg, total_scalar_functions
ROOT=Path(__file__).resolve().parents[1]
MAGIC=int.from_bytes(b"HIANDM03","little")
BAD=int.from_bytes(b"HIANDMB3","little")
CHANNEL=int.from_bytes(b"HIANDX03","little")
FS_MAGIC=int.from_bytes(b"HIANFR03","little")
DMS=r'''
def dms_entry(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < 8192:
        if length(w) >= 8:
            put(w, 0, DMS_BAD)
        return 4294967293
    if get(w, 0) == DMS_BAD:
        return dms_emit(o, w, 4294967293, 0)
    if length(s) < 320 or read64(s, 0) != DMS_CHANNEL or read64(s, 32) != length(s) - 64:
        return dms_reject(o, w, 44)
    page = read64(s, 48)
    if read64(s, 56) != 0 or page == 0 or page > 1073741824 or (page & (page - 1)) != 0:
        return dms_reject(o, w, 45)
    if get(w, 0) != 0 and page != get(w, 1352):
        return dms_reject(o, w, 92)
    origin = read64(s, 8)
    command = read64(s, 72)
    if origin == 1:
        if (read64(s, 16) | read64(s, 24) | read64(s, 40)) != 0 or (command < 1 or command > 7) and command != 10 and command != 12 and command != 14 and command != 15 and command != 16:
            return dms_reject(o, w, 46)
    elif origin == 2:
        if read64(s, 16) != 1 or (command != 8 and command != 11) or read64(s, 24) != read64(s, 152) or read64(s, 40) != read64(s, 160):
            return dms_reject(o, w, 47)
    elif origin == 3:
        expected_role = 1
        if get(w, 8) == 5:
            expected_role = get(w, 1280)
        if read64(s, 16) != expected_role or command != 9 or (read64(s, 24) | read64(s, 40)) != 0:
            return dms_reject(o, w, 48)
    elif origin == 4:
        if read64(s, 16) != 2 or command != 13 or read64(s, 24) != read64(s, 152) or read64(s, 40) != read64(s, 160):
            return dms_reject(o, w, 51)
    elif origin == 7:
        if read64(s, 16) != 4 or command != 19 or read64(s, 24) != 0 or read64(s, 40) != read64(s, 160):
            return dms_reject(o, w, 98)
    elif origin == 5 or origin == 6:
        role = origin - 3
        if read64(s, 16) != role or command != 15 + role or read64(s, 24) != read64(s, 152) or read64(s, 40) != read64(s, 160):
            return dms_reject(o, w, 87)
    else:
        return dms_reject(o, w, 49)
    return dms_owner(s, o, w)

def dms_length(s:readbuf) -> u64:
    return length(s) - 64

def dms_read(s:readbuf, at:u64) -> u64:
    return read64(s, 64 + at)

def dms_byte(s:readbuf, at:u64) -> u64:
    return byte(s, 64 + at)

def dms_copy(w:mutbuf, s:readbuf, target:u64, source:u64, amount:u64) -> u64:
    copy_input(w, s, target, 64 + source, amount)
    return 0

def dms_owner(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < 8192:
        if length(w) >= 8:
            put(w, 0, DMS_BAD)
        return 4294967293
    if get(w, 0) == DMS_BAD:
        return dms_emit(o, w, 4294967293, 0)
    if length(o) < 1280 or dms_length(s) < 256:
        return dms_reject(o, w, 1)
    if dms_read(s, 0) != DMS_MAGIC or dms_read(s, 128) != dms_length(s) - 256:
        return dms_reject(o, w, 2)
    at = 144
    while at < 256:
        if dms_read(s, at) != 0:
            return dms_reject(o, w, 3)
        at = at + 8
    command = dms_read(s, 8)
    if get(w, 0) == 0:
        return dms_init(s, o, w)
    if dms_steady(w) == 0:
        return dms_reject(o, w, 4)
    if dms_read(s, 16) != get(w, 16) or dms_read(s, 24) != get(w, 24):
        return dms_reject(o, w, 5)
    phase = get(w, 8)
    if phase == 10:
        if command != 19 or dj_retire_ack(s, w) == 0:
            return dms_reject(o, w, 99)
        put(w, 1336, dms_read(s, 96))
        node = dms_find(w, get(w, 136), 1)
        if node == 0:
            return dms_reject(o, w, 99)
        put(w, node + 24, 0)
        put(w, 136, 0)
        put(w, 1312, 0)
        put(w, 1344, 0)
        return dms_result(o, w, 0, 0)
    if phase == 6:
        if command == 9:
            return dms_reject(o, w, 93)
        if command != 8 or dms_init_ack_shape(s, w) == 0:
            return dms_reject(o, w, 94)
        put(w, 64, dms_read(s, 96))
        return dms_result(o, w, 0, 0)
    if phase == 5:
        if command == 9:
            if dms_length(s) != 256 or dms_read(s, 32) != get(w, 32) or dms_read(s, 40) != get(w, 40) or dms_read(s, 48) != get(w, 152):
                return dms_reject(o, w, 88)
            return dms_reject(o, w, 89)
        if command != 15 + get(w, 1280):
            return dms_reject(o, w, 90)
        return dj_child_reply(s, o, w)
    if phase == 8 or phase == 9:
        if command == 9:
            if dms_length(s) != 256 or dms_read(s, 32) != get(w, 32) or dms_read(s, 40) != get(w, 40) or dms_read(s, 48) != get(w, 152):
                return dms_reject(o, w, 6)
            return dms_reject(o, w, 7)
        if phase == 8:
            if command != 11 or dms_return_fs_shape(s, w) == 0:
                return dms_reject(o, w, 52)
            out = 256 + dms_read(s, 64)
            put(w, 48, dms_read(s, out + 32))
            put(w, 56, dms_read(s, out + 40))
            put(w, 64, dms_read(s, 96))
            return dms_result(o, w, 0, 0)
        if command != 13 or dms_purge_ack_shape(s, w) == 0:
            return dms_reject(o, w, 53)
        put(w, 464, dms_read(s, 96))
        put(w, 472, dms_read(s, 112))
        if dms_read(s, 104) != 0:
            put(w, 416, dms_read(s, 104))
        return dms_close_after_purge(o, w)
    if phase == 2 or phase == 4:
        if command == 9:
            if dms_length(s) != 256 or dms_read(s, 32) != get(w, 32) or dms_read(s, 40) != get(w, 40) or dms_read(s, 48) != get(w, 152):
                return dms_reject(o, w, 6)
            return dms_reject(o, w, 7)
        if command != 8:
            return dms_reject(o, w, 8)
        if phase == 2:
            if dms_fs_ack_shape(s, w) == 0:
                return dms_reject(o, w, 9)
            dms_copy(w, s, 1024, 0, 256)
            put(w, 56, get(w, 56) + 1)
            put(w, 64, dms_read(s, 96))
            put(w, 8, 4)
        else:
            at = 0
            while at < 256:
                if dms_byte(s, at) != byte(w, 1024 + at):
                    return dms_reject(o, w, 10)
                at = at + 1
        return dms_fs_reply(s, o, w)
    if phase == 3:
        at = 0
        while at < 256:
            if dms_byte(s, at) != byte(w, 512 + at):
                return dms_reject(o, w, 11)
            at = at + 1
        return dms_begin(s, o, w)
    if phase != 1 or (command < 2 or command > 7) and command != 10 and command != 12 and command != 14 and command != 15 and command != 16 or dms_request_shape(s) == 0:
        return dms_reject(o, w, 12)
    if get(w, 32) == 18446744073709551615 or dms_read(s, 32) != get(w, 32) + 1 or dms_read(s, 40) != 0:
        return dms_reject(o, w, 13)
    if dms_read(s, 48) == 0:
        return dms_reject(o, w, 13)
    dms_copy(w, s, 512, 0, 256)
    put(w, 32, dms_read(s, 32))
    put(w, 120, command)
    put(w, 152, dms_read(s, 48))
    put(w, 128, 0)
    put(w, 136, 0)
    put(w, 144, 0)
    put(w, 112, 10)
    put(w, 200, 0)
    put(w, 208, 0)
    put(w, 416, 0)
    put(w, 424, 0)
    put(w, 1280, 0)
    put(w, 1288, 0)
    put(w, 1296, 0)
    put(w, 1304, 0)
    put(w, 1320, 0)
    dms_zero(w, 4352, 256)
    put(w, 8, 3)
    return dms_begin(s, o, w)

def dms_init(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    at = 0
    while at < 8192:
        if byte(w, at) != 0:
            return dms_reject(o, w, 14)
        at = at + 1
    if dms_read(s, 8) != 1 or dms_length(s) != 256 or (dms_read(s, 16) | dms_read(s, 24)) == 0:
        return dms_reject(o, w, 15)
    if (dms_read(s, 32) | dms_read(s, 40) | dms_read(s, 48) | dms_read(s, 56)) != 0:
        return dms_reject(o, w, 15)
    if (dms_read(s, 64) | dms_read(s, 72)) == 0 or dms_read(s, 104) != 3 or dms_read(s, 112) != 420 or dms_read(s, 120) != 3:
        return dms_reject(o, w, 15)
    if (dms_read(s, 80) | dms_read(s, 88) | dms_read(s, 96) | dms_read(s, 136)) != 0:
        return dms_reject(o, w, 91)
    page = read64(s, 48)
    put(w, 1352, page)
    put(w, 0, DMS_MAGIC)
    put(w, 8, 1)
    put(w, 16, dms_read(s, 16))
    put(w, 24, dms_read(s, 24))
    put(w, 48, 0)
    put(w, 56, 0)
    put(w, 64, 0)
    put(w, 72, 1)
    put(w, 80, 8192)
    put(w, 232, dms_read(s, 64))
    put(w, 240, dms_read(s, 72))
    put(w, 248, 3)
    put(w, 480, DEV_NULL_WORD)
    store(w, 488, 108)
    put(w, 120, 1)
    put(w, 112, 90)
    put(w, 40, 1)
    put(w, 8, 6)
    dms_zero(w, 768, 256)
    put(w, 768, FS_MAGIC)
    put(w, 776, 1)
    put(w, 784, get(w, 232))
    put(w, 792, get(w, 240))
    dms_emit(o, w, 1, 256)
    copy_workspace(o, w, 256, 768, 256)
    return 1

def dj_retire_ack(s:readbuf, w:mutbuf) -> u64:
    if dms_length(s) != 512 or dms_read(s, 32) != get(w, 32) or dms_read(s, 40) != get(w, 40) or dms_read(s, 48) != get(w, 152) or dms_read(s, 56) != 4:
        return 0
    mask = get(w, 1312)
    count = (mask & 1) + ((mask >> 1) & 1)
    if dms_read(s, 64) != get(w, 136) or dms_read(s, 72) != mask or dms_read(s, 80) != count or dms_read(s, 88) != get(w, 1344):
        return 0
    if dms_read(s, 96) != get(w, 1336) + 1 or dms_read(s, 104) != 256 or (dms_read(s, 112) | dms_read(s, 120) | dms_read(s, 136)) != 0:
        return 0
    at = 0
    while at < 256:
        if dms_byte(s, 256 + at) != byte(w, 4608 + at):
            return 0
        at = at + 1
    return 1

def dj_internal_fs_token(w:mutbuf, token:u64, closing:u64) -> u64:
    if token == 0:
        return 0
    at = 8192
    while at < get(w, 80):
        if get(w, at + 24) == 1:
            if get(w, at + 8) == 1 and get(w, at + 48) == token:
                return 1
            if closing != 0 and get(w, at + 8) == 2 and get(w, at + 40) == token:
                return 1
        at = at + get(w, at)
    return 0

def dj_gateway(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    op = dms_read(s, 64)
    a = dms_read(s, 72)
    b = dms_read(s, 80)
    size = dms_read(s, 128)
    uses_a = choose(op != 12 and op != 13 and op != 14 and op != 16 and op != 20, 1, 0)
    if uses_a != 0 and dj_internal_fs_token(w, a, choose(op == 8, 1, 0)) != 0:
        return dms_reject(o, w, 96)
    if op == 7 and dj_internal_fs_token(w, b, 0) != 0:
        return dms_reject(o, w, 96)
    if size > 18446744073709551576:
        return dms_reject(o, w, 97)
    amount = 32 + ((size + 7) & 18446744073709551608)
    if size > 18446744073709551103:
        return dms_reject(o, w, 97)
    if dms_reserve(o, w, amount, 1, 512 + size) != 0:
        return 2
    pending = dms_allocate(w, 3, amount, 1)
    put(w, 144, get(w, pending + 16))
    if size != 0:
        dms_copy(w, s, pending + 32, 256, size)
    put(w, 112, 300)
    return dms_fs(o, w, op, a, b, dms_read(s, 88), dms_read(s, 96), pending + 32, size)

def dms_init_ack_shape(s:readbuf, w:mutbuf) -> u64:
    if dms_read(s, 32) != 0 or dms_read(s, 40) != 1 or dms_read(s, 48) != 0 or dms_read(s, 56) != 1:
        return 0
    if (dms_read(s, 104) | dms_read(s, 112) | dms_read(s, 120) | dms_read(s, 136)) != 0:
        return 0
    insize = dms_read(s, 64)
    outsize = dms_read(s, 72)
    worksize = dms_read(s, 80)
    if insize != 256 or outsize < 256 or worksize < 512 or dms_length(s) < 512:
        return 0
    remaining = dms_length(s) - 512
    if outsize > remaining or worksize != remaining - outsize or dms_read(s, 88) != 0 or dms_read(s, 96) != 1:
        return 0
    at = 0
    while at < 256:
        if dms_byte(s, 256 + at) != byte(w, 768 + at):
            return 0
        at = at + 1
    out = 512
    work = out + outsize
    at = 0
    while at < 256:
        expected = 0
        if at == 0:
            expected = FS_MAGIC
        elif at == 16:
            expected = get(w, 232)
        elif at == 24:
            expected = get(w, 240)
        elif at == 120 or at == 168:
            expected = 1
        elif at == 176:
            expected = 3
        if dms_read(s, out + at) != expected:
            return 0
        at = at + 8
    at = 0
    while at < 512:
        expected = 0
        if at == 0:
            expected = FS_MAGIC
        elif at == 8 or at == 64:
            expected = 1
        elif at == 16:
            expected = get(w, 232)
        elif at == 24:
            expected = get(w, 240)
        elif at == 248:
            expected = 3
        if dms_read(s, work + at) != expected:
            return 0
        at = at + 8
    at = 256
    while at < outsize:
        if dms_byte(s, out + at) != 0:
            return 0
        at = at + 1
    at = 512
    while at < worksize:
        if dms_byte(s, work + at) != 0:
            return 0
        at = at + 1
    return 1

def dms_request_shape(s:readbuf) -> u64:
    cmd = dms_read(s, 8)
    handle = dms_read(s, 56)
    size = dms_read(s, 128)
    if cmd == 16:
        if handle != 0 or dms_read(s, 64) == 0 or dms_read(s, 64) > 24:
            return 0
        return choose((dms_read(s, 104) | dms_read(s, 112) | dms_read(s, 120) | dms_read(s, 136)) == 0, 1, 0)
    if cmd == 14 or cmd == 15:
        if handle == 0 or size != 0 or (dms_read(s, 88) | dms_read(s, 96) | dms_read(s, 104) | dms_read(s, 112) | dms_read(s, 120) | dms_read(s, 136)) != 0:
            return 0
        if cmd == 14:
            return choose(dms_read(s, 72) <= 1 and dms_read(s, 80) == 32768, 1, 0)
        return choose((dms_read(s, 64) | dms_read(s, 72) | dms_read(s, 80)) == 0, 1, 0)
    if cmd == 10:
        at = 56
        while at < 144:
            if dms_read(s, at) != 0:
                return 0
            at = at + 8
        return choose(dms_length(s) == 256, 1, 0)
    if cmd == 2:
        if handle != 0 or dms_read(s, 64) == 0 or dms_read(s, 88) > 1 or dms_read(s, 96) > 1:
            return 0
        if (dms_read(s, 104) | dms_read(s, 112) | dms_read(s, 120) | dms_read(s, 136)) != 0 or size == 0:
            return 0
        at = 0
        while at < size:
            if dms_byte(s, 256 + at) == 0:
                return 0
            at = at + 1
        return 1
    if size != 0 or (dms_read(s, 64) | dms_read(s, 72) | dms_read(s, 80) | dms_read(s, 88) | dms_read(s, 96)) != 0:
        return 0
    if cmd == 4 or cmd == 5:
        kind = dms_read(s, 104)
        offset = dms_read(s, 112)
        count = dms_read(s, 120)
        if handle == 0 or kind < 1 or kind > 2 or offset >= 8 or count == 0 or count > 8 - offset or dms_read(s, 136) != 0:
            return 0
        if kind == 1 and count != 1:
            return 0
        return 1
    if (dms_read(s, 104) | dms_read(s, 112) | dms_read(s, 120)) != 0:
        return 0
    if cmd == 6 or cmd == 12:
        return choose(dms_read(s, 136) <= 1, 1, 0)
    return choose(handle != 0 and dms_read(s, 136) == 0, 1, 0)

def dms_find(w:mutbuf, identity:u64, kind:u64) -> u64:
    if identity == 0:
        return 0
    at = 8192
    while at < get(w, 80):
        if get(w, at + 16) == identity:
            if get(w, at + 24) == 0 or get(w, at + 8) != kind:
                return 0
            return at
        at = at + get(w, at)
    return 0

def dms_database_attached(w:mutbuf, token:u64) -> u64:
    at = 8192
    while at < get(w, 80):
        if get(w, at + 8) == 2 and get(w, at + 24) == 1 and get(w, at + 40) == token:
            return 1
        at = at + get(w, at)
    return 0


def dms_node_key(w:mutbuf, device:u64, number:u64) -> u64:
    at = 8192
    while at < get(w, 80):
        if get(w, at + 8) == 1 and get(w, at + 24) == 1 and get(w, at + 32) == device and get(w, at + 40) == number:
            return at
        at = at + get(w, at)
    return 0

def dms_other_masks(w:mutbuf, node:u64, connection:u64, kind:u64) -> u64:
    result = 0
    at = 8192
    while at < get(w, 80):
        if get(w, at + 8) == 2 and get(w, at + 24) == 1 and get(w, at + 32) == node and get(w, at + 16) != connection:
            if kind == 1:
                result = result | get(w, at + 48)
            else:
                result = result | get(w, at + 56)
        at = at + get(w, at)
    return result

def dms_steady(w:mutbuf) -> u64:
    if get(w, 0) != DMS_MAGIC or (get(w, 8) < 1 or get(w, 8) > 6) and get(w, 8) != 8 and get(w, 8) != 9 and get(w, 8) != 10 or get(w, 248) != 3:
        return 0
    if (get(w, 16) | get(w, 24)) == 0 or (get(w, 232) | get(w, 240)) == 0 or get(w, 104) != 0:
        return 0
    if get(w, 72) == 0 or get(w, 80) < 8192 or get(w, 80) > length(w) or (get(w, 80) & 7) != 0:
        return 0
    if dms_arena_bounds(w) == 0:
        return 0
    phase = get(w, 8)
    if phase == 1:
        if (get(w, 112) | get(w, 144) | get(w, 160) | get(w, 176) | get(w, 184)) != 0:
            return 0
    elif phase == 6:
        if get(w, 120) != 1 or get(w, 112) != 90 or get(w, 40) != 1 or get(w, 72) != 1 or get(w, 80) != 8192:
            return 0
        if (get(w, 32) | get(w, 48) | get(w, 56) | get(w, 64) | get(w, 88) | get(w, 96) | get(w, 128) | get(w, 136) | get(w, 144) | get(w, 152) | get(w, 160) | get(w, 176) | get(w, 184)) != 0:
            return 0
    elif (get(w, 120) < 2 or get(w, 120) > 7) and get(w, 120) != 10 and get(w, 120) != 12 and get(w, 120) != 14 and get(w, 120) != 15 and get(w, 120) != 16 or get(w, 152) == 0:
        return 0
    if phase == 5 and dj_pending(w) == 0:
        return 0
    if phase == 10:
        if get(w, 112) != 310 or (get(w, 120) != 6 and get(w, 120) != 12) or get(w, 1312) == 0 or get(w, 1312) > 3:
            return 0
        if (get(w, 128) | get(w, 144) | get(w, 160) | get(w, 176) | get(w, 184)) != 0 or get(w, 136) == 0:
            return 0
    if phase == 8:
        if get(w, 120) != 10 or get(w, 40) == 0 or (get(w, 112) | get(w, 144) | get(w, 160) | get(w, 176) | get(w, 184)) != 0:
            return 0
    if phase == 9:
        if get(w, 120) != 12 or get(w, 40) == 0 or get(w, 112) != 190 or get(w, 136) == 0 or (get(w, 128) | get(w, 144) | get(w, 160) | get(w, 176) | get(w, 184)) != 0:
            return 0
    if phase == 3 and get(w, 112) != 10:
        return 0
    if phase == 2 or phase == 4:
        expected_op = dms_stage_op(get(w, 112))
        if get(w, 112) == 300 and get(w, 120) == 16:
            expected_op = get(w, 576)
        if get(w, 40) == 0 or expected_op != get(w, 160) or get(w, 160) == 0:
            return 0
    count_nodes = 0
    count_connections = 0
    previous = 0
    at = 8192
    while at < get(w, 80):
        if get(w, 80) - at < 32:
            return 0
        span = get(w, at)
        kind = get(w, at + 8)
        identity = get(w, at + 16)
        live = get(w, at + 24)
        if span < 32 or (span & 7) != 0 or span > get(w, 80) - at or identity <= previous or identity >= get(w, 72) or live > 2:
            return 0
        previous = identity
        if kind == 1:
            if span < 256:
                return 0
            amount = get(w, at + 96)
            if amount > 18446744073709551352 or span != 256 + ((amount + 7) & 18446744073709551608):
                return 0
            if amount == 0 or get(w, at + 72) > 1 or get(w, at + 80) > 1 or get(w, at + 88) > 1 or get(w, at + 136) > 1:
                return 0
            if dj_node_shape(w, at, live) == 0:
                return 0
            if get(w, at + 104) > 511 or get(w, at + 112) > 4294967295 or get(w, at + 120) > 4294967295:
                return 0
            if live == 2 and (identity != get(w, 136) or get(w, at + 64) != 0):
                return 0
            if live == 1:
                count_nodes = count_nodes + 1
                if get(w, at + 64) == 0:
                    return 0
                if get(w, at + 136) == 0:
                    if get(w, at + 48) == 0 or get(w, at + 56) < 3:
                        return 0
                    if get(w, at + 80) == 0 and get(w, at + 88) != 1:
                        return 0
                elif (get(w, at + 48) | get(w, at + 56) | get(w, at + 72) | get(w, at + 80) | get(w, at + 88)) != 0:
                    return 0
                refs = 0
                scan = 8192
                while scan < get(w, 80):
                    if get(w, scan + 8) == 2 and get(w, scan + 24) == 1 and get(w, scan + 32) == identity:
                        refs = refs + 1
                    if scan < at and get(w, scan + 8) == 1 and get(w, scan + 24) == 1:
                        if get(w, scan + 32) == get(w, at + 32) and get(w, scan + 40) == get(w, at + 40):
                            return 0
                        if get(w, at + 48) != 0 and get(w, scan + 48) == get(w, at + 48):
                            return 0
                    scan = scan + get(w, scan)
                if refs != get(w, at + 64):
                    return 0
        elif kind == 2:
            if span != 96 or (get(w, at + 80) | get(w, at + 88)) != 0:
                return 0
            if get(w, at + 48) > 255 or get(w, at + 56) > 255 or (get(w, at + 48) & get(w, at + 56)) != 0:
                return 0
            if live == 2 and identity != get(w, 128):
                return 0
            if live == 1:
                count_connections = count_connections + 1
                node = dms_find(w, get(w, at + 32), 1)
                if node == 0 or get(w, node + 24) != 1 or get(w, at + 40) == 0 or get(w, at + 64) == 0:
                    return 0
                other_shared = dms_other_masks(w, get(w, at + 32), identity, 1)
                other_excl = dms_other_masks(w, get(w, at + 32), identity, 2)
                if (get(w, at + 56) & (other_shared | other_excl)) != 0 or (get(w, at + 48) & other_excl) != 0:
                    return 0
        elif kind == 3:
            if live == 2:
                return 0
            if live == 1 and identity != get(w, 144):
                return 0
        else:
            return 0
        at = at + span
    if at != get(w, 80) or count_nodes != get(w, 96) or count_connections != get(w, 88):
        return 0
    return 1

def dms_arena_bounds(w:mutbuf) -> u64:
    at = 8192
    previous = 0
    while at < get(w, 80):
        if get(w, 80) - at < 32:
            return 0
        span = get(w, at)
        kind = get(w, at + 8)
        identity = get(w, at + 16)
        if span < 32 or (span & 7) != 0 or span > get(w, 80) - at:
            return 0
        if identity <= previous or identity >= get(w, 72) or get(w, at + 24) > 2:
            return 0
        if kind == 1:
            if span < 256:
                return 0
        elif kind == 2:
            if span != 96:
                return 0
        elif kind != 3:
            return 0
        previous = identity
        at = at + span
    return choose(at == get(w, 80), 1, 0)

def dms_stage_op(stage:u64) -> u64:
    if stage == 100 or stage == 114 or stage == 210:
        return 15
    if stage == 110 or stage == 113:
        return 1
    if stage == 112 or stage == 130 or stage == 161:
        return 8
    if stage == 115:
        return 21
    if stage == 116:
        return 16
    if stage == 117:
        return 24
    if stage == 120:
        return 23
    if stage == 121 or stage == 123 or stage == 150:
        return 17
    if stage == 122:
        return 5
    if stage == 211:
        return 3
    if stage == 160:
        return 9
    return 0


def dms_compact(w:mutbuf) -> u64:
    source = 8192
    target = 8192
    end = get(w, 80)
    while source < end:
        span = get(w, source)
        if get(w, source + 24) != 0:
            if target != source:
                move_workspace(w, target, source, span)
            target = target + span
        source = source + span
    dms_zero(w, target, end - target)
    put(w, 80, target)
    return 0

def dms_reserve(o:mutbuf, w:mutbuf, amount:u64, nodes:u64, output:u64) -> u64:
    if nodes > 18446744073709551615 - get(w, 72):
        return dms_reject(o, w, 16)
    if amount > 18446744073709551615 - get(w, 80):
        return dms_reject(o, w, 16)
    if amount > length(w) - get(w, 80):
        dms_compact(w)
    if amount > 18446744073709551615 - get(w, 80):
        return dms_reject(o, w, 16)
    need = get(w, 80) + amount
    if need > length(w) or output > length(o):
        put(w, 176, need)
        put(w, 184, output)
        dms_emit(o, w, 2, 0)
        return 2
    put(w, 176, 0)
    put(w, 184, 0)
    return 0

def dms_allocate(w:mutbuf, kind:u64, span:u64, live:u64) -> u64:
    at = get(w, 80)
    dms_zero(w, at, span)
    put(w, at, span)
    put(w, at + 8, kind)
    put(w, at + 16, get(w, 72))
    put(w, at + 24, live)
    put(w, 72, get(w, 72) + 1)
    put(w, 80, at + span)
    return at

def dms_begin(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    cmd = get(w, 120)
    if cmd == 16:
        return dj_gateway(s, o, w)
    if cmd == 10:
        if get(w, 40) == 18446744073709551615:
            return dms_reject(o, w, 54)
        put(w, 40, get(w, 40) + 1)
        put(w, 112, 0)
        put(w, 8, 8)
        dms_emit(o, w, 3, 0)
        put(o, 152, get(w, 48))
        put(o, 160, get(w, 56))
        put(o, 168, get(w, 64))
        return 3
    if cmd == 2:
        if dms_database_attached(w, dms_read(s, 64)) != 0:
            return dms_reject(o, w, 50)
        size = dms_read(s, 128)
        if size > 18446744073709551096:
            return dms_reject(o, w, 17)
        needed = 128 + ((size + 7) & 18446744073709551608)
        status = dms_reserve(o, w, needed, 2, 516 + size)
        if status != 0:
            return status
        pending = dms_allocate(w, 3, 32 + ((size + 7) & 18446744073709551608), 1)
        put(w, 144, get(w, pending + 16))
        dms_copy(w, s, pending + 32, 256, size)
        connection = dms_allocate(w, 2, 96, 2)
        put(w, 128, get(w, connection + 16))
        put(w, connection + 40, dms_read(s, 64))
        put(w, connection + 64, dms_read(s, 48))
        node = dms_node_key(w, dms_read(s, 72), dms_read(s, 80))
        if node != 0:
            if get(w, node + 136) != dms_read(s, 96):
                return dms_reject(o, w, 43)
            put(w, 136, get(w, node + 16))
            return dms_attach(o, w, 0)
        put(w, 112, 100)
        return dms_fs(o, w, 15, dms_read(s, 64), 0, 0, 0, 0, 0)
    handle = dms_read(s, 56)
    if (cmd == 6 or cmd == 12) and handle == 0:
        return dms_result(o, w, 0, 0)
    connection = dms_find(w, handle, 2)
    if connection == 0 or get(w, connection + 24) != 1:
        return dms_reject(o, w, 18)
    node = dms_find(w, get(w, connection + 32), 1)
    if node == 0 or get(w, node + 24) != 1:
        return dms_reject(o, w, 18)
    status = dms_reserve(o, w, 0, 0, 512 + get(w, node + 96))
    if status != 0:
        return status
    connection = dms_find(w, handle, 2)
    node = dms_find(w, get(w, connection + 32), 1)
    put(w, 128, handle)
    put(w, 136, get(w, node + 16))
    if cmd == 14 or cmd == 15:
        return dj_enter(o, w)
    if cmd == 3:
        if get(w, node + 80) == 0:
            return dms_result(o, w, 0, 0)
        return dms_lock_start(o, w)
    if cmd == 4 or cmd == 5:
        return dms_wal(o, w)
    if cmd == 6 or cmd == 12:
        if (get(w, connection + 48) | get(w, connection + 56)) != 0:
            return dms_reject(o, w, 19)
        put(w, connection + 24, 0)
        put(w, 88, get(w, 88) - 1)
        put(w, node + 64, get(w, node + 64) - 1)
        put(w, 128, 0)
        if get(w, node + 64) != 0:
            return dms_result(o, w, 0, 0)
        put(w, node + 24, 2)
        put(w, 96, get(w, 96) - 1)
        if get(w, node + 48) == 0:
            return dj_last(o, w)
        if get(w, 648) != 0:
            put(w, 112, 160)
            return dms_fs(o, w, 9, 0, 0, 0, 0, node + 256, get(w, node + 96))
        return dms_last_close(o, w)
    return dms_result(o, w, 0, 0)

def dms_new_node(s:readbuf, o:mutbuf, w:mutbuf, out:u64) -> u32:
    error = dms_read(s, out + 56)
    if error != 0:
        return dms_failed_open(o, w, 1802, error)
    if dms_read(s, out + 64) != get(w, 584) or dms_read(s, out + 72) != get(w, 592):
        return dms_reject(o, w, 20)
    size = get(w, 640)
    if size > 18446744073709551348:
        return dms_reject(o, w, 21)
    span = 256 + ((size + 11) & 18446744073709551608)
    status = dms_reserve(o, w, span, 1, 516 + size)
    if status != 0:
        return status
    pending = dms_find(w, get(w, 144), 3)
    if pending == 0:
        return dms_reject(o, w, 22)
    node = dms_allocate(w, 1, span, 2)
    put(w, 136, get(w, node + 16))
    put(w, node + 32, get(w, 584))
    put(w, node + 40, get(w, 592))
    put(w, node + 96, size + 4)
    put(w, node + 104, dms_read(s, out + 80) & 511)
    put(w, node + 112, dms_read(s, out + 88))
    put(w, node + 120, dms_read(s, out + 96))
    put(w, node + 136, get(w, 608))
    move_workspace(w, node + 256, pending + 32, size)
    store(w, node + 256 + size, 45)
    store(w, node + 257 + size, 115)
    store(w, node + 258 + size, 104)
    store(w, node + 259 + size, 109)
    if get(w, node + 136) != 0:
        return dms_attach(o, w, 0)
    if get(w, 600) != 0:
        put(w, node + 72, 1)
        put(w, 320, 655360)
    else:
        put(w, 320, 655426)
    return dms_open(o, w)

def dms_open(o:mutbuf, w:mutbuf) -> u32:
    node = dms_find(w, get(w, 136), 1)
    if node == 0:
        return dms_reject(o, w, 23)
    mode = get(w, node + 104)
    if mode == 0:
        mode = 420
    put(w, 112, 110)
    return dms_fs(o, w, 1, 0, get(w, 320), mode, 0, node + 256, get(w, node + 96))

def dms_open_failed(o:mutbuf, w:mutbuf, error:u64) -> u32:
    if get(w, 320) == 655426:
        node = dms_find(w, get(w, 136), 1)
        if node == 0:
            return dms_reject(o, w, 24)
        put(w, node + 72, 1)
        put(w, 320, 655360)
        return dms_open(o, w)
    return dms_failed_open(o, w, 14, error)

def dms_raw_fd(s:readbuf, work:u64, worksize:u64, token:u64) -> u64:
    count = dms_read(s, work + 80)
    if count > (worksize - 512) >> 5:
        return 18446744073709551615
    at = 0
    while at < count:
        row = work + 512 + at * 32
        if dms_read(s, row + 16) == 1 and dms_read(s, row) == token:
            return dms_read(s, row + 8)
        at = at + 1
    return 18446744073709551615

def dms_open_complete(s:readbuf, o:mutbuf, w:mutbuf, out:u64, work:u64) -> u32:
    error = dms_read(s, out + 56)
    if error != 0:
        if error == 4:
            return dms_open(o, w)
        return dms_open_failed(o, w, error)
    token = dms_read(s, out + 64)
    raw = dms_raw_fd(s, work, dms_read(s, 80), token)
    if token == 0 or raw > 2147483647:
        return dms_reject(o, w, 25)
    if raw < 3:
        put(w, 312, token)
        put(w, 112, 112)
        return dms_fs(o, w, 8, token, 0, 0, 0, 0, 0)
    node = dms_find(w, get(w, 136), 1)
    if node == 0:
        return dms_reject(o, w, 26)
    put(w, node + 48, token)
    put(w, node + 56, raw)
    if get(w, node + 104) != 0:
        put(w, 112, 114)
        return dms_fs(o, w, 15, token, 0, 0, 0, 0, 0)
    return dms_chown_start(o, w)

def dms_chown_start(o:mutbuf, w:mutbuf) -> u32:
    put(w, 112, 116)
    return dms_fs(o, w, 16, 0, 0, 0, 0, 0, 0)

def dms_lock_start(o:mutbuf, w:mutbuf) -> u32:
    node = dms_find(w, get(w, 136), 1)
    if node == 0 or get(w, node + 48) == 0:
        return dms_reject(o, w, 27)
    put(w, 112, 120)
    return dms_fs(o, w, 23, get(w, node + 48), 1, 128, 1, 0, 0)

def dms_lock_done(o:mutbuf, w:mutbuf, result:u64, error:u64) -> u32:
    node = dms_find(w, get(w, 136), 1)
    if node == 0:
        return dms_reject(o, w, 28)
    if result == 0:
        put(w, node + 88, 1)
        put(w, node + 80, 0)
    if get(w, 120) == 14:
        if result == 0:
            return dj_map_ensure(o, w)
        return dms_result(o, w, result, error)
    if get(w, 120) == 2:
        if result == 0 or result == 1288:
            return dms_attach(o, w, result)
        return dms_failed_open(o, w, result, error)
    return dms_result(o, w, result, error)

def dms_attach(o:mutbuf, w:mutbuf, result:u64) -> u32:
    node = dms_find(w, get(w, 136), 1)
    connection = dms_find(w, get(w, 128), 2)
    if node == 0 or connection == 0 or get(w, connection + 24) != 2 or get(w, node + 64) == 18446744073709551615:
        return dms_reject(o, w, 29)
    if get(w, node + 24) == 2:
        put(w, node + 24, 1)
        put(w, 96, get(w, 96) + 1)
    put(w, node + 64, get(w, node + 64) + 1)
    put(w, connection + 32, get(w, node + 16))
    put(w, connection + 24, 1)
    put(w, 88, get(w, 88) + 1)
    return dms_result(o, w, result, 0)

def dms_failed_open(o:mutbuf, w:mutbuf, result:u64, error:u64) -> u32:
    put(w, 200, result)
    put(w, 208, error)
    node = dms_find(w, get(w, 136), 1)
    if node != 0:
        if get(w, node + 24) != 2 or get(w, node + 64) != 0:
            return dms_reject(o, w, 30)
        if get(w, node + 48) != 0:
            put(w, 112, 130)
            return dms_fs(o, w, 8, get(w, node + 48), 0, 0, 0, 0, 0)
    return dms_fail_finish(o, w)

def dms_fail_finish(o:mutbuf, w:mutbuf) -> u32:
    node = dms_find(w, get(w, 136), 1)
    connection = dms_find(w, get(w, 128), 2)
    if node != 0:
        put(w, node + 24, 0)
    if connection != 0:
        if get(w, connection + 24) != 2:
            return dms_reject(o, w, 31)
        put(w, connection + 24, 0)
    put(w, 128, 0)
    put(w, 136, 0)
    return dms_result(o, w, get(w, 200), get(w, 208))

def dms_wal(o:mutbuf, w:mutbuf) -> u32:
    connection = dms_find(w, get(w, 128), 2)
    node = dms_find(w, get(w, 136), 1)
    if connection == 0 or node == 0:
        return dms_reject(o, w, 32)
    kind = get(w, 616)
    offset = get(w, 624)
    count = get(w, 632)
    mask = ((1 << count) - 1) << offset
    shared = get(w, connection + 48)
    exclusive = get(w, connection + 56)
    other_shared = dms_other_masks(w, get(w, 136), get(w, 128), 1)
    other_excl = dms_other_masks(w, get(w, 136), get(w, 128), 2)
    put(w, 344, mask)
    put(w, 352, offset)
    put(w, 360, count)
    put(w, 368, kind)
    if get(w, 120) == 5:
        if ((shared | exclusive) & mask) == 0:
            return dms_result(o, w, 0, 0)
        if kind == 1:
            if (shared & mask) != mask or (exclusive & mask) != 0:
                return dms_reject(o, w, 33)
            if (other_shared & mask) != 0:
                put(w, connection + 48, shared & (18446744073709551615 - mask))
                return dms_result(o, w, 0, 0)
        elif (exclusive & mask) != mask or (shared & mask) != 0:
            return dms_reject(o, w, 33)
        put(w, 376, 2)
    elif kind == 1:
        if (shared & mask) != 0:
            return dms_result(o, w, 0, 0)
        if ((exclusive | other_excl) & mask) != 0:
            return dms_result(o, w, 5, 0)
        if (other_shared & mask) != 0:
            put(w, connection + 48, shared | mask)
            return dms_result(o, w, 0, 0)
        put(w, 376, 0)
    else:
        if ((shared | exclusive) & mask) != 0:
            return dms_reject(o, w, 34)
        if ((other_shared | other_excl) & mask) != 0:
            return dms_result(o, w, 5, 0)
        put(w, 376, 1)
    if get(w, node + 136) != 0:
        return dms_wal_apply(o, w)
    put(w, 112, 150)
    return dms_fs(o, w, 17, get(w, node + 48), get(w, 376), 120 + offset, count, 0, 0)

def dms_wal_apply(o:mutbuf, w:mutbuf) -> u32:
    connection = dms_find(w, get(w, 128), 2)
    if connection == 0:
        return dms_reject(o, w, 35)
    mask = get(w, 344)
    if get(w, 120) == 5:
        put(w, connection + 48, get(w, connection + 48) & (18446744073709551615 - mask))
        put(w, connection + 56, get(w, connection + 56) & (18446744073709551615 - mask))
    elif get(w, 368) == 1:
        put(w, connection + 48, get(w, connection + 48) | mask)
    else:
        put(w, connection + 56, get(w, connection + 56) | mask)
    return dms_result(o, w, 0, 0)

def dms_last_close(o:mutbuf, w:mutbuf) -> u32:
    return dj_last(o, w)

def dms_close_after_purge(o:mutbuf, w:mutbuf) -> u32:
    node = dms_find(w, get(w, 136), 1)
    if node == 0 or get(w, node + 64) != 0:
        return dms_reject(o, w, 36)
    if get(w, node + 48) == 0:
        return dms_finish_retire(o, w)
    put(w, 112, 161)
    return dms_fs(o, w, 8, get(w, node + 48), 0, 0, 0, 0, 0)

def dms_finish_retire(o:mutbuf, w:mutbuf) -> u32:
    node = dms_find(w, get(w, 136), 1)
    if node == 0 or get(w, node + 64) != 0:
        return dms_reject(o, w, 37)
    if get(w, node + 224) != 0:
        return dms_reject(o, w, 100)
    mask = 0
    if get(w, node + 144) != 0:
        if get(w, node + 144) != 2:
            return dms_reject(o, w, 100)
        mask = 1
    if get(w, node + 152) != 0:
        mask = mask | 2
    if mask != 0:
        if get(w, 40) == 18446744073709551615 or get(w, 1336) == 18446744073709551615:
            return dms_reject(o, w, 100)
        put(w, 40, get(w, 40) + 1)
        put(w, 1312, mask)
        put(w, 1344, get(w, node + 232))
        put(w, 112, 310)
        put(w, 8, 10)
        put(w, 160, 0)
        put(w, 176, 0)
        put(w, 184, 0)
        dms_emit(o, w, 6, 0)
        put(o, 48, mask)
        put(o, 56, get(w, 136))
        put(o, 64, get(w, 152))
        put(o, 72, get(w, 1344))
        put(o, 80, 0)
        put(o, 88, get(w, 1336) + 1)
        copy_workspace(w, o, 4608, 0, 256)
        return 6
    put(w, node + 24, 0)
    put(w, 136, 0)
    return dms_result(o, w, 0, 0)

def dms_fs(o:mutbuf, w:mutbuf, op:u64, a:u64, b:u64, c:u64, d:u64, start:u64, size:u64) -> u32:
    if length(o) < 512 or size > length(o) - 512 or start > length(w) or size > length(w) - start:
        return dms_reject(o, w, 38)
    if get(w, 48) == 18446744073709551615 or get(w, 56) == 18446744073709551615 or get(w, 40) == 18446744073709551615:
        return dms_reject(o, w, 39)
    put(w, 48, get(w, 48) + 1)
    put(w, 40, get(w, 40) + 1)
    put(w, 160, op)
    put(w, 448, start)
    put(w, 456, size)
    put(w, 8, 2)
    dms_zero(w, 768, 256)
    put(w, 768, FS_MAGIC)
    put(w, 776, 2)
    put(w, 784, get(w, 232))
    put(w, 792, get(w, 240))
    put(w, 800, get(w, 48))
    put(w, 816, op)
    put(w, 832, a)
    put(w, 840, b)
    put(w, 848, c)
    put(w, 856, d)
    put(w, 864, size)
    put(w, 872, get(w, 152))
    dms_emit(o, w, 1, 256 + size)
    copy_workspace(o, w, 256, 768, 256)
    if size != 0:
        copy_workspace(o, w, 512, start, size)
    return 1

def dms_fs_ack_shape(s:readbuf, w:mutbuf) -> u64:
    if dms_read(s, 32) != get(w, 32) or dms_read(s, 40) != get(w, 40) or dms_read(s, 48) != get(w, 152) or dms_read(s, 56) != 1:
        return 0
    if (dms_read(s, 104) | dms_read(s, 112) | dms_read(s, 120) | dms_read(s, 136)) != 0:
        return 0
    insize = dms_read(s, 64)
    outsize = dms_read(s, 72)
    worksize = dms_read(s, 80)
    if insize != 256 + get(w, 456) or outsize < 256 or worksize < 512 or insize > dms_length(s) - 256:
        return 0
    remaining = dms_length(s) - 256 - insize
    if outsize > remaining or worksize != remaining - outsize or dms_read(s, 88) != 0 or dms_read(s, 96) <= get(w, 64):
        return 0
    at = 0
    while at < 256:
        if dms_byte(s, 256 + at) != byte(w, 768 + at):
            return 0
        at = at + 1
    at = 0
    while at < get(w, 456):
        if dms_byte(s, 512 + at) != byte(w, get(w, 448) + at):
            return 0
        at = at + 1
    out = 256 + insize
    work = out + outsize
    if dms_read(s, out) != FS_MAGIC or dms_read(s, out + 8) != 0 or dms_read(s, out + 176) != 3 or dms_read(s, out + 120) != 1:
        return 0
    if dms_read(s, out + 16) != get(w, 232) or dms_read(s, out + 24) != get(w, 240) or dms_read(s, out + 32) != get(w, 48):
        return 0
    if dms_read(s, out + 40) != get(w, 56) + 1 or dms_read(s, out + 48) != get(w, 160) or dms_read(s, out + 112) != get(w, 152):
        return 0
    if dms_read(s, out + 56) > 4095 or dms_read(s, out + 128) > outsize - 256:
        return 0
    if dms_read(s, work) != FS_MAGIC or dms_read(s, work + 8) != 1 or dms_read(s, work + 248) != 3:
        return 0
    if dms_read(s, work + 16) != get(w, 232) or dms_read(s, work + 24) != get(w, 240) or dms_read(s, work + 32) != get(w, 48):
        return 0
    if dms_read(s, work + 40) != dms_read(s, out + 40) or dms_read(s, work + 72) != dms_read(s, out + 160) or dms_read(s, work + 64) != dms_read(s, out + 168):
        return 0
    if dms_read(s, work + 80) > (worksize - 512) >> 5 or dms_read(s, work + 72) > dms_read(s, work + 80):
        return 0
    at = 200
    while at < 256:
        if dms_read(s, out + at) != 0:
            return 0
        at = at + 8
    payload = dms_read(s, out + 128)
    if dms_read(s, out + 56) != 0:
        return choose(payload == 0, 1, 0)
    if get(w, 112) == 300:
        return 1
    if get(w, 160) == 15:
        return choose(payload == 144, 1, 0)
    if get(w, 160) == 23:
        if payload != 32 or dms_read(s, out + 64) > 2 or dms_read(s, out + 72) != 0:
            return 0
        return 1
    return choose(payload == 0, 1, 0)

def dms_fs_reply(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    out = 256 + dms_read(s, 64)
    work = out + dms_read(s, 72)
    error = dms_read(s, out + 56)
    stage = get(w, 112)
    if stage == 300:
        amount = dms_read(s, 72)
        if amount > 18446744073709551359:
            return dms_reject(o, w, 95)
        if amount > length(o) - 256:
            put(w, 176, length(w))
            put(w, 184, 256 + amount)
            dms_emit(o, w, 2, 0)
            return 2
        dms_result(o, w, 0, 0)
        put(o, 128, amount)
        put(o, 184, amount)
        put(o, 192, get(w, 64))
        copy_input(o, s, 256, 64 + out, amount)
        return 0
    if stage == 210 or stage == 211:
        return dj_fs_reply(s, o, w, out)
    if stage == 100:
        return dms_new_node(s, o, w, out)
    if stage == 110:
        return dms_open_complete(s, o, w, out, work)
    node = dms_find(w, get(w, 136), 1)
    if node == 0:
        return dms_reject(o, w, 40)
    if stage == 112:
        put(w, 416, error)
        put(w, 112, 113)
        return dms_fs(o, w, 1, 0, 0, get(w, node + 104), 0, 480, 9)
    if stage == 113:
        if error != 0:
            return dms_open_failed(o, w, error)
        token = dms_read(s, out + 64)
        raw = dms_raw_fd(s, work, dms_read(s, 80), token)
        if token == 0 or raw > 2147483647:
            return dms_reject(o, w, 41)
        if get(w, 432) == 18446744073709551615:
            return dms_reject(o, w, 41)
        put(w, 432, get(w, 432) + 1)
        return dms_open(o, w)
    if stage == 114:
        if error == 0 and dms_read(s, out + 104) == 0 and (dms_read(s, out + 80) & 511) != get(w, node + 104):
            put(w, 112, 115)
            return dms_fs(o, w, 21, get(w, node + 48), get(w, node + 104), 0, 0, 0, 0)
        return dms_chown_start(o, w)
    if stage == 115:
        put(w, 416, error)
        return dms_chown_start(o, w)
    if stage == 116:
        if error == 0 and dms_read(s, out + 64) == 0:
            put(w, 112, 117)
            return dms_fs(o, w, 24, get(w, node + 48), get(w, node + 112), get(w, node + 120), 0, 0, 0)
        return dms_lock_start(o, w)
    if stage == 117:
        put(w, 416, error)
        return dms_lock_start(o, w)
    if stage == 120:
        if error != 0:
            return dms_lock_done(o, w, 3850, error)
        lock = dms_read(s, out + 64)
        if lock == 1:
            return dms_lock_done(o, w, 5, 0)
        if lock == 2:
            if get(w, node + 72) != 0:
                put(w, node + 80, 1)
                return dms_lock_done(o, w, 1288, 0)
            put(w, 112, 121)
            return dms_fs(o, w, 17, get(w, node + 48), 1, 128, 1, 0, 0)
        put(w, 112, 123)
        return dms_fs(o, w, 17, get(w, node + 48), 0, 128, 1, 0, 0)
    if stage == 121:
        if error != 0:
            return dms_lock_done(o, w, 5, error)
        put(w, 112, 122)
        return dms_fs(o, w, 5, get(w, node + 48), 3, 0, 0, 0, 0)
    if stage == 122:
        if error == 4:
            return dms_fs(o, w, 5, get(w, node + 48), 3, 0, 0, 0, 0)
        if error != 0:
            return dms_lock_done(o, w, 4618, error)
        put(w, 112, 123)
        return dms_fs(o, w, 17, get(w, node + 48), 0, 128, 1, 0, 0)
    if stage == 123:
        if error != 0:
            return dms_lock_done(o, w, 5, error)
        return dms_lock_done(o, w, 0, 0)
    if stage == 130:
        put(w, 416, error)
        return dms_fail_finish(o, w)
    if stage == 150:
        if error != 0:
            return dms_result(o, w, 5, error)
        return dms_wal_apply(o, w)
    if stage == 160:
        put(w, 416, error)
        return dms_last_close(o, w)
    if stage == 161:
        put(w, 416, error)
        return dms_finish_retire(o, w)
    return dms_reject(o, w, 42)

def dms_offer_purge(o:mutbuf, w:mutbuf) -> u32:
    node = dms_find(w, get(w, 136), 1)
    if node == 0 or get(w, node + 24) != 2 or get(w, node + 64) != 0 or get(w, 40) == 18446744073709551615:
        return dms_reject(o, w, 55)
    put(w, 40, get(w, 40) + 1)
    put(w, 112, 190)
    put(w, 160, 0)
    put(w, 8, 9)
    dms_emit(o, w, 4, 0)
    put(o, 48, 2)
    put(o, 64, get(w, 136))
    put(o, 72, get(w, node + 48))
    put(o, 152, get(w, node + 136))
    return 4

def dms_purge_ack_shape(s:readbuf, w:mutbuf) -> u64:
    if dms_length(s) != 256 or dms_read(s, 32) != get(w, 32) or dms_read(s, 40) != get(w, 40) or dms_read(s, 48) != get(w, 152) or dms_read(s, 56) != 2:
        return 0
    node = dms_find(w, get(w, 136), 1)
    if node == 0 or get(w, node + 24) != 2 or get(w, node + 64) != 0:
        return 0
    if dms_read(s, 64) != get(w, 136) or dms_read(s, 72) != get(w, node + 48) or (dms_read(s, 80) | dms_read(s, 88) | dms_read(s, 136)) != 0:
        return 0
    if dms_read(s, 96) <= get(w, 464) or dms_read(s, 104) > 4095:
        return 0
    if dms_read(s, 120) != 0 and dms_read(s, 120) != get(w, 136):
        return 0
    return 1

def dms_return_fs_shape(s:readbuf, w:mutbuf) -> u64:
    if dms_read(s, 32) != get(w, 32) or dms_read(s, 40) != get(w, 40) or dms_read(s, 48) != get(w, 152) or dms_read(s, 56) != 1:
        return 0
    if (dms_read(s, 104) | dms_read(s, 112) | dms_read(s, 120) | dms_read(s, 136)) != 0:
        return 0
    insize = dms_read(s, 64)
    outsize = dms_read(s, 72)
    worksize = dms_read(s, 80)
    if insize < 256 or outsize < 256 or worksize < 512 or insize > dms_length(s) - 256:
        return 0
    remaining = dms_length(s) - 256 - insize
    if outsize > remaining or worksize != remaining - outsize or dms_read(s, 88) != 0 or dms_read(s, 96) < get(w, 64) or dms_read(s, 96) == 0:
        return 0
    source = 256
    out = source + insize
    work = out + outsize
    if dms_read(s, source) != FS_MAGIC or dms_read(s, source + 96) != insize - 256:
        return 0
    if dms_read(s, source + 16) != get(w, 232) or dms_read(s, source + 24) != get(w, 240):
        return 0
    if dms_read(s, out) != FS_MAGIC or dms_read(s, out + 8) != 0 or dms_read(s, out + 176) != 3 or dms_read(s, out + 120) != 1:
        return 0
    if dms_read(s, out + 16) != get(w, 232) or dms_read(s, out + 24) != get(w, 240) or dms_read(s, out + 32) < get(w, 48) or dms_read(s, out + 40) < get(w, 56):
        return 0
    if dms_read(s, out + 56) > 4095 or dms_read(s, out + 128) > outsize - 256:
        return 0
    if dms_read(s, work) != FS_MAGIC or dms_read(s, work + 8) != 1 or dms_read(s, work + 248) != 3 or dms_read(s, work + 56) != 0:
        return 0
    if dms_read(s, work + 16) != get(w, 232) or dms_read(s, work + 24) != get(w, 240) or dms_read(s, work + 32) != dms_read(s, out + 32) or dms_read(s, work + 40) != dms_read(s, out + 40):
        return 0
    if dms_read(s, source + 32) != dms_read(s, out + 32) or dms_read(s, work + 48) != dms_read(s, out + 48):
        return 0
    cmd = dms_read(s, source + 8)
    if cmd == 1:
        if insize != 256 or (dms_read(s, out + 32) | dms_read(s, out + 40) | dms_read(s, out + 48) | dms_read(s, out + 112)) != 0:
            return 0
        at = 32
        while at < 256:
            if dms_read(s, source + at) != 0:
                return 0
            at = at + 8
    elif cmd == 2:
        if (dms_read(s, source + 40) | dms_read(s, source + 56)) != 0 or dms_read(s, source + 48) != dms_read(s, out + 48) or dms_read(s, source + 104) != dms_read(s, out + 112):
            return 0
        if dms_read(s, source + 104) == 0 or dms_read(s, source + 48) == 0 or dms_read(s, source + 48) > 24:
            return 0
    else:
        return 0
    at = 112
    while at < 256:
        if dms_read(s, source + at) != 0:
            return 0
        at = at + 8
    at = 200
    while at < 256:
        if dms_read(s, out + at) != 0:
            return 0
        at = at + 8
    if dms_fs_snapshot_rows(s, work, worksize) == 0:
        return 0
    if dms_read(s, work + 72) != dms_read(s, out + 160) or dms_read(s, work + 64) != dms_read(s, out + 168):
        return 0
    at = 8192
    while at < get(w, 80):
        if get(w, at + 24) == 1:
            if get(w, at + 8) == 1 and get(w, at + 48) != 0:
                if dms_raw_fd(s, work, worksize, get(w, at + 48)) != get(w, at + 56):
                    return 0
            if get(w, at + 8) == 2:
                if dms_raw_fd(s, work, worksize, get(w, at + 40)) > 2147483647:
                    return 0
        at = at + get(w, at)
    return 1

def dms_fs_snapshot_rows(s:readbuf, work:u64, size:u64) -> u64:
    cap = dms_read(s, work + 80)
    if cap > (size - 512) >> 5 or dms_read(s, work + 64) == 0:
        return 0
    at = 88
    while at < 168:
        if dms_read(s, work + at) != 0:
            return 0
        at = at + 8
    at = 168
    while at < 248:
        if dms_read(s, work + at) != 0:
            return 0
        at = at + 8
    at = 256
    while at < 512:
        if dms_read(s, work + at) != 0:
            return 0
        at = at + 8
    index = 0
    live = 0
    while index < cap:
        row = work + 512 + (index << 5)
        token = dms_read(s, row)
        raw = dms_read(s, row + 8)
        state = dms_read(s, row + 16)
        if state > 1 or dms_read(s, row + 24) != 0:
            return 0
        if state == 0:
            if (token | raw) != 0:
                return 0
        else:
            if token == 0 or token >= dms_read(s, work + 64) or raw > 2147483647:
                return 0
            earlier = 0
            while earlier < index:
                previous = work + 512 + (earlier << 5)
                if dms_read(s, previous + 16) == 1 and (dms_read(s, previous) == token or dms_read(s, previous + 8) == raw):
                    return 0
                earlier = earlier + 1
            live = live + 1
        index = index + 1
    return choose(live == dms_read(s, work + 72), 1, 0)

def dms_result(o:mutbuf, w:mutbuf, code:u64, error:u64) -> u32:
    pending = dms_find(w, get(w, 144), 3)
    if pending != 0:
        put(w, pending + 24, 0)
    put(w, 144, 0)
    put(w, 8, 1)
    put(w, 112, 0)
    put(w, 160, 0)
    put(w, 176, 0)
    put(w, 184, 0)
    dms_emit(o, w, 0, 0)
    put(o, 48, code)
    put(o, 56, error)
    put(o, 64, get(w, 128))
    put(o, 72, get(w, 136))
    node = dms_find(w, get(w, 136), 1)
    if node != 0:
        put(o, 80, get(w, node + 64))
        put(o, 88, get(w, node + 72))
        put(o, 96, get(w, node + 80))
        put(o, 104, get(w, node + 88))
    connection = dms_find(w, get(w, 128), 2)
    if connection != 0:
        put(o, 112, get(w, connection + 48))
        put(o, 120, get(w, connection + 56))
    put(o, 136, get(w, 416))
    put(o, 144, get(w, 432))
    if get(w, 1320) == 1:
        put(o, 184, get(w, 4416))
        put(o, 192, get(w, 4424))
        put(o, 200, get(w, 4432))
        if get(w, 4432) != 0:
            put(o, 208, choose(get(w, 4496) == 1, 1, 3))
        if node != 0:
            put(o, 216, get(w, node + 160))
            put(o, 224, get(w, node + 16))
    put(w, 1280, 0)
    put(w, 1288, 0)
    put(w, 1296, 0)
    put(w, 1304, 0)
    put(w, 1320, 0)
    return 0

def dms_zero(w:mutbuf, at:u64, amount:u64) -> u64:
    end = at + amount
    while at < end:
        store(w, at, 0)
        at = at + 1
    return 0

def dms_reject(o:mutbuf, w:mutbuf, reason:u64) -> u32:
    if get(w, 0) != DMS_BAD:
        put(w, 104, reason)
    put(w, 0, DMS_BAD)
    put(w, 8, 7)
    return dms_emit(o, w, 4294967293, 0)

def dms_emit(o:mutbuf, w:mutbuf, status:u64, amount:u64) -> u32:
    if length(o) < 256:
        return 4294967293
    dms_zero(o, 0, 256)
    put(o, 0, DMS_MAGIC)
    put(o, 8, status)
    put(o, 16, get(w, 16))
    put(o, 24, get(w, 24))
    put(o, 32, get(w, 32))
    put(o, 40, get(w, 40))
    put(o, 48, 1)
    put(o, 56, get(w, 112))
    put(o, 64, amount)
    put(o, 72, get(w, 152))
    put(o, 80, get(w, 176))
    put(o, 88, get(w, 184))
    put(o, 96, get(w, 8))
    put(o, 104, get(w, 104))
    put(o, 128, amount)
    put(o, 152, get(w, 88))
    put(o, 160, get(w, 96))
    put(o, 168, get(w, 72))
    put(o, 176, 3)
    return status
def dj_node(w:mutbuf) -> u64:
    return dms_find(w, get(w, 136), 1)

def dj_nonce(w:mutbuf, role:u64) -> u64:
    if role == 2:
        return get(w, 16) ^ get(w, 136) ^ 0x4d4150
    return get(w, 16) ^ get(w, 136) ^ 0x4d454d

def dj_header(w:mutbuf, at:u64, role:u64, command:u64, call:u64, lease:u64) -> u64:
    dms_zero(w, at, choose(role == 2, 1024, 320))
    magic = JOIN_MAP_MAGIC
    channel = JOIN_MAP_CHANNEL
    if role == 3:
        magic = JOIN_MEM_MAGIC
        channel = JOIN_MEM_CHANNEL
    put(w, at, channel)
    put(w, at + 8, 1)
    put(w, at + 32, 256)
    put(w, at + 64, magic)
    put(w, at + 72, command)
    put(w, at + 80, dj_nonce(w, role))
    put(w, at + 88, get(w, 24) | 1)
    put(w, at + 96, call)
    put(w, at + 112, lease)
    put(w, at + 120, get(w, 136))
    return 0

def dj_child(o:mutbuf, w:mutbuf, role:u64, start:u64, amount:u64, create:u64, stage:u64) -> u32:
    if get(w, 40) == 18446744073709551615 or role < 2 or role > 3 or amount < 320 or amount > 1024 or length(o) < 256 + amount:
        return dms_reject(o, w, 60)
    if (role == 2 and start != 2048) or (role == 3 and start != 3072):
        return dms_reject(o, w, 61)
    put(w, 40, get(w, 40) + 1)
    put(w, 112, stage)
    put(w, 160, 0)
    put(w, 176, 0)
    put(w, 184, 0)
    put(w, 1280, role)
    put(w, 1288, start)
    put(w, 1296, amount)
    put(w, 1304, create)
    put(w, 8, 5)
    dms_emit(o, w, 5, amount)
    put(o, 48, role)
    put(o, 56, get(w, 136))
    put(o, 72, 1536)
    put(o, 80, choose(role == 2, 257, 256))
    put(o, 88, create)
    put(o, 112, stage)
    put(o, 120, get(w, 152))
    copy_workspace(o, w, 256, start, amount)
    return 5

def dj_enter(o:mutbuf, w:mutbuf) -> u32:
    node = dj_node(w)
    if node == 0 or get(w, node + 24) != 1:
        return dms_reject(o, w, 62)
    if get(w, 120) == 15:
        put(w, 1320, 2)
        return dj_memory_ensure(o, w)
    put(w, 1320, 1)
    if get(w, node + 80) != 0:
        return dms_lock_start(o, w)
    return dj_map_ensure(o, w)

def dj_map_ensure(o:mutbuf, w:mutbuf) -> u32:
    node = dj_node(w)
    if node == 0:
        return dms_reject(o, w, 63)
    if get(w, node + 144) == 1:
        return dj_map_user(o, w)
    if get(w, node + 144) != 0:
        return dms_reject(o, w, 64)
    dj_header(w, 2048, 2, 1, 0, 1)
    put(w, 2176, get(w, node + 48))
    put(w, 2184, get(w, node + 32))
    put(w, 2192, get(w, node + 40))
    put(w, 2200, get(w, node + 72))
    put(w, 2208, get(w, node + 136))
    put(w, 2216, get(w, 1352))
    put(w, 2224, get(w, 16))
    put(w, 2232, get(w, 24))
    put(w, 2248, get(w, node + 88))
    put(w, 2256, get(w, 136))
    return dj_child(o, w, 2, 2048, 320, 1, 200)

def dj_map_user(o:mutbuf, w:mutbuf) -> u32:
    node = dj_node(w)
    if node == 0 or get(w, node + 144) != 1 or get(w, node + 160) == 18446744073709551615:
        return dms_reject(o, w, 65)
    call = get(w, node + 160) + 1
    put(w, node + 160, call)
    command = 2
    stage = 201
    if get(w, 1320) == 3:
        command = 3
        stage = 203
    dj_header(w, 2048, 2, command, call, call)
    if command == 2:
        put(w, 2176, get(w, 576))
        put(w, 2184, 32768)
        put(w, 2192, get(w, 584))
    return dj_child(o, w, 2, 2048, 320, 0, stage)

def dj_last(o:mutbuf, w:mutbuf) -> u32:
    node = dj_node(w)
    if node == 0 or get(w, node + 64) != 0 or get(w, node + 24) != 2:
        return dms_reject(o, w, 66)
    if get(w, node + 144) == 1:
        put(w, 1320, 3)
        return dj_map_user(o, w)
    if get(w, node + 144) != 0:
        return dms_reject(o, w, 67)
    return dms_close_after_purge(o, w)

def dj_memory_ensure(o:mutbuf, w:mutbuf) -> u32:
    node = dj_node(w)
    if node == 0:
        return dms_reject(o, w, 68)
    if get(w, node + 152) == 1:
        return dj_memory_user(o, w)
    if get(w, node + 152) != 0:
        return dms_reject(o, w, 69)
    dj_header(w, 3072, 3, 1, 0, 0)
    put(w, 3200, get(w, 1352))
    put(w, 3208, get(w, 136))
    return dj_child(o, w, 3, 3072, 320, 1, 220)

def dj_memory_user(o:mutbuf, w:mutbuf) -> u32:
    node = dj_node(w)
    if node == 0 or get(w, node + 152) != 1 or get(w, node + 168) == 18446744073709551615:
        return dms_reject(o, w, 70)
    call = get(w, node + 168) + 1
    put(w, node + 168, call)
    dj_header(w, 3072, 3, 2, call, call)
    put(w, 3256, get(w, 136))
    if get(w, 1320) == 2:
        put(w, 3200, 6)
    else:
        operation = get(w, 3640)
        if operation < 1 or operation > 6 or get(w, 3632) != 2 or get(w, 3712) != 0:
            return dms_reject(o, w, 71)
        put(w, 3200, operation)
        put(w, 3208, get(w, 3648))
        put(w, 3216, get(w, 3656))
        put(w, 3224, get(w, 3664))
        put(w, 3232, get(w, 3672))
        if operation == 2:
            if get(w, 3648) != get(w, node + 48) or get(w, node + 136) != 0:
                return dms_reject(o, w, 72)
            put(w, 3240, get(w, node + 56))
            put(w, 3248, get(w, node + 48))
    return dj_child(o, w, 3, 3072, 320, 0, 221)

def dj_capsule(s:readbuf, w:mutbuf) -> u64:
    role = get(w, 1280)
    if role < 2 or role > 3 or get(w, 1296) < 320 or get(w, 1296) > 1024 or get(w, 1304) > 1:
        return 0
    if dms_read(s, 32) != get(w, 32) or dms_read(s, 40) != get(w, 40) or dms_read(s, 48) != get(w, 152) or dms_read(s, 56) != role:
        return 0
    if dms_read(s, 104) != get(w, 136) or dms_read(s, 112) != get(w, 1304) or dms_read(s, 120) != get(w, 112) or dms_read(s, 136) != 0:
        return 0
    insize = dms_read(s, 64)
    outsize = dms_read(s, 72)
    worksize = dms_read(s, 80)
    if insize != get(w, 1296) or insize > dms_length(s) - 256 or outsize < 256 or worksize < 1536:
        return 0
    remain = dms_length(s) - 256 - insize
    if outsize > remain or worksize != remain - outsize:
        return 0
    if role == 2 and outsize < 257:
        return 0
    at = 0
    while at < insize:
        if dms_byte(s, 256 + at) != byte(w, get(w, 1288) + at):
            return 0
        at = at + 1
    node = dj_node(w)
    if node == 0:
        return 0
    prior = get(w, node + 176)
    if role == 3:
        prior = get(w, node + 184)
    if dms_read(s, 96) <= prior:
        return 0
    out = 256 + insize
    work = out + outsize
    magic = JOIN_MAP_MAGIC
    if role == 3:
        magic = JOIN_MEM_MAGIC
    code = dms_read(s, 88)
    if code > 1 or (role == 3 and code != 0) or dms_read(s, out) != magic or dms_read(s, out + 8) != code or dms_read(s, work) != magic:
        return 0
    if dms_read(s, out + 16) != dj_nonce(w, role) or dms_read(s, out + 24) != (get(w, 24) | 1):
        return 0
    if dms_read(s, work + 16) != dms_read(s, out + 16) or dms_read(s, work + 24) != dms_read(s, out + 24):
        return 0
    if dms_read(s, out + 32) != dms_read(s, work + 32) or dms_read(s, out + 40) != dms_read(s, work + 40):
        return 0
    if dms_read(s, work + 56) != get(w, 136):
        return 0
    if role == 2:
        return dj_map_shape(s, w, out, work, code)
    return dj_memory_shape(s, w, out, work)

def dj_map_shape(s:readbuf, w:mutbuf, out:u64, work:u64, code:u64) -> u64:
    node = dj_node(w)
    if node == 0:
        return 0
    if dms_read(s, work + 32) != get(w, node + 160) or dms_read(s, out + 112) != dms_read(s, work + 48) or dms_read(s, out + 120) != get(w, 136):
        return 0
    if dms_read(s, work + 48) != choose(get(w, 112) == 200, 1, get(w, node + 160)):
        return 0
    if dms_read(s, out + 136) != dms_read(s, work + 8) or dms_read(s, out + 184) != 1:
        return 0
    if dms_read(s, work + 64) != get(w, node + 48) or dms_read(s, work + 72) != get(w, node + 72) or dms_read(s, work + 80) != get(w, node + 136):
        return 0
    if dms_read(s, work + 416) != get(w, 16) or dms_read(s, work + 424) != get(w, 24):
        return 0
    if dms_read(s, work + 432) != get(w, node + 32) or dms_read(s, work + 440) != get(w, node + 40) or dms_read(s, work + 448) != get(w, 1352) or dms_read(s, work + 472) != get(w, 136):
        return 0
    if code == 1:
        if dms_read(s, work + 8) != 2 or dms_read(s, out + 128) > 1 or dms_read(s, out + 128) > dms_read(s, 72) - 256:
            return 0
        if dms_read(s, out + 144) != dms_read(s, work + 88) or dms_read(s, out + 152) != dms_read(s, work + 104):
            return 0
        if dms_read(s, out + 160) != dms_read(s, work + 72) or dms_read(s, out + 168) != dms_read(s, work + 112):
            return 0
        return 1
    phase = dms_read(s, work + 8)
    if phase != 1 and phase != 6:
        return 0
    if dms_read(s, out + 48) > 4294967295 or dms_read(s, out + 56) > 4095:
        return 0
    if dms_read(s, out + 88) != dms_read(s, work + 88) or dms_read(s, out + 144) != dms_read(s, work + 72):
        return 0
    if dms_read(s, out + 152) != dms_read(s, work + 104) or dms_read(s, out + 160) != dms_read(s, work + 112) or dms_read(s, out + 168) != dms_read(s, work + 216) or dms_read(s, out + 192) != dms_read(s, work + 224):
        return 0
    return 1

def dj_memory_shape(s:readbuf, w:mutbuf, out:u64, work:u64) -> u64:
    node = dj_node(w)
    if node == 0 or dms_read(s, work + 8) != 1 or dms_read(s, work + 32) != get(w, node + 168):
        return 0
    if dms_read(s, work + 48) != get(w, node + 168):
        return 0
    if dms_read(s, out + 104) != dms_read(s, work + 216) or dms_read(s, out + 112) != dms_read(s, work + 224):
        return 0
    if dms_read(s, work + 240) != get(w, 136) or dms_read(s, work + 232) != get(w, 1352):
        return 0
    if dms_read(s, out + 48) != dms_read(s, work + 48) or dms_read(s, out + 56) != get(w, 136) or dms_read(s, out + 160) != 1:
        return 0
    if dms_read(s, out + 168) != dms_read(s, work + 80) or dms_read(s, out + 176) != dms_read(s, work + 88) or dms_read(s, out + 184) != get(w, 136) or dms_read(s, out + 192) != 0:
        return 0
    if dms_read(s, out + 64) > 4095 or (dms_read(s, out + 88) | dms_read(s, out + 96)) != 0:
        return 0
    if dms_read(s, out + 64) != 0 and (dms_read(s, out + 72) | dms_read(s, out + 80)) != 0:
        return 0
    return 1

def dj_child_reply(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if dj_capsule(s, w) == 0:
        return dms_reject(o, w, 73)
    node = dj_node(w)
    role = get(w, 1280)
    out = 256 + dms_read(s, 64)
    work = out + dms_read(s, 72)
    if role == 2:
        put(w, node + 176, dms_read(s, 96))
        return dj_map_reply(s, o, w, out, work)
    put(w, node + 184, dms_read(s, 96))
    put(w, node + 224, dms_read(s, work + 80))
    put(w, node + 232, dms_read(s, work + 88))
    if get(w, 112) == 220:
        if dms_read(s, out + 64) != 0 or (dms_read(s, work + 80) | dms_read(s, work + 88)) != 0:
            return dms_reject(o, w, 74)
        put(w, node + 152, 1)
        return dj_memory_user(o, w)
    if get(w, 112) != 221:
        return dms_reject(o, w, 75)
    if get(w, 1320) == 2:
        if dms_read(s, out + 64) != 0 or (dms_read(s, out + 72) | dms_read(s, out + 80)) != 0:
            return dms_reject(o, w, 76)
        return dms_result(o, w, 0, 0)
    return dj_map_ack(o, w, 2, dms_read(s, out + 64), dms_read(s, out + 72), dms_read(s, out + 80), dms_read(s, 96), 0)

def dj_map_reply(s:readbuf, o:mutbuf, w:mutbuf, out:u64, work:u64) -> u32:
    node = dj_node(w)
    if dms_read(s, 88) == 1:
        size = 256 + dms_read(s, out + 128)
        dms_copy(w, s, 3584, out, size)
        role = get(w, 3632)
        if role == 2:
            return dj_memory_ensure(o, w)
        if role != 1 or get(w, 3648) != get(w, node + 48) or get(w, node + 136) != 0:
            return dms_reject(o, w, 77)
        operation = get(w, 3640)
        if operation == 15:
            if (get(w, 3656) | get(w, 3664) | get(w, 3672) | get(w, 3712)) != 0:
                return dms_reject(o, w, 78)
            put(w, 112, 210)
            return dms_fs(o, w, 15, get(w, node + 48), 0, 0, 0, 0, 0)
        if operation == 3:
            if get(w, 3664) != 1 or get(w, 3672) != 0 or get(w, 3712) != 1 or byte(w, 3840) != 0:
                return dms_reject(o, w, 79)
            put(w, 112, 211)
            return dms_fs(o, w, 3, get(w, node + 48), get(w, 3656), 0, 0, 3840, 1)
        return dms_reject(o, w, 80)
    if get(w, 112) == 200:
        if dms_read(s, out + 48) != 0 or dms_read(s, work + 32) != 0 or dms_read(s, work + 8) != 1:
            return dms_reject(o, w, 81)
        put(w, node + 144, 1)
        return dj_map_user(o, w)
    if get(w, 1320) == 3:
        if dms_read(s, out + 48) != 0 or dms_read(s, work + 8) != 6 or (dms_read(s, work + 88) | dms_read(s, work + 96) | dms_read(s, work + 112)) != 0:
            return dms_reject(o, w, 82)
        if get(w, node + 224) != 0:
            return dms_reject(o, w, 83)
        put(w, node + 144, 2)
        put(w, 472, dms_read(s, out + 168))
        if dms_read(s, out + 192) != 0:
            put(w, 416, dms_read(s, out + 192))
        return dms_close_after_purge(o, w)
    if get(w, 1320) != 1 or dms_read(s, work + 8) != 1:
        return dms_reject(o, w, 84)
    dms_copy(w, s, 4352, out, 256)
    return dms_result(o, w, dms_read(s, out + 48), dms_read(s, out + 56))

def dj_fs_reply(s:readbuf, o:mutbuf, w:mutbuf, out:u64) -> u32:
    error = dms_read(s, out + 56)
    value = 0
    extent = 0
    result = 0
    if error == 0:
        if get(w, 112) == 210:
            dms_copy(w, s, 4096, out + 256, 144)
            extent = 144
            result = 144
        else:
            value = dms_read(s, out + 64)
            if value > 1:
                return dms_reject(o, w, 85)
    return dj_map_ack(o, w, 1, error, value, extent, dms_read(s, 96), result)

def dj_map_ack(o:mutbuf, w:mutbuf, role:u64, error:u64, value:u64, extent:u64, serial:u64, result:u64) -> u32:
    if get(w, 3632) != role or result > 144 or get(w, 3712) > 1:
        return dms_reject(o, w, 86)
    count = 256 + get(w, 3712)
    dj_header(w, 2048, 2, 5, get(w, 3616), get(w, 3696))
    put(w, 2056, 2)
    put(w, 2064, role)
    put(w, 2080, 256 + count + result)
    put(w, 2088, serial)
    put(w, 2152, get(w, 3624))
    put(w, 2176, role)
    put(w, 2184, get(w, 3640))
    put(w, 2192, error)
    put(w, 2200, value)
    put(w, 2208, extent)
    put(w, 2216, serial)
    put(w, 2240, count + result)
    put(w, 2248, count)
    put(w, 2256, result)
    move_workspace(w, 2368, 3584, count)
    if result != 0:
        move_workspace(w, 2368 + count, 4096, result)
    return dj_child(o, w, 2, 2048, 320 + count + result, 0, 205)

def dj_pending(w:mutbuf) -> u64:
    role = get(w, 1280)
    stage = get(w, 112)
    start = get(w, 1288)
    size = get(w, 1296)
    create = get(w, 1304)
    node = dj_node(w)
    if node == 0 or role < 2 or role > 3 or size < 320 or size > 1024 or create > 1 or get(w, 40) == 0:
        return 0
    if (get(w, 144) | get(w, 160) | get(w, 176) | get(w, 184)) != 0 or get(w, 1320) < 1 or get(w, 1320) > 3:
        return 0
    if role == 2:
        if start != 2048 or (stage != 200 and stage != 201 and stage != 203 and stage != 205):
            return 0
        if get(w, 1320) == 2 or create != choose(stage == 200, 1, 0):
            return 0
        if get(w, node + 144) != choose(stage == 200, 0, 1):
            return 0
        if get(w, start) != JOIN_MAP_CHANNEL or get(w, start + 64) != JOIN_MAP_MAGIC:
            return 0
    else:
        if start != 3072 or (stage != 220 and stage != 221) or size != 320:
            return 0
        if create != choose(stage == 220, 1, 0) or get(w, node + 152) != choose(stage == 220, 0, 1):
            return 0
        if get(w, start) != JOIN_MEM_CHANNEL or get(w, start + 64) != JOIN_MEM_MAGIC:
            return 0
    if get(w, start + 32) != size - 64 or (get(w, start + 48) | get(w, start + 56)) != 0:
        return 0
    if get(w, start + 80) != dj_nonce(w, role) or get(w, start + 88) != (get(w, 24) | 1) or get(w, start + 120) != get(w, 136):
        return 0
    return 1

def dj_node_shape(w:mutbuf, at:u64, live:u64) -> u64:
    if get(w, at + 128) != 0 or get(w, at + 144) > 2 or get(w, at + 152) > 1:
        return 0
    if (get(w, at + 192) | get(w, at + 200) | get(w, at + 208) | get(w, at + 216) | get(w, at + 240) | get(w, at + 248)) != 0:
        return 0
    if get(w, at + 144) == 0 and (get(w, at + 160) | get(w, at + 176)) != 0:
        return 0
    if get(w, at + 152) == 0 and (get(w, at + 168) | get(w, at + 184) | get(w, at + 224) | get(w, at + 232)) != 0:
        return 0
    if live == 1 and get(w, at + 144) == 2:
        return 0
    if get(w, at + 144) == 2 and get(w, at + 224) != 0:
        return 0
    return 1

'''
def source_program():
    source=DMS
    for name,value in [("DMS_MAGIC",MAGIC),("DMS_BAD",BAD),("DMS_CHANNEL",CHANNEL),("FS_MAGIC",FS_MAGIC),
                       ("DEV_NULL_WORD",int.from_bytes(b"/dev/nul","little")),
                       ("JOIN_MAP_MAGIC",int.from_bytes(b"HIASMP01","little")),
                       ("JOIN_MAP_CHANNEL",int.from_bytes(b"HIASMX01","little")),
                       ("JOIN_MEM_MAGIC",int.from_bytes(b"HIANML01","little")),
                       ("JOIN_MEM_CHANNEL",int.from_bytes(b"HIANMX01","little"))]:
        source=source.replace(name,str(value))
    return source+VALUES[VALUES.index("\ndef read64("):]
def document():
    nodes=ast.parse(source_program()).body
    names={node.name:"f"+str(index) for index,node in enumerate(nodes)}
    if len(names)!=len(nodes):
        raise ValueError("duplicate DMS symbol")
    signatures={node.name:([arg.annotation.id for arg in node.args.args],node.returns.id) for node in nodes}
    total=total_scalar_functions(nodes)
    functions=[]
    for node in nodes:
        b=ObjectBuilder(node,names,signatures,total)
        b.statements(node.body)
        functions.append({"name":names[node.name],"params":[b.param(v) for v in b.params],
            "returns":[b.returns],"effects":["read","write","trap"],"entry":"b0","blocks":b.blocks})
    return compact_authoring_cfg({"schema":"hepta.hia.program.v8","module":"agent_namespace_dms_map_join_r7","functions":functions})
if __name__=="__main__":
    path=ROOT/"examples/hia_bootstrap/agent_namespace_dms_map_join_r7.hiaasm"
    path.write_text(render_assembly(document()))
    print(path.name,path.stat().st_size)
