"""NEW native unixOpen raw-effect to shared FS gateway framer.

This is a private issued-view continuation, not a byte-header authenticator.
It maps all eight raw unixOpen effects through the same actual outer/DMS/FS
session. Other unixOpen peers and fixed issuer integration remain separate.
No execution evidence is inherited. The ABI requires original immutable
parent output and a correlated actual role-6 result/source/workspace lease.
"""
from __future__ import annotations
import ast
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_agent_namespace_objects import ObjectBuilder
from tools.generate_hia_agent_namespace_store import VALUES
from tools.generate_hia_selfhost import compact_authoring_cfg,total_scalar_functions
ROOT=Path(__file__).resolve().parents[1]
FRAMER=int.from_bytes(b"HIAUFS01","little")
BAD=int.from_bytes(b"HIAUFB01","little")
EVENT=int.from_bytes(b"HIAUFE01","little")
PEER=int.from_bytes(b"HIAUFP01","little")
PARENT=int.from_bytes(b"HIANUO01","little")
REQUEST=int.from_bytes(b"HIANUQ01","little")
JOIN=int.from_bytes(b"HIANDJ01","little")
CHANNEL=int.from_bytes(b"HIANDJX1","little")
FS=int.from_bytes(b"HIANFR03","little")
SOURCE=r'''
def unixopen_fs_framer(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    if length(w) < 512:
        if length(w) >= 8:
            put(w, 0, UF_BAD)
        return 4294967293
    if get(w, 0) == UF_BAD:
        return uf_emit(w, 4294967293, 0, 0, 0, get(w, 32))
    if length(s) < 640 or length(r) < 128:
        return uf_refuse(w, 1)
    if read64(s, 0) != UF_MAGIC or (read64(s, 16) | read64(s, 24)) == 0:
        return uf_refuse(w, 2)
    if read64(s, 32) == 0 or read64(s, 48) == 0 or read64(s, 56) == 0:
        return uf_refuse(w, 2)
    at = 64
    while at < 128:
        if read64(s, at) != 0:
            return uf_refuse(w, 2)
        at = at + 8
    if uf_parent(s) == 0 or uf_peer_layout(s, r) == 0:
        return uf_refuse(w, 3)
    command = read64(s, 8)
    if command == 1:
        if get(w, 0) == 0:
            at = 0
            while at < 512:
                if get(w, at) != 0:
                    return uf_refuse(w, 4)
                at = at + 8
            put(w, 0, UF_MAGIC)
            put(w, 8, 1)
            put(w, 16, read64(s, 16))
            put(w, 24, read64(s, 24))
        if get(w, 0) != UF_MAGIC or (get(w, 8) != 1 and get(w, 8) != 3):
            return uf_refuse(w, 4)
        if read64(s, 16) != get(w, 16) or read64(s, 24) != get(w, 24):
            return uf_refuse(w, 4)
        if get(w, 32) == 18446744073709551615 or read64(s, 32) != get(w, 32) + 1:
            return uf_refuse(w, 5)
        return uf_begin(s, r, w)
    if command != 2 or get(w, 0) != UF_MAGIC or get(w, 8) != 2:
        return uf_refuse(w, 6)
    if uf_stored(w) == 0 or read64(s, 32) != get(w, 32) or length(s) != get(w, 48):
        return uf_refuse(w, 6)
    at = 0
    while at < length(s):
        if at < 8 or at >= 16:
            if byte(s, at) != byte(w, 512 + at):
                return uf_refuse(w, 7)
        at = at + 1
    return uf_completed(s, r, w)

def uf_zero(w:mutbuf, at:u64, size:u64) -> u64:
    end = at + size
    while at < end:
        put(w, at, 0)
        at = at + 8
    return 0

def uf_parent(s:readbuf) -> u64:
    p = 128
    q = 384
    n = length(s) - 640
    if read64(s, 40) != 512 + n:
        return 0
    if read64(s, p) != UF_PARENT or read64(s, p + 8) != 1:
        return 0
    if (read64(s, p + 16) | read64(s, p + 24)) == 0 or read64(s, p + 32) == 0 or read64(s, p + 40) == 0:
        return 0
    if read64(s, p + 128) != 256 + n or read64(s, p + 72) > 4095 or read64(s, p + 248) == 0:
        return 0
    if read64(s, q) != UF_REQUEST or read64(s, q + 8) != 1:
        return 0
    at = 16
    while at < 64:
        if read64(s, q + at) != read64(s, p + at):
            return 0
        at = at + 8
    if read64(s, q + 112) != n or read64(s, q + 128) != read64(s, p + 248):
        return 0
    if (read64(s, q + 136) | read64(s, q + 144)) == 0:
        return 0
    if read64(s, q + 168) != 6 or read64(s, q + 176) == 0 or read64(s, q + 184) != read64(s, p + 72):
        return 0
    at = 192
    while at < 256:
        if read64(s, q + at) != 0:
            return 0
        at = at + 8
    at = 640
    while at < length(s):
        if byte(s, at) == 0:
            return 0
        at = at + 1
    op = read64(s, p + 48)
    stage = read64(s, p + 56)
    pathmode = read64(s, q + 120)
    a = read64(s, q + 64)
    b = read64(s, q + 72)
    c = read64(s, q + 80)
    if (read64(s, q + 88) | read64(s, q + 96) | read64(s, q + 104)) != 0:
        return 0
    if op == 1:
        return choose((stage == 10 or stage == 11) and (a | b | c | n | pathmode) == 0, 1, 0)
    if op == 8:
        return choose(stage == 32 and (a | b | c) == 0 and pathmode == 1, 1, 0)
    if op == 9:
        return choose(stage == 40 and (a | b | c | n | pathmode) == 0, 1, 0)
    if op == 10:
        return choose(stage == 41 and a != 0 and a == read64(s, p + 80) and b <= 4294967295 and c <= 4294967295 and (n | pathmode) == 0, 1, 0)
    if op == 11:
        return choose(stage == 50 and (a | b | c) == 0 and pathmode == 1, 1, 0)
    if op == 14:
        return choose(stage == 62 and a != 0 and a == read64(s, p + 80) and (b | c | n | pathmode) == 0, 1, 0)
    if op == 15:
        return choose(stage == 70 and a != 0 and a == read64(s, p + 80) and (b | c | n | pathmode) == 0, 1, 0)
    if op == 16:
        return choose(stage == 71 and (a | b | c) == 0 and pathmode == 4, 1, 0)
    return 0

def uf_fs_op(s:readbuf) -> u64:
    return uf_code(read64(s, 176), length(s) - 640)

def uf_code(op:u64, n:u64) -> u64:
    if op == 1:
        return 26
    if op == 8:
        return choose(n == 0, 30, 27)
    if op == 9:
        return 16
    if op == 10:
        return 24
    if op == 11:
        return choose(n == 0, 31, 9)
    if op == 14:
        return 8
    if op == 15:
        return 15
    if op == 16:
        return choose(n == 0, 29, 18)
    return 0

def uf_peer_layout(s:readbuf, r:readbuf) -> u64:
    if read64(r, 0) != UF_PEER or read64(r, 8) != read64(s, 8):
        return 0
    if read64(r, 40) != read64(s, 56) or read64(r, 48) == 0 or read64(r, 64) == 0:
        return 0
    if read64(r, 56) != 0:
        return 0
    if read64(r, 72) == 0 or read64(r, 80) != read64(s, 560):
        return 0
    at = 88
    while at < 128:
        if read64(r, at) != 0:
            return 0
        at = at + 8
    left = length(r) - 128
    if read64(r, 16) > left:
        return 0
    left = left - read64(r, 16)
    if read64(r, 24) > left:
        return 0
    left = left - read64(r, 24)
    if read64(r, 32) != left or left < 4096:
        return 0
    if read64(s, 8) == 1:
        return choose((read64(r, 16) | read64(r, 24)) == 0, 1, 0)
    return choose(read64(s, 8) == 2 and read64(r, 16) >= 640 and read64(r, 24) >= 512, 1, 0)

def uf_ready(s:readbuf, r:readbuf) -> u64:
    at = 128
    if read64(r, at) != UF_JOIN or read64(r, at + 8) != 1:
        return 0
    if (read64(r, at + 16) | read64(r, at + 24)) == 0 or read64(r, at + 32) == 18446744073709551615:
        return 0
    if read64(r, at + 80) != read64(s, 520) or read64(r, at + 88) != read64(s, 528):
        return 0
    if read64(r, at + 216) != read64(s, 536) or read64(r, at + 224) != read64(s, 544):
        return 0
    if read64(r, at + 216) == 18446744073709551615 or read64(r, at + 224) == 18446744073709551615:
        return 0
    if read64(r, at + 48) == 0 or read64(r, at + 56) < 4096 or read64(r, at + 56) > read64(r, 32):
        return 0
    if (read64(r, at + 120) | read64(r, at + 128) | read64(r, at + 136) | read64(r, at + 144) | read64(r, at + 152) | read64(r, at + 160) | read64(r, at + 168) | read64(r, at + 184)) != 0:
        return 0
    if (read64(r, at + 192) | read64(r, at + 200) | read64(r, at + 248) | read64(r, at + 256) | read64(r, at + 264)) != 0:
        return 0
    return 1

def uf_begin(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    if uf_ready(s, r) == 0:
        return uf_refuse(w, 8)
    size = length(s)
    if size > 18446744073709551096:
        return uf_refuse(w, 9)
    request = (512 + size + 7) & 18446744073709551608
    if size > 18446744073709551608 - request:
        return uf_refuse(w, 9)
    ack = (request + size + 7) & 18446744073709551608
    if ack > 18446744073709551103:
        return uf_refuse(w, 9)
    need = ack + 512
    if length(w) < need:
        put(w, 8, 1)
        put(w, 40, need)
        return uf_emit(w, 2, 0, 0, need, read64(s, 32))
    uf_zero(w, 0, 512)
    put(w, 0, UF_MAGIC)
    put(w, 8, 2)
    put(w, 16, read64(s, 16))
    put(w, 24, read64(s, 24))
    put(w, 32, read64(s, 32))
    put(w, 40, need)
    put(w, 48, size)
    put(w, 56, read64(s, 48))
    put(w, 64, read64(r, 40))
    put(w, 72, read64(r, 48))
    put(w, 80, read64(s, 536))
    put(w, 88, read64(s, 544))
    put(w, 96, read64(r, 160) + 1)
    put(w, 104, read64(r, 144))
    put(w, 112, read64(r, 152))
    put(w, 120, read64(s, 520))
    put(w, 128, read64(s, 528))
    put(w, 136, read64(s, 176))
    put(w, 144, uf_fs_op(s))
    put(w, 152, 11)
    if read64(s, 176) == 15 and read64(s, 288) != 0:
        put(w, 152, 12)
        put(w, 160, read64(s, 288))
    put(w, 168, size - 640)
    put(w, 176, read64(s, 200))
    put(w, 184, read64(r, 168))
    put(w, 192, request)
    put(w, 200, size)
    put(w, 208, ack)
    put(w, 224, read64(r, 72))
    copy_input(w, s, 512, 0, size)
    uf_request(w)
    return uf_emit(w, 1, request, size, need, get(w, 32))

def uf_request(w:mutbuf) -> u64:
    at = get(w, 192)
    size = get(w, 168)
    uf_zero(w, at, 640)
    put(w, at, UF_CHANNEL)
    put(w, at + 8, 1)
    put(w, at + 32, 512 + size)
    put(w, at + 88, 4096)
    put(w, at + 128, UF_JOIN)
    put(w, at + 136, get(w, 152))
    put(w, at + 144, get(w, 104))
    put(w, at + 152, get(w, 112))
    put(w, at + 160, get(w, 96))
    put(w, at + 176, get(w, 56))
    put(w, at + 184, get(w, 160))
    put(w, at + 240, 256 + size)
    put(w, at + 384, UF_FS)
    put(w, at + 392, 2)
    put(w, at + 400, get(w, 120))
    put(w, at + 408, get(w, 128))
    put(w, at + 416, get(w, 80) + 1)
    put(w, at + 432, get(w, 144))
    op = get(w, 136)
    if op == 10 or op == 14 or op == 15:
        put(w, at + 448, get(w, 960))
    if op == 10:
        put(w, at + 456, get(w, 968))
        put(w, at + 464, get(w, 976))
    put(w, at + 480, size)
    put(w, at + 488, get(w, 56))
    move_workspace(w, at + 640, 1152, size)
    return 0

def uf_stored(w:mutbuf) -> u64:
    if get(w, 48) < 640 or get(w, 168) != get(w, 48) - 640:
        return 0
    if get(w, 48) > 18446744073709551096:
        return 0
    request = (512 + get(w, 48) + 7) & 18446744073709551608
    if get(w, 48) > 18446744073709551608 - request:
        return 0
    ack = (request + get(w, 48) + 7) & 18446744073709551608
    if ack > 18446744073709551103:
        return 0
    if get(w, 192) != request or get(w, 200) != get(w, 48) or get(w, 208) != ack:
        return 0
    if get(w, 40) != ack + 512 or get(w, 40) > length(w):
        return 0
    if (get(w, 16) | get(w, 24)) == 0 or get(w, 32) == 0 or get(w, 56) == 0 or get(w, 64) == 0 or get(w, 72) == 0:
        return 0
    if get(w, 16) != get(w, 528) or get(w, 24) != get(w, 536) or get(w, 32) != get(w, 544):
        return 0
    if get(w, 56) != get(w, 560) or get(w, 64) != get(w, 568):
        return 0
    if get(w, 80) != get(w, 1048) or get(w, 88) != get(w, 1056) or get(w, 80) == 18446744073709551615 or get(w, 88) == 18446744073709551615:
        return 0
    if get(w, 120) != get(w, 1032) or get(w, 128) != get(w, 1040) or get(w, 136) != get(w, 688):
        return 0
    if get(w, 144) != uf_code(get(w, 136), get(w, 168)) or get(w, 144) == 0 or get(w, 176) != get(w, 712):
        return 0
    if get(w, 96) == 0 or (get(w, 104) | get(w, 112)) == 0:
        return 0
    if get(w, 216) != 0 or get(w, 224) == 0:
        return 0
    at = 232
    while at < 256:
        if get(w, at) != 0:
            return 0
        at = at + 8
    if get(w, 152) != 11 and get(w, 152) != 12:
        return 0
    if (get(w, 152) == 11 and get(w, 160) != 0) or (get(w, 152) == 12 and (get(w, 160) == 0 or get(w, 136) != 15)):
        return 0
    if get(w, 136) == 15 and get(w, 800) != 0:
        if get(w, 152) != 12 or get(w, 160) != get(w, 800):
            return 0
    elif get(w, 152) != 11:
        return 0
    return 1

def uf_completed(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    if read64(r, 40) != get(w, 64) or read64(r, 48) != get(w, 72) or read64(r, 72) <= get(w, 224):
        return uf_refuse(w, 10)
    if read64(r, 16) != get(w, 200):
        return uf_refuse(w, 10)
    at = 0
    while at < get(w, 200):
        if byte(r, 128 + at) != byte(w, get(w, 192) + at):
            return uf_refuse(w, 11)
        at = at + 1
    out = 128 + read64(r, 16)
    work = out + read64(r, 24)
    if read64(r, work) != UF_JOIN or read64(r, work + 8) != 1:
        return uf_refuse(w, 12)
    if read64(r, work + 16) != get(w, 104) or read64(r, work + 24) != get(w, 112) or read64(r, work + 32) != get(w, 96):
        return uf_refuse(w, 12)
    if read64(r, work + 40) <= get(w, 184):
        return uf_refuse(w, 12)
    if read64(r, work + 80) != get(w, 120) or read64(r, work + 88) != get(w, 128):
        return uf_refuse(w, 12)
    if read64(r, work + 216) != get(w, 80) + 1 or read64(r, work + 224) != get(w, 88) + 1:
        return uf_refuse(w, 12)
    if (read64(r, work + 120) | read64(r, work + 128) | read64(r, work + 136) | read64(r, work + 144) | read64(r, work + 152) | read64(r, work + 160) | read64(r, work + 168) | read64(r, work + 184)) != 0:
        return uf_refuse(w, 12)
    if (read64(r, work + 192) | read64(r, work + 200) | read64(r, work + 248) | read64(r, work + 256) | read64(r, work + 264)) != 0:
        return uf_refuse(w, 12)
    if read64(r, out) != UF_JOIN or read64(r, out + 8) != 0:
        return uf_refuse(w, 13)
    if read64(r, out + 16) != get(w, 104) or read64(r, out + 24) != get(w, 112) or read64(r, out + 32) != get(w, 96):
        return uf_refuse(w, 13)
    if read64(r, out + 40) != read64(r, work + 40) or (read64(r, out + 48) | read64(r, out + 56)) != 0:
        return uf_refuse(w, 13)
    if read64(r, out + 64) != read64(r, 24) - 256 or read64(r, out + 128) != read64(r, out + 64):
        return uf_refuse(w, 13)
    if read64(r, out + 104) != get(w, 56) or read64(r, out + 112) != get(w, 160) or read64(r, out + 176) != 1:
        return uf_refuse(w, 13)
    if (read64(r, out + 72) | read64(r, out + 80) | read64(r, out + 88) | read64(r, out + 96) | read64(r, out + 120) | read64(r, out + 136) | read64(r, out + 144) | read64(r, out + 152)) != 0:
        return uf_refuse(w, 13)
    fs = out + 256
    if uf_fs_result(r, fs, read64(r, 24) - 256, w) == 0:
        return uf_refuse(w, 14)
    uf_parent_ack(r, fs, w)
    put(w, 8, 3)
    return uf_emit(w, 0, get(w, 208), 512, get(w, 40), get(w, 32))

def uf_fs_result(r:readbuf, fs:u64, extent:u64, w:mutbuf) -> u64:
    if read64(r, fs) != UF_FS or read64(r, fs + 8) != 0:
        return 0
    if read64(r, fs + 16) != get(w, 120) or read64(r, fs + 24) != get(w, 128):
        return 0
    if read64(r, fs + 32) != get(w, 80) + 1 or read64(r, fs + 40) != get(w, 88) + 1 or read64(r, fs + 48) != get(w, 144):
        return 0
    if read64(r, fs + 112) != get(w, 56) or read64(r, fs + 120) != 1 or read64(r, fs + 176) != 3:
        return 0
    if read64(r, fs + 56) > 4095 or read64(r, fs + 128) != extent - 256:
        return 0
    if (read64(r, fs + 136) | read64(r, fs + 144) | read64(r, fs + 152) | read64(r, fs + 184)) != 0:
        return 0
    at = 200
    while at < 256:
        if read64(r, fs + at) != 0:
            return 0
        at = at + 8
    op = get(w, 136)
    error = read64(r, fs + 56)
    if error != 0:
        if op == 1 or op == 9 or extent != 256 or read64(r, fs + 192) != 0:
            return 0
        at = 64
        while at < 112:
            if read64(r, fs + at) != 0:
                return 0
            at = at + 8
        return 1
    if op == 15 or op == 16:
        if extent != 400:
            return 0
        if read64(r, fs + 64) != read64(r, fs + 256) or read64(r, fs + 72) != read64(r, fs + 264) or read64(r, fs + 192) != read64(r, fs + 272):
            return 0
        if read64(r, fs + 80) != (read64(r, fs + 280) & 4294967295) or read64(r, fs + 88) != (read64(r, fs + 280) >> 32):
            return 0
        if read64(r, fs + 96) != (read64(r, fs + 288) & 4294967295) or read64(r, fs + 104) != read64(r, fs + 304):
            return 0
        return 1
    if extent != 256 or read64(r, fs + 192) != 0:
        return 0
    at = 72
    while at < 112:
        if read64(r, fs + at) != 0:
            return 0
        at = at + 8
    if op == 1:
        return choose(read64(r, fs + 64) > 0 and read64(r, fs + 64) <= 2147483647, 1, 0)
    if op == 9:
        return choose(read64(r, fs + 64) <= 4294967295, 1, 0)
    return choose(read64(r, fs + 64) == 0, 1, 0)

def uf_parent_ack(r:readbuf, fs:u64, w:mutbuf) -> u64:
    ack = get(w, 208)
    uf_zero(w, ack, 512)
    put(w, ack, UF_PARENT)
    put(w, ack + 8, 2)
    move_workspace(w, ack + 16, 656, 48)
    error = read64(r, fs + 56)
    saved_errno = get(w, 176)
    if error != 0:
        saved_errno = error
    put(w, ack + 64, saved_errno)
    op = get(w, 136)
    if op == 1 or op == 9:
        put(w, ack + 72, read64(r, fs + 64))
    else:
        put(w, ack + 72, error)
        if error == 0 and (op == 15 or op == 16):
            put(w, ack + 80, read64(r, fs + 72))
            put(w, ack + 88, read64(r, fs + 192))
    put(w, ack + 120, read64(r, fs + 32))
    put(w, ack + 128, read64(r, fs + 40))
    put(w, ack + 144, 6)
    put(w, ack + 152, read64(r, 40))
    put(w, ack + 160, read64(r, 48))
    put(w, ack + 168, read64(r, 72))
    put(w, ack + 176, get(w, 56))
    move_workspace(w, ack + 256, 896, 256)
    return 0

def uf_refuse(w:mutbuf, reason:u64) -> u32:
    if get(w, 0) != UF_BAD:
        put(w, 216, reason)
    put(w, 0, UF_BAD)
    put(w, 8, 4)
    return uf_emit(w, 4294967293, 0, 0, 0, get(w, 32))

def uf_emit(w:mutbuf, status:u64, offset:u64, size:u64, need:u64, call:u64) -> u32:
    uf_zero(w, 256, 256)
    put(w, 256, UF_EVENT)
    put(w, 264, status)
    put(w, 272, call)
    put(w, 304, offset)
    put(w, 312, size)
    put(w, 320, need)
    put(w, 344, get(w, 216))
    if get(w, 8) == 2 or get(w, 8) == 3:
        put(w, 328, get(w, 56))
        put(w, 336, get(w, 64))
        put(w, 352, get(w, 152))
        put(w, 360, get(w, 96))
        put(w, 280, get(w, 672))
        put(w, 288, get(w, 680))
        put(w, 296, get(w, 136))
        put(w, 368, get(w, 80) + 1)
        put(w, 376, get(w, 88) + 1)
    return status
'''
def source_program():
    source=SOURCE
    for name,value in (("UF_MAGIC",FRAMER),("UF_BAD",BAD),("UF_EVENT",EVENT),
        ("UF_PEER",PEER),("UF_PARENT",PARENT),("UF_REQUEST",REQUEST),
        ("UF_CHANNEL",CHANNEL),("UF_JOIN",JOIN),("UF_FS",FS)):
        source=source.replace(name,str(value))
    return source+VALUES[VALUES.index("\ndef read64("):]
def document():
    nodes=ast.parse(source_program()).body
    names={node.name:"f"+str(i+1) for i,node in enumerate(nodes)}
    if len(names)!=len(nodes):raise ValueError("duplicate unixOpen FS framer symbol")
    signatures={node.name:([a.annotation.id for a in node.args.args],node.returns.id) for node in nodes}
    total=total_scalar_functions(nodes)
    functions=[{"name":"f0","params":[{"name":"s","type":"readbuf"},{"name":"peer","type":"mutbuf"},{"name":"w","type":"mutbuf"}],
        "returns":["u32"],"effects":["read","write","trap"],"entry":"b0",
        "blocks":[{"id":"b0","params":[{"name":"s","type":"readbuf"},{"name":"peer","type":"mutbuf"},{"name":"w","type":"mutbuf"}],"ops":[
            {"op":"borrow.read","args":["peer"],"out":[{"name":"r","type":"readbuf"}],"attrs":{}},
            {"op":"call","args":["s","r","w"],"out":[{"name":"status","type":"u32"}],"attrs":{"function":names["unixopen_fs_framer"]}},
            {"op":"loan.end","args":["r"],"out":[],"attrs":{}}],
            "term":{"op":"ret","values":["status"]}}]}]
    for node in nodes:
        b=ObjectBuilder(node,names,signatures,total);b.statements(node.body)
        functions.append({"name":names[node.name],"params":[b.param(v) for v in b.params],
            "returns":[b.returns],"effects":["read","write","trap"],"entry":"b0","blocks":b.blocks})
    return compact_authoring_cfg({"schema":"hepta.hia.program.v8",
        "module":"agent_namespace_unixopen_fs_framer_r4","functions":functions})
if __name__=="__main__":
    path=ROOT/"examples/hia_bootstrap/agent_namespace_unixopen_fs_framer_r4.hiaasm"
    path.write_text(render_assembly(document()))
    print(path.name,path.stat().st_size)
