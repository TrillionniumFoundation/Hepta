"""Namespace filesystem r5 draft: private ABI3 plus raw FCHOWN operation24.

NEW_AUTHORING_ONLY until separately generated, compiled, and executed. This source
does not reproduce the currently inaccessible earlier FS r2 artifact. It owns
logical descriptor issuance, syscall continuations, growth and retirement; it
does not yet admit roots, migrate SQLite or implement an ordinary AgentStore.
"""
from __future__ import annotations
import ast
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_agent_namespace_objects import ObjectBuilder
from tools.generate_hia_agent_namespace_store import VALUES
from tools.generate_hia_selfhost import compact_authoring_cfg, total_scalar_functions
ROOT=Path(__file__).resolve().parents[1]
MAGIC=int.from_bytes(b"HIANFR03","little")
BADMAGIC=int.from_bytes(b"HIANBAD3","little")
FS = r'''
def filesystem(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < 512:
        if length(w) >= 8:
            put(w, 0, FS_BADMAGIC)
        return 4294967293
    if get(w, 0) == FS_BADMAGIC:
        return emit(o, w, 4294967293, 0, 0)
    if length(o) < 256:
        refuse(w, 1)
        return 4294967293
    if length(s) < 256:
        refuse(w, 2)
        return emit(o, w, 4294967293, 0, 0)
    if read64(s, 0) != FS_MAGIC or read64(s, 96) != length(s) - 256:
        refuse(w, 3)
        return emit(o, w, 4294967293, 0, 0)
    at = 112
    while at < 256:
        if read64(s, at) != 0:
            refuse(w, 4)
            return emit(o, w, 4294967293, 0, 0)
        at = at + 8
    command = read64(s, 8)
    if get(w, 0) == 0:
        at = 0
        while at < 512:
            if get(w, at) != 0:
                refuse(w, 5)
                return emit(o, w, 4294967293, 0, 0)
            at = at + 8
        if command != 1 or length(s) != 256:
            refuse(w, 6)
            return emit(o, w, 4294967293, 0, 0)
        if (read64(s, 16) | read64(s, 24)) == 0:
            refuse(w, 6)
            return emit(o, w, 4294967293, 0, 0)
        at = 32
        while at < 256:
            if read64(s, at) != 0:
                refuse(w, 6)
                return emit(o, w, 4294967293, 0, 0)
            at = at + 8
        put(w, 0, FS_MAGIC)
        put(w, 8, 1)
        put(w, 16, read64(s, 16))
        put(w, 24, read64(s, 24))
        put(w, 64, 1)
        put(w, 248, 3)
        return emit(o, w, 0, 0, 0)
    if steady(w) == 0:
        refuse(w, 7)
        return emit(o, w, 4294967293, 0, 0)
    if read64(s, 16) != get(w, 16) or read64(s, 24) != get(w, 24):
        refuse(w, 8)
        return emit(o, w, 4294967293, 0, 0)
    phase = get(w, 8)
    if phase == 5:
        refuse(w, 9)
        return emit(o, w, 4294967293, 0, 0)
    if command == 2:
        if phase == 1:
            if get(w, 32) == 18446744073709551615 or read64(s, 32) != get(w, 32) + 1:
                refuse(w, 10)
                return emit(o, w, 4294967293, 0, 0)
            if read64(s, 40) != 0 or read64(s, 56) != 0 or read64(s, 104) == 0:
                refuse(w, 11)
                return emit(o, w, 4294967293, 0, 0)
            if call_shape(s, w) == 0:
                refuse(w, 12)
                return emit(o, w, 4294967293, 0, 0)
            put(w, 32, read64(s, 32))
            put(w, 48, read64(s, 48))
            put(w, 88, read64(s, 104))
            put(w, 96, read64(s, 96))
            copy_input(w, s, 256, 0, 256)
            put(w, 8, 3)
        elif phase == 3:
            at = 0
            while at < 256:
                if read64(s, at) != get(w, 256 + at):
                    refuse(w, 13)
                    return emit(o, w, 4294967293, 0, 0)
                at = at + 8
            if call_shape(s, w) == 0:
                refuse(w, 12)
                return emit(o, w, 4294967293, 0, 0)
        else:
            refuse(w, 14)
            return emit(o, w, 4294967293, 0, 0)
        return prepare(s, o, w)
    if command == 3:
        if phase != 2 or ack_identity(s, w) == 0:
            refuse(w, 15)
            return emit(o, w, 4294967293, 0, 0)
        return acknowledge(s, o, w)
    if command == 4:
        if phase != 1 or get(w, 32) == 18446744073709551615 or read64(s, 32) != get(w, 32) + 1:
            refuse(w, 16)
            return emit(o, w, 4294967293, 0, 0)
        if length(s) != 256:
            refuse(w, 16)
            return emit(o, w, 4294967293, 0, 0)
        at = 40
        while at < 256:
            if read64(s, at) != 0:
                refuse(w, 16)
                return emit(o, w, 4294967293, 0, 0)
            at = at + 8
        put(w, 32, read64(s, 32))
        put(w, 144, 1)
        return next_close(o, w)
    if command == 5 or command == 6:
        expected = 2
        if command == 6:
            expected = 3
        if phase != expected or ack_identity(s, w) == 0 or read64(s, 56) != 0 or length(s) != 256:
            refuse(w, 17)
            return emit(o, w, 4294967293, 0, 0)
        refuse(w, 18)
        return emit(o, w, 4294967293, 0, 0)
    refuse(w, 19)
    return emit(o, w, 4294967293, 0, 0)

def steady(w:mutbuf) -> u64:
    if get(w, 0) != FS_MAGIC or get(w, 248) != 3:
        return 0
    phase = get(w, 8)
    if phase != 1 and phase != 2 and phase != 3 and phase != 5:
        return 0
    if (get(w, 16) | get(w, 24)) == 0 or get(w, 64) == 0 or get(w, 56) != 0:
        return 0
    cap = get(w, 80)
    if cap > (length(w) - 512) >> 5:
        return 0
    if get(w, 48) > 24 or get(w, 144) > 1:
        return 0
    at = 168
    while at < 248:
        if get(w, at) != 0:
            return 0
        at = at + 8
    live = 0
    i = 0
    while i < cap:
        row = 512 + i * 32
        token = get(w, row)
        fd = get(w, row + 8)
        state = get(w, row + 16)
        if get(w, row + 24) != 0 or state > 1:
            return 0
        if state == 0:
            if token != 0 or fd != 0:
                return 0
        else:
            if token == 0 or token >= get(w, 64) or fd > 2147483647:
                return 0
            j = 0
            while j < i:
                other = 512 + j * 32
                if get(w, other + 16) == 1:
                    if token == get(w, other) or fd == get(w, other + 8):
                        return 0
                j = j + 1
            live = live + 1
        i = i + 1
    if live != get(w, 72):
        return 0
    if phase == 1 or phase == 5:
        at = 88
        while at < 168:
            if get(w, at) != 0:
                return 0
            at = at + 8
        at = 256
        while at < 512:
            if get(w, at) != 0:
                return 0
            at = at + 8
        if phase == 5 and live != 0:
            return 0
    else:
        if get(w, 32) == 0:
            return 0
        if get(w, 144) == 1:
            if phase != 2 or get(w, 48) != 8 or get(w, 88) != 0 or get(w, 96) != 0:
                return 0
            if get(w, 128) > cap or get(w, 136) > 4095 or get(w, 160) == 0:
                return 0
        else:
            if get(w, 48) == 0 or get(w, 88) == 0:
                return 0
            if get(w, 256) != FS_MAGIC or get(w, 264) != 2:
                return 0
            if get(w, 272) != get(w, 16) or get(w, 280) != get(w, 24):
                return 0
            if get(w, 288) != get(w, 32) or get(w, 304) != get(w, 48):
                return 0
            if get(w, 296) != 0 or get(w, 312) != 0:
                return 0
            if get(w, 352) != get(w, 96) or get(w, 360) != get(w, 88):
                return 0
            at = 368
            while at < 512:
                if get(w, at) != 0:
                    return 0
                at = at + 8
            if get(w, 128) != 0 or get(w, 136) != 0:
                return 0
        if phase == 2:
            if get(w, 40) == 0 or get(w, 104) != 0 or get(w, 112) != 0:
                return 0
            if get(w, 96) > length(w) - 512 - cap * 32:
                return 0
            if get(w, 48) == 1:
                slot = get(w, 120)
                if slot == 0 or slot > cap:
                    return 0
                if get(w, 512 + (slot - 1) * 32 + 16) != 0:
                    return 0
            elif get(w, 120) != 0:
                return 0
        else:
            if get(w, 104) < 512 or get(w, 112) < 256:
                return 0
    return 1

def lookup(w:mutbuf, token:u64) -> u64:
    if token == 0:
        return 0
    i = 0
    while i < get(w, 80):
        row = 512 + i * 32
        if get(w, row + 16) == 1 and get(w, row) == token:
            return i + 1
        i = i + 1
    return 0

def free_slot(w:mutbuf) -> u64:
    i = 0
    while i < get(w, 80):
        if get(w, 512 + i * 32 + 16) == 0:
            return i + 1
        i = i + 1
    return 0

def actual_fd(w:mutbuf, token:u64) -> u64:
    if token == 0:
        return 18446744073709551516
    slot = lookup(w, token)
    if slot == 0:
        return 18446744073709551615
    return get(w, 512 + (slot - 1) * 32 + 8)

def path_bytes(s:readbuf, start:u64, count:u64) -> u64:
    if count == 0 or start > length(s) or count > length(s) - start:
        return 0
    i = 0
    while i < count:
        if byte(s, start + i) == 0:
            return 0
        i = i + 1
    return 1

def call_shape(s:readbuf, w:mutbuf) -> u64:
    op = read64(s, 48)
    a = read64(s, 64)
    b = read64(s, 72)
    c = read64(s, 80)
    d = read64(s, 88)
    n = read64(s, 96)
    if op == 0 or op > 24 or n > 9223372036854775807:
        return 0
    if op == 1 or op == 9 or op == 10 or op == 18 or op == 19 or op == 22:
        if a != 0 and lookup(w, a) == 0:
            return 0
        if path_bytes(s, 256, n) == 0 or d != 0:
            return 0
        if op == 1:
            if b > 4294967295 or c > 4294967295:
                return 0
        elif op == 19:
            if b > 9223372036854775807 or c != 0:
                return 0
        else:
            if b > 4294967295 or c != 0:
                return 0
        return 1
    if op == 7:
        if (a != 0 and lookup(w, a) == 0) or (b != 0 and lookup(w, b) == 0):
            return 0
        if c == 0 or c >= n or d != 0:
            return 0
        if path_bytes(s, 256, c) == 0 or path_bytes(s, 256 + c, n - c) == 0:
            return 0
        return 1
    if op == 12 or op == 16:
        if (a | b | c | d | n) != 0:
            return 0
        return 1
    if op == 13:
        if a > 9223372036854775807 or b >= 1000000000 or (c | d | n) != 0:
            return 0
        return 1
    if op == 14:
        if a > 9223372036854775807 or b > 4294967295 or (c | d | n) != 0:
            return 0
        return 1
    if op == 20:
        if a > 9223372036854775807 or (b | c | d | n) != 0:
            return 0
        return 1
    if lookup(w, a) == 0:
        return 0
    if op == 2:
        if b > 9223372036854775807 or c > 9223372036854775807 or (d | n) != 0:
            return 0
        return 1
    if op == 3:
        if b > 9223372036854775807 or (c | d) != 0:
            return 0
        return 1
    if op == 4 or op == 6 or op == 8 or op == 15:
        if (b | c | d | n) != 0:
            return 0
        return 1
    if op == 5:
        if b > 9223372036854775807 or (c | d | n) != 0:
            return 0
        return 1
    if op == 11 or op == 21:
        if b > 4294967295 or (c | d | n) != 0:
            return 0
        return 1
    if op == 17 or op == 23:
        if b > 2 or c > 9223372036854775807 or d > 9223372036854775807 or n != 0:
            return 0
        return 1
    if op == 24:
        if b > 4294967295 or c > 4294967295 or (d | n) != 0:
            return 0
        return 1
    return 0

def prepare(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    op = get(w, 48)
    cap = get(w, 80)
    newcap = cap
    slot = 0
    if op == 1:
        if get(w, 64) == 18446744073709551615:
            refuse(w, 20)
            return emit(o, w, 4294967293, 0, 0)
        slot = free_slot(w)
        if slot == 0:
            if cap > 576460752303423455:
                refuse(w, 21)
                return emit(o, w, 4294967293, 0, 0)
            newcap = cap + 16
            slot = cap + 1
    base = 512 + newcap * 32
    n = get(w, 96)
    if n > 18446744073709551615 - base:
        refuse(w, 21)
        return emit(o, w, 4294967293, 0, 0)
    needw = base + n
    needo = 258 + n
    count = 0
    if op == 2 or op == 19:
        count = read64(s, 72)
    elif op == 14 or op == 20:
        count = read64(s, 64)
    elif op == 4 or op == 15 or op == 18:
        count = 144
    elif op == 12:
        count = 16
    elif op == 23:
        count = 32
    if count > needo - 256:
        needo = 256 + count
    if length(w) < needw or length(o) < needo:
        put(w, 104, needw)
        put(w, 112, needo)
        return emit(o, w, 2, 0, 0)
    at = 512 + cap * 32
    while at < base:
        put(w, at, 0)
        at = at + 8
    put(w, 80, newcap)
    copy_input(w, s, base, 256, n)
    put(w, 104, 0)
    put(w, 112, 0)
    put(w, 120, slot)
    if get(w, 40) == 18446744073709551615:
        refuse(w, 22)
        return emit(o, w, 4294967293, 0, 0)
    put(w, 40, get(w, 40) + 1)
    put(w, 8, 2)
    if op == 8:
        token = read64(s, 64)
        index = lookup(w, token)
        put(w, 152, actual_fd(w, token))
        put(w, 160, token)
        retire(w, index)
    return emit_system(o, w)

def emit_system(o:mutbuf, w:mutbuf) -> u32:
    emit(o, w, 1, 0, 0)
    op = get(w, 48)
    if get(w, 144) == 1:
        put(o, 64, get(w, 152))
        return 1
    a = get(w, 320)
    b = get(w, 328)
    c = get(w, 336)
    d = get(w, 344)
    n = get(w, 96)
    base = 512 + get(w, 80) * 32
    if op == 1:
        put(o, 64, actual_fd(w, a))
        put(o, 72, b)
        put(o, 80, c)
    elif op == 7:
        put(o, 64, actual_fd(w, a))
        put(o, 72, actual_fd(w, b))
        put(o, 80, c)
    elif op == 9 or op == 10 or op == 18 or op == 19 or op == 22:
        put(o, 64, actual_fd(w, a))
        put(o, 72, b)
    elif op == 12 or op == 16:
        put(o, 64, 0)
    elif op == 13 or op == 14 or op == 20:
        put(o, 64, a)
        put(o, 72, b)
    elif op == 8:
        put(o, 64, get(w, 152))
    else:
        put(o, 64, actual_fd(w, a))
        put(o, 72, b)
        put(o, 80, c)
        put(o, 88, d)
    if op == 7:
        copy_workspace(o, w, 256, base, c)
        store(o, 256 + c, 0)
        copy_workspace(o, w, 257 + c, base + c, n - c)
        store(o, 257 + n, 0)
        put(o, 128, n + 2)
    elif op == 1 or op == 9 or op == 10 or op == 18 or op == 19 or op == 22:
        copy_workspace(o, w, 256, base, n)
        store(o, 256 + n, 0)
        put(o, 128, n + 1)
    elif op == 3:
        copy_workspace(o, w, 256, base, n)
        put(o, 128, n)
        put(o, 80, n)
    return 1

def ack_identity(s:readbuf, w:mutbuf) -> u64:
    if read64(s, 32) != get(w, 32) or read64(s, 40) != get(w, 40):
        return 0
    if read64(s, 48) != get(w, 48) or read64(s, 104) != get(w, 88):
        return 0
    if (read64(s, 64) | read64(s, 72) | read64(s, 80) | read64(s, 88)) != 0:
        return 0
    return 1

def acknowledge(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    op = get(w, 48)
    raw = read64(s, 56)
    n = read64(s, 96)
    if raw >= 18446744073709547521:
        if n != 0:
            refuse(w, 23)
            return emit(o, w, 4294967293, 0, 0)
        error = 18446744073709551615 - raw + 1
        if get(w, 144) == 1:
            if get(w, 136) == 0:
                put(w, 136, error)
            return next_close(o, w)
        return finish(o, w, error, 0, 0)
    if op == 1:
        if raw > 2147483647 or n != 0:
            refuse(w, 24)
            return emit(o, w, 4294967293, 0, 0)
        i = 0
        while i < get(w, 80):
            row = 512 + i * 32
            if get(w, row + 16) == 1 and get(w, row + 8) == raw:
                refuse(w, 25)
                return emit(o, w, 4294967293, 0, 0)
            i = i + 1
        token = get(w, 64)
        row = 512 + (get(w, 120) - 1) * 32
        put(w, row, token)
        put(w, row + 8, raw)
        put(w, row + 16, 1)
        put(w, 64, token + 1)
        put(w, 72, get(w, 72) + 1)
        return finish(o, w, 0, token, 0)
    if op == 2 or op == 14 or op == 19 or op == 20:
        maximum = get(w, 328)
        if op == 14 or op == 20:
            maximum = get(w, 320)
        if raw > maximum or n != raw:
            refuse(w, 26)
            return emit(o, w, 4294967293, 0, 0)
        if op == 20:
            if n == 0:
                refuse(w, 26)
                return emit(o, w, 4294967293, 0, 0)
            if byte(s, 255 + n) != 0:
                refuse(w, 26)
                return emit(o, w, 4294967293, 0, 0)
        if length(o) - 256 < n:
            refuse(w, 27)
            return emit(o, w, 4294967293, 0, 0)
        finish(o, w, 0, raw, n)
        copy_input(o, s, 256, 256, n)
        return 0
    if op == 3:
        if raw > get(w, 96) or n != 0:
            refuse(w, 28)
            return emit(o, w, 4294967293, 0, 0)
        return finish(o, w, 0, raw, 0)
    if op == 16:
        if raw > 4294967295 or n != 0:
            refuse(w, 29)
            return emit(o, w, 4294967293, 0, 0)
        return finish(o, w, 0, raw, 0)
    if raw != 0:
        refuse(w, 30)
        return emit(o, w, 4294967293, 0, 0)
    if op == 4 or op == 15 or op == 18:
        if n != 144:
            refuse(w, 31)
            return emit(o, w, 4294967293, 0, 0)
        if op != 4 and length(o) < 400:
            refuse(w, 27)
            return emit(o, w, 4294967293, 0, 0)
        payload = 144
        if op == 4:
            payload = 0
        finish(o, w, 0, 0, payload)
        put(o, 64, read64(s, 256))
        put(o, 72, read64(s, 264))
        put(o, 80, read64(s, 280) & 4294967295)
        put(o, 88, read64(s, 280) >> 32)
        put(o, 96, read64(s, 288) & 4294967295)
        put(o, 104, read64(s, 304))
        put(o, 192, read64(s, 272))
        if op != 4:
            copy_input(o, s, 256, 256, 144)
        return 0
    if op == 23:
        if n != 32:
            refuse(w, 34)
            return emit(o, w, 4294967293, 0, 0)
        if length(o) < 288:
            refuse(w, 27)
            return emit(o, w, 4294967293, 0, 0)
        finish(o, w, 0, 0, 32)
        put(o, 64, read64(s, 256) & 65535)
        put(o, 72, (read64(s, 256) >> 16) & 65535)
        put(o, 80, read64(s, 264))
        put(o, 88, read64(s, 272))
        put(o, 96, read64(s, 280) & 4294967295)
        copy_input(o, s, 256, 256, 32)
        return 0
    if op == 12:
        if n != 16:
            refuse(w, 32)
            return emit(o, w, 4294967293, 0, 0)
        if read64(s, 264) >= 1000000000:
            refuse(w, 32)
            return emit(o, w, 4294967293, 0, 0)
        finish(o, w, 0, read64(s, 256), 0)
        put(o, 72, read64(s, 264))
        return 0
    if n != 0:
        refuse(w, 33)
        return emit(o, w, 4294967293, 0, 0)
    if get(w, 144) == 1:
        return next_close(o, w)
    return finish(o, w, 0, 0, 0)

def retire(w:mutbuf, slot:u64) -> u64:
    row = 512 + (slot - 1) * 32
    put(w, row, 0)
    put(w, row + 8, 0)
    put(w, row + 16, 0)
    put(w, row + 24, 0)
    put(w, 72, get(w, 72) - 1)
    return 0

def next_close(o:mutbuf, w:mutbuf) -> u32:
    i = get(w, 128)
    while i < get(w, 80):
        row = 512 + i * 32
        if get(w, row + 16) == 1:
            if get(w, 40) == 18446744073709551615:
                refuse(w, 22)
                return emit(o, w, 4294967293, 0, 0)
            put(w, 152, get(w, row + 8))
            put(w, 160, get(w, row))
            retire(w, i + 1)
            put(w, 128, i + 1)
            put(w, 48, 8)
            put(w, 40, get(w, 40) + 1)
            put(w, 8, 2)
            return emit_system(o, w)
        i = i + 1
    error = get(w, 136)
    put(w, 48, 0)
    put(w, 8, 5)
    emit(o, w, 0, error, 0)
    clear_pending(w)
    return 0

def finish(o:mutbuf, w:mutbuf, error:u64, value:u64, payload:u64) -> u32:
    put(w, 8, 1)
    emit(o, w, 0, error, payload)
    put(o, 64, value)
    clear_pending(w)
    return 0

def clear_pending(w:mutbuf) -> u64:
    at = 88
    while at < 168:
        put(w, at, 0)
        at = at + 8
    at = 256
    while at < 512:
        put(w, at, 0)
        at = at + 8
    return 0

def refuse(w:mutbuf, reason:u64) -> u64:
    if get(w, 0) != FS_BADMAGIC:
        put(w, 56, reason)
    put(w, 0, FS_BADMAGIC)
    put(w, 8, 4)
    return 4294967293

def emit(o:mutbuf, w:mutbuf, status:u64, error:u64, payload:u64) -> u32:
    if length(o) < 256:
        return 4294967293
    at = 0
    while at < 256:
        put(o, at, 0)
        at = at + 8
    put(o, 0, FS_MAGIC)
    put(o, 8, status)
    put(o, 16, get(w, 16))
    put(o, 24, get(w, 24))
    put(o, 32, get(w, 32))
    put(o, 40, get(w, 40))
    put(o, 48, get(w, 48))
    put(o, 56, error)
    put(o, 112, get(w, 88))
    put(o, 120, get(w, 8))
    put(o, 128, payload)
    put(o, 136, get(w, 104))
    put(o, 144, get(w, 112))
    put(o, 152, get(w, 56))
    put(o, 160, get(w, 72))
    put(o, 168, get(w, 64))
    put(o, 176, 3)
    put(o, 184, get(w, 144))
    return status
'''

def source_program():
    return FS.replace("FS_BADMAGIC",str(BADMAGIC)).replace("FS_MAGIC",str(MAGIC)) + VALUES[VALUES.index("\ndef read64("):]

def document():
    nodes=ast.parse(source_program()).body
    names={node.name:"f"+str(i) for i,node in enumerate(nodes)}
    if len(names)!=len(nodes):
        raise ValueError("duplicate filesystem symbol")
    signatures={node.name:([arg.annotation.id for arg in node.args.args],node.returns.id) for node in nodes}
    total=total_scalar_functions(nodes)
    functions=[]
    for node in nodes:
        builder=ObjectBuilder(node,names,signatures,total)
        builder.statements(node.body)
        functions.append({"name":names[node.name],"params":[builder.param(v) for v in builder.params],
            "returns":[builder.returns],"effects":["read","write","trap"],"entry":"b0","blocks":builder.blocks})
    return compact_authoring_cfg({"schema":"hepta.hia.program.v8","module":"agent_namespace_filesystem_r5","functions":functions})

if __name__=="__main__":
    path=ROOT/"examples/hia_bootstrap/agent_namespace_filesystem_r5.hiaasm"
    path.write_text(render_assembly(document()))
    print(path.name,path.stat().st_size)
