"""NEW private native memory-lease owner below the Unix SHM mapping owner.

HIA selects allocation/copy/retirement, validates issued identities and owns the
logical handle registry. A fixed mechanical peer supplies actual mmap, memmove,
munmap and process-local barrier completions. Headers do not authenticate
external input. This source has not yet been generated or executed.
"""
from __future__ import annotations
import ast
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_agent_namespace_objects import ObjectBuilder
from tools.generate_hia_agent_namespace_store import VALUES
from tools.generate_hia_selfhost import compact_authoring_cfg,total_scalar_functions
ROOT=Path(__file__).resolve().parents[1]
MAGIC=int.from_bytes(b"HIANML01","little")
BAD=int.from_bytes(b"HIANMLB1","little")
CHANNEL=int.from_bytes(b"HIANMX01","little")
MEMORY=r'''
def ml_entry(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < 1536:
        if length(w) >= 8:
            put(w, 0, ML_BAD)
        return 4294967293
    if get(w, 0) == ML_BAD:
        return ml_emit(o, w, 4294967293)
    if length(o) < 256 or length(s) < 320:
        return ml_refuse(o, w, 1)
    if read64(s, 0) != ML_CHANNEL or read64(s, 32) != length(s) - 64 or (read64(s, 48) | read64(s, 56)) != 0:
        return ml_refuse(o, w, 2)
    origin = read64(s, 8)
    cmd = ml_read(s, 8)
    if origin == 1:
        if (read64(s, 16) | read64(s, 24) | read64(s, 40)) != 0 or (cmd != 1 and cmd != 2 and cmd != 6):
            return ml_refuse(o, w, 3)
    elif origin == 2:
        if cmd != 3 or read64(s, 16) != ml_read(s, 64) or read64(s, 24) != 0 or read64(s, 40) != ml_read(s, 96):
            return ml_refuse(o, w, 4)
    elif origin == 3:
        if cmd != 4 or (read64(s, 16) | read64(s, 24) | read64(s, 40)) != 0:
            return ml_refuse(o, w, 5)
    elif origin == 4:
        if cmd != 5 or (read64(s, 16) | read64(s, 24) | read64(s, 40)) != 0:
            return ml_refuse(o, w, 6)
    else:
        return ml_refuse(o, w, 7)
    if ml_read(s, 0) != ML_MAGIC:
        return ml_refuse(o, w, 8)
    if get(w, 0) == 0:
        if cmd != 1 or origin != 1:
            return ml_refuse(o, w, 9)
        return ml_init(s, o, w)
    if ml_steady(w) == 0:
        return ml_refuse(o, w, 10)
    if ml_read(s, 16) != get(w, 16) or ml_read(s, 24) != get(w, 24) or ml_read(s, 56) != get(w, 56):
        return ml_refuse(o, w, 11)
    phase = get(w, 8)
    if cmd == 4:
        if phase != 2 or ml_control_shape(s, w, 1) == 0:
            return ml_refuse(o, w, 12)
        return ml_refuse(o, w, 13)
    if cmd == 5:
        if phase != 3 or ml_control_shape(s, w, 12) == 0:
            return ml_refuse(o, w, 14)
        return ml_result(o, w, 12, 0, 0, 0, 0)
    if phase == 3:
        if origin != 1 or length(s) != 320:
            return ml_refuse(o, w, 15)
        index = 0
        while index < 256:
            if ml_byte(s, index) != byte(w, 256 + index):
                return ml_refuse(o, w, 16)
            index = index + 1
        if length(w) < get(w, 200):
            return ml_emit(o, w, 2)
        put(w, 8, 1)
        put(w, 200, 0)
        return ml_start(o, w)
    if phase == 2:
        if origin != 2 or cmd != 3 or ml_ack_shape(s, w) == 0:
            return ml_refuse(o, w, 17)
        put(w, 224, ml_read(s, 96))
        return ml_reply(s, o, w)
    if phase != 1 or origin != 1 or (cmd != 2 and cmd != 6):
        return ml_refuse(o, w, 18)
    if ml_user_shape(s, w) == 0:
        return ml_refuse(o, w, 19)
    if get(w, 32) == 18446744073709551615 or ml_read(s, 32) != get(w, 32) + 1:
        return ml_refuse(o, w, 20)
    if ml_read(s, 40) != 0 or ml_read(s, 48) <= get(w, 48):
        return ml_refuse(o, w, 21)
    copy_input(w, s, 256, 64, 256)
    put(w, 32, ml_read(s, 32))
    put(w, 40, 0)
    put(w, 48, ml_read(s, 48))
    put(w, 96, ml_read(s, 64))
    put(w, 112, ml_read(s, 72))
    put(w, 120, ml_read(s, 80))
    put(w, 128, ml_read(s, 88))
    put(w, 136, ml_read(s, 80))
    put(w, 144, ml_read(s, 96))
    put(w, 152, ml_read(s, 104))
    put(w, 160, ml_read(s, 112))
    put(w, 168, 0)
    put(w, 176, 0)
    put(w, 184, 0)
    put(w, 192, 0)
    put(w, 200, 0)
    put(w, 208, 0)
    return ml_start(o, w)

def ml_read(s:readbuf, at:u64) -> u64:
    return read64(s, at + 64)

def ml_byte(s:readbuf, at:u64) -> u64:
    return widen(load(s, at + 64))

def ml_zero(w:mutbuf, at:u64, count:u64) -> u64:
    end = at + count
    while at < end:
        put(w, at, 0)
        at = at + 8
    return 0

def ml_init(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) != 320 or (ml_read(s, 16) | ml_read(s, 24)) == 0 or ml_read(s, 56) == 0:
        return ml_refuse(o, w, 22)
    if (ml_read(s, 32) | ml_read(s, 40) | ml_read(s, 48)) != 0:
        return ml_refuse(o, w, 23)
    page = ml_read(s, 64)
    generation = ml_read(s, 72)
    if page == 0 or page > 1073741824 or (page & (page - 1)) != 0 or generation == 0:
        return ml_refuse(o, w, 24)
    at = 80
    while at < 256:
        if ml_read(s, at) != 0:
            return ml_refuse(o, w, 25)
        at = at + 8
    at = 0
    while at < 1536:
        if byte(w, at) != 0:
            return ml_refuse(o, w, 26)
        at = at + 1
    put(w, 0, ML_MAGIC)
    put(w, 8, 1)
    put(w, 16, ml_read(s, 16))
    put(w, 24, ml_read(s, 24))
    put(w, 56, ml_read(s, 56))
    put(w, 64, 1)
    put(w, 72, 1536)
    put(w, 232, page)
    put(w, 240, generation)
    return ml_emit(o, w, 0)

def ml_control_shape(s:readbuf, w:mutbuf, reason:u64) -> u64:
    if length(s) != 320 or ml_read(s, 32) != get(w, 32) or ml_read(s, 40) != get(w, 40) or ml_read(s, 48) != get(w, 48):
        return 0
    if ml_read(s, 64) != reason:
        return 0
    at = 72
    while at < 256:
        if ml_read(s, at) != 0:
            return 0
        at = at + 8
    return 1

def ml_find(w:mutbuf, token:u64) -> u64:
    at = 1536
    while at < get(w, 72):
        if get(w, at) == token and get(w, at + 40) == 1:
            return at
        at = at + 80
    return 0

def ml_unused(w:mutbuf) -> u64:
    at = 1536
    while at < get(w, 72):
        if get(w, at + 40) == 0:
            return at
        at = at + 80
    return get(w, 72)

def ml_round(w:mutbuf, amount:u64) -> u64:
    page = get(w, 232)
    if amount == 0 or amount > 18446744073709551615 - (page - 1):
        return 0
    return (amount + page - 1) & (18446744073709551615 - page + 1)

def ml_user_shape(s:readbuf, w:mutbuf) -> u64:
    if length(s) != 320 or ml_read(s, 48) == 0 or ml_read(s, 120) != get(w, 240):
        return 0
    at = 128
    while at < 256:
        if ml_read(s, at) != 0:
            return 0
        at = at + 8
    op = ml_read(s, 64)
    token = ml_read(s, 72)
    a = ml_read(s, 80)
    b = ml_read(s, 88)
    c = ml_read(s, 96)
    fd = ml_read(s, 104)
    fs = ml_read(s, 112)
    if ml_read(s, 8) == 6:
        if op != 7 or token == 0 or (fd | fs) != 0 or c > 3 or b == 0:
            return 0
        row = ml_find(w, token)
        if row == 0 or get(w, row + 32) == 1 or a > get(w, row + 16) or b > get(w, row + 16) - a:
            return 0
        if c != 1 and c != 3 or (c & get(w, row + 48)) != c:
            return 0
        return 1
    if op == 1:
        if a == 0 or a < b or (c | fd | fs) != 0:
            return 0
        if token == 0:
            return choose(b == 0, 1, 0)
        row = ml_find(w, token)
        return choose(row != 0 and get(w, row + 32) == 1 and get(w, row + 16) == b, 1, 0)
    if op == 2:
        if token == 0 or token != fs or fd > 2147483647 or b == 0 or (a & (get(w, 232) - 1)) != 0:
            return 0
        if c != 1 and c != 3 or a > 9223372036854775807 or b > 9223372036854775807 - a:
            return 0
        return 1
    if op == 3:
        return choose(token == 0 and a != 0 and (b | c | fd | fs) == 0, 1, 0)
    if op == 4 or op == 5:
        row = ml_find(w, token)
        if row == 0 or (c | fd | fs) != 0:
            return 0
        if op == 4:
            return choose(get(w, row + 32) == 2 and b == get(w, row + 16) and ml_round(w, a) == get(w, row + 24), 1, 0)
        return choose(get(w, row + 32) != 2 and a == get(w, row + 16) and b == 0, 1, 0)
    if op == 6:
        return choose((token | a | b | c | fd | fs) == 0, 1, 0)
    return 0

def ml_steady(w:mutbuf) -> u64:
    phase = get(w, 8)
    if get(w, 0) != ML_MAGIC or (phase != 1 and phase != 2 and phase != 3) or (get(w, 16) | get(w, 24)) == 0 or get(w, 56) == 0:
        return 0
    if get(w, 64) == 0 or get(w, 72) < 1536 or get(w, 72) > length(w) or (get(w, 72) & 7) != 0:
        return 0
    page = get(w, 232)
    if page == 0 or page > 1073741824 or (page & (page - 1)) != 0 or get(w, 240) == 0 or get(w, 248) != 0:
        return 0
    at = 768
    while at < 1536:
        if get(w, at) != 0:
            return 0
        at = at + 8
    live = 0
    quarantine = 0
    at = 1536
    while at < get(w, 72):
        if 80 > get(w, 72) - at:
            return 0
        state = get(w, at + 40)
        if state == 0:
            n = 0
            while n < 80:
                if get(w, at + n) != 0:
                    return 0
                n = n + 8
        elif state == 1 or state == 2:
            token = get(w, at)
            address = get(w, at + 8)
            amount = get(w, at + 16)
            mapped = get(w, at + 24)
            kind = get(w, at + 32)
            prot = get(w, at + 48)
            if token == 0 or token >= get(w, 64) or mapped == 0 or mapped != ml_round(w, amount):
                return 0
            if (address & (page - 1)) != 0 or address > 18446744073709551615 - mapped or kind < 1 or kind > 3:
                return 0
            if get(w, at + 72) != get(w, 240) or (prot != 1 and prot != 3):
                return 0
            if kind == 2:
                if get(w, at + 56) == 0 or (get(w, at + 64) & (page - 1)) != 0:
                    return 0
            elif (get(w, at + 56) | get(w, at + 64)) != 0 or prot != 3:
                return 0
            prior = 1536
            while prior < at:
                if get(w, prior + 40) != 0:
                    if get(w, prior) == token:
                        return 0
                    p = get(w, prior + 8)
                    n = get(w, prior + 24)
                    if address < p + n and p < address + mapped:
                        return 0
                prior = prior + 80
            if state == 1:
                live = live + 1
            else:
                quarantine = quarantine + 1
        else:
            return 0
        at = at + 80
    if live != get(w, 80) or quarantine != get(w, 88):
        return 0
    if phase == 1:
        return choose(get(w, 104) == 0 and get(w, 200) == 0, 1, 0)
    if get(w, 32) == 0 or get(w, 48) == 0 or ml_saved_shape(w) == 0:
        return 0
    if phase == 3:
        if get(w, 104) != 0 or get(w, 96) < 1 or get(w, 96) > 3 or get(w, 200) < get(w, 72):
            return 0
        return choose(get(w, 200) == get(w, 176) + 80 and get(w, 176) == get(w, 72), 1, 0)
    return ml_pending(w)

def ml_saved_shape(w:mutbuf) -> u64:
    if get(w, 256) != ML_MAGIC or get(w, 264) != 2 or get(w, 272) != get(w, 16) or get(w, 280) != get(w, 24):
        return 0
    if get(w, 288) != get(w, 32) or get(w, 296) != 0 or get(w, 304) != get(w, 48) or get(w, 312) != get(w, 56):
        return 0
    if get(w, 320) != get(w, 96) or get(w, 328) != get(w, 112) or get(w, 336) != get(w, 120) or get(w, 344) != get(w, 128):
        return 0
    if get(w, 352) != get(w, 144) or get(w, 360) != get(w, 152) or get(w, 368) != get(w, 160) or get(w, 376) != get(w, 240) or get(w, 136) != get(w, 120):
        return 0
    at = 384
    while at < 512:
        if get(w, at) != 0:
            return 0
        at = at + 8
    return 1

def ml_pending(w:mutbuf) -> u64:
    stage = get(w, 104)
    op = get(w, 96)
    rawop = get(w, 576)
    if stage == 10:
        if op < 1 or op > 3 or rawop != 1 or get(w, 584) != 0 or get(w, 592) != get(w, 192) or ml_round(w, get(w, 192)) == 0:
            return 0
        if op == 2:
            if get(w, 600) != get(w, 144) or get(w, 608) != 1 or get(w, 616) != get(w, 152) or get(w, 624) != get(w, 136):
                return 0
        elif get(w, 600) != 3 or get(w, 608) != 34 or get(w, 616) != 18446744073709551615 or get(w, 624) != 0:
            return 0
    elif stage == 20 or stage == 21 or stage == 30:
        row = ml_find(w, get(w, 112))
        if row == 0 or row != get(w, 168):
            return 0
        if stage == 20 or stage == 21:
            if op != 1 or get(w, row + 32) != 1 or get(w, row + 16) != get(w, 128):
                return 0
            if ml_address_free(w, get(w, 184), ml_round(w, get(w, 192))) == 0:
                return 0
        elif op != 4 and op != 5:
            return 0
        if stage == 20:
            if rawop != 2 or get(w, 584) != get(w, 184) or get(w, 592) != get(w, row + 16) or get(w, 600) != get(w, row + 8):
                return 0
        else:
            size = get(w, row + 16)
            if stage == 30:
                size = get(w, 120)
            if rawop != 3 or get(w, 584) != get(w, row + 8) or get(w, 592) != size or get(w, 600) != 0:
                return 0
        if (get(w, 608) | get(w, 616) | get(w, 624)) != 0:
            return 0
    elif stage == 40:
        if op != 6 or rawop != 4:
            return 0
        at = 584
        while at < 632:
            if get(w, at) != 0:
                return 0
            at = at + 8
    else:
        return 0
    if get(w, 512) != ML_MAGIC or get(w, 520) != 1 or get(w, 528) != get(w, 16) or get(w, 536) != get(w, 24):
        return 0
    if get(w, 544) != get(w, 32) or get(w, 552) != get(w, 40) or get(w, 560) != get(w, 48) or get(w, 568) != get(w, 56):
        return 0
    if get(w, 632) != stage or get(w, 640) != 0 or get(w, 648) != get(w, 112) or get(w, 656) != get(w, 64) or get(w, 664) != get(w, 232):
        return 0
    if get(w, 672) != 2 or get(w, 680) != get(w, 80) or get(w, 688) != get(w, 88) or get(w, 696) != get(w, 240):
        return 0
    at = 704
    while at < 768:
        if get(w, at) != 0:
            return 0
        at = at + 8
    return 1

def ml_start(o:mutbuf, w:mutbuf) -> u32:
    op = get(w, 96)
    if op == 7:
        row = ml_find(w, get(w, 112))
        if row == 0:
            return ml_refuse(o, w, 27)
        return ml_result(o, w, 0, get(w, row), get(w, 128), get(w, row + 8) + get(w, 120), get(w, 144))
    if op >= 1 and op <= 3:
        if get(w, 64) == 18446744073709551615:
            return ml_refuse(o, w, 28)
        row = ml_unused(w)
        put(w, 176, row)
        if row > 18446744073709551615 - 80:
            return ml_result(o, w, 12, 0, 0, 0, 0)
        if row + 80 > length(w):
            put(w, 200, row + 80)
            put(w, 8, 3)
            return ml_emit(o, w, 2)
        amount = get(w, 120)
        if op == 2:
            amount = get(w, 128)
        mapped = ml_round(w, amount)
        if mapped == 0:
            return ml_result(o, w, 12, 0, 0, 0, 0)
        put(w, 192, amount)
        put(w, 104, 10)
        if op == 1 and get(w, 112) != 0:
            old = ml_find(w, get(w, 112))
            if old == 0:
                return ml_refuse(o, w, 29)
            put(w, 168, old)
        if op == 2:
            return ml_issue(o, w, 1, 0, amount, get(w, 144), 1, get(w, 152), get(w, 136))
        return ml_issue(o, w, 1, 0, amount, 3, 34, 18446744073709551615, 0)
    if op == 4 or op == 5:
        row = ml_find(w, get(w, 112))
        if row == 0:
            return ml_refuse(o, w, 30)
        put(w, 168, row)
        put(w, 104, 30)
        return ml_issue(o, w, 3, get(w, row + 8), get(w, 120), 0, 0, 0, 0)
    if op == 6:
        put(w, 104, 40)
        return ml_issue(o, w, 4, 0, 0, 0, 0, 0, 0)
    return ml_refuse(o, w, 31)

def ml_issue(o:mutbuf, w:mutbuf, primitive:u64, a:u64, b:u64, c:u64, d:u64, e:u64, f:u64) -> u32:
    if get(w, 40) == 18446744073709551615 or get(w, 224) == 18446744073709551615:
        return ml_refuse(o, w, 32)
    put(w, 40, get(w, 40) + 1)
    put(w, 8, 2)
    ml_emit(o, w, 1)
    put(o, 64, primitive)
    put(o, 72, a)
    put(o, 80, b)
    put(o, 88, c)
    put(o, 96, d)
    put(o, 104, e)
    put(o, 112, f)
    put(o, 120, get(w, 104))
    put(o, 136, get(w, 112))
    put(o, 144, get(w, 64))
    put(o, 152, get(w, 232))
    copy_workspace(w, o, 512, 0, 256)
    return 1

def ml_ack_shape(s:readbuf, w:mutbuf) -> u64:
    if length(s) != 576 or ml_read(s, 32) != get(w, 32) or ml_read(s, 40) != get(w, 40) or ml_read(s, 48) != get(w, 48):
        return 0
    if ml_read(s, 64) != get(w, 576) or ml_read(s, 72) > 4095 or ml_read(s, 88) != 0:
        return 0
    if ml_read(s, 96) <= get(w, 224) or ml_read(s, 104) != 256:
        return 0
    at = 112
    while at < 256:
        if ml_read(s, at) != 0:
            return 0
        at = at + 8
    at = 0
    while at < 256:
        if ml_byte(s, 256 + at) != byte(w, 512 + at):
            return 0
        at = at + 1
    error = ml_read(s, 72)
    value = ml_read(s, 80)
    if error != 0:
        return choose(value == 0, 1, 0)
    if get(w, 104) == 10:
        return choose((value & (get(w, 232) - 1)) == 0 and value <= 18446744073709551615 - ml_round(w, get(w, 192)), 1, 0)
    return choose(value == 0, 1, 0)

def ml_address_free(w:mutbuf, address:u64, extent:u64) -> u64:
    at = 1536
    while at < get(w, 72):
        if get(w, at + 40) != 0:
            start = get(w, at + 8)
            count = get(w, at + 24)
            if address < start + count and start < address + extent:
                return 0
        at = at + 80
    return 1

def ml_reply(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    stage = get(w, 104)
    error = ml_read(s, 72)
    value = ml_read(s, 80)
    if stage == 10:
        if error != 0:
            return ml_result(o, w, error, 0, 0, 0, 0)
        if ml_address_free(w, value, ml_round(w, get(w, 192))) == 0:
            return ml_refuse(o, w, 33)
        put(w, 184, value)
        if get(w, 96) == 1 and get(w, 168) != 0:
            row = get(w, 168)
            put(w, 104, 20)
            return ml_issue(o, w, 2, value, get(w, row + 16), get(w, row + 8), 0, 0, 0)
        return ml_commit(o, w)
    if stage == 20:
        if error != 0:
            return ml_refuse(o, w, 34)
        row = get(w, 168)
        put(w, 104, 21)
        return ml_issue(o, w, 3, get(w, row + 8), get(w, row + 16), 0, 0, 0, 0)
    if stage == 21:
        ml_retire(w, get(w, 168), error)
        if error != 0:
            put(w, 216, get(w, 216) + 1)
        return ml_commit(o, w)
    if stage == 30:
        ml_retire(w, get(w, 168), error)
        return ml_result(o, w, error, 0, 0, 0, 0)
    if stage == 40:
        if error != 0:
            return ml_refuse(o, w, 35)
        return ml_result(o, w, 0, 0, 0, 0, 0)
    return ml_refuse(o, w, 36)

def ml_retire(w:mutbuf, row:u64, error:u64) -> u64:
    put(w, 80, get(w, 80) - 1)
    if error == 0:
        ml_zero(w, row, 80)
    else:
        put(w, row + 40, 2)
        put(w, 88, get(w, 88) + 1)
    return 0

def ml_commit(o:mutbuf, w:mutbuf) -> u32:
    row = get(w, 176)
    token = get(w, 64)
    kind = get(w, 96)
    if row < 1536 or row > length(w) or 80 > length(w) - row or row > get(w, 72):
        return ml_refuse(o, w, 37)
    if row < get(w, 72) and get(w, row + 40) != 0:
        return ml_refuse(o, w, 38)
    ml_zero(w, row, 80)
    put(w, row, token)
    put(w, row + 8, get(w, 184))
    put(w, row + 16, get(w, 192))
    put(w, row + 24, ml_round(w, get(w, 192)))
    put(w, row + 32, kind)
    put(w, row + 40, 1)
    put(w, row + 48, choose(kind == 2, get(w, 144), 3))
    if kind == 2:
        put(w, row + 56, get(w, 160))
        put(w, row + 64, get(w, 136))
    put(w, row + 72, get(w, 240))
    put(w, 64, token + 1)
    put(w, 80, get(w, 80) + 1)
    if row == get(w, 72):
        put(w, 72, row + 80)
    return ml_result(o, w, 0, token, get(w, 192), 0, 0)

def ml_result(o:mutbuf, w:mutbuf, error:u64, token:u64, extent:u64, address:u64, prot:u64) -> u32:
    put(w, 8, 1)
    put(w, 104, 0)
    put(w, 200, 0)
    put(w, 208, error)
    ml_emit(o, w, 0)
    put(o, 64, error)
    put(o, 72, token)
    put(o, 80, extent)
    put(o, 88, address)
    put(o, 96, prot)
    put(o, 104, get(w, 216))
    put(o, 112, get(w, 224))
    return 0

def ml_refuse(o:mutbuf, w:mutbuf, reason:u64) -> u32:
    if get(w, 0) != ML_BAD:
        put(w, 248, reason)
    put(w, 0, ML_BAD)
    put(w, 8, 7)
    return ml_emit(o, w, 4294967293)

def ml_emit(o:mutbuf, w:mutbuf, status:u64) -> u32:
    if length(o) < 256:
        return 4294967293
    ml_zero(o, 0, 256)
    put(o, 0, ML_MAGIC)
    put(o, 8, status)
    put(o, 16, get(w, 16))
    put(o, 24, get(w, 24))
    put(o, 32, get(w, 32))
    put(o, 40, get(w, 40))
    put(o, 48, get(w, 48))
    put(o, 56, get(w, 56))
    if status == 2:
        put(o, 64, get(w, 200))
        put(o, 72, 256)
    put(o, 160, get(w, 8))
    put(o, 168, get(w, 80))
    put(o, 176, get(w, 88))
    put(o, 184, get(w, 240))
    put(o, 192, get(w, 248))
    return status
'''
def source_program():
    text=MEMORY.replace("ML_CHANNEL",str(CHANNEL)).replace("ML_MAGIC",str(MAGIC)).replace("ML_BAD",str(BAD))
    return text+VALUES[VALUES.index("\ndef read64("):]
def document():
    nodes=ast.parse(source_program()).body
    names={node.name:"f"+str(i) for i,node in enumerate(nodes)}
    if len(names)!=len(nodes):raise ValueError("duplicate memory lease symbol")
    signatures={node.name:([arg.annotation.id for arg in node.args.args],node.returns.id) for node in nodes}
    total=total_scalar_functions(nodes);functions=[]
    for node in nodes:
        b=ObjectBuilder(node,names,signatures,total);b.statements(node.body)
        functions.append({"name":names[node.name],"params":[b.param(v) for v in b.params],"returns":[b.returns],
            "effects":["read","write","trap"],"entry":"b0","blocks":b.blocks})
    return compact_authoring_cfg({"schema":"hepta.hia.program.v8","module":"agent_namespace_memory_leases_r1","functions":functions})
if __name__=="__main__":
    path=ROOT/"examples/hia_bootstrap/agent_namespace_memory_leases_r1.hiaasm"
    path.write_text(render_assembly(document()));print(path.name,path.stat().st_size)
