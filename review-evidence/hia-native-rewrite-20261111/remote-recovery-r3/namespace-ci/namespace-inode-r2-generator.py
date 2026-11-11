"""NEW namespace inode and WAL-lock owner; independent component, not AgentStore.

The HIA image owns descriptor registration after actual stat, all per-connection
shared/exclusive masks, same-inode conflicts, deferred logical retirement and
physical close order. FS replies are bound to the exact source-issued request.
The byte protocol is private and does not authenticate arbitrary external state.
No VM/native/ordinary-path result is claimed by this source checkpoint.
"""
from __future__ import annotations
import ast
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_agent_namespace_objects import ObjectBuilder
from tools.generate_hia_agent_namespace_store import VALUES
from tools.generate_hia_selfhost import compact_authoring_cfg,total_scalar_functions
ROOT=Path(__file__).resolve().parents[1]
MAGIC=int.from_bytes(b"HIANIR01","little")
BAD=int.from_bytes(b"HIANIB01","little")
FS_MAGIC=int.from_bytes(b"HIANFR03","little")
INODES=r'''
def inode_owner(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < 512:
        if length(w) >= 8:
            put(w, 0, INODE_BAD)
        return 4294967293
    if get(w, 0) == INODE_BAD:
        return inode_emit(o, w, 4294967293, 0, 0, 0)
    if length(o) < 256:
        inode_refuse(w, 1)
        return 4294967293
    if length(s) < 256:
        inode_refuse(w, 2)
        return inode_emit(o, w, 4294967293, 0, 0, 0)
    if read64(s, 0) != INODE_MAGIC or read64(s, 128) != length(s) - 256:
        inode_refuse(w, 3)
        return inode_emit(o, w, 4294967293, 0, 0, 0)
    at = 136
    while at < 256:
        if read64(s, at) != 0:
            inode_refuse(w, 4)
            return inode_emit(o, w, 4294967293, 0, 0, 0)
        at = at + 8
    command = read64(s, 8)
    if get(w, 0) == 0:
        at = 0
        while at < 512:
            if get(w, at) != 0:
                inode_refuse(w, 5)
                return inode_emit(o, w, 4294967293, 0, 0, 0)
            at = at + 8
        if command != 1 or length(s) != 256:
            inode_refuse(w, 6)
            return inode_emit(o, w, 4294967293, 0, 0, 0)
        if (read64(s, 16) | read64(s, 24)) == 0 or (read64(s, 72) | read64(s, 80)) == 0:
            inode_refuse(w, 6)
            return inode_emit(o, w, 4294967293, 0, 0, 0)
        at = 32
        while at < 72:
            if read64(s, at) != 0:
                inode_refuse(w, 6)
                return inode_emit(o, w, 4294967293, 0, 0, 0)
            at = at + 8
        at = 104
        while at < 256:
            if read64(s, at) != 0:
                inode_refuse(w, 6)
                return inode_emit(o, w, 4294967293, 0, 0, 0)
            at = at + 8
        put(w, 0, INODE_MAGIC)
        put(w, 8, 1)
        put(w, 16, read64(s, 16))
        put(w, 24, read64(s, 24))
        put(w, 48, 1)
        put(w, 200, read64(s, 72))
        put(w, 208, read64(s, 80))
        put(w, 216, read64(s, 88))
        put(w, 224, read64(s, 96))
        put(w, 232, 1)
        return inode_emit(o, w, 0, 0, 0, 0)
    if inode_steady(w) == 0:
        inode_refuse(w, 7)
        return inode_emit(o, w, 4294967293, 0, 0, 0)
    if read64(s, 16) != get(w, 16) or read64(s, 24) != get(w, 24):
        inode_refuse(w, 8)
        return inode_emit(o, w, 4294967293, 0, 0, 0)
    phase = get(w, 8)
    if phase == 3:
        if command != 2 or length(s) != 256:
            inode_refuse(w, 9)
            return inode_emit(o, w, 4294967293, 0, 0, 0)
        at = 0
        while at < 256:
            if read64(s, at) != get(w, 256 + at):
                inode_refuse(w, 10)
                return inode_emit(o, w, 4294967293, 0, 0, 0)
            at = at + 8
        return inode_register(s, o, w)
    if phase == 2:
        if command != 6 and command != 7:
            inode_refuse(w, 11)
            return inode_emit(o, w, 4294967293, 0, 0, 0)
        if inode_ack_shape(s, w) == 0:
            inode_refuse(w, 12)
            return inode_emit(o, w, 4294967293, 0, 0, 0)
        if command == 7:
            if length(s) != 256:
                inode_refuse(w, 12)
                return inode_emit(o, w, 4294967293, 0, 0, 0)
            inode_refuse(w, 13)
            return inode_emit(o, w, 4294967293, 0, 0, 0)
        return inode_acknowledge(s, o, w)
    if phase != 1 or command < 2 or command > 5 or length(s) != 256:
        inode_refuse(w, 14)
        return inode_emit(o, w, 4294967293, 0, 0, 0)
    if get(w, 32) == 18446744073709551615 or read64(s, 32) != get(w, 32) + 1:
        inode_refuse(w, 15)
        return inode_emit(o, w, 4294967293, 0, 0, 0)
    if (read64(s, 40) | read64(s, 56) | read64(s, 64)) != 0 or read64(s, 120) == 0:
        inode_refuse(w, 16)
        return inode_emit(o, w, 4294967293, 0, 0, 0)
    row = 0
    if command == 2:
        if read64(s, 48) != 0 or read64(s, 72) == 0:
            inode_refuse(w, 17)
            return inode_emit(o, w, 4294967293, 0, 0, 0)
        at = 80
        while at < 120:
            if read64(s, at) != 0:
                inode_refuse(w, 17)
                return inode_emit(o, w, 4294967293, 0, 0, 0)
            at = at + 8
        if inode_token_present(w, read64(s, 72)) != 0 or get(w, 48) == 18446744073709551615:
            inode_refuse(w, 18)
            return inode_emit(o, w, 4294967293, 0, 0, 0)
    else:
        row = inode_lookup(w, read64(s, 48))
        if row == 0 or get(w, row + 48) != 1:
            inode_refuse(w, 19)
            return inode_emit(o, w, 4294967293, 0, 0, 0)
        if (read64(s, 80) | read64(s, 88) | read64(s, 96)) != 0:
            inode_refuse(w, 20)
            return inode_emit(o, w, 4294967293, 0, 0, 0)
        if command == 5:
            if (read64(s, 72) | read64(s, 104) | read64(s, 112)) != 0:
                inode_refuse(w, 20)
                return inode_emit(o, w, 4294967293, 0, 0, 0)
            if (get(w, row + 32) | get(w, row + 40)) != 0:
                inode_refuse(w, 21)
                return inode_emit(o, w, 4294967293, 0, 0, 0)
        else:
            kind = read64(s, 72)
            offset = read64(s, 104)
            count = read64(s, 112)
            if kind < 1 or kind > 2 or offset >= 8 or count == 0 or count > 8 - offset:
                inode_refuse(w, 22)
                return inode_emit(o, w, 4294967293, 0, 0, 0)
            if kind == 1 and count != 1:
                inode_refuse(w, 22)
                return inode_emit(o, w, 4294967293, 0, 0, 0)
    put(w, 32, read64(s, 32))
    put(w, 80, row)
    put(w, 88, read64(s, 104))
    put(w, 96, read64(s, 112))
    put(w, 104, read64(s, 72))
    put(w, 144, read64(s, 120))
    copy_input(w, s, 256, 0, 256)
    if command == 2:
        return inode_register(s, o, w)
    if command == 5:
        return inode_retire(o, w)
    return inode_lock(o, w)

def inode_lookup(w:mutbuf, handle:u64) -> u64:
    at = 512
    end = 512 + get(w, 56) * 96
    while at < end:
        if get(w, at) == handle and get(w, at + 48) != 0:
            return at
        at = at + 96
    return 0

def inode_token_present(w:mutbuf, token:u64) -> u64:
    at = 512
    end = 512 + get(w, 56) * 96
    while at < end:
        if get(w, at + 48) != 0 and get(w, at + 8) == token:
            return 1
        at = at + 96
    return 0

def inode_free(w:mutbuf) -> u64:
    at = 512
    end = 512 + get(w, 56) * 96
    while at < end:
        if get(w, at + 48) == 0:
            return at
        at = at + 96
    return 0

def inode_same(w:mutbuf, a:u64, b:u64) -> u64:
    if get(w, a + 16) == get(w, b + 16) and get(w, a + 24) == get(w, b + 24):
        return 1
    return 0

def inode_other_masks(w:mutbuf, row:u64, kind:u64) -> u64:
    mask = 0
    at = 512
    end = 512 + get(w, 56) * 96
    while at < end:
        if at != row and get(w, at + 48) == 1 and inode_same(w, at, row) != 0:
            if kind == 1:
                mask = mask | get(w, at + 32)
            else:
                mask = mask | get(w, at + 40)
        at = at + 96
    return mask

def inode_group_masks(w:mutbuf, device:u64, number:u64) -> u64:
    mask = 0
    at = 512
    end = 512 + get(w, 56) * 96
    while at < end:
        if get(w, at + 48) == 1 and get(w, at + 16) == device and get(w, at + 24) == number:
            mask = mask | get(w, at + 32) | get(w, at + 40)
        at = at + 96
    return mask

def inode_slot(w:mutbuf, row:u64) -> u64:
    at = 512
    end = 512 + get(w, 56) * 96
    while at < end:
        if at == row:
            return 1
        at = at + 96
    return 0

def inode_steady(w:mutbuf) -> u64:
    if get(w, 0) != INODE_MAGIC or get(w, 232) != 1 or get(w, 48) == 0:
        return 0
    phase = get(w, 8)
    if phase < 1 or phase > 3:
        return 0
    if (get(w, 16) | get(w, 24)) == 0 or (get(w, 200) | get(w, 208)) == 0:
        return 0
    if get(w, 56) > 192153584101141157:
        return 0
    if 512 + get(w, 56) * 96 > length(w):
        return 0
    if get(w, 184) > 1 or get(w, 192) > 4095 or get(w, 248) != 0:
        return 0
    count = 0
    at = 512
    end = 512 + get(w, 56) * 96
    while at < end:
        state = get(w, at + 48)
        if state > 2:
            return 0
        if state == 0:
            part = at
            while part < at + 96:
                if get(w, part) != 0:
                    return 0
                part = part + 8
        else:
            if get(w, at) == 0 or get(w, at) >= get(w, 48) or get(w, at + 8) == 0:
                return 0
            if get(w, at + 32) > 255 or get(w, at + 40) > 255 or (get(w, at + 32) & get(w, at + 40)) != 0:
                return 0
            if get(w, at + 64) != 0 or get(w, at + 88) != 0:
                return 0
            if get(w, at + 72) > 4294967295 or get(w, at + 80) > 4294967295:
                return 0
            if state == 1:
                if get(w, at + 56) != 0:
                    return 0
            else:
                if (get(w, at + 32) | get(w, at + 40)) != 0 or get(w, at + 56) == 0 or get(w, at + 56) > get(w, 136):
                    return 0
            other = 512
            while other < at:
                if get(w, other + 48) != 0:
                    if get(w, other) == get(w, at) or get(w, other + 8) == get(w, at + 8):
                        return 0
                    if state == 2 and get(w, other + 48) == 2 and get(w, other + 56) == get(w, at + 56):
                        return 0
                    if inode_same(w, at, other) != 0:
                        if (get(w, at + 40) & (get(w, other + 32) | get(w, other + 40))) != 0:
                            return 0
                        if (get(w, other + 40) & get(w, at + 32)) != 0:
                            return 0
                other = other + 96
            count = count + 1
        at = at + 96
    if count != get(w, 64):
        return 0
    if phase == 1:
        at = 72
        while at < 136:
            if get(w, at) != 0:
                return 0
            at = at + 8
        at = 144
        while at < 200:
            if get(w, at) != 0:
                return 0
            at = at + 8
        if get(w, 240) != 0:
            return 0
        at = 256
        while at < 512:
            if get(w, at) != 0:
                return 0
            at = at + 8
    else:
        if get(w, 32) == 0 or get(w, 144) == 0 or get(w, 256) != INODE_MAGIC:
            return 0
        if get(w, 272) != get(w, 16) or get(w, 280) != get(w, 24) or get(w, 288) != get(w, 32):
            return 0
        if get(w, 376) != get(w, 144):
            return 0
        if phase == 3:
            if get(w, 264) != 2 or get(w, 72) != 0 or get(w, 120) < 512:
                return 0
        else:
            if get(w, 40) == 0 or get(w, 112) == 0 or get(w, 120) != 0:
                return 0
            operation = get(w, 72)
            if operation != 8 and operation != 15 and operation != 17:
                return 0
            original = get(w, 264)
            if operation == 15:
                if original != 2 or get(w, 112) != get(w, 328):
                    return 0
                if (get(w, 88) | get(w, 96) | get(w, 160) | get(w, 184) | get(w, 240)) != 0:
                    return 0
            elif operation == 17:
                if original != 3 and original != 4:
                    return 0
                if get(w, 104) < 1 or get(w, 104) > 2 or get(w, 88) >= 8 or get(w, 96) == 0 or get(w, 96) > 8 - get(w, 88):
                    return 0
                if get(w, 104) == 1 and get(w, 96) != 1:
                    return 0
                if get(w, 104) != get(w, 328) or get(w, 88) != get(w, 360) or get(w, 96) != get(w, 368):
                    return 0
                expected_kind = 2
                if original == 3:
                    expected_kind = get(w, 104) - 1
                if get(w, 160) != expected_kind or get(w, 184) != 0 or get(w, 240) != 0:
                    return 0
            else:
                if original != 4 and original != 5:
                    return 0
                if get(w, 184) != 1 or get(w, 240) == 0 or get(w, 240) >= get(w, 48):
                    return 0
                if inode_token_present(w, get(w, 112)) != 0:
                    return 0
                if inode_group_masks(w, get(w, 168), get(w, 176)) != 0:
                    return 0
            if operation != 8:
                row = get(w, 80)
                if inode_slot(w, row) == 0:
                    return 0
                if operation == 15:
                    if get(w, row + 48) != 0:
                        return 0
                elif get(w, row + 48) != 1:
                    return 0
                else:
                    if get(w, row) != get(w, 304) or get(w, row + 8) != get(w, 112):
                        return 0
    return 1

def inode_register(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    row = inode_free(w)
    cap = get(w, 56)
    if row == 0:
        if cap > 192153584101141141:
            inode_refuse(w, 23)
            return inode_emit(o, w, 4294967293, 0, 0, 0)
        need = 512 + (cap + 16) * 96
        if length(w) < need:
            put(w, 120, need)
            put(w, 8, 3)
            return inode_emit(o, w, 2, 0, 0, 0)
        row = 512 + cap * 96
        at = row
        while at < need:
            put(w, at, 0)
            at = at + 8
        put(w, 56, cap + 16)
    put(w, 80, row)
    put(w, 112, read64(s, 72))
    put(w, 120, 0)
    return inode_issue(o, w, 15, 0)

def inode_lock(o:mutbuf, w:mutbuf) -> u32:
    row = get(w, 80)
    kind = get(w, 104)
    mask = ((1 << get(w, 96)) - 1) << get(w, 88)
    held = get(w, row + 32)
    other = get(w, row + 40)
    if kind == 2:
        held = get(w, row + 40)
        other = get(w, row + 32)
    command = get(w, 264)
    if command == 3:
        if kind == 1 and (held & mask) == mask:
            return inode_finish(o, w, 0, 0, get(w, row))
        if ((held | other) & mask) != 0:
            inode_refuse(w, 24)
            return inode_emit(o, w, 4294967293, 0, 0, 0)
        conflict = inode_other_masks(w, row, 2)
        if kind == 2:
            conflict = conflict | inode_other_masks(w, row, 1)
        if (conflict & mask) != 0:
            return inode_finish(o, w, 5, 0, get(w, row))
        if kind == 1 and (inode_other_masks(w, row, 1) & mask) != 0:
            put(w, row + 32, held | mask)
            return inode_finish(o, w, 0, 0, get(w, row))
        put(w, 112, get(w, row + 8))
        return inode_issue(o, w, 17, kind - 1)
    if (held & mask) == 0:
        return inode_finish(o, w, 0, 0, get(w, row))
    if (held & mask) != mask:
        inode_refuse(w, 25)
        return inode_emit(o, w, 4294967293, 0, 0, 0)
    if kind == 1 and (inode_other_masks(w, row, 1) & mask) != 0:
        put(w, row + 32, held & (255 - mask))
        return inode_after_unlock(o, w)
    put(w, 112, get(w, row + 8))
    return inode_issue(o, w, 17, 2)

def inode_retire(o:mutbuf, w:mutbuf) -> u32:
    row = get(w, 80)
    if get(w, 136) == 18446744073709551615:
        inode_refuse(w, 26)
        return inode_emit(o, w, 4294967293, 0, 0, 0)
    put(w, 136, get(w, 136) + 1)
    put(w, row + 56, get(w, 136))
    put(w, row + 48, 2)
    put(w, 168, get(w, row + 16))
    put(w, 176, get(w, row + 24))
    put(w, 184, 1)
    if inode_group_masks(w, get(w, 168), get(w, 176)) != 0:
        return inode_finish(o, w, 0, 0, 0)
    return inode_drain(o, w)

def inode_after_unlock(o:mutbuf, w:mutbuf) -> u32:
    row = get(w, 80)
    put(w, 168, get(w, row + 16))
    put(w, 176, get(w, row + 24))
    put(w, 184, 1)
    if inode_group_masks(w, get(w, 168), get(w, 176)) != 0:
        return inode_finish(o, w, 0, 0, get(w, row))
    return inode_drain(o, w)

def inode_drain(o:mutbuf, w:mutbuf) -> u32:
    chosen = 0
    last = 0
    at = 512
    end = 512 + get(w, 56) * 96
    while at < end:
        if get(w, at + 48) == 2 and get(w, at + 16) == get(w, 168) and get(w, at + 24) == get(w, 176):
            if get(w, at + 56) > last:
                chosen = at
                last = get(w, at + 56)
        at = at + 96
    if chosen == 0:
        result = get(w, 304)
        if get(w, 264) == 5:
            result = 0
        return inode_finish(o, w, 0, 0, result)
    if get(w, 40) == 18446744073709551615:
        inode_refuse(w, 27)
        return inode_emit(o, w, 4294967293, 0, 0, 0)
    put(w, 112, get(w, chosen + 8))
    put(w, 240, get(w, chosen))
    at = chosen
    while at < chosen + 96:
        put(w, at, 0)
        at = at + 8
    put(w, 64, get(w, 64) - 1)
    return inode_issue(o, w, 8, 0)

def inode_issue(o:mutbuf, w:mutbuf, operation:u64, kind:u64) -> u32:
    if get(w, 40) == 18446744073709551615:
        inode_refuse(w, 27)
        return inode_emit(o, w, 4294967293, 0, 0, 0)
    put(w, 40, get(w, 40) + 1)
    put(w, 72, operation)
    put(w, 160, kind)
    put(w, 8, 2)
    return inode_emit(o, w, 1, 0, 0, 0)

def inode_ack_shape(s:readbuf, w:mutbuf) -> u64:
    if read64(s, 32) != get(w, 32) or read64(s, 40) != get(w, 40):
        return 0
    if read64(s, 48) != get(w, 304) or read64(s, 56) != get(w, 72):
        return 0
    if read64(s, 120) != get(w, 144):
        return 0
    at = 64
    while at < 120:
        if read64(s, at) != 0:
            return 0
        at = at + 8
    return 1

def inode_peer_valid(s:readbuf, w:mutbuf) -> u64:
    if length(s) < 768:
        return 0
    if read64(s, 256) != FS_MAGIC or read64(s, 264) != 2:
        return 0
    if read64(s, 272) != get(w, 200) or read64(s, 280) != get(w, 208):
        return 0
    call = read64(s, 288)
    if call <= get(w, 216) or read64(s, 296) != 0:
        return 0
    if read64(s, 304) != get(w, 72) or read64(s, 312) != 0 or read64(s, 320) != get(w, 112):
        return 0
    a = 0
    b = 0
    c = 0
    if get(w, 72) == 17:
        a = get(w, 160)
        b = 120 + get(w, 88)
        c = get(w, 96)
    if read64(s, 328) != a or read64(s, 336) != b or read64(s, 344) != c:
        return 0
    if read64(s, 352) != 0 or read64(s, 360) != get(w, 40):
        return 0
    at = 368
    while at < 512:
        if read64(s, at) != 0:
            return 0
        at = at + 8
    if read64(s, 512) != FS_MAGIC or read64(s, 520) != 0:
        return 0
    if read64(s, 528) != get(w, 200) or read64(s, 536) != get(w, 208) or read64(s, 544) != call:
        return 0
    if read64(s, 552) <= get(w, 224) or read64(s, 560) != get(w, 72):
        return 0
    if read64(s, 568) > 4095 or read64(s, 624) != get(w, 40):
        return 0
    if read64(s, 632) != 1 or read64(s, 688) != 3 or read64(s, 696) != 0:
        return 0
    if (read64(s, 648) | read64(s, 656) | read64(s, 664)) != 0 or read64(s, 680) == 0:
        return 0
    at = 712
    while at < 768:
        if read64(s, at) != 0:
            return 0
        at = at + 8
    n = read64(s, 640)
    if n > length(s) - 768:
        return 0
    if get(w, 72) == 15 and read64(s, 568) == 0:
        if n != 144 or length(s) < 912:
            return 0
        if read64(s, 576) != read64(s, 768) or read64(s, 584) != read64(s, 776):
            return 0
        if read64(s, 592) != (read64(s, 792) & 4294967295):
            return 0
        if read64(s, 600) != (read64(s, 792) >> 32):
            return 0
        if read64(s, 608) != (read64(s, 800) & 4294967295):
            return 0
        if read64(s, 616) != read64(s, 816) or read64(s, 704) != read64(s, 784):
            return 0
    else:
        if n != 0 or read64(s, 704) != 0:
            return 0
        at = 576
        while at < 624:
            if read64(s, at) != 0:
                return 0
            at = at + 8
    return 1

def inode_acknowledge(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if inode_peer_valid(s, w) == 0:
        inode_refuse(w, 28)
        return inode_emit(o, w, 4294967293, 0, 0, 0)
    put(w, 216, read64(s, 288))
    put(w, 224, read64(s, 552))
    error = read64(s, 568)
    operation = get(w, 72)
    row = get(w, 80)
    if operation == 8:
        if error != 0 and get(w, 192) == 0:
            put(w, 192, error)
        return inode_drain(o, w)
    if operation == 15:
        if error != 0:
            return inode_finish(o, w, 1, error, 0)
        handle = get(w, 48)
        put(w, row, handle)
        put(w, row + 8, get(w, 112))
        put(w, row + 16, read64(s, 576))
        put(w, row + 24, read64(s, 584))
        put(w, row + 48, 1)
        put(w, row + 72, read64(s, 592))
        put(w, row + 80, read64(s, 600))
        put(w, 48, handle + 1)
        put(w, 64, get(w, 64) + 1)
        return inode_finish(o, w, 0, 0, handle)
    if error != 0:
        return inode_finish(o, w, 5, error, get(w, row))
    mask = ((1 << get(w, 96)) - 1) << get(w, 88)
    place = row + 32
    if get(w, 104) == 2:
        place = row + 40
    if get(w, 264) == 3:
        put(w, place, get(w, place) | mask)
        return inode_finish(o, w, 0, 0, get(w, row))
    put(w, place, get(w, place) & (255 - mask))
    return inode_after_unlock(o, w)

def inode_clear_pending(w:mutbuf) -> u64:
    at = 72
    while at < 136:
        put(w, at, 0)
        at = at + 8
    at = 144
    while at < 200:
        put(w, at, 0)
        at = at + 8
    put(w, 240, 0)
    at = 256
    while at < 512:
        put(w, at, 0)
        at = at + 8
    return 0

def inode_finish(o:mutbuf, w:mutbuf, code:u64, error:u64, result:u64) -> u32:
    put(w, 8, 1)
    inode_emit(o, w, 0, code, error, result)
    inode_clear_pending(w)
    return 0

def inode_refuse(w:mutbuf, reason:u64) -> u64:
    if get(w, 0) != INODE_BAD:
        put(w, 128, reason)
    put(w, 0, INODE_BAD)
    put(w, 8, 4)
    return 4294967293

def inode_emit(o:mutbuf, w:mutbuf, status:u64, code:u64, error:u64, result:u64) -> u32:
    if length(o) < 256:
        return 4294967293
    at = 0
    while at < 256:
        put(o, at, 0)
        at = at + 8
    put(o, 0, INODE_MAGIC)
    put(o, 8, status)
    put(o, 16, get(w, 16))
    put(o, 24, get(w, 24))
    put(o, 32, get(w, 32))
    put(o, 40, get(w, 40))
    put(o, 48, get(w, 304))
    put(o, 56, get(w, 72))
    put(o, 64, code)
    put(o, 72, error)
    put(o, 80, result)
    put(o, 88, get(w, 144))
    put(o, 96, get(w, 64))
    put(o, 104, get(w, 48))
    put(o, 112, get(w, 8))
    put(o, 120, get(w, 120))
    put(o, 128, get(w, 112))
    put(o, 136, get(w, 160))
    if get(w, 72) == 17:
        put(o, 144, 120 + get(w, 88))
        put(o, 152, get(w, 96))
    put(o, 160, get(w, 192))
    put(o, 168, get(w, 240))
    put(o, 176, 1)
    put(o, 184, get(w, 128))
    return status
'''
def source_program():
    return INODES.replace("INODE_MAGIC",str(MAGIC)).replace("INODE_BAD",str(BAD)).replace("FS_MAGIC",str(FS_MAGIC))+VALUES[VALUES.index("\ndef read64("):]
def document():
    nodes=ast.parse(source_program()).body
    names={node.name:"f"+str(i) for i,node in enumerate(nodes)}
    if len(names)!=len(nodes):raise ValueError("duplicate inode-owner function")
    signatures={node.name:([arg.annotation.id for arg in node.args.args],node.returns.id) for node in nodes}
    total=total_scalar_functions(nodes)
    functions=[]
    for node in nodes:
        builder=ObjectBuilder(node,names,signatures,total)
        builder.statements(node.body)
        functions.append({"name":names[node.name],"params":[builder.param(v) for v in builder.params],
            "returns":[builder.returns],"effects":["read","write","trap"],"entry":"b0","blocks":builder.blocks})
    return compact_authoring_cfg({"schema":"hepta.hia.program.v8","module":"agent_namespace_inode_r2","functions":functions})
if __name__=="__main__":
    path=ROOT/"examples/hia_bootstrap/agent_namespace_inode_r2.hiaasm"
    path.write_text(render_assembly(document()))
    print(path.name,path.stat().st_size)
