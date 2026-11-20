"""Author the explicit HIA cold-observer child-lifetime controller.

Static prototype: this author source has not been executed, compiled or qualified.
It does not register a worker helper or change either existing observer entry.
The HIA functions select every parent lifecycle action; the C bridge implements
one named OS primitive and the fixed async-signal-safe child exec adapter.
"""
from __future__ import annotations
import ast
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

AUTHOR_SOURCE = r'''
def entry(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) != 128 or length(o) != 64 or length(w) != 256:
        return 0
    if read_word(s, 0) != 3688501220647785288 or read_word(s, 120) != 10177645963941345917:
        return 0
    nonce = read_word(s, 8)
    if nonce == 0 or read_word(s, 88) > 9223372036854775807:
        return 0
    if get(w, 0) == 0:
        i = 0
        while i < 256:
            if get(w, i) != 0:
                return 0
            i = i + 8
        if read_word(s, 16) != 0 or read_word(s, 24) != 0 or read_word(s, 32) != 0:
            return 0
        if read_word(s, 40) != 0 or read_word(s, 48) != 0 or read_word(s, 56) != 0:
            return 0
        if read_word(s, 64) != 0 or read_word(s, 96) != 0 or read_word(s, 104) != 0 or read_word(s, 112) != 0:
            return 0
        put(w, 0, 3688501233549464392)
        put(w, 8, nonce)
        put(w, 40, 1)
        put(w, 168, 500000)
        return issue(s, o, w, 1, 0, 0, 0)
    if get(w, 0) != 3688501233549464392 or get(w, 8) != nonce:
        return 0
    if get(w, 16) != read_word(s, 16) or get(w, 24) != read_word(s, 24) or get(w, 32) != read_word(s, 32):
        return 0
    if read_word(s, 40) > 4294967295 or read_word(s, 64) > 1 or read_word(s, 112) > 1:
        return 0
    if read_word(s, 96) > 511:
        return 0
    phase = get(w, 40)
    if phase < 12:
        return setup(s, o, w)
    if phase >= 22 and phase <= 29:
        return hosted_setup(s, o, w)
    if phase < 50:
        return io(s, o, w)
    if phase < 99:
        return cleanup(s, o, w)
    return 0

def setup(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    phase = get(w, 40)
    error = read_word(s, 40)
    value = read_word(s, 48)
    if phase == 1:
        if error != 0:
            return fail(s, o, w, 2, error, 1)
        if (read_word(s, 96) & 1) == 0:
            return 0
        if read_word(s, 72) == 0:
            put(w, 40, 3)
            return issue(s, o, w, 3, 0, 0, 0)
        put(w, 40, 2)
        return issue(s, o, w, 2, 0, 0, 0)
    if phase == 2:
        offset = get(w, 48)
        if error == 4:
            return issue(s, o, w, 2, 0, offset, 0)
        if error != 0:
            return fail(s, o, w, 2, error, 2)
        if value == 0:
            return fail(s, o, w, 2, 5, 2)
        if offset > read_word(s, 72) or value > read_word(s, 72) - offset:
            return 0
        offset = offset + value
        put(w, 48, offset)
        if offset < read_word(s, 72):
            return issue(s, o, w, 2, 0, offset, 0)
        put(w, 40, 3)
        return issue(s, o, w, 3, 0, 0, 0)
    if phase == 3:
        if error != 0:
            return fail(s, o, w, 2, error, 3)
        put(w, 40, 4)
        return issue(s, o, w, 4, 0, 0, 0)
    if phase == 4:
        if error != 0:
            return fail(s, o, w, 2, error, 4)
        if (value & 15) != 15:
            return fail(s, o, w, 2, 5, 4)
        put(w, 40, 22)
        return issue(s, o, w, 19, 0, 0, 0)
    if phase == 5:
        if error != 0:
            return fail(s, o, w, 2, error, 5)
        index = get(w, 136)
        if index >= 4:
            return 0
        if index < 2:
            index = index + 1
            put(w, 136, index)
            return issue(s, o, w, 5, index, 0, 0)
        if index == 2:
            put(w, 136, 3)
            put(w, 40, 23)
            return issue(s, o, w, 20, 2, 0, 0)
        put(w, 40, 27)
        return issue(s, o, w, 22, 0, 0, 0)
    if phase == 6:
        if error != 0:
            return fail(s, o, w, 2, error, 6)
        if value == 0 or value != read_word(s, 104) or read_word(s, 112) != 0:
            return 0
        put(w, 80, value)
        put(w, 40, 7)
        put(w, 128, 0)
        return issue(s, o, w, 7, 8, 0, 0)
    if phase == 7:
        if error != 0:
            if get(w, 128) == 0:
                return fail(s, o, w, 2, error, 7)
            put(w, 96, 2)
            put(w, 104, error)
            put(w, 112, 7)
            put(w, 248, 7)
        cursor = get(w, 128) + 1
        put(w, 128, cursor)
        if cursor == 1:
            return issue(s, o, w, 7, 6, 0, 0)
        if cursor == 2:
            return issue(s, o, w, 7, 4, 0, 0)
        if cursor == 3:
            return issue(s, o, w, 7, 1, 0, 0)
        if cursor != 4:
            return 0
        if get(w, 96) != 0:
            put(w, 40, 50)
            return cleanup_next(s, o, w)
        put(w, 40, 8)
        return issue(s, o, w, 8, 0, 0, 0)
    if phase == 8:
        if error == 4:
            return issue(s, o, w, 8, 0, 0, 0)
        if error != 0:
            return fail(s, o, w, 2, error, 8)
        count = get(w, 144)
        if value > 8 or count > 8 or value > 8 - count:
            return 0
        count = count + value
        put(w, 144, count)
        if value != 0:
            return issue(s, o, w, 8, 0, 0, 0)
        if count == 8:
            packed = read_word(s, 56)
            child_error = packed & 4294967295
            child_stage = packed >> 32
            if child_error == 0 or child_stage < 1 or child_stage > 6:
                return fail(s, o, w, 2, 71, 8)
            put(w, 96, 3)
            put(w, 104, child_error)
            put(w, 112, child_stage)
            put(w, 248, 8)
            put(w, 40, 9)
            return issue(s, o, w, 7, 7, 0, 0)
        if count != 0:
            return fail(s, o, w, 2, 71, 8)
        put(w, 40, 9)
        return issue(s, o, w, 7, 7, 0, 0)
    if phase == 9:
        if error != 0:
            return fail(s, o, w, 2, error, 7)
        if get(w, 96) != 0:
            put(w, 40, 50)
            return cleanup_next(s, o, w)
        put(w, 40, 28)
        return issue(s, o, w, 23, 0, 0, 0)
    if phase == 10:
        if error != 0:
            return fail(s, o, w, 2, error, 9)
        duration = read_word(s, 88)
        if value > 18446744073709551615 - duration:
            return fail(s, o, w, 2, 75, 9)
        put(w, 64, value + duration)
        put(w, 184, 1)
        put(w, 40, 29)
        return issue(s, o, w, 25, 0, 0, 0)
    if phase == 11:
        if error != 0:
            return fail(s, o, w, 2, error, 7)
        put(w, 40, 12)
        return issue(s, o, w, 9, 0, 0, 0)
    return 0

def hosted_setup(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    phase = get(w, 40)
    error = read_word(s, 40)
    if phase >= 23 and phase <= 25:
        ownership = read_word(s, 48)
        slot = read_word(s, 32)
        if ownership > 3 or ownership == 2 or read_word(s, 56) != 0:
            return 0
        if slot != 2 and slot != 3 and slot != 5:
            return 0
        if ownership != 0:
            if error == 0:
                return 0
            bit = 1 << slot
            if ownership == 3 and (read_word(s, 96) & bit) != 0:
                return 0
            if ownership == 1 and (read_word(s, 96) & bit) == 0:
                return 0
            put(w, 216, get(w, 216) | bit)
    if error != 0:
        return fail(s, o, w, 2, error, read_word(s, 24))
    if phase == 22:
        if read_word(s, 48) > 1:
            return 0
        put(w, 72, read_word(s, 48))
        put(w, 136, 0)
        put(w, 40, 5)
        return issue(s, o, w, 5, 0, 0, 0)
    if phase == 23:
        put(w, 40, 24)
        return issue(s, o, w, 20, 3, 0, 0)
    if phase == 24:
        put(w, 40, 25)
        return issue(s, o, w, 20, 5, 0, 0)
    if phase == 25:
        put(w, 40, 26)
        return issue(s, o, w, 21, 0, 0, 0)
    if phase == 26:
        put(w, 40, 5)
        return issue(s, o, w, 5, 3, 0, 0)
    if phase == 27:
        put(w, 40, 6)
        return issue(s, o, w, 6, 0, 0, 0)
    if phase == 28:
        put(w, 152, 1)
        put(w, 40, 10)
        return issue(s, o, w, 9, 0, 0, 0)
    if phase == 29:
        if read_word(s, 80) == 0:
            put(w, 40, 11)
            return issue(s, o, w, 7, 2, 0, 0)
        put(w, 40, 12)
        return issue(s, o, w, 9, 0, 0, 0)
    return 0

def io(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    phase = get(w, 40)
    if phase <= 14:
        return polling(s, o, w)
    if phase <= 17 or phase == 20:
        return exchange(s, o, w)
    if phase == 18 or phase == 19 or phase == 21:
        return waiting(s, o, w)
    return 0

def polling(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    phase = get(w, 40)
    error = read_word(s, 40)
    value = read_word(s, 48)
    if get(w, 184) != 1:
        return 0
    if phase == 12:
        if error != 0:
            return fail(s, o, w, 2, error, 9)
        if (read_word(s, 96) & 44) == 0:
            put(w, 40, 18)
            return issue(s, o, w, 14, 0, 0, 0)
        if value >= get(w, 64):
            return fail(s, o, w, 1, 0, 10)
        put(w, 40, 13)
        return issue(s, o, w, 10, 0, get(w, 64) - value, 0)
    if phase == 13:
        if error == 4:
            put(w, 40, 12)
            return issue(s, o, w, 9, 0, 0, 0)
        if error != 0:
            return fail(s, o, w, 2, error, 10)
        if value > 7:
            return 0
        put(w, 120, value)
        put(w, 40, 14)
        return issue(s, o, w, 9, 0, 0, 0)
    if phase == 14:
        if error != 0:
            return fail(s, o, w, 2, error, 9)
        if value > get(w, 64):
            return fail(s, o, w, 1, 0, 10)
        return ready(s, o, w)
    return 0

def ready(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    bits = get(w, 120)
    if (bits & 1) != 0:
        put(w, 120, bits & 6)
        offset = get(w, 56)
        if offset >= read_word(s, 80):
            return 0
        count = read_word(s, 80) - offset
        if count > 4096:
            count = 4096
        put(w, 40, 15)
        return issue(s, o, w, 11, 0, offset, count)
    if (bits & 2) != 0:
        put(w, 120, bits & 5)
        put(w, 40, 16)
        return issue(s, o, w, 12, 0, 0, 0)
    if (bits & 4) != 0:
        put(w, 120, bits & 3)
        put(w, 40, 17)
        return issue(s, o, w, 13, 0, 0, 0)
    put(w, 40, 12)
    return issue(s, o, w, 9, 0, 0, 0)

def exchange(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    phase = get(w, 40)
    error = read_word(s, 40)
    value = read_word(s, 48)
    if phase == 20:
        if error != 0:
            return fail(s, o, w, 2, error, 7)
        return ready(s, o, w)
    if phase == 15:
        offset = get(w, 56)
        if offset >= read_word(s, 80):
            return 0
        count = read_word(s, 80) - offset
        if count > 4096:
            count = 4096
        if error == 4:
            return issue(s, o, w, 11, 0, offset, count)
        if error == 32:
            put(w, 40, 20)
            return issue(s, o, w, 7, 2, 0, 0)
        if error != 0:
            return fail(s, o, w, 2, error, 11)
        if value > count:
            return 0
        offset = offset + value
        put(w, 56, offset)
        if offset == read_word(s, 80):
            put(w, 40, 20)
            return issue(s, o, w, 7, 2, 0, 0)
        return ready(s, o, w)
    action = 12
    descriptor = 3
    if phase == 17:
        action = 13
        descriptor = 5
    if phase != 16 and phase != 17:
        return 0
    if error == 4:
        return issue(s, o, w, action, 0, 0, 0)
    if error != 0:
        return fail(s, o, w, 2, error, action)
    if value > 32768:
        return 0
    if value == 0:
        put(w, 40, 20)
        return issue(s, o, w, 7, descriptor, 0, 0)
    return ready(s, o, w)

def waiting(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    phase = get(w, 40)
    error = read_word(s, 40)
    value = read_word(s, 48)
    if phase == 18:
        if error == 4:
            return issue(s, o, w, 14, 0, 0, 0)
        if error != 0:
            return fail(s, o, w, 2, error, 14)
        if value == 0:
            put(w, 40, 19)
            return issue(s, o, w, 9, 0, 0, 0)
        if value != read_word(s, 104) or value != get(w, 80) or read_word(s, 112) != 1:
            return 0
        put(w, 88, read_word(s, 56))
        put(w, 40, 50)
        return cleanup(s, o, w)
    if phase == 19:
        if error != 0:
            return fail(s, o, w, 2, error, 9)
        if value >= get(w, 64):
            return fail(s, o, w, 4, 0, 14)
        delay = get(w, 168) * 2
        if delay > 50000000:
            delay = 50000000
        if delay > get(w, 64) - value:
            delay = get(w, 64) - value
        put(w, 168, delay)
        put(w, 176, value + delay)
        put(w, 40, 21)
        return issue(s, o, w, 17, 0, value + delay, 0)
    if phase == 21:
        if error == 4:
            return issue(s, o, w, 17, 0, get(w, 176), 0)
        if error != 0:
            return fail(s, o, w, 2, error, 17)
        put(w, 40, 18)
        return issue(s, o, w, 14, 0, 0, 0)
    return 0

def fail(s:readbuf, o:mutbuf, w:mutbuf, mode:u64, error:u64, stage:u64) -> u32:
    put(w, 248, get(w, 40))
    put(w, 96, mode)
    put(w, 104, error)
    put(w, 112, stage)
    if error == 1073741826:
        put(w, 208, 2)
    else:
        if error == 1073741825:
            put(w, 208, 1)
    put(w, 40, 50)
    return cleanup_next(s, o, w)

def cleanup(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    phase = get(w, 40)
    error = read_word(s, 40)
    if phase >= 55 and phase <= 58:
        return interrupted_wait(s, o, w)
    if phase == 54:
        if error == 4:
            return issue(s, o, w, 14, 0, 0, 0)
        if error != 0:
            if error == 10 and read_word(s, 64) == 1:
                put(w, 96, 6)
                put(w, 104, error)
                put(w, 112, 14)
            else:
                if get(w, 72) != 1:
                    return 0
                put(w, 96, 2)
                put(w, 104, error)
                put(w, 112, 14)
                put(w, 160, 1)
        else:
            value = read_word(s, 48)
            if value != 0:
                if value != read_word(s, 104) or read_word(s, 112) != 1:
                    return 0
                put(w, 88, read_word(s, 56))
        put(w, 192, 1)
    if phase == 51:
        put(w, 200, 1)
        if error != 0 and error != 3:
            put(w, 96, 2)
            put(w, 104, error)
            put(w, 112, 15)
            put(w, 208, 1)
    if phase == 52:
        if error == 4:
            return issue(s, o, w, 16, 0, 0, 0)
        if error != 0:
            if error == 10 and read_word(s, 64) == 1:
                put(w, 96, 6)
                put(w, 104, error)
                put(w, 112, 16)
            else:
                if get(w, 72) != 1:
                    return 0
                put(w, 96, 2)
                put(w, 104, error)
                put(w, 112, 16)
                put(w, 160, 1)
        else:
            if read_word(s, 48) != read_word(s, 104) or read_word(s, 112) != 1:
                return 0
            put(w, 88, read_word(s, 56))
    if phase == 53 and error != 0:
        slot = read_word(s, 32)
        suppress = get(w, 152) == 0 and error < 4096 and slot != 0 and slot != 7 and slot != 8
        if suppress == False:
            put(w, 96, 2)
            put(w, 104, error)
            put(w, 112, 7)
            if get(w, 72) == 1:
                if get(w, 152) == 0 or slot == 3 or slot == 5:
                    put(w, 160, 1)
    return cleanup_next(s, o, w)

def interrupted_wait(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    phase = get(w, 40)
    error = read_word(s, 40)
    value = read_word(s, 48)
    if error == 4:
        if phase == 56:
            return issue(s, o, w, 14, 0, 0, 0)
        if phase == 58:
            return issue(s, o, w, 17, 0, get(w, 240), 0)
    if error != 0:
        put(w, 96, 2)
        put(w, 104, error)
        put(w, 112, read_word(s, 24))
        put(w, 208, 1)
        put(w, 232, 2)
        return cleanup_next(s, o, w)
    if phase == 55:
        bound = get(w, 64)
        if value > 18446744073709551615 - 250000000:
            return 0
        if value + 250000000 < bound:
            bound = value + 250000000
        put(w, 224, bound)
        put(w, 232, 500000)
        put(w, 40, 56)
        return issue(s, o, w, 14, 0, 0, 0)
    if phase == 56:
        if value != 0:
            if value != read_word(s, 104) or read_word(s, 112) != 1:
                return 0
            put(w, 88, read_word(s, 56))
            put(w, 232, 2)
            return cleanup_next(s, o, w)
        put(w, 40, 57)
        return issue(s, o, w, 9, 0, 0, 0)
    if phase == 57:
        if value >= get(w, 224):
            put(w, 232, 2)
            return cleanup_next(s, o, w)
        delay = get(w, 232) * 2
        if delay > 50000000:
            delay = 50000000
        if delay > get(w, 224) - value:
            delay = get(w, 224) - value
        put(w, 232, delay)
        put(w, 240, value + delay)
        put(w, 40, 58)
        return issue(s, o, w, 17, 0, value + delay, 0)
    if phase == 58:
        put(w, 40, 56)
        return issue(s, o, w, 14, 0, 0, 0)
    return 0

def close_next(s:readbuf, o:mutbuf, w:mutbuf, slot:u64) -> u32:
    put(w, 40, 53)
    return issue(s, o, w, 7, slot, 0, 0)

def cleanup_next(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    mask = read_word(s, 96)
    remaining = mask & (511 ^ get(w, 216))
    live = read_word(s, 104) != 0 and read_word(s, 112) == 0 and read_word(s, 64) == 0
    if read_word(s, 64) != 0:
        put(w, 96, 6)
        if get(w, 104) == 0:
            put(w, 104, 10)
            put(w, 112, 16)
    if get(w, 152) == 0 and (get(w, 72) == 1 or get(w, 96) == 3):
        if get(w, 160) == 1:
            return handback(s, o, w)
        if get(w, 248) == 5 and get(w, 136) < 3:
            index = 1
            while index < 7:
                if (remaining & (1 << index)) != 0:
                    return close_next(s, o, w, index)
                index = index + 1
            return handback(s, o, w)
        if (remaining & 256) != 0:
            return close_next(s, o, w, 8)
        if (remaining & 128) != 0:
            return close_next(s, o, w, 7)
        if live and get(w, 96) == 3:
            put(w, 40, 52)
            return issue(s, o, w, 16, 0, 0, 0)
        if (remaining & 4) != 0:
            return close_next(s, o, w, 2)
        if (remaining & 8) != 0:
            return close_next(s, o, w, 3)
        if (remaining & 32) != 0:
            return close_next(s, o, w, 5)
        if (remaining & 2) != 0:
            return close_next(s, o, w, 1)
        if (remaining & 16) != 0:
            return close_next(s, o, w, 4)
        if (remaining & 64) != 0:
            return close_next(s, o, w, 6)
        return handback(s, o, w)
    if get(w, 72) == 1 and get(w, 160) == 1:
        return handback(s, o, w)
    if live:
        if get(w, 208) == 2 and get(w, 184) == 1 and get(w, 232) == 0:
            put(w, 40, 55)
            return issue(s, o, w, 9, 0, 0, 0)
        if get(w, 192) == 0:
            put(w, 40, 54)
            return issue(s, o, w, 14, 0, 0, 0)
        if get(w, 200) == 0:
            put(w, 40, 51)
            return issue(s, o, w, 15, 0, 0, 0)
        if get(w, 96) == 2 and get(w, 152) == 1:
            if (remaining & 8) != 0:
                return close_next(s, o, w, 3)
            if (remaining & 32) != 0:
                return close_next(s, o, w, 5)
            if (remaining & 4) != 0:
                return close_next(s, o, w, 2)
            if get(w, 208) == 2 and get(w, 232) == 2:
                return handback(s, o, w)
        put(w, 40, 52)
        return issue(s, o, w, 16, 0, 0, 0)
    if get(w, 152) == 1:
        if (remaining & 8) != 0:
            return close_next(s, o, w, 3)
        if (remaining & 32) != 0:
            return close_next(s, o, w, 5)
        if (remaining & 4) != 0:
            return close_next(s, o, w, 2)
    index = 9
    while index > 0:
        index = index - 1
        if (remaining & (1 << index)) != 0:
            return close_next(s, o, w, index)
    return handback(s, o, w)

def handback(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    mask = read_word(s, 96)
    if (mask & 1) != 0 and (get(w, 216) & 1) == 0:
        return close_next(s, o, w, 0)
    live = read_word(s, 104) != 0 and read_word(s, 112) == 0 and read_word(s, 64) == 0
    if mask != 0 or live:
        if get(w, 72) != 1 or get(w, 96) == 0:
            return 0
        put(w, 40, 98)
        return issue(s, o, w, 24, get(w, 96), mask, read_word(s, 104))
    put(w, 40, 99)
    return issue(s, o, w, 18, get(w, 96), get(w, 104), get(w, 112))

def issue(s:readbuf, o:mutbuf, w:mutbuf, action:u64, argument:u64, amount:u64, auxiliary:u64) -> u32:
    sequence = get(w, 16)
    if sequence == 18446744073709551615:
        return 0
    sequence = sequence + 1
    put(w, 16, sequence)
    put(w, 24, action)
    put(w, 32, argument)
    if action == 7:
        if argument >= 9 or (get(w, 216) & (1 << argument)) != 0:
            return 0
        put(w, 216, get(w, 216) | (1 << argument))
    nonce = read_word(s, 8)
    put(o, 0, 3688501229237719880)
    put(o, 8, nonce)
    put(o, 16, sequence)
    put(o, 24, action)
    put(o, 32, argument)
    put(o, 40, amount)
    put(o, 48, auxiliary)
    seal = 10177645963941345917 ^ 3688501229237719880 ^ nonce ^ sequence ^ action ^ argument ^ amount ^ auxiliary
    put(o, 56, seal)
    return 64

def read_word(s:readbuf, at:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(s, at + i) << (i * 8))
        i = i + 1
    return value

def get(w:mutbuf, at:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(w, at + i) << (i * 8))
        i = i + 1
    return value

def put(w:mutbuf, at:u64, value:u64) -> u64:
    i = 0
    while i < 8:
        store(w, at + i, (value >> (i * 8)) & 255)
        i = i + 1
    return 0
'''

def document():
    nodes = ast.parse(AUTHOR_SOURCE).body
    names = {node.name: 'f' + str(i) for i, node in enumerate(nodes)}
    signatures = {
        node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id)
        for node in nodes
    }
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = Builder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({
            'name': names[node.name],
            'params': [builder.param(value) for value in builder.params],
            'returns': [builder.returns],
            'effects': ['read', 'write', 'trap'],
            'entry': 'b0',
            'blocks': builder.blocks,
        })
    # Original compiler/profile limits remain unchanged. Actual block/resource
    # validation is a mandatory root execution gate; no local limit override.
    return compact_authoring_cfg({
        'schema': 'hepta.hia.program.v8',
        'module': 'cold_native_transport',
        'functions': functions,
    })

def main():
    destination = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap/cold_native_transport.hepta'
    destination.write_text(render_assembly(document()))
    print(destination.name, destination.stat().st_size)

if __name__ == '__main__':
    main()
