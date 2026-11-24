"""Shared HIA stderr continuation; the errno table is linked only once.

Callers retain their original cleanup and observation ordering, then return
the action from diagnostic(), diagnostic_errno(), or diagnostic_context_errno().
The primary entry routes phases 2060 through 2064 to the existing supervisor owner.
"""
from __future__ import annotations

HELPERS = r'''
def diagnostic(w:mutbuf, source:u64, size:u64) -> u32:
    put(w, 67200, source)
    put(w, 67208, size)
    put(w, 67216, 0)
    put(w, 67224, 0)
    put(w, 0, 2060)
    return 8

def diagnostic_errno(w:mutbuf, result:u64) -> u32:
    return diagnostic_context_errno(w, 0, 0, result)

def diagnostic_context_errno(w:mutbuf, source:u64, size:u64, result:u64) -> u32:
    put(w, 67200, source)
    put(w, 67208, size)
    put(w, 67216, 1)
    code = 5
    if result >> 63 == 1:
        code = 0 - result
    put(w, 67224, code)
    put(w, 0, 2060)
    return 8

def diagnostic_stream(w:mutbuf, source:u64, size:u64, fd:u64) -> u32:
    put(w, 67200, source)
    put(w, 67208, size)
    put(w, 67216, 2)
    put(w, 68128, fd)
    put(w, 68136, 0)
    put(w, 68144, 0)
    put(w, 68152, 0)
    put(w, 0, 2060)
    return 8
'''

RENDERER = r'''
def diagnostic_step(o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 2060:
        source = get(w, 67200)
        size = get(w, 67208)
        if source > length(w) or size > length(w) - source:
            return call(o, w, 99999, 231, 1, 0, 0, 0, 0, 0, 0)
        putn(w, 67264, 2322287805002313578, 8)
        putn(w, 67272, 10, 1)
        put(w, 67248, 0)
        if get(w, 67216) == 1:
            end = io_error(w, 67328, get(w, 67224))
            if end == 18446744073709551615:
                return call(o, w, 99999, 231, 1, 0, 0, 0, 0, 0, 0)
            put(w, 67248, end - 67328)
        put(w, 67232, 0)
        put(w, 67240, 0)
        return diagnostic_write(o, w)
    if phase == 2061:
        if result == 18446744073709551612:
            return diagnostic_write(o, w)
        if result == 0 or result >> 63 == 1:
            return call(o, w, 99999, 231, 1, 0, 0, 0, 0, 0, 0)
        put(w, 67240, get(w, 67240) + result)
        return diagnostic_write(o, w)
    if phase == 2062:
        if result == 18446744073709551612:
            return diagnostic_stream_read(o, w)
        carry = get(w, 68144)
        if result >> 63 == 1 or carry > 3 or result > 4096 - carry:
            return call(o, w, 99999, 231, 1, 0, 0, 0, 0, 0, 0)
        if result == 0:
            put(w, 68152, 1)
        put(w, 68136, get(w, 68136) + result)
        size = diagnostic_lossy(w, carry + result, get(w, 68152))
        put(w, 68160, size)
        put(w, 68168, 0)
        return diagnostic_stream_write(o, w)
    if phase == 2063:
        if result == 18446744073709551612:
            return diagnostic_stream_write(o, w)
        if result == 0 or result >> 63 == 1 or result > get(w, 68160) - get(w, 68168):
            return call(o, w, 99999, 231, 1, 0, 0, 0, 0, 0, 0)
        put(w, 68168, get(w, 68168) + result)
        return diagnostic_stream_write(o, w)
    if phase == 2064:
        put(w, 68128, 18446744073709551615)
        put(w, 67232, 3)
        put(w, 67240, 0)
        return diagnostic_write(o, w)
    return 0

def diagnostic_write(o:mutbuf, w:mutbuf) -> u32:
    while get(w, 67232) < 4:
        stage = get(w, 67232)
        source = 67264
        size = 8
        if stage == 1:
            source = get(w, 67200)
            size = get(w, 67208)
        elif stage == 2:
            if get(w, 67216) == 2:
                return diagnostic_stream_read(o, w)
            source = 67328
            size = get(w, 67248)
        elif stage == 3:
            source = 67272
            size = 1
        used = get(w, 67240)
        if used < size:
            return call(o, w, 2061, 1, 2, source + used, size - used, 0, 0, 0, 12)
        put(w, 67232, stage + 1)
        put(w, 67240, 0)
    return call(o, w, 99999, 231, 1, 0, 0, 0, 0, 0, 0)

def diagnostic_stream_read(o:mutbuf, w:mutbuf) -> u32:
    carry = get(w, 68144)
    return call(o, w, 2062, 17, get(w, 68128), 180224 + carry, 4096 - carry, get(w, 68136), 0, 0, 12)

def diagnostic_stream_write(o:mutbuf, w:mutbuf) -> u32:
    used = get(w, 68168)
    size = get(w, 68160)
    if used < size:
        return call(o, w, 2063, 1, 2, 188416 + used, size - used, 0, 0, 0, 12)
    if get(w, 68152) == 1:
        return call(o, w, 2064, 3, get(w, 68128), 0, 0, 0, 0, 0, 0)
    return diagnostic_stream_read(o, w)

def diagnostic_lossy(w:mutbuf, size:u64, final:u64) -> u64:
    at = 0
    out = 0
    put(w, 68144, 0)
    while at < size:
        lead = byte(w, 180224 + at)
        width = 0
        if lead < 128:
            width = 1
        elif lead >= 194 and lead <= 223:
            width = 2
        elif lead >= 224 and lead <= 239:
            width = 3
        elif lead >= 240 and lead <= 244:
            width = 4
        valid = width != 0
        consumed = 1
        while valid and consumed < width and at + consumed < size:
            point = byte(w, 180224 + at + consumed)
            if point < 128 or point > 191:
                valid = False
            elif consumed == 1 and ((lead == 224 and point < 160) or (lead == 237 and point >= 160) or (lead == 240 and point < 144) or (lead == 244 and point >= 144)):
                valid = False
            else:
                consumed = consumed + 1
        if valid and consumed < width:
            if final == 0:
                copy(w, 180224, 180224 + at, size - at)
                put(w, 68144, size - at)
                return out
            valid = False
        if valid:
            copy(w, 188416 + out, 180224 + at, width)
            at = at + width
            out = out + width
        else:
            store(w, 188416 + out, 239)
            store(w, 188416 + out + 1, 191)
            store(w, 188416 + out + 2, 189)
            at = at + consumed
            out = out + 3
    return out
'''
