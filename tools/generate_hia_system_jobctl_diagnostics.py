"""Shared HIA stderr continuations; the errno table is linked only once.

Callers preserve cleanup and observation ordering before scheduling a diagnostic.
diagnostic_stderr takes custody of a sealed captured stderr FD and renders Rust
UTF-8 lossy text incrementally, without trimming or adding an output-size cap.
The primary entry routes phases 2060 through 2069 to the supervisor owner.
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

def diagnostic_stderr(w:mutbuf, fd:u64, extent:u64, source:u64, size:u64) -> u32:
    put(w, 67200, source)
    put(w, 67208, size)
    put(w, 67216, 2)
    put(w, 67224, 0)
    put(w, 68400, fd)
    put(w, 68408, extent)
    put(w, 68416, 0)
    put(w, 68424, 0)
    put(w, 0, 2062)
    return 8
'''

RENDERER = r'''
def diagnostic_step(o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase >= 2062 and phase < 2070:
        return diagnostic_stream_step(o, w, phase, result)
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
            if get(w, 67216) == 2:
                return diagnostic_stream_abort(o, w)
            return call(o, w, 99999, 231, 1, 0, 0, 0, 0, 0, 0)
        put(w, 67240, get(w, 67240) + result)
        return diagnostic_write(o, w)
    return 0

def diagnostic_write(o:mutbuf, w:mutbuf) -> u32:
    while get(w, 67232) < 4:
        stage = get(w, 67232)
        if stage == 2 and get(w, 67216) == 2:
            return diagnostic_stream_read(o, w)
        source = 67264
        size = 8
        if stage == 1:
            source = get(w, 67200)
            size = get(w, 67208)
        elif stage == 2:
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

def diagnostic_stream_step(o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 2062:
        source = get(w, 67200)
        size = get(w, 67208)
        if source > length(w) or size > length(w) - source:
            return diagnostic_stream_abort(o, w)
        putn(w, 67264, 2322287805002313578, 8)
        putn(w, 67272, 10, 1)
        put(w, 67232, 0)
        put(w, 67240, 0)
        put(w, 67248, 0)
        return diagnostic_write(o, w)
    if phase == 2063:
        if result == 18446744073709551612:
            return diagnostic_stream_read(o, w)
        if result == 0 or result >> 63 == 1 or result > get(w, 68408) - get(w, 68416) or result > 65536 - get(w, 68424):
            return diagnostic_stream_abort(o, w)
        put(w, 68416, get(w, 68416) + result)
        size = get(w, 68424) + result
        final = 0
        if get(w, 68416) == get(w, 68408):
            final = 1
        amount = diagnostic_lossy(w, size, final)
        put(w, 68448, amount)
        put(w, 68456, 0)
        return diagnostic_stream_write(o, w)
    if phase == 2064:
        if result == 18446744073709551612:
            return diagnostic_stream_write(o, w)
        if result == 0 or result >> 63 == 1 or result > get(w, 68448) - get(w, 68456):
            return diagnostic_stream_abort(o, w)
        put(w, 68456, get(w, 68456) + result)
        return diagnostic_stream_write(o, w)
    if phase == 2065:
        put(w, 67216, 0)
        put(w, 67232, 3)
        put(w, 67240, 0)
        return diagnostic_write(o, w)
    if phase == 2069:
        return call(o, w, 99999, 231, 1, 0, 0, 0, 0, 0, 0)
    return 0

def diagnostic_stream_read(o:mutbuf, w:mutbuf) -> u32:
    used = get(w, 68416)
    if used == get(w, 68408):
        if get(w, 68424) != 0:
            amount = diagnostic_lossy(w, get(w, 68424), 1)
            put(w, 68448, amount)
            put(w, 68456, 0)
            return diagnostic_stream_write(o, w)
        fd = get(w, 68400)
        put(w, 68400, 18446744073709551615)
        return call(o, w, 2065, 3, fd, 0, 0, 0, 0, 0, 0)
    take = get(w, 68408) - used
    carry = get(w, 68424)
    if take > 65536 - carry:
        take = 65536 - carry
    return call(o, w, 2063, 17, get(w, 68400), 100663296 + carry, take, used, 0, 0, 12)

def diagnostic_stream_write(o:mutbuf, w:mutbuf) -> u32:
    used = get(w, 68456)
    if used == get(w, 68448):
        return diagnostic_stream_read(o, w)
    return call(o, w, 2064, 1, 2, 101711872 + used, get(w, 68448) - used, 0, 0, 0, 12)

def diagnostic_stream_abort(o:mutbuf, w:mutbuf) -> u32:
    fd = get(w, 68400)
    put(w, 68400, 18446744073709551615)
    if fd == 18446744073709551615:
        return call(o, w, 99999, 231, 1, 0, 0, 0, 0, 0, 0)
    return call(o, w, 2069, 3, fd, 0, 0, 0, 0, 0, 0)

def diagnostic_lossy(w:mutbuf, size:u64, final:u64) -> u64:
    at = 0
    out = 0
    stop = False
    while at < size and stop == False:
        point = byte(w, 100663296 + at)
        if point < 128:
            start = at
            while at < size and byte(w, 100663296 + at) < 128:
                at = at + 1
            copy(w, 101711872 + out, 100663296 + start, at - start)
            out = out + at - start
        else:
            width = 0
            if point >= 194 and point <= 223:
                width = 2
            elif point >= 224 and point <= 239:
                width = 3
            elif point >= 240 and point <= 244:
                width = 4
            prefix = 1
            valid = width != 0
            while valid and prefix < width and at + prefix < size:
                part = byte(w, 100663296 + at + prefix)
                if part < 128 or part > 191:
                    valid = False
                elif prefix == 1 and ((point == 224 and part < 160) or (point == 237 and part > 159) or (point == 240 and part < 144) or (point == 244 and part > 143)):
                    valid = False
                else:
                    prefix = prefix + 1
            if valid and prefix == width:
                copy(w, 101711872 + out, 100663296 + at, width)
                out = out + width
                at = at + width
            elif valid and at + prefix == size and final == 0:
                stop = True
            else:
                store(w, 101711872 + out, 239)
                store(w, 101711872 + out + 1, 191)
                store(w, 101711872 + out + 2, 189)
                out = out + 3
                at = at + prefix
    carry = size - at
    if carry != 0:
        copy(w, 100663296, 100663296 + at, carry)
    put(w, 68424, carry)
    return out
'''
