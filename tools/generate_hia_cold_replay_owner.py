"""Development author for the native cold process owner; runtime is HIA only.

The owner retains the original 180 s / 3 s cold deadline, adopted-child
ownership, bounded /proc identities and final kernel ECHILD proof.  The 15 s
and 20 s profiles are the original export/CLI and flat-observer limits.
"""
from pathlib import Path
import re
import struct
import subprocess
import tempfile

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_native_filter import LINK_SOURCE

ROOT = Path(__file__).resolve().parents[1]

SOURCE = r'''def advance(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(o) != 128 or length(w) != 4194304:
        return 0
    p = get(w, 0)
    r = get(w, 8)
    if p < 100:
        return admission(s, o, w, p, r)
    if p < 200:
        return child(s, o, w, p, r)
    if p < 300:
        return watching(s, o, w, p, r)
    if p < 400:
        return scanning(s, o, w, p, r)
    if p < 500:
        return cleaning(s, o, w, p, r)
    return publish(s, o, w, p, r)

def admission(s:readbuf, o:mutbuf, w:mutbuf, p:u64, r:u64) -> u32:
    if p == 0:
        constants(w)
        if admit(s, w) == 0:
            return finish(o, w, 65)
        return call(o, w, 1, 110, 0, 0, 0, 0, 0, 0, 0)
    if p == 1:
        if r != uint(s, 8):
            return finish(o, w, 65)
        return call(o, w, 2, 39, 0, 0, 0, 0, 0, 0, 0)
    if failed(r) and (p != 16 or r != 18446744073709551605):
        return finish(o, w, 74)
    if p == 2:
        put(w, 16, r)
        return call(o, w, 3, 107, 0, 0, 0, 0, 0, 0, 0)
    if p == 3:
        put(w, 24, r)
        put(w, 32, 0)
        return call(o, w, 4, 5, uint(s, 40), 2048, 0, 0, 0, 0, 12)
    if p == 4:
        index = get(w, 32)
        mode = getn(w, 2072, 4)
        j = 0
        while j < index:
            if get(w, 2048) == get(w, 3072 + j * 16) and get(w, 2056) == get(w, 3080 + j * 16):
                return finish(o, w, 65)
            j = j + 1
        put(w, 3072 + index * 16, get(w, 2048))
        put(w, 3080 + index * 16, get(w, 2056))
        if index == 5:
            if mode & 61440 != 16384 or mode & 63 != 0 or getn(w, 2076, 4) != get(w, 24):
                return finish(o, w, 65)
        else:
            if mode & 61440 != 32768 or get(w, 2064) > 1:
                return finish(o, w, 65)
            if index >= 2 and (mode & 63 != 0 or getn(w, 2076, 4) != get(w, 24) or get(w, 2096) != 0):
                return finish(o, w, 65)
            if index < 2:
                if get(w, 2096) == 0 and index == 0:
                    return finish(o, w, 65)
                return call(o, w, 5, 72, uint(s, 40 + index * 8), 1034, 0, 0, 0, 0, 0)
        return inspect_next(s, o, w)
    if p == 5:
        if r & 15 != 15:
            return finish(o, w, 65)
        return inspect_next(s, o, w)
    if p == 6:
        if get(w, 600) != 0:
            return finish(o, w, 65)
        return call(o, w, 7, 157, 36, 1, 0, 0, 0, 0, 0)
    if p == 7:
        return call(o, w, 8, 157, 37, 640, 0, 0, 0, 0, 12)
    if p == 8:
        if getn(w, 640, 4) != 1:
            return finish(o, w, 74)
        return call(o, w, 9, 157, 1, 15, 0, 0, 0, 0, 0)
    if p == 9:
        return call(o, w, 10, 110, 0, 0, 0, 0, 0, 0, 0)
    if p == 10:
        if r != uint(s, 8):
            return finish(o, w, 65)
        put(w, 608, 16386)
        return call(o, w, 11, 14, 0, 608, 616, 8, 0, 0, 60)
    if p == 11:
        if get(w, 616) & 16386 != 0:
            return finish(o, w, 65)
        clear(w, 900, 32)
        return call(o, w, 18, 13, 15, 900, 0, 8, 0, 0, 12)
    if p == 18:
        return call(o, w, 19, 13, 2, 900, 0, 8, 0, 0, 12)
    if p == 19:
        return call(o, w, 12, 289, 18446744073709551615, 608, 8, 526336, 0, 0, 12)
    if p == 12:
        put(w, 240, r)
        return call(o, w, 13, 257, 18446744073709551516, C_PROC, 720896, 0, 0, 0, 12)
    if p == 13:
        put(w, 152, r)
        return scan_start(o, w, 0, 14)
    if p == 14:
        if get(w, 128) != 0:
            return finish(o, w, 65)
        return clock(o, w, 15)
    if p == 15:
        now = time(w)
        if uint(s, 16) > now:
            return finish(o, w, 65)
        if now >= uint(s, 24):
            put(w, 56, 1)
            return cleanup_start(o, w)
        return call(o, w, 16, 0, get(w, 240), 8192, 128, 0, 0, 0, 12)
    if p == 16:
        if r != 18446744073709551605:
            if r != 128:
                return finish(o, w, 74)
            put(w, 96, getn(w, 8192, 4))
            return cleanup_start(o, w)
        return call(o, w, 17, 57, 0, 0, 0, 0, 0, 0, 0)
    if p == 17:
        if r == 0:
            return call(o, w, 100, 157, 1, 15, 0, 0, 0, 0, 0)
        put(w, 40, r)
        event(w, 1, r, 0, 0)
        return wait_leader(o, w)
    return finish(o, w, 65)

def inspect_next(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    n = get(w, 32) + 1
    put(w, 32, n)
    if n < 6:
        return call(o, w, 4, 5, uint(s, 40 + n * 8), 2048, 0, 0, 0, 0, 12)
    return call(o, w, 6, 13, 17, 0, 600, 8, 0, 0, 48)

def admit(s:readbuf, w:mutbuf) -> u64:
    if length(s) < 138 or length(s) > 262144 or uint(s, 0) != MAGIC_REQUEST:
        return 0
    seconds = uint(s, 32)
    if seconds != 15 and seconds != 20 and seconds != 180:
        return 0
    if uint(s, 8) < 2 or uint(s, 8) > 2147483647 or uint(s, 16) > 18446743893709551615:
        return 0
    if uint(s, 24) != uint(s, 16) + seconds * 1000000000 or uint(s, 112) != 0 or uint(s, 120) != 0:
        return 0
    argc = uint(s, 88)
    envc = uint(s, 96)
    passc = uint(s, 104)
    if argc == 0 or argc > 64 or envc > 64 or passc > 64:
        return 0
    i = 0
    while i < 6:
        fd = uint(s, 40 + i * 8)
        if fd < 3 or fd > 2147483647:
            return 0
        j = 0
        while j < i:
            if fd == uint(s, 40 + j * 8):
                return 0
            j = j + 1
        i = i + 1
    at = 128
    target = 1048576
    i = 0
    while i < argc + envc:
        if at + 8 >= length(s):
            return 0
        n = uint(s, at)
        at = at + 8
        if (i < argc and n == 0) or n > 65535 or at + n >= length(s) or byte(s, at + n) != 0:
            return 0
        j = 0
        while j < n:
            if byte(s, at + j) == 0:
                return 0
            j = j + 1
        if i >= argc and valid_env(s, w, at, n, i - argc) == 0:
            return 0
        put(w, 4096 + i * 8, target)
        j = 0
        while j <= n:
            store(w, target + j, byte(s, at + j))
            j = j + 1
        at = at + n + 1
        target = target + n + 1
        i = i + 1
    put(w, 4096 + (argc + envc) * 8, 18446744073709551615)
    if at + passc * 8 != length(s):
        return 0
    put(w, 256, at)
    i = 0
    while i < passc:
        fd = uint(s, at + i * 8)
        if fd < 3 or fd > 2147483647:
            return 0
        j = 0
        while j < 6:
            if fd == uint(s, 40 + j * 8):
                return 0
            j = j + 1
        j = 0
        while j < i:
            if fd == uint(s, at + j * 8):
                return 0
            j = j + 1
        i = i + 1
    return 1

def valid_env(s:readbuf, w:mutbuf, at:u64, n:u64, i:u64) -> u64:
    size = 0
    while size < n and byte(s, at + size) != 61:
        c = byte(s, at + size)
        if ((c < 65 or c > 90) and (c < 97 or c > 122) and c != 95 and (size == 0 or c < 48 or c > 57)):
            return 0
        size = size + 1
    if size == 0 or size == n:
        return 0
    j = 0
    while j < i:
        if get(w, 8192 + j * 16 + 8) == size and same_s(s, get(w, 8192 + j * 16), at, size) == 1:
            return 0
        j = j + 1
    put(w, 8192 + i * 16, at)
    put(w, 8192 + i * 16 + 8, size)
    return 1

def child(s:readbuf, o:mutbuf, w:mutbuf, p:u64, r:u64) -> u32:
    if failed(r) or p == 114:
        return finish(o, w, 127)
    if p == 100:
        return call(o, w, 101, 110, 0, 0, 0, 0, 0, 0, 0)
    if p == 101:
        if r != get(w, 16):
            return finish(o, w, 127)
        return call(o, w, 102, 81, uint(s, 80), 0, 0, 0, 0, 0, 0)
    if p == 102:
        return call(o, w, 103, 33, uint(s, 48), 0, 0, 0, 0, 0, 0)
    if p == 103:
        return call(o, w, 104, 33, uint(s, 56), 1, 0, 0, 0, 0, 0)
    if p == 104:
        return call(o, w, 105, 33, uint(s, 64), 2, 0, 0, 0, 0, 0)
    if p == 105:
        return call(o, w, 106, 436, 3, 4294967295, 4, 0, 0, 0, 0)
    if p == 106 or p == 107:
        if p == 106:
            put(w, 264, 0)
        else:
            put(w, 264, get(w, 264) + 1)
        if get(w, 264) < uint(s, 104):
            return call(o, w, 107, 72, uint(s, get(w, 256) + get(w, 264) * 8), 2, 0, 0, 0, 0, 0)
        return call(o, w, 108, 14, 2, 616, 0, 8, 0, 0, 12)
    if p == 108:
        put(w, 4096 + uint(s, 88) * 8 + uint(s, 96) * 8, 18446744073709551615)
        put(w, 0, 109)
        put(o, 0, 4096)
        put(o, 8, uint(s, 88) + uint(s, 96) + 1)
        put(o, 16, 5120)
        return 2
    if p == 109:
        i = 0
        while i < uint(s, 88):
            put(w, 6400 + i * 8, get(w, 5120 + i * 8))
            i = i + 1
        put(w, 6400 + i * 8, 0)
        i = 0
        while i <= uint(s, 96):
            put(w, 7040 + i * 8, get(w, 5120 + (uint(s, 88) + i) * 8))
            i = i + 1
        return call(o, w, 114, 322, uint(s, 40), C_EMPTY, 6400, 7040, 4096, 0, 252)
    return finish(o, w, 127)

def wait_leader(o:mutbuf, w:mutbuf) -> u32:
    clear(w, 640, 128)
    return call(o, w, 200, 247, 1, get(w, 40), 640, 16777221, 0, 0, 48)

def watching(s:readbuf, o:mutbuf, w:mutbuf, p:u64, r:u64) -> u32:
    if failed(r) and (p != 203 or r != 18446744073709551605) and r != 18446744073709551612:
        put(w, 88, p)
        return cleanup_start(o, w)
    if p == 200:
        return clock(o, w, 201)
    if p == 201:
        if time(w) >= uint(s, 24):
            put(w, 56, 1)
            return cleanup_start(o, w)
        pid = getn(w, 656, 4)
        if pid != 0:
            if pid != get(w, 40):
                put(w, 88, 201)
            else:
                put(w, 64, 1)
                event(w, 3, pid, getn(w, 648, 4), getn(w, 664, 4))
            return cleanup_start(o, w)
        put(w, 768, get(w, 240))
        put(w, 772, 1)
        return call(o, w, 202, 7, 768, 1, 10, 0, 0, 0, 3)
    if p == 202:
        return call(o, w, 203, 0, get(w, 240), 8192, 128, 0, 0, 0, 12)
    if p == 203:
        if r == 128:
            put(w, 96, getn(w, 8192, 4))
            return cleanup_start(o, w)
        if r != 18446744073709551605:
            put(w, 88, 203)
            return cleanup_start(o, w)
        return wait_leader(o, w)
    put(w, 88, p)
    return cleanup_start(o, w)

def cleanup_start(o:mutbuf, w:mutbuf) -> u32:
    return clock(o, w, 400)

def scan_start(o:mutbuf, w:mutbuf, mode:u64, resume:u64) -> u32:
    put(w, 232, mode)
    put(w, 248, resume)
    put(w, 128, 0)
    put(w, 176, 0)
    return call(o, w, 300, 8, get(w, 152), 0, 0, 0, 0, 0, 0)

def scanning(s:readbuf, o:mutbuf, w:mutbuf, p:u64, r:u64) -> u32:
    if p == 303 and (r == 18446744073709551614 or r == 18446744073709551613):
        return scan_next(s, o, w)
    if p == 304 and r == 18446744073709551613:
        # The held proc stat inode can lose its process after open succeeds.
        # Always close it, then re-open the same numeric path once. A live
        # replacement must pass the complete original parent/starttime checks.
        put(w, 272, r)
        return call(o, w, 305, 3, get(w, 184), 0, 0, 0, 0, 0, 0)
    if p == 308 and r == 18446744073709551613:
        clear(w, 640, 128)
        return call(o, w, 309, 247, 1, get(w, 192), 640, 16777221, 0, 0, 48)
    if failed(r):
        put(w, 88, p)
        return report_start(s, o, w)
    if p == 300:
        if r != 0:
            put(w, 88, 300)
            return report_start(s, o, w)
        return call(o, w, 301, 217, get(w, 152), 131072, 16384, 0, 0, 0, 12)
    if p == 301:
        if r == 0:
            return resume(o, w, get(w, 248))
        if r > 16384:
            put(w, 88, 301)
            return report_start(s, o, w)
        put(w, 160, 0)
        put(w, 168, r)
        return scan_next(s, o, w)
    if p == 303:
        put(w, 184, r)
        return call(o, w, 304, 0, r, 65536, 65537, 0, 0, 0, 12)
    if p == 304:
        put(w, 272, r)
        return call(o, w, 305, 3, get(w, 184), 0, 0, 0, 0, 0, 0)
    if p == 305:
        if get(w, 272) == 18446744073709551613:
            if get(w, 360) != 0:
                put(w, 88, 305)
                return report_start(s, o, w)
            put(w, 360, 1)
            return call(o, w, 303, 257, get(w, 152), 1024, 655360, 0, 0, 0, 12)
        if get(w, 272) == 0 or get(w, 272) > 65536 or parse_stat(w, get(w, 272)) == 0:
            put(w, 88, 305)
            return report_start(s, o, w)
        if get(w, 200) != get(w, 16):
            return scan_next(s, o, w)
        put(w, 128, get(w, 128) + 1)
        if get(w, 128) > 4096 or remember(w) == 0:
            put(w, 88, 306)
            return report_start(s, o, w)
        if get(w, 232) != 1:
            return scan_next(s, o, w)
        clear(w, 640, 128)
        return call(o, w, 307, 247, 1, get(w, 192), 640, 16777221, 0, 0, 48)
    if p == 307:
        pid = getn(w, 656, 4)
        if pid != 0 and pid != get(w, 192):
            put(w, 88, 307)
            return report_start(s, o, w)
        if pid != 0 or get(w, get(w, 280) + 40) & 1 == 1:
            return scan_next(s, o, w)
        return call(o, w, 308, 62, get(w, 192), 9, 0, 0, 0, 0, 0)
    if p == 308:
        put(w, get(w, 280) + 40, get(w, get(w, 280) + 40) | 1)
        event(w, 4, get(w, 192), get(w, 224), 9)
        return scan_next(s, o, w)
    if p == 309:
        if getn(w, 656, 4) != get(w, 192):
            put(w, 88, 309)
            return report_start(s, o, w)
        return scan_next(s, o, w)
    put(w, 88, p)
    return report_start(s, o, w)

def scan_next(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    at = get(w, 160)
    while at < get(w, 168):
        start = 131072 + at
        size = getn(w, start + 16, 2)
        if size < 20 or at + size > get(w, 168):
            put(w, 88, 310)
            return report_start(s, o, w)
        end = 19
        while end < size and byte(w, start + end) != 0:
            end = end + 1
        if end == size:
            put(w, 88, 311)
            return report_start(s, o, w)
        pid = digits(w, start + 19, end - 19)
        at = at + size
        put(w, 160, at)
        if pid > 0 and pid <= 2147483647:
            put(w, 176, get(w, 176) + 1)
            if get(w, 176) > 16384:
                put(w, 88, 312)
                return report_start(s, o, w)
            put(w, 192, pid)
            put(w, 360, 0)
            path(w, pid)
            return call(o, w, 303, 257, get(w, 152), 1024, 655360, 0, 0, 0, 12)
    return call(o, w, 301, 217, get(w, 152), 131072, 16384, 0, 0, 0, 12)

def parse_stat(w:mutbuf, n:u64) -> u64:
    at = 0
    while at < n and byte(w, 65536 + at) != 32:
        at = at + 1
    if at + 2 >= n or digits(w, 65536, at) != get(w, 192) or byte(w, 65537 + at) != 40:
        return 0
    end = n
    while end > at and byte(w, 65536 + end - 1) != 41:
        end = end - 1
    if end <= at or end + 2 >= n or byte(w, 65536 + end) != 32:
        return 0
    at = end + 1
    field = 0
    while field < 20:
        begin = at
        while at < n and byte(w, 65536 + at) != 32 and byte(w, 65536 + at) != 10:
            at = at + 1
        if at == begin:
            return 0
        if field == 1 or field == 2 or field == 3 or field == 19:
            value = digits(w, 65536 + begin, at - begin)
            if value == 18446744073709551615:
                return 0
            if field == 1:
                put(w, 200, value)
            if field == 2:
                put(w, 208, value)
            if field == 3:
                put(w, 216, value)
            if field == 19:
                put(w, 224, value)
        if at >= n and field < 19:
            return 0
        at = at + 1
        field = field + 1
    return 1

def remember(w:mutbuf) -> u64:
    i = 0
    while i < get(w, 120):
        at = 262144 + i * 48
        if get(w, at) == get(w, 192) and get(w, at + 8) == get(w, 224):
            put(w, 280, at)
            return 1
        i = i + 1
    if i >= 16384:
        return 0
    at = 262144 + i * 48
    put(w, at, get(w, 192))
    put(w, at + 8, get(w, 224))
    put(w, at + 16, get(w, 208))
    put(w, at + 24, get(w, 216))
    put(w, at + 32, get(w, 200))
    put(w, at + 40, 0)
    put(w, 120, i + 1)
    put(w, 280, at)
    event(w, 2, get(w, 192), get(w, 224), get(w, 208))
    return 1

def cleaning(s:readbuf, o:mutbuf, w:mutbuf, p:u64, r:u64) -> u32:
    if p == 403 and r == 18446744073709551606:
        put(w, 80, 1)
        return clock(o, w, 410)
    if failed(r):
        if r == 18446744073709551612:
            return clock(o, w, 401)
        put(w, 88, p)
        return report_start(s, o, w)
    if p == 400:
        put(w, 136, time(w))
        put(w, 144, time(w) + 3000000000)
        return clock(o, w, 401)
    if p == 401:
        if time(w) >= get(w, 144):
            put(w, 288, 1)
            return report_start(s, o, w)
        return scan_start(o, w, 1, 402)
    if p == 402:
        clear(w, 640, 128)
        return call(o, w, 403, 247, 0, 0, 640, 16777221, 0, 0, 48)
    if p == 403:
        pid = getn(w, 656, 4)
        if pid == 0:
            put(w, 768, get(w, 240))
            put(w, 772, 1)
            return call(o, w, 409, 7, 768, 1, 10, 0, 0, 0, 3)
        put(w, 192, pid)
        path(w, pid)
        return call(o, w, 404, 257, get(w, 152), 1024, 655360, 0, 0, 0, 12)
    if p == 404:
        put(w, 184, r)
        return call(o, w, 405, 0, r, 65536, 65537, 0, 0, 0, 12)
    if p == 405:
        put(w, 272, r)
        return call(o, w, 406, 3, get(w, 184), 0, 0, 0, 0, 0, 0)
    if p == 406:
        if get(w, 272) == 0 or get(w, 272) > 65536 or parse_stat(w, get(w, 272)) == 0 or get(w, 200) != get(w, 16) or remember(w) == 0:
            put(w, 88, 406)
            return report_start(s, o, w)
        return call(o, w, 407, 61, get(w, 192), 800, 1, 0, 0, 0, 12)
    if p == 407:
        if r != get(w, 192):
            put(w, 88, 407)
            return report_start(s, o, w)
        status = getn(w, 800, 4)
        code = choose(status & 127 == 0, (status >> 8) & 255, 0 - (status & 127))
        put(w, get(w, 280) + 40, get(w, get(w, 280) + 40) | 2)
        event(w, 5, r, get(w, 224), code)
        if r == get(w, 40):
            put(w, 48, code)
            put(w, 304, 1)
        return resume(o, w, 402)
    if p == 409:
        return clock(o, w, 401)
    if p == 410:
        if time(w) >= get(w, 144):
            put(w, 288, 1)
            return report_start(s, o, w)
        return scan_start(o, w, 2, 411)
    if p == 411:
        if get(w, 128) != 0:
            put(w, 88, 411)
        else:
            put(w, 72, 1)
        return report_start(s, o, w)
    put(w, 88, p)
    return report_start(s, o, w)

def report_start(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    return clock(o, w, 500)

def publish(s:readbuf, o:mutbuf, w:mutbuf, p:u64, r:u64) -> u32:
    if failed(r):
        return finish(o, w, 74)
    if p == 500:
        put(w, 312, time(w))
        status = 0
        if get(w, 48) != 0 or get(w, 64) != 1 or get(w, 304) != 1:
            status = 1
        if get(w, 56) != 0:
            status = 2
        if get(w, 96) != 0:
            status = 3
        if get(w, 88) != 0:
            status = 4
        if get(w, 72) != 1 or get(w, 80) != 1 or get(w, 288) != 0 or get(w, 112) != 0:
            status = 5
        put(w, 320, status)
        header(s, w)
        put(w, 328, 0)
        put(w, 336, 256)
        put(w, 344, 16384)
        put(w, 352, 0)
        return write_report(s, o, w)
    if p == 501:
        if r == 0 or r > get(w, 336) - get(w, 328):
            return finish(o, w, 74)
        put(w, 328, get(w, 328) + r)
        if get(w, 328) < get(w, 336):
            return write_report(s, o, w)
        if get(w, 352) == 0:
            put(w, 352, 1)
            put(w, 336, get(w, 120) * 48)
            put(w, 344, 262144)
            put(w, 328, 0)
            if get(w, 336) != 0:
                return write_report(s, o, w)
        if get(w, 352) == 1:
            put(w, 352, 2)
            put(w, 336, get(w, 104) * 40)
            put(w, 344, 1572864)
            put(w, 328, 0)
            if get(w, 336) != 0:
                return write_report(s, o, w)
        return call(o, w, 502, 74, uint(s, 72), 0, 0, 0, 0, 0, 0)
    if p == 502:
        return finish(o, w, choose(get(w, 320) == 0, 0, 1))
    return finish(o, w, 74)

def write_report(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    return call(o, w, 501, 1, uint(s, 72), get(w, 344) + get(w, 328), get(w, 336) - get(w, 328), 0, 0, 0, 12)

def header(s:readbuf, w:mutbuf) -> u64:
    clear(w, 16384, 256)
    put(w, 16384, MAGIC_RECEIPT)
    put(w, 16392, get(w, 320))
    put(w, 16400, get(w, 16))
    put(w, 16408, uint(s, 8))
    put(w, 16416, uint(s, 16))
    put(w, 16424, uint(s, 24))
    put(w, 16432, uint(s, 32))
    put(w, 16440, 3000000000)
    put(w, 16448, get(w, 40))
    put(w, 16456, get(w, 48))
    put(w, 16464, get(w, 56))
    put(w, 16472, get(w, 64))
    put(w, 16480, get(w, 72))
    put(w, 16488, get(w, 80))
    put(w, 16496, get(w, 88))
    put(w, 16504, get(w, 96))
    put(w, 16512, get(w, 104))
    put(w, 16520, get(w, 112))
    put(w, 16528, get(w, 120))
    put(w, 16536, get(w, 136))
    put(w, 16544, get(w, 144))
    put(w, 16552, get(w, 288))
    put(w, 16560, get(w, 304))
    put(w, 16568, get(w, 312))
    put(w, 16576, get(w, 128))
    put(w, 16584, 4096)
    put(w, 16592, 16384)
    put(w, 16600, 65536)
    put(w, 16608, 1)
    return 0

def event(w:mutbuf, kind:u64, pid:u64, a:u64, b:u64) -> u64:
    i = get(w, 104)
    if i >= 16384:
        put(w, 112, 1)
        return 0
    at = 1572864 + i * 40
    put(w, at, kind)
    put(w, at + 8, time(w))
    put(w, at + 16, pid)
    put(w, at + 24, a)
    put(w, at + 32, b)
    put(w, 104, i + 1)
    return 0

def path(w:mutbuf, pid:u64) -> u64:
    n = decimal(w, 1024, pid)
    store(w, 1024 + n, 47)
    put(w, 1025 + n, 1952543859)
    return 0

def decimal(w:mutbuf, at:u64, value:u64) -> u64:
    n = 0
    remaining = value
    while remaining > 0:
        q = divide(remaining, 10)
        store(w, 1200 + n, remaining - q * 10 + 48)
        n = n + 1
        remaining = q
    i = 0
    while i < n:
        store(w, at + i, byte(w, 1200 + n - i - 1))
        i = i + 1
    return n

def divide(a:u64, b:u64) -> u64:
    q = 0
    rem = 0
    bit = 64
    while bit > 0:
        bit = bit - 1
        rem = (rem << 1) | ((a >> bit) & 1)
        if rem >= b:
            rem = rem - b
            q = q | (1 << bit)
    return q

def digits(w:mutbuf, at:u64, n:u64) -> u64:
    if n == 0 or n > 20:
        return 18446744073709551615
    value = 0
    i = 0
    while i < n:
        c = byte(w, at + i)
        if c < 48 or c > 57 or value > 1844674407370955161 or (value == 1844674407370955161 and c > 53):
            return 18446744073709551615
        value = value * 10 + c - 48
        i = i + 1
    return value

def same_s(s:readbuf, a:u64, b:u64, n:u64) -> u64:
    i = 0
    while i < n:
        if byte(s, a + i) != byte(s, b + i):
            return 0
        i = i + 1
    return 1

def clear(w:mutbuf, at:u64, n:u64) -> u64:
    i = 0
    while i < n:
        store(w, at + i, 0)
        i = i + 1
    return 0

def clock(o:mutbuf, w:mutbuf, p:u64) -> u32:
    return call(o, w, p, 228, 1, 512, 0, 0, 0, 0, 12)

def time(w:mutbuf) -> u64:
    return get(w, 512) * 1000000000 + get(w, 520)

def resume(o:mutbuf, w:mutbuf, p:u64) -> u32:
    put(w, 0, p)
    put(w, 8, 0)
    return 4

def call(o:mutbuf, w:mutbuf, p:u64, number:u64, a:u64, b:u64, c:u64, d:u64, e:u64, f:u64, mask:u64) -> u32:
    put(w, 0, p)
    put(o, 0, number)
    put(o, 8, a)
    put(o, 16, b)
    put(o, 24, c)
    put(o, 32, d)
    put(o, 40, e)
    put(o, 48, f)
    put(o, 56, mask)
    return 1

def finish(o:mutbuf, w:mutbuf, code:u64) -> u32:
    return call(o, w, 999, 60, code, 0, 0, 0, 0, 0, 0)

def failed(value:u64) -> bool:
    return value >= 18446744073709547521

def uint(s:readbuf, at:u64) -> u64:
    v = 0
    i = 0
    while i < 8:
        v = v | (byte(s, at + i) << (i * 8))
        i = i + 1
    return v

def get(w:mutbuf, at:u64) -> u64:
    return getn(w, at, 8)

def getn(w:mutbuf, at:u64, n:u64) -> u64:
    v = 0
    i = 0
    while i < n:
        v = v | (byte(w, at + i) << (i * 8))
        i = i + 1
    return v

def put(w:mutbuf, at:u64, value:u64) -> u64:
    i = 0
    while i < 8:
        store(w, at + i, (value >> (i * 8)) & 255)
        i = i + 1
    return 0
'''


def policy_source():
    values = {'MAGIC_REQUEST': int.from_bytes(b'HIACOW01', 'little'),
              'MAGIC_RECEIPT': int.from_bytes(b'HIACOR01', 'little'),
              'C_PROC': 18000, 'C_EMPTY': 18016}
    text = SOURCE
    for key, value in values.items():
        text = re.sub(r'\b' + key + r'\b', str(value), text)
    text += '\ndef constants(w:mutbuf) -> u64:\n    put(w, 18000, 427071533103)\n    put(w, 18016, 0)\n    return 0\n'
    return text


def template():
    adapter = ROOT / 'tools/hia_cold_replay_owner_syscalls.S'
    with tempfile.TemporaryDirectory(prefix='hia-cold-owner-author-') as tmp:
        obj, raw = Path(tmp) / 'a.o', Path(tmp) / 'a.bin'
        subprocess.run(['as', '--64', str(adapter), '-o', str(obj)], check=True, capture_output=True)
        subprocess.run(['objcopy', '-O', 'binary', '-j', '.text', str(obj), str(raw)], check=True, capture_output=True)
        symbols = {name: int(addr, 16) for addr, _, name in
                   (line.split() for line in subprocess.check_output(['nm', '-n', str(obj)], text=True).splitlines())}
        if symbols['_start'] != 0 or 'R_X86_64' in subprocess.check_output(['objdump', '-r', str(obj)], text=True):
            raise ValueError('unresolved cold owner capsule relocation')
        code = raw.read_bytes()
    header = (b'\x7fELF\x02\x01\x01' + bytes(9)
              + struct.pack('<HHIQQQIHHHHHH', 2, 62, 1, 0x4000b0, 64, 0, 0, 64, 56, 2, 0, 0, 0)
              + struct.pack('<IIQQQQQQ', 1, 5, 0, 0x400000, 0x400000, 0, 0, 4096)
              + struct.pack('<IIQQQQQQ', 0x6474e551, 6, 0, 0, 0, 0, 0, 16))
    return header + code, 176 + symbols['policy_hole']


def packer_source():
    prefix, hole = template()
    text = f'''def pack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 17 or uint(s, 0, 8) != {int.from_bytes(b'HIACOP01', 'little')}:
        return 4294967295
    n = uint(s, 8, 8)
    if n == 0 or n > 1048576 or length(s) != 16 + n:
        return 4294967295
    size = {len(prefix)} + n
    if size > 1048576 or length(o) < size:
        return 4294967294
'''
    for at in range(0, len(prefix), 8):
        chunk = prefix[at:at + 8]
        text += f'    write(o, {at}, {int.from_bytes(chunk, "little")}, {len(chunk)})\n'
    text += f'''    write(o, 96, size, 8)
    write(o, 104, size, 8)
    write(o, {hole}, {len(prefix) - hole - 4}, 4)
    copy_bytes(s, o, 16, {len(prefix)}, n)
    return size
'''
    return text + LINK_SOURCE[LINK_SOURCE.index('\ndef uint('):]


def main():
    for name, text in (('cold_replay_owner', policy_source()), ('cold_replay_owner_packer', packer_source())):
        path = ROOT / 'examples/hia_bootstrap' / (name + '.hepta')
        path.write_text(render_assembly(document(text, name)))
        print(path.name, path.stat().st_size)


if __name__ == '__main__':
    main()
