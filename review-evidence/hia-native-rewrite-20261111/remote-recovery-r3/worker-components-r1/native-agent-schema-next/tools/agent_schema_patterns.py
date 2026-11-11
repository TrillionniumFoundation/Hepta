"""Exact re.search decisions for every pattern in the fixed tool/schema inventory.

This new component is not a general regular-expression engine or the complete
schema validator. The complete validator must derive the pattern bytes from
the admitted schema itself; no host may select a pattern ID for it.
"""
PATTERNS = [
  "^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,191}$",
  "^[0-9a-f]{64}$",
  "^hia://artifacts/[A-Za-z0-9][A-Za-z0-9._~-]{0,191}$",
  "^(0|[1-9][0-9]{0,19})$",
  "^(?:[0-9a-f]{2})*$"
]
CONSTANTS = dict(COMMAND=int.from_bytes(b'HIARXC01','little'),
                EVENT=int.from_bytes(b'HIARXR01','little'),BAD=0xfffffffd)
BODY = r'''
def pattern(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 64 or length(o) < 64:
        return BAD
    if word(s, 0) != COMMAND or word(s, 8) == 0 or word(s, 16) == 0:
        return BAD
    pbytes = word(s, 24)
    vbytes = word(s, 32)
    if word(s, 40) != length(s) or word(s, 48) != 0 or word(s, 56) != 0:
        return BAD
    if pbytes > length(s) - 64:
        return BAD
    start = 64 + pbytes
    if vbytes != length(s) - start:
        return BAD
    kind = known_pattern(s, pbytes)
    if kind == 0:
        return BAD
    result = anchored_match(s, start, vbytes, kind)
    put(o, 0, EVENT)
    put(o, 8, word(s, 8))
    put(o, 16, word(s, 16))
    put(o, 24, result)
    put(o, 32, kind)
    put(o, 40, vbytes)
    put(o, 48, 0)
    put(o, 56, 0)
    return 64

def same_pattern(s:readbuf, size:u64, kind:u64, expected:u64) -> u64:
    if size != expected:
        return 0
    i = 0
    while i < size:
        if byte(s, 64 + i) != pattern_unit(kind, i):
            return 0
        i = i + 1
    return 1

def anchored_match(s:readbuf, start:u64, size:u64, kind:u64) -> u64:
    n = size
    if n != 0:
        if byte(s, start + n - 1) == 10:
            n = n - 1
    if kind == 1:
        if n == 0 or n > 192:
            return 0
        if alnum(byte(s, start)) == 0:
            return 0
        i = 1
        while i < n:
            ch = byte(s, start + i)
            if alnum(ch) == 0 and ch != 95 and ch != 46 and ch != 58 and ch != 47 and ch != 45:
                return 0
            i = i + 1
        return 1
    if kind == 2:
        if n != 64:
            return 0
        i = 0
        while i < n:
            if lower_hex(byte(s, start + i)) == 0:
                return 0
            i = i + 1
        return 1
    if kind == 3:
        if n < 17 or n > 208:
            return 0
        i = 0
        while i < 16:
            if byte(s, start + i) != uri_prefix(i):
                return 0
            i = i + 1
        if alnum(byte(s, start + 16)) == 0:
            return 0
        i = 17
        while i < n:
            ch = byte(s, start + i)
            if alnum(ch) == 0 and ch != 46 and ch != 95 and ch != 126 and ch != 45:
                return 0
            i = i + 1
        return 1
    if kind == 4:
        if n == 0 or n > 20:
            return 0
        first = byte(s, start)
        if first == 48:
            return choose(n == 1, 1, 0)
        if first < 49 or first > 57:
            return 0
        i = 1
        while i < n:
            ch = byte(s, start + i)
            if ch < 48 or ch > 57:
                return 0
            i = i + 1
        return 1
    if kind == 5:
        if (n & 1) != 0:
            return 0
        i = 0
        while i < n:
            if lower_hex(byte(s, start + i)) == 0:
                return 0
            i = i + 1
        return 1
    return 0

def alnum(ch:u64) -> u64:
    if (ch >= 65 and ch <= 90) or (ch >= 97 and ch <= 122) or (ch >= 48 and ch <= 57):
        return 1
    return 0

def lower_hex(ch:u64) -> u64:
    if (ch >= 48 and ch <= 57) or (ch >= 97 and ch <= 102):
        return 1
    return 0

def word(s:readbuf, at:u64) -> u64:
    result = 0
    i = 0
    while i < 8:
        result = result | (byte(s, at + i) << (i * 8))
        i = i + 1
    return result

def put(o:mutbuf, at:u64, value:u64) -> u64:
    i = 0
    while i < 8:
        store(o, at + i, (value >> (i * 8)) & 255)
        i = i + 1
    return value
'''
