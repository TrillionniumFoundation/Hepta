"""Pure native SocketAddr parser retaining the original loopback predicate."""
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_mcp_service import document

POLICY = r"""
def parse(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) == 0 or length(s) > 4096 or length(o) < 128 or length(w) < 128:
        return 4294967293
    index = 0
    while index < 128:
        store(w, index, 0)
        index = index + 1
    status = 0
    if byte(s, 0) != 91:
        status = parse4(s, w)
    else:
        status = parse6(s, w)
    if status != 128:
        return status
    word_store(w, 0, MAGIC)
    index = 0
    while index < 128:
        word_store(o, index, word_load(w, index))
        index = index + 8
    return 128

def parse4(s:readbuf, w:mutbuf) -> u64:
    end = find(s, 0, length(s), 58)
    address = ipv4(s, 0, end)
    if address == NONE or address >> 32 != end or end == length(s):
        return 4294967295
    port = decimal(s, end + 1, length(s), 65535)
    if port == NONE:
        return 4294967295
    store(w, 64, 2)
    store(w, 66, port >> 8)
    store(w, 67, port)
    index = 0
    while index < 4:
        store(w, 68 + index, address >> (24 - index * 8))
        index = index + 1
    word_store(w, 8, 2)
    word_store(w, 16, 16)
    word_store(w, 24, choose(((address >> 24) & 255) == 127, 1, 0))
    return 128

def parse6(s:readbuf, w:mutbuf) -> u64:
    end = find(s, 1, length(s), 93)
    if end == length(s) or end + 1 >= length(s) or byte(s, end + 1) != 58:
        return 4294967295
    stop = find(s, 1, end, 37)
    scope = 0
    if stop != end:
        scope = decimal(s, stop + 1, end, 4294967295)
        if scope == NONE:
            return 4294967295
    if ipv6(s, w, 1, stop) == False:
        return 4294967295
    port = decimal(s, end + 2, length(s), 65535)
    if port == NONE:
        return 4294967295
    store(w, 64, 10)
    store(w, 66, port >> 8)
    store(w, 67, port)
    index = 0
    bits = 0
    while index < 16:
        value = byte(w, 96 + index)
        store(w, 72 + index, value)
        if index < 15:
            bits = bits | value
        index = index + 1
    word_store(w, 88, scope)
    word_store(w, 8, 10)
    word_store(w, 16, 28)
    is_loopback = bits == 0 and byte(w, 87) == 1
    loopback = choose(is_loopback, 1, 0)
    word_store(w, 24, loopback)
    word_store(w, 96, 0)
    word_store(w, 104, 0)
    return 128

def find(s:readbuf, at:u64, end:u64, ch:u64) -> u64:
    while at < end and byte(s, at) != ch:
        at = at + 1
    return at

def decimal(s:readbuf, at:u64, end:u64, maximum:u64) -> u64:
    if at == end:
        return NONE
    value = 0
    while at < end:
        ch = byte(s, at)
        if ch < 48 or ch > 57:
            return NONE
        digit = ch - 48
        if value > maximum // 10 or value * 10 + digit > maximum:
            return NONE
        value = value * 10 + digit
        at = at + 1
    return value

def ipv4(s:readbuf, at:u64, end:u64) -> u64:
    value = 0
    index = 0
    while index < 4:
        start = at
        if index != 0:
            if at == end or byte(s, at) != 46:
                return NONE
            at = at + 1
            start = at
        part = 0
        while at < end and byte(s, at) >= 48 and byte(s, at) <= 57:
            part = part * 10 + byte(s, at) - 48
            at = at + 1
            if at - start > 3 or part > 255:
                return NONE
        if at == start or (at - start > 1 and byte(s, start) == 48):
            return NONE
        value = (value << 8) | part
        index = index + 1
    return (at << 32) | value

def digit(ch:u64) -> u64:
    if ch >= 48 and ch <= 57:
        return ch - 48
    if ch >= 65 and ch <= 70:
        return ch - 55
    if ch >= 97 and ch <= 102:
        return ch - 87
    return NONE

def groups(s:readbuf, w:mutbuf, at:u64, end:u64, maximum:u64, base:u64) -> u64:
    count = 0
    while count < maximum:
        next = at
        if count != 0:
            if next == end or byte(s, next) != 58:
                return (at << 32) | (count << 1)
            next = next + 1
        if count + 1 < maximum:
            address = ipv4(s, next, end)
            if address != NONE:
                value = address & 4294967295
                index = 0
                while index < 4:
                    store(w, base + count * 2 + index, value >> (24 - index * 8))
                    index = index + 1
                return (address & 18446744069414584320) | ((count + 2) << 1) | 1
        first = next
        value = 0
        while next < end and digit(byte(s, next)) != NONE:
            value = value * 16 + digit(byte(s, next))
            next = next + 1
            if next - first > 4:
                return (at << 32) | (count << 1)
        if first == next:
            return (at << 32) | (count << 1)
        store(w, base + count * 2, value >> 8)
        store(w, base + count * 2 + 1, value)
        at = next
        count = count + 1
    return (at << 32) | (count << 1)

def ipv6(s:readbuf, w:mutbuf, at:u64, end:u64) -> bool:
    first = groups(s, w, at, end, 8, 96)
    head = (first >> 1) & 255
    at = first >> 32
    if head == 8:
        return at == end
    if first & 1 != 0 or at + 2 > end or byte(s, at) != 58 or byte(s, at + 1) != 58:
        return False
    tail = groups(s, w, at + 2, end, 7 - head, 32)
    count = (tail >> 1) & 255
    if tail >> 32 != end:
        return False
    index = 0
    while index < count * 2:
        store(w, 112 - count * 2 + index, byte(w, 32 + index))
        index = index + 1
    index = 32
    while index < 64:
        store(w, index, 0)
        index = index + 1
    return True
"""

def source():
    return POLICY.replace('NONE', str((1<<64)-1)).replace('MAGIC',str(int.from_bytes(b'HIAHBD01','little')))

def render():
    return render_assembly(document(source(),'mcp_http_bind'))

if __name__=='__main__':
    root=Path(__file__).resolve().parents[1]
    value=render()
    (root/'examples/hia_bootstrap/mcp_http_bind.hepta').write_text(value)
    print('mcp_http_bind.hepta',len(value.encode()))
