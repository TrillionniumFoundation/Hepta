"""Author the native HTTP/1 request-head projection.

The installed implementation is the emitted HIA source. This development
author does not participate in HTTP request handling.
"""
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_mcp_service import document

SOURCE = r'''
def parse(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(o) < 3328 or length(w) < 4096:
        return 4294967293
    size = length(s)
    at = 0
    while at < size and (byte(s, at) == 10 or byte(s, at) == 13):
        if byte(s, at) == 10:
            at = at + 1
        else:
            if at + 1 >= size:
                return 0
            if byte(s, at + 1) != 10:
                return 4294967295
            at = at + 2
    if at >= size:
        return pending(size)
    method = at
    while at < size and token(byte(s, at)):
        at = at + 1
    if at >= size:
        return pending(size)
    if at == method or byte(s, at) != 32:
        return 4294967295
    method_size = at - method
    at = at + 1
    target = at
    while at < size and byte(s, at) != 32:
        ch = byte(s, at)
        if ch < 33 or ch == 127:
            return 4294967295
        at = at + 1
    if at >= size:
        return pending(size)
    if at == target:
        return 4294967295
    target_size = at - target
    if utf8(s, target, at) == False:
        return 4294967295
    at = at + 1
    if size - at < 8:
        index = 0
        while index < size - at:
            wanted = version_byte(index)
            if index == 7:
                if byte(s, at + index) != 48 and byte(s, at + index) != 49:
                    return 4294967295
            elif byte(s, at + index) != wanted:
                return 4294967295
            index = index + 1
        return pending(size)
    if word_load(s, at) != 3543824036068086856 and word_load(s, at) != 3471766442030158920:
        return 4294967295
    minor = byte(s, at + 7) - 48
    at = at + 8
    next = newline(s, at)
    if next == 0:
        return pending(size)
    if next == 18446744073709551615:
        return 4294967295
    at = next
    count = 0
    while at < size:
        if byte(s, at) == 10 or byte(s, at) == 13:
            next = newline(s, at)
            if next == 0:
                return pending(size)
            if next == 18446744073709551615:
                return 4294967295
            if next > 417792:
                return 4294967294
            word_store(w, 0, 3549236739585292616)
            word_store(w, 8, next)
            word_store(w, 16, method)
            word_store(w, 24, method_size)
            word_store(w, 32, target)
            word_store(w, 40, target_size)
            word_store(w, 48, minor)
            word_store(w, 56, count)
            index = 64
            while index < 128:
                word_store(w, index, 0)
                index = index + 8
            index = 0
            total = 128 + count * 32
            while index < total:
                word_store(o, index, word_load(w, index))
                index = index + 8
            return total
        if count == 100:
            return 4294967294
        name = at
        while at < size and token(byte(s, at)):
            at = at + 1
        if at >= size:
            return pending(size)
        if at == name or byte(s, at) != 58:
            return 4294967295
        name_size = at - name
        at = at + 1
        while at < size and (byte(s, at) == 32 or byte(s, at) == 9):
            at = at + 1
        value = at
        while at < size and byte(s, at) != 13 and byte(s, at) != 10:
            ch = byte(s, at)
            if (ch < 32 and ch != 9) or ch == 127:
                return 4294967295
            at = at + 1
        if at >= size:
            return pending(size)
        end = at
        while end > value and (byte(s, end - 1) == 32 or byte(s, end - 1) == 9):
            end = end - 1
        next = newline(s, at)
        if next == 0:
            return pending(size)
        if next == 18446744073709551615:
            return 4294967295
        row = 128 + count * 32
        word_store(w, row, name)
        word_store(w, row + 8, name_size)
        word_store(w, row + 16, value)
        word_store(w, row + 24, end - value)
        at = next
        count = count + 1
    return pending(size)

def pending(size:u64) -> u32:
    if size >= 417792:
        return 4294967294
    return 0

def newline(s:readbuf, at:u64) -> u64:
    if at >= length(s):
        return 0
    ch = byte(s, at)
    if ch == 10:
        return at + 1
    if ch != 13:
        return 18446744073709551615
    if at + 1 >= length(s):
        return 0
    if byte(s, at + 1) != 10:
        return 18446744073709551615
    return at + 2

def version_byte(index:u64) -> u64:
    if index == 0:
        return 72
    if index == 1 or index == 2:
        return 84
    if index == 3:
        return 80
    if index == 4:
        return 47
    if index == 5:
        return 49
    if index == 6:
        return 46
    return 0

def utf8(s:readbuf, at:u64, end:u64) -> bool:
    while at < end:
        ch = byte(s, at)
        if ch < 128:
            at = at + 1
        else:
            count = 0
            low = 128
            high = 191
            if ch >= 194 and ch <= 223:
                count = 2
            elif ch >= 224 and ch <= 239:
                count = 3
                if ch == 224:
                    low = 160
                if ch == 237:
                    high = 159
            elif ch >= 240 and ch <= 244:
                count = 4
                if ch == 240:
                    low = 144
                if ch == 244:
                    high = 143
            else:
                return False
            if count > end - at or byte(s, at + 1) < low or byte(s, at + 1) > high:
                return False
            index = 2
            while index < count:
                if byte(s, at + index) < 128 or byte(s, at + index) > 191:
                    return False
                index = index + 1
            at = at + count
    return True

def token(ch:u64) -> bool:
    if ch >= 48 and ch <= 57:
        return True
    if ch >= 65 and ch <= 90:
        return True
    if ch >= 97 and ch <= 122:
        return True
    return ch == 33 or ch == 35 or ch == 36 or ch == 37 or ch == 38 or ch == 39 or ch == 42 or ch == 43 or ch == 45 or ch == 46 or ch == 94 or ch == 95 or ch == 96 or ch == 124 or ch == 126
'''

def render():
    source = SOURCE.replace('3543824036068086856', str(int.from_bytes(b'HTTP/1.1', 'little'))).replace('3471766442030158920', str(int.from_bytes(b'HTTP/1.0','little'))).replace('3549236739585292616',str(int.from_bytes(b'HIAHHR01','little')))
    return render_assembly(document(source, 'mcp_http_headers'))

if __name__ == '__main__':
    path = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap/mcp_http_headers.hepta'
    rendered = render()
    path.write_text(rendered)
    print(path.name, len(rendered.encode()))
