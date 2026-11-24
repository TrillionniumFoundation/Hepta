"""Author the native captured-manifest to source-pin-inventory converter.

This owner validates the source-manifest representation and preserves all pins.
Physical source capture, file-size checks and hashing belong to the upstream
native capture owner; this pure byte transform does not reopen filesystem paths.
"""
from pathlib import Path
from hashlib import sha256
import json
from tools.generate_hia_cold_document import document
from hepta.hia_agent_assembly import render_assembly
ROOT=Path(__file__).resolve().parents[1]
SOURCE='examples/hia_bootstrap/source_contract_manifest.hepta'
PROGRAM=r'''
def manifest(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 32 or length(s) > 8388608:
        return 4294967295
    if word_load(s, 0) != MANIFEST or word_load(s, 16) != 1 or word_load(s, 24) != 0:
        return 4294967295
    count = word_load(s, 8)
    if count == 0 or count > 4096:
        return 4294967295
    at = 32
    index = 0
    needed = 16
    previous = 0
    previous_size = 0
    while index < count:
        if at > length(s) or length(s) - at < 48:
            return 4294967295
        size = word_load(s, at)
        file_size = word_load(s, at + 8)
        if size == 0 or size > 4095 or file_size > 67108864 or size > length(s) - at - 48:
            return 4294967295
        name = at + 48
        if relative(s, name, size) == 0:
            return 4294967295
        pin = word_load(s, at + 16) | word_load(s, at + 24) | word_load(s, at + 32) | word_load(s, at + 40)
        if pin == 0:
            return 4294967295
        if index != 0 and order(s, previous, previous_size, name, size) != 1:
            return 4294967295
        if needed > 8388608 or 40 + size > 8388608 - needed:
            return 4294967294
        needed = needed + 40 + size
        previous = name
        previous_size = size
        at = name + size
        index = index + 1
    if at != length(s):
        return 4294967295
    if needed > length(o):
        return 4294967294
    put(o, 0, INVENTORY)
    put(o, 8, count)
    at = 32
    out = 16
    index = 0
    while index < count:
        size = word_load(s, at)
        put(o, out, size)
        copy(s, o, out + 8, at + 16, 32)
        copy(s, o, out + 40, at + 48, size)
        out = out + 40 + size
        at = at + 48 + size
        index = index + 1
    return out

def relative(s:readbuf, at:u64, size:u64) -> u64:
    index = 0
    start = 0
    while index < size:
        ch = byte(s, at + index)
        if ch == 47:
            if segment(s, at + start, index - start) == 0:
                return 0
            start = index + 1
        else:
            if (ch < 48 or ch > 57) and (ch < 65 or ch > 90) and (ch < 97 or ch > 122) and ch != 45 and ch != 46 and ch != 95:
                return 0
        index = index + 1
    return segment(s, at + start, size - start)

def segment(s:readbuf, at:u64, size:u64) -> u64:
    if size == 0 or size > 255:
        return 0
    if size == 1 and byte(s, at) == 46:
        return 0
    if size == 2 and byte(s, at) == 46 and byte(s, at + 1) == 46:
        return 0
    if size == 4 and byte(s, at) == 46 and byte(s, at + 1) == 103 and byte(s, at + 2) == 105 and byte(s, at + 3) == 116:
        return 0
    if size == 11 and word_load(s, at) == 7521962882505924447 and byte(s, at + 8) == 101 and byte(s, at + 9) == 95 and byte(s, at + 10) == 95:
        return 0
    return 1

def order(s:readbuf, a:u64, an:u64, b:u64, bn:u64) -> u64:
    i = 0
    while i < an and i < bn:
        left = byte(s, a + i)
        right = byte(s, b + i)
        if left != right:
            return choose(left < right, 1, 2)
        i = i + 1
    return choose(an == bn, 0, choose(an < bn, 1, 2))

def copy(s:readbuf, o:mutbuf, to:u64, at:u64, size:u64) -> u64:
    i = 0
    while i < size:
        store(o, to + i, byte(s, at + i))
        i = i + 1
    return 0

def put(o:mutbuf, at:u64, value:u64) -> u64:
    i = 0
    while i < 8:
        store(o, at + i, (value >> (i * 8)) & 255)
        i = i + 1
    return 0
'''.replace('MANIFEST',str(int.from_bytes(b'HIASXM01','little'))).replace('INVENTORY',str(int.from_bytes(b'HIASPI01','little')))

def main():
    d=document(PROGRAM,'source_contract_manifest')
    raw=render_assembly(d).encode()
    p=ROOT/SOURCE;p.write_bytes(raw)
    print(json.dumps({'path':SOURCE,'sha256':sha256(raw).hexdigest(),'bytes':len(raw),'functions':len(d['functions']),'blocks':sum(len(f['blocks']) for f in d['functions'])}))
if __name__=='__main__':main()
