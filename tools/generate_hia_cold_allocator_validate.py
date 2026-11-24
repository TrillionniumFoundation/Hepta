"""Author the complete allocator event replay and original contract gate in HIA."""
from pathlib import Path
from hashlib import sha256
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_cold_allocator_witness import document
ROOT=Path(__file__).resolve().parents[1]
SOURCE=r'''
def validate(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) != 1048792 or length(w) < 1048576:
        return 4294967293
    if word_load(s, 0) != @MAGIC@ or word_load(s, 8) != 1048712:
        return 4294967295
    if word_load(s, 56) > 1 or word_load(s, 64) > 2 or word_load(s, 40) > 10000 or word_load(s, 48) > 1:
        return 4294967295
    if word_load(s, 72) != word_load(s, 80):
        return 4294967295
    stats = 88
    if word_load(s, stats + 120) != 5208766201261541710 or word_load(s, stats + 104) > 32768:
        return 4294967295
    if word_load(s, stats) != word_load(s, 16) or word_load(s, stats + 32) != word_load(s, 24) or word_load(s, stats + 40) != word_load(s, 32):
        return 4294967295
    if word_load(s, stats + 24) != word_load(s, 48) or word_load(s, stats + 112) != word_load(s, 40):
        return 4294967295
    if word_load(s, stats + 72) != 0 or word_load(s, stats + 80) != 0 or word_load(s, stats + 88) != 0 or word_load(s, stats + 96) != 0:
        return 4294967295
    if word_load(s, 40) == 0:
        if word_load(s, 48) != 0 or word_load(s, 64) != 0:
            return 4294967295
    elif word_load(s, 48) != 1 or word_load(s, 64) == 0:
        return 4294967295
    i = 0
    while i < 524560:
        store(w, i, 0)
        i = i + 1
    i = 0
    while i < word_load(s, stats + 104):
        if event(s, w, 216 + i * 32) == 0:
            return 4294967295
        i = i + 1
    i = 0
    while i < 9:
        if word_load(s, stats + i * 8) != word_load(w, i * 8):
            return 4294967295
        i = i + 1
    if word_load(s, 56) == 1 and (word_load(w, 48) != 0 or word_load(w, 56) != 0):
        return 4294967295
    if length(o) < 136:
        return 4294967294
    i = 0
    while i < 136:
        store(o, i, byte(s, 80 + i))
        i = i + 1
    return 136

def event(s:readbuf, w:mutbuf, at:u64) -> u64:
    kind = word_load(s, at)
    size = word_load(s, at + 8)
    identity = word_load(s, at + 16)
    success = word_load(s, at + 24)
    if kind == 0 or kind > 3 or success > 1 or identity > 32768:
        return 0
    if kind == 1 or kind == 2:
        put(w, 0, word_load(w, 0) + 1)
        put(w, kind * 8, word_load(w, kind * 8) + 1)
        if size == 0:
            return 0
        if success == 0:
            if identity != 0 or word_load(w, 0) != word_load(s, 40) or kind != word_load(s, 64):
                return 0
            put(w, 24, word_load(w, 24) + 1)
            return 1
        if identity == 0 or word_load(w, 256 + identity * 16) != 0 or size > 18446744073709551615 - word_load(w, 56):
            return 0
        put(w, 256 + identity * 16, 3)
        put(w, 264 + identity * 16, size)
        put(w, 32, word_load(w, 32) + 1)
        put(w, 48, word_load(w, 48) + 1)
        put(w, 56, word_load(w, 56) + size)
        if word_load(w, 56) > word_load(w, 64):
            put(w, 64, word_load(w, 56))
        return 1
    if success != 1 or identity == 0 or word_load(w, 256 + identity * 16) != 3 or word_load(w, 264 + identity * 16) != size:
        return 0
    put(w, 256 + identity * 16, 1)
    put(w, 40, word_load(w, 40) + 1)
    put(w, 48, word_load(w, 48) - 1)
    put(w, 56, word_load(w, 56) - size)
    return 1

def put(o:mutbuf, at:u64, value:u64) -> u64:
    i = 0
    while i < 8:
        store(o, at + i, (value >> (i * 8)) & 255)
        i = i + 1
    return 0
'''.replace('@MAGIC@',str(int.from_bytes(b'HIACAV01','little')))
def main():
 d=document(SOURCE,module='cold_allocator_validate');out=render_assembly(d).encode();(ROOT/'examples/hia_bootstrap/cold_allocator_validate.hepta').write_bytes(out);print('ALLOCATOR_VALIDATE',len(out),len(d['functions']),sum(len(f['blocks']) for f in d['functions']),sum(len(b['ops']) for f in d['functions'] for b in f['blocks']),sha256(out).hexdigest())
if __name__=='__main__':main()
