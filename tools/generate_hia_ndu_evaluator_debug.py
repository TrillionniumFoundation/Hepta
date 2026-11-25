"""HIA UTF-8 Rust-Debug string presentation for the pinned NDU oracle.
The complete Unicode escape property is explicit, finite semantic data; all
1,112,064 scalar values are independently compared to the reference formatter.
"""
from pathlib import Path
import struct
from tools.generate_hia_ndu_evaluator import document
from hepta.hia_agent_assembly import render_assembly
ROOT=Path(__file__).resolve().parents[1]
ENTRY=r'''
def ndu_debug(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) > 1048576 or length(o) < 8388608 or length(w) < 16384:
        return 4294967293
    ranges(w)
    store(o, 0, 34)
    out = 1
    at = 0
    while at < length(s):
        value = point(s, at)
        if value == 18446744073709551615:
            return 4294967295
        next = value >> 32
        cp = value & 4294967295
        special = 0
        if cp == 0:
            special = 48
        if cp == 9:
            special = 116
        if cp == 10:
            special = 110
        if cp == 13:
            special = 114
        if cp == 34 or cp == 92:
            special = cp
        if special != 0:
            store(o, out, 92)
            store(o, out + 1, special)
            out = out + 2
        else:
            if escaped(w, cp) == 1:
                store(o, out, 92)
                store(o, out + 1, 117)
                store(o, out + 2, 123)
                out = out + 3
                shift = 20
                while shift > 0 and (cp >> shift) == 0:
                    shift = shift - 4
                going = True
                while going:
                    digit = (cp >> shift) & 15
                    store(o, out, choose(digit < 10, digit + 48, digit + 87))
                    out = out + 1
                    if shift == 0:
                        going = False
                    else:
                        shift = shift - 4
                store(o, out, 125)
                out = out + 1
            else:
                i = at
                while i < next:
                    store(o, out, byte(s, i))
                    out = out + 1
                    i = i + 1
        at = next
    store(o, out, 34)
    return out + 1

def escaped(w:mutbuf, value:u64) -> u64:
    lo = 0
    hi = RANGE_COUNT
    while lo < hi:
        mid = (lo + hi) >> 1
        pair = word_load(w, mid * 8)
        start = pair & 4294967295
        end = pair >> 32
        if value < start:
            hi = mid
        else:
            if value >= end:
                lo = mid + 1
            else:
                return 1
    return 0

def point(s:readbuf, at:u64) -> u64:
    if at >= length(s):
        return 18446744073709551615
    ch = byte(s, at)
    if ch < 128:
        return ((at + 1) << 32) | ch
    count = 0
    low = 128
    high = 191
    value = 0
    if ch >= 194 and ch <= 223:
        count = 2
        value = ch & 31
    if ch >= 224 and ch <= 239:
        count = 3
        value = ch & 15
        if ch == 224:
            low = 160
        if ch == 237:
            high = 159
    if ch >= 240 and ch <= 244:
        count = 4
        value = ch & 7
        if ch == 240:
            low = 144
        if ch == 244:
            high = 143
    if count == 0 or count > length(s) - at:
        return 18446744073709551615
    first = byte(s, at + 1)
    if first < low or first > high:
        return 18446744073709551615
    value = (value << 6) | (first & 63)
    i = 2
    while i < count:
        ch = byte(s, at + i)
        if ch < 128 or ch > 191:
            return 18446744073709551615
        value = (value << 6) | (ch & 63)
        i = i + 1
    return ((at + count) << 32) | value
'''
def program():
    raw=(ROOT/'examples/hia_bootstrap/ndu_evaluator_unicode.hiadat').read_bytes()
    assert raw[:8]==b'HIANDU01'
    count=struct.unpack_from('<Q',raw,8)[0];assert len(raw)==16+8*count and count<=2048
    values=struct.unpack_from('<'+'Q'*count,raw,16)
    pieces=[]
    for g in range((count+31)//32):
        lines=[f'def ranges_{g}(w:mutbuf) -> u64:']
        for i in range(g*32,min(count,(g+1)*32)):lines.append(f'    word_store(w, {i*8}, {values[i]})')
        lines+=['    return 0'];pieces.append('\n'.join(lines))
    lines=['def ranges(w:mutbuf) -> u64:']
    for g in range((count+31)//32):lines.append(f'    ranges_{g}(w)')
    lines+=['    return 0']
    return ENTRY.replace('RANGE_COUNT',str(count))+'\n\n'+'\n\n'.join(['\n'.join(lines),*pieces])
def render():return render_assembly(document(program(),'ndu_evaluator_debug'))
if __name__=='__main__':
    p=ROOT/'examples/hia_bootstrap/ndu_evaluator_debug.hepta';p.write_text(render());print(p.name,p.stat().st_size)
