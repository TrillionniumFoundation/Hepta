"""Author bounded SHA-256 as executable HIA, not a foreign hash call.

The generator is development-time authoring. Native payload hashing contains
padding, scheduling, compression and big-endian digest serialization in HIA.
It is not an HMAC, password KDF, streaming I/O library or full runtime rewrite.
"""
from __future__ import annotations
import ast
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

INITIAL = (0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19)
ROUND = (
 0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
 0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
 0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
 0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
 0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
 0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
 0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
 0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2)

BODY = r'''
    padded = (length(s) + 72) & 18446744073709551552
    block = 0
    while block < padded:
        i = 0
        while i < 16:
            value = 0
            j = 0
            while j < 4:
                value = (value << 8) | padded_byte(s, block + i * 4 + j, padded)
                j = j + 1
            put(w, 512 + i * 8, value)
            i = i + 1
        while i < 64:
            x = get(w, 512 + (i - 15) * 8)
            y = get(w, 512 + (i - 2) * 8)
            sx = rotate(x, 7) ^ rotate(x, 18) ^ (x >> 3)
            sy = rotate(y, 17) ^ rotate(y, 19) ^ (y >> 10)
            value = (get(w, 512 + (i - 16) * 8) + sx + get(w, 512 + (i - 7) * 8) + sy) & 4294967295
            put(w, 512 + i * 8, value)
            i = i + 1
        a = get(w, 1024)
        b = get(w, 1032)
        c = get(w, 1040)
        d = get(w, 1048)
        e = get(w, 1056)
        f = get(w, 1064)
        g = get(w, 1072)
        h = get(w, 1080)
        i = 0
        while i < 64:
            s1 = rotate(e, 6) ^ rotate(e, 11) ^ rotate(e, 25)
            choose_bits = (e & f) ^ ((4294967295 ^ e) & g)
            t1 = (h + s1 + choose_bits + get(w, i * 8) + get(w, 512 + i * 8)) & 4294967295
            s0 = rotate(a, 2) ^ rotate(a, 13) ^ rotate(a, 22)
            majority = (a & b) ^ (a & c) ^ (b & c)
            t2 = (s0 + majority) & 4294967295
            h = g
            g = f
            f = e
            e = (d + t1) & 4294967295
            d = c
            c = b
            b = a
            a = (t1 + t2) & 4294967295
            i = i + 1
'''
HELPERS = r'''
def padded_byte(s:readbuf, index:u64, total:u64) -> u64:
    if index < length(s):
        return byte(s, index)
    if index == length(s):
        return 128
    if index < total - 8:
        return 0
    return ((length(s) << 3) >> ((total - 1 - index) * 8)) & 255

def rotate(value:u64, shift:u64) -> u64:
    return (value >> shift) | ((value << (32 - shift)) & 4294967295)

def get(w:mutbuf, index:u64) -> u64:
    value = 0
    value = value | (byte(w, index + 0) << 0)
    value = value | (byte(w, index + 1) << 8)
    value = value | (byte(w, index + 2) << 16)
    value = value | (byte(w, index + 3) << 24)
    value = value | (byte(w, index + 4) << 32)
    value = value | (byte(w, index + 5) << 40)
    value = value | (byte(w, index + 6) << 48)
    value = value | (byte(w, index + 7) << 56)
    return value

def put(w:mutbuf, index:u64, value:u64) -> u64:
    store(w, index + 0, value & 255)
    value = value >> 8
    store(w, index + 1, value & 255)
    value = value >> 8
    store(w, index + 2, value & 255)
    value = value >> 8
    store(w, index + 3, value & 255)
    value = value >> 8
    store(w, index + 4, value & 255)
    value = value >> 8
    store(w, index + 5, value & 255)
    value = value >> 8
    store(w, index + 6, value & 255)
    value = value >> 8
    store(w, index + 7, value & 255)
    value = value >> 8
    return 0
'''


def source_program():
    source = 'def sha256(s:readbuf, o:mutbuf, w:mutbuf) -> u32:\n'
    source += '    if length(s) > 8388608 or length(o) < 32 or length(w) < 1088:\n        return 4294967293\n'
    for i, value in enumerate(ROUND):
        source += f'    put(w, {i*8}, {value})\n'
    for i, value in enumerate(INITIAL):
        source += f'    put(w, {1024+i*8}, {value})\n'
    source += BODY
    for i, name in enumerate('abcdefgh'):
        source += f'        put(w, {1024+i*8}, (get(w, {1024+i*8}) + {name}) & 4294967295)\n'
    source += '''        block = block + 64
    i = 0
    while i < 8:
        value = get(w, 1024 + i * 8)
        j = 0
        while j < 4:
            store(o, i * 4 + j, (value >> ((3 - j) * 8)) & 255)
            j = j + 1
        i = i + 1
    return 32
'''
    return source + HELPERS


def document():
    nodes = ast.parse(source_program()).body
    names = {node.name:'f'+str(i) for i,node in enumerate(nodes)}
    signatures = {node.name:([a.annotation.id for a in node.args.args],node.returns.id) for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = Builder(node,names,signatures,total)
        builder.statements(node.body)
        functions.append({'name':names[node.name],'params':[builder.param(v) for v in builder.params],
            'returns':[builder.returns],'effects':['read','write','trap'],'entry':'b0','blocks':builder.blocks})
    return compact_authoring_cfg({'schema':'hepta.hia.program.v8','module':'sha256','functions':functions})


def main():
    path=Path(__file__).resolve().parents[1]/'examples/hia_bootstrap/sha256.hiaasm'
    path.write_text(render_assembly(document()))
    print(path.name,path.stat().st_size)


if __name__=='__main__':
    main()
