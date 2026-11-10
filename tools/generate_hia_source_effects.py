"""Author the source checker's complete call-effect/resource final phase in HIA.

One phase of whole checker migration, not a complete semantic frontend. The
native phase computes the fixed point and decides every final-phase diagnostic;
the host only transports sets/graph identities and materializes diagnostics.
"""
from __future__ import annotations
import ast
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder,compact_authoring_cfg,total_scalar_functions

SOURCE=r'''
def validate(s:readbuf, w:mutbuf) -> u64:
    if length(s) < 112 or length(s) > 1048576:
        return 4294967293
    n = read_word(s, 8)
    m = read_word(s, 16)
    edges = read_word(s, 24)
    resources = read_word(s, 32)
    workers = read_word(s, 40)
    symbols = read_word(s, 48)
    if read_word(s, 0) != 3549479791681612106 or n > 2048 or m > 64 or edges > 16384 or resources > 8192 or workers > 4096 or symbols < m or symbols > 8256:
        return 4294967293
    e_at = 112 + n * 48
    r_at = e_at + edges * 8
    w_at = r_at + resources * 8
    y_at = w_at + workers * 8
    p_at = y_at + symbols * 16
    if read_word(s, 56) != 112 or read_word(s, 64) != e_at or read_word(s, 72) != r_at or read_word(s, 80) != w_at or read_word(s, 88) != y_at or read_word(s, 96) != p_at or p_at > length(s) or read_word(s, 104) != length(s) - p_at or length(w) < 64 + n * 8:
        return 4294967293
    mask = 18446744073709551615
    if m < 64:
        mask = (1 << m) - 1
    i = 0
    while i < n:
        at = 112 + i * 48
        if (read_word(s, at) | read_word(s, at + 8)) & (18446744073709551615 ^ mask) != 0:
            return 4294967293
        if read_word(s, at + 16) > edges or read_word(s, at + 24) > edges - read_word(s, at + 16) or read_word(s, at + 32) > resources or read_word(s, at + 40) > resources - read_word(s, at + 32):
            return 4294967293
        i = i + 1
    i = 0
    while i < edges:
        if read_word(s, e_at + i * 8) >= n:
            return 4294967293
        i = i + 1
    i = 0
    while i < resources:
        if read_word(s, r_at + i * 8) >= symbols:
            return 4294967293
        i = i + 1
    i = 0
    while i < workers:
        if read_word(s, w_at + i * 8) >= n:
            return 4294967293
        i = i + 1
    i = 0
    while i < symbols:
        at = y_at + i * 16
        if read_word(s, at) > read_word(s, at + 8) or read_word(s, at + 8) > length(s) - p_at:
            return 4294967293
        i = i + 1
    return 0

def masks(s:readbuf, w:mutbuf) -> u64:
    m = read_word(s, 16)
    known = 0
    forbidden = 0
    alloc = 0
    block = 0
    spawn = 0
    i = 0
    while i < m:
        b = 1 << i
        if word_is(s, i, W_ALLOC, 0, 5) == 1:
            alloc = b
        if word_is(s, i, W_BLOCK, 0, 5) == 1:
            block = b
        if word_is(s, i, W_SPAWN, 0, 5) == 1:
            spawn = b
        if word_is(s, i, W_ALLOC, 0, 5) == 1 or word_is(s, i, W_BLOCK, 0, 5) == 1 or word_is(s, i, W_SPAWN, 0, 5) == 1 or word_is(s, i, W_PANIC, 0, 5) == 1 or word_is(s, i, W_IO, 0, 2) == 1 or word_is(s, i, W_FFI, 0, 3) == 1 or word_is(s, i, W_UNSAFE, 0, 6) == 1 or word_is(s, i, W_WRITE, 0, 5) == 1:
            known = known | b
        if word_is(s, i, W_SPAWN, 0, 5) == 1 or word_is(s, i, W_FFI, 0, 3) == 1 or word_is(s, i, W_UNSAFE, 0, 6) == 1:
            forbidden = forbidden | b
        i = i + 1
    put(w, 0, known)
    put(w, 8, forbidden)
    put(w, 16, alloc)
    put(w, 24, block)
    put(w, 32, spawn)
    return 0

def infer(s:readbuf, w:mutbuf) -> u64:
    n = read_word(s, 8)
    known = get(w, 0)
    e_at = read_word(s, 64)
    i = 0
    while i < n:
        put(w, 64 + i * 8, read_word(s, 112 + i * 48))
        i = i + 1
    changed = 1
    while changed != 0:
        changed = 0
        i = 0
        while i < n:
            old = get(w, 64 + i * 8)
            value = old
            first = read_word(s, 112 + i * 48 + 16)
            count = read_word(s, 112 + i * 48 + 24)
            j = 0
            while j < count:
                callee = read_word(s, e_at + (first + j) * 8)
                value = value | get(w, 64 + callee * 8) | (read_word(s, 112 + callee * 48 + 8) & known)
                j = j + 1
            if value != old:
                changed = 1
                put(w, 64 + i * 8, value)
            i = i + 1
    return 0

def entry(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    code = validate(s, w)
    if code != 0:
        return code
    masks(s, w)
    infer(s, w)
    n = read_word(s, 8)
    count = issues(s, o, w, 0)
    size = 32 + n * 8 + count * 24
    if length(o) < size:
        return 4294967294
    put(o, 0, 3549479791681612107)
    put(o, 8, n)
    put(o, 16, count)
    put(o, 24, 0)
    i = 0
    while i < n:
        put(o, 32 + i * 8, get(w, 64 + i * 8))
        i = i + 1
    issues(s, o, w, 1)
    return size

def issues(s:readbuf, o:mutbuf, w:mutbuf, publish:u64) -> u64:
    known = get(w, 0)
    forbidden = get(w, 8)
    n = read_word(s, 8)
    e_at = read_word(s, 64)
    r_at = read_word(s, 72)
    w_at = read_word(s, 80)
    count = 0
    i = 0
    while i < read_word(s, 40):
        worker = read_word(s, w_at + i * 8)
        value = (get(w, 64 + worker * 8) | read_word(s, 112 + worker * 48 + 8)) & forbidden
        if value != 0:
            issue(o, n, count, publish, 1, i, value)
            count = count + 1
        i = i + 1
    i = 0
    while i < n:
        at = 112 + i * 48
        declared = read_word(s, at + 8)
        inferred = get(w, 64 + i * 8)
        missing = inferred & (18446744073709551615 ^ declared)
        if missing != 0:
            issue(o, n, count, publish, 2, i, missing)
            count = count + 1
        upper = inferred | (declared & known)
        which = 1
        while which < 4:
            effect = get(w, 16)
            if which == 2:
                effect = get(w, 24)
            if which == 3:
                effect = get(w, 32)
            if upper & effect != 0:
                j = 0
                first = read_word(s, at + 32)
                while j < read_word(s, at + 40):
                    symbol = read_word(s, r_at + (first + j) * 8)
                    match = 0
                    if which == 1:
                        match = word_is(s, symbol, W_HEAPLOW, W_HEAPHIGH, 16)
                    if which == 2:
                        match = word_is(s, symbol, W_MAYBLOCK, W_MAYBLOCKHI, 9)
                    if which == 3:
                        match = word_is(s, symbol, W_MAYSPAWN, W_MAYSPAWNHI, 9)
                    if match == 1:
                        issue(o, n, count, publish, 3, i, which)
                        count = count + 1
                    j = j + 1
            which = which + 1
        i = i + 1
    return count

def issue(o:mutbuf, functions:u64, index:u64, publish:u64, code:u64, ref:u64, value:u64) -> u64:
    if publish == 1:
        at = 32 + functions * 8 + index * 24
        put(o, at, code)
        put(o, at + 8, ref)
        put(o, at + 16, value)
    return 0

def word_is(s:readbuf, symbol:u64, low:u64, high:u64, size:u64) -> u64:
    row = read_word(s, 88) + symbol * 16
    begin = read_word(s, row)
    if read_word(s, row + 8) - begin != size:
        return 0
    at = read_word(s, 96) + begin
    i = 0
    while i < size:
        value = 0
        if i < 8:
            value = (low >> (i * 8)) & 255
        else:
            value = (high >> ((i - 8) * 8)) & 255
        if byte(s, at + i) != value:
            return 0
        i = i + 1
    return 1
'''
# Ordered byte operations preserve the existing native word ABI.
for name,read,annotation in (('read_word',True,'readbuf'),('get',True,'mutbuf'),('put',False,'mutbuf')):
    SOURCE+='\ndef '+name+'(s:'+annotation+', at:u64'+('' if read else ', value:u64')+') -> u64:\n'
    if read:
        SOURCE+='    value = 0\n'+''.join(f'    value = value | (byte(s, at + {i}) << {8*i})\n' for i in range(8))+'    return value\n'
    else:SOURCE+=''.join(f'    store(s, at + {i}, (value >> {8*i}) & 255)\n' for i in range(8))+'    return 0\n'

def source_program():
    import re
    values={}
    for label,value in {'ALLOC':'alloc','BLOCK':'block','SPAWN':'spawn','PANIC':'panic','IO':'io','FFI':'ffi','UNSAFE':'unsafe','WRITE':'write','HEAPLOW':'heap_all','HEAPHIGH':'ocations','MAYBLOCK':'may_bloc','MAYBLOCKHI':'k','MAYSPAWN':'may_spaw','MAYSPAWNHI':'n'}.items():
        values['W_'+label]=int.from_bytes(value.encode(),'little')
    return re.sub(r'\bW_[A-Z]+\b',lambda m:str(values[m[0]]),SOURCE)

def document():
    nodes=ast.parse(source_program()).body
    nodes.sort(key=lambda node: node.name != "entry")
    names={n.name:'f'+str(i) for i,n in enumerate(nodes)}
    signatures={n.name:([a.annotation.id for a in n.args.args],n.returns.id) for n in nodes}
    total=total_scalar_functions(nodes);functions=[]
    for node in nodes:
        b=Builder(node,names,signatures,total);b.statements(node.body)
        functions.append({'name':names[node.name],'params':[b.param(v) for v in b.params],
            'returns':[b.returns],'effects':['read','write','trap'],'entry':'b0','blocks':b.blocks})
    return compact_authoring_cfg({'schema':'hepta.hia.program.v8','module':'source_effects','functions':functions})

def main():
    path=Path(__file__).resolve().parents[1]/'examples/hia_bootstrap/source_effects.hiaasm';doc=document()
    path.write_text(render_assembly(doc));print(path.name,path.stat().st_size,len(doc['functions']),sum(len(f['blocks']) for f in doc['functions']))

if __name__=='__main__':main()
