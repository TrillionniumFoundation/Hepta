"""Author the exact finite allocator witness policy in HIA.

The original C witness remains an independent development comparator. Production
events, failure decisions, identity assignment and live accounting belong here;
the mechanical bridge only calls this policy and the real libc functions.
"""
from pathlib import Path
import ast
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import compact_authoring_cfg,total_scalar_functions
from tools.generate_hia_elf_linker import LinkerBuilder
ROOT=Path(__file__).resolve().parents[1]
SOURCE=r"""
def allocator_witness(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) != 64 or length(o) < 128 or length(w) < 393280:
        return 4294967293
    if word_load(s, 0) != @PACKET@ or word_load(s, 48) != 0 or word_load(s, 56) != 0:
        return 4294967295
    op = word_load(s, 8)
    if op == 0:
        return begin(s, o, w)
    capacity = word_load(w, 32)
    if capacity > 32768 or length(o) != 128 + capacity * 32:
        return 4294967295
    if word_load(w, 56) != @READY@ or word_load(o, 120) != @READY@ or word_load(o, 112) != word_load(w, 40):
        return 4294967295
    if op == 1 or op == 2:
        if word_load(w, 16) != 0 or word_load(s, 32) != 0 or word_load(s, 40) != 0:
            return 4294967295
        size = word_load(s, 16)
        if op == 1:
            count = size
            size = word_load(s, 24)
            if size != 0 and count > 18446744073709551615 // size:
                size = 18446744073709551615
            else:
                size = count * size
        elif word_load(s, 24) != 0:
            return 4294967295
        return before(o, w, op, size)
    if op == 3:
        kind = word_load(s, 16)
        size = word_load(s, 24)
        if (kind != 1 and kind != 2) or word_load(w, 16) != kind or word_load(w, 24) != size or word_load(s, 40) != 0:
            return 4294967295
        put(w, 16, 0)
        return remember(o, w, kind, size, word_load(s, 32))
    if op == 4:
        if word_load(w, 16) != 0 or word_load(s, 24) != 0 or word_load(s, 32) != 0 or word_load(s, 40) != 0:
            return 4294967295
        return release(o, w, word_load(s, 16))
    return 4294967295

def begin(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    counter = word_load(s, 24)
    capacity = word_load(s, 40)
    if counter == 0 or counter > 18446744073709551487 or word_load(s, 32) != counter + 128 or capacity > 32768:
        return 4294967295
    if length(o) != 128 + capacity * 32 or word_load(w, 0) != counter or word_load(w, 8) != length(o):
        return 4294967295
    i = 0
    while i < 16:
        put(o, i * 8, 0)
        i = i + 1
    i = 0
    while i < 16384:
        at = 64 + i * 24
        put(w, at, 0)
        put(w, at + 8, 0)
        put(w, at + 16, 0)
        i = i + 1
    put(w, 16, 0)
    put(w, 24, 0)
    put(w, 32, capacity)
    put(w, 40, word_load(s, 16))
    put(w, 48, 0)
    put(w, 56, @READY@)
    put(o, 112, word_load(s, 16))
    put(o, 120, @READY@)
    return 0

def event(o:mutbuf, w:mutbuf, kind:u64, size:u64, identity:u64, success:u64) -> u64:
    index = word_load(o, 104)
    if index >= word_load(w, 32):
        add(o, 80, 1)
        return 0
    at = 128 + index * 32
    put(o, at, kind)
    put(o, at + 8, size)
    put(o, at + 16, identity)
    put(o, at + 24, success)
    put(o, 104, index + 1)
    return 0

def before(o:mutbuf, w:mutbuf, kind:u64, size:u64) -> u32:
    add(o, 0, 1)
    add(o, kind * 8, 1)
    if size == 0:
        add(o, 88, 1)
    put(w, 24, size)
    if word_load(w, 40) != 0 and word_load(o, 0) == word_load(w, 40):
        add(o, 24, 1)
        event(o, w, kind, size, 0, 0)
        return 0
    put(w, 16, kind)
    return 1

def remember(o:mutbuf, w:mutbuf, kind:u64, size:u64, pointer:u64) -> u32:
    if pointer == 0:
        add(o, 96, 1)
        event(o, w, kind, size, 0, 0)
        return 0
    identity = word_load(w, 48) + 1
    put(w, 48, identity)
    i = 0
    while i < 16384:
        at = 64 + i * 24
        if word_load(w, at) == 0:
            put(w, at, pointer)
            put(w, at + 8, size)
            put(w, at + 16, identity)
            add(o, 32, 1)
            add(o, 48, 1)
            add(o, 56, size)
            if word_load(o, 56) > word_load(o, 64):
                put(o, 64, word_load(o, 56))
            event(o, w, kind, size, identity, 1)
            return 1
        i = i + 1
    add(o, 80, 1)
    event(o, w, kind, size, identity, 1)
    return 1

def release(o:mutbuf, w:mutbuf, pointer:u64) -> u32:
    if pointer == 0:
        return 0
    i = 0
    while i < 16384:
        at = 64 + i * 24
        if word_load(w, at) == pointer:
            size = word_load(w, at + 8)
            identity = word_load(w, at + 16)
            put(w, at, 0)
            put(w, at + 8, 0)
            put(w, at + 16, 0)
            add(o, 40, 1)
            put(o, 48, word_load(o, 48) - 1)
            put(o, 56, word_load(o, 56) - size)
            event(o, w, 3, size, identity, 1)
            return 1
        i = i + 1
    add(o, 72, 1)
    event(o, w, 3, 0, 0, 0)
    return 0

def add(o:mutbuf, at:u64, value:u64) -> u64:
    return put(o, at, word_load(o, at) + value)

def put(o:mutbuf, at:u64, value:u64) -> u64:
    i = 0
    while i < 8:
        store(o, at + i, (value >> (i * 8)) & 255)
        i = i + 1
    return 0
"""
SOURCE=SOURCE.replace('@PACKET@',str(int.from_bytes(b'HIACAW01','little'))).replace('@READY@',str(0x484941434841494e))
def document(source=SOURCE,module='cold_allocator_witness'):
 nodes=ast.parse(source).body;names={n.name:'f'+str(i) for i,n in enumerate(nodes)}
 signatures={n.name:([a.annotation.id for a in n.args.args],n.returns.id) for n in nodes}
 total=total_scalar_functions(nodes);functions=[]
 for n in nodes:
  b=LinkerBuilder(n,names,signatures,total);b.statements(n.body)
  functions.append({'name':names[n.name],'params':[b.param(p) for p in b.params],'returns':[b.returns],'effects':['read','write','trap'],'entry':'b0','blocks':b.blocks})
 return compact_authoring_cfg({'schema':'hepta.hia.program.v9','module':module,'functions':functions})
def main():
 d=document();raw=render_assembly(d).encode();(ROOT/'examples/hia_bootstrap/cold_allocator_witness.hepta').write_bytes(raw)
 print('COLD_ALLOCATOR_WITNESS_SOURCE',len(raw),len(d['functions']),sum(len(f['blocks']) for f in d['functions']),sum(len(b['ops']) for f in d['functions'] for b in f['blocks']))
if __name__=='__main__':main()
