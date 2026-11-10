"""Author native nominal/generic capability and stored-borrow graph queries.

Dependency stage of semantic type/ownership migration, not the complete checker.
Generic substitutions use native contextual references, not host instantiation.
"""
from __future__ import annotations
import ast
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder,compact_authoring_cfg,total_scalar_functions

SOURCE=r'''
def entry(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    code = validate(s, w)
    if code != 0:
        return code
    code = prepare(s, w)
    if code != 0:
        return code
    answer = query(s, w)
    if answer > 1:
        return answer
    if length(o) < 32:
        return 4294967294
    put(o, 0, 3549479791681612109)
    put(o, 8, answer)
    put(o, 16, word(s, 8))
    put(o, 24, 0)
    return 32

def validate(s:readbuf, w:mutbuf) -> u64:
    if length(s) < 128 or length(s) > 1048576 or length(w) < 680256:
        return 4294967293
    if word(s, 0) != 3549479791681612108 or word(s, 8) < 1 or word(s, 8) > 2:
        return 4294967293
    if word(s, 16) == 0 or word(s, 16) > 8192 or word(s, 24) > 512 or word(s, 32) > 32768 or word(s, 40) == 0 or word(s, 40) > 8192 or word(s, 48) > 4096 or word(s, 56) > 8192 or word(s, 64) > 8192 or word(s, 72) > 8192 or word(s, 80) >= word(s, 16):
        return 4294967293
    if word(s, 88) != 128 or word(s, 96) != 128 + word(s, 16) * 64 or word(s, 104) != word(s, 96) + word(s, 24) * 48:
        return 4294967293
    if word(s, 112) != word(s, 104) + (word(s, 32) + word(s, 48) + word(s, 56) + word(s, 64) + word(s, 72)) * 8 or word(s, 120) != word(s, 112) + word(s, 40) * 16 or word(s, 120) > length(s):
        return 4294967293
    cursor = 0
    i = 0
    while i < word(s, 16):
        at = 128 + i * 64
        if word(s, at) >= word(s, 40) or word(s, at + 8) != cursor or word(s, at + 16) > word(s, 32) - cursor:
            return 4294967293
        count = word(s, at + 16)
        j = 0
        while j < count:
            if word(s, word(s, 104) + (cursor + j) * 8) >= i:
                return 4294967293
            j = j + 1
        cursor = cursor + count
        if word(s, at + 24) != cursor or word(s, at + 32) > word(s, 32) - cursor:
            return 4294967293
        count = word(s, at + 32)
        j = 0
        while j < count:
            if word(s, word(s, 104) + (cursor + j) * 8) >= word(s, 40):
                return 4294967293
            j = j + 1
        cursor = cursor + count
        if word(s, at + 40) > 2 or word(s, at + 56) != 0:
            return 4294967293
        if word(s, at + 40) == 0:
            if word(s, at + 48) != 0:
                return 4294967293
        else:
            if word(s, at + 48) >= word(s, 40):
                return 4294967293
        i = i + 1
    if cursor != word(s, 32):
        return 4294967293
    if validate_declarations(s) != 0:
        return 4294967293
    cursor = 0
    i = 0
    while i < word(s, 40):
        at = word(s, 112) + i * 16
        if word(s, at) != cursor or word(s, at + 8) < cursor or word(s, at + 8) > length(s) - word(s, 120):
            return 4294967293
        cursor = word(s, at + 8)
        i = i + 1
    if cursor != length(s) - word(s, 120):
        return 4294967293
    return 0

def validate_declarations(s:readbuf) -> u64:
    pc = 0
    mc = 0
    i = 0
    while i < word(s, 24):
        at = word(s, 96) + i * 48
        if word(s, at) >= word(s, 40) or word(s, at + 8) != pc or word(s, at + 16) > word(s, 48) - pc or word(s, at + 24) != mc or word(s, at + 32) > word(s, 56) - mc:
            return 1
        pc = pc + word(s, at + 16)
        mc = mc + word(s, at + 32)
        i = i + 1
    if pc != word(s, 48) or mc != word(s, 56):
        return 1
    i = 0
    while i < word(s, 48) + word(s, 56) + word(s, 64) + word(s, 72):
        limit = word(s, 40)
        if i >= word(s, 48) and i < word(s, 48) + word(s, 56):
            limit = word(s, 16)
        if word(s, word(s, 104) + (word(s, 32) + i) * 8) >= limit:
            return 1
        i = i + 1
    return 0

def prepare(s:readbuf, w:mutbuf) -> u64:
    put(w, 0, 1)
    put(w, 8, 0)
    put(w, 16, 0)
    put(w, 32, 0)
    put(w, 256, word(s, 80))
    i = 0
    while i < word(s, 40):
        store(w, 524544 + i, 0)
        store(w, 532736 + i, 0)
        put(w, 614720 + i * 8, 0)
        i = i + 1
    i = 0
    while i < word(s, 24):
        name = word(s, word(s, 96) + i * 48)
        if get(w, 614720 + name * 8) != 0:
            return 4294967293
        put(w, 614720 + name * 8, i + 1)
        i = i + 1
    at = word(s, 104) + (word(s, 32) + word(s, 48) + word(s, 56)) * 8
    i = 0
    while i < word(s, 64):
        name = word(s, at + i * 8)
        store(w, 532736 + name, 1)
        if same_word(s, name, W_REF_MUT, 7) == 1:
            put(w, 32, 1)
        i = i + 1
    at = at + word(s, 64) * 8
    i = 0
    while i < word(s, 72):
        store(w, 524544 + word(s, at + i * 8), 1)
        i = i + 1
    return 0

def query(s:readbuf, w:mutbuf) -> u64:
    mode = word(s, 8)
    while get(w, 0) != 0:
        put(w, 0, get(w, 0) - 1)
        ref = resolve(s, w, get(w, 256 + get(w, 0) * 8))
        if ref == 18446744073709551615:
            return 4294967292
        at = 128 + (ref & 65535) * 64
        name = word(s, at)
        opaque = 0
        if mode == 1:
            if byte(w, 532736 + name) != 0:
                return 1
            if get(w, 32) == 1 and is_reference(s, name) == 1:
                opaque = 1
        else:
            if is_reference(s, name) == 1 or word(s, at + 32) != 0:
                return 1
        if opaque == 0:
            if push_args(s, w, ref) != 0:
                return 4294967292
            if byte(w, 524544 + name) == 0:
                store(w, 524544 + name, 1)
                declaration = get(w, 614720 + name * 8)
                if declaration != 0:
                    declaration = declaration - 1
                    if mode == 2 and word(s, word(s, 96) + declaration * 48 + 40) != 0:
                        return 1
                    env = 0
                    if mode == 1:
                        env = new_env(s, w, ref, declaration)
                    if env == 18446744073709551615 or push_members(s, w, declaration, env) != 0:
                        return 4294967292
    return 0

def push_args(s:readbuf, w:mutbuf, ref:u64) -> u64:
    at = 128 + (ref & 65535) * 64
    first = word(s, at + 8)
    count = word(s, at + 16)
    top = get(w, 0)
    if count > 65536 - top:
        return 1
    i = 0
    while i < count:
        value = word(s, word(s, 104) + (first + i) * 8) | (ref & 18446744073709486080)
        put(w, 256 + (top + i) * 8, value)
        i = i + 1
    put(w, 0, top + count)
    return 0

def push_members(s:readbuf, w:mutbuf, declaration:u64, env:u64) -> u64:
    at = word(s, 96) + declaration * 48
    first = word(s, at + 24)
    count = word(s, at + 32)
    top = get(w, 0)
    if count > 65536 - top:
        return 1
    base = word(s, 104) + (word(s, 32) + word(s, 48)) * 8
    i = 0
    while i < count:
        value = word(s, base + (first + i) * 8) | (env << 16)
        put(w, 256 + (top + i) * 8, value)
        i = i + 1
    put(w, 0, top + count)
    return 0

def new_env(s:readbuf, w:mutbuf, ref:u64, declaration:u64) -> u64:
    at = word(s, 96) + declaration * 48
    count = word(s, at + 16)
    args = word(s, 128 + (ref & 65535) * 64 + 16)
    if count > args:
        count = args
    if count == 0:
        return 0
    env = get(w, 8) + 1
    first = get(w, 16)
    if env > 512 or count > 4096 - first:
        return 18446744073709551615
    put(w, 540928 + env * 16, count)
    put(w, 540928 + env * 16 + 8, first)
    params = word(s, word(s, 96) + declaration * 48 + 8)
    args = word(s, 128 + (ref & 65535) * 64 + 8)
    i = 0
    while i < count:
        name = word(s, word(s, 104) + (word(s, 32) + params + i) * 8)
        target = word(s, word(s, 104) + (args + i) * 8) | (ref & 18446744073709486080)
        put(w, 549136 + (first + i) * 16, name)
        put(w, 549136 + (first + i) * 16 + 8, target)
        i = i + 1
    put(w, 8, env)
    put(w, 16, first + count)
    return env

def resolve(s:readbuf, w:mutbuf, ref:u64) -> u64:
    step = 0
    while step < 513:
        env = ref >> 16
        at = 128 + (ref & 65535) * 64
        if env == 0 or word(s, at + 16) != 0 or word(s, at + 40) != 0:
            return ref
        first = get(w, 540928 + env * 16 + 8)
        i = get(w, 540928 + env * 16)
        found = 0
        target = ref
        while i > 0 and found == 0:
            i = i - 1
            at = 549136 + (first + i) * 16
            if get(w, at) == word(s, 128 + (ref & 65535) * 64):
                target = get(w, at + 8)
                found = 1
        if found == 0:
            return ref
        ref = target
        step = step + 1
    return 18446744073709551615

def is_reference(s:readbuf, name:u64) -> u64:
    if same_word(s, name, W_REF_READ, 8) == 1 or same_word(s, name, W_REF_MUT, 7) == 1:
        return 1
    return 0

def same_word(s:readbuf, symbol:u64, value:u64, size:u64) -> u64:
    row = word(s, 112) + symbol * 16
    begin = word(s, row)
    if word(s, row + 8) - begin != size:
        return 0
    at = word(s, 120) + begin
    i = 0
    while i < size:
        if byte(s, at + i) != ((value >> (i * 8)) & 255):
            return 0
        i = i + 1
    return 1
'''
for name,read,annotation in (('word',True,'readbuf'),('get',True,'mutbuf'),('put',False,'mutbuf')):
    SOURCE+='\ndef '+name+'(s:'+annotation+', at:u64'+('' if read else ', value:u64')+') -> u64:\n'
    if read:
        SOURCE+='    value = 0\n'+''.join(f'    value = value | (byte(s, at + {i}) << {8*i})\n' for i in range(8))+'    return value\n'
    else:SOURCE+=''.join(f'    store(s, at + {i}, (value >> {8*i}) & 255)\n' for i in range(8))+'    return 0\n'

def document():
    source=SOURCE
    for name in ('ref_mut','ref_read'):
        source=source.replace('W_'+name.upper(),str(int.from_bytes(name.encode(),'little')))
    nodes=ast.parse(source).body
    names={n.name:'f'+str(i) for i,n in enumerate(nodes)}
    signatures={n.name:([a.annotation.id for a in n.args.args],n.returns.id) for n in nodes}
    total=total_scalar_functions(nodes);functions=[]
    for node in nodes:
        b=Builder(node,names,signatures,total);b.statements(node.body)
        functions.append({'name':names[node.name],'params':[b.param(v) for v in b.params],
            'returns':[b.returns],'effects':['read','write','trap'],'entry':'b0','blocks':b.blocks})
    return compact_authoring_cfg({'schema':'hepta.hia.program.v8','module':'type_graph','functions':functions})

def main():
    p=Path(__file__).resolve().parents[1]/'examples/hia_bootstrap/type_graph.hiaasm';d=document()
    p.write_text(render_assembly(d));print(p.name,p.stat().st_size,len(d['functions']),sum(len(f['blocks']) for f in d['functions']))
if __name__=='__main__':main()
