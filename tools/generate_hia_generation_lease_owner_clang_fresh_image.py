"""Read the actual artifact, freshly emit LLVM, then admit the same holder.

HIAMVI04 cannot carry an expected LLVM digest. Its fixed LLVM role computes
that digest from the actual Core after the artifact has been captured, matching
ScalarMultiversionRuntime._prepare's observable order. VI03 remains unchanged.
"""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_generation_lease_owner_clang_image as prior
ROOT=Path(__file__).resolve().parents[1]
C=dict(LL_MAGIC=int.from_bytes(b'HIALLV01','little'),LL_FRAME=176<<20,
 LL_WORK=192<<20,LL_OUTPUT=320<<20,LL_CORE_N=1968,LL_IR_N=1976,
 LL_CURSOR=1984,LL_AMOUNT=1992,LL_KIND=2000,LL_COMPLETE=2008,
 CORE_SHA=prior.C['CORE_SHA'],IR_SHA=prior.C['IR_SHA'],
 SHA_CHUNK=prior.C['SHA_CHUNK'],SHA_OUT=prior.C['SHA_OUT'],SHA_WORK=prior.C['SHA_WORK'],
 JSON=prior.C['JSON'],JSONWORK=prior.C['JSONWORK'],ARENA=prior.C['ARENA'],
 RECEIPT_N=prior.C['RECEIPT_N'])
EXTRA=r'''
def fresh_begin(o:mutbuf,w:mutbuf) -> u32:
    put(w,LL_KIND,0)
    put(w,LL_CURSOR,0)
    store(w,SHA_CHUNK,0)
    return image_role(o,w,100,2,SHA_CHUNK,1,SHA_OUT,32,SHA_WORK,1184)

def fresh_step(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    raw=get(w,8)
    if phase==100 or phase==104:
        if raw!=0:
            return fresh_fail(o,w,13,raw)
        return fresh_chunk(o,w)
    if phase==101:
        if raw!=0:
            return fresh_fail(o,w,13,raw)
        put(w,LL_CURSOR,get(w,LL_CURSOR)+get(w,LL_AMOUNT))
        return fresh_chunk(o,w)
    if phase==102:
        if raw!=32:
            return fresh_fail(o,w,13,raw)
        if get(w,LL_KIND)==0:
            if image_equal(w,SHA_OUT,CORE_SHA,32)==0:
                return fresh_fail(o,w,12,0)
            return image_role(o,w,103,8,LL_FRAME,64+get(w,LL_CORE_N),LL_OUTPUT,16777216,LL_WORK,134217728)
        image_copy(w,IR_SHA,SHA_OUT,32)
        image_copy(w,SHA_OUT,1700,32)
        put(w,LL_COMPLETE,1)
        i=0
        while i<128:
            store(w,JSONWORK+i,0)
            i=i+1
        put(w,JSONWORK+48,131073)
        put(w,JSONWORK+56,128)
        return image_role(o,w,49,7,JSON,get(w,RECEIPT_N),ARENA,16777216,JSONWORK,8388608)
    if phase==103:
        if raw==0 or raw>16777216:
            return fresh_fail(o,w,25,raw)
        put(w,LL_IR_N,raw)
        put(w,LL_KIND,1)
        put(w,LL_CURSOR,0)
        store(w,SHA_CHUNK,0)
        return image_role(o,w,104,2,SHA_CHUNK,1,SHA_OUT,32,SHA_WORK,1184)
    return fresh_fail(o,w,25,phase)

def fresh_chunk(o:mutbuf,w:mutbuf) -> u32:
    source=LL_FRAME+64
    size=get(w,LL_CORE_N)
    if get(w,LL_KIND)==1:
        source=LL_OUTPUT
        size=get(w,LL_IR_N)
    used=get(w,LL_CURSOR)
    if used>size:
        return fresh_fail(o,w,25,used)
    n=size-used
    if n==0:
        store(w,SHA_CHUNK,2)
        return image_role(o,w,102,2,SHA_CHUNK,1,SHA_OUT,32,SHA_WORK,1184)
    if n>1048576:
        n=1048576
    put(w,LL_AMOUNT,n)
    store(w,SHA_CHUNK,1)
    image_copy(w,SHA_CHUNK+1,source+used,n)
    return image_role(o,w,101,2,SHA_CHUNK,n+1,SHA_OUT,32,SHA_WORK,1184)

def fresh_fail(o:mutbuf,w:mutbuf,status:u64,raw:u64) -> u32:
    image_copy(w,SHA_OUT,1700,32)
    return image_fail(o,w,status,raw)
'''
def once(source,old,new):
    assert source.count(old)==1,(old,source.count(old))
    return source.replace(old,new)
def source_program():
    s=prior.source_program()
    s=once(s,f'length(w)<{160<<20} or length(o)<512',f'length(w)<{336<<20} or length(o)<512')
    s=once(s,str(prior.C['INPUT_MAGIC']),str(int.from_bytes(b'HIAMVI04','little')))
    s=once(s,'    if phase<40:\n',
        '    if phase>=100 and phase<=104:\n        return fresh_step(o,w,phase)\n    if phase<40:\n')
    s=once(s,'    receipt_n=readword(s,24)\n',
        '    receipt_n=readword(s,24)\n    core_n=readword(s,160)\n    if core_n==0 or core_n>8388608 or core_n>length(s)-256:\n        return 4294967293\n')
    s=once(s,'receipt_n>length(s)-256-path_n','receipt_n>length(s)-256-path_n or core_n>length(s)-256-path_n-receipt_n')
    s=once(s,'abi_n!=length(s)-256-path_n-receipt_n','abi_n!=length(s)-256-path_n-receipt_n-core_n')
    s=once(s,'    i=160\n    while i<256:',
        '    i=96\n    while i<128:\n        if readword(s,i)!=0:\n            return 4294967293\n        i=i+8\n    i=168\n    while i<256:')
    mark=f'    put(w,{prior.C["RECEIPT_N"]},receipt_n)\n'
    s=once(s,mark,mark+'''    put(w,LL_CORE_N,core_n)
    i=0
    while i<64:
        store(w,LL_FRAME+i,0)
        i=i+1
    put(w,LL_FRAME,LL_MAGIC)
    put(w,LL_FRAME+24,core_n)
    i=0
    while i<core_n:
        store(w,LL_FRAME+64+i,byte(s,256+path_n+abi_n+receipt_n+i))
        i=i+1
''')
    start=s.index('    if phase==42:')
    end=s.index('    if phase==49:',start)
    s=s[:start]+f'''    if phase==42:
        if raw!=32:
            return image_fail(o,w,13,raw)
        image_copy(w,1700,{prior.C["SHA_OUT"]},32)
        return fresh_begin(o,w)
'''+s[end:]
    s=once(s,'    put(o,152,get(w,176))\n',
        '''    put(o,152,get(w,176))
    if get(w,LL_COMPLETE)==1:
        i=0
        while i<32:
            store(o,160+i,byte(w,IR_SHA+i))
            i=i+1
        put(o,192,get(w,LL_IR_N))
        put(o,200,1)
''')
    s+='\n'+EXTRA
    for name,value in sorted(C.items(),key=lambda x:-len(x[0])):
        s=re.sub(r'\b'+name+r'\b',str(value),s)
    return s
def main():
    tree=document(source_program(),'generation_lease_owner_clang_fresh_image')
    path=ROOT/'examples/hia_bootstrap/generation_lease_owner_clang_fresh_image.hepta'
    path.write_text(render_assembly(tree))
    print(path.name,path.stat().st_size,len(tree['functions']),
          sum(len(f['blocks'])for f in tree['functions']),
          sum(len(b['ops'])for f in tree['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
