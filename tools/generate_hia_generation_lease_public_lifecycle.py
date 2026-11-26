"""Native GenerationLease public lifecycle through the fixed actual MV carrier.

Typed call and GenerationInfo owners compose this same require-open boundary;
they remain separate from this lifecycle facet.
"""
from pathlib import Path
import json,re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
ROOT=Path(__file__).resolve().parents[1]
C={'MAGIC':int.from_bytes(b'HIAGLQ01','little'),'REPLY':int.from_bytes(b'HIAGLR01','little'),
'CONTEXT':int.from_bytes(b'HIAGLC01','little'),'HANDLES':int.from_bytes(b'HIAMVHQ1','little'),
'HREPLY':int.from_bytes(b'HIAMVHR1','little'),'EFFECTS':int.from_bytes(b'HIAMVEX3','little'),
'EREPLY':int.from_bytes(b'HIAMVER1','little'),'LEASE_ADMISSION':int.from_bytes(b'HIAMVLA1','little'),
'OUT':(96<<20)+16384,'CHILD':16384,'RQ':4096,'PHASE':256,'FEEDBACK':384,
'BAD':4294967293}
ERRORS={1:'E_HIA_MULTIVERSION: generation lease is closed',
2:'E_HIA_MULTIVERSION: leases have one close owner; acquire another lease instead of copying'}
SOURCE=r'''
def lease(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=64 or length(o)<OUT or length(w)<128:
        return BAD
    phase=get(o,PHASE)
    if phase==0:
        return begin(s,o,w)
    if phase==1:
        if get(o,FEEDBACK)!=get(w,32):
            return finish(s,o,3,0,0)
        zero(o,RQ,128)
        put(o,RQ,HANDLES)
        put(o,RQ+8,6)
        copy_source(s,o,16,RQ+24,24)
        return invoke(o,2,128)
    if phase==2:
        if handles_ok(o)==False:
            return dependency(s,o)
        if get(o,CHILD+16)!=2:
            return finish(s,o,1,0,0)
        op=word_load(s,8)
        if op==3 or op==4:
            return finish(s,o,4,0,2)
        zero(o,RQ,384)
        put(o,RQ,HANDLES)
        copy_source(s,o,16,RQ+24,24)
        n=128
        if op==5 or op==6:
            put(o,RQ+8,op-3)
        else:
            put(o,RQ+8,4)
            put(o,RQ+72,256)
            n=384
            if op==0:
                put(o,RQ+128,LEASE_ADMISSION)
            else:
                put(o,RQ+128,EFFECTS)
                put(o,RQ+136,5)
        return invoke(o,3,n)
    if phase==3:
        if handles_ok(o)==False:
            return dependency(s,o)
        op=word_load(s,8)
        if op==5:
            if get(o,CHILD+16)!=2 or get(o,CHILD+24)==0:
                return finish(s,o,5,0,0)
            return finish(s,o,0,2,0)
        if op==6:
            return finish(s,o,0,0,0)
        at=get(o,CHILD+56)
        if at!=1048576 or get(o,CHILD+64)!=1024:
            return finish(s,o,5,0,0)
        if get(o,CHILD+at)!=EREPLY:
            return finish(s,o,5,0,0)
        status=get(o,CHILD+at+8)
        if status!=get(o,CHILD+48):
            return finish(s,o,5,0,0)
        if status==32:
            return finish(s,o,4,0,1)
        if status!=0:
            return finish(s,o,5,0,0)
        if op==0:
            return finish(s,o,0,1,0)
        return finish(s,o,0,0,0)
    return BAD

def begin(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if word_load(s,0)!=MAGIC or word_load(s,8)>6:
        return BAD
    if get(w,0)!=CONTEXT or get(w,8)==0 or get(w,16)==0 or get(w,24)<256 or get(w,32)==0:
        return BAD
    i=40
    while i<128:
        if get(w,i)!=0:
            return BAD
        i=i+8
    i=40
    while i<64:
        if word_load(s,i)!=0:
            return BAD
        i=i+8
    zero(o,128,8192-128)
    zero(o,CHILD,128)
    put(o,PHASE,1)
    return 1

def handles_ok(o:mutbuf) -> bool:
    return get(o,FEEDBACK)==0 and get(o,CHILD)==HREPLY and get(o,CHILD+8)==0

def dependency(s:readbuf,o:mutbuf) -> u32:
    status=5
    if get(o,FEEDBACK)==0 and get(o,CHILD)==HREPLY:
        child=get(o,CHILD+8)
        if child==1 or child==3:
            status=1
        elif child==4:
            status=2
        elif child==5:
            status=3
    return finish(s,o,status,0,0)

def invoke(o:mutbuf,next:u64,n:u64) -> u32:
    zero(o,CHILD,128)
    put(o,0,n)
    put(o,PHASE,next)
    return 12

def finish(s:readbuf,o:mutbuf,status:u64,kind:u64,error:u64) -> u32:
    zero(o,0,128)
    put(o,0,REPLY)
    put(o,8,status)
    put(o,16,kind)
    if kind==1:
        copy_source(s,o,16,24,24)
    elif kind==2:
        within(o,24,CHILD+24,24)
    put(o,48,error)
    put(o,64,get(o,CHILD+48))
    put(o,72,get(o,CHILD+88))
    put(o,80,get(o,CHILD+72))
    put(o,88,get(o,CHILD+80))
    if error!=0:
        put(o,56,error_text(o,error))
    return 0

def get(w:mutbuf,at:u64) -> u64:
    return word_load(w,at)
def put(w:mutbuf,at:u64,value:u64) -> u64:
    i=0
    while i<8:
        store(w,at+i,(value>>(i*8))&255)
        i=i+1
    return 0
def zero(w:mutbuf,at:u64,n:u64) -> u64:
    fill_range(w,at,n,0)
    return 0
def copy_source(s:readbuf,o:mutbuf,at:u64,to:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(o,to+i,byte(s,at+i))
        i=i+1
    return 0
def within(w:mutbuf,to:u64,at:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(w,to+i,byte(w,at+i))
        i=i+1
    return 0
'''
def source_program():
    source=SOURCE+'\ndef error_text(o:mutbuf,error:u64) -> u64:\n'
    for key,message in ERRORS.items():
        raw=json.dumps({'class':'MultiversionRejected','message':message},
            separators=(',',':'),sort_keys=True).encode()
        source+=f'    if error=={key}:\n'
        for i in range(0,len(raw),8):
            source+=f'        put(o,{128+i},{int.from_bytes(raw[i:i+8].ljust(8,bytes(1)),"little")})\n'
        source+=f'        return {len(raw)}\n'
    source+='    return 0\n'
    for key,value in sorted(C.items(),key=lambda item:-len(item[0])):
        source=re.sub(r'\b'+key+r'\b',str(value),source)
    return source
def main():
    doc=document(source_program(),'generation_lease_public_lifecycle')
    path=ROOT/'examples/hia_bootstrap/generation_lease_public_lifecycle.hepta'
    path.write_text(render_assembly(doc))
    print(path.name,path.stat().st_size)
if __name__=='__main__':
    main()
