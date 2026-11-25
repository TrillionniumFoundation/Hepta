"""HIA full finite VM/native probes for an admitted captured generation.

This is private preparation code. The enclosing native preparation owner binds
the canonical Core and actual build receipt. No finite observation substitutes
for fresh totality or translation proof.
"""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
ROOT=Path(__file__).resolve().parents[1]
C={'NONE':(1<<64)-1,'IMAGE_MAGIC':int.from_bytes(b'HIAMVIS1','little'),'ABI_MAGIC':int.from_bytes(b'HIAMVAB1','little'),
 'VECTORS_MAGIC':int.from_bytes(b'HIAMVPV1','little'),'WIRE_MAGIC':int.from_bytes(b'HIAERW01','little'),
 'VM_MAGIC':int.from_bytes(b'HIASPG01','little'),'VM_REPLY':int.from_bytes(b'HIASPR01','little'),
 'RESULT_MAGIC':int.from_bytes(b'HIAMVPR1','little'),
 'PHASE':4608,'INDEX':4616,'VECTOR':4624,'VCOUNT':4632,'ARGC':4640,'RESULT_TYPE':4648,'END':4656,'REGS':4664,'BOUNCE':4672,
 'CALLS':4680,'STEPS':4688,'TOTAL_STEPS':4696,'EXPECTED':4704,'ACTUAL':4712,'RETURNED':4720,'SOURCE_N':4728,'ERROR':4736,'VM_CAP':4744,
 'VOUT':1<<20,'VWORK':2<<20,'VMOUT':3<<20,'ARGS':(3<<20)+128,'RINPUT':8<<20,'ROUT':24<<20,'RWORK':64<<20,'VMWORK':112<<20}
SOURCE=r'''
def multiversion_probe_owner(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(o)<128 or length(w)<167772160 or length(s)==0 or length(s)>8388608:
        return 4294967293
    phase=get(w,PHASE)
    if phase==0:
        if get(w,16)!=IMAGE_MAGIC or get(w,0)!=999 or get(w,112)!=1 or get(w,120)!=0 or get(w,48)==NONE or get(w,56)==0:
            return 4294967293
        if get(w,65536)!=ABI_MAGIC or get(w,65544)!=get(w,80) or get(w,80)==0 or get(w,80)>16:
            return 4294967293
        put(w,INDEX,0)
        put(w,CALLS,0)
        put(w,TOTAL_STEPS,0)
        put(w,EXPECTED,0)
        put(w,ACTUAL,0)
        put(w,ERROR,0)
        return system(o,w,1,39)
    if phase==1:
        if get(w,8)!=get(w,24) or get(w,8)==0:
            return finish(o,w,1)
        return next_function(o,w)
    if phase==2:
        result=get(w,8)
        if result<304 or result>21808 or get(w,VOUT)!=VECTORS_MAGIC:
            return finish(o,w,2)
        count=get(w,VOUT+8)
        argc=get(w,VOUT+16)
        typ=get(w,VOUT+24)
        if count==0 or count>168 or result!=304+count*128 or argc>16 or typ==0 or typ>11:
            return finish(o,w,2)
        put(w,VCOUNT,count)
        put(w,ARGC,argc)
        put(w,RESULT_TYPE,typ)
        put(w,VECTOR,0)
        return project(s,o,w)
    if phase==3:
        result=get(w,8)
        if result<72 or result>33554432 or get(w,ROUT)!=WIRE_MAGIC:
            return finish(o,w,3)
        registers=get(w,ROUT+8)
        bounce=get(w,ROUT+16)
        end=get(w,ROUT+24)
        if registers>524288 or bounce>524288-registers or end<64 or end>33554432-128:
            return finish(o,w,3)
        if get(w,ROUT+32)!=1 or result!=end+8 or get(w,ROUT+40)!=0 or get(w,ROUT+48)!=0 or get(w,ROUT+56)!=0:
            return finish(o,w,3)
        if vm_type(get(w,RESULT_TYPE))!=get(w,ROUT+end):
            return finish(o,w,4)
        put(w,REGS,registers)
        put(w,BOUNCE,bounce)
        put(w,END,end)
        put(w,ROUT,VM_MAGIC)
        put(w,ROUT+8,4224)
        put(w,ROUT+16,256)
        put(w,ROUT+24,registers)
        put(w,ROUT+32,bounce)
        put(w,ROUT+40,end)
        put(w,ROUT+48,get(w,ARGC))
        put(w,ROUT+56,1)
        return next_vector(o,w)
    if phase==4:
        raw=get(w,8)
        if raw==32 and get(w,VMOUT)==VM_REPLY and get(w,VMOUT+8)==14:
            needed=get(w,VMOUT+24)
            maximum=64+256*8*(get(w,REGS)+get(w,BOUNCE)+1)
            if needed<=get(w,VM_CAP) or needed>maximum or needed>50331648 or get(w,VMOUT+16)>4224:
                return finish(o,w,5)
            put(w,VM_CAP,needed)
            return role(o,w,4,4,ROUT,get(w,END)+8*get(w,ARGC),VMOUT,40,VMWORK,needed)
        if raw!=40 or get(w,VMOUT)!=VM_REPLY or get(w,VMOUT+8)!=0 or get(w,VMOUT+16)>4224:
            return finish(o,w,5)
        expected=get(w,VMOUT+32)
        if get(w,RESULT_TYPE)==1 and expected>1:
            return finish(o,w,5)
        put(w,EXPECTED,expected&mask(width(get(w,RESULT_TYPE))))
        put(w,STEPS,get(w,VMOUT+16))
        put(w,TOTAL_STEPS,get(w,TOTAL_STEPS)+get(w,STEPS))
        pointer=get(w,2048+get(w,INDEX)*8)
        if pointer==0:
            return finish(o,w,6)
        put(w,PHASE,5)
        put(o,0,pointer)
        put(o,8,ARGS)
        return 5
    if phase==5:
        actual=get(w,8)
        typ=get(w,RESULT_TYPE)
        if typ==1:
            actual=choose((actual&255)!=0,1,0)
        else:
            actual=actual&mask(width(typ))
        put(w,ACTUAL,actual)
        put(w,CALLS,get(w,CALLS)+1)
        if actual!=get(w,EXPECTED):
            return finish(o,w,7)
        put(w,VECTOR,get(w,VECTOR)+1)
        if get(w,VECTOR)<get(w,VCOUNT):
            return next_vector(o,w)
        put(w,INDEX,get(w,INDEX)+1)
        return next_function(o,w)
    return finish(o,w,8)

def next_function(o:mutbuf,w:mutbuf) -> u32:
    index=get(w,INDEX)
    if index>=get(w,80):
        return finish(o,w,0)
    put(w,VOUT,index)
    return role(o,w,2,2,65536,16+get(w,80)*320,VOUT,21808,VWORK,32768)

def project(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    n=get(w,VOUT+40)
    if n==0 or n>128:
        return finish(o,w,2)
    i=0
    while i<n:
        ch=byte(w,VOUT+48+i)
        if (ch<65 or ch>90) and (ch<97 or ch>122) and ch!=95:
            if i==0 or ch<48 or ch>57:
                return finish(o,w,2)
        i=i+1
    store(w,RINPUT,91)
    i=0
    while i<length(s):
        store(w,RINPUT+1+i,byte(s,i))
        i=i+1
    at=RINPUT+1+length(s)
    store(w,at,44)
    store(w,at+1,34)
    i=0
    while i<n:
        store(w,at+2+i,byte(w,VOUT+48+i))
        i=i+1
    at=at+2+n
    store(w,at,34)
    store(w,at+1,44)
    store(w,at+2,48)
    store(w,at+3,93)
    put(w,SOURCE_N,at+4-RINPUT)
    return role(o,w,3,3,RINPUT,get(w,SOURCE_N),ROUT,33554432,RWORK,50331648)

def next_vector(o:mutbuf,w:mutbuf) -> u32:
    i=0
    while i<16:
        value=get(w,VOUT+304+get(w,VECTOR)*128+i*8)
        if i<get(w,ARGC):
            typ=get(w,VOUT+176+i*8)
            value=parameter(value,typ)
            put(w,ROUT+get(w,END)+i*8,value)
        else:
            value=0
        put(w,ARGS+i*8,value)
        i=i+1
    i=0
    while i<64:
        store(w,VMWORK+i,0)
        i=i+1
    put(w,VM_CAP,64+8*(get(w,REGS)+get(w,BOUNCE)+1))
    return role(o,w,4,4,ROUT,get(w,END)+8*get(w,ARGC),VMOUT,40,VMWORK,get(w,VM_CAP))

def parameter(value:u64,typ:u64) -> u64:
    bits=width(typ)
    value=value&mask(bits)
    if typ==2 or typ==4 or typ==6:
        if (value&(1<<(bits-1)))!=0:
            value=value|(18446744073709551615^mask(bits))
    return value

def width(typ:u64) -> u64:
    if typ==1:
        return 1
    if typ==2 or typ==3:
        return 8
    if typ==4 or typ==5:
        return 16
    if typ==6 or typ==7:
        return 32
    return 64

def mask(bits:u64) -> u64:
    if bits==64:
        return 18446744073709551615
    return (1<<bits)-1

def vm_type(typ:u64) -> u64:
    if typ==1:
        return 0
    if typ==2:
        return 2
    if typ==3:
        return 6
    if typ==4:
        return 3
    if typ==5:
        return 7
    if typ==6:
        return 4
    if typ==7:
        return 8
    if typ==8:
        return 5
    if typ==9:
        return 9
    if typ==10:
        return 10
    if typ==11:
        return 11
    return 18446744073709551615

def finish(o:mutbuf,w:mutbuf,status:u64) -> u32:
    i=0
    while i<128:
        store(o,i,0)
        i=i+1
    put(o,0,RESULT_MAGIC)
    put(o,8,status)
    put(o,16,get(w,INDEX))
    put(o,24,get(w,VECTOR))
    put(o,32,get(w,EXPECTED))
    put(o,40,get(w,ACTUAL))
    put(o,48,get(w,STEPS))
    put(o,56,get(w,CALLS))
    put(o,64,get(w,TOTAL_STEPS))
    put(o,72,get(w,8))
    put(w,PHASE,0)
    return 0

def role(o:mutbuf,w:mutbuf,phase:u64,action:u64,source:u64,size:u64,output:u64,capacity:u64,work:u64,workspace:u64) -> u32:
    put(w,PHASE,phase)
    put(o,0,source)
    put(o,8,size)
    put(o,16,output)
    put(o,24,capacity)
    put(o,32,work)
    put(o,40,workspace)
    return action

def system(o:mutbuf,w:mutbuf,phase:u64,number:u64) -> u32:
    put(w,PHASE,phase)
    put(o,0,number)
    i=8
    while i<64:
        put(o,i,0)
        i=i+8
    return 1

def get(w:mutbuf,at:u64) -> u64:
    value=0
    i=0
    while i<8:
        value=value|(byte(w,at+i)<<(i*8))
        i=i+1
    return value
def put(w:mutbuf,at:u64,value:u64) -> u64:
    i=0
    while i<8:
        store(w,at+i,(value>>(i*8))&255)
        i=i+1
    return 0
def choose(test:bool,yes:u64,no:u64) -> u64:
    if test:
        return yes
    return no
'''
def source_program():
    s=SOURCE
    for name,value in sorted(C.items(),key=lambda x:-len(x[0])):s=re.sub(r'\b'+name+r'\b',str(value),s)
    return s
def main():
    t=document(source_program(),'multiversion_probe_owner');p=ROOT/'examples/hia_bootstrap/multiversion_probe_owner.hepta';p.write_text(render_assembly(t));print(p.name,p.stat().st_size,len(t['functions']),sum(len(f['blocks']) for f in t['functions']),flush=True)
if __name__=='__main__':main()
