"""Actual captured Core -> admission/canonical identities/scalar profile/ABI.

All companion calls are selected by HIA. This private preparation stage does
not grant totality, translation, publication or native execution authority.
"""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
ROOT=Path(__file__).resolve().parents[1]
C={'INPUT_MAGIC':int.from_bytes(b'HIAMVIT1','little'),'OUTPUT_MAGIC':int.from_bytes(b'HIAMVIP1','little'),'ABI_MAGIC':int.from_bytes(b'HIAMVAB1','little'),'CORE_MAX':8<<20,'WORK_BYTES':160<<20,'RAW':1<<20,'CANON':9<<20,'FACTS':17<<20,'ABI':26<<20,'DECISION':512<<10,'ROLE_OUT':32<<20,'ROLE_WORK':96<<20,'RAW_SHA':512,'CORE_SHA':544,'ABI_SHA':576,'HASH_WORK':65536,'RAW_N':256,'CANON_N':264,'FACT_N':272,'ABI_N':280,'TOTAL':288}
SOURCE=r'''
def intake(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)<64 or length(o)<256 or length(w)<WORK_BYTES:
        return 4294967293
    if readword(s,0)!=INPUT_MAGIC or readword(s,8)>1 or readword(s,16)>CORE_MAX:
        return 4294967293
    if length(s)-64!=readword(s,16):
        return 4294967293
    i=24
    while i<64:
        if readword(s,i)!=0:
            return 4294967293
        i=i+8
    phase=get(w,0)
    if phase==0:
        zero(w,64,1024)
        put(w,RAW_N,readword(s,16))
        put(w,TOTAL,readword(s,8))
        copy_input(s,64,w,RAW,get(w,RAW_N))
        zero(w,HASH_WORK,1184)
        return role(w,1,4,RAW,get(w,RAW_N),RAW_SHA,32,HASH_WORK,1184)
    if phase==1:
        if get(w,8)!=32:
            return finish(o,w,5,get(w,8))
        zero(w,ROLE_OUT,512)
        zero(w,ROLE_WORK,512)
        return role(w,2,2,RAW,get(w,RAW_N),ROLE_OUT,67108864,ROLE_WORK,33554432)
    if phase==2:
        if get(w,8)!=0:
            return finish(o,w,1,get(w,8))
        zero(w,ROLE_WORK,512)
        put(w,ROLE_WORK+48,262144)
        put(w,ROLE_WORK+56,64)
        return role(w,3,3,RAW,get(w,RAW_N),CANON,CORE_MAX,ROLE_WORK,33554432)
    if phase==3:
        size=get(w,8)
        if size==0 or size>CORE_MAX:
            return finish(o,w,2,size)
        put(w,CANON_N,size)
        zero(w,HASH_WORK,1184)
        return role(w,4,4,CANON,size,CORE_SHA,32,HASH_WORK,1184)
    if phase==4:
        if get(w,8)!=32:
            return finish(o,w,5,get(w,8))
        return profile(w,5,0)
    if phase==5:
        size=get(w,8)
        if size<64 or size>CORE_MAX:
            return finish(o,w,3,size)
        zero(w,ROLE_WORK,8192)
        zero(w,DECISION,144)
        return role(w,6,6,ROLE_OUT,size,DECISION,144,ROLE_WORK,8192)
    if phase==6:
        if get(w,8)!=17:
            return finish(o,w,3,get(w,8))
        return profile(w,7,1)
    if phase==7:
        size=get(w,8)
        if size<64 or size>CORE_MAX:
            return finish(o,w,3,size)
        copy(w,ROLE_OUT,FACTS,size)
        put(w,FACT_N,size)
        zero(w,ROLE_WORK,8192)
        zero(w,DECISION,144)
        return role(w,8,6,FACTS,size,DECISION,144,ROLE_WORK,8192)
    if phase==8:
        if get(w,8)!=0:
            return finish(o,w,3,get(w,8))
        zero(w,ROLE_WORK,8192)
        copy(w,DECISION,ROLE_WORK,144)
        return role(w,9,7,FACTS,get(w,FACT_N),ABI,8192,ROLE_WORK,8192)
    if phase==9:
        size=get(w,8)
        if size<16 or size>5136:
            return finish(o,w,4,size)
        if get(w,ABI)!=ABI_MAGIC or get(w,ABI+8)==0 or get(w,ABI+8)>16:
            return finish(o,w,4,size)
        if size!=16+get(w,ABI+8)*320:
            return finish(o,w,4,size)
        put(w,ABI_N,size)
        zero(w,HASH_WORK,1184)
        return role(w,10,4,ABI,size,ABI_SHA,32,HASH_WORK,1184)
    if phase==10:
        if get(w,8)!=32:
            return finish(o,w,5,get(w,8))
        need=256+get(w,CANON_N)+get(w,ABI_N)
        if need>length(o):
            return finish(o,w,6,need)
        return finish(o,w,0,0)
    return 4294967293

def profile(w:mutbuf,next:u64,phase:u64) -> u32:
    zero(w,ROLE_WORK,512)
    zero(w,ROLE_OUT,512)
    put(w,ROLE_OUT,get(w,TOTAL))
    put(w,ROLE_OUT+8,phase)
    put(w,ROLE_OUT+16,0)
    return role(w,next,5,CANON,get(w,CANON_N),ROLE_OUT,CORE_MAX,ROLE_WORK,33554432)

def role(w:mutbuf,next:u64,action:u64,si:u64,sn:u64,oi:u64,on:u64,wi:u64,wn:u64) -> u32:
    put(w,0,next)
    put(w,16,si)
    put(w,24,sn)
    put(w,32,oi)
    put(w,40,on)
    put(w,48,wi)
    put(w,56,wn)
    return action

def finish(o:mutbuf,w:mutbuf,status:u64,detail:u64) -> u32:
    zero(o,0,256)
    put(o,0,OUTPUT_MAGIC)
    put(o,8,status)
    put(o,16,detail)
    put(o,24,get(w,RAW_N))
    put(o,32,get(w,CANON_N))
    put(o,40,get(w,ABI_N))
    put(o,56,get(w,TOTAL))
    copy_output(w,RAW_SHA,o,64,32)
    copy_output(w,CORE_SHA,o,96,32)
    copy_output(w,CORE_SHA,o,128,32)
    copy_output(w,ABI_SHA,o,160,32)
    if status==0:
        put(o,48,get(w,ABI+8))
        put(o,192,7)
        copy_output(w,CANON,o,256,get(w,CANON_N))
        copy_output(w,ABI,o,256+get(w,CANON_N),get(w,ABI_N))
    put(w,128,status)
    return 0

def zero(w:mutbuf,at:u64,size:u64) -> u64:
    i=0
    while i<size:
        store(w,at+i,0)
        i=i+1
    return 0

def copy_input(s:readbuf,si:u64,w:mutbuf,wi:u64,size:u64) -> u64:
    i=0
    while i<size:
        store(w,wi+i,byte(s,si+i))
        i=i+1
    return 0

def copy(w:mutbuf,si:u64,oi:u64,size:u64) -> u64:
    i=0
    while i<size:
        store(w,oi+i,byte(w,si+i))
        i=i+1
    return 0

def copy_output(w:mutbuf,si:u64,o:mutbuf,oi:u64,size:u64) -> u64:
    i=0
    while i<size:
        store(o,oi+i,byte(w,si+i))
        i=i+1
    return 0

def readword(s:readbuf,at:u64) -> u64:
    value=0
    i=0
    while i<8:
        value=value|(byte(s,at+i)<<(i*8))
        i=i+1
    return value

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
'''
def source_program():
    text=SOURCE
    for name,value in sorted(C.items(),key=lambda x:-len(x[0])):text=re.sub(r'\b'+name+r'\b',str(value),text)
    return text

def main():
    tree=document(source_program(),'multiversion_intake');p=ROOT/'examples/hia_bootstrap/multiversion_intake.hepta';p.write_text(render_assembly(tree));print(p.name,p.stat().st_size,len(tree['functions']),sum(len(f['blocks']) for f in tree['functions']),flush=True)
if __name__=='__main__':main()
