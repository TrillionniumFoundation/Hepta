"""HIA exact-type classification for public proof arguments.

Opaque value handles are only returned to their owner; this component never
follows them or treats them as executable authority. JSON adapters derive these
tags from the actual decoded JSON value, and native callers from actual types.
"""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_system_jobctl_request import document
ROOT=Path(__file__).resolve().parents[1]
C={'REQUEST':int.from_bytes(b'HIAPTV01','little'),'REPLY':int.from_bytes(b'HIAPTR01','little'),'BAD':0xfffffffd}
SOURCE=r'''
def classify(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)<64 or length(o)<96 or uint(s,0)!=REQUEST:
        return BAD
    maximum=uint(s,8)
    timeout_kind=uint(s,16)
    magnitude=uint(s,24)
    function_kind=uint(s,40)
    text=uint(s,56)
    if maximum==0 or maximum>60000 or timeout_kind>3 or function_kind>2:
        return BAD
    if text!=length(s)-64 or (function_kind!=1 and text!=0):
        return BAD
    valid_timeout=timeout_kind==0 and magnitude>=1 and magnitude<=maximum
    selected=0
    name=0
    if function_kind==1:
        selected=2
        if identifier(s,64,text):
            selected=1
            name=text
    if function_kind==2:
        selected=3
    if name>length(o)-96:
        return BAD
    put(o,0,REPLY)
    put(o,8,choose(valid_timeout,1,0))
    put(o,16,choose(valid_timeout,magnitude,0))
    put(o,24,uint(s,32))
    put(o,32,selected)
    put(o,40,uint(s,48))
    put(o,48,name)
    put(o,56,timeout_kind)
    put(o,64,function_kind)
    put(o,72,0)
    put(o,80,0)
    put(o,88,0)
    i=0
    while i<name:
        store(o,96+i,byte(s,64+i))
        i=i+1
    return 96+name

def identifier(s:readbuf,at:u64,n:u64) -> bool:
    if n==0 or n>128 or at>length(s) or n>length(s)-at:
        return False
    i=0
    while i<n:
        c=byte(s,at+i)
        if ((c>=65 and c<=90) or (c>=97 and c<=122) or c==95 or (i!=0 and c>=48 and c<=57))==False:
            return False
        i=i+1
    return True

def choose(flag:bool,a:u64,b:u64) -> u64:
    if flag:
        return a
    return b

def uint(s:readbuf,at:u64) -> u64:
    value=0
    i=0
    while i<8:
        value=value|(byte(s,at+i)<<(i*8))
        i=i+1
    return value

def put(o:mutbuf,at:u64,value:u64) -> u64:
    i=0
    while i<8:
        store(o,at+i,(value>>(i*8))&255)
        i=i+1
    return 0
'''
def source_program():
    text=SOURCE
    for name,value in C.items():text=re.sub(r'\b'+name+r'\b',str(value),text)
    return document(text,'public_proof_typed')
if __name__=='__main__':
    p=ROOT/'examples/hia_bootstrap/public_proof_typed.hepta';d=source_program();p.write_text(render_assembly(d));print(p.name,p.stat().st_size,len(d['functions']),sum(len(f['blocks']) for f in d['functions']))
