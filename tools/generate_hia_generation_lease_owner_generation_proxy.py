"""Thin fixed generation proxy with native per-generation component custody.

All normal GX1/GX2/GX3 policy executes in the admitted installed child.
The independent close entry is called before the real runtime frees a GEN
workspace, including failed intake and partially initialized child bindings.
"""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_multiversion_intake import SOURCE as HELPERS
ROOT=Path(__file__).resolve().parents[1]
C=dict(Q=int.from_bytes(b'HIAMVGX1','little'),Q2=int.from_bytes(b'HIAMVGX2','little'),Q3=int.from_bytes(b'HIAMVGX3','little'),
 R=int.from_bytes(b'HIAMVGD1','little'),CQ=int.from_bytes(b'HIAGPBQ1','little'),CR=int.from_bytes(b'HIAGPBR1','little'),
 BQ=int.from_bytes(b'HIAGPBO1','little'),TAG=int.from_bytes(b'HIAGPXW1','little'),
 CT=509<<20,PH=509<<20,FB=(509<<20)+8,MODE=(509<<20)+16,STATE=(509<<20)+24,
 SELF=(509<<20)+32,PID=(509<<20)+40,ENTRY=(509<<20)+48,PTAG=(509<<20)+56,PARENT=(509<<20)+64,
 PASS=(509<<20)+72,FAIL=(509<<20)+80,STARTED=(509<<20)+88,
 COMPONENT=511<<20,FRAME=508<<20,WORK=512<<20,BAD=4294967293,NONE=(1<<64)-1)
SOURCE=r'''
def proxy(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase=get(w,PH)
    if phase==0:
        if get(w,MODE)==1:
            return close(s,o,w)
        return begin(s,o,w)
    if phase==1:
        put(w,PARENT,get(w,FB))
        if get(w,PARENT)==0:
            return failed_begin(o,w,1)
        zero(w,FRAME,16)
        put(w,FRAME,BQ)
        put(w,PH,2)
        return 3
    if phase==2:
        if get(w,FB)!=0:
            return failed_begin(o,w,get(w,FB))
        put(w,STATE,2)
        put(w,PH,3)
        return 4
    if phase==3:
        raw=get(w,FB)
        if raw==BAD:
            return BAD
        put(w,PASS,raw)
        if get(o,0)!=R or get(o,8)!=raw or raw>10:
            put(w,STATE,5)
        put(w,PH,0)
        return 6
    if phase==4:
        raw=get(w,FB)
        if raw==BAD:
            return BAD
        put(w,PASS,raw)
        if raw==0 and get(o,0)==CR and get(o,88)==1 and get(o,104)==1 and get(o,80)==0:
            put(w,STATE,4)
        put(w,PH,0)
        return 6
    return BAD

def begin(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if valid(s)==False:
        return BAD
    op=readword(s,8)
    if op==0:
        if get(w,PTAG)!=0 or get(w,COMPONENT+16)!=0:
            return BAD
        i=24
        while i<4096:
            if i!=96 and get(w,CT+i)!=0:
                return BAD
            i=i+8
        put(w,PTAG,TAG)
        put(w,STATE,1)
        put(w,STARTED,1)
        put(w,PH,1)
        return 2
    if get(w,PTAG)!=TAG or get(w,STATE)!=2:
        return BAD
    put(w,PH,3)
    return 4

def valid(s:readbuf) -> bool:
    if length(s)<256:
        return False
    magic=readword(s,0)
    if magic!=Q and magic!=Q2 and magic!=Q3:
        return False
    op=readword(s,8)
    if op>6:
        return False
    if op!=0:
        if magic!=Q or length(s)!=256:
            return False
        i=16
        while i<256:
            if readword(s,i)!=0:
                return False
            i=i+8
        return True
    raw=readword(s,80)
    base=readword(s,88)
    abi=readword(s,96)
    path=readword(s,104)
    if raw>8388608 or base>8388608 or abi>5136 or path==0 or path>4095:
        return False
    if raw>length(s)-256 or base>length(s)-256-raw or abi>length(s)-256-raw-base or path!=length(s)-256-raw-base-abi:
        return False
    if readword(s,40)==0 or readword(s,40)>30000 or readword(s,48)==0 or readword(s,56)==0:
        return False
    if readword(s,64)>1 or readword(s,72)>1 or readword(s,112)!=0 or readword(s,120)!=0:
        return False
    i=224
    if magic==Q3:
        if readword(s,224)==0:
            return False
        i=248
    while i<256:
        if readword(s,i)!=0:
            return False
        i=i+8
    i=16
    while i<40:
        fd=readword(s,i)
        if fd<3 or fd>2147483647:
            return False
        i=i+8
    baseline=readword(s,72)
    if magic==Q2 and baseline!=1:
        return False
    if (baseline==1 and (base!=0 or abi!=0)) or (baseline==0 and (base==0 or abi<336)):
        return False
    at=256+raw+base+abi
    if byte(s,at)!=47:
        return False
    i=0
    while i<path:
        if byte(s,at+i)==0:
            return False
        i=i+1
    return True

def close(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=128 or readword(s,0)!=CQ or readword(s,8)!=1:
        return BAD
    i=16
    while i<128:
        if readword(s,i)!=0:
            return BAD
        i=i+8
    if get(w,COMPONENT+16)==0:
        i=0
        while i<4096:
            if get(w,COMPONENT+i)!=0:
                return BAD
            i=i+8
        if get(w,PTAG)!=0 and (get(w,PTAG)!=TAG or get(w,STATE)!=1):
            return BAD
        zero(o,0,128)
        put(o,0,CR)
        put(o,16,4)
        put(o,88,1)
        put(o,104,1)
        if get(w,PTAG)==TAG:
            put(w,STATE,4)
        put(w,PH,0)
        return 0
    if get(w,PTAG)!=TAG:
        return BAD
    put(w,PH,4)
    return 5

def failed_begin(o:mutbuf,w:mutbuf,raw:u64) -> u32:
    put(w,FAIL,raw)
    zero(o,0,4096)
    put(o,0,R)
    put(o,8,10)
    put(o,16,7)
    put(o,32,raw)
    put(o,96,NONE)
    put(o,104,NONE)
    put(w,PH,0)
    put(w,PASS,10)
    return 6
'''
SOURCE+='\n'+HELPERS[HELPERS.index('def zero('):]
def source_program():
    s=SOURCE
    for k,v in sorted(C.items(),key=lambda x:-len(x[0])):s=re.sub(r'\b'+k+r'\b',str(v),s)
    return s
def main():
    tree=document(source_program(),'generation_lease_owner_generation_proxy')
    path=ROOT/'examples/hia_bootstrap/generation_lease_owner_generation_proxy.hepta'
    path.write_text(render_assembly(tree))
    print(path.name,path.stat().st_size,len(tree['functions']),sum(len(f['blocks'])for f in tree['functions']),sum(len(b['ops'])for f in tree['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
