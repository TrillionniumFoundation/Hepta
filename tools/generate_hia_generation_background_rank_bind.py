"""Fixed BG binding with a separately admitted public rank-proof executable.

The existing global scalar-proof bank remains unchanged. This profile owns an
additional native resource context and a real borrow until all BG work retires.
"""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools import generate_hia_generation_background_bind as original
ROOT=Path(__file__).resolve().parents[1]
C=dict(original.C)
C.update(PROOF_ENTRY=2097728,PROOF_Q=int.from_bytes(b"HIABPRQ1","little"),
 PROOF_R=int.from_bytes(b"HIABPRR1","little"),PROOF_TAG=int.from_bytes(b"HIABPRW1","little"),
 PROOF_WORK=original.C["M"]+368,PROOF_N=original.C["M"]+376,
 PROOF_STATE=original.C["M"]+384,PROOF_PENDING=original.C["M"]+392,
 PROOF_CAP=original.C["M"]+400,PROOF_FD=original.C["M"]+424,
 BOUND_PROOF=original.C["M"]+432,PROOF_NONCE=original.C["M"]+440)
def change(text,old,new):
    assert text.count(old)==1,(old[:100],text.count(old))
    return text.replace(old,new)
def source_template():
    s=original.SOURCE
    s=change(s,"def background_bind(","def background_rank_bind(")
    s=change(s,"    if phase>=100 and phase<200:\n        return closing(s,o,w,phase,r)",
        "    if phase>=170 and phase<=177:\n        return proof_closing(s,o,w,phase,r)\n"
        "    if phase>=100 and phase<200:\n        return closing(s,o,w,phase,r)")
    s=change(s,"    if get(o,at+48)<1 or get(o,at+48)>5 or get(o,at+64)>1:",
        "    if get(o,at+432)!=get(o,PROOF_ENTRY):\n        return 0\n"
        "    if get(o,at+368)!=0 and (get(o,at+376)!=8388608 or get(o,at+368)>NONE-8388608):\n        return 0\n"
        "    if get(o,at+384)>3 or get(o,at+392)>1:\n        return 0\n"
        "    if get(o,at+48)<1 or get(o,at+48)>5 or get(o,at+64)>1:")
    s=change(s,"    put(o,BOUND_VALUE,get(o,VALUE_ENTRY))",
        "    put(o,BOUND_VALUE,get(o,VALUE_ENTRY))\n    put(o,BOUND_PROOF,get(o,PROOF_ENTRY))")
    old="""        put(o,LSTARTED,1)
        put(o,STAGE,30)
        return loader_call(o,30,0)"""
    new="""        put(o,STAGE,24)
        return system(o,24,9,0,0,8388608,3,34,NONE,0)
    if phase==24:
        if r==0 or failed(r):
            return initial_fail(o,w,1,r)
        put(o,PROOF_WORK,r)
        put(o,PROOF_N,8388608)
        put(o,PROOF_STATE,1)
        return proof_call(o,25,0)
    if phase==25:
        if proof_reply(o,r)==0 or get(o,CHILD+88)!=1:
            return quarantine(o,w,25)
        put(o,PROOF_PENDING,get(o,CHILD+80))
        if get(o,CHILD+104)==1:
            put(o,PROOF_STATE,3)
        if get(o,CHILD+8)!=0 or get(o,CHILD+16)!=2 or get(o,CHILD+80)!=0:
            return initial_fail(o,w,get(o,CHILD+8),get(o,CHILD+112))
        put(o,PROOF_STATE,2)
        return proof_call(o,26,2)
    if phase==26:
        if proof_reply(o,r)==0 or get(o,CHILD+88)!=1:
            return quarantine(o,w,26)
        if get(o,CHILD+96)==1:
            if cap_shape(o,CHILD+24)==0:
                return quarantine(o,w,27)
            within(o,PROOF_CAP,CHILD+24,24)
        put(o,PROOF_PENDING,get(o,CHILD+80))
        if get(o,CHILD+8)!=0 or get(o,CHILD+80)!=0 or get(o,PROOF_CAP)==0:
            return initial_fail(o,w,get(o,CHILD+8),get(o,CHILD+112))
        if get(o,CHILD+48)<3 or get(o,CHILD+48)>2147483647 or get(o,CHILD+152)==0:
            return quarantine(o,w,28)
        put(o,PROOF_FD,get(o,CHILD+48))
        put(o,PROOF_NONCE,get(o,CHILD+152))
        put(o,LSTARTED,1)
        put(o,STAGE,30)
        return loader_call(o,30,0)"""
    s=change(s,old,new)
    s=change(s,"        within(o,FRAME+32,TOOLS,24)",
        "        within(o,FRAME+32,TOOLS,24)\n        put(o,FRAME+40,get(o,PROOF_FD))")
    s=change(s,"    if phase==140:\n        if get(o,GCAP)!=0:",
        "    if phase==140:\n        if get(o,PROOF_WORK)!=0:\n            return proof_close(o,w)\n"
        "        if get(o,GCAP)!=0:")
    return s+EXTRA
EXTRA=r'''
def proof_call(o:mutbuf,next:u64,op:u64) -> u32:
    zero(o,FRAME,128)
    put(o,FRAME,PROOF_Q)
    put(o,FRAME+8,op)
    if op==3:
        within(o,FRAME+24,PROOF_CAP,24)
    return role(o,next,16)

def proof_reply(o:mutbuf,r:u64) -> u64:
    if r!=0 or get(o,CHILD)!=PROOF_R:
        return 0
    if get(o,CHILD+80)>1 or get(o,CHILD+88)>1 or get(o,CHILD+96)>1 or get(o,CHILD+104)>1:
        return 0
    return 1

def proof_close(o:mutbuf,w:mutbuf) -> u32:
    if get(o,PROOF_CAP)!=0:
        return proof_call(o,170,3)
    return again(o,171)

def proof_closing(s:readbuf,o:mutbuf,w:mutbuf,phase:u64,r:u64) -> u32:
    if phase==170:
        if proof_reply(o,r)==0 or get(o,CHILD+88)!=1:
            return quarantine(o,w,170)
        if get(o,CHILD+96)==1:
            zero(o,PROOF_CAP,24)
        put(o,PROOF_PENDING,get(o,CHILD+80))
        if get(o,PROOF_CAP)!=0:
            return parked(o,w,get(o,CHILD+8),170)
        return again(o,171)
    if phase==171:
        if get(o,PROOF_STATE)==1:
            return memory(o,174,0,get(o,PROOF_WORK),3,SNAP,4096)
        if get(o,PROOF_STATE)!=0 and get(o,PROOF_STATE)!=3:
            if get(o,PROOF_PENDING)!=0:
                return proof_call(o,172,4)
            return proof_call(o,172,1)
        return again(o,175)
    if phase==172:
        if proof_reply(o,r)==0 or get(o,CHILD+88)!=1:
            return quarantine(o,w,172)
        put(o,PROOF_PENDING,get(o,CHILD+80))
        if get(o,CHILD+104)==1 and get(o,CHILD+80)==0:
            put(o,PROOF_STATE,3)
            put(o,PROOF_FD,0)
            put(o,PROOF_NONCE,0)
            return again(o,175)
        if get(o,CHILD+8)==0 and get(o,CHILD+80)==0 and get(o,CHILD+16)==2:
            return proof_call(o,172,1)
        return parked(o,w,get(o,CHILD+8),173)
    if phase==174:
        if r!=0:
            return quarantine(o,w,174)
        if get(o,SNAP)==0:
            i=0
            while i<4096:
                if get(o,SNAP+i)!=0:
                    return quarantine(o,w,174)
                i=i+8
            put(o,PROOF_STATE,3)
            return again(o,175)
        if get(o,SNAP)!=PROOF_TAG:
            return quarantine(o,w,174)
        return proof_call(o,172,1)
    if phase==175:
        if get(o,PROOF_CAP)!=0 or get(o,PROOF_PENDING)!=0:
            return quarantine(o,w,175)
        return system(o,176,11,0,get(o,PROOF_WORK),get(o,PROOF_N),0,0,0,0)
    if phase==176:
        if r!=0:
            return parked(o,w,11,r)
        put(o,PROOF_WORK,0)
        put(o,PROOF_N,0)
        return again(o,140)
    return BAD
'''
def source_program():
    s=source_template()
    for k,v in sorted(C.items(),key=lambda x:-len(x[0])):
        s=re.sub(r'\b'+k+r'\b',str(v),s)
    return s
def main():
    name="generation_background_rank_bind"
    d=document(source_program(),name);p=ROOT/"examples/hia_bootstrap"/(name+".hepta")
    p.write_text(render_assembly(d))
    print(p.name,p.stat().st_size,len(d["functions"]),sum(len(f["blocks"])for f in d["functions"]),
          sum(len(b["ops"])for f in d["functions"]for b in f["blocks"]),flush=True)
if __name__=="__main__":main()
