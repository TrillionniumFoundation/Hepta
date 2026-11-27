"""Managed finite Future timeouts; the original FP01 conversion stays intact.

FP04 holds one actual cleanup reservation before cloning the timeout capability.
The fixed cleanup wrapper owns its independent 32768-byte frame and returns only
the 128-byte custody receipt into this role's original 16384-byte output.
"""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools import generate_hia_background_optimizer_future_public_timeout as original
ROOT=Path(__file__).resolve().parents[1]
C=dict(original.C)
C.update(MAGIC4=int.from_bytes(b'HIABFP04','little'),
 M_VREQUEST5=int.from_bytes(b'HIABVQ05','little'),M_VREQUEST6=int.from_bytes(b'HIABVQ06','little'),
 M_GREQUEST=int.from_bytes(b'HIABFC02','little'),M_GREPLY=int.from_bytes(b'HIABFCR2','little'),
 M_GCAP=232,M_MAP=256,M_QUEUE=264,M_UNKNOWN=272,M_LOCAL=280,
 M_GRQ=1024,M_GRP=1280,M_SHADOW=1440,M_MAX=(1<<64)-1)
MANAGED=r'''
def managed_timeout(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase=get(o,PHASE)
    if phase==0:
        if readword(s,8)!=10 and readword(s,8)!=11:
            return 4294967293
        if readword(s,16)==0 or readword(s,40)==0:
            return 4294967293
        at=64
        while at<192:
            if (at<104 or at>120) and readword(s,at)!=0:
                return 4294967293
            at=at+8
        zero(o,128,OUT-128)
        managed_guard_packet(s,o,0)
        put(o,M_GRQ+96,1)
        return managed_guard(o,w,2001)
    if phase==2001:
        if managed_guard_receipt(o)==False:
            return managed_finish(o,1,107)
        if get(o,M_GRP+8)!=0:
            return managed_finish(o,1,choose(get(o,M_GRP+8)==4,103,107))
        if get(o,M_GRP+48)!=1 or get(o,M_GRP+16)==0 or get(o,M_GRP+24)==0 or get(o,M_GRP+32)==0 or get(o,M_GRP+72)!=224 or get(o,M_GRP+80)!=1:
            return managed_finish(o,1,107)
        within(o,M_GCAP,M_GRP+16,24)
        managed_value_packet(o,91)
        copy_input(s,104,o,RQ+24,24)
        return value(o,w,2002)
    if phase==2002:
        if managed_clone_receipt(o)==False:
            within(o,CAP,VP+24,24)
            return managed_quarantine(o,1)
        if get(o,VP+96)==0:
            return fail(o,choose(get(o,VP+8)==1,3,1),choose(get(o,VP+8)==5,103,107))
        within(o,CAP,VP+24,24)
        managed_value_packet(o,7)
        within(o,RQ+24,CAP,24)
        return value(o,w,2003)
    if phase==2003:
        if ok(o)==False:
            return fail(o,1,107)
        kind=get(o,VP+16)
        put(o,KIND,kind)
        if kind==0:
            put(o,INFINITE,1)
            return fail(o,0,0)
        if kind!=1 and kind!=2 and kind!=3:
            put(o,DETAIL,kind)
            return fail(o,1,104)
        n=get(o,VP+72)
        managed_value_packet(o,19)
        within(o,RQ+24,CAP,24)
        put(o,RQ+112,choose(n<32,n,32))
        return value(o,w,2004)
    if phase==2004:
        if ok(o)==False:
            return fail(o,1,107)
        kind=get(o,KIND)
        if kind==1:
            put(o,NS,choose(byte(o,RAW)==0,0,1000000000))
            return fail(o,0,0)
        if kind==2:
            return integer_timeout(o)
        return float_timeout(o)
    if phase==900:
        if get(o,M_GCAP)==0:
            return managed_finish(o,get(o,ERROR),get(o,CLASS))
        if get(o,CAP)!=0:
            managed_guard_packet(s,o,1)
            put(o,M_GRQ+64,2)
            within(o,M_GRQ+72,CAP,24)
            return managed_guard(o,w,2901)
        return again(o,2902)
    if phase==2901:
        if managed_guard_receipt(o)==False:
            return managed_quarantine(o,1)
        if get(o,M_GRP+56)!=1:
            return managed_quarantine(o,1)
        # The actual cleanup registry accepted this cap. It retains any
        # unconsumed cap or mapping retry; this call must never drop it again.
        zero(o,CAP,24)
        if get(o,M_GRP+8)!=0:
            put(o,ERROR,1)
            put(o,CLASS,107)
            put(o,M_LOCAL,1)
        return again(o,2902)
    if phase==2902:
        managed_guard_packet(s,o,2)
        return managed_guard(o,w,2903)
    if phase==2903:
        if managed_guard_receipt(o)==False:
            put(o,M_UNKNOWN,1)
            put(o,M_LOCAL,1)
            return managed_finish(o,1,107)
        if get(o,M_GRP+56)!=1:
            put(o,M_UNKNOWN,1)
            put(o,M_LOCAL,1)
            return managed_finish(o,1,107)
        zero(o,M_GCAP,24)
        if get(o,M_GRP+8)!=0:
            put(o,M_LOCAL,1)
            return managed_finish(o,1,107)
        return managed_finish(o,get(o,ERROR),get(o,CLASS))
    if phase==2950:
        # This actual, still-unsealed reservation is private to the call.
        # Publish the unresolved shadow before sealing it for registry retry.
        return managed_memory(o,2951,3,M_SHADOW,0,get(o,M_GCAP)+192,32)
    if phase==2951:
        put(o,M_SHADOW,1)
        return managed_memory(o,2952,3,M_SHADOW,0,get(o,M_GCAP)+112,8)
    if phase==2952:
        return managed_memory(o,2953,3,M_SHADOW,0,get(o,M_GCAP)+72,8)
    if phase==2953:
        zero(o,CAP,24)
        return managed_finish(o,1,107)
    return managed_finish(o,1,107)

def managed_value_packet(o:mutbuf,op:u64) -> u64:
    packet(o,op)
    put(o,RQ,choose(op==91,M_VREQUEST5,M_VREQUEST6))
    return 0

def managed_guard_packet(s:readbuf,o:mutbuf,op:u64) -> u64:
    zero(o,M_GRQ,192)
    put(o,M_GRQ,M_GREQUEST)
    put(o,M_GRQ+8,op)
    copy_input(s,16,o,M_GRQ+16,24)
    if op==1 or op==2:
        within(o,M_GRQ+40,M_GCAP,24)
    return 0

def managed_guard(o:mutbuf,w:mutbuf,next:u64) -> u32:
    if get(w,216)==0 or get(w,208)==0:
        put(o,FEEDBACK,M_MAX)
        return again(o,next)
    return invoke(o,next,get(w,216),M_GRQ,192,M_GRP,128,get(w,208),256)

def managed_guard_receipt(o:mutbuf) -> bool:
    if get(o,FEEDBACK)!=0 or get(o,M_GRP)!=M_GREPLY:
        return False
    status=get(o,M_GRP+8)
    if status!=0 and status!=1 and status!=4 and status!=5 and status!=9:
        return False
    if get(o,M_GRP+40)>1 or get(o,M_GRP+48)>1 or get(o,M_GRP+56)>1 or get(o,M_GRP+88)>1 or get(o,M_GRP+96)>1:
        return False
    if get(o,M_GRP+48)==0 and status!=9:
        return False
    if get(o,M_GRP+56)!=0 and status!=0 and status!=9:
        return False
    raw=get(o,M_GRP+64)
    if raw!=0 and raw!=1 and raw!=5 and raw!=6 and raw!=9 and raw!=11:
        return False
    at=104
    while at<128:
        if get(o,M_GRP+at)!=0:
            return False
        at=at+8
    if get(o,M_GRP+88)!=0:
        put(o,M_QUEUE,1)
    if get(o,M_GRP+96)!=0:
        put(o,M_MAP,1)
    return True

def managed_clone_receipt(o:mutbuf) -> bool:
    if get(o,FEEDBACK)!=0 or get(o,VP)!=VREPLY or get(o,VP+88)!=1:
        return False
    if get(o,VP+80)>1 or get(o,VP+96)>1 or get(o,VP+104)>1 or get(o,VP+112)>1 or get(o,VP+120)!=1:
        return False
    pending=0
    if get(o,VP+104)!=0 or get(o,VP+112)!=0:
        pending=1
    if get(o,VP+80)!=pending:
        return False
    consumed=get(o,VP+96)
    if consumed!=0:
        if get(o,VP+24)==0 or get(o,VP+32)==0 or get(o,VP+40)==0:
            return False
        if get(o,VP+8)!=0 and get(o,VP+8)!=11:
            return False
    elif get(o,VP+24)!=0 or get(o,VP+32)!=0 or get(o,VP+40)!=0 or get(o,VP+8)==0:
        return False
    if get(o,VP+104)!=0:
        put(o,M_MAP,1)
    if get(o,VP+112)!=0:
        put(o,M_QUEUE,1)
    return True

def managed_quarantine(o:mutbuf,reason:u64) -> u32:
    put(o,M_UNKNOWN,reason)
    put(o,M_LOCAL,1)
    zero(o,M_SHADOW,32)
    if get(o,CAP)!=0:
        put(o,M_SHADOW,2)
        within(o,M_SHADOW+8,CAP,24)
    if get(o,M_GCAP)==0:
        return managed_finish(o,1,107)
    return again(o,2950)

def managed_memory(o:mutbuf,next:u64,a:u64,src:u64,b:u64,dst:u64,n:u64) -> u32:
    put(o,PHASE,next)
    put(o,0,a)
    put(o,8,src)
    put(o,16,b)
    put(o,24,dst)
    put(o,32,n)
    return 8

def managed_finish(o:mutbuf,status:u64,kind:u64) -> u32:
    finish(o,status,kind)
    put(o,48,choose(get(o,M_UNKNOWN)==0,1,0))
    put(o,56,get(o,M_LOCAL))
    put(o,64,get(o,M_MAP))
    put(o,72,get(o,M_QUEUE))
    put(o,80,get(o,M_UNKNOWN))
    within(o,88,M_GCAP,24)
    return 0
'''
def source_program():
    s=original.SOURCE
    old='    if length(s)!=192 or length(o)<OUT or length(w)<256 or readword(s,0)!=MAGIC:\n        return 4294967293\n    phase=get(o,PHASE)\n'
    new='    if length(s)!=192 or length(o)<OUT or length(w)<256:\n        return 4294967293\n    if readword(s,0)==MAGIC4:\n        return managed_timeout(s,o,w)\n    if readword(s,0)!=MAGIC:\n        return 4294967293\n    phase=get(o,PHASE)\n'
    assert s.count(old)==1
    s=s.replace(old,new)+MANAGED
    for key,value in sorted(C.items(),key=lambda x:-len(x[0])):s=re.sub(r'\b'+key+r'\b',str(value),s)
    return s
def program():return document(source_program(),'background_optimizer_future_managed_timeout')
def main():
    d=program();p=ROOT/'examples/hia_bootstrap/background_optimizer_future_managed_timeout.hepta'
    p.write_text(render_assembly(d))
    print(p.name,p.stat().st_size,len(d['functions']),sum(len(f['blocks'])for f in d['functions']),sum(len(b['ops'])for f in d['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
