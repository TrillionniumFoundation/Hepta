"""Native deferred canonical Future producer for enclosing BG critical sections.

HIAFRD01 preserves the Q02/Q03 domains and uses Q08/48 only in its own domain.
Every returned reference remains governed by the real Value/native receipts.
"""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools import generate_hia_future_resource_owner as original
ROOT=Path(__file__).resolve().parents[1]
C=dict(original.C)
C.update(D_REQUEST=int.from_bytes(b'HIAFRD01','little'),D_REPLY=int.from_bytes(b'HIAFRDR1','little'),
         V_CAPTURE_DEFER=int.from_bytes(b'HIABVQ08','little'),D_MODE=1896,D_NATIVE_PENDING=1904)
def replace(text,before,after):
    assert text.count(before)==1,before
    return text.replace(before,after)
def source_program():
    text=replace(original.SOURCE,'def future_resource_owner(','def future_resource_deferred_owner(')
    text=replace(text,"""    elif word(s,0)==REQUEST4:""","""    elif word(s,0)==D_REQUEST:
        if op>1:
            return 4294967293
        family=choose(op==0,3,4)
        if op==0:
            if read_zero(s,40,24)==False or read_zero(s,88,40)==False:
                return 4294967293
        elif read_zero(s,40,88)==False:
            return 4294967293
    elif word(s,0)==REQUEST4:""")
    text=replace(text,"""    put(o,REPLY_BYTES,128)
    if family==2:""","""    put(o,REPLY_BYTES,128)
    if word(s,0)==D_REQUEST:
        put(o,D_MODE,1)
        put(o,OP,0)
        put(o,REPLY_BYTES,160)
    if family==2:""")
    text=replace(text,"""        if get(o,FAMILY)==5:
            if get(o,FIXED_CALLBACK)==0:""","""        if get(o,D_MODE)!=0 and get(o,CALLER_OUTPUT)<160:
            return 4294967294
        if get(o,FAMILY)==5:
            if get(o,FIXED_CALLBACK)==0:""")
    text=replace(text,"""        return unlock(o,802)
    if phase==802:
        if get(o,C_NEED_DRAIN)!=0:""","""        if get(o,D_MODE)!=0:
            put(o,D_NATIVE_PENDING,choose(get(w,112)!=0,1,0))
        return unlock(o,802)
    if phase==802:
        if get(o,D_MODE)!=0:
            return deferred_finish(o)
        if get(o,C_NEED_DRAIN)!=0:""")
    text=replace(text,"""def finish(o:mutbuf) -> u32:
    if get(o,FAMILY)==5:""","""def finish(o:mutbuf) -> u32:
    if get(o,D_MODE)!=0:
        return deferred_reply(o)
    if get(o,FAMILY)==5:""")
    text=replace(text,"""        put(o,PTR,0)
        value_packet(o,V_PRIVATE,56)
        return values(o,w,949)""","""        put(o,PTR,0)
        if get(o,D_MODE)!=0:
            # Value already owns the queued actual resource and its edges.
            # The enclosing caller drains after releasing its own mutex.
            return failure(o,get(o,ERROR),1)
        value_packet(o,V_PRIVATE,56)
        return values(o,w,949)""")
    text=replace(text,"""        elif op==31:
            put(o,RQ,V_PRIVATE)
            put(o,RQ+8,93)
    return 0""","""        elif op==31:
            put(o,RQ,V_PRIVATE)
            put(o,RQ+8,93)
    if get(o,D_MODE)!=0 and magic==V_PRIVATE and op==48:
        put(o,RQ,V_CAPTURE_DEFER)
    return 0""")
    text=replace(text,"""    status=get(o,VP+8)
    if get(o,VP+96)==0:
        return status!=0 and get(o,VP+24)==0 and get(o,VP+32)==0 and get(o,VP+40)==0
    return (status==0 or status==11) and get(o,VP+16)==8""","""    status=get(o,VP+8)
    if get(o,D_MODE)!=0:
        if mapping!=0:
            put(o,VALUE_UNMAP,1)
        if queue!=0:
            put(o,VALUE_QUEUE,1)
    if get(o,VP+96)==0:
        return status!=0 and get(o,VP+24)==0 and get(o,VP+32)==0 and get(o,VP+40)==0
    return (status==0 or status==11) and get(o,VP+16)==8""")
    text=replace(text,"""def canonical_capture_record(o:mutbuf) -> bool:
    if value_valid(o)==False or get(o,VP+88)!=1 or get(o,VP+96)>1 or get(o,VP+80)>1:
        return False
    status=get(o,VP+8)""","""def canonical_capture_record(o:mutbuf) -> bool:
    if value_valid(o)==False or get(o,VP+88)!=1 or get(o,VP+96)>1 or get(o,VP+80)>1:
        return False
    if get(o,D_MODE)!=0:
        mapping=get(o,VP+104)
        queue=get(o,VP+112)
        if mapping>1 or queue>1 or get(o,VP+120)!=1:
            return False
        both=choose(mapping!=0 or queue!=0,1,0)
        if get(o,VP+80)!=both:
            return False
        if mapping!=0:
            put(o,VALUE_UNMAP,1)
        if queue!=0:
            put(o,VALUE_QUEUE,1)
    status=get(o,VP+8)""")
    text+="""
def deferred_finish(o:mutbuf) -> u32:
    pending=get(o,PENDING)
    if get(o,D_NATIVE_PENDING)!=0 or get(o,VALUE_QUEUE)!=0:
        pending=1
    if get(o,VALUE_UNMAP)!=0 or get(o,VALUE_BAD)!=0 or get(o,QUAR)!=0:
        pending=1
        put(o,STATUS,11)
    put(o,PENDING,pending)
    return deferred_reply(o)
def deferred_reply(o:mutbuf) -> u32:
    zero(o,R_FINAL,160)
    put(o,R_FINAL,D_REPLY)
    put(o,R_FINAL+8,get(o,STATUS))
    put(o,R_FINAL+16,get(o,KIND))
    copy(o,R_FINAL+24,RESULT,24)
    if get(o,FAMILY)==4 and get(o,KIND)==7:
        copy(o,R_FINAL+48,ROW+64,24)
        copy(o,R_FINAL+72,ROW+88,24)
    put(o,R_FINAL+96,get(o,KNOWN))
    put(o,R_FINAL+104,get(o,CONSUMED))
    put(o,R_FINAL+112,get(o,PENDING))
    put(o,R_FINAL+120,get(o,VALUE_UNMAP))
    put(o,R_FINAL+128,get(o,VALUE_QUEUE))
    unknown=choose(get(o,VALUE_BAD)!=0 or get(o,QUAR)!=0,1,0)
    put(o,R_FINAL+136,unknown)
    put(o,R_FINAL+144,1)
    put(o,R_FINAL+152,get(o,D_NATIVE_PENDING))
    copy(o,0,R_FINAL,160)
    return 0
"""
    saved=(original.SOURCE,original.C)
    try:
        original.SOURCE=text;original.C=C
        return original.source_program()
    finally:
        original.SOURCE,original.C=saved
def main():
    doc=document(source_program(),'future_resource_deferred_owner')
    p=ROOT/'examples/hia_bootstrap/future_resource_deferred_owner.hepta'
    p.write_text(render_assembly(doc))
    print(p.name,p.stat().st_size,len(doc['functions']),sum(len(f['blocks'])for f in doc['functions']),sum(len(b['ops'])for f in doc['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
