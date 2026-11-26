"""Private deferred HIA report construction with explicit retained custody.

The original report domains stay frozen. This variant performs the same ordered
report and receipt mutations using the sole Value arena's private profiles.
"""
from pathlib import Path
import ast,re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools import generate_hia_background_optimizer_report as original
ROOT=Path(__file__).resolve().parents[1]
def replace(text,a,b):
    assert text.count(a)==1,(a,text.count(a));return text.replace(a,b)
def source_program():
    text=original.COMMON
    text=replace(text,"    if phase==0:\n        if length(s)!=128 or readword(s,8)>1:",
        "    if phase==0:\n        if length(s)==128 and readword(s,0)==D_RETRY:\n            return retry_begin(s,o,w)\n        if get(w,288)!=0:\n            return 4294967293\n        if length(s)!=128 or readword(s,8)>1:")
    start=text.index("    pending=get(w,136)\n")
    end=text.index("    if get(w,128)==CLEANUP:\n",start)
    text=text[:start]+"""    pending=get(w,136)
    if pending!=0:
        put(w,136,0)
        outcome=response(o,w,pending)
        if outcome==2:
            return retained(o,w,2)
        if outcome==1:
            return retained(o,w,1)
"""+text[end:]
    text=replace(text,"    put(w,REQUEST,VALUE_MAGIC)\n    put(w,REQUEST+8,op)",
        "    private_request(w,op)")
    text=replace(text,"def cleanup(o:mutbuf,w:mutbuf) -> u64:\n    i=get(w,216)",
        "def cleanup(o:mutbuf,w:mutbuf) -> u64:\n    if get(w,272)!=0:\n        return retry_mapping(o,w)\n    i=get(w,216)")
    text=replace(text,"    put(o,128,2)\n    return 0",
        "    put(o,96,0)\n    put(o,104,0)\n    put(o,112,0)\n    put(o,120,get(w,264))\n    put(o,128,2)\n    put(o,144,0)\n    put(o,152,0)\n    put(o,160,1)\n    return 0")
    text+=EXTRA
    values=dict(MAGIC="HIABRP03",OBSERVED_MAGIC="HIABRP04",REPLY="HIABRR02",
      CONTEXT="HIABRC02",OBSERVATION_REQUEST="HIABROQ2",
      D_RETRY="HIABRP05",D_Q="HIABVQ06",D_FIXED="HIABVQ07",D_SNAPSHOT="HIABVQ09",
      D_IMPORT="HIABVQ10",D_PRIVATE="HIABVQ05",D_RELEASE="HIABVR02")
    for key,value in sorted(values.items(),key=lambda x:-len(x[0])):
        text=re.sub(r'\b'+key+r'\b',str(int.from_bytes(value.encode(),"little")),text)
    saved=original.COMMON
    try:
        original.COMMON=text
        return original.generated()
    finally:original.COMMON=saved

EXTRA=r'''
def private_request(w:mutbuf,op:u64) -> u64:
    magic=D_Q
    actual=op
    if op==1:
        magic=D_IMPORT
    elif op==5:
        magic=D_PRIVATE
        actual=91
    elif op==6:
        magic=D_PRIVATE
        actual=78
    elif op==23:
        magic=D_SNAPSHOT
    elif op==3 or op==12 or op==16 or op==18 or op==24:
        magic=D_FIXED
    put(w,REQUEST,magic)
    put(w,REQUEST+8,actual)
    put(w,256,actual)
    return 0
def flags(w:mutbuf) -> u64:
    pending=get(w,VALUE_OUT+80)
    mapping=get(w,VALUE_OUT+104)
    queue=get(w,VALUE_OUT+112)
    if pending>1 or mapping>1 or queue>1 or get(w,VALUE_OUT+120)!=1:
        return 0
    union=choose(mapping!=0 or queue!=0,1,0)
    if pending!=union:
        return 0
    if queue!=0:
        put(w,264,1)
    put(w,272,mapping)
    return 1
def response(o:mutbuf,w:mutbuf,pending:u64) -> u64:
    op=get(w,256)
    expected=choose(op==78 or op==93,D_RELEASE,VALUE_REPLY)
    if get(o,136)!=0 or get(w,VALUE_OUT)!=expected:
        return 2
    status=get(w,VALUE_OUT+8)
    put(w,168,status)
    put(w,176,get(w,VALUE_OUT+16))
    put(w,184,get(w,VALUE_OUT+48))
    if op==78 or op==93:
        if get(w,VALUE_OUT+88)!=1 or get(w,VALUE_OUT+96)>1:
            return 2
        consumed=get(w,VALUE_OUT+96)
        if (consumed!=0 and status!=0 and status!=11) or (op==93 and consumed!=0):
            return 2
        if status!=0 and status!=1 and status!=6 and status!=11:
            return 2
        if status==0 and consumed!=choose(op==93,0,1):
            return 2
        source=get(w,208)
        if consumed!=0:
            if source==0 or get(w,CAPS+source*32+24)!=1:
                return 2
            zero(w,CAPS+source*32,32)
        at=16
        while at<80:
            if get(w,VALUE_OUT+at)!=0:
                return 2
            at=at+8
        if flags(w)==0:
            return 2
        if op==93:
            if status==1 or (status==6 and get(w,VALUE_OUT+112)!=0):
                return 2
            if get(w,272)!=0:
                return 1
            if status==11 and get(w,VALUE_OUT+112)==0:
                return 2
            return 0
        if consumed==0:
            return choose(status==6,1,2)
        if status==11 and get(w,VALUE_OUT+80)==0:
            return 2
        if get(w,272)!=0:
            return 1
        return 0
    if op==91:
        if get(w,VALUE_OUT+88)!=1 or get(w,VALUE_OUT+96)>1:
            return 2
        delivered=get(w,VALUE_OUT+96)
        if delivered!=0:
            dest=get(w,152)
            if dest==0 or get(w,CAPS+dest*32+24)!=0 or get(w,VALUE_OUT+24)==0:
                return 2
            copy(w,CAPS+dest*32,VALUE_OUT+24,24)
            put(w,CAPS+dest*32+24,1)
        if flags(w)==0:
            return 2
        if delivered==0 and get(w,VALUE_OUT+24)!=0:
            return 2
        if status!=0 and status!=11:
            if delivered!=0:
                return 2
            stop(w,status)
            return 0
        if status==11 and delivered!=0 and get(w,VALUE_OUT+80)==0:
            return 2
        if get(w,272)!=0:
            return 1
        if delivered==0:
            stop(w,11)
            return 0
        put(w,168,0)
        return 0
    if status!=0:
        if get(w,160)!=1 or status!=3:
            stop(w,status)
        return 0
    dest=get(w,152)
    if dest!=0:
        if get(w,VALUE_OUT+24)==0 or get(w,CAPS+dest*32+24)!=0:
            return 2
        copy(w,CAPS+dest*32,VALUE_OUT+24,24)
        put(w,CAPS+dest*32+24,1)
    return 0
def retained(o:mutbuf,w:mutbuf,kind:u64) -> u64:
    put(w,288,kind)
    zero(o,0,128)
    put(o,0,REPLY)
    put(o,8,11)
    put(o,96,1)
    put(o,104,kind)
    pending=choose(get(w,272)!=0 or get(w,288)==1,1,0)
    put(o,112,pending)
    put(o,120,get(w,264))
    put(o,128,2)
    put(o,144,get(w,272))
    put(o,152,choose(kind==2,1,0))
    put(o,160,1)
    return 0
def retry_begin(s:readbuf,o:mutbuf,w:mutbuf) -> u64:
    if readword(s,8)!=2 or get(w,0)!=CONTEXT or get(w,8)==0 or get(w,16)==0 or get(w,24)!=256:
        return 4294967293
    at=16
    while at<128:
        if readword(s,at)!=0:
            return 4294967293
        at=at+8
    if get(w,288)==2:
        return retained(o,w,2)
    if get(w,288)!=1:
        return 4294967293
    put(w,288,0)
    put(w,144,11)
    put(w,216,1)
    put(w,128,CLEANUP)
    put(w,136,0)
    put(o,128,1)
    return cleanup(o,w)
def retry_mapping(o:mutbuf,w:mutbuf) -> u64:
    zero(w,REQUEST,128)
    put(w,REQUEST,D_PRIVATE)
    put(w,REQUEST+8,93)
    put(w,256,93)
    put(w,208,0)
    put(w,136,3)
    put(o,0,get(w,8))
    put(o,8,17)
    put(o,16,REQUEST)
    put(o,24,128)
    put(o,32,VALUE_OUT)
    put(o,40,16384)
    put(o,48,get(w,16))
    put(o,56,get(w,24))
    return 4
'''
def main():
    doc=document(source_program(),"background_optimizer_report_deferred")
    path=ROOT/"examples/hia_bootstrap/background_optimizer_report_deferred.hepta";path.write_text(render_assembly(doc))
    print(path.name,path.stat().st_size,len(doc["functions"]),sum(len(f["blocks"])for f in doc["functions"]),sum(len(b["ops"])for f in doc["functions"]for b in f["blocks"]),flush=True)
if __name__=="__main__":main()
