"""Fixed native callable adapter for canonical Future callbacks.

Only the mechanical Value call is external. Argument ownership, invocation,
actual exception MRO classification and cleanup receipts are HIA policy.
"""
from pathlib import Path
import ast,re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools import generate_hia_future_resource_owner as helpers
from tools import generate_hia_background_optimizer_future_public_owner as reach
ROOT=Path(__file__).resolve().parents[1]
C=dict(helpers.C)
C.update({k:int.from_bytes(v.encode(),'little')for k,v in dict(
 MAGIC='HIAFCBQ2',REPLY='HIAFCBR2',STATE='HIABFPS1',
 V1='HIABVQ01',V2='HIABVQ02',V3='HIABVQ03',V4='HIABVQ04',V5='HIABVQ05',
 VR1='HIABVR01',VR2='HIABVR02').items()})
C.update(PH=128,FB=136,USER_KIND=144,ERROR_KIND=152,PID=160,FACT_SELF=176,FACT_VALUE=184,
 LIST=192,TUPLE=216,PRIMARY=240,CLASS=264,DROP_AT=288,CLEAN_INDEX=296,
 FLAGS=304,VALUE_OP=312,RAW_OP=320,CLEAN_ERROR=328,DISPOSITION=336,
 RQ=512,RAW=1024,FINAL=2048,RP=16384,OUT=65536)
SOURCE=r"""
def future_callable_adapter(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=192 or length(o)<OUT or length(w)!=256:
        return 4294967293
    phase=get(o,PH)
    if phase==0:
        if word(s,0)!=MAGIC or word(s,8)!=0 or read_zero(s,112,80)==False:
            return 4294967293
        at=16
        while at<112:
            if word(s,at)==0:
                return 4294967293
            at=at+8
        zero(o,128,OUT-128)
        return system(o,1,39,0,0,0,0,0,0,0)
    if phase==1:
        if get(o,FB)==0 or get(o,FB)>=NEGATIVE:
            return failed(o,107)
        put(o,PID,get(o,FB))
        put(o,PH,2)
        return 15
    if phase==2:
        if get(w,0)!=STATE or get(w,8)!=get(o,PID) or get(w,24)!=0:
            return failed(o,107)
        if get(w,208)!=get(o,FACT_SELF) or get(w,72)!=get(o,FACT_VALUE):
            return failed(o,107)
        if get(w,112)==0 or get(w,112)>MAX-256 or get(w,120)!=256:
            return failed(o,107)
        packet(o,49)
        readcopy(s,88,o,RQ+24,24)
        return value(o,3)
    if phase==3:
        if ordinary(o)==False or get(o,RP+16)!=7:
            return failed(o,107)
        packet(o,3)
        return value(o,10)
    if phase==10:
        if ordinary(o)==False or delivered(o,LIST,5)==False:
            return failed(o,error_kind(o))
        packet(o,16)
        copy(o,RQ+24,LIST,24)
        readcopy(s,88,o,RQ+48,24)
        return value(o,11)
    if phase==11:
        if ordinary(o)==False:
            return failed(o,error_kind(o))
        packet(o,40)
        copy(o,RQ+24,LIST,24)
        return value(o,12)
    if phase==12:
        if ordinary(o)==False or delivered(o,TUPLE,11)==False:
            return failed(o,error_kind(o))
        packet(o,70)
        readcopy(s,64,o,RQ+24,24)
        copy(o,RQ+48,TUPLE,24)
        return value(o,20)
    if phase==20:
        if get(o,FB)!=0 or get(o,RP)!=VR1 or get(o,RP+88)!=1:
            return uncertain(o)
        published=get(o,RP+96)
        disposition=get(o,RP+64)
        status=get(o,RP+8)
        if published>1 or get(o,RP+80)>1:
            return uncertain(o)
        if get(o,RP+80)!=0 or get(o,RP+104)!=0:
            put(o,FLAGS,get(o,FLAGS)|2)
        if published==0:
            if get(o,RP+24)!=0 or get(o,RP+32)!=0 or get(o,RP+40)!=0 or disposition!=0 or status==0:
                return uncertain(o)
            return failed(o,error_kind(o))
        if (status!=0 and status!=11) or (disposition!=1 and disposition!=2):
            return uncertain(o)
        if get(o,RP+24)==0 or get(o,RP+32)==0 or get(o,RP+40)==0:
            return uncertain(o)
        copy(o,PRIMARY,RP+24,24)
        put(o,DISPOSITION,disposition)
        if disposition==1:
            return again(o,100)
        packet(o,32)
        put(o,RQ+104,22)
        return value(o,21)
    if phase==21:
        if ordinary(o)==False or delivered(o,CLASS,10)==False:
            return failed(o,error_kind(o))
        packet(o,37)
        copy(o,RQ+24,PRIMARY,24)
        copy(o,RQ+48,CLASS,24)
        return value(o,22)
    if phase==22:
        if ordinary(o)==False or get(o,RP+48)>1:
            return failed(o,error_kind(o))
        put(o,USER_KIND,choose(get(o,RP+48)!=0,1,2))
        put(o,ERROR_KIND,200)
        return again(o,100)
    if phase>=100:
        return cleanup(o,phase)
    return uncertain(o)

def cleanup(o:mutbuf,phase:u64) -> u32:
    if phase==100:
        if (get(o,FLAGS)&4)!=0:
            return finish(o)
        index=get(o,CLEAN_INDEX)
        if index==3:
            if (get(o,FLAGS)&2)!=0 and (get(o,FLAGS)&4)==0:
                packet(o,56)
                return value(o,120)
            return finish(o)
        at=choose(index==0,CLASS,choose(index==1,TUPLE,LIST))
        put(o,CLEAN_INDEX,index+1)
        if get(o,at)==0:
            if get(o,at+8)!=0 or get(o,at+16)!=0:
                put(o,FLAGS,get(o,FLAGS)|4)
            return again(o,100)
        put(o,DROP_AT,at)
        packet(o,78)
        copy(o,RQ+24,at,24)
        return value(o,101)
    if phase==101:
        if get(o,FB)!=0 or get(o,RP)!=VR2:
            cleanup_unknown(o)
            return again(o,100)
        known=get(o,RP+88)
        consumed=get(o,RP+96)
        mapping=get(o,RP+104)
        queued=get(o,RP+112)
        status=get(o,RP+8)
        if known>1 or consumed>1 or mapping>1 or queued>1 or get(o,RP+120)!=1:
            cleanup_unknown(o)
            return again(o,100)
        if get(o,RP+80)!=choose(mapping!=0 or queued!=0,1,0):
            cleanup_unknown(o)
            return again(o,100)
        if consumed!=0 and (known!=1 or (status!=0 and status!=11)):
            cleanup_unknown(o)
            return again(o,100)
        at=16
        while at<80:
            if get(o,RP+at)!=0:
                cleanup_unknown(o)
                return again(o,100)
            at=at+8
        if consumed!=0:
            zero(o,get(o,DROP_AT),24)
        if mapping!=0:
            put(o,FLAGS,get(o,FLAGS)|1)
        if queued!=0:
            put(o,FLAGS,get(o,FLAGS)|2)
        if known!=1 or consumed!=1:
            put(o,CLEAN_ERROR,1)
            if known!=1:
                cleanup_unknown(o)
        return again(o,100)
    if phase==120:
        if get(o,FB)==0 and get(o,RP)==VR1 and get(o,RP+8)==0:
            put(o,FLAGS,get(o,FLAGS)&18446744073709551613)
        else:
            put(o,FLAGS,get(o,FLAGS)|2)
            put(o,CLEAN_ERROR,1)
        return finish(o)
    return finish(o)

def packet(o:mutbuf,op:u64) -> u64:
    zero(o,RQ,128)
    magic=V1
    if op==29 or op==30 or op==31:
        magic=V2
    elif op>=32 and op<=39:
        magic=V3
    elif op>=40 and op<=47:
        magic=V4
    elif op>=48:
        magic=V5
    put(o,RQ,magic)
    put(o,RQ+8,op)
    put(o,VALUE_OP,op)
    zero(o,RP,32768)
    return 0

def value(o:mutbuf,next:u64) -> u32:
    put(o,PH,next)
    return 12

def ordinary(o:mutbuf) -> bool:
    if get(o,FB)!=0 or get(o,RP)!=VR1:
        cleanup_unknown(o)
        return False
    if get(o,RP+8)!=0 and (get(o,RP+24)!=0 or get(o,RP+32)!=0 or get(o,RP+40)!=0 or get(o,RP+8)==11):
        cleanup_unknown(o)
    return get(o,RP+8)==0

def delivered(o:mutbuf,at:u64,kind:u64) -> bool:
    if get(o,RP+24)==0 or get(o,RP+32)==0 or get(o,RP+40)==0:
        cleanup_unknown(o)
        return False
    copy(o,at,RP+24,24)
    return get(o,RP+16)==kind

def error_kind(o:mutbuf) -> u64:
    return choose(get(o,RP+8)==5,103,107)

def cleanup_unknown(o:mutbuf) -> u64:
    put(o,FLAGS,get(o,FLAGS)|4)
    if get(o,RAW_OP)==0:
        copy(o,RAW,RP,128)
        put(o,RAW_OP,get(o,VALUE_OP))
    return 0

def uncertain(o:mutbuf) -> u32:
    cleanup_unknown(o)
    return failed(o,107)

def failed(o:mutbuf,kind:u64) -> u32:
    put(o,USER_KIND,1)
    put(o,ERROR_KIND,kind)
    return again(o,100)

def finish(o:mutbuf) -> u32:
    zero(o,FINAL,288)
    put(o,FINAL,REPLY)
    put(o,FINAL+8,get(o,USER_KIND))
    put(o,FINAL+16,get(o,ERROR_KIND))
    copy(o,FINAL+24,PRIMARY,24)
    copy(o,FINAL+48,LIST,24)
    copy(o,FINAL+72,TUPLE,24)
    copy(o,FINAL+96,CLASS,24)
    put(o,FINAL+120,get(o,FLAGS))
    if (get(o,FLAGS)&4)!=0:
        copy(o,FINAL+128,RAW,128)
        put(o,FINAL+256,get(o,RAW_OP))
    put(o,FINAL+264,get(o,CLEAN_ERROR))
    copy(o,0,FINAL,288)
    return 0
"""
def source_program():
    names={'get','put','word','read_zero','readcopy','copy','zero','system','again','choose'}
    complete=helpers.source_program();tree=ast.parse(complete)
    common='\n'.join(ast.get_source_segment(complete,n)for n in tree.body if isinstance(n,ast.FunctionDef)and n.name in names)
    source=reach.reachable_source(SOURCE+'\n'+common,'future_callable_adapter')
    for key,value in sorted(C.items(),key=lambda x:-len(x[0])):source=re.sub(r'\b'+key+r'\b',str(value),source)
    return source
def main():
    d=document(source_program(),'future_callable_adapter');p=ROOT/'examples/hia_bootstrap/future_callable_adapter.hepta'
    p.write_text(render_assembly(d))
    print(p.name,p.stat().st_size,len(d['functions']),sum(len(f['blocks'])for f in d['functions']),sum(len(b['ops'])for f in d['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
