"""Native fixed Future resource finalizer adapter.

The Value resource-finalizer ABI has a 256-byte context.  The actual compound
registry owns 512 bytes.  This HIA policy validates the two captured domains,
then forwards the real retirement receipt without interpreting queue state as
a successful drop.  The binding initializer remains a separate trusted layer.
"""
from pathlib import Path
import ast,re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools import generate_hia_future_resource_owner as owner
from tools import generate_hia_background_optimizer_future_public_owner as reach
ROOT=Path(__file__).resolve().parents[1]
C=dict(owner.C)
C.update(STATE=int.from_bytes(b'HIAFRAX1','little'),PROVIDER_STATE=int.from_bytes(b'HIAFRCX2','little'),
 PH=128,FB=136,PID=144,FACT_SELF=152,FACT_ENTRY=160,FACT_PROVIDER=168,FACT_VALUE=176,
 RQ=512,RP=768,VCTX=1024,PCTX=1280,OUT=4096)
SOURCE=r"""
def future_resource_finalizer_adapter(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=128 or length(o)<OUT or length(w)!=256:
        return 4294967293
    phase=get(o,PH)
    if phase==0:
        if word(s,0)!=FINAL_REQUEST or word(s,8)>1 or word(s,24)!=7:
            return 4294967293
        if read_zero(s,56,72)==False:
            return 4294967293
        zero(o,128,3968)
        return system(o,1,39,0,0,0,0,0,0,0)
    if phase==1:
        if get(o,FB)==0 or get(o,FB)>=NEGATIVE:
            return refuse(o)
        put(o,PID,get(o,FB))
        put(o,PH,2)
        return 15
    if phase==2:
        if get(w,0)!=STATE or get(w,8)!=get(o,PID):
            return refuse(o)
        if get(w,16)!=get(o,FACT_SELF) or get(w,24)!=get(o,FACT_ENTRY):
            return refuse(o)
        if get(w,32)!=get(o,FACT_PROVIDER) or get(w,40)==0 or get(w,40)>MAX-512 or get(w,48)!=512:
            return refuse(o)
        if get(w,56)!=get(o,FACT_VALUE) or get(w,64)==0 or get(w,64)>MAX-256 or get(w,72)!=256:
            return refuse(o)
        if get(w,80)==0 or get(w,88)==0 or word(s,16)!=get(w,80):
            return refuse(o)
        at=96
        while at<256:
            if get(w,at)!=0:
                return refuse(o)
            at=at+8
        return memory(o,3,0,get(w,64),3,VCTX,256)
    if phase==3:
        if get(o,VCTX+128)!=get(o,FACT_ENTRY) or get(o,VCTX+136)!=get(o,FACT_SELF) or get(o,VCTX+144)!=256 or get(o,VCTX+152)!=get(w,80):
            return refuse(o)
        if get(o,VCTX+224)!=get(w,32) or get(o,VCTX+232)!=get(w,40) or get(o,VCTX+240)!=512 or get(o,VCTX+248)!=get(w,88):
            return refuse(o)
        return memory(o,4,0,get(w,40),3,PCTX,176)
    if phase==4:
        if get(o,PCTX)!=PROVIDER_STATE or get(o,PCTX+8)!=get(o,PID) or get(o,PCTX+16)!=get(w,40) or get(o,PCTX+24)!=get(w,32):
            return refuse(o)
        if get(o,PCTX+56)!=get(w,56) or get(o,PCTX+64)!=get(w,64) or get(o,PCTX+72)!=256:
            return refuse(o)
        if get(o,PCTX+80)!=get(w,88) or get(o,PCTX+160)!=get(w,80):
            return refuse(o)
        readcopy(s,0,o,RQ,128)
        put(o,RQ+16,get(w,88))
        put(o,PH,5)
        return 12
    if phase==5:
        if get(o,FB)!=0 or get(o,RP)!=FINAL_REPLY:
            return refuse(o)
        known=get(o,RP+16)
        consumed=get(o,RP+24)
        pending=get(o,RP+32)
        status=get(o,RP+8)
        if known>1 or consumed>1 or pending>1:
            return refuse(o)
        if consumed!=0 and (known!=1 or (status!=0 and status!=11)):
            return refuse(o)
        if status==0 and (known!=1 or pending!=0):
            return refuse(o)
        at=40
        while at<128:
            if get(o,RP+at)!=0:
                return refuse(o)
            at=at+8
        copy(o,0,RP,128)
        return 0
    return refuse(o)
def refuse(o:mutbuf) -> u32:
    zero(o,0,128)
    put(o,0,FINAL_REPLY)
    put(o,8,11)
    put(o,32,1)
    return 0
"""
def source_program():
    wanted={'get','put','word','read_zero','readcopy','copy','zero','system','memory','again'}
    complete=owner.source_program()
    tree=ast.parse(complete)
    helpers='\n'.join(ast.get_source_segment(complete,n)for n in tree.body if isinstance(n,ast.FunctionDef)and n.name in wanted)
    source=reach.reachable_source(SOURCE+'\n'+helpers,'future_resource_finalizer_adapter')
    for key,value in sorted(C.items(),key=lambda x:-len(x[0])):
        source=re.sub(r'\b'+key+r'\b',str(value),source)
    return source
def main():
    d=document(source_program(),'future_resource_finalizer_adapter')
    p=ROOT/'examples/hia_bootstrap/future_resource_finalizer_adapter.hepta'
    p.write_text(render_assembly(d))
    print(p.name,p.stat().st_size,len(d['functions']),sum(len(f['blocks'])for f in d['functions']),sum(len(b['ops'])for f in d['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
