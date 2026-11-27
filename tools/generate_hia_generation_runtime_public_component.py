"""Preserve the actual Clang exception across a failed native generation.

This is a derived public constructor component. The previous fixed component
profile remains unchanged. Exception authority comes only from the already
captured child export and is transferred with its own known/delivered facts.
"""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_generation_lease_owner_component as original
ROOT=Path(__file__).resolve().parents[1]
C=dict(original.C,GSAVE=(510<<20)+16384,GE=int.from_bytes(b'HIARTGE1','little'),PE=int.from_bytes(b'HIARTPE1','little'),PER=int.from_bytes(b'HIARTPR1','little'))
EXTRA=r'''
def generation_exception(o:mutbuf,w:mutbuf) -> u32:
    copy_output(o,0,w,GSAVE,4096)
    zero(w,PFRAME,128)
    zero(w,POUT,128)
    put(w,PFRAME,EQ)
    return role(o,w,23,13,PFRAME,128,POUT,128)

def generation_exception_reply(o:mutbuf,w:mutbuf,raw:u64) -> u32:
    valid=raw==0 and get(w,POUT)==ER
    if valid:
        valid=get(w,POUT+88)==1 and get(w,POUT+96)<=1
    delivered=0
    if valid:
        delivered=get(w,POUT+96)
        if delivered==1:
            valid=get(w,POUT+16)==2 and get(w,POUT+24)!=0 and get(w,POUT+32)!=0 and get(w,POUT+40)!=0
        else:
            valid=get(w,POUT+16)==0 and get(w,POUT+24)==0 and get(w,POUT+32)==0 and get(w,POUT+40)==0
    copy_output(w,GSAVE,o,0,4096)
    if delivered==1 or valid==False:
        put(o,256,GE)
        copy_output(w,POUT,o,264,128)
    if valid==False:
        put(w,UNKNOWN,1)
        put(w,STATE,5)
        put(w,PENDING,1)
        put(w,PASS_RC,10)
        put(o,8,10)
    zero(w,GSAVE,4096)
    zero(w,POUT,128)
    put(w,PH,0)
    return 11
'''
def replace(s,a,b):
    assert s.count(a)==1,(a,s.count(a))
    return s.replace(a,b,1)
def source_program():
    s=original.SOURCE
    s=replace(s,'    if phase==20 or phase==21 or phase==22:\n','    if phase==20 or phase==21 or phase==22 or phase==23:\n')
    s=replace(s,'def forwarded(s:readbuf,o:mutbuf,w:mutbuf,phase:u64,raw:u64) -> u32:\n',
      'def forwarded(s:readbuf,o:mutbuf,w:mutbuf,phase:u64,raw:u64) -> u32:\n    if phase==23:\n        return generation_exception_reply(o,w,raw)\n')
    old='''    if phase==22:
        if get(o,0)!=GR or raw!=get(o,8) or raw>10:
            put(w,UNKNOWN,1)
            put(w,STATE,5)
            put(w,PENDING,1)
        put(w,PH,0)
        return 11
'''
    new='''    if phase==22:
        if get(o,0)!=GR or raw!=get(o,8) or raw>10:
            put(w,UNKNOWN,1)
            put(w,STATE,5)
            put(w,PENDING,1)
        elif raw!=0 and get(o,912)==1:
            return generation_exception(o,w)
        elif raw==1 and get(o,24)==0 and get(o,40)==3 and get(o,48)>=1 and get(o,48)<=9:
            put(o,256,PE)
            put(o,264,PER)
            put(o,272,get(o,40))
            put(o,280,get(o,48))
            put(o,352,1)
        put(w,PH,0)
        return 11
'''
    s=replace(s,old,new)+'\n'+EXTRA
    for k,v in sorted(C.items(),key=lambda x:-len(x[0])):s=re.sub(r'\b'+k+r'\b',str(v),s)
    return s
def main():
    tree=document(source_program(),'generation_runtime_public_component')
    p=ROOT/'examples/hia_bootstrap/generation_runtime_public_component.hepta'
    p.write_text(render_assembly(tree))
    print(p.name,p.stat().st_size,len(tree['functions']),sum(len(f['blocks'])for f in tree['functions']),sum(len(b['ops'])for f in tree['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
