"""Fixed sole-owner callable finalizer extension; original carrier path retained.

This author adds only fixed code-owner dispatch. It does not implement Value
callable construction or body execution and does not by itself enable kind bits.
"""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools import generate_hia_generation_lease_owner_finalizer as original
ROOT=Path(__file__).resolve().parents[1]
ADDITION=r'''
def callable_facts(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if get(w,128)!=get(o,80)-256:
        return unlock(o,11,0,0,0)
    if get(w,136)==0 or get(w,136)!=get(w,168):
        return unlock(o,11,0,0,0)
    if get(w,144)==0 or get(w,152)!=256 or get(w,160)==0:
        return unlock(o,11,0,0,0)
    if get(w,176)!=get(w,64) or (get(w,184)&(1<<word_load(s,24)))==0:
        return unlock(o,11,0,0,0)
    nonce=get(w,160)
    i=0
    while i<128:
        store(w,128+i,byte(s,i))
        i=i+1
    put(w,144,nonce)
    put(o,PHASE,9)
    return 13

def callable_reply(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if get(o,FEEDBACK)!=0 or get(w,128)!=REPLY:
        return unlock(o,11,0,0,0)
    known=get(w,144)
    consumed=get(w,152)
    pending=get(w,160)
    if known>1 or consumed>1 or pending>1:
        return unlock(o,11,0,0,0)
    if known==0 and consumed!=0:
        return unlock(o,11,0,0,0)
    i=200
    while i<256:
        if get(w,i)!=0:
            return unlock(o,11,0,0,0)
        i=i+8
    status=get(w,136)
    if status==0:
        if known!=1 or pending!=0:
            return unlock(o,11,0,0,0)
        if word_load(s,8)==0 and consumed!=1:
            return unlock(o,11,0,0,0)
    put(o,40,get(w,168))
    put(o,48,get(w,176))
    put(o,56,get(w,184))
    put(o,64,get(w,192))
    return unlock(o,status,known,consumed,pending)
'''
def replace(source,old,new):
    assert source.count(old)==1,(old,source.count(old))
    return source.replace(old,new)
def source_program():
    source=original.SOURCE
    source=replace(source,'word_load(s,24)>2','word_load(s,24)>5')
    source=replace(source,'        zero(w,128,128)\n','''        if word_load(s,24)>=3:
            put(o,PHASE,8)
            return 14
        zero(w,128,128)
''')
    source=replace(source,'    if phase==5:\n','''    if phase==8:
        return callable_facts(s,o,w)
    if phase==9:
        return callable_reply(s,o,w)
    if phase==5:
''')
    source+='\n'+ADDITION
    for key,value in sorted(original.C.items(),key=lambda row:-len(row[0])):
        source=re.sub(r'\b'+key+r'\b',str(value),source)
    return source
def main():
    doc=document(source_program(),'generation_lease_owner_callable_finalizer')
    path=ROOT/'examples/hia_bootstrap/generation_lease_owner_callable_finalizer.hepta'
    path.write_text(render_assembly(doc))
    print(path.name,path.stat().st_size,len(doc['functions']),sum(len(f['blocks'])for f in doc['functions']),sum(len(b['ops'])for f in doc['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
