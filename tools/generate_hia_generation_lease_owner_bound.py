"""Enclosing Runtime/Value owner with the native common provider registry.

The existing HIAGLOQ1 / 2048-byte owner ABI is retained. This policy is selected
only by HIAGLOP2, whose fixed bridge supplies the provider entry. HIAGLOP1 remains
the separately buildable original 54-role product.
"""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools import generate_hia_generation_lease_owner as original
from tools import generate_hia_generation_lease_owner_provider_packer as provider
ROOT=Path(__file__).resolve().parents[1]
ADDITION=r'''
def provider_prefix(o:mutbuf,w:mutbuf) -> u32:
    within(o,2048,CHILD,128)
    zero(w,1280,768)
    put(w,1280,PROVIDER_CONTEXT)
    put(w,1288,get(o,400))
    put(w,1320,get(o,512))
    put(w,1328,get(o,512)+1280)
    put(w,1336,get(o,552))
    put(w,1344,get(o,512)+256)
    put(w,1352,256)
    put(w,1360,get(o,536))
    put(w,1368,get(o,512)+512)
    put(w,1376,256)
    put(w,1384,get(o,552)+PAYLOAD_OFFSET)
    put(w,1392,get(o,512)+1792)
    put(w,1400,256)
    put(w,1408,get(w,664))
    put(w,80,11)
    return provider_control(o,0,80)

def provider_control(o:mutbuf,op:u64,next:u64) -> u32:
    zero(o,RQ,128)
    zero(o,CHILD,128)
    put(o,RQ,PROVIDER_CONTROL)
    put(o,RQ+8,op)
    put(o,PHASE,next)
    return 26

def provider_reply(o:mutbuf) -> bool:
    if get(o,FEEDBACK)!=0 or get(o,CHILD)!=PROVIDER_REPLY:
        return False
    if get(o,CHILD+16)!=4 or get(o,CHILD+72)!=1:
        return False
    if get(o,CHILD+80)!=0 or get(o,CHILD+88)>1:
        return False
    i=24
    while i<72:
        if get(o,CHILD+i)!=0:
            return False
        i=i+8
    i=96
    while i<128:
        if get(o,CHILD+i)!=0:
            return False
        i=i+8
    return True

def provider_ok(o:mutbuf) -> bool:
    return provider_reply(o) and get(o,CHILD+8)==0 and get(o,CHILD+88)==0

def provider_rollback(o:mutbuf,w:mutbuf,keep:u64) -> u32:
    put(w,80,12)
    put(o,1216,keep)
    return provider_control(o,2,84)

def provider_phases(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==80:
        if provider_ok(o)==False or get(w,1296)!=1:
            return unlock(o,w,5,0)
        put(w,80,1)
        if word_load(s,8)==3:
            return value_control(o,VALUE5,56,54)
        if get(o,2048)==VREPLY1:
            within(o,CHILD,2048,128)
            return unlock(o,w,0,4)
        return unlock(o,w,0,0)
    if phase==81:
        if provider_ok(o)==False or get(w,1296)!=1:
            return unlock(o,w,5,0)
        return value_control(o,VALUE5,52,15)
    if phase==82:
        if provider_ok(o) and get(w,1296)==2:
            return private_cleanup(o)
        put(o,1216,0)
        if provider_reply(o) and get(w,1296)==1:
            put(w,80,13)
            return value_control(o,VALUE5,53,85)
        put(w,80,12)
        return unlock(o,w,5,0)
    if phase==83:
        if provider_ok(o)==False or get(w,1296)!=3:
            return unlock(o,w,5,0)
        put(w,80,5)
        return value_control(o,VALUE2,30,16)
    if phase==84:
        if provider_ok(o)==False or get(w,1296)!=1:
            return unlock(o,w,5,0)
        put(w,80,13)
        return value_control(o,VALUE5,53,85)
    if phase==85:
        put(o,608,get(o,FEEDBACK))
        if value_ok(o,VREPLY1)==False:
            return unlock(o,w,5,0)
        put(w,80,1)
        if get(o,1216)!=0:
            within(o,CHILD,2048,128)
            put(o,608,get(o,592))
            return unlock(o,w,2,1)
        return unlock(o,w,2,0)
    return BAD

def provider_binding(o:mutbuf,w:mutbuf) -> bool:
    if get(w,1280)!=PROVIDER_CONTEXT or get(w,1288)!=get(o,400):
        return False
    if get(w,1320)!=get(o,512) or get(w,1328)!=get(o,512)+1280 or get(w,1336)!=get(o,552):
        return False
    if get(w,1344)!=get(o,512)+256 or get(w,1352)!=256:
        return False
    if get(w,1360)!=get(o,536) or get(w,1368)!=get(o,512)+512 or get(w,1376)!=256:
        return False
    if get(w,1384)!=get(o,552)+PAYLOAD_OFFSET or get(w,1392)!=get(o,512)+1792 or get(w,1400)!=256:
        return False
    return get(w,1408)==get(w,664) and get(w,1296)==1
'''
def replace(source,old,new,count=1):
    assert source.count(old)==count,(old,source.count(old),count)
    return source.replace(old,new)

def source_program():
    source=original.SOURCE
    source=replace(source,'    if phase==20:\n', '    if phase>=80 and phase<=85:\n        return provider_phases(s,o,w,phase)\n    if phase==20:\n')
    source=replace(source,'        put(w,80,1)\n        return unlock(o,w,0,4)\n','        return provider_prefix(o,w)\n')
    source=replace(source,'        put(w,80,2)\n        return private_cleanup(o)\n','        put(w,80,2)\n        return provider_control(o,1,82)\n')
    source=replace(source,'        put(w,80,5)\n        return value_control(o,VALUE2,30,16)\n','        put(w,80,14)\n        return provider_control(o,3,83)\n')
    source=replace(source,'            return value_control(o,VALUE5,53,46)\n','            return provider_rollback(o,w,1)\n',2)
    source=replace(source,'        return value_control(o,VALUE5,52,15)\n','        return provider_control(o,4,81)\n')
    source=replace(source,'    if state==1:\n        if get(w,768)!=FINALIZER', '    if state==1:\n        if provider_binding(o,w)==False:\n            return unlock(o,w,1,0)\n        if get(w,768)!=FINALIZER')
    source=replace(source,'    if op==0:\n        if state==1:', '    if op==0:\n        if state==11:\n            return provider_control(o,0,80)\n        if state==1:')
    source=replace(source,'        if state==10:\n', '''        if state==11:
            return provider_control(o,0,80)
        if state==12:
            put(o,1216,0)
            return provider_control(o,2,84)
        if state==13:
            put(o,1216,0)
            return value_control(o,VALUE5,53,85)
        if state==14:
            return provider_control(o,3,83)
        if state==10:
''')
    source+='\n'+ADDITION
    constants=dict(original.C)
    constants.update(PROVIDER_CONTEXT=int.from_bytes(b'HIAGPCX1','little'),
                     PROVIDER_CONTROL=int.from_bytes(b'HIAGPCQ1','little'),
                     PROVIDER_REPLY=int.from_bytes(b'HIAMVBO2','little'),
                     PAYLOAD_OFFSET=provider.PAYLOAD_OFFSET)
    for key,value in sorted(constants.items(),key=lambda item:-len(item[0])):
        source=re.sub(r'\b'+key+r'\b',str(value),source)
    return source
def main():
    doc=document(source_program(),'generation_lease_owner_bound')
    path=ROOT/'examples/hia_bootstrap/generation_lease_owner_bound.hepta'
    path.write_text(render_assembly(doc))
    print(path.name,path.stat().st_size,len(doc['functions']),sum(len(f['blocks']) for f in doc['functions']),flush=True)
if __name__=='__main__':main()
