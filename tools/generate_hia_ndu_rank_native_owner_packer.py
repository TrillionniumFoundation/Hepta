"""Native packer for the six-role NDU execution owner and its mechanical callback ABI."""
from pathlib import Path
import re
from tools.generate_hia_ndu_evaluator import document
from tools.generate_hia_ndu_evaluator_packer import capsule,literal
from hepta.hia_agent_assembly import render_assembly
ROOT=Path(__file__).resolve().parents[1]
SOURCE=r'''
def pack(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)<64 or length(o)<8388608:
        return 4294967293
    if word_load(s,0)!=MAGIC or word_load(s,56)>1:
        return 4294967295
    total=64
    i=0
    while i<6:
        n=word_load(s,8+i*8)
        if n<16 or n>1048576:
            return 4294967295
        total=total+n
        i=i+1
    if total!=length(s):
        return 4294967295
    at=0
    if word_load(s,56)==1:
        effects_prefix(o,0)
        poke32(o,EFFECT_CALL,EFFECT_BYTES-EFFECT_CALL-4)
        at=EFFECT_BYTES
    join_prefix(o,at)
    target=at+JOIN_BYTES
    offset=64
    i=0
    while i<6:
        n=word_load(s,8+i*8)
        copy(s,o,offset,target,n)
        p=join_call(i)
        poke32(o,at+p,target-at-p-4)
        if i==0:
            poke32(o,at+SAMPLE_CALL,target-at-SAMPLE_CALL-4)
        offset=offset+n
        target=target+n
        i=i+1
    return target
def join_call(i:u64) -> u64:
    if i==0:
        return OWNER_CALL
    if i==1:
        return SHA_CALL
    if i==2:
        return ID_CALL
    if i==3:
        return PATH_CALL
    if i==4:
        return PUMP_CALL
    return JSON_CALL
def copy(s:readbuf,o:mutbuf,at:u64,to:u64,n:u64) -> u64:
    i=0
    while n-i>=8:
        word_store(o,to+i,word_load(s,at+i))
        i=i+8
    while i<n:
        store(o,to+i,byte(s,at+i))
        i=i+1
    return 0
def poke32(o:mutbuf,at:u64,v:u64) -> u64:
    store(o,at,v)
    store(o,at+1,v>>8)
    store(o,at+2,v>>16)
    store(o,at+3,v>>24)
    return 0
'''
def program():
    join,j=capsule('hia_ndu_rank_native_owner_join.S');effect,e=capsule('hia_ndu_rank_native_owner_effects.S')
    C={'MAGIC':int.from_bytes(b'HIANOP02','little'),'JOIN_BYTES':len(join),'EFFECT_BYTES':len(effect),'EFFECT_CALL':e['effect_policy_call'],'OWNER_CALL':j['owner_call'],'SAMPLE_CALL':j['cancel_sample_call'],'SHA_CALL':j['sha_call'],'ID_CALL':j['identity_call'],'PATH_CALL':j['path_call'],'PUMP_CALL':j['pump_call'],'JSON_CALL':j['json_call']}
    s=SOURCE+'\n'+literal('join_prefix',join,True)+'\n'+literal('effects_prefix',effect,True)
    for k,v in C.items():s=re.sub(r'\b'+k+r'\b',str(v),s)
    return s
if __name__=='__main__':
    d=document(program(),'ndu_rank_native_owner_packer');p=ROOT/'examples/hia_bootstrap/ndu_rank_native_owner_packer.hepta';p.write_text(render_assembly(d));print(p.name,p.stat().st_size,len(d['functions']),sum(len(f['blocks'])for f in d['functions']),sum(len(b['ops'])for f in d['functions']for b in f['blocks']))
