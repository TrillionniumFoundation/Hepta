"""Generation custody before the enclosing Runtime releases its workspace.

This is a new native-owner profile. The frozen public-carrier profile is kept
unchanged. The fixed bridge's action 34 calls only the captured native proxy
close entry, and a real retired ACK is required before munmap.
"""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_generation_lease_typed as typed
from tools import generate_hia_multiversion_public_lease_admission as public
from tools import generate_hia_multiversion_runtime_effects as original
ROOT=Path(__file__).resolve().parents[1]
CLOSE_REQUEST=int.from_bytes(b'HIAGPBQ1','little')
CLOSE_REPLY=int.from_bytes(b'HIAGPBR1','little')
def replace_once(source,old,new):
    assert source.count(old)==1,(old,source.count(old))
    return source.replace(old,new,1)
def source_program():
    source=typed.effects_source()
    fn=re.search(r'def generation_release\(.*?(?=\ndef |\Z)',original.SOURCE,re.S).group(0)
    updated=replace_once(fn,
        '            return system(o,353,11,0,get(o,GO+32),GW,0,0,0,0)',
        '''            zero(o,FRAME,128)
            put(o,FRAME,CLOSE_REQUEST)
            put(o,FRAME+8,1)
            return role(o,362,34,3,FRAME,128,3,GOUT,128,0,get(o,GO+32),GW)''')
    updated=replace_once(updated,'    if phase==353:\n',
        '''    if phase==362:
        if get(o,FEEDBACK)!=0 or get(o,GOUT)!=CLOSE_REPLY or get(o,GOUT+88)!=1 or get(o,GOUT+104)!=1 or get(o,GOUT+80)!=0:
            put(w,312,1)
            put(o,NATIVE_ERROR,choose(get(o,FEEDBACK)!=0,get(o,FEEDBACK),5))
            return private_lock(o,2,264,get(o,AFTER_GEN))
        return system(o,353,11,0,get(o,GO+32),GW,0,0,0,0)
    if phase==353:
''')
    source=replace_once(source,public.substitute(fn,original.C),
        public.substitute(updated,{**original.C,'CLOSE_REQUEST':CLOSE_REQUEST,'CLOSE_REPLY':CLOSE_REPLY}))
    assert 'if phase>=350 and phase<370:' in source  # Includes private phase 362.
    return source
def main():
    tree=document(source_program(),'generation_lease_owner_generation_effects')
    path=ROOT/'examples/hia_bootstrap/generation_lease_owner_generation_effects.hepta'
    path.write_text(render_assembly(tree))
    print(path.name,path.stat().st_size,len(tree['functions']),
      sum(len(f['blocks'])for f in tree['functions']),
      sum(len(b['ops'])for f in tree['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
