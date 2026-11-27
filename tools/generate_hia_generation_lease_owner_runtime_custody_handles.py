"""New carrier profile: retire actual Runtime resource custody before freeing it."""
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_generation_lease_owner_component_handles as prior
ROOT=Path(__file__).resolve().parents[1]
REQUEST=int.from_bytes(b'HIARTLQ1','little')
REPLY=int.from_bytes(b'HIARTLR1','little')
HOOK_RC=600
def source_program():
 s=prior.source_program();c=prior.base.original.C
 old=f'''    if phase==620:
        # Never reuse neighbours captured before the unlocked finalizer.
        return memory(o,621,0,get(o,{c['OBJ']}),3,{c['HEADER']},192)
'''
 new=f'''    if phase==620:
        if get(o,{c['KIND']})==1:
            zero(o,{c['CHILD_I']},128)
            put(o,{c['CHILD_I']},{REQUEST})
            put(o,{c['CHILD_I']+8},1)
            put(o,{c['CHILD_I']+24},get(o,{c['OBJ']}))
            return unlock(o,650)
        return memory(o,621,0,get(o,{c['OBJ']}),3,{c['HEADER']},192)
    if phase==650:
        put(o,{c['PHASE']},651)
        return 13
    if phase==651:
        put(o,{HOOK_RC},get(o,{c['FEEDBACK']}))
        return lock(o,652)
    if phase==652:
        if get(o,{HOOK_RC})!=0 or get(o,{c['CHILD_O']})!={REPLY} or get(o,{c['CHILD_O']+88})!=1 or get(o,{c['CHILD_O']+80})!=0 or get(o,{c['CHILD_O']+104})!=1:
            put(o,{c['RETAINED']},1)
            put(o,{c['FINAL_RC']},choose(get(o,{HOOK_RC})!=0,get(o,{HOOK_RC}),9))
            return write_pointer(o,619,get(o,{c['OBJ']})+128,3)
        return memory(o,621,0,get(o,{c['OBJ']}),3,{c['HEADER']},192)
'''
 assert s.count(old)==1;s=s.replace(old,new)
 return s
def main():
 tree=document(source_program(),'generation_lease_owner_runtime_custody_handles')
 path=ROOT/'examples/hia_bootstrap/generation_lease_owner_runtime_custody_handles.hepta';path.write_text(render_assembly(tree))
 print(path.name,path.stat().st_size,len(tree['functions']),sum(len(f['blocks'])for f in tree['functions']),sum(len(b['ops'])for f in tree['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
