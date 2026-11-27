"""Private failed-constructor capture of the actual locked cleanup snapshot.

The old carrier domains are unchanged. A failed HC1 creation has already run
the coordinator's original preparation/directory cleanup. While the retiring
Runtime is still owned, this profile obtains its actual public snapshot, copies
the detached bytes into the caller-owned result span, and frees that allocation
before continuing the original context destruction. No receipt fields are
synthesized from a successful finalizer.
"""
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_generation_runtime_constructor_handles as prior
from tools import generate_hia_multiversion_runtime_handles as base
ROOT=Path(__file__).resolve().parents[1]
TAG=int.from_bytes(b'HIARTCL1','little')
SEEN=672
META=680
POINTER=688
SIZE=696
AREA=base.C['CHILD_I']+4096
LIMIT=base.C['SAVED']-AREA
def replace(s,a,b):
    assert s.count(a)==1,(a,s.count(a))
    return s.replace(a,b,1)
def source_program():
    s=prior.source_program();c=base.C
    marker=f"""    if phase==609:
        if get(o,{c['TEMP']})==0:
            return again(o,620)
"""
    s=replace(s,marker,marker+f"""        if get(o,528)==3 and get(o,{c['OP']})==1 and get(o,{SEEN})==0:
            put(o,{SEEN},1)
            return memory(o,653,0,get(o,{c['RUNTIME']})+256+82500,3,{META},8)
""")
    marker='    if phase==619:\n'
    s=replace(s,marker,f"""    if phase==653:
        if get(o,{META})==0:
            return again(o,609)
        constructor_snapshot_request(o,10)
        return unlock(o,654)
    if phase==654:
        return effects(o,655)
    if phase==655:
        if get(o,{c['FEEDBACK']})!=0 or get(o,{c['CHILD_O']})!={c['EFFECT_REPLY']}:
            return constructor_snapshot_unknown(o)
        if get(o,{c['CHILD_O']+144})!=0:
            put(o,{POINTER},get(o,{c['CHILD_O']+144}))
            put(o,{SIZE},get(o,{c['CHILD_O']+152}))
            put(o,{c['CHILD_O']+144},0)
            put(o,{c['CHILD_O']+152},0)
            if get(o,{c['CHILD_O']+8})!=0 or get(o,{SIZE})==0 or get(o,{SIZE})>{LIMIT}:
                return constructor_snapshot_unknown(o)
            return memory(o,656,0,get(o,{POINTER}),3,{AREA},get(o,{SIZE}))
        if get(o,{c['CHILD_O']+8})==0:
            return constructor_snapshot_unknown(o)
        return constructor_snapshot_destroy(o)
    if phase==656:
        put(o,{c['SAVED']+304},{TAG})
        put(o,{c['SAVED']+312},{AREA})
        put(o,{c['SAVED']+320},get(o,{SIZE}))
        put(o,{c['SAVED']+328},0)
        put(o,{c['SAVED']+336},1)
        return deallocate(o,657,get(o,{POINTER}))
    if phase==657:
        put(o,{POINTER},0)
        return constructor_snapshot_destroy(o)
"""+marker)
    s+=f"""
def constructor_snapshot_request(o:mutbuf,op:u64) -> u64:
    zero(o,{c['CHILD_I']},256)
    put(o,{c['CHILD_I']},{c['PUBLIC_EFFECTS']})
    put(o,{c['CHILD_I']+8},op)
    put(o,{c['CHILD_I']+72},{c['NONE']})
    put(o,{c['FRAME_N']},256)
    return 0

def constructor_snapshot_destroy(o:mutbuf) -> u32:
    constructor_snapshot_request(o,13)
    return effects(o,613)

def constructor_snapshot_unknown(o:mutbuf) -> u32:
    put(o,{c['SAVED']+304},{TAG})
    put(o,{c['SAVED']+328},9)
    put(o,{c['SAVED']+336},0)
    put(o,{c['RETAINED']},1)
    put(o,{c['FINAL_RC']},9)
    return lock(o,614)
"""
    return s
def main():
    t=document(source_program(),'generation_runtime_public_cleanup_handles')
    p=ROOT/'examples/hia_bootstrap/generation_runtime_public_cleanup_handles.hepta'
    p.write_text(render_assembly(t))
    print(p.name,p.stat().st_size,len(t['functions']),sum(len(f['blocks'])for f in t['functions']),sum(len(b['ops'])for f in t['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
