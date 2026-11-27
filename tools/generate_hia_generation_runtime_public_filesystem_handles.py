"""Constructor-only filesystem facts captured before native Runtime retirement."""
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_generation_runtime_public_cleanup_handles as prior
ROOT=Path(__file__).resolve().parents[1]
FSTAG=int.from_bytes(b'HIARTFE1','little')
FS_AREA=prior.base.C['SAVED']-8192
def replace(s,a,b):
    assert s.count(a)==1,(a,s.count(a))
    return s.replace(a,b,1)
def source_program():
    s=prior.source_program();c=prior.base.C
    s=replace(s,f"if get(o,{c['FEEDBACK']})!=0 or get(o,{c['CHILD_O']})!={c['EFFECT_REPLY']}:",
      f"if get(o,{c['CHILD_O']})!={c['EFFECT_REPLY']} or get(o,{c['FEEDBACK']})!=get(o,{c['CHILD_O']+8}):")
    marker=f"""    if phase==653:
        if get(o,{prior.META})==0:
            return again(o,609)
        constructor_snapshot_request(o,10)
        return unlock(o,654)
"""
    s=replace(s,marker,f"""    if phase==653:
        if get(o,{prior.META})==0:
            return again(o,609)
        return memory(o,658,0,get(o,{c['RUNTIME']})+256+82532,3,{c['SAVED']+352},8)
    if phase==658:
        raw=get(o,{c['SAVED']+352})
        if raw<18446744073709547521:
            put(o,{c['SAVED']+352},0)
            return constructor_filesystem_snapshot(o)
        return memory(o,659,0,get(o,{c['RUNTIME']})+256+224,3,{c['SAVED']+368},8)
    if phase==659:
        n=get(o,{c['SAVED']+368})
        if n==0 or n>4095:
            return constructor_snapshot_unknown(o)
        put(o,{c['SAVED']+344},{FSTAG})
        put(o,{c['SAVED']+360},{FS_AREA})
        return memory(o,660,0,get(o,{c['RUNTIME']})+256+77824,3,{FS_AREA},n)
    if phase==660:
        return constructor_filesystem_snapshot(o)
""")
    s+=f"""
def constructor_filesystem_snapshot(o:mutbuf) -> u32:
    constructor_snapshot_request(o,10)
    return unlock(o,654)
"""
    return s
def main():
    t=document(source_program(),'generation_runtime_public_filesystem_handles')
    p=ROOT/'examples/hia_bootstrap/generation_runtime_public_filesystem_handles.hepta';p.write_text(render_assembly(t))
    print(p.name,p.stat().st_size,len(t['functions']),sum(len(f['blocks'])for f in t['functions']),sum(len(b['ops'])for f in t['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
