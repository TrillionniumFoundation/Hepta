"""Sole public core with the exact trusted Future-provider binding checks."""
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools import generate_hia_generation_lease_owner_sidecar_callable_core as base
ROOT=Path(__file__).resolve().parents[1]
def source_program():
    s=base.source_program()
    old='            if get(w,680)!=62:\n'
    assert s.count(old)==1
    s=s.replace(old,'            if get(w,680)!=62 and get(w,680)!=190:\n')
    old='            if get(w,704)==0 or get(w,704)!=get(w,1248) or get(w,712)!=get(w,1152)+1024 or get(w,720)!=256 or get(w,728)==0:\n                return unlock(o,w,1,0)\n'
    assert s.count(old)==1
    new=old+'''            if get(w,680)==190:
                if get(w,736)==0 or get(w,744)!=get(w,1152)+1536 or get(w,752)!=512 or get(w,760)==0:
                    return unlock(o,w,1,0)
'''
    return s.replace(old,new)
def main():
    tree=document(source_program(),'generation_lease_owner_sidecar_future_core')
    path=ROOT/'examples/hia_bootstrap/generation_lease_owner_sidecar_future_core.hepta'
    path.write_text(render_assembly(tree));print(path.name,path.stat().st_size,flush=True)
if __name__=='__main__':main()
