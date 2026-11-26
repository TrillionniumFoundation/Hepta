"""Code-bound public callable core; preserves the original mask-6 owner profile."""
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools import generate_hia_generation_lease_owner_sidecar_core as base
ROOT=Path(__file__).resolve().parents[1]
def source_program():
    source=base.source_program()
    needle='        if get(w,680)!=6:\n            return unlock(o,w,1,0)\n'
    assert source.count(needle)==1
    replacement='''        if get(w,680)!=6:
            if get(w,680)!=62:
                return unlock(o,w,1,0)
            if get(w,1136)!=3555665930765814088 or get(w,1144)<2 or get(w,1144)>4:
                return unlock(o,w,1,0)
            if get(w,1152)==0 or get(w,1160)!=212992 or get(w,1168)==0 or get(w,1176)==0:
                return unlock(o,w,1,0)
            if get(w,704)==0 or get(w,704)!=get(w,1248) or get(w,712)!=get(w,1152)+1024 or get(w,720)!=256 or get(w,728)==0:
                return unlock(o,w,1,0)
'''
    source=source.replace(needle,replacement)
    public='        if magic=='+str(int.from_bytes(b'HIABVQ05','little'))+' and action!=50 and action!=51 and action!=57 and action!=62 and action!=63 and action!=67:\n            return '+str(4294967293)+'\n'
    assert source.count(public)==1,public
    widened=public.replace(' and action!=67:', ' and action!=67 and action!=68 and action!=69 and action!=70 and action!=75 and action!=87:')
    return source.replace(public,widened)
def main():
    doc=document(source_program(),'generation_lease_owner_sidecar_callable_core')
    path=ROOT/'examples/hia_bootstrap/generation_lease_owner_sidecar_callable_core.hepta'
    path.write_text(render_assembly(doc));print(path.name,path.stat().st_size,flush=True)
if __name__=='__main__':main()
