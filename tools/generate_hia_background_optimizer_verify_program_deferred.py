"""VFY5/6: native verifier with explicit deferred sole-Value custody."""
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools import generate_hia_background_optimizer_verify_program as original
from tools import hia_background_managed_value_source as M
from tools import hia_background_decision_deferred_source as D
ROOT=Path(__file__).resolve().parents[1]
def magic(s):return int.from_bytes(s.encode(),"little")
C=dict(original.C)
C.update(M.MAGICS)
C.update(D_QUEUE=816,D_UNKNOWN=824,D_VOP=832,VALUE_INPUT=C["VREQUEST"],VALUE_REPLY=C["VREPLY"])
for a,b in {
 "MAGIC":"HIABVFY5","NEW_MAGIC":"HIABVFY5","VERIFIED":"HIABVFY6","NEW_VERIFIED":"HIABVFY6",
 "REPLY":"HIABVFR3","NEW_REPLY":"HIABVFR3","CONTEXT":"HIABVYC3","NEW_CONTEXT":"HIABVYC3",
 "TREQUEST":"HIABTC05","NEW_TREQUEST":"HIABTC05","TRETRY":"HIABTC06","NEW_TRETRY":"HIABTC06",
 "TREPLY":"HIABTV03","NEW_TREPLY":"HIABTV03","TCONTEXT":"HIABVC03","NEW_TCONTEXT":"HIABVC03",
 "FREQUEST":"HIABFZQ3","NEW_FREQUEST":"HIABFZQ3","FREPLY":"HIABFZR3","NEW_FREPLY":"HIABFZR3",
 "FCONTEXT":"HIABFZC3","NEW_FCONTEXT":"HIABFZC3"}.items():C[a]=magic(b)

def source_template():
    text=D.symbolic(original)
    text=M.replace(text,"def verify_program(","def verify_program_deferred(")
    for phase,cap in [(3,"CAP"),(4,"STRUCTCAP")]:
        text=M.replace(text,
          f"    if phase=={phase}:\n        if value_ok(o)==False:\n            return value_fail(o)\n        within(o,{cap},RP+24,24)",
          f"    if phase=={phase}:\n        if deferred_take(o,{cap})==0:\n            return value_fail(o)")
    text=M.replace(text,"return memory(o,114,0,get(o,TOUT),3,HEAD,128)",
                        "return memory(o,114,0,get(o,TOUT),3,HEAD,192)")
    text=M.replace(text,"return memory(o,202,0,get(o,TOUT),3,HEAD,128)",
                        "return memory(o,202,0,get(o,TOUT),3,HEAD,192)")
    # TC05 moved its private continuation fields above the new reply trailer.
    text=M.replace(text,"return memory(o,113,3,TMP,0,get(o,TOUT)+136,8)",
                        "return memory(o,113,3,TMP,0,get(o,TOUT)+264,8)")
    text=M.replace(text,"        status=get(o,HEAD+8)\n        if get(o,MODERN)!=0:\n            kind=get(o,HEAD+112)",
        "        if managed_pending(o,HEAD,128,136,144,152)==0:\n            return quarantine(o,w,114)\n"
        "        status=get(o,HEAD+8)\n        if get(o,MODERN)!=0:\n            kind=get(o,HEAD+112)")
    text=M.replace(text,"        status=get(o,HEAD+8)\n        if get(o,MODERN)!=0:\n            retained=get(o,HEAD+56)",
        "        if managed_pending(o,HEAD,128,136,144,152)==0:\n            return quarantine(o,w,202)\n"
        "        status=get(o,HEAD+8)\n        if get(o,MODERN)!=0:\n            retained=get(o,HEAD+56)")
    text=M.replace(text,"    if phase==700:\n        if get(o,TYPED_PENDING)!=0:",
        "    if phase==700:\n        if get(o,D_UNKNOWN)!=0:\n            return quarantine(o,w,get(o,DETAIL))\n"
        "        if get(o,TYPED_PENDING)!=0:")
    text=M.replace(text,"def quarantine(o:mutbuf,w:mutbuf,detail:u64) -> u32:\n    if get(o,MODERN)!=0:",
        "def quarantine(o:mutbuf,w:mutbuf,detail:u64) -> u32:\n"
        "    if get(o,D_UNKNOWN)!=0:\n        put(o,QUARANTINE_KIND,2)\n    if get(o,MODERN)!=0:")
    text=M.replace(text,"        put(o,72,choose(pending,1,0))\n    return 0",
        "        put(o,72,choose(pending,1,0))\n"
        "    put(o,128,get(o,D_QUEUE))\n"
        "    put(o,136,managed_local_pending(o))\n"
        "    put(o,144,get(o,D_UNKNOWN))\n    put(o,152,1)\n    return 0")
    return D.apply(text)

def source_program():return M.render(source_template(),C,"verify_program_deferred")
def main():
    name="background_optimizer_verify_program_deferred"
    d=document(source_program(),name)
    p=ROOT/"examples/hia_bootstrap"/(name+".hepta")
    p.write_text(render_assembly(d))
    print(p.name,p.stat().st_size,len(d["functions"]),
          sum(len(f["blocks"])for f in d["functions"]),
          sum(len(b["ops"])for f in d["functions"]for b in f["blocks"]),flush=True)
if __name__=="__main__":main()
