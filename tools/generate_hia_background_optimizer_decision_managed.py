"""DO03 decision capsule with deferred Value and nested retirement domains."""
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools import generate_hia_background_optimizer_decision_bound as original
from tools import hia_background_managed_value_source as M
from tools import hia_background_decision_deferred_source as D
ROOT=Path(__file__).resolve().parents[1]
def magic(s):return int.from_bytes(s.encode(),"little")
C=dict(original.C);C.update(M.MAGICS)
C.update(D_QUEUE=2552,D_UNKNOWN=2560,D_VOP=2568,
         VALUE_INPUT=C["VREQUEST"],VALUE_REPLY=C["VREPLY"])
for a,b in {"MAGIC":"HIABDO03","REPLY":"HIABDRP3","CONTEXT":"HIABDOC3",
 "FREQUEST":"HIABFZQ3","FREPLY":"HIABFZR3","FCONTEXT":"HIABFZC3",
 "IREQUEST":"HIABIQ03","IREPLY":"HIABIO03","ICONTEXT":"HIABIC03",
 "YREQUEST":"HIABVFY5","YREPLY":"HIABVFR3","YCONTEXT":"HIABVYC3"}.items():C[a]=magic(b)

def source_template():
    text=D.decision_symbolic(original)
    text=M.replace(text,"def decision_bound(","def decision_managed(")
    text=M.replace(text,
        "    if phase==3:\n        if value_ok(o)==False:\n            return value_fail(o)\n"
        "        within(o,CMETA+get(o,RETAIN_AT)*24,RP+24,24)",
        "    if phase==3:\n        if deferred_take(o,CMETA+get(o,RETAIN_AT)*24)==0:\n"
        "            return value_fail(o)")
    for phase in (602,1002,1202):
        text=M.replace(text,f"return memory(o,{phase},0,get(o,NESTED),3,HEAD,128)",
                            f"return memory(o,{phase},0,get(o,NESTED),3,HEAD,192)")
    text=M.replace(text,"return memory(o,1500,0,get(o,NESTED)+128,3,ERRBUF,n)",
                        "return memory(o,1500,0,get(o,NESTED)+256,3,ERRBUF,n)")
    for phase,magic_name,flags in [(602,"IREPLY",(72,80,88,96)),(1002,"FREPLY",(128,136,144,152)),(1202,"YREPLY",(128,136,144,152))]:
        old=f"        if get(o,HEAD)!={magic_name}:\n            return fail(o,7,{phase})"
        new=old+f"\n        if managed_pending(o,HEAD,{flags[0]},{flags[1]},{flags[2]},{flags[3]})==0:\n"
        new+=f"            return bound_quarantine(o,w,2,{phase})"
        text=M.replace(text,old,new)
    # Any actually delivered verifier payload is adopted before retained-state handling.
    transfer="""        status=get(o,HEAD+8)
        if status<=2 and get(o,HEAD+16)!=0:
            dest=choose(status==0,get(o,VPAY),PERROR)
            within(o,dest,HEAD+16,24)
            put(o,dest+24,get(o,HEAD+40))
"""
    text=M.replace(text,transfer,"        status=get(o,HEAD+8)\n")
    point="        if get(o,HEAD+56)!=0 or get(w,6296)!=0:"
    transfer=transfer.replace("            within(o,dest,HEAD+16,24)",
        "            if get(o,dest)!=0:\n                return bound_quarantine(o,w,2,1202)\n"
        "            within(o,dest,HEAD+16,24)")
    text=M.replace(text,point,transfer+point)
    text=M.replace(text,"    if phase==3000:\n        if get(o,DROP_ACTIVE)!=0",
        "    if phase==3000:\n        if get(o,D_UNKNOWN)!=0:\n            return bound_quarantine(o,w,2,3000)\n"
        "        if get(o,DROP_ACTIVE)!=0")
    text=M.replace(text,
        "    put(o,QUARANTINE_KIND,choose(get(o,BOUND_QUARANTINE)==1,1,2))",
        "    kind=2\n    if get(o,BOUND_QUARANTINE)==1 and get(o,D_UNKNOWN)==0:\n        kind=1\n    put(o,QUARANTINE_KIND,kind)")
    text=M.replace(text,"    put(o,96,get(o,DETAIL))",
        "    put(o,96,get(o,DETAIL))\n    put(o,192,get(o,D_QUEUE))\n"
        "    put(o,200,managed_local_pending(o))\n"
        "    put(o,208,get(o,D_UNKNOWN))\n    put(o,216,1)")
    old="return invoke(o,1201,get(w,88),259,RQ,128,get(o,NESTED),262144,6144,4096)"
    assert text.count(old)==2
    text=text.replace(old,"return fixed_verify(o,w,1201)")
    text+="""
def fixed_verify(o:mutbuf,w:mutbuf,next:u64) -> u32:
    invoke(o,next,0,259,RQ,128,get(o,NESTED),262144,6144,4096)
    return 16
"""
    return D.apply(text)
def source_program():return M.render(source_template(),C,"decision_managed")
def main():
    name="background_optimizer_decision_managed"
    d=document(source_program(),name);p=ROOT/"examples/hia_bootstrap"/(name+".hepta")
    p.write_text(render_assembly(d))
    print(p.name,p.stat().st_size,len(d["functions"]),
          sum(len(f["blocks"])for f in d["functions"]),
          sum(len(b["ops"])for f in d["functions"]for b in f["blocks"]),flush=True)
if __name__=="__main__":main()
