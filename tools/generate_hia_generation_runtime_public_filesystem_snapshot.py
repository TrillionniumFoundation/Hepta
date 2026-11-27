"""Actual empty pre-generation Runtime snapshots on the constructor profile.

No identity registry or generation has been admitted in this state. The
coordinator's initial epoch, absent current generation and zero retirement
attempts are captured only after checking all corresponding native custody
slots. Directory observations remain the existing real retirement records.
"""
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_multiversion_runtime_snapshot_capture as prior
from tools import generate_hia_generation_runtime_constructor_handles as ctor
ROOT=Path(__file__).resolve().parents[1]
EARLY=98616
def replace(s,a,b):
    assert s.count(a)==1,(a,s.count(a))
    return s.replace(a,b,1)
def source_program():
    s=prior.source_program();c=prior.C
    s=replace(s,'    return identity_select(o,1370,64)\n',
       f"""    if get(w,424)=={ctor.CONTEXT} and get(w,{c['IDENTITY']})==0:
        return constructor_empty_snapshot(o,w)
    return identity_select(o,1370,64)
""")
    s=replace(s,f"        field(o,0,get(o,{c['SC_EPOCH']}),get(o,{c['SC_EPOCHN']}))\n",
       f"""        if get(o,{EARLY})==1:
            number_field(o,get(w,{c['COOR']+40}))
        else:
            field(o,0,get(o,{c['SC_EPOCH']}),get(o,{c['SC_EPOCHN']}))
""")
    s=replace(s,f"    field(o,0,get(o,{c['SC_ATTEMPTS']}),get(o,{c['SC_ATTEMPTSN']}))\n",
       f"""    if get(o,{EARLY})==1:
        number_field(o,0)
    else:
        field(o,0,get(o,{c['SC_ATTEMPTS']}),get(o,{c['SC_ATTEMPTSN']}))
""")
    s+=f"""
def constructor_empty_snapshot(o:mutbuf,w:mutbuf) -> u32:
    if get(w,304)!=0 or get(o,{c['SC_GCOUNT']})!=0 or get(w,{c['COOR']+24})!=1:
        return capture_error(o,9)
    if get(w,{c['COOR']+40})!=0 or get(w,{c['COOR']+48})!=18446744073709551615:
        return capture_error(o,9)
    if get(w,272)!=0 or get(w,280)!=0 or get(w,312)!=0:
        return capture_error(o,9)
    if get(w,{c['COOR']+80})!=0 or get(w,{c['COOR']+88})!=0 or get(w,{c['COOR']+128})!=0:
        return capture_error(o,9)
    if get(w,{c['SHCOUNT']})!=0 or get(w,{c['SPENDING_HEAD']})!=0 or get(w,{c['SPENDING_TAIL']})!=0:
        return capture_error(o,9)
    i=0
    while i<64:
        if get(w,{c['COOR']+512}+i*256)!=0 or get(w,{c['SLOTS']}+i*16)!=0:
            return capture_error(o,9)
        i=i+1
    put(o,{EARLY},1)
    dir_capture(o,w,{c['SC_DIR']},0)
    dir_capture(o,w,{c['SC_DIR_OLD']},1)
    return build_packet(o,w)
"""
    return s
def main():
    t=document(source_program(),'generation_runtime_public_filesystem_snapshot')
    p=ROOT/'examples/hia_bootstrap/generation_runtime_public_filesystem_snapshot.hepta';p.write_text(render_assembly(t))
    print(p.name,p.stat().st_size,len(t['functions']),sum(len(f['blocks'])for f in t['functions']),sum(len(b['ops'])for f in t['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
