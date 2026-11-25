"""Capture the fixed constructor; defer receipt interpretation until artifact pin/read."""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_multiversion_prepare_build as base
ROOT=Path(__file__).resolve().parents[1]
def source_program():
    s=base.SOURCE
    a='readword(s,8)!=0';assert s.count(a)==1;s=s.replace(a,'readword(s,8)!=1')
    a='''        zero(w,JSONWORK,128)
        put(w,JSONWORK+48,131073)
        put(w,JSONWORK+56,128)
        return role(w,12,4,JSON,get(w,160),ARENA,16777216,JSONWORK,8388608)'''
    b='''        if length(o)-512<get(w,160):
            return fail(o,w,4,512+get(w,160))
        copy_output(w,JSON,o,512,get(w,160))
        put(w,224,get(w,160))
        put(w,96,0)
        return image_read(o,w,13)'''
    assert s.count(a)==1;s=s.replace(a,b)
    s+='\n'+base.labels()
    for k,v in sorted(base.C.items(),key=lambda x:-len(x[0])):s=re.sub(r'\b'+k+r'\b',str(v),s)
    return s

def main():
    t=document(source_program(),'multiversion_prepare_capture');p=ROOT/'examples/hia_bootstrap/multiversion_prepare_capture.hepta';p.write_text(render_assembly(t));print(p.name,p.stat().st_size,len(t['functions']),sum(len(f['blocks']) for f in t['functions']),flush=True)
if __name__=='__main__':main()
