"""Private scalar intake over an actual VFY-owned canonical Core capture.

The enclosing constructor obtains this input from its fixed VFY3/4 component,
checks the actual profile and equal original/Core bytes, and retains the owned
payload until this call returns. The ordinary HIAMVNQ1 process path is intact.
The new HIAMVNQ2 path still runs real Core admission, canonical identity checks,
scalar-profile validation and ABI construction. Its completion mask is 61:
this entry did not itself duplicate or execute the normalizer.
"""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_multiversion_prepare_intake as original

ROOT=Path(__file__).resolve().parents[1]
CAPTURED=int.from_bytes(b'HIAMVNQ2','little')
MODE=368

def replace_once(source,old,new):
    assert source.count(old)==1,(old,source.count(old))
    return source.replace(old,new)

def source_program():
    source=original.SOURCE
    source=replace_once(source,
        '    if length(s)<128 or readword(s,0)!=REQUEST or readword(s,8)>1:\n',
        '    if length(s)<128 or (readword(s,0)!=REQUEST and readword(s,0)!=CAPTURED) or readword(s,8)>1:\n')
    source=replace_once(source,'    if readword(s,32)!=0 and (readword(s,32)&7)!=0:\n',
        '    if readword(s,0)==CAPTURED and readword(s,32)!=0:\n        return 4294967293\n    if readword(s,32)!=0 and (readword(s,32)&7)!=0:\n')
    source=replace_once(source,'    put(w,360,readword(s,16))\n',
        '    put(w,360,readword(s,16))\n    put(w,CAPTURE_MODE,choose(readword(s,0)==CAPTURED,1,0))\n')
    source=replace_once(source,'        put(w,224,2)\n',
        '        if get(w,CAPTURE_MODE)==1:\n            return captured_core(o,w)\n        put(w,224,2)\n')
    source+='''
def captured_core(o:mutbuf,w:mutbuf) -> u32:
    n=get(w,144)
    zero(w,NORMAL,64)
    put(w,NORMAL,NORM)
    put(w,NORMAL+32,n)
    put(w,NORMAL+40,n)
    copy(w,RAW,NORMAL+64,n)
    copy(w,RAW,NORMAL+64+n,n)
    put(w,248,64+n*2)
    return guard(o,w,8)

def choose(condition:bool,yes:u64,no:u64) -> u64:
    if condition:
        return yes
    return no
'''
    constants=dict(original.C,CAPTURED=CAPTURED,CAPTURE_MODE=MODE)
    for name,value in sorted(constants.items(),key=lambda item:-len(item[0])):
        source=re.sub(r'\b'+name+r'\b',str(value),source)
    return source

def main():
    tree=document(source_program(),'generation_lease_owner_intake')
    path=ROOT/'examples/hia_bootstrap/generation_lease_owner_intake.hepta'
    path.write_text(render_assembly(tree))
    print(path.name,path.stat().st_size,len(tree['functions']),
          sum(len(f['blocks'])for f in tree['functions']),
          sum(len(b['ops'])for f in tree['functions']for b in f['blocks']),flush=True)

if __name__=='__main__':main()
