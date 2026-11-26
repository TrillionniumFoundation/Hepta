"""Private baseline preparation after the fixed enclosing VFY capture.

HIAMVGX2 is restricted to baseline initialization. Its Core intake consumes
the actual canonical bytes retained by the enclosing constructor, with real
admission/profile/ABI checks and the original proof/build/load/probe stages.
Every ordinary HIAMVGX1 request and subsequent lifecycle operation remains.
"""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_multiversion_runtime_generation as original

ROOT=Path(__file__).resolve().parents[1]
CAPTURED=int.from_bytes(b'HIAMVGX2','little')
CAPTURE_INTAKE=int.from_bytes(b'HIAMVNQ2','little')
MODE=400

def replace_once(source,old,new):
    assert source.count(old)==1,(old,source.count(old))
    return source.replace(old,new)

def source_program():
    source=original.SOURCE
    source=replace_once(source,
        '    if length(s)<256 or readword(s,0)!=REQUEST:\n',
        '    if length(s)<256 or (readword(s,0)!=REQUEST and readword(s,0)!=CAPTURED):\n')
    source=replace_once(source,'    op=readword(s,8)\n',
        '''    op=readword(s,8)
    if readword(s,0)==CAPTURED:
        if op!=0 or readword(s,72)!=1:
            return 4294967293
''')
    source=replace_once(source,'    put(w,CTRL+16,STATE)\n',
        '    put(w,CTRL+16,STATE)\n    put(w,CTRL+CAPTURE_MODE,choose(readword(s,0)==CAPTURED,1,0))\n')
    source=replace_once(source,'    put(w,FRAME,INTAKE)\n',
        '    put(w,FRAME,choose(get(w,CTRL+CAPTURE_MODE)==1,CAPTURE_INTAKE,INTAKE))\n')
    source=replace_once(source,'get(w,OUT+248)!=63',
        'get(w,OUT+248)!=choose(get(w,CTRL+CAPTURE_MODE)==1,61,63)')
    source+='''
def choose(condition:bool,yes:u64,no:u64) -> u64:
    if condition:
        return yes
    return no
'''
    constants=dict(original.C,CAPTURED=CAPTURED,CAPTURE_INTAKE=CAPTURE_INTAKE,CAPTURE_MODE=MODE)
    for name,value in sorted(constants.items(),key=lambda item:-len(item[0])):
        source=re.sub(r'\b'+name+r'\b',str(value),source)
    return source

def main():
    tree=document(source_program(),'generation_lease_owner_generation')
    path=ROOT/'examples/hia_bootstrap/generation_lease_owner_generation.hepta'
    path.write_text(render_assembly(tree))
    print(path.name,path.stat().st_size,len(tree['functions']),
          sum(len(f['blocks'])for f in tree['functions']),
          sum(len(b['ops'])for f in tree['functions']for b in f['blocks']),flush=True)

if __name__=='__main__':main()
