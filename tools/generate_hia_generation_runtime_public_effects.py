"""Derived constructor effects carrying an actual generation exception."""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_generation_runtime_constructor_generation_effects as original
from tools import generate_hia_multiversion_runtime_effects as base
ROOT=Path(__file__).resolve().parents[1]
GE=int.from_bytes(b'HIARTGE1','little')
DE=int.from_bytes(b'HIARTDE1','little')
PE=int.from_bytes(b'HIARTPE1','little')
def source_program():
    s=original.source_program()
    matches=re.findall(r'    if phase==315:\n        if [^\n]*:\n            return feedback\(o,9\)\n',s)
    assert len(matches)==1,len(matches)
    marker=matches[0]
    extra=marker+f'''        if get(o,{base.C['GOUT']+256})=={GE}:
            copy(w,560,o,{base.C['GOUT']+256},136)
            zero(o,{base.C['GOUT']+256},136)
'''
    assert s.count(marker)==1
    s=s.replace(marker,extra,1)
    initial=re.findall(r'    if phase==307:\n        if [^\n]*:\n            return feedback\(o,9\)\n',s)
    assert len(initial)==1,len(initial)
    s=s.replace(initial[0],initial[0]+f'''        copy(w,560,o,{base.C['GOUT']+256},136)
        zero(o,{base.C['GOUT']+256},136)
''',1)
    marker=f'    if get(w,560)=={DE}:\n'
    assert s.count(marker)==1
    s=s.replace(marker,f'    if get(w,560)=={DE} or get(w,560)=={GE} or get(w,560)=={PE}:\n',1)
    return s
def main():
    tree=document(source_program(),'generation_runtime_public_effects')
    p=ROOT/'examples/hia_bootstrap/generation_runtime_public_effects.hepta'
    p.write_text(render_assembly(tree))
    print(p.name,p.stat().st_size,len(tree['functions']),sum(len(f['blocks'])for f in tree['functions']),sum(len(b['ops'])for f in tree['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
