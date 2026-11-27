"""Private Runtime constructor generation and ordered Path hook.

The previous raw domain is preserved. Only the private HC1 Runtime capture
enables typed Clang and the Path policy at the actual coordinator's directory
action, after admission and the original optional proof.
"""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_generation_lease_owner_generation_effects as prior
from tools import generate_hia_multiversion_runtime_effects as original
from tools import generate_hia_generation_runtime_constructor_handles as handles
ROOT=Path(__file__).resolve().parents[1]
def replace(s,a,b):
    assert s.count(a)==1,(a,s.count(a))
    return s.replace(a,b,1)
def source_program():
    s=prior.source_program();c=original.C
    marker=f"    put(o,{c['FRAME']},{c['GENREQ']})\n"
    extra=marker+f'''    if get(w,424)=={handles.CONTEXT} and get(o,{c['OP']})==0:
        put(o,{c['FRAME']},{int.from_bytes(b'HIAMVGX3','little')})
        copy(o,{c['FRAME']+224},w,456,24)
'''
    fn=re.search(r'def begin_generation\(.*?(?=\ndef |\Z)',s,re.S).group(0)
    assert fn.count(marker)==1
    s=s.replace(fn,fn.replace(marker,extra),1)
    s=replace(s,'    if phase>=1300:\n',f'''    if phase==2009:
        return feedback(o,6)
    if phase==2019:
        return finish_context(o,w)
    if phase==2029:
        return result(o,w,5)
    if phase>=2000:
        return 35
    if phase>=1300:
''')
    marker='    if phase==700:\n'
    s=replace(s,marker,marker+f'''        if get(w,424)=={handles.CONTEXT} and get(w,528)!=1:
            return 35
''')
    marker='def finish_context(o:mutbuf,w:mutbuf) -> u32:\n'
    s=replace(s,marker,marker+f'''    if get(w,424)=={handles.CONTEXT} and get(w,512)!=0:
        return again(o,2010)
''')
    fn=re.search(r'def result\(.*?(?=\ndef |\Z)',s,re.S).group(0)
    assert fn.count('    return 0\n')==1
    new=fn.replace('    return 0\n',f'''    if get(w,560)=={int.from_bytes(b'HIARTDE1','little')}:
        copy(o,160,w,560,136)
        zero(w,560,136)
    return 0
''')
    s=s.replace(fn,new,1)
    return s
def main():
    tree=document(source_program(),'generation_runtime_constructor_generation_effects')
    path=ROOT/'examples/hia_bootstrap/generation_runtime_constructor_generation_effects.hepta'
    path.write_text(render_assembly(tree))
    print(path.name,path.stat().st_size,len(tree['functions']),
      sum(len(f['blocks'])for f in tree['functions']),sum(len(b['ops'])for f in tree['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
