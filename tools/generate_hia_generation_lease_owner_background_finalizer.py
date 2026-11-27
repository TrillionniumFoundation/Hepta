"""Unique fixed native finalizer with installed BackgroundOptimizer custody.

The existing 1/2/3/4/5/7 paths are retained. Kind 6 is admitted only after the
native BG binder has captured the fixed catalog export and actual BG context.
The request supplies only a resource capability and the existing Value nonce.
"""
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools import generate_hia_generation_lease_owner_future_finalizer as base
ROOT=Path(__file__).resolve().parents[1]
def once(source,old,new):
    assert source.count(old)==1,(old,source.count(old))
    return source.replace(old,new)
ADDITION=r'''
def background_facts(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if get(w,128)!=get(o,80)-256:
        return unlock(o,11,0,0,0)
    if get(w,136)==0 or get(w,136)!=get(w,168):
        return unlock(o,11,0,0,0)
    if get(w,144)==0 or get(w,152)!=512 or get(w,160)==0:
        return unlock(o,11,0,0,0)
    if get(w,176)!=get(w,64) or (get(w,184)&64)==0:
        return unlock(o,11,0,0,0)
    if get(w,192)!=3552567433984297288:
        return unlock(o,11,0,0,0)
    if get(w,200)!=2 and get(w,200)!=3:
        return unlock(o,11,0,0,0)
    if get(w,208)!=get(o,80)-768 or get(w,216)!=get(w,16):
        return unlock(o,11,0,0,0)
    if get(w,224)!=get(w,144) or get(w,232)!=get(w,160):
        return unlock(o,11,0,0,0)
    if get(w,240)!=get(w,64) or get(w,248)!=get(w,136):
        return unlock(o,11,0,0,0)
    i=0
    while i<128:
        store(w,128+i,byte(s,i))
        i=i+1
    put(o,96,13)
    return 18
'''
def source_program():
    source=base.source_program()
    source=once(source,'(word_load(s,24)>7 or word_load(s,24)==6)','word_load(s,24)>7')
    source=once(source,'        if word_load(s,24)==7:\n', '''        if word_load(s,24)==6:
            put(o,96,12)
            return 17
        if word_load(s,24)==7:
''')
    source=once(source,'    if phase==10:\n', '''    if phase==12:
        return background_facts(s,o,w)
    if phase==13:
        return callable_reply(s,o,w)
    if phase==10:
''')
    return source+'\n'+ADDITION
def main():
    tree=document(source_program(),'generation_lease_owner_background_finalizer')
    path=ROOT/'examples/hia_bootstrap/generation_lease_owner_background_finalizer.hepta'
    path.write_text(render_assembly(tree))
    print(path.name,path.stat().st_size,len(tree['functions']),sum(len(f['blocks'])for f in tree['functions']),sum(len(b['ops'])for f in tree['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
