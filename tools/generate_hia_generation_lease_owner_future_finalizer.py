"""Unique sole-owner fixed finalizer: carrier 1/2, callable 3/4/5, Future 7."""
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools import generate_hia_generation_lease_owner_callable_finalizer as base
ROOT=Path(__file__).resolve().parents[1]
def once(source,old,new):
    assert source.count(old)==1,(old,source.count(old))
    return source.replace(old,new)
def source_program():
    source=base.source_program()
    source=once(source,'word_load(s,24)>5','(word_load(s,24)>7 or word_load(s,24)==6)')
    needle='        if word_load(s,24)>=3:\n            put(o,96,8)\n            return 14\n'
    source=once(source,needle,'''        if word_load(s,24)==7:
            put(o,96,10)
            return 15
'''+needle)
    source=once(source,'    if phase==8:\n', '''    if phase==10:
        return future_facts(s,o,w)
    if phase==11:
        return callable_reply(s,o,w)
    if phase==8:
''')
    start=source.index('def callable_facts(');end=source.index('\ndef callable_reply(',start)
    future=source[start:end].replace('def callable_facts(','def future_facts(')
    future=once(future,'get(w,152)!=256','get(w,152)!=512')
    future=once(future,'put(o,96,9)','put(o,96,11)')
    future=once(future,'return 13','return 16')
    return source+'\n'+future
def main():
    tree=document(source_program(),'generation_lease_owner_future_finalizer')
    path=ROOT/'examples/hia_bootstrap/generation_lease_owner_future_finalizer.hepta'
    path.write_text(render_assembly(tree));print(path.name,path.stat().st_size,flush=True)
if __name__=='__main__':main()
