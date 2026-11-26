"""Author an independent private lease-admission protocol over real MV owners.

Old handles/effects/state source bytes and old request semantics are unchanged.
HIAMVLA1 is accepted only by these explicit public-runtime roles and only for
one real registered lease require-open action. It grants no numeric/proof facts.
"""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools import generate_hia_multiversion_runtime_handles as handles
from tools import generate_hia_multiversion_runtime_effects as effects
from tools import generate_hia_multiversion_runtime_state as state
ROOT=Path(__file__).resolve().parents[1]
LEASE_MAGIC=int.from_bytes(b'HIAMVLA1','little')
STATE_MAGIC=int.from_bytes(b'HIAMVC03','little')
I_ADMISSION=26880

def substitute(source,constants):
    for key,value in sorted(constants.items(),key=lambda item:-len(item[0])):
        source=re.sub(r'\b'+key+r'\b',str(value),source)
    return source

def replace_once(source,before,after):
    assert source.count(before)==1,(before,source.count(before))
    return source.replace(before,after,1)

def handles_source():
    source=handles.SOURCE
    marker='''def valid_command(s:readbuf,o:mutbuf,kind:u64) -> u64:
'''
    source=replace_once(source,marker,marker+'''    if word(s,128)==LEASE_ADMISSION:
        if kind!=2 or word(s,136)!=0 or get(o,N)!=256:
            return 0
        i=144
        while i<384:
            if word(s,i)!=0:
                return 0
            i=i+8
        return 1
''')
    constants=dict(handles.C)
    constants['LEASE_ADMISSION']=LEASE_MAGIC
    return substitute(source,constants)

def effects_source():
    source=effects.SOURCE
    source=replace_once(source,'''    if word(s,0)!=REQUEST and word(s,0)!=EXT_REQUEST and word(s,0)!=PUBLIC_REQUEST and word(s,0)!=TIMED_REQUEST:
''','''    if word(s,0)!=REQUEST and word(s,0)!=EXT_REQUEST and word(s,0)!=PUBLIC_REQUEST and word(s,0)!=TIMED_REQUEST and word(s,0)!=LEASE_ADMISSION:
''')
    source=replace_once(source,'''    public=word(s,0)==PUBLIC_REQUEST or word(s,0)==TIMED_REQUEST
''','''    if word(s,0)==LEASE_ADMISSION:
        if length(s)!=256 or word(s,8)!=0:
            return 4294967293
        i=40
        while i<256:
            if word(s,i)!=0:
                return 4294967293
            i=i+8
    public=word(s,0)==PUBLIC_REQUEST or word(s,0)==TIMED_REQUEST
''')
    source=replace_once(source,'''    put(o,OP,word(s,8))
''','''    put(o,I_ADMISSION,choose(word(s,0)==LEASE_ADMISSION,1,0))
    put(o,OP,choose(word(s,0)==LEASE_ADMISSION,6,word(s,8)))
''')
    source=replace_once(source,
'''    put(o,CINPUT+8,choose(get(o,OP)==14,10,choose(get(o,OP)==12,5,choose(get(o,OP)==13,8,get(o,OP)))))
''',
'''    put(o,CINPUT+8,choose(get(o,I_ADMISSION)==1,12,choose(get(o,OP)==14,10,choose(get(o,OP)==12,5,choose(get(o,OP)==13,8,get(o,OP))))))
''')
    source=replace_once(source,
'''    if get(o,I_PUBLIC)==1 and get(o,I_RETURNED)==0 and action==2 and get(o,STATE_O+120)==0:
''',
'''    if get(o,I_PUBLIC)==1 and get(o,I_ADMISSION)==0 and get(o,I_RETURNED)==0 and action==2 and get(o,STATE_O+120)==0:
''')
    constants=dict(effects.C)
    constants.update(LEASE_ADMISSION=LEASE_MAGIC,I_ADMISSION=I_ADMISSION,COREQ=STATE_MAGIC)
    return substitute(source,constants)

def state_source():
    source=state.source_program()
    source=replace_once(source,'    if op > 11:\n','    if op > 12:\n')
    source=replace_once(source,'    if op == 4 or op == 5 or op == 6:\n',
        '    if op == 4 or op == 5 or op == 6 or op == 12:\n')
    source=replace_once(source,'''        if get(o,8)!=1:
            return fail(o,32)
        return issue(o,32,313,get(o,32),0)
''','''        if get(o,8)!=1:
            return fail(o,32)
        if get(o,16)==12:
            return done(o)
        return issue(o,32,313,get(o,32),0)
''')
    source=source.replace(str(state.MAGIC),str(STATE_MAGIC))
    return source

def main():
    for name,source in [('multiversion_runtime_public_handles',handles_source()),
        ('multiversion_runtime_public_effects',effects_source()),
        ('multiversion_runtime_public_state',state_source())]:
        doc=document(source,name)
        path=ROOT/'examples/hia_bootstrap'/f'{name}.hepta'
        path.write_text(render_assembly(doc))
        print(path.name,path.stat().st_size,len(doc['functions']),
            sum(len(f['blocks']) for f in doc['functions']),flush=True)

if __name__=='__main__':
    main()
