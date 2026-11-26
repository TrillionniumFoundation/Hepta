"""Private carrier consumption acknowledgements for native Value finalizers.

All earlier public carrier request and reply domains remain unchanged. Only the
fixed enclosing owner's finalizer emits HIAMVHA1. The consumed bit is set at the
actual capability unlink, and pending retirement is observed while the registry
mutex is held. No status code is guessed to mean ownership transfer.
"""
from pathlib import Path
import ast
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_generation_lease_typed as typed
from tools import generate_hia_multiversion_runtime_handles as original

ROOT=Path(__file__).resolve().parents[1]
REQUEST=int.from_bytes(b'HIAMVHA1','little')
REPLY=int.from_bytes(b'HIAMVHA2','little')
MODE=528
EXPECTED=536
KNOWN=544
CONSUMED=552
PENDING=560
RETRY_CLEANUP=568
PARENT=576
IDENTITY=584

def replace_once(source,old,new):
    assert source.count(old)==1,(old,source.count(old))
    return source.replace(old,new)

def source_program():
    source=typed.handles_source()
    magic=original.C['MAGIC']
    source=replace_once(source,
        f'    if length(s)<128 or word(s,0)!={magic} or word(s,8)>7:',
        f'    if length(s)<128 or (word(s,0)!={magic} and word(s,0)!={REQUEST}) or word(s,8)>7:')
    source=replace_once(source,'    op=word(s,8)\n    n=word(s,72)\n',
        f'''    op=word(s,8)
    private=word(s,0)=={REQUEST}
    if private:
        if op!=3 and op!=6 and op!=7:
            return 4294967293
        if (op==3 or op==6) and (word(s,16)<1 or word(s,16)>2):
            return 4294967293
        if op==7 and word(s,16)!=0:
            return 4294967293
    n=word(s,72)
''')
    source=replace_once(source,'        used=i==72\n',
        '        used=i==72 or (private and i==16)\n')
    source=replace_once(source,'    zero(o,64,8192-64)\n',
        f'''    zero(o,64,8192-64)
    put(o,{MODE},choose(private,1,0))
    put(o,{EXPECTED},word(s,16))
''')
    source=replace_once(source,'        if get(w,24)!=0:\n            return fail(o,5)\n        op=get(o,136)\n',
        f'''        if get(w,24)!=0:
            return fail(o,5)
        if get(o,{MODE})!=0:
            put(o,{KNOWN},1)
        op=get(o,136)
''')
    source=replace_once(source,'        put(o,200,kind)\n',
        f'''        if get(o,{MODE})!=0 and (get(o,136)==3 or get(o,136)==6) and kind!=get(o,{EXPECTED}):
            return fail(o,3)
        put(o,200,kind)
''')
    source=replace_once(source,'    if phase==404:\n',
        f'''    if phase==404:
        if get(o,{MODE})!=0 and get(o,136)==3:
            put(o,{CONSUMED},1)
''')
    source=replace_once(source,'        if get(o,144)!=0:\n            return unlock(o,980)\n',
        f'''        if get(o,144)!=0:
            if get(o,{MODE})!=0:
                if get(o,136)==7:
                    put(o,{PENDING},choose(get(w,40)!=0,1,0))
                else:
                    put(o,{PENDING},get(o,424))
            return unlock(o,980)
''')
    source=replace_once(source,'    put(o,88,get(w,8))\n    return 0\n',
        f'''    put(o,88,get(w,8))
    if get(o,{MODE})!=0:
        put(o,0,{REPLY})
        put(o,96,get(o,{KNOWN}))
        put(o,104,get(o,{CONSUMED}))
        put(o,112,get(o,{PENDING}))
    return 0
''')
    # Private query compares the actual enclosing Runtime object while the
    # registry mutex pins both capability rows. The runtime nonce is read from
    # its real initialized native workspace, never supplied by the requester.
    source=replace_once(source,'        if op==6:\n            return fail(o,0)\n',
        f'''        if op==6:
            if get(o,{MODE})!=0:
                runtime=get(o,{original.C['OBJ']})
                if kind==2:
                    runtime=get(o,{original.C['HEADER']}+64)
                if runtime==0:
                    return fail(o,9)
                put(o,{PARENT},runtime)
                return memory(o,122,0,runtime+272,3,{IDENTITY},16)
            return fail(o,0)
''')
    source=replace_once(source,'    if phase==180:\n',
        '''    if phase==122:
        return fail(o,0)
    if phase==180:
''')
    source=replace_once(source,f'        put(o,112,get(o,{PENDING}))\n',
        f'''        put(o,112,get(o,{PENDING}))
        if get(o,{original.C['OP']})==6:
            put(o,24,get(o,{IDENTITY}))
            put(o,32,get(o,{IDENTITY}+8))
            put(o,40,get(o,{PARENT}))
''')
    # Runtime close marks live generations retired. A later finalizer retry
    # must also enter the original bounded cleanup operation, since completed
    # close deliberately does not replay pending retirement tasks.
    child=original.C['CHILD_I']
    source=replace_once(source,f'        put(o,{child}+8,13)\n',
        f'''        put(o,{child+8},13)
        if get(o,{MODE})!=0 and get(o,{original.C['OP']})==7:
            put(o,{child+8},9)
            put(o,{RETRY_CLEANUP},1)
''')
    source=replace_once(source,'    if phase==613:\n',
        f'''    if phase==613:
        if get(o,{RETRY_CLEANUP})!=0:
            put(o,{RETRY_CLEANUP},0)
            if get(o,{original.C['FEEDBACK']})==0:
                zero(o,{child},256)
                put(o,{child},{original.C['EFFECTS']})
                put(o,{child+8},13)
                put(o,{child+72},{original.C['NONE']})
                put(o,{original.C['FRAME_N']},256)
                return again(o,612)
''')
    return source

def main():
    source=source_program()
    tree=document(source,'generation_lease_owner_handles')
    target=ROOT/'examples/hia_bootstrap/generation_lease_owner_handles.hepta'
    target.write_text(render_assembly(tree))
    print(target.name,target.stat().st_size,
          sum(len(f['blocks'])for f in tree['functions']),flush=True)

if __name__=='__main__':main()
