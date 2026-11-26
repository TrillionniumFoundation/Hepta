"""Typed GenerationLease admission for the sole native owner product.

The original public-carrier sources remain unchanged. Only the owner packer
uses these roles together with fixed Value action 32 and typed-policy action 33.
"""
from pathlib import Path
import ast
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools import generate_hia_multiversion_public_lease_admission as public
from tools import generate_hia_multiversion_runtime_handles as handles
from tools import generate_hia_multiversion_runtime_effects as effects

ROOT=Path(__file__).resolve().parents[1]
TYPED_MAGIC=int.from_bytes(b'HIAMVTC1','little')
VALUE_MAGIC=int.from_bytes(b'HIABVQ04','little')
VALUE_REPLY=int.from_bytes(b'HIABVR01','little')
CALL_MAGIC=int.from_bytes(b'HIAMVCAL','little')
T_TYPED=26888
T_REQUEST=524288
T_OUTPUT=532480

def handles_source():
    source=public.handles_source()
    marker='def valid_command(s:readbuf,o:mutbuf,kind:u64) -> u64:\n'
    source=public.replace_once(source,marker,marker+'''    if word(s,128)==TYPED_MAGIC:
        if kind!=2 or word(s,136)!=0 or get(o,N)!=256:
            return 0
        i=144
        while i<384:
            if (i<168 or i>208) and word(s,i)!=0:
                return 0
            i=i+8
        return 1
''')
    return public.substitute(source,{**handles.C,'TYPED_MAGIC':TYPED_MAGIC})

HELPERS=r'''
def typed_begin(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=256 or word(s,8)!=0:
        return 4294967293
    i=88
    while i<256:
        if word(s,i)!=0:
            return 4294967293
        i=i+8
    zero(o,128,24320)
    zero(o,D_BASE,384)
    zero(o,I_PUBLIC,512)
    put(o,I_ADMISSION,0)
    put(o,T_TYPED,1)
    put(o,OP,4)
    put(o,TOKEN,0)
    put(o,GEN,NONE)
    put(o,SLOT,NONE)
    put(o,LOCAL_TOKEN,0)
    put(o,RESULT,NONE)
    put(o,RESULT+8,NONE)
    return system(o,1,39,0,0,0,0,0,0,0)

def typed_prepare(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    zero(o,T_REQUEST,5264)
    put(o,T_REQUEST,TYPED_VALUE_MAGIC)
    put(o,T_REQUEST+8,45)
    copy_input(s,40,o,T_REQUEST+24,48)
    put(o,T_REQUEST+96,5136)
    within(o,T_REQUEST+128,FRAME,5136)
    return role(o,636,32,3,T_REQUEST,5264,3,T_OUTPUT,8344,0,0,0)

def typed_prepared(o:mutbuf,w:mutbuf) -> u32:
    if get(o,FEEDBACK)!=0 or get(o,T_OUTPUT)!=TYPED_VALUE_REPLY:
        put(o,NATIVE_ERROR,11)
        return feedback(o,1)
    status=get(o,T_OUTPUT+8)
    if status!=0:
        if status!=1 and status!=11 and status!=13 and status!=20 and status!=21 and status!=22:
            status=11
        put(o,NATIVE_ERROR,status)
        return feedback(o,1)
    index=get(o,T_OUTPUT+56)
    count=get(o,FRAME+8)
    if index>=count or count==0 or count>16 or get(o,T_OUTPUT+64)!=152 or get(o,T_OUTPUT+72)!=8344:
        put(o,NATIVE_ERROR,11)
        return feedback(o,1)
    if get(o,T_OUTPUT+8192)!=TYPED_CALL_MAGIC:
        put(o,NATIVE_ERROR,11)
        return feedback(o,1)
    row=FRAME+16+index*320
    argc=get(o,row+16)
    result=get(o,row+24)
    if argc>16 or result==0 or result>11 or get(o,T_OUTPUT+48)!=argc or get(o,T_OUTPUT+8200)!=argc or get(o,T_OUTPUT+8208)!=result:
        put(o,NATIVE_ERROR,11)
        return feedback(o,1)
    i=16
    while i<48:
        if get(o,T_OUTPUT+i)!=0:
            put(o,NATIVE_ERROR,11)
            return feedback(o,1)
        i=i+8
    i=80
    while i<128:
        if get(o,T_OUTPUT+i)!=0:
            put(o,NATIVE_ERROR,11)
            return feedback(o,1)
        i=i+8
    i=argc
    while i<16:
        if get(o,T_OUTPUT+8216+i*8)!=0:
            put(o,NATIVE_ERROR,11)
            return feedback(o,1)
        i=i+1
    zero(o,CALL_W,512)
    put(o,CALL_W+8,argc)
    put(o,CALL_W+16,result)
    within(o,CALL_W+24,row+160,128)
    within(o,CALL_O,T_OUTPUT+8192,152)
    put(o,INDEX,index)
    return call_actual(o,w)
'''

def effects_source():
    source=public.effects_source()
    marker='def begin(s:readbuf,o:mutbuf,w:mutbuf) -> u32:\n'
    source=public.replace_once(source,marker,marker+'''    if word(s,0)==TYPED_MAGIC:
        return 33
''')
    source=public.replace_once(source,'    zero(o,128,24320)\n','    zero(o,128,24320)\n    put(o,T_TYPED,0)\n')
    source=public.replace_once(source,'    return state_step(o)\n\ndef state_step','''    if get(o,T_TYPED)==1:
        zero(o,CINPUT+48,48)
    return state_step(o)

def state_step''')
    marker='def find_call_function(s:readbuf,o:mutbuf,w:mutbuf) -> u32:\n'
    source=public.replace_once(source,marker,marker+'''    if get(o,T_TYPED)==1:
        return 33
''')
    source=public.replace_once(source,'    if phase==630:\n','    if phase==636:\n        return 33\n    if phase==630:\n')
    constants={**effects.C,'I_ADMISSION':public.I_ADMISSION,'TYPED_MAGIC':TYPED_MAGIC,
               'TYPED_VALUE_MAGIC':VALUE_MAGIC,'TYPED_VALUE_REPLY':VALUE_REPLY,
               'TYPED_CALL_MAGIC':CALL_MAGIC,'T_TYPED':T_TYPED,
               'T_REQUEST':T_REQUEST,'T_OUTPUT':T_OUTPUT}
    return public.substitute(source,constants)

POLICY_ENTRY=r'''
def generation_lease_typed_policy(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=256 or length(w)<WORK or length(o)<OUTPUT:
        return 4294967293
    phase=get(o,PHASE)
    if phase==0 and word(s,0)==TYPED_MAGIC:
        return typed_begin(s,o,w)
    if get(o,T_TYPED)!=1:
        return 4294967293
    if phase==631:
        return typed_prepare(s,o,w)
    if phase==636:
        return typed_prepared(o,w)
    return 4294967293
'''

def policy_source():
    # Keep policy in a separate native role within the original compiler domain.
    # Include only transitively used original mechanics; the fixed bridge carries
    # returned actions directly into its existing dispatcher.
    functions=ast.parse(POLICY_ENTRY+'\n'+HELPERS+'\n'+public.effects_source()).body
    by_name={node.name:node for node in functions if isinstance(node,ast.FunctionDef)}
    needed={'generation_lease_typed_policy'}
    pending=list(needed)
    while pending:
        name=pending.pop()
        for node in ast.walk(by_name[name]):
            if isinstance(node,ast.Call) and isinstance(node.func,ast.Name):
                dependency=node.func.id
                if dependency in by_name and dependency not in needed:
                    needed.add(dependency)
                    pending.append(dependency)
    source='\n\n'.join(ast.unparse(node) for node in functions if isinstance(node,ast.FunctionDef) and node.name in needed)
    constants={**effects.C,'I_ADMISSION':public.I_ADMISSION,'TYPED_MAGIC':TYPED_MAGIC,
               'TYPED_VALUE_MAGIC':VALUE_MAGIC,'TYPED_VALUE_REPLY':VALUE_REPLY,
               'TYPED_CALL_MAGIC':CALL_MAGIC,'T_TYPED':T_TYPED,
               'T_REQUEST':T_REQUEST,'T_OUTPUT':T_OUTPUT,'COREQ':public.STATE_MAGIC}
    return public.substitute(source,constants)


def main():
    for name,source in [('generation_lease_typed_handles',handles_source()),('generation_lease_typed_effects',effects_source()),('generation_lease_typed_policy',policy_source())]:
        target=ROOT/'examples/hia_bootstrap'/(name+'.hepta')
        target.write_text(render_assembly(document(source,name)))
        print(target.name,target.stat().st_size,flush=True)
if __name__=='__main__':main()
