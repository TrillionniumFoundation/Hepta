"""Fixed class-backed PosixPath construction from an actual exact-str value.

This internal factory preserves owned value references until actual V02 cleanup
completes. It neither resolves the path nor accepts a caller type/verified bit.
The general public Path constructor and callable execution are separate owners.
"""
from pathlib import Path
import ast, re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_ndu_evaluator import document
from tools import generate_hia_native_path_value as shared

ROOT=Path(__file__).resolve().parents[1]
C=dict(shared.C)
C.update(MAGIC=int.from_bytes(b'HIANPX01','little'),REPLY=int.from_bytes(b'HIANPXR1','little'),CONTEXT=int.from_bytes(b'HIANPXC1','little'),VQ3=int.from_bytes(b'HIABVQ03','little'))

SOURCE=r'''
def native_posix_path_factory(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(o)<32768 or length(w)<4096:
        return BAD
    phase=get(o,PHASE)
    if phase==0:
        if length(s)!=128 or (readword(s,8)!=0 and readword(s,8)!=2):
            return BAD
        return begin(s,o,w)
    if (phase>=10 and phase<=18) or phase==201 or phase==202:
        to_work(o,w,2048,RP,128)
        put(w,2304,phase)
    if phase<10:
        return enter(s,o,w,phase)
    if phase<100:
        return construct(o,w,phase)
    if phase<300:
        return cleanup(o,w,phase)
    return final_reply(o,w)
def construct(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==10:
        if value_ok(o)==False:
            return value_failure(o,w,10)
        if capture(o,w,0,RP+24)==False:
            return quarantine(o,w,10)
        if get(o,RP+16)!=4:
            put(w,DETAIL,10)
            return outcome(o,w,4,MAX)
        request(o,32)
        put(o,RQ+104,18)
        return value(o,w,11,128)
    if phase==11:
        if value_ok(o)==False:
            return value_failure(o,w,11)
        if capture(o,w,1,RP+24)==False or get(o,RP+16)!=10:
            return quarantine(o,w,11)
        request(o,2)
        return value(o,w,12,128)
    if phase==12:
        if value_ok(o)==False:
            return value_failure(o,w,12)
        if capture(o,w,2,RP+24)==False or get(o,RP+16)!=0:
            return quarantine(o,w,12)
        request(o,3)
        return value(o,w,13,128)
    if phase==13:
        if value_ok(o)==False:
            return value_failure(o,w,13)
        if capture(o,w,3,RP+24)==False or get(o,RP+16)!=5:
            return quarantine(o,w,13)
        request(o,16)
        ref_request(o,w,3)
        from_work(w,o,RQ+48,REFS,24)
        return value(o,w,14,128)
    if phase==14:
        if value_ok(o)==False:
            return value_failure(o,w,14)
        request(o,35)
        ref_request(o,w,1)
        from_work(w,o,RQ+48,REFS+2*32,24)
        from_work(w,o,RQ+72,REFS+3*32,24)
        return value(o,w,15,128)
    if phase==15:
        if value_ok(o)==False:
            return value_failure(o,w,15)
        if capture(o,w,4,RP+24)==False or get(o,RP+16)!=8:
            return quarantine(o,w,15)
        request(o,36)
        ref_request(o,w,4)
        return value(o,w,16,128)
    if phase==16:
        if value_ok(o)==False:
            return value_failure(o,w,16)
        if capture(o,w,5,RP+24)==False or get(o,RP+16)!=10:
            return quarantine(o,w,16)
        request(o,8)
        ref_request(o,w,1)
        from_work(w,o,RQ+48,REFS+5*32,24)
        return value(o,w,17,128)
    if phase==17:
        if value_ok(o)==False:
            return value_failure(o,w,17)
        if get(o,RP+16)!=1 or get(o,RP+48)!=1:
            return quarantine(o,w,17)
        return outcome(o,w,0,4)
    return quarantine(o,w,phase)
def request(o:mutbuf,op:u64) -> u64:
    zero(o,RQ,128)
    put(o,RQ,choose(op>=32,VQ3,choose(op>=25,VQ2,VQ)))
    put(o,RQ+8,op)
    return 0
'''


def source_program():
    # Select the same, frozen cleanup functions from the shared source. This
    # author dependency is not needed at runtime; emitted HIA is self-contained.
    own=ast.parse(SOURCE)
    own_names={n.name for n in own.body if isinstance(n,ast.FunctionDef)}
    support=ast.parse(shared.SOURCE)
    text='\n\n'.join(ast.unparse(n)for n in support.body if isinstance(n,ast.FunctionDef)and n.name not in own_names)+'\n'+SOURCE
    for key,value in sorted(C.items(),key=lambda p:-len(p[0])):
        text=re.sub(r'\b'+key+r'\b',str(value),text)
    tree=ast.parse(text);functions={n.name:n for n in tree.body if isinstance(n,ast.FunctionDef)}
    needed={'native_posix_path_factory'};pending=list(needed)
    while pending:
        for n in ast.walk(functions[pending.pop()]):
            if isinstance(n,ast.Call)and isinstance(n.func,ast.Name)and n.func.id in functions and n.func.id not in needed:
                needed.add(n.func.id);pending.append(n.func.id)
    ordered=[functions['native_posix_path_factory']]+[n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name in needed and n.name!='native_posix_path_factory']
    return '\n\n'.join(ast.unparse(n)for n in ordered)+'\n'


def program():return document(source_program(),'native_posix_path_factory')
if __name__=='__main__':
    path=ROOT/'examples/hia_bootstrap/native_posix_path_factory.hepta'
    path.write_text(render_assembly(program()))
    print(path.name,path.stat().st_size,flush=True)
