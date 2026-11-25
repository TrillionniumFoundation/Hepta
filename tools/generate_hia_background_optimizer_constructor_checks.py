"""Private constructor checks over fresh native Core and snapshot views.

This leaf does not supply verification or runtime authority. Its closed owner
obtains the Core from the actual verifier, creates the arena with the captured
decoder, and obtains the snapshot from the retained runtime capability.
"""
from pathlib import Path
import ast,re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools.generate_hia_background_optimizer_structure import SOURCE as structure_source

ROOT=Path(__file__).resolve().parents[1]
C={'MAGIC':int.from_bytes(b'HIABCCQ1','little'),'REPLY':int.from_bytes(b'HIABCCR1','little'),
   'SNAPSHOT':int.from_bytes(b'HIAMVBS1','little'),'ARENA':5208772604367785521,
   'SEEN':0,'BAD':4294967293,'NONE':(1<<64)-1}
SOURCE=r'''
def constructor_checks(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)<128 or length(o)<128 or length(w)<1:
        return BAD
    if read64(s,0)!=MAGIC or read64(s,8)>1 or read64(s,48)!=0 or read64(s,56)!=0:
        return BAD
    mode=read64(s,8)
    cn=read64(s,16)
    an=read64(s,24)
    fn=read64(s,32)
    sn=read64(s,40)
    left=length(s)-128
    if cn>left:
        return BAD
    left=left-cn
    if an>left:
        return BAD
    left=left-an
    if fn>left or sn!=left-fn:
        return BAD
    error=0
    if mode==0:
        if cn==0 or an==0 or sn!=0:
            return BAD
        at=64
        while at<128:
            if read64(s,at)!=0:
                return BAD
            at=at+8
        a=128+cn
        if arena_valid(s,w,a,an,cn)==False or nodeword(s,a,0,0)!=6:
            return BAD
        error=function_raw(s,a,a+an,fn)
    else:
        if cn!=0 or an!=0 or fn!=0 or snapshot_valid(s,128,sn)==False:
            return BAD
        error=binding(s,128)
    if error==BAD:
        return BAD
    zero(o,0,128)
    put(o,0,REPLY)
    put(o,8,choose(error==0,0,1))
    put(o,16,error)
    return 0

def function_raw(s:readbuf,a:u64,at:u64,n:u64) -> u64:
    exports=field(s,a,0,8)
    if exports!=NONE:
        if nodeword(s,a,exports,0)!=5:
            return BAD
        child=nodeword(s,a,exports,24)
        while child!=NONE:
            if raw_name(s,a,child,at,n):
                return 0
            child=nodeword(s,a,child,16)
        return 6
    functions=field(s,a,0,9)
    if nodeword(s,a,functions,0)!=5:
        return BAD
    child=nodeword(s,a,functions,24)
    while child!=NONE:
        if raw_name(s,a,field(s,a,child,10),at,n) and scalar_signature(s,a,child):
            return 0
        child=nodeword(s,a,child,16)
    return 6

def raw_name(s:readbuf,a:u64,node:u64,at:u64,n:u64) -> bool:
    if nodeword(s,a,node,0)!=4:
        return False
    return same(s,a+nodeword(s,a,node,24),nodeword(s,a,node,32),at,n)

def binding(s:readbuf,at:u64) -> u64:
    flags=read64(s,at+16)
    if (flags&1)!=0 or (flags&2)==0 or same(s,at+64,32,64,32)==False or same(s,at+96,32,96,32)==False:
        return 7
    if (flags&4)!=0 and same(s,at+128,32,64,32) and same(s,at+160,32,96,32):
        return 0
    return 9
'''

def source_program():
    module=ast.parse((ROOT/'tools/generate_hia_background_optimizer_admission.py').read_text())
    values={n.targets[0].id:ast.literal_eval(n.value) for n in module.body
            if isinstance(n,ast.Assign) and isinstance(n.targets[0],ast.Name)
            and n.targets[0].id in ('SOURCE','LABELS')}
    wanted={'arena_valid','nodeword','read64','get','put','zero','choose','field',
            'string_id','same','scalar_signature','snapshot_valid','decimal_valid'}
    helpers=[]
    for source in (values['SOURCE'],structure_source):
        for f in ast.parse(source).body:
            if isinstance(f,ast.FunctionDef) and f.name in wanted:
                helpers.append(ast.unparse(f));wanted.remove(f.name)
    assert not wanted,wanted
    labels=dict(values['LABELS'])
    for i,name in enumerate(['bool','i16','i32','i64','i8','isize','u16','u32','u64','u8','unit','usize'],100):
        labels[i]=name
    text=SOURCE+'\n'+'\n'.join(helpers)+'\n'
    groups=[list(labels.items())[i:i+8] for i in range(0,len(labels),8)]
    text+='\ndef label(s:readbuf,at:u64,n:u64) -> u64:\n'
    for index in range(len(groups)):
        text+=f'    value=label_{index}(s,at,n)\n    if value!=0:\n        return value\n'
    text+='    return 0\n'
    for index,group in enumerate(groups):
        text+=f'\ndef label_{index}(s:readbuf,at:u64,n:u64) -> u64:\n'
        for ident,name in group:
            raw=name.encode();test=' and '.join([f'n=={len(raw)}']+[f'byte(s,at+{i})=={b}' for i,b in enumerate(raw)])
            text+=f'    if {test}:\n        return {ident}\n'
        text+='    return 0\n'
    for name,value in sorted(C.items(),key=lambda x:-len(x[0])):
        text=re.sub(r'\b'+name+r'\b',str(value),text)
    return text

def program():return document(source_program(),'background_optimizer_constructor_checks')
def main():
    d=program();p=ROOT/'examples/hia_bootstrap/background_optimizer_constructor_checks.hepta'
    p.write_text(render_assembly(d))
    print(p.name,p.stat().st_size,len(d['functions']),sum(len(f['blocks'])for f in d['functions']),flush=True)
if __name__=='__main__':main()
