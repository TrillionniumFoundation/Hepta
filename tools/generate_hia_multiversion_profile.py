"""Project admitted Core facts to the existing HIA scalar-profile owner.

No admission or proof predicate is repeated here. This private six-word role
consumes exact Core JSON and preserves original names, types, cast-field tags,
block ordering, edges, and explicit exports. Output controls @0=prove_total,
@8=phase (0 metadata or 1 full facts), @16=original structured input flag are captured before JSON decoding. The
runtime must perform independent complete Core admission before this role.
"""
from pathlib import Path
import ast
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_core_inspect_json import source_program as json_source
from tools.generate_hia_artifact_publication import document
ROOT=Path(__file__).resolve().parents[1]
MAGIC=int.from_bytes(b'HIASCP01','little')
POLICY=r'''
def multiversion_profile(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(o)<128 or length(w)<4096 or length(s)>8388608:
        return 4294967293
    total=get(o,0)
    phase=get(o,8)
    structured=get(o,16)
    if total>1 or phase>1 or structured>1:
        return 4294967293
    put(o,48,262144)
    put(o,56,64)
    end=widen(decode_json(s,w,o))
    if end>=4294967292:
        return end
    if end>length(w) or kind(w,0)!=6:
        return 4294967293
    put(w,16,0)
    put(w,24,0)
    functions=field(w,0,K_functions)
    exports=field(w,0,K_exports)
    if functions==NONE or kind(w,functions)!=5:
        return 4294967293
    n=count(w,functions)
    mv_word(o,w,MAGIC)
    mv_word(o,w,structured)
    mv_word(o,w,total)
    mv_word(o,w,choose(exports!=NONE,1,0))
    mv_word(o,w,n)
    if exports==NONE:
        mv_word(o,w,0)
    else:
        if kind(w,exports)!=5:
            return 4294967293
        mv_word(o,w,count(w,exports))
    mv_word(o,w,phase)
    mv_text(o,w,field(w,0,K_schema))
    if phase==1:
        if exports!=NONE:
            e=child(w,exports)
            while e!=NONE:
                mv_text(o,w,e)
                e=next_node(w,e)
        fn=child(w,functions)
        while fn!=NONE:
            mv_function(o,w,fn)
            fn=next_node(w,fn)
    if get(w,24)!=0:
        return 4294967294
    return get(w,16)

def mv_function(o:mutbuf,w:mutbuf,fn:u64) -> u64:
    start=get(w,16)
    mv_word(o,w,0)
    mv_text(o,w,field(w,fn,K_name))
    mv_sequence(o,w,field(w,fn,K_params),1)
    mv_sequence(o,w,field(w,fn,K_returns),0)
    mv_sequence(o,w,field(w,fn,K_effects),0)
    blocks=field(w,fn,K_blocks)
    if blocks==NONE or kind(w,blocks)!=5:
        put(w,24,1)
        return 0
    mv_word(o,w,count(w,blocks))
    b=child(w,blocks)
    while b!=NONE:
        mv_block(o,w,b)
        b=next_node(w,b)
    mv_patch(o,w,start)
    return 0

def mv_block(o:mutbuf,w:mutbuf,b:u64) -> u64:
    start=get(w,16)
    mv_word(o,w,0)
    mv_text(o,w,field(w,b,K_id))
    mv_sequence(o,w,field(w,b,K_params),1)
    ops=field(w,b,K_ops)
    if ops==NONE or kind(w,ops)!=5:
        put(w,24,1)
        return 0
    mv_word(o,w,count(w,ops))
    op=child(w,ops)
    while op!=NONE:
        mv_instruction(o,w,op)
        op=next_node(w,op)
    term=field(w,b,K_term)
    if term==NONE or kind(w,term)!=6:
        put(w,24,1)
        return 0
    mv_text(o,w,field(w,term,K_op))
    mv_optional_text(o,w,field(w,term,K_target))
    edge=field(w,term,K_then)
    if edge==NONE:
        mv_word(o,w,0)
    else:
        mv_optional_text(o,w,field(w,edge,K_target))
    edge=field(w,term,K_else)
    if edge==NONE:
        mv_word(o,w,0)
    else:
        mv_optional_text(o,w,field(w,edge,K_target))
    mv_patch(o,w,start)
    return 0

def mv_instruction(o:mutbuf,w:mutbuf,op:u64) -> u64:
    start=get(w,16)
    mv_word(o,w,0)
    mv_text(o,w,field(w,op,K_op))
    mv_sequence(o,w,field(w,op,K_out),1)
    attrs=field(w,op,K_attrs)
    mode=NONE
    if attrs!=NONE:
        node=child(w,attrs)
        while node!=NONE:
            row=64+node*56
            if same(w,get(w,row+40),get(w,row+48),4,1701080941,0,0)==1:
                mode=node
            node=next_node(w,node)
    if mode==NONE:
        mv_word(o,w,0)
        mv_word(o,w,0)
    elif kind(w,mode)==4:
        mv_word(o,w,1)
        mv_text(o,w,mode)
    else:
        mv_word(o,w,0)
        mv_word(o,w,0)
    mv_patch(o,w,start)
    return 0

def mv_sequence(o:mutbuf,w:mutbuf,node:u64,typed:u64) -> u64:
    if node==NONE or kind(w,node)!=5:
        put(w,24,1)
        return 0
    mv_word(o,w,count(w,node))
    item=child(w,node)
    while item!=NONE:
        value=item
        if typed!=0:
            value=field(w,item,K_type)
        mv_text(o,w,value)
        item=next_node(w,item)
    return 0

def mv_optional_text(o:mutbuf,w:mutbuf,node:u64) -> u64:
    if node==NONE:
        return mv_word(o,w,0)
    return mv_text(o,w,node)

def mv_text(o:mutbuf,w:mutbuf,node:u64) -> u64:
    if node==NONE or kind(w,node)!=4:
        put(w,24,1)
        return 0
    row=64+node*56
    at=get(w,row+24)
    size=get(w,row+32)
    mv_word(o,w,size)
    out=get(w,16)
    if out>length(o) or size>length(o)-out:
        put(w,24,1)
        return 0
    i=0
    while i<size:
        store(o,out+i,byte(w,at+i))
        i=i+1
    put(w,16,out+size)
    return 0

def mv_word(o:mutbuf,w:mutbuf,value:u64) -> u64:
    at=get(w,16)
    if at>length(o) or length(o)-at<8:
        put(w,24,1)
        return 0
    put(o,at,value)
    put(w,16,at+8)
    return 0

def mv_patch(o:mutbuf,w:mutbuf,start:u64) -> u64:
    if get(w,24)!=0:
        return 0
    put(o,start,get(w,16)-start-8)
    return 0
'''
def source_program():
    raw=json_source(entry=POLICY.replace('MAGIC',str(MAGIC)))
    tree=ast.parse(raw);functions={n.name:n for n in tree.body if isinstance(n,ast.FunctionDef)}
    needed=set();pending=['multiversion_profile']
    while pending:
        name=pending.pop()
        if name in needed:continue
        needed.add(name)
        pending.extend(n.func.id for n in ast.walk(functions[name]) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id in functions)
    return ast.unparse(ast.Module(body=[functions['multiversion_profile']]+[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in needed and n.name!='multiversion_profile'],type_ignores=[]))
def main():
    tree=document(source_program(),'multiversion_profile')
    p=ROOT/'examples/hia_bootstrap/multiversion_profile.hepta';p.write_text(render_assembly(tree))
    print(p.name,p.stat().st_size,len(tree['functions']))
if __name__=='__main__':main()
