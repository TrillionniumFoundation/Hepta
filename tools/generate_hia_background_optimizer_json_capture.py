"""Lossless owned-JSON capture for native background and rank arguments.

The strict Core/receipt/NDU-wire decoder remains unchanged. This profile keeps
lone surrogate code points in WTF-8, nonfinite number lexemes, and Python dict
last-value/first-insertion semantics. Business limits remain in callers.
"""
from pathlib import Path
import ast
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools.generate_hia_ndu_rank_json import source_program as wide_source
from tools.generate_hia_json_preflight import SOURCE as preflight_source
ROOT=Path(__file__).resolve().parents[1]
ENTRY=r'''
def background_optimizer_json_capture(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(w)<128 or length(o)<64:
        return 4294967293
    action=get(w,104)
    if action==0:
        result=rank_json_sizes(s,o)
        if widen(result)!=0:
            return result
        nodes=get(o,8)
        keys=get(o,16)
        arena=get(o,32)
        slots=2
        while slots<keys*2:
            slots=slots*2
        if slots>576460752303423487 or arena>18446744073709551103:
            return 4294967293
        need=(arena+7)&18446744073709551608
        if nodes>(18446744073709551103-need)//48:
            return 4294967293
        need=need+nodes*48+512
        if slots>(18446744073709551615-need)//32:
            return 4294967293
        need=need+slots*32
        if need<get(o,40):
            need=get(o,40)
        put(o,40,need)
        return 0
    if action!=1:
        return 4294967293
    result=decode_json(s,o,w)
    if widen(result)!=0:
        return result
    return normalize_owned(o,w)

def special_atom(s:readbuf,index:u64) -> u64:
    n=length(s)-index
    if n>=3 and byte(s,index)==78 and byte(s,index+1)==97 and byte(s,index+2)==78:
        return index+3
    start=index
    if n!=0 and byte(s,index)==45:
        start=start+1
    if length(s)-start>=8:
        if byte(s,start)==73 and byte(s,start+1)==110 and byte(s,start+2)==102 and byte(s,start+3)==105 and byte(s,start+4)==110 and byte(s,start+5)==105 and byte(s,start+6)==116 and byte(s,start+7)==121:
            return start+8
    return 18446744073709551615

def normalize_owned(o:mutbuf,w:mutbuf) -> u32:
    n=get(o,8)
    size=get(o,24)
    if n==0 or length(w)<512 or size>length(w)-512 or size>18446744073709551608:
        return 4294967293
    map=(size+7)&18446744073709551608
    if map>length(w)-512 or n>(length(w)-512-map)//48:
        return 4294967293
    table=map+n*48
    slots=2
    keys=capture_keys(o,n)
    while slots<keys*2:
        slots=slots*2
    if table>length(w)-512 or slots>(length(w)-512-table)//32:
        return 4294967293
    i=0
    while i<size:
        store(w,i,byte(o,i))
        i=i+1
    c=length(w)-512
    i=0
    while i<512:
        store(w,c+i,0)
        i=i+1
    put(w,c,n)
    put(w,c+8,size)
    put(w,c+16,map)
    put(w,c+24,map+n*8)
    put(w,c+32,map+n*16)
    put(w,c+40,map+n*24)
    put(w,c+48,table)
    put(w,c+56,slots)
    capture_maps(w)
    capture_count(w)
    chosen=get(w,c+64)
    strings=get(w,c+72)
    if chosen>(length(o)-64)//72:
        return 4294967293
    base=64+chosen*72
    if strings>length(o)-base:
        return 4294967293
    put(w,c+80,base)
    return capture_emit(o,w)

def capture_keys(o:mutbuf,n:u64) -> u64:
    keys=0
    i=1
    while i<n:
        parent=get(o,64+i*72+8)
        if get(o,64+parent*72)==6:
            keys=keys+1
        i=i+1
    return keys

def capture_maps(w:mutbuf) -> u64:
    n=capture_state(w,0)
    map=capture_state(w,16)
    first=capture_state(w,24)
    last=capture_state(w,32)
    i=0
    while i<n:
        put(w,map+i*8,i)
        put(w,first+i*8,i)
        put(w,last+i*8,18446744073709551615)
        i=i+1
    table=capture_state(w,48)
    total=capture_state(w,56)*32
    i=0
    while i<total:
        put(w,table+i,0)
        i=i+8
    i=1
    while i<n:
        if get(w,64+get(w,64+i*72+8)*72)==6:
            capture_insert(w,i)
        i=i+1
    return 0

def capture_insert(w:mutbuf,node:u64) -> u64:
    row=64+node*72
    parent=get(w,row+8)
    at=get(w,row+40)
    span=get(w,row+48)
    hash=14695981039346656037
    j=0
    while j<span:
        hash=(hash^byte(w,at+j))*1099511628211
        j=j+1
    slots=capture_state(w,56)
    slot=(hash^(parent*1099511628211))&(slots-1)
    while True:
        cell=capture_state(w,48)+slot*32
        saved=get(w,cell)
        if saved==0:
            put(w,cell,node+1)
            put(w,cell+8,parent)
            put(w,cell+16,hash)
            return 0
        if get(w,cell+8)==parent and get(w,cell+16)==hash and capture_same_key(w,saved-1,node):
            put(w,capture_state(w,16)+(saved-1)*8,node)
            put(w,capture_state(w,24)+node*8,saved-1)
            return 0
        slot=(slot+1)&(slots-1)
    return 0

def capture_count(w:mutbuf) -> u64:
    stack=capture_state(w,40)
    put(w,stack,0)
    put(w,stack+8,18446744073709551615)
    put(w,stack+16,18446744073709551615)
    pending=1
    chosen=0
    strings=0
    while pending!=0:
        pending=pending-1
        item=stack+pending*24
        node=get(w,item)
        key=get(w,item+8)
        row=64+node*72
        kind=get(w,row)
        chosen=chosen+1
        if key!=18446744073709551615:
            strings=strings+get(w,64+key*72+48)
        if kind==4:
            strings=strings+get(w,row+32)
        if kind==5 or kind==6:
            pending=capture_push(w,capture_state(w,16),capture_state(w,24),stack,pending,node,0)
    put(w,length(w)-512+64,chosen)
    put(w,length(w)-512+72,strings)
    return 0

def capture_emit(o:mutbuf,w:mutbuf) -> u32:
    cursor=capture_state(w,80)
    stack=capture_state(w,40)
    put(w,stack,0)
    put(w,stack+8,18446744073709551615)
    put(w,stack+16,18446744073709551615)
    pending=1
    number=0
    while pending!=0:
        pending=pending-1
        item=stack+pending*24
        node=get(w,item)
        key=get(w,item+8)
        parent=get(w,item+16)
        cursor=capture_emit_node(o,w,node,key,parent,number,cursor)
        kind=get(w,64+node*72)
        if kind==5 or kind==6:
            pending=capture_push(w,capture_state(w,16),capture_state(w,24),stack,pending,node,number)
        number=number+1
    if number!=capture_state(w,64) or cursor!=capture_state(w,80)+capture_state(w,72):
        return 4294967293
    put(o,0,5208772604367785521)
    put(o,8,number)
    put(o,16,capture_state(w,80))
    put(o,24,cursor)
    put(o,32,cursor)
    put(o,40,get(w,40))
    put(o,48,1)
    put(o,56,0)
    return 0

def capture_emit_node(o:mutbuf,w:mutbuf,node:u64,key:u64,parent:u64,number:u64,cursor:u64) -> u64:
    row=64+node*72
    out=64+number*72
    kind=get(w,row)
    put(o,out,kind)
    put(o,out+8,parent)
    put(o,out+16,18446744073709551615)
    put(o,out+24,get(w,row+24))
    put(o,out+32,get(w,row+32))
    put(o,out+40,0)
    put(o,out+48,0)
    put(o,out+56,0)
    put(o,out+64,0)
    if kind>=4:
        put(o,out+56,get(w,row+56))
        put(o,out+64,get(w,row+64))
    if parent!=18446744073709551615:
        previous=get(w,capture_state(w,32)+parent*8)
        if previous==18446744073709551615:
            put(o,64+parent*72+24,number)
        else:
            put(o,64+previous*72+16,number)
        put(w,capture_state(w,32)+parent*8,number)
        put(o,64+parent*72+32,get(o,64+parent*72+32)+1)
    if key!=18446744073709551615:
        source=get(w,64+key*72+40)
        span=get(w,64+key*72+48)
        put(o,out+40,cursor)
        put(o,out+48,span)
        capture_copy(w,o,source,cursor,span)
        cursor=cursor+span
    if kind==4:
        source=get(w,row+24)
        span=get(w,row+32)
        put(o,out+24,cursor)
        capture_copy(w,o,source,cursor,span)
        cursor=cursor+span
    if kind==5 or kind==6:
        put(o,out+24,18446744073709551615)
        put(o,out+32,0)
    return cursor

def capture_state(w:mutbuf,offset:u64) -> u64:
    return get(w,length(w)-512+offset)

def capture_push(w:mutbuf,map:u64,first:u64,stack:u64,pending:u64,node:u64,parent:u64) -> u64:
    begin=pending
    row=64+node*72
    kind=get(w,row)
    child=get(w,row+24)
    while child!=18446744073709551615:
        if kind==5 or get(w,first+child*8)==child:
            source=child
            key=18446744073709551615
            if kind==6:
                source=get(w,map+child*8)
                key=child
            put(w,stack+pending*24,source)
            put(w,stack+pending*24+8,key)
            put(w,stack+pending*24+16,parent)
            pending=pending+1
        child=get(w,64+child*72+16)
    end=pending
    while begin+1<end:
        end=end-1
        i=0
        while i<24:
            value=get(w,stack+begin*24+i)
            put(w,stack+begin*24+i,get(w,stack+end*24+i))
            put(w,stack+end*24+i,value)
            i=i+8
        begin=begin+1
    return pending

def capture_same_key(w:mutbuf,a:u64,b:u64) -> bool:
    aa=get(w,64+a*72+40)
    an=get(w,64+a*72+48)
    ba=get(w,64+b*72+40)
    bn=get(w,64+b*72+48)
    if an!=bn:
        return False
    i=0
    while i<an:
        if byte(w,aa+i)!=byte(w,ba+i):
            return False
        i=i+1
    return True

def capture_copy(w:mutbuf,o:mutbuf,source:u64,dest:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(o,dest+i,byte(w,source+i))
        i=i+1
    return 0
'''
def source_program():
    tree=ast.parse(wide_source())
    # Only this separate owned-value capture changes Unicode and constants.
    decoded=next(n for n in ast.parse(preflight_source).body if n.name=='decoded')
    text=ast.unparse(decoded)
    begin=text.index('        if cp >= 55296 and cp <= 56319:')
    end=text.index('        return index << 32 | cp',begin)
    text=text[:begin]+"""        if cp>=55296 and cp<=56319 and index+6<=size:
            if byte(s,index)==92 and byte(s,index+1)==117:
                low=hex4(s,index+2)
                if low>=56320 and low<=57343:
                    cp=65536+(cp-55296)*1024+low-56320
                    index=index+6
"""+text[end:]
    text=text.replace('    if cp >= 55296 and cp <= 57343:\n        return 20 << 32 | 1114113\n','')
    decoded=ast.parse(text).body[0]
    decoded.args.args.insert(1,ast.arg(arg='w',annotation=ast.Name('mutbuf',ast.Load())))
    class Returns(ast.NodeTransformer):
        def visit_Return(self,node):
            expr=node.value
            assert isinstance(expr,ast.BinOp) and isinstance(expr.op,ast.BitOr) and isinstance(expr.left,ast.BinOp) and isinstance(expr.left.op,ast.LShift),ast.unparse(node)
            scalar=expr.right
            fail=isinstance(scalar,ast.Constant) and scalar.value==1114113
            return [ast.Expr(ast.Call(ast.Name('put',ast.Load()),[ast.Name('w',ast.Load()),ast.Constant(120 if fail else 112),expr.left.left],[])),ast.Return(scalar)]
    decoded=Returns().visit(decoded)
    result=[]
    for n in tree.body:
        if n.name=='rank_json':continue
        if n.name=='decoded':n=decoded
        elif n.name=='insert_key':
            raw=ast.unparse(n)
            assert 'return 4' in raw
            n=ast.parse(raw.replace('return 4','return 0')).body[0]
        elif n.name=='wire_atom':
            raw=ast.unparse(n)
            lines=raw.splitlines()
            raw=lines[0]+'\n    special=special_atom(s,index)\n    if special!=18446744073709551615:\n        return special\n'+'\n'.join(lines[1:])
            n=ast.parse(raw).body[0]
        result.append(n)
    source=ENTRY+'\n'+ast.unparse(ast.fix_missing_locations(ast.Module(body=result,type_ignores=[])))+'\n'
    return source
def main():
    doc=document(source_program(),'background_optimizer_json_capture')
    target=ROOT/'examples/hia_bootstrap/background_optimizer_json_capture.hepta'
    target.write_text(render_assembly(doc))
    print(target.name,target.stat().st_size,len(doc['functions']),sum(len(f['blocks'])for f in doc['functions']),flush=True)
if __name__=='__main__':main()
