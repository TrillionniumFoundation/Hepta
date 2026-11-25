"""Size-derived HIA JSON arena for the NDU caller, with full u64 offsets.

This is a separate private transport role. Original Core, proof, evaluator and
background-submit semantic budgets remain in their respective owners.
"""
from pathlib import Path
import ast,re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_system_jobctl_request import document
from tools.generate_hia_json_decode import source_program as decoder_source
ROOT=Path(__file__).resolve().parents[1]
ENTRY=r'''
def rank_json(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(w)<128 or length(o)<64:
        return 4294967293
    action=get(w,104)
    if action==0:
        return rank_json_sizes(s,o)
    if action!=1:
        return 4294967293
    return decode_json(s,o,w)

def rank_json_sizes(s:readbuf,o:mutbuf) -> u32:
    nodes=0
    keys=0
    depth=0
    peak=0
    at=0
    size=length(s)
    while at<size:
        ch=byte(s,at)
        if ch==34:
            at=at+1
            quoted=True
            while at<size and quoted:
                value=byte(s,at)
                at=at+1
                if value==34:
                    quoted=False
                elif value==92 and at<size:
                    at=at+1
            following=at
            while following<size and json_space(byte(s,following)):
                following=following+1
            if following<size and byte(s,following)==58:
                keys=keys+1
            else:
                nodes=nodes+1
        elif ch==91 or ch==123:
            depth=depth+1
            if depth>peak:
                peak=depth
            nodes=nodes+1
            at=at+1
        elif ch==93 or ch==125:
            if depth!=0:
                depth=depth-1
            at=at+1
        elif ch==44 or ch==58 or json_space(ch):
            at=at+1
        else:
            nodes=nodes+1
            at=at+1
            atom_open=True
            while at<size and atom_open:
                ch=byte(s,at)
                if ch==91 or ch==93 or ch==123 or ch==125 or ch==34 or ch==44 or ch==58 or json_space(ch):
                    atom_open=False
                else:
                    at=at+1
    if nodes==0:
        nodes=1
    if size>18446744073709551551 or nodes>(18446744073709551551-size)//72:
        return 4294967293
    arena=64+nodes*72+size
    if peak>384307168202282322:
        return 4294967293
    stack=128+(peak+1)*48
    scratch=32
    slots=2
    if keys>576460752303423487:
        return 4294967293
    while slots<keys*2:
        slots=slots*2
    scratch=slots*16
    if scratch<stack:
        scratch=stack
    state_stack=128+(peak+1)*32
    if arena<state_stack:
        arena=state_stack
    put(o,0,3544424485346167112)
    put(o,8,nodes)
    put(o,16,keys)
    put(o,24,peak)
    put(o,32,arena)
    put(o,40,scratch)
    put(o,48,size)
    put(o,56,0)
    return 0

def json_space(ch:u64) -> bool:
    return ch==32 or ch==9 or ch==10 or ch==13
'''
WIDE_FUNCTIONS=r'''
def string_token(s:readbuf,w:mutbuf) -> u64:
    index=get(w,0)+1
    hash=14695981039346656037
    going=True
    while going:
        cp=decoded(s,w,index)
        if cp==1114113:
            put(w,32,get(w,120))
            return 1
        index=get(w,112)
        if cp==1114112:
            going=False
        else:
            hash=(hash^cp)*1099511628211
    put(w,0,index)
    put(w,40,hash)
    return 0

def decode_string(s:readbuf,o:mutbuf,w:mutbuf) -> u64:
    index=get(w,0)+1
    start=get(w,72)
    going=True
    while going:
        cp=decoded(s,w,index)
        index=get(w,112)
        if cp==1114112:
            going=False
        else:
            write_scalar(o,w,cp)
    put(w,0,index)
    put(w,80,start)
    put(w,88,get(w,72)-start)
    return 0

def insert_key(s:readbuf,o:mutbuf,w:mutbuf,slots:u64,scope:u64,start:u64) -> u64:
    slot=(get(w,40)^(scope*1099511628211))&(slots-1)
    probes=0
    while probes<slots:
        item=get(o,slot*16)
        if item==0:
            put(o,slot*16,start)
            put(o,slot*16+8,scope)
            return 0
        if get(o,slot*16+8)==scope:
            if same_key(s,w,item,start)==1:
                return 4
        slot=(slot+1)&(slots-1)
        probes=probes+1
    return 3

def same_key(s:readbuf,w:mutbuf,left:u64,right:u64) -> u64:
    going=True
    while going:
        l=decoded(s,w,left)
        left=get(w,112)
        r=decoded(s,w,right)
        right=get(w,112)
        if l!=r:
            return 0
        if l==1114112:
            return 1
        if l==1114113:
            return 0
    return 0
'''
def source_program():
    source=decoder_source(wire_spans=True)
    replacements=[
      ('if length(s) > 8388608 or length(w) < 128 or length(o) < 128:', 'if length(w) < 128 or length(o) < 128:'),
      ('if length(s) > 8388608 or length(w) < 128:', 'if length(w) < 128:'),
      ('if maximum < 1 or maximum > 1048576 or maximum_depth > 128:', 'if maximum < 1:'),
      ('    maximum = get(w, 48)', '    maximum = length(s) + 1'),
      ('if length(w) < 128 + (maximum_depth + 1) * 48:', 'if maximum_depth >= (length(w)-128)//48:'),
      ('if length(w) < 128 + (maximum_depth + 1) * 32:', 'if maximum_depth >= (length(w)-128)//32:'),
      ('    put(o, 56, maximum_depth)\n    result =', '    put(o, 56, maximum_depth)\n    put(o, 96, get(w,96))\n    result ='),
      ('    key_bound = choose(maximum < (length(s) >> 2) + 1, maximum, (length(s) >> 2) + 1)', '    key_bound = get(w,96)\n    if key_bound>576460752303423487:\n        return 3'),
      ('slots * 8', 'slots * 16'),
      ('if length(o) < slots * 16:', 'if slots > length(o)//16:'),
      ('    base = 64 + count * 72\n    if length(o) < base + length(s):', '    if length(s)>length(o)-64 or count>(length(o)-64-length(s))//72:\n        return 4294967293\n    base = 64 + count * 72\n    if length(o) < base + length(s):'),
      ('    return get(w, 72)\n\ndef widen', '    return 0\n\ndef widen'),
    ]
    for old,new in replacements:
        assert old in source,old
        source=source.replace(old,new)
    tree=ast.parse(source)
    replacements_by_name={n.name:n for n in ast.parse(WIDE_FUNCTIONS).body}
    class OffsetFailure(ast.NodeTransformer):
        def visit_Constant(self,node):
            if node.value==4294967295:return ast.copy_location(ast.Constant((1<<64)-1),node)
            return node
    class UnicodeReturns(ast.NodeTransformer):
        def visit_Return(self,node):
            expr=node.value
            assert isinstance(expr,ast.BinOp) and isinstance(expr.op,ast.BitOr) and isinstance(expr.left,ast.BinOp) and isinstance(expr.left.op,ast.LShift) and isinstance(expr.left.right,ast.Constant) and expr.left.right.value==32,ast.unparse(node)
            place=expr.left.left;scalar=expr.right
            fail=isinstance(scalar,ast.Constant) and scalar.value==1114113
            put=ast.Expr(ast.Call(ast.Name('put',ast.Load()),[ast.Name('w',ast.Load()),ast.Constant(120 if fail else 112),place],[]))
            return [put,ast.Return(scalar)]
    for i,node in enumerate(tree.body):
        if node.name in replacements_by_name:tree.body[i]=replacements_by_name[node.name]
        elif node.name=='decoded':
            node.args.args.insert(1,ast.arg(arg='w',annotation=ast.Name('mutbuf',ast.Load())))
            tree.body[i]=UnicodeReturns().visit(node)
        elif node.name in ('atom','wire_atom'):
            tree.body[i]=OffsetFailure().visit(node)
        elif node.name=='preflight':
            tree.body[i]=OffsetFailure().visit(node)
    source=ENTRY+'\n'+ast.unparse(ast.fix_missing_locations(tree))+'\n'
    return source
def program():return document(source_program(),'ndu_rank_json')
if __name__=='__main__':
    target=ROOT/'examples/hia_bootstrap/ndu_rank_json.hepta';target.write_text(render_assembly(program()));print(target.name,target.stat().st_size,flush=True)
