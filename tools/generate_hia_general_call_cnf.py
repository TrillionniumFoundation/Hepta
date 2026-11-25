"""Independent native general call-summary and CNF projection.

The original primitive general role is unchanged. This development author
lifts the original direct-call summary semantics into the wide word graph,
then uses the same native CNF, search and witness stages. Runtime is HIA only.
"""
from pathlib import Path
import ast,copy,json
from hepta.hia_agent_assembly import render_assembly
from hepta.hia_cnf_native import _CORE_TRAP_TAGS,SCALAR_SUMMARY,TUPLE_SUMMARY
from tools.generate_hia_cold_document import document
from tools.generate_hia_cold_sha_alias import Builder
from tools.generate_hia_cnf import BODY,PROJECTION
from tools import generate_hia_general_cnf as base
from tools.hia_general_cnf_common import CONSTANTS,ENTRY,HASH,FORMULA_HASH,sha_source
from tools.hia_general_cnf_projection import NODES,DRIVER,lifted_projection
from tools.hia_general_cnf_bitblast import LOGIC,DRIVER as BITBLAST,lifted_bitblast
from tools.hia_general_cnf_solver import SOLVER,WITNESS
ROOT=Path(__file__).resolve().parents[1]
CONTRACT={
 'REQUEST_MAGIC':int.from_bytes(b'HIACGC01','little'),
 'REPLY_MAGIC':int.from_bytes(b'HIACGR01','little'),
 'STATE_MAGIC':int.from_bytes(b'HIAWCC01','little'),
 'CALL_GRAPH_MAGIC':int.from_bytes(b'HIABVP02','little'),
 'CALL_TAIL':1792,'CALL_TYPES':1800,'CALL_GRAPH_FLAG':1808,
 'SCALAR_SUMMARY':SCALAR_SUMMARY,'TUPLE_SUMMARY':TUPLE_SUMMARY,
 'SUMMARIZED_CALL_INPUTS':32,'CIRCUIT_RETURNS':16,
 'PROJECT_DIRECT_CALL':40,'PROJECT_CALL_RESULT':41,
}
SUMMARY=r'''
def call_summary_reply(o:mutbuf,w:mutbuf) -> u32:
    nodes=pget(w,0)
    inputs=get(w,88)
    outputs=get(w,96)
    if nodes==0 or nodes>NODE_CAP or inputs>32 or outputs>16:
        return invalid_reply(o,5)
    size=32+40*nodes+24+16*outputs+8*inputs
    if outputs==1:
        size=32+40*nodes+32+8*inputs
    if length(o)<128+size:
        return invalid_reply(o,2)
    put(o,96,size)
    put(o,104,nodes)
    begin=128
    put(o,begin,choose(outputs==1,SCALAR_SUMMARY,TUPLE_SUMMARY))
    put(o,begin+8,nodes)
    put(o,begin+16,inputs)
    output_type=outputs
    if outputs==1:
        output_type=graph(w,get(w,CALL_TYPES)+8*inputs)
    put(o,begin+24,output_type)
    i=0
    while i<nodes:
        row=32+40*i
        j=0
        while j<40:
            put(o,begin+row+j,nget(w,row+j))
            j=j+8
        i=i+1
    tail=begin+32+40*nodes
    put(o,tail,pget(w,64))
    put(o,tail+8,pget(w,80))
    put(o,tail+16,pget(w,56))
    at=tail+24
    if outputs==1:
        put(o,at,pget(w,128))
        at=at+8
    else:
        i=0
        while i<outputs:
            put(o,at,graph(w,get(w,CALL_TYPES)+8*(inputs+i)))
            put(o,at+8,pget(w,128+8*i))
            at=at+16
            i=i+1
    i=0
    while i<inputs:
        put(o,at,graph(w,get(w,CALL_TYPES)+8*i))
        at=at+8
        i=i+1
    return 128+size
'''
BEGIN=r'''
def projection_begin(w:mutbuf) -> u64:
    mode=graph(w,8)
    inputs=graph(w,16)
    outputs=graph(w,24)
    magic=graph(w,0)
    origin=32
    tail=get(w,64)
    calls=magic==CALL_GRAPH_MAGIC
    if calls:
        if tail<40:
            return stop(w,4,1)
        origin=40
        tail=graph(w,32)
    elif magic!=GRAPH_MAGIC:
        return stop(w,4,1)
    if mode<1 or mode>4 or inputs>32 or outputs>16:
        return stop(w,4,1)
    if mode==3 and calls==False:
        return stop(w,4,1)
    if tail<origin+8*(inputs+outputs) or tail>get(w,64):
        return stop(w,4,1)
    if mode==4 and (calls or outputs!=1 or graph(w,origin+8*inputs)!=1):
        return stop(w,4,1)
    put(w,CALL_TAIL,tail)
    put(w,CALL_TYPES,origin)
    put(w,CALL_GRAPH_FLAG,choose(calls,1,0))
    put(w,80,mode)
    put(w,88,inputs)
    put(w,96,outputs)
    put(w,112,0)
    pput(w,0,0)
    pput(w,8,mode)
    pput(w,16,inputs)
    pput(w,24,outputs)
    pput(w,72,origin)
    pput(w,120,tail)
    put(w,200,0)
    put(w,192,1)
    return 0
'''
def replace_function(source,name,replacement):
    tree=ast.parse(source);node=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name==name)
    old=ast.get_source_segment(source,node)
    assert source.count(old)==1
    return source.replace(old,replacement.strip())
def call_source():
    functions={n.name:n for n in ast.parse(PROJECTION).body if isinstance(n,ast.FunctionDef)}
    selected=['p_call','p_bind_call_tuple','p_summary_result','p_rebind_summary','p_clone_bound_word']
    argument_names={name:[a.arg for a in node.args.args] for name,node in functions.items()}
    argument_names.update({'p_node':['o','w','op','width','a','b','c'],'p_append_node':['o','w','op','width','a','b','c']})
    class Lift(ast.NodeTransformer):
        def visit_FunctionDef(self,node):
            if node.name=='p_clone_bound_word':
                node.body=[n for n in node.body if not (isinstance(n,ast.If) and isinstance(n.test,ast.Name) and n.test.id=='artifact')]
            args=[];placed=False
            for a in node.args.args:
                if a.arg in ('s','o','w'):
                    if not placed:
                        a.arg='w';a.annotation=ast.Name('mutbuf',ast.Load());args.append(a);placed=True
                else:args.append(a)
            node.args.args=args
            return self.generic_visit(node)
        def visit_Call(self,node):
            node=self.generic_visit(node)
            if not isinstance(node.func,ast.Name):return node
            name=node.func.id
            if name=='length' and isinstance(node.args[0],ast.Name) and node.args[0].id=='s':
                return ast.Call(ast.Name('get',ast.Load()),[ast.Name('w',ast.Load()),ast.Constant(64)],[])
            if name=='read64' and isinstance(node.args[0],ast.Name) and node.args[0].id=='s':
                return ast.Call(ast.Name('graph',ast.Load()),[ast.Name('w',ast.Load()),node.args[1]],[])
            if name in ('read_stack','write64'):
                plane=node.args[0].id
                assert plane in ('o','w')
                offset=node.args[1]
                mapping=(plane=='w' and isinstance(offset,ast.BinOp) and isinstance(offset.op,ast.Add) and isinstance(offset.left,ast.Constant) and offset.left.value==270336)
                if mapping:
                    node.func.id='get' if name=='read_stack' else 'put'
                    node.args[1]=ast.BinOp(ast.Name('BITS_BASE',ast.Load()),ast.Add(),offset.right)
                else:
                    node.func.id=('nget' if name=='read_stack' else 'nput') if plane=='o' else ('pget' if name=='read_stack' else 'pput')
                node.args[0]=ast.Name('w',ast.Load())
            elif name in argument_names:
                args=[];placed=False
                for key,value in zip(argument_names[name],node.args):
                    if key in ('s','o','w'):
                        if not placed:args.append(ast.Name('w',ast.Load()));placed=True
                    else:args.append(value)
                node.args=args
            return node
        def visit_BinOp(self,node):
            node=self.generic_visit(node)
            if isinstance(node.op,ast.RShift) and isinstance(node.right,ast.Constant):
                if node.right.value==16:node.right.value=32
                elif node.right.value==23:node.right.value=39
            return node
        def visit_Constant(self,node):
            if node.value==65535:return ast.copy_location(ast.Constant((1<<32)-1),node)
            if node.value==65536:return ast.copy_location(ast.Constant(1<<32),node)
            return node
    return '\n\n'.join(ast.unparse(ast.fix_missing_locations(Lift().visit(copy.deepcopy(functions[name])))) for name in selected)
def projection_source():
    source=replace_function(DRIVER,'projection_begin',BEGIN)
    source=source.replace('end=get(w,64)','end=get(w,CALL_TAIL)')
    source=source.replace('put(w,104,32+8*(inputs+get(w,96)))','put(w,104,get(w,CALL_TYPES)+8*(inputs+get(w,96)))')
    source=source.replace('if get(w,224) != get(w,64):','if get(w,224) != get(w,CALL_TAIL):')
    source=source.replace('ops > 2048-get(w,256)','ops > choose(get(w,CALL_GRAPH_FLAG)==1,8192,2048)-get(w,256)')
    old='''            if p_operation(w,row,get(w,288)-index) != 1:
                if get(w,16) == 3:
                    stop(w,4,1)
                return 0
            put(w,240,index+1)'''
    new='''            amount=p_operation(w,row,get(w,288)-index)
            if amount==0 or amount>get(w,288)-index:
                if get(w,16) == 3:
                    stop(w,4,1)
                return 0
            put(w,240,index+amount)'''
    assert source.count(old)==1
    source=source.replace(old,new)
    old='''        if get(w,80) == 4:
            pput(w,80,p_logic(w,4,reach,pget(w,80)))'''
    new='''        if get(w,80) == 3 or get(w,80) == 4:
            pput(w,80,p_logic(w,4,reach,pget(w,80)))'''
    assert source.count(old)==1;source=source.replace(old,new)
    old='''    pairs=1
    both=pget(w,64)'''
    new='''    if mode==3:
        put(w,16,5)
        put(w,24,7)
        return 0
    pairs=1
    both=pget(w,64)'''
    assert source.count(old)==1;source=source.replace(old,new)
    return source

def call_solver_source():
    # Decision order and saved phases only: clauses, propagation, 1-UIP
    # derivation, backtracking and final witness validation remain unchanged.
    # Projection PHI and LOCAL storage are dead during search, then reused
    # for independently evaluated SAT arguments only after search completes.
    source=SOLVER
    needle='    store(w,ASSIGN_BASE+variable-1,2-(literal&1))'
    assert source.count(needle)==1
    source=source.replace(needle,needle+'\n    store(w,LOCAL_BASE+variable-1,2-(literal&1))')
    needle='    if state == 12:\n        return solver_learn_publish(w)'
    assert source.count(needle)==1
    source=source.replace(needle,needle+'\n    if state == 13:\n        return solver_decay(w)')
    needle='    elif region == 3:\n        base=SEEN_BASE'
    assert source.count(needle)==1
    source=source.replace(needle,needle+'\n    elif region == 4:\n        base=PHI_BASE\n        size=size*4\n    elif region == 5:\n        base=LOCAL_BASE')
    source=source.replace('    if region < 3:', '    if region < 5:')
    needle='    store(w,SEEN_BASE+variable-1,1)'
    assert source.count(needle)==1
    source=source.replace(needle,needle+"""
    activity=get32(w,PHI_BASE+4*(variable-1))
    put32(w,PHI_BASE+4*(variable-1),choose(activity<1073741792,activity+32,1073741824))""")
    needle='    put(w,648,1)\n    put(w,440,7)'
    assert source.count(needle)==1
    source=source.replace(needle,'''    put(w,648,1)
    conflicts=get(w,1840)+1
    put(w,1840,conflicts)
    put(w,440,7)
    if (conflicts&127)==0:
        put(w,1848,0)
        put(w,440,13)''')
    source=replace_function(source,'solver_decide',r'''
def solver_decide(w:mutbuf) -> u64:
    variable=get(w,512)
    if variable<=bget(w,0):
        if byte(w,ASSIGN_BASE+variable-1)==0:
            activity=get32(w,PHI_BASE+4*(variable-1))
            if get(w,1824)==0 or activity>get(w,1832):
                put(w,1824,variable)
                put(w,1832,activity)
        put(w,512,variable+1)
        return 0
    best=get(w,1824)
    if best==0:
        put(w,24,6)
        put(w,800,0)
        put(w,680,0)
        put(w,688,0)
        put(w,696,0)
        return 0
    put(w,512,1)
    put(w,1824,0)
    put(w,1832,0)
    level=get(w,504)
    if level>=VAR_CAP:
        return stop(w,0,2)
    put32(w,LIMIT_BASE+4*level,get(w,488))
    put(w,504,level+1)
    phase=choose(byte(w,LOCAL_BASE+best-1)==2,0,1)
    if enqueue(w,(best<<1)|phase,0)==0:
        return stop(w,4,6)
    put(w,440,3)
    return 0
''')
    source+=r'''
def solver_decay(w:mutbuf) -> u64:
    index=get(w,1848)
    end=choose(index+1024<bget(w,0),index+1024,bget(w,0))
    while index<end:
        at=PHI_BASE+4*index
        put32(w,at,get32(w,at)>>1)
        index=index+1
    put(w,1848,index)
    if index==bget(w,0):
        put(w,440,7)
    return 0
'''
    return source

def policy_source():
    constants={**CONSTANTS,**CONTRACT}
    constants.update(PROJECT_OVERFLOW_CODE=_CORE_TRAP_TAGS['overflow'],PROJECT_DIVISION_CODE=_CORE_TRAP_TAGS['division_by_zero'],PROJECT_TRAP_CODE_MAX=len(_CORE_TRAP_TAGS))
    entry=ENTRY.replace('def general_cnf(', 'def general_call_cnf(')
    old='''    if status != 1:
        return 128'''
    assert entry.count(old)==1
    entry=entry.replace(old,'''    if status == 5:
        return call_summary_reply(o,w)
'''+old)
    projection=lifted_projection()
    old='''    if role == 40 or role == 41:
        return 0'''
    assert projection.count(old)==1
    projection=projection.replace(old,'''    if role == PROJECT_DIRECT_CALL:
        if get(w,CALL_GRAPH_FLAG)==0:
            return 0
        return p_call(w,row,typ,remaining)''')
    source='\n\n'.join((entry,HASH,FORMULA_HASH,sha_source(),NODES,projection,projection_source(),call_source(),SUMMARY,LOGIC,lifted_bitblast(),BITBLAST,call_solver_source(),WITNESS,base.evaluator_source()))
    tree=ast.parse(source)
    names={n.name for n in tree.body}
    if 'word_arguments' not in names:
        bodies={n.name:n for n in ast.parse(BODY).body if isinstance(n,ast.FunctionDef)}
        tree.body.append(copy.deepcopy(bodies['word_arguments']))
    class Bind(ast.NodeTransformer):
        def visit_Call(self,node):
            node=self.generic_visit(node)
            if isinstance(node.func,ast.Name) and node.func.id=='graph':
                off=node.args[1]
                if isinstance(off,ast.BinOp) and isinstance(off.op,ast.Add) and isinstance(off.left,ast.Constant) and off.left.value==32 and isinstance(off.right,ast.BinOp) and isinstance(off.right.op,ast.Mult) and isinstance(off.right.left,ast.Constant) and off.right.left.value==8:
                    node.args[1]=ast.BinOp(ast.Call(ast.Name('get',ast.Load()),[ast.Name('w',ast.Load()),ast.Constant(CONTRACT['CALL_TYPES'])],[]),ast.Add(),off.right)
            return node
        def visit_Name(self,node):
            if node.id in constants:return ast.copy_location(ast.Constant(constants[node.id]),node)
            return node
    tree=ast.fix_missing_locations(Bind().visit(tree))
    names=[n.name for n in tree.body];assert len(names)==len(set(names)),names
    return ast.unparse(tree)+'\n'
def program():
    return document(policy_source(),'general_call_cnf',builder_type=Builder)
def main():
    tree=program();p=ROOT/'examples/hia_bootstrap/general_call_cnf.hepta';p.write_text(render_assembly(tree))
    counts={'functions':len(tree['functions']),'blocks':sum(len(f['blocks']) for f in tree['functions']),'ops':sum(len(b['ops']) for f in tree['functions'] for b in f['blocks']),'max_function_blocks':max(len(f['blocks']) for f in tree['functions']),'max_block_parameters':max(len(b['params']) for f in tree['functions'] for b in f['blocks'])}
    print(json.dumps({'source_bytes':p.stat().st_size,'counts':counts}),flush=True)
if __name__=='__main__':main()
