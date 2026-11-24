"""Separate v1 and div seed profiles adding only resource buffer.move_within.

The old profiles and their checked sources remain unchanged. The new operation
checks both complete ranges before emitting a single memory write. Correct
memmove direction handles overlap; all returning paths leave the SysV direction
flag clear. The author itself uses only old seed instructions.
"""
from pathlib import Path
import ast
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_worker_config_json import document
from tools.generate_hia_seed_backend import program as base_program
ROOT=Path(__file__).resolve().parents[1]
MOVE=r'''
def bulk_move(s:readbuf,o:mutbuf,w:mutbuf,inputs:u64) -> u64:
    value_load(o,w,0,word(s,inputs))
    value_load(o,w,1,word(s,inputs+8))
    value_load(o,w,8,word(s,inputs+16))
    value_load(o,w,9,word(s,inputs+24))
    load(o,w,2,0,8)
    enc(o,w,14,1,2,0,0,0)
    failure(o,w,7)
    enc(o,w,2,10,2,0,0,0)
    enc(o,w,10,10,1,0,0,0)
    enc(o,w,14,9,10,0,0,0)
    failure(o,w,7)
    enc(o,w,14,8,2,0,0,0)
    failure(o,w,7)
    enc(o,w,10,2,8,0,0,0)
    enc(o,w,14,9,2,0,0,0)
    failure(o,w,7)
    enc(o,w,15,9,9,0,0,0)
    empty = patch(o,w,34,4,0)
    load(o,w,0,0,0)
    enc(o,w,2,7,0,0,0,0)
    enc(o,w,9,7,1,0,0,0)
    enc(o,w,2,6,0,0,0,0)
    enc(o,w,9,6,8,0,0,0)
    enc(o,w,14,1,8,0,0,0)
    forward_before = patch(o,w,34,6,0)
    enc(o,w,2,10,1,0,0,0)
    enc(o,w,10,10,8,0,0,0)
    enc(o,w,14,10,9,0,0,0)
    forward_after = patch(o,w,34,3,0)
    enc(o,w,2,1,9,0,0,0)
    enc(o,w,9,7,9,0,0,0)
    enc(o,w,16,7,0,1,3,0)
    enc(o,w,9,6,9,0,0,0)
    enc(o,w,16,6,0,1,3,0)
    emit(o,w,253)
    emit(o,w,243)
    emit(o,w,164)
    emit(o,w,252)
    finished = patch(o,w,33,0,0)
    absolute_target(w,forward_before,get(w,0))
    absolute_target(w,forward_after,get(w,0))
    enc(o,w,2,1,9,0,0,0)
    emit(o,w,252)
    emit(o,w,243)
    emit(o,w,164)
    absolute_target(w,empty,get(w,0))
    absolute_target(w,finished,get(w,0))
    return 0
'''


def program(*,division=False):
    if division:
        from tools.generate_hia_seed_div_backend import program as division_program
        raw=division_program();name='seed_div_bulk_backend'
    else:
        raw=base_program();name='seed_bulk_backend'
    tree=ast.parse(raw);admission=0;emission=0;entry=0
    for fn in tree.body:
        if fn.name in ('seed_backend','seed_div_backend'):
            fn.name=name;entry+=1
        if fn.name=='resource_admit':
            for node in ast.walk(fn):
                if isinstance(node,ast.If) and ast.unparse(node.test)=='op == 7':
                    node.test=ast.parse('op == 7 or op == 10',mode='eval').body;admission+=1
        if fn.name=='resource':
            indices=[i for i,node in enumerate(fn.body) if isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name) and node.targets[0].id=='inputs']
            if len(indices)!=1:raise ValueError('seed resource input shape differs')
            point=indices[0]+1;fn.body[point:point]=ast.parse('if code == 10:\n    bulk_move(s,o,w,inputs)\n    return 0').body;emission+=1
    if (admission,emission,entry)!=(1,1,1):raise ValueError('seed source profile changed')
    tree.body.extend(ast.parse(MOVE).body)
    return ast.unparse(ast.fix_missing_locations(tree))


def main():
    for division,name in ((False,'seed_bulk_backend'),(True,'seed_div_bulk_backend')):
        doc=document(program(division=division),name);raw=render_assembly(doc).encode();path=ROOT/'examples/hia_bootstrap'/(name+'.hepta');path.write_bytes(raw)
        print('SEED_BULK_SOURCE',name,len(raw),len(doc['functions']),sum(len(f['blocks']) for f in doc['functions']),sum(len(b['ops']) for f in doc['functions'] for b in f['blocks']))
if __name__=='__main__':main()
