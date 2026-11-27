"""Isolated HIA seed profile: adjacent literal shifts within one basic block.

This development profile preserves the original admission and generic scalar
path. It cannot specialize an instruction which is a function or edge target.
It reuses only the original, already bounded instruction-offset workspace.
"""
import ast
import copy
from hashlib import sha256
from pathlib import Path

from tools.generate_hia_seed_cold_backend import program as cold_program


MARK = '''
def mark_shift_entries(s:readbuf,w:mutbuf)->u64:
    start=get(w,40)
    at=start
    while at<get(w,48):
        put(w,8192+((at-start)>>6)*8,0)
        at=at+64
    owner=0
    while owner<get(w,72):
        target=get(w,272+owner*32)
        put(w,8192+((target-start)>>6)*8,9223372036854775808)
        owner=owner+1
    at=start
    while at<get(w,48):
        op=word(s,at)
        if op==36:
            target=word(s,word(s,at+8))
            put(w,8192+((target-start)>>6)*8,9223372036854775808)
        elif op==37:
            target=word(s,word(s,at+16))
            put(w,8192+((target-start)>>6)*8,9223372036854775808)
            target=word(s,word(s,at+24))
            put(w,8192+((target-start)>>6)*8,9223372036854775808)
        at=at+64
    return 0
'''

SPECIAL = '''
if op==9 or op==10:
    if at>=get(w,40)+64 and get(w,8192+((at-get(w,40))>>6)*8)==0:
        if word(s,at-64)==32 and word(s,at-56)==word(s,at+24):
            shift=word(s,at-48)
            width=word(s,at+40)
            if shift<width:
                value_load(o,w,0,word(s,at+16))
                enc(o,w,17,0,0,shift,choose(op==9,0,1),0)
                normalize(o,w,width)
                value_save(o,w,0,word(s,at+8))
                return 0
'''


def program():
    parent = cold_program('endian')
    if sha256(parent.encode()).hexdigest() != '1ee2fc9627af1378d5dbcd8a677957f13a7cf6ebba6309079fb9f910a3760445':
        raise ValueError('constant-shift cold-endian parent source differs')
    original = ast.parse(parent)
    tree = copy.deepcopy(original)
    functions = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}
    assert len(functions) == len(tree.body)
    functions['seed_cold_endian_backend'].name = 'seed_cold_endian_shift_backend'
    generate = functions['generate']
    old_generate = copy.deepcopy(generate)
    assert ast.unparse(generate.body[3]) == 'public_entry(o, w)'
    generate.body.insert(3, ast.parse('mark_shift_entries(s,w)').body[0])
    loop = next(n for n in generate.body if isinstance(n, ast.While))
    expected = ast.parse('put(w,8192+((at-get(w,40))>>6)*8,get(w,0))').body[0]
    positions = [i for i,n in enumerate(loop.body) if ast.dump(n)==ast.dump(expected)]
    assert len(positions)==1
    i=positions[0]
    assert ast.unparse(loop.body[i+1])=='instruction(s, o, w, at)'
    loop.body[i:i+2]=ast.parse('position=get(w,0)\ninstruction(s,o,w,at)\nput(w,8192+((at-get(w,40))>>6)*8,position)').body
    scalar=functions['scalar']
    old_scalar=copy.deepcopy(scalar)
    scalar.body[0:0]=ast.parse(SPECIAL).body
    tree.body.append(ast.parse(MARK).body[0])
    # Exact inverse checks guard every original function and body.
    inverse=copy.deepcopy(tree)
    inverse.body.pop()
    for i,n in enumerate(inverse.body):
        if n.name=='generate':inverse.body[i]=old_generate
        elif n.name=='scalar':inverse.body[i]=old_scalar
        elif n.name=='seed_cold_endian_shift_backend':n.name='seed_cold_endian_backend'
    assert ast.dump(inverse)==ast.dump(original)
    return ast.unparse(ast.fix_missing_locations(tree))+'\n'


def main():
    from hepta.hia_agent_assembly import render_assembly
    from tools.generate_hia_worker_config_json import document
    name = 'seed_cold_endian_shift_backend'
    raw = render_assembly(document(program(), name)).encode()
    root = Path(__file__).resolve().parents[1]
    path = root / 'examples/hia_bootstrap' / (name + '.hepta')
    path.write_bytes(raw)
    print('COLD_ENDIAN_SHIFT_SOURCE', name, len(raw), sha256(raw).hexdigest())


if __name__ == '__main__':
    main()
