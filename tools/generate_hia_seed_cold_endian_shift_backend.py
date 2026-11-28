"""Isolated HIA seed profile: literal shifts and bounded scalar register reuse.

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


def shift_program():
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


def cache_program(parent):
    if sha256(parent.encode()).hexdigest() != '529cc4bc12eb3f783b15fd60eaf0ad4b65f6f410d8409368568512b5dbd228e7':
        raise ValueError('fixed constant-shift parent source differs')
    tree = ast.parse(parent)
    before = copy.deepcopy(tree)
    functions = {n.name: n for n in tree.body}
    changed = ('generate', 'instruction', 'scalar')
    original_functions = {name: copy.deepcopy(functions[name]) for name in changed}
    generate = functions['generate']
    mark = [i for i, n in enumerate(generate.body) if ast.unparse(n) == 'mark_shift_entries(s, w)']
    if not len(mark) == 1:
        raise ValueError('fixed scalar cache transform differs')
    generate.body[mark[0] + 1:mark[0] + 1] = ast.parse('scalar_cache_reset(w)').body
    loop = next((n for n in generate.body if isinstance(n, ast.While)))
    position = [i for i, n in enumerate(loop.body) if ast.unparse(n) == 'position = get(w, 0)']
    if not len(position) == 1:
        raise ValueError('fixed scalar cache transform differs')
    loop.body[position[0]:position[0]] = ast.parse('if get(w,8192+((at-get(w,40))>>6)*8) != 0:\n    scalar_cache_reset(w)\n').body
    instruction = functions['instruction']
    if not ast.unparse(instruction.body[0]) == 'op = word(s, at)':
        raise ValueError('fixed scalar cache transform differs')
    instruction.body[1:1] = ast.parse('if op > 27 and op != 32:\n    scalar_cache_reset(w)\n').body
    const = next((n for n in ast.walk(instruction) if isinstance(n, ast.If) and ast.unparse(n.test) == 'op == 32'))
    if not [ast.unparse(n) for n in const.body] == ['immediate(o, w, 0, word(s, at + 16))', 'value_save(o, w, 0, word(s, at + 8))']:
        raise ValueError('fixed scalar cache transform differs')
    const.body = ast.parse('immediate(o,w,1,word(s,at+16))\nvalue_save(o,w,1,word(s,at+8))\nput(w,224,word(s,at+8))\nput(w,232,1)\nif get(w,216) != 0 and get(w,208) == word(s,at+8):\n    put(w,216,0)\n').body
    scalar = functions['scalar']
    pair = ast.parse('value_load(o,w,0,word(s,at+16))\nvalue_load(o,w,1,word(s,at+24))').body
    matches = [i for i in range(len(scalar.body) - 1) if all((ast.dump(scalar.body[i + j]) == ast.dump(pair[j]) for j in range(2)))]
    if not len(matches) == 1:
        raise ValueError('fixed scalar cache transform differs')
    index = matches[0]
    scalar.body[index:index + 2] = ast.parse('if get(w,216) != 0 and get(w,208) == word(s,at+24) and (op == 1 or op == 3 or op == 12 or op == 13 or op == 14 or op == 16 or op == 17 or op == 22 or op == 23):\n    scalar_cached_load(o,w,1,word(s,at+16))\nelse:\n    scalar_cached_load(o,w,0,word(s,at+16))\n    scalar_cached_load(o,w,1,word(s,at+24))\n').body

    class Loads(ast.NodeTransformer):
        loads = 0
        saves = 0

        def visit_Expr(self, node):
            if isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name):
                call = node.value
                if call.func.id == 'value_load' and isinstance(call.args[2], ast.Constant) and (call.args[2].value in (0, 1)):
                    self.loads += 1
                    call.func.id = 'scalar_cached_load'
                    return node
                if call.func.id == 'value_save' and ast.dump(node) == ast.dump(ast.parse('value_save(o,w,0,word(s,at+8))').body[0]):
                    self.saves += 1
                    return [node, ast.parse('scalar_cache_result(w,word(s,at+8))').body[0]]
            return node
    loads = Loads()
    loads.visit(scalar)
    if not (loads.loads == 1 and loads.saves == 2):
        raise ValueError('fixed scalar cache transform differs')
    helpers = 'def scalar_cache_reset(w:mutbuf) -> u64:\n    put(w,216,0)\n    put(w,232,0)\n    return 0\n\ndef scalar_cached_load(o:mutbuf,w:mutbuf,reg:u64,slot:u64) -> u64:\n    if reg == 0:\n        if get(w,216) != 0 and get(w,208) == slot:\n            return 0\n        value_load(o,w,reg,slot)\n        put(w,208,slot)\n        put(w,216,1)\n        return 0\n    if reg == 1:\n        if get(w,232) != 0 and get(w,224) == slot:\n            return 0\n        value_load(o,w,reg,slot)\n        put(w,224,slot)\n        put(w,232,1)\n        return 0\n    return value_load(o,w,reg,slot)\n\ndef scalar_cache_result(w:mutbuf,slot:u64) -> u64:\n    put(w,208,slot)\n    put(w,216,1)\n    if get(w,232) != 0 and get(w,224) == slot:\n        put(w,232,0)\n    return 0\n'
    added = ast.parse(helpers).body
    if not not set((n.name for n in added)).intersection(functions):
        raise ValueError('fixed scalar cache transform differs')
    tree.body.extend(added)
    inverse = copy.deepcopy(tree)
    inverse.body = inverse.body[:-len(added)]
    for i, n in enumerate(inverse.body):
        if n.name in original_functions:
            inverse.body[i] = original_functions[n.name]
    if not ast.dump(inverse) == ast.dump(before):
        raise ValueError('fixed scalar cache transform differs')
    return ast.unparse(ast.fix_missing_locations(tree)) + '\n'

def program():
    return cache_program(shift_program())


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
