"""Author native streaming frontends for the six existing HIA capsule policies.

The authority function bodies retain their original HIA logic. The author
adjusts only read-view offsets and the two fixed ABI view lengths, allowing the
same policy to run through the native source kit without a Python/FFI caller.
"""
from pathlib import Path
from hashlib import sha256
import argparse, ast, copy, json
from tools.generate_hia_read_capsule import source_program as read_program
from tools.generate_hia_readonly_worker_capsule import source_program as other_program
from tools.generate_hia_direct_load_plan import LinkerBuilder
from tools.generate_hia_selfhost import compact_authoring_cfg, total_scalar_functions
from hepta.hia_agent_assembly import render_assembly
ROOT=Path(__file__).resolve().parents[1]
KINDS=('read','readonly','native','evaluate-replay','evaluate-intake','evaluate-full')

ENTRY=r'''def entry(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(o) < 1048576 or length(w) < 2097152:
        return 17
    phase = word_load(w, 0)
    mode = word_load(w, 16)
    if phase == 0 and mode == 0:
        if length(s) != 21 or header(s, 0) != 1 or header(s, 8) != 5:
            return 16
        if byte(s, 16) != 98 or byte(s, 17) != 117 or byte(s, 18) != 105 or byte(s, 19) != 108 or byte(s, 20) != 100:
            return 16
        put(w, 16, 1)
        return 0
    if phase == 2 and mode == 3:
        return 3
    if phase != 1 or mode != 1 or length(s) < 64 or length(s) > 8388672:
        return 16
    if header(s, 0) != REQUEST_MAGIC or header(s, 24) != length(s) - 64:
        return 16
    i = 0
    while i < 32:
        store(o, i, 0)
        store(o, 32 + i, byte(s, 32 + i))
        i = i + 1
    put(o, 64, header(s, 8))
    put(o, 72, header(s, 16))
    put(o, 80, length(s) - 64)
    result = authority_widen(authority_authenticate(s, o, w))
    if result != 1:
        return 16
    i = 0
    while i < 32:
        if byte(o, i) != byte(s, 32 + i) or byte(o, 32 + i) != byte(s, 32 + i):
            return 16
        i = i + 1
    if word_load(o, 64) != header(s, 8) or word_load(o, 72) != header(s, 16) or word_load(o, 80) != length(s) - 64:
        return 16
    put(o, 0, RESPONSE_MAGIC)
    i = 0
    while i < 32:
        store(o, 8 + i, byte(s, 32 + i))
        i = i + 1
    put(w, 0, 1)
    put(w, 16, 3)
    put(w, 88, 40)
    return 0

def header(s:readbuf, at:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(s, at + i) << (i * 8))
        i = i + 1
    return value

def put(w:mutbuf, at:u64, value:u64) -> u64:
    i = 0
    while i < 8:
        store(w, at + i, (value >> (i * 8)) & 255)
        i = i + 1
    return 0
'''

def source(kind):
    if kind=='read': return read_program()
    return other_program(artifact=kind!='readonly',evaluate_replay=kind=='evaluate-replay',evaluate_intake=kind=='evaluate-intake',evaluate_full=kind=='evaluate-full')

def policy_source(kind):
    original=ast.parse(source(kind)).body
    names={n.name:'authority_'+n.name for n in original}
    class AdjustViews(ast.NodeTransformer):
        def visit_FunctionDef(self,node):
            node=copy.deepcopy(node)
            self.types={p.arg:p.annotation.id for p in node.args.args}
            node.name=names[node.name]
            return self.generic_visit(node)
        def visit_Call(self,node):
            node=self.generic_visit(node)
            if isinstance(node.func,ast.Name):
                name=node.func.id
                if name=='length' and isinstance(node.args[0],ast.Name):
                    arg=node.args[0].id
                    if self.types.get(arg)=='readbuf':
                        return ast.BinOp(left=node,op=ast.Sub(),right=ast.Constant(value=64))
                    if arg=='o': return ast.Constant(value=88)
                    if arg=='w': return ast.Constant(value=1088)
                if name in ('byte','word_load') and isinstance(node.args[0],ast.Name) and self.types.get(node.args[0].id)=='readbuf':
                    node.args[1]=ast.BinOp(left=ast.Constant(value=64),op=ast.Add(),right=node.args[1])
                if name == 'word_store': node.func.id = 'put'
                if name in names:node.func.id=names[name]
            return node
    adjusted='\n\n'.join(ast.unparse(ast.fix_missing_locations(AdjustViews().visit(n))) for n in original)
    entry=ENTRY.replace('REQUEST_MAGIC',str(int.from_bytes(b'HIAWCC01','little'))).replace('RESPONSE_MAGIC',str(int.from_bytes(b'HIAWCO01','little')))
    return entry+'\n'+adjusted+'\n'

def render(kind):
    nodes=ast.parse(policy_source(kind)).body
    names={n.name:f'f{i}' for i,n in enumerate(nodes)}
    signatures={n.name:([a.annotation.id for a in n.args.args],n.returns.id) for n in nodes}
    total=total_scalar_functions(nodes);functions=[]
    for node in nodes:
        b=LinkerBuilder(node,names,signatures,total);b.statements(node.body)
        functions.append({'name':names[node.name],'params':[b.param(a) for a in b.params],'returns':[b.returns],'effects':['read','write','trap'],'entry':'b0','blocks':b.blocks})
    doc=compact_authoring_cfg({'schema':'hepta.hia.program.v9','module':'source_worker_capsule_check_'+kind.replace('-','_'),'functions':functions})
    text=render_assembly(doc)
    return text,{'kind':kind,'functions':len(functions),'source_bytes':len(text.encode()),'sha256':sha256(text.encode()).hexdigest(),'maximum_block_parameters':max(len(b['params']) for f in doc['functions'] for b in f['blocks'])}

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--check',action='store_true');a=p.parse_args()
    for kind in KINDS:
        text,record=render(kind);path=ROOT/'examples/hia_bootstrap'/('source_worker_capsule_check_'+kind.replace('-','_')+'.hepta')
        if a.check:
            if path.read_text()!=text:raise SystemExit('capsule native frontend differs: '+kind)
        else:path.write_text(text)
        print(json.dumps(record,sort_keys=True))
if __name__=='__main__':main()
