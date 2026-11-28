"""Author a closed native frontend for the existing HIA inprocess packer."""
from pathlib import Path
from hashlib import sha256
import argparse, ast, copy, json
from tools.generate_hia_continuation import packer_source
from tools.generate_hia_worker_install_bind import sha_functions
from tools.generate_hia_direct_load_plan import LinkerBuilder
from tools.generate_hia_selfhost import compact_authoring_cfg, total_scalar_functions
from hepta.hia_agent_assembly import render_assembly
ROOT=Path(__file__).resolve().parents[1]
PACKER='examples/hia_bootstrap/continuation_inprocess_packer.hepta'
ENTRY=r'''def entry(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(o) < 33554432 or length(w) < 2097152:
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
    if phase != 1 or mode != 1 or length(s) < 96 or length(s) > 67108864 or header(s, 0) != MAGIC:
        return 16
    source_size = header(s, 8)
    if source_size != SOURCE_BYTES or source_size > length(s) - 88:
        return 16
    constants(w)
    digest(s, o, w, 16, source_size, 16777216)
    i = 0
    while i < 32:
        if byte(o, 16777216 + i) != byte(w, 16384 + i):
            return 16
        i = i + 1
    result = widen(original_pack(s, o, w))
    if result == 0 or result > 33554432:
        return 16
    put(w, 0, 1)
    put(w, 16, 3)
    put(w, 88, result)
    return 0

def widen(v:u32) -> u64:
    return v

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

def policy_source(profile='v1'):
    if type(profile) is not str or profile not in ('v1','v2'):
        raise ValueError('Worker continuation pack profile differs')
    selected_path=PACKER
    original_source=packer_source(in_process=True)
    magic=b'HIAWCP01'
    if profile=='v2':
        from tools.generate_hia_continuation_v2 import packer_source as v2_packer_source
        selected_path='examples/hia_bootstrap/continuation_inprocess_packer_v2.hepta'
        original_source=v2_packer_source()
        magic=b'HIAWCP02'
    raw=(ROOT/selected_path).read_bytes();pin=sha256(raw).digest()
    original=ast.parse(original_source).body
    names={n.name:'original_'+n.name for n in original}
    assert original[0].name=='pack'
    class Offset(ast.NodeTransformer):
        def visit_FunctionDef(self,n):
            n=copy.deepcopy(n);self.types={p.arg:p.annotation.id for p in n.args.args};n.name=names[n.name];return self.generic_visit(n)
        def offset(self,arg):
            return ast.BinOp(left=ast.Constant(value=16),op=ast.Add(),right=ast.Call(func=ast.Name(id='header',ctx=ast.Load()),args=[copy.deepcopy(arg),ast.Constant(value=8)],keywords=[]))
        def visit_Call(self,n):
            n=self.generic_visit(n)
            if isinstance(n.func,ast.Name):
                name=n.func.id
                if name=='length' and isinstance(n.args[0],ast.Name) and self.types.get(n.args[0].id)=='readbuf':
                    return ast.BinOp(left=n,op=ast.Sub(),right=self.offset(n.args[0]))
                if name in ('byte','word_load') and isinstance(n.args[0],ast.Name) and self.types.get(n.args[0].id)=='readbuf':
                    n.args[1]=ast.BinOp(left=self.offset(n.args[0]),op=ast.Add(),right=n.args[1])
                if name in names:n.func.id=names[name]
            return n
    source=ENTRY.replace('MAGIC',str(int.from_bytes(magic,'little'))).replace('SOURCE_BYTES',str(len(raw)))
    source+='\n'+'\n\n'.join(ast.unparse(ast.fix_missing_locations(Offset().visit(n))) for n in original)+'\n'
    source+='\ndef constants(w:mutbuf) -> u64:\n'
    for i in range(0,32,8):source+=f'    put(w, {16384+i}, {int.from_bytes(pin[i:i+8],"little")})\n'
    source+='    return 0\n'+sha_functions()
    return source

def render(profile='v1'):
    nodes=ast.parse(policy_source(profile)).body;names={n.name:f'f{i}' for i,n in enumerate(nodes)};assert len(names)==len(nodes)
    signatures={n.name:([a.annotation.id for a in n.args.args],n.returns.id) for n in nodes};total=total_scalar_functions(nodes);functions=[]
    for n in nodes:
        b=LinkerBuilder(n,names,signatures,total);b.statements(n.body);functions.append({'name':names[n.name],'params':[b.param(a) for a in b.params],'returns':[b.returns],'effects':['read','write','trap'],'entry':'b0','blocks':b.blocks})
    doc=compact_authoring_cfg({'schema':'hepta.hia.program.v9','module':'source_worker_continuation_pack_v2' if profile=='v2' else 'source_worker_continuation_pack','functions':functions});text=render_assembly(doc)
    return text,{'functions':len(functions),'source_bytes':len(text.encode()),'sha256':sha256(text.encode()).hexdigest(),'maximum_block_parameters':max(len(b['params']) for f in doc['functions'] for b in f['blocks'])}
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--check',action='store_true');p.add_argument('--core-profile',choices=('v1','v2'),default='v1');a=p.parse_args();text,record=render(a.core_profile);path=ROOT/('examples/hia_bootstrap/source_worker_continuation_pack'+('_v2' if a.core_profile=='v2' else '')+'.hepta')
    if a.check:
        if path.read_text()!=text:raise SystemExit('worker continuation pack policy differs')
    else:path.write_text(text)
    print(json.dumps(record,sort_keys=True))
if __name__=='__main__':main()
