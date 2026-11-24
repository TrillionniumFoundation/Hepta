"""Author nonalias HIA SHA and a mechanical view-dispatch flat packer.

The original HIA entry is preserved byte-for-byte inside the resulting flat.
Only checked, pairwise disjoint six-word foreign ABI views enter the HIA word
copy variant.  The assembly prefix observes pointers and lengths only; it does
not read input bytes, compute SHA, copy payloads, or alter any argument/stack.
The checked-in HIA packer contains the fixed mechanical template and produces
both relative jumps from actual supplied flat extents without a host linker.
"""
from pathlib import Path
import ast,struct,subprocess,tempfile
from tools.generate_hia_cold_sha256_stream import source_program as original_source,Builder
from tools.generate_hia_selfhost import compact_authoring_cfg,total_scalar_functions
from hepta.hia_agent_assembly import render_assembly

ROOT=Path(__file__).resolve().parents[1]
MAGIC=int.from_bytes(b'HIASHA01','little')
MAX_FLAT=1<<20

def template():
    with tempfile.TemporaryDirectory(prefix='hia-sha-alias-') as tmp:
        p=Path(tmp);obj=p/'prefix.o';raw=p/'prefix.bin'
        subprocess.run(['as','--64','-o',str(obj),str(ROOT/'examples/hia_bootstrap/hia_cold_sha_alias.S')],check=True,capture_output=True)
        subprocess.run(['objcopy','-O','binary','--only-section=.text',str(obj),str(raw)],check=True,capture_output=True)
        symbols={parts[-1]:int(parts[0],16) for line in subprocess.check_output(['nm','-n',str(obj)],text=True).splitlines() if len(parts:=line.split())==3}
        code=raw.read_bytes();old=symbols['hia_cold_sha_alias_old_hole'];fast=symbols['hia_cold_sha_alias_fast_hole'];assert code[old:old+4]==code[fast:fast+4]==bytes(4)
        return code,old,fast

class LowWordAlgebra(ast.NodeTransformer):
    """Drop masks only before final low-word consumers, never before a shift.

    Rotate left arms feed XOR/addition only; t1/t2 feed the final masked a/e
    assignments. All schedule/chaining stores and a/e masks remain unchanged.
    This preserves even arbitrary full-u64 state and round constants.
    """
    def __init__(self):
        self.removed=0
    def visit_BinOp(self,node):
        node=self.generic_visit(node)
        if (isinstance(node.op,ast.BitAnd) and isinstance(node.right,ast.Constant)
            and node.right.value==4294967295 and isinstance(node.left,ast.BinOp)
            and isinstance(node.left.op,ast.LShift)):
            self.removed+=1
            return node.left
        return node
    def visit_Assign(self,node):
        node=self.generic_visit(node)
        if (len(node.targets)==1 and isinstance(node.targets[0],ast.Name)
            and node.targets[0].id in ('t1','t2')):
            assert isinstance(node.value,ast.BinOp) and isinstance(node.value.op,ast.BitAnd)
            assert isinstance(node.value.right,ast.Constant) and node.value.right.value==4294967295
            node.value=node.value.left
            self.removed+=1
        return node

def nonalias_source():
    module=ast.parse(original_source())
    compression=next(n for n in module.body if isinstance(n,ast.FunctionDef) and n.name=='compress')
    algebra=LowWordAlgebra();algebra.visit(compression)
    assert algebra.removed==48
    stream=next(n for n in module.body if isinstance(n,ast.FunctionDef) and n.name=='stream')
    update=next(n for n in stream.body if isinstance(n,ast.If) and ast.unparse(n.test)=='op == 1')
    loop=next(n for n in update.body if isinstance(n,ast.While));fast=loop.body[0]
    assert isinstance(fast,ast.If) and ast.unparse(fast.test)=='used == 0 and length(s) - i >= 64'
    body=''
    for index in range(8):
        body+=f'cold_transfer = word_load(s, i + {index*8})\nword_store(w, {1112+index*8}, cold_transfer)\n'
    fast.body=ast.parse(body+'compress(w)\ni = i + 64\n').body
    return ast.unparse(ast.fix_missing_locations(module))+'\n'

def packer_source():
    prefix,old_hole,fast_hole=template()
    s=f'''def pack(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s) < 24:
        return 4294967295
    if word_load(s, 0) != {MAGIC}:
        return 4294967295
    old_bytes = word_load(s, 8)
    fast_bytes = word_load(s, 16)
    if old_bytes == 0 or fast_bytes == 0 or old_bytes > {MAX_FLAT} or fast_bytes > {MAX_FLAT}:
        return 4294967295
    if length(s) != 24 + old_bytes + fast_bytes:
        return 4294967295
    total = {len(prefix)} + old_bytes + fast_bytes
    if length(o) < total:
        return 4294967294
'''
    at=0
    while at+8<=len(prefix):
        s+=f'    put(o, {at}, {int.from_bytes(prefix[at:at+8],"little")})\n';at+=8
    while at<len(prefix):
        s+=f'    store(o, {at}, {prefix[at]})\n';at+=1
    s+=f'''    put32(o, {old_hole}, {len(prefix)-old_hole-4})
    put32(o, {fast_hole}, {len(prefix)-fast_hole-4} + old_bytes)
    i = 0
    while i < old_bytes + fast_bytes:
        store(o, {len(prefix)} + i, byte(s, 24 + i))
        i = i + 1
    return total

def put(o:mutbuf,at:u64,value:u64) -> u64:
'''
    s+=''.join(f'    store(o, at + {i}, (value >> {8*i}) & 255)\n' for i in range(8))+'    return 0\n\ndef put32(o:mutbuf,at:u64,value:u64) -> u64:\n'
    s+=''.join(f'    store(o, at + {i}, (value >> {8*i}) & 255)\n' for i in range(4))+'    return 0\n'
    return s

def document(source,module):
    nodes=ast.parse(source).body;names={n.name:'f'+str(i)for i,n in enumerate(nodes)}
    signatures={n.name:([a.annotation.id for a in n.args.args],n.returns.id)for n in nodes}
    total=total_scalar_functions(nodes);functions=[]
    for node in nodes:
        b=Builder(node,names,signatures,total);b.statements(node.body)
        functions.append({'name':names[node.name],'params':[b.param(v)for v in b.params],'returns':[b.returns],'effects':['read','write','trap'],'entry':'b0','blocks':b.blocks})
    return compact_authoring_cfg({'schema':'hepta.hia.program.v9','module':module,'functions':functions})

def main():
    for name,source in [('cold_sha256_nonalias',nonalias_source()),('cold_sha256_alias_packer',packer_source())]:
        doc=document(source,name);raw=render_assembly(doc).encode();(ROOT/'examples/hia_bootstrap'/(name+'.hepta')).write_bytes(raw)
        print(name,len(raw),len(doc['functions']),sum(len(f['blocks'])for f in doc['functions']),sum(len(b['ops'])for f in doc['functions']for b in f['blocks']))
if __name__=='__main__':main()
