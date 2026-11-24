"""Author the HIA finalizer ELF packer from its mechanical syscall adapter."""
from pathlib import Path
import argparse,ast,struct,subprocess,tempfile
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_direct_load_plan import LinkerBuilder
from tools.generate_hia_selfhost import compact_authoring_cfg,total_scalar_functions
ROOT=Path(__file__).resolve().parents[1]
HELPERS='\ndef copy(s:readbuf, w:mutbuf, target:u64, source:u64, count:u64) -> u64:\n    i = 0\n    while i < count:\n        store(w, target + i, byte(s, source + i))\n        i = i + 1\n    return 0\n\ndef uint(s:readbuf, at:u64) -> u64:\n    index = 0\n    value = 0\n    while index < 8:\n        value = value | (byte(s, at + index) << (index * 8))\n        index = index + 1\n    return value\n\ndef put(w:mutbuf, at:u64, value:u64) -> u64:\n    index = 0\n    while index < 8:\n        store(w, at + index, (value >> (index * 8)) & 255)\n        index = index + 1\n    return 0\n'
def document(source,module):
 nodes=ast.parse(source).body
 names={n.name:f'f{i}' for i,n in enumerate(nodes)}
 signatures={n.name:([a.annotation.id for a in n.args.args],n.returns.id) for n in nodes}
 total=total_scalar_functions(nodes);functions=[]
 for n in nodes:
  b=LinkerBuilder(n,names,signatures,total);b.statements(n.body)
  functions.append({'name':names[n.name],'params':[b.param(a) for a in b.params],'returns':[b.returns],'effects':['read','write','trap'],'entry':'b0','blocks':b.blocks})
 return compact_authoring_cfg({'schema':'hepta.hia.program.v8','module':module,'functions':functions})

with tempfile.TemporaryDirectory(prefix='hia-finalize-author-') as tmp:
 t=Path(tmp);obj=t/'a.o';blob=t/'a.bin'
 subprocess.run(['as','--64',str(ROOT/'tools/hia_release_finalize_syscalls.S'),'-o',str(obj)],check=True,capture_output=True)
 subprocess.run(['objcopy','-O','binary','-j','.text',str(obj),str(blob)],check=True,capture_output=True)
 symbols={name:int(address,16) for address,_,name in (l.split() for l in subprocess.check_output(['nm','-n',str(obj)],text=True).splitlines())}
 assert symbols['_start']==0 and 'R_X86_64' not in subprocess.check_output(['objdump','-r',str(obj)],text=True)
 adapter=blob.read_bytes()
header=(b'\x7fELF\x02\x01\x01'+bytes(9)+struct.pack('<HHIQQQIHHHHHH',2,62,1,0x4000b0,64,0,0,64,56,2,0,0,0)+struct.pack('<IIQQQQQQ',1,5,0,0x400000,0x400000,0,0,4096)+struct.pack('<IIQQQQQQ',0x6474e551,6,0,0,0,0,0,16))
prefix=header+adapter;holes={n:176+symbols[n] for n in ('policy_hole','sha_hole')}
packer=f'''def pack(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s) < 26 or uint(s, 0) != {int.from_bytes(b'HIAFINK1','little')}:
        return 4294967295
    policy = uint(s, 8)
    sha = uint(s, 16)
    if policy == 0 or sha == 0 or policy > 1048576 or sha > 1048576 or length(s) != 24 + policy + sha:
        return 4294967295
    size = {len(prefix)} + policy + sha
    if size > 1048576 or length(o) < size:
        return 4294967294
'''
for at in range(0,len(prefix),8):
 part=prefix[at:at+8]
 for i,ch in enumerate(part):packer+=f'    store(o, {at+i}, {ch})\n'
packer+='    put(o, 96, size)\n    put(o, 104, size)\n'
for name,at in holes.items():
 target=f'{len(prefix)}'+(' + policy' if name=='sha_hole' else '')
 packer+=f'    displacement = {target} - {at+4}\n'
 for i in range(4):packer+=f'    store(o, {at+i}, (displacement >> {8*i}) & 255)\n'
packer+=f'    copy(s, o, {len(prefix)}, 24, policy + sha)\n    return size\n'
packer += HELPERS

def render():
 return render_assembly(document(packer,'release_finalize_packer'))

def main():
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('--check',action='store_true')
 args=parser.parse_args()
 path=ROOT/'examples/hia_bootstrap/release_finalize_packer.hepta'
 text=render()
 if args.check:
  if path.read_text()!=text:raise SystemExit('finalizer packer differs from current adapter')
 else:path.write_text(text)

if __name__=='__main__':
 main()
