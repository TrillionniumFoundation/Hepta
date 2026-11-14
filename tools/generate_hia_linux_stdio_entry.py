"""Independent HIA-owned ELF layout and a fixed, documented CPU startup ABI.

No assembler, template .S, or opaque adapter image is consumed. The HIA function
owns structural admission, segment fields, startup encodings, relocation and copy.
This is a mechanical packer, not proof that arbitrary input code was HIA-verified.
"""
from pathlib import Path
import ast,hashlib,json,struct,sys

ROOT=Path(__file__).resolve().parents[1]
BASE=ROOT
sys.path.insert(0,str(BASE))
from tools.generate_hia_selfhost import Builder,compact_authoring_cfg,total_scalar_functions
from tools.generate_hia_elf_linker import SOURCE as LINK_SOURCE
from hepta.hia_agent_assembly import render_assembly

LIMIT=1048576
MAGIC=int.from_bytes(b'HIALNXE1','little')
IMAGE_AT=384
TEXT_BASE=0x400000
DATA_BASE=0x600000
ENTRY_AT=232

SOURCE=r'''
def pack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 32 or length(s) > 1048576:
        return 4294967295
    if uint(s, 0, 8) != MAGIC or uint(s, 8, 8) != 1 or uint(s, 24, 8) != 0:
        return 4294967295
    image = uint(s, 16, 8)
    if image == 0 or image > 1048192:
        return 4294967295
    if length(s) != image + 32:
        return 4294967295
    file_size = (image + 384 + 4095) & 18446744073709547520
    if file_size > 1048576 or length(o) < file_size:
        return 4294967294
    fill_range(o, 0, file_size, 0)
    headers(o, file_size)
    start = startup(o, 232)
    if start > 384:
        return 4294967295
    copy_exact(o, s, 384, 32, image)
    return file_size

def headers(o:mutbuf, file_size:u64) -> u64:
    # ELF identity, class64, little endian, ELF version1; remaining ident is zero.
    write(o, 0, 282584257676671, 8)
    write(o, 16, 2, 2)
    write(o, 18, 62, 2)
    write(o, 20, 1, 4)
    write(o, 24, 4194536, 8)
    write(o, 32, 64, 8)
    write(o, 52, 64, 2)
    write(o, 54, 56, 2)
    write(o, 56, 3, 2)
    # PT_LOAD: exact immutable file bytes, R|X only.
    write(o, 64, 1, 4)
    write(o, 68, 5, 4)
    write(o, 80, 4194304, 8)
    write(o, 88, 4194304, 8)
    write(o, 96, file_size, 8)
    write(o, 104, file_size, 8)
    write(o, 112, 4096, 8)
    # PT_LOAD: two fixed 1MiB borrowed buffers, zero-filled R|W/NX BSS.
    write(o, 120, 1, 4)
    write(o, 124, 6, 4)
    write(o, 128, file_size, 8)
    write(o, 136, 6291456, 8)
    write(o, 144, 6291456, 8)
    write(o, 160, 2097152, 8)
    write(o, 168, 4096, 8)
    # PT_GNU_STACK: R|W only, no executable stack or interpreter.
    write(o, 176, 1685382481, 4)
    write(o, 180, 6, 4)
    write(o, 224, 16, 8)
    return 0

def startup(o:mutbuf, at:u64) -> u64:
    # xor ebp,ebp; cld; and rsp,-16. No argv/env or data-dependent entry policy.
    at = instruction(o, at, 60721, 2)
    at = instruction(o, at, 252, 1)
    at = instruction(o, at, 4041507656, 4)
    # Fixed nondumpable transition, preserving the original native-child guard.
    at = register32(o, at, 7, 4)
    at = register32(o, at, 6, 0)
    at = instruction(o, at, 53809, 2)
    at = instruction(o, at, 13775173, 3)
    at = instruction(o, at, 12595525, 3)
    at = register32(o, at, 0, 157)
    at = instruction(o, at, 1295, 2)
    at = instruction(o, at, 49285, 2)
    at = instruction(o, at, 34063, 2)
    failed = at
    at = at + 4
    # Six fixed borrowed-buffer arguments: empty readbuf, output, workspace.
    at = register32(o, at, 7, 4194304)
    at = register32(o, at, 6, 0)
    at = register32(o, at, 2, 6291456)
    at = register32(o, at, 1, 1048576)
    at = register32(o, at, 8, 7340032)
    at = register32(o, at, 9, 1048576)
    at = instruction(o, at, 232, 1)
    write(o, at, 384 - at - 4, 4)
    at = at + 4
    # mov edi,eax; exit(status); ud2 if the kernel unexpectedly returns.
    at = instruction(o, at, 51081, 2)
    at = register32(o, at, 0, 60)
    at = instruction(o, at, 1295, 2)
    at = instruction(o, at, 2831, 2)
    write(o, failed, at - failed - 4, 4)
    # Only startup failure is category126; it never calls the HIA program.
    at = register32(o, at, 7, 126)
    at = register32(o, at, 0, 60)
    at = instruction(o, at, 1295, 2)
    at = instruction(o, at, 2831, 2)
    return at

def register32(o:mutbuf, at:u64, reg:u64, value:u64) -> u64:
    if reg >= 8:
        store(o, at, 65)
        at = at + 1
        reg = reg - 8
    store(o, at, 184 + reg)
    write(o, at + 1, value, 4)
    return at + 5

def instruction(o:mutbuf, at:u64, encoding:u64, size:u64) -> u64:
    write(o, at, encoding, size)
    return at + size
'''.replace('MAGIC',str(MAGIC))

# These two reviewed fixed-width buffer helpers retain the exact existing HIA ELF
# linker's author AST. No old high-level packing function is used as a callback.
_tree=ast.parse(LINK_SOURCE)
_helpers=[n for n in _tree.body if isinstance(n,ast.FunctionDef) and n.name in ('uint','write')]
assert {n.name for n in _helpers}=={'uint','write'}
SOURCE+='\n'+'\n\n'.join(ast.unparse(n) for n in _helpers)+'\n'

class PackerBuilder(Builder):
    def expr(self,node):
        if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id=='copy_exact':
            assert not node.keywords and len(node.args)==5
            a=[self.expr(v) for v in node.args]
            return self.op('buffer.copy_range',a[:2]+[self.cast(v,'usize') for v in a[2:]])
        return super().expr(node)

def document():
    nodes=ast.parse(SOURCE).body;names={n.name:'f'+str(i) for i,n in enumerate(nodes)}
    signatures={n.name:([a.annotation.id for a in n.args.args],n.returns.id) for n in nodes}
    total=total_scalar_functions(nodes);functions=[]
    for node in nodes:
        b=PackerBuilder(node,names,signatures,total);b.statements(node.body)
        functions.append({'name':names[node.name],'params':[b.param(x) for x in b.params],'returns':[b.returns],'effects':['read','write','trap'],'entry':'b0','blocks':b.blocks})
    return compact_authoring_cfg({'schema':'hepta.hia.program.v8','module':'linux_stdio_entry_packer','functions':functions})

def frame(image):
    assert type(image)is bytes
    return struct.pack('<QQQQ',MAGIC,1,len(image),0)+image

def generated():
 return render_assembly(document())
def main():
 import argparse
 parser=argparse.ArgumentParser(description='Generate the HIA Linux stdio ELF entry packer')
 parser.add_argument('--check',action='store_true');args=parser.parse_args()
 target=ROOT/'examples/hia_bootstrap/linux_stdio_entry_packer.hepta'
 text=generated()
 if args.check:
  if target.read_text()!=text:raise SystemExit('Linux stdio entry source differs')
 else:target.write_text(text)
 print(json.dumps({'source':str(target.relative_to(ROOT)),'sha256':hashlib.sha256(text.encode()).hexdigest(),'bytes':len(text.encode()),'matching_cold':False,'whole':False},sort_keys=True))
if __name__=='__main__':main()
