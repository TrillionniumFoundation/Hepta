"""Author a HIA packer for one native borrowed-buffer application.

The syscall template has no payload parser or linker logic. Actual ELF emission,
call displacement and image copying are performed by the checked-in HIA packer.
"""
from __future__ import annotations
import ast
from pathlib import Path
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder,compact_authoring_cfg,total_scalar_functions
from tools.generate_hia_elf_linker import SOURCE as LINK_SOURCE
MAGIC=int.from_bytes(b'HIAFLT01','little')
WIRE_BYTES=8<<20
OUTPUT_OFFSET=WIRE_BYTES+4096
OUTPUT_BYTES=8<<20
WORKSPACE_OFFSET=OUTPUT_OFFSET+OUTPUT_BYTES
WORKSPACE_BYTES=16<<20
MAPPING_BYTES=WORKSPACE_OFFSET+WORKSPACE_BYTES


def template(*, output_bytes=OUTPUT_BYTES, workspace_bytes=WORKSPACE_BYTES):
    workspace_offset=OUTPUT_OFFSET+output_bytes
    mapping_bytes=workspace_offset+workspace_bytes
    code=bytearray();labels={};branches=[]
    def emit(value):code.extend(bytes.fromhex(value))
    def word(value):code.extend(struct.pack('<I',value))
    def label(name):labels[name]=len(code)
    def branch(op,name):emit(op);branches.append((len(code),name));word(0)
    emit('48 83 3c 24 01');branch('0f 85','usage')
    emit('31 ff be');word(mapping_bytes)
    emit('ba 03 00 00 00 41 ba 22 00 00 00 49 c7 c0 ff ff ff ff 45 31 c9 b8 09 00 00 00 0f 05 48 3d 01 f0 ff ff');branch('0f 83','io')
    emit('49 89 c4 45 31 ed');label('read')
    emit('31 c0 31 ff 4b 8d 34 2c ba');word(WIRE_BYTES+1)
    emit('4c 29 ea 0f 05 48 83 f8 fc');branch('0f 84','read')
    emit('48 85 c0');branch('0f 88','io');branch('0f 84','invoke')
    emit('49 01 c5 49 81 fd');word(WIRE_BYTES);branch('0f 87','space');branch('e9','read')
    label('invoke')
    emit('4c 89 e7 4c 89 ee 49 8d 94 24');word(OUTPUT_OFFSET)
    emit('b9');word(output_bytes)
    emit('4d 8d 84 24');word(workspace_offset)
    emit('41 b9');word(workspace_bytes)
    emit('e8');hole=len(code);word(0)
    emit('83 f8 fe');branch('0f 84','space')
    emit('3d');word(output_bytes);branch('0f 87','invalid')
    emit('41 89 c6 4d 8d bc 24');word(OUTPUT_OFFSET)
    label('write');emit('4d 85 f6');branch('0f 84','success')
    emit('b8 01 00 00 00 bf 01 00 00 00 4c 89 fe 4c 89 f2 0f 05 48 83 f8 fc');branch('0f 84','write')
    emit('48 85 c0');branch('0f 8e','io')
    emit('49 01 c7 49 29 c6');branch('e9','write')
    for name,status in (('success',0),('invalid',2),('space',3),('io',4),('usage',64)):
        label(name);emit('bf');word(status);branch('e9','exit')
    label('exit');emit('b8 3c 00 00 00 0f 05 0f 0b')
    for at,name in branches:struct.pack_into('<i',code,at,labels[name]-at-4)
    head=(b'\x7fELF\x02\x01\x01'+bytes(9)+struct.pack('<HHIQQQIHHHHHH',2,62,1,0x4000b0,64,0,0,64,56,2,0,0,0)
        +struct.pack('<IIQQQQQQ',1,5,0,0x400000,0x400000,0,0,4096)
        +struct.pack('<IIQQQQQQ',0x6474e551,6,0,0,0,0,0,16))
    assert len(head)==176
    return head+code,176+hole


def source_program(*, output_bytes=OUTPUT_BYTES, workspace_bytes=WORKSPACE_BYTES, magic=MAGIC):
    prefix,hole=template(output_bytes=output_bytes,workspace_bytes=workspace_bytes)
    text=f'''def pack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 17 or length(s) > 1048576:
        return 4294967295
    if uint(s, 0, 8) != {magic}:
        return 4294967295
    image = uint(s, 8, 8)
    if image != length(s) - 16:
        return 4294967295
    size = {len(prefix)} + image
    if size > 1048576 or length(o) < size:
        return 4294967294
'''
    for at in range(0,len(prefix),8):
        chunk=prefix[at:at+8];text+=f'    write(o, {at}, {int.from_bytes(chunk,"little")}, {len(chunk)})\n'
    text+=f'''    write(o, 96, size, 8)
    write(o, 104, size, 8)
    write(o, {hole}, {len(prefix)-hole-4}, 4)
    copy_bytes(s, o, 16, {len(prefix)}, image)
    return size
'''
    # Exact ordinary Core helper bodies, never a host-side payload copier.
    text+=LINK_SOURCE[LINK_SOURCE.index('\ndef uint('):]
    return text


def document(*, output_bytes=OUTPUT_BYTES, workspace_bytes=WORKSPACE_BYTES, magic=MAGIC, module='native_filter_packer'):
    nodes=ast.parse(source_program(output_bytes=output_bytes,workspace_bytes=workspace_bytes,magic=magic)).body
    names={n.name:'f'+str(i) for i,n in enumerate(nodes)}
    sigs={n.name:([a.annotation.id for a in n.args.args],n.returns.id) for n in nodes}
    fns=[]
    for n in nodes:
        b=Builder(n,names,sigs,total_scalar_functions(nodes));b.statements(n.body)
        fns.append({'name':names[n.name],'params':[b.param(p) for p in b.params],'returns':[b.returns],
                    'effects':['read','write','trap'],'entry':'b0','blocks':b.blocks})
    return compact_authoring_cfg({'schema':'hepta.hia.program.v8','module':module,'functions':fns})


def main():
    p=Path(__file__).resolve().parents[1]/'examples/hia_bootstrap/native_filter_packer.hepta'
    p.write_text(render_assembly(document()));print(p.name,p.stat().st_size)
if __name__=='__main__':main()
