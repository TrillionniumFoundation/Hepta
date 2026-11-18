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
from tools.generate_hia_elf_linker import MAGIC as LINK_WIRE_MAGIC, SOURCE as LINK_SOURCE
MAGIC=int.from_bytes(b'HIAFLT01','little')
LINK_FILTER_MAGIC = int.from_bytes(b'HIAELF01', 'little')
WIRE_BYTES=8<<20
OUTPUT_OFFSET=WIRE_BYTES+4096
OUTPUT_BYTES=8<<20
WORKSPACE_OFFSET=OUTPUT_OFFSET+OUTPUT_BYTES
WORKSPACE_BYTES=16<<20
MAPPING_BYTES=WORKSPACE_OFFSET+WORKSPACE_BYTES
CORE_REPORT_MODE = int.from_bytes(b'HIACRPT1', 'little')


def template(*, output_bytes=OUTPUT_BYTES, workspace_bytes=WORKSPACE_BYTES,
             formatter=False, suite=False, object_files=False):
    workspace_offset=OUTPUT_OFFSET+output_bytes
    mapping_bytes=workspace_offset+workspace_bytes
    code=bytearray();labels={};branches=[]
    def emit(value):code.extend(bytes.fromhex(value))
    def word(value):code.extend(struct.pack('<I',value))
    def label(name):labels[name]=len(code)
    def branch(op,name):emit(op);branches.append((len(code),name));word(0)
    def call_image(*, argument=False):
        if argument:
            emit('48 8b 7c 24 10 48 89 de')  # argv[1] and its observed extent
        else:
            emit('4c 89 e7 4c 89 ee')
        emit('49 8d 94 24');word(OUTPUT_OFFSET)
        emit('b9');word(output_bytes)
        emit('4d 8d 84 24');word(workspace_offset)
        emit('41 b9');word(workspace_bytes)
        emit('e8');offset=len(code);word(0)
        return offset
    emit('48 83 3c 24');emit('02' if suite else '01')
    if suite:
        branch('0f 84','map')
        emit('48 83 3c 24 03')
    if object_files:
        branch('0f 84','map')
        emit('48 83 3c 24 03');branch('0f 82','usage')
        emit('48 83 3c 24 42');branch('0f 87','usage')
    else:
        branch('0f 85','usage')
    label('map')
    emit('31 ff be');word(mapping_bytes)
    emit('ba 03 00 00 00 41 ba 22 00 00 00 49 c7 c0 ff ff ff ff 45 31 c9 b8 09 00 00 00 0f 05 48 3d 01 f0 ff ff');branch('0f 83','io')
    calls = []
    emit('49 89 c4 45 31 ed')
    if suite:
        emit('48 8b 7c 24 10 31 db')
        label('argument')
        emit('83 fb 10');branch('0f 83','usage')
        emit('80 3c 1f 00');branch('0f 84','dispatch')
        emit('48 ff c3');branch('e9','argument')
        label('dispatch')
        calls.append(call_image(argument=True))
        emit('83 f8 01');branch('0f 82','usage')
        emit('83 f8 04');branch('0f 87','usage')
        emit('89 c3')  # Admitted mode remains in the callee-saved register.
        emit('45 31 ff 48 83 3c 24 02');branch('0f 84','read')
        label('open_input')
        # openat(AT_FDCWD, argv[2], O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC)
        emit('b8 01 01 00 00 bf 9c ff ff ff 48 8b 74 24 18 ba 00 08 0a 00 45 31 d2 0f 05')
        emit('48 83 f8 fc');branch('0f 84','open_input')
        emit('48 85 c0');branch('0f 88','io')
        emit('41 89 c7')  # r15d = opened descriptor (possibly zero).
        label('stat_input')
        # fstat(fd, input mapping); only st_mode and st_size are needed.
        emit('b8 05 00 00 00 44 89 ff 4c 89 e6 0f 05')
        emit('48 83 f8 fc');branch('0f 84','stat_input')
        emit('48 85 c0');branch('0f 88','io')
        emit('41 8b 44 24 18 25 00 f0 00 00 3d 00 80 00 00');branch('0f 85','io')
        emit('49 81 7c 24 30');word(WIRE_BYTES);branch('0f 87','space')
    if object_files:
        emit('48 83 3c 24 01');branch('0f 84','read')
        # Capture the argument extents and construct HIALNK01 for the existing
        # HIA linker. Only that linker admits object headers, symbols and code.
        emit('48 b8');code.extend(struct.pack('<Q', LINK_WIRE_MAGIC))
        emit('49 89 04 24 48 8b 04 24 48 83 e8 02 49 89 44 24 08')
        emit('48 8b 74 24 10')  # argv[1], entry.
        label('entry_byte')
        emit('42 80 3c 2e 00');branch('0f 84','entry_end')
        emit('49 81 fd 00 10 00 00');branch('0f 83','usage')
        emit('49 ff c5');branch('e9','entry_byte')
        label('entry_end')
        emit('4d 85 ed');branch('0f 84','usage')
        emit('4d 89 6c 24 10 49 8d 7c 24 20 4c 89 e9 fc f3 a4 49 83 c5 20')
        emit('bb 02 00 00 00')  # rbx: argv index, r13: total frame extent.
        label('next_object')
        emit('48 3b 1c 24');branch('0f 83','invoke')
        emit('49 81 fd');word(WIRE_BYTES - 8);branch('0f 87','space')
        emit('4d 89 ee 49 83 c5 08 48 8b 74 dc 08')  # r14: size word offset.
        label('open_object')
        emit('b8 01 01 00 00 bf 9c ff ff ff ba 00 08 0a 00 45 31 d2 0f 05')
        emit('48 83 f8 fc');branch('0f 84','open_object')
        emit('48 85 c0');branch('0f 88','io')
        emit('41 89 c7')  # r15: descriptor, including zero.
        label('stat_object')
        emit('b8 05 00 00 00 44 89 ff 49 8d b4 24');word(workspace_offset);emit('0f 05')
        emit('48 83 f8 fc');branch('0f 84','stat_object')
        emit('48 85 c0');branch('0f 88','io')
        emit('41 8b 84 24');word(workspace_offset + 24)
        emit('25 00 f0 00 00 3d 00 80 00 00');branch('0f 85','io')
        emit('b8');word(WIRE_BYTES);emit('4c 29 e8 49 3b 84 24');word(workspace_offset + 48)
        branch('0f 82','space')
        label('read_object')
        emit('31 c0 44 89 ff 4b 8d 34 2c ba');word(WIRE_BYTES + 1)
        emit('4c 29 ea 0f 05 48 83 f8 fc');branch('0f 84','read_object')
        emit('48 85 c0');branch('0f 88','io');branch('0f 84','object_end')
        emit('49 01 c5 49 81 fd');word(WIRE_BYTES);branch('0f 87','space')
        branch('e9','read_object')
        label('object_end')
        emit('b8 03 00 00 00 44 89 ff 0f 05 48 85 c0');branch('0f 88','io')
        emit('4c 89 e8 4c 29 f0 48 83 e8 08 4b 89 04 34 48 ff c3')
        branch('e9','next_object')
    label('read')
    emit('31 c0')
    emit('44 89 ff' if suite else '31 ff')
    emit('4b 8d 34 2c ba');word(WIRE_BYTES+1)
    emit('4c 29 ea 0f 05 48 83 f8 fc');branch('0f 84','read')
    emit('48 85 c0');branch('0f 88','io');branch('0f 84','invoke')
    emit('49 01 c5 49 81 fd');word(WIRE_BYTES);branch('0f 87','space');branch('e9','read')
    label('invoke')
    if suite:
        emit('48 83 3c 24 02');branch('0f 84','admit')
        emit('b8 03 00 00 00 44 89 ff 0f 05 48 85 c0');branch('0f 88','io')
        label('admit')
    calls.append(call_image())
    if formatter or suite:
        emit('83 f8 fe');branch('0f 84','space')
        emit('85 c0');branch('0f 85','invalid')
        if suite:
            emit('83 fb 01');branch('0f 84','check_output')
            emit('83 fb 02');branch('0f 85','inspect')
        calls.append(call_image())
        if suite:
            branch('e9','check_output')
            label('inspect')
            emit('83 fb 04');branch('0f 85','render_view')
            emit('48 b8');code.extend(struct.pack('<Q', CORE_REPORT_MODE))
            emit('49 89 84 24');word(workspace_offset+workspace_bytes-8)
            label('render_view')
            calls.append(call_image())
    label('check_output')
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
    return head+code,tuple(176+offset for offset in calls)


def source_program(*, output_bytes=OUTPUT_BYTES, workspace_bytes=WORKSPACE_BYTES,
                   magic=MAGIC, formatter=False, object_files=False):
    prefix,calls=template(output_bytes=output_bytes,workspace_bytes=workspace_bytes,
                          formatter=formatter,object_files=object_files)
    header = 24 if formatter else 16
    minimum = header + len(calls)
    text=f'''def pack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < {minimum} or length(s) > 1048576:
        return 4294967295
    if uint(s, 0, 8) != {magic}:
        return 4294967295
    image = uint(s, 8, 8)
'''
    if formatter:
        text += '''    format_image = uint(s, 16, 8)
    if image == 0 or image >= length(s) - 24 or format_image != length(s) - 24 - image:
        return 4294967295
'''
    else:
        text += '''    if image != length(s) - 16:
        return 4294967295
'''
    payload = 'length(s) - 24' if formatter else 'image'
    text += f'''    size = {len(prefix)} + ({payload})
    if size > 1048576 or length(o) < size:
        return 4294967294
'''
    for at in range(0,len(prefix),8):
        chunk=prefix[at:at+8];text+=f'    write(o, {at}, {int.from_bytes(chunk,"little")}, {len(chunk)})\n'
    text+=f'''    write(o, 96, size, 8)
    write(o, 104, size, 8)
    write(o, {calls[0]}, {len(prefix)-calls[0]-4}, 4)
'''
    if formatter:
        text+=f'    write(o, {calls[1]}, {len(prefix)-calls[1]-4} + image, 4)\n'
    text+=f'''    copy_bytes(s, o, {header}, {len(prefix)}, {payload})
    return size
'''
    # Exact ordinary Core helper bodies, never a host-side payload copier.
    text+=LINK_SOURCE[LINK_SOURCE.index('\ndef uint('):]
    return text


def document(*, output_bytes=OUTPUT_BYTES, workspace_bytes=WORKSPACE_BYTES, magic=MAGIC,
             module='native_filter_packer', formatter=False, object_files=False):
    nodes=ast.parse(source_program(output_bytes=output_bytes,workspace_bytes=workspace_bytes,
                                   magic=magic,formatter=formatter,object_files=object_files)).body
    names={n.name:'f'+str(i) for i,n in enumerate(nodes)}
    sigs={n.name:([a.annotation.id for a in n.args.args],n.returns.id) for n in nodes}
    fns=[]
    for n in nodes:
        b=Builder(n,names,sigs,total_scalar_functions(nodes));b.statements(n.body)
        fns.append({'name':names[n.name],'params':[b.param(p) for p in b.params],'returns':[b.returns],
                    'effects':['read','write','trap'],'entry':'b0','blocks':b.blocks})
    return compact_authoring_cfg({'schema':'hepta.hia.program.v8','module':module,'functions':fns})


def main():
    root=Path(__file__).resolve().parents[1]/'examples/hia_bootstrap'
    for name, source in (
        ('native_filter_packer', document()),
        ('elf_linker_filter_packer', document(magic=LINK_FILTER_MAGIC,
                                             module='elf_linker_filter_packer', object_files=True)),
    ):
        path = root/f'{name}.hepta'
        path.write_text(render_assembly(source))
        print(path.name,path.stat().st_size)
if __name__=='__main__':main()
