"""Author a HIA packer composing the current three native workspace stages.

This is a hosted authoring aid. Runtime JSON policy/materialization, Core
representation and mandatory semantic compilation run in separate HIA images
inside one copied syscall-only ELF filter. General delivery remains OPEN.
"""
import ast
from pathlib import Path
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder,compact_authoring_cfg,total_scalar_functions
from tools.generate_hia_core_workspace_json_cli import WORKSPACE_BYTES
from tools.generate_hia_core_json_cli import source_program as json_packer_source

MAGIC=int.from_bytes(b'HIAWCP01','little')
IMAGE_LIMIT=1<<20
BUNDLE_LIMIT=3*IMAGE_LIMIT+4096
WIRE_LIMIT=8<<20
JSON_OFFSET=WIRE_LIMIT+4096
FRONTEND_OFFSET=JSON_OFFSET+(16<<20)
ARENA_OFFSET=FRONTEND_OFFSET+(16<<20)
FRONTEND_ARENA=(64<<20)+4096
MAPPING_BYTES=ARENA_OFFSET+max(WORKSPACE_BYTES,FRONTEND_ARENA)


def template():
    code=bytearray();labels={};branches=[];holes={}
    def emit(value):code.extend(bytes.fromhex(value))
    def word(value):code.extend(struct.pack('<I',value))
    def label(name):labels[name]=len(code)
    def branch(op,name):emit(op);branches.append((len(code),name));word(0)
    def call(name):emit('e8');holes[name]=len(code);word(0)
    def pointer(op,offset):emit(op);word(offset)
    def clear(size):
        pointer('49 8d bc 24',ARENA_OFFSET)
        emit('31 c0 b9');word(size);emit('fc f3 aa')
    def refuse(value,label_name):
        emit('3d');word(value);branch('0f 84',label_name)
    def length_check(maximum):
        emit('85 c0');branch('0f 84','invalid')
        emit('3d');word(maximum);branch('0f 87','invalid')
        emit('41 89 c5')
    emit('48 83 3c 24 01');branch('0f 85','usage')
    emit('31 ff be');word(MAPPING_BYTES)
    emit('ba 03 00 00 00 41 ba 22 00 00 00 49 c7 c0 ff ff ff ff'
         ' 45 31 c9 b8 09 00 00 00 0f 05 48 3d 01 f0 ff ff')
    branch('0f 83','io');emit('49 89 c4 45 31 ed')
    label('read')
    emit('31 c0 31 ff 4b 8d 34 2c ba');word(WIRE_LIMIT+1)
    emit('4c 29 ea 0f 05 48 83 f8 fc');branch('0f 84','read')
    emit('48 85 c0');branch('0f 88','io');branch('0f 84','workspace')
    emit('49 01 c5 49 81 fd');word(WIRE_LIMIT);branch('0f 87','space');branch('e9','read')
    label('workspace')
    emit('4c 89 e7 4c 89 ee');pointer('49 8d 94 24',JSON_OFFSET)
    emit('b9');word(16<<20);pointer('4d 8d 84 24',ARENA_OFFSET)
    emit('41 b9');word(WORKSPACE_BYTES);call('workspace')
    # Workspace duplicate-module (-3) and other policy errors are INVALID,
    # never IO failures. Its linked-JSON overflow has a separate -18 code.
    refuse(0xfffffffe,'space');refuse(0xffffffee,'space');length_check(WIRE_LIMIT)
    # Start the next image with exactly its fresh-arena initialization ABI.
    clear(FRONTEND_ARENA)
    pointer('49 8d bc 24',JSON_OFFSET);emit('4c 89 ee')
    pointer('49 8d 94 24',FRONTEND_OFFSET);emit('b9');word(16<<20)
    pointer('4d 8d 84 24',ARENA_OFFSET);emit('41 b9');word(FRONTEND_ARENA)
    emit('49 c7 40 28');word(1)
    emit('49 c7 40 30');word(1<<20);emit('49 c7 40 38');word(128)
    call('frontend')
    for value in (0xfffffffe,0xfffffffd,0xfffffffa):refuse(value,'space')
    length_check(IMAGE_LIMIT)
    clear(IMAGE_LIMIT)
    pointer('49 8d bc 24',FRONTEND_OFFSET);emit('4c 89 ee 4c 89 e2 b9');word(IMAGE_LIMIT)
    pointer('4d 8d 84 24',ARENA_OFFSET);emit('41 b9');word(IMAGE_LIMIT);call('compiler')
    refuse(0xfffffffe,'space');emit('3d');word(IMAGE_LIMIT);branch('0f 87','invalid')
    emit('83 f8 40');branch('0f 82','invalid')
    emit('41 81 3c 24 7f 45 4c 46');branch('0f 85','invalid')
    emit('66 41 83 7c 24 10 01');branch('0f 85','invalid')
    emit('66 41 83 7c 24 12 3e');branch('0f 85','invalid')
    emit('41 89 c6 4d 89 e7')
    label('write');emit('4d 85 f6');branch('0f 84','success')
    emit('b8 01 00 00 00 bf 01 00 00 00 4c 89 fe 4c 89 f2'
         ' 0f 05 48 83 f8 fc');branch('0f 84','write')
    emit('48 85 c0');branch('0f 8e','io')
    emit('49 01 c7 49 29 c6');branch('e9','write')
    for name,status in (('success',0),('invalid',2),('space',3),('io',4),('usage',64)):
        label(name);emit('bf');word(status);branch('e9','exit')
    label('exit');emit('b8 3c 00 00 00 0f 05 0f 0b')
    for offset,target in branches:struct.pack_into('<i',code,offset,labels[target]-offset-4)
    header=(b'\x7fELF\x02\x01\x01'+bytes(9)
        +struct.pack('<HHIQQQIHHHHHH',2,62,1,0x4000b0,64,0,0,64,56,2,0,0,0)
        +struct.pack('<IIQQQQQQ',1,5,0,0x400000,0x400000,0,0,4096)
        +struct.pack('<IIQQQQQQ',0x6474e551,6,0,0,0,0,0,16))
    assert len(header)==176
    return header+code,{name:176+offset for name,offset in holes.items()}


def source_program():
    prefix,holes=template()
    text=f'''def pack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 40 or length(s) > {BUNDLE_LIMIT} or read_word(s, 0) != {MAGIC}:
        return 4294967295
    workspace = read_word(s, 8)
    frontend = read_word(s, 16)
    compiler = read_word(s, 24)
    profile = read_word(s, 32)
    if workspace == 0 or workspace > 1048576 or frontend == 0 or frontend > 1048576 or compiler == 0 or compiler > 1048576 or profile != 1:
        return 4294967295
    if length(s) != 40 + workspace + frontend + compiler:
        return 4294967295
    size = {len(prefix)} + workspace + frontend + compiler
    if size > {BUNDLE_LIMIT} or length(o) < size:
        return 4294967294
'''
    for offset in range(0,len(prefix),8):
        chunk=prefix[offset:offset+8]
        if len(chunk)==8:text+=f'    put_word(o, {offset}, {int.from_bytes(chunk,"little")})\n'
        else:
            for j,value in enumerate(chunk):text+=f'    store(o, {offset+j}, {value})\n'
    text+=f'''    put_word(o, 96, size)
    put_word(o, 104, size)
    put_four(o, {holes['workspace']}, {len(prefix)-holes['workspace']-4})
    put_four(o, {holes['frontend']}, {len(prefix)-holes['frontend']-4} + workspace)
    put_four(o, {holes['compiler']}, {len(prefix)-holes['compiler']-4} + workspace + frontend)
    i = 40
    while i < length(s):
        store(o, {len(prefix)} + i - 40, byte(s, i))
        i = i + 1
    return size
'''
    helpers=json_packer_source();return text+helpers[helpers.index('\ndef read_word('):]


def document():
    nodes=ast.parse(source_program()).body;names={n.name:'f'+str(i) for i,n in enumerate(nodes)}
    signatures={n.name:([a.annotation.id for a in n.args.args],n.returns.id) for n in nodes}
    total=total_scalar_functions(nodes);functions=[]
    for node in nodes:
        b=Builder(node,names,signatures,total);b.statements(node.body)
        functions.append({'name':names[node.name],'params':[b.param(v) for v in b.params],
            'returns':[b.returns],'effects':['read','write','trap'],'entry':'b0','blocks':b.blocks})
    return compact_authoring_cfg({'schema':'hepta.hia.program.v8','module':'core_workspace_pipeline_packer','functions':functions})


def main():
    target=Path(__file__).resolve().parents[1]/'examples/hia_bootstrap/core_workspace_pipeline_packer.hiaasm'
    target.write_text(render_assembly(document()));print(target.name,target.stat().st_size)


if __name__=='__main__':main()
