# Independent complete program admission packer, adapted from frozen ordinary authoring SHA 27f25239c548a3b634882f8c89ac9cfcab5a457365e7197ac257110ee301605f.
"""Author the HIA packer for the fixed complete composite native executable.

The fixed syscall template has no JSON parser, type materializer, operation
planner or language checker. HIA emits every ELF header, exact role address,
policy field and complete compiled image. The native executable needs no
Python, shell, dynamic loader, source files, manifests or external executable.
"""
import ast
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import sys

ROOT=Path(__file__).resolve().parents[1]
BASE=Path(os.environ.get('HIA_BASELINE_ROOT',str(ROOT.parent/'Hepta-v66-restored')))
sys.path[:0]=[str(ROOT),str(BASE)]
from hepta.hia_agent_assembly import render_assembly
ORDINARY=ROOT.parent/'native-composite-driver-reconstructed'
sys.path.insert(1,str(ORDINARY))
from tools.generate_hia_selfhost import Builder,compact_authoring_cfg,total_scalar_functions
from tools.generate_hia_elf_linker import SOURCE as LINK_SOURCE

MAGIC=int.from_bytes(b'HIAEPX01','little')
ROLES=tuple(range(1,29))+tuple(range(40,47))+(56,)
MAX_IMAGE=1<<20
MAX_PACKAGE=64+len(ROLES)*24+len(ROLES)*MAX_IMAGE


def template():
    directory=ROOT/'tools'
    meta=json.loads((directory/'edit_native_executor_layout.json').read_text())
    binary=(directory/'edit_native_executor.bin').read_bytes()
    assert sha256(binary).hexdigest()==meta['template_sha256'] and len(binary)==meta['template_bytes']
    assert sha256((directory/'edit_native_executor.S').read_bytes()).hexdigest()==meta['source_sha256']
    assert meta['relocation_count']==0 and meta['entry']==0 and meta['end']==len(binary)
    assert binary[meta['image_table']:meta['image_table']+512]==bytes(512)
    assert struct.unpack_from('<2Q',binary,meta['policy'])==(4,4300)
    header=(b'\x7fELF\x02\x01\x01'+bytes(9)+struct.pack('<HHIQQQIHHHHHH',2,62,1,0x4000b0,64,0,0,64,56,2,0,0,0)
        +struct.pack('<IIQQQQQQ',1,5,0,0x400000,0x400000,0,0,4096)
        +struct.pack('<IIQQQQQQ',0x6474e551,6,0,0,0,0,0,16))
    assert len(header)==176
    return header+binary,176+meta['image_table'],176+meta['policy']


def source_program(roles=ROLES):
    prefix,table,policy=template();count=len(roles);start=64+count*24
    assert len(set(roles)) == count and tuple(sorted(roles)) == tuple(roles) and all(1 <= r <= 63 for r in roles)
    maximum_package=64+count*(24+MAX_IMAGE)
    source=f'''def pack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < {start} or length(s) > {maximum_package}:
        return 4294967295
    if uint(s, 0, 8) != {MAGIC} or uint(s, 8, 8) != {count}:
        return 4294967295
    if uint(s, 16, 8) != 4 or uint(s, 32, 8) != length(s):
        return 4294967295
    digits = uint(s, 24, 8)
    if digits != 0 and digits < 640:
        return 4294967295
    if uint(s, 40, 8) != 0 or uint(s, 48, 8) != 0 or uint(s, 56, 8) != 0:
        return 4294967295
    input_at = {start}
    output_at = {len(prefix)}
    index = 0
    previous = 0
    while index < {count}:
        row = 64 + index * 24
        role = uint(s, row, 8)
        if role <= previous or role > 63:
            return 4294967295
        if (({sum(1 << r for r in roles)} >> role) & 1) == 0 or uint(s, row + 16, 8) != 0:
            return 4294967295
        size = uint(s, row + 8, 8)
        if size == 0 or size > {MAX_IMAGE} or size > length(s) - input_at:
            return 4294967295
        previous = role
        input_at = input_at + size
        output_at = ((output_at + 15) & 18446744073709551600) + size
        index = index + 1
    if input_at != length(s):
        return 4294967295
    if length(o) < output_at:
        return 4294967294
    size = output_at
'''
    for n,at in enumerate(range(0,len(prefix),256)):source+=f'    literal_{n}(o)\n'
    source+=f'''    write(o, 96, size, 8)
    write(o, 104, size, 8)
    write(o, {policy}, uint(s, 16, 8), 8)
    write(o, {policy+8}, digits, 8)
    input_at = {start}
    output_at = {len(prefix)}
    index = 0
    while index < {count}:
        aligned = (output_at + 15) & 18446744073709551600
        while output_at < aligned:
            store(o, output_at, 0)
            output_at = output_at + 1
        row = 64 + index * 24
        role = uint(s, row, 8)
        extent = uint(s, row + 8, 8)
        write(o, {table} + role * 8, 4194304 + output_at, 8)
        copy_bytes(s, o, input_at, output_at, extent)
        input_at = input_at + extent
        output_at = output_at + extent
        index = index + 1
    return size
'''
    for n,at in enumerate(range(0,len(prefix),256)):
        source+=f'\ndef literal_{n}(o:mutbuf) -> u64:\n'
        for offset in range(at,min(at+256,len(prefix)),8):
            raw=prefix[offset:min(offset+8,at+256,len(prefix))]
            source+=f'    write(o, {offset}, {int.from_bytes(raw,"little")}, {len(raw)})\n'
        source+='    return 0\n'
    return source+LINK_SOURCE[LINK_SOURCE.index('\ndef uint('):]


def document(roles=ROLES):
    nodes=ast.parse(source_program(roles)).body;names={n.name:'f'+str(i) for i,n in enumerate(nodes)}
    sigs={n.name:([a.annotation.id for a in n.args.args],n.returns.id) for n in nodes}
    total=total_scalar_functions(nodes);functions=[]
    for n in nodes:
        builder=Builder(n,names,sigs,total);builder.statements(n.body)
        functions.append({'name':names[n.name],'params':[builder.param(p) for p in builder.params],
            'returns':[builder.returns],'effects':['read','write','trap'],'entry':'b0','blocks':builder.blocks})
    return compact_authoring_cfg({'schema':'hepta.hia.program.v8','module':'edit_cli_packer','functions':functions})


if __name__=='__main__':
    path=ROOT/'examples/hia_bootstrap/edit_cli_packer.hiaasm'
    path.write_text(render_assembly(document()));print(path.name,path.stat().st_size)
