"""Author the complete native HIA durable MCP call bridge and its ELF packer.

Python is an authoring tool only. The shipped image executes the checked-in HIA
policies, immutable existing companions and a fixed Linux syscall adapter.
"""
from __future__ import annotations
import argparse
import ast
import importlib
import struct
import subprocess
import tempfile
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_direct_load_plan import LinkerBuilder
from tools.generate_hia_selfhost import compact_authoring_cfg, total_scalar_functions
from tools.generate_hia_json_decode import source_program as generic_json
from tools.generate_hia_native_filter import LINK_SOURCE

ROOT=Path(__file__).resolve().parents[1]
COMPONENTS=('bootstrap','provider','registry','process','transport','result','fence','files','audit','status','pages','replay')
ROLES=COMPONENTS+('json','sha','terminal','canonical')
SOURCE_FILES=tuple('examples/hia_bootstrap/mcp_job_bridge_'+name+'.hepta' for name in COMPONENTS+('json','packer'))
COMPANIONS={'sha':'examples/hia_bootstrap/sha256_stream.hepta',
            'terminal':'examples/hia_bootstrap/job_terminal_receipt.hepta',
            'canonical':'examples/hia_bootstrap/mcp_canonical.hepta'}
PACKER_MAGIC=b'HIAJBP01'


class BridgeBuilder(LinkerBuilder):
    def expr(self,node):
        if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id=='word_store':
            args=[self.expr(value) for value in node.args]
            return self.op('buffer.store.u64.le',[args[0],self.cast(args[1],'usize'),self.cast(args[2],'u64')])
        return super().expr(node)


def document(source,module):
    nodes=ast.parse(source).body
    names={node.name:'f'+str(i) for i,node in enumerate(nodes)}
    signatures={node.name:([a.annotation.id for a in node.args.args],node.returns.id) for node in nodes}
    total=total_scalar_functions(nodes);functions=[]
    for node in nodes:
        builder=BridgeBuilder(node,names,signatures,total);builder.statements(node.body)
        functions.append({'name':names[node.name],'params':[builder.param(a) for a in builder.params],
                          'returns':[builder.returns],'effects':['read','write','trap'],
                          'entry':'b0','blocks':builder.blocks})
    return compact_authoring_cfg({'schema':'hepta.hia.program.v9','module':module,'functions':functions})


def json_source():
    # serde_json::Value is last-key-wins. Typed registry/config structures
    # retain their explicit known-field duplicate checks in HIA policy.
    source=generic_json(wire_spans=True)
    old='''            if same_key(s, item & 4294967295, start) == 1:
                return 4'''
    if source.count(old)!=1:raise ValueError('JSON duplicate-key admission changed')
    return source.replace(old,old.replace('return 4','return 0'))


def template():
    with tempfile.TemporaryDirectory(prefix='hia-mcp-job-bridge-author-') as temp:
        obj=Path(temp)/'adapter.o';raw=Path(temp)/'adapter.bin'
        subprocess.run(['as','--64',str(ROOT/'tools/hia_mcp_job_bridge_syscalls.S'),'-o',str(obj)],check=True,capture_output=True)
        subprocess.run(['objcopy','-O','binary','-j','.text',str(obj),str(raw)],check=True,capture_output=True)
        symbols={name:int(address,16) for address,_,name in
                 (line.split() for line in subprocess.check_output(['nm','-n',str(obj)],text=True).splitlines())}
        if symbols['_start']!=0 or 'R_X86_64' in subprocess.check_output(['objdump','-r',str(obj)],text=True):
            raise ValueError('MCP bridge adapter has unresolved relocations')
        code=raw.read_bytes()
    header=(b'\x7fELF\x02\x01\x01'+bytes(9)
            +struct.pack('<HHIQQQIHHHHHH',2,62,1,0x4000b0,64,0,0,64,56,2,0,0,0)
            +struct.pack('<IIQQQQQQ',1,5,0,0x400000,0x400000,0,0,4096)
            +struct.pack('<IIQQQQQQ',0x6474e551,6,0,0,0,0,0,16))
    return header+code,{name:176+symbols['mcp_job_bridge_'+name+'_hole'] for name in ROLES}


def packer_source():
    prefix,holes=template();head=8+8*len(ROLES)
    code=f'''def pack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < {head+len(ROLES)} or uint(s, 0, 8) != {int.from_bytes(PACKER_MAGIC,'little')}:
        return 4294967295
    size = {len(prefix)}
'''
    code+=f'''    index = 0
    while index < {len(ROLES)}:
        part = uint(s, 8 + index * 8, 8)
        if part == 0 or part > 1048576:
            return 4294967295
        size = size + part
        index = index + 1
'''
    code+=f'''    if length(s) != size - {len(prefix)} + {head}:
        return 4294967295
    if size > 8388608 or length(o) < size:
        return 4294967294
'''
    prefix_helpers=''
    for bank,start in enumerate(range(0,len(prefix),512)):
        code+=f'    prefix_{bank}(o)\n'
        prefix_helpers+=f'\ndef prefix_{bank}(o:mutbuf) -> u64:\n'
        for at in range(start,min(start+512,len(prefix)),8):
            chunk=prefix[at:at+8]
            prefix_helpers+=f'    write(o, {at}, {int.from_bytes(chunk,"little")}, {len(chunk)})\n'
        prefix_helpers+='    return 0\n'
    code+='    write(o, 96, size, 8)\n    write(o, 104, size, 8)\n'
    code+=f'    target = {len(prefix)}\n'
    for i,name in enumerate(ROLES):
        at=holes[name]
        code+=f'    write(o, {at}, target - {at+4}, 4)\n'
        code+=f'    target = target + uint(s, {8+i*8}, 8)\n'
    code+=f'    copy_bytes(s, o, {head}, {len(prefix)}, size - {len(prefix)})\n    return size\n'
    return code+prefix_helpers+LINK_SOURCE[LINK_SOURCE.index('\ndef uint('):]


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--check',action='store_true');args=parser.parse_args()
    sources=[]
    for name in COMPONENTS:
        module=importlib.import_module('tools.generate_hia_mcp_job_bridge_'+name)
        sources.append((name,module.source()))
    sources.extend((('json',json_source()),('packer',packer_source())))
    for name,source in sources:
        path=ROOT/'examples/hia_bootstrap'/('mcp_job_bridge_'+name+'.hepta')
        rendered=render_assembly(document(source,'mcp_job_bridge_'+name))
        if args.check:
            if path.read_text()!=rendered:raise SystemExit('generated source differs: '+str(path))
        else:path.write_text(rendered)
        print(name,len(rendered),flush=True)

if __name__=='__main__':main()
