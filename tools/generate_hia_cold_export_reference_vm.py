"""Full existing reference VM with the original linked-packer 30M budget.

Only two packet step-limit admission constants differ. Instruction execution,
step charging, resource semantics, arenas and syscall adapter are unchanged.
The original owned_reference source and its 10M profile remain untouched.
"""
from pathlib import Path
import ast
from hepta.hia_agent_assembly import render_assembly
from hepta.hia_native_byte_abi import MAX_EXTENT, MAX_RANGES
from hepta.hia_program_runtime import CHAIN_NODE_BYTES
from hepta.hia_scalar_reference_wire import RESOURCE_CODES
from tools import generate_hia_owned_reference as owned
from tools import generate_hia_scalar_reference as scalar
from tools.generate_hia_selfhost import compact_authoring_cfg,total_scalar_functions
ROOT=Path(__file__).resolve().parents[1]

def document():
    prefix=owned.SOURCE
    for key,value in {'CHAIN_NODE_BYTES':CHAIN_NODE_BYTES,'MAX_RANGES':MAX_RANGES,'MAX_EXTENT':MAX_EXTENT,'MAX_EXTERNAL_BYTES':MAX_EXTENT*MAX_RANGES}.items():
        prefix=prefix.replace('@'+key+'@',str(value))
    for key,value in RESOURCE_CODES.items():prefix=prefix.replace('@r.'+key+'@',str(value))
    old='if steps == 0 or steps > 10000000 or depth == 0 or depth > 256:'
    assert prefix.count(old)==1
    prefix=prefix.replace(old,old.replace('10000000','30000000'))
    main=scalar.SOURCE
    old='if uint(s, 8, 8) == 0 or uint(s, 8, 8) > 10000000:'
    assert main.count(old)==1
    main=main.replace(old,old.replace('10000000','30000000'))
    constants={name:getattr(scalar,name) for name in ('MAGIC','BYTE_MAGIC','ALLOCATION_MAGIC','DOMAIN_MAGIC','OBSERVATION_MAGIC','LOAN_MAGIC','CHAIN_MAGIC','OWNER_MAGIC','STORAGE_MAGIC','OWNER_RECORD_BYTES','ARENA_BYTES_MAGIC','RESULT','PROGRAM_MAGIC','RESOURCE_PROGRAM_MAGIC','PROGRAM_RESULT','MAX_FRAME_WORDS','MAX_PACKET_BYTES','RETURN_LOANS_CODE')}
    constants.update(RESOURCE_KINDS=len(scalar.RESOURCE_KINDS),**scalar.OPCODES)
    source=(prefix+main).replace('@RESOURCE_SIGNATURES@',scalar.resource_signatures())
    for name,value in constants.items():source=source.replace('@'+name+'@',str(value))
    source+='\ndef within('+scalar.STATIC_SOURCE.split('\ndef within(',1)[1]
    nodes=ast.parse(source).body
    names={node.name:'f'+str(i) for i,node in enumerate(nodes)}
    signatures={node.name:([arg.annotation.id for arg in node.args.args],node.returns.id) for node in nodes}
    total=total_scalar_functions(nodes);functions=[]
    for node in nodes:
        builder=scalar.ReferenceBuilder(node,names,signatures,total);builder.statements(node.body)
        functions.append({'name':names[node.name],'params':[builder.param(p) for p in builder.params],'returns':[builder.returns],'effects':['read','write','trap'],'entry':'b0','blocks':builder.blocks})
    return compact_authoring_cfg({'schema':'hepta.hia.program.v9','module':'cold_export_reference_vm','functions':functions})

def main():
    p=ROOT/'examples/hia_bootstrap/cold_export_reference_vm.hepta';p.write_text(render_assembly(document()));print(p.name,p.stat().st_size)
if __name__=='__main__':main()
