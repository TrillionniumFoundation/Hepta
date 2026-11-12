"""Author three complete default DataJSON controller images.

All source-dependent choices execute in HIA. Python composes only fixed literal
tables, removes unreachable functions and invokes the retained exact authoring
toolchain and original verifier. The selected-AgentDataJSON profile is separate.
"""
from __future__ import annotations
import ast,json,sys
from hashlib import sha256
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
REFERENCE=ROOT.parent/'Hepta-agent-edit-native'
sys.path.insert(0,str(REFERENCE))
from hepta.hia_program import verify_program
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import compact_authoring_cfg,total_scalar_functions
from tools.hia_agent_edit_source_views import CopyBuilder
import agent_default_json_common as common
import agent_default_json_lexical as lexical
import agent_default_json_errors as errors
import agent_default_json_services as services
import agent_default_json_late as late
ROLES={1:('default_json_raw',lexical.LEXICAL),
       2:('default_json_services',services.SERVICES),
       3:('default_json_late',late.LATE)}
INTRINSICS={'byte','length','store','copy_bytes','fill_range','choose'}

def table_functions(prefix,values):
    output=[];ordered=sorted(values.items())
    output.append('def '+prefix+'_size(identifier:u64) -> u64:\n'+''.join(
        '    if identifier == '+str(k)+':\n        return '+str(len(v))+'\n' for k,v in ordered)
        +'    return 18446744073709551615\n')
    groups=[ordered[i:i+6] for i in range(0,len(ordered),6)]
    for index,group in enumerate(groups):
        lines=['def '+prefix+'_word_'+str(index)+'(identifier:u64, part:u64) -> u64:']
        for key,value in group:
            lines.append('    if identifier == '+str(key)+':')
            for offset in range(0,len(value),8):
                word=int.from_bytes(value[offset:offset+8],'little')
                lines.extend(['        if part == '+str(offset//8)+':','            return '+str(word)])
            lines.append('        return 0')
        lines.append('    return 0');output.append('\n'.join(lines)+'\n')
    lines=['def '+prefix+'_word(identifier:u64, part:u64) -> u64:']
    for index,group in enumerate(groups):
        lines.extend(['    if identifier <= '+str(group[-1][0])+':',
                      '        return '+prefix+'_word_'+str(index)+'(identifier, part)'])
    lines.append('    return 0');output.append('\n'.join(lines)+'\n')
    return '\n'.join(output)

def source_program(role):
    assert role in ROLES
    functions={}
    for source in (common.COMMON,lexical.LEXICAL,errors.ERRORS,services.SERVICES,late.LATE):
        for node in ast.parse(source).body:
            assert isinstance(node,ast.FunctionDef)
            if node.name=='gc_step':continue
            assert node.name not in functions,node.name
            functions[node.name]=node
    for node in ast.parse(ROLES[role][1]).body:
        if node.name=='gc_step':functions['gc_step']=node
    literals=table_functions('gc_literal',{k:v.encode('utf-8') for k,v in errors.LITERALS.items()})
    for node in ast.parse(literals).body:
        assert node.name not in functions
        functions[node.name]=node
    reached=set();pending=['gc_entry']
    while pending:
        name=pending.pop()
        if name in reached:continue
        reached.add(name)
        for node in ast.walk(functions[name]):
            if isinstance(node,ast.Call):
                assert isinstance(node.func,ast.Name),ast.dump(node)
                target=node.func.id
                if target in functions:pending.append(target)
                else:assert target in INTRINSICS,(name,target)
    selected=[functions['gc_entry']]+[node for name,node in functions.items()
        if name!='gc_entry' and name in reached]
    class Expand(ast.NodeTransformer):
        def visit_Name(self,node):
            if node.id in common.CONSTANTS:
                return ast.copy_location(ast.Constant(common.CONSTANTS[node.id]),node)
            return node
    return ast.unparse(ast.fix_missing_locations(Expand().visit(
        ast.Module(body=selected,type_ignores=[]))))+'\n'

def document(role):
    nodes=ast.parse(source_program(role)).body
    names={node.name:'f'+str(i+1) for i,node in enumerate(nodes)}
    signatures={node.name:([a.annotation.id for a in node.args.args],node.returns.id) for node in nodes}
    total=total_scalar_functions(nodes)
    params=[dict(name='v0',type='readbuf'),dict(name='v1',type='mutbuf'),dict(name='v2',type='mutbuf')]
    functions=[dict(name='f0',params=params,returns=['u32'],effects=['read','write','trap'],entry='b0',
        blocks=[dict(id='b0',params=params,ops=[
            dict(op='borrow.read',args=['v1'],out=[dict(name='v3',type='readbuf')],attrs={}),
            dict(op='const',args=[],out=[dict(name='v4',type='u64')],attrs=dict(value=role)),
            dict(op='call',args=['v0','v3','v2','v4'],out=[dict(name='v5',type='u32')],attrs=dict(function=names['gc_entry'])),
            dict(op='loan.end',args=['v3'],out=[],attrs={})],term=dict(op='ret',values=['v5']))])]
    for node in nodes:
        builder=CopyBuilder(node,names,signatures,total);builder.statements(node.body)
        functions.append(dict(name=names[node.name],params=[builder.param(v) for v in builder.params],
            returns=[builder.returns],effects=['read','write','trap'],entry='b0',blocks=builder.blocks))
    value=compact_authoring_cfg(dict(schema='hepta.hia.program.v8',
        module='agent_'+ROLES[role][0],functions=functions))
    fs=value['functions']
    counts=(len(fs),sum(len(f['blocks']) for f in fs),
        sum(len(b['ops']) for f in fs for b in f['blocks']),
        max(len(f['blocks']) for f in fs),max(len(b['params']) for f in fs for b in f['blocks']))
    assert all(actual<=limit for actual,limit in zip(counts,(128,1536,8192,256,16))),counts
    verify_program(value)
    return value

if __name__=='__main__':
    for role,(name,_) in ROLES.items():
        value=document(role);raw=render_assembly(value).encode()
        target=ROOT/'examples/hia_bootstrap'/(name+'.hiaasm')
        target.parent.mkdir(parents=True,exist_ok=True)
        assert not target.exists(),'new output revision required'
        target.write_bytes(raw)
        fs=value['functions']
        print(json.dumps(dict(role=role,name=name,path=str(target),bytes=len(raw),
            sha256=sha256(raw).hexdigest(),functions=len(fs),
            blocks=sum(len(f['blocks']) for f in fs),
            instructions=sum(len(b['ops']) for f in fs for b in f['blocks']),
            max_function_blocks=max(len(f['blocks']) for f in fs),
            max_block_parameters=max(len(b['params']) for f in fs for b in f['blocks']),
            scope='DEFAULT_DATAJSON_CONTROLLER_AUTHORING_NOT_YET_EXECUTED'),sort_keys=True),flush=True)
