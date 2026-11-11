"""Author the complete four-image fixed-catalog schema owner under original limits.

All runtime choices are HIA. Python composes fixed source, prunes only unreachable
functions, expands immutable constants, and invokes the unchanged retained
authoring/verifier. No received schema/value is evaluated by this generator.
"""
from __future__ import annotations
import ast,copy,json,sys
from hashlib import sha256
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
REFERENCE=ROOT.parent/'Hepta-agent-edit-native'
sys.path.insert(0,str(REFERENCE))
from hepta.hia_program import verify_program
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import compact_authoring_cfg,total_scalar_functions
from tools.hia_agent_edit_source_views import CopyBuilder
import agent_schema_common as common
import agent_schema_peers as peers
import agent_schema_numbers as numbers
import agent_schema_scalars as scalars
import agent_schema_logic as logic
import agent_schema_containers as containers
import agent_schema_errors as errors
import agent_schema_patterns as patterns
import graph_wire_frozen_original as graph
ROLES={1:('scalar',scalars.SCALARS),2:('logic',logic.LOGIC),
       3:('containers',containers.CONTAINERS),4:('errors',errors.ERRORS)}
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

MATCH=r'''
def sv_partial_word(g:readbuf, start:u64, size:u64) -> u64:
    result = 0
    index = 0
    while index < size:
        result = result | (byte(g, start + index) << (index * 8))
        index = index + 1
    return result

def sv_named(g:readbuf, w:mutbuf, identifier:u64, key:u64) -> u64:
    at = sv_node(g, w, identifier)
    if at == 0:
        return 0
    if sn_word(g, at) != 4:
        return 0
    size = sv_name_size(key)
    if sn_word(g, at + 16) != size:
        return 0
    start = sn_word(g, at + 8)
    index = 0
    while index < size:
        remaining = size - index
        actual = 0
        if remaining >= 8:
            actual = sn_word(g, start + index)
        else:
            actual = sv_partial_word(g, start + index, remaining)
        if actual != sv_name_word(key, index >> 3):
            return 0
        index = index + choose(remaining >= 8, 8, remaining)
    return 1
'''

def source_program(role):
    assert role in ROLES
    modules=(common.COMMON,peers.PEERS,numbers.NUMBERS,scalars.SCALARS,
             logic.LOGIC,containers.CONTAINERS,errors.ERRORS)
    functions={}
    for source in modules:
        for node in ast.parse(source).body:
            assert isinstance(node,ast.FunctionDef)
            if node.name=='sv_step':continue
            assert node.name not in functions,node.name
            functions[node.name]=node
    for node in ast.parse(ROLES[role][1]).body:
        if node.name=='sv_step':functions['sv_step']=node
    class Rename(ast.NodeTransformer):
        def visit_Name(self,node):
            if node.id in common.GRAPH_RENAMES:
                return ast.copy_location(ast.Name(id=common.GRAPH_RENAMES[node.id],ctx=node.ctx),node)
            return node
        def visit_FunctionDef(self,node):
            self.generic_visit(node);node.name=common.GRAPH_RENAMES.get(node.name,node.name);return node
    originals={node.name:node for node in ast.parse(graph.COMMON).body}
    for name in common.GRAPH_FUNCTIONS:
        node=Rename().visit(copy.deepcopy(originals[name]))
        assert node.name not in functions
        functions[node.name]=node
    name_values={i+1:v.encode('utf-8') for i,v in enumerate(common.KEYWORDS)}
    name_values.update({101+i:v.encode('utf-8') for i,v in enumerate(common.TYPE_NAMES)})
    name_values.update({201+i:v.encode('utf-8') for i,v in enumerate(patterns.PATTERNS)})
    literals=table_functions('sv_name',name_values)+table_functions(
        'sv_text',{k:v.encode('utf-8') for k,v in errors.TEXTS.items()})+MATCH
    for node in ast.parse(literals).body:
        assert node.name not in functions
        functions[node.name]=node
    reached=set();pending=['sv_entry']
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
    selected=[functions['sv_entry']]+[node for name,node in functions.items()
                                       if name!='sv_entry' and name in reached]
    class Expand(ast.NodeTransformer):
        def visit_Name(self,node):
            if node.id in common.CONSTANTS:
                return ast.copy_location(ast.Constant(common.CONSTANTS[node.id]),node)
            return node
    module=ast.Module(body=selected,type_ignores=[])
    return ast.unparse(ast.fix_missing_locations(Expand().visit(module)))+'\n'

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
            dict(op='call',args=['v0','v3','v2','v4'],out=[dict(name='v5',type='u32')],attrs=dict(function=names['sv_entry'])),
            dict(op='loan.end',args=['v3'],out=[],attrs={})],term=dict(op='ret',values=['v5']))])]
    for node in nodes:
        builder=CopyBuilder(node,names,signatures,total);builder.statements(node.body)
        functions.append(dict(name=names[node.name],params=[builder.param(v) for v in builder.params],
            returns=[builder.returns],effects=['read','write','trap'],entry='b0',blocks=builder.blocks))
    value=compact_authoring_cfg(dict(schema='hepta.hia.program.v8',
        module='agent_schema_'+ROLES[role][0],functions=functions))
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
        target=ROOT/'examples/hia_bootstrap'/('agent_schema_'+name+'.hiaasm')
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
            scope='COMPLETE_FIXED_CATALOG_SCHEMA_AUTHORING_NOT_YET_EXECUTED'),sort_keys=True),flush=True)
