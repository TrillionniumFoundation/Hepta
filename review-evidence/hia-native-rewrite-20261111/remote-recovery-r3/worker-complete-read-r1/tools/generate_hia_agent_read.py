"""Author the two complete hia_read HIA business kernels.

Namespace operation numbers are resolved only at development compile time from
the exact published 31-operation ABI. The generated native code has fixed op
constants. No Python object or SQL decision is made at runtime.
"""
from __future__ import annotations
import argparse,ast,json,sys
from hashlib import sha256
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
REFERENCE=ROOT.parent/'Hepta-agent-edit-native'
sys.path.insert(0,str(REFERENCE))
from hepta.hia_program import verify_program
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import compact_authoring_cfg,total_scalar_functions
from tools.hia_agent_edit_source_views import CopyBuilder
import agent_read_common as common
import agent_read_graph as graph
import agent_read_values as values
import agent_read_flow as flow

ABI_SHA='c15222c99cb04ef8bc6a7f13108a7e90adb0bc908876d663eb4329fd14563c04'
ABI_BYTES=51264
ROLES={1:('agent_read_flow','rd_flow'),2:('agent_read_values','rd_values')}
INTRINSICS={'byte','length','store','copy_bytes','fill_range','choose'}

def namespace_bindings(raw):
    assert (len(raw),sha256(raw).hexdigest())==(ABI_BYTES,ABI_SHA)
    data=json.loads(raw)
    assert data['schema']=='hepta.hia.agent-namespace-store-abi.v1'
    assert len(data['tables'])==10
    operations=data['relational_operations']
    if isinstance(operations,dict):operations=list(operations.values())
    assert isinstance(operations,list) and len(operations)==31
    def identifier(row):
        value=row['id'];assert type(value) is int and 1<=value<=31
        return value
    assert [identifier(row) for row in operations]==list(range(1,32))
    assert sum(len(row['call_sites']) for row in operations)==45
    result={};bound=[]
    for symbol,(sql,arity) in common.NAMESPACE_SQL.items():
        # The exact whole-document hash is authoritative; discover the
        # spelling of the direct SQL field from its complete original value.
        # No substring/normalization or approximate operation match is allowed.
        matches=[(row,key) for row in operations for key,value in row.items()
                 if type(value) is str and value==sql]
        assert len(matches)==1,(symbol,matches)
        row,sql_key=matches[0]
        assert row['bind_count']==arity
        assert type(row['table_id']) is int and 1<=row['table_id']<=10
        result[symbol]=identifier(row)
        bound.append(dict(symbol=symbol,operation_id=result[symbol],sql=sql,
                          bind_count=arity,table_id=row['table_id'],sql_field=sql_key))
    assert len(set(result.values()))==2 and bound[0]['table_id']==bound[1]['table_id']
    # Select the table by the two exact operations' issued table id. The
    # column sequence is checked against the complete original row shape;
    # unfamiliar representations are refused before any native compilation.
    tables=[row for row in data['tables'] if row['id']==bound[0]['table_id']]
    assert len(tables)==1
    table=tables[0];columns=table['columns']
    if isinstance(columns,dict):names=list(columns)
    elif isinstance(columns,list):
        names=[item if isinstance(item,str) else item.get('name') if isinstance(item,dict)
               else item[0] if isinstance(item,list) and item else None for item in columns]
    else:names=None
    assert names==['id','artifact_id','sha256','offset'],table
    return result,dict(schema='hia-read-fixed-namespace-binding-v1',
        source_bytes=len(raw),source_sha256=sha256(raw).hexdigest(),
        operations=bound,row_columns=['id','artifact_id','sha256','offset'],
        compile_time_only=True,runtime_host_sql_selection=False)

def literal_functions():
    result=[]
    lines=['def rd_literal_size(code:u64) -> u64:']
    for code,raw in sorted(common.LITERALS.items()):
        lines.extend(['    if code == '+str(code)+':','        return '+str(len(raw))])
    lines.append('    return 18446744073709551615');result.append('\n'.join(lines))
    lines=['def rd_literal(w:mutbuf, code:u64, start:u64) -> u64:']
    for code,raw in sorted(common.LITERALS.items()):
        lines.append('    if code == '+str(code)+':')
        offset=0
        while offset+8<=len(raw):
            lines.append('        rd_put(w, start + '+str(offset)+', '+
                         str(int.from_bytes(raw[offset:offset+8],'little'))+')')
            offset+=8
        for i in range(offset,len(raw)):
            lines.append('        store(w, start + '+str(i)+', '+str(raw[i])+')')
        lines.append('        return '+str(len(raw)))
    lines.append('    return 18446744073709551615');result.append('\n'.join(lines))
    lines=['def rd_matches(g:readbuf, at:u64, code:u64) -> u64:']
    for code in range(1,7):
        raw=common.LITERALS[code]
        lines.extend(['    if code == '+str(code)+':',
                      '        if rd_word(g, at + 16) != '+str(len(raw))+':',
                      '            return 0','        begin = rd_word(g, at + 8)'])
        for i,b in enumerate(raw):
            lines.extend(['        if byte(g, begin + '+str(i)+') != '+str(b)+':',
                          '            return 0'])
        lines.append('        return 1')
    lines.append('    return 0');result.append('\n'.join(lines))
    return '\n\n'.join(result)+'\n'

def source_program(role,opcodes):
    assert role in ROLES and set(opcodes)==set(common.NAMESPACE_SQL)
    assert len(set(opcodes.values()))==2 and all(type(v) is int and 1<=v<=31 for v in opcodes.values())
    functions={}
    sources=(common.COMMON,graph.GRAPH,values.VALUES,values.PREFIX,
             values.WORK_PREFIX,flow.FLOW,literal_functions(),
             'def rd_step(g:readbuf, r:readbuf, w:mutbuf) -> u64:\n    return '+
             ROLES[role][1]+'(g, r, w)\n')
    for source in sources:
        for node in ast.parse(source).body:
            assert isinstance(node,ast.FunctionDef)
            assert node.name not in functions,node.name
            functions[node.name]=node
    reached=set();pending=['rd_entry']
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
    selected=[functions['rd_entry']]+[node for name,node in functions.items()
        if name!='rd_entry' and name in reached]
    constants={**common.CONSTANTS,**opcodes}
    class Expand(ast.NodeTransformer):
        def visit_Name(self,node):
            if node.id in constants:
                return ast.copy_location(ast.Constant(constants[node.id]),node)
            return node
    return ast.unparse(ast.fix_missing_locations(Expand().visit(
        ast.Module(body=selected,type_ignores=[]))))+'\n'

def document(role,opcodes):
    nodes=ast.parse(source_program(role,opcodes)).body
    names={node.name:'f'+str(i+1) for i,node in enumerate(nodes)}
    signatures={node.name:([a.annotation.id for a in node.args.args],node.returns.id) for node in nodes}
    total=total_scalar_functions(nodes)
    params=[dict(name='v0',type='readbuf'),dict(name='v1',type='mutbuf'),dict(name='v2',type='mutbuf')]
    functions=[dict(name='f0',params=params,returns=['u32'],effects=['read','write','trap'],entry='b0',
        blocks=[dict(id='b0',params=params,ops=[
            dict(op='borrow.read',args=['v1'],out=[dict(name='v3',type='readbuf')],attrs={}),
            dict(op='const',args=[],out=[dict(name='v4',type='u64')],attrs=dict(value=role)),
            dict(op='call',args=['v0','v3','v2','v4'],out=[dict(name='v5',type='u32')],attrs=dict(function=names['rd_entry'])),
            dict(op='loan.end',args=['v3'],out=[],attrs={})],term=dict(op='ret',values=['v5']))])]
    for node in nodes:
        builder=CopyBuilder(node,names,signatures,total);builder.statements(node.body)
        functions.append(dict(name=names[node.name],params=[builder.param(v) for v in builder.params],
            returns=[builder.returns],effects=['read','write','trap'],entry='b0',blocks=builder.blocks))
    value=compact_authoring_cfg(dict(schema='hepta.hia.program.v8',module=ROLES[role][0],functions=functions))
    fs=value['functions'];counts=(len(fs),sum(len(f['blocks']) for f in fs),
        sum(len(b['ops']) for f in fs for b in f['blocks']),
        max(len(f['blocks']) for f in fs),max(len(b['params']) for f in fs for b in f['blocks']))
    assert all(actual<=limit for actual,limit in zip(counts,(128,1536,8192,256,16))),counts
    verify_program(value)
    return value

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--namespace-abi',type=Path,required=True)
    a=p.parse_args();raw=a.namespace_abi.read_bytes();opcodes,binding=namespace_bindings(raw)
    directory=ROOT/'examples/hia_bootstrap';directory.mkdir(parents=True,exist_ok=True)
    proof=ROOT/'development/namespace-binding.json';proof.parent.mkdir(parents=True,exist_ok=True)
    assert not proof.exists(),'new revision output required'
    proof.write_text(json.dumps(binding,sort_keys=True,indent=2)+'\n')
    for role,(name,_) in ROLES.items():
        value=document(role,opcodes);assembly=render_assembly(value).encode()
        target=directory/(name+'.hiaasm');assert not target.exists(),'new revision output required'
        target.write_bytes(assembly);fs=value['functions']
        print(json.dumps(dict(role=role,name=name,path=str(target),bytes=len(assembly),
            sha256=sha256(assembly).hexdigest(),functions=len(fs),
            blocks=sum(len(f['blocks']) for f in fs),
            instructions=sum(len(b['ops']) for f in fs for b in f['blocks']),
            max_function_blocks=max(len(f['blocks']) for f in fs),
            max_block_parameters=max(len(b['params']) for f in fs for b in f['blocks']),
            namespace_binding=binding,scope='HIA_READ_AUTHORING_WITH_PENDING_HIGH_LEVEL_NAMESPACE'),sort_keys=True),flush=True)
