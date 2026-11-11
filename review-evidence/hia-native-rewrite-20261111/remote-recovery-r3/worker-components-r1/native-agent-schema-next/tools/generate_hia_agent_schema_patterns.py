"""Generate exact HIA matching for all five frozen Worker schema patterns."""
from __future__ import annotations
import ast,json,sys
from pathlib import Path
from hashlib import sha256
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT.parent/'Hepta-agent-edit-native'))
from hepta.hia_agent_assembly import render_assembly
from hepta.hia_program import verify_program
from tools.generate_hia_selfhost import Builder,compact_authoring_cfg,total_scalar_functions
import agent_schema_patterns as patterns

def unit_function(name,raw):
    lines=[f'def {name}(index:u64) -> u64:',f'    if index >= {len(raw)}:','        return 0',
           '    part = index >> 3','    shift = (index & 7) * 8']
    for i in range(0,len(raw),8):
        literal=int.from_bytes(raw[i:i+8],'little')
        lines.extend((f'    if part == {i//8}:',f'        return ({literal} >> shift) & 255'))
    lines.append('    return 0')
    return '\n'.join(lines)+'\n'

def source_program():
    source=patterns.BODY+'\n'
    for i,p in enumerate(patterns.PATTERNS,1):
        source+=unit_function('pattern_'+str(i),p.encode('ascii'))+'\n'
    source+=unit_function('uri_prefix',b'hia://artifacts/')+'\n'
    source+='def pattern_unit(kind:u64, index:u64) -> u64:\n'
    for i in range(1,len(patterns.PATTERNS)+1):
        source+=f'    if kind == {i}:\n        return pattern_{i}(index)\n'
    source+='    return 0\n\n'
    source+='def known_pattern(s:readbuf, size:u64) -> u64:\n'
    for i,p in enumerate(patterns.PATTERNS,1):
        source+=f'    if same_pattern(s, size, {i}, {len(p)}) != 0:\n        return {i}\n'
    source+='    return 0\n'
    class Expand(ast.NodeTransformer):
        def visit_Name(self,node):
            if node.id in patterns.CONSTANTS:
                return ast.copy_location(ast.Constant(patterns.CONSTANTS[node.id]),node)
            return node
    return ast.unparse(ast.fix_missing_locations(Expand().visit(ast.parse(source))))+'\n'

def inventory():
    from hepta import hia_agent_contract as contract
    found=set()
    def walk(node):
        if type(node) is dict:
            if 'pattern' in node:found.add(node['pattern'])
            for child in node.values():walk(child)
        elif type(node) is list:
            for child in node:walk(child)
    value,_=contract.catalog()
    for tool in value['tools']:
        walk(tool['inputSchema']);walk(tool['outputSchema'])
    names=('SCALAR_WORKLOAD_SCHEMA','BUFFER_WORKLOAD_SCHEMA','WORKLOAD_SCHEMA','OBJECTIVE_SCHEMA',
           'COST_POLICY_SCHEMA','BLOCK_PLAN_SCHEMA','MACHINE_PLAN_SCHEMA','VALUE_REGISTER_PLAN_SCHEMA',
           'LEAF_REGISTER_PLAN_SCHEMA','PLAN_SCHEMA')
    for name in names:walk(getattr(contract,name))
    assert found==set(patterns.PATTERNS),(sorted(found),patterns.PATTERNS)
    return dict(patterns=sorted(found),schema_constants=list(names),tools=[t['name'] for t in value['tools']])

def document():
    inventory()
    nodes=ast.parse(source_program()).body
    names={n.name:'f'+str(i) for i,n in enumerate(nodes)}
    signatures={n.name:([a.annotation.id for a in n.args.args],n.returns.id) for n in nodes}
    total=total_scalar_functions(nodes)
    functions=[]
    for n in nodes:
        b=Builder(n,names,signatures,total);b.statements(n.body)
        functions.append(dict(name=names[n.name],params=[b.param(p) for p in b.params],returns=[b.returns],
            effects=['read','write','trap'],entry='b0',blocks=b.blocks))
    result=compact_authoring_cfg(dict(schema='hepta.hia.program.v8',module='agent_schema_patterns',functions=functions))
    fs=result['functions']
    counts=(len(fs),sum(len(f['blocks']) for f in fs),sum(len(b['ops']) for f in fs for b in f['blocks']),
            max(len(f['blocks']) for f in fs),max(len(b['params']) for f in fs for b in f['blocks']))
    assert all(a<=b for a,b in zip(counts,(128,1536,8192,256,16))),counts
    verify_program(result)
    return result

if __name__=='__main__':
    value=document();raw=render_assembly(value).encode()
    target=ROOT/'examples/hia_bootstrap/agent_schema_patterns.hiaasm'
    target.parent.mkdir(parents=True,exist_ok=True)
    assert not target.exists(),'Use a new output revision'
    target.write_bytes(raw)
    print(json.dumps(dict(source=str(target),bytes=len(raw),sha256=sha256(raw).hexdigest(),
                          inventory=inventory(),scope='PUBLISHED_PATTERNS_ONLY_NOT_COMPLETE_SCHEMA'),sort_keys=True))
