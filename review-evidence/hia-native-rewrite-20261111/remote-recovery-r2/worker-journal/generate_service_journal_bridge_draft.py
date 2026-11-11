"""Generate complete selected Agent journal transport/state/diagnostic owner."""
from __future__ import annotations
import ast
from hashlib import sha256
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT.parent
sys.path.insert(0, str(BASE / 'Hepta-agent-edit-native'))
from hepta.hia_agent_assembly import render_assembly
from hepta.hia_program import verify_program
from hepta.hia_json_preflight_native import SYNTAX_REASONS
from tools.generate_hia_selfhost import compact_authoring_cfg, total_scalar_functions
from tools.hia_agent_edit_source_views import CopyBuilder
from service_journal_bridge import BODY, CONSTANTS, ERROR_MESSAGES, ORIGINAL_MESSAGES

def dispatch(name, values, valid=False):
    lines=['def '+name+'(reason:u64) -> u64:' if valid else 'def '+name+'(w:mutbuf, reason:u64) -> u64:']
    for key,value in sorted(values.items()):
        lines.append('    if reason == '+str(key)+':')
        if valid: lines.append('        return 1')
        else:
            lines.append('        say(w, '+repr(value)+')')
            lines.append('        return 0')
    lines.append('    return 0')
    return '\n'.join(lines)+'\n'

def source_program():
    source = BODY
    for name,values,valid in (
        ('syntax_valid',SYNTAX_REASONS,True),('syntax_message',SYNTAX_REASONS,False),
        ('original_valid',ORIGINAL_MESSAGES,True),('original_message',ORIGINAL_MESSAGES,False),
        ('error_message',ERROR_MESSAGES,False)):
        source += '\n'+dispatch(name,values,valid)
    class Expand(ast.NodeTransformer):
        def visit_Name(self,node):
            if node.id in CONSTANTS:
                return ast.copy_location(ast.Constant(CONSTANTS[node.id]),node)
            return node
        def visit_Expr(self,node):
            call=node.value
            if isinstance(call,ast.Call) and isinstance(call.func,ast.Name) and call.func.id=='say':
                assert len(call.args)==2 and isinstance(call.args[1],ast.Constant) and type(call.args[1].value) is str
                raw=call.args[1].value.encode('utf-8')
                result=[]
                for offset in range(0,len(raw),32):
                    part=raw[offset:offset+32]
                    args=[call.args[0],ast.Constant(len(part))]+[ast.Constant(int.from_bytes(part[i:i+8],'little')) for i in (0,8,16,24)]
                    result.append(ast.copy_location(ast.Expr(ast.Call(ast.Name('literal',ast.Load()),args,[])),node))
                return result
            return self.generic_visit(node)
    tree=Expand().visit(ast.parse(source))
    return ast.unparse(ast.fix_missing_locations(tree))+'\n'

def document():
    nodes=ast.parse(source_program()).body
    names={node.name:'f'+str(i+1) for i,node in enumerate(nodes)}
    signatures={node.name:([arg.annotation.id for arg in node.args.args],node.returns.id) for node in nodes}
    total=total_scalar_functions(nodes)
    params=[{'name':'v0','type':'readbuf'},{'name':'v1','type':'mutbuf'},{'name':'v2','type':'mutbuf'}]
    functions=[dict(name='f0',params=params,returns=['u32'],effects=['read','write','trap'],entry='b0',
       blocks=[dict(id='b0',params=params,ops=[
         {'op':'borrow.read','args':['v1'],'out':[{'name':'v3','type':'readbuf'}],'attrs':{}},
         {'op':'call','args':['v0','v3','v2'],'out':[{'name':'v4','type':'u32'}],'attrs':{'function':names['service_journal']}},
         {'op':'loan.end','args':['v3'],'out':[],'attrs':{}}],
         term={'op':'ret','values':['v4']})])]
    for node in nodes:
        builder=CopyBuilder(node,names,signatures,total)
        builder.statements(node.body)
        functions.append(dict(name=names[node.name],params=[builder.param(v) for v in builder.params],
          returns=[builder.returns],effects=['read','write','trap'],entry='b0',blocks=builder.blocks))
    value=compact_authoring_cfg(dict(schema='hepta.hia.program.v8',module='agent_service_journal_bridge',functions=functions))
    fs=value['functions']
    counts=(len(fs),sum(len(f['blocks']) for f in fs),sum(len(b['ops']) for f in fs for b in f['blocks']),
            max(len(f['blocks']) for f in fs),max(len(b['params']) for f in fs for b in f['blocks']))
    if any(a>b for a,b in zip(counts,(128,1536,8192,256,16))):
        raise ValueError(dict(original_compiler_limits_exceeded=counts))
    verify_program(value)
    return value

if __name__=='__main__':
    value=document()
    raw=render_assembly(value).encode()
    target=ROOT/'examples/hia_bootstrap/agent_service_journal_bridge.hiaasm'
    target.write_bytes(raw)
    fs=value['functions']
    print(json.dumps(dict(path=str(target),bytes=len(raw),sha256=sha256(raw).hexdigest(),
        functions=len(fs),blocks=sum(len(f['blocks']) for f in fs),
        instructions=sum(len(b['ops']) for f in fs for b in f['blocks']),
        max_blocks=max(len(f['blocks']) for f in fs),
        max_block_parameters=max(len(b['params']) for f in fs for b in f['blocks'])),sort_keys=True),flush=True)
