"""Author native complete GraphLease preflight and canonical-wire images."""
from __future__ import annotations
import ast
import copy
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_program import verify_program
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
from tools.generate_hia_agent_binary64_format import source_program as float_source
from tools.cli_graph_wire_common import COMMON, CONSTANTS
from tools.cli_graph_wire_scan import BODY as SCAN
from tools.cli_graph_wire_emit import BODY as EMIT

SOURCES = {role:'examples/hia_bootstrap/cli_graph_json_wire_'+role+'.hiaasm' for role in ('scan','emit')}


def floating_functions():
    nodes=ast.parse(float_source()).body
    names={node.name for node in nodes}
    entry=next(node for node in nodes if node.name=='render_binary64')
    original=entry.body
    start=next(i for i,node in enumerate(original)
               if isinstance(node,ast.Assign) and node.targets[0].id=='original')
    stop=next(i for i,node in enumerate(original)
              if isinstance(node,ast.If) and isinstance(node.test,ast.Compare)
              and isinstance(node.test.left,ast.Call) and node.test.left.func.id=='length'
              and node.test.left.args[0].id=='o')
    entry.body=[ast.parse('original = bits').body[0],*original[start+1:stop],
                ast.Return(value=ast.Name(id='cursor',ctx=ast.Load()))]
    entry.args.args=[ast.arg(arg='w',annotation=ast.Name(id='mutbuf',ctx=ast.Load())),
                     ast.arg(arg='bits',annotation=ast.Name(id='u64',ctx=ast.Load()))]
    entry.returns=ast.Name(id='u64',ctx=ast.Load())

    class Relocate(ast.NodeTransformer):
        def visit_Call(self,node):
            node=self.generic_visit(node)
            if (isinstance(node.func,ast.Name) and node.func.id in ('byte','store')
                    and isinstance(node.args[0],ast.Name) and node.args[0].id=='w'):
                node.args[1]=ast.BinOp(left=ast.Name(id='FLOAT_BASE',ctx=ast.Load()),
                                       op=ast.Add(),right=node.args[1])
            if isinstance(node.func,ast.Name) and node.func.id in names:
                node.func.id='fp_'+node.func.id
            return node
        def visit_FunctionDef(self,node):
            node=self.generic_visit(node)
            node.name='fp_'+node.name
            return node
    return [Relocate().visit(copy.deepcopy(node)) for node in nodes]


def authoring(which):
    if which not in SOURCES:
        raise ValueError('unknown GraphLease wire component')
    nodes=ast.parse((SCAN if which=='scan' else EMIT)+COMMON).body+floating_functions()
    definitions={node.name:node for node in nodes}
    assert len(definitions)==len(nodes)
    wanted={which};pending=[which]
    while pending:
        name=pending.pop()
        for item in ast.walk(definitions[name]):
            if isinstance(item,ast.Call) and isinstance(item.func,ast.Name):
                target=item.func.id
                if target in definitions and target not in wanted:
                    wanted.add(target);pending.append(target)
    nodes=[node for node in nodes if node.name in wanted]

    class Constants(ast.NodeTransformer):
        def visit_Name(self,node):
            if node.id in CONSTANTS:
                return ast.copy_location(ast.Constant(CONSTANTS[node.id]),node)
            return node
    return [Constants().visit(node) for node in nodes]


def document(which):
    nodes=authoring(which)
    names={node.name:'f'+str(index+1) for index,node in enumerate(nodes)}
    signatures={node.name:([arg.annotation.id for arg in node.args.args],node.returns.id)
                for node in nodes}
    total=total_scalar_functions(nodes)
    params=[{'name':'v0','type':'readbuf'},{'name':'v1','type':'mutbuf'},
            {'name':'v2','type':'mutbuf'}]
    functions=[{'name':'f0','params':params,'returns':['u32'],
        'effects':['read','write','trap'],'entry':'b0','blocks':[{
        'id':'b0','params':params,'ops':[
            {'op':'borrow.read','args':['v1'],'out':[{'name':'v3','type':'readbuf'}],'attrs':{}},
            {'op':'call','args':['v0','v3','v2'],'out':[{'name':'v4','type':'u32'}],
             'attrs':{'function':names[which]}},
            {'op':'loan.end','args':['v3'],'out':[],'attrs':{}}],
        'term':{'op':'ret','values':['v4']}}]}]
    for node in nodes:
        builder=Builder(node,names,signatures,total)
        builder.statements(node.body)
        functions.append({'name':names[node.name],
            'params':[builder.param(value) for value in builder.params],
            'returns':[builder.returns],'effects':['read','write','trap'],
            'entry':'b0','blocks':builder.blocks})
    result=compact_authoring_cfg({'schema':'hepta.hia.program.v8',
                'module':'cli_graph_json_wire_'+which,'functions':functions})
    functions=result['functions']
    limits=(len(functions),sum(len(fn['blocks']) for fn in functions),
            sum(len(block['ops']) for fn in functions for block in fn['blocks']),
            max(len(fn['blocks']) for fn in functions),
            max(len(block['params']) for fn in functions for block in fn['blocks']))
    if any(actual>maximum for actual,maximum in zip(limits,(128,1536,8192,256,16))):
        raise ValueError({'original_compiler_limits_exceeded':limits})
    verify_program(result)
    return result


def main():
    root=Path(__file__).resolve().parents[1]
    for which,relative in SOURCES.items():
        doc=document(which)
        target=root/relative
        target.parent.mkdir(parents=True,exist_ok=True)
        raw=render_assembly(doc)
        target.write_text(raw)
        print(which,len(raw.encode()),len(doc['functions']),
              sum(len(fn['blocks']) for fn in doc['functions']),
              sum(len(block['ops']) for fn in doc['functions'] for block in fn['blocks']),
              max(len(fn['blocks']) for fn in doc['functions']),
              max(len(block['params']) for fn in doc['functions'] for block in fn['blocks']),
              flush=True)


if __name__=='__main__':
    main()

