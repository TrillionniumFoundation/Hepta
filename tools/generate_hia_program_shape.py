"""Author whole primitive Core declaration admission, excluding body semantics.

Embeds the complete HIA function-shape policy, not a host decision or receipt.
Decode the whole document once. One shared namespaced table retains global
function/export identities and separate function-local SSA/CFG identities.
"""
import ast
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_core_json_frontend import KEYS,packed
from tools.generate_hia_function_shape import source_program as function_source
from tools.generate_hia_selfhost import Builder,compact_authoring_cfg,total_scalar_functions

ERRORS={'FORMAT':0xfffffffb,'NAME':0xfffffffa,'TYPE':0xfffffff9,
        'SCHEMA_ERROR':0xfffffff4,'CALL_ERROR':0xfffffff3,'EXPORT_TYPE':0xfffffff2,'NONE':(1<<64)-1}

PROGRAM = r'''
def program_shape(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < 128 or length(o) < 128:
        return 4294967293
    put(o, 48, 262144)
    put(o, 56, 64)
    decoded_size = widen(decode_json(s, w, o))
    if decoded_size >= 4294967292:
        return decoded_size
    slots = 2
    while slots < get(w, 8) * 4:
        slots = slots * 2
    base = 128 + slots * 24
    if length(o) < base + 4096 * 40:
        return 4294967293
    put(o, 16, slots)
    put(o, 32, base)
    put(o, 96, 0)
    at = 128
    while at < base:
        put(o, at, 0)
        at = at + 24
    fields = K_schema | K_module | K_functions
    exports = field(w, 0, K_exports)
    if exports != NONE:
        fields = fields | K_exports
    if shape(w, 0, fields) == 0:
        return FORMAT
    version = schema_version(w, field(w, 0, K_schema))
    if version == 0:
        return SCHEMA_ERROR
    if identifier(w, field(w, 0, K_module)) == 0:
        return NAME
    functions = field(w, 0, K_functions)
    if kind(w, functions) != 5 or count(w, functions) == 0 or count(w, functions) > 1024:
        return FORMAT
    flags = choose(version >= 7, 1, 0) | choose(version >= 8, 2, 0)
    fn = child(w, functions)
    index = 1
    while fn != NONE:
        put(o, 96, index << 32)
        status = check_function(w, o, fn, flags)
        if status != 0:
            return status
        # Complete function admission precedes duplicate function diagnostics.
        put(o, 96, 0)
        if symbol(w, o, field(w, fn, K_name), 1, 1, fn) != NONE:
            return NAME
        fn = next_node(w, fn)
        index = index + 1
    if exports != NONE:
        status = names(w, exports)
        if status != 0:
            return status
        item = child(w, exports)
        while item != NONE:
            if symbol(w, o, item, 2, 1, 0) != NONE:
                return NAME
            item = next_node(w, item)
        item = child(w, exports)
        while item != NONE:
            fn = symbol(w, o, item, 1, 0, 0)
            if fn == NONE:
                return CALL_ERROR
            parameter = child(w, field(w, fn, K_params))
            while parameter != NONE:
                if type_id(w, field(w, parameter, K_type)) > 12:
                    return EXPORT_TYPE
                parameter = next_node(w, parameter)
            result = child(w, field(w, fn, K_returns))
            while result != NONE:
                if type_id(w, result) > 12:
                    return EXPORT_TYPE
                result = next_node(w, result)
            item = next_node(w, item)
    return 0
'''


def source_program():
    nodes=ast.parse(function_source()).body
    original=nodes[0]
    assert original.name=='function_shape'
    cut=next(i for i,n in enumerate(original.body) if isinstance(n,ast.Assign)
             and isinstance(n.targets[0],ast.Name) and n.targets[0].id=='fields')
    class FunctionRoot(ast.NodeTransformer):
        def visit_Call(self,node):
            node=self.generic_visit(node)
            if (isinstance(node.func,ast.Name) and node.func.id in {'field','shape'}
                    and isinstance(node.args[1],ast.Constant) and node.args[1].value==0):
                node.args[1]=ast.Name(id='fn',ctx=ast.Load())
            return node
    body=FunctionRoot().visit(ast.Module(body=original.body[cut:],type_ignores=[])).body
    header=ast.parse('''def check_function(w:mutbuf, o:mutbuf, fn:u64, flags:u64) -> u64:
    base = get(o, 32)
    put(o, 8, 4)
    put(o, 24, 0)
''').body[0]
    header.body+=body
    # Context tags must be part of exact equality AND the bucket hash. Folding
    # high context bits avoids clustering same local names across many functions.
    symbol=next(n for n in nodes if n.name=='symbol')
    symbol.body[:1]=ast.parse('namespace = namespace + get(o, 96)\nhash_value = namespace ^ (namespace >> 32)').body
    constants={**ERRORS,**{'K_'+name:1<<i for i,name in enumerate(KEYS)}}
    class Expand(ast.NodeTransformer):
        def visit_Name(self,node):
            return ast.copy_location(ast.Constant(constants[node.id]),node) if node.id in constants else node
    root=Expand().visit(ast.parse(PROGRAM))
    body=[*root.body,header,*nodes[1:]]
    text=ast.unparse(ast.fix_missing_locations(ast.Module(body=body,type_ignores=[])))+'\n'
    text+='def schema_version(w:mutbuf, node:u64) -> u64:\n'
    for version in range(1,9):
        text+='    if text_is(w, node, '+', '.join(map(str,packed('hepta.hia.program.v'+str(version))))+') != 0:\n        return '+str(version)+'\n'
    return text+'    return 0\n'


def document():
    nodes=ast.parse(source_program()).body
    names={n.name:'f'+str(i) for i,n in enumerate(nodes)}
    signatures={n.name:([a.annotation.id for a in n.args.args],n.returns.id) for n in nodes}
    total=total_scalar_functions(nodes);functions=[]
    for node in nodes:
        b=Builder(node,names,signatures,total);b.statements(node.body)
        functions.append({'name':names[node.name],'params':[b.param(v) for v in b.params],
                          'returns':[b.returns],'effects':['read','write','trap'],'entry':'b0','blocks':b.blocks})
    return compact_authoring_cfg({'schema':'hepta.hia.program.v8','module':'program_shape','functions':functions})


if __name__=='__main__':
    path=Path(__file__).resolve().parents[1]/'examples/hia_bootstrap/program_shape.hiaasm'
    path.write_text(render_assembly(document()));print(path.name,path.stat().st_size)
