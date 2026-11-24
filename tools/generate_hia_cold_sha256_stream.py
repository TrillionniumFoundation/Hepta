"""Author a cold-replay SHA implementation with the original state ABI.

Only the compression implementation removes helper calls. Stream admission,
state layout, update ordering, padding and partial byte-store ordering remain
the same as the original independently executed SHA transition.
"""
from pathlib import Path
import ast,copy
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_sha256_stream import source_program as original_source,STATE_BYTES,MAX_CHUNK,MAX_TOTAL,MAGIC
from tools.generate_hia_selfhost import compact_authoring_cfg,total_scalar_functions
from tools.generate_hia_worker_config_json import ConfigBuilder as Builder

class Compression(ast.NodeTransformer):
    def __init__(self):
        self.puts=0
    def visit_Call(self,node):
        node=self.generic_visit(node)
        if isinstance(node.func,ast.Name) and node.func.id=='get':
            assert len(node.args)==2 and not node.keywords
            return ast.copy_location(ast.Call(func=ast.Name(id='word_load',ctx=ast.Load()),args=node.args,keywords=[]),node)
        if isinstance(node.func,ast.Name) and node.func.id=='rotate':
            assert len(node.args)==2 and isinstance(node.args[1],ast.Constant)
            value,amount=node.args;shift=amount.value;assert 0<shift<32
            # Exactly the old helper: its right-shift arm is not masked.
            result=ast.BinOp(left=ast.BinOp(left=value,op=ast.RShift(),right=ast.Constant(shift)),
              op=ast.BitOr(),right=ast.BinOp(left=ast.BinOp(left=copy.deepcopy(value),op=ast.LShift(),right=ast.Constant(32-shift)),
                                            op=ast.BitAnd(),right=ast.Constant(4294967295)))
            return ast.copy_location(result,node)
        return node
    def visit_Expr(self,node):
        node=self.generic_visit(node)
        call=node.value
        if not(isinstance(call,ast.Call) and isinstance(call.func,ast.Name) and call.func.id=='put'):
            return node
        assert len(call.args)==3 and not call.keywords
        view,index,value=call.args;assert isinstance(view,ast.Name) and view.id=='w'
        self.puts += 1
        # Compression is private to the guarded 1184-byte state transition.
        # Every scheduled/chaining index here has a complete eight-byte range.
        return ast.copy_location(ast.Expr(value=ast.Call(func=ast.Name(id='word_store', ctx=ast.Load()), args=[view,index,value], keywords=[])), node)

def source_program():
    module=ast.parse(original_source())
    compress=next(node for node in module.body if isinstance(node,ast.FunctionDef) and node.name=='compress')
    first=next(node for node in compress.body if isinstance(node,ast.While))
    inner=next(node for node in first.body if isinstance(node,ast.While))
    assert ast.unparse(inner.test)=='j < 4'
    decode=ast.parse('cold_word_at = 1112 + i * 4\nvalue = (byte(w, cold_word_at) << 24) | (byte(w, cold_word_at + 1) << 16) | (byte(w, cold_word_at + 2) << 8) | byte(w, cold_word_at + 3)').body
    index=first.body.index(inner);first.body[index:index+1]=decode
    transformer=Compression();transformer.visit(compress)
    assert transformer.puts==10,transformer.puts
    assert not any(isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id in ('rotate','get','put') for n in ast.walk(compress))
    # Preserve every memory access and round transition, grouping only loops
    # whose fixed trip counts are multiples of four. No state word is assumed
    # canonical; arbitrary full-u64 chaining and round words remain observable.
    for loop in [n for n in compress.body if isinstance(n, ast.While)]:
        assert ast.unparse(loop.test) in ('i < 16', 'i < 64')
        original_body = loop.body
        loop.body = [copy.deepcopy(n) for _ in range(4) for n in original_body]
    stream = next(n for n in module.body if isinstance(n, ast.FunctionDef) and n.name == 'stream')
    update = next(n for n in stream.body if isinstance(n, ast.If) and ast.unparse(n.test) == 'op == 1')
    loop = next(n for n in update.body if isinstance(n, ast.While))
    assert ast.unparse(loop.test) == 'i < length(s)'
    fast = []
    # Read then write each byte in its original order. This also preserves
    # foreign pointer aliases with any source/state displacement.
    for j in range(64):
        fast.extend(ast.parse(f'store(w, {1112+j}, byte(s, i + {j}))').body)
    fast.extend(ast.parse('compress(w)\ni = i + 64').body)
    loop.body = [ast.If(test=ast.parse('used == 0 and length(s) - i >= 64', mode='eval').body,
                        body=fast, orelse=loop.body)]
    put_fn = next(n for n in module.body if isinstance(n,ast.FunctionDef) and n.name=='put')
    guarded = ast.parse('if index <= length(w) and length(w) - index >= 8:\n    word_store(w, index, value)\n    return 0').body[0]
    put_fn.body.insert(0, guarded)
    module.body=[n for n in module.body if not(isinstance(n,ast.FunctionDef)and n.name=='rotate')]
    return ast.unparse(ast.fix_missing_locations(module))+'\n'

def document():
    nodes=ast.parse(source_program()).body
    names={node.name:'f'+str(i)for i,node in enumerate(nodes)}
    signatures={node.name:([a.annotation.id for a in node.args.args],node.returns.id)for node in nodes}
    total=total_scalar_functions(nodes);functions=[]
    for node in nodes:
        builder=Builder(node,names,signatures,total);builder.statements(node.body)
        functions.append({'name':names[node.name],'params':[builder.param(v)for v in builder.params],
                          'returns':[builder.returns],'effects':['read','write','trap'],'entry':'b0','blocks':builder.blocks})
    return compact_authoring_cfg({'schema':'hepta.hia.program.v9','module':'cold_sha256_stream','functions':functions})

def main():
    root=Path(__file__).resolve().parents[1]
    path=root/'examples/hia_bootstrap/cold_sha256_stream.hepta';doc=document()
    path.write_text(render_assembly(doc))
    print(path.name,path.stat().st_size,len(doc['functions']),sum(len(f['blocks'])for f in doc['functions']),sum(len(b['ops'])for f in doc['functions']for b in f['blocks']))
if __name__=='__main__':main()
