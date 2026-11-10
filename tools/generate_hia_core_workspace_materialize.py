"""Compose native workspace facts/policy and Core assembly materialization.

No host payload decoder, name allocator, call rewrite or Core renderer executes
inside the resulting image. Representation still requires the existing native
semantic compiler; this authoring/build tool is hosted, not native-only delivery.
"""
import ast
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_core_workspace_facts import source_program as json_source
from tools.generate_hia_core_module_graph import source_program as graph_source
from tools.generate_hia_core_json_frontend import source_program as frontend_source, packed
from tools.generate_hia_selfhost import Builder,compact_authoring_cfg,total_scalar_functions

ARENA_BYTES=88<<20
WORKSPACE_BYTES=(16<<20)+8192
FACTS_BASE=72<<20
FACTS_LENGTH=FACTS_BASE-8
NAME_BASE=80<<20
FN_TABLE=524288
CALL_TABLE=600000
NAME_TABLE=800000
PUBLIC_TABLE=900000
OUTPUT_BASE=3<<20


TOP=r'''
def workspace_materialize(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(o) < 92274688 or length(w) < 16785408:
        return 4294967294
    facts = widen(J_workspace_json(s, o, w))
    if facts >= 4294967292:
        return facts
    J_put(o, 75497464, facts)
    policy = widen(G_resolve(o, w))
    if policy >= 4294967270:
        return policy
    if M_index(o, w) == 0:
        return 4294967270
    if M_names(o, w) == 0:
        return 4294967270
    M_calls(o, w)
    rendered = widen(M_render(s, o, w))
    if rendered == 4294967290:
        return 4294967294
    return rendered

def M_index(o:mutbuf, w:mutbuf) -> u64:
    modules = J_field(o, 0, 3)
    module = J_get(o, 64 + modules * 56 + 24)
    fi = 0
    ci = 0
    mi = 0
    while mi < G_uint(o, 8):
        core = J_field(o, module, 4)
        # The reused native semantic compiler accepts primitive v8. Do not
        # silently upgrade an older feature schema or erase nominal types.
        if J_workspace_token(o, J_field(o, core, 1)) != 26:
            return 0
        functions = J_field(o, core, 8)
        fn = J_get(o, 64 + functions * 56 + 24)
        j = 0
        while j < J_get(o, 64 + functions * 56 + 32):
            G_put(w, 524288 + fi * 8, fn)
            blocks = J_field(o, fn, 10)
            block = J_get(o, 64 + blocks * 56 + 24)
            b = 0
            while b < J_get(o, 64 + blocks * 56 + 32):
                ops = J_field(o, block, 11)
                op = J_get(o, 64 + ops * 56 + 24)
                k = 0
                while k < J_get(o, 64 + ops * 56 + 32):
                    if J_workspace_token(o, J_field(o, op, 12)) == 18:
                        attrs = J_field(o, op, 13)
                        G_put(w, 600000 + ci * 8, J_field(o, attrs, 14))
                        ci = ci + 1
                    op = J_get(o, 64 + op * 56 + 16)
                    k = k + 1
                block = J_get(o, 64 + block * 56 + 16)
                b = b + 1
            fi = fi + 1
            fn = J_get(o, 64 + fn * 56 + 16)
            j = j + 1
        module = J_get(o, 64 + module * 56 + 16)
        mi = mi + 1
    return choose(fi == G_uint(o, 16) and ci == G_uint(o, 32), 1, 0)

def M_names(o:mutbuf, w:mutbuf) -> u64:
    nf = G_uint(o, 16)
    nx = G_uint(o, 40)
    public = 64 + 8 * (G_uint(o, 8) + G_uint(o, 24) + G_uint(o, 32))
    fill_range(w, 900000, nf * 8, 0)
    i = 0
    while i < nx:
        target = G_get(w, public + i * 8)
        if target != 18446744073709551615:
            G_put(w, 900000 + target * 8, 1)
        i = i + 1
    i = 0
    while i < nf:
        if G_get(w, 900000 + i * 8) != 0:
            node = J_field(o, G_get(w, 524288 + i * 8), 9)
            G_put(w, 800000 + i * 16, J_get(o, 64 + node * 56 + 24))
            G_put(w, 800008 + i * 16, J_get(o, 64 + node * 56 + 32))
        i = i + 1
    i = 0
    while i < nf:
        if G_get(w, 900000 + i * 8) == 0:
            suffix = i
            start = 83886080 + i * 128
            size = M_decimal_name(o, start, suffix)
            while M_used(o, w, i, start, size) != 0:
                suffix = suffix + 1
                if suffix > 2048:
                    return 0
                size = M_decimal_name(o, start, suffix)
            G_put(w, 800000 + i * 16, start)
            G_put(w, 800008 + i * 16, size)
        node = J_field(o, G_get(w, 524288 + i * 8), 9)
        J_put(o, 64 + node * 56 + 24, G_get(w, 800000 + i * 16))
        J_put(o, 64 + node * 56 + 32, G_get(w, 800008 + i * 16))
        i = i + 1
    return 1

def M_used(o:mutbuf, w:mutbuf, fi:u64, start:u64, size:u64) -> u64:
    j = 0
    while j < G_uint(o, 16):
        if j < fi or G_get(w, 900000 + j * 8) != 0:
            other = G_get(w, 800000 + j * 16)
            length = G_get(w, 800008 + j * 16)
            if M_equal(o, start, size, other, length) != 0:
                return 1
        j = j + 1
    return 0

def M_equal(o:mutbuf, a:u64, na:u64, b:u64, nb:u64) -> u64:
    if na != nb:
        return 0
    j = 0
    while j < na:
        if byte(o, a + j) != byte(o, b + j):
            return 0
        j = j + 1
    return 1

def M_calls(o:mutbuf, w:mutbuf) -> u64:
    i = 0
    targets = 64 + 8 * (G_uint(o, 8) + G_uint(o, 24))
    while i < G_uint(o, 32):
        node = G_get(w, 600000 + i * 8)
        target = G_get(w, targets + i * 8)
        J_put(o, 64 + node * 56 + 24, G_get(w, 800000 + target * 16))
        J_put(o, 64 + node * 56 + 32, G_get(w, 800008 + target * 16))
        i = i + 1
    return 0

def M_render(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    J_put(o, 48, 0)
    J_put(o, 56, 0)
    M_header(w, o)
    public = 64 + 8 * (G_uint(o, 8) + G_uint(o, 24) + G_uint(o, 32))
    seen = 0
    i = 0
    while i < G_uint(o, 40):
        target = G_get(w, public + i * 8)
        if target != 18446744073709551615:
            if seen != 0:
                F_append_byte(w, o, 44)
            F_token(w, o, J_field(o, G_get(w, 524288 + target * 8), 9), 0)
            seen = seen + 1
        i = i + 1
    F_append_byte(w, o, 41)
    F_append_byte(w, o, 10)
    i = 0
    while i < G_uint(o, 16):
        F_render_function(s, w, o, G_get(w, 524288 + i * 8))
        i = i + 1
    if J_get(o, 48) != 0:
        return J_get(o, 48)
    size = J_get(o, 56)
    i = 0
    while i < size:
        store(o, i, byte(w, 3145728 + i))
        i = i + 1
    return size

def widen(value:u64) -> u64:
    return value
'''


def namespace(text,prefix):
    tree=ast.parse(text);names={n.name:prefix+n.name for n in tree.body}
    class Rename(ast.NodeTransformer):
        def visit_Call(self,node):
            node=self.generic_visit(node)
            if isinstance(node.func,ast.Name) and node.func.id in names:
                node.func.id=names[node.func.id]
            return node
        def visit_FunctionDef(self,node):
            node.name=names[node.name];return self.generic_visit(node)
    return Rename().visit(tree).body


def source_nodes():
    text=json_source()
    old='store(o, at, byte(w, 4096 + at))'
    assert text.count(old)==1
    j=namespace(text.replace(old,f'store(o, {FACTS_BASE} + at, byte(w, 4096 + at))'),'J_')
    text=graph_source()
    assert 'if length(o) < size or length(w) < size + 8 * (nf + nm):' in text
    text=text.replace('s:readbuf','s:mutbuf').replace('resolve(s:mutbuf, o:mutbuf, w:mutbuf)',
        'resolve(s:mutbuf, w:mutbuf)').replace('if length(o) < size or length(w) < size + 8 * (nf + nm):',
        'if length(w) < size + 8 * (nf + nm):')
    old='    i = 0\n    while i < size:\n        store(o, i, byte(w, i))\n        i = i + 1\n    return size'
    assert text.count(old)==1;text=text.replace(old,'    return size')
    gtree=ast.parse(text)
    class FactsView(ast.NodeTransformer):
        def visit_Call(self,node):
            node=self.generic_visit(node)
            if isinstance(node.func,ast.Name) and node.args and isinstance(node.args[0],ast.Name) and node.args[0].id=='s':
                if node.func.id=='length':return ast.Call(func=ast.Name(id='get',ctx=ast.Load()),args=[node.args[0],ast.Constant(FACTS_LENGTH)],keywords=[])
                if node.func.id=='byte':node.args[1]=ast.BinOp(left=ast.Constant(FACTS_BASE),op=ast.Add(),right=node.args[1])
            return node
    g=namespace(ast.unparse(ast.fix_missing_locations(FactsView().visit(gtree))),'G_')
    ftree=ast.parse(frontend_source())
    # Do not call the single-program root decoder: use its exact body renderer
    # only after workspace policy and capture-avoiding materialization.
    functions={n.name:n for n in ftree.body};reachable={'render_function'};pending=['render_function']
    while pending:
        function=pending.pop()
        for call in ast.walk(functions[function]):
            if (isinstance(call,ast.Call) and isinstance(call.func,ast.Name)
                    and call.func.id in functions and call.func.id not in reachable):
                reachable.add(call.func.id);pending.append(call.func.id)
    # Keep every reachable body/shape/resource representation control, excluding
    # only the unused second root decoder and its otherwise-unreachable helpers.
    ftree.body=[n for n in ftree.body if n.name in reachable]
    class OutputView(ast.NodeTransformer):
        def visit_Call(self,node):
            node=self.generic_visit(node)
            if (isinstance(node.func,ast.Name) and node.func.id=='store' and isinstance(node.args[0],ast.Name)
                    and node.args[0].id=='o'):
                node.args[1]=ast.BinOp(left=ast.Constant(OUTPUT_BASE),op=ast.Add(),right=node.args[1])
            return node
    # Only append_byte writes this renderer's o output.
    for n in ftree.body:
        if n.name=='append_byte': OutputView().visit(n)
    f=namespace(ast.unparse(ast.fix_missing_locations(ftree)),'F_')
    extra='\ndef M_header(out:mutbuf, arena:mutbuf) -> u64:\n'
    header='hia-asm.v1 hepta.hia.program.v8 core_workspace\nexports('
    for at in range(0,len(header),24):
        extra+='    F_emit(out, arena, '+', '.join(map(str,packed(header[at:at+24])))+')\n'
    extra+='    return 0\n\ndef M_decimal_name(o:mutbuf, start:u64, value:u64) -> u64:\n    store(o, start, 102)\n    size = 1\n    begun = False\n'
    for place in (1000,100,10,1):
        extra+=f'''    digit = 0
    while value >= {place}:
        value = value - {place}
        digit = digit + 1
    if digit != 0 or begun or {place} == 1:
        store(o, start + size, digit + 48)
        size = size + 1
        begun = True
'''
    extra+='    return size\n'
    nodes=ast.parse(TOP+extra).body+j+g+f
    assert len({n.name for n in nodes})==len(nodes)
    return nodes


def document():
    nodes=source_nodes();names={n.name:'f'+str(i) for i,n in enumerate(nodes)}
    signatures={n.name:([a.annotation.id for a in n.args.args],n.returns.id) for n in nodes}
    total=total_scalar_functions(nodes);functions=[]
    for n in nodes:
        b=Builder(n,names,signatures,total);b.statements(n.body)
        functions.append({'name':names[n.name],'params':[b.param(v) for v in b.params],
            'returns':[b.returns],'effects':['read','write','trap'],'entry':'b0','blocks':b.blocks})
    return compact_authoring_cfg({'schema':'hepta.hia.program.v8','module':'core_workspace_materialize','functions':functions})


def main():
    path=Path(__file__).resolve().parents[1]/'examples/hia_bootstrap/core_workspace_materialize.hiaasm'
    path.write_text(render_assembly(document()));print(path.name,path.stat().st_size)


if __name__=='__main__':main()
