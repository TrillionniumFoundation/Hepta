"""Native workspace JSON admission, graph policy and Core JSON materialization.

Authoring uses Python AST, execution does not use a foreign JSON value graph.
The unchanged graph algorithm is relocated into private arena regions. Each
relocated function has ONE mutable-buffer argument: no aliased loans are passed
to the verifier and no resource check is waived. General Core verification and
filesystem/build/install custody are deliberately not claimed by this image.
"""
from __future__ import annotations
import ast
import copy
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_core_module_graph import source_program as graph_source
from tools.generate_hia_core_json_frontend import source_program as frontend_source, packed
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

KEYS = ('schema', 'entry', 'modules', 'core', 'imports', 'exports', 'module',
        'functions', 'blocks', 'ops', 'op', 'attrs', 'function', 'name', 'alias', 'symbol')
NONE = (1 << 64) - 1

WORKSPACE = r'''
def workspace_json(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) > 8388608 or length(o) < 8192 or length(w) < 128:
        return 4294967294
    put(o, 48, 1048576)
    put(o, 56, 128)
    decoded_size = widen(decode_json(s, w, o))
    if decoded_size >= 4294967292:
        return decoded_size
    put(w, 48, 0)
    put(w, 56, 0)
    status = check_workspace(w)
    if status != 0:
        return status
    status = layout(w, decoded_size)
    if status != 0:
        return status
    encode_facts(w)
    status = widen(g_resolve(w))
    if status != get(w, 24):
        return status
    link_names(w)
    return render_workspace(s, o, w)

def check_workspace(w:mutbuf) -> u64:
    if shape(w, 0, K_schema | K_entry | K_modules) == 0:
        return 4294967279
    if is_workspace_schema(w, field(w, 0, K_schema)) == 0:
        return 4294967279
    entry = field(w, 0, K_entry)
    modules = field(w, 0, K_modules)
    if kind(w, entry) != 4 or kind(w, modules) != 5 or count(w, modules) == 0 or count(w, modules) > 1024:
        return 4294967279
    put(w, 0, count(w, modules))
    put(w, 8, 0)
    put(w, 16, 0)
    put(w, 24, 0)
    put(w, 32, 0)
    put(w, 40, count(w, entry))
    module = child(w, modules)
    schema = field(w, field(w, module, K_core), K_schema)
    while module != NONE:
        status = check_module(w, module, schema)
        if status != 0:
            return status
        if get(w, 8) > 1024 or get(w, 16) > 4096 or get(w, 24) > 16384 or get(w, 32) > 1024 or get(w, 40) > 8388608:
            return 4294967279
        module = next_node(w, module)
    return 0

def check_module(w:mutbuf, module:u64, schema:u64) -> u64:
    if shape(w, module, K_core | K_imports | K_exports) == 0:
        return 4294967279
    core = field(w, module, K_core)
    if shape(w, core, K_schema | K_module | K_functions) == 0:
        return 4294967279
    current_schema = field(w, core, K_schema)
    if is_core_schema(w, current_schema) == 0 or text_equal(w, schema, current_schema) == 0:
        return 4294967279
    name = field(w, core, K_module)
    functions = field(w, core, K_functions)
    imports = field(w, module, K_imports)
    exports = field(w, module, K_exports)
    if kind(w, name) != 4 or kind(w, functions) != 5 or kind(w, imports) != 5 or kind(w, exports) != 5:
        return 4294967279
    put(w, 8, get(w, 8) + count(w, functions))
    put(w, 16, get(w, 16) + count(w, imports))
    put(w, 32, get(w, 32) + count(w, exports))
    ns = count(w, name)
    status = check_functions(w, functions)
    if status >= 4294960000:
        return status
    ns = ns + status
    item = child(w, imports)
    while item != NONE:
        if shape(w, item, K_alias | K_module | K_symbol) == 0:
            return 4294967279
        a = field(w, item, K_alias)
        b = field(w, item, K_module)
        c = field(w, item, K_symbol)
        if kind(w, a) != 4 or kind(w, b) != 4 or kind(w, c) != 4:
            return 4294967279
        ns = ns + count(w, a) + count(w, b) + count(w, c)
        item = next_node(w, item)
    item = child(w, exports)
    while item != NONE:
        if kind(w, item) != 4:
            return 4294967279
        ns = ns + count(w, item)
        item = next_node(w, item)
    put(w, 40, get(w, 40) + ns)
    return 0

def check_functions(w:mutbuf, functions:u64) -> u64:
    ns = 0
    fn = child(w, functions)
    while fn != NONE:
        name = field(w, fn, K_name)
        blocks = field(w, fn, K_blocks)
        if kind(w, fn) != 6 or kind(w, name) != 4 or kind(w, blocks) != 5:
            return 4294967279
        ns = ns + count(w, name)
        block = child(w, blocks)
        while block != NONE:
            ops = field(w, block, K_ops)
            if kind(w, block) != 6 or kind(w, ops) != 5:
                return 4294967279
            op = child(w, ops)
            while op != NONE:
                if kind(w, op) != 6:
                    return 4294967279
                if is_call(w, field(w, op, K_op)) != 0:
                    attrs = field(w, op, K_attrs)
                    target = field(w, attrs, K_function)
                    if kind(w, attrs) != 6 or kind(w, target) != 4:
                        return 4294967279
                    put(w, 24, get(w, 24) + 1)
                    ns = ns + count(w, target)
                op = next_node(w, op)
            block = next_node(w, block)
        fn = next_node(w, fn)
    return ns

def layout(w:mutbuf, decoded_size:u64) -> u64:
    nm = get(w, 0)
    nf = get(w, 8)
    ni = get(w, 16)
    nc = get(w, 24)
    nx = get(w, 32)
    ns = get(w, 40)
    entry = field(w, 0, K_entry)
    fact_size = 80 + 32 * (nm + nf) + 56 * ni + 24 * (nc + nx) + ns
    if fact_size > 8388608:
        return 4294967279
    result_size = 64 + 8 * (nm + ni + nc + nx)
    fact_base = (decoded_size + 7) & 18446744073709551608
    work_base = fact_base + fact_size
    table_base = work_base + result_size + 8 * (nf + nm)
    names_base = table_base + nf * 24 + nc * 8
    if length(w) < names_base + nf * 24:
        return 4294967294
    # Decoding has finished. Only reserved/global arena words are reused;
    # node records and decoded strings remain intact until native serialization.
    put(w, 0, fact_base)
    put(w, 8, fact_size)
    put(w, 16, work_base)
    put(w, 24, result_size)
    put(w, 32, table_base)
    put(w, 40, 0)
    fput(w, 0, MAGIC)
    fput(w, 8, nm)
    fput(w, 16, nf)
    fput(w, 24, ni)
    fput(w, 32, nc)
    fput(w, 40, nx)
    fput(w, 48, ns)
    fput(w, 56, 0)
    fput(w, 64, count(w, entry))
    fput(w, 72, 0)
    copy_name(w, entry)
    return 0

def encode_facts(w:mutbuf) -> u64:
    nm = g_uint(w, 8)
    nf = g_uint(w, 16)
    ni = g_uint(w, 24)
    nc = g_uint(w, 32)
    table_base = get(w, 32)
    modules = field(w, 0, K_modules)
    mi = 0
    fi = 0
    ii = 0
    ci = 0
    xi = 0
    module = child(w, modules)
    while module != NONE:
        core = field(w, module, K_core)
        functions = field(w, core, K_functions)
        at = 80 + mi * 32
        fact_name(w, at, field(w, core, K_module))
        fput(w, at + 16, fi)
        fput(w, at + 24, count(w, functions))
        ci = encode_functions(w, functions, mi, fi, ci)
        fi = fi + count(w, functions)
        item = child(w, field(w, module, K_imports))
        while item != NONE:
            at = 80 + (nm + nf) * 32 + ii * 56
            fput(w, at, mi)
            fact_name(w, at + 8, field(w, item, K_alias))
            fact_name(w, at + 24, field(w, item, K_module))
            fact_name(w, at + 40, field(w, item, K_symbol))
            ii = ii + 1
            item = next_node(w, item)
        item = child(w, field(w, module, K_exports))
        while item != NONE:
            at = 80 + (nm + nf) * 32 + ni * 56 + nc * 24 + xi * 24
            fput(w, at, mi)
            fact_name(w, at + 8, item)
            xi = xi + 1
            item = next_node(w, item)
        mi = mi + 1
        module = next_node(w, module)
    return 0

def encode_functions(w:mutbuf, functions:u64, mi:u64, fi:u64, ci:u64) -> u64:
    nm = g_uint(w, 8)
    nf = g_uint(w, 16)
    ni = g_uint(w, 24)
    table_base = get(w, 32)
    fn = child(w, functions)
    while fn != NONE:
        put(w, table_base + fi * 24, fn)
        at = 80 + nm * 32 + fi * 32
        fput(w, at, mi)
        fact_name(w, at + 8, field(w, fn, K_name))
        fput(w, at + 24, 0)
        block = child(w, field(w, fn, K_blocks))
        while block != NONE:
            op = child(w, field(w, block, K_ops))
            while op != NONE:
                if is_call(w, field(w, op, K_op)) != 0:
                    target = field(w, field(w, op, K_attrs), K_function)
                    at = 80 + (nm + nf) * 32 + ni * 56 + ci * 24
                    fput(w, at, fi)
                    fact_name(w, at + 8, target)
                    put(w, table_base + nf * 24 + ci * 8, target)
                    ci = ci + 1
                op = next_node(w, op)
            block = next_node(w, block)
        fi = fi + 1
        fn = next_node(w, fn)
    return ci

def link_names(w:mutbuf) -> u64:
    nm = g_uint(w, 8)
    nf = g_uint(w, 16)
    ni = g_uint(w, 24)
    nc = g_uint(w, 32)
    table_base = get(w, 32)
    names_base = table_base + nf * 24 + nc * 8
    fi = 0
    while fi < nf:
        name_node = field(w, get(w, table_base + fi * 24), K_name)
        start = get(w, 64 + name_node * 56 + 24)
        size = count(w, name_node)
        if public_target(w, fi) == 0:
            suffix = fi
            start = names_base + fi * 24
            size = make_name(w, start, suffix)
            while name_used(w, start, size, fi) != 0:
                suffix = suffix + 1
                size = make_name(w, start, suffix)
        put(w, table_base + fi * 24 + 8, start)
        put(w, table_base + fi * 24 + 16, size)
        fi = fi + 1
    fi = 0
    while fi < nf:
        name_node = field(w, get(w, table_base + fi * 24), K_name)
        rename(w, name_node, fi)
        fi = fi + 1
    ci = 0
    while ci < nc:
        target = g_get(w, 64 + (nm + ni + ci) * 8)
        rename(w, get(w, table_base + nf * 24 + ci * 8), target)
        ci = ci + 1
    return 0

def render_workspace(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    nm = g_uint(w, 8)
    nf = g_uint(w, 16)
    ni = g_uint(w, 24)
    nc = g_uint(w, 32)
    nx = g_uint(w, 40)
    table_base = get(w, 32)
    modules = field(w, 0, K_modules)
    schema = field(w, field(w, child(w, modules), K_core), K_schema)
    emit(o, w, L_open)
    render_fragment(s, o, w, schema)
    emit(o, w, L_functions)
    fi = 0
    while fi < nf:
        if fi != 0:
            append_byte(o, w, 44)
        render_fragment(s, o, w, get(w, table_base + fi * 24))
        fi = fi + 1
    emit(o, w, L_exports)
    xi = 0
    emitted = 0
    while xi < nx:
        target = g_get(w, 64 + (nm + ni + nc + xi) * 8)
        if target != NONE:
            if emitted != 0:
                append_byte(o, w, 44)
            append_string(o, w, get(w, table_base + target * 24 + 8), get(w, table_base + target * 24 + 16))
            emitted = emitted + 1
        xi = xi + 1
    emit(o, w, L_close)
    if get(w, 48) != 0:
        return get(w, 48)
    return get(w, 56)

def fput(w:mutbuf, at:u64, value:u64) -> u64:
    return put(w, get(w, 0) + at, value)

def copy_name(w:mutbuf, node:u64) -> u64:
    cursor = get(w, 40)
    source = get(w, 64 + node * 56 + 24)
    size = count(w, node)
    dest = get(w, 0) + g_strings(w) + cursor
    i = 0
    while i < size:
        store(w, dest + i, byte(w, source + i))
        i = i + 1
    put(w, 40, cursor + size)
    return cursor

def fact_name(w:mutbuf, at:u64, node:u64) -> u64:
    fput(w, at, copy_name(w, node))
    fput(w, at + 8, count(w, node))
    return 0

def text_equal(w:mutbuf, a:u64, b:u64) -> u64:
    if kind(w, a) != 4 or kind(w, b) != 4:
        return 0
    return bytes_equal(w, get(w, 64 + a * 56 + 24), count(w, a), get(w, 64 + b * 56 + 24), count(w, b))

def bytes_equal(w:mutbuf, a:u64, n:u64, b:u64, m:u64) -> u64:
    if n != m:
        return 0
    i = 0
    while i < n:
        if byte(w, a + i) != byte(w, b + i):
            return 0
        i = i + 1
    return 1

def public_target(w:mutbuf, fi:u64) -> u64:
    # The mandatory native graph has already set its per-function export bit
    # and resolved the exact entry module. Read those results, not a repeated
    # scan of all public slots inside each capture-avoidance comparison.
    if g_get(w, get(w, 24) + fi * 8) == 0:
        return 0
    return choose(g_row(w, 1, fi, 0) == g_get(w, 48), 1, 0)

def name_used(w:mutbuf, start:u64, size:u64, fi:u64) -> u64:
    nf = g_uint(w, 16)
    table = get(w, 32)
    j = 0
    while j < nf:
        if public_target(w, j) != 0:
            node = field(w, get(w, table + j * 24), K_name)
            if bytes_equal(w, start, size, get(w, 64 + node * 56 + 24), count(w, node)) != 0:
                return 1
        if j < fi:
            if bytes_equal(w, start, size, get(w, table + j * 24 + 8), get(w, table + j * 24 + 16)) != 0:
                return 1
        j = j + 1
    return 0

def make_name(w:mutbuf, start:u64, suffix:u64) -> u64:
    store(w, start, 102)
    # At most 1024 public and 1023 prior internal names can conflict, so a
    # starting index <=1023 always finds a free suffix below 3072.
    divisor = 1000
    size = 1
    while divisor != 0:
        digit = 0
        while suffix >= divisor:
            suffix = suffix - divisor
            digit = digit + 1
        if digit != 0 or size != 1 or divisor == 1:
            store(w, start + size, 48 + digit)
            size = size + 1
        if divisor == 1:
            divisor = 0
        else:
            if divisor == 10:
                divisor = 1
            else:
                if divisor == 100:
                    divisor = 10
                else:
                    divisor = 100
    return size

def rename(w:mutbuf, node:u64, fi:u64) -> u64:
    table = get(w, 32) + fi * 24
    put(w, 64 + node * 56 + 24, get(w, table + 8))
    put(w, 64 + node * 56 + 32, get(w, table + 16))
    return 0
'''


def relocated_graph():
    """Mechanically preserve graph policy, relocating only buffer addressing."""
    tree = ast.parse(graph_source())
    signatures = {fn.name: [a.arg for a in fn.args.args if a.annotation.id in ('readbuf', 'mutbuf')]
                  for fn in tree.body}

    def expr(text):
        return ast.parse(text, mode='eval').body

    class Relocate(ast.NodeTransformer):
        def visit_Call(self, node):
            # Inspect original buffer roles before replacing arguments.
            name = node.func.id if isinstance(node.func, ast.Name) else None
            if name in signatures:
                args = [a for a in node.args if not (isinstance(a, ast.Name) and a.id in ('s', 'o', 'w'))]
                return ast.Call(func=ast.Name(id='region_' + name, ctx=ast.Load()),
                                args=[expr('w'),expr('graph_source_base'),expr('graph_work_base'),
                                      *[self.visit(a) for a in args]], keywords=[])
            if name in ('length', 'byte', 'store') and isinstance(node.args[0], ast.Name):
                role = node.args[0].id
                if role in ('s', 'o', 'w'):
                    if name == 'length':
                        return expr({'s': 'get(w, 8)', 'o': 'get(w, 24)',
                                     'w': 'length(w) - graph_work_base'}[role])
                    base='graph_source_base' if role == 's' else 'graph_work_base'
                    offset = ast.BinOp(left=expr(base),
                                       op=ast.Add(), right=self.visit(node.args[1]))
                    return ast.Call(func=copy.deepcopy(node.func), args=[expr('w'), offset,
                                    *[self.visit(a) for a in node.args[2:]]], keywords=[])
            return self.generic_visit(node)

    wrappers=[]
    for fn in tree.body:
        original=copy.deepcopy(fn)
        fn.name = 'region_' + fn.name
        fn.args.args = [ast.arg(arg='w', annotation=ast.Name(id='mutbuf', ctx=ast.Load())),
                        ast.arg(arg='graph_source_base',annotation=ast.Name(id='u64',ctx=ast.Load())),
                        ast.arg(arg='graph_work_base',annotation=ast.Name(id='u64',ctx=ast.Load())),
                        *[a for a in fn.args.args if a.annotation.id not in ('readbuf', 'mutbuf')]]
        relocate=Relocate()
        fn.body = [relocate.visit(n) for n in fn.body]
        # Pass immutable scalar region offsets through the graph call tree.
        # Re-reading an eight-byte base in every scalar word accessor made the
        # complete, unchanged 1024/4096 graph exceed its original CPU budget.
        # These are NOT pointer/loan aliases and do not alter graph decisions.
        wrapper=copy.deepcopy(original)
        wrapper.name='g_'+original.name
        scalars=[a for a in original.args.args if a.annotation.id not in ('readbuf','mutbuf')]
        wrapper.args.args=[ast.arg(arg='w',annotation=ast.Name(id='mutbuf',ctx=ast.Load())),*scalars]
        wrapper.body=[ast.Return(value=ast.Call(func=ast.Name(id=fn.name,ctx=ast.Load()),
            args=[expr('w'),expr('get(w, 0)'),expr('get(w, 16)'),
                  *[ast.Name(id=a.arg,ctx=ast.Load()) for a in scalars]],keywords=[]))]
        wrappers.append(wrapper)
    # Only entry/accessor facades used outside the relocated graph are needed.
    return tree.body+[f for f in wrappers if f.name in ('g_resolve','g_uint','g_get','g_strings','g_row')]


def source_program():
    # Reuse the exact qualified JSON decoder and canonical subtree serializer.
    helpers = ast.parse(frontend_source()).body
    keep = {'kind', 'count', 'child', 'field', 'shape', 'same', 'text_is', 'emit',
            'render_fragment', 'append_byte', 'append_string', 'hex_digit',
            'next_node', 'key_less', 'sort_object'}
    decoder_index = next(i for i, n in enumerate(helpers) if n.name == 'decode_json')
    helpers = [n for n in helpers[:decoder_index] if n.name in keep] + helpers[decoder_index:]
    append = next(n for n in helpers if n.name == 'append_byte')
    append.body = ast.parse('''
index = get(w, 56)
if index >= 8388608 or index >= length(o):
    put(w, 48, 4294967278)
else:
    store(o, index, value)
    put(w, 56, index + 1)
return 0
''').body
    key = ['def key_id(w:mutbuf, node:u64) -> u64:',
           '    start = get(w, 64 + node * 56 + 40)', '    size = get(w, 64 + node * 56 + 48)']
    for i, name in enumerate(KEYS):
        key += ['    if same(w, start, size, ' + ', '.join(map(str, packed(name))) + ') != 0:',
                '        return ' + str(1 << i)]
    key += ['    return 0']
    literals = {'L_open': '{"module":"core_workspace","schema":',
                'L_functions': ',"functions":[', 'L_exports': '],"exports":[', 'L_close': ']}'}
    # Literals can exceed the three-word emit helper: expand into safe chunks.
    class Expand(ast.NodeTransformer):
        def visit_Expr(self, node):
            if isinstance(node.value, ast.Call) and node.value.func.id == 'emit':
                label = node.value.args[-1]
                if isinstance(label, ast.Name) and label.id in literals:
                    raw = literals[label.id]
                    return [ast.Expr(value=ast.Call(func=ast.Name(id='emit', ctx=ast.Load()),
                            args=[ast.Name(id='o',ctx=ast.Load()), ast.Name(id='w',ctx=ast.Load()),
                                  *[ast.Constant(x) for x in packed(raw[i:i+24])]], keywords=[]))
                            for i in range(0,len(raw),24)]
            return self.generic_visit(node)
        def visit_Name(self, node):
            if node.id.startswith('K_') and node.id[2:] in KEYS:
                return ast.Constant(1 << KEYS.index(node.id[2:]))
            if node.id == 'NONE': return ast.Constant(NONE)
            if node.id == 'MAGIC': return ast.Constant(int.from_bytes(b'HIAMOD01','little'))
            return node
    primary = Expand().visit(ast.parse(WORKSPACE)).body
    literal_functions = []
    from hepta.hia_schema import PRIMITIVE_SCHEMAS
    for name, values in [('is_workspace_schema', ['hepta.hia.core-workspace.v1']),
                         ('is_core_schema', sorted(PRIMITIVE_SCHEMAS)), ('is_call', ['call'])]:
        lines = ['def '+name+'(w:mutbuf, node:u64) -> u64:',
                 '    if kind(w, node) != 4:', '        return 0',
                 '    start = get(w, 64 + node * 56 + 24)']
        for value in values:
            raw = value.encode()
            chunks=[value[i:i+24] for i in range(0,len(value),24)]
            conditions=['same(w, start + '+str(i*24)+', '+str(len(chunk))+', '+
                        ', '.join(map(str,packed(chunk)))+') != 0' for i,chunk in enumerate(chunks)]
            lines += ['    if count(w, node) == '+str(len(raw))+':',
                      '        if '+' and '.join(conditions)+':',
                      '            return 1']
        lines += ['    return 0']
        literal_functions += ast.parse('\n'.join(lines)).body
    body = primary + relocated_graph() + ast.parse('\n'.join(key)).body + literal_functions + helpers
    assert len({n.name for n in body}) == len(body)
    return ast.unparse(ast.fix_missing_locations(ast.Module(body=body,type_ignores=[])))


def document():
    nodes = ast.parse(source_program()).body
    names = {n.name:'f'+str(i) for i,n in enumerate(nodes)}
    signatures = {n.name:([a.annotation.id for a in n.args.args],n.returns.id) for n in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        b = Builder(node,names,signatures,total)
        b.statements(node.body)
        functions.append({'name':names[node.name],'params':[b.param(v) for v in b.params],
                          'returns':[b.returns],'effects':['read','write','trap'],'entry':'b0','blocks':b.blocks})
    return compact_authoring_cfg({'schema':'hepta.hia.program.v8','module':'core_workspace_json','functions':functions})


if __name__ == '__main__':
    path = Path(__file__).resolve().parents[1]/'examples/hia_bootstrap/core_workspace_json.hiaasm'
    path.write_text(render_assembly(document()))
    print(path.name,path.stat().st_size)
