"""Author complete nominal module aggregation and export policy in HIA.

The owner requests original function producers in order, then observes their
complete retained helper suffix. Inventory refusal and sorted scalar exports
remain after all function production. Complete objects cross only the generic
external-value pool boundary; their instructions are not reconstructed here.
"""
from __future__ import annotations
import ast
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from hepta.hia_opcodes import SCALARS
from tools.generate_hia_core_json_frontend import packed
from tools.generate_hia_instruction_policy import SOURCE as TRANSPORT_SOURCE
from tools.generate_hia_enum_match import BODY as MATCH_BODY
from tools.generate_hia_task_helpers import BODY as HELPER_BODY, PRIMITIVES
from tools.hia_native_value_graph import BODY as GRAPH_BODY
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

MAGIC = int.from_bytes(b'HIANMD01', 'little')
INPUT_BYTES = 256 << 20
OUTPUT_BYTES = 8 << 20
WORKSPACE_BYTES = 8 << 20
CONSTANTS = {'MAGIC': MAGIC, 'INPUT_BYTES': INPUT_BYTES, 'O_BYTES': OUTPUT_BYTES,
    'W_BYTES': WORKSPACE_BYTES, 'S': 4096, 'P': 8192, 'T': 16384,
    'SG': 4210688, 'FT': 4218880, 'N': (1 << 64) - 1, 'ABI': 0xfffffff1}

BODY = r'''
def nominal_module(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) > INPUT_BYTES or length(o) < O_BYTES or length(w) < W_BYTES:
        return ABI
    i = 0
    while i < 64:
        put(w, S + i, 0)
        i = i + 8
    if get(o, 0) != MAGIC or get(o, 56) != 0:
        return ABI
    if get(w, P) == 0:
        if initialize(s, o, w) == 0:
            return ABI
    else:
        if get(w, P) != MAGIC or get(w, P + 16) == 4:
            return ABI
        if get(o, 8) != get(w, P + 8) or get(o, 16) != get(w, P + 16):
            return ABI
        if continuation(s, o, w) == 0:
            return ABI
    if get(w, S + 32) != 0:
        return ABI
    put(w, S + 24, 64)
    if get(w, P + 16) == 4 and get(w, P + 64) == 0:
        render(s, o, w)
    else:
        graph_null(o, w)
    if get(w, S + 32) != 0:
        return ABI
    put(o, 0, MAGIC)
    put(o, 8, get(w, P + 64))
    put(o, 16, choose(get(w, P + 16) == 4, 0, get(w, P + 16)))
    put(o, 24, get(w, P + 24))
    put(o, 32, get(w, P + 8))
    put(o, 40, get(w, S + 24) - 64)
    put(o, 48, get(w, P + 32) + 1)
    put(o, 56, 0)
    return get(w, S + 24)

def metadata(s:readbuf, w:mutbuf, capture:u64) -> u64:
    if tag(s, 0) != 5 or total(s, 0) < 4:
        return 0
    at = 24
    stop = end(s, element(s, 0, 3))
    if stop - 24 > 512:
        return 0
    if capture == 0 and get(w, P + 96) != stop - 24:
        return 0
    put(w, P + 96, stop - 24)
    while at < stop:
        if capture != 0:
            store(w, P + 256 + at - 24, byte(s, at))
        elif byte(w, P + 256 + at - 24) != byte(s, at):
            return 0
        at = at + 1
    return 1

def initialize(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if get(o, 8) != 0 or get(o, 16) != 0 or get(o, 24) != 0 or get(o, 32) != 0 or get(o, 40) != 0 or get(o, 48) != 0:
        return 0
    if validate(s, w) == 0:
        return 0
    if tag(s, 0) != 5 or total(s, 0) != 4:
        return 0
    schema = schema_id(s, element(s, 0, 0))
    count = unsigned(s, element(s, 0, 2))
    if schema == 0 or name_status(s, element(s, 0, 1)) != 0 or count == 0 or count > 1024:
        return 0
    nonce = element(s, 0, 3)
    if tag(s, nonce) != 4 or size_of(s, nonce) != 32:
        return 0
    i = 0
    while i < 128:
        put(w, P + i, 0)
        i = i + 8
    put(w, P, MAGIC)
    put(w, P + 8, 1)
    put(w, P + 16, 1)
    put(w, P + 32, count)
    if metadata(s, w, 1) == 0:
        return 0
    put(w, P + 88, schema)
    return 1

def continuation(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if validate(s, w) == 0 or metadata(s, w, 0) == 0:
        return 0
    if get(w, P + 16) != 3 and total(s, 0) != 4:
        return 0
    if get(w, P + 16) == 1:
        return accept_function(o, w)
    if get(w, P + 16) == 2:
        return accept_helpers(o, w)
    if get(w, P + 16) == 3:
        if get(o, 24) != 0 or get(o, 32) != 0 or get(o, 40) != 0 or get(o, 48) != 0:
            return 0
        if total(s, 0) != 6 or signatures(s, w) == 0:
            return 0
        put(w, P + 16, 4)
        return 1
    return 0

def accept_function(o:mutbuf, w:mutbuf) -> u64:
    index = get(w, P + 24)
    if get(o, 24) != index or get(o, 32) != index or get(o, 48) != 0:
        return 0
    put(w, FT + index * 8, get(o, 32))
    if get(o, 40) > 4096:
        put(w, P + 48, 1)
    put(w, P + 8, get(w, P + 8) + 1)
    put(w, P + 24, index + 1)
    if index + 1 == get(w, P + 32):
        put(w, P + 16, 2)
        put(w, P + 24, 0)
    return 1

def accept_helpers(o:mutbuf, w:mutbuf) -> u64:
    count = get(o, 40)
    if get(o, 24) != 0 or get(o, 32) != get(w, P + 32):
        return 0
    if count > 262144 or get(o, 48) != count * 8 or 64 + count * 8 > O_BYTES:
        return 0
    put(w, FT + get(w, P + 32) * 8, get(o, 32))
    if count > 1024 - get(w, P + 32) or get(w, P + 48) != 0:
        put(w, P + 64, 1)
        put(w, P + 16, 4)
        return 1
    i = 0
    while i < count:
        if get(o, 64 + i * 8) > 4096:
            put(w, P + 64, 1)
            put(w, P + 16, 4)
            return 1
        i = i + 1
    put(w, P + 8, get(w, P + 8) + 1)
    put(w, P + 24, 0)
    put(w, P + 16, 3)
    return 1

def descriptor_ok(s:readbuf, node:u64) -> u64:
    if tag(s, node) != 5 or total(s, node) != 2:
        return 0
    kind = kind_id(s, element(s, node, 0))
    flat = element(s, node, 1)
    if kind == 0 or tag(s, flat) != 5 or total(s, flat) > 512:
        return 0
    if kind == 1 and total(s, flat) != 1:
        return 0
    at = flat + 24
    i = 0
    while i < total(s, flat):
        if type_id(s, at) == 0:
            return 0
        at = end(s, at)
        i = i + 1
    return 1

def type_list(s:readbuf, w:mutbuf, node:u64) -> u64:
    if tag(s, node) != 5 or total(s, node) > 262144:
        return 0
    result = 1
    at = node + 24
    i = 0
    while i < total(s, node):
        ident = unsigned(s, at)
        if ident >= get(w, P + 40):
            return 0
        descriptor = get(w, T + ident * 8)
        if kind_id(s, element(s, descriptor, 0)) != 1:
            result = 2
        elif scalar_id(s, element(s, element(s, descriptor, 1), 0)) == 0:
            result = 2
        at = end(s, at)
        i = i + 1
    return result

def before(s:readbuf, a:u64, b:u64) -> u64:
    i = 0
    count = size_of(s, a)
    if size_of(s, b) < count:
        count = size_of(s, b)
    while i < count:
        left = byte(s, a + 16 + i)
        right = byte(s, b + 16 + i)
        if left != right:
            return choose(left < right, 1, 0)
        i = i + 1
    return choose(size_of(s, a) < size_of(s, b), 1, 0)

def signatures(s:readbuf, w:mutbuf) -> u64:
    types = element(s, 0, 4)
    rows = element(s, 0, 5)
    if tag(s, types) != 5 or tag(s, rows) != 5 or total(s, types) > 524288 or total(s, rows) > 1024:
        return 0
    put(w, P + 40, total(s, types))
    at = types + 24
    i = 0
    while i < total(s, types):
        if descriptor_ok(s, at) == 0:
            return 0
        put(w, T + i * 8, at)
        at = end(s, at)
        i = i + 1
    at = rows + 24
    i = 0
    count = 0
    while i < total(s, rows):
        if tag(s, at) != 5 or total(s, at) != 3:
            return 0
        name = element(s, at, 0)
        if name_status(s, name) != 0:
            return 0
        params = type_list(s, w, element(s, at, 1))
        returns = type_list(s, w, element(s, at, 2))
        if params == 0 or returns == 0:
            return 0
        if params == 1 and returns == 1:
            j = count
            while j > 0 and before(s, name, get(w, SG + (j - 1) * 8)) != 0:
                put(w, SG + j * 8, get(w, SG + (j - 1) * 8))
                j = j - 1
            put(w, SG + j * 8, name)
            count = count + 1
        at = end(s, at)
        i = i + 1
    put(w, P + 80, count)
    return 1

def graph_pool_concat(o:mutbuf, w:mutbuf, originals:u64, count:u64) -> u64:
    graph_word(o, w, 11)
    graph_word(o, w, 8 + count * 8)
    graph_word(o, w, count)
    i = 0
    while i < count:
        graph_word(o, w, get(w, originals + i * 8))
        i = i + 1
    return 0

def render(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    root = graph_begin(o, w, 6, 4)
    graph_string(o, w, L_schema)
    schema = get(w, P + 88)
    if schema == 1:
        graph_string(o, w, L_v6)
    elif schema == 4:
        graph_string(o, w, L_v8)
    else:
        graph_string(o, w, L_v7)
    graph_string(o, w, L_module)
    graph_ref(o, w, element(s, 0, 1))
    graph_string(o, w, L_exports)
    exports = graph_begin(o, w, 5, get(w, P + 80))
    i = 0
    while i < get(w, P + 80):
        graph_ref(o, w, get(w, SG + i * 8))
        i = i + 1
    graph_end(o, w, exports)
    graph_string(o, w, L_functions)
    graph_pool_concat(o, w, FT, get(w, P + 32) + 1)
    graph_end(o, w, root)
    return 0
'''


def source_program():
    literals = {'L_' + key: packed(value) for key, value in
                [('schema','schema'),('module','module'),('exports','exports'),('functions','functions'),
                 ('v6','hepta.hia.program.v6'),('v7','hepta.hia.program.v7'),('v8','hepta.hia.program.v8')]}
    class Expand(ast.NodeTransformer):
        def visit_Name(self, node):
            return ast.Constant(CONSTANTS[node.id]) if node.id in CONSTANTS else node
        def visit_Call(self, node):
            node = self.generic_visit(node); args=[]
            for arg in node.args:
                if isinstance(arg, ast.Name) and arg.id in literals:
                    args.extend(ast.Constant(value) for value in literals[arg.id])
                else: args.append(arg)
            node.args=args;return node
    own=ast.parse(BODY)
    common={'validate','word','put','get','tag','size_of','end','total','element','text_is','same_text'}
    raw=TRANSPORT_SOURCE.replace('    DISPATCH','    pass').replace('1048576','8388608')
    own.body.extend(n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef) and n.name in common)
    shared={'unsigned','prefix','name_status'}
    raw=MATCH_BODY.replace('if value > 262144:', 'if value > 524288:')
    own.body.extend(n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef) and n.name in shared)
    own.body.extend(ast.parse(GRAPH_BODY).body)
    own.body.extend(n for n in ast.parse(HELPER_BODY).body if isinstance(n,ast.FunctionDef) and n.name in {'append_byte','emit'})
    own=Expand().visit(own);suffix=[]
    for fn,values in [('type_id',enumerate(PRIMITIVES,1)),('scalar_id',enumerate(sorted(SCALARS),1)),
        ('kind_id',enumerate(('primitive','record','enum','task','partial_record'),1)),
        ('schema_id',enumerate(('hepta.hia.composite.v1','hepta.hia.composite.v2','hepta.hia.composite.v3','hepta.hia.composite.v4'),1))]:
        suffix.append('def '+fn+'(s:readbuf, node:u64) -> u64:')
        for ident,value in values:
            suffix+=['    if text_is(s, node, '+', '.join(map(str,packed(value)))+') != 0:', '        return '+str(ident)]
        suffix+=['    return 0']
    return ast.unparse(ast.fix_missing_locations(own))+'\n'+'\n'.join(suffix)+'\n'


def document():
    nodes=ast.parse(source_program()).body
    assert len({n.name for n in nodes})==len(nodes)
    names={n.name:'f'+str(i) for i,n in enumerate(nodes)}
    sigs={n.name:([a.annotation.id for a in n.args.args],n.returns.id) for n in nodes}
    total=total_scalar_functions(nodes);functions=[]
    for n in nodes:
        b=Builder(n,names,sigs,total);b.statements(n.body)
        functions.append({'name':names[n.name],'params':[b.param(p) for p in b.params],
            'returns':[b.returns],'effects':['read','write','trap'],'entry':'b0','blocks':b.blocks})
    return compact_authoring_cfg({'schema':'hepta.hia.program.v8','module':'nominal_module','functions':functions})


if __name__=='__main__':
    path=Path(__file__).resolve().parents[1]/'examples/hia_bootstrap/nominal_module.hepta'
    path.write_text(render_assembly(document()));print(path.name,path.stat().st_size)
