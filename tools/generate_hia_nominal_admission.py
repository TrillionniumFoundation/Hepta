"""Author nominal root/function declaration admission and ordered callbacks."""
from __future__ import annotations
import ast
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from hepta.hia_opcodes import EFFECTS
from hepta.hia_schema import COMPOSITE_OPERATIONS_BY_SCHEMA, LEGACY_COMPOSITE_OPERATIONS
from tools.generate_hia_core_json_frontend import packed
from tools.generate_hia_instruction_policy import SOURCE as TRANSPORT_SOURCE
from tools.generate_hia_enum_match import BODY as MATCH_BODY
from tools.generate_hia_task_helpers import BODY as HELPER_BODY, PRIMITIVES
from tools.hia_native_value_graph import BODY as GRAPH_BODY
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

MAGIC = int.from_bytes(b'HIANAD01', 'little')
INPUT_BYTES = 32 << 20
OUTPUT_BYTES = 1 << 20
WORKSPACE_BYTES = 40 << 20
FIELDS = ('schema', 'module', 'types', 'functions', 'name', 'params', 'returns',
          'effects', 'entry', 'blocks', 'return_loans', 'kind')
CONSTANTS = {'MAGIC': MAGIC, 'INPUT_BYTES': INPUT_BYTES, 'O_BYTES': OUTPUT_BYTES,
    'W_BYTES': WORKSPACE_BYTES, 'S': 4096, 'P': 8192, 'FN': 16384,
    'SOURCE_BASE': 1 << 20, 'N': (1 << 64) - 1, 'ABI': 0xfffffff1}
CONSTANTS.update({'F_' + key: index + 1 for index, key in enumerate(FIELDS)})
CONSTANTS['ROOT_KEYS'] = sum(1 << CONSTANTS['F_' + key] for key in ('schema','module','types','functions'))
CONSTANTS['FN_KEYS'] = sum(1 << CONSTANTS['F_' + key] for key in ('name','params','returns','effects','entry','blocks'))

BODY = r'''
def nominal_admission(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) > INPUT_BYTES or length(o) < O_BYTES or length(w) < W_BYTES:
        return ABI
    i = 0
    while i < 64:
        put(w, S + i, 0)
        i = i + 8
    if get(o, 0) != MAGIC or get(o, 40) != 0 or get(o, 48) != 0 or get(o, 56) != 0:
        return ABI
    if a_validate(s, w) == 0:
        return ABI
    if get(w, P) == 0:
        if initialize(s, o, w) == 0:
            return ABI
    else:
        action = get(w, P + 16)
        if get(w, P) != MAGIC or action == 0:
            return ABI
        if get(o, 8) != get(w, P + 8) or get(o, 16) != action:
            return ABI
        if get(o, 24) != position(w) or get(o, 32) != item(w):
            return ABI
        if action != 5 and action != 9 and action != 11 and a_tag(s, 0) != 0:
            return ABI
        if advance(s, w, action) == 0:
            return ABI
    if get(w, S + 32) != 0:
        return ABI
    put(w, S + 24, 64)
    render(o, w)
    if get(w, S + 32) != 0:
        return ABI
    put(o, 0, MAGIC)
    put(o, 8, get(w, P + 128))
    put(o, 16, get(w, P + 16))
    put(o, 24, position(w))
    put(o, 32, item(w))
    put(o, 40, get(w, P + 8))
    put(o, 48, get(w, S + 24) - 64)
    put(o, 56, 0)
    return get(w, S + 24)

def initialize(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if get(o, 8) != 0 or get(o, 16) != 0 or get(o, 24) != 0 or get(o, 32) != 0:
        return 0
    if a_tag(s, 0) != 5 or a_total(s, 0) != 3:
        return 0
    legacy = a_element(s, 0, 0)
    nonce = a_element(s, 0, 1)
    if a_tag(s, legacy) != 0 or a_tag(s, nonce) != 4 or a_size_of(s, nonce) != 32:
        return 0
    i = 0
    while i < 256:
        put(w, P + i, 0)
        i = i + 8
    put(w, P, MAGIC)
    capture(s, w, a_element(s, 0, 2))
    root(w)
    return 1

def capture(s:readbuf, w:mutbuf, document:u64) -> u64:
    put(w, P + 144, length(s))
    put(w, P + 136, SOURCE_BASE + document)
    i = 0
    while i < length(s):
        store(w, SOURCE_BASE + i, byte(s, i))
        i = i + 1
    return 0

def position(w:mutbuf) -> u64:
    action = get(w, P + 16)
    if action == 8:
        return get(w, P + 104)
    if action >= 4 and action <= 7:
        return get(w, P + 24)
    return 0

def item(w:mutbuf) -> u64:
    return choose(get(w, P + 16) == 5, get(w, P + 32), 0)

def request(w:mutbuf, action:u64) -> u64:
    put(w, P + 16, action)
    put(w, P + 8, get(w, P + 8) + 1)
    return 0

def refuse(w:mutbuf, error:u64) -> u64:
    put(w, P + 128, error)
    put(w, P + 16, 0)
    return 0

def missing(w:mutbuf, key:u64) -> u64:
    put(w, P + 160, key)
    return refuse(w, 15)

def unhashable(w:mutbuf, kind:u64, error:u64) -> u64:
    put(w, P + 160, kind)
    return refuse(w, error)

def fields(w:mutbuf, node:u64) -> u64:
    if tag(w, node) != 6:
        return 0
    result = 0
    at = node + 24
    i = 0
    while i < total(w, node):
        ident = field_id(w, at)
        if ident == 0 or (result & (1 << ident)) != 0:
            return 0
        result = result | (1 << ident)
        at = end(w, end(w, at))
        i = i + 1
    return result

def field(w:mutbuf, node:u64, wanted:u64) -> u64:
    if tag(w, node) != 6:
        return N
    at = node + 24
    i = 0
    while i < total(w, node):
        value = end(w, at)
        if field_id(w, at) == wanted:
            return value
        at = end(w, value)
        i = i + 1
    return N

def root(w:mutbuf) -> u64:
    doc = get(w, P + 136)
    if fields(w, doc) != ROOT_KEYS:
        return refuse(w, 1)
    schema = schema_id(w, field(w, doc, F_schema))
    if schema == 0:
        return refuse(w, 2)
    put(w, P + 40, schema)
    return request(w, 9)

def legacy_control(s:readbuf, w:mutbuf, second:bool) -> u64:
    if a_tag(s, 0) != 5 or a_total(s, 0) != 2:
        return 0
    flag = a_element(s, 0, 0)
    if a_tag(s, flag) != 1:
        return 0
    put(w, P + 48, byte(s, flag + 16))
    capture(s, w, a_element(s, 0, 1))
    schema = field(w, get(w, P + 136), F_schema)
    if second:
        if get(w, P + 48) == 0:
            if schema == N:
                missing(w, F_schema)
                return 1
            ident = schema_id(w, schema)
            if ident == 0:
                if tag(w, schema) == 5 or tag(w, schema) == 6:
                    unhashable(w, tag(w, schema), 17)
                else:
                    refuse(w, 16)
                return 1
            put(w, P + 40, ident)
        request(w, 1)
        return 1
    if get(w, P + 48) != 0:
        if schema == N:
            missing(w, F_schema)
            return 1
        if schema_id(w, schema) != 1:
            refuse(w, 3)
            return 1
    module = field(w, get(w, P + 136), F_module)
    if module == N:
        missing(w, F_module)
        return 1
    status = name_status(w, module)
    if status != 0:
        refuse(w, 3 + status)
    else:
        request(w, 10)
    return 1

def type_flags(w:mutbuf) -> u64:
    schema = field(w, get(w, P + 136), F_schema)
    if schema == N:
        return missing(w, F_schema)
    if tag(w, schema) == 5 or tag(w, schema) == 6:
        return unhashable(w, tag(w, schema), 18)
    put(w, P + 40, schema_id(w, schema))
    return request(w, 12)

def function_inventory(w:mutbuf) -> u64:
    functions = field(w, get(w, P + 136), F_functions)
    if functions == N:
        return missing(w, F_functions)
    if tag(w, functions) != 5 or total(w, functions) == 0 or total(w, functions) > 1024:
        return refuse(w, 6)
    put(w, P + 56, total(w, functions))
    put(w, P + 72, functions + 24)
    return request(w, 3)

def next_function(w:mutbuf) -> u64:
    node = get(w, P + 72)
    put(w, P + 64, node)
    wanted = FN_KEYS
    extra = get(w, P + 40) == 4 and field(w, node, F_return_loans) != N
    if extra:
        wanted = wanted | (1 << F_return_loans)
    if fields(w, node) != wanted:
        return refuse(w, choose(extra, 8, 7))
    name = field(w, node, F_name)
    status = name_status(w, name)
    if status != 0:
        return refuse(w, 8 + status)
    i = 0
    while i < get(w, P + 24):
        if same_text(w, name, get(w, FN + i * 8)) != 0:
            return refuse(w, 11)
        i = i + 1
    return request(w, 4)

def return_inventory(w:mutbuf) -> u64:
    returns = field(w, get(w, P + 64), F_returns)
    if tag(w, returns) != 5:
        return refuse(w, 12)
    put(w, P + 32, 0)
    put(w, P + 80, returns + 24)
    put(w, P + 88, total(w, returns))
    put(w, P + 96, 0)
    if total(w, returns) != 0:
        return request(w, 5)
    return after_returns(w)

def returned_type(s:readbuf, w:mutbuf) -> u64:
    if a_tag(s, 0) != 5 or a_total(s, 0) != 2:
        return 0
    kind = a_kind_id(s, a_element(s, 0, 0))
    flat = a_element(s, 0, 1)
    if kind == 0 or a_tag(s, flat) != 5 or a_total(s, flat) > 512:
        return 0
    if kind == 1 and a_total(s, flat) != 1:
        return 0
    at = flat + 24
    i = 0
    borrowed = 0
    while i < a_total(s, flat):
        typ = a_type_id(s, at)
        if typ == 0:
            return 0
        if a_loan(s, at) != 0:
            borrowed = 1
        at = a_end(s, at)
        i = i + 1
    if borrowed != 0 and (get(w, P + 40) != 4 or kind != 1):
        put(w, P + 96, 1)
    put(w, P + 32, get(w, P + 32) + 1)
    put(w, P + 80, end(w, get(w, P + 80)))
    if get(w, P + 32) < get(w, P + 88):
        request(w, 5)
    else:
        after_returns(w)
    return 1

def after_returns(w:mutbuf) -> u64:
    if get(w, P + 96) != 0:
        return refuse(w, 13)
    if get(w, P + 40) == 4:
        return request(w, 6)
    return effects(w)

def effects(w:mutbuf) -> u64:
    node = field(w, get(w, P + 64), F_effects)
    if tag(w, node) != 5:
        return refuse(w, 14)
    mask = 0
    at = node + 24
    i = 0
    while i < total(w, node):
        ident = effect_id(w, at)
        if ident == 0 or (mask & (1 << ident)) != 0:
            return refuse(w, 14)
        mask = mask | (1 << ident)
        at = end(w, at)
        i = i + 1
    return request(w, 7)

def bound(w:mutbuf) -> u64:
    node = get(w, P + 64)
    put(w, FN + get(w, P + 24) * 8, field(w, node, F_name))
    put(w, P + 72, end(w, node))
    put(w, P + 24, get(w, P + 24) + 1)
    if get(w, P + 24) < get(w, P + 56):
        return next_function(w)
    types = field(w, get(w, P + 136), F_types)
    if tag(w, types) != 5:
        put(w, S + 32, 1)
        return 0
    put(w, P + 112, types + 24)
    put(w, P + 120, total(w, types))
    return next_task(w)

def next_task(w:mutbuf) -> u64:
    while get(w, P + 104) < get(w, P + 120):
        node = get(w, P + 112)
        kind = field(w, node, F_kind)
        if kind == N:
            put(w, S + 32, 1)
            return 0
        if task_kind(w, kind) != 0:
            return request(w, 8)
        put(w, P + 104, get(w, P + 104) + 1)
        put(w, P + 112, end(w, node))
    put(w, P + 16, 0)
    return 0

def advance(s:readbuf, w:mutbuf, action:u64) -> u64:
    if action == 1:
        type_flags(w)
    elif action == 2:
        function_inventory(w)
    elif action == 3:
        next_function(w)
    elif action == 4:
        return_inventory(w)
    elif action == 5:
        return returned_type(s, w)
    elif action == 6:
        effects(w)
    elif action == 7:
        bound(w)
    elif action == 8:
        put(w, P + 104, get(w, P + 104) + 1)
        put(w, P + 112, end(w, get(w, P + 112)))
        next_task(w)
    elif action == 9:
        return legacy_control(s, w, False)
    elif action == 10:
        request(w, 11)
    elif action == 11:
        return legacy_control(s, w, True)
    elif action == 12:
        request(w, 2)
    else:
        return 0
    return 1

def graph_boolean(o:mutbuf, w:mutbuf, flag:bool) -> u64:
    graph_word(o, w, 1)
    graph_word(o, w, 1)
    append_byte(o, w, choose(flag, 1, 0))
    return 0

def graph_zero(o:mutbuf, w:mutbuf) -> u64:
    graph_word(o, w, 2)
    graph_word(o, w, 1)
    append_byte(o, w, 48)
    return 0

def graph_held_name(o:mutbuf, w:mutbuf, node:u64) -> u64:
    graph_word(o, w, 4)
    graph_word(o, w, size_of(w, node))
    i = 0
    while i < size_of(w, node):
        append_byte(o, w, byte(w, node + 16 + i))
        i = i + 1
    return 0

def render(o:mutbuf, w:mutbuf) -> u64:
    action = get(w, P + 16)
    error = get(w, P + 128)
    if error == 15:
        if get(w, P + 160) == F_schema:
            graph_string(o, w, L_schema)
        elif get(w, P + 160) == F_module:
            graph_string(o, w, L_module)
        else:
            graph_string(o, w, L_functions)
    elif error == 16:
        graph_ref(o, w, field(w, get(w, P + 136), F_schema) - SOURCE_BASE)
    elif error == 17 or error == 18:
        if get(w, P + 160) == 5:
            graph_string(o, w, L_list)
        else:
            graph_string(o, w, L_dict)
    elif action == 1:
        operation_names(o, w)
    elif action == 12:
        root = graph_begin(o, w, 6, 2)
        graph_string(o, w, L_recursive)
        graph_boolean(o, w, get(w, P + 40) != 1)
        graph_string(o, w, L_partial)
        graph_boolean(o, w, get(w, P + 40) >= 3)
        graph_end(o, w, root)
    elif action == 10:
        root = graph_begin(o, w, 6, 2)
        graph_string(o, w, L_serial)
        graph_zero(o, w)
        graph_string(o, w, L_slots)
        graph_zero(o, w)
        graph_end(o, w, root)
    elif action == 2:
        graph_boolean(o, w, get(w, P + 40) == 4)
    elif action == 6 or action == 7:
        graph_held_name(o, w, field(w, get(w, P + 64), F_name))
    else:
        graph_null(o, w)
    return 0
'''


def source_program():
    common={'word','put','get','tag','size_of','end','total','element','text_is','same_text'}
    raw=TRANSPORT_SOURCE.replace('    DISPATCH','    pass').replace('1048576','8388608')
    originals=[n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef) and n.name in common]
    class Mutable(ast.NodeTransformer):
        def visit_arg(self,node):
            if isinstance(node.annotation,ast.Name) and node.annotation.id=='readbuf':
                node.annotation=ast.Name(id='mutbuf',ctx=ast.Load())
            return node
    original_nodes=[Mutable().visit(n) for n in originals]
    incoming=common-{'put','get'}|{'validate'}
    class Incoming(ast.NodeTransformer):
        def visit_FunctionDef(self,node):
            node.name='a_'+node.name
            return self.generic_visit(node)
        def visit_Name(self,node):
            if node.id in incoming:node.id='a_'+node.id
            return node
    incoming_nodes=[Incoming().visit(n) for n in ast.parse(raw).body
                    if isinstance(n,ast.FunctionDef) and n.name in incoming]
    own=ast.parse(BODY)
    own.body+=original_nodes+incoming_nodes
    own.body += [Mutable().visit(n) for n in ast.parse(MATCH_BODY).body
                 if isinstance(n,ast.FunctionDef) and n.name in {'prefix','name_status'}]
    own.body += ast.parse(GRAPH_BODY).body
    own.body += [n for n in ast.parse(HELPER_BODY).body if isinstance(n,ast.FunctionDef) and n.name in {'append_byte','emit'}]
    literals={'L_'+key:packed(value) for key,value in [
        ('operations','nominal_operations'),('recursive','recursive_chain'),
        ('partial','partial_records'),('serial','serial'),('slots','value_slots'),
        ('schema','schema'),('module','module'),('functions','functions'),('list','list'),('dict','dict')]}
    class Expand(ast.NodeTransformer):
        def visit_Name(self,node):
            return ast.Constant(CONSTANTS[node.id]) if node.id in CONSTANTS else node
        def visit_Call(self,node):
            node=self.generic_visit(node);args=[]
            for arg in node.args:
                if isinstance(arg,ast.Name) and arg.id in literals:
                    args.extend(ast.Constant(value) for value in literals[arg.id])
                else:args.append(arg)
            node.args=args;return node
    own=Expand().visit(own)
    suffix=[]
    tables=[('field_id','mutbuf',enumerate(FIELDS,1),'text_is'),
            ('schema_id','mutbuf',enumerate(COMPOSITE_OPERATIONS_BY_SCHEMA,1),'text_is'),
            ('effect_id','mutbuf',enumerate(sorted(EFFECTS),1),'text_is'),
            ('task_kind','mutbuf',[(1,'task')],'text_is'),
            ('a_kind_id','readbuf',enumerate(('primitive','record','enum','task','partial_record'),1),'a_text_is'),
            ('a_type_id','readbuf',enumerate(PRIMITIVES,1),'a_text_is'),
            ('a_loan','readbuf',[(1,'readbuf'),(1,'mutbuf')],'a_text_is')]
    for name,kind,values,predicate in tables:
        suffix.append('def '+name+'(s:'+kind+', node:u64) -> u64:')
        for ident,value in values:
            suffix += ['    if '+predicate+'(s, node, '+', '.join(map(str,packed(value)))+') != 0:',
                       '        return '+str(ident)]
        suffix.append('    return 0')
    suffix.append('def operation_names(o:mutbuf, w:mutbuf) -> u64:')
    selections=[('get(w, 8192 + 48) != 0',LEGACY_COMPOSITE_OPERATIONS)]
    selections += [('get(w, 8192 + 40) == '+str(i),values)
                   for i,values in enumerate(COMPOSITE_OPERATIONS_BY_SCHEMA.values(),1)]
    for condition,values in selections:
        suffix += ['    if '+condition+':','        start = graph_begin(o, w, 5, '+str(len(values))+')']
        for value in sorted(values):suffix.append('        graph_string(o, w, '+', '.join(map(str,packed(value)))+')')
        suffix += ['        graph_end(o, w, start)','        return 0']
    suffix += ['    put(w, 4096 + 32, 1)','    return 0']
    return ast.unparse(ast.fix_missing_locations(own))+'\n'+'\n'.join(suffix)+'\n'


def document():
    nodes=ast.parse(source_program()).body
    assert len({n.name for n in nodes})==len(nodes)
    names={n.name:'f'+str(i) for i,n in enumerate(nodes)}
    sigs={n.name:([a.annotation.id for a in n.args.args],n.returns.id) for n in nodes}
    total=total_scalar_functions(nodes);functions=[]
    for node in nodes:
        builder=Builder(node,names,sigs,total);builder.statements(node.body)
        functions.append({'name':names[node.name],'params':[builder.param(p) for p in builder.params],
            'returns':[builder.returns],'effects':['read','write','trap'],'entry':'b0','blocks':builder.blocks})
    return compact_authoring_cfg({'schema':'hepta.hia.program.v8','module':'nominal_admission','functions':functions})


if __name__=='__main__':
    path=Path(__file__).resolve().parents[1]/'examples/hia_bootstrap/nominal_admission.hiaasm'
    path.write_text(render_assembly(document()));print(path.name,path.stat().st_size)
