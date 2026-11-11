"""Author complete primitive Core function-shape admission, not body semantics.

Consumes raw JSON with the full existing Core byte/node/depth/block ceilings.
No assembly-emitter grammar, compiler function limit or export limit is reused.
Both buffers are private scratch; the result is the u32 status, not buffer bytes.
"""
import ast
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_core_json_frontend import FRONTEND, KEYS, packed
from tools.generate_hia_json_decode import source_program as decoder_source
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

TYPES = ('i8','i16','i32','i64','u8','u16','u32','u64','isize','usize',
         'bool','unit','buffer','chain','readbuf','mutbuf')
ERRORS = {'FORMAT': 0xfffffffb, 'NAME': 0xfffffffa, 'TYPE': 0xfffffff9,
          'LOAN': 0xfffffff8, 'EFFECT': 0xfffffff7, 'CFG': 0xfffffff6,
          'SSA': 0xfffffff5}

SOURCE = r'''
def function_shape(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < 128 or length(o) < 128:
        return 4294967293
    flags = get(w, 40)
    if flags > 3:
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
    put(o, 0, 0)
    put(o, 8, 4)
    put(o, 16, slots)
    put(o, 24, 0)
    put(o, 32, base)
    at = 128
    while at < base:
        put(o, at, 0)
        at = at + 24
    fields = K_name | K_params | K_returns | K_effects | K_entry | K_blocks
    origins = field(w, 0, K_return_loans)
    if (flags & 2) != 0 and origins != NONE:
        fields = fields | K_return_loans
    if shape(w, 0, fields) == 0:
        return FORMAT
    name = field(w, 0, K_name)
    if identifier(w, name) == 0 or runtime_name(w, name) != 0:
        return NAME
    params = field(w, 0, K_params)
    error = parameters(w, o, params, 1)
    if error != 0:
        return error
    returns = field(w, 0, K_returns)
    if kind(w, returns) != 5:
        return TYPE
    item = child(w, returns)
    while item != NONE:
        typ = type_id(w, item)
        if typ == 0:
            return TYPE
        if typ == T_chain:
            put(o, 24, 1)
        if typ >= T_readbuf and (flags & 2) == 0:
            return LOAN
        item = next_node(w, item)
    if (flags & 2) != 0:
        if origins != NONE:
            if kind(w, origins) != 5 or count(w, origins) != count(w, returns):
                return LOAN
        item = child(w, returns)
        origin = child(w, origins)
        while item != NONE:
            typ = type_id(w, item)
            if typ < T_readbuf:
                if origin != NONE and kind(w, origin) != 0:
                    return LOAN
            else:
                if kind(w, origin) != 4:
                    return LOAN
                parameter_type = symbol(w, o, origin, 1, 0, 0)
                if parameter_type != T_readbuf and parameter_type != T_mutbuf:
                    return LOAN
                if typ == T_mutbuf and parameter_type != T_mutbuf:
                    return LOAN
            item = next_node(w, item)
            if origin != NONE:
                origin = next_node(w, origin)
    effects = field(w, 0, K_effects)
    if kind(w, effects) != 5:
        return EFFECT
    item = child(w, effects)
    seen_effects = 0
    while item != NONE:
        flag = effect_id(w, item)
        if flag == 0 or (seen_effects & flag) != 0:
            return EFFECT
        seen_effects = seen_effects | flag
        item = next_node(w, item)
    entry = field(w, 0, K_entry)
    if identifier(w, entry) == 0:
        return NAME
    blocks = field(w, 0, K_blocks)
    if kind(w, blocks) != 5 or count(w, blocks) == 0 or count(w, blocks) > 4096:
        return CFG
    block = child(w, blocks)
    index = 0
    while block != NONE:
        if shape(w, block, K_id | K_params | K_ops | K_term) == 0:
            return FORMAT
        name = field(w, block, K_id)
        if identifier(w, name) == 0:
            return NAME
        if symbol(w, o, name, 2, 1, index) != NONE:
            return CFG
        put(o, base + index * 32, block)
        put(o, base + index * 32 + 8, NONE)
        put(o, base + index * 32 + 16, NONE)
        put(o, base + index * 32 + 24, 0)
        error = parameters(w, o, field(w, block, K_params), fresh(o))
        if error != 0:
            return error
        ops = field(w, block, K_ops)
        if kind(w, ops) != 5:
            return FORMAT
        ins = child(w, ops)
        while ins != NONE:
            if shape(w, ins, K_op | K_args | K_out | K_attrs) == 0:
                return FORMAT
            if kind(w, field(w, ins, K_op)) != 4:
                return FORMAT
            error = names(w, field(w, ins, K_args))
            if error != 0:
                return error
            error = parameters(w, o, field(w, ins, K_out), fresh(o))
            if error != 0:
                return error
            if kind(w, field(w, ins, K_attrs)) != 6:
                return FORMAT
            ins = next_node(w, ins)
        error = definitions(w, o, field(w, block, K_params))
        if error != 0:
            return error
        ins = child(w, ops)
        while ins != NONE:
            error = definitions(w, o, field(w, ins, K_out))
            if error != 0:
                return error
            ins = next_node(w, ins)
        error = terminator(w, field(w, block, K_term))
        if error != 0:
            return error
        index = index + 1
        block = next_node(w, block)
    entry_index = symbol(w, o, entry, 2, 0, 0)
    if entry_index == NONE:
        return CFG
    entry_block = get(o, base + entry_index * 32)
    if same_parameters(w, params, field(w, entry_block, K_params)) == 0:
        return CFG
    index = 0
    while index < count(w, blocks):
        block = get(o, base + index * 32)
        term = field(w, block, K_term)
        op = field(w, term, K_op)
        if text_is(w, op, L_jump) != 0:
            error = connect(w, o, term, entry_index, base + index * 32 + 8)
            if error != 0:
                return error
        if text_is(w, op, L_branch) != 0:
            error = connect(w, o, field(w, term, K_then), entry_index, base + index * 32 + 8)
            if error != 0:
                return error
            error = connect(w, o, field(w, term, K_else), entry_index, base + index * 32 + 16)
            if error != 0:
                return error
        index = index + 1
    queue = base + 4096 * 32
    put(o, queue, entry_index)
    put(o, base + entry_index * 32 + 24, 1)
    first = 0
    last = 1
    while first < last:
        index = get(o, queue + first * 8)
        edge_offset = 8
        while edge_offset <= 16:
            target = get(o, base + index * 32 + edge_offset)
            if target != NONE:
                if get(o, base + target * 32 + 24) == 0:
                    put(o, base + target * 32 + 24, 1)
                    put(o, queue + last * 8, target)
                    last = last + 1
            edge_offset = edge_offset + 8
        first = first + 1
    if last != count(w, blocks):
        return CFG
    if (flags & 1) == 0 and get(o, 24) != 0:
        return TYPE
    return 0

def fresh(o:mutbuf) -> u64:
    result = get(o, 8)
    put(o, 8, result + 1)
    return result

def parameters(w:mutbuf, o:mutbuf, array:u64, namespace:u64) -> u64:
    if kind(w, array) != 5:
        return FORMAT
    item = child(w, array)
    while item != NONE:
        if shape(w, item, K_name | K_type) == 0:
            return FORMAT
        name = field(w, item, K_name)
        if identifier(w, name) == 0:
            return NAME
        typ = type_id(w, field(w, item, K_type))
        if typ == 0:
            return TYPE
        if typ == T_chain:
            put(o, 24, 1)
        if symbol(w, o, name, namespace, 1, typ) != NONE:
            return SSA
        item = next_node(w, item)
    return 0

def definitions(w:mutbuf, o:mutbuf, array:u64) -> u64:
    item = child(w, array)
    while item != NONE:
        if symbol(w, o, field(w, item, K_name), 3, 1, 0) != NONE:
            return SSA
        item = next_node(w, item)
    return 0

def names(w:mutbuf, array:u64) -> u64:
    if kind(w, array) != 5:
        return FORMAT
    item = child(w, array)
    while item != NONE:
        if identifier(w, item) == 0:
            return NAME
        item = next_node(w, item)
    return 0

def edge(w:mutbuf, node:u64) -> u64:
    if shape(w, node, K_target | K_args) == 0:
        return FORMAT
    if identifier(w, field(w, node, K_target)) == 0:
        return NAME
    return names(w, field(w, node, K_args))

def terminator(w:mutbuf, node:u64) -> u64:
    if kind(w, node) != 6:
        return CFG
    op = field(w, node, K_op)
    if text_is(w, op, L_ret) != 0:
        if shape(w, node, K_op | K_values) == 0:
            return FORMAT
        return names(w, field(w, node, K_values))
    if text_is(w, op, L_jump) != 0:
        if shape(w, node, K_op | K_target | K_args) == 0:
            return FORMAT
        if identifier(w, field(w, node, K_target)) == 0:
            return NAME
        return names(w, field(w, node, K_args))
    if text_is(w, op, L_branch) != 0:
        if shape(w, node, K_op | K_cond | K_then | K_else) == 0:
            return FORMAT
        if identifier(w, field(w, node, K_cond)) == 0:
            return NAME
        error = edge(w, field(w, node, K_then))
        if error != 0:
            return error
        return edge(w, field(w, node, K_else))
    if text_is(w, op, L_trap) != 0:
        if shape(w, node, K_op | K_code) == 0:
            return FORMAT
        if trap_id(w, field(w, node, K_code)) == 0:
            return CFG
        return 0
    return CFG

def connect(w:mutbuf, o:mutbuf, edge_node:u64, entry:u64, destination:u64) -> u64:
    target = symbol(w, o, field(w, edge_node, K_target), 2, 0, 0)
    if target == NONE or target == entry:
        return CFG
    block = get(o, get(o, 32) + target * 32)
    if count(w, field(w, edge_node, K_args)) != count(w, field(w, block, K_params)):
        return CFG
    put(o, destination, target)
    return 0

def same_parameters(w:mutbuf, left:u64, right:u64) -> u64:
    if count(w, left) != count(w, right):
        return 0
    a = child(w, left)
    b = child(w, right)
    while a != NONE:
        if same_text(w, field(w, a, K_name), field(w, b, K_name)) == 0:
            return 0
        if type_id(w, field(w, a, K_type)) != type_id(w, field(w, b, K_type)):
            return 0
        a = next_node(w, a)
        b = next_node(w, b)
    return 1

def identifier(w:mutbuf, node:u64) -> u64:
    if kind(w, node) != 4 or count(w, node) == 0 or count(w, node) > 128:
        return 0
    start = get(w, 64 + node * 56 + 24)
    if count(w, node) >= 6:
        if same(w, start, 6, 6, 104871984914271, 0, 0) != 0:
            return 0
    i = 0
    while i < count(w, node):
        ch = byte(w, start + i)
        valid = (ch >= 65 and ch <= 90) or (ch >= 97 and ch <= 122) or ch == 95
        if i > 0:
            valid = valid or (ch >= 48 and ch <= 57)
        if valid == False:
            return 0
        i = i + 1
    return 1

def same_text(w:mutbuf, left:u64, right:u64) -> u64:
    if count(w, left) != count(w, right):
        return 0
    a = get(w, 64 + left * 56 + 24)
    b = get(w, 64 + right * 56 + 24)
    i = 0
    while i < count(w, left):
        if byte(w, a + i) != byte(w, b + i):
            return 0
        i = i + 1
    return 1

def symbol(w:mutbuf, o:mutbuf, node:u64, namespace:u64, insert:u64, value:u64) -> u64:
    hash_value = namespace
    start = get(w, 64 + node * 56 + 24)
    i = 0
    while i < count(w, node):
        hash_value = (hash_value ^ byte(w, start + i)) * 1099511628211
        i = i + 1
    mask = get(o, 16) - 1
    slot = hash_value & mask
    while True:
        record = 128 + slot * 24
        previous_namespace = get(o, record)
        if previous_namespace == 0:
            if insert != 0:
                put(o, record, namespace)
                put(o, record + 8, node)
                put(o, record + 16, value)
            return NONE
        if previous_namespace == namespace:
            if same_text(w, node, get(o, record + 8)) != 0:
                return get(o, record + 16)
        slot = (slot + 1) & mask
    return NONE
'''


def source_program():
    constants = {'K_'+name: 1<<i for i,name in enumerate(KEYS)}
    constants.update({'NONE': (1<<64)-1, **ERRORS})
    constants.update({'T_'+name:i+1 for i,name in enumerate(TYPES)})
    literals = {'L_'+x:packed(x) for x in ('ret','jump','branch','trap')}
    class Expand(ast.NodeTransformer):
        def visit_Name(self,node):
            return ast.copy_location(ast.Constant(constants[node.id]),node) if node.id in constants else node
        def visit_Call(self,node):
            node=self.generic_visit(node);args=[]
            for arg in node.args:
                args.extend(ast.Constant(x) for x in literals[arg.id]) if isinstance(arg,ast.Name) and arg.id in literals else args.append(arg)
            node.args=args;return node
    helpers=[n for n in ast.parse(FRONTEND).body if n.name in {'kind','count','child','field','shape','same','text_is'}]
    tree=Expand().visit(ast.parse(SOURCE+'\n'+ast.unparse(ast.Module(body=helpers,type_ignores=[]))))
    text=ast.unparse(ast.fix_missing_locations(tree))+'\n'
    key_fn=['def key_id(w:mutbuf, node:u64) -> u64:',
            '    start = get(w, 64 + node * 56 + 40)', '    size = get(w, 64 + node * 56 + 48)']
    for i,key in enumerate(KEYS):
        key_fn += ['    if same(w, start, size, '+', '.join(map(str,packed(key)))+') != 0:', '        return '+str(1<<i)]
    key_fn += ['    return 0']
    text+='\n'.join(key_fn)+'\n'
    for name,words in [('type_id',TYPES),('effect_id',('alloc','read','write','trap')),
                       ('trap_id',('user','overflow','division_by_zero','bounds','allocation')),
                       ('runtime_name',('abort','calloc','malloc','free','memcpy','memmove','memset'))]:
        text+='def '+name+'(w:mutbuf, node:u64) -> u64:\n'
        for i,word in enumerate(words):
            text+='    if text_is(w, node, '+', '.join(map(str,packed(word)))+') != 0:\n        return '+str((1<<i) if name=='effect_id' else i+1)+'\n'
        text+='    return 0\n'
    return text+'\ndef next_node(w:mutbuf, node:u64) -> u64:\n    return get(w, 64 + node * 56 + 16)\n'+decoder_source()


def document():
    nodes=ast.parse(source_program()).body
    names={n.name:'f'+str(i) for i,n in enumerate(nodes)}
    signatures={n.name:([a.annotation.id for a in n.args.args],n.returns.id) for n in nodes}
    total=total_scalar_functions(nodes);functions=[]
    for node in nodes:
        b=Builder(node,names,signatures,total);b.statements(node.body)
        functions.append({'name':names[node.name],'params':[b.param(v) for v in b.params],
                          'returns':[b.returns],'effects':['read','write','trap'],'entry':'b0','blocks':b.blocks})
    return compact_authoring_cfg({'schema':'hepta.hia.program.v8','module':'function_shape','functions':functions})


if __name__=='__main__':
    path=Path(__file__).resolve().parents[1]/'examples/hia_bootstrap/function_shape.hepta'
    path.write_text(render_assembly(document()));print(path.name,path.stat().st_size)
