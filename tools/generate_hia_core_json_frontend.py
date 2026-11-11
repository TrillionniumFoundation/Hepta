"""Author the HIA primitive JSON-Core representation frontend.

The image emits bounded assembly for the existing native HIA compiler. It is
not a semantic Core verifier by itself, a linker, or the production CLI.
"""
from __future__ import annotations
import ast
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_json_canonical import SOURCE as CANONICAL_SOURCE
from tools.generate_hia_json_decode import source_program as decoder_source
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

KEYS = ('schema','module','functions','exports','name','params','returns','effects',
        'entry','blocks','return_loans','id','ops','term','op','args','out','attrs',
        'values','target','cond','then','else','code','type')

FRONTEND = r'''
def render_core(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < 128 or length(o) < 128:
        return 4294967293
    output_profile = get(w, 40)
    put(o, 48, get(w, 48))
    put(o, 56, get(w, 56))
    result = widen(decode_json(s, w, o))
    if result >= 4294967292:
        return result
    put(w, 48, 0)
    put(w, 56, 0)
    fields = K_schema | K_module | K_functions
    exports = field(w, 0, K_exports)
    if exports != 18446744073709551615:
        fields = fields | K_exports
        if kind(w, exports) != 5 or count(w, exports) == 0 or count(w, exports) > 128:
            return 4294967291
    if shape(w, 0, fields) == 0:
        return 4294967291
    if text_is(w, field(w, 0, K_schema), L_hepta_hia_program_v8) == 0:
        return 4294967291
    module = field(w, 0, K_module)
    # Require operator selection in addition to the legacy assembly label.
    # JSON module metadata cannot silently switch the artifact's output ABI.
    if output_profile > 2:
        return 4294967291
    if text_is(w, module, L_selfhost_exec) == 1:
        if output_profile != 2 or exports != 18446744073709551615:
            return 4294967291
    else:
        if exports != 18446744073709551615 or text_is(w, module, L_selfhost_elf) == 1:
            if output_profile != 1:
                return 4294967291
        else:
            if output_profile != 0:
                return 4294967291
    emit(o, w, L_header)
    emit(o, w, L_hepta_hia_program_v8)
    emit(o, w, L_space)
    token(o, w, module, 0)
    emit(o, w, L_lf)
    if exports != 18446744073709551615:
        emit(o, w, L_exports_open)
        tokens(o, w, exports, 0)
        emit(o, w, L_close_lf)
    functions = field(w, 0, K_functions)
    if kind(w, functions) != 5 or count(w, functions) == 0:
        return 4294967291
    fn = child(w, functions)
    while fn != 18446744073709551615:
        render_function(s, o, w, fn)
        fn = next_node(w, fn)
    if get(w, 48) != 0:
        return get(w, 48)
    return get(w, 56)

def render_function(s:readbuf, o:mutbuf, w:mutbuf, fn:u64) -> u64:
    fields = K_name | K_params | K_returns | K_effects | K_entry | K_blocks
    loans = field(w, fn, K_return_loans)
    if loans != 18446744073709551615:
        fields = fields | K_return_loans
    if shape(w, fn, fields) == 0:
        return fail(w)
    emit(o, w, L_fn)
    token(o, w, field(w, fn, K_name), 0)
    emit(o, w, L_open)
    parameters(o, w, field(w, fn, K_params), 0)
    emit(o, w, L_returns)
    tokens(o, w, field(w, fn, K_returns), 0)
    emit(o, w, L_effects)
    tokens(o, w, field(w, fn, K_effects), 0)
    emit(o, w, L_entry)
    token(o, w, field(w, fn, K_entry), 0)
    emit(o, w, L_close)
    if loans != 18446744073709551615:
        if kind(w, loans) != 5:
            return fail(w)
        emit(o, w, L_loans)
        render_fragment(s, o, w, loans)
        emit(o, w, L_close)
    emit(o, w, L_lf)
    blocks = field(w, fn, K_blocks)
    if kind(w, blocks) != 5 or count(w, blocks) == 0:
        return fail(w)
    block = child(w, blocks)
    while block != 18446744073709551615:
        render_block(s, o, w, block)
        block = next_node(w, block)
    emit(o, w, L_end)
    return 0

def render_block(s:readbuf, o:mutbuf, w:mutbuf, block:u64) -> u64:
    if shape(w, block, K_id | K_params | K_ops | K_term) == 0:
        return fail(w)
    emit(o, w, L_block)
    token(o, w, field(w, block, K_id), 0)
    emit(o, w, L_open)
    parameters(o, w, field(w, block, K_params), 0)
    emit(o, w, L_close_lf)
    ops = field(w, block, K_ops)
    if kind(w, ops) != 5:
        return fail(w)
    ins = child(w, ops)
    while ins != 18446744073709551615:
        render_instruction(s, o, w, ins)
        ins = next_node(w, ins)
    emit(o, w, L_indent)
    term = field(w, block, K_term)
    op = field(w, term, K_op)
    if text_is(w, op, L_ret) == 1:
        if shape(w, term, K_op | K_values) == 0:
            return fail(w)
        emit(o, w, L_ret_open)
        tokens(o, w, field(w, term, K_values), 0)
        emit(o, w, L_close)
    else:
        if text_is(w, op, L_jump) == 1:
            if shape(w, term, K_op | K_target | K_args) == 0:
                return fail(w)
            emit(o, w, L_jump_space)
            edge(o, w, term)
        else:
            if text_is(w, op, L_branch) == 1:
                if shape(w, term, K_op | K_cond | K_then | K_else) == 0:
                    return fail(w)
                emit(o, w, L_branch_space)
                token(o, w, field(w, term, K_cond), 0)
                emit(o, w, L_space)
                left = field(w, term, K_then)
                right = field(w, term, K_else)
                if shape(w, left, K_target | K_args) == 0 or shape(w, right, K_target | K_args) == 0:
                    return fail(w)
                edge(o, w, left)
                emit(o, w, L_space)
                edge(o, w, right)
            else:
                if text_is(w, op, L_trap) == 1:
                    if shape(w, term, K_op | K_code) == 0:
                        return fail(w)
                    emit(o, w, L_trap_space)
                    token(o, w, field(w, term, K_code), 0)
                else:
                    return fail(w)
    emit(o, w, L_lf)
    return 0

def render_instruction(s:readbuf, o:mutbuf, w:mutbuf, ins:u64) -> u64:
    if shape(w, ins, K_op | K_args | K_out | K_attrs) == 0:
        return fail(w)
    emit(o, w, L_indent)
    parameters(o, w, field(w, ins, K_out), 1)
    emit(o, w, L_equal)
    token(o, w, field(w, ins, K_op), 1)
    emit(o, w, L_open)
    tokens(o, w, field(w, ins, K_args), 0)
    emit(o, w, L_close)
    attrs = field(w, ins, K_attrs)
    if kind(w, attrs) != 6:
        return fail(w)
    if count(w, attrs) > 0:
        emit(o, w, L_space)
        render_fragment(s, o, w, attrs)
    emit(o, w, L_lf)
    return 0

def edge(o:mutbuf, w:mutbuf, edge_node:u64) -> u64:
    token(o, w, field(w, edge_node, K_target), 0)
    emit(o, w, L_open)
    tokens(o, w, field(w, edge_node, K_args), 0)
    emit(o, w, L_close)
    return 0

def parameters(o:mutbuf, w:mutbuf, array:u64, underscore:u64) -> u64:
    if kind(w, array) != 5:
        return fail(w)
    if underscore == 1 and count(w, array) == 0:
        emit(o, w, L_underscore)
    item = child(w, array)
    while item != 18446744073709551615:
        if shape(w, item, K_name | K_type) == 0:
            return fail(w)
        token(o, w, field(w, item, K_name), 0)
        emit(o, w, L_colon)
        token(o, w, field(w, item, K_type), 0)
        item = next_node(w, item)
        if item != 18446744073709551615:
            emit(o, w, L_comma)
    return 0

def tokens(o:mutbuf, w:mutbuf, array:u64, dots:u64) -> u64:
    if kind(w, array) != 5:
        return fail(w)
    item = child(w, array)
    while item != 18446744073709551615:
        token(o, w, item, dots)
        item = next_node(w, item)
        if item != 18446744073709551615:
            emit(o, w, L_comma)
    return 0

def token(o:mutbuf, w:mutbuf, node:u64, dots:u64) -> u64:
    if kind(w, node) != 4:
        return fail(w)
    start = get(w, 64 + node * 56 + 24)
    size = count(w, node)
    if size == 0 or size > 128:
        return fail(w)
    i = 0
    while i < size:
        ch = byte(w, start + i)
        valid = (ch >= 65 and ch <= 90) or (ch >= 97 and ch <= 122) or ch == 95
        if i > 0:
            valid = valid or (ch >= 48 and ch <= 57) or (dots == 1 and ch == 46)
        if valid:
            append_byte(o, w, ch)
        else:
            return fail(w)
        i = i + 1
    return 0

def fail(w:mutbuf) -> u64:
    put(w, 48, 4294967291)
    return 0

def kind(w:mutbuf, node:u64) -> u64:
    if node == 18446744073709551615:
        return 18446744073709551615
    return get(w, 64 + node * 56)

def count(w:mutbuf, node:u64) -> u64:
    if node == 18446744073709551615:
        return 0
    return get(w, 64 + node * 56 + 32)

def child(w:mutbuf, node:u64) -> u64:
    if kind(w, node) != 5 and kind(w, node) != 6:
        return 18446744073709551615
    return get(w, 64 + node * 56 + 24)

def field(w:mutbuf, node:u64, flag:u64) -> u64:
    if kind(w, node) != 6:
        return 18446744073709551615
    item = child(w, node)
    while item != 18446744073709551615:
        if key_id(w, item) == flag:
            return item
        item = next_node(w, item)
    return 18446744073709551615

def shape(w:mutbuf, node:u64, expected:u64) -> u64:
    if kind(w, node) != 6:
        return 0
    actual = 0
    item = child(w, node)
    while item != 18446744073709551615:
        flag = key_id(w, item)
        if flag == 0:
            return 0
        actual = actual | flag
        item = next_node(w, item)
    return choose(actual == expected, 1, 0)

def same(w:mutbuf, start:u64, size:u64, n:u64, a:u64, b:u64, c:u64) -> u64:
    if size != n:
        return 0
    i = 0
    while i < n:
        word = a
        shift = i * 8
        if i >= 8:
            word = b
            shift = (i - 8) * 8
        if i >= 16:
            word = c
            shift = (i - 16) * 8
        if byte(w, start + i) != ((word >> shift) & 255):
            return 0
        i = i + 1
    return 1

def text_is(w:mutbuf, node:u64, n:u64, a:u64, b:u64, c:u64) -> u64:
    if kind(w, node) != 4:
        return 0
    return same(w, get(w, 64 + node * 56 + 24), count(w, node), n, a, b, c)

def emit(o:mutbuf, w:mutbuf, n:u64, a:u64, b:u64, c:u64) -> u64:
    i = 0
    while i < n:
        word = a
        shift = i * 8
        if i >= 8:
            word = b
            shift = (i - 8) * 8
        if i >= 16:
            word = c
            shift = (i - 16) * 8
        append_byte(o, w, (word >> shift) & 255)
        i = i + 1
    return 0
'''

LITERALS = {'hepta_hia_program_v8':'hepta.hia.program.v8',
 'selfhost_elf':'selfhost_elf','selfhost_exec':'selfhost_exec',
 'exports_open':'exports(', 'header':'hia-asm.v1 ','lf':'\n','fn':'fn ',
 'open':'(','returns':') -> (','effects':') effects(','entry':') entry(',
 'close':')','loans':' return_loans(','end':'end\n','block':'block ',
 'close_lf':')\n','indent':'  ','ret':'ret','ret_open':'ret(',
 'jump':'jump','jump_space':'jump ','branch':'branch','branch_space':'branch ',
 'trap':'trap','trap_space':'trap ','space':' ','equal':' = ',
 'underscore':'_','colon':':','comma':','}


def packed(value):
    raw=value.encode('utf-8')
    assert len(raw)<=24
    return [len(raw),*(int.from_bytes(raw[i:i+8],'little') for i in (0,8,16))]


def source_program():
    # Root first: the borrowed ABI entry is the frontend, not its JSON helper.
    frontend=ast.parse(FRONTEND)
    constants={'K_'+name:1<<i for i,name in enumerate(KEYS)}
    literals={'L_'+name:packed(value) for name,value in LITERALS.items()}
    class Expand(ast.NodeTransformer):
        def visit_Call(self,node):
            node=self.generic_visit(node)
            args=[]
            for arg in node.args:
                if isinstance(arg,ast.Name) and arg.id in literals:
                    args.extend(ast.Constant(v) for v in literals[arg.id])
                else: args.append(arg)
            node.args=args
            return node
        def visit_Name(self,node):
            if node.id in constants:return ast.Constant(constants[node.id])
            return node
    frontend=Expand().visit(frontend)
    key_fn=['def key_id(w:mutbuf, node:u64) -> u64:',
            '    start = get(w, 64 + node * 56 + 40)',
            '    size = get(w, 64 + node * 56 + 48)']
    for i,key in enumerate(KEYS):
        key_fn += ['    if same(w, start, size, '+', '.join(map(str,packed(key)))+') == 1:',
                   '        return '+str(1<<i)]
    key_fn += ['    return 0']
    canonical=ast.parse(CANONICAL_SOURCE)
    fragment=canonical.body[0]
    fragment.name='render_fragment'
    fragment.returns=ast.Name(id='u64',ctx=ast.Load())
    fragment.args.args.append(ast.arg(arg='root',annotation=ast.Name(id='u64',ctx=ast.Load())))
    cut=next(i for i,n in enumerate(fragment.body) if isinstance(n,ast.Assign) and n.targets[0].id=='node')
    fragment.body=fragment.body[cut:]
    fragment.body[0].value=ast.Name(id='root',ctx=ast.Load())
    # Treat the chosen subtree as a new root; never follow its external siblings.
    fragment=ast.unparse(ast.fix_missing_locations(fragment))
    fragment=fragment.replace('if parent != 18446744073709551615:', 'if node != root:')
    fragment=fragment.replace('sibling = get(w, record + 16)', 'sibling = choose(node == root, 18446744073709551615, get(w, record + 16))')
    fragment=fragment.replace('if parent == 18446744073709551615:', 'if node == root:')
    helpers=canonical.body[1:]
    append=helpers[0]
    append.body=ast.parse('''
index = get(w, 56)
if index >= 1048576 or index >= length(o):
    put(w, 48, 4294967290)
else:
    store(o, index, value)
    put(w, 56, index + 1)
return 0
''').body
    helpers_text=ast.unparse(ast.fix_missing_locations(ast.Module(body=helpers,type_ignores=[])))
    return (ast.unparse(ast.fix_missing_locations(frontend))+'\n'+fragment+'\n'+
            '\n'.join(key_fn)+'\n'+helpers_text+'\n'+decoder_source())


def document():
    nodes=ast.parse(source_program()).body
    names={node.name:'f'+str(i) for i,node in enumerate(nodes)}
    signatures={node.name:([a.annotation.id for a in node.args.args],node.returns.id) for node in nodes}
    total=total_scalar_functions(nodes)
    functions=[]
    for node in nodes:
        builder=Builder(node,names,signatures,total)
        builder.statements(node.body)
        functions.append({'name':names[node.name],'params':[builder.param(v) for v in builder.params],
            'returns':[builder.returns],'effects':['read','write','trap'],'entry':'b0','blocks':builder.blocks})
    return compact_authoring_cfg({'schema':'hepta.hia.program.v8','module':'core_json_frontend','functions':functions})


def main():
    path=Path(__file__).resolve().parents[1]/'examples/hia_bootstrap/core_json_frontend.hepta'
    path.write_text(render_assembly(document()))
    print(path.name,path.stat().st_size)


if __name__=='__main__':main()
