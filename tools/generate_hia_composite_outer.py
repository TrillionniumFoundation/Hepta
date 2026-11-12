"""Author complete outer nominal lowering and leased native metadata reads."""
from __future__ import annotations
import ast
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_core_json_frontend import packed
from tools.generate_hia_composite_functions import COMMON, RENDER, CONSTANTS as GENERIC
from tools.generate_hia_composite_function_admission import BODY as ADMISSION
from tools.generate_hia_instruction_policy import SOURCE as TRANSPORT
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

KEYS = ('schema', 'module', 'functions', 'name')
CONSTANTS = {**GENERIC,
    'MAGIC': int.from_bytes(b'HIAOTK01','little'),
    'STATE_MAGIC': int.from_bytes(b'HIAOTS01','little'),
    'OUTER_MAGIC': int.from_bytes(b'HIAOTR01','little'),
    'ACK_MAGIC': int.from_bytes(b'HIAOTA01','little'),
    'FAIL_MAGIC': int.from_bytes(b'HIAOTF01','little'),
    'HEADER_MAGIC': int.from_bytes(b'HIAOTH01','little'),
    'HELPER_MAGIC': int.from_bytes(b'HIATHP01','little'),
    'FUNCTION_MAGIC': int.from_bytes(b'HIAFNS01','little'),
    'TYPE_MAGIC': int.from_bytes(b'HIATYS01','little'),
    'W_BYTES': 80 << 20, 'FUNCTION_BYTES': 192 << 20, 'HELPER_BYTES': 2 << 20,
    'HELPER_OUTPUT_BYTES': 4 << 20,
    'TYPE_BYTES': 128 << 20, 'TS': 96 << 20, 'TYPES': (96 << 20)+65536,
    'OBJECTS': 1 << 63,
    **{'K_'+key:1<<i for i,key in enumerate(KEYS)},
}

BODY = r'''
def outer(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < W_BYTES:
        return ABI
    if length(o) < 64 or get(w, S + 96) != 0:
        return fatal(w)
    if get(w, S) == 0:
        if length(s) > I_BYTES or validate_packet(s, w) == 0:
            return fatal(w)
        i = 0
        while i < 384:
            put(w, S + i, 0)
            i = i + 8
        i = 0
        while i < length(s):
            store(w, SOURCE_BASE + i, byte(s, i))
            i = i + 1
        put(w, S, STATE_MAGIC)
        put(w, S + 8, ARENA)
        put(w, S + 16, length(s))
        put(w, S + 24, SOURCE_BASE)
        if initialize(w) == 0:
            return fatal(w)
        return frame(o, w, 0, 0)
    if get(w, S) != STATE_MAGIC or get(w, S + 120) == 2000:
        return fatal(w)
    if length(s) == 96:
        if word(s, 0) != HEADER_MAGIC or word(s, 8) != get(w, S + 88) or get(w, S + 120) != 22:
            return fatal(w)
        return helper_header(s, o, w)
    if length(s) == 32:
        if word(s, 8) != get(w, S + 88):
            return fatal(w)
        if word(s, 0) == FAIL_MAGIC:
            if get(w, S + 120) != 10 or word(s, 16) != 0 or word(s, 24) != 0:
                return fatal(w)
            return finish_error(o, w, 999)
        if word(s, 0) != ACK_MAGIC or word(s, 24) != get(w, S + 272):
            return fatal(w)
        phase = get(w, S + 120)
        if phase == 11 and word(s, 16) == 1:
            put(w, S + 120, 0)
        elif phase == 21 and word(s, 16) == 2:
            put(w, S + 120, 10)
        else:
            return fatal(w)
        return frame(o, w, 0, 0)
    if length(s) == TYPE_BYTES:
        if get(w, S + 120) != 0 or word(s, TS) != TYPE_MAGIC or word(s, TS + 48) != 1:
            return fatal(w)
        return next_function(s, o, w)
    if length(s) == FUNCTION_BYTES:
        if get(w, S + 120) != 10 or function_binding(s, w) == 0:
            return fatal(w)
        if word(s, S + 120) == 212 and word(s, S + 312) == 6 and word(s, S + 728) == 0:
            return helper_begin(s, o, w)
        if word(s, S + 120) == 2000 and word(s, S + 312) == 0 and word(s, S + 728) == 1:
            return function_complete(s, o, w)
        return fatal(w)
    if length(s) == HELPER_BYTES:
        if get(w, S + 120) != 20:
            return fatal(w)
        return helper_complete(s, o, w)
    return fatal(w)

def frame(o:mutbuf, w:mutbuf, action:u64, handle:u64) -> u32:
    if get(w, S + 96) != 0:
        return ABI
    put(o, 0, OUTER_MAGIC)
    put(o, 8, action)
    put(o, 16, get(w, S + 112))
    put(o, 24, get(w, S + 120))
    put(o, 32, get(w, S + 88))
    put(o, 40, handle)
    put(o, 48, get(w, S + 160))
    put(o, 56, get(w, S + 216))
    return 64

def finish_error(o:mutbuf, w:mutbuf, error:u64) -> u32:
    put(w, S + 112, error)
    put(w, S + 120, 2000)
    return frame(o, w, 1, 0)

def initialize(w:mutbuf) -> u64:
    root = SOURCE_BASE
    if g_kind(w, root) != 5 or g_count(w, root) != 6:
        return 0
    doc = g_at(w, root, 0)
    registry = g_at(w, root, 1)
    if g_integer(w, g_at(w, root, 2)) != 0 or g_integer(w, g_at(w, root, 3)) != 0:
        return 0
    helpers = g_at(w, root, 4)
    names = g_at(w, root, 5)
    if g_kind(w, helpers) != 5 or g_count(w, helpers) != 0 or g_kind(w, names) != 5 or g_count(w, names) != 0:
        return 0
    functions = g_field(w, doc, K_functions)
    count = g_count(w, functions)
    version = profile(w, g_field(w, doc, K_schema))
    if version == 0 or g_kind(w, functions) != 5 or count == 0 or count > 1024:
        return 0
    if g_kind(w, registry) != 5 or g_count(w, registry) != count:
        return 0
    put(w, S + 128, doc)
    put(w, S + 136, registry)
    put(w, S + 144, functions)
    put(w, S + 152, functions + 24)
    put(w, S + 168, count)
    put(w, S + 176, registry + 24)
    put(w, S + 184, version)
    put(w, S + 200, ir_list(w))
    put(w, S + 208, ir_list(w))
    put(w, S + 232, allocate(w, 720 * 24))
    put(w, S + 296, allocate(w, count * 8))
    return 1

def next_function(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if get(w, S + 160) == get(w, S + 168):
        return complete_program(s, o, w)
    source = get(w, S + 152)
    signature = get(w, S + 176)
    if g_kind(w, signature) != 5 or g_count(w, signature) != 3:
        return fatal(w)
    if same_text(w, g_field(w, source, K_name), g_at(w, signature, 0)) == 0:
        return fatal(w)
    command = ir_list(w)
    ir_append(w, command, ir_integer(w, 1))
    ir_append(w, command, ir_source(w, source))
    put(w, S + 88, get(w, S + 88) + 1)
    put(w, S + 120, 10)
    put(w, S + 224, get(w, S + 216))
    stream_begin(w, command, 1)
    return frame(o, w, 2, 0)

def function_binding(s:readbuf, w:mutbuf) -> u64:
    if word(s, S) != FUNCTION_MAGIC or word(s, S + 96) != 0 or word(s, S + 112) != 0:
        return 0
    if word(s, S + 280) != get(w, S + 160) or word(s, S + 16) < 16 or word(s, S + 16) > I_BYTES:
        return 0
    doc = word(s, S + 352)
    if doc < SOURCE_BASE or doc > SOURCE_BASE + word(s, S + 16) - 16:
        return 0
    if word(s, doc + 8) > SOURCE_BASE + word(s, S + 16) - doc - 16:
        return 0
    extent = 16 + word(s, doc + 8)
    own = get(w, S + 128)
    if extent != 16 + g_size(w, own) or extent > SOURCE_BASE + word(s, S + 16) - doc:
        return 0
    if get(w, S + 288) == 0:
        i = 0
        while i < extent:
            if byte(s, doc + i) != byte(w, own + i):
                return 0
            i = i + 1
        put(w, S + 288, 1)
        put(w, S + 312, doc)
        put(w, S + 320, word(s, S + 16))
    elif doc != get(w, S + 312) or word(s, S + 16) != get(w, S + 320):
        return 0
    return 1

def helper_begin(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    request = word(s, S + 88)
    serial = word(s, S + 640)
    if request <= get(w, S + 256) or serial != word(s, S + 72) or serial < get(w, S + 264) or serial > 8192:
        return fatal(w)
    put(w, S + 240, request)
    put(w, S + 248, serial)
    put(w, S + 256, request)
    put(w, S + 120, 20)
    return frame(o, w, 3, 0)

def helper_complete(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    error = word(s, S + 8)
    serial = word(s, S)
    start = get(w, S + 248)
    name = word(s, S + 56)
    if error > 3 or word(s, S + 32) != 0 or serial < start or serial > 8192:
        return fatal(w)
    expected = start + 1
    if start == 8192:
        expected = 0
    if name != expected or (error == 1 and serial != 8192):
        return fatal(w)
    if error != 1 and (name == 0 or serial < name):
        return fatal(w)
    extent = word(s, S + 24)
    if extent < 64 or extent > HELPER_OUTPUT_BYTES:
        return fatal(w)
    put(w, S + 328, error)
    put(w, S + 336, serial)
    put(w, S + 344, name)
    put(w, S + 352, word(s, S + 40))
    put(w, S + 360, extent)
    put(w, S + 120, 22)
    return frame(o, w, 7, 0)

def helper_header(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if word(s, 16) != get(w, S + 360) or word(s, 24) != HELPER_OUTPUT_BYTES:
        return fatal(w)
    if word(s, 32) != HELPER_MAGIC or word(s, 40) != get(w, S + 328):
        return fatal(w)
    if word(s, 48) != get(w, S + 336) or word(s, 56) != get(w, S + 344):
        return fatal(w)
    if word(s, 64) != get(w, S + 360) - 64 or word(s, 72) != 0 or word(s, 80) != 0 or word(s, 88) != 0:
        return fatal(w)
    error = get(w, S + 328)
    put(w, S + 264, get(w, S + 336))
    if error != 0:
        put(w, S + 120, 10)
        return frame(o, w, 6, 0)
    count = get(w, S + 352)
    index = get(w, S + 216)
    if count < 2 or count > 5 or index >= 720:
        return fatal(w)
    handle = OBJECTS + 1024 + index
    row = get(w, S + 232) + index * 24
    put(w, row, get(w, S + 240))
    put(w, row + 8, count)
    put(w, row + 16, handle)
    ir_append(w, get(w, S + 208), ir_node(w, 0, handle, 0, 0))
    put(w, S + 216, index + 1)
    if count > get(w, S + 192):
        put(w, S + 192, count)
    put(w, S + 272, handle)
    put(w, S + 120, 21)
    return frame(o, w, 5, handle)

def valid_ir(s:readbuf, node:u64, size:u64) -> u64:
    cursor = word(s, S + 8)
    if cursor < ARENA or cursor > FUNCTION_BYTES or node < ARENA or node > cursor:
        return 0
    return choose(size <= cursor - node, 1, 0)

def completed_helpers(s:readbuf, w:mutbuf) -> u64:
    root = word(s, S + 720)
    if valid_ir(s, root, 32) == 0 or word(s, root) != 5:
        return 0
    count = get(w, S + 216) - get(w, S + 224)
    if word(s, root + 24) != count:
        return 0
    segment = word(s, root + 8)
    index = 0
    while index < count:
        if valid_ir(s, segment, 32) == 0 or word(s, segment + 8) != 0 or word(s, segment + 24) != 1:
            return 0
        item = word(s, segment + 16)
        if valid_ir(s, item, 32) == 0 or word(s, item) != 2:
            return 0
        row = get(w, S + 232) + (get(w, S + 224) + index) * 24
        if word(s, item + 8) != get(w, row):
            return 0
        segment = word(s, segment)
        index = index + 1
    return choose(segment == 0, 1, 0)

def function_complete(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if word(s, S + 48) != 1 or completed_helpers(s, w) == 0:
        return fatal(w)
    blocks = word(s, S + 392)
    if valid_ir(s, blocks, 32) == 0 or word(s, blocks) != 5:
        return fatal(w)
    count = word(s, blocks + 24)
    if count > get(w, S + 192):
        put(w, S + 192, count)
    if word(s, S + 72) < get(w, S + 264) or word(s, S + 72) > 8192:
        return fatal(w)
    put(w, S + 264, word(s, S + 72))
    handle = OBJECTS + get(w, S + 160)
    ir_append(w, get(w, S + 200), ir_node(w, 0, handle, 0, 0))
    put(w, S + 152, g_end(w, get(w, S + 152)))
    put(w, S + 176, g_end(w, get(w, S + 176)))
    put(w, S + 160, get(w, S + 160) + 1)
    put(w, S + 272, handle)
    put(w, S + 120, 11)
    return frame(o, w, 4, handle)

def scalar_type(s:readbuf, identifier:u64) -> u64:
    if issued(s, identifier) == 0:
        return N
    return choose(word(s, type_at(identifier)) == 0 and identifier <= 12, 1, 0)

def signature_scalar(s:readbuf, w:mutbuf, row:u64) -> u64:
    parameters = g_at(w, row, 1)
    returns = g_at(w, row, 2)
    if g_kind(w, parameters) != 5 or g_kind(w, returns) != 5:
        return N
    item = parameters + 24
    i = 0
    eligible = 1
    while i < g_count(w, parameters):
        if g_kind(w, item) != 5 or g_count(w, item) != 2:
            return N
        result = scalar_type(s, g_integer(w, g_at(w, item, 1)))
        if result == N:
            return N
        eligible = eligible & result
        item = g_end(w, item)
        i = i + 1
    item = returns + 24
    i = 0
    while i < g_count(w, returns):
        result = scalar_type(s, g_integer(w, item))
        if result == N:
            return N
        eligible = eligible & result
        item = g_end(w, item)
        i = i + 1
    return eligible

def before(w:mutbuf, left:u64, right:u64) -> u64:
    if g_kind(w, left) != 4 or g_kind(w, right) != 4:
        fatal(w)
        return 0
    i = 0
    while i < g_size(w, left) and i < g_size(w, right):
        a = byte(w, left + 16 + i)
        b = byte(w, right + 16 + i)
        if a != b:
            return choose(a < b, 1, 0)
        i = i + 1
    return choose(g_size(w, left) < g_size(w, right), 1, 0)

def complete_program(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if get(w, S + 168) + get(w, S + 216) > 1024 or get(w, S + 192) > 4096:
        return finish_error(o, w, 1)
    registry = get(w, S + 136)
    row = registry + 24
    i = 0
    count = 0
    values = get(w, S + 296)
    while i < get(w, S + 168):
        result = signature_scalar(s, w, row)
        if result == N:
            return fatal(w)
        if result == 1:
            name = g_at(w, row, 0)
            index = count
            going = True
            while index > 0 and going:
                previous = get(w, values + (index - 1) * 8)
                if before(w, name, previous) == 0:
                    going = False
                else:
                    put(w, values + index * 8, previous)
                    index = index - 1
            put(w, values + index * 8, name)
            count = count + 1
        row = g_end(w, row)
        i = i + 1
    exports = ir_list(w)
    i = 0
    while i < count:
        ir_append(w, exports, ir_source(w, get(w, values + i * 8)))
        i = i + 1
    functions = get(w, S + 200)
    segment = get(w, get(w, S + 208) + 8)
    while segment != 0:
        ir_append(w, functions, get(w, segment + 16))
        segment = get(w, segment)
    root = ir_object(w)
    schema = ir_text(w, L_core_v7)
    if get(w, S + 184) == 1:
        schema = ir_text(w, L_core_v6)
    if get(w, S + 184) == 4:
        schema = ir_text(w, L_core_v8)
    ir_pair(w, root, ir_text(w, L_schema), schema)
    ir_pair(w, root, ir_text(w, L_module), ir_source(w, g_field(w, get(w, S + 128), K_module)))
    ir_pair(w, root, ir_text(w, L_exports), exports)
    ir_pair(w, root, ir_text(w, L_functions), functions)
    put(w, S + 120, 2000)
    stream_begin(w, root, 0)
    return frame(o, w, 2, 0)
'''


def suffix():
    lines=['def key_id(w:mutbuf, node:u64) -> u64:']
    for i,text in enumerate(KEYS):
        lines += [f'    if text_is(w, node, {", ".join(map(str,packed(text)))}) != 0:', f'        return {1<<i}']
    lines += ['    return 0','','def profile(w:mutbuf, node:u64) -> u64:']
    for i in range(1,5):
        text=', '.join(map(str,packed('hepta.hia.composite.v'+str(i))))
        lines += [f'    if text_is(w, node, {text}) != 0:',f'        return {i}']
    return '\n'.join(lines+['    return 0'])+'\n'


def source_program(kernel):
    generic_names={'type_at','issued','g_kind','g_size','g_count','g_end','g_at',
                   'g_field','g_integer','text_is','prefix','same_text'}
    generic='\n'.join(ast.unparse(node) for node in ast.parse(ADMISSION).body
                      if isinstance(node,ast.FunctionDef) and node.name in generic_names)
    validation=next(node for node in ast.parse(TRANSPORT.replace('    DISPATCH','    pass')).body
                    if isinstance(node,ast.FunctionDef) and node.name=='validate')
    validation.name='validate_packet'
    body=BODY+'\n'+generic+'\n'+suffix()+'\n'+ast.unparse(validation)
    if kernel=='render':body=RENDER.replace('def function_render(', 'def outer_render(')
    elif kernel!='owner':raise ValueError('unknown outer kernel')
    literals={'L_'+key:packed(key) for key in ('schema','module','exports','functions')}
    literals.update({'L_core_v'+str(i):packed('hepta.hia.program.v'+str(i)) for i in (6,7,8)})
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
    tree=ast.fix_missing_locations(Expand().visit(ast.parse(body+'\n'+COMMON)))
    names={node.name:node for node in tree.body};reachable={tree.body[0].name};pending=list(reachable)
    while pending:
        for node in ast.walk(names[pending.pop()]):
            if isinstance(node,ast.Call) and isinstance(node.func,ast.Name):
                name=node.func.id
                if name in names and name not in reachable:reachable.add(name);pending.append(name)
    tree.body=[node for node in tree.body if node.name in reachable]
    return ast.unparse(tree)+'\n'


def document(kernel):
    nodes=ast.parse(source_program(kernel)).body
    names={node.name:'f'+str(i) for i,node in enumerate(nodes)}
    signatures={node.name:([arg.annotation.id for arg in node.args.args],node.returns.id) for node in nodes}
    total=total_scalar_functions(nodes);functions=[]
    for node in nodes:
        builder=Builder(node,names,signatures,total);builder.statements(node.body)
        functions.append({'name':names[node.name],'params':[builder.param(p) for p in builder.params],
            'returns':[builder.returns],'effects':['read','write','trap'],'entry':'b0','blocks':builder.blocks})
    return compact_authoring_cfg({'schema':'hepta.hia.program.v8','module':'composite_outer_'+kernel,'functions':functions})


if __name__=='__main__':
    root=Path(__file__).resolve().parents[1]
    for kernel in ('owner','render'):
        target=root/('examples/hia_bootstrap/composite_outer_'+kernel+'.hepta')
        target.write_text(render_assembly(document(kernel)))
        print(target.name,target.stat().st_size)
