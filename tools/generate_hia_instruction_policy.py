"""Author all primitive opcode/version/signature/attribute/effect decisions.

The typed length-delimited transport preserves exact host scalar kinds. It is
not a host precomputed admission result. Guards, calls and ownership stay open.
"""
import ast
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from hepta.hia_opcodes import OPCODES, _GROUPS
from tools.generate_hia_function_shape import TYPES
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

ERRORS={'FORMAT':0xfffffffb,'TYPE':0xfffffff9,'LOAN':0xfffffff8,'OPCODE':0xfffffff0,
        'LIMIT':0xfffffffe,'ABI':0xfffffffd,'NONE':(1<<64)-1}
GROUPS=('integer','scalar','equality','owner','bytes','view','mutable_source')

SOURCE=r'''
def instruction_policy(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < 128 + 129 * 24:
        return ABI
    if length(s) > 33554432:
        return LIMIT
    if validate(s, w) == 0:
        return FORMAT
    if tag(s, 0) != 5 or total(s, 0) != 5:
        return FORMAT
    schema = element(s, 0, 0)
    op = element(s, 0, 1)
    args = element(s, 0, 2)
    out = element(s, 0, 3)
    attrs = element(s, 0, 4)
    version = schema_version(s, schema)
    if version == 0:
        return OPCODE
    DISPATCH
    return OPCODE

def local_check(s:readbuf, args:u64, out:u64, attrs:u64, a:u64, r:u64) -> u64:
    attribute = (r >> 40) & 255
    if tag(s, attrs) != 6:
        return FORMAT
    if total(s, attrs) != choose(attribute == 0, 0, 1):
        return FORMAT
    value = NONE
    if attribute != 0:
        key = attrs + 24
        if attribute_name(s, key) != attribute:
            return FORMAT
        value = end(s, key)
    if tag(s, args) != 5 or tag(s, out) != 5:
        return TYPE
    ac = a >> 56
    rc = (r >> 32) & 255
    if ac != 255:
        if total(s, args) != ac:
            return TYPE
        i = 0
        while i < ac:
            if matches(s, element(s, args, i), args, (a >> (i * 8)) & 255) == 0:
                if (a & 281474976710656) != 0:
                    return LOAN
                return TYPE
            i = i + 1
    if rc != 255:
        if total(s, out) != rc:
            return TYPE
        i = 0
        while i < rc:
            if matches(s, element(s, out, i), args, (r >> (i * 8)) & 255) == 0:
                return TYPE
            i = i + 1
    special = r >> 56
    effects = (r >> 48) & 255
    if special == 1:
        if literal(s, value, type_id(s, element(s, out, 0))) == 0:
            return TYPE
    if special == 2:
        mode = cast_mode(s, value)
        if mode == 0:
            return TYPE
        if mode == 1:
            effects = effects | 8
    return effects

def matches(s:readbuf, node:u64, args:u64, rule:u64) -> u64:
    typ = type_id(s, node)
    if rule >= 32:
        other = element(s, args, rule - 32)
        return same_text(s, node, other)
    if rule >= 17:
        return group(typ, rule)
    return choose(typ == rule, 1, 0)

def literal(s:readbuf, node:u64, typ:u64) -> u64:
    if typ == 11:
        return choose(tag(s, node) == 1, 1, 0)
    if typ == 12:
        return choose(tag(s, node) == 0, 1, 0)
    if tag(s, node) != 2 or typ == 0 or typ > 10:
        return 0
    size = size_of(s, node)
    if size == 0:
        return 0
    at = node + 16
    negative = byte(s, at) == 45
    if negative:
        at = at + 1
    if at == node + 16 + size:
        return 0
    signed = typ <= 4 or typ == 9
    tenth = literal_bound(typ, negative, 0)
    final_digit = literal_bound(typ, negative, 1)
    value = 0
    while at < node + 16 + size:
        digit = byte(s, at)
        if digit < 48 or digit > 57:
            return 0
        digit = digit - 48
        if value > tenth or (value == tenth and digit > final_digit):
            return 0
        value = value * 10 + digit
        at = at + 1
    if negative and signed == False and value != 0:
        return 0
    return 1

def validate(s:readbuf, w:mutbuf) -> u64:
    if length(s) < 16:
        return 0
    depth = 0
    put(w, 128, length(s))
    put(w, 136, 1)
    at = 0
    nodes = 0
    going = True
    while going:
        frame = 128 + depth * 24
        stop = get(w, frame)
        remaining = get(w, frame + 8)
        if remaining == 0:
            if at != stop:
                return 0
            if depth == 0:
                going = False
            else:
                depth = depth - 1
        else:
            if at > stop or stop - at < 16:
                return 0
            size = word(s, at + 8)
            if size > stop - at - 16:
                return 0
            finish = at + 16 + size
            kind = word(s, at)
            if kind > 7:
                return 0
            put(w, frame + 8, remaining - 1)
            nodes = nodes + 1
            if nodes > 1048576:
                return 0
            if kind == 5 or kind == 6:
                if size < 8 or depth == 128:
                    return 0
                children = word(s, at + 16)
                if children > 1048576:
                    return 0
                if kind == 6:
                    children = children * 2
                depth = depth + 1
                frame = 128 + depth * 24
                put(w, frame, finish)
                put(w, frame + 8, children)
                at = at + 24
            else:
                if kind == 0 and size != 0:
                    return 0
                if kind == 1:
                    if size != 1:
                        return 0
                    if byte(s, at + 16) > 1:
                        return 0
                at = finish
    return choose(at == length(s), 1, 0)

def word(s:readbuf, at:u64) -> u64:
    i = 0
    value = 0
    while i < 8:
        value = value | (byte(s, at + i) << (i * 8))
        i = i + 1
    return value

def put(w:mutbuf, at:u64, value:u64) -> u64:
    i = 0
    while i < 8:
        store(w, at + i, (value >> (i * 8)) & 255)
        i = i + 1
    return 0

def get(w:mutbuf, at:u64) -> u64:
    i = 0
    value = 0
    while i < 8:
        value = value | (byte(w, at + i) << (i * 8))
        i = i + 1
    return value

def tag(s:readbuf, node:u64) -> u64:
    return word(s, node)

def size_of(s:readbuf, node:u64) -> u64:
    return word(s, node + 8)

def end(s:readbuf, node:u64) -> u64:
    return node + 16 + size_of(s, node)

def total(s:readbuf, node:u64) -> u64:
    return word(s, node + 16)

def element(s:readbuf, node:u64, index:u64) -> u64:
    item = node + 24
    while index != 0:
        item = end(s, item)
        index = index - 1
    return item

def text_is(s:readbuf, node:u64, n:u64, a:u64, b:u64, c:u64) -> u64:
    if tag(s, node) != 4 or size_of(s, node) != n:
        return 0
    i = 0
    while i < n:
        expected = a
        if i >= 8:
            expected = b
        if i >= 16:
            expected = c
        if byte(s, node + 16 + i) != ((expected >> ((i & 7) * 8)) & 255):
            return 0
        i = i + 1
    return 1

def same_text(s:readbuf, left:u64, right:u64) -> u64:
    if tag(s, left) != 4 or tag(s, right) != 4 or size_of(s, left) != size_of(s, right):
        return 0
    i = 0
    while i < size_of(s, left):
        if byte(s, left + 16 + i) != byte(s, right + 16 + i):
            return 0
        i = i + 1
    return 1
'''


def packed(text):
    raw=text.encode('ascii');assert len(raw)<=24
    return ', '.join(map(str,[len(raw),*[int.from_bytes(raw[i:i+8],'little') for i in (0,8,16)]]))


def rules(values):
    if values is None:return 255<<56
    def code(rule):
        rule=rule.removeprefix('declared:')
        if rule.startswith('='):return 32+int(rule[1:])
        return 17+GROUPS.index(rule) if rule in GROUPS else TYPES.index(rule)+1
    return sum(code(rule)<<(i*8) for i,rule in enumerate(values)) | len(values)<<56


def source_program():
    dispatch=[]
    for spec in OPCODES.values():
        assert len(spec.attributes)<=1 and (spec.operands is None or len(spec.operands)<=5)
        a=rules(spec.operands) | ((1<<48) if spec.name in {'borrow.read','borrow.mut'} else 0)
        r=rules(spec.results)
        r=(r&((1<<32)-1)) | ((r>>56)<<32)
        attr={'value':1,'mode':2,'function':3}.get(spec.attributes[0],0) if spec.attributes else 0
        effects=sum(1<<('alloc','read','write','trap').index(v) for v in spec.effects)
        special=1 if spec.name=='const' else 2 if spec.name=='int.cast' else 0
        r|=attr<<40 | effects<<48 | special<<56
        dispatch+=['    if text_is(s, op, '+packed(spec.name)+') != 0:',
                   '        if version < '+str(spec.since)+':','            return OPCODE',
                   '        return local_check(s, args, out, attrs, '+str(a)+', '+str(r)+')']
    text=SOURCE.replace('    DISPATCH','\n'.join(dispatch))
    for name,words in [('type_id',TYPES),('schema_version',tuple('hepta.hia.program.v'+str(v) for v in range(1,9))),
                       ('attribute_name',('value','mode','function')),('cast_mode',('checked','wrap'))]:
        text+='\ndef '+name+'(s:readbuf, node:u64) -> u64:\n'
        for i,word in enumerate(words):text+='    if text_is(s, node, '+packed(word)+') != 0:\n        return '+str(i+1)+'\n'
        text+='    return 0\n'
    text+='\ndef group(typ:u64, rule:u64) -> u64:\n'
    for i,name in enumerate(GROUPS):
        ids=[TYPES.index(v)+1 for v in sorted(_GROUPS[name])]
        text+='    if rule == '+str(i+17)+':\n        return choose('+(' or '.join('typ == '+str(v) for v in ids))+', 1, 0)\n'
    text+='    return 0\n\ndef width(typ:u64) -> u64:\n'
    for i,typ in enumerate(TYPES[:10]):text+='    if typ == '+str(i+1)+':\n        return '+str(64 if typ in {'isize','usize'} else int(typ[1:]))+'\n'
    text+='    return 0\n'
    text+='\ndef literal_bound(typ:u64, negative:bool, part:u64) -> u64:\n'
    for i,typ in enumerate(TYPES[:10]):
        bits=64 if typ in {'isize','usize'} else int(typ[1:])
        signed=typ.startswith('i');high=(1<<(bits-1))-1 if signed else (1<<bits)-1
        text+='    if typ == '+str(i+1)+':\n'
        if signed:
            text+='        if negative:\n            return choose(part == 0, '+str((high+1)//10)+', '+str((high+1)%10)+')\n'
        text+='        return choose(part == 0, '+str(high//10)+', '+str(high%10)+')\n'
    text+='    return 0\n'
    class Expand(ast.NodeTransformer):
        def visit_Name(self,node):return ast.copy_location(ast.Constant(ERRORS[node.id]),node) if node.id in ERRORS else node
    return ast.unparse(ast.fix_missing_locations(Expand().visit(ast.parse(text))))+'\n'


def document():
    nodes=ast.parse(source_program()).body;names={n.name:'f'+str(i) for i,n in enumerate(nodes)}
    signatures={n.name:([a.annotation.id for a in n.args.args],n.returns.id) for n in nodes}
    total=total_scalar_functions(nodes);functions=[]
    for node in nodes:
        b=Builder(node,names,signatures,total);b.statements(node.body)
        functions.append({'name':names[node.name],'params':[b.param(v) for v in b.params],
            'returns':[b.returns],'effects':['read','write','trap'],'entry':'b0','blocks':b.blocks})
    return compact_authoring_cfg({'schema':'hepta.hia.program.v8','module':'instruction_policy','functions':functions})


if __name__=='__main__':
    path=Path(__file__).resolve().parents[1]/'examples/hia_bootstrap/instruction_policy.hepta'
    path.write_text(render_assembly(document()));print(path.name,path.stat().st_size)
