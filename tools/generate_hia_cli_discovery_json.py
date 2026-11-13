"""Author a complete HIA capabilities/opcode-catalog JSON semantic component.

This file is authoring only. Runtime selection, version filtering, ordering,
JSON construction and SHA-256 are HIA. No final JSON or catalog digest is stored.
The ordinary CLI parser/formatter and all production entry routes are unchanged.
"""
from __future__ import annotations
import ast
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT=Path(__file__).resolve().parents[1]
BASE=ROOT
if __package__ in {None, ''}:
    sys.path.insert(0,str(ROOT))
TARGET=ROOT/'examples/hia_bootstrap/cli_discovery_json.hepta'
from hepta import cli
from hepta import hia_opcodes as original
from hepta.hia_schema import PRIMITIVE_PROFILES
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder,compact_authoring_cfg,total_scalar_functions
from tools.generate_hia_sha256 import source_program as sha_source
from tools.generate_hia_sha256_stream import STREAM_WORD_HELPERS

MAGIC=int.from_bytes(b'HCLJSON1','little')
WORK_BYTES=131072
TABLE_BASE=4096
STACK_BASE=32768
JSON_BASE=65536
JSON_BYTES=65536
COUNT_AT=2048
RAW_HASH=1152
HEX_HASH=1184
DEPENDENCIES=('hepta/cli.py','hepta/hia_opcodes.py','hepta/hia_schema.py',
              'tools/generate_hia_selfhost.py','tools/generate_hia_sha256.py',
              'tools/generate_hia_sha256_stream.py',
              'hepta/hia_agent_assembly.py')

class Array:
    def __init__(self,items,sort=False):self.items=items;self.sort=sort
class Marker:
    def __init__(self,kind,items=()):self.kind=kind;self.items=items

class Table:
    def __init__(self):self.nodes=[];self.intern={}
    def add(self,kind,flags,data):
        signature=(kind,flags,data)
        if signature in self.intern:return self.intern[signature]
        index=len(self.nodes)+1
        self.nodes.append((kind,flags,data));self.intern[signature]=index
        return index
    def node(self,value):
        if value is None:return self.add(0,0,0)
        if type(value)is bool:return self.add(1,0,int(value))
        if type(value)is int:
            assert 0<=value<65536
            return self.add(2,0,value)
        if type(value)is str:
            raw=value.encode('ascii')
            return self.add(3,0,raw)
        if isinstance(value,Array):
            children=tuple((self.node(item),since) for item,since in value.items)
            return self.add(4,int(value.sort),children)
        if isinstance(value,Marker):
            return self.add(value.kind,0,tuple(self.node(x) for x in value.items))
        if type(value)in(list,tuple):
            return self.node(Array([(x,1) for x in value]))
        if type(value)is dict:
            return self.add(5,0,tuple((self.node(k),self.node(v)) for k,v in value.items()))
        raise TypeError(type(value))
    def encode(self):
        offset=TABLE_BASE+len(self.nodes)*8
        payload=bytearray();headers=[]
        for kind,flags,data in self.nodes:
            n=0;value=0;extra=0
            if kind in(0,1,2):value=data
            else:
                value=offset+len(payload)
                if kind==3:
                    n=len(data);payload.extend(data)
                elif kind==4:
                    n=len(data)
                    for child,since in data:payload.extend(struct.pack('<HBB',child,since,0))
                elif kind==5:
                    n=len(data)
                    for key,child in data:payload.extend(struct.pack('<HH',key,child))
                elif kind in(6,7,8):
                    n=len(data)
                    for child in data:payload.extend(struct.pack('<H',child))
                elif kind==9:
                    value=HEX_HASH;n=64
                else:raise ValueError(kind)
            headers.append(struct.pack('<BBHHH',kind,flags,value,n,extra))
        return b''.join(headers)+payload

def structured_table():
    # Read the literal capabilities data without executing the old policy.
    source=(BASE/'hepta/cli.py').read_text()
    tree=ast.parse(source)
    action=next(n.value for n in tree.body if isinstance(n,ast.Assign) and
                any(isinstance(t,ast.Name) and t.id=='HIA_AGENT_ACTIONS' for t in n.targets))
    actions=ast.literal_eval(action)
    capfn=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='agent_capabilities')
    value=next(n.value for n in capfn.body if isinstance(n,ast.Return))
    class LiteralActions(ast.NodeTransformer):
        def visit_Call(self,node):
            assert isinstance(node.func,ast.Name) and node.func.id=='list'
            assert len(node.args)==1 and isinstance(node.args[0],ast.Name) and node.args[0].id=='HIA_AGENT_ACTIONS'
            return ast.List(elts=[ast.Constant(x) for x in actions],ctx=ast.Load())
    capabilities=ast.literal_eval(LiteralActions().visit(value))
    # Exactly one metadata table; eight profiles share all instruction records.
    def visible(values):
        return Array([(x,7 if x=='chain' else 1) for x in reversed(sorted(values))],sort=True)
    catalog={
        'schema':'hepta.hia.opcode-catalog.v1',
        'core_schema':Marker(6,tuple(PRIMITIVE_PROFILES)),
        'profile':Marker(7,tuple(PRIMITIVE_PROFILES.values())),
        'word_bits':64,
        'types':visible(original.TYPES),
        'type_groups':{k:visible(v) for k,v in original._GROUPS.items()},
        'signature_rules':{
            '=N':'same type as zero-based operand N',
            'declared:T':'explicit result type in group T',
            'null':'arity/types/effects determined by verified callee interface'},
        'instructions':Array([(asdict(spec),spec.since) for spec in original.OPCODES.values()]),
        'terminators':[{'name':name,'fields':list(fields)} for name,fields in original.TERMINATORS.items()],
        'function_contract':{'return_loans':Marker(8,(
            'loan returns forbidden','explicit formal-name/null per return; parameter origin checked'))},
        'conditional_effects':{'int.cast':'checked mode requires trap','call':'all callee effects'},
        'resource_checks':'all guards, transitions, exact CFG joins and return cleanup remain mandatory',
        'backend_scope':'VM, direct LLVM and direct x86-64 machine backends have separate supported-target/entry-ABI checks; catalog inclusion grants no native entry ABI',
        'admission_authority':'hepta.hia_program.verify_program','safety_certificate':False,
        'generated_checker_scope':'opcode/version, operand/result signatures, attributes, effects, named resource guards',
        'not_generated_or_proved':['CFG ownership algorithm','interpreter','LLVM lowering','machine code'],
        'catalog_sha256':Marker(9),
    }
    original_fn=next(n for n in ast.parse((BASE/'hepta/hia_opcodes.py').read_text()).body
                     if isinstance(n,ast.FunctionDef) and n.name=='opcode_catalog')
    declaration=next(n.value for n in original_fn.body if isinstance(n,ast.Assign) and
                     any(isinstance(t,ast.Name) and t.id=='result' for t in n.targets))
    assert set(catalog)=={ast.literal_eval(x) for x in declaration.keys}|{'catalog_sha256'}
    t=Table();cap=t.node(capabilities);cat=t.node(catalog)
    return t,cap,cat

SEMANTICS=r'''
def discovery(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 32:
        return 4294967295
    if read64(s, 0) != MAGIC:
        return 4294967295
    operation = read64(s, 8)
    mode = read64(s, 16)
    n = read64(s, 24)
    if n != length(s) - 32:
        return 4294967295
    if operation != 1 and operation != 2:
        return 4294967295
    if mode > 1 or (mode == 0 and n != 0):
        return 4294967295
    if operation == 1 and (mode != 0 or n != 0):
        return 4294967295
    version = 8
    if operation == 2 and mode == 1:
        if n != 20:
            return 4294967293
        i = 0
        while i < 19:
            if byte(s, 32 + i) != schema_prefix(i):
                return 4294967293
            i = i + 1
        version = byte(s, 51) - 48
        if version < 1 or version > 8:
            return 4294967293
    if length(w) < WORK_BYTES:
        return 4294967292
    initialize(w)
    sort_tables(w)
    root = CAP_ROOT
    if operation == 2:
        root = CAT_ROOT
        n = render(w, root, version, 0, 0)
        if n >= JSON_BYTES:
            return 4294967291
        hash_json(w, n)
        i = 0
        while i < 32:
            value = byte(w, RAW_HASH + i)
            store(w, HEX_HASH + i * 2, hex_digit(value >> 4))
            store(w, HEX_HASH + i * 2 + 1, hex_digit(value & 15))
            i = i + 1
    n = render(w, root, version, 1, 1)
    if n >= JSON_BYTES:
        return 4294967291
    emit(w, 10)
    n = get(w, COUNT_AT)
    if length(o) < n:
        return 4294967294
    i = 0
    while i < n:
        store(o, i, byte(w, JSON_BASE + i))
        i = i + 1
    return n

def schema_prefix(index:u64) -> u64:
    return 0

def record(node:u64) -> u64:
    return TABLE_BASE + (node - 1) * 8

def u16(w:mutbuf, at:u64) -> u64:
    return byte(w, at) | (byte(w, at + 1) << 8)

def u32(w:mutbuf, at:u64) -> u64:
    return u16(w, at) | (u16(w, at + 2) << 16)

def set32(w:mutbuf, at:u64, value:u64) -> u64:
    store(w, at, value & 255)
    store(w, at + 1, (value >> 8) & 255)
    store(w, at + 2, (value >> 16) & 255)
    store(w, at + 3, (value >> 24) & 255)
    return 0

def read64(s:readbuf, at:u64) -> u64:
    result = 0
    i = 0
    while i < 8:
        result = result | (byte(s, at + i) << (i * 8))
        i = i + 1
    return result

def less_string(w:mutbuf, a:u64, b:u64) -> bool:
    pa = record(a)
    pb = record(b)
    la = u16(w, pa + 4)
    lb = u16(w, pb + 4)
    aa = u16(w, pa + 2)
    bb = u16(w, pb + 2)
    i = 0
    while i < la and i < lb:
        x = byte(w, aa + i)
        y = byte(w, bb + i)
        if x != y:
            return x < y
        i = i + 1
    return la < lb

def sort_tables(w:mutbuf) -> u64:
    node = 1
    while node <= NODE_COUNT:
        p = record(node)
        kind = byte(w, p)
        if kind == 5 or (kind == 4 and byte(w, p + 1) == 1):
            data = u16(w, p + 2)
            count = u16(w, p + 4)
            i = 1
            while i < count:
                value = u32(w, data + i * 4)
                j = i
                moving = 1
                while j > 0 and moving == 1:
                    previous = u32(w, data + (j - 1) * 4)
                    if less_string(w, value & 65535, previous & 65535):
                        set32(w, data + j * 4, previous)
                        j = j - 1
                    else:
                        moving = 0
                set32(w, data + j * 4, value)
                i = i + 1
        node = node + 1
    return 0

def resolve(w:mutbuf, node:u64, version:u64) -> u64:
    p = record(node)
    kind = byte(w, p)
    at = u16(w, p + 2)
    if kind == 6 or kind == 7:
        return u16(w, at + (version - 1) * 2)
    if kind == 8:
        if version >= 8:
            return u16(w, at + 2)
        return u16(w, at)
    return node

def allowed(w:mutbuf, entry:u64, kind:u64, version:u64, include_hash:u64) -> bool:
    if kind == 4:
        return byte(w, entry + 2) <= version
    child = u16(w, entry + 2)
    return include_hash == 1 or byte(w, record(child)) != 9

def emit(w:mutbuf, value:u64) -> u64:
    n = get(w, COUNT_AT)
    if n < JSON_BYTES:
        store(w, JSON_BASE + n, value)
    put(w, COUNT_AT, n + 1)
    return 0

def fixed(w:mutbuf, value:u64, size:u64) -> u64:
    cursor = get(w, COUNT_AT)
    i = 0
    while i < size:
        cursor = append(w, cursor, value & 255)
        value = value >> 8
        i = i + 1
    put(w, COUNT_AT, cursor)
    return 0

def append(w:mutbuf, cursor:u64, value:u64) -> u64:
    if cursor < JSON_BYTES:
        store(w, JSON_BASE + cursor, value)
    return cursor + 1

def hex_digit(value:u64) -> u64:
    if value < 10:
        return value + 48
    return value + 87

def quoted(w:mutbuf, at:u64, size:u64) -> u64:
    cursor = append(w, get(w, COUNT_AT), 34)
    i = 0
    while i < size:
        b = byte(w, at + i)
        if b == 34 or b == 92:
            cursor = append(w, cursor, 92)
            cursor = append(w, cursor, b)
        else:
            if b < 32:
                cursor = append(w, cursor, 92)
                if b == 8:
                    cursor = append(w, cursor, 98)
                else:
                    if b == 9:
                        cursor = append(w, cursor, 116)
                    else:
                        if b == 10:
                            cursor = append(w, cursor, 110)
                        else:
                            if b == 12:
                                cursor = append(w, cursor, 102)
                            else:
                                if b == 13:
                                    cursor = append(w, cursor, 114)
                                else:
                                    cursor = append(w, cursor, 117)
                                    cursor = append(w, cursor, 48)
                                    cursor = append(w, cursor, 48)
                                    cursor = append(w, cursor, hex_digit(b >> 4))
                                    cursor = append(w, cursor, hex_digit(b & 15))
            else:
                cursor = append(w, cursor, b)
        i = i + 1
    cursor = append(w, cursor, 34)
    put(w, COUNT_AT, cursor)
    return 0

def integer(w:mutbuf, value:u64) -> u64:
    if value == 0:
        emit(w, 48)
        return 0
    n = 0
    while value != 0:
        store(w, 2080 + n, 48 + value % 10)
        value = value // 10
        n = n + 1
    cursor = get(w, COUNT_AT)
    while n > 0:
        n = n - 1
        cursor = append(w, cursor, byte(w, 2080 + n))
    put(w, COUNT_AT, cursor)
    return 0

def indent(w:mutbuf, depth:u64, pretty:u64) -> u64:
    if pretty == 1:
        cursor = append(w, get(w, COUNT_AT), 10)
        i = 0
        while i < depth * 2:
            cursor = append(w, cursor, 32)
            i = i + 1
        put(w, COUNT_AT, cursor)
    return 0

def push(w:mutbuf, depth:u64, node:u64) -> u64:
    at = STACK_BASE + depth * 40
    put(w, at, node)
    put(w, at + 8, 0)
    put(w, at + 16, 0)
    put(w, at + 24, 0)
    put(w, at + 32, 0)
    return 0

def render(w:mutbuf, root:u64, version:u64, pretty:u64, include_hash:u64) -> u64:
    put(w, COUNT_AT, 0)
    push(w, 0, root)
    depth = 1
    while depth > 0:
        frame = STACK_BASE + (depth - 1) * 40
        node = resolve(w, get(w, frame), version)
        p = record(node)
        kind = byte(w, p)
        value = u16(w, p + 2)
        count = u16(w, p + 4)
        state = get(w, frame + 32)
        if kind == 0:
            fixed(w, 1819047278, 4)
            depth = depth - 1
        else:
            if kind == 1:
                if value == 0:
                    fixed(w, 435728179558, 5)
                else:
                    fixed(w, 1702195828, 4)
                depth = depth - 1
            else:
                if kind == 2:
                    integer(w, value)
                    depth = depth - 1
                else:
                    if kind == 3 or kind == 9:
                        quoted(w, value, count)
                        depth = depth - 1
                    else:
                        if kind != 4 and kind != 5:
                            return JSON_BYTES
                        if state == 0:
                            total = 0
                            i = 0
                            while i < count:
                                if allowed(w, value + i * 4, kind, version, include_hash):
                                    total = total + 1
                                i = i + 1
                            put(w, frame + 24, total)
                            if kind == 4:
                                emit(w, 91)
                            else:
                                emit(w, 123)
                            if total == 0:
                                if kind == 4:
                                    emit(w, 93)
                                else:
                                    emit(w, 125)
                                depth = depth - 1
                            else:
                                indent(w, depth, pretty)
                                put(w, frame + 32, 1)
                        else:
                            if state == 1:
                                index = get(w, frame + 8)
                                scanning = 1
                                while index < count and scanning == 1:
                                    if allowed(w, value + index * 4, kind, version, include_hash):
                                        scanning = 0
                                    else:
                                        index = index + 1
                                if index == count or depth == 32:
                                    return JSON_BYTES
                                entry = value + index * 4
                                child = u16(w, entry)
                                if kind == 5:
                                    key = record(child)
                                    quoted(w, u16(w, key + 2), u16(w, key + 4))
                                    emit(w, 58)
                                    if pretty == 1:
                                        emit(w, 32)
                                    child = u16(w, entry + 2)
                                put(w, frame + 8, index + 1)
                                put(w, frame + 16, get(w, frame + 16) + 1)
                                put(w, frame + 32, 2)
                                push(w, depth, child)
                                depth = depth + 1
                            else:
                                if get(w, frame + 16) < get(w, frame + 24):
                                    emit(w, 44)
                                    indent(w, depth, pretty)
                                    put(w, frame + 32, 1)
                                else:
                                    indent(w, depth - 1, pretty)
                                    if kind == 4:
                                        emit(w, 93)
                                    else:
                                        emit(w, 125)
                                    depth = depth - 1
    return get(w, COUNT_AT)
'''

def hash_functions():
    tree=ast.parse(sha_source())
    primary=tree.body[0]
    primary.name='hash_json'
    primary.args.args=[ast.arg(arg='w',annotation=ast.Name(id='mutbuf')),
                       ast.arg(arg='n',annotation=ast.Name(id='u64'))]
    primary.returns=ast.Name(id='u64')
    primary.body=primary.body[1:]  # replaced by the caller's fixed metadata bound
    class HashInput(ast.NodeTransformer):
        def visit_Call(self,node):
            node=self.generic_visit(node)
            if isinstance(node.func,ast.Name):
                if node.func.id=='length' and len(node.args)==1 and isinstance(node.args[0],ast.Name) and node.args[0].id=='s':
                    return ast.Name(id='n',ctx=ast.Load())
                if node.func.id=='padded_byte':
                    node.args[0]=ast.Name(id='w',ctx=ast.Load())
                    node.args.append(ast.Name(id='n',ctx=ast.Load()))
                if node.func.id=='store' and isinstance(node.args[0],ast.Name) and node.args[0].id=='o':
                    node.args[0]=ast.Name(id='w',ctx=ast.Load())
                    node.args[1]=ast.BinOp(left=ast.Constant(RAW_HASH),op=ast.Add(),right=node.args[1])
                if node.func.id=='byte' and isinstance(node.args[0],ast.Name) and node.args[0].id=='s':
                    node.args[0]=ast.Name(id='w',ctx=ast.Load())
                    node.args[1]=ast.BinOp(left=ast.Constant(JSON_BASE),op=ast.Add(),right=node.args[1])
            return node
    padded=tree.body[1]
    padded.args.args[0].arg='w'
    padded.args.args[0].annotation=ast.Name(id='mutbuf')
    padded.args.args.append(ast.arg(arg='n',annotation=ast.Name(id='u64')))
    tree=HashInput().visit(tree)
    # The SHA region is private to hash_json. Every write is either an original
    # 32-bit constant, four assembled input bytes, or a masked schedule/state
    # value. Keep its original 8-byte layout and zero high words, while reading
    # only the four significant bytes. JSON counters/stacks retain 64-bit get.
    class HashWords(ast.NodeTransformer):
        def visit_Call(self, node):
            node = self.generic_visit(node)
            if isinstance(node.func, ast.Name) and node.func.id in ('get', 'put'):
                node.func.id = {'get': 'sha_get32', 'put': 'sha_put32'}[node.func.id]
            return node
    tree.body[0] = HashWords().visit(tree.body[0])
    word_nodes = {node.name: node for node in ast.parse(STREAM_WORD_HELPERS).body}
    assert set(word_nodes) == {'get', 'put'}
    tree.body = [word_nodes.get(node.name, node) for node in tree.body]
    tree.body.extend(ast.parse('''
def sha_get32(w:mutbuf, index:u64) -> u64:
    return byte(w, index) | (byte(w, index + 1) << 8) | (byte(w, index + 2) << 16) | (byte(w, index + 3) << 24)

def sha_put32(w:mutbuf, index:u64, value:u64) -> u64:
    store(w, index, value & 255)
    store(w, index + 1, (value >> 8) & 255)
    store(w, index + 2, (value >> 16) & 255)
    store(w, index + 3, (value >> 24) & 255)
    store(w, index + 4, 0)
    store(w, index + 5, 0)
    store(w, index + 6, 0)
    store(w, index + 7, 0)
    return 0
''').body)
    ast.fix_missing_locations(tree)
    return ast.unparse(tree)+'\n'

def source_program():
    table,cap,cat=structured_table()
    raw=table.encode()
    assert TABLE_BASE+len(raw)<STACK_BASE
    source=SEMANTICS
    constants={'MAGIC':MAGIC,'WORK_BYTES':WORK_BYTES,'TABLE_BASE':TABLE_BASE,'STACK_BASE':STACK_BASE,
               'JSON_BASE':JSON_BASE,'JSON_BYTES':JSON_BYTES,'COUNT_AT':COUNT_AT,'RAW_HASH':RAW_HASH,
               'HEX_HASH':HEX_HASH,'NODE_COUNT':len(table.nodes),'CAP_ROOT':cap,'CAT_ROOT':cat}
    class Bind(ast.NodeTransformer):
        def visit_Name(self,n):
            if isinstance(n.ctx,ast.Load) and n.id in constants:return ast.copy_location(ast.Constant(constants[n.id]),n)
            return n
        def visit_Call(self, n):
            n = self.generic_visit(n)
            # Only SEMANTICS is visited here. Its word cells are the JSON
            # cursor or stack fields (node/index/emitted/total/state), all
            # initialized by HIA and bounded by 65536. Retain all eight bytes
            # on writes; do not narrow input read64 or metadata seed words.
            if isinstance(n.func, ast.Name) and n.func.id in ('get', 'put'):
                n.func.id = {'get': 'sha_get32', 'put': 'sha_put32'}[n.func.id]
            return n
    tree=Bind().visit(ast.parse(source));ast.fix_missing_locations(tree)
    prefix=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='schema_prefix')
    expected=b'hepta.hia.program.v'
    assert len(expected)==19
    prefix.body=[]
    for i,value in enumerate(expected):
        prefix.body.append(ast.If(test=ast.Compare(left=ast.Name(id='index',ctx=ast.Load()),ops=[ast.Eq()],comparators=[ast.Constant(i)]),
                                  body=[ast.Return(ast.Constant(value))],orelse=[]))
    prefix.body.append(ast.Return(ast.Constant(0)))
    ast.fix_missing_locations(tree)
    source=ast.unparse(tree)+'\n'+hash_functions()
    seed=bytearray(raw)
    seed.extend(bytes((-len(seed))%8))
    chunks=[]
    for at in range(0,len(seed),8):
        value=int.from_bytes(seed[at:at+8],'little')
        if value:chunks.append(f'    put(w, {TABLE_BASE+at}, {value})')
    pieces=[]
    for k in range(0,len(chunks),128):
        pieces.append(f'def seed_{k//128}(w:mutbuf) -> u64:\n'+'\n'.join(chunks[k:k+128])+'\n    return 0\n')
    source+='\ndef initialize(w:mutbuf) -> u64:\n'
    source+=f'    fill_range(w, {TABLE_BASE}, {len(seed)}, 0)\n'
    for k in range(len(pieces)):source+=f'    seed_{k}(w)\n'
    source+='    return 0\n'+'\n'.join(pieces)
    metadata={'nodes':len(table.nodes),'seed_bytes':len(raw),'seed_word_initializers':len(chunks),
              'capabilities_root':cap,'catalog_root':cat,'table_sha256':hashlib.sha256(raw).hexdigest(),
              'schema_count':len(PRIMITIVE_PROFILES),'instruction_records':len(original.OPCODES),
              'final_json_documents_stored':0,'catalog_digests_stored':0,
              'sorting':'HIA insertion sort over every object and the explicitly marked type arrays',
              'structured_nodes':[{'kind':k,'flags':f,'data':d.decode('ascii') if type(d)is bytes else d} for k,f,d in table.nodes]}
    return source,metadata

class DiscoveryBuilder(Builder):
    def expr(self, node):
        if isinstance(node, ast.BinOp) and type(node.op) in (ast.Mod, ast.FloorDiv):
            assert isinstance(node.right, ast.Constant) and node.right.value == 10
            left = self.expr(node.left)
            assert left[1] == 'u64'
            right = self.expr(node.right)
            operation = 'int.rem.checked' if isinstance(node.op, ast.Mod) else 'int.div.checked'
            return self.op(operation, [left, right], 'u64')
        return super().expr(node)

def document(source):
    nodes=ast.parse(source).body
    names={n.name:'f'+str(i) for i,n in enumerate(nodes)}
    signatures={n.name:([a.annotation.id for a in n.args.args],n.returns.id) for n in nodes}
    total=total_scalar_functions(nodes);functions=[]
    for node in nodes:
        b=DiscoveryBuilder(node,names,signatures,total);b.statements(node.body)
        functions.append({'name':names[node.name],'params':[b.param(x) for x in b.params],
                          'returns':[b.returns],'effects':['read','write','trap'],'entry':'b0','blocks':b.blocks})
    return compact_authoring_cfg({'schema':'hepta.hia.program.v8','module':'cli_discovery_json','functions':functions})

def identities():
    rows=[]
    for name in DEPENDENCIES:
        data=(BASE/name).read_bytes()
        rows.append({'path':name,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),
                     'git_blob':hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()})
    return rows

def generation():
    before=identities()
    source,metadata=source_program()
    data=document(source)
    raw=render_assembly(data).encode('utf-8')
    counts={'functions':len(data['functions']),'blocks':sum(len(f['blocks']) for f in data['functions']),
            'operations':sum(len(b['ops']) for f in data['functions'] for b in f['blocks']),
            'max_ssa':max(sum(len(p['out']) for b in f['blocks'] for p in b['ops'])+len(f['params'])+
                          sum(len(b['params']) for b in f['blocks']) for f in data['functions'])}
    if not (counts['functions']<=128 and counts['blocks']<=1536 and counts['operations']<=8192
            and counts['max_ssa']<=2047 and len(raw)<=1048576):
        raise ValueError('discovery JSON authoring exceeds the unchanged compiler profile')
    if identities()!=before:
        raise ValueError('discovery JSON authoring input changed')
    return raw, {'schema':'hepta.hia.cli-discovery-json-generation.v1',
                 'scope':'SOURCE_GENERATION_NOT_RUNTIME_OR_COLD_QUALIFICATION',
                 'sources':before,'counts':counts,'source_bytes':len(raw),
                 'source_sha256':hashlib.sha256(raw).hexdigest(),
                 'table_sha256':metadata['table_sha256'],
                 'final_json_documents_stored':metadata['final_json_documents_stored'],
                 'catalog_digests_stored':metadata['catalog_digests_stored']}

def main(argv=None):
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check',action='store_true')
    parser.add_argument('--output',type=Path,default=TARGET)
    parser.add_argument('--report',type=Path)
    args=parser.parse_args(argv)
    raw,report=generation()
    if args.check:
        if args.output.read_bytes()!=raw:
            raise ValueError('discovery JSON HIA differs from its complete authoring inputs')
    else:
        args.output.write_bytes(raw)
        if args.output.read_bytes()!=raw:
            raise ValueError('discovery JSON publication readback differs')
    if args.report is not None:
        args.report.write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    print(json.dumps(report,indent=2,sort_keys=True))

if __name__=='__main__':main()
